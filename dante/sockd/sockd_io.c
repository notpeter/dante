/*
 * Copyright (c) 1997, 1998, 1999
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. The above copyright notice, this list of conditions and the following
 *    disclaimer must appear in all copies of the software, derivative works
 *    or modified versions, and any portions thereof, aswell as in all
 *    supporting documentation.
 * 2. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by
 *      Inferno Nettverk A/S, Norway.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Inferno Nettverk A/S requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  sdc@inet.no
 *  Inferno Nettverk A/S
 *  Oslo Research Park
 *  Gaustadaléen 21
 *  N-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

#include "common.h"

static const char rcsid[] =
"$Id: sockd_io.c,v 1.138 1999/06/07 08:10:46 michaels Exp $";

/*
 * Accept io objects from mother and does io on them.  We never
 * send back ancillary data, only ordinary data, so no need for
 * locking here even on broken systems (#ifdef HAVE_SENDMSG_DEADLOCK).
*/


__BEGIN_DECLS

static int
allocated __P((void));
/*
 * Returns the number of allocated (active) io's
*/


static struct sockd_io_t *
io_getset __P((fd_set *set));
/*
 * Goes through our list until it finds a io object where atleast one of the
 * descriptors is set.
 * Returns NULL if none found.
*/

static struct sockd_io_t *
io_finddescriptor __P((int d));
/*
 * Finds the io object where one of the descriptors matches "fd".
*/

static int
io_fillset __P((fd_set *set, int antiflags));
/*
 * Sets all descriptors in our list in the set "set".  If "flags"
 * is set, io's with any of the flags in "flags" set will be excluded.
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors open currently.
*/


static void
io_clearset __P((const struct sockd_io_t *io, fd_set *set));
/*
 * Clears all filedescriptors in "io" from "set".
*/

static void
doio __P((int mother, struct sockd_io_t *io, fd_set *rset, fd_set *wset,
			 int flags));
/*
 * Does i/o over the descriptors in "io", in to out and out to in.
 * "mother" is write connection to mother if we need to send a ack.
 * "io" is the object to do i/o over,
 * "flags" is the flags to set on the actual i/o calls
 * (read()/write(), recvfrom()/sendto()), currently only MSG_OOB.
 * If any of the calls fails the "io" is deleted.
*/

static int
io_rw __P((struct sockd_io_direction_t *in, struct sockd_io_direction_t *out,
			  int *bad, char *buf, int flags));
/*
 * Transfers data from "in" to "out" using flag "flags".  The data
 * transfered uses "buf" as a buffer, which must be big enough to
 * hold the data transfered.
 * The function never transfers more that the receive low watermark of
 * "out".
 * Returns:
 *		On success: bytes transfered or 0 for eof.
 *		On failure: -1.  "bad" is set to the value of the descriptor that
 *						failure was first detected on.
*/

static void
delete_io __P((int mother, struct sockd_io_t *io, int fd, int status));
/*
 * deletes the io object "io".  "fd" is the descriptor on which "status"
 * was returned.  If "fd" is negative, it's ignored.
 * If "mother" is >= 0 the deletion of "io" is ACK'ed to her.
 * "status" can have one of these values and is normally intended to be the
 * result from a io call (read/write/etc).
 *		IO_ERRORUNKNOWN:	unknown error.
 *		IO_TIMEOUT		:	connection timed out.  ("fd" argument is ignored).
 *		IO_ERROR			:  error using "fd".
 *		IO_CLOSE			:	socket was closed.
 *		> 0				:  short read/write
*/


static void
proctitleupdate __P((void));
/*
 * Updates the title of this process.
*/

static struct timeval *
io_gettimeout __P((struct timeval *timeout));
/*
 * If there is a timeout on the current clients for how long to exist
 * without doing i/o, this function fills in "timeout" with the appropriate
 * timeout.
 * Returns:
 *		If there is a timeout: pointer to filled in "timeout".
 *		If there is no timeout: NULL.
*/

static struct sockd_io_t *
io_gettimedout __P((void));
/*
 * Scans all clients for one that has timed out according to config
 * settings.
 * Returns:
 *		If timed out client found: pointer to it.
 *		Else: NULL.
*/

#define UDPFROMLENCHECK(socket, fromlen) \
	do { \
		if (fromlen == 0) { \
			static int failures; \
\
			swarnx("%s: system error: did not get address in recvfrom()", \
			function); \
\
			if (++failures > 5) { \
				swarnx("%s: running Solaris 2.5.1 are we?  " \
				"giving up after %d failures", function, failures); \
				delete_io(mother, io, (socket), IO_ERROR); \
				failures = 0; \
			} \
			return; \
		} \
	} while (0)

__END_DECLS


static struct sockd_io_t iov[SOCKD_IOMAX];	/* each child has these io's. */
static int ioc = ELEMENTS(iov);

void
run_io(mother)
	struct sockd_mother_t *mother;
{
	const char *function = "run_io()";
	int p;

	proctitleupdate();

	/* CONSTCOND */
	while (1) {
		int rbits, wbits;
		fd_set rset, wset, xset, newrset;
		struct sockd_io_t *io;
		struct timeval timeout;

		rbits = io_fillset(&rset, 0);

		if (mother->s != -1) {
			FD_SET(mother->s, &rset);
			rbits = MAX(rbits, mother->s);
		}
		else /* no mother.  Do we have any descriptors to work with? */
			if (rbits == -1) {
				slog(LOG_DEBUG, "%s: can't find mother and no io's", function);
				sockdexit(-EXIT_FAILURE);
			}
		++rbits;

		/*
		 * first find descriptors that are readable, we won't write if we can't
		 * read.  Since we receive oob data inline we can delay checking for
		 * exception until next select().
		*/
		switch (select(rbits, &rset, NULL, NULL, io_gettimeout(&timeout))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
				if ((io = io_gettimedout()) == NULL)
					continue; /* should only be possible if sighup received. */
				delete_io(mother->ack, io, -1, IO_TIMEOUT);
				continue;
		}

		if (mother->s != -1 && FD_ISSET(mother->s, &rset)) {
			FD_CLR(mother->s, &rset);

			if ((p = recv_io(mother->s, NULL)) != 0)
				mother->s = -1;
			else
				proctitleupdate();
		}

		/*
		 * This is tricky but we need to check for write separately to avoid
		 * busylooping.
		 * The problem is that if the descriptor is ready for
		 * reading but the corresponding descriptor to write out on is not
		 * ready we will be busylooping; above select will keep returning
		 * descriptors set, but we will not be able to write (and thus read)
		 * them.
		 * We therefore only set in wset the descriptors that have the
		 * corresponding read descriptor readable so that when the
		 * below select() returns, the io objects we get will be both
		 * readable and writable.  A problem is that if while we wait for
		 * writability, a new descriptor becomes readable (and writable), we
		 * thus can't block forever here.  We solve this by in the below
		 * select() also checking for readability, but now only the descriptors
		 * that were not found to be readable in the previous select().
		*/

		FD_ZERO(&wset);

		/* find descriptors to check for writability. */
		for (wbits = -1, p = 0; p < rbits; ++p) {
			if (!FD_ISSET(p, &rset)) /* only write after read. */
				continue;

			if ((io = io_finddescriptor(p)) == NULL) {
				SASSERTX(p == mother->s);
				continue;
			}

			if (io->in.s == p) {
				/* to read from in requires out to be writable. */
				FD_SET(io->out.s, &wset);
				wbits = MAX(wbits, io->out.s);
				continue;
			}
			else if (io->out.s == p) {
				/* to read from out requires in to be writable. */
				FD_SET(io->in.s, &wset);
				wbits = MAX(wbits, io->in.s);
				continue;
			}
			else {
				SASSERTX(io->control.s == p);
				FD_SET(io->control.s, &wset); /* no match for control, always ok. */
				wbits = MAX(wbits, io->control.s);
			}
		}

		if (wbits < 0)
			continue;

		/*
		 * We need to know when a new descriptor becomes readable.
		 * A new descriptor would be one not set in the checked rset,
		 * but set in the full rset.  We need to refill rset since we
		 * may have received new children since previous select() call.
		 * This means that a positive return from below select does not
		 * necessarily indicate we have i/o to do, but it does mean we
		 * either have it or a new descriptor became readable, in either,
		 * case, something has happened.
		*/

		io_fillset(&xset, MSG_OOB);
		rbits = io_fillset(&newrset, 0);

		newrset = *fdsetop(rbits + 1, &rset, &newrset, '^');

		if (mother->s != -1) {
			FD_SET(mother->s, &newrset); /* mother is special, always checked. */
			rbits = MAX(mother->s, rbits);
		}

		++rbits;
		switch (select(rbits, &newrset, &wset, &xset, io_gettimeout(&timeout))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
				if ((io = io_gettimedout()) == NULL)
					continue; /* should only be possible if sighup received. */
				delete_io(mother->ack, io, -1, IO_TIMEOUT);
				continue;
		}


		/*
		 * newrset; new descriptors readable.  Don't do anything with them
		 *          here, must loop around and check for writability first.
		 * wset;	descriptors writable with a matching readable descriptor (rset),
		 *       these are what we can do i/o over.
		*/

		while ((io = io_getset(&xset)) != NULL) {
			slog(LOG_DEBUG, "select(): exception set");

			doio(mother->ack, io, &xset, &wset, MSG_OOB);
			io_clearset(io, &xset);
			io_clearset(io, &wset);
		}

		while ((io = io_getset(&wset)) != NULL) {
			doio(mother->ack, io, &rset, &wset, 0);
			io_clearset(io, &rset);
			io_clearset(io, &wset);
		}
	}
}


void
delete_io(mother, io, fd, status)
	int mother;
	struct sockd_io_t *io;
	int fd;
	int status;
{
	const char *function = "delete_io()";
	const int errno_s = errno;

	SASSERTX(io->allocated);

	if (io->rule.log.disconnect) {
		char logmsg[MAXHOSTNAMELEN * 2 + 1024];
		char in[MAXSOCKADDRSTRING], out[MAXSOCKADDRSTRING];

		/* LINTED pointer casts may be troublesome */
		sockaddr2string((struct sockaddr *)&io->in.raddr, in, sizeof(in));

		switch (io->state.command) {
			case SOCKS_BIND:
			case SOCKS_BINDREPLY:
			case SOCKS_CONNECT:
				/* LINTED pointer casts may be troublesome */
				sockaddr2string((struct sockaddr *)&io->out.raddr, out,
				sizeof(out));
				break;

			case SOCKS_UDPASSOCIATE:
				snprintf(out, sizeof(out), "`world'");
				break;

			default:
				SERRX(io->state.command);
		}

		snprintf(logmsg, sizeof(logmsg),
		"%s: %lu -> %s -> %lu,  %lu -> %s -> %lu",
		protocol2string(io->state.protocol),
		(unsigned long)io->in.written, in, (unsigned long)io->in.read,
		(unsigned long)io->out.written, out, (unsigned long)io->out.read);

		errno = errno_s;
		if (fd < 0)
			switch (status) {
				case IO_ERROR:
					swarn("%s: connection error", logmsg);
					break;

				case IO_CLOSE:
					slog(LOG_INFO, "%s: connection closed", logmsg);
					break;

				case IO_TIMEOUT:
					slog(LOG_INFO, "%s: connection i/o expired", logmsg);
					break;

				default:
					slog(LOG_INFO, "%s: short read/write", logmsg);
			}
		else if (fd == io->in.s || fd == io->control.s) {
			switch (status) {
				case IO_ERROR:
					swarn("%s: client error", logmsg);
					break;

				case IO_CLOSE:
					slog(LOG_INFO, "%s: client closed", logmsg);
					break;

				case IO_TIMEOUT:
					slog(LOG_INFO, "%s: client i/o expired", logmsg);
					break;

				default:
					slog(LOG_INFO, "%s: client short read/write", logmsg);
			}
		}
		else if (fd == io->out.s) {
			switch (status) {
				case IO_ERROR:
					swarn("%s: remote error", logmsg);
					break;

				case IO_CLOSE:
					slog(LOG_INFO, "%s: remote closed", logmsg);
					break;

				case IO_TIMEOUT:
					slog(LOG_INFO, "%s: remote i/o expired", logmsg);
					break;

				default:
					slog(LOG_INFO, "%s: remote short read/write", logmsg);

			}
		}
		else
			SERRX(fd);
	}

	if (io->acceptrule.log.disconnect) {
		struct connectionstate_t state = io->state;

		state.command = SOCKS_DISCONNECT;

		iolog(&io->acceptrule, &state, OPERATION_DISCONNECT, &io->src, &io->dst,
		NULL, 0);
	}

	close_iodescriptors(io);

	io->allocated = 0;

	if (mother != -1) {
		const char b = SOCKD_FREESLOT;

		/* ack io slot free. */
		if (writen(mother, &b, sizeof(b)) != sizeof(b))
			swarn("%s: writen(): mother", function);
	}

	proctitleupdate();
}


void
close_iodescriptors(io)
	const struct sockd_io_t *io;
{

	close(io->in.s);
	close(io->out.s);

	switch (io->state.command) {
		case SOCKS_CONNECT:
			break;

		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (!io->state.extension.bind)
				break;
			/* else: */ /* FALLTHROUGH */

		case SOCKS_UDPASSOCIATE:
			close(io->control.s);
			break;

		default:
			SERRX(io->state.command);
	}
}


int
recv_io(s, io)
	int s;
	struct sockd_io_t *io;
{
	const char *function = "recv_io()";
	int i, fdexpect, fdreceived;
	size_t length = 0;
	struct iovec iovec[1];
	struct msghdr msg;
	CMSG_AALLOC(sizeof(int) * FDPASS_MAX);

	if (io == NULL) {	/* child semantics; find a io ourselves. */
		for (i = 0; i < ioc; ++i)
			if (!iov[i].allocated) {
				io = &iov[i];
				break;
			}

		if (io == NULL) {
			/*
			 * either mother died/closed connection, or there is another error.
			 * Both cases should be rare so try to find out what the problem is.
			*/
			char buf;

			if (recv(s, &buf, sizeof(buf), MSG_PEEK) > 0)
				SERRX(allocated());
			return -1;
		}
	}

	iovec[0].iov_base		= io;
	iovec[0].iov_len		= sizeof(*io);
	length				  += iovec[0].iov_len;

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

	CMSG_SETHDR_RECV(sizeof(cmsgmem));

	if (recvmsgn(s, &msg, 0, length) != (ssize_t)length) {
		swarn("%s: recvmsgn()", function);
		return -1;
	}

	/* figure out how many descriptors we are supposed to be passed. */
	switch (io->state.command) {
		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (io->state.extension.bind)
				fdexpect = 3;	/* in, out, control. */
			else
				fdexpect = 2;	/* in and out. */
			break;

		case SOCKS_CONNECT:
			fdexpect = 2;	/* in and out */
			break;

		case SOCKS_UDPASSOCIATE:
			fdexpect = 3;	/* in, out, and control */
			break;

		default:
			SERRX(io->state.command);
	}

	/* calculate expected datalen */

#if !HAVE_DEFECT_RECVMSG
	SASSERT(CMSG_GETLEN(msg) == sizeof(int) * fdexpect);
#endif

	/*
	 * Get descriptors sent us.
	*/

	fdreceived = 0;

	CMSG_GETOBJECT(io->in.s, sizeof(io->in.s) * fdreceived++);
	CMSG_GETOBJECT(io->out.s, sizeof(io->out.s) * fdreceived++);

	switch (io->state.command) {
		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (io->state.extension.bind)
				CMSG_GETOBJECT(io->control.s, sizeof(io->control.s) * fdreceived++);
			else
				io->control.s = -1;
			break;

		case SOCKS_CONNECT:
			io->control.s = -1;
			break;

		case SOCKS_UDPASSOCIATE:
			CMSG_GETOBJECT(io->control.s, sizeof(io->control.s) * fdreceived++);
			break;

		default:
			SERRX(io->state.command);
	}

	time(&io->time);
	io->allocated = 1;

#if DEBUG
	printfd(io, "received");
#endif

	return 0;
}


static void
io_clearset(io, set)
	const struct sockd_io_t *io;
	fd_set *set;
{

	FD_CLR(io->in.s, set);
	FD_CLR(io->out.s, set);

	switch (io->state.command) {
		case SOCKS_CONNECT:
			break;

		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (!io->state.extension.bind)
				break;
			/* else: */ /* FALLTHROUGH */

		case SOCKS_UDPASSOCIATE:
			FD_CLR(io->control.s, set);
			break;

		default:
			SERRX(io->state.command);
	}
}


static int
allocated(void)
{
	int i, alloc;

	for (i = 0, alloc = 0; i < ioc; ++i)
		if (iov[i].allocated)
			++alloc;

	return alloc;
}


static void
doio(mother, io, rset, wset, flags)
	int mother;
	struct sockd_io_t *io;
	fd_set *rset, *wset;
	int flags;
{
	const char *function = "doio()";
	/* CONSTCOND */
	char buf[MAX(SOCKD_BUFSIZETCP, SOCKD_BUFSIZEUDP)];
	ssize_t r, w;


	SASSERTX(io->allocated);

	SASSERTX(flags & MSG_OOB
	|| (FD_ISSET(io->in.s, rset) && FD_ISSET(io->out.s, wset))
	|| (FD_ISSET(io->in.s, wset) && FD_ISSET(io->out.s, rset))
	||	(io->control.s != -1 && FD_ISSET(io->control.s, rset)));

	switch (io->state.protocol) {
		case SOCKS_TCP: {
			int bad;

			/* from in to out... */
			if (FD_ISSET(io->in.s, rset) && FD_ISSET(io->out.s, wset)) {
				bad = -1;
				r = io_rw(&io->in, &io->out, &bad, buf, flags);
				if (bad != -1) {
					delete_io(mother, io, bad, r);
					return;
				}

				iolog(&io->rule, &io->state, OPERATION_IO, &io->src, &io->dst, buf,
				(size_t)r);
			}

			/* and out to in. */
			if (FD_ISSET(io->out.s, rset) && FD_ISSET(io->in.s, wset)) {
				bad = -1;
				r = io_rw(&io->out, &io->in, &bad, buf, flags);
				if (bad != -1) {
					delete_io(mother, io, bad, r);
					return;
				}

				iolog(&io->rule, &io->state, OPERATION_IO, &io->dst, &io->src, buf,
				(size_t)r);
			}

			break;
		}

		case SOCKS_UDP: {
			struct udpheader_t header;
			struct sockaddr from, to;
			socklen_t fromlen;
			int permit;

			/*
			 * UDP is sadly considerably more complex than TCP;
			 * need to check rules on each packet, need to check if it
			 * was received from expected src, etc.
			 * We first peek at it so we can find out what address it's from,
			 * then we check rules and then we read the packet out of the buffer.
			 * Reason why we first peek is that if the rule calls libwrap,
			 * libwrap would hang since we'd already read the packet and it
			 * wants to peek itself.
			*/

			/* udp to relay from client to destination? */
			if (FD_ISSET(io->in.s, rset) && FD_ISSET(io->out.s, wset)) {
				const int lflags = flags & ~MSG_OOB;

				fromlen = sizeof(from);
				/* LINTED pointer casts may be troublesome */
				if ((r = recvfrom(io->in.s, buf,
				MIN(io->out.sndlowat, sizeof(header)), lflags | MSG_PEEK,
				&from, &fromlen)) == -1) {
					delete_io(mother, io, io->in.s, r);
					return;
				}
				UDPFROMLENCHECK(io->in.s, fromlen);

				/*
				 * If client hasn't sent us it's address yet we have to
				 * assume the first packet is from is it.  Client can only
				 * blame itself if not.
				*/
				if (io->in.raddr.sin_addr.s_addr == htonl(INADDR_ANY)
				||  io->in.raddr.sin_port == htons(0)) {

					if (io->in.raddr.sin_addr.s_addr == htonl(INADDR_ANY))
					/* LINTED pointer casts may be troublesome */
						io->in.raddr.sin_addr.s_addr
						= ((struct sockaddr_in *)&from)->sin_addr.s_addr;

					if (io->in.raddr.sin_port == htons(0))
						/* LINTED pointer casts may be troublesome */
						io->in.raddr.sin_port
						= ((struct sockaddr_in *)&from)->sin_port;
				}

				/* first packet; check and connect socket for performance. */
				if (io->in.read == 0) {
					/* LINTED pointer casts may be troublesome */
					if (sockaddrcmp((struct sockaddr *)&io->in.raddr, &from) != 0) {
						char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];

						slog(LOG_NOTICE,
						"%s(u): udp: expected from %s, got it from %s",
						VERDICT_BLOCKs,
						/* LINTED pointer casts may be troublesome */
						sockaddr2string((struct sockaddr *)&io->in.raddr, src,
						sizeof(src)),
						sockaddr2string(&from, dst, sizeof(dst)));

						/* need to read the peeked at packet out of socket buffer. */
						fromlen = 0;
						if (recvfrom(io->in.s, buf, io->out.sndlowat, lflags, NULL,
						&fromlen) == -1) {
							swarn("%s: recvfrom() of peeked data", function);
							return;
						}

						break;
					}

					if (connect(io->in.s, &from, sizeof(from)) != 0) {
						delete_io(mother, io, io->in.s, r);
						return;
					}
				}
				io->in.read += r;

				/* got packet, pull out socks udp header. */
				if (string2udpheader(buf, (size_t)r, &header) == NULL) {
					char badfrom[MAXSOCKADDRSTRING];

					/* LINTED pointer casts may be troublesome */
					swarnx("%s: bad socks udppacket (length = %d) from %s",
					function, r, sockaddr2string((struct sockaddr *)&io->in.raddr,
					badfrom, sizeof(badfrom)));

					/* to read the peeked packet out of the buffer. */
					fromlen = 0;
					if (recvfrom(io->in.s, buf, io->out.sndlowat, lflags, NULL,
					&fromlen) == -1) {
						swarn("%s: recvfrom() of peeked data", function);
						return;
					}

					break;
				}

				io->dst = header.host;

				/* strip of socks udpheader before sending to destination */
				r -= PACKETSIZE_UDP(&header);

				/* is the packet to be permitted out? */
				permit
				= rulespermit(io->in.s, &io->rule, &io->state, &io->src, &io->dst);

				/* read the peeked out of socket buffer. */
				fromlen = 0;
				if (recvfrom(io->in.s, buf, io->out.sndlowat, lflags, NULL,
				&fromlen) == -1) {
					swarn("%s: recvfrom() of peeked data", function);
					return;
				}

				if (header.frag != 0) {
					char badfrom[MAXSOCKADDRSTRING];

					/* LINTED pointer casts may be troublesome */
					swarnx("%s: udp: fragmented packet from %s.  Not supported",
					function, sockaddr2string((struct sockaddr *)&io->in.raddr,
					badfrom, sizeof(badfrom)));
					break;
				}

				iolog(&io->rule, &io->state, OPERATION_IO, &io->src, &io->dst,
				&buf[PACKETSIZE_UDP(&header)], (size_t)r);

				if (!permit)
					break;

				sockshost2sockaddr(&header.host, &to);
				if ((w = sendto(io->out.s, &buf[PACKETSIZE_UDP(&header)],
				(size_t)r, lflags, &to, sizeof(to))) != r) {
					char badsend[MAXSOCKADDRSTRING];

					swarn("%s: sendto(%s): %d of %d",
					function, sockaddr2string(&to, badsend, sizeof(badsend)), w, r);
				}
				else
					io->out.written += w;
			}

			/* datagram reply from remote present? */
			if (FD_ISSET(io->out.s, rset) && FD_ISSET(io->in.s, wset)) {
				const int lflags = flags & ~MSG_OOB;
				struct sockshost_t srcsh;
				char *newmsg;

				/* MSG_PEEK because of libwrap, see above. */
				fromlen = sizeof(from);
				/* LINTED possible pointer alignment problem */
				if ((r = recvfrom(io->out.s, buf, 1, lflags | MSG_PEEK,
				&from, &fromlen)) == -1) {
					delete_io(mother, io, io->out.s, r);
					return;
				}
				UDPFROMLENCHECK(io->out.s, fromlen);

				sockaddr2sockshost(&from, &srcsh);

				permit
				= rulespermit(io->out.s, &io->rule, &io->state, &srcsh, &io->src);

				/* read the peeked packet out of the buffer. */
				if ((r = recvfrom(io->out.s, buf, io->in.sndlowat, lflags, &from,
				&fromlen)) == -1) {
					delete_io(mother, io, io->out.s, r);
					return;
				}
				io->out.read += r;

				iolog(&io->rule, &io->state, OPERATION_IO, &srcsh, &io->src, buf,
				(size_t)r);

				if (!permit)
					break;

				/* add socks udpheader */
				/* LINTED pointer casts may be troublesome */
				if ((newmsg = udpheader_add(&from, buf, (size_t *)&r)) == NULL) {
					swarnx("%s: %s", function, NOMEM);
					break;
				}

				/* XXX socket must be connected. */
				if ((w = sendto(io->in.s, newmsg, (size_t)r, lflags, NULL, 0))
				!= r) {
					char badsend[MAXSOCKADDRSTRING];

					/* LINTED pointer casts may be troublesome */
					swarn("%s: sendto(%s): %d of %d",
					function,
					sockaddr2string((struct sockaddr *)&io->in.raddr, badsend,
					sizeof(badsend)), w, r);
					free(newmsg);
					break;
				}
				free(newmsg);

				io->in.written += w;
			}
			break;
		}

		default:
			SERRX(io->state.protocol);
	}

	/*
	 * Only thing we expect from client's control connection is a eof.
	 * For commands that do not have a controlconnection, we
	 * set descriptor to -1 when receiving others.
	*/

	if (io->control.s != -1 && FD_ISSET(io->control.s, rset)) {
		if ((r = read(io->control.s, buf, sizeof(buf))) <= 0)
			delete_io(mother, io, io->control.s, r);
		else {
			char *unexpected, hmmread[MAXSOCKADDRSTRING];

			slog(LOG_NOTICE, "%s/control: %d unexpected bytes: %s",
			/* LINTED pointer casts may be troublesome */
			sockaddr2string((struct sockaddr *)&io->control.raddr, hmmread,
			sizeof(hmmread)), r, strcheck(unexpected = str2vis(buf, r)));

			free(unexpected);
		}
	}

	/* don't care what direction/descriptors i/o was done over. */
	time(&io->time);
}

static int
io_rw(in, out, bad, buf, flag)
	struct sockd_io_direction_t *in;
	struct sockd_io_direction_t *out;
	int *bad;
	char *buf;
	int flag;
{
	ssize_t r, w;
	size_t len;

	if (flag & MSG_OOB)
		if (sockatmark(in->s) != 1)
			flag &= ~MSG_OOB;

	/* we receive oob inline. */
	len = flag & MSG_OOB ? 1 : out->sndlowat;
	if ((r = recv(in->s, buf, len, flag & ~MSG_OOB)) <= 0) {
		*bad = in->s;
		return r;
	}
	in->read += r;

	if (flag & MSG_OOB)
		in->flags |= MSG_OOB;	/* read oob data.				*/
	else
		in->flags &= ~MSG_OOB;	/* did not read oob data.	*/

	if ((w = send(out->s, buf, (size_t)r, flag)) != r) {
		*bad = out->s;
		return w;
	}
	out->written += w;

	return w;
}

static void
proctitleupdate(void)
{

	setproctitle("iorelayer: %d/%d", allocated(), SOCKD_IOMAX);
}

static struct sockd_io_t *
io_getset(set)
	fd_set *set;
{
	int i;

	for (i = 0; i < ioc; ++i)
		if (iov[i].allocated) {
			if (FD_ISSET(iov[i].in.s, set))
				return &iov[i];

			if (FD_ISSET(iov[i].out.s, set))
				return &iov[i];

			switch (iov[i].state.command) {
				case SOCKS_BIND:
				case SOCKS_BINDREPLY:
					if (!iov[i].state.extension.bind)
						break;
					/* else: */ /* FALLTHROUGH */

				case SOCKS_UDPASSOCIATE:
					if (FD_ISSET(iov[i].control.s, set))
						return &iov[i];
					break;

				default:
					break;
			}
		}

	return NULL;
}


static struct sockd_io_t *
io_finddescriptor(d)
	int d;
{
	int i;

	for (i = 0; i < ioc; ++i)
		if (iov[i].allocated) {
			if (d == iov[i].in.s ||	 d == iov[i].out.s)
				return &iov[i];

			switch (iov[i].state.command) {
				case SOCKS_BIND:
				case SOCKS_BINDREPLY:
					if (!iov[i].state.extension.bind)
						break;
					/* else: */ /* FALLTHROUGH */

				case SOCKS_UDPASSOCIATE:
					if (d == iov[i].control.s)
						return &iov[i];
					break;

				default:
					break;
			}
		}

	return NULL;
}


static int
io_fillset(set, antiflags)
	fd_set *set;
	int antiflags;
{
	int i, max;

	FD_ZERO(set);

	for (i = 0, max = -1; i < ioc; ++i)
		if (iov[i].allocated) {
			if (! (antiflags & iov[i].in.flags)) {
				FD_SET(iov[i].in.s, set);
				max = MAX(max, iov[i].in.s);
			}

			if (! (antiflags & iov[i].out.flags)) {
				FD_SET(iov[i].out.s, set);
				max = MAX(max, iov[i].out.s);
			}

			switch (iov[i].state.command) {
				case SOCKS_BIND:
				case SOCKS_BINDREPLY:
					if (!iov[i].state.extension.bind)
						break;
					/* else: */ /* FALLTHROUGH */

				case SOCKS_UDPASSOCIATE:
					if (! (antiflags & iov[i].control.flags)) {
						FD_SET(iov[i].control.s, set);
						max = MAX(max, iov[i].control.s);
					}
					break;

				default:
					break;
			}
		}

	return max;
}

static struct timeval *
io_gettimeout(timeout)
	struct timeval *timeout;
{
	time_t timenow;
	int i;

	if (allocated() == 0 || config.timeout.io == 0)
		return NULL;

	timeout->tv_sec	= config.timeout.io;
	timeout->tv_usec	= 0;

	time(&timenow);

	for (i = 0; i < ioc; ++i)
		if (!iov[i].allocated)
			continue;
		else
			timeout->tv_sec = MAX(0, MIN(timeout->tv_sec,
			config.timeout.io - (timenow - iov[i].time)));

	return timeout;
}

static struct sockd_io_t *
io_gettimedout(void)
{
	int i;
	time_t timenow;

	if (config.timeout.io == 0)
		return NULL;

	time(&timenow);

	for (i = 0; i < ioc; ++i)
		if (!iov[i].allocated)
			continue;
		else
			if (timenow - iov[i].time >= config.timeout.io)
				return &iov[i];

	return NULL;
}
