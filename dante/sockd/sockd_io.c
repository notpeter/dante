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
"$Id: sockd_io.c,v 1.159 1999/09/02 10:42:04 michaels Exp $";

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

static void
checkmother __P((struct sockd_mother_t *mother, fd_set *readset));
/*
 * Checks if "mother" is set in "readset" and if so receives
 * a io from "mother".  Closes "mother" if there is an error.
 */

static void
siginfo __P((int sig));
/*
 * Print information about our current connections.
 */

/* Solaris sometimes fails to return srcaddress in recvfrom(). */
#define UDPFROMLENCHECK(socket, fromlen) \
	do { \
		if (fromlen == 0) { \
			static int failures; \
\
			swarnx("%s: system error: did not get address in recvfrom()", \
			function); \
\
			if (++failures > 5) { \
				swarnx("%s: running Solaris <= 2.5.1 are we?  " \
				"giving up after %d failures", function, failures); \
				delete_io(mother, io, (socket), IO_ERROR); \
				failures = 0; \
			} \
			return; \
		} \
	} while (lintnoloop_sockd_h)

__END_DECLS


static struct sockd_io_t iov[SOCKD_IOMAX];	/* each child has these io's. */
static int ioc = ELEMENTS(iov);

void
run_io(mother)
	struct sockd_mother_t *mother;
{
	const char *function = "run_io()";
	struct sigaction sigact;
	int p;

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags	= SA_RESTART;
	sigact.sa_handler = siginfo;

#if HAVE_SIGNAL_SIGINFO
	if (sigaction(SIGINFO, &sigact, NULL) != 0)
		serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);
#endif  /* HAVE_SIGNAL_SIGINFO */

	/* same handler, for systems without SIGINFO. */
	if (sigaction(SIGUSR1, &sigact, NULL) != 0)
		serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);

	proctitleupdate();

	/* CONSTCOND */
	while (1) {
		int rbits, bits;
		fd_set rset, wset, xset, newrset, controlset, tmpset;
		struct sockd_io_t *io;
		struct timeval timeout;

		io_fillset(&xset, MSG_OOB);
		rbits = io_fillset(&rset, 0);

		if (mother->s != -1) {
			FD_SET(mother->s, &rset);
			rbits = MAX(rbits, mother->s);
		}
		else /* no mother.  Do we have any other descriptors to work with? */
			if (rbits == -1) {
				slog(LOG_DEBUG, "%s: can't find mother and no io's", function);
				sockdexit(-EXIT_FAILURE);
			}

		/*
		 * first find descriptors that are readable; we won't write if
		 * we can't read.  Also select for exception so we can tell
		 * the i/o function if there's one pending later.
 		 */
		++rbits;
		switch (selectn(rbits, &rset, NULL, &xset, io_gettimeout(&timeout))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
				if ((io = io_gettimedout()) != NULL)
					delete_io(mother->ack, io, -1, IO_TIMEOUT);
				/* else: should only be possible if sighup received. */
				continue;
		}

		checkmother(mother, &rset);

		/*
		 * This is tricky but we need to check for write separately to
		 * avoid busylooping.
		 * The problem is that if the descriptor is ready for reading but
		 * the corresponding descriptor to write out on is not ready we will
		 * be busylooping; above select will keep returning descriptors set,
		 * but we will not be able to write (and thus read) them.
		 * We therefore only set in wset the descriptors that have the
		 * corresponding read descriptor readable so that when the
		 * below select() returns, the io objects we get from wset will
		 * be both readable and writable.
		 *
		 * A problem is that if while we wait for writability, a new
		 * descriptor becomes readable, we thus can't block forever here.
		 * We solve this by in the below select() also checking for
		 * readability, but now only the descriptors that were not found
		 * to be readable in the previous select().
		 * This means that a positive return from below select does not
		 * necessarily indicate we have i/o to do, but it does mean we
		 * either have it or a new descriptor became readable; in either
		 * case, something has happened. 
		 * Reason we do not check for exceptions in this select is that
		 * there is nothing we do about them until the descriptor becomes
		 * readable too, thus any new exceptions will be in newrset before
		 * we have reason to care about them.
		 */

		/* descriptors to check for readability; those not already set. */
		bits = io_fillset(&tmpset, 0);
		bits = fdsetop(bits + 1, '^', &rset, &tmpset, &newrset);
		if (mother->s != -1) { /* mother status may change too. */
			FD_SET(mother->s, &newrset);
			bits = MAX(bits, mother->s);
		}

		/*
		 * descriptors to check for writability aswell as
		 * controldescriptors to check for readability.
		 */
		FD_ZERO(&wset);
		FD_ZERO(&controlset);
		for (p = 0; p < rbits; ++p) {
			if (!FD_ISSET(p, &rset)) { /* only write after read. */
				FD_CLR(p, &xset);	/* don't care about xset without rset */
				continue;
			}

			io = io_finddescriptor(p);
			SASSERTX(io != NULL);

			if (io->in.s == p) {
				/* read from in requires out to be writable. */
				FD_SET(io->out.s, &wset);
				continue;
			}
			else if (io->out.s == p) {
				/* read from out requires in to be writable. */
				FD_SET(io->in.s, &wset);
				continue;
			}
			else {
				SASSERTX(io->control.s == p);
				/* doesn't need matching writable. */
				FD_SET(io->control.s, &newrset);
				FD_SET(io->control.s, &controlset);
				bits = MAX(bits, io->control.s);
			}
		}
		bits = MAX(bits, rbits);

		++bits;
		switch (selectn(bits, &newrset, &wset, NULL, io_gettimeout(&timeout))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
				if ((io = io_gettimedout()) != NULL)
					delete_io(mother->ack, io, -1, IO_TIMEOUT);
				/* else: should only be possible if sighup received. */
				continue;
		}

		checkmother(mother, &rset);

		tmpset = controlset;
		fdsetop(bits, '&', &newrset, &tmpset, &controlset);

		/*
		 * newrset; descriptors readable, all new apart from controldescriptors.
		 *				Don't do anything with them here, loop around and check for
		 *				writability first.
		 *
		 *	controlset; subset of newrset containing control descriptors
		 *					that are readable.
		 *
		 * rset; descriptors readable, not necessarily with a match in wset. 
		 *
		 * xset; subset of rset with exceptions pending.
		 *
		 * wset;	descriptors writable with a matching in rset/xset,
		 *			what we can do i/o over.
		 */

		/*
		 * First check all io's which have an exception pending. 
		 * Getting a io here does not mean we can do i/o over it
		 * however.
		 */
		while ((io = io_getset(&xset)) != NULL) {
			slog(LOG_DEBUG, "select(): exception set");

			doio(mother->ack, io, &xset, &wset, MSG_OOB);
			io_clearset(io, &xset);
			io_clearset(io, &wset);

			/* xset is subset of rset so clear rset too. */
			io_clearset(io, &rset);
		}

		/*
		 * Get all io's which are writable.  They will have a matching
		 * descriptor that is readable.
		 */
		while ((io = io_getset(&wset)) != NULL) {
			doio(mother->ack, io, &rset, &wset, 0);
			io_clearset(io, &rset);
			io_clearset(io, &wset);

			/* xset is subset of rset so clear xset too. */
			io_clearset(io, &xset);
		}

		/*
		 * Get all io's which have controldescriptors that are readable.
		 */
		while ((io = io_getset(&controlset)) != NULL) {
			fd_set nullset;

			FD_ZERO(&nullset);
			doio(mother->ack, io, &controlset, &nullset, 0);
			io_clearset(io, &controlset);

			/* controlset is subset of newrset so clear newrset too. */
			io_clearset(io, &newrset);
		}

		/* possible future optimization: if newrset not empty, use it? */
	}
}


static void
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
				case IO_SRCBLOCK:
					slog(LOG_INFO, "%s: delayed sourceblock", logmsg);
					break;

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
				case IO_SRCBLOCK:
					slog(LOG_INFO, "%s: delayed sourceblock", logmsg);
					break;

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
				case IO_SRCBLOCK:
					slog(LOG_INFO, "%s: delayed sourceblock", logmsg);
					break;

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

	/* this may end up logging same disconnect twice, but not our choice. */
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

	SASSERTX((FD_ISSET(io->in.s, rset) && FD_ISSET(io->out.s, wset))
	|| 		(FD_ISSET(io->in.s, wset) && FD_ISSET(io->out.s, rset))
	||			(flags & MSG_OOB)
	||			(io->control.s != -1 && FD_ISSET(io->control.s, rset)));

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

			/* ... and out to in. */
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
			socklen_t fromlen;
			int permit;

			/*
			 * UDP is sadly considerably more complex than TCP;
			 * need to check rules on each packet, need to check if it
			 * was received from expected src, etc.
			 */

			/* udp to relay from client to destination? */
			if (FD_ISSET(io->in.s, rset) && FD_ISSET(io->out.s, wset)) {
				const int lflags = flags & ~MSG_OOB;
				struct sockaddr from;

				fromlen = sizeof(from);
				if ((r = recvfrom(io->in.s, buf, io->out.sndlowat, lflags, &from,
				&fromlen)) == -1) {
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
					
					/* LINTED pointer casts may be troublesome */
					sockaddr2sockshost((struct sockaddr *)&io->in.raddr, &io->src);

					/*
					 * Do a rulecheck here with destination set to NULL, 
					 * if that isn't permitted nothing else is either from
					 * this source so disconnect it.
					 */
					if (!rulespermit(io->in.s, &io->rule, &io->state, &io->src,
					NULL)) {
						delete_io(mother, io, io->in.s, IO_SRCBLOCK);
						return;
					}
				}

				/*
				 * When we receive the first packet we also have a fixed
				 * source so connect the socket, both for better performance
				 * and so that getpeername() will work on it, for
				 * libwrap/rulespermit(). 
				 */
				if (io->in.read == 0) { /* could happend more than once, but ok. */
					/* LINTED pointer casts may be troublesome */
					if (!sockaddrareeq((struct sockaddr *)&io->in.raddr, &from)) {
						char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];

						slog(LOG_NOTICE,
						"%s(0): %s: expected from %s, got it from %s",
						VERDICT_BLOCKs, protocol2string(io->state.protocol),
						/* LINTED pointer casts may be troublesome */
						sockaddr2string((struct sockaddr *)&io->in.raddr, src,
						sizeof(src)), sockaddr2string(&from, dst, sizeof(dst)));
						break;
					}

					if (connect(io->in.s, &from, sizeof(from)) != 0) {
						delete_io(mother, io, io->in.s, IO_ERROR);
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
					break;
				}

				if (header.frag != 0) {
					char badfrom[MAXSOCKADDRSTRING];

					/* LINTED pointer casts may be troublesome */
					swarnx("%s: %s: fragmented packet from %s.  Not supported",
					function, protocol2string(io->state.protocol),
					sockaddr2string((struct sockaddr *)&io->in.raddr, badfrom,
					sizeof(badfrom)));
					break;
				}

				io->dst = header.host;

				/* is the packet to be permitted out? */
				permit
				= rulespermit(io->in.s, &io->rule, &io->state, &io->src, &io->dst);

				/* set r to bytes sent by client sans socks udp header. */
				r -= PACKETSIZE_UDP(&header);

				iolog(&io->rule, &io->state, OPERATION_IO, &io->src, &io->dst,
				&buf[PACKETSIZE_UDP(&header)], (size_t)r);

				if (!permit)
					break;

				/* LINTED pointer casts may be troublesome */
				sockshost2sockaddr(&header.host, (struct sockaddr *)&io->out.raddr);

				/* LINTED pointer casts may be troublesome */
				if ((w = sendto(io->out.s, &buf[PACKETSIZE_UDP(&header)],
				(size_t)r, lflags, (struct sockaddr *)&io->out.raddr,
				sizeof(io->out.raddr))) != r)
					iolog(&io->rule, &io->state, OPERATION_ERROR, &io->src, &io->dst,
					NULL, 0);
				io->out.written += MAX(0, w);
			}


			/*
			 * Datagram reply from remote present?
			 * We first peek at it so we can find out what address it's from,
			 * then we check rules and then we read the packet out of the buffer.
			 * Reason why we first peek is that if the rule calls libwrap,
			 * libwrap would hang since we'd already read the packet and it
			 * wants to peek itself.
			 * We only peek enough to get the source but this still involves
			 * an extra systemcall.  Can we find a better/faster way to do it?
			 */
			if (FD_ISSET(io->out.s, rset) && FD_ISSET(io->in.s, wset)) {
				const int lflags = flags & ~MSG_OOB;
				struct connectionstate_t state;
				struct sockaddr from;
				struct sockshost_t srcsh;
				char *newmsg;

				/* MSG_PEEK because of libwrap, see above. */
				fromlen = sizeof(from);
				if ((r = recvfrom(io->out.s, buf, 1, lflags | MSG_PEEK, &from,
				&fromlen)) == -1) {
					delete_io(mother, io, io->out.s, r);
					return;
				}
				UDPFROMLENCHECK(io->out.s, fromlen);

				/*
				 * We can get some problems here in the case that
				 * the client sends a hostname for destination.
				 * If it does it probably means it can't resolve and if
				 * we then send it a ipaddress as source, the client
				 * wont be able to match our source as it's destination,
				 * even if they are the same.
				 * We check for this case specifically, though we only catch
				 * the last case, which may not always be good enough.
				 * We could expand the below check, using addressmatch()
				 * instead, but that need not always be right, better safe
				 * than sorry for now.
				 */

				/* LINTED possible pointer alignment problem */
				if (io->dst.atype == SOCKS_ADDR_DOMAIN
				&& sockaddrareeq((struct sockaddr *)&io->out.raddr, &from))
					srcsh = io->dst;
				else
					sockaddr2sockshost(&from, &srcsh);

				/* only set temporary here for one replypacket at a time. */
				state 			= io->state;
				state.command	= SOCKS_UDPREPLY;

				permit
				= rulespermit(io->out.s, &io->rule, &state, &srcsh, &io->src);

				/* read the peeked packet out of the buffer. */
				fromlen = sizeof(from);
				if ((r = recvfrom(io->out.s, buf, io->in.sndlowat, lflags, &from,
				&fromlen)) == -1) {
					delete_io(mother, io, io->out.s, r);
					return;
				}
				io->out.read += r;

				iolog(&io->rule, &state, OPERATION_IO, &srcsh, &io->src, buf,
				(size_t)r);

				if (!permit)
					break;

				/* add socks udpheader.  */
				/* LINTED pointer casts may be troublesome */
				if ((newmsg = udpheader_add(&srcsh, buf, (size_t *)&r)) == NULL) {
					swarnx("%s: %s", function, NOMEM);
					break;
				}

				/*
				 * XXX socket must be connected but that should always be the
				 * case for now since binding udp addresses is not supported.
				 */
				if ((w = sendto(io->in.s, newmsg, (size_t)r, lflags, NULL, 0))
				!= r)
					iolog(&io->rule, &state, OPERATION_ERROR, &srcsh, &io->src,
					NULL, 0);
				free(newmsg);

				io->in.written += MAX(0, w);
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
			difftime(config.timeout.io, (time_t)difftime(timenow, iov[i].time))));

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
			if (difftime(timenow, iov[i].time) >= config.timeout.io)
				return &iov[i];

	return NULL;
}

static void
checkmother(mother, readset)
	struct sockd_mother_t *mother;
	fd_set *readset;
{

	if (mother->s != -1 && FD_ISSET(mother->s, readset)) {
		FD_CLR(mother->s, readset);

		if (recv_io(mother->s, NULL) != 0) {
			close(mother->s);
			close(mother->ack);
			mother->s = mother->ack = -1;
		}
		else
			proctitleupdate();
	}
}

/* ARGSUSED */
static void
siginfo(sig)
	int sig;
{
	int i;
	time_t timenow;

	time(&timenow);

	for (i = 0; i < ioc; ++i)
		if (!iov[i].allocated)
			continue;
		else {
			char srcstring[MAXSOCKSHOSTSTRING];
			char dststring[MAXSOCKSHOSTSTRING];

			slog(LOG_INFO, "%s <-> %s: idle %.0fs",
			sockshost2string(&iov[i].src, srcstring, sizeof(srcstring)),
			sockshost2string(&iov[i].dst, dststring, sizeof(dststring)),
			difftime(timenow, iov[i].time));
		}

}
