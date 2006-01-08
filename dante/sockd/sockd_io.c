/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004
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
 *  Gaustadalléen 21
 *  NO-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

#include "common.h"
#include "config_parse.h"

static const char rcsid[] =
"$Id: sockd_io.c,v 1.231 2005/12/25 17:18:08 michaels Exp $";

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
io_fillset __P((fd_set *set, int antiflags, const struct timeval *timenow));
/*
 * Sets all descriptors from our list, in "set".  If "antiflags"
 * is set, io's with any of the flags in "antiflags" set will be excluded.
 * IO's with state.fin set will also be excluded.
 * "timenow" is the time now.
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors we want to select() on currently.
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
			  int *bad, void *buf, size_t bufsize, int flags));
/*
 * Transfers data from "in" to "out" using flag "flags".
 * "inauth" is the authentication used for reading from "in",
 * "outauth" is the authentication * used when writing to out.
 * The data transfered uses "buf" as a buffer, which is of size "bufsize".
 * The function never transfers more than the receive low watermark
 * of "out".
 *
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
io_gettimeout __P((struct timeval *timeout, const struct timeval *timenow));
/*
 * If there is a timeout on the current clients for how long to exist
 * without doing i/o, this function fills in "timeout" with the appropriate
 * timeout.
 * Returns:
 *		If there is a timeout: pointer to filled in "timeout".
 *		If there is no timeout: NULL.
 */

static struct sockd_io_t *
io_gettimedout __P((const struct timeval *timenow));
/*
 * Scans all clients for one that has timed out according to sockscf
 * settings. "timenow" is the time now.
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

#define BWUPDATE(io, timenow, bwused) \
do { \
	if (bwused) { \
		io->time = timenow; \
\
		if (io->rule.bw != NULL) { \
			bw_update(io->rule.bw, bwused, &io->time); \
		} \
	} \
} while (lintnoloop_sockd_h)

/* timersub macro from OpenBSD */
#define timersub_hack(tvp, uvp, vvp)                                    \
	do {                                                            \
					(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
					(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
					if ((vvp)->tv_usec < 0) {                               \
								(vvp)->tv_sec--;                                \
								(vvp)->tv_usec += 1000000;                      \
					}                                                       \
			} while (0)


__END_DECLS


static struct sockd_io_t iov[SOCKD_IOMAX];	/* each child has these io's. */
static int ioc = ELEMENTS(iov);
static struct timeval bwoverflow;

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
		serr(EXIT_FAILURE, "%s: sigaction(SIGUSR1)", function);

	proctitleupdate();

	/* CONSTCOND */
	while (1) {
		int rbits, bits;
		fd_set rset, wset, xset, newrset, controlset, tmpset;
		struct sockd_io_t *io;
		struct timeval timeout, timenow;

		gettimeofday(&timenow, NULL);

		/* look for timed-out clients. */
		while ((io = io_gettimedout(&timenow)) != NULL)
			delete_io(mother->ack, io, -1, IO_TIMEOUT);

		/* starting a new run. */
		timerclear(&bwoverflow);

		io_fillset(&xset, MSG_OOB, &timenow);
		rbits = io_fillset(&rset, 0, &timenow);

		if (mother->s != -1) {
			FD_SET(mother->s, &rset);
			rbits = MAX(rbits, mother->s);
		}
		else /* no mother.  Do we have any other descriptors to work with? */
			if (rbits == -1) {
				SASSERTX(allocated() == 0);
				slog(LOG_DEBUG, "%s: can't find mother and no io's", function);
				sockdexit(-EXIT_FAILURE);
			}

		/*
		 * first find descriptors that are readable; we won't write if
		 * we can't read.  Also select for exceptions so we can tell
		 * the i/o function if there's one pending later.
		 */
		++rbits;
		switch (selectn(rbits, &rset, NULL, &xset,
		io_gettimeout(&timeout, &timenow))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
				continue;
		}

		checkmother(mother, &rset);

		/*
		 * This is tricky, but we need to check for write separately to
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
		 * Another problem is that if while we wait for writability, a new
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

		gettimeofday(&timenow, NULL);

		/* descriptors to check for readability; those not already set. */
		bits = io_fillset(&tmpset, 0, &timenow);
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

			if (io->src.s == p) {
				/* read from in requires out to be writable. */
				FD_SET(io->dst.s, &wset);
				bits = MAX(bits, io->dst.s);
			}
			else if (io->dst.s == p) {
				/* read from out requires in to be writable. */
				FD_SET(io->src.s, &wset);
				bits = MAX(bits, io->src.s);
			}
			else {
				SASSERTX(io->control.s == p);
				FD_SET(io->control.s, &controlset);
				/* also readable without matching writable. */
				FD_SET(io->control.s, &newrset);

				bits = MAX(bits, io->control.s);
			}
		}

		if (bits++ < 0) {
			SASSERTX(allocated() == 0
			&& mother->s == mother->ack && mother->s < 0);
			continue;
		}

		switch (selectn(bits, &newrset, &wset, NULL,
		io_gettimeout(&timeout, &timenow))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
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
	struct rule_t *rulev[2];
	size_t i;

	SASSERTX(io->allocated);

	if (io->state.protocol == SOCKS_TCP) { /* udp rules are temporary. */
		/* request handled. */
		bw_unuse(io->rule.bw);
		session_unuse(io->rule.ss);
	}

	/* log the disconnect if client-rule or socks-rule says so. */
	rulev[0] = &io->crule;
	rulev[1] = &io->rule;
	for (i = 0; i < ELEMENTS(rulev); ++i) {
		/* LINTED constant in conditional context */
		char in[MAXSOCKADDRSTRING + MAXAUTHINFOLEN];
		char out[sizeof(in)];
		char logmsg[sizeof(in) + sizeof(out) + 1024];
		int p;
		const struct rule_t *rule = rulev[i];

		if (!rule->log.disconnect)
			continue;

		if (rule == &io->crule) { /* client-rule */
			authinfo(&io->control.auth, in, sizeof(in)); p = strlen(in);
			/* LINTED pointer casts may be troublesome */
			sockaddr2string(&io->control.raddr, &in[p], sizeof(in) - p);

			authinfo(&io->control.auth, out, sizeof(out));
			p = strlen(out);

			sockaddr2string(&io->control.laddr, &out[p], sizeof(out) - p);
		}
		else if (rule == &io->rule) { /* socks rule. */
			authinfo(&io->src.auth, in, sizeof(in)); p = strlen(in);
			/* LINTED pointer casts may be troublesome */
			sockaddr2string(&io->src.raddr, &in[p], sizeof(in) - p);

			authinfo(&io->dst.auth, out, sizeof(out));
			p = strlen(out);

			switch (io->state.command) {
				case SOCKS_BIND:
				case SOCKS_BINDREPLY:
					/* LINTED pointer casts may be troublesome */
					sockaddr2string(&io->dst.raddr, &out[p], sizeof(out) - p);
					break;

				case SOCKS_CONNECT:
					/* LINTED pointer casts may be troublesome */
					sockshost2string(&io->dst.host, &out[p], sizeof(out) - p);
					break;

				case SOCKS_UDPASSOCIATE:
					snprintfn(&out[p], sizeof(out) - p, "`world'");
					break;

				default:
					SERRX(io->state.command);
			}
		}
		else
			SERRX(0);


		snprintfn(logmsg, sizeof(logmsg),
		"%s(%d): %s/%s ]: %lu -> %s -> %lu,  %lu -> %s -> %lu",
		rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
		rule->number,
		protocol2string(io->state.protocol), command2string(io->state.command),
		(unsigned long)io->src.written, in, (unsigned long)io->src.read,
		(unsigned long)io->dst.written, out, (unsigned long)io->dst.read);

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
		else if (fd == io->src.s || fd == io->control.s) {
			switch (status) {
				case IO_SRCBLOCK:
					slog(LOG_INFO, "%s: delayed sourceblock", logmsg);
					break;

				case IO_ERROR: {
					struct linger linger;

					swarn("%s: client error", logmsg);

					/* send rst to other end. */
					linger.l_onoff 	= 1;
					linger.l_linger 	= 0;
					if (setsockopt(io->dst.s, SOL_SOCKET, SO_LINGER, &linger,
					sizeof(linger)) != 0)
						swarn("%s: setsockopt(io->dst, SO_LINGER)", function);

					break;
				}
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
		else if (fd == io->dst.s) {
			switch (status) {
				case IO_SRCBLOCK:
					slog(LOG_INFO, "%s: delayed sourceblock", logmsg);
					break;

				case IO_ERROR: {
					struct linger linger;

					swarn("%s: remote error", logmsg);

					/* send rst to other end. */
					linger.l_onoff 	= 1;
					linger.l_linger 	= 0;
					if (setsockopt(io->src.s, SOL_SOCKET, SO_LINGER, &linger,
					sizeof(linger)) != 0)
						swarn("%s: setsockopt(io->dst, SO_LINGER)", function);
					break;
				}

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

	close_iodescriptors(io);

	io->allocated = 0;

	if (mother != -1) {
		const char b = SOCKD_FREESLOT;

		/* ack io slot free. */
		if (writen(mother, &b, sizeof(b), NULL) != sizeof(b))
			 swarn("%s: writen(): mother", function);
	}

	proctitleupdate();
}


void
close_iodescriptors(io)
	const struct sockd_io_t *io;
{

	close(io->src.s);
	close(io->dst.s);

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
	CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);

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

	/* LINTED pointer casts may be troublesome */
	CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

	if ((i = recvmsg(s, &msg, 0)) != (ssize_t)length) {
		if (i == 0)
			slog(LOG_DEBUG, "%s: recvmsg(): mother closed connection", function);
		else
			swarn("%s: recvmsg()", function);
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
	SASSERT(CMSG_TOTLEN(msg) == CMSG_SPACE(sizeof(int) * fdexpect));
#endif

	/*
	 * Get descriptors sent us.
	 */

	fdreceived = 0;

	/* LINTED pointer casts may be troublesome */
	CMSG_GETOBJECT(io->src.s, cmsg, sizeof(io->src.s) * fdreceived++);
	/* LINTED pointer casts may be troublesome */
	CMSG_GETOBJECT(io->dst.s, cmsg, sizeof(io->dst.s) * fdreceived++);

	switch (io->state.command) {
		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (io->state.extension.bind)
				/* LINTED pointer casts may be troublesome */
				CMSG_GETOBJECT(io->control.s, cmsg,
				sizeof(io->control.s) * fdreceived++);
			else
				io->control.s = -1;
			break;

		case SOCKS_CONNECT:
			io->control.s = -1;
			break;

		case SOCKS_UDPASSOCIATE:
			/* LINTED pointer casts may be troublesome */
			CMSG_GETOBJECT(io->control.s, cmsg,
			sizeof(io->control.s) * fdreceived++);
			break;

		default:
			SERRX(io->state.command);
	}

	gettimeofday(&io->time, NULL);
	io->allocated = 1;

#if HARDCORE_DEBUG
	printfd(io, "received");
#endif

	return 0;
}


static void
io_clearset(io, set)
	const struct sockd_io_t *io;
	fd_set *set;
{

	FD_CLR(io->src.s, set);
	FD_CLR(io->dst.s, set);

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
	char buf[MAX(SOCKD_BUFSIZETCP, SOCKD_BUFSIZEUDP)
	+ sizeof(struct udpheader_t)];
	ssize_t r, w;
	struct timeval timenow;


	SASSERTX(io->allocated);

	SASSERTX((FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset))
	||			(FD_ISSET(io->src.s, wset) && FD_ISSET(io->dst.s, rset))
	||			(flags & MSG_OOB)
	||			(io->control.s != -1 && FD_ISSET(io->control.s, rset)));

	/*
	 * we are only called when we have i/o to do.
	 * Could probably remove this gettimeofday() call to, but there are
	 * platforms without SO_SNDLOWAT which prevents us.
	 */
	gettimeofday(&timenow, NULL);

	switch (io->state.protocol) {
		case SOCKS_TCP: {
			int bad;
			size_t bufsize, bwused;

			if (io->rule.bw != NULL) {
				ssize_t left;

				if ((left = bw_left(io->rule.bw)) <= 0) {
					/*
					 * update data (new time) so next bw_left() presumably
					 * has some left.
					 * No harm in calling bw_update() without le 0 check, but
					 * maybe this is smarter (avoids extra lock in gt 0 case).
					 */
					bw_update(io->rule.bw, 0, &timenow);
					left = bw_left(io->rule.bw);
				}

				if ((bufsize = MIN(sizeof(buf), (size_t)left)) == 0)
					break;
			}
			else
				bufsize = sizeof(buf);


			bwused = 0;

			/* from in to out ... */
			if (FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset)) {
				bad = -1;
				r = io_rw(&io->src, &io->dst, &bad, buf, bufsize, flags);
				if (bad != -1) {
					delete_io(mother, io, bad, r);
					return;
				}

				iolog(&io->rule, &io->state, OPERATION_IO, &io->src.host,
				&io->src.auth, &io->dst.host, &io->dst.auth, buf, (size_t)r);

				bwused += r;
			}

			/* ... and out to in. */
#if 0
			/*
			 * This doesn't work too good since we can end up doing i/o
			 * only in -> out for a long time.  Also since we assume one
			 * side is on the lan (where b/w isn't that critical)
			 * and the other side is the net, assume some slack on
			 * one side is ok.  Same applies to udp case.
			 * Another option would be to alternate which direction we
			 * do i/o on first each time, but we instead do the simple
			 * thing and just don't subtract bufsize.
			 */
			bufsize -= bwused;
#endif

			if (bufsize == 0) {
				BWUPDATE(io, timenow, bwused);
				break;
			}

			if (FD_ISSET(io->dst.s, rset) && FD_ISSET(io->src.s, wset)) {
				bad = -1;
				r = io_rw(&io->dst, &io->src, &bad, buf, bufsize, flags);
				if (bad != -1) {
					delete_io(mother, io, bad, r);
					return;
				}

				iolog(&io->rule, &io->state, OPERATION_IO, &io->dst.host,
				&io->dst.auth, &io->src.host, &io->src.auth, buf, (size_t)r);

				bwused += r;
			}

			BWUPDATE(io, timenow, bwused);
			break;
		}

		case SOCKS_UDP: {
			struct udpheader_t header;
			socklen_t fromlen;
			int permit;

			/*
			 * UDP is sadly considerably more complex than TCP;
			 * need to check rules on each packet, need to check if it
			 * was received from expected in.host, etc.
			 */

			/*
			 * We are less strict about bandwidth in the udp case since we don't
			 * want to truncate packets.
			 */

			/* UDP to relay from client to destination? */
			if (FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset)) {
				const int lflags = flags & ~MSG_OOB;
				struct sockaddr from;
				size_t bwused;

				fromlen = sizeof(from);
				if ((r = socks_recvfrom(io->src.s, buf, io->dst.sndlowat, lflags,
				&from, &fromlen, &io->src.auth)) == -1) {
					delete_io(mother, io, io->src.s, r);
					return;
				}
				UDPFROMLENCHECK(io->src.s, fromlen);

				/*
				 * If client hasn't sent us it's address yet we have to
				 * assume the first packet is from it.
				 * Client can only blame itself if not.
				 */

				/* LINTED pointer casts may be troublesome */
				if (TOIN(&io->src.raddr)->sin_addr.s_addr == htonl(INADDR_ANY)
				||  TOIN(&io->src.raddr)->sin_port == htons(0)) {
					/* LINTED pointer casts may be troublesome */
					if (TOIN(&io->src.raddr)->sin_addr.s_addr == htonl(INADDR_ANY))
					/* LINTED pointer casts may be troublesome */
						TOIN(&io->src.raddr)->sin_addr.s_addr
						= TOIN(&from)->sin_addr.s_addr;

					/* LINTED pointer casts may be troublesome */
					if (TOIN(&io->src.raddr)->sin_port == htons(0))
						/* LINTED pointer casts may be troublesome */
						TOIN(&io->src.raddr)->sin_port = TOIN(&from)->sin_port;

					sockaddr2sockshost(&io->src.raddr, &io->src.host);
				}

				/*
				 * When we receive the first packet we also have a fixed source
				 * so connect the socket, both for better performance and so
				 * that getpeername() will work on it (libwrap in rulespermit()).
				 */
				if (io->src.read == 0) { /* could happen more than once, but ok. */
					struct connectionstate_t rstate;

					if (!sockaddrareeq(&io->src.raddr, &from)) {
						char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];

						/* perhaps this should be LOG_DEBUG. */
						slog(LOG_INFO,
						"%s(0): %s: expected from %s, got it from %s",
						VERDICT_BLOCKs, protocol2string(io->state.protocol),
						sockaddr2string(&io->src.raddr, src, sizeof(src)),
						sockaddr2string(&from, dst, sizeof(dst)));
						break;
					}

					if (connect(io->src.s, &from, sizeof(from)) != 0) {
						delete_io(mother, io, io->src.s, IO_ERROR);
						return;
					}

					rstate			= io->state;
					rstate.command	= SOCKS_UDPREPLY;

					if (!rulespermit(io->src.s, &io->control.raddr,
					&io->control.laddr, &io->rule, &io->state, &io->src.host,
					NULL, NULL, 0)
					&&  !rulespermit(io->src.s, &io->control.raddr,
					&io->control.laddr, &io->rule, &rstate, NULL, &io->src.host,
					NULL, 0)) {
						/* can't send, can't receive; drop it. */
						delete_io(mother, io, io->src.s, IO_SRCBLOCK);
						return;
					}
				}
				io->src.read += r;

				/* got packet, pull out socks UDP header. */
				if (string2udpheader(buf, (size_t)r, &header) == NULL) {
					char badfrom[MAXSOCKADDRSTRING];

					/* LINTED pointer casts may be troublesome */
					swarnx("%s: bad socks udppacket (length = %d) from %s",
					function, r, sockaddr2string(&io->src.raddr, badfrom,
					sizeof(badfrom)));
					break;
				}

				if (header.frag != 0) {
					char badfrom[MAXSOCKADDRSTRING];

					/* LINTED pointer casts may be troublesome */
					swarnx("%s: %s: fragmented packet from %s.  Not supported",
					function, protocol2string(io->state.protocol),
					sockaddr2string(&io->src.raddr, badfrom, sizeof(badfrom)));
					break;
				}

				io->dst.host = header.host;

				if (sockscf.bwlock != -1)
					socks_lock(sockscf.bwlock, F_WRLCK, -1);

				/* is the packet to be permitted out? */
				permit = rulespermit(io->src.s, &io->control.raddr,
				&io->control.laddr, &io->rule, &io->state, &io->src.host,
				&io->dst.host, NULL, 0);

				if (io->rule.bw != NULL)
					bw_use(io->rule.bw);

				if (sockscf.bwlock != -1)
					socks_unlock(sockscf.bwlock);

				/* set r to bytes sent by client sans socks UDP header. */
				r -= PACKETSIZE_UDP(&header);

				iolog(&io->rule, &io->state, OPERATION_IO, &io->src.host,
				&io->src.auth, &io->dst.host, &io->dst.auth,
				&buf[PACKETSIZE_UDP(&header)], (size_t)r);

				if (!permit) {
					bw_unuse(io->rule.bw);
					break;
				}

				if (redirect(io->dst.s, &io->dst.laddr, &io->dst.host,
				io->state.command, &io->rule.rdr_from, &io->rule.rdr_to) != 0) {
					swarn("%s: redirect()", function);
					bw_unuse(io->rule.bw);
					break;
				}

				/* LINTED pointer casts may be troublesome */
				sockshost2sockaddr(&io->dst.host, &io->dst.raddr);

				/* LINTED pointer casts may be troublesome */
				if ((w = socks_sendto(io->dst.s, &buf[PACKETSIZE_UDP(&header)],
				(size_t)r, lflags, &io->dst.raddr, sizeof(io->dst.raddr),
				&io->dst.auth)) != r)
					iolog(&io->rule, &io->state, OPERATION_ERROR, &io->src.host,
					&io->src.auth, &io->dst.host, &io->dst.auth, NULL, 0);

				io->dst.written += MAX(0, w);
				bwused = MAX(0, w);
				BWUPDATE(io, timenow, bwused);
				/* for the lack of anything better, see bw_update(). */
				bw_unuse(io->rule.bw);
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

#if 0 /* see comment for tcp case. */
			if (bwused >= io->rule.bw->maxbps)
				break;
#endif

			if (FD_ISSET(io->dst.s, rset) && FD_ISSET(io->src.s, wset)) {
				const int lflags = flags & ~MSG_OOB;
				struct connectionstate_t state;
				struct sockaddr rfrom;
				struct sockshost_t rfromhost, replyto;
				char *newbuf;
				size_t bwused;
				int s = io->src.s;

				/* MSG_PEEK because of libwrap, see above. */
				fromlen = sizeof(rfrom);
				if ((r = socks_recvfrom(io->dst.s, buf, 1, lflags | MSG_PEEK,
				&rfrom, &fromlen, &io->dst.auth)) == -1) {
					delete_io(mother, io, io->dst.s, r);
					return;
				}
				UDPFROMLENCHECK(io->dst.s, fromlen);

				/*
				 * We can get some problems here in the case that
				 * the client sends a hostname for destination.
				 * If it does it probably means it can't resolve and if
				 * we then send it a IP address as source, the client
				 * wont be able to match our source as it's destination,
				 * even if they are the same.
				 * We check for this case specifically, though we only catch
				 * the last case, which may not always be good enough.
				 * We could expand the below check, using addressmatch()
				 * instead, but that need not always be right.
				 * Better safe than sorry for now.
				 */

				/* LINTED possible pointer alignment problem */
				if (io->dst.host.atype == SOCKS_ADDR_DOMAIN
				&& sockaddrareeq(&io->dst.raddr, &rfrom))
					rfromhost = io->dst.host;
				else
					sockaddr2sockshost(&rfrom, &rfromhost);

				/* only set temporary here for one replypacket at a time. */
				state				= io->state;
				state.command	= SOCKS_UDPREPLY;

				permit = rulespermit(io->dst.s, &io->control.raddr,
				&io->control.laddr, &io->rule, &state, &rfromhost,
				&io->src.host, NULL, 0);

				if (io->rule.bw != NULL)
					bw_use(io->rule.bw);

				io->dst.auth = io->state.auth;

				/* read the peeked packet out of the buffer. */
				fromlen = sizeof(rfrom);
				if ((r = socks_recvfrom(io->dst.s, buf, io->src.sndlowat, lflags,
				&rfrom, &fromlen, &io->dst.auth)) == -1) {
					bw_unuse(io->rule.bw);
					delete_io(mother, io, io->dst.s, r);
					return;
				}
				io->dst.read += r;
				bwused = r;

				iolog(&io->rule, &state, OPERATION_IO, &rfromhost,
				&io->dst.auth, &io->src.host, &io->src.auth, buf, (size_t)r);

				if (!permit) {
					bw_unuse(io->rule.bw);
					break;
				}

				replyto = io->src.host;
				if (redirect(io->src.s, &rfrom, &replyto,
				state.command, &io->rule.rdr_from, &io->rule.rdr_to) != 0) {
					swarn("%s: redirect()", function);
					bw_unuse(io->rule.bw);
					break;
				}

				if (!sockshostareeq(&replyto, &io->src.host)) {
					/* need to redirect reply. */
					if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
						swarn("%s: socket()", function);
						bw_unuse(io->rule.bw);
						break;
					}

					if (socks_connect(s, &replyto) != 0) {
						swarn("%s: socks_connect()", function);
						bw_unuse(io->rule.bw);
						break;
					}
				}

				/* in case redirect() changed it . */
				sockaddr2sockshost(&rfrom, &rfromhost);

				/* add socks UDP header.  */
				/* LINTED pointer casts may be troublesome */
				newbuf = udpheader_add(&rfromhost, buf, (size_t *)&r, sizeof(buf));
				SASSERTX(newbuf == buf);

				/*
				 * XXX socket must be connected but that should always be the
				 * case for now since binding UDP addresses is not supported.
				 */
				if ((w = socks_sendto(s, newbuf, (size_t)r, lflags, NULL, 0,
				&io->src.auth)) != r)
					iolog(&io->rule, &state, OPERATION_ERROR, &rfromhost,
					&io->dst.auth, &io->src.host, &io->src.auth, NULL, 0);
				io->src.written += MAX(0, w);

				if (s != io->src.s) /* socket temporarily created for redirect. */
					close(s);

				BWUPDATE(io, timenow, bwused);
				/* for the lack of anything better, see bw_update(). */
				bw_unuse(io->rule.bw);
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
			sockaddr2string(&io->control.raddr, hmmread, sizeof(hmmread)), r,
			strcheck(unexpected = str2vis(buf, r)));

			free(unexpected);
		}
	}

}

static int
io_rw(in, out, bad, buf, bufsize, flag)
	struct sockd_io_direction_t *in;
	struct sockd_io_direction_t *out;
	int *bad;
	void *buf;
	size_t bufsize;
	int flag;
{
	const char *function = "io_rw()";
	ssize_t r, w;
	size_t len;

	if (flag & MSG_OOB)
		if (sockatmark(in->s) != 1)
			flag &= ~MSG_OOB;

	/* we receive oob inline. */
	len = MIN(bufsize, flag & MSG_OOB ? 1 : out->sndlowat);

	/* read data from in ... */
	if ((r = socks_recvfrom(in->s, buf, len, flag & ~MSG_OOB, NULL, NULL,
	&in->auth)) <= 0) {
		if (r == 0) {
			/*
			 * FIN from "in".  It won't send us any more data, so
			 * we shutdown "out" for writting to let it know.
			 * When "out" has nothing more to send, it will
			 * send an FIN too, and we will shutdown "in" for writting.
			 * At that point, both "in" and "out" has sent an FIN,
			 * meaning, none of them will send us any more data.
			 * Only then can we close the socket.  Since we may
			 * clear state.fin however, state.shutdown should be used
			 * for testing here.
			 */
			in->state.fin = 1;

			if (in->state.shutdown_wr) /* means we have received FIN from out. */
				*bad = out->s; /* done with this socket, "out" closed first. */

			if (!out->state.shutdown_wr) /* use shutdown() to forward FIN. */
				if (shutdown(out->s, SHUT_WR) != 0) /* but continue reading. */
					swarn("%s: shutdown()", function);
				else
					out->state.shutdown_wr = 1;
		}
		else
			*bad = in->s;

		return r;
	}
	in->read += r;


	slog(LOG_DEBUG, "%s: bufsize = %ld, r = %ld",
	function, (long)bufsize, (long)r);

	if (flag & MSG_OOB)
		in->flags |= MSG_OOB;	/* read oob data.				*/
	else
		in->flags &= ~MSG_OOB;	/* did not read oob data.	*/

	/* ... and send the data read to out. */
	if ((w = socks_sendto(out->s, buf, (size_t)r, flag, NULL, 0, &out->auth))
	!= r) {
		*bad = out->s;
		return w;
	}
	out->written += w;
	/*
	 * we want to select for read again on socket we sent data out on,
	 * regardless of whether we have received a FIN from it, to get
	 * write errors.  
	 * XXX
	 * Unfortunatly, there's no way to make select() not keep
	 * returning ready-for-read once the client has sent the FIN, 
	 * and we do not want to busy-loop around this.  What we would want
	 * to, is to only select for error on the socket after we receive
	 * a FIN.
	 * Best we can do is to let io_fillset() skip sockets that
	 * have state.fin set, and reset state.fin if we send data on on the
	 * socket, hoping to catch any pending errors on second go round.
	 * This means some sessions can occupy space for a long time, until
	 * tcp keep-alive check kicks in.
	 */
	out->state.fin = 0;

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
	struct sockd_io_t *best, *evaluating;

	for (i = 0, best = evaluating = NULL; i < ioc; ++i)
		if (iov[i].allocated) {
			if (FD_ISSET(iov[i].src.s, set))
					evaluating = &iov[i];

			if (FD_ISSET(iov[i].dst.s, set))
				evaluating = &iov[i];

			switch (iov[i].state.command) {
				case SOCKS_BIND:
				case SOCKS_BINDREPLY:
					if (!iov[i].state.extension.bind)
						break;
					/* else: */ /* FALLTHROUGH */

				case SOCKS_UDPASSOCIATE:
					if (FD_ISSET(iov[i].control.s, set))
						evaluating = &iov[i];
					break;

				default:
					break;
			}

			/* select the i/o that has least recently done i/o. */
			if (best == NULL || timercmp(&evaluating->time, &best->time, <))
				best = evaluating;
		}

	return best;
}


static struct sockd_io_t *
io_finddescriptor(d)
	int d;
{
	int i;

	for (i = 0; i < ioc; ++i)
		if (iov[i].allocated) {
			if (d == iov[i].src.s ||	 d == iov[i].dst.s)
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
io_fillset(set, antiflags, timenow)
	fd_set *set;
	int antiflags;
	const struct timeval *timenow;
{
	const char *function = "io_fillset()";
	int i, max;

	FD_ZERO(set);

	for (i = 0, max = -1; i < ioc; ++i) {
		struct sockd_io_t *io = &iov[i];

		if (io->allocated) {
			if (io->rule.bw != NULL) {
				struct timeval new_bwoverflow;

				if (bw_isoverflow(io->rule.bw, timenow, &new_bwoverflow) != NULL) {
					if (!timerisset(&bwoverflow)
					|| timercmp(&new_bwoverflow, &bwoverflow, <))
						bwoverflow = new_bwoverflow;

					/*
					 * XXX this also means we won't catch errors on this
					 * client for the duration.  Hopefully not a problem.
					 */
					continue;
				}
			}

			if (!io->src.state.fin && !(antiflags & io->src.flags)) {
				FD_SET(io->src.s, set);
				max = MAX(max, io->src.s);
			}

			if (!io->dst.state.fin && !(antiflags & io->dst.flags)) {
				FD_SET(io->dst.s, set);
				max = MAX(max, io->dst.s);
			}

			switch (io->state.command) {
				case SOCKS_BIND:
				case SOCKS_BINDREPLY:
					if (!io->state.extension.bind)
						break;
					/* else: */ /* FALLTHROUGH */

				case SOCKS_UDPASSOCIATE:
					if (! (antiflags & io->control.flags)) {
						FD_SET(io->control.s, set);
						max = MAX(max, io->control.s);
					}
					break;

				default:
					break;
			}
		}
	}

	return max;
}

static struct timeval *
io_gettimeout(timeout, timenow)
	struct timeval *timeout;
	const struct timeval *timenow;
{
/*	const char *function = "io_gettimeout()"; */
	int i;

	if (allocated() == 0)
		return NULL;

	if (sockscf.timeout.io == 0 && !timerisset(&bwoverflow))
		return NULL;

	timeout->tv_sec	= sockscf.timeout.io;
	timeout->tv_usec	= 0;

	if (timerisset(timeout)) /* iotimeout set. */ 
		for (i = 0; i < ioc; ++i)
			if (!iov[i].allocated)
				continue;
			else
				timeout->tv_sec = MAX(0, MIN(timeout->tv_sec,
				difftime(sockscf.timeout.io,
				(time_t)difftime((time_t)timenow->tv_sec,
				(time_t)iov[i].time.tv_sec))));

	if (timerisset(&bwoverflow)) {
		struct timeval timetobw;

		if (timercmp(timenow, &bwoverflow, >)) /* waited long enough. */
			timerclear(&timetobw);
		else
			/* CONSTCOND */ /* macro operation. */ /* still have some to wait. */
			timersub_hack(&bwoverflow, timenow, &timetobw);

		if (!timerisset(timeout) || timercmp(&timetobw, timeout, <)) {
			*timeout = timetobw;
		}
	}

#if 0
slog(LOG_DEBUG, "%s: timeout = %d.%d",
function, timeout->tv_sec, timeout->tv_usec);
#endif

	return timeout;
}

static struct sockd_io_t *
io_gettimedout(timenow)
	const struct timeval *timenow;
{
	int i;

	if (sockscf.timeout.io == 0)
		return NULL;

	for (i = 0; i < ioc; ++i)
		if (!iov[i].allocated)
			continue;
		else
			if (difftime((time_t)timenow->tv_sec, (time_t)iov[i].time.tv_sec)
			>= sockscf.timeout.io)
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
			sockshost2string(&iov[i].src.host, srcstring, sizeof(srcstring)),
			sockshost2string(&iov[i].dst.host, dststring, sizeof(dststring)),
			difftime(timenow, (time_t)iov[i].time.tv_sec));
		}

}
