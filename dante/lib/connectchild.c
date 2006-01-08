/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003
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

static const char rcsid[] =
"$Id: connectchild.c,v 1.119 2005/12/24 16:44:57 michaels Exp $";

#define MOTHER 0	/* descriptor mother reads/writes on.  */
#define CHILD	1	/* descriptor child reads/writes on.   */

__BEGIN_DECLS

static void
sigchld __P((int sig));

static void
run_connectchild __P((int mother));

__END_DECLS

/*
 * if caller already has a signal handler for SIGCHLD, save it
 * so we can call it from our own handler if something else than our
 * own child dies, for compatibility with caller.
 */
static struct sigaction oldsig;

#ifdef FDPASS_MAX
#undef FDPASS_MAX
#endif
#define FDPASS_MAX 2 /* one for socks, one more if msproxy (separate control) */

struct route_t *
socks_nbconnectroute(s, control, packet, src, dst)
	int s;
	int control;
	struct socks_t *packet;
	const struct sockshost_t *src, *dst;
{
	const char *function = "socks_nbconnectroute()";
	struct sigaction currentsig;
	struct socksfd_t socksfd;
	struct childpacket_t childreq;
	struct iovec iov[1];
	struct sockaddr_in local;
	socklen_t len;
	ssize_t p, fdsent;
	struct msghdr msg;
	CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);


	slog(LOG_DEBUG, "%s: s = %d", function, s);

	if (socks_getroute(&packet->req, src, dst) == NULL)
		return NULL;

	if (sigaction(SIGCHLD, NULL, &currentsig) != 0) {
		swarn("%s: sigaction(SIGCHLD)", function);
		return NULL;
	}

	if (currentsig.sa_handler != sigchld) {
		/*
		 * Our signalhandler is not installed, install it.
		 */
		struct sigaction oursig;

		oldsig = currentsig;

		/*
		 * This is far from 100% but...
		 */

		if (oldsig.sa_flags != 0)
			swarnx("%s: sigchld sa_flags not handled currently,\n"
					 "contact Inferno Nettverk A/S for more information", function);

		if (oldsig.sa_handler == SIG_DFL
		||	 oldsig.sa_handler == SIG_IGN)
			oldsig.sa_handler = NULL;

		if (oldsig.sa_handler == NULL) {
			/* no signal handler, free to do what we want. */
			sigemptyset(&oursig.sa_mask);
			oursig.sa_flags = SA_RESTART;
		}
		else
			/* duplicate old handler as much as possible */
			oursig = oldsig;

		oursig.sa_handler = sigchld;
		if (sigaction(SIGCHLD, &oursig, NULL) != 0) {
			swarn("%s: sigaction(SIGCHLD)", function);
			return NULL;
		}
	}

	if (sockscf.connectchild == 0) {
		/*
		 * Create child process that will do our connections.
		 */
		int pipev[2];

		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pipev) != 0) {
			swarn("%s: socketpair(AF_LOCAL, SOCK_STREAM)", function);
			return NULL;
		}

		switch (sockscf.connectchild = fork()) {
			case -1:
				swarn("%s: fork()", function);
				return NULL;

			case 0: {
				struct itimerval timerval;
				int i, max;

				slog(LOG_DEBUG, "%s: connectchild forked", function);

				/* close unknown descriptors. */
				for (i = 0, max = getdtablesize(); i < max; ++i)
					if (socks_logmatch((unsigned int)i, &sockscf.log)
					|| i == pipev[CHILD])
						continue;
					else if (isatty(i))
						continue;
					else
						close(i);

				newprocinit();

				/*
				 * in case of using msproxy stuff, don't want mothers mess,
				 * disable alarmtimers.
				 */

				if (signal(SIGALRM, SIG_DFL) == SIG_ERR)
					swarn("%s: signal()", function);

				timerval.it_value.tv_sec	= 0;
				timerval.it_value.tv_usec	= 0;
				timerval.it_interval = timerval.it_value;

				if (setitimer(ITIMER_REAL, &timerval, NULL) != 0)
					swarn("%s: setitimer()", function);

				run_connectchild(pipev[CHILD]);
				/* NOTREACHED */
			}

			default:
				sockscf.connect_s = pipev[MOTHER];
				close(pipev[CHILD]);
		}
	}

	switch (packet->req.version) {
		case SOCKS_V4:
		case SOCKS_V5:
		case HTTP_V1_0: {
			/*
			 * Controlsocket is what later becomes datasocket.
			 * We don't want to allow the client to read/write/select etc.
			 * on the socket yet, since we need to read/write on it
			 * ourselves to setup the connection to the socksserver.
			 *
			 * We therefore create a new unconnected socket and assign
			 * it the same descriptor number as the number the client uses.
			 * This way, the clients select(2)/poll(2) will not
			 * mark the descriptor as ready for anything untill we 
			 * are working.
			 *
			 * When the connection has been set up we duplicate back the
			 * socket we were passed here and close the temporarily created
			 * socket.
			 */
			int tmp;
			struct sockaddr_in addr;

			SASSERTX(control == s);
			if ((control = socketoptdup(s)) == -1)
				return NULL;

			/* 
			 * The below bind(2) and listen(2) is neccessary for
			 * Linux not to mark the socket as readable/writable.
			 * Under other unix systems, just a socket() is 
			 * enough.  Judging from the Open Unix spec., Linux
			 * is the one that is correct though.
			 */

			bzero(&addr, sizeof(addr));
			addr.sin_family 		= AF_INET;
			addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
			addr.sin_port 			= htons(0);

			/* LINTED pointer casts may be troublesome */
			if (bind(control, (struct sockaddr *)&addr, sizeof(addr)) != 0
			||  listen(control, 1) != 0) {
				close(control);
				return NULL;
			}
			
			if ((tmp = dup(s)) == -1) {
				close(control);
				return NULL;
			}

			if (dup2(control, s) == -1) {
				close(control);
				return NULL;
			}
			close(control);

			control = tmp;

			/*
			 * s: new (temporary) socket using original index of "s".
			 * control: original "s" socket, but using new descriptor index.
			 */
			break;
		}

		case MSPROXY_V2:
			/*
			 * Controlsocket is separate from datasocket.
			 * Identical to our fixed sockssetup.
			 */
			break;

		default:
			SERRX(packet->req.version);
	}

	bzero(&socksfd, sizeof(socksfd));
	if ((socksfd.route = socks_connectroute(control, packet, src, dst)) == NULL)
		return NULL;

	/*
	 * datasocket probably unbound.  If so we need to bind it so
	 * we can get a (hopefully) unique local address for it.
	 */

	len = sizeof(local);
	/* LINTED pointer casts may be troublesome */
	if (getsockname(s, (struct sockaddr *)&local, &len) != 0)
		return NULL;

	if (!ADDRISBOUND(local)) {
		bzero(&local, sizeof(local));

		/* bind same IP as control, any fixed address would do though. */

		len = sizeof(local);
		/* LINTED pointer casts may be troublesome */
		if (getsockname(control, (struct sockaddr *)&local, &len) != 0) {
			int new_control;

			socks_badroute(socksfd.route);

			if ((new_control = socketoptdup(control)) == -1)
				return NULL;

			switch (packet->req.version) {
				case SOCKS_V4:
				case SOCKS_V5:
				case HTTP_V1_0:
					close(control); /* created in this function. */
					control = s;
					break;

				case MSPROXY_V2:
				swarn("%s: connect failed", function);
					break;

				default:
					SERRX(packet->req.version);
			}

			if (dup2(new_control, control) != -1) {
				close(new_control);
				/* try again, hopefully there's a backup route. */
				return socks_nbconnectroute(s, control, packet, src, dst);
			}
			close(new_control);
			return NULL;
		}

		SASSERTX(ADDRISBOUND(local));
		local.sin_port = htons(0);

		/* LINTED pointer casts may be troublesome */
		if (bind(s, (struct sockaddr *)&local, sizeof(local)) != 0)
			return NULL;
	}

	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0)
		SERR(s);

	/* this has to be done here or there would be a race against the signal. */
	socksfd.control				= control;
	socksfd.state.command		= packet->req.command;
	socksfd.state.version		= packet->req.version;
	socksfd.state.protocol.tcp	= 1;
	socksfd.state.inprogress	= 1;
	sockshost2sockaddr(&packet->req.host, &socksfd.forus.connected);

	socks_addaddr((unsigned int)s, &socksfd);

	/*
	 * send the request to our connectprocess and let it do the rest.
	 * When it's done, we get a signal and dup "s" over "socksfd.control"
	 * in the handler.
	 */

	fdsent = 0;
	/* LINTED pointer casts may be troublesome */
	CMSG_ADDOBJECT(control, cmsg, sizeof(control) * fdsent++);

	switch (packet->req.version) {
		case SOCKS_V4:
		case SOCKS_V5:
		case HTTP_V1_0:
			break;

		case MSPROXY_V2:
			/* LINTED pointer casts may be troublesome */
			CMSG_ADDOBJECT(s, cmsg, sizeof(s) * fdsent++);
			break;

		default:
			SERRX(packet->req.version);
	}

	childreq.s			= s;
	childreq.src		= *src;
	childreq.dst		= *dst;
	childreq.packet	= *packet;

	iov[0].iov_base	= &childreq;
	iov[0].iov_len		= sizeof(childreq);
	len					= sizeof(childreq);

	msg.msg_iov				= iov;
	msg.msg_iovlen			= ELEMENTS(iov);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

	/* LINTED pointer casts may be troublesome */
	CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

	slog(LOG_DEBUG, "sending request to connectchild");
#if 0
	sleep(20);
#endif
	if ((p = sendmsg(sockscf.connect_s, &msg, 0)) != (ssize_t)len) {
		swarn("%s: sendmsg(): %d of %d", function, p, len);
		return NULL;
	}

	errno = EINPROGRESS;

	return socksfd.route;
}

/*
 * XXX should have more code so we could handle multiple requests at
 * a time.
 */
static void
run_connectchild(mother)
	int mother;
{
	const char *function = "run_connectchild()";
	char string[MAXSOCKADDRSTRING];
	int p, rbits;
	fd_set rset;
	struct sigaction sig;

	slog(LOG_DEBUG, function);
#if 0
	sleep(20);
#endif

	sigemptyset(&sig.sa_mask);
	sig.sa_flags	= 0;
	sig.sa_handler	= SIG_DFL;

	if (sigaction(SIGCONT, &sig, NULL) != 0)
		serr(EXIT_FAILURE, "%s: sigaction(SIGCONT)", function);

	setproctitle("connectchild");

	/* CONSTCOND */
	while (1) {
		int flags;

		FD_ZERO(&rset);
		FD_SET(mother, &rset);
		rbits = mother;

		++rbits;
		switch (selectn(rbits, &rset, NULL, NULL, NULL)) {
			case -1:
				SERR(-1);
				/* NOTREACHED */
		}

		if (FD_ISSET(mother, &rset)) {
			/*
			 * Mother sending us a connected (or in the process of being
			 * connected) socket and necessary info to negotiate with
			 * proxyserver.
			 */
			struct childpacket_t req;
			struct iovec iov[1];
			socklen_t len;
			int s, control;
			struct sockaddr local, remote;
			struct msghdr msg;
			CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);

			iov[0].iov_base	= &req;
			iov[0].iov_len		= sizeof(req);
			len					= sizeof(req);

			msg.msg_iov          = iov;
			msg.msg_iovlen       = ELEMENTS(iov);
			msg.msg_name         = NULL;
			msg.msg_namelen      = 0;

			/* LINTED pointer casts may be troublesome */
			CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

			if ((p = recvmsgn(mother, &msg, 0)) != (ssize_t)len) {
				switch (p) {
					case -1:
						serr(EXIT_FAILURE, "%s: recvmsgn()", function);
						/* NOTREACHED */

					case 0:
						serrx(LOG_DEBUG, "%s: recvmsgn(): mother closed", function);
						_exit(EXIT_SUCCESS);
						/* NOTREACHED */

					default:
						swarn("%s: recvmsgn(): got %d of %d",
						function, p, len);
				}
				continue;
			}

			/* how many descriptors are we supposed to receive? */
			switch (req.packet.req.version) {
				case MSPROXY_V2:
					len = 2;	/* control + socket for dataflow. */
					break;

				case SOCKS_V4:
				case SOCKS_V5:
				case HTTP_V1_0:
					len = 1; /* only controlsocket (which is also datasocket). */
					break;

				default:
					SERRX(req.packet.req.version);
			}


#if !HAVE_DEFECT_RECVMSG
			SASSERTX(CMSG_TOTLEN(msg) == CMSG_SPACE(sizeof(int) * len));
#endif

			len = 0;
			/* LINTED pointer casts may be troublesome */
			CMSG_GETOBJECT(control, cmsg, sizeof(control) * len++);

			switch (req.packet.req.version) {
				case MSPROXY_V2:
					/* LINTED pointer casts may be troublesome */
					CMSG_GETOBJECT(s, cmsg, sizeof(s) * len++);
					break;

				case SOCKS_V4:
				case SOCKS_V5:
				case HTTP_V1_0:
					s = control;	/* datachannel is controlchannel. */
					break;

				default:
					SERRX(req.packet.req.version);
			}

			slog(LOG_DEBUG, "%s: req.s = %d", function, req.s);

#if DIAGNOSTIC /* DIAGNOSTIC */
			len = sizeof(local);
			if (getsockname(s, &local, &len) == 0)
				slog(LOG_DEBUG, "%s: s local: %s",
				function, sockaddr2string(&local, string, sizeof(string)));

			len = sizeof(local);
			if (getsockname(control, &local, &len) == 0)
				slog(LOG_DEBUG, "%s: control local: %s",
				function, sockaddr2string(&local, string, sizeof(string)));
			else
				swarn("%s: getsockname(%d)", function, control);

			len = sizeof(local);
			if (getpeername(control, &local, &len) == 0)
				slog(LOG_DEBUG, "%s: control remote: %s",
				function, sockaddr2string(&local, string, sizeof(string)));
#endif /* DIAGNOSTIC */

			/* XXX set socket to blocking while we use it. */
			if ((flags = fcntl(s, F_GETFL, 0)) == -1
			|| fcntl(s, F_SETFL, flags & ~NONBLOCKING) == -1)
				swarn("%s: fcntl(s)", function);

			/* default, in case we don't even get a response. */
			req.packet.res.reply = (char)sockscode(req.packet.req.version,
			SOCKS_FAILURE);
			req.packet.res.version = req.packet.req.version;

			/* CONSTCOND */
			if (1) { /* XXX wait for the connection to complete. */
				fd_set wset;

				FD_ZERO(&wset);
				FD_SET(control, &wset);

				slog(LOG_DEBUG, "%s: waiting for connectresponse ...", function);
				switch (selectn(control + 1, NULL, &wset, NULL, NULL)) {
					case -1:
						SERR(-1);
						/* NOTREACHED */

					case 0:
						SERRX(0);
						/* NOTREACHED */
				}
			}

#if !HAVE_SOLARIS_BUGS
			len = sizeof(errno);
			if (getsockopt(control, SOL_SOCKET, SO_ERROR, &errno, &len) != 0)
				SERR(-1);
#else /* !HAVE_SOLARIS_2_5_1 */ /* even read() doesn't work right on 2.5.1. */
			errno = 0;
			recvfrom(control, NULL, 0, 0, NULL, NULL); /* just get errno. */
#endif /* !HAVE_SO_ERROR */

			if (errno != 0) {
				req.packet.state.err = errno;
				swarn("%s: connect failed", function);
			}
			else
				/* connected ok. */
				if (socks_negotiate(s, control, &req.packet, NULL) != 0)
					req.packet.state.err = errno;

			/* XXX back to original. */
			if (fcntl(s, F_SETFL, flags) == -1)
				swarn("%s: fcntl(s)", function);

			len = sizeof(local);
			if (getsockname(control, &local, &len) != 0) {
				if (req.packet.state.err == 0) /* not warned. */
					swarn("%s: getsockname(control)", function);

				/*
				 * this is pretty bad, but it could happen unfortunately.
				 */
				bzero(&local, sizeof(local));
				local.sa_family = AF_INET;
				/* LINTED pointer casts may be troublesome */
				TOIN(&local)->sin_addr.s_addr = htonl(INADDR_ANY);
				/* LINTED pointer casts may be troublesome */
				TOIN(&local)->sin_port = htons(0);
			}

			len = sizeof(remote);
			if (getpeername(control, &remote, &len) != 0) {
				if (req.packet.state.err != 0) /* not warned. */
					swarn("%s: getpeername(control)", function);

				bzero(&remote, sizeof(remote));
				remote.sa_family = AF_INET;
				/* LINTED pointer casts may be troublesome */
				TOIN(&remote)->sin_addr.s_addr = htonl(INADDR_ANY);
				/* LINTED pointer casts may be troublesome */
				TOIN(&remote)->sin_port = htons(0);
			}

			sockaddr2sockshost(&local, &req.src);
			sockaddr2sockshost(&remote, &req.dst);

			/* send response to mother. */
			if ((p = write(mother, &req, sizeof(req))) != sizeof(req))
				swarn("%s: write(): %d out of %d", function, p, sizeof(req));
			close(s);

			slog(LOG_DEBUG, "raising SIGSTOP");
			if (raise(SIGSTOP) != 0)
				serr(EXIT_FAILURE, "raise(SIGSTOP)");
		}
	}
}


static void
sigchld(sig)
	int sig;
{
	const char *function = "sigchld()";
	const int errno_s = errno;
	/* CONSTCOND */
	char string[MAX(MAXSOCKADDRSTRING, MAXSOCKSHOSTSTRING)];
	int status;

	slog(LOG_DEBUG, "%s: connectchild: %d", function, sockscf.connectchild);

	switch (waitpid(sockscf.connectchild, &status, WNOHANG | WUNTRACED)) {
		case -1:
			break;

		case 0:
			/* Does user have a handler for this signal? */
			if (oldsig.sa_handler != NULL) {
				errno = errno_s;
				oldsig.sa_handler(sig);
			}
			break;

		default: {
			struct childpacket_t childres;
			struct sockaddr localmem, *local = &localmem;
			struct sockaddr remotemem, *remote = &remotemem;
			socklen_t len;
			struct socksfd_t *socksfd;
			int p, s;

			/* XXX if child dies, set err in all "inprogress" socksfd's. */

			if (WIFSIGNALED(status)) {
				swarnx("%s: connectchild terminated on signal %d",
				function, WTERMSIG(status));
				sockscf.connectchild = 0;
				close(sockscf.connect_s);
				break;
			}

			/* LINTED bitwise operation on signed value possibly nonportable */
			if (WIFEXITED(status)) {
				/* LINTED bitwise operation on signed value possibly nonportable */
				swarnx("%s: cconnectchild exited with status %d",
				function, WEXITSTATUS(status));
				sockscf.connectchild = 0;
				close(sockscf.connect_s);
				break;
			}

			SASSERTX(WIFSTOPPED(status));

			kill(sockscf.connectchild, SIGCONT);

			if ((p = read(sockscf.connect_s, &childres, sizeof(childres)))
			!= sizeof(childres)) {
				swarn("%s: read(): got %d of %d", function, p, sizeof(childres));
				return;
			}

			sockshost2sockaddr(&childres.src, local);
			sockshost2sockaddr(&childres.dst, remote);

			slog(LOG_DEBUG, "%s: local = %s",
			function, sockaddr2string(local, string, sizeof(string)));

			slog(LOG_DEBUG, "%s: remote = %s",
			function, sockaddr2string(remote, string, sizeof(string)));

			if ((s = socks_addrcontrol(local, remote)) == -1) {
				char lstring[MAXSOCKADDRSTRING];
				char rstring[MAXSOCKADDRSTRING];

				
				if (socks_isaddr(childres.s))
					s = childres.s; /* not as safe. */
				else {
					swarnx("%s: can't find controlsocket for %s <-> %s, s = %d",
					function, sockaddr2string(local, lstring, sizeof(lstring)),
					sockaddr2string(remote, rstring, sizeof(rstring)), 
					childres.s);

					return;
				}
			}

			socksfd = socks_getaddr((unsigned int)s);
			SASSERTX(socksfd != NULL);

			switch (socksfd->state.version) {
				case MSPROXY_V2:
					break; /* nothing to do, control separate from data. */

				case SOCKS_V4:
				case SOCKS_V5:
				case HTTP_V1_0:
					slog(LOG_DEBUG, "%s: duping %d over %d",
					function, socksfd->control, s);

					if (dup2(socksfd->control, s) == -1) {
						SASSERT(errno != EBADF);
						swarn("%s: dup2(socksfd->control, s)", function);
						socksfd->state.err = errno;
						break;
					}
					close(socksfd->control);
					socksfd->control = s;
					break;

				default:
					SERRX(socksfd->state.version);
			}

			/*
			 * it's possible endpoint changed/got fixed.  Update in case.
			 */

			len = sizeof(socksfd->local);
			if (getsockname(s, &socksfd->local, &len) != 0)
				swarn("%s: getsockname(s)", function);
			else
				slog(LOG_DEBUG, "%s: socksfd->local: %s",
				function, sockaddr2string(&socksfd->local, string, sizeof(string)));

			len = sizeof(socksfd->server);
			if (getpeername(s, &socksfd->server, &len) != 0)
				swarn("%s: getpeername(s)", function);

			/* child that was supposed to setup relaying finished.  status? */
			if (!serverreplyisok(childres.packet.res.version,
			childres.packet.res.reply, socksfd->route)) {
				socksfd->state.err = errno;
				/*
				 * XXX If it's a servererror it would be nice to retry, could
				 * be there's a backup route.
				 */
				return;
			}

			slog(LOG_DEBUG, "serverreplyisok, server will use as src: %s",
			sockshost2string(&childres.packet.res.host, string, sizeof(string)));

			socksfd->state.auth			= childres.packet.auth;
			socksfd->state.msproxy		= childres.packet.state.msproxy;
			socksfd->state.inprogress	= 0;
			sockshost2sockaddr(&childres.packet.res.host, &socksfd->remote);

			/* needed for standard socks bind. */
			sockscf.state.lastconnect = socksfd->forus.connected;
		}
	}

	errno = errno_s;
}
