/*
 * Copyright (c) 1997, 1998
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
 *  N-0371 Oslo
 *  Norway
 * 
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

static const char rcsid[] =
"$Id: connectchild.c,v 1.52 1998/12/10 11:54:58 michaels Exp $";

#include "common.h"

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

struct route_t *
socks_nbconnectroute(s, packet, src, dst)
	int s;
	struct socks_t *packet;
	const struct sockshost_t *src, *dst;
{
	const char *function = "socks_nbconnectroute()";
	struct sigaction currentsig;
	struct socksfd_t socksfd;
	ssize_t p;
	struct iovec iov[3];
	int len, ioc;
	struct msghdr msg;
#ifdef HAVE_CMSGHDR
   union {
      char cmsgmem[sizeof(struct cmsghdr) + sizeof(int)];
      struct cmsghdr align;
   } cmsgmem;
   struct cmsghdr *cmsg = &cmsgmem.align;
#else
   char cmsgmem[sizeof(int)];
#endif /* HAVE_CMSGHDR */


	bzero(&socksfd, sizeof(socksfd));

	if ((socksfd.route = socks_getroute(&packet->req, src, dst)) == NULL) {
		errno = 0;
		return NULL;
	}

	if (sigaction(SIGCHLD, NULL, &currentsig) != 0) {
		swarn("%s: sigaction(SIGCHLD)", function);
		return NULL;
	}

	if (currentsig.sa_handler != sigchld) {
		/*
		 * Our signalhandler is not installed, install it.
		*/
		struct sigaction oursig;

		if (sigaction(SIGCHLD, NULL, &oldsig) != 0) {
			swarn("%s: sigaction(SIGCHLD)", function);
			return NULL;
		}

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

	if (config.connectchild == 0) {
		/* 
		 * Create child process that will do our connections.
		*/
		int pipev[2];

		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pipev) != 0) {
			swarn("%s: socketpair(AF_LOCAL, SOCK_STREAM)", function);
			return NULL;
		}

		slog(LOG_DEBUG, "forking connectchild");
		switch (config.connectchild = fork()) {
			case -1:
				swarn("%s: fork()", function);
				return NULL;

			case 0: {
				int i, max;

				slog(LOG_DEBUG, "connectchild forked");

				/* close unknown descriptors. */
				for (i = 0, max = getdtablesize(); i < max; ++i)
					if (socks_logmatch(i, &config.log)) 
						continue;
					else if (i == pipev[1])
						continue;
					else
						close(i);

				run_connectchild(pipev[1]);
				/* NOTREACHED */
			}

			default:
				config.connect_s = pipev[0];
				close(pipev[1]);
		}
	}


	/*
	 * We don't want to allow the client to read/write/select etc.
	 * on the original socket yet since we need to read/write on it
	 * ourselves to setup the connection to the socksserver. 
	 * We therefore create a new socket to be used for setting up the
	 * connection and then duplicate over the socket we were passed here
	 * when we have successfully setup relaying with the socksserver.
	*/

	if ((socksfd.s = socketoptdup(s)) == -1) {
		swarn("%s: socketoptdup()", function);
		return NULL;
	}

	socksfd.state.command 			= SOCKS_CONNECT;
	socksfd.state.version 			= packet->req.version;
	socksfd.state.inprogress 		= 1;
	sockshost2sockaddr(&packet->req.host, &socksfd.connected);

	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0)
		swarn("%s: getsockname()", function);

	socks_addaddr((unsigned int)s, &socksfd);

	/*
	 * send the request to our connectprocess and let it do the rest.
	 * When it's done, we get a signal and dup "s" over "socksfd.s" in
	 * the handler.
	*/

#ifdef HAVE_CMSGHDR
	/* LINTED pointer casts may be troublesome */
	*(int *)(CMSG_DATA(cmsg)) 	= socksfd.s;
   cmsg->cmsg_level     		= SOL_SOCKET;
   cmsg->cmsg_type      		= SCM_RIGHTS;
   cmsg->cmsg_len       		= sizeof(struct cmsghdr) + sizeof(socksfd.s);
#else /* HAVE_CMSGHDR */
	memcpy(cmsgmem, &socksfd.s, sizeof(socksfd.s));
   msg.msg_accrights    		= (caddr_t) cmsgmem;
   msg.msg_accrightslen 		= sizeof(int);
#endif /* !HAVE_CMSGHDR */

	ioc = 0;
	len = 0;

	/* LINTED cast discards 'const' from pointer target type */
	iov[ioc].iov_base 	= (void *)src;
	iov[ioc].iov_len		= sizeof(*src);
	len 					  += iov[ioc].iov_len;
	++ioc;

	/* LINTED cast discards 'const' from pointer target type */
	iov[ioc].iov_base 	= (void *)dst;
	iov[ioc].iov_len		= sizeof(*dst);
	len 					  += iov[ioc].iov_len;
	++ioc;

	iov[ioc].iov_base 	= &packet->req;
	iov[ioc].iov_len		= sizeof(packet->req);
	len 					  += iov[ioc].iov_len;
	++ioc;

	msg.msg_iov				= iov;
	msg.msg_iovlen			= ioc;
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

#ifdef HAVE_CMSGHDR
	/* LINTED pointer casts may be troublesome */
	msg.msg_control		= (caddr_t)cmsg;
	msg.msg_controllen 	= cmsg->cmsg_len;
#endif /* HAVE_CMSGHDR */

	slog(LOG_DEBUG, "sending request to connectchild");
	if ((p = sendmsg(config.connect_s, &msg, 0)) != len) {
		swarn("%s: sendmsg(): %d of %d", function, p, len);
		return NULL;
	}

	errno = EINPROGRESS;

	return socksfd.route;
}

static void
run_connectchild(mother)
	int mother;
{
	const char *function = "run_connectchild()";
	int p, rbits;
	fd_set rset;
	struct sigaction sig;

	sigemptyset(&sig.sa_mask);
	sig.sa_flags 	= 0;
	sig.sa_handler = SIG_DFL;  

	if (sigaction(SIGCONT, &sig, NULL) != 0)
		serr(EXIT_FAILURE, "%s: sigaction(SIGCONT)", function);

	setproctitle("dante's connectchild");

	/* CONSTCOND */
	while (1) {
		FD_ZERO(&rset);

		FD_SET(mother, &rset);
		rbits = mother;

		++rbits;
		switch (select(rbits, &rset, NULL, NULL, NULL)) {
			case -1:
				SERR(-1);
				/* NOTREACHED */
		}

		if (FD_ISSET(mother, &rset)) {
			struct sockaddr local, remote;
			int s, len;
			struct sockshost_t src, dst;
			struct socks_t packet;
			struct route_t *route;
#ifdef HAVE_CMSGHDR
			union {
				char cmsgmem[sizeof(struct cmsghdr) + sizeof(int)];
				struct cmsghdr align;
			} cmsgmem;
			struct cmsghdr *cmsg = &cmsgmem.align;
#endif  /* HAVE_CMSGHDR */
			struct iovec iov[3];
			int ioc;
			struct msghdr msg;

			len = 0;
			ioc = 0;

			iov[ioc].iov_base	= &src;
			iov[ioc].iov_len	= sizeof(src);
			len 					+= iov[ioc].iov_len;
			++ioc;

			iov[ioc].iov_base	= &dst;
			iov[ioc].iov_len	= sizeof(dst);
			len 					+= iov[ioc].iov_len;
			++ioc;

			iov[ioc].iov_base	= &packet.req;
			iov[ioc].iov_len	= sizeof(packet.req);
			len 					+= iov[ioc].iov_len;
			++ioc;

			msg.msg_iov          = iov;
			msg.msg_iovlen       = ioc;
			msg.msg_name         = NULL;
			msg.msg_namelen      = 0;

#ifdef HAVE_CMSGHDR
			/* LINTED pointer casts may be troublesome */
			msg.msg_control      = (caddr_t)cmsg;
			msg.msg_controllen   = sizeof(cmsgmem);
#else
			msg.msg_accrights    = (caddr_t)&s;
			msg.msg_accrightslen = sizeof(s);
#endif  /* HAVE_CMSGHDR */
			
			if ((p = recvmsgn(mother, &msg, 0, (size_t)len)) != len) {
				switch (p) {
					case -1:
						slog(LOG_DEBUG, "%s: recvmsgn(): %s",
						function, strerror(errno));
						_exit(EXIT_SUCCESS);	
						/* NOTREACHED */
				
					case 0:
						slog(LOG_DEBUG, "%s: recvmsgn(): mother closed", function);
						_exit(EXIT_SUCCESS);	
						/* NOTREACHED */

					default:
						swarn("%s: recvmsgn(): got %d of %d",
						function, p, len);
				}
				continue;
			}

#ifdef HAVE_CMSGHDR
#ifndef HAVE_DEFECT_RECVMSG
			SASSERTX(msg.msg_controllen == sizeof(cmsgmem));
#endif /* !HAVE_DEFECT_RECVMSG */
#else
			SASSERTX(msg.msg_accrightslen == sizeof(int));
#endif  /* HAVE_CMSGHDR */

#ifdef HAVE_CMSGHDR
   		/* LINTED pointer casts may be troublesome */
			s = *(int *)(CMSG_DATA(cmsg));
#endif  /* HAVE_CMSGHDR */

			if (1) { /* XXX */
				int flags;

				if ((flags = fcntl(s, F_GETFL, 0)) == -1
				||  fcntl(s, F_SETFL, flags & ~NONBLOCKING) == -1)
					swarn("%s: fcntl()");
			}

			route = socks_connectroute(s, &packet, &src, &dst);
			SASSERTX(route != NULL);

			/* default in case we don't even get a response. */
			packet.res.reply = (char)sockscode(packet.req.version, SOCKS_FAILURE);
			packet.res.version = packet.req.version;

			p = socks_negotiate(s, &packet);

			if (1) { /* XXX */
				int flags;

				if ((flags = fcntl(s, F_GETFL, 0)) == -1
				||  fcntl(s, F_SETFL, flags | NONBLOCKING) == -1)
					swarn("%s: fcntl()");
			}
			

			len = sizeof(local);
			if (getsockname(s, &local, &len) != 0)
				swarn("%s: getsockname()", function);

			len = sizeof(remote);
			if (getpeername(s, &remote, &len) != 0)
				swarn("%s: getpeername()", function);

			len = 0;
			ioc = 0;

			iov[ioc].iov_base	= &local;
			iov[ioc].iov_len	= sizeof(local);
			len 					+= iov[ioc].iov_len;
			++ioc;

			iov[ioc].iov_base	= &remote;
			iov[ioc].iov_len	= sizeof(remote);
			len 					+= iov[ioc].iov_len;
			++ioc;

			iov[ioc].iov_base	= &packet.res;
			iov[ioc].iov_len	= sizeof(packet.res);
			len 					+= iov[ioc].iov_len;
			++ioc;
			
			/* send response to mother. */
			if ((p = writev(mother, iov, ioc)) != len)
				swarn("%s: writev(): %d out of %d", p, len);
			close(s);

			slog(LOG_DEBUG, "raising SIGSTOP");
			if (kill(getpid(), SIGSTOP) != 0)
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
	int status;

	slog(LOG_DEBUG, "%s: connectchild: %d", function, config.connectchild);

	switch (waitpid(config.connectchild, &status, WNOHANG | WUNTRACED)) {
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
			struct response_t response;	
			struct sockaddr local, remote;
			struct iovec iov[3];
			int ioc;
			struct socksfd_t *socksfd;
			int len, p, clientfd;

			/* XXX if child dies, set err in all "inprogress" socksfd's. */

			if (WIFSIGNALED(status)) {
				swarnx("%s: connect child terminated on signal %d",
				function, WTERMSIG(status));
				config.connectchild = 0;
				close(config.connect_s);
				break;
			}

			if (WIFEXITED(status)) {
				swarnx("%s: nbcconnect child exited with status %d",
				function, WEXITSTATUS(status));
				config.connectchild = 0;
				close(config.connect_s);
				break;
			}

			SASSERTX(WIFSTOPPED(status));

			kill(config.connectchild, SIGCONT); 

			len = 0;
			ioc = 0;

			iov[ioc].iov_base = &local;
			iov[ioc].iov_len	= sizeof(local);
			len 				  += iov[ioc].iov_len;
			++ioc;

			iov[ioc].iov_base = &remote;
			iov[ioc].iov_len	= sizeof(remote);
			len 				  += iov[ioc].iov_len;
			++ioc;

			iov[ioc].iov_base = &response;
			iov[ioc].iov_len	= sizeof(response);
			len 				   += iov[ioc].iov_len;
			++ioc;

			if ((p = readv(config.connect_s, iov, ioc)) != len) {
				swarn("%s: readv(): got %d of %d", function, p, len);
				return;
			}
			
			if ((clientfd = socks_addrcontrol(&local, &remote)) == -1) {
				swarnx("%s: hmm, can't find controlsocket?", function);
				return;
			}

			socksfd = socks_getaddr((unsigned int)clientfd);
			SASSERTX(socksfd != NULL);

			/* child that was supposed to setup relaying finished.  status? */

			slog(LOG_DEBUG, "duping %d over %d", socksfd->s, clientfd);
			if (dup2(socksfd->s, clientfd) == -1) {
				SASSERT(errno != EBADF);
				swarn("%s: dup2(socksfd->s, clientfd)", function);
				socksfd->state.err = errno;
				break;
			}
			close(socksfd->s);

			if (!serverreplyisok(response.version, response.reply)) {
				socksfd->state.err = errno;
				return;
			}

			socksfd->state.inprogress 	= 0;
			socksfd->s 						= clientfd;

			len = sizeof(socksfd->server);
			if (getpeername(socksfd->s, &socksfd->server, &len) != 0)
				swarn("%s: getpeername(socksfd->s)", function);

			len = sizeof(socksfd->local);
			if (getsockname(socksfd->s, &socksfd->local, &len) != 0)
				swarn("%s: getsockname(socksfd->s)", function);

			sockshost2sockaddr(&response.host, &socksfd->remote);
		}
	}

	errno = errno_s;
}
