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
"$Id: socket_nonblocking.c,v 1.43 1998/11/13 21:18:24 michaels Exp $";

#include "common.h"

__BEGIN_DECLS

static void
sigchld __P((int sig));

static void
socks_donegotiate __P((int s, struct socks_t *packet));
/*
 * Analogous to socks_negotiate but instead of returning the server reply,
 * it exits with the reply as exit code.  (used on non-blocking connects.)
*/ 

__END_DECLS

static struct sigaction old_sigchld;

struct route_t *
socks_nbconnectroute(s, packet, src, dst)
	int s;
	struct socks_t *packet;
	const struct sockshost_t *src, *dst;
{
	const char *function = "socks_nbconnectroute()";
	struct socksfd_t socksfd, *socksfdp;
	struct sigaction newsig, oldsig;
	int len;

	/*
	 * We don't want to allow the client to read/write/select etc.
	 * on the original socket yet since we need to read/write on it
	 * ourselves to setup the connection to the socksserver. 
	 * We therefore create a new socket to be used for setting up the
	 * connection and then duplicate over the socket we were passed here
	 * when we have successfully setup relaying with the socksserver.
	*/

	bzero(&socksfd, sizeof(socksfd));
	if ((socksfd.s = socketoptdup(s)) == -1)
		return NULL;

	errno = 0;
	if ((socksfd.route = socks_connectroute(socksfd.s, packet, src, dst))
	== NULL)
		return NULL;
	else
		if (errno != EINPROGRESS)
			return NULL;

	if (sigaction(SIGCHLD, NULL, &oldsig) != 0)
		return NULL;

	if (oldsig.sa_handler == NULL) {
		/* no signal handler, free to do what we want. */
		sigemptyset(&newsig.sa_mask);
		newsig.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	}
	else
		/* duplicate old handler as much as possible */
		newsig = oldsig;

	newsig.sa_handler = sigchld;

	if (sigaction(SIGCHLD, &newsig, &oldsig) != 0)
		return NULL;

	/*
	 * if caller already has a signal handler for SIGCHLD, save it
	 * so we can call it from our own handler if something else than our
	 * own child dies, for compatibility with callee.
	*/
	if (memcmp(&newsig, &oldsig, sizeof(newsig)) != 0)
		old_sigchld = oldsig;

	/*
	 * The tricky stuff;  try to fake non-blocking i/o by forking off a
	 * child and letting it set up relaying with server.  When child exits, 
	 * we dup over the descriptor if the child exited with a code
	 * matching a serverreply of success.
	*/

	socksfd.state.command 			= SOCKS_CONNECT;
	socksfd.state.version 			= packet->req.version;
	socksfd.state.inprogress 		= 1;

	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0)
		swarn("%s: getsockname(s)", function);

	socksfdp = socks_addaddr((unsigned int)s, &socksfd);

	/* important to set it this way to avoid race. */
	switch (socksfdp->state.childpid = fork()) {
		case (pid_t)-1:
			swarn("%s: fork()", function);
			return NULL;

		case 0:
			slog(LOG_DEBUG, "%s: forked to connect", function);
			socks_donegotiate(socksfd.s, packet);
			/* NOTREACHED */

		default:
			/* 
			 * Note that when the forked child finished, we will get a signal
			 * and in that signal, we call socks_rmaddr() on s, thus
			 * socksfdp may point to who knows what.  Since we only need
			 * to return the route, that's not a problem and we can use socksfd
			 * instead.
			*/
			errno = EINPROGRESS;
			return socksfd.route;
	}
}


static void
sigchld(sig)
	int sig;
{
	const char *function = "sigchld()";
	const int errno_s = errno;
	int status, childpid;

	switch (childpid = waitpid(-1, &status, WNOHANG)) {
		case -1:
		case 0:
			break;
		
		default: {
			struct socksfd_t *socksfd;
			struct socksstate_t state;
			int len, clientfd;

			state.version 			= -1;
			state.command 			= -1;
			state.inprogress 		= 1;
			state.acceptpending 	= -1;
			state.childpid 		= childpid;

			/* child finished.  One of ours? */
			if ((clientfd = socks_addrmatch(NULL, NULL, &state)) == -1) {
				/* No.  Does user have a handler for this signal? */
				if (old_sigchld.sa_handler != NULL) {
					errno = errno_s;
					old_sigchld.sa_handler(sig);
				}
				break;
			}	

			socksfd = socks_getaddr((unsigned int)clientfd);
			SASSERTX(socksfd != NULL);

			/* child that was supposed to setup relaying finished.  status? */

			if (WIFSIGNALED(status)) {
				swarnx("%s: nbconnect child terminated on signal %d",
				function, WTERMSIG(status));
				socks_rmaddr((unsigned int)clientfd);
				break;
			}

			/* needed in case using callee's signal setup. */
			if (WIFSTOPPED(status))
				break;

			if (WIFEXITED(status)) {
				if (!serverreplyisok(socksfd->state.version, WEXITSTATUS(status))) {
					swarnx("%s: server returned error: %d",
					function, WEXITSTATUS(status));
					socks_rmaddr((unsigned int)clientfd);
					close(socksfd->s);
					break;
				}

				slog(LOG_DEBUG, "duping %d over %d", socksfd->s, clientfd);
				if (dup2(socksfd->s, clientfd) == -1) {
					SASSERT(errno != EBADF);
					swarn("%s: dup2(socksfd->s, clientfd)", function);
					socks_rmaddr((unsigned int)clientfd);
					close(socksfd->s);
					break;
				}
				close(socksfd->s);
			}

			socksfd->state.inprogress 	= 0;
			socksfd->state.childpid 	= 0;
			socksfd->s 						= clientfd;

			len = sizeof(socksfd->server);
			if (getpeername(socksfd->s, &socksfd->server, &len) != 0)
				swarn("%s: getpeername(socksfd->s)", function);

			len = sizeof(socksfd->local);
			if (getsockname(socksfd->s, &socksfd->local, &len) != 0)
				swarn("%s: getsockname(socksfd->s)", function);
		}
	}

	errno = errno_s;
}

static void
socks_donegotiate(s, packet)
	int s;
	struct socks_t *packet;
{
	const char *function = "socks_donegotiate()";
	int flags;

	/* set descriptor to blocking temporary, easier to use. */
	if ((flags = fcntl(s, F_GETFL, 0)) == -1
	||  fcntl(s, F_SETFL, flags & ~(O_NONBLOCK | FNDELAY)) == -1)
		swarn("%s: fcntl()", function);

	if (socks_negotiate(s, packet) != 0)
		; /* failed negotiation with server, anything to do? */

	/* reset back to original state. */
	if (flags != -1 && fcntl(s, F_SETFL, flags) == -1)
		swarn("%s: fcntl()", function);
	
	_exit(packet->res.reply);
}
