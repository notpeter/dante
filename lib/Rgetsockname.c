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

static const char rcsid[] =
"$Id: Rgetsockname.c,v 1.44 2005/01/24 10:24:21 karls Exp $";

int
Rgetsockname(s, name, namelen)
	int s;
	struct sockaddr *name;
	socklen_t *namelen;
{
	const char *function = "Rgetsockname()";
	struct socksfd_t *socksfd;
	struct sockaddr *addr;

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	if (!socks_addrisok((unsigned int)s)) {
		socks_rmaddr((unsigned int)s);
		return getsockname(s, name, namelen);
	}

	socksfd = socks_getaddr((unsigned int)s);
	SASSERTX(socksfd != NULL);

	switch (socksfd->state.command) {
		case SOCKS_CONNECT: {
			sigset_t set, oset;

			/* for non-blocking connect, we get a SIGCHLD upon completion. */
			sigemptyset(&set);
			sigaddset(&set, SIGCHLD);
			if (sigprocmask(SIG_BLOCK, &set, &oset) != 0) {
				swarn("%s: sigprocmask()", function);
				return -1;
			}

			if (socksfd->state.inprogress) { /* non-blocking connect. */
				/*
				 * this is bad.  We don't know what address the socksserver
				 * will use on our behalf yet.  Lets wait for a SIGCHLD
				 * and then retry, unless client is blocking that signal,
				 * then we can only hope the client will retry on ENOBUFS,
				 * but we are probably screwed anyway.
				*/
				if (sigismember(&oset, SIGCHLD)) {
					slog(LOG_DEBUG, "%s: SIGCHLD blocked by client", function);

					if (sigprocmask(SIG_BLOCK, &oset, NULL) != 0) {
						swarn("%s: sigprocmask()", function);
						return -1;
					}

					errno = ENOBUFS;
					return -1;
				}

				sigsuspend(&oset);
				if (sigprocmask(SIG_BLOCK, &oset, NULL) != 0) {
					swarn("%s: sigprocmask()", function);
					return -1;
				}

				return Rgetsockname(s, name, namelen);
			}

			if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
				swarn("%s: sigprocmask()", function);
			addr = &socksfd->remote;
			break;
		}

		case SOCKS_BIND:
			addr = &socksfd->remote;
			break;

		case SOCKS_UDPASSOCIATE:
			swarnx("%s: getsockname() on udp sockets is not supported by the "
			"socks protocol, trying to fake it.", function);

			/*
			 * some clients might call this for no good reason, try to
			 * help them by returning a invalid address; if they are
			 * going to use it for anything, they will fail later though.
			 */

			addr = &socksfd->remote;
			/* LINTED pointer casts may be troublesome */
			TOIN(addr)->sin_family			= AF_INET;
			/* LINTED pointer casts may be troublesome */
			TOIN(addr)->sin_addr.s_addr	= htonl(INADDR_ANY);
			/* LINTED pointer casts may be troublesome */
			TOIN(addr)->sin_port				= htons(0);
			break;

		default:
			SERRX(socksfd->state.command);
	}

	*namelen = MIN(*namelen, (socklen_t)sizeof(*addr));
	memcpy(name, addr, (size_t)*namelen);

	return 0;
}
