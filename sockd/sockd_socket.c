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
"$Id: sockd_socket.c,v 1.36 2003/07/01 13:21:49 michaels Exp $";

int
sockd_bind(s, addr, retries)
	int s;
	struct sockaddr *addr;
	size_t retries;
{
/*	const char *function = "sockd_bind()"; */
	size_t tries;
	int p;

	errno = 0;
	tries = 0;
	do {
		if (tries++ > 0)
			sleep(tries - 1);

		/* LINTED pointer casts may be troublesome */
		if (PORTISRESERVED(TOIN(addr)->sin_port) && sockscf.compat.sameport) {
			uid_t euid;

			socks_seteuid(&euid, sockscf.uid.privileged);
			/* LINTED pointer casts may be troublesome */
			if ((p = bind(s, addr, sizeof(*addr))) == -1 && errno == EADDRINUSE) {
#if HAVE_BINDRESVPORT
				/*
				 * There are some differences in whether bindresvport()
				 * retries or not on different systems, and Linux
				 * ignores the portnumber altogether, so we have to
				 * do two calls.
				 */
				TOIN(addr)->sin_port = htons(0);
				p = bindresvport(s, TOIN(addr));
#endif /* HAVE_BINDRESVPORT */
			}
			socks_reseteuid(sockscf.uid.privileged, euid);
		}
		else if ((p = bind(s, addr, sizeof(*addr))) == 0) {
			socklen_t addrlen;

			addrlen = sizeof(*addr);
			p = getsockname(s, addr, &addrlen);
		}

		if (p == 0)
			break;
		else {
			/* non-fatal error? */
			switch (errno) {
				case EADDRINUSE:
					continue;

				case EINTR:
					continue;
			}
			break; /* fatal error. */
		}
	} while (tries <= retries);

	return p;
}
