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
"$Id: Rgetsockname.c,v 1.17 1998/11/13 21:17:56 michaels Exp $";

#include "common.h"

int
Rgetsockname(s, name, namelen)
	int s;
	struct sockaddr *name;
	socklen_t *namelen;
{
	struct socksfd_t *socksfd;
	struct sockaddr *addr;

	if (!socks_addrisok((unsigned int)s)) {
		socks_rmaddr((unsigned int)s);
		return getsockname(s, name, namelen);
	}

	socksfd = socks_getaddr((unsigned int)s);
	SASSERTX(socksfd != NULL);

	switch (socksfd->state.command) {
		case SOCKS_CONNECT:
			addr = &socksfd->remote;

			/* XXX */
			/* LINTED pointer casts may be troublesome */
			if (((struct sockaddr_in *)addr)->sin_addr.s_addr == htonl(INADDR_ANY)
			&& ((struct sockaddr_in *)addr)->sin_port == htons(0)) {
				swarnx("sorry, getsockname() on nonblocking connect() is\n"
						 "not supported in this version.\n"
						 "Please contact Inferno Nettverk for more information.");

				errno = EADDRNOTAVAIL;
				return -1;
			}
			break;

		case SOCKS_BIND:
		case SOCKS_UDPASSOCIATE:
			addr = &socksfd->remote;
			break;

		default:
			SERRX(socksfd->state.command);
	}

	*namelen = MIN(*namelen, sizeof(*addr));
	memcpy(name, addr, (unsigned int)*namelen);

	return 0;
}
