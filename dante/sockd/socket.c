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
"$Id: socket.c,v 1.21 1999/05/25 17:22:35 michaels Exp $";

int
socks_connect(s, host)
	int s;
	const struct sockshost_t *host;
{
	int new_s;
	struct hostent *hostent;
	struct sockaddr_in address;
	char **ip;

	bzero(&address, sizeof(address));
	address.sin_family	= AF_INET;
	address.sin_port		= host->port;

	switch (host->atype) {
		case SOCKS_ADDR_IPV4:
			address.sin_addr = host->addr.ipv4;

			/* LINTED pointer casts may be troublesome */
			return connect(s, (struct sockaddr *)&address, sizeof(address));

		case SOCKS_ADDR_DOMAIN:
			hostent = gethostbyname((const char *)host->addr.domain);
			break;

		default:
			SERRX(host->atype);
	}

	if (hostent == NULL)
		return -1;

	new_s = -1;
	ip = hostent->h_addr_list;
	do {
		if (new_s == -1)
			new_s = s;	/* try to use given descriptor before creating our own. */
		else
			if ((new_s = socketoptdup(s)) == -1)
				return -1;

		/* LINTED pointer casts may be troublesome */
		address.sin_addr = *((struct in_addr *)*ip);

		/* LINTED pointer casts may be troublesome */
		if (connect(new_s, (struct sockaddr *)&address, sizeof(address)) == 0)
			break;

		if (new_s != s)
			close(new_s);

		/*
		 * Only try next address if errno indicates server/network error.
		*/
		switch (errno) {
			case ETIMEDOUT:
			case EINVAL:
			case ECONNREFUSED:
			case ENETUNREACH:
				break;

			default:
				return -1;
		}
	} while (*++ip != NULL);

	if (*ip == NULL)
		return -1; /* list exhausted, no successfull connect. */

	if (new_s != s) {	/* had to create a new socket of our own. */
		if (dup2(new_s, s) == -1) {
			close(new_s);
			return -1;
		}
		close(new_s);
	}

	return 0;
}

int
acceptn(s, addr, addrlen)
	int s;
	struct sockaddr *addr;
	socklen_t *addrlen;
{
	int rc;

	while ((rc = accept(s, addr, addrlen)) == -1 && errno == EINTR)
		;

	return rc;
}
