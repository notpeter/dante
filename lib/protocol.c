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
"$Id: protocol.c,v 1.55 2003/07/01 13:21:31 michaels Exp $";

unsigned char *
sockshost2mem(host, mem, version)
	const struct sockshost_t *host;
	unsigned char *mem;
	int version;
{

	switch (version) {
		case SOCKS_V4:
		case SOCKS_V4REPLY_VERSION:
			SASSERTX(host->atype == SOCKS_ADDR_IPV4);

			/* DSTPORT */
			memcpy(mem, &host->port, sizeof(host->port));
			mem += sizeof(host->port);

			/* DSTIP */
			memcpy(mem, &host->addr.ipv4, sizeof(host->addr.ipv4));
			mem += sizeof(host->addr.ipv4);

			break;

		case SOCKS_V5:
			/* ATYP */
			memcpy(mem, &host->atype, sizeof(host->atype));
			mem += sizeof(host->atype);

			switch (host->atype) {
				case SOCKS_ADDR_IPV4:
					memcpy(mem, &host->addr.ipv4.s_addr,
					sizeof(host->addr.ipv4.s_addr));
					mem += sizeof(host->addr.ipv4.s_addr);
					break;

				case SOCKS_ADDR_IPV6:
					memcpy(mem, &host->addr.ipv6, sizeof(host->addr.ipv6));
					mem += sizeof(host->addr.ipv6);
					break;

				case SOCKS_ADDR_DOMAIN:
					/* first byte gives length of rest. */
					*mem = (unsigned char)strlen(host->addr.domain);
					memcpy(mem + 1, host->addr.domain, (size_t)*mem);
					mem += *mem + 1;
					break;

				default:
					SERRX(host->atype);
			}

			/* DST.PORT */
			memcpy(mem, &host->port, sizeof(host->port));
			mem += sizeof(host->port);

			break;

		default:
			SERRX(version);
	}

	return mem;
}

const unsigned char *
mem2sockshost(host, mem, len, version)
	struct sockshost_t *host;
	const unsigned char *mem;
	size_t len;
	int version;
{
	const char *function = "mem2sockshost()";

	switch (version) {
		case SOCKS_V5:
			if (len < sizeof(host->atype))
				return NULL;
			memcpy(&host->atype, mem, sizeof(host->atype));
			mem += sizeof(host->atype);
			len -= sizeof(host->atype);

			switch (host->atype) {
				case SOCKS_ADDR_IPV4:
					if (len < sizeof(host->addr.ipv4))
						return NULL;
					memcpy(&host->addr.ipv4, mem, sizeof(host->addr.ipv4));
					mem += sizeof(host->addr.ipv4);
					len -= sizeof(host->addr.ipv4);
					break;

				case SOCKS_ADDR_DOMAIN: {
					size_t domainlen = (size_t)*mem;

					mem += sizeof(*mem);

					OCTETIFY(domainlen);

					if (len < domainlen + 1) /* +1 for NUL to be added. */
						return NULL;

					SASSERTX(domainlen < sizeof(host->addr.domain));

					memcpy(host->addr.domain, mem, domainlen);
					host->addr.domain[domainlen] = NUL;
					mem += domainlen;
					len -= domainlen + 1; /* +1 for added NUL. */
					break;
				}

				case SOCKS_ADDR_IPV6:
					slog(LOG_INFO, "%s: IPv6 not supported", function);
					return NULL;

				default:
					slog(LOG_INFO, "%s: unknown atype field: %d",
					function, host->atype);
					return NULL;
			}

			if (len < sizeof(host->port))
				return NULL;
			memcpy(&host->port, mem, sizeof(host->port));
			mem += sizeof(host->port);
			len -= sizeof(host->port);

			break;

		default:
			SERRX(version);
	}

	return mem;
}
