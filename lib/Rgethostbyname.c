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
"$Id: Rgethostbyname.c,v 1.12 1999/02/20 19:26:24 michaels Exp $";

#include "common.h"

struct hostent *
Rgethostbyname2(name, af)
	const char *name;
	int af;
{
	static struct hostent hostentmem;
	static char **addrlist;
	struct in_addr ipindex;
	struct hostent *hostent;

	if (getenv("SOCKS_NORESOLVE") == NULL) {
#ifdef HAVE_GETHOSTBYNAME2
		if ((hostent = gethostbyname2(name, af)) != NULL)
#else
		if ((hostent = gethostbyname(name)) != NULL)
#endif /* !HAVE_GETHOSTBYNAME2 */
			return hostent;
	}
	else {
		hostent = NULL;
		h_errno = NO_RECOVERY;
	}

	if (h_errno != NO_RECOVERY)
		return hostent;

	hostent = &hostentmem;

	/* anything that fails from here is due to resource shortage. */
	h_errno = TRY_AGAIN;

	free(hostent->h_name);
	if ((hostent->h_name = strdup(name)) == NULL)
		return NULL;
		
	hostent->h_aliases 	= NULL;
	hostent->h_addrtype	= af;

	if (addrlist == NULL)
		/* * 2; NULL terminated. */
		if ((addrlist = malloc(sizeof(addrlist) * 2)) == NULL)
			return NULL;

	switch (af) {
		case AF_INET: {
			static char ipv4[4];

			hostent->h_length = sizeof(ipv4);
			*addrlist = ipv4;
			break;
		}

#ifdef SOCKS_IPV6
		case AF_INET6: {
			static char ipv6[16];

			hostent->h_length = sizeof(ipv6);
			*addrlist = ipv6;
			break;
		}
#endif  /* SOCKS_IPV6 */

		default:
			errno = ENOPROTOOPT;
			return NULL;
	}

	if ((ipindex.s_addr = socks_addfakeip(name)) == INADDR_NONE)
		return NULL;

	if (inet_pton(af, inet_ntoa(ipindex), *addrlist) != 1)
		return NULL;
	hostent->h_addr_list = addrlist++;
	*addrlist = NULL;	

	return hostent;
}

struct hostent *
Rgethostbyname(name)
	const char *name;
{
	
	return Rgethostbyname2(name, AF_INET);
}

