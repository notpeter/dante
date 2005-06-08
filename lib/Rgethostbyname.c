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

/*
 * getaddrinfo() contributed by Motoyuki Kasahara <m-kasahr@sra.co.jp>
 * getipnodebyname() contributed by Lennart Dahlström <lennart@appgate.com>
 */

#include "common.h"

static const char rcsid[] =
"$Id: Rgethostbyname.c,v 1.46 2005/05/10 11:44:57 michaels Exp $";

struct hostent *
Rgethostbyname2(name, af)
	const char *name;
	int af;
{
	const char *function = "Rgethostbyname2()";
	static struct hostent hostentmem;
	static char *aliases[] = { NULL };
	struct in_addr ipindex;
	struct hostent *hostent;

	clientinit();

	slog(LOG_DEBUG, "%s: %s", function, name);

	switch (sockscf.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
		case RESOLVEPROTOCOL_UDP:
			if ((hostent = gethostbyname(name)) != NULL)
				return hostent;
			break;

		case RESOLVEPROTOCOL_FAKE:
			hostent = NULL;
			break;

		default:
			SERRX(sockscf.resolveprotocol);
	}

	if (hostent != NULL)
		return hostent;

	if (sockscf.resolveprotocol != RESOLVEPROTOCOL_FAKE)
		slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
		function, name, hstrerror(h_errno));

	/* continue as if resolveprotocol is set to fake and hope that works. */

	hostent = &hostentmem;

	/* anything that fails from here is due to resource shortage. */
	h_errno = TRY_AGAIN;

	free(hostent->h_name);
	if ((hostent->h_name = strdup(name)) == NULL)
		return NULL;

	hostent->h_aliases	= aliases;
	hostent->h_addrtype	= af;

	if (hostent->h_addr_list == NULL) {
		/* * 2; NULL terminated and always only one valid entry (fake). */
		if ((hostent->h_addr_list
		= (char **)malloc(sizeof(hostent->h_addr_list) * 2)) == NULL)
			return NULL;
		hostent->h_addr_list[1] = NULL;
	}

	switch (af) {
		case AF_INET: {
			static char ipv4[INET_ADDRSTRLEN];

			hostent->h_length			= sizeof(ipv4);
			*hostent->h_addr_list	= ipv4;
			break;
		}

#if HAVE_IPV6_SUPPORT
		case AF_INET6: {
			static char ipv6[INET6_ADDRSTRLEN];

			hostent->h_length			= sizeof(ipv6);
			*hostent->h_addr_list	= ipv6;
			break;
		}
#endif /* HAVE_IPV6_SUPPORT */

		default:
			errno = ENOPROTOOPT;
			return NULL;
	}

	if ((ipindex.s_addr = socks_addfakeip(name)) == htonl(INADDR_NONE))
		return NULL;

	if (inet_pton(af, inet_ntoa(ipindex), *hostent->h_addr_list) != 1)
		return NULL;

	return hostent;
}

struct hostent *
Rgethostbyname(name)
	const char *name;
{

	return Rgethostbyname2(name, AF_INET);
}

#if HAVE_GETADDRINFO

int
Rgetaddrinfo(nodename, servname, hints, res)
	const char *nodename;
	const char *servname;
	const struct addrinfo *hints;
	struct addrinfo **res;
{
	const char *function = "Rgetaddrinfo()"; 
	struct addrinfo fakehints;
	struct in_addr ipindex;
	char addrstr[INET6_ADDRSTRLEN];
	char addrbuf[sizeof(struct in6_addr)];
	int fakeip_flag;
	int gaierr;

	clientinit();

	if (nodename != NULL)
		slog(LOG_DEBUG, "%s: %s", function, nodename);

	fakeip_flag = 1;

	if (nodename == NULL
	|| (hints != NULL && hints->ai_flags & AI_NUMERICHOST)) {
		fakeip_flag = 0;

	} else if (hints == NULL || hints->ai_protocol == PF_UNSPEC) {
#if HAVE_IPV6_SUPPORT
		if (inet_pton(AF_INET6, nodename, addrbuf) == 1
		||  inet_pton(AF_INET,  nodename, addrbuf) == 1)
			fakeip_flag = 0;
#else  /* HAVE_IPV6_SUPPORT */
		if (inet_pton(AF_INET,  nodename, addrbuf) == 1)
			fakeip_flag = 0;
#endif  /* HAVE_IPV6_SUPPORT */

#if HAVE_IPV6_SUPPORT
	} else if (hints->ai_protocol == PF_INET6) {
		if (inet_pton(AF_INET6, nodename, addrbuf) == 1)
			fakeip_flag = 0;
#endif  /* HAVE_IPV6_SUPPORT */

	} else if (hints->ai_protocol == PF_INET) {
		if (inet_pton(AF_INET,  nodename, addrbuf) == 1)
			fakeip_flag = 0;
	}

	switch (sockscf.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
		case RESOLVEPROTOCOL_UDP:
			gaierr = getaddrinfo(nodename, servname, hints, res);
			if (gaierr == 0 || !fakeip_flag)
				return gaierr;
			break;

		case RESOLVEPROTOCOL_FAKE:
			if (!fakeip_flag)
				return getaddrinfo(nodename, servname, hints, res);
			break;

		default:
			SERRX(sockscf.resolveprotocol);
	}

	if (!fakeip_flag || nodename == NULL)
		return EAI_NONAME;

	if (sockscf.resolveprotocol != RESOLVEPROTOCOL_FAKE) 
		slog(LOG_DEBUG, "%s: getaddrinfo(%s): %s",
		function, nodename, gai_strerror(gaierr));

	if ((ipindex.s_addr = socks_addfakeip(nodename)) == htonl(INADDR_NONE))
		return EAI_NONAME;
	strcpy(addrstr, inet_ntoa(ipindex));

	if (hints == NULL) {
		fakehints.ai_flags	= AI_NUMERICHOST;
		fakehints.ai_family	= PF_INET;
		fakehints.ai_socktype	= 0;
		fakehints.ai_protocol	= 0;
	} else {
		fakehints.ai_flags	= hints->ai_flags | AI_NUMERICHOST;
		fakehints.ai_family	= hints->ai_family;
		fakehints.ai_socktype	= hints->ai_socktype;
		fakehints.ai_protocol	= hints->ai_protocol;
	}
	fakehints.ai_addrlen	= 0;
	fakehints.ai_canonname	= NULL;
	fakehints.ai_addr	= NULL;
	fakehints.ai_next	= NULL;
	
	return getaddrinfo(addrstr, servname, &fakehints, res);
}

#endif /* HAVE_GETADDRINFO */

#if HAVE_GETIPNODEBYNAME
/*
 * Solaris appears to implement getaddrinfo() by calling
 * getipnodebyname(), but since they are in different libraries, they
 * must be implemented independently.
 *
 * XXX thread safety
 */

struct hostent *
Rgetipnodebyname2(name, af, flags, error_num)
	const char *name;
	int af;
	int flags;
        int *error_num;
{
	const char *function = "Rgetipnodebyname2()"; 
	char **addrlist;
	struct in_addr ipindex;
	struct hostent *hostent;

	/* needs to be done before getipnodebyname calls. */
	clientinit();

	slog(LOG_DEBUG, "%s: %s", function, name); 

	switch (sockscf.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
		case RESOLVEPROTOCOL_UDP:
		    	slog(LOG_DEBUG, "%s: using udp/tcp", function); 
			if ((hostent = getipnodebyname(name, af, flags, 
						       error_num)) != NULL)
			  return hostent;
			break;

		case RESOLVEPROTOCOL_FAKE:
		    	slog(LOG_DEBUG, "%s: using fake", function); 
			hostent = NULL;
			h_errno = NO_RECOVERY;
			break;

		default:
			SERRX(sockscf.resolveprotocol);
	}

	if (h_errno != NO_RECOVERY)
		return hostent;

	hostent = (struct hostent *) malloc(sizeof(struct hostent));

	/* anything that fails from here is due to resource shortage. */
	h_errno = TRY_AGAIN;

	if ((hostent->h_name = strdup(name)) == NULL) {
	        free(hostent);
		return NULL;
	}

	hostent->h_aliases	= NULL;
	hostent->h_addrtype	= af;

	/* * 2; NULL terminated. */
	if ((addrlist = (char **)malloc(sizeof(addrlist) * 2)) == NULL) {
	        free(hostent->h_name);
		free(hostent);
		return NULL;
	}

	switch (af) {
		case AF_INET: {
			static char ipv4[INET_ADDRSTRLEN];

			slog(LOG_DEBUG, "%s: AF_INET", function); 
			hostent->h_length = sizeof(ipv4);
			*addrlist = ipv4;
			break;
		}

		case AF_INET6: {
		        static char ipv6[INET6_ADDRSTRLEN];

			slog(LOG_DEBUG, "%s: AF_INET6", function); 
			hostent->h_length = sizeof(ipv6);
			*addrlist = ipv6;
			break;
		}


		default:
		    slog(LOG_DEBUG, "%s: AF_????? (%d)", function, af);
			errno = ENOPROTOOPT;
			free(hostent->h_name);
			free(hostent);
			return NULL;
	}

	if ((ipindex.s_addr = socks_addfakeip(name)) == htonl(INADDR_NONE)) {
	        free(hostent->h_name);
		free(*addrlist);
		free(addrlist);
		free(hostent);
     		return NULL;
	}

	switch (af) {
		case AF_INET: {
         memcpy(*addrlist, &ipindex.s_addr, sizeof(in_addr_t));
			break;
		}

		case AF_INET6: {
		   unsigned char ff[] = {0xff,0xff};
			memset(*addrlist, 0, 10);
			memcpy(*addrlist+10, ff, 2);
        	memcpy(*addrlist+12, &ipindex.s_addr, 
	      sizeof(in_addr_t));
			break;
		}


		default:
		        slog(LOG_DEBUG, "%s: AF_????? (%d)", function, af);
			errno = ENOPROTOOPT;
			free(hostent->h_name);
			free(*addrlist);
			free(addrlist);
			free(hostent);
			return NULL;
	}

	slog(LOG_DEBUG, "%s: after inet_pton (0x%x, %s)", function, (unsigned int)*addrlist, inet_ntoa(ipindex)); 
	hostent->h_addr_list = addrlist++;
	*addrlist = NULL;

	return hostent;
}

struct hostent *
Rgetipnodebyname(name, af, flags, error_num)
	const char *name;
	int af;
	int flags;
	int *error_num;
{
   struct hostent *hent;
	const char *function = "Rgetipnodebyname()";

	slog(LOG_DEBUG, "%s: %s, %d", function, name, af);

	if ((hent = Rgetipnodebyname2(name, af, flags, error_num)) == NULL)
	    *error_num = h_errno;

	return hent;
	    
}

void 
Rfreehostent(ptr)
        struct hostent *ptr;
{
        struct in_addr addr;
	
	if(socks_getfakeip(ptr->h_name, &addr)) {
              free(ptr->h_name);
	      free(*(ptr->h_addr_list));
	      free(ptr->h_addr_list);
	      free(ptr);
	} else freehostent(ptr);
}

#endif /* HAVE_GETIPNODEBYNAME */
