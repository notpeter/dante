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
"$Id: addressmatch.c,v 1.10 2005/05/28 17:12:37 michaels Exp $";

__BEGIN_DECLS

static int
addrisinlist __P((const struct in_addr *addr, const struct in_addr *mask,
					  const struct in_addr **list));
/*
 * Compares "addr" bitwise anded with "mask" against each element in
 * "list" bitwise anded with "mask".  "list" is NULL terminated.
 * Returns:
 *		If "list" contains a element matching "addr" and "mask": true
 *		else: false
 */

static int
addrareeq __P((const struct in_addr *addr, const struct in_addr *mask,
					const struct in_addr *against));
/*
 * Compares "addr" bitwise anded with "mask" against "against" bitwise
 * anded with "mask".
 * Returns:
 *		If "against" matches "addr" and "mask": true
 *		else: false
 */

static int
hostisinlist __P((const char *host, const char **list));
/*
 * Compares "host" against each element in "list", which is NULL
 * terminated.
 * Note that if "host" starts with a dot, it will match "list" if the
 * last part of "list" matches the part after the dot in "host".
 * Returns:
 *		If "list" contains a element matching "host": true
 *		else: false
 */

static int
hostareeq __P((const char *domain, const char *remotedomain));
/*
 * Compares the rulegiven domain "domain" against "remotedomain".
 * Note that if "domain" starts with a dot, it will match
 * "remotedomain" if the last part of "remotedomain" matches
 * the part after the dot in "domain".
 * Returns:
 *		on match: true
 *		else: false
 */


__END_DECLS

int
addressmatch(rule, address, protocol, alias)
	const struct ruleaddress_t *rule;
	const struct sockshost_t *address;
	int protocol;
	int alias;
{
	const char *function = "addressmatch()";
	struct hostent *hostent;
	in_port_t ruleport;
	int matched, doresolve;
	char rstring[MAXRULEADDRSTRING], astring[MAXSOCKSHOSTSTRING];

	slog(LOG_DEBUG, "%s: %s, %s, %s, %d",
	function,
	ruleaddress2string(rule, rstring, sizeof(rstring)),
	sockshost2string(address, astring, sizeof(astring)),
	protocol2string(protocol),
	alias);

	/* test port first since we always have all info needed for that locally. */
	switch (protocol) {
		case SOCKS_TCP:
			ruleport = rule->port.tcp;
			break;

		case SOCKS_UDP:
			ruleport = rule->port.udp;
			break;

		default:
			SERRX(protocol);
	}

	switch (rule->operator) {
		case none:
			break;

		case eq:
			if (address->port == ruleport)
				break;
			return 0;

		case neq:
			if (address->port != ruleport)
				break;
			return 0;

		case ge:
			if (ntohs(address->port) >= ntohs(ruleport))
				break;
			return 0;

		case le:
			if (ntohs(address->port) <= ntohs(ruleport))
				break;
			return 0;

		case gt:
			if (ntohs(address->port) > ntohs(ruleport))
				break;
			return 0;

		case lt:
			if (ntohs(address->port) < ntohs(ruleport))
				break;
			return 0;

		case range:
			if (ntohs(address->port) >= ntohs(ruleport)
			&&  ntohs(address->port) <= ntohs(rule->portend))
				break;
			return 0;

		default:
			SERRX(rule->operator);
	}

	/* only needed for client really... */
	switch (sockscf.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
		case RESOLVEPROTOCOL_UDP:
			doresolve = 1;
			break;

		case RESOLVEPROTOCOL_FAKE:
			doresolve = 0;
			break;

		default:
			SERRX(sockscf.resolveprotocol);
	}

	/*
	 * The hard work begins.
	 */

	matched = 0;

	/*
	 * if mask of rule is 0, it should match anything.  Try that first
	 * so we can save lots of potentioally heavy work.
	 */
	if (rule->atype == SOCKS_ADDR_IPV4 && (rule->addr.ipv4.mask.s_addr == 0))
		matched = 1;
	else if (rule->atype == SOCKS_ADDR_IPV4
	&& address->atype == SOCKS_ADDR_DOMAIN) {
		/*
		 * match(rule.ipaddress, address.hostname)
		 * resolve address to ipaddress(es) and try to match each
		 *	resolved IP address against rule.
		 *		rule isin address->ipaddress(es)
		 *		.
		 */

		if (!doresolve)
			return 0;

		/* LINTED pointer casts may be troublesome */
		if ((hostent = gethostbyname(address->addr.domain)) == NULL) {
			slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
			function, address->addr.domain, hstrerror(h_errno));
			return 0;
		}

		matched = addrisinlist(&rule->addr.ipv4.ip, &rule->addr.ipv4.mask,
		(const struct in_addr **)hostent->h_addr_list);
	}
	else if (rule->atype == SOCKS_ADDR_IPV4
	&& address->atype == SOCKS_ADDR_IPV4) {
		/*
		 * match(rule.ipaddress, address.ipaddress)
		 * try first a simple comparison, address against rule.
		 */
		if (!(matched = addrareeq(&rule->addr.ipv4.ip, &rule->addr.ipv4.mask,
		&address->addr.ipv4))) {
			/*
			 * Didn't match.  If alias is set, try to resolve address
			 * to hostname(s), the hostname back to IP address(es) and
			 * then match those IP address(es) against rule.
			 *		rule isin address->hostname(s)->ipaddress(es)
			 *		.
			 */

			if (!doresolve)
				return 0;

			if (alias) {
				char *nexthost;
				int i;

				/* LINTED pointer casts may be troublesome */
				if ((hostent = gethostbyaddr((const char *)&address->addr.ipv4,
				sizeof(address->addr.ipv4), AF_INET)) == NULL) {
					slog(LOG_DEBUG, "%s: %s: %s",
					function, inet_ntoa(address->addr.ipv4), hstrerror(h_errno));
					return 0;
				}

				if ((hostent = hostentdup(hostent)) == NULL) {
					swarnx("%s: hostentdup()", function);
					return 0;
				}

				nexthost = hostent->h_name;
				i = 0;
				do {
					struct hostent *iphostent;

					/* iphostent = address->hostname(s)->ipaddress(es) */
					if ((iphostent = gethostbyname(nexthost)) == NULL) {
						slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
						function, nexthost, hstrerror(h_errno));
						continue;
					}

					/* rule isin address->hostname(s)->ipaddress(es) */
					if (addrisinlist(&rule->addr.ipv4.ip, &rule->addr.ipv4.mask,
					(const struct in_addr **)iphostent->h_addr_list)) {
						matched = 1;
						break;
					}
				} while (hostent->h_aliases != NULL
				&& (nexthost = hostent->h_aliases[i++]) != NULL);

				hostentfree(hostent);
			}

			if (!matched)
				return 0;
		}
	}
	else if (rule->atype == SOCKS_ADDR_DOMAIN
	&& address->atype == SOCKS_ADDR_DOMAIN) {
		/*
		 * match(rule.hostname, address.hostname)
		 * Try simple match first.
		 *
		 * If no go and rule is a hostname rather than a domain,
		 * resolve both rule and address to IP address(es) and compare
		 * each IP address of resolved rule against each IP address of
		 * resolved address.
		 *		rule->ipaddress(es) isin address->ipaddress(es)
		 *		.
		 *
		 */
		if (hostareeq(rule->addr.domain, address->addr.domain))
			matched = 1;
		else if (doresolve && *rule->addr.domain != '.') {
			struct hostent *addresshostent;
			struct in_addr mask;
			int i;

			if ((hostent = gethostbyname(rule->addr.domain)) == NULL) {
					slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
					function, rule->addr.domain, hstrerror(h_errno));
					return 0;
			}

			if ((hostent = hostentdup(hostent)) == NULL) {
				swarnx("%s: hostentdup()", function);
				return 0;
			}

			if ((addresshostent = gethostbyname(address->addr.domain)) == NULL) {
				slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
				function, address->addr.domain, hstrerror(h_errno));
				hostentfree(hostent);
				return 0;
			}

			/*
			 *	rule->ipaddress(es) isin address->ipaddress(es)
			 */

			if (hostent->h_addr_list == NULL) {
				hostentfree(hostent);
				return 0;
			}

			mask.s_addr = htonl(0xffffffff);
			for (i = 0; !matched && hostent->h_addr_list[i] != NULL; ++i)
				/* LINTED pointer casts may be troublesome */
				matched
				= addrisinlist((const struct in_addr *)hostent->h_addr_list[i],
				&mask, (const struct in_addr **)addresshostent->h_addr_list);

			hostentfree(hostent);
		}

		if (!matched)
			return 0;
	}
	else if (rule->atype == SOCKS_ADDR_DOMAIN
	&& address->atype == SOCKS_ADDR_IPV4) {
		/*
		 * match(rule.hostname, address.ipaddress)
		 * If rule is not a domain, try resolving rule to IP address(es)
		 * and match against address.
		 *		address isin rule->ipaddress
		 *		.
		 *
		 * If no match, resolve address to hostname(s) and match each
		 * against rule.
		 *		rule isin address->hostname
		 *		.
		 *
		 * If still no match and alias is set, resolve all IP addresses
		 * of all hostname(s) resolved from address back to hostname(s)
		 * and match them against rule.
		 *		rule isin address->hostname->ipaddress->hostname
		 *		.
		 */

		if (!doresolve)
			return 0;

		if (*rule->addr.domain != '.') {
			/* address isin rule->ipaddress */
			struct in_addr mask;

			if ((hostent = gethostbyname(rule->addr.domain)) == NULL) {
				slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
				function, rule->addr.domain, hstrerror(h_errno));
				return 0;
			}

			mask.s_addr = htonl(0xffffffff);
			matched = addrisinlist(&address->addr.ipv4, &mask,
			(const struct in_addr **)hostent->h_addr_list);
		}

		if (!matched) {
			/* rule isin address->hostname */

			/* LINTED pointer casts may be troublesome */
			if ((hostent = gethostbyaddr((const char *)&address->addr.ipv4,
			sizeof(address->addr.ipv4), AF_INET)) == NULL) {
				slog(LOG_DEBUG, "%s: gethostbyaddr(%s): %s",
				function, inet_ntoa(address->addr.ipv4), hstrerror(h_errno));
				return 0;
			}

			if (hostareeq(rule->addr.domain, hostent->h_name)
			||  hostisinlist(rule->addr.domain, (const char **)hostent->h_aliases))
				matched = 1;
		}

		if (!matched && alias) {
			/*
			 * rule isin address->hostname->ipaddress->hostname.
			 * hostent is already address->hostname due to above.
			 */
			char *nexthost;
			int i;

			if ((hostent = hostentdup(hostent)) == NULL) {
				swarnx("%s: hostentdup()", function);
				return 0;
			}

			nexthost = hostent->h_name;
			i = 0;
			do {
				int ii;
				struct hostent *host;

				/* host; address->hostname->ipaddress */
				if ((host = gethostbyname(nexthost)) == NULL) {
					slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
					function, nexthost, hstrerror(h_errno));
					continue;
				}

				if ((host = hostentdup(host)) == NULL) {
					swarnx("%s: hostentdup()", function);
					break;
				}

				/* LINTED pointer casts may be troublesome */
				for (ii = 0;
				host->h_addr_list != NULL && host->h_addr_list[ii] != NULL;
				++ii) {
					struct hostent *ip;

					/* ip; address->hostname->ipaddress->hostname */
					if ((ip = gethostbyaddr(host->h_addr_list[ii],
					sizeof(struct in_addr), AF_INET)) == NULL) {
						/* LINTED pointer casts may be troublesome */
						slog(LOG_DEBUG, "%s: gethostbyaddr(%s): %s",
						function, inet_ntoa(*(struct in_addr *)host->h_addr_list[ii]),
						hstrerror(h_errno));
						continue;
					}

					if (hostareeq(rule->addr.domain, ip->h_name)
					||  hostisinlist(rule->addr.domain,
					(const char **)ip->h_aliases)) {
						matched = 1;
						break;
					}
				}

				hostentfree(host);
			} while (!matched && hostent->h_aliases != NULL
			&& (nexthost = hostent->h_aliases[i++]) != NULL);

			hostentfree(hostent);
		}
		if (!matched)
			return 0;
	}
	else if (rule->atype == SOCKS_ADDR_IFNAME) {
		/*
		 * Like ipaddress, just call it for each IP address of interface.
		 *
		 * match(rule.ifname2ipaddress, address)
		 */
		 int i;
		 struct sockaddr sa;

		 i = 0;
		 while (!matched && ifname2sockaddr(rule->addr.ifname, i++, &sa)
		 != NULL) {
			struct ruleaddress_t ruleaddr;

			ruleaddr = *rule;	/* identical except addr field. */
			ruleaddr.atype							= SOCKS_ADDR_IPV4;
			/* LINTED pointer casts may be troublesome */
			ruleaddr.addr.ipv4.ip				= TOIN(&sa)->sin_addr;
			ruleaddr.addr.ipv4.mask.s_addr	= htonl(0xffffffff);

			matched = addressmatch(&ruleaddr, address, protocol, alias);
		}
	}
	else
		SERRX(0);

	return matched;
}

static int
addrisinlist(addr, mask, list)
	const struct in_addr *addr;
	const struct in_addr *mask;
	const struct in_addr **list;
{

	if (list == NULL)
		return 0;

	while (*list != NULL)
		if (addrareeq(addr, mask, *list))
			return 1;
		else
			++list;
	return 0;
}

static int
addrareeq(addr, mask, against)
	const struct in_addr *addr;
	const struct in_addr *mask;
	const struct in_addr *against;
{

	if ((addr->s_addr & mask->s_addr) == (against->s_addr & mask->s_addr))
		return 1;
	return 0;
}

static int
hostisinlist(host, list)
	const char *host;
	const char **list;
{

	if (list == NULL)
		return 0;

	while (*list != NULL)
		if (hostareeq(host, *list))
			return 1;
		else
			++list;
	return 0;
}

static int
hostareeq(domain, remotedomain)
	const char *domain;
	const char *remotedomain;
{
	const int domainlen = strlen(domain);
	const int remotedomainlen = strlen(remotedomain);

	if	(*domain == '.')	{ /* match everything ending in domain */
		if (domainlen - 1 > remotedomainlen)
			return 0;	/* address to compare against too short, can't match. */
		return strcasecmp(domain + 1,
		remotedomain + (remotedomainlen - (domainlen - 1))) == 0;
	}
	else /* need exact match. */
		return strcasecmp(domain, remotedomain) == 0;
}
