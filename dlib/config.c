/*
 * Copyright (c) 1997, 1998, 1999, 2000
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
"$Id: config.c,v 1.124 2000/06/09 10:45:17 karls Exp $";

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

void
genericinit(void)
{
	const char *function = "genericinit()";
	int i;

	if (!config.state.init) {
#if !HAVE_SETPROCTITLE
		/* create a backup to avoid setproctitle replacement overwriting it. */
		if ((__progname = strdup(__progname)) == NULL)
			serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
#endif /* !HAVE_SETPROCTITLE */
	}

	if (readconfig(config.option.configfile) != 0)
#if SOCKS_SERVER
		exit(EXIT_FAILURE);
#else
		return;
#endif

	newprocinit();

#if !HAVE_NO_RESOLVESTUFF
	res_init();
#endif /* !HAVE_NO_RESOLVSTUFF */

	switch (config.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
#if !HAVE_NO_RESOLVESTUFF
			_res.options |= RES_USEVC;
#else /* HAVE_NO_RESOLVESTUFF */
			SERRX(config.resolveprotocol);
#endif  /* HAVE_NO_RESOLVESTUFF */
			break;

		case RESOLVEPROTOCOL_UDP:
		case RESOLVEPROTOCOL_FAKE:
			break;

		default:
			SERRX(config.resolveprotocol);
	}

	if (!config.state.init)
		if (config.option.lbuf)
			for (i = 0; i < config.log.fpc; ++i)
				if (setvbuf(config.log.fpv[i], NULL, _IOLBF, 0) != 0)
					swarn("%s: setvbuf(_IOLBF)", function);

	config.state.init = 1;
}

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

	/* test port first since we have all info needed for that locally. */
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
	switch (config.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
		case RESOLVEPROTOCOL_UDP:
			doresolve = 1;
			break;

		case RESOLVEPROTOCOL_FAKE:
			doresolve = 0;
			break;

		default:
			SERRX(config.resolveprotocol);
	}

	/*
	 * The hard work begins.
	 */

	matched = 0;
	if (rule->atype == SOCKS_ADDR_IPV4 && address->atype == SOCKS_ADDR_DOMAIN) {
		/*
		 * match(rule.ipaddress, address.hostname)
		 * resolve address to ipaddress(es) and try to match each
		 *	resolved ipaddress against rule.
		 *		rule is in address->ipaddress(es)
		 */

		if (!doresolve)
			return 0;

		/* LINTED pointer casts may be troublesome */
		if ((hostent = gethostbyname(address->addr.domain)) == NULL) {
			slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
			function, address->addr.domain, hstrerror(h_errno));
			return 0;
		}

		if (addrisinlist(&rule->addr.ipv4.ip, &rule->addr.ipv4.mask,
		(const struct in_addr **)hostent->h_addr_list))
			matched = 1;
	}
	else if (rule->atype == SOCKS_ADDR_IPV4
	&& address->atype == SOCKS_ADDR_IPV4) {
		/*
		 * match(rule.ipaddress, address.ipaddress)
		 * try first a simple comparison, address against rule.
		 */
		if (addrareeq(&rule->addr.ipv4.ip, &rule->addr.ipv4.mask,
		&address->addr.ipv4))
			matched = 1;
		else {
			/*
			 * Didn't match.  If alias is set, try to resolve address
			 * to hostname(s), the hostname back to ipaddress(es) and
			 * then match those ipaddress(es) against rule.
			 *		rule is in address->hostname(s)->ipaddress(es)
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

					/* rule is in address->hostname(s)->ipaddress(es) */
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
		 * resolve both rule and address to ipaddress(es) and compare
		 * each ipaddress of resolved rule against each ipaddress of
		 * resolved address.
		 *		rule->ipaddress(es) is in address->ipaddress(es)
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
			 *	rule->ipaddress(es) is in address->ipaddress(es)
			 */

			for (i = 0, mask.s_addr = htonl(0xffffffff);
			hostent->h_addr_list != NULL && hostent->h_addr_list[i] != NULL;
			++i) {
				/* LINTED pointer casts may be troublesome */
				if (addrisinlist((const struct in_addr *)hostent->h_addr_list[i],
				&mask, (const struct in_addr **)addresshostent->h_addr_list)) {
					matched = 1;
					break;
				}
			}

			hostentfree(hostent);
		}

		if (!matched)
			return 0;
	}
	else if (rule->atype == SOCKS_ADDR_DOMAIN
	&& address->atype == SOCKS_ADDR_IPV4) {
		/*
		 * match(rule.hostname, address.ipaddress)
		 * If rule is not a domain, try resolving rule to ipaddress(es)
		 * and match against address.
		 *		address is in rule->ipaddress
		 *
		 * If no match, resolve address to hostname(s) and match each
		 * against rule.
		 *		rule is in address->hostname
		 *
		 * If still no match and alias is set, resolve all ipaddresses
		 * of all hostname(s) resolved from address back to hostname(s)
		 * and match them against rule.
		 *		rule is in address->hostname->ipaddress->hostname
		 */

		if (!doresolve)
			return 0;

		if (*rule->addr.domain != '.') {
			/* address is in rule->ipaddress */
			struct in_addr mask;

			if ((hostent = gethostbyname(rule->addr.domain)) == NULL) {
				slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
				function, rule->addr.domain, hstrerror(h_errno));
				return 0;
			}

			mask.s_addr = htonl(0xffffffff);
			if (addrisinlist(&address->addr.ipv4, &mask,
			(const struct in_addr **)hostent->h_addr_list))
				matched = 1;
		}

		if (!matched) {
			/* rule is in address->hostname */

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
			 * rule is in address->hostname->ipaddress->hostname.
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


#if SOCKS_CLIENT

struct route_t *
addroute(newroute)
	const struct route_t *newroute;
{
	const char *function = "addroute()";
	static const struct serverstate_t state;
	struct route_t *route;

	if ((route = (struct route_t *)malloc(sizeof(*route))) == NULL)
		serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
	*route = *newroute;

	/* check gateway. */

	/* if no command set, set all. */
	if (memcmp(&state.command, &route->gw.state.command, sizeof(state.command))
	== 0)
		memset(&route->gw.state.command, UCHAR_MAX,
		sizeof(route->gw.state.command));

	/* if no protocol set, set all. */
	if (memcmp(&state.protocol, &route->gw.state.protocol,
	sizeof(state.protocol)) == 0)
		memset(&route->gw.state.protocol, UCHAR_MAX,
		sizeof(route->gw.state.protocol));

	/* if no proxyprotocol set, set all except msproxy. */
	if (memcmp(&state.proxyprotocol, &route->gw.state.proxyprotocol,
	sizeof(state.proxyprotocol)) == 0) {
		memset(&route->gw.state.proxyprotocol, UCHAR_MAX,
		sizeof(route->gw.state.proxyprotocol));
		route->gw.state.proxyprotocol.msproxy_v2 = 0;
	}

	/* if no method set, set all we support. */
	if (route->gw.state.methodc == 0) {
		int *methodv = route->gw.state.methodv;
		int *methodc = &route->gw.state.methodc;

		methodv[(*methodc)++] = AUTHMETHOD_NONE;
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
	}

	if (config.route == NULL) {
		config.route = route;
		config.route->number = 1;
	}
	else {
		/* append rule to the end of list. */
		struct route_t *lastroute;

		lastroute = config.route;
		while (lastroute->next != NULL)
			lastroute = lastroute->next;

		route->number = lastroute->number + 1;
		lastroute->next = route;
	}
	route->next = NULL;

	return route;
}


void
showroute(route)
	const struct route_t *route;
{
	char hstring[MAXSOCKSHOSTSTRING];
	char addr[MAXRULEADDRSTRING];

	slog(LOG_INFO, "route #%d", route->number);

	slog(LOG_INFO, "src: %s",
	ruleaddress2string(&route->src, addr, sizeof(addr)));

	slog(LOG_INFO, "dst: %s",
	ruleaddress2string(&route->dst, addr, sizeof(addr)));

	slog(LOG_INFO, "gateway: %s",
	sockshost2string(&route->gw.host, hstring, sizeof(hstring)));

	showstate(&route->gw.state);
}


struct route_t *
socks_getroute(req, src, dst)
	const struct request_t *req;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
{
	struct route_t *route;
	int protocol;

#if SOCKS_CLIENT
	clientinit();
#endif

	for (route = config.route; route != NULL; route = route->next) {
		if (route->state.bad)
			continue; /* XXX code to retry and remove bad status when ok. */

		switch (req->version) {
			case SOCKS_V4:
				if (!route->gw.state.proxyprotocol.socks_v4)
					continue;

				switch (req->host.atype) {
					case SOCKS_ADDR_IPV4:
						break;

					case SOCKS_ADDR_IPV6:
					case SOCKS_ADDR_DOMAIN:
						continue; /* not failure, just checking. */

					default:
						SERRX(req->host.atype); /* failure, nothing else exists. */
				}
				break;

			case SOCKS_V5:
				if (!route->gw.state.proxyprotocol.socks_v5)
					continue;

				switch (req->host.atype) {
					case SOCKS_ADDR_IPV4:
					case SOCKS_ADDR_IPV6:
					case SOCKS_ADDR_DOMAIN:
						break;

					default:
						SERRX(req->host.atype); /* failure, nothing else exists. */
				}
				break;

			case MSPROXY_V2:
				if (!route->gw.state.proxyprotocol.msproxy_v2)
					continue;
				break;

			default:
				SERRX(req->version);
		}

		switch (req->command) {
			case SOCKS_BIND:
				if (!route->gw.state.command.bind)
					continue;

				if (req->host.atype == SOCKS_ADDR_IPV4
				&&  req->host.addr.ipv4.s_addr == htonl(0))
					if (req->version == MSPROXY_V2)
						; /* supports binding wildcard */
					else if (!route->gw.state.extension.bind)
						continue;
				break;

			case SOCKS_CONNECT:
				if (!route->gw.state.command.connect)
					continue;
				break;

			case SOCKS_UDPASSOCIATE:
				if (!route->gw.state.command.udpassociate)
					continue;
				break;

			default:
				SERRX(req->command);
		}

		/* server supports protocol? */
		switch (req->command) {
			case SOCKS_BIND:
			case SOCKS_CONNECT:
				if (!route->gw.state.protocol.tcp)
					continue;
				protocol = SOCKS_TCP;
				break;

			case SOCKS_UDPASSOCIATE:
				if (!route->gw.state.protocol.udp)
					continue;
				protocol = SOCKS_UDP;
				break;

			default:
				SERRX(req->command);
		}

		if (src != NULL)
			if (!addressmatch(&route->src, src, protocol, 0))
				continue;

		if (dst != NULL)
			if (!addressmatch(&route->dst, dst, protocol, 0))
				continue;

		if (route->state.direct)
			return NULL; /* don't use any route, connect directly. */

		break;	/* all matched */
	}

	return route;
}


struct route_t *
socks_connectroute(s, packet, src, dst)
	int s;
	struct socks_t *packet;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
{
	const char *function = "socks_connectroute()";
	int sdup, current_s, errno_s;
	struct route_t *route;

	/*
	 * This is a little tricky since we attempt to support trying
	 * more than one socksserver.  If the first one fails, we try
	 * the next, etc.  Ofcourse, if connect() on one socket fails,
	 * that socket can no longer be used, so we need to be able to
	 * copy/dup the original socket as much as possible.  Later,
	 * if it turned out a connection failed and we had to use a
	 * different socket than the orignal 's', we try to dup the
	 * differently numbered socket to 's' and hope the best.
	 *
	 * sdup:			copy of the original socket.  Need to create this
	 *					before the first connectattempt since the connectattempt
	 *				   could prevent us from doing it later, depending on failure
	 *					reason.
	 *
	 * current_s:	socket to use for next connection attempt.  For the
	 *					first attempt this is 's'.
	 */

	errno			= 0; /* let caller differentiate between missing route and not.*/
	current_s	= s;
	sdup			= -1;

	while ((route = socks_getroute(&packet->req, src, dst)) != NULL) {
		char hstring[MAXSOCKSHOSTSTRING];

		/* inside loop since if no route, no need for it. */
		if (sdup == -1)
			sdup = socketoptdup(s);

		if (current_s == -1)
			if ((current_s = socketoptdup(sdup == -1 ? s : sdup)) == -1)
				return NULL;

		slog(LOG_DEBUG, "%s: trying route #%d (%s)",
		function, route->number,
		sockshost2string(&route->gw.host, hstring, sizeof(hstring)));

		if (socks_connect(current_s, &route->gw.host) == 0)
			break;
		else
			/*
			 * Check whether the error indicates bad socksserver or
			 * something else.
			 */
			if (errno == EINPROGRESS) {
				SASSERTX(current_s == s);
				break;
			}
			else if (errno == EADDRINUSE) {
				/* see Rbind() for explanation. */
				SASSERTX(current_s == s);
				route = NULL;
				break;
			}
			else {
				swarn("%s: socks_connect(%s)",
				function, sockshost2string(&route->gw.host, hstring,
				sizeof(hstring)));
				socks_badroute(route);
				close(current_s);
				current_s = -1;
		}
	}

	errno_s = errno;

	if (sdup != -1)
		close(sdup);

	if (current_s != s && current_s != -1)	{
		/* created a new socket for connect, need to make it same descriptor #. */
		if (dup2(current_s, s) == -1) {
			close(current_s);
			return NULL;
		}
		close(current_s);

#if SOCKS_SERVER && HAVE_LIBWRAP
		if ((current_s = fcntl(s, F_GETFD, 0)) == -1
		|| fcntl(s, F_SETFD, current_s | FD_CLOEXEC) == -1)
			swarn("%s: fcntl(F_GETFD/F_SETFD)", function);
#endif
	}

	if (route != NULL) {
		static int init;

		packet->gw = route->gw;

		/* need to set up misc. crap for msproxy stuff. */
		if (!init && route->gw.state.proxyprotocol.msproxy_v2) {
			if (msproxy_init() != 0)
				;	/* yes, then what? */
			init = 1;
		}
	}

	errno = errno_s;
	return route;
}

void
socks_badroute(route)
	struct route_t *route;
{
	const char *function = "socks_badroute()";

	slog(LOG_DEBUG, "%s: badrouting route #%d", function, route->number);
	route->state.bad = 1;
}


struct request_t *
socks_requestpolish(req, src, dst)
	struct request_t *req;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
{
	const char *function = "socks_requestpolish()";
	unsigned char version;

	if (socks_getroute(req, src, dst) != NULL)
		return req;

	switch (req->command) {
		case SOCKS_BIND:
		case SOCKS_CONNECT:
			break;

		case SOCKS_UDPASSOCIATE:
			SERRX(req->command);	/* currently not implemented, shouldn't happen. */
			/* NOTREACHED */

		default:
			SERRX(req->command);
	}

	/* unsupported version? */
	switch (req->version) {
		case SOCKS_V4:
			req->version = SOCKS_V5;
			break;

		case SOCKS_V5:
			req->version = SOCKS_V4;
			break;
	}

	if (socks_getroute(req, src, dst) != NULL)
		return req;

	SASSERTX(req->version != MSPROXY_V2); /* never gets set outside function. */
	version = req->version;
	req->version = MSPROXY_V2;
	if (socks_getroute(req, src, dst) != NULL)
		return req;
	req->version = version;

	switch (req->command) {
		case SOCKS_BIND:
			if (req->host.addr.ipv4.s_addr == htonl(0)) {
				const in_port_t originalport = req->host.port;
				const int originalversion = req->version;

				/* attempting to use bind extension, can we retry without it? */
				/* LINTED pointer casts may be troublesome */
				if (ADDRISBOUND(config.state.lastconnect)) {

					fakesockaddr2sockshost(&config.state.lastconnect, &req->host);

					/*
					 * v4 and v5 differ in how portnumber is treated
					 * so we need to be a little smarter than just returning
					 * the result of the next socks_requestpolish()
					 * while we still have the original portnumber.
					 */

					switch (req->version) {
						case SOCKS_V4:
							/* LINTED pointer casts may be troublesome */
							req->host.port = ((struct sockaddr_in *)
							&config.state.lastconnect)->sin_port;
							break;

						case SOCKS_V5:
							/* only wants ip address. */
							req->host.port = originalport;
							break;

						default:
							SERRX(req->version);
					}

					if (socks_requestpolish(req, src, dst) == NULL)
						return NULL;

					/*
					 * else, it may be that socks_requestpolish() was
					 * forced to change req.version to succeed, we then
					 * need to change req->host.port due to difference in
					 * v4 and v5 semantics.
					*/

					if (req->version != originalversion) { /* version changed. */
						/* currently it can only change from 4 to 5, or 5 to 4. */
						switch (req->version) {
							case SOCKS_V4:
								/* LINTED pointer casts may be troublesome */
								req->host.port = ((struct sockaddr_in *)
								&config.state.lastconnect)->sin_port;
								break;

							case SOCKS_V5:
								req->host.port = originalport;
								break;

							default:
								SERRX(req->version);
						}

					}

					return socks_requestpolish(req, src, dst);
				}
				else
					slog(LOG_DEBUG,
					"%s: couldn't find route for bind, try enabling bind extension?",
					function);
			}
			break;
	}

	return NULL;
}

#endif /* SOCKS_CLIENT */

void
showstate(state)
	const struct serverstate_t *state;
{
	char buf[1024];
	size_t bufused;

	bufused = snprintf(buf, sizeof(buf), "command(s): ");
	if (state->command.bind)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_BINDs);
	if (state->command.bindreply)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_BINDREPLYs);
	if (state->command.connect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_CONNECTs);
	if (state->command.udpassociate)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_UDPASSOCIATEs);
	if (state->command.udpreply)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_UDPREPLYs);
	slog(LOG_INFO, buf);

	bufused = snprintf(buf, sizeof(buf), "extension(s): ");
	if (state->extension.bind)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "bind");
	slog(LOG_INFO, buf);

	bufused = snprintf(buf, sizeof(buf), "protocol(s): ");
	if (state->protocol.tcp)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		PROTOCOL_TCPs);
	if (state->protocol.udp)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		PROTOCOL_UDPs);
	slog(LOG_INFO, buf);

	showmethod(state->methodc, state->methodv);

	bufused = snprintf(buf, sizeof(buf), "proxyprotocol(s): ");
	if (state->proxyprotocol.socks_v4)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "socks v4, ");
	if (state->proxyprotocol.socks_v5)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "socks v5, ");
	if (state->proxyprotocol.msproxy_v2)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "msproxy v2");
	slog(LOG_INFO, buf);
}

void
showmethod(methodc, methodv)
	int methodc;
	const int *methodv;
{
	int i;
	char buf[1024];
	size_t bufused;

	bufused = snprintf(buf, sizeof(buf), "method(s): ");
	for (i = 0; i < methodc; ++i)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		method2string(methodv[i]));
	slog(LOG_INFO, buf);
}
