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
"$Id: config.c,v 1.103 1999/05/13 14:09:18 karls Exp $";

__BEGIN_DECLS

static int
hostcmp __P((const char *domain, const char *remotedomain));

__END_DECLS

void
genericinit(void)
{
	const char *function = "init()";
	int i;

	if (!config.state.init) {
#if !HAVE_SETPROCTITLE
		/* create a backup to avoid having setproctitle overwriting it */
		if ((__progname = strdup(__progname)) == NULL)
			serrx(EXIT_FAILURE, NOMEM);
#endif /* !HAVE_SETPROCTITLE */
	}

	if (readconfig(config.option.configfile) != 0)
#if SOCKS_SERVER
		exit(EXIT_FAILURE);
#else
		return;
#endif

	initlog();

#if !HAVE_NO_RESOLVESTUFF
	res_init();
#endif /* !HAVE_NO_RESOLVSTUFF */

	if (*config.domain == NUL) {

#if HAVE_NO_RESOLVESTUFF
		strncpy(config.domain, SOCKS_DOMAINNAME, sizeof(config.domain));
#else /* !HAVE_NO_RESOLVESTUFF */
		strncpy(config.domain, _res.defdname, sizeof(config.domain));
#endif /* !HAVE_NO_RESOLVESTUFF */

		if (config.domain[sizeof(config.domain) - 1] != NUL) {
			swarnx("%s: local domainname too long, truncated", function);
			config.domain[sizeof(config.domain) - 1] = NUL;
		}
	}

	switch (config.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
#if HAVE_NO_RESOLVESTUFF
			swarnx("%s: resolveprotocol keyword not supported for you", function);
#else /* !HAVE_NO_RESOLVESTUFF */
			_res.options |= RES_USEVC;
#endif /* !HAVE_NO_RESOLVESTUFF */
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
	int matched = 0;

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

	/*
	 * Does address match too?
	 * Logic:
	 *		addressmatch(ip, host, alias):
	 *			resolve host to ip
	 *			addressmatch(ip, each ipmember of resolved host, 0)
	 *
	 *		addressmatch(ip1, ip2, alias):
	 *			if alias, addressmatch(ip1, each ipmember of resolved ip2, 0)
	 *
	 *		addressmatch(host1, host2, alias):
	 *			if alias, addressmatch(host1, each hostmember of resolved host2, 0)
	 *
	 *		addressmatch(host, ip, alias):
	 *			resolve ip
	 *			addressmatch(host, each hostmember of ip, 0)
	*/

	/* try for exact match first, avoid gethostby*() call. */
	switch (rule->atype) {
		case SOCKS_ADDR_IPV4:
			if (address->atype == rule->atype) {
				if ((address->addr.ipv4.s_addr & rule->addr.ipv4.mask.s_addr)
				==  (rule->addr.ipv4.ip.s_addr & rule->addr.ipv4.mask.s_addr)) {
					matched = 1;
					break;
				}
			}
			else if (address->atype == SOCKS_ADDR_DOMAIN)
				alias = 1; /* must resolve. */
			break;

		case SOCKS_ADDR_DOMAIN:
			if (address->atype == rule->atype) {
				if (hostcmp(rule->addr.domain, address->addr.domain) == 0) {
					matched = 1;
					break;
				}
			}
			else if (address->atype == SOCKS_ADDR_IPV4)
				alias = 1; /* must resolve. */
			break;

		default:
			SERRX(rule->atype);
	}

	if (!matched) { /* no exact match, try to resolve and match against that? */
		switch (config.resolveprotocol) {
			case RESOLVEPROTOCOL_TCP:
			case RESOLVEPROTOCOL_UDP:
				break;

			case RESOLVEPROTOCOL_FAKE:
				alias = 0;	/* can't resolve. */
				break;

			default:
				SERRX(config.resolveprotocol);
		}

		if (alias) {
			switch (address->atype) {
				case SOCKS_ADDR_IPV4:
					/* LINTED pointer casts may be troublesome */
					if ((hostent = gethostbyaddr((const char *)&address->addr.ipv4,
					sizeof(address->addr.ipv4), AF_INET)) == NULL) {
						slog(LOG_DEBUG, "%s: %s: %s",
						function, inet_ntoa(address->addr.ipv4), hstrerror(h_errno));
						return 0;
					}
					break;

				case SOCKS_ADDR_DOMAIN:
					if ((hostent = gethostbyname(address->addr.domain)) == NULL) {
						slog(LOG_DEBUG, "%s: %s: %s",
						function, address->addr.domain, hstrerror(h_errno));
						return 0;
					}
					break;

				default:
					SERRX(address->atype);
			}

			/* resolved, try to match. */
			switch (rule->atype) {
				case SOCKS_ADDR_IPV4: {
					struct in_addr *ip;
					struct sockaddr_in addr;
					struct sockshost_t newaddress;
					int i;

					bzero(&addr, sizeof(addr));
					addr.sin_family	= AF_INET;
					addr.sin_port		= address->port;

					/* LINTED pointer casts may be troublesome */
					for (i = 0; (ip = (struct in_addr *)hostent->h_addr_list[i])
					!= NULL; ++i) {

						addr.sin_addr = *ip;
						/* LINTED pointer casts may be troublesome */
						sockaddr2sockshost((struct sockaddr *)&addr, &newaddress);

						if (addressmatch(rule, &newaddress, protocol, 0)) {
							matched = 1;
							break;
						}
					}
					break;
				}

				case SOCKS_ADDR_DOMAIN: {
					char *remotedomain;
					struct sockshost_t newaddress;
					int i;

					newaddress.atype	= SOCKS_ADDR_DOMAIN;
					newaddress.port	= address->port;
					remotedomain = hostent->h_name;

					i = 0;
					do {
						strncpy(newaddress.addr.domain, remotedomain,
						sizeof(newaddress.addr.domain) - 1);
						newaddress.addr.domain[sizeof(newaddress.addr.domain) - 1]
						= NUL;

						if (addressmatch(rule, &newaddress, protocol, 0)) {
							matched = 1;
							break;
						}
					} while ((remotedomain = hostent->h_aliases[i++]) != NULL);
					break;
				}

				default:
					SERRX(rule->atype);
			}
		}
	}

	return matched;
}

static int
hostcmp(domain, remotedomain)
	const char *domain;
	const char *remotedomain;
{
	const int domainlen = strlen(domain);
	int remotedomainlen;
	char buf[MAXHOSTNAMELEN];

	/* if no domain, assume local host and append ours. */
	if (strchr(remotedomain, '.') == NULL) {
		snprintf(buf, sizeof(buf), "%s.%s",
		remotedomain, config.domain);
		remotedomain = buf;
	}
	remotedomainlen = strlen(remotedomain);

	if	(*domain == '.')	{ /* match everything ending in domain */
		if (domainlen - 1 > remotedomainlen)
			return 1;	/* address to compare against too short, can't match. */
		return strcasecmp(domain + 1,
		remotedomain + (remotedomainlen - (domainlen - 1)));
	}
	else /* need exact match. */
		return strcasecmp(domain, remotedomain);
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
		serrx(1, "%s: %s", function, NOMEM);

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
		char *methodv = route->gw.state.methodv;
		unsigned char *methodc = &route->gw.state.methodc;

		methodv[*methodc++] = AUTHMETHOD_NONE;
		methodv[*methodc++] = AUTHMETHOD_UNAME;
	}

	if (config.route == NULL) {
		config.route = route;
		config.route->number = 1;
	}
	else {
		/* append this rule to the end of our list. */
		struct route_t *lastroute;

		lastroute = config.route;
		while (lastroute->next != NULL)
			lastroute = lastroute->next;

		lastroute->next = route;
		route->number = lastroute->number + 1;
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
	int current_s;
	struct route_t *route;

	errno = 0;		/* let caller differentiate between missing route and not.	*/
	current_s = s; /* we may have other gateways to try if first found fails.	*/

	while ((route = socks_getroute(&packet->req, src, dst)) != NULL) {
		char hstring[MAXSOCKSHOSTSTRING];

		if (current_s != s) {
			if (current_s != -1)
				close(current_s);

			if ((current_s = socketoptdup(s)) == -1)
				return NULL;
		}

		slog(LOG_DEBUG, "%s: trying route #%d (%s)",
		function, route->number,
		sockshost2string(&route->gw.host, hstring, sizeof(hstring)));

		if (socks_connect(current_s, &route->gw.host) == 0)
			break;

		if (errno == EINPROGRESS) {
			SASSERTX(current_s == s);
			break;
		}

		switch (errno) {
			case EADDRINUSE:
				/* see Rbind() for explanation. */
				SASSERTX(current_s == s);
				return NULL;

			default:
				swarn("%s: socks_connect(%s)",
				function, sockshost2string(&route->gw.host, hstring,
				sizeof(hstring)));
				socks_badroute(route);
				current_s = -1;
		}
	}

	if (current_s != -1 && current_s != s)	{
		/* created a new socket for connect, need to make it same descriptor #. */
		if (dup2(current_s, s) == -1) {
			close(current_s);
			return NULL;
		}
		close(current_s);
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

	return route;
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
				/* attempting to use bind extension, can we retry without it. */

				/* LINTED */
				if (ADDRISBOUND(config.state.lastconnect)) {
					/* LINTED pointer casts may be troublesome */
					req->host.addr.ipv4
					= ((struct sockaddr_in *)&config.state.lastconnect)->sin_addr;

					switch (req->version) {
						case SOCKS_V4:
							/* LINTED pointer casts may be troublesome */
							req->host.port = ((struct sockaddr_in *)
							&config.state.lastconnect)->sin_port;
							break;

						case SOCKS_V5:
							/* only wants ip address. */
							break;

						default:
							SERRX(req->version);
					}

					return socks_requestpolish(req, src, dst);
				}
				else
					slog(LOG_DEBUG,
					"%s: couldn't find route for bind, try enabling bind extension",
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
	int i;
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

	bufused = snprintf(buf, sizeof(buf), "method(s): ");
	for (i = 0; i < state->methodc; ++i)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		method2string(state->methodv[i]));
	slog(LOG_INFO, buf);

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
socks_badroute(route)
	struct route_t *route;
{
	const char *function = "socks_badroute()";

	slog(LOG_DEBUG, "%s: badrouting route #%d", function, route->number);
	route->state.bad = 1;
}
