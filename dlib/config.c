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
"$Id: config.c,v 1.75 1999/02/26 19:24:58 michaels Exp $";

#include "common.h"

__BEGIN_DECLS

static int
hostcmp __P((const char *domain, const char *remotedomain));

static void
socks_badroute __P((struct route_t *route));

__END_DECLS

int
addressmatch(rule, address, protocol, ipalias)
	const struct ruleaddress_t *rule;
	const struct sockshost_t *address;
	int protocol;
	int ipalias;
{
	const char *function = "addressmatch()";
	struct hostent *hostent;
	int matched = 0;

	/* test port first since we have already have all info needed for that. */
	if (address->port == ntohs(0))
		; /* wildcard. */
	else { 
		in_port_t ruleport;

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
	}


	/* address match? */

	/* try for exact match first, can avoid gethostby*() call. */
	switch (rule->atype) {
		case SOCKS_ADDR_IPV4:
			if (address->atype == rule->atype) {
				if (address->addr.ipv4.s_addr == htonl(INADDR_ANY)) {
					matched = 1;
					break;
				}

				if ((address->addr.ipv4.s_addr & rule->addr.ipv4.mask.s_addr)
				==  (rule->addr.ipv4.ip.s_addr & rule->addr.ipv4.mask.s_addr)) {
					matched = 1;
					break;
				}
			}
			break;
	
		case SOCKS_ADDR_DOMAIN:
			if (address->atype == rule->atype)
				if (hostcmp(rule->addr.domain, address->addr.domain) == 0) {
					matched = 1;
					break;
				}
			break;

		default:
			SERRX(rule->atype);
	}

	if (!matched) { /* no exact match, try to resolve and match against that? */
		if (ipalias) { /* no, caller doesn't want to match against resolved. */
			switch (address->atype) {
				case SOCKS_ADDR_IPV4:
					/* LINTED pointer casts may be troublesome */
					if ((hostent = gethostbyaddr((char *)&address->addr.ipv4,
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
					struct in_addr *addr;
					int i;

					/* LINTED pointer casts may be troublesome */
					for (i = 0; (addr = (struct in_addr *)hostent->h_addr_list[i])
					!= NULL; ++i)
						if ((addr->s_addr & rule->addr.ipv4.mask.s_addr)
						==  (rule->addr.ipv4.ip.s_addr & rule->addr.ipv4.mask.s_addr))
							break;

					if (addr == NULL)
						return 0; /* list exhausted, no match. */
				}
				break;

				case SOCKS_ADDR_DOMAIN: {
					const char *domain = rule->addr.domain;
					char *remotedomain;
					int i;

					remotedomain = hostent->h_name;
					i = 0;
					do
						if (hostcmp(domain, remotedomain) == 0)
							break;
					while ((remotedomain = hostent->h_aliases[i++]) != NULL);

					if (remotedomain == NULL)
						return 0;	/* list exhausted, no match. */

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
			return 1;	/* address to compare against too short. */

		return strcasecmp(domain + 1,
		remotedomain + (remotedomainlen - (domainlen - 1)));
	}
	else /* need exact match. */
		return strcasecmp(domain, remotedomain);
}


#ifdef SOCKS_CLIENT

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

	/* if no version set, set all. */
	if (memcmp(&state.proxyprotocol, &route->gw.state.proxyprotocol,
	sizeof(state.proxyprotocol)) == 0)
		memset(&route->gw.state.proxyprotocol, UCHAR_MAX,
		sizeof(route->gw.state.proxyprotocol));

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
		struct route_t *lastroute;

		/* append this rule to the end of our list. */

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

	slog(LOG_INFO, "\tsrc: %s",
	ruleaddress2string(&route->src, addr, sizeof(addr)));

	slog(LOG_INFO, "\tdst: %s",
	ruleaddress2string(&route->dst, addr, sizeof(addr)));

	slog(LOG_INFO, "\tgw : %s",
	sockshost2string(&route->gw.host, hstring,
	sizeof(hstring)));

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

#ifdef SOCKS_CLIENT
	clientinit();
#endif

	for (route = config.route; route != NULL; route = route->next) {
		if (route->state.bad)
			continue; /* XXX, code to retry and remove bad status when ok. */

		switch (req->version) {
			case SOCKS_V4:
				if (!route->gw.state.proxyprotocol.socks_v4)
					continue;

				switch (req->host.atype) {
					case SOCKS_ADDR_IPV4:
						break;

					default:
						continue;
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
						continue;
				}
				break;

			case MSPROXY_V2:
				if (!route->gw.state.proxyprotocol.msproxy_v2)
					continue;
				break;

			default:
				SERRX(req->version);
		}

		/* peek a little at the request. */
		if (req != NULL) {
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
		}
		else
			protocol = SOCKS_TCP; /* default. */

		if (src != NULL)
			if (!addressmatch(&route->src, src, protocol, 0))
				continue;

		if (dst != NULL)
			if (!addressmatch(&route->dst, dst, protocol, 0))
				continue;

		if (route->state.direct)
			return NULL; /* no route, Rconnect will default to standard connect. */

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
	int current_s;
	struct route_t *route;
	
	errno = 0;		/* let caller differentiate between missing route and not.	*/
	current_s = s; /* we may have other gateways to try if first found fails. 	*/

	while ((route = socks_getroute(&packet->req, src, dst)) != NULL) {
		if (current_s != s) {
			if (current_s != -1)
				close(current_s);
			
			if ((current_s = socketoptdup(s)) == -1)
				return NULL;
		}

		if (socks_connect(current_s, &route->gw.host) == 0)
			break;
		else {
			char hstring[MAXSOCKSHOSTSTRING];

			if (errno == EINPROGRESS) {
				SASSERTX(current_s == s);
				break;
			}

			swarn("socks_connect(%s)", 
			sockshost2string(&route->gw.host, hstring, sizeof(hstring)));
			socks_badroute(route);
			current_s = -1;
		}
	}

	if (current_s != s && current_s != -1)	{
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
		if (route->gw.state.proxyprotocol.msproxy_v2 && !init) {
			msproxy_init();
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

	if (socks_getroute(req, src, dst) != NULL)
		return req;

	switch (req->command) {
		case SOCKS_UDPASSOCIATE:
			return NULL;	/* nothing to do about that command. */
	}

	/* bad version? */
	if (req->version == SOCKS_V4)
		req->version = SOCKS_V5;
	else if (req->version == SOCKS_V5)
		req->version = SOCKS_V4;

	if (socks_getroute(req, src, dst) != NULL)
		return req;

	req->version 	= MSPROXY_V2;

	if (socks_getroute(req, src, dst) != NULL)
		return req;

	if (req->host.addr.ipv4.s_addr == htonl(0))
		/* attempting to use bind extension, retry without it. */

		/* LINTED */
		if (ADDRISBOUND(config.state.lastconnect)) {
			/* LINTED pointer casts may be troublesome */
			req->host.addr.ipv4
			= ((struct sockaddr_in *)&config.state.lastconnect)->sin_addr;
			req->host.port = htons(0);

			return socks_requestpolish(req, src, dst);
		}
		/* else; not much we can do. */
			

	return NULL;
}

#endif /* SOCKS_CLIENT */

void
showstate(state)
	const struct serverstate_t *state;
{
	int i;

	slog(LOG_INFO, "\tcommand(s) : ");
	if (state->command.bind)
		slog(LOG_INFO, "\t\t%s, ", SOCKS_BINDs);
	if (state->command.bindreply)
		slog(LOG_INFO, "\t\t%s, ", SOCKS_BINDREPLYs);
	if (state->command.connect)
		slog(LOG_INFO, "\t\t%s, ", SOCKS_CONNECTs);
	if (state->command.udpassociate)
		slog(LOG_INFO, "\t\t%s, ", SOCKS_UDPASSOCIATEs);


	slog(LOG_INFO, "\textension(s):");
	if (state->extension.bind)
		slog(LOG_INFO, "\t\tbind, ");

	slog(LOG_INFO, "\tprotocol(s):");
	if (state->protocol.tcp)
		slog(LOG_INFO, "\t\t%s, ", PROTOCOL_TCPs);
	if (state->protocol.udp)
		slog(LOG_INFO, "\t\t%s, ", PROTOCOL_UDPs);

	slog(LOG_INFO, "\tmethod(s):");
	for (i = 0; i < state->methodc; ++i)
		slog(LOG_INFO, "\t\t%d, ", state->methodv[i]);

	slog(LOG_INFO, "\tversion(s):");
	if (state->proxyprotocol.socks_v4)
		slog(LOG_INFO, "\t\t%s, ", "socks v4");
	if (state->proxyprotocol.socks_v5)
		slog(LOG_INFO, "\t\t%s, ", "socks v5");
	if (state->proxyprotocol.msproxy_v2)
		slog(LOG_INFO, "\t\t%s, ", "msproxy v2");
}


static void
socks_badroute(route)
	struct route_t *route;
{
	
	route->state.bad = 1;
}

