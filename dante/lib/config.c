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
"$Id: config.c,v 1.162 2005/12/28 18:25:04 michaels Exp $";

void
genericinit(void)
{
	const char *function = "genericinit()";
	size_t i;
#if SOCKS_SERVER
	sigset_t set, oset;
#endif

	if (!sockscf.state.init) {
#if !HAVE_SETPROCTITLE
		/* create a backup to avoid setproctitle replacement overwriting it. */
		if ((__progname = strdup(__progname)) == NULL)
			serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
#endif /* !HAVE_SETPROCTITLE */
	}

	
#if SOCKS_SERVER
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
		swarn("%s: sigprocmask(SIG_BLOCK)", function);
#endif

	if (readconfig(sockscf.option.configfile) != 0)
#if SOCKS_SERVER
		exit(EXIT_FAILURE);
#else
		return;
#endif

#if SOCKS_SERVER
	if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
		swarn("%s: sigprocmask(SIG_SETMASK)", function);
#endif

	newprocinit();

	switch (sockscf.resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
#if !HAVE_NO_RESOLVESTUFF
			_res.options |= RES_USEVC;
#else /* HAVE_NO_RESOLVESTUFF */
			SERRX(sockscf.resolveprotocol);
#endif  /* HAVE_NO_RESOLVESTUFF */
			break;

		case RESOLVEPROTOCOL_UDP:
		case RESOLVEPROTOCOL_FAKE:
			break;

		default:
			SERRX(sockscf.resolveprotocol);
	}

	for (i = 0; i < sockscf.log.fpc; ++i)
		if (setvbuf(sockscf.log.fpv[i], NULL, _IOLBF, 0) != 0)
			swarn("%s: setvbuf(_IOLBF)", function);

#if !HAVE_NO_RESOLVESTUFF
	res_init();
#endif /* !HAVE_NO_RESOLVSTUFF */

	sockscf.state.init = 1;
}

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
	== 0) {
#if SOCKS_CLIENT 
		memset(&route->gw.state.command, UCHAR_MAX,
		sizeof(route->gw.state.command));
#else /* SOCKS_SERVER, only connect is supported. */
		route->gw.state.command.connect = 1;
#endif
	}
#if SOCKS_SERVER
	else
		if (route->gw.state.command.bind
		||  route->gw.state.command.bindreply
		||  route->gw.state.command.udpassociate
		||  route->gw.state.command.udpreply)
			swarnx("%s: serverchaining is only supported for the connect command",
			function);
#endif

	/* if no protocol set, set all. */
	if (memcmp(&state.protocol, &route->gw.state.protocol,
	sizeof(state.protocol)) == 0) {
#if SOCKS_CLIENT
		memset(&route->gw.state.protocol, UCHAR_MAX,
		sizeof(route->gw.state.protocol));
#else /* SOCKS_SERVER, only connect is supported. */
		route->gw.state.protocol.tcp = 1;
#endif
	}
#if SOCKS_SERVER
	else
		if (route->gw.state.protocol.udp)
			swarnx("%s: serverchaining is only supported for the tcp protocol",
			function);
#endif

	/* if no proxyprotocol set, set all except msproxy. */
	if (memcmp(&state.proxyprotocol, &route->gw.state.proxyprotocol,
	sizeof(state.proxyprotocol)) == 0) {
		memset(&route->gw.state.proxyprotocol, UCHAR_MAX,
		sizeof(route->gw.state.proxyprotocol));
		route->gw.state.proxyprotocol.msproxy_v2 = 0;
	}

	/* switch off commands/protocols set but not supported by proxyprotocol. */
	if (!route->gw.state.proxyprotocol.socks_v5) {
		route->gw.state.command.udpassociate	= 0;
		route->gw.state.protocol.udp				= 0;
	}

	if (!route->gw.state.proxyprotocol.socks_v4
	&& !route->gw.state.proxyprotocol.socks_v5
	&& !route->gw.state.proxyprotocol.msproxy_v2)
		route->gw.state.command.bind = 0;

	/* if no method set, set all we support. */
	if (route->gw.state.methodc == 0) {
		int *methodv = route->gw.state.methodv;
		size_t *methodc = &route->gw.state.methodc;

		methodv[(*methodc)++] = AUTHMETHOD_NONE;
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
	}

	if (route->src.atype == SOCKS_ADDR_IFNAME)
		yyerror("interfacenames not supported for src address");

	if (route->dst.atype == SOCKS_ADDR_IFNAME)
		yyerror("interfacenames not supported for src address");

	if (sockscf.route == NULL) {
		sockscf.route = route;
		sockscf.route->number = 1;
	}
	else {
		/* append rule to the end of list. */
		struct route_t *lastroute;

		lastroute = sockscf.route;
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
/*	const char *function = "socks_getroute()"; */
	struct route_t *route;
	int protocol;

#if SOCKS_CLIENT
	clientinit();
#endif

	for (route = sockscf.route; route != NULL; route = route->next) {
		if (route->state.bad)
			/* CONSTCOND */
			if (BADROUTE_EXPIRE == 0
			||  difftime(time(NULL), route->state.badtime) <= BADROUTE_EXPIRE)
				continue;
			else
				route->state.bad = 0;

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

			case HTTP_V1_0:
				if (!route->gw.state.proxyprotocol.http_v1_0)
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

		if (req->auth != NULL) /* find server that supports method in use. */
			switch (req->auth->method) {
				case AUTHMETHOD_NOTSET:
					break;

				default:
					if (!methodisset(req->auth->method, route->gw.state.methodv,
					route->gw.state.methodc))
						continue; /* does not support the method in use. */
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

	slog(LOG_DEBUG, "%s: s = %d", function, s);

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
#if SOCKS_CLIENT
				swarn("%s: socks_connect(%s)",
				function, sockshost2string(&route->gw.host, hstring,
				sizeof(hstring)));
#endif
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
#if SOCKS_CLIENT
		static int init;
#endif

		packet->gw = route->gw;

#if SOCKS_CLIENT
		/* need to set up misc. crap for msproxy stuff. */
		if (!init && route->gw.state.proxyprotocol.msproxy_v2) {
			if (msproxy_init() != 0)
				;	/* yes, then what? */
			init = 1;
		}
#endif /* SOCKS_CLIENT */
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
	time(&route->state.badtime);
}


#if SOCKS_CLIENT
struct request_t *
socks_requestpolish(req, src, dst)
	struct request_t *req;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
{
	const char *function = "socks_requestpolish()";
	const unsigned char originalversion = req->version;

	if (socks_getroute(req, src, dst) != NULL)
		return req;

	/* no route found.  Can we "polish" the request and then find a route? */
	switch (req->command) {
		case SOCKS_BIND:
			/*
			 * bind semantics differ between v4 and everything else.
			 * Assuming we always start with v5 semantics makes the
			 * following code much simpler.
			 */
			SASSERTX(req->version == SOCKS_V5);
			break;

		case SOCKS_CONNECT:
			break;

		case SOCKS_UDPASSOCIATE:
			SERRX(req->command);	/* currently not implemented, shouldn't happen. */
			/* NOTREACHED */

		default:
			SERRX(req->command);
	}

	/*
	 * Try all proxyprotocols we support.
	 */

	req->version = SOCKS_V4;
	if (socks_getroute(req, src, dst) != NULL) {
		if (req->command == SOCKS_BIND) /* v4/v5 difference in portsemantics. */
			/* LINTED pointer casts may be troublesome */
			req->host.port = TOIN(&sockscf.state.lastconnect)->sin_port;
		return req;
	}

	req->version = HTTP_V1_0;
	if (socks_getroute(req, src, dst) != NULL)
		return req;

	req->version = MSPROXY_V2;
	if (socks_getroute(req, src, dst) != NULL)
		return req;

	req->version = originalversion;

	/* changing proxyprotocol didn't do it, can we try other things? */
	switch (req->command) {
		case SOCKS_BIND:
			if (req->host.addr.ipv4.s_addr == htonl(0)) {
				in_port_t originalport;

				/* attempting to use bind extension, can we retry without it? */
				/* LINTED pointer casts may be troublesome */
				if (!ADDRISBOUND(sockscf.state.lastconnect)) {
					slog(LOG_DEBUG, "%s: couldn't find route for bind(2), "
					"try enabling \"extension: bind\"?", function);
					return NULL;
				}

				originalport = req->host.port;
				fakesockaddr2sockshost(&sockscf.state.lastconnect, &req->host);
				/* keep portnumber req. for bind(2), not a previous connect(2). */
				req->host.port = originalport;

				if (socks_requestpolish(req, src, dst) == NULL)
					return NULL; /* giving up. */

				/*
				 * else, it may be that socks_requestpolish() was
				 * forced to change req.version to succeed.  We may
				 * the need to change req->host.port due to difference
				 * in v4 and v5 semantics.
				*/
				if (req->version != originalversion) { /* version changed. */
					SASSERTX(originalversion == SOCKS_V5);

					switch (req->version) {
						case SOCKS_V4: /* the only one with this strangeness. */
							/* LINTED pointer casts may be troublesome */
							req->host.port
							= TOIN(&sockscf.state.lastconnect)->sin_port;
							break;
					}
				}

				return req;
			}
			break;
	}

	slog(LOG_DEBUG, function);
	return NULL;
}
#endif /* SOCKS_CLIENT */

void
showstate(state)
	const struct serverstate_t *state;
{
	char buf[1024];
	size_t bufused;

	bufused = snprintfn(buf, sizeof(buf), "command(s): ");
	if (state->command.bind)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_BINDs);
	if (state->command.bindreply)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_BINDREPLYs);
	if (state->command.connect)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_CONNECTs);
	if (state->command.udpassociate)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_UDPASSOCIATEs);
	if (state->command.udpreply)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		SOCKS_UDPREPLYs);
	slog(LOG_INFO, buf);

	bufused = snprintfn(buf, sizeof(buf), "extension(s): ");
	if (state->extension.bind)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "bind");
	slog(LOG_INFO, buf);

	bufused = snprintfn(buf, sizeof(buf), "protocol(s): ");
	protocols2string(&state->protocol,
	&buf[bufused], sizeof(buf) - bufused);
	slog(LOG_INFO, buf);

	showmethod(state->methodc, state->methodv);

	bufused = snprintfn(buf, sizeof(buf), "proxyprotocol(s): ");
	proxyprotocols2string(&state->proxyprotocol,
	&buf[bufused], sizeof(buf) - bufused);
	slog(LOG_INFO, buf);

}

void
showmethod(methodc, methodv)
	size_t methodc;
	const int *methodv;
{
	char buf[1024];

	slog(LOG_INFO, "method(s): %s",
	methods2string(methodc, methodv, buf, sizeof(buf)));
}
