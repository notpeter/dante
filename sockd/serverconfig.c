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
#include "config_parse.h"

static const char rcsid[] =
"$Id: serverconfig.c,v 1.205 2005/11/01 16:40:10 michaels Exp $";

__BEGIN_DECLS

static void
showuser __P((const struct linkedname_t *user));
/*
 * shows usernames in "user".
 */

static void
showlog __P((const struct log_t *log));
/*
 * shows what type of logging is specified in "log".
 */

#if HAVE_LIBWRAP
	extern jmp_buf tcpd_buf;

static void
libwrapinit __P((int s, struct request_info *request));
/*
 * Initializes "request" for later usage via libwrap.
 */

static int
connectisok __P((struct request_info *request, const struct rule_t *rule));
#else /* !HAVE_LIBWRAP */
static int
connectisok __P((void *request, const struct rule_t *rule));
#endif /* !HAVE_LIBWRAP */
/*
 * Checks the connection on "s".
 * "rule" is the rule that matched the connection.
 * This function should be called after each rulecheck for a new
 * connection/packet.
 *
 * Returns:
 *		If connection is acceptable: true
 *		If connection is not acceptable: false
 */

static struct rule_t *
addrule __P((const struct rule_t *newrule, struct rule_t **rulebase,
				 int client));
/*
 * Appends a copy of "newrule" to "rulebase".
 * If "client" is true, "newrule" is a clientrule.
 * Returns a pointer to the added rule (not "newrule").
 */

static void
checkrule __P((const struct rule_t *rule));
/*
 * Check that the rule "rule" makes sense.
 */

__END_DECLS

struct config_t sockscf;
const int socks_configtype = CONFIGTYPE_SERVER;

#if HAVE_LIBWRAP
int allow_severity, deny_severity;
#endif  /* HAVE_LIBWRAP */

/* expand array by one, increment argc. */
#define NEWINTERNAL_EXTERNAL(argc, argv)  \
do { \
	if ((argv = realloc(argv, sizeof(*argv) * ++argc)) == NULL) \
		yyerror(NOMEM); \
	bzero(&argv[argc - 1], sizeof(*argv)); \
} while (lintnoloop_common_h)


void
addinternal(addr)
	const struct ruleaddress_t *addr;
{

	if (sockscf.state.init) {
#if 0 /* XXX don't know how to do this now, seems like too much work. */
		int i;

		for (i = 0; i < sockscf.internalc; ++i)
			if (memcmp(&sockscf.internalv[i], addr, sizeof(addr)) == 0)
				break;

		if (i == sockscf.internalc)
			swarnx("can't change internal addresses once running");
#endif
	}
	else
		switch (addr->atype) {
			case SOCKS_ADDR_IPV4: {
				struct sockshost_t host;

				NEWINTERNAL_EXTERNAL(sockscf.internalc, sockscf.internalv);

				sockshost2sockaddr(ruleaddress2sockshost(addr, &host, SOCKS_TCP),
				&sockscf.internalv[sockscf.internalc - 1].addr);
				break;
			}

			case SOCKS_ADDR_DOMAIN: {
				struct sockaddr sa;
				int i;

				i = 0;
				while (hostname2sockaddr(addr->addr.domain, i, &sa) != NULL) {
					NEWINTERNAL_EXTERNAL(sockscf.internalc,
					sockscf.internalv);

					/* LINTED pointer casts may be troublesome */
					TOIN(&sa)->sin_port = addr->port.tcp;
					sockscf.internalv[sockscf.internalc - 1].addr = sa;
					++i;
				}

				if (i == 0)
					yyerror("could not resolve name %s: %s",
					addr->addr.domain, hstrerror(h_errno));
				break;
			}

			case SOCKS_ADDR_IFNAME: {
				struct ifaddrs ifa, *ifap = &ifa, *iface;
				int m;

				if (getifaddrs(&ifap) != 0)
					serr(EXIT_FAILURE, "getifaddrs()");

				for (m = 0, iface = ifap; iface != NULL; iface = iface->ifa_next)
					if (strcmp(iface->ifa_name, addr->addr.ifname) == 0
					&& iface->ifa_addr != NULL
					&& iface->ifa_addr->sa_family == AF_INET) {
						NEWINTERNAL_EXTERNAL(sockscf.internalc,
						sockscf.internalv);

						/* LINTED pointer casts may be troublesome */
						TOIN(iface->ifa_addr)->sin_port = addr->port.tcp;

						sockscf.internalv[sockscf.internalc - 1].addr
						= *iface->ifa_addr;

						m = 1;
					}
				freeifaddrs(ifap);

				if (!m)
					yyerror("can't find interface/address: %s", addr->addr.ifname);
				break;
			}

			default:
				SERRX(addr->atype);
		}
}

void
addexternal(addr)
	const struct ruleaddress_t *addr;
{

	switch (addr->atype) {
			case SOCKS_ADDR_DOMAIN: {
				struct sockaddr sa;
				int i;

				i = 0;
				while (hostname2sockaddr(addr->addr.domain, i, &sa) != NULL) {
					NEWINTERNAL_EXTERNAL(sockscf.external.addrc,
					sockscf.external.addrv);

					/* LINTED pointer casts may be troublesome */
					TOIN(&sa)->sin_port = addr->port.tcp;
					sockaddr2ruleaddress(&sa,
					&sockscf.external.addrv[sockscf.external.addrc - 1]);
					++i;
				}

				if (i == 0)
					yyerror("could not resolve name %s: %s",
					addr->addr.domain, hstrerror(h_errno));
				break;
			}

		case SOCKS_ADDR_IPV4: {
			if (addr->addr.ipv4.ip.s_addr == htonl(INADDR_ANY))
				yyerror("external address can't be a wildcard address");
			NEWINTERNAL_EXTERNAL(sockscf.external.addrc,
			sockscf.external.addrv);
			sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
			sockscf.external.addrv[sockscf.external.addrc - 1].addr.ipv4.mask.s_addr = htonl(0xffffffff);
			break;

		case SOCKS_ADDR_IFNAME:
			NEWINTERNAL_EXTERNAL(sockscf.external.addrc,
			sockscf.external.addrv);
			sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
			break;
		}

		default:
			SERRX(addr->atype);
	}
}


struct rule_t *
addclientrule(newrule)
	const struct rule_t *newrule;
{
	struct rule_t *rule, ruletoadd;
	size_t i;

	ruletoadd = *newrule; /* for const. */

	rule = addrule(&ruletoadd, &sockscf.crule, 1);

	if (rule->state.methodc == 0)
		if (rule->user == NULL)
			rule->state.methodv[rule->state.methodc++] = AUTHMETHOD_NONE;

	for (i = 0; i < rule->state.methodc; ++i)
		switch (rule->state.methodv[i]) {
			case AUTHMETHOD_NONE:
			case AUTHMETHOD_RFC931:
			case AUTHMETHOD_PAM:
				break;

			default:
				yyerror("method %s is not valid for clientrules",
				method2string(rule->state.methodv[i]));
		}

	checkrule(rule);

	/* LINTED cast discards 'const' from pointer target type */
	return (struct rule_t *)rule;
}

struct rule_t *
addsocksrule(newrule)
	const struct rule_t *newrule;
{

	struct rule_t *rule;

	rule = addrule(newrule, &sockscf.srule, 0);

	checkrule(rule);

	/* LINTED cast discards 'const' from pointer target type */
	return (struct rule_t *)rule;
}

struct linkedname_t *
adduser(ruleuser, name)
	struct linkedname_t **ruleuser;
	const char *name;
{
	struct linkedname_t *user, *last;

	for (user = *ruleuser, last = NULL; user != NULL; user = user->next)
		last = user;

	if ((user = (struct linkedname_t *)malloc(sizeof(*user))) == NULL)
		return NULL;

	if ((user->name = strdup(name)) == NULL)
		return NULL;
	user->next = NULL;

	if (*ruleuser == NULL)
		*ruleuser = user;
	else
		last->next = user;

	return *ruleuser;
}


void
showrule(rule)
	const struct rule_t *rule;
{
	char addr[MAXRULEADDRSTRING];

	slog(LOG_INFO, "socks-rule #%u, line #%lu",
	rule->number, rule->linenumber);

	slog(LOG_INFO, "verdict: %s", verdict2string(rule->verdict));

	slog(LOG_INFO, "src: %s",
	ruleaddress2string(&rule->src, addr, sizeof(addr)));

	slog(LOG_INFO, "dst: %s",
	ruleaddress2string(&rule->dst, addr, sizeof(addr)));

	slog(LOG_INFO, "redirect from: %s",
	ruleaddress2string(&rule->rdr_from, addr, sizeof(addr)));

	slog(LOG_INFO, "redirect to: %s",
	ruleaddress2string(&rule->rdr_to, addr, sizeof(addr)));

	if (rule->bw != NULL)
		slog(LOG_INFO, "max bandwidth to use: %ld B/s", rule->bw->maxbps);

	if (rule->ss != NULL)
		slog(LOG_INFO, "max sessions: %d", rule->ss->maxsessions);

	showuser(rule->user);

#if HAVE_PAM
	if (*rule->pamservicename != NUL)
		slog(LOG_INFO, "pam.servicename: %s", rule->pamservicename);
#endif  /* HAVE_PAM */

	showstate(&rule->state);

	showlog(&rule->log);

#if HAVE_LIBWRAP
	if (*rule->libwrap != NUL)
		slog(LOG_INFO, "libwrap: %s", rule->libwrap);
#endif  /* HAVE_LIBWRAP */
}

void
showclient(rule)
	const struct rule_t *rule;
{
	char addr[MAXRULEADDRSTRING];

	slog(LOG_INFO, "client-rule #%u, line #%lu",
	rule->number, rule->linenumber);

	slog(LOG_INFO, "verdict: %s", verdict2string(rule->verdict));

	slog(LOG_INFO, "src: %s",
	ruleaddress2string(&rule->src, addr, sizeof(addr)));

	slog(LOG_INFO, "dst: %s",
	ruleaddress2string(&rule->dst, addr, sizeof(addr)));

	showmethod(rule->state.methodc, rule->state.methodv);

	showuser(rule->user);

#if HAVE_PAM
	if (*rule->pamservicename != NUL)
		slog(LOG_INFO, "pamservicename: %s", rule->pamservicename);
#endif  /* HAVE_PAM */

	if (rule->bw != NULL)
		slog(LOG_INFO, "max bandwidth to use: %ld B/s", rule->bw->maxbps);

	if (rule->ss != NULL)
		slog(LOG_INFO, "max sessions: %d", rule->ss->maxsessions);

	showlog(&rule->log);

#if HAVE_LIBWRAP
	if (*rule->libwrap != NUL)
		slog(LOG_INFO, "libwrap: %s", rule->libwrap);
#endif  /* HAVE_LIBWRAP */
}

void
showconfig(sockscf)
	const struct config_t *sockscf;
{
	int i;
	char address[MAXRULEADDRSTRING], buf[1024];
	size_t bufused;

	slog(LOG_DEBUG, "internal addresses (%d):", sockscf->internalc);
	for (i = 0; i < sockscf->internalc; ++i)
		slog(LOG_DEBUG, "\t%s",
		sockaddr2string(&sockscf->internalv[i].addr, address,
		sizeof(address)));

	slog(LOG_DEBUG, "external addresses (%d):", sockscf->external.addrc);
	for (i = 0; i < sockscf->external.addrc; ++i) {
		ruleaddress2string(&sockscf->external.addrv[i], address,
		sizeof(address));

		slog(LOG_DEBUG, "\t%s", address);
	}
	slog(LOG_DEBUG, "external address rotation: %s",
	rotation2string(sockscf->external.rotation));

	slog(LOG_DEBUG, "compatibility options: %s",
	compats2string(&sockscf->compat, buf, sizeof(buf)));

	slog(LOG_DEBUG, "extensions enabled: %s",
	extensions2string(&sockscf->extension, buf, sizeof(buf)));

	slog(LOG_DEBUG, "logoutput goes to: %s",
	logtypes2string(&sockscf->log, buf, sizeof(buf)));

	slog(LOG_DEBUG, "cmdline options:\n%s",
	options2string(&sockscf->option, "", buf, sizeof(buf)));

	slog(LOG_DEBUG, "resolveprotocol: %s",
	resolveprotocol2string(sockscf->resolveprotocol));

	slog(LOG_DEBUG, "srchost:\n%s",
	srchosts2string(&sockscf->srchost, "", buf, sizeof(buf)));

	slog(LOG_DEBUG, "negotiate timeout: %lds",
	(long)sockscf->timeout.negotiate);
	slog(LOG_DEBUG, "i/o timeout: %lds",
	(long)sockscf->timeout.io);

	slog(LOG_DEBUG, "euid: %d", sockscf->state.euid);

	slog(LOG_DEBUG, "userid:\n%s",
	userids2string(&sockscf->uid, "", buf, sizeof(buf)));

	slog(LOG_DEBUG, "child.maxidle: %d",
	sockscf->child.maxidle);

	bufused = snprintfn(buf, sizeof(buf), "method(s): ");
	for (i = 0; (size_t)i < sockscf->methodc; ++i)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s%s",
		i > 0 ? ", " : "", method2string(sockscf->methodv[i]));
	slog(LOG_DEBUG, buf);

	bufused = snprintfn(buf, sizeof(buf), "clientmethod(s): ");
	for (i = 0; (size_t)i < sockscf->clientmethodc; ++i)
		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s%s",
		i > 0 ? ", " : "", method2string(sockscf->clientmethodv[i]));
	slog(LOG_DEBUG, buf);

	if (sockscf->option.debug) {
		struct rule_t *rule;
		struct route_t *route;
		int count;

		for (count = 0, rule = sockscf->crule; rule != NULL; rule = rule->next)
			++count;
		slog(LOG_DEBUG, "client-rules (%d): ", count);
		for (rule = sockscf->crule; rule != NULL; rule = rule->next)
			showclient(rule);

		for (count = 0, rule = sockscf->srule; rule != NULL; rule = rule->next)
			++count;
		slog(LOG_DEBUG, "socks-rules (%d): ", count);
		for (rule = sockscf->srule; rule != NULL; rule = rule->next)
			showrule(rule);

		for (count = 0, route = sockscf->route; route != NULL;
		route = route->next)
			++count;
		slog(LOG_DEBUG, "routes (%d): ", count);
		for (route = sockscf->route; route != NULL; route = route->next)
			showroute(route);
	}
}


void
resetconfig(void)
{
	struct rule_t *rule;
	struct route_t *route;

	/*
	 * internal; don't touch, only settable at start.
	 */

	/* external addresses can be changed. */
	free(sockscf.external.addrv);
	sockscf.external.addrv			= NULL;
	sockscf.external.addrc			= 0;

	/* delete all old socks rules */
	rule = sockscf.srule;
	while (rule != NULL) {
		struct rule_t *next = rule->next;
		struct linkedname_t *user, *nextuser;

		user = rule->user;
		while (user != NULL) {
			nextuser = user->next;
			free(user);
			user = nextuser;
		}

		free(rule);
		rule = next;
	}
	sockscf.srule = NULL;

	/* clientrules too. */
	rule = sockscf.crule;
	while (rule != NULL) {
		struct rule_t *next = rule->next;
		struct linkedname_t *user, *nextuser;

		user = rule->user;
		while (user != NULL) {
			nextuser = user->next;
			free(user);
			user = nextuser;
		}

		free(rule);
		rule = next;
	}
	sockscf.crule = NULL;

	/* and routes. */
	route = sockscf.route;
	while (route != NULL) {
		struct route_t *next = route->next;

		free(route);
		route = next;
	}
	sockscf.route = NULL;

	/* compat, read from configfile. */
	bzero(&sockscf.compat, sizeof(sockscf.compat));

	/* extensions, read from configfile. */
	bzero(&sockscf.extension, sizeof(sockscf.extension));

	/* log; only settable at start. */

	/* option; only settable at commandline. */

	/* resolveprotocol, read from configfile. */
	bzero(&sockscf.resolveprotocol, sizeof(sockscf.resolveprotocol));

	/* srchost, read from configfile. */
	bzero(&sockscf.srchost, sizeof(sockscf.srchost));

	/* stat: keep it. */

	/* state; keep most of it. */
#if HAVE_PAM
	sockscf.state.pamservicename = DEFAULT_PAMSERVICENAME;
#endif

	/* methods, read from configfile. */
	bzero(sockscf.methodv, sizeof(sockscf.methodv));
	sockscf.methodc = 0;

	bzero(sockscf.clientmethodv, sizeof(sockscf.clientmethodv));
	sockscf.clientmethodc = 0;


	/* timeout, read from configfile. */
	bzero(&sockscf.timeout, sizeof(sockscf.timeout));

	/* uid, read from configfile. */
	bzero(&sockscf.uid, sizeof(sockscf.uid));

	/* childstate, most read from configfile, but some not. */
	sockscf.child.maxidle = 0;
}

void
iolog(rule, state, operation, src, srcauth, dst, dstauth, data, count)
	struct rule_t *rule;
	const struct connectionstate_t *state;
	int operation;
	const struct sockshost_t *src;
	const struct authmethod_t *srcauth;
	const struct sockshost_t *dst;
	const struct authmethod_t *dstauth;
	const char *data;
	size_t count;
{
	/* CONSTCOND */
	char srcstring[MAXSOCKSHOSTSTRING + MAXAUTHINFOLEN];
	char dststring[sizeof(srcstring)];
	char rulecommand[256];
	int p;

	authinfo(srcauth, srcstring, sizeof(srcstring));
	p = strlen(srcstring);
	sockshost2string(src, &srcstring[p], sizeof(srcstring) - p);

	authinfo(dstauth, dststring, sizeof(dststring));
	p = strlen(dststring);
	sockshost2string(dst, &dststring[p], sizeof(dststring) - p);

	snprintfn(rulecommand, sizeof(rulecommand), "%s(%d): %s/%s",
	verdict2string(rule->verdict),
	rule->number, protocol2string(state->protocol),
	command2string(state->command));

	switch (operation) {
		case OPERATION_ACCEPT:
		case OPERATION_CONNECT:
			if (rule->log.connect)
				slog(LOG_INFO, "%s [: %s -> %s%s%s",
				rulecommand, srcstring, dststring,
				(data == NULL || *data == NUL) ? "" : ": ",
				(data == NULL || *data == NUL) ? "" : data);
			break;

		case OPERATION_ABORT:
			if (rule->log.disconnect || rule->log.error)
				slog(LOG_INFO, "%s ]: %s -> %s: %s",
				rulecommand, srcstring, dststring,
				(data == NULL || *data == NUL) ? strerror(errno) : data);
			break;

		case OPERATION_ERROR:
			if (rule->log.error)
				slog(LOG_INFO, "%s ]: %s -> %s: %s",
				rulecommand, srcstring, dststring,
				(data == NULL || *data == NUL) ? strerror(errno) : data);
			break;

		case OPERATION_IO:
			if (rule->log.data) {
				char *visdata;

				SASSERTX(data != NULL);

				slog(LOG_INFO, "%s -: %s -> %s (%lu): %s",
				rulecommand, srcstring, dststring, (unsigned long)count,
				strcheck(visdata = str2vis(data, count)));

				free(visdata);
				break;
			}

			if (rule->log.iooperation)
				slog(LOG_INFO, "%s -: %s -> %s (%lu)",
				rulecommand, srcstring, dststring, (unsigned long)count);
			break;

		default:
			SERRX(operation);
	}
}

int
rulespermit(s, peer, local, match, state, src, dst, msg, msgsize)
	int s;
	const struct sockaddr *peer, *local;
	struct rule_t *match;
	struct connectionstate_t *state;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
	char *msg;
	size_t msgsize;
{
	const char *function = "rulespermit()";
	static int init;
	static struct rule_t defrule;
	struct rule_t *rule;
	struct connectionstate_t ostate;
	int *methodv;
	int methodc;
#if HAVE_LIBWRAP
	struct request_info libwraprequest;

	libwrapinit(s, &libwraprequest);
#else /* !HAVE_LIBWRAP */
	void *libwraprequest = NULL;
#endif

	/* make a somewhat sensible default rule for entries with no match. */
	if (!init) {
		defrule.verdict							= VERDICT_BLOCK;
		defrule.number								= 0;

		defrule.src.atype							= SOCKS_ADDR_IPV4;
		defrule.src.addr.ipv4.ip.s_addr		= htonl(INADDR_ANY);
		defrule.src.addr.ipv4.mask.s_addr	= htonl(0);
		defrule.src.port.tcp						= htons(0);
		defrule.src.port.udp						= htons(0);
		defrule.src.portend						= htons(0);
		defrule.src.operator						= none;

		defrule.dst									= defrule.src;

		memset(&defrule.log, 0, sizeof(defrule.log));
		defrule.log.connect		= 1;
		defrule.log.iooperation	= 1; /* blocked iooperations. */

		if (sockscf.option.debug) {
			defrule.log.disconnect	= 1;
			defrule.log.error			= 1;
		}

		memset(&defrule.state.command, UCHAR_MAX, sizeof(defrule.state.command));

		defrule.state.methodc = 0;

		memset(&defrule.state.protocol, UCHAR_MAX,
		sizeof(defrule.state.protocol));

		memset(&defrule.state.proxyprotocol, UCHAR_MAX,
		sizeof(defrule.state.proxyprotocol));

#if HAVE_LIBWRAP
		*defrule.libwrap = NUL;
#endif  /* HAVE_LIBWRAP */

		init = 1;
	}

	if (msgsize > 0)
		*msg = NUL;

	/* what rulebase to use. */
	switch (state->command) {
		case SOCKS_ACCEPT:
			/* only set by negotiate children so must be clientrule. */
			rule		= sockscf.crule;
			methodv	= sockscf.clientmethodv;
			methodc	= sockscf.clientmethodc;
			break;

		default:
			/* everyone else, socksrules. */
			rule = sockscf.srule;
			methodv	= sockscf.methodv;
			methodc	= sockscf.methodc;
			break;
	}

	/*
	 * let "state" be unchanged from original unless we actually get a match.
	 * The exception to this is state->auth.methodv and state->auth.badmethodv,
	 * we change them so we can "cache" it, and callee could in theory
	 * use it to see which methods we tried.
	 */
	for (ostate = *state; rule != NULL; rule = rule->next, *state = ostate) {
		int i;

		/* current rule covers desired command? */
		switch (state->command) {
			/* client-rule commands. */
			case SOCKS_ACCEPT:
				break;

			/* socks-rule commands. */
			case SOCKS_BIND:
				if (!rule->state.command.bind)
					continue;
				break;

			case SOCKS_CONNECT:
				if (!rule->state.command.connect)
					continue;
				break;

			case SOCKS_UDPASSOCIATE:
				if (!rule->state.command.udpassociate)
					continue;
				break;

			/* pseudo commands. */

			case SOCKS_BINDREPLY:
				if (!rule->state.command.bindreply)
					continue;
				break;

			case SOCKS_UDPREPLY:
				if (!rule->state.command.udpreply)
					continue;
				break;

			default:
				SERRX(state->command);
		}

		/* current rule covers desired protocol? */
		switch (state->protocol) {
			case SOCKS_TCP:
				if (!rule->state.protocol.tcp)
					continue;
				break;

			case SOCKS_UDP:
				if (!rule->state.protocol.udp)
					continue;
				break;

			default:
				SERRX(state->protocol);
		}

		/* current rule covers desired version? */
		switch (state->version) {
			case SOCKS_V4:
				if (!rule->state.proxyprotocol.socks_v4)
					continue;
				break;

			case SOCKS_V5:
				if (!rule->state.proxyprotocol.socks_v5)
					continue;
				break;

			default:
				SERRX(state->version);
		}

		/*
		 * This is a little tricky.  For some commands we may not
		 * have all info at time of (preliminary) rulechecks.
		 * What we want to do if there is no (complete) address given is
		 * to see if there's any chance at all the rules will permit this
		 * request when the address (later) becomes available.
		 * We therefore continue to scan the rules until we either get
		 * a pass (ignoring peer with missing info), or the default block
		 * is triggered. 
		 *
		 * This is the case for e.g. bindreply and udp, where we will
		 * have to call this function again when we get the addresses
		 * in question.
		 */

		if (src != NULL) {
			if (!addressmatch(&rule->src, src, state->protocol, 0))
				continue;
		}
		else
			if (rule->verdict == VERDICT_BLOCK)
				continue; /* continue scan.  It's possible we will get a pass. */

		if (dst != NULL) {
			 if (!addressmatch(&rule->dst, dst, state->protocol, 0))
				continue;
		}
		else
			if (rule->verdict == VERDICT_BLOCK)
				continue; /* continue scan.  It's possible we will get a pass. */

		/* current rule authentication matches selected authentication? */
		if (!methodisset(state->auth.method, rule->state.methodv,
		rule->state.methodc)) {
			/*
			 * There are some "extra" (non-standard) methods that are 
			 * independent of socks protocol negotiation, and it's possible
			 * to get a match on them, even if above check failed.  I.e.
			 * it's possible to change the method.  E.g. PAM is based 
			 * on UNAME; if we have UNAME, we can also get PAM.
			 *
			 * We therefor look at what methods this rule wants and see
			 * if can match it with what the client _can_ provide, if we
			 * do some extra work to get the information.
			 * Currently these methods are: rfc931 and pam.
			 */

			/* 
			 * This variable only says if current client has provided the
			 * neccessary information to to check it's access with
			 * one of the methods required by the current rule.
			 *
			 * XXX would be nice to cache this, so we don't have to
			 * copy memory around each time.
			 */
			size_t methodischeckable = 0;

			for (i = 0; i < methodc; ++i) {
				if (methodisset(methodv[i], rule->state.methodv,
				rule->state.methodc)) {
					switch (methodv[i]) {
#if HAVE_LIBWRAP
						case AUTHMETHOD_RFC931:
							strncpy((char *)state->auth.mdata.rfc931.name,
							eval_user(&libwraprequest),
							sizeof(state->auth.mdata.rfc931.name) - 1);

							/* libwrap sets it to unknown if no identreply. */
							if (strcmp((char *)state->auth.mdata.rfc931.name,
							STRING_UNKNOWN) == 0)
								*state->auth.mdata.rfc931.name = NUL;
							else if (state->auth.mdata.rfc931.name[
							sizeof(state->auth.mdata.rfc931.name) - 1] != NUL) {
								state->auth.mdata.rfc931.name[
								sizeof(state->auth.mdata.rfc931.name) - 1] = NUL;
								swarnx("%s: rfc931 name \"%s\" truncated", function,
								state->auth.mdata.rfc931.name);

								*state->auth.mdata.rfc931.name = NUL;
							}

							if (*state->auth.mdata.rfc931.name != NUL)
								methodischeckable = 1;
							break;
#endif /* HAVE_LIBWRAP */

#if HAVE_PAM
						case AUTHMETHOD_PAM:
							/*
							 * PAM can support username/password, just username,
							 * or neither username nor password.
							 */

							slog(LOG_DEBUG, "%s: trying to find match for pam ...",
							function);

							switch (state->auth.method) {
								case AUTHMETHOD_UNAME: {
                          	/* it's a union, make a copy first. */
                          	const struct authmethod_uname_t uname
                          	= state->auth.mdata.uname;

                          	/* similar enough, just copy name/password. */
                          	strcpy((char *)state->auth.mdata.pam.name,
                          	(const char *)uname.name);
                          	strcpy((char *)state->auth.mdata.pam.password,
                          	(const char *)uname.password);

									methodischeckable = 1;
									break;
								}

								case AUTHMETHOD_RFC931: {
                          	/* it's a union, make a copy first. */
                          	const struct authmethod_rfc931_t rfc931
                          	= state->auth.mdata.rfc931;

									/*
									 * no password, but we can check for the username 
									 * we got from ident, with an empty password.
									 */

                          	strcpy((char *)state->auth.mdata.pam.name,
                          	(const char *)rfc931.name);

									*state->auth.mdata.pam.password = NUL;

									methodischeckable = 1;
									break;
								}

								case AUTHMETHOD_NONE:
									/*
									 * PAM can also support no username/password.
									 */

									*state->auth.mdata.pam.name		= NUL;
									*state->auth.mdata.pam.password	= NUL;

									methodischeckable = 1;
									break;

							}

							strcpy(state->auth.mdata.pam.servicename,
							rule->pamservicename);
#endif /* HAVE_PAM */
					}

					if (methodischeckable) {
						state->auth.method = methodv[i]; /* chainging method. */
						break;
					}
				}
			}

			if (i == methodc)
				/* 
				 * current rules methods differs from what client can
				 * provide us with.  Go to next rule.
				 */
				continue;
			/* else; XXX should try other methods if acccess fails on this. */
		}

		SASSERTX(methodisset(state->auth.method, rule->state.methodv,
		rule->state.methodc));

		/* rule requires a user, and covers current user? */
		if (rule->user != NULL)
			if (!usermatch(&state->auth, rule->user))
				continue; /* no match. */

		/* last step.  Does the authentication match? */
		i = accesscheck(s, &state->auth, peer, local, msg, msgsize);

		/*
		 * two fields we want to copy.  This is to speed things up so
		 * we don't re-check the same method.
		*/
		memcpy(ostate.auth.methodv, state->auth.methodv,
		state->auth.methodc * sizeof(*state->auth.methodv));
		ostate.auth.methodc = state->auth.methodc;
		memcpy(ostate.auth.badmethodv, state->auth.badmethodv,
		state->auth.badmethodc * sizeof(*state->auth.badmethodv));
		ostate.auth.badmethodc = state->auth.badmethodc;

		if (!i) {
			match->verdict = VERDICT_BLOCK;
			return 0;
		}	

		break;
	}

	if (rule == NULL) /* no rules matched; match default rule. */
		rule = &defrule;

	*match = *rule;

	/*
	 * got our rule, now check connection.  Connectioncheck
	 * requires the rule matched so needs to be delayed til here.
	 */

	if (!connectisok(&libwraprequest, match))
		match->verdict = VERDICT_BLOCK;

	/*
	 * specialcases that we delay til here to get correct addr/rule match,
	 * even if we could have decided on the final answer before.
	 */
	switch (state->command) {
		case SOCKS_BIND:
			if (dst->atype == SOCKS_ADDR_IPV4 && dst->addr.ipv4.s_addr == htonl(0))
				if (!sockscf.extension.bind) {
					slog(LOG_DEBUG, "%s: client requested disabled extension: bind",
					function);
					match->verdict = VERDICT_BLOCK;
				}
			break;
	}

	return match->verdict == VERDICT_PASS;
}

const char *
authinfo(auth, info, infolen)
	const struct authmethod_t *auth;
	char *info;
	size_t infolen;
{
	const char *authname, *methodname;

	if (auth != NULL) {
		methodname = method2string(auth->method);

		switch (auth->method) {
			case AUTHMETHOD_NONE:
			case AUTHMETHOD_NOACCEPT: /* closing connection next presumably. */
				authname = methodname = NULL;
				break;

			case AUTHMETHOD_UNAME:
				authname = (const char *)auth->mdata.uname.name;
				break;

			case AUTHMETHOD_RFC931:
				authname = (const char *)auth->mdata.rfc931.name;
				break;

#if HAVE_PAM
			case AUTHMETHOD_PAM:
				authname = (const char *)auth->mdata.pam.name;
				break;
#endif

			default:
				SERRX(auth->method);
		}
	}
	else
		authname = methodname = NULL;

	if (authname == NULL || *authname == NUL)
		*info = NUL;
	else
		snprintfn(info, infolen, "%s%%%s@", methodname, authname);

	return info;
}

int
addressisbindable(addr)
	const struct ruleaddress_t *addr;
{
	const char *function = "addressisbindable()";
	struct sockaddr saddr;
	/* CONSTCOND */
	char saddrs[MAX(MAXSOCKSHOSTSTRING, MAXSOCKADDRSTRING)];
	int s;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		swarn("%s: socket(SOCK_STREAM)", function);
		return 0;
	}

	switch (addr->atype) {
		case SOCKS_ADDR_IPV4: {
			struct sockshost_t host;

			sockshost2sockaddr(ruleaddress2sockshost(addr, &host, SOCKS_TCP),
			&saddr);

			if (bind(s, &saddr, sizeof(saddr)) != 0) {
				swarn("%s: can't bind address: %s",
				function, sockaddr2string(&saddr, saddrs, sizeof(saddrs)));
				close(s);
				return 0;
			}
			break;
		}

		case SOCKS_ADDR_IFNAME:
			if (ifname2sockaddr(addr->addr.ifname, 0, &saddr) == NULL) {
				swarn("%s: can't find interface: %s", function, addr->addr.ifname);
				close(s);
				return 0;
			}

			if (bind(s, &saddr, sizeof(saddr)) != 0) {
				swarn("%s: can't bind address %s of interface %s",
				function, sockaddr2string(&saddr, saddrs, sizeof(saddrs)),
				addr->addr.ifname);
				close(s);
				return 0;
			}
			break;

		default:
			SERRX(addr->atype);
	}

	close(s);
	return 1;
}


static struct rule_t *
addrule(newrule, rulebase, client)
	const struct rule_t *newrule;
	struct rule_t **rulebase;
	int client;
{
	static const struct serverstate_t state;
	const char *function = "addrule()";
	struct rule_t *rule;
	size_t i;
	int *methodv;
	size_t methodc;

	if (client) {
		methodv = sockscf.clientmethodv;
		methodc = sockscf.clientmethodc;
	}
	else {
		methodv = sockscf.methodv;
		methodc = sockscf.methodc;
	}

	if ((rule = malloc(sizeof(*rule))) == NULL)
		serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
	*rule = *newrule;

	/* try to set values not set to a sensible default. */

	if (sockscf.option.debug) {
		rule->log.connect			= 1;
		rule->log.disconnect		= 1;
		rule->log.error			= 1;
		rule->log.iooperation	= 1;
	}
	/* else; don't touch logging, no logging is ok. */

	/* if no command set, set all. */
	if (memcmp(&state.command, &rule->state.command, sizeof(state.command)) == 0)
		memset(&rule->state.command, UCHAR_MAX, sizeof(rule->state.command));

	/*
	 * If no method set, set all set from global methodline that make sense.
	 */
	if (rule->state.methodc == 0) {
		for (i = 0; i < methodc; ++i)
			switch (methodv[i]) {
				case AUTHMETHOD_NONE:
					if (rule->user != NULL)
						break;
					/* else; */ /* FALLTHROUGH */

				default:
					rule->state.methodv[rule->state.methodc++] = methodv[i];
			}
	}

	/* warn about methods not set in the global method?  May not be an error. */
	for (i = 0; i < rule->state.methodc; ++i)
		if (!methodisset(rule->state.methodv[i], methodv, methodc))
			yywarn("method \"%s\" set in rule but not in global methodline",
			method2string(rule->state.methodv[i]));

	/* if no protocol set, set all for socks-rules, tcp for client-rules. */
	if (memcmp(&state.protocol, &rule->state.protocol, sizeof(state.protocol))
	== 0)
		if (client)
			rule->state.protocol.tcp = 1;
		else
			memset(&rule->state.protocol, UCHAR_MAX, sizeof(rule->state.protocol));

	/* if no proxyprotocol set, set all socks protocols. */
	if (memcmp(&state.proxyprotocol, &rule->state.proxyprotocol,
	sizeof(state.proxyprotocol)) == 0) {
		rule->state.proxyprotocol.socks_v4 = 1;
		rule->state.proxyprotocol.socks_v5 = 1;
	}

	if (*rulebase == NULL) {
		*rulebase = rule;
		(*rulebase)->number = 1;
	}
	else {
		struct rule_t *lastrule;

		/* append this rule to the end of our list. */

		lastrule = *rulebase;
		while (lastrule->next != NULL)
			lastrule = lastrule->next;

		rule->number = lastrule->number + 1;
		lastrule->next = rule;
	}

	rule->next = NULL;

	return rule;
}

static void
checkrule(rule)
	const struct rule_t *rule;
{
	size_t i;
	struct ruleaddress_t ruleaddr;
	const char *function = "checkrule()";

	if (rule->state.methodc == 0)
		yywarn("rule allows no methods");

	if (rule->user != NULL) {
		/* check that all methods given provide usernames. */
		for (i = 0; i < rule->state.methodc; ++i)
			switch (rule->state.methodv[i]) {
				case AUTHMETHOD_UNAME:
				case AUTHMETHOD_RFC931:
				case AUTHMETHOD_PAM:
					break;

				default:
					yyerror("method \"%s\" can not provide usernames",
					method2string(rule->state.methodv[i]));
			}
	}

	if (rule->src.atype == SOCKS_ADDR_IFNAME
	||  rule->dst.atype == SOCKS_ADDR_IFNAME)
		yyerror("src/dst address in rules can't use interfacenames");

	/* any port is good for testing. */
	ruleaddr = rule->rdr_from;
	ruleaddr.port.tcp = htons(0);
	if (!addressisbindable(&ruleaddr)) {
		char addr[MAXRULEADDRSTRING];

		yyerror("%s is not bindable",
		ruleaddress2string(&ruleaddr, addr, sizeof(addr)));
	}

	if (rule->rdr_to.atype == SOCKS_ADDR_IFNAME)
		yyerror("redirect to an interface (%s) is not supported (or meaningful?)",
		rule->rdr_to.addr.ifname);

#if HAVE_PAM
	if (*rule->pamservicename != NUL)
		if (!methodisset(AUTHMETHOD_PAM, rule->state.methodv,
		rule->state.methodc))
			yyerror("pamservicename set for rule but not method pam");
		else
			if (sockscf.state.pamservicename != NULL
			&& strcmp(rule->pamservicename, sockscf.state.pamservicename) != 0) {
				slog(LOG_DEBUG, "%s: %s ne %s",
				function, rule->pamservicename, sockscf.state.pamservicename);

				sockscf.state.pamservicename = NULL; /* pamservicename varies. */
			}
#endif /* HAVE_PAM */
}

static void
showuser(user)
	const struct linkedname_t *user;
{
	char buf[10240];

	users2string(user, buf, sizeof(buf));
	if (strlen(buf) > 0)
		slog(LOG_INFO, "user: %s", buf);
}

static void
showlog(log)
	const struct log_t *log;
{
	char buf[1024];

	slog(LOG_INFO, "log: %s", logs2string(log, buf, sizeof(buf)));
}


#if HAVE_LIBWRAP
static void
libwrapinit(s, request)
	int s;
	struct request_info *request;
{
	const int errno_s = errno;

	request_init(request, RQ_FILE, s, RQ_DAEMON, __progname, 0);
	fromhost(request);

	errno = errno_s;
}
#endif /* HAVE_LIBWRAP */

static int
connectisok(request, rule)
#if HAVE_LIBWRAP
	struct request_info *request;
#else
	void *request;
#endif
	const struct rule_t *rule;
{

#if HAVE_LIBWRAP

	/* do we need to involve libwrap for this rule? */
	if (*rule->libwrap != NUL
	||  sockscf.srchost.nomismatch
	||  sockscf.srchost.nounknown) {
		const char *function = "connectisok()";
		char libwrap[LIBWRAPBUF];
		uid_t euid;

		socks_seteuid(&euid, sockscf.uid.libwrap);

		/* libwrap modifies the passed buffer. */
		SASSERTX(strlen(rule->libwrap) < sizeof(libwrap));
		strcpy(libwrap, rule->libwrap);

		/* Wietse Venema says something along the lines of: */
		if (setjmp(tcpd_buf) != 0) {
			socks_reseteuid(sockscf.uid.libwrap, euid);
			swarnx("%s: failed libwrap line: %s", function, libwrap);
			return 0;	/* something got screwed up. */
		}
		process_options(libwrap, request);

		if (sockscf.srchost.nounknown)
			if (strcmp(eval_hostname(request->client), STRING_UNKNOWN) == 0) {
				slog(LOG_INFO, "%s: srchost unknown",
				eval_hostaddr(request->client));
				socks_reseteuid(sockscf.uid.libwrap, euid);
				return 0;
		}

		if (sockscf.srchost.nomismatch)
			if (strcmp(eval_hostname(request->client), STRING_PARANOID) == 0) {
				slog(LOG_INFO, "%s: srchost ip/host mismatch",
				eval_hostaddr(request->client));
				socks_reseteuid(sockscf.uid.libwrap, euid);
				return 0;
		}

		socks_reseteuid(sockscf.uid.libwrap, euid);
	}

#else	/* !HAVE_LIBWRAP */

#endif  /* !HAVE_LIBWRAP */

	return 1;
}
