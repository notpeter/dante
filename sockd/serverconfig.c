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
#include "config_parse.h"

static const char rcsid[] =
"$Id: serverconfig.c,v 1.87 1999/09/25 13:08:04 karls Exp $";

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
connectisok __P((struct request_info *request, const struct rule_t *rule,
					  struct connectionstate_t *state));
#else /* !HAVE_LIBWRAP */
static int
connectisok __P((void *request, const struct rule_t *rule,
					  struct connectionstate_t *state));
#endif /* !HAVE_LIBWRAP */
/*
 * Checks the connection on "s".
 * "rule" is the rule that matched the connection and "state" is the current
 * state.
 * This function should be called after each rulecheck for a new
 * connection/packet.
 *
 * Returns:
 *		If connection is acceptable: true
 *		If connection is not acceptable: false
 */

static struct rule_t *
addrule __P((const struct rule_t *newrule, struct rule_t **rulebase));
/*
 * Appends a copy of "newrule" to "rulebase".
 * Returns a pointer to the added rule (not "newrule").
 */

static void
checkrule __P((const struct rule_t *rule));
/*
 * Check that the rule "rule" makes sense.
 */

__END_DECLS

struct config_t config;
const int configtype = CONFIGTYPE_SERVER;

#if HAVE_LIBWRAP
int allow_severity, deny_severity;
#endif  /* HAVE_LIBWRAP */

struct rule_t *
addclientrule(newrule)
	const struct rule_t *newrule;
{
	struct rule_t *rule;

	rule = addrule(newrule, &config.crule);

	/*
	 * there are a few things that need to be changed versus the generic
	 * init done by addrule().
	 */

	if (rule->user != NULL) {
		/*
		 * this is a clientrule so strip away any methods that
		 * can not provide a username without socks negotiation.
		 */
		int i;

		for (i = 0; i < rule->state.methodc; ++i)
			switch (rule->state.methodv[i]) {
				case AUTHMETHOD_RFC931:
					break;

				default:
					rule->state.methodv[i--]
					= rule->state.methodv[--rule->state.methodc];
			}
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

	rule = addrule(newrule, &config.srule);

	if (rule->user == NULL) {
		/*
		 * For each method taking a username, default to
		 * allowing everybody that's in the passwordfile.
		 */
		int i;

		for (i = 0; i < rule->state.methodc; ++i)
			switch (rule->state.methodv[i]) {
				case AUTHMETHOD_UNAME:
				case AUTHMETHOD_RFC931:
					if (adduser(&rule->user, method2string(rule->state.methodv[i]))
					== NULL)
						serrx(EXIT_FAILURE, NOMEM);
					break;
			}
	}

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

	for (user = *ruleuser; user != NULL; user = user->next)
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

	slog(LOG_INFO, "socks-rule #%d",
	rule->number);

	slog(LOG_INFO, "verdict: %s",
	rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs);

	slog(LOG_INFO, "src: %s",
	ruleaddress2string(&rule->src, addr, sizeof(addr)));

	slog(LOG_INFO, "dst: %s",
	ruleaddress2string(&rule->dst, addr, sizeof(addr)));

	showuser(rule->user);

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

	slog(LOG_INFO, "client-rule #%d", rule->number);

	slog(LOG_INFO, "verdict: %s",
	rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs);

	slog(LOG_INFO, "from: %s",
	ruleaddress2string(&rule->src, addr, sizeof(addr)));

	slog(LOG_INFO, "to: %s",
	ruleaddress2string(&rule->dst, addr, sizeof(addr)));

	showuser(rule->user);

	showlog(&rule->log);

#if HAVE_LIBWRAP
	if (*rule->libwrap != NUL)
		slog(LOG_INFO, "libwrap: %s", rule->libwrap);
#endif  /* HAVE_LIBWRAP */
}

void
showconfig(config)
	const struct config_t *config;
{
	int i;
	char address[MAXSOCKADDRSTRING], buf[1024];
	size_t bufused;

	slog(LOG_INFO, "internal addresses (%d):", config->internalc);
	for (i = 0; i < config->internalc; ++i)
		slog(LOG_INFO, "%s",
		/* LINTED pointer casts may be troublesome */
		sockaddr2string((struct sockaddr *)&config->internalv[i], address,
		sizeof(address)));

	slog(LOG_INFO, "external addresses (%d):", config->externalc);
	for (i = 0; i < config->externalc; ++i)
		slog(LOG_INFO, "%s",
		/* LINTED pointer casts may be troublesome */
		sockaddr2string((struct sockaddr *)&config->externalv[i], address,
		sizeof(address)));

	bufused = snprintf(buf, sizeof(buf), "compatibility options: ");
	if (config->compat.reuseaddr)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "reuseaddr, ");
	if (config->compat.sameport)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "sameport, ");
	slog(LOG_INFO, buf);

	bufused = snprintf(buf, sizeof(buf), "extensions enabled: ");
	if (config->extension.bind)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "bind, ");
	slog(LOG_INFO, buf);

	bufused = snprintf(buf, sizeof(buf), "logoutput goes to: ");
	if (config->log.type & LOGTYPE_SYSLOG)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "syslog, ");
	if (config->log.type & LOGTYPE_FILE)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "files (%d)",
		config->log.fpc);
	slog(LOG_INFO, buf);

	slog(LOG_INFO, "debug level: %d",
	config->option.debug);

	bufused = snprintf(buf, sizeof(buf), "resolveprotocol: ");
	switch (config->resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
			bufused += snprintf(&buf[bufused], sizeof(buf) - bufused,
			PROTOCOL_TCPs);
			break;

		case RESOLVEPROTOCOL_UDP:
			bufused += snprintf(&buf[bufused], sizeof(buf) - bufused,
			PROTOCOL_UDPs);
			break;
	
		case RESOLVEPROTOCOL_FAKE:
			bufused += snprintf(&buf[bufused], sizeof(buf) - bufused,
			"fake");
			break;

		default:
			SERRX(config->resolveprotocol);
	}
	slog(LOG_INFO, buf);
			
	slog(LOG_INFO, "address/host mismatch tolerated: %s",
	config->srchost.nomismatch ? "no" : "yes");
	slog(LOG_INFO, "unresolvable addresses tolerated: %s",
	config->srchost.nounknown ? "no" : "yes");

	slog(LOG_INFO, "negotiate timeout: %lds",
	(long)config->timeout.negotiate);
	slog(LOG_INFO, "I/O timeout: %lds",
	(long)config->timeout.io);

	slog(LOG_INFO, "euid: %d", config->state.euid);

	slog(LOG_INFO, "userid.privileged: %lu",
	(unsigned long)config->uid.privileged);
	slog(LOG_INFO, "userid.unprivileged: %lu",
	(unsigned long)config->uid.unprivileged);
	slog(LOG_INFO, "userid.libwrap: %lu",
	(unsigned long)config->uid.libwrap);

	bufused = snprintf(buf, sizeof(buf), "method(s): ");
	for (i = 0; i < config->methodc; ++i)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s%s",
		i > 0 ? ", " : "", method2string(config->methodv[i]));
	slog(LOG_INFO, buf);

	if (config->option.debug) {
		struct rule_t *rule;
		int count;

		for (count = 0, rule = config->crule; rule != NULL; rule = rule->next)
			++count;
		slog(LOG_INFO, "client-rules (%d): ", count);
		for (rule = config->crule; rule != NULL; rule = rule->next)
			showclient(rule);

		for (count = 0, rule = config->srule; rule != NULL; rule = rule->next)
			++count;
		slog(LOG_INFO, "socks-rules (%d): ", count);
		for (rule = config->srule; rule != NULL; rule = rule->next)
			showrule(rule);
	}
}


void
resetconfig(void)
{
	struct rule_t *rule;

	/*
	 * internal; don't touch, only settable at start.
	 */

	/* external addresses can be changed. */
	free(config.externalv);
	config.externalv = NULL;
	config.externalc = 0;

	/* delete all old rules */
	rule = config.srule;
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
	config.srule = NULL;

	/* clientrules too. */
	rule = config.crule;
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
	config.crule = NULL;

	/* route; currently not supported in server. */

	/* compat, read from configfile. */
	bzero(&config.compat, sizeof(config.compat));

	/* extensions, read from configfile. */
	bzero(&config.extension, sizeof(config.extension));

	/* log; only settable at start. */

	/* option; only settable at commandline. */

	/* resolveprotocol, read from configfile. */
	bzero(&config.resolveprotocol, sizeof(config.resolveprotocol));

	/* srchost, read from configfile. */
	bzero(&config.srchost, sizeof(config.srchost));

	/* stat: keep it. */

	/* state; keep it. */

	/* methods, read from configfile. */
	bzero(config.methodv, sizeof(config.methodv));
	config.methodc = 0;

	/* timeout, read from configfile. */
	bzero(&config.timeout, sizeof(config.timeout));

	/* uid, read from configfile. */
	bzero(&config.uid, sizeof(config.uid));

	/*
	 * initialize misc options to sensible default.
	 */

	config.resolveprotocol		= RESOLVEPROTOCOL_UDP;
	config.option.keepalive		= 1;
	config.timeout.negotiate	= SOCKD_NEGOTIATETIMEOUT;
	config.timeout.io				= SOCKD_IOTIMEOUT;
}

void
iolog(rule, state, operation, src, dst, data, count)
	struct rule_t *rule;
	const struct connectionstate_t *state;
	int operation;
	const struct sockshost_t *src, *dst;
	const char *data;
	size_t count;
{
	char srcstring[MAXSOCKSHOSTSTRING + MAXNAMELEN + sizeof("@") - 1];
	char dststring[MAXSOCKSHOSTSTRING];
	const char *name;
	int p;

	name = NULL;
	switch (state->auth.method) {
		case AUTHMETHOD_NONE:
		case AUTHMETHOD_NOACCEPT: /* closing connection. */
			/*
			 * doesn't take any space so it's possible it has a name, even
			 * if method doesn't indicate it.
			 */
			name = state->auth.mdata.rfc931.name;
			break;

		case AUTHMETHOD_UNAME:
			name = state->auth.mdata.uname.name;
			break;

		case AUTHMETHOD_RFC931:
			name = state->auth.mdata.rfc931.name;
			break;

		default:
			SERRX(state->auth.method);
	}

	if (name != NULL && *name != NUL)
		p = snprintf(srcstring, sizeof(srcstring), "%s@", name);
	else
		p = 0;

	sockshost2string(src, &srcstring[p], sizeof(srcstring) - p);
	sockshost2string(dst, dststring, sizeof(dststring));

	/* XXX should probably include authinfo somewhere here too. */
	switch (operation) {
		case OPERATION_ACCEPT:
		case OPERATION_DISCONNECT:
		case OPERATION_CONNECT:
			if (rule->log.connect || rule->log.disconnect)
				slog(LOG_INFO, "%s(%d): %s: %s -> %s",
				rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
				rule->number, command2string(state->command),
				srcstring, dststring);
			break;

		case OPERATION_ABORT:
			if (rule->log.disconnect || rule->log.error)
				slog(LOG_INFO, "%s(%d): %s abort: %s -> %s: %s",
				rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
				rule->number, command2string(state->command), srcstring, dststring,
				data == NULL ? strerror(errno) : data);
			break;

		case OPERATION_ERROR:
			if (rule->log.error)
				slog(LOG_INFO, "%s(%d): %s error: %s -> %s: %s",
				rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
				rule->number, protocol2string(state->protocol), srcstring,
				dststring, data == NULL ? strerror(errno) : data);
			break;

		case OPERATION_IO:
			if (rule->log.data) {
				char *visdata;

				SASSERTX(data != NULL);

				slog(LOG_INFO, "%s(%d): %s: %s -> %s (%lu): %s",
				rule->verdict == VERDICT_BLOCK ? VERDICT_BLOCKs : VERDICT_PASSs,
				rule->number, protocol2string(state->protocol),
				srcstring, dststring, (unsigned long)count,
				strcheck(visdata = str2vis(data, count)));

				free(visdata);
			}
			else if (rule->log.iooperation)
				slog(LOG_INFO, "%s(%d): %s: %s -> %s (%lu)",
				rule->verdict == VERDICT_BLOCK ? VERDICT_BLOCKs : VERDICT_PASSs,
				rule->number, protocol2string(state->protocol),
				srcstring, dststring, (unsigned long)count);
			break;

		default:
			SERRX(operation);
	}
}

int
rulespermit(s, match, state, src, dst)
	int s;
	struct rule_t *match;
	struct connectionstate_t *state;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
{
	const char *function = "rulespermit()";
	static int init;
	static struct rule_t defrule;
	struct rule_t *rule;
	struct connectionstate_t ostate;
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

		if (config.option.debug) {
			defrule.log.connect 		= 1;
			defrule.log.disconnect	= 1;
			defrule.log.error			= 1;
			defrule.log.iooperation	= 1;
		}
		else {
			memset(&defrule.log, 0, sizeof(defrule.log));
			defrule.log.connect = 1;
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

	/* what rulebase to use.  XXX nicer way to do this. */
	switch (state->command) {
		case SOCKS_ACCEPT:
			/* only set by negotiate children so must be clientrule. */
			rule = config.crule;
			break;

		default:
			/* everyone else, socksrules. */
			rule = config.srule;
			break;
	}

	/* let "state" be unchanged from original unless we actually get a match. */
	for (ostate = *state; rule != NULL; rule = rule->next, *state = ostate) {
		char *name, *password;

		/* current rule covers desired command? */
		switch (state->command) {
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

			/* client-rule commands. */
			case SOCKS_ACCEPT:
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

		/* current rule allows for selected authentication? */
		if (!methodisset(state->auth.method, rule->state.methodv,
		(size_t)rule->state.methodc))
			/*
			 * There are some "extra" methods that are independent of
			 * socks protocol negotiation and it's thus possible
			 * to get a match on them even if above check failed.
			 * Currently it's only rfc931.
			 */

#if HAVE_LIBWRAP
			if (methodisset(AUTHMETHOD_RFC931, rule->state.methodv,
			(size_t)rule->state.methodc)) {
				strncpy(state->auth.mdata.rfc931.name, eval_user(&libwraprequest),
				sizeof(state->auth.mdata.rfc931.name) - 1);

				if (state->auth.mdata.rfc931.name[
				sizeof(state->auth.mdata.rfc931.name) - 1] != NUL) {
					slog(LOG_INFO, "%s: rfc931 name truncated", function);
					state->auth.mdata.rfc931.name[
					sizeof(state->auth.mdata.rfc931.name) - 1] = NUL;
				}

				state->auth.method = AUTHMETHOD_RFC931;
			}
			else
#endif /* HAVE_LIBWRAP */
				continue;

		SASSERTX(methodisset(state->auth.method, rule->state.methodv,
		(size_t)rule->state.methodc));

		switch (state->auth.method) {
			case AUTHMETHOD_UNAME:
				name		= state->auth.mdata.uname.name;
				password	= state->auth.mdata.uname.password;
				break;

			case AUTHMETHOD_RFC931:
				name		= state->auth.mdata.rfc931.name;
				password	= NULL;
				break;

			default:
				name = password = NULL;
		}

		if (name != NULL && rule->user != NULL) {
			const char *methodname;
			char srcstring[MAXSOCKSHOSTSTRING];
			struct linkedname_t *ruleuser;

			/*
			 * The rule->user names restricts access further, only names
			 * appearing there and in the passwordfile are matched.
			 * An alias for "everyone" is a name that is the same as the
			 * name of the selected method.
			 */

			methodname = method2string(state->auth.method);
			ruleuser = rule->user;
			do {
				if (strcmp(methodname, ruleuser->name) == 0)
					break;
				else if (string2method(name) >= 0)
					slog(LOG_INFO, "%s: suspicious username from %s: %s",
					function, sockshost2string(src, srcstring, sizeof(srcstring)),
					name);
				else if (strcmp(name, ruleuser->name)	== 0)
					break;
			} while ((ruleuser = ruleuser->next) != NULL);

			if (ruleuser == NULL)
				continue; /* no match. */

			if (!state->auth.checked) {
				state->auth.checked = 1;
				if (!passwordmatch(name, password))
					continue;
			}
		}

		/*
		 * This is a little tricky, but for some commands we may not
		 * have all info at time of (preliminary) rulechecks.
		 * What we want to do if there is no (complete) address given is
		 * to see if there's any chance at all the rules will permit this
		 * request when the address (later) becomes available. 
		 * We therefore continue to scan the rules until we either get
		 * a pass (ignoring peer with missing info), or the default block
		 * is triggered.
		 */

		if (src != NULL) {
			if (!addressmatch(&rule->src, src, state->protocol, 0))
				continue;
		}
		else
			if (rule->verdict == VERDICT_BLOCK)
				continue; /* continue scan. */

		if (dst != NULL) {
			if (!addressmatch(&rule->dst, dst, state->protocol, 0))
				continue;
		}
		else
			if (rule->verdict == VERDICT_BLOCK)
				continue; /* continue scan. */

		break;
	}

	if (rule == NULL) /* no rules matched; match default rule. */
		rule = &defrule;
	*match = *rule;

	/*
	 * got our rule, now check connection.  Connectioncheck
	 * requires the rule matched so needs to be delayed til here.
	 */

	if (!connectisok(&libwraprequest, match, state))
		match->verdict = VERDICT_BLOCK;

	/*
	 * specialcases that we delay til here to get correct addr/rule match,
	 * even if we could have decided on the final answer before.
	 */
	switch (state->command) {
		case SOCKS_BIND:
			if (dst->atype == SOCKS_ADDR_IPV4 && dst->addr.ipv4.s_addr == htonl(0))
				if (!config.extension.bind) {
					slog(LOG_DEBUG, "%s: client requested disabled extension: bind",
					function);
					match->verdict = VERDICT_BLOCK;
				}
			break;
	}

	return match->verdict == VERDICT_PASS;
}

static struct rule_t *
addrule(newrule, rulebase)
	const struct rule_t *newrule;
	struct rule_t **rulebase;
{
	static const struct serverstate_t state;
	const char *function = "addrule()";
	struct rule_t *rule;

	if ((rule = malloc(sizeof(*rule))) == NULL)
		serrx(1, "%s: %s", function, NOMEM);
	*rule = *newrule;

	/* try to set values not set to a sensible default. */

	if (config.option.debug) {
		rule->log.connect 		= 1;
		rule->log.disconnect		= 1;
		rule->log.error			= 1;
		rule->log.iooperation	= 1;
	}
	/* else; don't touch logging, no logging is ok. */

	/* if no command set, set all. */
	if (memcmp(&state.command, &rule->state.command, sizeof(state.command)) == 0)
		memset(&rule->state.command, UCHAR_MAX, sizeof(rule->state.command));

	/*
	 * If no method set, set all we support.  This in practice
	 * limits the methods we accept here to the globally set methods
	 * (config.methodv), since they are checked before we get to
	 * rulespesific checks.  We can't just copy config.methodv
	 * since it may not be set yet.
	 */
	if (rule->state.methodc == 0) {
		int *methodv = rule->state.methodv;
		int *methodc = &rule->state.methodc;

		if (rule->user == NULL)
			methodv[(*methodc)++] = AUTHMETHOD_NONE;

		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
#if HAVE_LIBWRAP
		methodv[(*methodc)++] = AUTHMETHOD_RFC931;
#endif
	}

	/* if no protocol set, set all. */
	if (memcmp(&state.protocol, &rule->state.protocol, sizeof(state.protocol))
	== 0)
		memset(&rule->state.protocol, UCHAR_MAX, sizeof(rule->state.protocol));

	/* if no proxyprotocol set, set all except msproxy. */
	if (memcmp(&state.proxyprotocol, &rule->state.proxyprotocol,
	sizeof(state.proxyprotocol)) == 0) {
		memset(&rule->state.proxyprotocol, UCHAR_MAX,
		sizeof(rule->state.proxyprotocol));

		rule->state.proxyprotocol.msproxy_v2 = 0;
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

	if (rule->user != NULL)
		if (rule->state.methodc == 0)
			yyerror("rule restricts by name, but no username-based method given");
}

static void
showuser(user)
	const struct linkedname_t *user;
{
	char buf[10240];
	size_t bufused;

	bufused = snprintf(buf, sizeof(buf), "user: ");
	for (; user != NULL; user = user->next)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		user->name);

	if (bufused > sizeof("user: "))
		slog(LOG_INFO, buf);
}

static void
showlog(log)
	const struct log_t *log;
{
	char buf[1024];
	size_t bufused;

	bufused = snprintf(buf, sizeof(buf), "log: ");

	if (log->connect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_CONNECTs);

	if (log->disconnect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_DISCONNECTs);

	if (log->data)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_DATAs);

	if (log->error)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_ERRORs);

	if (log->iooperation)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_IOOPERATIONs);

	slog(LOG_INFO, buf);
}


#if HAVE_LIBWRAP
static void
libwrapinit(s, request)
	int s;
	struct request_info *request;
{

	request_init(request, RQ_FILE, s, RQ_DAEMON, __progname, 0);
	fromhost(request);
}
#endif /* HAVE_LIBWRAP */

static int
connectisok(request, rule, state)
#if HAVE_LIBWRAP
	struct request_info *request;
#else
	void *request;
#endif
	const struct rule_t *rule;
	struct connectionstate_t *state;
{

#if HAVE_LIBWRAP

	/* do we need to involve libwrap for this rule? */
	if (rule->libwrap != NULL
	||  config.srchost.nomismatch
	||  config.srchost.nounknown) {
		const char *function = "connectisok()";
		char libwrap[LIBWRAPBUF];
		uid_t euid;
		int checkforname;

		socks_seteuid(&euid, config.uid.libwrap);

		/* libwrap modifies the passed buffer. */
		SASSERTX(strlen(rule->libwrap) < sizeof(libwrap));
		strcpy(libwrap, rule->libwrap);

		/* Wietse Venema says something along the lines of: */
		if (setjmp(tcpd_buf) != 0) {
			socks_reseteuid(config.uid.libwrap, euid);
			swarnx("%s: failed libwrap line: %s", function, libwrap);
			return 0;	/* something got screwed up. */
		}
		process_options(libwrap, request);

		/*
		 * check if we got a username and won't clobber anything by saving it.
		 */
		switch (state->auth.method) {
			case AUTHMETHOD_NONE:	/* doesn't take any memory from rfc931. */
				checkforname = 1;
				break;

			default:
				checkforname = 0;	/* can't take it or should already have it. */
		}

		if (checkforname) {
			/* XXX can't use eval_user() since it always does rfc931 lookup. */
			if (*request->user != NUL) {
				strncpy(state->auth.mdata.rfc931.name, request->user,
				sizeof(state->auth.mdata.rfc931.name) - 1);

				if (state->auth.mdata.rfc931.name
				[sizeof(state->auth.mdata.rfc931.name) - 1] != NUL) {
					slog(LOG_DEBUG, "%s: rfc931 name too long, truncated", function);
					state->auth.mdata.rfc931.name
					[sizeof(state->auth.mdata.rfc931.name)
					- 1] = NUL;
				}
			}
		}

		if (config.srchost.nounknown)
			if (strcmp(eval_hostname(request->client), STRING_UNKNOWN) == 0) {
				slog(LOG_INFO, "%s: srchost unknown",
				eval_hostaddr(request->client));
				socks_reseteuid(config.uid.libwrap, euid);
				return 0;
		}

		if (config.srchost.nomismatch)
			if (strcmp(eval_hostname(request->client), STRING_PARANOID) == 0) {
				slog(LOG_INFO, "%s: srchost ip/host mismatch",
				eval_hostaddr(request->client));
				socks_reseteuid(config.uid.libwrap, euid);
				return 0;
		}

		socks_reseteuid(config.uid.libwrap, euid);
	}

#else	/* !HAVE_LIBWRAP */

#endif  /* !HAVE_LIBWRAP */

	return 1;
}
