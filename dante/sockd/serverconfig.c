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
"$Id: serverconfig.c,v 1.70 1999/05/13 14:58:44 karls Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP */

static int
connectisok __P((int s, struct rule_t *rule));

/*
 * Checks the connection on "s".
 * "rule" is the rule that matched the connection (not const due to libwrap
 * interaction).
 * This function should be called after each rulecheck for a new
 * connection/packet.
 *
 * Returns:
 *		If connection is acceptable: true
 *		If connection is not acceptable: false
*/

__END_DECLS

struct config_t config;
const int configtype = CONFIGTYPE_SERVER;

#if HAVE_LIBWRAP
int allow_severity, deny_severity;
#endif  /* HAVE_LIBWRAP */


struct rule_t *
addrule(newrule)
	const struct rule_t *newrule;
{
	static const struct serverstate_t state;
	const char *function = "addrule()";
	struct rule_t *rule;

	if ((rule = malloc(sizeof(*rule))) == NULL)
		serrx(1, "%s: %s", function, NOMEM);
	*rule = *newrule;

	/* try to set values not set to a sensible default. */

	/* if no command set, set all. */
	if (memcmp(&state.command, &rule->state.command, sizeof(state.command)) == 0)
		memset(&rule->state.command, UCHAR_MAX, sizeof(rule->state.command));

	/*
	 * if no method set, set all we support.  This in practice
	 * limits the methods we accept here to the globally
	 * set methods (config.methodv), since they are checked
	 * before we get to rulespesific checks.
	*/
	if (rule->state.methodc == 0) {
		char *methodv = rule->state.methodv;
		unsigned char *methodc = &rule->state.methodc;

		methodv[(*methodc)++] = AUTHMETHOD_NONE;
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
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

	/* don't touch logging, no logging is ok. */

	if (config.rule == NULL) {
		config.rule = rule;
		config.rule->number = 1;
	}
	else {
		struct rule_t *lastrule;

		/* append this rule to the end of our list. */

		lastrule = config.rule;
		while (lastrule->next != NULL)
			lastrule = lastrule->next;

		rule->number = lastrule->number + 1;
		lastrule->next = rule;
	}

	rule->next = NULL;

	return rule;
}


void
showrule(rule)
	const struct rule_t *rule;
{
	char addr[MAXRULEADDRSTRING], buf[1024];
	size_t bufused;

	slog(LOG_INFO, "rule #%d",
	rule->number);

	slog(LOG_INFO, "verdict: %s",
	rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs);

	slog(LOG_INFO, "src: %s",
	ruleaddress2string(&rule->src, addr, sizeof(addr)));

	slog(LOG_INFO, "dst: %s",
	ruleaddress2string(&rule->dst, addr, sizeof(addr)));

	showstate(&rule->state);

	bufused = snprintf(buf, sizeof(buf), "log: ");
	if (rule->log.connect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_CONNECTs);

	if (rule->log.disconnect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_DISCONNECTs);

	if (rule->log.iooperation)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_IOOPERATIONs);

	if (rule->log.data)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_DATAs);

	slog(LOG_INFO, buf);

#if HAVE_LIBWRAP
	if (*rule->libwrap != NUL)
		slog(LOG_INFO, "libwrap: %s", rule->libwrap);
#endif  /* HAVE_LIBWRAP */
}

struct rule_t *
addclient(newclient)
	const struct rule_t *newclient;
{
	const char *function = "addclient()";
	struct rule_t *client;

	if ((client = (struct rule_t *)malloc(sizeof(*client))) == NULL)
		serrx(1, "%s: %s", function, NOMEM);
	*client = *newclient;

	/* try to set values not set to a sensible default. */

	client->state.protocol.tcp = 1;

	if (config.client == NULL) {
		config.client = client;
		config.client->number = 1;
	}
	else {
		struct rule_t *lastclient;

		/* append this client to the end of our list. */

		lastclient = config.client;
		while (lastclient->next != NULL)
			lastclient = lastclient->next;

		client->number = lastclient->number + 1;
		lastclient->next = client;
	}

	client->next = NULL;

	return client;
}

void
showclient(rule)
	const struct rule_t *rule;
{
	char addr[MAXRULEADDRSTRING], buf[1024];
	size_t bufused;

	slog(LOG_INFO, "client #%d", rule->number);

	slog(LOG_INFO, "verdict: %s",
	rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs);

	slog(LOG_INFO, "from: %s",
	ruleaddress2string(&rule->src, addr, sizeof(addr)));

	slog(LOG_INFO, "to: %s",
	ruleaddress2string(&rule->dst, addr, sizeof(addr)));

	bufused = snprintf(buf, sizeof(buf), "log: ");
	if (rule->log.connect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_CONNECTs);

	if (rule->log.disconnect)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_DISCONNECTs);

	if (rule->log.iooperation)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_IOOPERATIONs);

	if (rule->log.data)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s, ",
		LOG_DATAs);

	slog(LOG_INFO, buf);

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

	if (config->domain != NULL)
		slog(LOG_INFO, "localdomain: %s", config->domain);

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

	bufused = snprintf(buf, sizeof(buf), "method(s): ");
	for (i = 0; i < config->methodc; ++i)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s%s",
		i > 0 ? ", " : "", method2string(config->methodv[i]));
	slog(LOG_INFO, buf);

	slog(LOG_INFO, "debug level: %d",
	config->option.debug);
	slog(LOG_INFO, "negotiate timeout: %lds",
	(long)config->timeout.negotiate);
	slog(LOG_INFO, "I/O timeout: %lds\n",
	(long)config->timeout.io);
	slog(LOG_INFO, "address/host mismatch tolerated: %s",
	config->srchost.nomismatch ? "no" : "yes");
	slog(LOG_INFO, "unresolvable addresses tolerated: %s",
	config->srchost.nounknown ? "no" : "yes");

	slog(LOG_INFO, "userid.privileged: %lu",
	(unsigned long)config->uid.privileged);
	slog(LOG_INFO, "userid.unprivileged: %lu",
	(unsigned long)config->uid.unprivileged);
	slog(LOG_INFO, "userid.libwrap: %lu",
	(unsigned long)config->uid.libwrap);

	bufused = snprintf(buf, sizeof(buf), "logoutput goes to: ");
	if (config->log.type & LOGTYPE_SYSLOG)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "syslog, ");
	if (config->log.type & LOGTYPE_FILE)
		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "files(%d)",
		config->log.fpc);
	slog(LOG_INFO, buf);

	if (config->option.debug) {
		struct rule_t *rule;
		int count;

		for (count = 0, rule = config->client; rule != NULL; rule = rule->next)
			++count;
		slog(LOG_INFO, "clientrules (%d): ", count);
		for (rule = config->client; rule != NULL; rule = rule->next)
			showclient(rule);

		for (count = 0, rule = config->rule; rule != NULL; rule = rule->next)
			++count;
		slog(LOG_INFO, "rules (%d): ", count);
		for (rule = config->rule; rule != NULL; rule = rule->next)
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
	rule = config.rule;
	while (rule != NULL) {
		struct rule_t *next = rule->next;

		free(rule);
		rule = next;
	}
	config.rule = NULL;

	/* clientrules too. */
	rule = config.client;
	while (rule != NULL) {
		struct rule_t *next = rule->next;

		free(rule);
		rule = next;
	}
	config.client = NULL;

	/* route; currently not supported in server. */

	/* compat, read from configfile. */
	bzero(&config.compat, sizeof(config.compat));

	/* domain, gotten via BIND. */
	bzero(config.domain, sizeof(config.domain));

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
	const char *command;
	char srcstring[MAXSOCKSHOSTSTRING], dststring[MAXSOCKSHOSTSTRING];

	command = command2string(state->command);
	sockshost2string(src, srcstring, sizeof(srcstring));
	sockshost2string(dst, dststring, sizeof(dststring));

	switch (operation) {
		case OPERATION_ACCEPT:
		case OPERATION_DISCONNECT:
			if (rule->log.connect
			||  rule->log.disconnect)
#if HAVE_LIBWRAP
				/* can't use eval_user() since it always does rfc931 lookup. */
				if (*rule->request.user != NUL) {
					slog(LOG_INFO, "%s(%d): %s: %s@%s -> %s",
					rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
					rule->number, command, rule->request.user, srcstring, dststring);
					break;
				}
#endif  /* HAVE_LIBWRAP */

			/* FALLTHROUGH */

		case OPERATION_CONNECT:
			if (rule->log.connect)
				slog(LOG_INFO, "%s(%d): %s: %s -> %s",
				rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
				rule->number, command, srcstring, dststring);
			break;

		case OPERATION_ABORT:
			if (rule->log.disconnect)
				slog(LOG_INFO, "%s(%d): %s: %s -> %s: %s",
				rule->verdict == VERDICT_PASS ? VERDICT_PASSs : VERDICT_BLOCKs,
				rule->number, command, srcstring, dststring, data);
			break;

		case OPERATION_IO:
			if (rule->log.data) {
				char *visdata;

				SASSERTX(data != NULL);

				slog(LOG_INFO, "%s(%d): %s: %s -> %s (%lu): %s",
				rule->verdict == VERDICT_BLOCK ? VERDICT_BLOCKs : VERDICT_PASSs,
				rule->number, command, srcstring, dststring,
				(unsigned long)count, strcheck(visdata = str2vis(data, count)));

				free(visdata);
			}
			else if (rule->log.iooperation)
				slog(LOG_INFO, "%s(%d): %s: %s -> %s (%lu)",
				rule->verdict == VERDICT_BLOCK ? VERDICT_BLOCKs : VERDICT_PASSs,
				rule->number, command, srcstring, dststring, (unsigned long)count);

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
	struct sockshost_t newsrc;


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
		defrule.log.connect = 1;

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

	switch (state->version) {
		case SOCKS_V4:
			switch (state->command) {
				case SOCKS_BIND:
					/*
					 * v4 bind is even more weird than v5 since the port
					 * given is the port of a existing connect.
					 * We don't check/care if there really is a matching
					 * connection but set the portnumber to wildcard so we
					 * can treat it the same way as other (v5) bind requests.
					*/
					newsrc		= *src;
					newsrc.port	= htons(0);
					src = &newsrc;	/* src is const. */
					break;
			}
			break;
	}


	for (rule = config.rule; rule != NULL; rule = rule->next) {
		/* current rule allows for selected authentication? */
		if (!methodisset(state->auth.method, rule->state.methodv,
		(size_t)rule->state.methodc))
			continue;

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

			case SOCKS_BINDREPLY:
				if (!rule->state.command.bindreply)
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

		/* state matches, check for address match. */

		if (!addressmatch(&rule->src, src, state->protocol, 0))
			continue;

		if (!addressmatch(&rule->dst, dst, state->protocol, 0))
			continue;

		break;
	}

	if (rule == NULL) /* no rules matched, match default rule. */
		rule = &defrule;
	*match = *rule;

	/*
	 * got a match, now check connection.  Connectioncheck
	 * requires the rule matched so needs to be done here.
	*/

	if (!connectisok(s, match))
		match->verdict = VERDICT_BLOCK;

	/*
	 * specialcases that we delay to here to get correct addr/rule match
	 * even if we could get the final answer before.
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

static int
connectisok(s, rule)
	int s;
	struct rule_t *rule;
{

#if HAVE_LIBWRAP
/*	const char *function = "connectisok()"; */
	char libwrap[LIBWRAPBUF];
	uid_t euid;

	socks_seteuid(&euid, config.uid.libwrap);

	request_init(&rule->request, RQ_FILE, s, RQ_DAEMON, __progname, 0);
	fromhost(&rule->request);

	/* libwrap modifies the passed buffer. */
	SASSERTX(strlen(rule->libwrap) < sizeof(libwrap));
	strcpy(libwrap, rule->libwrap);

	/* Wietse Venema says something along the lines of: */
	if (setjmp(tcpd_buf) != 0) {
		socks_reseteuid(euid);
		return 0;	/* something got screwed up. */
	}
	process_options(libwrap, &rule->request);

	if (config.srchost.nounknown)
		if (strcmp(eval_hostname(rule->request.client), STRING_UNKNOWN) == 0) {
			slog(LOG_INFO, "%s: failed lookup",
			eval_hostaddr(rule->request.client));
			socks_reseteuid(euid);
			return 0;
	}

	if (config.srchost.nomismatch)
		if (strcmp(eval_hostname(rule->request.client), STRING_PARANOID) == 0) {
			slog(LOG_INFO, "%s: ip/hostname mismatch",
			eval_hostaddr(rule->request.client));
			socks_reseteuid(euid);
			return 0;
	}

	socks_reseteuid(euid);

	if (&rule->request.client->sin == NULL) {
		SWARNX(&rule->request.client->sin);
		return 0;
	}
#else	/* !HAVE_LIBWRAP */

#endif  /* HAVE_LIBWRAP */

	return 1;
}


int
clientaddressisok(s, src, dst, protocol, match)
	int s;
	const struct sockshost_t *src;
	const struct sockshost_t *dst;
	int protocol;
	struct rule_t *match;
{
	static int init;
	static struct rule_t defrule;
	struct rule_t *client;


	/* make a somewhat sensible default rule for entries with no match. */
	if (!init) {
		init = 1;

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
		defrule.log.connect						= 1;

		/* shouldn't be used on accept() check. */
		memset(&defrule.state, 0, sizeof(defrule.state));

#if HAVE_LIBWRAP
		*defrule.libwrap = NUL;
#endif  /* HAVE_LIBWRAP */
	}

	for (client = config.client; client != NULL; client = client->next) {
		if (!addressmatch(&client->src, src, protocol, 0))
			continue;

		if (!addressmatch(&client->dst, dst, protocol, 0))
			continue;
		break;
	}

	if (client == NULL)
		client = &defrule;	/* default rule. */

	*match = *client;

	if (!connectisok(s, client))
		match->verdict = VERDICT_BLOCK;

	return match->verdict == VERDICT_PASS;
}
