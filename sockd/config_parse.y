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

%{

#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.121 1999/12/22 09:29:23 karls Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

__END_DECLS

extern int yylineno;
extern char *yytext;

#if SOCKS_SERVER
static struct rule_t				ruleinit;
static struct rule_t				rule;				/* new rule.							*/
static struct protocol_t		protocolmem;	/* new protocolmem.					*/
struct linkedname_t				**userbase;		/* users rule applies to.			*/
#endif

#if SOCKS_CLIENT
static struct serverstate_t	state;
static struct route_t			route;			/* new route.							*/
static struct ruleaddress_t	gw;				/* new gateway.						*/
#endif


static struct ruleaddress_t	src;				/* new src.								*/
static struct ruleaddress_t	dst;				/* new dst.								*/
static struct ruleaddress_t	*ruleaddress;	/* current ruleaddress				*/
static struct extension_t		*extension;		/* new extensions						*/
static struct proxyprotocol_t	*proxyprotocol;/* proxy protocol.					*/

static char							*atype;			/* atype of new address.			*/
static struct in_addr			*ipaddr;			/* new ipaddress						*/
static struct in_addr			*netmask;		/* new netmask							*/
static char							*domain;			/* new domain.							*/

static in_port_t					*port_tcp;		/* new tcp portnumber.				*/
static in_port_t					*port_udp;		/* new udp portnumber.				*/
static int							*methodv;		/* new authmethods.					*/
static int							*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/

static const struct {
	const char *name;
	const int value;
} syslogfacility[] = {
#ifdef LOG_AUTH
	{ "auth",	LOG_AUTH		},
#endif /* LOG_AUTH */
#ifdef LOG_AUTHPRIV
	{ "authpriv",	LOG_AUTHPRIV		},
#endif /* LOG_AUTHPRIV */
#ifdef LOG_DAEMON
	{ "daemon",	LOG_DAEMON	},
#endif /* LOG_DAEMON */
#ifdef LOG_USER
	{ "user",	LOG_USER		},
#endif /* LOG_USER */
#ifdef LOG_LOCAL0
	{ "local0",	LOG_LOCAL0	},
#endif /* LOG_LOCAL0 */
#ifdef LOG_LOCAL1
	{ "local1",	LOG_LOCAL1	},
#endif /* LOG_LOCAL1 */
#ifdef LOG_LOCAL2
	{ "local2",	LOG_LOCAL2	},
#endif /* LOG_LOCAL2 */
#ifdef LOG_LOCAL3
	{ "local3",	LOG_LOCAL3	},
#endif /* LOG_LOCAL3 */
#ifdef LOG_LOCAL4
	{ "local4",	LOG_LOCAL4	},
#endif /* LOG_LOCAL4 */
#ifdef LOG_LOCAL5
	{ "local5",	LOG_LOCAL5	},
#endif /* LOG_LOCAL5 */
#ifdef LOG_LOCAL6
	{ "local6",	LOG_LOCAL6	},
#endif /* LOG_LOCAL6 */
#ifdef LOG_LOCAL7
	{ "local7",	LOG_LOCAL7	}
#endif /* LOG_LOCAL7 */
};


#define YYDEBUG 1

#define ADDMETHOD(method) \
	do { \
		if (*methodc >= AUTHMETHOD_MAX)	\
			yyerror("internal error or duplicate methods given");	\
		methodv[(*methodc)++] = method; \
	} while (0)


%}

%union {
	char	*string;
	uid_t	uid;
}


%type <string> configtype serverline clientline deprecated
%token <string> SERVERCONFIG CLIENTCONFIG DEPRECATED

%type	<string> protocol protocols protocolname
%type	<string> proxyprotocol proxyprotocolname proxyprotocols
%type	<string> user username usernames
%type	<string> resolveprotocol resolveprotocolname
%type	<string> srchost srchostoption srchostoptions
%type	<string> command commands commandname
%type	<string> routeinit

	/* clientconfig exclusive. */
%type	<string> clientinit clientconfig
%type	<string> clientoption
%type	<string> debuging


	/* serverconfig exclusive */
%type	<string> iotimeout connecttimeout
%type	<string> extension extensionname extensions
%type	<string> internal internalinit external externalinit
%type	<string> logoutput logoutputdevice logoutputdevices
%type	<string> compatibility compatibilityname compatibilitys
%type	<string> authmethod authmethods authmethodname
%type	<string> serveroption
%type	<string> serverinit serverconfig
%type	<string> userids user_privileged user_unprivileged user_libwrap
%type	<uid>		userid

%token	<string> CLIENTRULE
%token	<string> INTERNAL EXTERNAL
%token	<string> DEBUGING RESOLVEPROTOCOL
%token	<string> SRCHOST NOMISMATCH NOUNKNOWN
%token	<string> EXTENSION BIND PRIVILEGED
%token	<string> IOTIMEOUT CONNECTTIMEOUT
%token	<string> METHOD NONE GSSAPI UNAME RFC931
%token	<string> COMPATIBILITY REUSEADDR SAMEPORT
%token	<string> USERNAME
%token	<string> USER_PRIVILEGED USER_UNPRIVILEGED USER_LIBWRAP
%token	<string> LOGOUTPUT LOGFILE

	/* route */
%type	<string> route
%type	<string> via gateway routeoption routeoptions

%token	<string> ROUTE VIA

	/* rulelines */
%type	<string> rule ruleoption ruleoptions
%type	<string> clientrule clientruleoption clientruleoptions
%type	<string> verdict
%type	<string> fromto
%type	<string> log logs logname
%type	<string> libwrap
%type	<string> srcaddress dstaddress
%type	<string> address ipaddress gwaddress domain direct
%type	<string> from to
%type	<string> netmask
%type	<string> port portrange portstart portoperator portnumber portservice

%token <string> VERDICT_BLOCK VERDICT_PASS
%token <string> PROTOCOL PROTOCOL_TCP PROTOCOL_UDP PROTOCOL_FAKE
%token <string> PROXYPROTOCOL PROXYPROTOCOL_SOCKS_V4 PROXYPROTOCOL_SOCKS_V5
					 PROXYPROTOCOL_MSPROXY_V2
%token <string> USER
%token <string> COMMAND COMMAND_BIND COMMAND_CONNECT COMMAND_UDPASSOCIATE								 COMMAND_BINDREPLY COMMAND_UDPREPLY
%token <string> ACTION
%token <string> LINE
%token <string> LIBWRAPSTART
%token <string> OPERATOR
%token <string> LOG LOG_CONNECT  LOG_DATA LOG_DISCONNECT LOG_ERROR									    LOG_IOOPERATION
%token <string> IPADDRESS DOMAIN DIRECT
%token <string> PORT PORTNUMBER SERVICENAME
%token <string> NUMBER
%token <string> FROM TO

%%


	/*
	 * first token we get should say whether we are parsing for client
	 * or server.  Init as appropriate.
	 */

configtype:	serverinit serverline
	|	clientinit clientline
	;


serverinit:	SERVERCONFIG {
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &config.extension;
		methodv			= config.methodv;
		methodc			= &config.methodc;
#endif
	}
	;


serverline:	{ $$ = NULL; }
	|	serverline '\n'
	|	serverline serverconfig
	|	serverline clientrule
	|	serverline rule
	;

clientline:	{ $$ = NULL; }
	|	clientline '\n'
	|	clientline clientconfig
	|	clientline route
	;


clientinit:	CLIENTCONFIG {
	}
	;

clientconfig:	clientoption
	|  deprecated
	;

serverconfig:	authmethod
	|  deprecated
	|	internal
	|	external
	|	logoutput
	|	serveroption
	|	userids
	;

serveroption:	compatibility
	|	connecttimeout
	|	extension
	|	iotimeout
	|	resolveprotocol
	|	srchost
	;


deprecated:	DEPRECATED {
		yyerror("given keyword is deprecated");
	}

route:	ROUTE routeinit '{' routeoptions fromto gateway routeoptions '}' {
#if SOCKS_CLIENT
		route.src		= src;
		route.dst		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
#endif
	}
	;

routeinit: {
#if SOCKS_CLIENT
		command			= &state.command;
		extension		= &state.extension;
		methodv			= state.methodv;
		methodc			= &state.methodc;
		protocol			= &state.protocol;
		proxyprotocol	= &state.proxyprotocol;

		bzero(&state, sizeof(state));
		bzero(&route, sizeof(route));
		bzero(&gw, sizeof(gw));
		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		src.atype		= SOCKS_ADDR_IPV4;
		dst.atype		= SOCKS_ADDR_IPV4;
#endif
	}
	;


proxyprotocol:	PROXYPROTOCOL ':' proxyprotocols
	;

proxyprotocolname:	PROXYPROTOCOL_SOCKS_V4 {
			proxyprotocol->socks_v4 = 1;
	}
	|	PROXYPROTOCOL_SOCKS_V5 {
			proxyprotocol->socks_v5 = 1;
	}
	|  PROXYPROTOCOL_MSPROXY_V2 {
			proxyprotocol->msproxy_v2 = 1;
	}
	;

proxyprotocols: proxyprotocolname
	|	proxyprotocolname proxyprotocols
	;

user: USER ':' usernames
	;

username:	USERNAME {
#if SOCKS_SERVER
#if !HAVE_LIBWRAP
		if (strcmp($1, method2string(AUTHMETHOD_RFC931)) == 0)
			yyerror("method rfc931 requires libwrap");
#endif /* !HAVE_LIBWRAP */
		if (adduser(userbase, $1) == NULL)
			yyerror(NOMEM);
#endif /* SOCKS_SERVER */
	}
	;

usernames:	username
	|	username usernames
	;

extension:	EXTENSION ':' extensions
	;

extensionname:	BIND {
			extension->bind = 1;
	}
	;

extensions:	extensionname
	|	extensionname extensions
	;


internal:	INTERNAL internalinit ':' ipaddress port {
#if SOCKS_SERVER
		if (config.state.init) {
			int i;

			for (i = 0; i < config.internalc; ++i)
				if (config.internalv[i].addr.sin_addr.s_addr == ipaddr->s_addr
				&&	 config.internalv[i].addr.sin_port == *port_tcp)
					break;

			if (i == config.internalc)
				swarnx("can not change internal addresses once running");
		}
#endif /* SOCKS_SERVER */
	}
	;

internalinit: {
#if SOCKS_SERVER
	static struct ruleaddress_t mem;
	struct servent	*service;

	addressinit(&mem);

	if (!config.state.init) {
		if ((config.internalv = (struct listenaddress_t *)
		realloc(config.internalv, sizeof(*config.internalv) * ++config.internalc))
		== NULL)
			yyerror(NOMEM);

		bzero(&config.internalv[config.internalc - 1].addr,
		sizeof((*config.internalv).addr));
		config.internalv[config.internalc - 1].addr.sin_family = AF_INET;

		ipaddr		= &config.internalv[config.internalc - 1].addr.sin_addr;
		port_tcp		= &config.internalv[config.internalc - 1].addr.sin_port;
	}
	else { /* can only set internal addresses once. */
		static struct in_addr inaddrmem;
		static in_port_t portmem;

		ipaddr		= &inaddrmem;
		port_tcp		= &portmem;
	}

	/* set default port. */
	if ((service = getservbyname("socks", "tcp")) == NULL)
		*port_tcp = htons(SOCKD_PORT);
	else
		*port_tcp = service->s_port;
#endif
	}
	;

external:	EXTERNAL externalinit ':' ipaddress {
#if SOCKS_SERVER
		if (config.externalv[config.externalc - 1].sin_addr.s_addr
		== htonl(INADDR_ANY))
			yyerror("external address can't be a wildcard address");
#endif
		}
	;

externalinit: {
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		if ((config.externalv = (struct sockaddr_in *)realloc(config.externalv,
		sizeof(*config.externalv) * ++config.externalc)) == NULL)
			yyerror(NOMEM);

		bzero(&config.externalv[config.externalc - 1], sizeof(*config.externalv));
		config.externalv[config.externalc - 1].sin_family = AF_INET;

		addressinit(&mem);

		ipaddr = &config.externalv[config.externalc - 1].sin_addr;
#endif
	}
	;

clientoption:	logoutput
	|	debuging
	|	resolveprotocol
	;

logoutput: LOGOUTPUT ':' logoutputdevices
	;

logoutputdevice:	LOGFILE {
		if (!config.state.init) {
			const char *syslogname = "syslog";

			if (strncmp($1, syslogname, strlen(syslogname)) == 0
			&& ($1[strlen(syslogname)] == NUL || $1[strlen(syslogname)] == '/')) {
				char *sl;

				config.log.type |= LOGTYPE_SYSLOG;

				if (*(sl = &($1[strlen(syslogname)])) == '/') { /* facility. */
					size_t i;

					for (i = 0, ++sl; i < ELEMENTS(syslogfacility); ++i)
						if (strcmp(sl, syslogfacility[i].name) == 0)
							break;

					if (i == ELEMENTS(syslogfacility))
						serrx(EXIT_FAILURE, "unknown syslog facility \"%s\"", sl);
					config.log.facility = syslogfacility[i].value;
				}
				else
					config.log.facility = LOG_DAEMON; /* default. */
			}
			else {
				config.log.type |= LOGTYPE_FILE;

				if ((config.log.fpv = (FILE **)realloc(config.log.fpv,
				sizeof(*config.log.fpv) * (config.log.fpc + 1))) == NULL
				|| (config.log.fplockv = (int *)realloc(config.log.fplockv,
				sizeof(*config.log.fplockv) * (config.log.fpc + 1))) == NULL)
					serrx(EXIT_FAILURE, NOMEM);

				if ((config.log.fplockv[config.log.fpc]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp($1, "stdout") == 0)
					config.log.fpv[config.log.fpc] = stdout;
				else if (strcmp($1, "stderr") == 0)
					config.log.fpv[config.log.fpc] = stderr;
				else {
					int flag;

					if ((config.log.fpv[config.log.fpc] = fopen($1, "a"))
					== NULL)
						serr(EXIT_FAILURE, "fopen(%s)", $1);

					if ((flag = fcntl(fileno(config.log.fpv[config.log.fpc]),
					F_GETFD, 0)) == -1
					||  fcntl(fileno(config.log.fpv[config.log.fpc]), F_SETFD,
					flag | FD_CLOEXEC) == -1)
						serr(EXIT_FAILURE, "fcntl(F_GETFD/F_SETFD)");
				}
				++config.log.fpc;
			}
		}
		else
			;	/* XXX warn/exit if output changed. */
	}
	;

logoutputdevices:	logoutputdevice
	|	logoutputdevice logoutputdevices
	;

userids:	user_privileged
	|	user_unprivileged
	|	user_libwrap
	;

user_privileged:	USER_PRIVILEGED ':' userid {
#if SOCKS_SERVER
		config.uid.privileged			= $3;
		config.uid.privileged_isset	= 1;
#endif
	}
	;

user_unprivileged:	USER_UNPRIVILEGED ':' userid {
#if SOCKS_SERVER
		config.uid.unprivileged			= $3;
		config.uid.unprivileged_isset	= 1;
#endif
	}
	;

user_libwrap:	USER_LIBWRAP ':' userid {
#if HAVE_LIBWRAP && SOCKS_SERVER
		config.uid.libwrap			= $3;
		config.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrap support not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
	;


userid:	USERNAME {
		struct passwd *pw;

		if ((pw = getpwnam($1)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", $1);
		else
			$$ = pw->pw_uid;
	}
	;

iotimeout:	IOTIMEOUT ':' NUMBER {
#if SOCKS_SERVER
		config.timeout.io = atol($3);
#endif
	}
	;

connecttimeout:	CONNECTTIMEOUT ':' NUMBER {
#if SOCKS_SERVER
		config.timeout.negotiate = atol($3);
#endif
	}
	;

debuging: DEBUGING ':' NUMBER {
		config.option.debug = atoi($3);
	}
	;

compatibility:	COMPATIBILITY ':' compatibilitys
	;

compatibilityname:	REUSEADDR {
#if SOCKS_SERVER
		config.compat.reuseaddr = 1;
	}
	|	SAMEPORT {
		config.compat.sameport = 1;
#endif
	}
	;

compatibilitys:	compatibilityname
	|	compatibilityname compatibilitys
	;

resolveprotocol:	RESOLVEPROTOCOL ':' resolveprotocolname
	;

resolveprotocolname:	PROTOCOL_FAKE {
			config.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
	|  PROTOCOL_TCP {
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			config.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
	|	PROTOCOL_UDP {
			config.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
	;

srchost:	SRCHOST ':' srchostoptions
	;

srchostoption:	NOMISMATCH {
#if HAVE_LIBWRAP && SOCKS_SERVER
			config.srchost.nomismatch = 1;
	}
	|  NOUNKNOWN {
			config.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
	;

srchostoptions:	srchostoption
	|	srchostoption srchostoptions
	;


authmethod:	METHOD ':' authmethods
	;

authmethodname:	NONE {
		ADDMETHOD(AUTHMETHOD_NONE);
	};
	|	GSSAPI {
		yyerror("GSSAPI not supported");
	}
	|	UNAME {
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
	|	RFC931 {
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method rfc931 requires libwrap");
#endif /* !HAVE_LIBWRAP */
	}
	;

authmethods:	authmethodname
	|	authmethodname authmethods
	;


	/* filterrules */

clientrule: CLIENTRULE verdict '{' clientruleoptions fromto clientruleoptions '}' {
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addclientrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinit;

		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	}
	;

clientruleoption:	libwrap
	|	log
	|	user
	;

clientruleoptions:	{ $$ = NULL; }
	|	clientruleoption clientruleoptions
	;

rule:	verdict '{' ruleoptions fromto ruleoptions '}' {
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addsocksrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinit;

		src.atype	= SOCKS_ADDR_IPV4;
		dst.atype	= SOCKS_ADDR_IPV4;
#endif
	}
	;


ruleoption:	authmethod
	|	command
	|	libwrap
	|	log
	|	protocol
	|	proxyprotocol
	|	user
	;

ruleoptions:	{ $$ = NULL; }
	| ruleoption ruleoptions
	;

verdict:	VERDICT_BLOCK {
#if SOCKS_SERVER
		rule.verdict	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
		userbase			= &rule.user;
	}
	|	VERDICT_PASS {
		rule.verdict	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
		userbase			= &rule.user;
#endif
	}
	;

command:	COMMAND ':' commands
	;

commandname:	COMMAND_BIND {
			command->bind = 1;
	}
	|	COMMAND_CONNECT {
			command->connect = 1;
	}
	|	COMMAND_UDPASSOCIATE {
			command->udpassociate = 1;
	}

	/* pseudocommands */

	|	COMMAND_BINDREPLY	{
			command->bindreply = 1;
	}

	|	COMMAND_UDPREPLY {
			command->udpreply = 1;
	}
	;

commands:	commandname
	|	commandname commands
	;

protocol:	PROTOCOL ':'  protocols
	;

protocolname:	PROTOCOL_TCP {
		protocol->tcp = 1;
	}
	|	PROTOCOL_UDP {
		protocol->udp = 1;
	}
	;

protocols:	protocolname
	|	protocolname protocols
	;


fromto:	srcaddress dstaddress
	;

log:	LOG ':' logs
	;

logname:  LOG_CONNECT {
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
	|	LOG_DATA {
			rule.log.data = 1;
	}
	|	LOG_DISCONNECT {
			rule.log.disconnect = 1;
	}
	|	LOG_ERROR {
			rule.log.error = 1;
	}
	|	LOG_IOOPERATION {
			rule.log.iooperation = 1;
#endif
	}
	;

logs:	logname
	|  logname logs
	;


libwrap:	LIBWRAPSTART ':' LINE {
#if HAVE_LIBWRAP && SOCKS_SERVER
		struct request_info request;
		char libwrap[LIBWRAPBUF];

		if (strlen($3) >= sizeof(rule.libwrap))
			yyerror("libwrap line too long, make LIBWRAPBUF bigger");
		strcpy(rule.libwrap, $3);

		/* libwrap modifies the passed buffer. */
		SASSERTX(strlen(rule.libwrap) < sizeof(libwrap));
		strcpy(libwrap, rule.libwrap);

		++dry_run;
		request_init(&request, RQ_FILE, -1, RQ_DAEMON, __progname, 0);
		if (setjmp(tcpd_buf) != 0)
			yyerror("bad libwrap line");
		process_options(libwrap, &request);
		--dry_run;

#else /* !HAVE_LIBWRAP */
		yyerror("libwrap support not compiled in");
#endif
	}
	;


srcaddress:	from ':' address
	;


dstaddress:	to ':' address
	;


gateway:	via ':' gwaddress
	;

routeoption:	command
	|	extension
	|	protocol
	|	proxyprotocol
	|	authmethod
	;

routeoptions:	{ $$ = NULL; }
	| routeoption routeoptions
	;

from:	FROM {
		addressinit(&src);
	}
	;


to:	TO {
		addressinit(&dst);
	}
	;


via:	VIA {
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	}
	;


address:		ipaddress '/' netmask port
	|	domain port
	;


gwaddress:	ipaddress port
	|	domain port
	|	direct
	;


ipaddress:	IPADDRESS {
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton($1, ipaddr) != 1)
			yyerror("bad address");
	}
	;


netmask:	NUMBER {
		if (atoi($1) < 0 || atoi($1) > 32)
			yyerror("bad netmask");

		netmask->s_addr
		= atoi($1) == 0 ? 0 : htonl(0xffffffff << (32 - atoi($1)));
	}
	|	IPADDRESS {
			if (!inet_aton($1, netmask))
				yyerror("bad netmask");
	}
	;

domain:	DOMAIN {
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen($1) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, $1);
	}
	;

direct:	DIRECT {
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen($1) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, $1);

#if SOCKS_CLIENT
		route.state.direct = 1;
#endif
	}
	;

port: { $$ = NULL; }
	|	PORT portoperator portnumber
	|	PORT portrange
	;

portnumber:	portservice
	|	portstart
	;

portrange:	portstart '-' portend
	;


portstart:	PORTNUMBER {
		*port_tcp	= htons((in_port_t)atoi($1));
		*port_udp	= htons((in_port_t)atoi($1));
	}
	;

portservice:	SERVICENAME {
		struct servent	*service;
		struct protocol_t	protocolunset;
		int set;

		bzero(&protocolunset, sizeof(protocolunset));

		/* set all protocols if none set, default. */
		if (memcmp(protocol, &protocolunset, sizeof(*protocol)) == 0) {
			memset(protocol, UCHAR_MAX, sizeof(*protocol));
			set = 0;
		}
		else
			set = 1;

		if (protocol->tcp) {
			if ((service = getservbyname($1, "tcp")) == NULL) {
				if (set)
					yyerror("bad servicename for tcp");
				else
					*port_tcp = htons(0);
			}
			else
				*port_tcp = (in_port_t)service->s_port;
		}

		if (protocol->udp) {
			if ((service = getservbyname($1, "udp")) == NULL) {
				if (set)
					yyerror("bad servicename for udp");
				else
					*port_udp = htons(0);
			}
			else
				*port_udp = (in_port_t)service->s_port;
		}

		/* check we got both protocol ports set right. */
		if (*port_tcp == htons(0) && *port_udp == htons(0))
			yyerror("bad service name for tcp/udp");
		if (*port_tcp == htons(0))
			*port_tcp = *port_udp;
		else if (*port_udp == htons(0))
			*port_udp = *port_tcp;
	}
	;


portend:	PORTNUMBER {
		ruleaddress->portend = htons((in_port_t)atoi($1));
		ruleaddress->operator = range;
	}
	;

portoperator:	OPERATOR {
		*operator = string2operator($1);
	}
	;

%%

#define INTERACTIVE		0

#if SOCKS_SERVER
#define ELECTRICFENCE	0
#else
#define ELECTRICFENCE	0
#endif


#if ELECTRICFENCE
	extern int EF_PROTECT_FREE;
	extern int EF_ALLOW_MALLOC_0;
	extern int EF_ALIGNMENT;
	extern int EF_PROTECT_BELOW;
#endif /* ELECTRICFENCE */

extern FILE *yyin;

int parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";

#if ELECTRICFENCE
	EF_PROTECT_FREE         = 1;
	EF_ALLOW_MALLOC_0       = 1;
	EF_ALIGNMENT            = 0;
	EF_PROTECT_BELOW			= 0;
#endif /* ELECTRICFENCE */

/*	yydebug		= 0; */
	yylineno		= 1;
	parseinit	= 0;

	if ((yyin = fopen(filename, "r")) == NULL) {
		swarn("%s: %s", function, filename);
		return -1;
	}

	yyparse();
	fclose(yyin);

	errno = 0; /* yacc for some reason alters errno sometimes. */

	return 0;
}


void
yyerror(s)
	const char *s;
{

	serrx(1, "%s: error on line %d, near '%.10s': %s",
	config.option.configfile, yylineno,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext, s);
}


static void
addressinit(address)
	struct ruleaddress_t *address;
{
		ruleaddress	= address;

		atype			= &ruleaddress->atype;
		ipaddr		= &ruleaddress->addr.ipv4.ip;
		netmask		= &ruleaddress->addr.ipv4.mask;
		domain		= ruleaddress->addr.domain;
		port_tcp		= &ruleaddress->port.tcp;
		port_udp		= &ruleaddress->port.udp;
		operator		= &ruleaddress->operator;
}
