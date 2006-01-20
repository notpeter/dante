/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004, 2005
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

%{

#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.199 2006/01/20 12:59:06 michaels Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

#if SOCKS_SERVER
static void
ruleinit __P((struct rule_t *rule));

static void
fixconfig __P((void));

#endif

__END_DECLS

extern int yylineno;
extern char *yytext;

#if SOCKS_SERVER
static struct rule_t				ruleinitmem;
static struct rule_t				rule;				/* new rule.							*/
static struct protocol_t		protocolmem;	/* new protocolmem.					*/
#endif

static struct serverstate_t	state;
static struct route_t			route;			/* new route.							*/
static struct ruleaddress_t	gw;				/* new gateway.						*/

static struct ruleaddress_t	src;				/* new src.								*/
static struct ruleaddress_t	dst;				/* new dst.								*/
static struct ruleaddress_t	rdr_from;
static struct ruleaddress_t	rdr_to;

static struct ruleaddress_t	*ruleaddress;	/* current ruleaddress				*/
static struct extension_t		*extension;		/* new extensions						*/
static struct proxyprotocol_t	*proxyprotocol;/* proxy protocol.					*/

static char							*atype;			/* atype of new address.			*/
static struct in_addr			*ipaddr;			/* new ipaddress						*/
static struct in_addr			*netmask;		/* new netmask							*/
static char							*domain;			/* new domain.							*/
static char							*ifname;			/* new ifname.							*/

static in_port_t					*port_tcp;		/* new TCP portnumber.				*/
static in_port_t					*port_udp;		/* new UDP portnumber.				*/
static int							*methodv;		/* new authmethods.					*/
static size_t						*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/

static const struct {
	const char *name;
	const int value;
} syslogfacilityv[] = {
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
		if (methodisset(method, methodv, *methodc)) \
			yywarn("duplicate method: %s", method2string(method)); \
		else { \
			if (*methodc >= MAXMETHOD)	\
				yyerror("internal error, (%d >= %d)", *methodc, MAXMETHOD);	\
			methodv[(*methodc)++] = method; \
		} \
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
%type	<string> pamservicename
%type	<string> resolveprotocol resolveprotocolname
%type	<string> srchost srchostoption srchostoptions
%type	<string> command commands commandname
%type	<string> redirect
%type	<string> bandwidth
%type	<string> session maxsessions
%type	<string> routeinit


	/* clientconfig exclusive. */
%type	<string> clientinit clientconfig
%type	<string> clientoption
%type	<string> debuging


	/* serverconfig exclusive */
%type	<string> iotimeout connecttimeout
%type	<string> extension extensionname extensions
%type	<string> internal internalinit external externalinit
%type	<string> external_rotation
%type	<string> logoutput logoutputdevice logoutputdevices
%type	<string> compatibility compatibilityname compatibilitys
%type	<string> global_authmethod global_clientauthmethod
%type	<string> authmethod authmethods authmethodname
%type	<string> serveroption
%type	<string> serverinit serverconfig
%type	<string> userids user_privileged user_unprivileged user_libwrap
%type	<uid>		userid
%type	<string> childstate

%token	<string> CLIENTRULE
%token	<string> INTERNAL EXTERNAL EXTERNAL_ROTATION
%token	<string> DEBUGING RESOLVEPROTOCOL
%token	<string> SRCHOST NOMISMATCH NOUNKNOWN
%token	<string> EXTENSION BIND PRIVILEGED
%token	<string> IOTIMEOUT CONNECTTIMEOUT
%token	<string> METHOD CLIENTMETHOD NONE GSSAPI UNAME RFC931 PAM
%token	<string> COMPATIBILITY REUSEADDR SAMEPORT
%token	<string> USERNAME
%token	<string> USER_PRIVILEGED USER_UNPRIVILEGED USER_LIBWRAP
%token	<string> LOGOUTPUT LOGFILE
%token	<string> CHILD_MAXIDLE

	/* route */
%type	<string> route
%type	<string> via gateway routeoption routeoptions

%token	<string> ROUTE VIA

	/* rulelines */
%type	<string> rule ruleoption ruleoptions
%type	<string> clientrule clientruleoption clientruleoptions
%type	<string> option
%type	<string> verdict
%type	<string> fromto
%type	<string> log logs logname
%type	<string> libwrap
%type	<string> srcaddress dstaddress
%type	<string> internaladdress externaladdress
%type	<string> address ipaddress gwaddress domain ifname direct
%type	<string> from to
%type	<string> netmask
%type	<string> port portrange portstart portoperator portnumber portservice

%token <string> VERDICT_BLOCK VERDICT_PASS
%token <string> PAMSERVICENAME
%token <string> PROTOCOL PROTOCOL_TCP PROTOCOL_UDP PROTOCOL_FAKE
%token <string> PROXYPROTOCOL PROXYPROTOCOL_SOCKS_V4 PROXYPROTOCOL_SOCKS_V5
					 PROXYPROTOCOL_MSPROXY_V2 PROXYPROTOCOL_HTTP_V1_0
%token <string> USER
%token <string> COMMAND COMMAND_BIND COMMAND_CONNECT COMMAND_UDPASSOCIATE								 COMMAND_BINDREPLY COMMAND_UDPREPLY
%token <string> ACTION
%token <string> LINE
%token <string> LIBWRAPSTART
%token <string> OPERATOR
%token <string> LOG LOG_CONNECT  LOG_DATA LOG_DISCONNECT LOG_ERROR									    LOG_IOOPERATION
%token <string> IPADDRESS DOMAINNAME DIRECT IFNAME
%token <string> PORT PORTNUMBER SERVICENAME
%token <string> NUMBER
%token <string> FROM TO
%token <string> REDIRECT
%token <string> BANDWIDTH

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
		extension		= &sockscf.extension;
#endif
	}
	;


serverline:	{ $$ = NULL; }
	|	serverline '\n'
	|	serverline serverconfig
	|	serverline clientrule
	|	serverline rule
	|	serverline route
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

serverconfig:	global_authmethod
	|	global_clientauthmethod
	|  deprecated
	|	internal
	|	external
	|	external_rotation
	|	logoutput
	|	serveroption
	|	userids
	|	childstate
	;

serveroption:	compatibility
	|	connecttimeout
	|	extension
	|	iotimeout
	|	resolveprotocol
	|	srchost
	;


deprecated:	DEPRECATED {
		yywarn("given keyword is deprecated");
	}

route:	ROUTE routeinit '{' routeoptions fromto gateway routeoptions '}' {
		route.src		= src;
		route.dst		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
	}
	;

routeinit: {
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
		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
	}
	;


proxyprotocol:	PROXYPROTOCOL ':' proxyprotocols
	;

proxyprotocolname:	PROXYPROTOCOL_SOCKS_V4 {
			proxyprotocol->socks_v4		= 1;
	}
	|	PROXYPROTOCOL_SOCKS_V5 {
			proxyprotocol->socks_v5		= 1;
	}
	|  PROXYPROTOCOL_MSPROXY_V2 {
			proxyprotocol->msproxy_v2	= 1;
	}
	|  PROXYPROTOCOL_HTTP_V1_0 {
			proxyprotocol->http_v1_0	= 1;
	}
	| deprecated
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
			yyerror("method %s requires libwrap", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
		if (adduser(&rule.user, $1) == NULL)
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


internal:	INTERNAL internalinit ':' internaladdress {
#if SOCKS_SERVER
		addinternal(ruleaddress);
#endif
	}
	;

internalinit: {
#if SOCKS_SERVER
	static struct ruleaddress_t mem;
	struct servent	*service;

	addressinit(&mem);

	/* set default port. */
	if ((service = getservbyname("socks", "tcp")) == NULL)
		*port_tcp = htons(SOCKD_PORT);
	else
		*port_tcp = (in_port_t)service->s_port;
#endif
	}
	;

external:	EXTERNAL externalinit ':' externaladdress {
#if SOCKS_SERVER
		addexternal(ruleaddress);
#endif
	}
	;

externalinit: {
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		addressinit(&mem);
#endif
	}
	;

external_rotation:	EXTERNAL_ROTATION ':' NONE {
#if SOCKS_SERVER
		sockscf.external.rotation = ROTATION_NONE;
	}
	|	EXTERNAL_ROTATION ':' ROUTE {
#if !HAVE_ROUTE_SOURCE
		yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
		sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
	}
	;

clientoption:	logoutput
	|	debuging
	|	resolveprotocol
	;

logoutput: LOGOUTPUT ':' logoutputdevices
	;

logoutputdevice:	LOGFILE {
		const char *syslogname = "syslog";

		if (strncmp($1, syslogname, strlen(syslogname)) == 0
		&& ($1[strlen(syslogname)] == NUL || $1[strlen(syslogname)] == '/')) {
			char *sl;

			sockscf.log.type |= LOGTYPE_SYSLOG;

			if (*(sl = &($1[strlen(syslogname)])) == '/') { /* facility. */
				size_t i;

				for (i = 0, ++sl; i < ELEMENTS(syslogfacilityv); ++i)
					if (strcmp(sl, syslogfacilityv[i].name) == 0)
						break;

				if (i == ELEMENTS(syslogfacilityv))
					yyerror("unknown syslog facility \"%s\"", sl);

				sockscf.log.facility = syslogfacilityv[i].value;
				sockscf.log.facilityname = syslogfacilityv[i].name;
			}
			else {
				sockscf.log.facility = LOG_DAEMON; /* default. */
				sockscf.log.facilityname = "daemon";
			}
		}
		else /* adding/changing filename. */
			if (!sockscf.state.init) {
				int flag;

				sockscf.log.type |= LOGTYPE_FILE;

				if ((sockscf.log.fpv = (FILE **)realloc(sockscf.log.fpv,
				sizeof(*sockscf.log.fpv) * (sockscf.log.fpc + 1))) == NULL
				|| (sockscf.log.fplockv = (int *)realloc(sockscf.log.fplockv,
				sizeof(*sockscf.log.fplockv) * (sockscf.log.fpc + 1))) == NULL
				|| (sockscf.log.fnamev = (char **)realloc(sockscf.log.fnamev,
				sizeof(*sockscf.log.fnamev) * (sockscf.log.fpc + 1)))
				== NULL)
					serrx(EXIT_FAILURE, NOMEM);

				if ((sockscf.log.fplockv[sockscf.log.fpc]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp($1, "stdout") == 0)
					sockscf.log.fpv[sockscf.log.fpc] = stdout;
				else if (strcmp($1, "stderr") == 0)
					sockscf.log.fpv[sockscf.log.fpc] = stderr;
				else
					if ((sockscf.log.fpv[sockscf.log.fpc] = fopen($1, "a"))
					== NULL)
						yyerror("fopen(%s)", $1);

				if ((flag = fcntl(fileno(sockscf.log.fpv[sockscf.log.fpc]),
				F_GETFD, 0)) == -1
				||  fcntl(fileno(sockscf.log.fpv[sockscf.log.fpc]), F_SETFD,
				flag | FD_CLOEXEC) == -1)
					serr(EXIT_FAILURE, "fcntl(F_GETFD/F_SETFD)");

				if ((sockscf.log.fnamev[sockscf.log.fpc] = strdup($1)) == NULL)
					serr(EXIT_FAILURE, NOMEM);

				++sockscf.log.fpc;
			}
			else {
				/*
				 * Can't change filenames we log to after startup (well,
				 * to be exact, we can't add new filenames, but we complain
				 * about changing too for now since it's easier.
				 */
				size_t i;

				for (i = 0; i < sockscf.log.fpc; ++i)
					if (strcmp(sockscf.log.fnamev[i], $1) == 0) { /* same name. */
						FILE *fp;

						if (strcmp(sockscf.log.fnamev[i], "stdout") == 0
						||  strcmp(sockscf.log.fnamev[i], "stderr") == 0)
							continue; /* don't need to close these, hard to reopen. */

						/* reopen logfiles. */
						if ((fp = fopen(sockscf.log.fnamev[i], "a")) == NULL)
							yyerror("fopen(%s)", $1);

						fclose(sockscf.log.fpv[i]);
						sockscf.log.fpv[i] = fp;
						break;
					}

				if (i == sockscf.log.fpc) /* no match found. */
					yywarn("can't change logoutput after startup");
			}
	}
	;

logoutputdevices:	logoutputdevice
	|	logoutputdevice logoutputdevices
	;

childstate:
	CHILD_MAXIDLE ':' NUMBER {
#if SOCKS_SERVER
		yyerror("Sorry, child.maxidle is disabled due to a suspected bug");
		if (atoi($3) != 0 && atoi($3) < SOCKD_FREESLOTS)
			yyerror("%s (%s) can't be less than SOCKD_FREESLOTS (%d)",
			$1, $3, SOCKD_FREESLOTS);
		sockscf.child.maxidle = atoi($3);
#endif
	}
	;


userids:	user_privileged
	|	user_unprivileged
	|	user_libwrap
	;

user_privileged:	USER_PRIVILEGED ':' userid {
#if SOCKS_SERVER
		sockscf.uid.privileged			= $3;
		sockscf.uid.privileged_isset	= 1;
#endif
	}
	;

user_unprivileged:	USER_UNPRIVILEGED ':' userid {
#if SOCKS_SERVER
		sockscf.uid.unprivileged			= $3;
		sockscf.uid.unprivileged_isset	= 1;
#endif
	}
	;

user_libwrap:	USER_LIBWRAP ':' userid {
#if HAVE_LIBWRAP && SOCKS_SERVER
		sockscf.uid.libwrap			= $3;
		sockscf.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrapsupport not compiled in");
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
		sockscf.timeout.io = (time_t)atol($3);
#endif
	}
	;

connecttimeout:	CONNECTTIMEOUT ':' NUMBER {
#if SOCKS_SERVER
		sockscf.timeout.negotiate = (time_t)atol($3);
#endif
	}
	;

debuging: DEBUGING ':' NUMBER {
		sockscf.option.debug = atoi($3);
	}
	;

compatibility:	COMPATIBILITY ':' compatibilitys
	;

compatibilityname:	REUSEADDR {
#if SOCKS_SERVER
		sockscf.compat.reuseaddr = 1;
	}
	|	SAMEPORT {
		sockscf.compat.sameport = 1;
#endif
	}
	;

compatibilitys:	compatibilityname
	|	compatibilityname compatibilitys
	;

resolveprotocol:	RESOLVEPROTOCOL ':' resolveprotocolname
	;

resolveprotocolname:	PROTOCOL_FAKE {
			sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
	|  PROTOCOL_TCP {
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
	|	PROTOCOL_UDP {
			sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
	;

srchost:	SRCHOST ':' srchostoptions
	;

srchostoption:	NOMISMATCH {
#if HAVE_LIBWRAP && SOCKS_SERVER
			sockscf.srchost.nomismatch = 1;
	}
	|  NOUNKNOWN {
			sockscf.srchost.nounknown = 1;
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

global_authmethod:	METHOD ':' {
#if SOCKS_SERVER
	methodv = sockscf.methodv;
	methodc = &sockscf.methodc;
	*methodc = 0; /* reset. */
#endif
	} authmethods
	;

global_clientauthmethod:	CLIENTMETHOD ':' {
#if SOCKS_SERVER
	methodv = sockscf.clientmethodv;
	methodc = &sockscf.clientmethodc;
	*methodc = 0; /* reset. */
#endif
	} authmethods
	;

authmethodname:	NONE {
		ADDMETHOD(AUTHMETHOD_NONE);
	};
	|	GSSAPI {
		yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
	}
	|	UNAME {
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
	|	RFC931 {
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method %s requires libwraplibrary", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
	}
	|	PAM {
#if !HAVE_PAM
		yyerror("method %s requires pamlibrary", AUTHMETHOD_PAMs);
#else /* HAVE_PAM */
		ADDMETHOD(AUTHMETHOD_PAM);
#endif /* !HAVE_PAM */
	}
	;

authmethods:	authmethodname
	|	authmethodname authmethods
	;


	/* filterrules */

clientrule: CLIENTRULE verdict '{' clientruleoptions fromto clientruleoptions '}' {
#if SOCKS_SERVER
		rule.src			= src;
		rule.dst			= dst;
		rule.rdr_from	= rdr_from;
		rule.rdr_to		= rdr_to;

		addclientrule(&rule);

#endif
	}
	;

clientruleoption:	option
	;

clientruleoptions:	{ $$ = NULL; }
	|	clientruleoption clientruleoptions
	;

rule:	verdict '{' ruleoptions fromto ruleoptions '}' {
#if SOCKS_SERVER
		rule.src			= src;
		rule.dst			= dst;
		rule.rdr_from	= rdr_from;
		rule.rdr_to		= rdr_to;

		addsocksrule(&rule);
#endif
	}
	;


ruleoption:	option
	|	bandwidth {
#if SOCKS_SERVER
			checkmodule("bandwidth");
#endif
	}
	|	command
	|	protocol
	|	proxyprotocol
	|	redirect	{
#if SOCKS_SERVER
			checkmodule("redirect");
#endif
	}
	;

ruleoptions:	{ $$ = NULL; }
	| ruleoption ruleoptions
	;

option: authmethod
	|	libwrap
	|	log
	|	pamservicename
	|	user
	|	session	{
#if SOCKS_SERVER
			checkmodule("session");
#endif
	}
	;

verdict:	VERDICT_BLOCK {
#if SOCKS_SERVER
		ruleinit(&rule);
		rule.verdict	= VERDICT_BLOCK;
	}
	|	VERDICT_PASS {
		ruleinit(&rule);
		rule.verdict	= VERDICT_PASS;
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

redirect:	REDIRECT rdr_fromaddress
	|	REDIRECT rdr_toaddress
	;

session: maxsessions
	;

maxsessions: MAXSESSIONS ':' NUMBER {
#if SOCKS_SERVER
	static session_t ssinit;

  /*
	* temporarily allocate ordinary memory, later on point it to
	* the correct shared mem.
	*/
	if ((rule.ss = malloc(sizeof(*rule.ss))) == NULL)
		serr(EXIT_FAILURE, NOMEM);
	*rule.ss = ssinit;
	if ((rule.ss->maxsessions = atoi($3)) < 0)
		yyerror("session value can not be less than 0");
#endif /* SOCKS_SERVER */
}
;

bandwidth:	BANDWIDTH ':' NUMBER {
#if SOCKS_SERVER
		static bw_t bwmeminit;

     /*
		* temporarily allocate ordinary memory, later on point it to
		* the correct index in sockscf.bwv.
		*/
		if ((rule.bw = (bw_t *)malloc(sizeof(*rule.bw))) == NULL)
			serr(EXIT_FAILURE, NOMEM);
		*rule.bw = bwmeminit;
		if ((rule.bw->maxbps = atoi($3)) <= 0)
			yyerror("bandwidth value must be greater than 0");
#endif /* SOCKS_SERVER */
	}
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


pamservicename: PAMSERVICENAME ':' SERVICENAME {
#if HAVE_PAM && SOCKS_SERVER
		if (strlen($3) >= sizeof(rule.pamservicename))
			yyerror("servicename too long");
		strcpy(rule.pamservicename, $3);
#else /* !HAVE_PAM */
		yyerror("pamsupport not compiled in");
#endif /* HAVE_PAM */
	}
	;

libwrap:	LIBWRAPSTART ':' LINE {
#if HAVE_LIBWRAP && SOCKS_SERVER
		struct request_info request;
		char libwrap[LIBWRAPBUF];

		if (strlen($3) >= sizeof(rule.libwrap))
			yyerror("libwrapline too long, make LIBWRAPBUF bigger");
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
		yyerror("libwrapsupport not compiled in");
#endif
	}
	;


srcaddress:	from ':' address
	;


dstaddress:	to ':' address
	;

rdr_fromaddress: rdr_from ':' address
	;

rdr_toaddress: rdr_to ':' address
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

rdr_from:	FROM {
		addressinit(&rdr_from);
	}
	;

rdr_to:	TO {
		addressinit(&rdr_to);
	}
	;



via:	VIA {
		addressinit(&gw);
	}
	;

internaladdress: ipaddress port
	|	domain port
	|	ifname port
	;

externaladdress: ipaddress
	|	domain
	|	ifname
	;


address: ipaddress '/' netmask port
	|	domain port
	|	ifname port
	;


gwaddress:	ipaddress port
	|	domain port
	|	direct
	;


ipaddress:	IPADDRESS {
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton($1, ipaddr) != 1)
			yyerror("bad address: %s", $1);
	}
	;


netmask:	NUMBER {
		if (atoi($1) < 0 || atoi($1) > 32)
			yyerror("bad netmask: %s", $1);

		netmask->s_addr
		= atoi($1) == 0 ? 0 : htonl(0xffffffff << (32 - atoi($1)));
	}
	|	IPADDRESS {
			if (!inet_aton($1, netmask))
				yyerror("bad netmask: %s", $1);
	}
	;

domain:	DOMAINNAME {
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen($1) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, $1);
	}
	;

ifname:	IFNAME {
		*atype = SOCKS_ADDR_IFNAME;

		if (strlen($1) >= MAXIFNAMELEN)
			yyerror("interfacename too long");
		strcpy(ifname, $1);
	}
	;


direct:	DIRECT {
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen($1) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, $1);

		route.state.direct = 1;
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

portend:	PORTNUMBER {
		ruleaddress->portend		= htons((in_port_t)atoi($1));
		ruleaddress->operator	= range;
	}
	;

portservice:	SERVICENAME {
		struct servent	*service;

		if ((service = getservbyname($1, "tcp")) == NULL) {
			if (protocol->tcp)
				yyerror("unknown tcp protocol: %s", $1);
			*port_tcp = htons(0);
		}
		else
			*port_tcp = (in_port_t)service->s_port;

		if ((service = getservbyname($1, "udp")) == NULL) {
			if (protocol->udp)
					yyerror("unknown udp protocol: %s", $1);
				*port_udp = htons(0);
		}
		else
			*port_udp = (in_port_t)service->s_port;

		if (*port_tcp == htons(0) && *port_udp == htons(0))
			yyerror("unknown tcp/udp protocol");

		/* if one protocol is unset, set to same as the other. */
		if (*port_tcp == htons(0))
			*port_tcp = *port_udp;
		else if (*port_udp == htons(0))
			*port_udp = *port_tcp;
	}
	;


portoperator:	OPERATOR {
		*operator = string2operator($1);
	}
	;

%%

#define INTERACTIVE		0

extern FILE *yyin;

int socks_parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";

/*	yydebug				= 1;          */
	yylineno				= 1;
	socks_parseinit	= 0;

	if ((yyin = fopen(filename, "r")) == NULL) {
		swarn("%s: %s", function, filename);
		return -1;
	}

	errno = 0;	/* don't report old errors in yyparse(). */
	yyparse();
	fclose(yyin);

#if SOCKS_SERVER
	fixconfig();
#endif /* SOCKS_SERVER */

	errno = 0;

	return 0;
}


void
#ifdef STDC_HEADERS
yyerror(const char *fmt, ...)
#else
yyerror(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;
	char buf[2048];
	size_t bufused;

#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

	bufused = snprintfn(buf, sizeof(buf),
	"%s: error on line %d, near '%.10s': ",
	sockscf.option.configfile, yylineno,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);

	vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

	/* LINTED expression has null effect */
	va_end(ap);

	if (errno)
		serr(EXIT_FAILURE, buf);
	serrx(EXIT_FAILURE, buf);
}

void
#ifdef STDC_HEADERS
yywarn(const char *fmt, ...)
#else
yywarn(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;
	char buf[2048];
	size_t bufused;

#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

	bufused = snprintfn(buf, sizeof(buf),
	"%s: warning on line %d, near '%.10s': ",
	sockscf.option.configfile, yylineno,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);

	vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

	/* LINTED expression has null effect */
	va_end(ap);

	if (errno)
		swarn(buf);
	swarnx(buf);
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
		ifname		= ruleaddress->addr.ifname;
		port_tcp		= &ruleaddress->port.tcp;
		port_udp		= &ruleaddress->port.udp;
		operator		= &ruleaddress->operator;
}


#if SOCKS_SERVER
static void
ruleinit(rule)
	struct rule_t *rule;
{
	rule->linenumber = yylineno;

	command			= &rule->state.command;
	methodv			= rule->state.methodv;
	methodc			= &rule->state.methodc;
	protocol			= &rule->state.protocol;
	proxyprotocol	= &rule->state.proxyprotocol;

	bzero(&src, sizeof(src));
	bzero(&dst, sizeof(dst));
	*rule = ruleinitmem;

	src.atype = SOCKS_ADDR_IPV4;
	src.addr.ipv4.ip.s_addr = htonl(INADDR_ANY);
	src.port.tcp = src.port.udp = src.portend = htons(0);

	dst = rdr_from = rdr_to = src;
}

static void
fixconfig(void)
{
	const char *function = "fixsettings()";
	int i;
	uid_t euid;

	/*
	 * Check arguments and settings, do they make sense?
	 */

	if (sockscf.clientmethodc == 0)
		sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;

#if !HAVE_DUMPCONF
	if (!sockscf.uid.privileged_isset)
		sockscf.uid.privileged = sockscf.state.euid;
	else {
		socks_seteuid(&euid, sockscf.uid.privileged);
		socks_reseteuid(sockscf.uid.privileged, euid);
	}

	if (!sockscf.uid.unprivileged_isset)
		sockscf.uid.unprivileged = sockscf.state.euid;
	else {
		socks_seteuid(&euid, sockscf.uid.unprivileged);
		socks_reseteuid(sockscf.uid.unprivileged, euid);
	}

#if HAVE_LIBWRAP
	if (!sockscf.uid.libwrap_isset)
		sockscf.uid.libwrap = sockscf.state.euid;
	else {
		socks_seteuid(&euid, sockscf.uid.libwrap);
		socks_reseteuid(sockscf.uid.libwrap, euid);
	}
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_DUMPCONF */

	if (sockscf.internalc == 0)
		serrx(EXIT_FAILURE, "%s: no internal address given", function);
	/* values will be used once and checked there. */

	if (sockscf.external.addrc == 0)
		serrx(EXIT_FAILURE, "%s: no external address given", function);
#if !HAVE_DUMPCONF
	for (i = 0; i < sockscf.external.addrc; ++i)
		if (!addressisbindable(&sockscf.external.addrv[i]))
			serrx(EXIT_FAILURE, NULL);
#endif /* !HAVE_DUMPCONF */

#if !HAVE_DUMPCONF 
	if (sockscf.methodc == 0)
		swarnx("%s: no methods enabled (total block)", function);

	if (sockscf.uid.unprivileged == 0)
		swarnx("%s: setting the unprivileged uid to %d is not recommended",
		function, sockscf.uid.unprivileged);

#if HAVE_LIBWRAP
	if (sockscf.uid.libwrap == 0)
		swarnx("%s: setting the libwrap uid to %d is not recommended",
		function, sockscf.uid.libwrap);
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_DUMPCONF */
}

#endif /* SOCKS_SERVER */
