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

%{

static const char rcsid[] =
"$Id: config_parse.y,v 1.78 1999/02/20 19:18:49 michaels Exp $";

#include "common.h"

#include "yacconfig.h" 


__BEGIN_DECLS

static void
addressinit(struct ruleaddress_t *address);

static void
yyerror(const char *s);

__END_DECLS

/* hmm. */
extern int yylex();
extern int yyparse();

extern struct config_t config;

extern int yylineno;
extern char *yytext;

#ifdef SOCKS_SERVER
static struct rule_t				rule;				/* new rule.							*/
#endif

#ifdef SOCKS_CLIENT
static struct serverstate_t 	state;
static struct route_t 			route;			/* new route.							*/
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
static unsigned char 			*methodv;		/* new authmethods.					*/
static unsigned char 			*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/


#define YYDEBUG 1

%}

%union {
	char 	*string;
	uid_t	uid;
}


%type <string> configtype serverline clientline
%token <string> SERVERCONFIG CLIENTCONFIG

%type	<string> protocol protocol_list protocolname 
%type	<string> proxyprotocol proxyprotocolname proxyprotocol_list 
%type	<string> command command_list commandname
%type <string> routeinit

	/* clientconfig exclusive. */
%type <string> clientinit clientconfig clientoption debuging


	/* serverconfig exclusive */
%type <string> iotimeout connecttimeout
%type <string> extension extensionname extension_list 
%type <string> internal internalinit external externalinit
%type <string> localdomain 
%type <string> logoutput logoutputdevice logoutputdevice_list
%type	<string> compatibility compatibilityname compatibility_list
%type <string> authmethod authmethod_list authmethodname
%type <string> serveroption
%type <string> privileged
%type <string> serverinit serverconfig 
%type <string> users user_privileged user_unprivileged user_libwrap
%type <uid>		userid

%token <string> LOCALDOMAIN
%token <string> CLIENT
%token <string> INTERNAL EXTERNAL
%token <string> DEBUGING 
%token <string> EXTENSION BIND PRIVILEGED
%token <string> IOTIMEOUT CONNECTTIMEOUT
%token <string> METHOD NONE GSSAPI UNAME
%token <string> COMPATIBILITY REUSEADDR SAMEPORT
%token <string> USERNAME USER_PRIVILEGED USER_UNPRIVILEGED USER_LIBWRAP
%token <string> LOGOUTPUT LOGFILE

	/* route */
%type <string> route 
%type <string> via gateway gatewayoption

%token <string> ROUTE VIA

	/* rulelines */
%type	<string> rule ruleoption 
%type <string> clientrule clientruleoption 
%type	<string> verdict
%type <string> fromto
%type <string> log log_list logname
%type <string> libwrap
%type <string> srcaddress dstaddress
%type <string> address ipaddress gwaddress domain direct
%type	<string> from to
%type	<string> netmask
%type	<string> port portrange portstart portoperator portnumber portservice

%token <string> VERDICT_BLOCK VERDICT_PASS 
%token <string> PROTOCOL PROTOCOL_TCP PROTOCOL_UDP
%token <string> PROXYPROTOCOL PROXYPROTOCOL_SOCKS_V4 PROXYPROTOCOL_SOCKS_V5
                PROXYPROTOCOL_MSPROXY_V2
%token <string> COMMAND COMMAND_BIND COMMAND_CONNECT COMMAND_UDPASSOCIATE 								 COMMAND_BINDREPLY
%token <string> ACTION
%token <string> AUTH AUTHMETHOD
%token <string> LINE
%token <string> LIBWRAPSTART
%token <string> OPERATOR
%token <string> LOG LOG_CONNECT  LOG_DATA LOG_DISCONNECT LOG_ERROR 									    LOG_IOOPERATION
%token <string> IPADDRESS DOMAIN DIRECT
%token <string> PORT SERVICENAME
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
#ifdef SOCKS_SERVER
		extension 	= &config.extension;	
		methodv		= config.methodv;
		methodc		= &config.methodc;
		src.atype 	= SOCKS_ADDR_IPV4;
		dst.atype 	= SOCKS_ADDR_IPV4;
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
		/* abuse the fact that INADDR_ANY is 0. */
		src.atype 	= SOCKS_ADDR_IPV4;
		dst.atype 	= SOCKS_ADDR_IPV4;
	}
	;


clientconfig: 	clientoption
	;


serverconfig: logoutput internal external localdomain authmethod users serveroption 
	;


serveroption: compatibility extension connecttimeout iotimeout 
	;


route:	ROUTE routeinit '{' fromto gateway '}' {
#ifdef SOCKS_CLIENT
		route.src		= src;
		route.dst 		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
#endif
	}
	;

routeinit: {
#ifdef SOCKS_CLIENT
		command			= &state.command;
		extension 		= &state.extension;	
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



proxyprotocol:	{ $$ = NULL; }
	|	PROXYPROTOCOL ':' proxyprotocolname proxyprotocol_list
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

proxyprotocol_list:	{ $$ = NULL; }
	|	proxyprotocolname proxyprotocol_list
	;

extension:	{ $$ = NULL; }
	|	EXTENSION ':' extensionname extension_list
	;


extensionname:	BIND {
			extension->bind = 1;
	}
	;

extension_list:	{ $$ = NULL; }
	|	extensionname extension_list
	;



internal:	{ $$ = NULL; }
	|	INTERNAL internalinit ':' ipaddress port internal {
#ifdef SOCKS_SERVER
		if (config.state.init) {
			int i;

			for (i = 0; i < config.internalc; ++i)
				if (config.internalv[i].addr.sin_addr.s_addr == ipaddr->s_addr
				&&	 config.internalv[i].addr.sin_port == *port_tcp)
					break;

			if (i == config.internalc)
				swarnx("can not change internal address' once running");
		}
#endif /* SOCKS_SERVER */
	}
	;

internalinit: {
#ifdef SOCKS_SERVER
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
		
		ipaddr 		= &config.internalv[config.internalc - 1].addr.sin_addr;
		port_tcp 	= &config.internalv[config.internalc - 1].addr.sin_port;

		if ((service = getservbyname("socks", "tcp")) == NULL)
			*port_tcp = htons(SOCKD_PORT);
		else
			*port_tcp = service->s_port;
	}
	else { /* can only set internal address' once. */
		static struct in_addr inaddrmem;
		static in_port_t portmem;

		ipaddr 		= &inaddrmem;
		port_tcp		= &portmem;
	}
#endif
	}
	;

external:	EXTERNAL externalinit ':' ipaddress
	;

externalinit: {
#ifdef SOCKS_SERVER
		static struct ruleaddress_t mem;

		if ((config.externalv = (struct sockaddr_in *)realloc(config.externalv,
		sizeof(*config.externalv) * ++config.externalc)) == NULL)
			yyerror(NOMEM);

		bzero(&config.externalv[config.externalc - 1], sizeof(*config.externalv));
		config.externalv[config.externalc - 1].sin_family = AF_INET;
		
		addressinit(&mem);

		ipaddr 	= &config.externalv[config.externalc - 1].sin_addr;
#endif
	}
	;


clientoption:	logoutput localdomain debuging
	;


logoutput:	{ $$ = NULL; }
	|	LOGOUTPUT ':' logoutputdevice logoutputdevice_list
	;


logoutputdevice:	LOGFILE {
		if (!config.state.init) {
			if (strcmp($1, "syslog") == 0)	
				config.log.type |= LOGTYPE_SYSLOG;
			else {
				config.log.type |= LOGTYPE_FILE;
				
				if ((config.log.fpv = (FILE **)realloc(config.log.fpv, 
				sizeof(*config.log.fpv) * config.log.fpc + 1)) == NULL
				|| (config.log.fplockv = (int *)realloc(config.log.fplockv,
				sizeof(*config.log.fplockv) * config.log.fpc + 1)) == NULL)
					serrx(EXIT_FAILURE, NOMEM);
				++config.log.fpc;

				if ((config.log.fplockv[config.log.fpc - 1]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp($1, "stdout") == 0)
					config.log.fpv[config.log.fpc - 1] = stdout;
				else if (strcmp($1, "stderr") == 0)
					config.log.fpv[config.log.fpc - 1] = stderr;
				else
					if ((config.log.fpv[config.log.fpc - 1] = fopen($1, "a"))
					== NULL)
						serr(EXIT_FAILURE, "fopen(%s)", $1);
			}
		}
		else 
			;	/* XXX warn/exit if output changed. */
	}
	;


logoutputdevice_list:	{ $$ = NULL; }
	|	logoutputdevice logoutputdevice_list
	;

users:	user_privileged user_unprivileged user_libwrap
	;

user_privileged:	USER_PRIVILEGED ':' userid {
#ifdef SOCKS_SERVER
		config.uid.privileged = $3;
#endif
	}
	;

user_unprivileged:	USER_UNPRIVILEGED ':' userid {
#ifdef SOCKS_SERVER
		config.uid.unprivileged = $3;
#endif
	}
	;

user_libwrap:	{ 
#ifdef SOCKS_SERVER

#ifdef HAVE_LIBWRAP
		config.uid.libwrap = config.uid.unprivileged;	/* default. */
#endif  /* HAVE_LIBWRAP */
	}
	|	USER_LIBWRAP ':' userid {
#ifndef HAVE_LIBWRAP
		yyerror("libwrap support not compiled in");
#endif  /* HAVE_LIBWRAP */
		config.uid.libwrap = $3;

#endif /* SOCKS_SERVER */
	}
	;


userid:	USERNAME {
		struct passwd *pw;

		if ((pw = getpwnam($1)) == NULL)
			serr(EXIT_FAILURE, $1);
		else
			$$ = pw->pw_uid;
	}
	;

iotimeout:	{ $$ = NULL; }
	|	IOTIMEOUT ':' NUMBER {
#ifdef SOCKS_SERVER
		config.timeout.io = atol($3);
#endif
	}
	;

connecttimeout:	{ $$ = NULL; }
	|	CONNECTTIMEOUT ':' NUMBER {
#ifdef SOCKS_SERVER
		config.timeout.negotiate = atol($3);
#endif
	}
	;

debuging:	{	$$ = NULL; }
	| 	DEBUGING ':' NUMBER {
		config.option.debug = atoi($3);
	}
	;

localdomain:	LOCALDOMAIN ':' LINE {
		const char *skip = "\t\n";

		/* lose whitespace from line. */
		$3 += strspn($3, skip);
		$3[strcspn($3, skip)] = NUL; 

		if (strlen($3) >= sizeof(config.domain))
			yyerror("domainname too long");
		strcpy(config.domain, $3);
	}
	;

compatibility:	{ $$ = NULL; }
	|	COMPATIBILITY ':' compatibilityname compatibility_list
	;

compatibilityname:	REUSEADDR {
#ifdef SOCKS_SERVER
		config.compat.reuseaddr = 1;	
	}
	|	SAMEPORT {
		config.compat.sameport = 1;
#endif
	}
	;

compatibility_list:	{ $$ = NULL; }
	|	compatibilityname compatibility_list
	;


authmethod: { $$ = NULL; }
	|	METHOD ':' authmethodname authmethod_list
	;

authmethod_list:	{ $$ = NULL; }
	|	authmethodname authmethod_list
	;

authmethodname:	NONE {
		methodv[(*methodc)++] = AUTHMETHOD_NONE; 
	};
	|	GSSAPI {
		yyerror("GSSAPI not supported");	
	}
	|	UNAME {
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
	}
	;


	/* filterrules */

clientrule: CLIENT verdict '{' fromto clientruleoption '}' {
#ifdef SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addclient(&rule); 

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		bzero(&rule, sizeof(rule));

		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	}
	;

clientruleoption:	libwrap log
	;



rule:	verdict '{' protocol fromto ruleoption '}' {
#ifdef SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addrule(&rule); 

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		bzero(&rule, sizeof(rule));

		src.atype	= SOCKS_ADDR_IPV4;
		dst.atype	= SOCKS_ADDR_IPV4;
#endif
	}
	;


ruleoption:	authmethod command libwrap log privileged proxyprotocol 
	;


verdict:	VERDICT_BLOCK {
#ifdef SOCKS_SERVER
		rule.verdict 	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol 		= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
	}
	|	VERDICT_PASS {
		rule.verdict 	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol 		= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
#endif 
	}
	;

command:	{ $$ = NULL; }
	| COMMAND ':' commandname command_list
	;

command_list:	{ $$ = NULL; }
	|	commandname command_list
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
	;


protocol:	{ $$ = NULL; }
	|	PROTOCOL ':'  protocolname protocol_list
	;

protocol_list:	{ $$ = NULL; }
	|	protocolname protocol_list
	;


protocolname: 	PROTOCOL_TCP {
		protocol->tcp = 1;
	}
 	|	PROTOCOL_UDP {
		protocol->udp = 1;
	}
	;


fromto:	srcaddress dstaddress
	;

log:	{ $$ = NULL; }
	|  LOG ':' logname log_list 
  	;
 
log_list:	{ $$ = NULL; }
	|  logname log_list
	;
 
logname:  LOG_CONNECT {
#ifdef SOCKS_SERVER
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


libwrap:	{ $$ = NULL; }
	|	LIBWRAPSTART ':' LINE {
#if defined(HAVE_LIBWRAP) && defined(SOCKS_SERVER)
		if (strlen($3) >= sizeof(rule.libwrap))
			yyerror("libwrap line too long.  Make buffer bigger");
		strcpy(rule.libwrap, $3);
#else		
		yyerror("libwrap support not compiled in");
#endif
	}
	;

privileged:	{ $$ = NULL; }
	|	PRIVILEGED	{
#ifdef SOCKSSERVER
		rule.privileged = 1;
#endif
	}
	;

srcaddress:	{ $$ = NULL; }
	|	from ':' address 
	;


dstaddress:	{ $$ = NULL; }
	|	to ':' address 
	;


gateway:	via ':' gwaddress gatewayoption
	;

gatewayoption:	command extension protocol proxyprotocol authmethod
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
#ifdef SOCKS_CLIENT
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

#ifdef SOCKS_CLIENT
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


portstart:	NUMBER {
		*port_tcp	= htons((in_port_t)atoi($1));
		*port_udp	= *port_tcp;
	}
	;

portservice:	SERVICENAME {
		struct servent	*service;
		struct protocol_t	protocolunset;
		
		bzero(&protocolunset, sizeof(protocolunset));

		/* set all protocols if none set, default. */
		if (memcmp(protocol, &protocolunset, sizeof(*protocol)) == 0)
			memset(protocol, UCHAR_MAX, sizeof(*protocol));

		if (protocol->tcp) {
			if ((service = getservbyname($1, "tcp")) == NULL)
				yyerror("bad servicename for tcp");
			*port_tcp = (in_port_t)service->s_port;
		}

		if (protocol->udp) {
			if ((service = getservbyname($1, "udp")) == NULL)
				yyerror("bad servicename for udp");
			*port_udp = (in_port_t)service->s_port;
		}
	}
	;


portend:	NUMBER {
		ruleaddress->portend = htons((in_port_t)atoi($1));
		ruleaddress->operator = range;
	}
	;

portoperator:	OPERATOR {
		*operator = string2operator($1);
	}
	;	


%%

#define INTERACTIVE 0

extern FILE *yyin;

int parseinit;

int
readconfig(fp)
	FILE *fp;
{

	yydebug = 0;
	parseinit = 0;

	yyin = fp;

	yyparse();

#ifdef SOCKS_CLIENT	/* client never rereads configfile. */
	fclose(yyin);
#endif

	errno = 0;	/* yacc for some reason alters errno atleast sometimes. */

	return 0;
}


static void
yyerror(s)
	const char *s;
{

	serrx(1, "%s: %d: %s near '%.50s'",
	config.option.configfile, yylineno, s,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);
}


static void
addressinit(address)
	struct ruleaddress_t *address;
{
		ruleaddress	= address;

		atype			= &ruleaddress->atype;
		ipaddr 		= &ruleaddress->addr.ipv4.ip;
		netmask 		= &ruleaddress->addr.ipv4.mask;
		domain		= ruleaddress->addr.domain;
		port_tcp 	= &ruleaddress->port.tcp;
		port_udp 	= &ruleaddress->port.udp;
		operator		= &ruleaddress->operator;
}
