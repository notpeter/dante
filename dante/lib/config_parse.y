/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2008,
 *               2009
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

#if 0 /* XXX automatically added at head of generated .c file */
#include "common.h"
#endif
#include "ifaddrs_compat.h"
#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.290 2009/09/10 14:23:30 michaels Exp $";

#if HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD)
   extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD) */

static void
addrinit(struct ruleaddr_t *addr);

static void
gwaddrinit(gwaddr_t *addr);

#if SOCKS_SERVER || BAREFOOTD
static void
ruleinit(struct rule_t *rule);
#endif /* SOCKS_SERVER || BAREFOOTD */

extern int yylineno;
extern char *yytext;

static int parsingconfig;

#if SOCKS_SERVER || BAREFOOTD
static struct rule_t          ruleinitmem;
static struct rule_t          rule;          /* new rule.                     */
static struct protocol_t      protocolmem;   /* new protocolmem.              */
#endif /* SOCKS_SERVER || BAREFOOTD */

static struct serverstate_t   state;
static struct route_t         route;         /* new route.                    */
static gwaddr_t               gw;            /* new gateway.                  */

static struct ruleaddr_t      src;            /* new src.                     */
static struct ruleaddr_t      dst;            /* new dst.                     */
static struct ruleaddr_t      rdr_from;
static struct ruleaddr_t      rdr_to;

#if BAREFOOTD
static struct ruleaddr_t      bounce_to;
#endif /* BAREFOOTD */

static struct ruleaddr_t      *ruleaddr;      /* current ruleaddr             */
static struct extension_t     *extension;     /* new extensions               */
static struct proxyprotocol_t *proxyprotocol; /* proxy protocol.              */

static unsigned char          *atype;         /* atype of new address.        */
static struct in_addr         *ipaddr;        /* new ipaddress                */
static struct in_addr         *netmask;       /* new netmask                  */
static char                   *domain;        /* new domain.                  */
static char                   *ifname;        /* new ifname.                  */
static char                   *url;           /* new url.                     */

static in_port_t              *port_tcp;      /* new TCP portnumber.          */
static in_port_t              *port_udp;      /* new UDP portnumber.          */
static int                    *methodv;       /* new authmethods.             */
static size_t                 *methodc;       /* number of them.              */
static struct protocol_t      *protocol;      /* new protocol.                */
static struct command_t       *command;       /* new command.                 */
static enum operator_t        *operator;      /* new operator.                */

#if HAVE_GSSAPI
static char                  *gssapiservicename; /* new gssapiservice.        */
static char                  *gssapikeytab;      /* new gssapikeytab.         */
static struct gssapi_enc_t   *gssapiencryption;  /* new encryption status.    */
#endif /* HAVE_GSSAPI */


#if DEBUG
#define YYDEBUG 1
#endif

#define ADDMETHOD(method)                                        \
do {                                                             \
   if (methodisset(method, methodv, *methodc))                   \
      yywarn("duplicate method: %s", method2string(method));     \
   else {                                                        \
      if (*methodc >= MAXMETHOD)                                 \
         yyerror("internal error, (%ld >= %ld)",                 \
         (long)*methodc, (long)MAXMETHOD);                       \
      methodv[(*methodc)++] = method;                            \
   }                                                             \
} while (0)

%}

%union {
   char   *string;
   uid_t   uid;
};


%type <string> configtype serverline clientline deprecated
%token <string> SERVERCONFIG CLIENTCONFIG DEPRECATED

%type   <string> protocol protocols protocolname
%type   <string> proxyprotocol proxyprotocolname proxyprotocols
%type   <string> user username usernames
%type   <string> group groupname groupnames
%type   <string> pamservicename
%type   <string> gssapiservicename
%type   <string> gssapikeytab
%type   <string> gssapienctype
%type   <string> resolveprotocol resolveprotocolname
%type   <string> srchost srchostoption srchostoptions
%type   <string> command commands commandname
%type   <string> redirect
%type   <string> bandwidth
%type   <string> session maxsessions
%type   <string> routeinit
%type   <string> udpportrange udpportrange_start udpportrange_end
%type   <string> debuging udpconnectdst


   /* clientconfig exclusive. */
%type   <string> clientinit clientconfig
%type   <string> clientoption


   /* serverconfig exclusive */
%type   <string> iotimeout negotiatetimeout
%type   <string> extension extensionname extensions
%type   <string> internal internalinit external externalinit
%type   <string> external_rotation
%type   <string> logoutput logoutputdevice logoutputdevices
%type   <string> compatibility compatibilityname compatibilitynames
%type   <string> global_authmethod global_clientauthmethod
%type   <string> authmethod authmethods authmethodname
%type   <string> clientcompatibility clientcompatibilityname
                 clientcompatibilitynames
%type   <string> serveroption
%type   <string> serverinit serverconfig
%type   <string> userids user_privileged user_unprivileged user_libwrap
%type   <uid>    userid
%type   <string> childstate

%token   <string> CLIENTRULE
%token   <string> INTERNAL EXTERNAL EXTERNAL_ROTATION
%token   <string> DEBUGING RESOLVEPROTOCOL
%token   <string> SRCHOST NOMISMATCH NOUNKNOWN CHECKREPLYAUTH
%token   <string> EXTENSION BIND PRIVILEGED
%token   <string> IOTIMEOUT IOTIMEOUT_TCP IOTIMEOUT_UDP NEGOTIATETIMEOUT
%token   <string> METHOD CLIENTMETHOD NONE GSSAPI UNAME RFC931 PAM
%token   <string> COMPATIBILITY REUSEADDR SAMEPORT DRAFT_5_05
%token   <string> CLIENTCOMPATIBILITY NECGSSAPI
%token   <string> USERNAME
%token   <string> GROUPNAME
%token   <string> USER_PRIVILEGED USER_UNPRIVILEGED USER_LIBWRAP
%token   <string> LOGOUTPUT LOGFILE
%token   <string> CHILD_MAXIDLE

   /* route */
%type   <string> route
%type   <string> via gateway routeoption routeoptions

%token   <string> ROUTE VIA

   /* rulelines */
%type   <string> rule ruleoption ruleoptions
%type   <string> clientrule clientruleoption clientruleoptions
%type   <string> option
%type   <string> verdict
%type   <string> fromto
%type   <string> log logs logname
%type   <string> libwrap
%type   <string> srcaddress dstaddress
%type   <string> internaladdress externaladdress
%type   <string> address ipaddress gwaddress domain ifname direct url
%type   <string> from to
%type   <string> netmask
%type   <string> port gwport portrange portstart portoperator portnumber
                 portservice
%type   <string> bounce bounce_to

%token <string> VERDICT_BLOCK VERDICT_PASS
%token <string> PAMSERVICENAME
%token <string> GSSAPISERVICE
%token <string> GSSAPIKEYTAB
%token <string> GSSAPIENCTYPE
%token <string> GSSAPIENC_ANY GSSAPIENC_CLEAR GSSAPIENC_INTEGRITY GSSAPIENC_CONFIDENTIALITY GSSAPIENC_PERMESSAGE
%token <string> GSSAPISERVICENAME GSSAPIKEYTABNAME
%token <string> PROTOCOL PROTOCOL_TCP PROTOCOL_UDP PROTOCOL_FAKE
%token <string> PROXYPROTOCOL PROXYPROTOCOL_SOCKS_V4 PROXYPROTOCOL_SOCKS_V5
                PROXYPROTOCOL_MSPROXY_V2 PROXYPROTOCOL_HTTP_V1_0
                PROXYPROTOCOL_UPNP
%token <string> USER GROUP
%token <string> COMMAND COMMAND_BIND COMMAND_CONNECT COMMAND_UDPASSOCIATE                         COMMAND_BINDREPLY COMMAND_UDPREPLY
%token <string> ACTION
%token <string> LINE
%token <string> LIBWRAPSTART
%token <string> OPERATOR
%token <string> LOG LOG_CONNECT  LOG_DATA LOG_DISCONNECT LOG_ERROR                               LOG_IOOPERATION
%token <string> IPADDRESS DOMAINNAME DIRECT IFNAME URL
%token <string> PORT PORTNUMBER SERVICENAME
%token <string> NUMBER
%token <string> FROM TO
%token <string> REDIRECT
%token <string> BANDWIDTH
%token <string> MAXSESSIONS
%token <string> UDPPORTRANGE UDPCONNECTDST
%token <string> YES NO
%token <string> BOUNCE


%%


   /*
    * first token we get should say whether we are parsing for client
    * or server.  Init as appropriate.
    */

configtype:   serverinit serverline
   |   clientinit clientline
   ;

serverinit:   SERVERCONFIG {
#if SOCKS_SERVER || BAREFOOTD
      protocol       = &protocolmem;
      extension      = &sockscf.extension;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;


serverline:   { $$ = NULL; }
   |   serverline '\n'
   |   serverline serverconfig
   |   serverline clientrule
   |   serverline rule
   |   serverline route
   ;

clientline:   { $$ = NULL; }
   |   clientline '\n'
   |   clientline clientconfig
   |   clientline route
   ;


clientinit:   CLIENTCONFIG {
   }
   ;

clientconfig:   clientoption
   |  deprecated
   ;

serverconfig:   global_authmethod
   |   global_clientauthmethod
   |   deprecated
   |   internal
   |   external
   |   external_rotation
   |   logoutput
   |   serveroption
   |   userids
   |   childstate
   |   debuging
   |   udpconnectdst
   ;

serveroption:   compatibility
   |   negotiatetimeout
   |   extension
   |   iotimeout
   |   resolveprotocol
   |   srchost
   ;


deprecated:   DEPRECATED {
      yyerror("given keyword \"%s\" is deprecated", $1);
   }
   ;

route:   ROUTE routeinit '{' routeoptions fromto gateway routeoptions '}' {
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;
      route.gw.state  = state;

      socks_addroute(&route, 1);
   }
   ;

routeinit: {
      command             = &state.command;
      extension           = &state.extension;
      methodv             = state.methodv;
      methodc             = &state.methodc;
      protocol            = &state.protocol;
      proxyprotocol       = &state.proxyprotocol;

#if HAVE_GSSAPI
      gssapiservicename = state.gssapiservicename;
      gssapikeytab      = state.gssapikeytab;
      gssapiencryption  = &state.gssapiencryption;
#endif /* HAVE_GSSAPI */

      bzero(&state, sizeof(state));
      bzero(&route, sizeof(route));
      bzero(&gw, sizeof(gw));
      bzero(&src, sizeof(src));
      bzero(&dst, sizeof(dst));
      src.atype = SOCKS_ADDR_IPV4;
      dst.atype = SOCKS_ADDR_IPV4;
   }
   ;


proxyprotocol:   PROXYPROTOCOL ':' proxyprotocols
   ;

proxyprotocolname:   PROXYPROTOCOL_SOCKS_V4 {
         proxyprotocol->socks_v4    = 1;
   }
   |   PROXYPROTOCOL_SOCKS_V5 {
         proxyprotocol->socks_v5    = 1;
   }
   |  PROXYPROTOCOL_MSPROXY_V2 {
         proxyprotocol->msproxy_v2  = 1;
   }
   |  PROXYPROTOCOL_HTTP_V1_0 {
         proxyprotocol->http_v1_0   = 1;
   }
   |  PROXYPROTOCOL_UPNP {
         proxyprotocol->upnp        = 1;
   }
   | deprecated
   ;

proxyprotocols: proxyprotocolname
   |   proxyprotocolname proxyprotocols
   ;

user: USER ':' usernames
   ;

username:   USERNAME {
#if SOCKS_SERVER || BAREFOOTD
      if (addlinkedname(&rule.user, $1) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER  || BAREFOOTD */
   }
   ;

usernames:   username
   |   username usernames
   ;

group: GROUP ':' groupnames
   ;

groupname:   GROUPNAME {
#if SOCKS_SERVER || BAREFOOTD
      if (addlinkedname(&rule.group, $1) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER  || BAREFOOTD */
   }
   ;

groupnames:   groupname
   |   groupname groupnames
   ;

extension:   EXTENSION ':' extensions
   ;

extensionname:   BIND {
         extension->bind = 1;
   }
   ;

extensions:   extensionname
   |   extensionname extensions
   ;

internal:   INTERNAL internalinit ':' internaladdress {
#if SOCKS_SERVER || BAREFOOTD
      addinternal(ruleaddr);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

internalinit: {
#if SOCKS_SERVER || BAREFOOTD
   static struct ruleaddr_t mem;
   struct servent   *service;

   addrinit(&mem);
   bzero(protocol, sizeof(*protocol));

   /* set default port. */
   if ((service = getservbyname("socks", "tcp")) == NULL)
      *port_tcp = htons(SOCKD_PORT);
   else
      *port_tcp = (in_port_t)service->s_port;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

external:   EXTERNAL externalinit ':' externaladdress {
#if SOCKS_SERVER || BAREFOOTD
      addexternal(ruleaddr);
#endif
   }
   ;

externalinit: {
#if SOCKS_SERVER || BAREFOOTD
      static struct ruleaddr_t mem;

      addrinit(&mem);
#endif
   }
   ;

external_rotation:   EXTERNAL_ROTATION ':' NONE {
#if SOCKS_SERVER || BAREFOOTD
      sockscf.external.rotation = ROTATION_NONE;
   }
   |   EXTERNAL_ROTATION ':' ROUTE {
#if !HAVE_ROUTE_SOURCE
      yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
   }
   ;

clientoption:   logoutput
   |   debuging
   |   resolveprotocol
   ;

logoutput: LOGOUTPUT ':' logoutputdevices
   ;

logoutputdevice:   LOGFILE {
   socks_addlogfile($1);
}


logoutputdevices:   logoutputdevice
   |   logoutputdevice logoutputdevices
   ;

childstate:
   CHILD_MAXIDLE ':' NUMBER {
#if SOCKS_SERVER || BAREFOOTD
      yyerror("Sorry, child.maxidle is disabled due to a suspected bug");
      if (atoi($3) != 0 && atoi($3) < SOCKD_FREESLOTS)
         yyerror("%s (%s) can't be less than SOCKD_FREESLOTS (%d)",
         $1, $3, SOCKD_FREESLOTS);
      sockscf.child.maxidle = atoi($3);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;


userids:   user_privileged
   |   user_unprivileged
   |   user_libwrap
   ;

user_privileged:   USER_PRIVILEGED ':' userid {
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged         = $3;
      sockscf.uid.privileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

user_unprivileged:   USER_UNPRIVILEGED ':' userid {
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged         = $3;
      sockscf.uid.unprivileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

user_libwrap:   USER_LIBWRAP ':' userid {
#if HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD)
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.libwrap         = $3;
      sockscf.uid.libwrap_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#else  /* !HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD) */
      yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP (SOCKS_SERVER || BAREFOOTD)*/
   }
   ;


userid:   USERNAME {
      struct passwd *pw;

      if ((pw = socks_getpwnam($1)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", $1);
      else
         $$ = pw->pw_uid;
   }
   ;

iotimeout:   IOTIMEOUT ':' NUMBER {
#if SOCKS_SERVER || BAREFOOTD
      sockscf.timeout.tcpio = (time_t)atol($3);
      sockscf.timeout.udpio = sockscf.timeout.tcpio;
   }
   | IOTIMEOUT_TCP ':' NUMBER  {
      sockscf.timeout.tcpio = (time_t)atol($3);
   }
   | IOTIMEOUT_UDP ':' NUMBER  {
      sockscf.timeout.udpio = (time_t)atol($3);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

negotiatetimeout:   NEGOTIATETIMEOUT ':' NUMBER {
#if SOCKS_SERVER || BAREFOOTD
      sockscf.timeout.negotiate = (time_t)atol($3);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

debuging: DEBUGING ':' NUMBER {
      sockscf.option.debug = atoi($3);
   }
   ;

udpconnectdst: UDPCONNECTDST ':' YES {
#if SOCKS_SERVER || BAREFOOTD
      sockscf.option.udpconnectdst = 1;
   }
   | UDPCONNECTDST ':' NO {
      sockscf.option.udpconnectdst = 0;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;


compatibility:   COMPATIBILITY ':' compatibilitynames
   ;

compatibilityname:   REUSEADDR {
#if SOCKS_SERVER || BAREFOOTD
      sockscf.compat.reuseaddr = 1;
   }
   |   SAMEPORT {
      sockscf.compat.sameport = 1;
   }
   |  DRAFT_5_05 {
      sockscf.compat.draft_5_05 = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

compatibilitynames:   compatibilityname
   |   compatibilityname compatibilitynames
   ;

resolveprotocol:   RESOLVEPROTOCOL ':' resolveprotocolname
   ;

resolveprotocolname:   PROTOCOL_FAKE {
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
   |  PROTOCOL_TCP {
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
   |   PROTOCOL_UDP {
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
   ;

srchost:   SRCHOST ':' srchostoptions
   ;

srchostoption:   NOMISMATCH {
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_LIBWRAP
         sockscf.srchost.nomismatch = 1;
   }
   |  NOUNKNOWN {
         sockscf.srchost.nounknown = 1;
#else
      yyerror("srchostoption requires libwrap");
#endif /* HAVE_LIBWRAP */
   }
   |  CHECKREPLYAUTH {
         sockscf.srchost.checkreplyauth = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

srchostoptions:   srchostoption
   |   srchostoption srchostoptions
   ;


authmethod:   METHOD ':' authmethods
   ;

global_authmethod:   METHOD ':' {
#if SOCKS_SERVER
   methodv = sockscf.methodv;
   methodc = &sockscf.methodc;
   *methodc = 0; /* reset. */
#endif /* SOCKS_SERVER */
   } authmethods
   ;

global_clientauthmethod:   CLIENTMETHOD ':' {
#if SOCKS_SERVER
   methodv = sockscf.clientmethodv;
   methodc = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif /* SOCKS_SERVER */
   } authmethods
   ;

authmethodname:   NONE {
      ADDMETHOD(AUTHMETHOD_NONE);
   };
   |   GSSAPI {
#if !HAVE_GSSAPI
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#else
      ADDMETHOD(AUTHMETHOD_GSSAPI);
#endif /* !HAVE_GSSAPI */
   }
   |   UNAME {
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
   |   RFC931 {
#if HAVE_LIBWRAP
#if SOCKS_SERVER
      ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !SOCKS_SERVER not a real socks method.  For client same as none. */
      ADDMETHOD(AUTHMETHOD_NONE);
#endif /* SOCKS_SERVER */
#else
      yyerror("method %s requires libwrap library", AUTHMETHOD_RFC931s);
#endif /* HAVE_LIBWRAP */
   }
   |   PAM {
#if HAVE_PAM
      ADDMETHOD(AUTHMETHOD_PAM);
#else /* !HAVE_PAM */
      yyerror("method %s requires pam library", AUTHMETHOD_PAMs);
#endif /* HAVE_PAM */
   }
   ;

authmethods:   authmethodname
   |   authmethodname authmethods
   ;


   /* filter rules */

clientrule: CLIENTRULE verdict '{' clientruleoptions fromto clientruleoptions
'}' {
#if BAREFOOTD
   if (bounce_to.atype == 0)
      yyerror("no address to bounce to given");
#endif /* BAREFOOTD */

#if SOCKS_SERVER || BAREFOOTD
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;
#if BAREFOOTD
      rule.bounce_to   = bounce_to;
#endif /* BAREFOOTD */

      addclientrule(&rule);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

clientruleoption:   option
   |   bandwidth {
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("bandwidth");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   |   protocol {
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
   |   redirect   {
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("redirect");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

clientruleoptions:   { $$ = NULL; }
   |   clientruleoption clientruleoptions
   ;

rule:   verdict '{' ruleoptions fromto ruleoptions '}' {
#if SOCKS_SERVER || BAREFOOTD
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

      addsocksrule(&rule);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;


ruleoption:   option
   |   bandwidth {
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("bandwidth");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   |   command
   |   udpportrange
   |   protocol
   |   proxyprotocol
   |   redirect   {
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("redirect");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

ruleoptions:   { $$ = NULL; }
   | ruleoption ruleoptions
   ;

option: authmethod
   |   clientcompatibility
   |   libwrap
   |   log
   |   pamservicename
   |   gssapiservicename
   |   gssapikeytab
   |   gssapienctype
   |   user
   |   group
   |   bounce  {
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
   |   session   {
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("session");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

clientcompatibility:   CLIENTCOMPATIBILITY ':' clientcompatibilitynames
   ;

clientcompatibilityname: NECGSSAPI {
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#endif /* HAVE_GSSAPI */
   }
   ;

clientcompatibilitynames:   clientcompatibilityname
   |   clientcompatibilityname clientcompatibilitynames
   ;


verdict:   VERDICT_BLOCK {
#if SOCKS_SERVER || BAREFOOTD
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
   |   VERDICT_PASS {
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;


command:   COMMAND ':' commands
   ;

commands:   commandname
   |   commandname commands
   ;

commandname:   COMMAND_BIND {
         command->bind = 1;
   }
   |   COMMAND_CONNECT {
         command->connect = 1;
   }
   |   COMMAND_UDPASSOCIATE {
         command->udpassociate = 1;
   }

   /* pseudocommands */

   |   COMMAND_BINDREPLY   {
         command->bindreply = 1;
   }

   |   COMMAND_UDPREPLY {
         command->udpreply = 1;
   }
   ;


protocol:   PROTOCOL ':'  protocols
   ;

protocols:   protocolname
   |   protocolname protocols
   ;

protocolname:   PROTOCOL_TCP {
      protocol->tcp = 1;
   }
   |   PROTOCOL_UDP {
      protocol->udp = 1;
   }
   ;


fromto:   srcaddress dstaddress
   ;

redirect:   REDIRECT rdr_fromaddress rdr_toaddress
   |        REDIRECT rdr_fromaddress
   |        REDIRECT rdr_toaddress
   ;

session: maxsessions
   ;

maxsessions: MAXSESSIONS ':' NUMBER {
#if SOCKS_SERVER || BAREFOOTD
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
#endif /* SOCKS_SERVER || BAREFOOTD */
}
;

bandwidth:   BANDWIDTH ':' NUMBER {
#if SOCKS_SERVER || BAREFOOTD
      static bw_t bwmeminit;

     /*
      * temporarily allocate ordinary memory, later on point it to
      * the correct index in sockscf.bwv.
      */
      if ((rule.bw = malloc(sizeof(*rule.bw))) == NULL)
         serr(EXIT_FAILURE, NOMEM);

      *rule.bw = bwmeminit;

      if ((rule.bw->maxbps = atoi($3)) <= 0)
         yyerror("bandwidth value must be greater than 0");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;


log:   LOG ':' logs
   ;

logname:  LOG_CONNECT {
#if SOCKS_SERVER || BAREFOOTD
   rule.log.connect = 1;
   }
   |   LOG_DATA {
         rule.log.data = 1;
   }
   |   LOG_DISCONNECT {
         rule.log.disconnect = 1;
   }
   |   LOG_ERROR {
         rule.log.error = 1;
   }
   |   LOG_IOOPERATION {
         rule.log.iooperation = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
   ;

logs:   logname
   |  logname logs
   ;


pamservicename: PAMSERVICENAME ':' SERVICENAME {
#if HAVE_PAM && (SOCKS_SERVER || BAREFOOTD)
      if (strlen($3) >= sizeof(rule.state.pamservicename))
         yyerror("servicename too long");
      strcpy(rule.state.pamservicename, $3);
#else
      yyerror("pam support not compiled in");
#endif /* HAVE_PAM && (SOCKS_SERVER || BAREFOOTD) */
   }
   ;


gssapiservicename: GSSAPISERVICE ':' GSSAPISERVICENAME {
#if HAVE_GSSAPI
      if (strlen($3) >= sizeof(state.gssapiservicename))
         yyerror("service name too long");
      strcpy(gssapiservicename, $3);
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
   ;

gssapikeytab: GSSAPIKEYTAB ':' GSSAPIKEYTABNAME {
#if HAVE_GSSAPI
#if SOCKS_SERVER
      if (strlen($3) >= sizeof(state.gssapikeytab))
         yyerror("keytab name too long");
      strcpy(gssapikeytab, $3);
#else
      yyerror("gssapi keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
   ;

gssapienctype: GSSAPIENCTYPE':' gssapienctypes
   ;

gssapienctypename: GSSAPIENC_ANY {
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
   |  GSSAPIENC_CLEAR {
      gssapiencryption->clear = 1;
   }
   |  GSSAPIENC_INTEGRITY {
      gssapiencryption->integrity = 1;
   }
   |  GSSAPIENC_CONFIDENTIALITY {
      gssapiencryption->confidentiality = 1;
   }
   |  GSSAPIENC_PERMESSAGE {
      yyerror("gssapi per-message encryption not supported");
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
   ;

gssapienctypes: gssapienctypename
   |  gssapienctypename gssapienctypes
   ;

bounce: BOUNCE bounce_to ':' address
   ;

libwrap:   LIBWRAPSTART ':' LINE {
#if HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD)
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

#else
      yyerror("libwrapsupport not compiled in");
#endif /* HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD) */
   }
   ;


srcaddress:   from ':' address
   ;


dstaddress:   to ':' address
   ;

rdr_fromaddress: rdr_from ':' address
   ;

rdr_toaddress: rdr_to ':' address
   ;

gateway:   via ':' gwaddress
   ;

routeoption:   command
   |   clientcompatibility
   |   extension
   |   protocol
   |   gssapiservicename
   |   gssapikeytab
   |   gssapienctype
   |   proxyprotocol
   |   authmethod
   ;

routeoptions:   { $$ = NULL; }
   | routeoption routeoptions
   ;

from:   FROM {
      addrinit(&src);
   }
   ;

to:   TO {
      addrinit(&dst);
   }
   ;

rdr_from:   FROM {
      addrinit(&rdr_from);
   }
   ;

rdr_to:   TO {
      addrinit(&rdr_to);
   }
   ;

bounce_to:   TO {
#if BAREFOOTD
      addrinit(&bounce_to);
#endif /* BAREFOOTD */
   }
   ;


via:   VIA {
      gwaddrinit(&gw);
   }
   ;

internaladdress: ipaddress port
   |   domain port
   |   ifname port
   ;

externaladdress: ipaddress
   |   domain
   |   ifname
   ;


address: ipaddress '/' netmask port
   |   domain port
   |   ifname port
   ;


gwaddress:   ipaddress gwport
   |   domain gwport
   |   ifname gwport
   |   direct
   |   url
   ;


ipaddress:   IPADDRESS {
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton($1, ipaddr) != 1)
         yyerror("bad address: %s", $1);
   }
   ;


netmask:   NUMBER {
      if (atoi($1) < 0 || atoi($1) > 32)
         yyerror("bad netmask: %s", $1);

      netmask->s_addr
      = atoi($1) == 0 ? 0 : htonl(0xffffffff << (32 - atoi($1)));
   }
   |   IPADDRESS {
         if (!inet_aton($1, netmask))
            yyerror("bad netmask: %s", $1);
   }
   ;

domain:   DOMAINNAME {
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen($1) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");
      strcpy(domain, $1);
   }
   ;

ifname:   IFNAME {
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen($1) >= MAXIFNAMELEN)
         yyerror("interfacename too long");
      strcpy(ifname, $1);
   }
   ;


direct:   DIRECT {
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen($1) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", $1);
      strcpy(domain, $1);

      proxyprotocol->direct = 1;
   }
   ;

url:   URL {
      *atype = SOCKS_ADDR_URL;

      if (strlen($1) >= MAXURLLEN)
         yyerror("url \"%s\" too long", $1);
      strcpy(url, $1);
   }
   ;


port: { $$ = NULL; }
   |   PORT ':' portnumber
   |   PORT portoperator portnumber
   |   PORT portrange
   ;

gwport: { $$ = NULL; }
   |      PORT portoperator portnumber
   ;

portnumber:   portservice
   |   portstart
   ;

portrange:   portstart '-' portend
   ;


portstart:   PORTNUMBER {
      *port_tcp   = htons((in_port_t)atoi($1));
      *port_udp   = htons((in_port_t)atoi($1));
   }
   ;

portend:   PORTNUMBER {
      ruleaddr->portend    = htons((in_port_t)atoi($1));
      ruleaddr->operator   = range;
   }
   ;

portservice:   SERVICENAME {
      struct servent   *service;

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


portoperator:   OPERATOR {
      *operator = string2operator($1);
   }
   ;

udpportrange: UDPPORTRANGE ':' udpportrange_start '-' udpportrange_end
   ;

udpportrange_start: PORTNUMBER {
#if SOCKS_SERVER
   rule.udprange.start = htons((in_port_t)atoi($1));
#endif /* SOCKS_SERVER */
   }
   ;

udpportrange_end: PORTNUMBER {
#if SOCKS_SERVER
   rule.udprange.end = htons((in_port_t)atoi($1));
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerror("udp end port (%s) can not be less than udp start port (%u)",
      $1, ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
   ;


%%

#define INTERACTIVE      0

extern FILE *yyin;

int socks_parseinit;

int
parseconfig(filename)
   const char *filename;
{
   const char *function = "parseconfig()";
   struct stat statbuf;
   int havefile;
#if SOCKS_CLIENT
   char *proxyserver, *logfile, *debug;
#endif /* SOCKS_CLIENT */

   if ((yyin = fopen(filename, "r")) == NULL
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         swarn("%s: could not open %s", function, filename);

      havefile              = 0;
      sockscf.option.debug  = 1;
   }
   else {
      socks_parseinit = 0;
      yydebug         = 0;               
      yylineno        = 1;

      errno         = 0;   /* don't report old errors in yyparse(). */
      havefile      = 1;
      parsingconfig = 1;
      yyparse();
      parsingconfig = 0;
      fclose(yyin);
   }

   errno = 0;

#if SOCKS_CLIENT /* assume server admin can set it up correctly himself. */
   if ((logfile = socks_getenv("SOCKS_LOGOUTPUT", dontcare)) != NULL)
      socks_addlogfile(logfile);

   if ((debug = socks_getenv("SOCKS_DEBUG", dontcare)) != NULL)
      sockscf.option.debug = atoi(debug);

   if ((proxyserver = socks_getenv("SOCKS4_SERVER", dontcare)) != NULL
   ||  (proxyserver = socks_getenv("SOCKS5_SERVER", dontcare)) != NULL
   ||  (proxyserver = socks_getenv("SOCKS_SERVER", dontcare))  != NULL
   ||  (proxyserver = socks_getenv("HTTP_PROXY",    dontcare)) != NULL) {
      char ipstring[INET_ADDRSTRLEN], *portstring;
      struct sockaddr_in saddr;
      struct route_t route;
      struct ruleaddr_t raddr;

      slog(LOG_DEBUG, "%s: found proxyserver set in environment, value %s",
      function, proxyserver);

      if ((portstring = strchr(proxyserver, ':')) == NULL)
         serrx(EXIT_FAILURE, "%s: illegal format for port specification "
         "in SOCKS_SERVER %s: missing ':' delimiter", function, proxyserver);

      if (atoi(portstring + 1) < 1 || atoi(portstring + 1) > 0xffff)
         serrx(EXIT_FAILURE, "%s: illegal value for port specification "
         "in SOCKS_SERVER %s: must be between %d and %d",
         function, proxyserver, 1, 0xffff);

      if (portstring - proxyserver == 0
      || (size_t)(portstring - proxyserver) > sizeof(ipstring) - 1)
         serrx(EXIT_FAILURE, "%s: illegal format for ipaddress specification "
         "in SOCKS_SERVER %s: too short/long", function, proxyserver);

      strncpy(ipstring, proxyserver, (size_t)(portstring - proxyserver));
      ipstring[portstring - proxyserver] = NUL;
      ++portstring;

      bzero(&saddr, sizeof(saddr));
      saddr.sin_family = AF_INET;
      if (inet_pton(saddr.sin_family, ipstring, &saddr.sin_addr) != 1)
         serr(EXIT_FAILURE, "%s: illegal format for ipaddress specification "
         "in SOCKS_SERVER %s", function, ipstring);
      saddr.sin_port = htons(atoi(portstring));

      memset(&route, 0, sizeof(route));
      route.src.atype                           = SOCKS_ADDR_IPV4;
      route.src.addr.ipv4.ip.s_addr             = htonl(0);
      route.src.addr.ipv4.mask.s_addr           = htonl(0);
      route.src.port.tcp                        = route.src.port.udp = htons(0);
      route.src.operator                        = none;

      route.dst = route.src;

      ruleaddr2gwaddr(sockaddr2ruleaddr((struct sockaddr *)&saddr, &raddr),
      &route.gw.addr);

      if (socks_getenv("SOCKS4_SERVER", dontcare)      != NULL)
         route.gw.state.proxyprotocol.socks_v4 = 1;
      else if (socks_getenv("SOCKS5_SERVER", dontcare) != NULL)
         route.gw.state.proxyprotocol.socks_v5 = 1;
      else if (socks_getenv("SOCKS_SERVER", dontcare)  != NULL) {
         route.gw.state.proxyprotocol.socks_v5 = 1;
         route.gw.state.proxyprotocol.socks_v4 = 1;
      }
      else if (socks_getenv("HTTP_PROXY", dontcare)    != NULL)
         route.gw.state.proxyprotocol.http_v1_0 = 1;
      else
         SERRX(0); /* NOTREACHED */

      socks_addroute(&route, 1);
   }
   else if ((proxyserver = socks_getenv("UPNP_IGD", dontcare)) != NULL) {
      /*
       * Should be either an interface name (the interface to broadcast
       * for a response from the igd-device), "broadcast", to indicate
       * all interfaces, or a full url to the igd.
       */
      struct route_t route;

      memset(&route, 0, sizeof(route));
      route.src.atype                 = SOCKS_ADDR_IPV4;
      route.src.addr.ipv4.ip.s_addr   = htonl(0);
      route.src.addr.ipv4.mask.s_addr = htonl(0);
      route.src.port.tcp              = route.src.port.udp = htons(0);
      route.src.operator              = none;

      route.dst                       = route.src;

      /*
       * url or interface to broadcast for a response for?
       */
      if (strncasecmp(proxyserver, "http://", strlen("http://")) == 0) {
         route.gw.addr.atype = SOCKS_ADDR_URL;
         strncpy(route.gw.addr.addr.urlname, proxyserver,
                 sizeof(route.gw.addr.addr.urlname));

         if (route.gw.addr.addr.urlname[sizeof(route.gw.addr.addr.urlname) - 1]
         != NUL)
            serrx(EXIT_FAILURE, "url for igd, \"%s\", is too.  "
                                "Max is %lu characters",
                                proxyserver,
                                (unsigned long)sizeof(
                                               route.gw.addr.addr.urlname) - 1);

         route.gw.state.proxyprotocol.upnp = 1;
         socks_addroute(&route, 1);
      }
      else if (strcasecmp(proxyserver, "broadcast") == 0) {
         /*
          * Don't know what interface the igd is on, so add routes
          * for it on all interfaces.  Hopefully at least one interface
          * will get a response.
          */
         struct ifaddrs *ifap, *iface;

         route.gw.addr.atype                 = SOCKS_ADDR_IFNAME;
         route.gw.state.proxyprotocol.upnp = 1;

         if (getifaddrs(&ifap) == -1)
            serr(EXIT_FAILURE, "%s: getifaddrs() failed to get interface list",
            function);

         for (iface = ifap; iface != NULL; iface = iface->ifa_next) {
            if (iface->ifa_addr                          == NULL
            ||  iface->ifa_addr->sa_family               != AF_INET
            ||  TOIN(iface->ifa_addr)->sin_addr.s_addr   == htonl(0)
            ||  !(iface->ifa_flags & (IFF_UP | IFF_MULTICAST))
            ||  iface->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
               continue;

            if (strlen(iface->ifa_name)
            > sizeof(route.gw.addr.addr.ifname) - 1) {
               serr(1, "%s: ifname %s is too long, max is %lu",
               function, iface->ifa_name,
               (unsigned long)(sizeof(route.gw.addr.addr.ifname) - 1));
            }

            strcpy(route.gw.addr.addr.ifname, iface->ifa_name);
            socks_addroute(&route, 1);
         }

         freeifaddrs(ifap);
      }
      else { /* must be an interface name. */
         /*
          * check that the given interface exists and has an address
          */
         struct sockaddr addr, mask;

         if (ifname2sockaddr(proxyserver, 0, &addr, &mask) == NULL)
            serr(1, "%s: can't find interface named %s with ip configured",
            function, proxyserver);

         route.gw.addr.atype = SOCKS_ADDR_IFNAME;

         if (strlen(proxyserver) > sizeof(route.gw.addr.addr.ifname) - 1)
            serr(1, "%s: ifname %s is too long, max is %lu",
            function, proxyserver,
            (unsigned long)(sizeof(route.gw.addr.addr.ifname) - 1));

         strcpy(route.gw.addr.addr.ifname, proxyserver);

         route.gw.state.proxyprotocol.upnp = 1;
         socks_addroute(&route, 1);
      }
   }

   if (socks_getenv("SOCKS_AUTOADD_LANROUTES", isfalse) == NULL) {
      /*
       * assume it's good to add direct routes for the lan also.
       */
      struct ifaddrs *ifap;

      slog(LOG_DEBUG, "%s: auto-adding direct routes for lan ...", function);

      if (getifaddrs(&ifap) == 0) {
         struct ifaddrs *iface;

         for (iface = ifap; iface != NULL; iface = iface->ifa_next)
            if (iface->ifa_addr            != NULL
            &&  iface->ifa_addr->sa_family == AF_INET)
               socks_autoadd_directroute(
               (const struct sockaddr_in *)iface->ifa_addr,
               (const struct sockaddr_in *)iface->ifa_netmask);

         freeifaddrs(ifap);
      }
   }
   else
      slog(LOG_DEBUG, "%s: not auto-adding direct routes for lan", function);

#endif /* SOCKS_CLIENT */

   return havefile ? 0 : -1;
}

void
yyerror(const char *fmt, ...)
{
   va_list ap;
   char buf[2048];
   size_t bufused;

   /* LINTED pointer casts may be troublesome */
   va_start(ap, fmt);

   if (parsingconfig)
      bufused = snprintfn(buf, sizeof(buf),
                          "%s: error on line %d, near \"%.20s\": ",
                          sockscf.option.configfile, yylineno,
                          (yytext == NULL || *yytext == NUL) ?
                          "'start of line'" : yytext);

   else 
      bufused = snprintfn(buf, sizeof(buf),
                          "error in syntax of environment variable: ");

   vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (errno)
      serr(EXIT_FAILURE, buf);
   serrx(EXIT_FAILURE, buf);
}

void
yywarn(const char *fmt, ...)
{
   va_list ap;
   char buf[2048];
   size_t bufused;

   /* LINTED pointer casts may be troublesome */
   va_start(ap, fmt);

   if (parsingconfig)
      bufused = snprintfn(buf, sizeof(buf),
                         "%s: warning on line %d, near \"%.10s\": ",
                         sockscf.option.configfile, yylineno,
                         (yytext == NULL || *yytext == NUL) ?
                         "'start of line'" : yytext);
   else 
      bufused = snprintfn(buf, sizeof(buf),
                          "error in syntax of environment variable: ");

   vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (errno)
      swarn(buf);
   swarnx(buf);
}

static void
addrinit(addr)
   struct ruleaddr_t *addr;
{
   ruleaddr   = addr;

   atype      = &ruleaddr->atype;
   ipaddr     = &ruleaddr->addr.ipv4.ip;
   netmask    = &ruleaddr->addr.ipv4.mask;
   domain     = ruleaddr->addr.domain;
   ifname     = ruleaddr->addr.ifname;
   port_tcp   = &ruleaddr->port.tcp;
   port_udp   = &ruleaddr->port.udp;
   operator   = &ruleaddr->operator;
}

static void
gwaddrinit(addr)
   gwaddr_t *addr;
{
   static enum operator_t operatormem;

   atype    = &addr->atype;
   ipaddr   = &addr->addr.ipv4;
   domain   = addr->addr.domain;
   ifname   = addr->addr.ifname;
   url      = addr->addr.urlname;
   port_tcp = &addr->port;
   port_udp = &addr->port;
   operator = &operatormem; /* no operator in gwaddr. */
}

#if SOCKS_SERVER || BAREFOOTD
static void
ruleinit(rule)
   struct rule_t *rule;
{
   rule->linenumber  = yylineno;

   command             = &rule->state.command;
   methodv             = rule->state.methodv;
   methodc             = &rule->state.methodc;
   protocol            = &rule->state.protocol;
   proxyprotocol       = &rule->state.proxyprotocol;

#if HAVE_GSSAPI
   gssapiservicename = rule->state.gssapiservicename;
   gssapikeytab      = rule->state.gssapikeytab;
   gssapiencryption  = &rule->state.gssapiencryption;
#endif /* HAVE_GSSAPI */

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   *rule = ruleinitmem;

   src.atype = SOCKS_ADDR_IPV4;
   src.addr.ipv4.ip.s_addr = htonl(INADDR_ANY);
   src.port.tcp = src.port.udp = src.portend = htons(0);

   dst = rdr_from = rdr_to = src;
}

#endif /* SOCKS_SERVER || BAREFOOTD */
