/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2008,
 *               2009, 2010, 2011
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
"$Id: config_parse.y,v 1.401 2011/08/01 15:23:27 michaels Exp $";

#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
   extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

#define CHECKNUMBER(number, op, checkagainst)                                  \
do {                                                                           \
   if (!(atol((number)) op (checkagainst)))                                    \
      yyerror("number must be " #op " " #checkagainst ".  It can not be %ld",  \
              atol((number)));                                                 \
} while (0)

#define CHECKPORTNUMBER(portnumber)                                            \
do {                                                                           \
      CHECKNUMBER(portnumber, >=, 0);                                          \
      CHECKNUMBER(portnumber, <=, IP_MAXPORT);                                 \
} while (0)

static void
addrinit(struct ruleaddr_t *addr, const int netmask_required);

static void
gwaddrinit(gwaddr_t *addr);

#if SOCKS_CLIENT
static void parseclientenv(int *haveproxyserver);
/*
 * parses client environment, if any.  
 * If a proxyserver is configured in enviroment, "haveproxyserver" is set
 * to true upon return.  If not, it is set to false.
 */

static void
addproxyserver(const char *proxyserver, 
               const struct proxyprotocol_t *proxyprotocol);
/*
 * Adds a route for a proxyserver with address "proxyserver" to our
 * routes.
 * "proxyprotocol" is the proxyprotocols supported by the proxyserver.
 */
#else /* !SOCKS_CLIENT */

/*
 * Reset pointers to point away from rule-specific memory to global
 * memory.  Should be called after adding a rule.
 */
static void rulereset(void);

/*
 * Prepare pointers to point to the correct memory for adding a new rule.
 */
static void ruleinit(struct rule_t *rule);

#endif /* !SOCKS_CLIENT */

extern int yylineno;
extern char *yytext;

static int parsingconfig;

static unsigned char          add_to_errorlog; /* adding logfile to errorlog? */
static struct timeout_t       *timeout = &sockscf.timeout;

#if !SOCKS_CLIENT
static struct rule_t          rule;          /* new rule.                     */
static struct protocol_t      protocolmem;   /* new protocolmem.              */
#if !HAVE_PRIVILEGES
static struct userid_t        olduserid;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */

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

static atype_t                *atype;         /* atype of new address.        */
static struct in_addr         *ipaddr;        /* new ip address               */
static struct in_addr         *netmask;       /* new netmask                  */
static int                    netmask_required;/*
                                                * netmask required for this
                                                * address?
                                                */
static char                   *domain;        /* new domain.                  */
static char                   *ifname;        /* new ifname.                  */
static char                   *url;           /* new url.                     */

static in_port_t              *port_tcp;      /* new TCP port number.         */
static in_port_t              *port_udp;      /* new UDP port number.         */
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

#if HAVE_LDAP
static struct ldap_t         *ldap;        /* new ldap server details.        */
#endif

#if DEBUG
#define YYDEBUG 1
#endif /* DEBUG */

#define ADDMETHOD(method)                                                      \
do {                                                                           \
   if (methodisset(method, methodv, *methodc))                                 \
      yywarn("duplicate method: %s", method2string(method));                   \
   else {                                                                      \
      if (*methodc >= MAXMETHOD)                                               \
         yyerror("internal error, too many authmethods (%ld >= %ld)",          \
         (long)*methodc, (long)MAXMETHOD);                                     \
      methodv[(*methodc)++] = method;                                          \
   }                                                                           \
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
%type   <string> bsdauthstylename
%type   <string> gssapiservicename
%type   <string> gssapikeytab
%type   <string> gssapienctype
%type   <string> resolveprotocol resolveprotocolname
%type   <string> socket
%type   <string> srchost srchostoption srchostoptions
%type   <string> command commands commandname
%type   <string> routeinit
%type   <string> udpportrange udpportrange_start udpportrange_end
%type   <string> debuging
%type   <string> realm

   /* clientconfig exclusive. */
%type   <string> clientinit clientconfig
%type   <string> clientoption


   /* serverconfig exclusive */
%type   <string> timeout iotimeout negotiatetimeout connecttimeout
                 tcp_fin_timeout
%type   <string> extension extensionname extensions
%type   <string> internal internalinit external externalinit
%type   <string> external_rotation
%type   <string> errorlog logoutput logoutputdevice logoutputdevices
%type   <string> compatibility compatibilityname compatibilitynames
%type   <string> global_authmethod global_clientauthmethod
%type   <string> authmethod authmethods authmethodname
%type   <string> clientcompatibility clientcompatibilityname
                 clientcompatibilitynames
%type   <string> serveroption
%type   <string> serverinit serverconfig serverconfigs
%type   <string> rulesorroutes ruleorroute
%type   <string> userids user_privileged user_unprivileged user_libwrap
%type   <uid>    userid
%type   <string> childstate
%type   <string> redirect
%type   <string> bandwidth
%type   <string> session maxsessions
%type   <string> libwrapfiles libwrap_allowfile libwrap_denyfile
%type   <string> libwrap_hosts_access
%type   <string> udpconnectdst
%type   <string> lurl ldapssl ldapcertcheck ldapkeeprealm
%type   <string> lbasedn lbasedn_hex lbasedn_hex_all
%type   <string> lserver lgroup lgroup_hex lgroup_hex_all
%type   <string> ldapfilter ldapfilter_ad ldapfilter_hex ldapfilter_ad_hex
%type   <string> ldapdomain
%type   <string> ldapattribute ldapattribute_ad ldapattribute_hex ldapattribute_ad_hex
%type   <string> ldapcertfile ldapcertpath ldapkeytab
%type   <string> ldapauto ldapdebug ldapdepth ldapport ldapportssl


%token   <string> CLIENTRULE
%token   <string> INTERNAL EXTERNAL
%token   <string> REALM REALNAME
%token   <string> EXTERNAL_ROTATION SAMESAME
%token   <string> DEBUGGING RESOLVEPROTOCOL
%token   <string> SOCKET CLIENTSIDE_SOCKET SNDBUF RCVBUF
%token   <string> SRCHOST NODNSMISMATCH NODNSUNKNOWN CHECKREPLYAUTH
%token   <string> EXTENSION BIND PRIVILEGED
%token   <string> IOTIMEOUT IOTIMEOUT_TCP IOTIMEOUT_UDP NEGOTIATETIMEOUT
%token   <string> CONNECTTIMEOUT TCP_FIN_WAIT
%token   <string> METHOD CLIENTMETHOD NONE GSSAPI UNAME RFC931 PAM BSDAUTH
%token   <string> COMPATIBILITY SAMEPORT DRAFT_5_05
%token   <string> CLIENTCOMPATIBILITY NECGSSAPI
%token   <string> USERNAME
%token   <string> GROUPNAME
%token   <string> USER_PRIVILEGED USER_UNPRIVILEGED USER_LIBWRAP
%token   <string> LIBWRAP_FILE
%token   <string> ERRORLOG LOGOUTPUT LOGFILE
%token   <string> CHILD_MAXIDLE CHILD_MAXREQUESTS

   /* route */
%type   <string> global_routeoption
%type   <string> route via gateway routeoption routeoptions

%token   <string> ROUTE VIA BADROUTE_EXPIRE MAXFAIL

   /* rulelines */
%type   <string> rule ruleoption ruleoptions
%type   <string> clientrule clientruleoption clientruleoptions
%type   <string> option
%type   <string> verdict
%type   <string> fromto
%type   <string> log logs logname
%type   <string> libwrap
%type   <string> srcaddress dstaddress
%type   <string> externaladdress
%type   <string> address ipaddress gwaddress domain ifname direct url
%type   <string> from to
%type   <string> netmask
%type   <string> port gwport portrange portstart portoperator portnumber
                 portservice
%type   <string> bounce bounce_to

%token <string> VERDICT_BLOCK VERDICT_PASS
%token <string> PAMSERVICENAME
%token <string> BSDAUTHSTYLENAME
%token <string> BSDAUTHSTYLE
%token <string> GSSAPISERVICE
%token <string> GSSAPIKEYTAB
%token <string> GSSAPIENCTYPE
%token <string> GSSAPIENC_ANY GSSAPIENC_CLEAR GSSAPIENC_INTEGRITY                               GSSAPIENC_CONFIDENTIALITY GSSAPIENC_PERMESSAGE
%token <string> GSSAPISERVICENAME GSSAPIKEYTABNAME
%token <string> PROTOCOL PROTOCOL_TCP PROTOCOL_UDP PROTOCOL_FAKE
%token <string> PROXYPROTOCOL PROXYPROTOCOL_SOCKS_V4 PROXYPROTOCOL_SOCKS_V5
                PROXYPROTOCOL_HTTP PROXYPROTOCOL_UPNP
%token <string> USER GROUP
%token <string> COMMAND COMMAND_BIND COMMAND_CONNECT COMMAND_UDPASSOCIATE                         COMMAND_BINDREPLY COMMAND_UDPREPLY
%token <string> ACTION
%token <string> LINE
%token <string> LIBWRAPSTART LIBWRAP_ALLOW LIBWRAP_DENY LIBWRAP_HOSTS_ACCESS
%token <string> OPERATOR
%token <string> SOCKS_LOG SOCKS_LOG_CONNECT SOCKS_LOG_DATA
                SOCKS_LOG_DISCONNECT SOCKS_LOG_ERROR SOCKS_LOG_IOOPERATION
%token <string> IPADDRESS DOMAINNAME DIRECT IFNAME URL
%token <string> PORT SERVICENAME
%token <string> NUMBER
%token <string> FROM TO
%token <string> REDIRECT
%token <string> BANDWIDTH
%token <string> MAXSESSIONS
%token <string> UDPPORTRANGE UDPCONNECTDST
%token <string> YES NO
%token <string> BOUNCE
%token <string> LDAPURL LDAP_URL
%token <string> LDAPSSL LDAPCERTCHECK LDAPKEEPREALM
%token <string> LDAPBASEDN LDAP_BASEDN
%token <string> LDAPBASEDN_HEX LDAPBASEDN_HEX_ALL
%token <string> LDAPSERVER LDAPSERVER_NAME
%token <string> LDAPGROUP LDAPGROUP_NAME
%token <string> LDAPGROUP_HEX LDAPGROUP_HEX_ALL
%token <string> LDAPFILTER LDAPFILTER_AD LDAPFILTER_HEX LDAPFILTER_AD_HEX
%token <string> LDAPATTRIBUTE LDAPATTRIBUTE_AD LDAPATTRIBUTE_HEX LDAPATTRIBUTE_AD_HEX
%token <string> LDAPCERTFILE LDAPCERTPATH LDAPPORT LDAPPORTSSL
%token <string> LDAP_FILTER LDAP_ATTRIBUTE LDAP_CERTFILE LDAP_CERTPATH
%token <string> LDAPDOMAIN LDAP_DOMAIN
%token <string> LDAPTIMEOUT LDAPCACHE LDAPCACHEPOS LDAPCACHENEG
%token <string> LDAPKEYTAB LDAPKEYTABNAME LDAPDEADTIME
%token <string> LDAPDEBUG LDAPDEPTH LDAPAUTO LDAPSEARCHTIME


%%


   /*
    * first token we get should say whether we are parsing for client
    * or server.  Init as appropriate.
    */

configtype:   serverinit serverline
   |   clientinit clientline
   ;

serverinit:   SERVERCONFIG {
#if !SOCKS_CLIENT
      protocol  = &protocolmem;
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
   ;


serverline: serverconfigs rulesorroutes
   ;

rulesorroutes: { $$ = NULL; }
   | ruleorroute rulesorroutes
   ;

ruleorroute: clientrule
   | rule
   | route
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

serverconfigs:  serverconfig
   | serverconfigs serverconfig;

serverconfig: global_authmethod
   |   global_clientauthmethod
   |   deprecated
   |   internal
   |   external
   |   external_rotation
   |   errorlog
   |   logoutput
   |   serveroption
   |   userids
   |   childstate
   |   debuging
   |   libwrapfiles
   |   libwrap_hosts_access
   |   udpconnectdst
   ;

serveroption:  compatibility
   |   extension
   |   global_routeoption
   |   resolveprotocol
   |   realm
   |   socket
   |   srchost
   |   timeout {
#if !SOCKS_CLIENT
                  if (timeout->tcp_fin_wait == 0
                  ||  timeout->tcp_fin_wait >  timeout->tcpio)
                     timeout->tcp_fin_wait = timeout->tcpio;
#endif /* !SOCKS_CLIENT */
      }
   ;

timeout: connecttimeout
   |  iotimeout
   |  negotiatetimeout
   |  tcp_fin_timeout
   ;

deprecated:   DEPRECATED {
      yyerror("given keyword, \"%s\", is deprecated", $1);
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
#if HAVE_LDAP
      ldap              = &state.ldap;
#endif /* HAVE_LDAP*/

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
   |  PROXYPROTOCOL_HTTP {
         proxyprotocol->http        = 1;
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
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.user, $1) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
   ;

usernames:   username
   |   username usernames
   ;

group: GROUP ':' groupnames
   ;

groupname:   GROUPNAME {
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, $1) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
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

internal:   INTERNAL internalinit ':' address {
#if !SOCKS_CLIENT
#if BAREFOOTD
      yyerror("\"internal:\" specification is not used in %s", PACKAGE);
#endif /* BAREFOOTD */

      addinternal(ruleaddr, SOCKS_TCP);
#endif /* !SOCKS_CLIENT */
   }
   ;

internalinit: {
#if !SOCKS_CLIENT
   static struct ruleaddr_t mem;
   struct servent   *service;

   addrinit(&mem, 0);
   bzero(protocol, sizeof(*protocol));

   /* set default port. */
   if ((service = getservbyname("socks", "tcp")) == NULL)
      *port_tcp = htons(SOCKD_PORT);
   else
      *port_tcp = (in_port_t)service->s_port;
#endif /* !SOCKS_CLIENT */
   }
   ;

external:   EXTERNAL externalinit ':' externaladdress {
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
   ;

externalinit: {
#if !SOCKS_CLIENT
      static struct ruleaddr_t mem;

      addrinit(&mem, 0);
#endif /* !SOCKS_CLIENT */
   }
   ;

external_rotation:   EXTERNAL_ROTATION ':' NONE {
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
   |   EXTERNAL_ROTATION ':' SAMESAME {
      sockscf.external.rotation = ROTATION_SAMESAME;
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

clientoption: debuging
   |   global_routeoption
   |   logoutput
   |   resolveprotocol
   |   timeout;
   ;

global_routeoption: ROUTE '.' MAXFAIL ':' NUMBER {
      const int value = atoi($5);

      if (value < 0)
         yyerror("max route fails can not be negative (%d)  Use \"0\" to "
                 "indicate routes should never be marked as bad",
                 value);

      sockscf.routeoptions.maxfail = value;
   }
   | ROUTE '.' BADROUTE_EXPIRE  ':' NUMBER {
      const int value = atoi($5);

      if (value < 0)
         yyerror("route failure expiry time can not be negative (%d).  "
                 "Use \"0\" to indicate bad route marking should never expire",
                 value);

      sockscf.routeoptions.badexpire = value;
   }
   ;

errorlog: ERRORLOG ':' { add_to_errorlog = 1; } logoutputdevices
   ;

logoutput: LOGOUTPUT ':' { add_to_errorlog = 0; } logoutputdevices
   ;

logoutputdevice:   LOGFILE {
   int p;
#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   const struct userid_t currentuserid = sockscf.uid;;
   struct userid_t zuid;

   bzero(&zuid, sizeof(zuid));
   if (memcmp(&zuid, &sockscf.uid, sizeof(zuid)) == 0)
      /*
       * We dont enforce that userid must be set before logfiles, so make sure
       * that the old userids, if any, are set before (re)opening logfiles.
       */
      sockscf.uid = olduserid;
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

#if !SOCKS_CLIENT 
   sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
#endif /* !SOCKS_CLIENT */

   p = socks_addlogfile(add_to_errorlog ? &sockscf.errlog : &sockscf.log, $1);

#if !SOCKS_CLIENT 
   sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
#endif /* !SOCKS_CLIENT */

#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   if (p != 0 && sockscf.state.inited) {
      /* try again with original euid, before giving up. */
      sockscf.uid.privileged       = sockscf.state.euid;
      sockscf.uid.privileged_isset = 1;

      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
      p= socks_addlogfile(add_to_errorlog ? &sockscf.errlog : &sockscf.log, $1);
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
   }
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

   if (p != 0)
      /*
       * bad, but what else can we do?
       */
      yyerror("failed to add logfile %s", $1);


#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   sockscf.uid = currentuserid;
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */
}

logoutputdevices:   logoutputdevice
   |   logoutputdevice logoutputdevices
   ;

childstate: CHILD_MAXIDLE ':' YES {
#if !SOCKS_CLIENT
      sockscf.child.maxidle.negotiate = SOCKD_FREESLOTS_NEGOTIATE * 2;
      sockscf.child.maxidle.request   = SOCKD_FREESLOTS_REQUEST   * 2;
      sockscf.child.maxidle.io        = SOCKD_FREESLOTS_IO        * 2;
   }
   | CHILD_MAXIDLE ':' NO {
      bzero(&sockscf.child.maxidle, sizeof(sockscf.child.maxidle));
   }
   | CHILD_MAXREQUESTS ':' NUMBER {
      CHECKNUMBER($3, >=, 0);
      sockscf.child.maxrequests = (size_t)atol($3);
#endif /* !SOCKS_CLIENT */
   }
   ;

userids:   user_privileged
   |   user_unprivileged
   |   user_libwrap
   ;

user_privileged:   USER_PRIVILEGED ':' userid {
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged         = $3;
      sockscf.uid.privileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
   ;

user_unprivileged:   USER_UNPRIVILEGED ':' userid {
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged         = $3;
      sockscf.uid.unprivileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
   ;

user_libwrap:   USER_LIBWRAP ':' userid {
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.libwrap         = $3;
      sockscf.uid.libwrap_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#else  /* !HAVE_LIBWRAP && (!SOCKS_CLIENT) */
      yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP (!SOCKS_CLIENT)*/
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
#if !SOCKS_CLIENT
      CHECKNUMBER($3, >=, 0);
      timeout->tcpio = (size_t)atol($3);
      timeout->udpio = timeout->tcpio;
   }
   | IOTIMEOUT_TCP ':' NUMBER  {
      CHECKNUMBER($3, >=, 0);
      timeout->tcpio = (size_t)atol($3);
   }
   | IOTIMEOUT_UDP ':' NUMBER  {
      CHECKNUMBER($3, >=, 0);
      timeout->udpio = (size_t)atol($3);
#endif /* !SOCKS_CLIENT */
   }
   ;

negotiatetimeout:   NEGOTIATETIMEOUT ':' NUMBER {
#if !SOCKS_CLIENT
      CHECKNUMBER($3, >=, 0);
      timeout->negotiate = (size_t)atol($3);
#endif /* !SOCKS_CLIENT */
   }
   ;

connecttimeout:   CONNECTTIMEOUT ':' NUMBER {
      CHECKNUMBER($3, >=, 0);
      timeout->connect = (size_t)atol($3);
   }
   ;

tcp_fin_timeout:   TCP_FIN_WAIT ':' NUMBER {
#if !SOCKS_CLIENT
      CHECKNUMBER($3, >=, 0);
      timeout->tcp_fin_wait = (size_t)atol($3);
#endif /* !SOCKS_CLIENT */
   }
   ;


debuging: DEBUGGING ':' NUMBER {
#if !SOCKS_CLIENT
      if (sockscf.option.debugrunopt == -1)
#endif /* !SOCKS_CLIENT */
          sockscf.option.debug = atoi($3);
   }
   ;

libwrapfiles: libwrap_allowfile
   |  libwrap_denyfile
   ;

libwrap_allowfile: LIBWRAP_ALLOW ':' LIBWRAP_FILE {
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_allow_table = strdup($3)) == NULL)
         yyerror(NOMEM);
      slog(LOG_DEBUG, "libwrap.allow: %s", hosts_allow_table);
#else
      yyerror("libwrap.allow requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
   ;

libwrap_denyfile: LIBWRAP_DENY ':' LIBWRAP_FILE {
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_deny_table = strdup($3)) == NULL)
         yyerror(NOMEM);
      slog(LOG_DEBUG, "libwrap.deny: %s", hosts_deny_table);
#else
      yyerror("libwrap.deny requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
   ;

libwrap_hosts_access: LIBWRAP_HOSTS_ACCESS ':' YES {
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerror("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
   | LIBWRAP_HOSTS_ACCESS ':' NO {
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerror("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
   ;

udpconnectdst: UDPCONNECTDST ':' YES {
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
   | UDPCONNECTDST ':' NO {
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
   ;


compatibility:   COMPATIBILITY ':' compatibilitynames
   ;

compatibilityname: SAMEPORT {
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
   |  DRAFT_5_05 {
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
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

socket: SOCKET '.' SNDBUF '.' PROTOCOL_UDP ':' NUMBER {
#if !SOCKS_CLIENT
      CHECKNUMBER($7, >=, 0);
      sockscf.socket.udp.sndbuf = (size_t)atol($7);
   }
   | SOCKET '.' RCVBUF '.' PROTOCOL_UDP ':' NUMBER {
      CHECKNUMBER($7, >=, 0);
      sockscf.socket.udp.rcvbuf = (size_t)atol($7);
   }
   | SOCKET '.' SNDBUF '.' PROTOCOL_TCP ':' NUMBER {
      CHECKNUMBER($7, >=, 0);
      sockscf.socket.tcp.sndbuf = (size_t)atol($7);
   }
   | SOCKET '.' RCVBUF '.' PROTOCOL_TCP ':' NUMBER {
      CHECKNUMBER($7, >=, 0);
      sockscf.socket.tcp.rcvbuf = (size_t)atol($7);
#if BAREFOOTD
   }
   | CLIENTSIDE_SOCKET '.' SNDBUF '.' PROTOCOL_UDP ':' NUMBER {
      CHECKNUMBER($7, >=, 0);
      sockscf.socket.clientside_udp.sndbuf = (size_t)atol($7);
   }
   | CLIENTSIDE_SOCKET '.' RCVBUF '.' PROTOCOL_UDP ':' NUMBER {
      CHECKNUMBER($7, >=, 0);
      sockscf.socket.clientside_udp.rcvbuf = (size_t)atol($7);
#endif /* BAREFOOTD */

#endif /* !SOCKS_CLIENT */
   }
   ;


srchost: SRCHOST ':' srchostoptions
   ;

srchostoption:   NODNSMISMATCH {
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
   |  NODNSUNKNOWN {
         sockscf.srchost.nodnsunknown = 1;
   }
   |  CHECKREPLYAUTH {
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
   ;

srchostoptions:   srchostoption
   |   srchostoption srchostoptions
   ;

realm: REALM ':' REALNAME {
#if COVENANT
   if (strlen($3) >= sizeof(sockscf.realmname))
      yyerror("realmname \"%s\" is too long.  Recompilation of %s required "
              "is required if you want to use a name longer than %d characters",
               $3, PACKAGE,
               sizeof(sockscf.realmname) - 1);

   strcpy(sockscf.realmname, $3);
#else /* !COVENANT */
   yyerror("unknown keyword \"%s\"", $1);
#endif /* !COVENANT */
}
   ;

authmethod: METHOD ':' authmethods
   ;

authmethods:   authmethodname
   |   authmethodname authmethods
   ;

global_authmethod:   METHOD ':' {
#if SOCKS_SERVER
      methodv  = sockscf.methodv;
      methodc  = &sockscf.methodc;
      *methodc = 0; /* reset. */
#else
      yyerror("\"clientmethod\" is used for the global method line in %s, "
              "not \"%s\"",
              PACKAGE, $1);
#endif /* !SOCKS_SERVER */
   } authmethods
   ;

global_clientauthmethod:   CLIENTMETHOD ':' {
#if !SOCKS_CLIENT
   methodv  = sockscf.clientmethodv;
   methodc  = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif /* !SOCKS_CLIENT */
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
      ADDMETHOD(AUTHMETHOD_RFC931);
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
   |   BSDAUTH {
#if HAVE_BSDAUTH
      ADDMETHOD(AUTHMETHOD_BSDAUTH);
#else /* !HAVE_PAM */
      yyerror("method %s requires bsd authentication", AUTHMETHOD_BSDAUTHs);
#endif /* HAVE_PAM */
   }
   ;


   /* filter rules */

clientrule: CLIENTRULE verdict
   '{' clientruleoptions fromto clientruleoptions '}' {

#if !SOCKS_CLIENT
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

#if BAREFOOTD
      if (bounce_to.atype == SOCKS_ADDR_NOTSET) {
         if (rule.verdict == VERDICT_PASS)
            yyerror("no address traffic should bounce to has been given");
         else {
            /*
             * allow no bounce-to if it is a block, as the bounce-to address
             * will not be used in any case then.
             */
            bounce_to.atype                 = SOCKS_ADDR_IPV4;
            bounce_to.addr.ipv4.ip.s_addr   = htonl(INADDR_ANY);
            bounce_to.addr.ipv4.mask.s_addr = htonl(0xffffffff);
            bounce_to.port.tcp              = bounce_to.port.udp = htons(0);
            bounce_to.operator              = none;
         }
      }

      rule.bounce_to = bounce_to;
#endif /* BAREFOOTD */

      addclientrule(&rule);

      rulereset();
#endif /* !SOCKS_CLIENT */
   }
   ;

clientruleoption:   option
   |   bandwidth {
#if !SOCKS_CLIENT
         checkmodule("bandwidth");
#endif /* !SOCKS_CLIENT */
   }
   |   protocol {
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
   |   redirect   {
#if !SOCKS_CLIENT
         checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
   ;

clientruleoptions:   { $$ = NULL; }
   |   clientruleoption clientruleoptions
   ;

rule:   verdict '{' ruleoptions fromto ruleoptions '}' {
#if !SOCKS_CLIENT
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

#if !SOCKS_SERVER
   yyerror("socks-rules are not used in %s", PACKAGE);
#endif /* !SOCKS_SERVER */

      addsocksrule(&rule);
      rulereset();
#endif /* !SOCKS_CLIENT */
   }
   ;


ruleoption:   option
   |   bandwidth {
#if !SOCKS_CLIENT
         checkmodule("bandwidth");
#endif /* !SOCKS_CLIENT */
   }
   |   command
   |   udpportrange
   |   protocol
   |   proxyprotocol
   |   redirect   {
#if !SOCKS_CLIENT
         checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
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
   |   bsdauthstylename
   |   gssapiservicename
   |   gssapikeytab
   |   gssapienctype
   |   lurl
   |   ldapauto
   |   ldapdomain
   |   ldapdebug
   |   ldapdepth
   |   lbasedn
   |   lbasedn_hex
   |   lbasedn_hex_all
   |   ldapport
   |   ldapportssl
   |   ldapssl
   |   ldapcertcheck
   |   ldapkeeprealm
   |   ldapfilter
   |   ldapattribute
   |   ldapfilter_ad
   |   ldapattribute_ad
   |   ldapfilter_hex
   |   ldapattribute_hex
   |   ldapfilter_ad_hex
   |   ldapattribute_ad_hex
   |   ldapcertfile
   |   ldapcertpath
   |   lgroup
   |   lgroup_hex
   |   lgroup_hex_all
   |   lserver
   |   ldapkeytab
   |   user
   |   group
   |   timeout
   |   bounce  {
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
   |   session   {
#if !SOCKS_CLIENT
         checkmodule("session");
#endif /* !SOCKS_CLIENT */
   }
   ;

ldapdebug: LDAPDEBUG ':' NUMBER {
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->debug = atoi($3);
   }
   | LDAPDEBUG ':' '-'NUMBER {
      ldap->debug = -atoi($4);
 #else /* !HAVE_LDAP */
      yyerror("ldap debug support requires openldap support");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapdomain: LDAPDOMAIN ':' LDAP_DOMAIN {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.domain))
         yyerror("filter too long");
      strcpy(ldap->domain, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapdepth: LDAPDEPTH ':' NUMBER {
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->mdepth = atoi($3);
#else /* !HAVE_LDAP */
      yyerror("ldap debug support requires openldap support");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapcertfile: LDAPCERTFILE ':' LDAP_CERTFILE {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.certfile))
         yyerror("ca cert file name too long");
      strcpy(ldap->certfile, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapcertpath: LDAPCERTPATH ':' LDAP_CERTPATH {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.certpath))
         yyerror("cert db path too long");
      strcpy(ldap->certpath, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lurl: LDAPURL ':' LDAP_URL {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapurl, $3) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lbasedn: LDAPBASEDN ':' LDAP_BASEDN {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapbasedn, $3) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lbasedn_hex: LDAPBASEDN_HEX ':' LDAP_BASEDN {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapbasedn, hextoutf8($3, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lbasedn_hex_all: LDAPBASEDN_HEX_ALL ':' LDAP_BASEDN {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapbasedn, hextoutf8($3, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapport: LDAPPORT ':' NUMBER {
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->port = atoi($3);
#else /* !HAVE_LDAP */
   yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapportssl: LDAPPORTSSL ':' NUMBER {
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->portssl = atoi($3);
#else /* !HAVE_LDAP */
   yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapssl: LDAPSSL ':' YES {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->ssl = 1;
   }
   | LDAPSSL ':' NO {
      ldap->ssl = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapauto: LDAPAUTO ':' YES {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->auto_off = 1;
   }
   | LDAPAUTO ':' NO {
      ldap->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapcertcheck: LDAPCERTCHECK ':'  YES {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->certcheck = 1;
   }
   | LDAPCERTCHECK ':' NO {
      ldap->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapkeeprealm: LDAPKEEPREALM ':'  YES {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->keeprealm = 1;
   }
   | LDAPKEEPREALM ':' NO {
      ldap->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapfilter: LDAPFILTER ':' LDAP_FILTER {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.filter))
         yyerror("filter too long");
      strcpy(ldap->filter, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapfilter_ad: LDAPFILTER_AD ':' LDAP_FILTER {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.filter_AD))
         yyerror("AD filter too long");
      strcpy(ldap->filter_AD, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapfilter_hex: LDAPFILTER_HEX ':' LDAP_FILTER {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3)/2 >= sizeof(state.ldap.filter))
         yyerror("filter too long");
      strcpy(ldap->filter, hextoutf8($3, 2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapfilter_ad_hex: LDAPFILTER_AD_HEX ':' LDAP_FILTER {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3)/2 >= sizeof(state.ldap.filter_AD))
         yyerror("AD filter too long");
      strcpy(ldap->filter_AD, hextoutf8($3,2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapattribute: LDAPATTRIBUTE ':' LDAP_ATTRIBUTE {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.attribute))
         yyerror("attribute too long");
      strcpy(ldap->attribute, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapattribute_ad: LDAPATTRIBUTE_AD ':' LDAP_ATTRIBUTE {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) >= sizeof(state.ldap.attribute_AD))
         yyerror("AD attribute too long");
      strcpy(ldap->attribute_AD, $3);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapattribute_hex: LDAPATTRIBUTE_HEX ':' LDAP_ATTRIBUTE {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) / 2 >= sizeof(state.ldap.attribute))
         yyerror("attribute too long");
      strcpy(ldap->attribute, hextoutf8($3, 2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapattribute_ad_hex: LDAPATTRIBUTE_AD_HEX ':' LDAP_ATTRIBUTE {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen($3) / 2 >= sizeof(state.ldap.attribute_AD))
         yyerror("AD attribute too long");
      strcpy(ldap->attribute_AD, hextoutf8($3, 2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lgroup_hex: LDAPGROUP_HEX ':' LDAPGROUP_NAME {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8($3, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lgroup_hex_all: LDAPGROUP_HEX_ALL ':' LDAPGROUP_NAME {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8($3, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lgroup: LDAPGROUP ':' LDAPGROUP_NAME {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, asciitoutf8($3)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

lserver: LDAPSERVER ':' LDAPSERVER_NAME {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapserver, $3) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
   ;

ldapkeytab: LDAPKEYTAB ':' LDAPKEYTABNAME {
#if HAVE_LDAP
#if SOCKS_SERVER
      if (strlen($3) >= sizeof(state.ldap.keytab))
         yyerror("keytab name too long");
      strcpy(ldap->keytab, $3);
#else
      yyerror("ldap keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* HAVE_LDAP */
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
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
   |   VERDICT_PASS {
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
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
#if !SOCKS_CLIENT
   static shmem_object_t ssinit;

   CHECKNUMBER($3, >=, 0);

   if (pidismother(sockscf.state.pid) == 1) {
      if ((rule.ss = malloc(sizeof(*rule.ss))) == NULL)
         yyerror("failed to malloc %lu bytes for ss memory",
         (unsigned long)sizeof(*rule.ss));

      *rule.ss                       = ssinit;
      rule.ss->object.ss.maxsessions = (size_t)atol($3);
   }
   else
      rule.ss = &ssinit;

   rule.ss_fd = -1;
#endif /* !SOCKS_CLIENT */
}
;

bandwidth:   BANDWIDTH ':' NUMBER {
#if !SOCKS_CLIENT
   static shmem_object_t bwmeminit;

   CHECKNUMBER($3, >=, 0);

   if (pidismother(sockscf.state.pid) == 1) {
      if ((rule.bw = malloc(sizeof(*rule.bw))) == NULL)
         yyerror("failed to malloc %lu bytes for bw memory",
         (unsigned long)sizeof(*rule.bw));

      *rule.bw                  = bwmeminit;
      rule.bw->object.bw.maxbps = (size_t)atol($3);
   }
   else
      rule.bw = &bwmeminit;

   rule.bw_fd = -1;
#endif /* !SOCKS_CLIENT */
}
;


log:   SOCKS_LOG ':' logs
   ;

logname:  SOCKS_LOG_CONNECT {
#if !SOCKS_CLIENT
   rule.log.connect = 1;
   }
   |   SOCKS_LOG_DATA {
         rule.log.data = 1;
   }
   |   SOCKS_LOG_DISCONNECT {
         rule.log.disconnect = 1;
   }
   |   SOCKS_LOG_ERROR {
         rule.log.error = 1;
   }
   |   SOCKS_LOG_IOOPERATION {
         rule.log.iooperation = 1;
#endif /* !SOCKS_CLIENT */
   }
   ;

logs:   logname
   |  logname logs
   ;


pamservicename: PAMSERVICENAME ':' SERVICENAME {
#if HAVE_PAM && (!SOCKS_CLIENT)
      if (strlen($3) >= sizeof(rule.state.pamservicename))
         yyerror("servicename too long");
      strcpy(rule.state.pamservicename, $3);
#else
      yyerror("pam support not compiled in");
#endif /* HAVE_PAM && (!SOCKS_CLIENT) */
   }
   ;

bsdauthstylename: BSDAUTHSTYLE ':' BSDAUTHSTYLENAME {
#if HAVE_BSDAUTH && SOCKS_SERVER
      if (strlen($3) >= sizeof(rule.state.bsdauthstylename))
         yyerror("bsdauthstyle too long");
      strcpy(rule.state.bsdauthstylename, $3);
#else
      yyerror("bsdauth support not compiled in");
#endif /* HAVE_BSDAUTH && SOCKS_SERVER */
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
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
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
      yyerror("libwrap support not compiled in");
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */
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
      addrinit(&src, 1);
   }
   ;

to:   TO {
      addrinit(&dst,
#if SOCKS_SERVER
               1
#else /* BAREFOOT || COVENANT */
               0 /* the address the server should bind, so must be /32. */
#endif /*  BAREFOOT || COVENANT */
      );
   }
   ;

rdr_from:   FROM {
      addrinit(&rdr_from, 1);
   }
   ;

rdr_to:   TO {
      addrinit(&rdr_to, 1);
   }
   ;

bounce_to:   TO {
#if BAREFOOTD
      addrinit(&bounce_to, 0);
#endif /* BAREFOOTD */
   }
   ;


via:   VIA {
      gwaddrinit(&gw);
   }
   ;

externaladdress: ipaddress
   |   domain
   |   ifname
   ;


address: ipaddress '/' netmask port
   |   ipaddress {
         if (netmask_required)
            yyerror("no netmask given");
         else
            netmask->s_addr = htonl(0xffffffff);
       } port
   |   domain port
   |   ifname port
   ;

gwaddress:   ipaddress gwport
   |   domain gwport
   |   ifname gwport
   |   url
   |   direct
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
         yyerror("interface name too long");

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

portrange:   portstart '-' portend {
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerror("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
   ;


portstart:   NUMBER {
      CHECKPORTNUMBER($1);
      *port_tcp   = htons((in_port_t)atoi($1));
      *port_udp   = htons((in_port_t)atoi($1));
   }
   ;

portend:   NUMBER {
      CHECKPORTNUMBER($1);
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

udpportrange_start: NUMBER {
#if SOCKS_SERVER
   CHECKPORTNUMBER($1);
   rule.udprange.start = htons((in_port_t)atoi($1));
#endif /* SOCKS_SERVER */
   }
   ;

udpportrange_end: NUMBER {
#if SOCKS_SERVER
   CHECKPORTNUMBER($1);
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
   int haveconfig;

#if SOCKS_CLIENT /* assume server admin can set things up correctly himself. */
   parseclientenv(&haveconfig);
   if (haveconfig)
      return 0;
#endif


#if !SOCKS_CLIENT
   if (sockscf.state.inited) {
      /* in case needed to reopen config-file. */
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);

      if (yyin != NULL)
         fclose(yyin);
   }
#endif /* SERVER */

   yyin = fopen(filename, "r");

#if !SOCKS_CLIENT
   if (sockscf.state.inited)
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
#endif /* SERVER */

#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   if (yyin == NULL && sockscf.state.inited) {
      const struct userid_t currentuserid = sockscf.uid;;

      sockscf.uid.privileged       = sockscf.state.euid;
      sockscf.uid.privileged_isset = 1;

      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
      yyin = fopen(filename, "r");
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);

      sockscf.uid = currentuserid;
   }
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   /*
    * uid, read from configfile.  But save old one first, in case we
    * need them to reopen logfiles.
    */

   olduserid = sockscf.uid;
   bzero(&sockscf.uid, sizeof(sockscf.uid));
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

   if (yyin == NULL
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         swarn("%s: could not open %s", function, filename);

      haveconfig            = 0;
      sockscf.option.debug  = 1;
   }
   else {
      slog(LOG_DEBUG, "%s: not parsing configfile %s (%s)",
                      function, filename,
                      yyin == NULL ? strerror(errno) : "zero-sized file");
      socks_parseinit = 0;
#if YYDEBUG
      yydebug         = 0;
#endif /* YYDEBUG */

      yylineno      = 1;
      errno         = 0;   /* don't report old errors in yyparse(). */
      haveconfig    = 1;

      parsingconfig = 1;
      yyparse();
      parsingconfig = 0;

#if SOCKS_CLIENT
      fclose(yyin);
#else
      /*
       * Leave it open so that if we get a sighup later, we are
       * always guaranteed to have a descriptor we can close/reopen
       * to parse the configfile.
       */
      sockscf.configfd = fileno(yyin);
#endif
   }

   errno = 0;
   return haveconfig ? 0 : -1;
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
      bufused = snprintfn(buf, sizeof(buf), "error: ");

   vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (errno)
      serr(EXIT_FAILURE, "%s", buf);
   serrx(EXIT_FAILURE, "%s", buf);
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
                         "%s: on line %d, near \"%.10s\": ",
                         sockscf.option.configfile, yylineno,
                         (yytext == NULL || *yytext == NUL) ?
                         "'start of line'" : yytext);
   else
      bufused = snprintfn(buf, sizeof(buf), "error: ");

   vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (errno)
      swarn("%s", buf);
   swarnx("%s", buf);
}

static void
addrinit(addr, _netmask_required)
   struct ruleaddr_t *addr;
   const int _netmask_required;
{

   atype            = &addr->atype;
   ipaddr           = &addr->addr.ipv4.ip;
   netmask          = &addr->addr.ipv4.mask;
   domain           = addr->addr.domain;
   ifname           = addr->addr.ifname;
   port_tcp         = &addr->port.tcp;
   port_udp         = &addr->port.udp;
   operator         = &addr->operator;

   netmask_required = _netmask_required;
   ruleaddr         = addr;
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
   operator = &operatormem; /* no operator in gwaddr and not used. */
}

#if SOCKS_CLIENT
static void
parseclientenv(haveproxyserver)
   int *haveproxyserver;
{
   const char *function = "parseclientenv()";
   char *proxyserver, *logfile, *debug, proxyservervis[256];

   if ((logfile = socks_getenv("SOCKS_LOGOUTPUT", dontcare)) != NULL)
      socks_addlogfile(&sockscf.log, logfile);

   if ((debug = socks_getenv("SOCKS_DEBUG", dontcare)) != NULL)
      sockscf.option.debug = atoi(debug);


   /*
    * Check if there is a proxyserver configured in the environment.
    * Initially assume there is none.
    */
   *haveproxyserver = 0;

   if ((proxyserver = socks_getenv(ENV_SOCKS4_SERVER, dontcare)) != NULL) {
      struct proxyprotocol_t proxyprotocol = { .socks_v4 = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv(ENV_SOCKS5_SERVER, dontcare)) != NULL) {
      struct proxyprotocol_t proxyprotocol = { .socks_v5 = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv(ENV_SOCKS_SERVER, dontcare)) != NULL) {
      struct proxyprotocol_t proxyprotocol = { .socks_v4 = 1, .socks_v5 = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv(ENV_HTTP_PROXY, dontcare)) != NULL) {
      struct proxyprotocol_t proxyprotocol = { .http = 1 };
      
      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv("UPNP_IGD", dontcare)) != NULL) {
      /*
       * Should be either an interface name (the interface to broadcast
       * for a response from the igd-device), "broadcast", to indicate
       * all interfaces, or a full url to the igd.
       */
      struct route_t route;

      bzero(&route, sizeof(route));
      route.gw.state.proxyprotocol.upnp = 1;

      str2vis(proxyserver,
              strlen(proxyserver),
              proxyservervis,
              sizeof(proxyservervis));

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
                                proxyservervis,
                                (unsigned long)sizeof(
                                               route.gw.addr.addr.urlname) - 1);

         socks_addroute(&route, 1);
      }
      else if (strcasecmp(proxyserver, "broadcast") == 0) {
         /*
          * Don't know what interface the igd is on, so add routes
          * for it on all interfaces.  Hopefully at least one interface
          * will get a response.
          */
         struct ifaddrs *ifap, *iface;

         route.gw.addr.atype = SOCKS_ADDR_IFNAME;

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

            if (strlen(iface->ifa_name) > sizeof(route.gw.addr.addr.ifname) - 1)
            {
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
            function, proxyservervis);

         route.gw.addr.atype = SOCKS_ADDR_IFNAME;

         if (strlen(proxyserver) > sizeof(route.gw.addr.addr.ifname) - 1)
            serr(1, "%s: ifname %s is too long, max is %lu",
                    function,
                    proxyservervis,
                    (unsigned long)(sizeof(route.gw.addr.addr.ifname) - 1));

         strcpy(route.gw.addr.addr.ifname, proxyserver);

         socks_addroute(&route, 1);
      }

      *haveproxyserver = 1;
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
}

static void
addproxyserver(proxyserver, proxyprotocol)
   const char *proxyserver;
   const struct proxyprotocol_t *proxyprotocol;
{
   const char *function = "addproxyserver()";
   struct sockaddr_in saddr;
   struct route_t route;
   struct ruleaddr_t raddr;
   char ipstring[INET_ADDRSTRLEN], *portstring, proxyservervis[256];

   bzero(&route, sizeof(route));
   route.gw.state.proxyprotocol = *proxyprotocol;

   str2vis(proxyserver,
           strlen(proxyserver),
           proxyservervis,
           sizeof(proxyservervis));

   slog(LOG_DEBUG,
        "%s: have a %s proxyserver set in environment, value %s",
        function,
        proxyprotocols2string(&route.gw.state.proxyprotocol, NULL, 0),
        proxyservervis);

   if (route.gw.state.proxyprotocol.http) {
      char emsg[256];

      if (urlstring2sockaddr(proxyserver,
                             (struct sockaddr *)&saddr,
                             emsg,
                             sizeof(emsg))
      == NULL) 
         serrx(EXIT_FAILURE,
               "%s: can't understand format of proxyserver %s: %s",
               function, proxyservervis, emsg);
               
   }
   else {
      if ((portstring = strchr(proxyserver, ':')) == NULL)
         serrx(EXIT_FAILURE, "%s: illegal format for port specification "
                             "in proxyserver %s: missing ':' delimiter",
                             function, proxyservervis);

      if (atoi(portstring + 1) < 1 || atoi(portstring + 1) > 0xffff)
         serrx(EXIT_FAILURE, "%s: illegal value (%d) for port specification "
                             "in proxyserver %s: must be between %d and %d",
                             function, atoi(portstring + 1),
                             proxyservervis, 1, 0xffff);

      if (portstring - proxyserver == 0
      || (size_t)(portstring - proxyserver) > sizeof(ipstring) - 1)
         serrx(EXIT_FAILURE,
               "%s: illegal format for ip address specification "
               "in proxyserver %s: too short/long",
               function, proxyservervis);

      strncpy(ipstring, proxyserver, (size_t)(portstring - proxyserver));
      ipstring[portstring - proxyserver] = NUL;
      ++portstring;

      bzero(&saddr, sizeof(saddr));
      saddr.sin_family = AF_INET;
      if (inet_pton(saddr.sin_family, ipstring, &saddr.sin_addr) != 1)
         serr(EXIT_FAILURE, "%s: illegal format for ip address "
                            "specification in proxyserver %s",
                            function, proxyservervis);
      saddr.sin_port = htons(atoi(portstring));
   }

   route.src.atype                           = SOCKS_ADDR_IPV4;
   route.src.addr.ipv4.ip.s_addr             = htonl(0);
   route.src.addr.ipv4.mask.s_addr           = htonl(0);
   route.src.port.tcp                        = route.src.port.udp = htons(0);
   route.src.operator                        = none;

   route.dst = route.src;

   ruleaddr2gwaddr(sockaddr2ruleaddr((struct sockaddr *)&saddr, &raddr),
   &route.gw.addr);

   socks_addroute(&route, 1);
}

#else /* !SOCKS_CLIENT */

static void
rulereset(void)
{

   timeout = &sockscf.timeout; /* default is global timeout, unless in a rule */
}

static void
ruleinit(rule)
   struct rule_t *rule;
{

   bzero(rule, sizeof(*rule));

   rule->linenumber        = yylineno;

   command                 = &rule->state.command;
   methodv                 = rule->state.methodv;
   methodc                 = &rule->state.methodc;
   protocol                = &rule->state.protocol;
   proxyprotocol           = &rule->state.proxyprotocol;
   timeout                 = &rule->timeout;
   *timeout                = sockscf.timeout; /* default values: as global. */

#if HAVE_GSSAPI
   gssapiservicename = rule->state.gssapiservicename;
   gssapikeytab      = rule->state.gssapikeytab;
   gssapiencryption  = &rule->state.gssapiencryption;
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
   ldap              = &rule->state.ldap;
#endif

   bzero(&src, sizeof(src));
   src.atype = SOCKS_ADDR_NOTSET;

   dst = rdr_from = rdr_to = src;

}

#endif /* !SOCKS_CLIENT */
