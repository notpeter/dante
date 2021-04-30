#include "common.h"
/* A Bison parser, made by GNU Bison 3.3.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2019 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.3.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         socks_yyparse
#define yylex           socks_yylex
#define yyerror         socks_yyerror
#define yydebug         socks_yydebug
#define yynerrs         socks_yynerrs

#define yylval          socks_yylval
#define yychar          socks_yychar

/* First part of user prologue.  */
#line 46 "config_parse.y" /* yacc.c:337  */


#include "yacconfig.h"

#if !SOCKS_CLIENT

#include "monitor.h"

#endif /* !SOCKS_CLIENT */

static const char rcsid[] =
"$Id: config_parse.y,v 1.703.4.8.2.8.4.14 2021/02/02 19:34:11 karls Exp $";

#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
   extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

extern void yyrestart(FILE *fp);

typedef enum { from, to, bounce } addresscontext_t;

static int
ipaddr_requires_netmask(const addresscontext_t context,
                        const objecttype_t objecttype);
/*
 * Returns true if an ipaddress used in the context of "objecttype" requires
 * a netmask, or false otherwise.
 *
 * "isfrom" is true if the address is to be used in the source/from
 * context, and false otherwise.
 */

static void
addnumber(size_t *numberc, long long *numberv[], const long long number);

static void
addrinit(ruleaddr_t *addr, const int netmask_required);

static void
gwaddrinit(sockshost_t *addr);

static void
routeinit(route_t *route);

#if SOCKS_CLIENT
static void parseclientenv(int *haveproxyserver);
/*
 * parses client environment, if any.
 * If a proxy server is configured in environment, "haveproxyserver" is set
 * to true upon return.  If not, it is set to false.
 */

static char *serverstring2gwstring(const char *server, const int version,
                                   char *gw, const size_t gwsize);
/*
 * Converts a gateway specified in environment to the format expected
 * in a socks.conf file.
 * "server" is the address specified in the environment,
 * "version" the kind of server address,
 * "gw", of size "gwsize", is the string to store the converted address in.
 *
 * Returns "gw" on success, exits on error.
 */

#define alarminit()
#define SET_TCPOPTION(logobject, level, attr)

#else /* !SOCKS_CLIENT */

/*
 * Reset pointers to point away from object-specific memory to global
 * memory.  Should be called after adding the object.
 */
static void post_addrule(void);

/*
 * Sets up various things after a object has been parsed, but before it has
 * been added.  Should be called before adding the object.
 *
 */
static void pre_addrule(struct rule_t *rule);
static void pre_addmonitor(monitor_t *monitor);

/*
 * Prepare pointers to point to the correct memory for adding a
 * new objects.  Should always be called once we know what type of
 * object we are dealing with.
 */
static void ruleinit(rule_t *rule);
static void monitorinit(monitor_t *monitor);
static void alarminit(void);

static int configure_privileges(void);
/*
 * Sets up privileges/userids.
 */

static int
checkugid(uid_t *uid, gid_t *gid, unsigned char *isset, const char *type);

#define SET_TCPOPTION(tcp, level, attr)                                        \
do {                                                                           \
   (tcp)->isconfigured              = 1;                                       \
                                                                               \
   (tcp)->attr                      = 1;                                       \
   (tcp)->__CONCAT(attr, _loglevel) = cloglevel;                               \
} while (/* CONSTCOND */ 0)

/*
 * Let commandline-options override configfile-options.
 * Currently there's only one such option.
 */
#define LOG_CMDLINE_OVERRIDE(name, newvalue, oldvalue, fmt)                    \
do {                                                                           \
   slog(LOG_NOTICE,                                                            \
        "%s: %s commandline value \"" fmt "\" overrides "                      \
        "config-file value \"" fmt "\" set in file %s",                        \
        function, name, (newvalue), (oldvalue), sockscf.option.configfile);    \
} while (/* CONSTCOND */ 0 )

#define CMDLINE_OVERRIDE(cmdline, option)                                      \
do {                                                                           \
   if ((cmdline)->debug_isset) {                                               \
      if ((option)->debug != (cmdline)->debug)                                 \
         LOG_CMDLINE_OVERRIDE("debug",                                         \
                              (cmdline)->debug,                                \
                              (option)->debug,                                 \
                              "%d");                                           \
                                                                               \
      (option)->debug      = (cmdline)->debug;                                 \
      (option)->debug_isset= (cmdline)->debug_isset;                           \
   }                                                                           \
} while (/* CONSTCOND */ 0)

#endif /* !SOCKS_CLIENT */

extern int  yylineno;
extern char *yytext;
extern char currentlexline[];
extern char previouslexline[];

static const char *function = "configparsing()";

/*
 * Globals because used by functions for reporting parsing errors in
 * parse_util.c
 */
unsigned char   *atype;         /* atype of new address.               */
unsigned char  parsingconfig;   /* currently parsing config?          */

/*
 * for case we are unable to (re-)open logfiles operator specifies.
 */

#if !SOCKS_CLIENT
static logtype_t       old_log,           old_errlog;
#endif /* !SOCKS_CLIENT */

static int             failed_to_add_log, failed_to_add_errlog;

static unsigned char   add_to_errlog;   /* adding file to errlog or regular?  */

static objecttype_t    objecttype;      /* current object_type we are parsing.*/


#if !SOCKS_CLIENT
static  logspecial_t                *logspecial;
static warn_protocol_tcp_options_t  *tcpoptions;

static interfaceprotocol_t *ifproto;  /* new interfaceprotocol settings.      */

static monitor_t       monitor;       /* new monitor.                         */
static monitor_if_t    *monitorif;    /* new monitor interface.               */
static int             *alarmside;    /* data-side to monitor (read/write).   */

static int             cloglevel;     /* current loglevel.                    */

static rule_t          rule;          /* new rule.                            */

static shmem_object_t  ss;
static int session_isset;
static shmem_object_t  bw;
static int bw_isset;


#endif /* !SOCKS_CLIENT */

static unsigned char   *hostidoption_isset;

static long long       *numberv;
static size_t          numberc;

#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
static unsigned char   *hostindex;
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID  */

static timeout_t       *timeout = &sockscf.timeout;           /* default.     */

static socketoption_t  socketopt;

static serverstate_t   *state;
static route_t         route;         /* new route.                           */
static sockshost_t     gw;            /* new gateway.                         */

static ruleaddr_t      src;            /* new src.                            */
static ruleaddr_t      dst;            /* new dst.                            */
static ruleaddr_t      hostid;         /* new hostid.                         */
static ruleaddr_t      rdr_from;       /* new redirect from.                  */
static ruleaddr_t      rdr_to;         /* new redirect to.                    */

#if BAREFOOTD
static ruleaddr_t      bounceto;       /* new bounce-to address.              */
#endif /* BAREFOOTD */

static ruleaddr_t      *ruleaddr;      /* current ruleaddr                    */
static extension_t     *extension;     /* new extensions                      */


static struct in_addr  *ipv4;          /* new ip address                      */
static struct in_addr  *netmask_v4;    /* new netmask                         */

static struct in6_addr *ipv6;          /* new ip address                      */
static unsigned int    *netmask_v6;    /* new netmask                         */
static uint32_t        *scopeid_v6;    /* new scopeid.                        */

static struct in_addr  *ipvany;        /* new ip address                      */
static struct in_addr  *netmask_vany;  /* new netmask                         */

static int             netmask_required;/*
                                         * netmask required for this
                                         * address?
                                         */
static char            *domain;        /* new domain.                         */
static char            *ifname;        /* new ifname.                         */
static char            *url;           /* new url.                            */

static in_port_t       *port_tcp;      /* new TCP port number.                */
static in_port_t       *port_udp;      /* new UDP port number.                */

static int             *cmethodv;      /* new client authmethods.             */
static size_t          *cmethodc;      /* number of them.                     */
static int             *smethodv;      /* new socks authmethods.              */
static size_t          *smethodc;      /* number of them.                     */

static enum operator_t *operator;      /* new port operator.                  */

#if HAVE_GSSAPI
static char            *gssapiservicename; /* new gssapiservice.              */
static char            *gssapikeytab;      /* new gssapikeytab.               */
static gssapi_enc_t    *gssapiencryption;  /* new encryption status.          */
#endif /* HAVE_GSSAPI */

#if !SOCKS_CLIENT && HAVE_LDAP
/*
 * new ldapauthorisation server details.  Used for checking if an already
 * (GSSAPI) authenticated user is member of the appropriate LDAP group.
 */
static ldapauthorisation_t    *ldapauthorisation;


/*
 * new ldapauthorisation auth server details.
 * Used for doing LDAP-based authentication of a new client.
 */
static ldapauthentication_t   *ldapauthentication;

#endif /* SOCKS_SERVER && HAVE_LDAP */

#if !SOCKS_CLIENT && HAVE_PAC
static char            *b64;        /* new b64 encoded sid.                   */
#endif /* !SOCKS_CLIENT && HAVE_PAC */

#if DEBUG
#define YYDEBUG 1
#endif /* DEBUG */

#define ADDMETHOD(method, methodc, methodv)                                    \
do {                                                                           \
   if (methodisset((method), (methodv), (methodc)))                            \
      yywarnx("duplicate method: %s.  Already set on this methodline",         \
              method2string((method)));                                        \
   else {                                                                      \
      if ((methodc) >= METHODS_KNOWN) {                                        \
         yyerrorx("too many authmethods (%lu, max is %ld)",                    \
                  (unsigned long)(methodc), (long)METHODS_KNOWN);              \
         SERRX(methodc);                                                       \
      }                                                                        \
                                                                               \
      /*                                                                       \
       * check if we have the external libraries required for the method.      \
       */                                                                      \
      switch (method) {                                                        \
         case AUTHMETHOD_BSDAUTH:                                              \
            if (!HAVE_BSDAUTH)                                                 \
               yyerrorx_nolib("bsdauth");                                      \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_GSSAPI:                                               \
            if (!HAVE_GSSAPI)                                                  \
               yyerrorx_nolib("GSSAPI");                                       \
                                                                               \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_RFC931:                                               \
            if (!HAVE_LIBWRAP)                                                 \
               yyerrorx_nolib("libwrap");                                      \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_PAM_ANY:                                              \
         case AUTHMETHOD_PAM_ADDRESS:                                          \
         case AUTHMETHOD_PAM_USERNAME:                                         \
            if (!HAVE_PAM)                                                     \
               yyerrorx_nolib("PAM");                                          \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_LDAPAUTH:                                             \
            if (!HAVE_LDAP)                                                    \
               yyerrorx_nolib("LDAP");                                         \
            break;                                                             \
      }                                                                        \
                                                                               \
      methodv[(methodc)++] = method;                                           \
   }                                                                           \
} while (0)

#define ASSIGN_NUMBER(number, op, checkagainst, object, issigned)              \
do {                                                                           \
   if (!((number) op (checkagainst)))                                          \
      yyerrorx("number (%lld) must be " #op " %lld (" #checkagainst ")",       \
               (long long)(number), (long long)(checkagainst));                \
                                                                               \
   if (issigned) {                                                             \
      if ((long long)(number) < minvalueoftype(sizeof(object)))                \
         yyerrorx("number %lld is too small.  Minimum is %lld",                \
                  (long long)number, minvalueoftype(sizeof(object)));          \
                                                                               \
      if ((long long)(number) > maxvalueoftype(sizeof(object)))                \
         yyerrorx("number %lld is too large.  Maximum is %lld",                \
                  (long long)number,  maxvalueoftype(sizeof(object)));         \
   }                                                                           \
   else  {                                                                     \
      if ((unsigned long long)(number) < uminvalueoftype(sizeof(object)))      \
         yyerrorx("number %llu is too small.  Minimum is %llu",                \
                  (unsigned long long)number, uminvalueoftype(sizeof(object)));\
                                                                               \
      if ((unsigned long long)(number) > umaxvalueoftype(sizeof(object)))      \
         yyerrorx("number %llu is too large.  Maximum is %llu",                \
                  (unsigned long long)number, umaxvalueoftype(sizeof(object)));\
   }                                                                           \
                                                                               \
   (object) = (number);                                                        \
} while (0)

#define ASSIGN_PORTNUMBER(portnumber, object)                                  \
do {                                                                           \
   /* includes 0 and MAXPORT because the exp might be "> 0" or "< MAXPORT". */ \
   ASSIGN_NUMBER(portnumber, >=,  0,         (object), 0);                     \
   ASSIGN_NUMBER(portnumber, <=, IP_MAXPORT, (object), 0);                     \
                                                                               \
   (object) = htons((in_port_t)(portnumber));                                  \
} while (0)

#define ASSIGN_THROTTLE_SECONDS(number, obj, issigned)     \
            ASSIGN_NUMBER((number), >, 0, obj, issigned)
#define ASSIGN_THROTTLE_CLIENTS(number, obj, issigned)     \
            ASSIGN_NUMBER((number), >, 0, obj, issigned)
#define ASSIGN_MAXSESSIONS(number, obj, issigned)          \
            ASSIGN_NUMBER((number), >, 0, obj, issigned)

#line 448 "config_parse.c" /* yacc.c:337  */
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_SOCKS_YY_Y_TAB_H_INCLUDED
# define YY_SOCKS_YY_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int socks_yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    ALARM = 258,
    ALARMTYPE_DATA = 259,
    ALARMTYPE_DISCONNECT = 260,
    ALARMIF_INTERNAL = 261,
    ALARMIF_EXTERNAL = 262,
    TCPOPTION_DISABLED = 263,
    ECN = 264,
    SACK = 265,
    TIMESTAMPS = 266,
    WSCALE = 267,
    MTU_ERROR = 268,
    CLIENTCOMPATIBILITY = 269,
    NECGSSAPI = 270,
    CLIENTRULE = 271,
    HOSTIDRULE = 272,
    SOCKSRULE = 273,
    COMPATIBILITY = 274,
    SAMEPORT = 275,
    DRAFT_5_05 = 276,
    CONNECTTIMEOUT = 277,
    TCP_FIN_WAIT = 278,
    CPU = 279,
    MASK = 280,
    SCHEDULE = 281,
    CPUMASK_ANYCPU = 282,
    DEBUGGING = 283,
    DEPRECATED = 284,
    ERRORLOG = 285,
    LOGOUTPUT = 286,
    LOGFILE = 287,
    LOGTYPE_ERROR = 288,
    LOGTYPE_TCP_DISABLED = 289,
    LOGTYPE_TCP_ENABLED = 290,
    LOGIF_INTERNAL = 291,
    LOGIF_EXTERNAL = 292,
    ERRORVALUE = 293,
    EXTENSION = 294,
    BIND = 295,
    PRIVILEGED = 296,
    EXTERNAL_PROTOCOL = 297,
    INTERNAL_PROTOCOL = 298,
    EXTERNAL_ROTATION = 299,
    SAMESAME = 300,
    GROUPNAME = 301,
    HOSTID = 302,
    HOSTINDEX = 303,
    INTERFACE = 304,
    SOCKETOPTION_SYMBOLICVALUE = 305,
    INTERNAL = 306,
    EXTERNAL = 307,
    INTERNALSOCKET = 308,
    EXTERNALSOCKET = 309,
    IOTIMEOUT = 310,
    IOTIMEOUT_TCP = 311,
    IOTIMEOUT_UDP = 312,
    NEGOTIATETIMEOUT = 313,
    LIBWRAP_FILE = 314,
    LOGLEVEL = 315,
    SOCKSMETHOD = 316,
    CLIENTMETHOD = 317,
    METHOD = 318,
    METHODNAME = 319,
    NONE = 320,
    BSDAUTH = 321,
    GSSAPI = 322,
    PAM_ADDRESS = 323,
    PAM_ANY = 324,
    PAM_USERNAME = 325,
    RFC931 = 326,
    UNAME = 327,
    MONITOR = 328,
    PROCESSTYPE = 329,
    PROC_MAXREQUESTS = 330,
    PROC_MAXLIFETIME = 331,
    REALM = 332,
    REALNAME = 333,
    RESOLVEPROTOCOL = 334,
    REQUIRED = 335,
    SCHEDULEPOLICY = 336,
    SERVERCONFIG = 337,
    CLIENTCONFIG = 338,
    SOCKET = 339,
    CLIENTSIDE_SOCKET = 340,
    SNDBUF = 341,
    RCVBUF = 342,
    SOCKETPROTOCOL = 343,
    SOCKETOPTION_OPTID = 344,
    SRCHOST = 345,
    NODNSMISMATCH = 346,
    NODNSUNKNOWN = 347,
    CHECKREPLYAUTH = 348,
    USERNAME = 349,
    USER_PRIVILEGED = 350,
    USER_UNPRIVILEGED = 351,
    USER_LIBWRAP = 352,
    WORD__IN = 353,
    ROUTE = 354,
    VIA = 355,
    GLOBALROUTEOPTION = 356,
    BADROUTE_EXPIRE = 357,
    MAXFAIL = 358,
    PORT = 359,
    NUMBER = 360,
    BANDWIDTH = 361,
    BOUNCE = 362,
    BSDAUTHSTYLE = 363,
    BSDAUTHSTYLENAME = 364,
    COMMAND = 365,
    COMMAND_BIND = 366,
    COMMAND_CONNECT = 367,
    COMMAND_UDPASSOCIATE = 368,
    COMMAND_BINDREPLY = 369,
    COMMAND_UDPREPLY = 370,
    ACTION = 371,
    FROM = 372,
    TO = 373,
    GSSAPIENCTYPE = 374,
    GSSAPIENC_ANY = 375,
    GSSAPIENC_CLEAR = 376,
    GSSAPIENC_INTEGRITY = 377,
    GSSAPIENC_CONFIDENTIALITY = 378,
    GSSAPIENC_PERMESSAGE = 379,
    GSSAPIKEYTAB = 380,
    GSSAPISERVICE = 381,
    GSSAPISERVICENAME = 382,
    GSSAPIKEYTABNAME = 383,
    IPV4 = 384,
    IPV6 = 385,
    IPVANY = 386,
    DOMAINNAME = 387,
    IFNAME = 388,
    URL = 389,
    LDAPATTRIBUTE = 390,
    LDAPATTRIBUTE_AD = 391,
    LDAPATTRIBUTE_HEX = 392,
    LDAPATTRIBUTE_AD_HEX = 393,
    LDAPBASEDN = 394,
    LDAP_BASEDN = 395,
    LDAPBASEDN_HEX = 396,
    LDAPBASEDN_HEX_ALL = 397,
    LDAPCERTFILE = 398,
    LDAPCERTPATH = 399,
    LDAPPORT = 400,
    LDAPPORTSSL = 401,
    LDAPDEBUG = 402,
    LDAPDEPTH = 403,
    LDAPAUTO = 404,
    LDAPSEARCHTIME = 405,
    LDAPDOMAIN = 406,
    LDAP_DOMAIN = 407,
    LDAPFILTER = 408,
    LDAPFILTER_AD = 409,
    LDAPFILTER_HEX = 410,
    LDAPFILTER_AD_HEX = 411,
    LDAPGROUP = 412,
    LDAPGROUP_NAME = 413,
    LDAPGROUP_HEX = 414,
    LDAPGROUP_HEX_ALL = 415,
    LDAPKEYTAB = 416,
    LDAPKEYTABNAME = 417,
    LDAPDEADTIME = 418,
    LDAPSERVER = 419,
    LDAPSERVER_NAME = 420,
    LDAPAUTHSERVER = 421,
    LDAPAUTHKEYTAB = 422,
    LDAPSSL = 423,
    LDAPCERTCHECK = 424,
    LDAPKEEPREALM = 425,
    LDAPTIMEOUT = 426,
    LDAPCACHE = 427,
    LDAPCACHEPOS = 428,
    LDAPCACHENEG = 429,
    LDAPURL = 430,
    LDAP_URL = 431,
    LDAPAUTHBASEDN = 432,
    LDAPAUTHBASEDN_HEX = 433,
    LDAPAUTHBASEDN_HEX_ALL = 434,
    LDAPAUTHURL = 435,
    LDAPAUTHPORT = 436,
    LDAPAUTHPORTSSL = 437,
    LDAPAUTHDEBUG = 438,
    LDAPAUTHSSL = 439,
    LDAPAUTHAUTO = 440,
    LDAPAUTHCERTCHECK = 441,
    LDAPAUTHFILTER = 442,
    LDAPAUTHDOMAIN = 443,
    LDAPAUTHCERTFILE = 444,
    LDAPAUTHCERTPATH = 445,
    LDAP_FILTER = 446,
    LDAP_ATTRIBUTE = 447,
    LDAP_CERTFILE = 448,
    LDAP_CERTPATH = 449,
    LIBWRAPSTART = 450,
    LIBWRAP_ALLOW = 451,
    LIBWRAP_DENY = 452,
    LIBWRAP_HOSTS_ACCESS = 453,
    LINE = 454,
    OPERATOR = 455,
    PACSID = 456,
    PACSID_B64 = 457,
    PACSID_FLAG = 458,
    PACSID_NAME = 459,
    PAMSERVICENAME = 460,
    PROTOCOL = 461,
    PROTOCOL_TCP = 462,
    PROTOCOL_UDP = 463,
    PROTOCOL_FAKE = 464,
    PROXYPROTOCOL = 465,
    PROXYPROTOCOL_SOCKS_V4 = 466,
    PROXYPROTOCOL_SOCKS_V5 = 467,
    PROXYPROTOCOL_HTTP = 468,
    PROXYPROTOCOL_UPNP = 469,
    REDIRECT = 470,
    SENDSIDE = 471,
    RECVSIDE = 472,
    SERVICENAME = 473,
    SESSION_INHERITABLE = 474,
    SESSIONMAX = 475,
    SESSIONTHROTTLE = 476,
    SESSIONSTATE_KEY = 477,
    SESSIONSTATE_MAX = 478,
    SESSIONSTATE_THROTTLE = 479,
    RULE_LOG = 480,
    RULE_LOG_CONNECT = 481,
    RULE_LOG_DATA = 482,
    RULE_LOG_DISCONNECT = 483,
    RULE_LOG_ERROR = 484,
    RULE_LOG_IOOPERATION = 485,
    RULE_LOG_TCPINFO = 486,
    STATEKEY = 487,
    UDPPORTRANGE = 488,
    UDPCONNECTDST = 489,
    USER = 490,
    GROUP = 491,
    VERDICT_BLOCK = 492,
    VERDICT_PASS = 493,
    YES = 494,
    NO = 495
  };
#endif
/* Tokens.  */
#define ALARM 258
#define ALARMTYPE_DATA 259
#define ALARMTYPE_DISCONNECT 260
#define ALARMIF_INTERNAL 261
#define ALARMIF_EXTERNAL 262
#define TCPOPTION_DISABLED 263
#define ECN 264
#define SACK 265
#define TIMESTAMPS 266
#define WSCALE 267
#define MTU_ERROR 268
#define CLIENTCOMPATIBILITY 269
#define NECGSSAPI 270
#define CLIENTRULE 271
#define HOSTIDRULE 272
#define SOCKSRULE 273
#define COMPATIBILITY 274
#define SAMEPORT 275
#define DRAFT_5_05 276
#define CONNECTTIMEOUT 277
#define TCP_FIN_WAIT 278
#define CPU 279
#define MASK 280
#define SCHEDULE 281
#define CPUMASK_ANYCPU 282
#define DEBUGGING 283
#define DEPRECATED 284
#define ERRORLOG 285
#define LOGOUTPUT 286
#define LOGFILE 287
#define LOGTYPE_ERROR 288
#define LOGTYPE_TCP_DISABLED 289
#define LOGTYPE_TCP_ENABLED 290
#define LOGIF_INTERNAL 291
#define LOGIF_EXTERNAL 292
#define ERRORVALUE 293
#define EXTENSION 294
#define BIND 295
#define PRIVILEGED 296
#define EXTERNAL_PROTOCOL 297
#define INTERNAL_PROTOCOL 298
#define EXTERNAL_ROTATION 299
#define SAMESAME 300
#define GROUPNAME 301
#define HOSTID 302
#define HOSTINDEX 303
#define INTERFACE 304
#define SOCKETOPTION_SYMBOLICVALUE 305
#define INTERNAL 306
#define EXTERNAL 307
#define INTERNALSOCKET 308
#define EXTERNALSOCKET 309
#define IOTIMEOUT 310
#define IOTIMEOUT_TCP 311
#define IOTIMEOUT_UDP 312
#define NEGOTIATETIMEOUT 313
#define LIBWRAP_FILE 314
#define LOGLEVEL 315
#define SOCKSMETHOD 316
#define CLIENTMETHOD 317
#define METHOD 318
#define METHODNAME 319
#define NONE 320
#define BSDAUTH 321
#define GSSAPI 322
#define PAM_ADDRESS 323
#define PAM_ANY 324
#define PAM_USERNAME 325
#define RFC931 326
#define UNAME 327
#define MONITOR 328
#define PROCESSTYPE 329
#define PROC_MAXREQUESTS 330
#define PROC_MAXLIFETIME 331
#define REALM 332
#define REALNAME 333
#define RESOLVEPROTOCOL 334
#define REQUIRED 335
#define SCHEDULEPOLICY 336
#define SERVERCONFIG 337
#define CLIENTCONFIG 338
#define SOCKET 339
#define CLIENTSIDE_SOCKET 340
#define SNDBUF 341
#define RCVBUF 342
#define SOCKETPROTOCOL 343
#define SOCKETOPTION_OPTID 344
#define SRCHOST 345
#define NODNSMISMATCH 346
#define NODNSUNKNOWN 347
#define CHECKREPLYAUTH 348
#define USERNAME 349
#define USER_PRIVILEGED 350
#define USER_UNPRIVILEGED 351
#define USER_LIBWRAP 352
#define WORD__IN 353
#define ROUTE 354
#define VIA 355
#define GLOBALROUTEOPTION 356
#define BADROUTE_EXPIRE 357
#define MAXFAIL 358
#define PORT 359
#define NUMBER 360
#define BANDWIDTH 361
#define BOUNCE 362
#define BSDAUTHSTYLE 363
#define BSDAUTHSTYLENAME 364
#define COMMAND 365
#define COMMAND_BIND 366
#define COMMAND_CONNECT 367
#define COMMAND_UDPASSOCIATE 368
#define COMMAND_BINDREPLY 369
#define COMMAND_UDPREPLY 370
#define ACTION 371
#define FROM 372
#define TO 373
#define GSSAPIENCTYPE 374
#define GSSAPIENC_ANY 375
#define GSSAPIENC_CLEAR 376
#define GSSAPIENC_INTEGRITY 377
#define GSSAPIENC_CONFIDENTIALITY 378
#define GSSAPIENC_PERMESSAGE 379
#define GSSAPIKEYTAB 380
#define GSSAPISERVICE 381
#define GSSAPISERVICENAME 382
#define GSSAPIKEYTABNAME 383
#define IPV4 384
#define IPV6 385
#define IPVANY 386
#define DOMAINNAME 387
#define IFNAME 388
#define URL 389
#define LDAPATTRIBUTE 390
#define LDAPATTRIBUTE_AD 391
#define LDAPATTRIBUTE_HEX 392
#define LDAPATTRIBUTE_AD_HEX 393
#define LDAPBASEDN 394
#define LDAP_BASEDN 395
#define LDAPBASEDN_HEX 396
#define LDAPBASEDN_HEX_ALL 397
#define LDAPCERTFILE 398
#define LDAPCERTPATH 399
#define LDAPPORT 400
#define LDAPPORTSSL 401
#define LDAPDEBUG 402
#define LDAPDEPTH 403
#define LDAPAUTO 404
#define LDAPSEARCHTIME 405
#define LDAPDOMAIN 406
#define LDAP_DOMAIN 407
#define LDAPFILTER 408
#define LDAPFILTER_AD 409
#define LDAPFILTER_HEX 410
#define LDAPFILTER_AD_HEX 411
#define LDAPGROUP 412
#define LDAPGROUP_NAME 413
#define LDAPGROUP_HEX 414
#define LDAPGROUP_HEX_ALL 415
#define LDAPKEYTAB 416
#define LDAPKEYTABNAME 417
#define LDAPDEADTIME 418
#define LDAPSERVER 419
#define LDAPSERVER_NAME 420
#define LDAPAUTHSERVER 421
#define LDAPAUTHKEYTAB 422
#define LDAPSSL 423
#define LDAPCERTCHECK 424
#define LDAPKEEPREALM 425
#define LDAPTIMEOUT 426
#define LDAPCACHE 427
#define LDAPCACHEPOS 428
#define LDAPCACHENEG 429
#define LDAPURL 430
#define LDAP_URL 431
#define LDAPAUTHBASEDN 432
#define LDAPAUTHBASEDN_HEX 433
#define LDAPAUTHBASEDN_HEX_ALL 434
#define LDAPAUTHURL 435
#define LDAPAUTHPORT 436
#define LDAPAUTHPORTSSL 437
#define LDAPAUTHDEBUG 438
#define LDAPAUTHSSL 439
#define LDAPAUTHAUTO 440
#define LDAPAUTHCERTCHECK 441
#define LDAPAUTHFILTER 442
#define LDAPAUTHDOMAIN 443
#define LDAPAUTHCERTFILE 444
#define LDAPAUTHCERTPATH 445
#define LDAP_FILTER 446
#define LDAP_ATTRIBUTE 447
#define LDAP_CERTFILE 448
#define LDAP_CERTPATH 449
#define LIBWRAPSTART 450
#define LIBWRAP_ALLOW 451
#define LIBWRAP_DENY 452
#define LIBWRAP_HOSTS_ACCESS 453
#define LINE 454
#define OPERATOR 455
#define PACSID 456
#define PACSID_B64 457
#define PACSID_FLAG 458
#define PACSID_NAME 459
#define PAMSERVICENAME 460
#define PROTOCOL 461
#define PROTOCOL_TCP 462
#define PROTOCOL_UDP 463
#define PROTOCOL_FAKE 464
#define PROXYPROTOCOL 465
#define PROXYPROTOCOL_SOCKS_V4 466
#define PROXYPROTOCOL_SOCKS_V5 467
#define PROXYPROTOCOL_HTTP 468
#define PROXYPROTOCOL_UPNP 469
#define REDIRECT 470
#define SENDSIDE 471
#define RECVSIDE 472
#define SERVICENAME 473
#define SESSION_INHERITABLE 474
#define SESSIONMAX 475
#define SESSIONTHROTTLE 476
#define SESSIONSTATE_KEY 477
#define SESSIONSTATE_MAX 478
#define SESSIONSTATE_THROTTLE 479
#define RULE_LOG 480
#define RULE_LOG_CONNECT 481
#define RULE_LOG_DATA 482
#define RULE_LOG_DISCONNECT 483
#define RULE_LOG_ERROR 484
#define RULE_LOG_IOOPERATION 485
#define RULE_LOG_TCPINFO 486
#define STATEKEY 487
#define UDPPORTRANGE 488
#define UDPCONNECTDST 489
#define USER 490
#define GROUP 491
#define VERDICT_BLOCK 492
#define VERDICT_PASS 493
#define YES 494
#define NO 495

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 417 "config_parse.y" /* yacc.c:352  */

   struct {
      uid_t   uid;
      gid_t   gid;
   } uid;

   struct {
      valuetype_t valuetype;
      const int   *valuev;
   } error;

   struct {
      const char *oldname;
      const char *newname;
   } deprecated;

   char       *string;
   int        method;
   long long  number;

#line 992 "config_parse.c" /* yacc.c:352  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE socks_yylval;

int socks_yyparse (void);

#endif /* !YY_SOCKS_YY_Y_TAB_H_INCLUDED  */



#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  30
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   721

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  247
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  263
/* YYNRULES -- Number of rules.  */
#define YYNRULES  507
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  842

#define YYUNDEFTOK  2
#define YYMAXUTOK   495

/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  ((unsigned) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,   246,   242,   245,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   241,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   243,     2,   244,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   653,   653,   653,   658,   661,   662,   665,   666,   667,
     668,   669,   672,   673,   675,   676,   677,   678,   679,   680,
     681,   682,   683,   684,   685,   686,   687,   688,   689,   690,
     691,   692,   693,   694,   695,   696,   697,   698,   699,   700,
     701,   709,   710,   710,   715,   715,   723,   723,   733,   733,
     743,   743,   753,   753,   764,   774,   775,   778,   785,   792,
     799,   808,   809,   812,   864,   865,   866,   867,   870,   877,
     878,   877,   889,   890,   892,   895,   898,   901,   904,   907,
     910,   911,   914,   917,   925,   926,   929,   932,   940,   941,
     944,   947,   956,   957,   960,   961,   965,   969,   975,  1000,
    1024,  1024,  1049,  1056,  1078,  1078,  1091,  1095,  1098,  1104,
    1105,  1106,  1107,  1108,  1109,  1110,  1113,  1114,  1117,  1125,
    1135,  1135,  1138,  1138,  1141,  1198,  1199,  1202,  1209,  1218,
    1219,  1220,  1223,  1236,  1249,  1268,  1284,  1289,  1292,  1298,
    1305,  1310,  1318,  1338,  1339,  1342,  1356,  1370,  1378,  1388,
    1392,  1399,  1402,  1406,  1412,  1413,  1416,  1419,  1422,  1429,
    1434,  1435,  1438,  1480,  1541,  1541,  1548,  1560,  1571,  1575,
    1592,  1595,  1601,  1604,  1608,  1611,  1617,  1618,  1621,  1633,
    1633,  1644,  1644,  1659,  1662,  1663,  1666,  1675,  1678,  1679,
    1683,  1691,  1691,  1691,  1708,  1708,  1737,  1738,  1739,  1742,
    1746,  1749,  1755,  1759,  1762,  1768,  1768,  1830,  1833,  1851,
    1882,  1887,  1890,  1891,  1892,  1893,  1896,  1897,  1900,  1905,
    1910,  1911,  1916,  1919,  1919,  1944,  1945,  1948,  1949,  1952,
    1952,  1963,  1975,  1975,  1990,  1991,  1995,  1996,  1997,  1998,
    1999,  2000,  2001,  2002,  2007,  2011,  2017,  2018,  2019,  2020,
    2021,  2022,  2023,  2024,  2025,  2026,  2027,  2028,  2029,  2034,
    2039,  2047,  2052,  2075,  2076,  2079,  2080,  2081,  2082,  2083,
    2084,  2085,  2086,  2087,  2088,  2089,  2090,  2091,  2092,  2093,
    2094,  2097,  2098,  2099,  2100,  2101,  2102,  2103,  2104,  2105,
    2106,  2107,  2108,  2109,  2110,  2111,  2112,  2113,  2114,  2115,
    2116,  2117,  2118,  2119,  2120,  2121,  2122,  2123,  2124,  2128,
    2133,  2142,  2147,  2156,  2170,  2184,  2195,  2209,  2223,  2237,
    2253,  2265,  2279,  2291,  2303,  2315,  2327,  2339,  2351,  2362,
    2373,  2384,  2395,  2400,  2409,  2414,  2423,  2428,  2437,  2442,
    2451,  2456,  2465,  2470,  2479,  2484,  2493,  2504,  2515,  2530,
    2544,  2558,  2573,  2587,  2601,  2615,  2627,  2641,  2655,  2667,
    2679,  2694,  2709,  2727,  2745,  2751,  2761,  2764,  2773,  2774,
    2778,  2783,  2790,  2793,  2794,  2797,  2800,  2803,  2809,  2813,
    2819,  2822,  2823,  2826,  2829,  2835,  2838,  2841,  2842,  2843,
    2846,  2847,  2848,  2851,  2854,  2855,  2858,  2862,  2868,  2877,
    2886,  2887,  2888,  2889,  2892,  2920,  2920,  2931,  2939,  2948,
    2957,  2960,  2964,  2967,  2970,  2973,  2976,  2982,  2983,  2987,
    2999,  3012,  3024,  3040,  3043,  3049,  3052,  3055,  3058,  3066,
    3067,  3070,  3073,  3113,  3116,  3119,  3122,  3125,  3135,  3138,
    3139,  3140,  3141,  3142,  3143,  3144,  3145,  3146,  3147,  3148,
    3156,  3157,  3160,  3163,  3168,  3173,  3178,  3183,  3191,  3196,
    3197,  3198,  3199,  3202,  3203,  3204,  3207,  3211,  3212,  3213,
    3214,  3215,  3217,  3219,  3220,  3221,  3222,  3225,  3226,  3230,
    3238,  3245,  3251,  3259,  3268,  3276,  3286,  3292,  3299,  3306,
    3307,  3308,  3309,  3312,  3313,  3316,  3317,  3320,  3328,  3334,
    3340,  3375,  3381,  3384,  3391,  3403,  3408,  3409
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "ALARM", "ALARMTYPE_DATA",
  "ALARMTYPE_DISCONNECT", "ALARMIF_INTERNAL", "ALARMIF_EXTERNAL",
  "TCPOPTION_DISABLED", "ECN", "SACK", "TIMESTAMPS", "WSCALE", "MTU_ERROR",
  "CLIENTCOMPATIBILITY", "NECGSSAPI", "CLIENTRULE", "HOSTIDRULE",
  "SOCKSRULE", "COMPATIBILITY", "SAMEPORT", "DRAFT_5_05", "CONNECTTIMEOUT",
  "TCP_FIN_WAIT", "CPU", "MASK", "SCHEDULE", "CPUMASK_ANYCPU", "DEBUGGING",
  "DEPRECATED", "ERRORLOG", "LOGOUTPUT", "LOGFILE", "LOGTYPE_ERROR",
  "LOGTYPE_TCP_DISABLED", "LOGTYPE_TCP_ENABLED", "LOGIF_INTERNAL",
  "LOGIF_EXTERNAL", "ERRORVALUE", "EXTENSION", "BIND", "PRIVILEGED",
  "EXTERNAL_PROTOCOL", "INTERNAL_PROTOCOL", "EXTERNAL_ROTATION",
  "SAMESAME", "GROUPNAME", "HOSTID", "HOSTINDEX", "INTERFACE",
  "SOCKETOPTION_SYMBOLICVALUE", "INTERNAL", "EXTERNAL", "INTERNALSOCKET",
  "EXTERNALSOCKET", "IOTIMEOUT", "IOTIMEOUT_TCP", "IOTIMEOUT_UDP",
  "NEGOTIATETIMEOUT", "LIBWRAP_FILE", "LOGLEVEL", "SOCKSMETHOD",
  "CLIENTMETHOD", "METHOD", "METHODNAME", "NONE", "BSDAUTH", "GSSAPI",
  "PAM_ADDRESS", "PAM_ANY", "PAM_USERNAME", "RFC931", "UNAME", "MONITOR",
  "PROCESSTYPE", "PROC_MAXREQUESTS", "PROC_MAXLIFETIME", "REALM",
  "REALNAME", "RESOLVEPROTOCOL", "REQUIRED", "SCHEDULEPOLICY",
  "SERVERCONFIG", "CLIENTCONFIG", "SOCKET", "CLIENTSIDE_SOCKET", "SNDBUF",
  "RCVBUF", "SOCKETPROTOCOL", "SOCKETOPTION_OPTID", "SRCHOST",
  "NODNSMISMATCH", "NODNSUNKNOWN", "CHECKREPLYAUTH", "USERNAME",
  "USER_PRIVILEGED", "USER_UNPRIVILEGED", "USER_LIBWRAP", "WORD__IN",
  "ROUTE", "VIA", "GLOBALROUTEOPTION", "BADROUTE_EXPIRE", "MAXFAIL",
  "PORT", "NUMBER", "BANDWIDTH", "BOUNCE", "BSDAUTHSTYLE",
  "BSDAUTHSTYLENAME", "COMMAND", "COMMAND_BIND", "COMMAND_CONNECT",
  "COMMAND_UDPASSOCIATE", "COMMAND_BINDREPLY", "COMMAND_UDPREPLY",
  "ACTION", "FROM", "TO", "GSSAPIENCTYPE", "GSSAPIENC_ANY",
  "GSSAPIENC_CLEAR", "GSSAPIENC_INTEGRITY", "GSSAPIENC_CONFIDENTIALITY",
  "GSSAPIENC_PERMESSAGE", "GSSAPIKEYTAB", "GSSAPISERVICE",
  "GSSAPISERVICENAME", "GSSAPIKEYTABNAME", "IPV4", "IPV6", "IPVANY",
  "DOMAINNAME", "IFNAME", "URL", "LDAPATTRIBUTE", "LDAPATTRIBUTE_AD",
  "LDAPATTRIBUTE_HEX", "LDAPATTRIBUTE_AD_HEX", "LDAPBASEDN", "LDAP_BASEDN",
  "LDAPBASEDN_HEX", "LDAPBASEDN_HEX_ALL", "LDAPCERTFILE", "LDAPCERTPATH",
  "LDAPPORT", "LDAPPORTSSL", "LDAPDEBUG", "LDAPDEPTH", "LDAPAUTO",
  "LDAPSEARCHTIME", "LDAPDOMAIN", "LDAP_DOMAIN", "LDAPFILTER",
  "LDAPFILTER_AD", "LDAPFILTER_HEX", "LDAPFILTER_AD_HEX", "LDAPGROUP",
  "LDAPGROUP_NAME", "LDAPGROUP_HEX", "LDAPGROUP_HEX_ALL", "LDAPKEYTAB",
  "LDAPKEYTABNAME", "LDAPDEADTIME", "LDAPSERVER", "LDAPSERVER_NAME",
  "LDAPAUTHSERVER", "LDAPAUTHKEYTAB", "LDAPSSL", "LDAPCERTCHECK",
  "LDAPKEEPREALM", "LDAPTIMEOUT", "LDAPCACHE", "LDAPCACHEPOS",
  "LDAPCACHENEG", "LDAPURL", "LDAP_URL", "LDAPAUTHBASEDN",
  "LDAPAUTHBASEDN_HEX", "LDAPAUTHBASEDN_HEX_ALL", "LDAPAUTHURL",
  "LDAPAUTHPORT", "LDAPAUTHPORTSSL", "LDAPAUTHDEBUG", "LDAPAUTHSSL",
  "LDAPAUTHAUTO", "LDAPAUTHCERTCHECK", "LDAPAUTHFILTER", "LDAPAUTHDOMAIN",
  "LDAPAUTHCERTFILE", "LDAPAUTHCERTPATH", "LDAP_FILTER", "LDAP_ATTRIBUTE",
  "LDAP_CERTFILE", "LDAP_CERTPATH", "LIBWRAPSTART", "LIBWRAP_ALLOW",
  "LIBWRAP_DENY", "LIBWRAP_HOSTS_ACCESS", "LINE", "OPERATOR", "PACSID",
  "PACSID_B64", "PACSID_FLAG", "PACSID_NAME", "PAMSERVICENAME", "PROTOCOL",
  "PROTOCOL_TCP", "PROTOCOL_UDP", "PROTOCOL_FAKE", "PROXYPROTOCOL",
  "PROXYPROTOCOL_SOCKS_V4", "PROXYPROTOCOL_SOCKS_V5", "PROXYPROTOCOL_HTTP",
  "PROXYPROTOCOL_UPNP", "REDIRECT", "SENDSIDE", "RECVSIDE", "SERVICENAME",
  "SESSION_INHERITABLE", "SESSIONMAX", "SESSIONTHROTTLE",
  "SESSIONSTATE_KEY", "SESSIONSTATE_MAX", "SESSIONSTATE_THROTTLE",
  "RULE_LOG", "RULE_LOG_CONNECT", "RULE_LOG_DATA", "RULE_LOG_DISCONNECT",
  "RULE_LOG_ERROR", "RULE_LOG_IOOPERATION", "RULE_LOG_TCPINFO", "STATEKEY",
  "UDPPORTRANGE", "UDPCONNECTDST", "USER", "GROUP", "VERDICT_BLOCK",
  "VERDICT_PASS", "YES", "NO", "':'", "'.'", "'{'", "'}'", "'/'", "'-'",
  "$accept", "configtype", "$@1", "serverobjects", "serverobject",
  "serveroptions", "serveroption", "logspecial", "$@2", "$@3",
  "internal_if_logoption", "$@4", "external_if_logoption", "$@5",
  "rule_internal_logoption", "$@6", "rule_external_logoption", "$@7",
  "loglevel", "tcpoptions", "tcpoption", "errors", "errorobject",
  "timeout", "deprecated", "route", "$@8", "$@9", "routes",
  "proxyprotocol", "proxyprotocolname", "proxyprotocols", "user",
  "username", "usernames", "group", "groupname", "groupnames", "extension",
  "extensionname", "extensions", "ifprotocols", "ifprotocol", "internal",
  "internalinit", "internal_protocol", "$@10", "external", "externalinit",
  "external_protocol", "$@11", "external_rotation", "clientoption",
  "clientoptions", "global_routeoption", "errorlog", "$@12", "logoutput",
  "$@13", "logoutputdevice", "logoutputdevices", "childstate", "userids",
  "user_privileged", "user_unprivileged", "user_libwrap", "userid",
  "iotimeout", "negotiatetimeout", "connecttimeout", "tcp_fin_timeout",
  "debugging", "libwrapfiles", "libwrap_allowfile", "libwrap_denyfile",
  "libwrap_hosts_access", "udpconnectdst", "compatibility",
  "compatibilityname", "compatibilitynames", "resolveprotocol",
  "resolveprotocolname", "cpu", "cpuschedule", "cpuaffinity",
  "socketoption", "$@14", "socketoptionname", "socketoptionvalue",
  "socketside", "srchost", "srchostoption", "srchostoptions", "realm",
  "global_clientmethod", "$@15", "global_socksmethod", "$@16",
  "socksmethod", "socksmethods", "socksmethodname", "clientmethod",
  "clientmethods", "clientmethodname", "monitor", "$@17", "$@18", "crule",
  "$@19", "alarm", "monitorside", "alarmside", "alarm_data", "$@20",
  "alarm_test", "networkproblem", "alarm_disconnect", "alarmperiod",
  "monitoroption", "monitoroptions", "cruleoption", "hrule", "$@21",
  "cruleoptions", "hostidoption", "hostid", "$@22", "hostindex", "srule",
  "$@23", "sruleoptions", "sruleoption", "genericruleoption",
  "ldapauthoption", "ldapoption", "ldapdebug", "ldapauthdebug",
  "ldapdomain", "ldapauthdomain", "ldapdepth", "ldapcertfile",
  "ldapauthcertfile", "ldapcertpath", "ldapauthcertpath", "ldapurl",
  "ldapauthurl", "ldapauthbasedn", "ldapauthbasedn_hex",
  "ldapauthbasedn_hex_all", "lbasedn", "lbasedn_hex", "lbasedn_hex_all",
  "ldapauthport", "ldapport", "ldapauthportssl", "ldapportssl", "ldapssl",
  "ldapauthssl", "ldapauto", "ldapauthauto", "ldapcertcheck",
  "ldapauthcertcheck", "ldapkeeprealm", "ldapfilter", "ldapauthfilter",
  "ldapfilter_ad", "ldapfilter_hex", "ldapfilter_ad_hex", "ldapattribute",
  "ldapattribute_ad", "ldapattribute_hex", "ldapattribute_ad_hex",
  "lgroup_hex", "lgroup_hex_all", "lgroup", "lserver", "ldapauthserver",
  "ldapkeytab", "ldapauthkeytab", "psid", "psid_b64", "psid_off",
  "clientcompatibility", "clientcompatibilityname",
  "clientcompatibilitynames", "verdict", "command", "commands",
  "commandname", "protocol", "protocols", "protocolname", "fromto",
  "hostid_fromto", "redirect", "sessionoption", "sockssessionoption",
  "crulesessionoption", "sessioninheritable", "sessionmax",
  "sessionthrottle", "sessionstate", "sessionstate_key",
  "sessionstate_keyinfo", "$@24", "sessionstate_max",
  "sessionstate_throttle", "bandwidth", "log", "logname", "logs",
  "pamservicename", "bsdauthstylename", "gssapiservicename",
  "gssapikeytab", "gssapienctype", "gssapienctypename", "gssapienctypes",
  "bounce", "libwrap", "srcaddress", "hostid_srcaddress", "dstaddress",
  "rdr_fromaddress", "rdr_toaddress", "gateway", "routeoption",
  "routeoptions", "routemethod", "from", "to", "rdr_from", "rdr_to",
  "bounceto", "via", "externaladdress", "address_without_port", "address",
  "ipaddress", "gwaddress", "bouncetoaddress", "ipv4", "netmask_v4",
  "ipv6", "netmask_v6", "ipvany", "netmask_vany", "domain", "ifname",
  "url", "port", "gwport", "portnumber", "portrange", "portstart",
  "portend", "portservice", "portoperator", "udpportrange",
  "udpportrange_start", "udpportrange_end", "number", "numbers", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   466,   467,   468,   469,   470,   471,   472,   473,   474,
     475,   476,   477,   478,   479,   480,   481,   482,   483,   484,
     485,   486,   487,   488,   489,   490,   491,   492,   493,   494,
     495,    58,    46,   123,   125,    47,    45
};
# endif

#define YYPACT_NINF -696

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-696)))

#define YYTABLE_NINF -217

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
      -7,  -696,   157,    82,   378,  -149,  -146,  -132,  -696,  -108,
    -105,  -101,   -97,   -81,   -79,   -71,    23,  -696,  -696,   157,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,   -69,  -152,  -696,  -696,   -46,   -34,   -25,   -17,  -696,
    -696,  -696,  -696,    12,    71,    74,    76,    77,    81,    83,
      86,    87,    88,    90,    91,    92,  -696,   378,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,   149,  -696,
    -696,  -696,  -696,   183,   186,   211,  -696,  -696,   216,   218,
     220,   221,  -159,    98,   100,  -696,   163,   138,   141,   101,
     102,   290,  -696,  -696,    36,   105,   106,  -696,  -696,   237,
     240,   271,    29,   257,   257,   257,   293,   294,   -21,   -19,
      25,  -696,   112,  -696,  -696,  -696,   323,   323,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,   252,   253,  -696,  -696,
    -696,  -696,   138,  -696,   117,   118,   301,   301,  -696,   290,
    -696,   104,   104,  -696,  -696,  -696,   110,    99,   298,   299,
    -696,  -696,  -696,  -696,  -696,  -696,    29,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
     323,  -696,  -696,  -696,  -696,   121,  -696,   291,   292,  -696,
     125,   126,  -696,  -696,  -696,  -696,   104,  -696,  -696,  -696,
    -696,  -696,  -696,   265,  -696,  -696,   127,   128,   129,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,   298,  -696,
    -696,   299,  -696,    22,    22,    22,   132,   -27,  -696,  -696,
     130,   135,   114,   114,  -696,   -72,  -696,   -11,   272,   273,
    -696,  -696,  -696,  -696,   136,   137,   140,  -696,  -696,  -696,
     143,    20,   276,   289,   144,   145,   146,  -696,  -696,  -696,
    -696,   -68,  -696,   147,   -68,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,    49,    49,   485,    21,     8,   148,   151,   162,
     164,   169,   170,   171,   172,   281,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,    20,   282,  -696,  -696,   276,
    -696,   159,   344,  -696,  -696,  -696,  -696,  -696,  -696,   283,
    -696,  -696,  -696,   175,   177,   178,   182,   184,   306,   185,
     187,   196,   197,   200,   139,   201,   202,   203,    24,   204,
     205,   207,   208,   209,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,    49,   282,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,   282,   210,   215,   217,   219,   222,   223,   224,
     225,   226,   228,   229,   230,   231,   235,   236,   239,   241,
     242,   243,   244,   245,   246,   247,   248,   249,   250,   251,
     254,   255,   256,   258,   259,   260,   261,   262,   263,   264,
     268,   269,   274,   275,   279,   284,   285,   286,   287,  -696,
     282,   485,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,   206,  -696,
    -696,  -696,    17,   282,  -696,  -696,  -696,  -696,  -696,  -696,
     412,   298,   134,   155,   319,   325,    73,    -8,  -696,  -696,
     288,  -696,  -696,   359,   343,   295,  -696,   357,  -696,  -696,
     344,   142,   142,  -696,  -696,   270,   302,  -696,   373,   298,
     299,   376,  -696,   296,   307,   309,   313,    47,   280,  -696,
     375,  -696,   304,    50,   389,   418,   303,  -696,   419,   425,
     -37,   437,   488,  -696,    49,    49,   343,   308,   439,   358,
     360,   361,   363,   411,   416,   417,   365,   366,   454,   456,
     -73,   457,    56,   413,   372,   377,   380,   381,   406,   408,
     409,   415,   414,   420,   421,    58,    60,    62,   397,   438,
     440,   441,   410,   477,   479,   -70,    64,    68,    70,   396,
     436,   399,   395,   489,   485,  -696,   348,  -696,   355,  -696,
      19,  -696,   412,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,   134,  -696,  -696,  -696,  -696,  -696,   155,  -696,  -696,
    -696,  -696,  -696,  -696,    73,  -696,  -696,  -696,  -696,  -696,
      -8,  -696,   110,  -696,    20,   356,  -696,  -696,   362,   110,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,   142,  -696,   301,
     301,   110,  -696,  -696,  -696,  -696,    52,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,   110,  -696,  -696,  -696,   353,  -696,
     551,  -696,   364,  -696,  -696,  -696,  -696,  -696,  -696,   -37,
    -696,  -696,  -696,   437,  -696,  -696,   488,   369,   374,  -696,
     110,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,   495,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,   496,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,   370,   391,   589,    89,
     500,   393,  -696,  -696,  -696,  -696,  -696,  -696,   404,    67,
     110,  -696,  -696,   383,   401,  -696,   502,  -696,   502,  -696,
     503,  -696,   512,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,   514,  -696,  -696,  -696,  -696,  -696,   435,   432,  -696,
    -696,  -696,   502,  -696,   502,  -696,  -696,  -696,   114,   114,
     407,  -696,  -696,  -696,  -696,  -696,  -696,   552,   553,  -696,
    -696,  -696,  -696,   -68,   558,   561,  -696,   556,   573,  -696,
    -696,  -696
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       0,     2,   116,     0,    12,     0,     0,     0,    68,     0,
       0,     0,     0,     0,     0,     0,     0,   115,   110,   116,
      72,   111,   112,   113,    65,    66,    64,    67,   109,   114,
       1,     0,     0,    46,    48,     0,     0,     0,     0,    99,
     103,   170,   171,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     5,    12,    30,    24,
      37,    18,    20,    28,    29,    21,    22,    23,    27,    19,
      33,    14,    39,   129,   130,   131,    17,    32,   143,   144,
      31,    38,    15,    35,    16,   160,   161,    40,     0,    36,
      34,    25,    26,     0,     0,     0,   120,   122,     0,     0,
       0,     0,     0,     0,     0,   117,     4,     0,     0,     0,
       0,     0,   104,   100,     0,     0,     0,   181,   179,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       3,    13,     0,   140,   141,   142,     0,     0,   136,   137,
     138,   139,   158,   159,   157,   156,     0,     0,    69,    73,
     152,   153,   154,   151,     0,     0,     0,     0,    91,    92,
      90,     0,     0,   107,   106,   108,     0,     0,     0,     0,
     127,   128,   178,   173,   174,   175,   176,   172,   135,   132,
     133,   134,   145,   146,   147,   148,   149,   150,   194,   223,
     232,   191,     6,    11,    10,     7,     8,     9,   164,   124,
     125,   121,   123,   119,   118,     0,   155,     0,     0,    54,
       0,     0,    93,    96,    97,   105,    94,   101,   479,   482,
     484,   486,   487,   489,    98,   463,   468,   470,   472,   464,
     465,   102,   459,   460,   461,   462,   186,   182,   184,   190,
     180,   188,   177,     0,     0,     0,     0,     0,   126,    70,
       0,     0,     0,     0,    95,     0,   466,     0,     0,     0,
     185,   189,   370,   371,     0,     0,     0,   192,   167,   166,
       0,   450,     0,     0,     0,     0,     0,    47,    49,   498,
     501,     0,   492,     0,     0,   480,   481,   467,   483,   469,
     485,   471,   225,   225,   234,   199,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   447,   442,   449,   441,
     440,   443,   444,   445,   446,   450,     0,   439,   505,   506,
     163,     0,     0,    42,    44,   500,   490,   496,   495,     0,
     491,    50,    52,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   254,   248,   263,   264,   249,   262,
     247,   246,   225,     0,   253,   227,   228,   222,   258,   259,
     260,   220,   219,   261,   395,   221,   394,   390,   391,   392,
     400,   401,   403,   402,   245,   256,   257,   252,   251,   250,
     218,   255,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   242,
       0,   234,   238,   240,   239,   292,   272,   294,   271,   293,
     290,   279,   291,   280,   308,   267,   268,   269,   270,   286,
     287,   288,   273,   301,   274,   302,   303,   275,   285,   276,
     289,   278,   299,   295,   277,   296,   298,   297,   281,   282,
     284,   283,   305,   306,   304,   307,   265,   300,   266,   237,
     241,   393,   243,   236,   244,   200,   201,   212,     0,   196,
     198,   197,   199,     0,   214,   213,   215,   169,   168,   165,
       0,     0,     0,     0,     0,     0,     0,     0,   455,   448,
       0,   451,   453,     0,     0,     0,   507,     0,    63,    41,
      61,     0,     0,   499,   497,     0,     0,   229,     0,     0,
       0,     0,   457,     0,     0,     0,     0,     0,     0,   456,
     388,   389,     0,     0,     0,     0,     0,   405,     0,     0,
       0,     0,     0,   226,   225,   225,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   234,   235,     0,   205,     0,   217,
     199,   367,   368,   366,   452,   375,   376,   377,   378,   379,
     372,   373,   424,   425,   426,   427,   428,   429,   423,   422,
     421,   383,   384,   380,   381,    75,    76,    77,    78,    79,
      80,    74,     0,   458,   450,     0,   454,   385,     0,     0,
     162,    62,    57,    58,    59,    60,    43,    55,    45,     0,
       0,     0,   231,   183,   187,   409,     0,   432,   362,   363,
     364,   365,   419,   387,     0,   396,   397,   398,     0,   404,
       0,   407,     0,   411,   412,   413,   414,   415,   416,   417,
     410,    83,    84,    82,    87,    88,    86,     0,     0,   386,
       0,   420,   351,   352,   353,   354,   325,   326,   327,   316,
     318,   329,   331,   309,     0,   315,   336,   337,   313,   346,
     348,   349,   350,   357,   355,   356,   360,   358,   359,   361,
     332,   333,   340,   341,   344,   345,   320,   322,   323,   324,
     321,   328,   330,   311,     0,   334,   335,   338,   339,   342,
     343,   347,   314,   317,   319,   503,     0,     0,     0,   202,
       0,     0,   369,   374,   430,   382,    81,   436,     0,     0,
       0,   433,    56,     0,     0,   230,   493,   431,   493,   437,
       0,   406,     0,   418,    85,    89,   195,   224,   434,   310,
     312,     0,   233,   208,   207,   204,   203,     0,     0,   193,
      71,   488,   493,   438,   493,   475,   476,   435,     0,     0,
       0,   477,   478,   399,   408,   504,   502,     0,     0,   473,
     474,    51,    53,     0,     0,   210,   494,     0,     0,   209,
     206,   211
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -696,  -696,  -696,  -696,  -696,   622,  -696,  -249,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -151,  -496,
    -696,   152,  -696,    42,    -3,   554,  -696,  -696,  -696,  -278,
    -696,    31,  -696,   -20,  -696,  -696,   -14,  -696,    43,  -696,
     526,  -102,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,   670,    66,    75,  -696,    80,  -696,  -696,
     -92,  -696,  -696,  -696,  -696,  -696,   158,  -696,  -696,  -696,
    -696,    84,  -696,  -696,  -696,  -696,  -696,  -696,  -696,   541,
      85,  -696,  -696,  -696,  -696,    -4,  -696,  -696,  -696,  -696,
    -696,  -696,   518,  -696,  -696,  -696,  -696,  -696,  -696,  -219,
    -696,  -696,  -221,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -463,
    -696,  -696,  -696,  -271,  -285,  -696,  -696,     6,  -696,  -696,
    -412,  -696,  -277,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
    -696,  -696,  -263,  -696,    79,    69,  -280,    72,  -696,  -264,
      53,  -696,  -325,  -696,  -696,  -276,  -696,  -696,  -696,  -696,
    -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,  -696,
      -1,  -696,  -696,  -260,  -259,  -258,  -696,    65,  -696,  -696,
    -696,  -696,   133,   367,   154,  -696,  -696,  -306,  -696,   320,
    -696,  -696,  -696,  -696,  -696,  -696,  -594,  -572,  -636,  -696,
    -696,   546,  -696,   547,  -696,  -696,  -696,  -165,  -164,  -696,
    -696,  -695,  -279,  -696,   460,  -696,  -696,  -104,  -696,  -696,
    -696,  -696,   398
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     3,     4,   130,   192,    56,    57,   277,   531,   532,
      58,   109,    59,   110,   354,   535,   355,   536,   210,   666,
     667,   529,   530,   356,    18,   149,   205,   271,   106,   306,
     650,   651,   357,   702,   703,   358,   705,   706,   307,   159,
     160,   215,   216,    63,   115,    64,   162,    65,   116,    66,
     161,    67,    19,    20,    21,    22,   136,    23,   137,   200,
     201,    71,    72,    73,    74,    75,   179,    24,    25,    26,
      27,    28,    77,    78,    79,    80,    81,    82,   152,   153,
      29,   145,    84,    85,    86,   359,   247,   270,   509,    88,
      89,   176,   177,    90,    91,   169,    92,   168,   360,   237,
     238,   361,   240,   241,   194,   246,   295,   195,   243,   497,
     498,   807,   499,   769,   500,   804,   501,   839,   502,   503,
     362,   196,   244,   363,   364,   365,   671,   366,   197,   245,
     440,   441,   367,   443,   444,   445,   446,   447,   448,   449,
     450,   451,   452,   453,   454,   455,   456,   457,   458,   459,
     460,   461,   462,   463,   464,   465,   466,   467,   468,   469,
     470,   471,   472,   473,   474,   475,   476,   477,   478,   479,
     480,   481,   482,   483,   484,   485,   486,   487,   488,   368,
     369,   370,   371,   622,   623,   264,   310,   630,   631,   372,
     643,   644,   523,   565,   373,   374,   492,   375,   376,   377,
     378,   379,   380,   381,   690,   382,   383,   384,   385,   699,
     700,   386,   493,   387,   388,   389,   637,   638,   390,   391,
     524,   566,   657,   519,   551,   654,   315,   316,   317,   525,
     658,   520,   552,   543,   655,   231,   223,   224,   225,   813,
     787,   226,   287,   227,   289,   228,   291,   229,   230,   816,
     256,   821,   326,   282,   327,   534,   328,   284,   494,   766,
     826,   319,   320
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      87,    61,   234,   235,   278,   330,   211,   311,   309,   521,
     504,   312,   313,   314,   489,   505,   439,   442,   491,   260,
     261,     8,   392,   495,   496,   495,   496,   495,   496,   615,
     490,   506,   723,   279,   297,   753,   668,   279,   564,   619,
     786,   188,   189,   190,    17,   202,    60,    62,   142,   143,
     144,   311,   309,    87,    61,   312,   313,   314,   507,    35,
     217,    17,   268,   297,   333,   334,   333,   334,   333,   334,
      68,     5,     6,    41,    42,     1,     2,   785,   269,    69,
     777,   163,    30,   298,    70,   331,   332,   781,    76,    83,
     108,   563,    93,   822,   285,    94,   333,   334,   191,    60,
      62,   164,    41,    42,    11,    12,    13,    14,   248,    95,
     335,   336,   789,   508,   254,   614,   798,   829,   286,   830,
     173,   174,   175,    68,   148,   103,   104,   299,   280,   299,
     299,   299,    69,    96,  -216,   165,    97,    70,  -216,   300,
      98,    76,    83,   812,    99,   301,   302,   274,   275,   276,
     325,   662,   663,   664,   665,   337,   338,   771,   150,   151,
     100,   489,   101,   439,   442,   491,   154,   155,   300,   281,
     102,   782,   107,   724,   301,   302,   754,   490,   620,     5,
       6,   218,   219,   220,   221,     7,     8,     9,    10,   693,
     694,   695,   696,   697,   698,   111,   218,   219,   220,   221,
     222,   811,   767,   645,   646,   647,   648,   112,   817,   616,
     617,   618,    11,    12,    13,    14,   113,   504,   184,   185,
     186,   187,   505,   303,   114,   303,   303,   303,   218,   219,
     304,   221,   222,   213,   214,   305,    15,   132,   506,   218,
     219,   220,   221,   222,   339,   625,   626,   627,   628,   629,
     340,   341,   342,   117,   343,   303,   518,   549,    16,   262,
     263,  -216,   148,  -216,   344,   556,   557,   308,   345,   346,
     347,   348,   349,   350,   351,   632,   633,   634,   635,   636,
     641,   642,   180,   181,   352,   353,   680,   681,   133,   685,
     686,   134,   624,   707,   708,   726,   727,   740,   741,   742,
     743,   744,   745,   755,   756,   805,   806,   757,   758,   759,
     760,   308,   118,   265,   266,   119,   135,   120,   121,   674,
     673,   138,   122,   139,   123,   140,   141,   124,   125,   126,
     158,   127,   128,   129,   489,   504,   439,   442,   491,   146,
     505,   147,   170,   156,   157,   171,   166,   167,   778,   172,
     490,   178,   182,   183,   198,   199,   506,   203,   204,   207,
     208,   209,   236,   239,   249,   250,   251,   252,   253,   255,
     321,   272,   257,   258,   259,   267,   273,   288,   290,   292,
     293,   318,   528,   294,   296,   322,   323,   324,   533,   510,
     311,   309,   511,   329,   312,   313,   314,    31,   518,   522,
       5,     6,    32,   512,   527,   513,     7,     8,     9,    10,
     514,   515,   516,   517,    33,    34,   537,    35,   538,   539,
      36,    37,    38,   540,   542,   541,   544,   621,   545,    39,
      40,    41,    42,    11,    12,    13,    14,   546,   547,    43,
      44,   548,   553,   554,   555,   558,   559,   639,   560,   561,
     562,   568,   640,    45,    46,    47,   569,    15,   570,   653,
     571,   656,   660,   572,   573,   574,   575,   576,    48,   577,
     578,   579,   580,    49,    50,    51,   581,   582,   672,    16,
     583,   675,   584,   585,   586,   587,   588,   589,   590,   591,
     592,   593,   594,   549,   687,   595,   596,   597,   682,   598,
     599,   600,   601,   602,   603,   604,   677,     5,     6,   605,
     606,   788,   669,   678,   649,   607,   608,   679,   783,   784,
     609,   331,   332,   688,   691,   610,   611,   612,   613,   652,
     692,   701,   333,   334,   704,   689,   659,   676,    41,    42,
      11,    12,    13,    14,   670,   684,   335,   336,   711,   710,
     712,   716,   713,   714,   836,   715,   717,   718,   719,   721,
     720,   722,   725,   729,   733,   728,   734,   735,   730,   831,
     832,   731,   732,   746,    52,    53,    54,   736,   747,   737,
     748,   749,   751,   739,   752,   738,   750,   761,   762,   764,
     768,   337,   763,   393,   765,   299,   770,   779,   790,   334,
     799,   800,   803,   780,   300,   808,   820,   280,   823,   792,
     301,   302,    55,   796,   814,   815,   801,   824,   797,   825,
     394,   395,   396,   397,   398,   818,   399,   400,   401,   402,
     403,   404,   405,   406,   407,   802,   408,   809,   409,   410,
     411,   412,   413,   819,   414,   415,   416,   649,   810,   417,
     308,   418,   419,   420,   421,   422,   837,   834,   835,   838,
     423,   840,   424,   425,   426,   427,   428,   429,   430,   431,
     432,   433,   434,   435,   436,   437,   827,   828,   841,   131,
     339,   776,   661,   794,   193,   212,   340,   341,   342,   105,
     343,   303,   795,   206,   242,   304,   791,   775,   793,   709,
     344,   772,   774,   773,   683,   346,   347,   348,   349,   350,
     351,   550,   567,   232,   233,   283,   833,   526,   438,     0,
     352,   353
};

static const yytype_int16 yycheck[] =
{
       4,     4,   167,   167,   253,   284,   157,   271,   271,   315,
     295,   271,   271,   271,   294,   295,   294,   294,   294,   238,
     241,    29,   293,     6,     7,     6,     7,     6,     7,   441,
     294,   295,   105,   105,    14,   105,   532,   105,   363,   502,
     676,    16,    17,    18,     2,   137,     4,     4,   207,   208,
     209,   315,   315,    57,    57,   315,   315,   315,    50,    39,
     162,    19,    89,    14,    47,    48,    47,    48,    47,    48,
       4,    22,    23,    53,    54,    82,    83,   671,   105,     4,
     652,    45,     0,    63,     4,    36,    37,   659,     4,     4,
     242,   362,   241,   788,   105,   241,    47,    48,    73,    57,
      57,    65,    53,    54,    55,    56,    57,    58,   200,   241,
      61,    62,   684,   105,   216,   440,   710,   812,   129,   814,
      91,    92,    93,    57,    99,   102,   103,   110,   200,   110,
     110,   110,    57,   241,   117,    99,   241,    57,   117,   119,
     241,    57,    57,   779,   241,   125,   126,    33,    34,    35,
     218,     9,    10,    11,    12,   106,   107,   620,    20,    21,
     241,   441,   241,   441,   441,   441,    25,    26,   119,   241,
     241,   667,   241,   246,   125,   126,   246,   441,   503,    22,
      23,   129,   130,   131,   132,    28,    29,    30,    31,   226,
     227,   228,   229,   230,   231,   241,   129,   130,   131,   132,
     133,   134,   614,   211,   212,   213,   214,   241,   780,     3,
       4,     5,    55,    56,    57,    58,   241,   502,   239,   240,
     239,   240,   502,   206,   241,   206,   206,   206,   129,   130,
     210,   132,   133,   129,   130,   215,    79,    88,   502,   129,
     130,   131,   132,   133,   195,   111,   112,   113,   114,   115,
     201,   202,   203,   241,   205,   206,   117,   118,   101,   237,
     238,   244,    99,   244,   215,   241,   242,   271,   219,   220,
     221,   222,   223,   224,   225,   120,   121,   122,   123,   124,
     207,   208,   124,   125,   235,   236,   239,   240,   105,   239,
     240,   105,   511,   564,   565,   239,   240,   239,   240,   239,
     240,   239,   240,   239,   240,   216,   217,   239,   240,   239,
     240,   315,   241,   244,   245,   241,   105,   241,   241,   540,
     539,   105,   241,   105,   241,   105,   105,   241,   241,   241,
      40,   241,   241,   241,   614,   620,   614,   614,   614,   241,
     620,   241,   105,   242,   242,   105,   241,   241,   654,    78,
     614,    94,    59,    59,   242,    32,   620,   105,   105,   242,
     242,    60,    64,    64,   243,    74,    74,   242,   242,   104,
      81,   241,   245,   245,   245,   243,   241,   105,   105,   243,
     243,   105,    38,   243,   241,   241,   241,   241,   105,   241,
     654,   654,   241,   246,   654,   654,   654,    19,   117,   117,
      22,    23,    24,   241,   245,   241,    28,    29,    30,    31,
     241,   241,   241,   241,    36,    37,   241,    39,   241,   241,
      42,    43,    44,   241,   118,   241,   241,    15,   241,    51,
      52,    53,    54,    55,    56,    57,    58,   241,   241,    61,
      62,   241,   241,   241,   241,   241,   241,   128,   241,   241,
     241,   241,   127,    75,    76,    77,   241,    79,   241,   100,
     241,   118,   105,   241,   241,   241,   241,   241,    90,   241,
     241,   241,   241,    95,    96,    97,   241,   241,   105,   101,
     241,   105,   241,   241,   241,   241,   241,   241,   241,   241,
     241,   241,   241,   118,   105,   241,   241,   241,   218,   241,
     241,   241,   241,   241,   241,   241,   199,    22,    23,   241,
     241,   676,   242,   204,   517,   241,   241,   204,   669,   670,
     241,    36,    37,   105,   105,   241,   241,   241,   241,   241,
     105,    94,    47,    48,    46,   232,   241,   241,    53,    54,
      55,    56,    57,    58,   242,   241,    61,    62,   109,   241,
     192,   140,   192,   192,   833,   192,   140,   140,   193,   105,
     194,   105,   105,   191,   158,   152,   158,   158,   191,   818,
     819,   191,   191,   176,   196,   197,   198,   162,   140,   165,
     140,   140,   105,   162,   105,   165,   176,   191,   152,   194,
     242,   106,   193,   108,   105,   110,   241,   241,   245,    48,
     105,   105,    13,   241,   119,   105,   104,   200,   105,   245,
     125,   126,   234,   244,   779,   779,   246,   105,   244,   105,
     135,   136,   137,   138,   139,   242,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   244,   151,   244,   153,   154,
     155,   156,   157,   242,   159,   160,   161,   650,   244,   164,
     654,   166,   167,   168,   169,   170,    98,   105,   105,    98,
     175,   105,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   241,   245,   105,    57,
     195,   650,   530,   703,   130,   159,   201,   202,   203,    19,
     205,   206,   706,   152,   176,   210,   690,   644,   699,   566,
     215,   622,   637,   631,   550,   220,   221,   222,   223,   224,
     225,   344,   392,   167,   167,   255,   820,   319,   233,    -1,
     235,   236
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,    82,    83,   248,   249,    22,    23,    28,    29,    30,
      31,    55,    56,    57,    58,    79,   101,   270,   271,   299,
     300,   301,   302,   304,   314,   315,   316,   317,   318,   327,
       0,    19,    24,    36,    37,    39,    42,    43,    44,    51,
      52,    53,    54,    61,    62,    75,    76,    77,    90,    95,
      96,    97,   196,   197,   198,   234,   252,   253,   257,   259,
     270,   271,   285,   290,   292,   294,   296,   298,   301,   302,
     304,   308,   309,   310,   311,   312,   318,   319,   320,   321,
     322,   323,   324,   327,   329,   330,   331,   332,   336,   337,
     340,   341,   343,   241,   241,   241,   241,   241,   241,   241,
     241,   241,   241,   102,   103,   300,   275,   241,   242,   258,
     260,   241,   241,   241,   241,   291,   295,   241,   241,   241,
     241,   241,   241,   241,   241,   241,   241,   241,   241,   241,
     250,   252,    88,   105,   105,   105,   303,   305,   105,   105,
     105,   105,   207,   208,   209,   328,   241,   241,    99,   272,
      20,    21,   325,   326,    25,    26,   242,   242,    40,   286,
     287,   297,   293,    45,    65,    99,   241,   241,   344,   342,
     105,   105,    78,    91,    92,    93,   338,   339,    94,   313,
     313,   313,    59,    59,   239,   240,   239,   240,    16,    17,
      18,    73,   251,   272,   351,   354,   368,   375,   242,    32,
     306,   307,   307,   105,   105,   273,   326,   242,   242,    60,
     265,   265,   287,   129,   130,   288,   289,   288,   129,   130,
     131,   132,   133,   483,   484,   485,   488,   490,   492,   494,
     495,   482,   488,   490,   494,   495,    64,   346,   347,    64,
     349,   350,   339,   355,   369,   376,   352,   333,   307,   243,
      74,    74,   242,   242,   288,   104,   497,   245,   245,   245,
     346,   349,   237,   238,   432,   432,   432,   243,    89,   105,
     334,   274,   241,   241,    33,    34,    35,   254,   254,   105,
     200,   241,   500,   501,   504,   105,   129,   489,   105,   491,
     105,   493,   243,   243,   243,   353,   241,    14,    63,   110,
     119,   125,   126,   206,   210,   215,   276,   285,   332,   429,
     433,   436,   460,   461,   462,   473,   474,   475,   105,   508,
     509,    81,   241,   241,   241,   218,   499,   501,   503,   246,
     499,    36,    37,    47,    48,    61,    62,   106,   107,   195,
     201,   202,   203,   205,   215,   219,   220,   221,   222,   223,
     224,   225,   235,   236,   261,   263,   270,   279,   282,   332,
     345,   348,   367,   370,   371,   372,   374,   379,   426,   427,
     428,   429,   436,   441,   442,   444,   445,   446,   447,   448,
     449,   450,   452,   453,   454,   455,   458,   460,   461,   462,
     465,   466,   370,   108,   135,   136,   137,   138,   139,   141,
     142,   143,   144,   145,   146,   147,   148,   149,   151,   153,
     154,   155,   156,   157,   159,   160,   161,   164,   166,   167,
     168,   169,   170,   175,   177,   178,   179,   180,   181,   182,
     183,   184,   185,   186,   187,   188,   189,   190,   233,   276,
     377,   378,   379,   380,   381,   382,   383,   384,   385,   386,
     387,   388,   389,   390,   391,   392,   393,   394,   395,   396,
     397,   398,   399,   400,   401,   402,   403,   404,   405,   406,
     407,   408,   409,   410,   411,   412,   413,   414,   415,   416,
     417,   418,   419,   420,   421,   422,   423,   424,   425,   433,
     436,   442,   443,   459,   505,     6,     7,   356,   357,   359,
     361,   363,   365,   366,   371,   433,   436,    50,   105,   335,
     241,   241,   241,   241,   241,   241,   241,   241,   117,   470,
     478,   474,   117,   439,   467,   476,   509,   245,    38,   268,
     269,   255,   256,   105,   502,   262,   264,   241,   241,   241,
     241,   241,   118,   480,   241,   241,   241,   241,   241,   118,
     470,   471,   479,   241,   241,   241,   241,   242,   241,   241,
     241,   241,   241,   370,   439,   440,   468,   476,   241,   241,
     241,   241,   241,   241,   241,   241,   241,   241,   241,   241,
     241,   241,   241,   241,   241,   241,   241,   241,   241,   241,
     241,   241,   241,   241,   241,   241,   241,   241,   241,   241,
     241,   241,   241,   241,   241,   241,   241,   241,   241,   241,
     241,   241,   241,   241,   439,   377,     3,     4,     5,   366,
     439,    15,   430,   431,   346,   111,   112,   113,   114,   115,
     434,   435,   120,   121,   122,   123,   124,   463,   464,   128,
     127,   207,   208,   437,   438,   211,   212,   213,   214,   271,
     277,   278,   241,   100,   472,   481,   118,   469,   477,   241,
     105,   268,     9,    10,    11,    12,   266,   267,   266,   242,
     242,   373,   105,   346,   349,   105,   241,   199,   204,   204,
     239,   240,   218,   471,   241,   239,   240,   105,   105,   232,
     451,   105,   105,   226,   227,   228,   229,   230,   231,   456,
     457,    94,   280,   281,    46,   283,   284,   370,   370,   469,
     241,   109,   192,   192,   192,   192,   140,   140,   140,   193,
     194,   105,   105,   105,   246,   105,   239,   240,   152,   191,
     191,   191,   191,   158,   158,   158,   162,   165,   165,   162,
     239,   240,   239,   240,   239,   240,   176,   140,   140,   140,
     176,   105,   105,   105,   246,   239,   240,   239,   240,   239,
     240,   191,   152,   193,   194,   105,   506,   377,   242,   360,
     241,   366,   431,   434,   464,   437,   278,   484,   474,   241,
     241,   484,   266,   265,   265,   483,   485,   487,   494,   484,
     245,   374,   245,   457,   280,   283,   244,   244,   483,   105,
     105,   246,   244,    13,   362,   216,   217,   358,   105,   244,
     244,   134,   485,   486,   494,   495,   496,   484,   242,   242,
     104,   498,   498,   105,   105,   105,   507,   241,   245,   498,
     498,   254,   254,   504,   105,   105,   499,    98,    98,   364,
     105,   105
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   247,   249,   248,   248,   250,   250,   251,   251,   251,
     251,   251,   252,   252,   253,   253,   253,   253,   253,   253,
     253,   253,   253,   253,   253,   253,   253,   253,   253,   253,
     253,   253,   253,   253,   253,   253,   253,   253,   253,   253,
     253,   254,   255,   254,   256,   254,   258,   257,   260,   259,
     262,   261,   264,   263,   265,   266,   266,   267,   267,   267,
     267,   268,   268,   269,   270,   270,   270,   270,   271,   273,
     274,   272,   275,   275,   276,   277,   277,   277,   277,   277,
     278,   278,   279,   280,   281,   281,   282,   283,   284,   284,
     285,   286,   287,   287,   288,   288,   289,   289,   290,   291,
     293,   292,   294,   295,   297,   296,   298,   298,   298,   299,
     299,   299,   299,   299,   299,   299,   300,   300,   301,   301,
     303,   302,   305,   304,   306,   307,   307,   308,   308,   309,
     309,   309,   310,   311,   312,   313,   314,   314,   314,   315,
     316,   317,   318,   319,   319,   320,   321,   322,   322,   323,
     323,   324,   325,   325,   326,   326,   327,   328,   328,   328,
     329,   329,   330,   331,   333,   332,   334,   334,   335,   335,
     336,   336,   337,   338,   338,   338,   339,   339,   340,   342,
     341,   344,   343,   345,   346,   346,   347,   348,   349,   349,
     350,   352,   353,   351,   355,   354,   356,   356,   356,   357,
     357,   357,   358,   358,   358,   360,   359,   361,   362,   363,
     364,   364,   365,   365,   365,   365,   366,   366,   367,   367,
     367,   367,   367,   369,   368,   370,   370,   371,   371,   373,
     372,   374,   376,   375,   377,   377,   378,   378,   378,   378,
     378,   378,   378,   378,   378,   379,   379,   379,   379,   379,
     379,   379,   379,   379,   379,   379,   379,   379,   379,   379,
     379,   379,   379,   379,   379,   380,   380,   380,   380,   380,
     380,   380,   380,   380,   380,   380,   380,   380,   380,   380,
     380,   381,   381,   381,   381,   381,   381,   381,   381,   381,
     381,   381,   381,   381,   381,   381,   381,   381,   381,   381,
     381,   381,   381,   381,   381,   381,   381,   381,   381,   382,
     382,   383,   383,   384,   385,   386,   387,   388,   389,   390,
     391,   392,   393,   394,   395,   396,   397,   398,   399,   400,
     401,   402,   403,   403,   404,   404,   405,   405,   406,   406,
     407,   407,   408,   408,   409,   409,   410,   411,   412,   413,
     414,   415,   416,   417,   418,   419,   420,   421,   422,   423,
     424,   425,   426,   427,   428,   428,   429,   430,   431,   431,
     432,   432,   433,   434,   434,   435,   435,   435,   435,   435,
     436,   437,   437,   438,   438,   439,   440,   441,   441,   441,
     442,   442,   442,   443,   444,   444,   445,   445,   446,   447,
     448,   448,   448,   448,   449,   451,   450,   452,   453,   454,
     455,   456,   456,   456,   456,   456,   456,   457,   457,   458,
     459,   460,   461,   462,   463,   463,   463,   463,   463,   464,
     464,   465,   466,   467,   468,   469,   470,   471,   472,   473,
     473,   473,   473,   473,   473,   473,   473,   473,   473,   473,
     474,   474,   475,   476,   477,   478,   479,   480,   481,   482,
     482,   482,   482,   483,   483,   483,   484,   485,   485,   485,
     485,   485,   485,   486,   486,   486,   486,   487,   487,   488,
     489,   489,   490,   491,   492,   493,   494,   495,   496,   497,
     497,   497,   497,   498,   498,   499,   499,   500,   501,   502,
     503,   504,   505,   506,   507,   508,   509,   509
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     4,     3,     0,     2,     1,     1,     1,
       1,     1,     0,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     3,     0,     4,     0,     4,     0,     6,     0,     6,
       0,     6,     0,     6,     1,     1,     2,     1,     1,     1,
       1,     1,     2,     1,     1,     1,     1,     1,     1,     0,
       0,     9,     0,     2,     3,     1,     1,     1,     1,     1,
       1,     2,     3,     1,     1,     2,     3,     1,     1,     2,
       3,     1,     1,     2,     1,     2,     1,     1,     4,     0,
       0,     4,     4,     0,     0,     4,     3,     3,     3,     1,
       1,     1,     1,     1,     1,     1,     0,     2,     4,     4,
       0,     4,     0,     4,     1,     1,     2,     3,     3,     1,
       1,     1,     3,     3,     3,     1,     3,     3,     3,     3,
       3,     3,     3,     1,     1,     3,     3,     3,     3,     3,
       3,     3,     1,     1,     1,     2,     3,     1,     1,     1,
       1,     1,     9,     7,     0,     7,     1,     1,     1,     1,
       1,     1,     3,     1,     1,     1,     1,     2,     3,     0,
       4,     0,     4,     3,     1,     2,     1,     3,     1,     2,
       1,     0,     0,     8,     0,     8,     1,     1,     1,     0,
       1,     1,     0,     1,     1,     0,     8,     4,     1,     7,
       0,     2,     1,     1,     1,     1,     0,     2,     1,     1,
       1,     1,     1,     0,     8,     0,     2,     1,     1,     0,
       4,     3,     0,     8,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       4,     3,     4,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     1,     1,     2,
       1,     1,     3,     1,     2,     1,     1,     1,     1,     1,
       3,     1,     2,     1,     1,     2,     2,     3,     2,     2,
       1,     1,     1,     1,     1,     1,     3,     3,     3,     5,
       1,     1,     1,     1,     3,     0,     4,     3,     5,     3,
       3,     1,     1,     1,     1,     1,     1,     1,     2,     3,
       3,     3,     3,     3,     1,     1,     1,     1,     1,     1,
       2,     4,     3,     3,     3,     3,     3,     3,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     2,     1,
       0,     2,     3,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     3,     1,     3,
       1,     3,     1,     2,     2,     1,     1,     2,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     0,
       3,     3,     2,     0,     3,     1,     1,     3,     1,     1,
       1,     1,     5,     1,     1,     1,     1,     2
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return (YYSIZE_T) (yystpcpy (yyres, yystr) - yyres);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yynewstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  *yyssp = (yytype_int16) yystate;

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = (YYSIZE_T) (yyssp - yyss + 1);

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 653 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
#line 2837 "config_parse.c" /* yacc.c:1652  */
    break;

  case 5:
#line 661 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 2843 "config_parse.c" /* yacc.c:1652  */
    break;

  case 12:
#line 672 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 2849 "config_parse.c" /* yacc.c:1652  */
    break;

  case 40:
#line 701 "config_parse.y" /* yacc.c:1652  */
    {
      if (!addedsocketoption(&sockscf.socketoptionc,
                             &sockscf.socketoptionv,
                             &socketopt))
         yywarn("could not add socket option");
   }
#line 2860 "config_parse.c" /* yacc.c:1652  */
    break;

  case 42:
#line 710 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                                tcpoptions = &logspecial->protocol.tcp.disabled;
#endif /* !SOCKS_CLIENT */
          }
#line 2870 "config_parse.c" /* yacc.c:1652  */
    break;

  case 44:
#line 715 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                                tcpoptions = &logspecial->protocol.tcp.enabled;
#endif /* !SOCKS_CLIENT */
          }
#line 2880 "config_parse.c" /* yacc.c:1652  */
    break;

  case 46:
#line 723 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

      logspecial = &sockscf.internal.log;

#endif /* !SOCKS_CLIENT */

   }
#line 2893 "config_parse.c" /* yacc.c:1652  */
    break;

  case 48:
#line 733 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

      logspecial = &sockscf.external.log;

#endif /* !SOCKS_CLIENT */

   }
#line 2906 "config_parse.c" /* yacc.c:1652  */
    break;

  case 50:
#line 743 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

      logspecial = &rule.internal.log;

#endif /* !SOCKS_CLIENT */

   }
#line 2919 "config_parse.c" /* yacc.c:1652  */
    break;

  case 52:
#line 753 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

      logspecial = &rule.external.log;

#endif /* !SOCKS_CLIENT */

   }
#line 2932 "config_parse.c" /* yacc.c:1652  */
    break;

  case 54:
#line 764 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   SASSERTX((yyvsp[0].number) >= 0);
   SASSERTX((yyvsp[0].number) < MAXLOGLEVELS);

   cloglevel = (yyvsp[0].number);
#endif /* !SOCKS_CLIENT */
   }
#line 2945 "config_parse.c" /* yacc.c:1652  */
    break;

  case 57:
#line 778 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, ecn);
#endif /* !SOCKS_CLIENT */
   }
#line 2955 "config_parse.c" /* yacc.c:1652  */
    break;

  case 58:
#line 785 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, sack);
#endif /* !SOCKS_CLIENT */
   }
#line 2965 "config_parse.c" /* yacc.c:1652  */
    break;

  case 59:
#line 792 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, timestamps);
#endif /* !SOCKS_CLIENT */
   }
#line 2975 "config_parse.c" /* yacc.c:1652  */
    break;

  case 60:
#line 799 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, wscale);
#endif /* !SOCKS_CLIENT */
   }
#line 2985 "config_parse.c" /* yacc.c:1652  */
    break;

  case 63:
#line 812 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

   if ((yyvsp[0].error).valuev == NULL)
      yywarnx("unknown error symbol specified");
   else {
      size_t *ec, ec_max, i;
      int *ev;

      switch ((yyvsp[0].error).valuetype) {
         case VALUETYPE_ERRNO:
            ev     = logspecial->errno_loglevelv[cloglevel];
            ec     = &logspecial->errno_loglevelc[cloglevel];
            ec_max = ELEMENTS(logspecial->errno_loglevelv[cloglevel]);
            break;

         case VALUETYPE_GAIERR:
            ev     = logspecial->gaierr_loglevelv[cloglevel];
            ec     = &logspecial->gaierr_loglevelc[cloglevel];
            ec_max = ELEMENTS(logspecial->gaierr_loglevelv[cloglevel]);
            break;

         default:
            SERRX((yyvsp[0].error).valuetype);
      }

      for (i = 0; (yyvsp[0].error).valuev[i] != 0; ++i) {
         /*
          * If the value is already set in the array, e.g. because some
          * errno-symbols have the same values, ignore this value.
          */
         size_t j;

         for (j = 0; j < *ec; ++j) {
            if (ev[j] == (yyvsp[0].error).valuev[i])
               break;
         }

         if (j < *ec)
            continue; /* error-value already set in array. */

         SASSERTX(*ec < ec_max);

         ev[(*ec)] = (yyvsp[0].error).valuev[i];
         ++(*ec);
      }
   }
#endif /* !SOCKS_CLIENT */
   }
#line 3039 "config_parse.c" /* yacc.c:1652  */
    break;

  case 68:
#line 870 "config_parse.y" /* yacc.c:1652  */
    {
      yyerrorx("given keyword \"%s\" is deprecated.  New keyword is %s.  "
               "Please see %s's manual for more information",
               (yyvsp[0].deprecated).oldname, (yyvsp[0].deprecated).newname, PRODUCT);
   }
#line 3049 "config_parse.c" /* yacc.c:1652  */
    break;

  case 69:
#line 877 "config_parse.y" /* yacc.c:1652  */
    { objecttype = object_route; }
#line 3055 "config_parse.c" /* yacc.c:1652  */
    break;

  case 70:
#line 878 "config_parse.y" /* yacc.c:1652  */
    { routeinit(&route); }
#line 3061 "config_parse.c" /* yacc.c:1652  */
    break;

  case 71:
#line 878 "config_parse.y" /* yacc.c:1652  */
    {
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;

      route.rdr_from  = rdr_from;

      socks_addroute(&route, 1);
   }
#line 3075 "config_parse.c" /* yacc.c:1652  */
    break;

  case 72:
#line 889 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 3081 "config_parse.c" /* yacc.c:1652  */
    break;

  case 75:
#line 895 "config_parse.y" /* yacc.c:1652  */
    {
         state->proxyprotocol.socks_v4 = 1;
   }
#line 3089 "config_parse.c" /* yacc.c:1652  */
    break;

  case 76:
#line 898 "config_parse.y" /* yacc.c:1652  */
    {
         state->proxyprotocol.socks_v5 = 1;
   }
#line 3097 "config_parse.c" /* yacc.c:1652  */
    break;

  case 77:
#line 901 "config_parse.y" /* yacc.c:1652  */
    {
         state->proxyprotocol.http     = 1;
   }
#line 3105 "config_parse.c" /* yacc.c:1652  */
    break;

  case 78:
#line 904 "config_parse.y" /* yacc.c:1652  */
    {
         state->proxyprotocol.upnp     = 1;
   }
#line 3113 "config_parse.c" /* yacc.c:1652  */
    break;

  case 83:
#line 917 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.user, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
#line 3124 "config_parse.c" /* yacc.c:1652  */
    break;

  case 87:
#line 932 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
#line 3135 "config_parse.c" /* yacc.c:1652  */
    break;

  case 91:
#line 947 "config_parse.y" /* yacc.c:1652  */
    {
         yywarnx("we are currently considering deprecating the Dante-specific "
                 "SOCKS bind extension.  If you are using it, please let us "
                 "know on the public dante-misc@inet.no mailinglist");

         extension->bind = 1;
   }
#line 3147 "config_parse.c" /* yacc.c:1652  */
    break;

  case 96:
#line 965 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ifproto->ipv4  = 1;
   }
#line 3156 "config_parse.c" /* yacc.c:1652  */
    break;

  case 97:
#line 969 "config_parse.y" /* yacc.c:1652  */
    {
      ifproto->ipv6  = 1;
#endif /* SOCKS_SERVER */
   }
#line 3165 "config_parse.c" /* yacc.c:1652  */
    break;

  case 98:
#line 975 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if BAREFOOTD
      yyerrorx("\"internal:\" specification is not used in %s", PRODUCT);
#endif /* BAREFOOTD */

      interfaceprotocol_t ifprotozero;

      bzero(&ifprotozero, sizeof(ifprotozero));
      if (memcmp(&ifprotozero,
                 &sockscf.internal.protocol,
                 sizeof(sockscf.internal.protocol)) == 0) {
         slog(LOG_DEBUG, "%s: no address families explicitly enabled on "
                         "internal interface.  Enabling default address "
                         "families",
                         function);

         sockscf.internal.protocol.ipv4 = sockscf.internal.protocol.ipv6 = 1;
      }

      addinternal(ruleaddr, SOCKS_TCP);
#endif /* !SOCKS_CLIENT */
   }
#line 3193 "config_parse.c" /* yacc.c:1652  */
    break;

  case 99:
#line 1000 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   static ruleaddr_t mem;
   struct servent    *service;
   serverstate_t     statemem;

   bzero(&statemem, sizeof(statemem));
   state               = &statemem;
   state->protocol.tcp = 1;

   bzero(&logspecial, sizeof(logspecial));

   bzero(&mem, sizeof(mem));
   addrinit(&mem, 0);

   /* set default port. */
   if ((service = getservbyname("socks", "tcp")) == NULL)
      *port_tcp = htons(SOCKD_PORT);
   else
      *port_tcp = (in_port_t)service->s_port;
#endif /* !SOCKS_CLIENT */
   }
#line 3220 "config_parse.c" /* yacc.c:1652  */
    break;

  case 100:
#line 1024 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      if (sockscf.internal.addrc > 0) {
         if (sockscf.state.inited) {
            /*
             * Must be running due to SIGHUP.  The internal interface requires
             * special considerations, so let the SIGHUP code deal with this
             * later when we know if the change in protocol also results in.
             * adding a new interface.
             */
            ;
         }
         else {
            log_interfaceprotocol_set_too_late(INTERNALIF);
            exit(1);
         }
      }

      ifproto = &sockscf.internal.protocol;
#endif /* !SOCKS_CLIENT */
   }
#line 3246 "config_parse.c" /* yacc.c:1652  */
    break;

  case 102:
#line 1049 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
#line 3256 "config_parse.c" /* yacc.c:1652  */
    break;

  case 103:
#line 1056 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      static ruleaddr_t mem;
      interfaceprotocol_t ifprotozero = { 0 };

      bzero(&mem, sizeof(mem));
      addrinit(&mem, 0);

      if (memcmp(&ifprotozero,
                 &sockscf.external.protocol,
                 sizeof(sockscf.external.protocol)) == 0) {
         slog(LOG_DEBUG, "%s: no address families explicitly enabled on "
                         "external interface.  Enabling default address "
                         "families",
                         function);

         sockscf.external.protocol.ipv4 = sockscf.external.protocol.ipv6 = 1;
      }
#endif /* !SOCKS_CLIENT */
   }
#line 3281 "config_parse.c" /* yacc.c:1652  */
    break;

  case 104:
#line 1078 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      if (sockscf.external.addrc > 0) {
         log_interfaceprotocol_set_too_late(EXTERNALIF);
         sockdexit(EXIT_FAILURE);
      }

      ifproto = &sockscf.external.protocol;
#endif /* !SOCKS_CLIENT */
   }
#line 3296 "config_parse.c" /* yacc.c:1652  */
    break;

  case 106:
#line 1091 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
#line 3305 "config_parse.c" /* yacc.c:1652  */
    break;

  case 107:
#line 1095 "config_parse.y" /* yacc.c:1652  */
    {
      sockscf.external.rotation = ROTATION_SAMESAME;
   }
#line 3313 "config_parse.c" /* yacc.c:1652  */
    break;

  case 108:
#line 1098 "config_parse.y" /* yacc.c:1652  */
    {
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* SOCKS_SERVER */
   }
#line 3322 "config_parse.c" /* yacc.c:1652  */
    break;

  case 116:
#line 1113 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 3328 "config_parse.c" /* yacc.c:1652  */
    break;

  case 118:
#line 1117 "config_parse.y" /* yacc.c:1652  */
    {
      if ((yyvsp[0].number) < 0)
         yyerrorx("max route fails can not be negative (%ld)  Use \"0\" to "
                  "indicate routes should never be marked as bad",
                  (long)(yyvsp[0].number));

      sockscf.routeoptions.maxfail = (yyvsp[0].number);
   }
#line 3341 "config_parse.c" /* yacc.c:1652  */
    break;

  case 119:
#line 1125 "config_parse.y" /* yacc.c:1652  */
    {
      if ((yyvsp[0].number) < 0)
         yyerrorx("route failure expiry time can not be negative (%ld).  "
                  "Use \"0\" to indicate bad route marking should never expire",
                  (long)(yyvsp[0].number));

      sockscf.routeoptions.badexpire = (yyvsp[0].number);
   }
#line 3354 "config_parse.c" /* yacc.c:1652  */
    break;

  case 120:
#line 1135 "config_parse.y" /* yacc.c:1652  */
    { add_to_errlog = 1; }
#line 3360 "config_parse.c" /* yacc.c:1652  */
    break;

  case 122:
#line 1138 "config_parse.y" /* yacc.c:1652  */
    { add_to_errlog = 0; }
#line 3366 "config_parse.c" /* yacc.c:1652  */
    break;

  case 124:
#line 1141 "config_parse.y" /* yacc.c:1652  */
    {
   int p;

   if ((add_to_errlog && failed_to_add_errlog)
   ||      (!add_to_errlog && failed_to_add_log)) {
      yywarnx("not adding logfile \"%s\"", (yyvsp[0].string));

      slog(LOG_ALERT,
           "%s: not trying to add logfile \"%s\" due to having already failed "
           "adding logfiles during this SIGHUP.  Only if all logfiles "
           "specified in the config can be added will we switch to using "
           "the new logfiles.  Until then, we will continue using only the "
           "old logfiles",
           function, (yyvsp[0].string));
   }
   else {
      p = socks_addlogfile(add_to_errlog ? &sockscf.errlog : &sockscf.log, (yyvsp[0].string));

#if !SOCKS_CLIENT
      if (sockscf.state.inited) {
         if (p == -1) {
            if (add_to_errlog) {
               sockscf.errlog       = old_errlog;
               failed_to_add_errlog = 1;
            }
            else {
               sockscf.log          = old_log;
               failed_to_add_log    = 1;
            }
         }
         else {
            sockd_freelogobject(add_to_errlog ?  &old_errlog : &old_log, 1);
            slog(LOG_DEBUG, "%s: added logfile \"%s\" to %s",
                 function, (yyvsp[0].string), add_to_errlog ? "errlog" : "logoutput");
         }
      }

      if (p == -1)
         slog(LOG_ALERT, "%s: could not (re)open logfile \"%s\": %s%s  %s",
              function,
              (yyvsp[0].string),
              strerror(errno),
              sockscf.state.inited ?
                  "." : "",
              sockscf.state.inited ?
                  "Will continue using old logfiles" : "");

#else /* SOCKS_CLIENT  */
      if (p == -1)
         /*
          * bad, but don't consider it fatal in the client.
          */
         yywarn("failed to add logfile %s", (yyvsp[0].string));
#endif /* SOCKS_CLIENT */
   }
}
#line 3427 "config_parse.c" /* yacc.c:1652  */
    break;

  case 127:
#line 1202 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, sockscf.child.maxrequests, 0);

#endif /* !SOCKS_CLIENT */
   }
#line 3439 "config_parse.c" /* yacc.c:1652  */
    break;

  case 128:
#line 1209 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, sockscf.child.maxlifetime, 0);

#endif /* !SOCKS_CLIENT */
   }
#line 3451 "config_parse.c" /* yacc.c:1652  */
    break;

  case 132:
#line 1223 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged_uid   = (yyvsp[0].uid).uid;
      sockscf.uid.privileged_gid   = (yyvsp[0].uid).gid;
      sockscf.uid.privileged_isset = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
#line 3467 "config_parse.c" /* yacc.c:1652  */
    break;

  case 133:
#line 1236 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged_uid   = (yyvsp[0].uid).uid;
      sockscf.uid.unprivileged_gid   = (yyvsp[0].uid).gid;
      sockscf.uid.unprivileged_isset = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
#line 3483 "config_parse.c" /* yacc.c:1652  */
    break;

  case 134:
#line 1249 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)

#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");

#else
      sockscf.uid.libwrap_uid   = (yyvsp[0].uid).uid;
      sockscf.uid.libwrap_gid   = (yyvsp[0].uid).gid;
      sockscf.uid.libwrap_isset = 1;
#endif /* !HAVE_PRIVILEGES */

#else  /* !HAVE_LIBWRAP && (!SOCKS_CLIENT) */
      yyerrorx_nolib("libwrap");
#endif /* !HAVE_LIBWRAP (!SOCKS_CLIENT)*/
   }
#line 3504 "config_parse.c" /* yacc.c:1652  */
    break;

  case 135:
#line 1268 "config_parse.y" /* yacc.c:1652  */
    {
      struct passwd *pw;

      if ((pw = getpwnam((yyvsp[0].string))) == NULL)
         yyerror("getpwnam(3) says no such user \"%s\"", (yyvsp[0].string));

      (yyval.uid).uid = pw->pw_uid;

      if ((pw = getpwuid((yyval.uid).uid)) == NULL)
         yyerror("getpwuid(3) says no such uid %lu (from user \"%s\")",
                 (unsigned long)(yyval.uid).uid, (yyvsp[0].string));

      (yyval.uid).gid = pw->pw_gid;
   }
#line 3523 "config_parse.c" /* yacc.c:1652  */
    break;

  case 136:
#line 1284 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, timeout->tcpio, 1);
      timeout->udpio = timeout->tcpio;
   }
#line 3533 "config_parse.c" /* yacc.c:1652  */
    break;

  case 137:
#line 1289 "config_parse.y" /* yacc.c:1652  */
    {
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, timeout->tcpio, 1);
   }
#line 3541 "config_parse.c" /* yacc.c:1652  */
    break;

  case 138:
#line 1292 "config_parse.y" /* yacc.c:1652  */
    {
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, timeout->udpio, 1);
#endif /* !SOCKS_CLIENT */
   }
#line 3550 "config_parse.c" /* yacc.c:1652  */
    break;

  case 139:
#line 1298 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, timeout->negotiate, 1);
#endif /* !SOCKS_CLIENT */
   }
#line 3560 "config_parse.c" /* yacc.c:1652  */
    break;

  case 140:
#line 1305 "config_parse.y" /* yacc.c:1652  */
    {
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, timeout->connect, 1);
   }
#line 3568 "config_parse.c" /* yacc.c:1652  */
    break;

  case 141:
#line 1310 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, timeout->tcp_fin_wait, 1);
#endif /* !SOCKS_CLIENT */
   }
#line 3578 "config_parse.c" /* yacc.c:1652  */
    break;

  case 142:
#line 1318 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_CLIENT

       sockscf.option.debug = (int)(yyvsp[0].number);

#else /* !SOCKS_CLIENT */

      if (sockscf.initial.cmdline.debug_isset
      &&  sockscf.initial.cmdline.debug != (yyvsp[0].number))
         LOG_CMDLINE_OVERRIDE("debug",
                              sockscf.initial.cmdline.debug,
                              (int)(yyvsp[0].number),
                              "%d");
      else
         sockscf.option.debug = (int)(yyvsp[0].number);

#endif /* !SOCKS_CLIENT */
   }
#line 3601 "config_parse.c" /* yacc.c:1652  */
    break;

  case 145:
#line 1342 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_allow_table  = strdup((yyvsp[0].string))) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "%s: libwrap.allow: %s", function, hosts_allow_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
#line 3618 "config_parse.c" /* yacc.c:1652  */
    break;

  case 146:
#line 1356 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_deny_table  = strdup((yyvsp[0].string))) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "%s: libwrap.deny: %s", function, hosts_deny_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
#line 3635 "config_parse.c" /* yacc.c:1652  */
    break;

  case 147:
#line 1370 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerrorx("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
#line 3648 "config_parse.c" /* yacc.c:1652  */
    break;

  case 148:
#line 1378 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
#line 3661 "config_parse.c" /* yacc.c:1652  */
    break;

  case 149:
#line 1388 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
#line 3670 "config_parse.c" /* yacc.c:1652  */
    break;

  case 150:
#line 1392 "config_parse.y" /* yacc.c:1652  */
    {
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
#line 3679 "config_parse.c" /* yacc.c:1652  */
    break;

  case 152:
#line 1402 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
#line 3688 "config_parse.c" /* yacc.c:1652  */
    break;

  case 153:
#line 1406 "config_parse.y" /* yacc.c:1652  */
    {
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 3697 "config_parse.c" /* yacc.c:1652  */
    break;

  case 157:
#line 1419 "config_parse.y" /* yacc.c:1652  */
    {
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
#line 3705 "config_parse.c" /* yacc.c:1652  */
    break;

  case 158:
#line 1422 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_NO_RESOLVESTUFF
         yyerrorx("resolveprotocol keyword not supported on this system");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
#line 3717 "config_parse.c" /* yacc.c:1652  */
    break;

  case 159:
#line 1429 "config_parse.y" /* yacc.c:1652  */
    {
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
#line 3725 "config_parse.c" /* yacc.c:1652  */
    break;

  case 162:
#line 1438 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETSCHEDULER
      yyerrorx("cpu scheduling policy is not supported on this system");
#else /* HAVE_SCHED_SETSCHEDULER */
      cpusetting_t *cpusetting;

      switch ((yyvsp[-4].number)) {
         case PROC_MOTHER:
            cpusetting = &sockscf.cpu.mother;
            break;

         case PROC_MONITOR:
            cpusetting = &sockscf.cpu.monitor;
            break;

         case PROC_NEGOTIATE:
            cpusetting = &sockscf.cpu.negotiate;
            break;

         case PROC_REQUEST:
            cpusetting = &sockscf.cpu.request;
            break;

         case PROC_IO:
            cpusetting = &sockscf.cpu.io;
            break;

         default:
            SERRX((yyvsp[-4].number));
      }

      bzero(&cpusetting->param, sizeof(cpusetting->param));

      cpusetting->scheduling_isset     = 1;
      cpusetting->policy               = (yyvsp[-2].number);
      cpusetting->param.sched_priority = (int)(yyvsp[0].number);
#endif /* HAVE_SCHED_SETSCHEDULER */
#endif /* !SOCKS_CLIENT */
   }
#line 3770 "config_parse.c" /* yacc.c:1652  */
    break;

  case 163:
#line 1480 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETAFFINITY
      yyerrorx("cpu scheduling affinity is not supported on this system");
#else /* HAVE_SCHED_SETAFFINITY */
      cpusetting_t *cpusetting;

      switch ((yyvsp[-2].number)) {
         case PROC_MOTHER:
            cpusetting = &sockscf.cpu.mother;
            break;

         case PROC_MONITOR:
            cpusetting = &sockscf.cpu.monitor;
            break;

         case PROC_NEGOTIATE:
            cpusetting = &sockscf.cpu.negotiate;
            break;

         case PROC_REQUEST:
            cpusetting = &sockscf.cpu.request;
            break;

         case PROC_IO:
            cpusetting = &sockscf.cpu.io;
            break;

         default:
            SERRX((yyvsp[-2].number));
      }

      cpu_zero(&cpusetting->mask);
      while (numberc-- > 0)
         if (numberv[numberc] == CPUMASK_ANYCPU) {
            const long cpus = sysconf(_SC_NPROCESSORS_ONLN);
            long i;

            if (cpus == -1)
               yyerror("sysconf(_SC_NPROCESSORS_ONLN) failed");

            for (i = 0; i < cpus; ++i)
               cpu_set((int)i, &cpusetting->mask);
         }
         else if (numberv[numberc] < 0)
            yyerrorx("invalid CPU number: %ld.  The CPU number can not be "
                     "negative", (long)numberv[numberc]);
         else
            cpu_set(numberv[numberc], &cpusetting->mask);

      free(numberv);
      numberv = NULL;
      numberc = 0;

      cpusetting->affinity_isset = 1;

#endif /* HAVE_SCHED_SETAFFINITY */
#endif /* !SOCKS_CLIENT */
   }
#line 3834 "config_parse.c" /* yacc.c:1652  */
    break;

  case 164:
#line 1541 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      socketopt.level = (yyvsp[-1].number);
#endif /* !SOCKS_CLIENT */
   }
#line 3844 "config_parse.c" /* yacc.c:1652  */
    break;

  case 166:
#line 1548 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   socketopt.optname = (yyvsp[0].number);
   socketopt.info    = optval2sockopt(socketopt.level, socketopt.optname);

   if (socketopt.info == NULL)
      slog(LOG_DEBUG,
           "%s: unknown/unsupported socket option: level %d, value %d",
           function, socketopt.level, socketopt.optname);
   else
      socketoptioncheck(&socketopt);
   }
#line 3861 "config_parse.c" /* yacc.c:1652  */
    break;

  case 167:
#line 1560 "config_parse.y" /* yacc.c:1652  */
    {
      socketopt.info           = optid2sockopt((size_t)(yyvsp[0].number));
      SASSERTX(socketopt.info != NULL);

      socketopt.optname        = socketopt.info->value;

      socketoptioncheck(&socketopt);
#endif /* !SOCKS_CLIENT */
   }
#line 3875 "config_parse.c" /* yacc.c:1652  */
    break;

  case 168:
#line 1571 "config_parse.y" /* yacc.c:1652  */
    {
      socketopt.optval.int_val = (int)(yyvsp[0].number);
      socketopt.opttype        = int_val;
   }
#line 3884 "config_parse.c" /* yacc.c:1652  */
    break;

  case 169:
#line 1575 "config_parse.y" /* yacc.c:1652  */
    {
      const sockoptvalsym_t *p;

      if (socketopt.info == NULL)
         yyerrorx("the given socket option is unknown, so can not lookup "
                  "symbolic option value");

      if ((p = optval2valsym(socketopt.info->optid, (yyvsp[0].string))) == NULL)
         yyerrorx("symbolic value \"%s\" is unknown for socket option %s",
                  (yyvsp[0].string), sockopt2string(&socketopt, NULL, 0));

      socketopt.optval  = p->symval;
      socketopt.opttype = socketopt.info->opttype;
   }
#line 3903 "config_parse.c" /* yacc.c:1652  */
    break;

  case 170:
#line 1592 "config_parse.y" /* yacc.c:1652  */
    { bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 1;
   }
#line 3911 "config_parse.c" /* yacc.c:1652  */
    break;

  case 171:
#line 1595 "config_parse.y" /* yacc.c:1652  */
    { bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 0;
   }
#line 3919 "config_parse.c" /* yacc.c:1652  */
    break;

  case 173:
#line 1604 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
#line 3928 "config_parse.c" /* yacc.c:1652  */
    break;

  case 174:
#line 1608 "config_parse.y" /* yacc.c:1652  */
    {
         sockscf.srchost.nodnsunknown = 1;
   }
#line 3936 "config_parse.c" /* yacc.c:1652  */
    break;

  case 175:
#line 1611 "config_parse.y" /* yacc.c:1652  */
    {
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 3945 "config_parse.c" /* yacc.c:1652  */
    break;

  case 178:
#line 1621 "config_parse.y" /* yacc.c:1652  */
    {
#if COVENANT
   STRCPY_CHECKLEN(sockscf.realmname,
                   (yyvsp[0].string),
                   sizeof(sockscf.realmname) - 1,
                   yyerrorx);
#else /* !COVENANT */
   yyerrorx("unknown keyword \"%s\"", (yyvsp[-2].string));
#endif /* !COVENANT */
}
#line 3960 "config_parse.c" /* yacc.c:1652  */
    break;

  case 179:
#line 1633 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT

   cmethodv  = sockscf.cmethodv;
   cmethodc  = &sockscf.cmethodc;
  *cmethodc  = 0; /* reset. */

#endif /* !SOCKS_CLIENT */
   }
#line 3974 "config_parse.c" /* yacc.c:1652  */
    break;

  case 181:
#line 1644 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_SOCKS_RULES

      smethodv  = sockscf.smethodv;
      smethodc  = &sockscf.smethodc;
     *smethodc  = 0; /* reset. */

#else
      yyerrorx("\"socksmethod\" is not used in %s.  Only \"clientmethod\" "
               "is used",
               PRODUCT);
#endif /* !HAVE_SOCKS_RULES */
   }
#line 3992 "config_parse.c" /* yacc.c:1652  */
    break;

  case 186:
#line 1666 "config_parse.y" /* yacc.c:1652  */
    {
      if (methodisvalid((yyvsp[0].method), object_srule))
         ADDMETHOD((yyvsp[0].method), *smethodc, smethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for socksmethods",
                  method2string((yyvsp[0].method)), (yyvsp[0].method));
   }
#line 4004 "config_parse.c" /* yacc.c:1652  */
    break;

  case 190:
#line 1683 "config_parse.y" /* yacc.c:1652  */
    {
      if (methodisvalid((yyvsp[0].method), object_crule))
         ADDMETHOD((yyvsp[0].method), *cmethodc, cmethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for clientmethods",
                  method2string((yyvsp[0].method)), (yyvsp[0].method));
   }
#line 4016 "config_parse.c" /* yacc.c:1652  */
    break;

  case 191:
#line 1691 "config_parse.y" /* yacc.c:1652  */
    { objecttype = object_monitor; }
#line 4022 "config_parse.c" /* yacc.c:1652  */
    break;

  case 192:
#line 1691 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                        monitorinit(&monitor);
#endif /* !SOCKS_CLIENT */
}
#line 4032 "config_parse.c" /* yacc.c:1652  */
    break;

  case 193:
#line 1696 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   pre_addmonitor(&monitor);

   addmonitor(&monitor);
#endif /* !SOCKS_CLIENT */
}
#line 4044 "config_parse.c" /* yacc.c:1652  */
    break;

  case 194:
#line 1708 "config_parse.y" /* yacc.c:1652  */
    { objecttype = object_crule; }
#line 4050 "config_parse.c" /* yacc.c:1652  */
    break;

  case 195:
#line 1709 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if BAREFOOTD
      if (bounceto.atype == SOCKS_ADDR_NOTSET) {
         if (rule.verdict == VERDICT_PASS)
            yyerrorx("no address traffic should bounce to has been given");
         else {
            /*
             * allow no bounce-to address if it is a block, as the bounce-to
             * address will not be used in any case then.
             */
            bounceto.atype               = SOCKS_ADDR_IPV4;
            bounceto.addr.ipv4.ip.s_addr = htonl(INADDR_ANY);
            bounceto.port.tcp            = htons(0);
            bounceto.port.udp            = htons(0);
         }
      }

      rule.extra.bounceto = bounceto;
#endif /* BAREFOOTD */

      pre_addrule(&rule);
      addclientrule(&rule);
      post_addrule();
#endif /* !SOCKS_CLIENT */
   }
#line 4081 "config_parse.c" /* yacc.c:1652  */
    break;

  case 199:
#line 1742 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
         monitorif = NULL;
   }
#line 4090 "config_parse.c" /* yacc.c:1652  */
    break;

  case 200:
#line 1746 "config_parse.y" /* yacc.c:1652  */
    {
         monitorif = &monitor.mstats->object.monitor.internal;
   }
#line 4098 "config_parse.c" /* yacc.c:1652  */
    break;

  case 201:
#line 1749 "config_parse.y" /* yacc.c:1652  */
    {
         monitorif = &monitor.mstats->object.monitor.external;
#endif /* !SOCKS_CLIENT */
   }
#line 4107 "config_parse.c" /* yacc.c:1652  */
    break;

  case 202:
#line 1755 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      alarmside = NULL;
   }
#line 4116 "config_parse.c" /* yacc.c:1652  */
    break;

  case 203:
#line 1759 "config_parse.y" /* yacc.c:1652  */
    {
      *alarmside = RECVSIDE;
   }
#line 4124 "config_parse.c" /* yacc.c:1652  */
    break;

  case 204:
#line 1762 "config_parse.y" /* yacc.c:1652  */
    {
      *alarmside = SENDSIDE;
#endif /* !SOCKS_CLIENT */
   }
#line 4133 "config_parse.c" /* yacc.c:1652  */
    break;

  case 205:
#line 1768 "config_parse.y" /* yacc.c:1652  */
    { alarminit(); }
#line 4139 "config_parse.c" /* yacc.c:1652  */
    break;

  case 206:
#line 1769 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   alarm_data_limit_t limit;

   ASSIGN_NUMBER((yyvsp[-2].number), >=, 0, limit.bytes, 0);
   ASSIGN_NUMBER((yyvsp[0].number), >, 0, limit.seconds, 1);

   monitor.alarmsconfigured |= ALARM_DATA;

   if (monitor.alarm_data_aggregate != 0)
      yyerrorx("one aggregated data alarm has already been specified.  "
               "No more data alarms can be specified in this monitor");

   if (monitorif == NULL) {
      monitor.alarm_data_aggregate = ALARM_INTERNAL | ALARM_EXTERNAL;

      if (alarmside == NULL)
         monitor.alarm_data_aggregate |= ALARM_RECV | ALARM_SEND;

      if (alarmside == NULL || *alarmside == RECVSIDE) {
         monitor.mstats->object.monitor.internal.alarm.data.recv.isconfigured
         = 1;
         monitor.mstats->object.monitor.internal.alarm.data.recv.limit = limit;
      }

      if (alarmside == NULL || *alarmside == SENDSIDE) {
         monitor.mstats->object.monitor.internal.alarm.data.send.isconfigured
         = 1;
         monitor.mstats->object.monitor.internal.alarm.data.send.limit = limit;
      }

      if (alarmside == NULL || *alarmside == RECVSIDE) {
         monitor.mstats->object.monitor.external.alarm.data.recv.isconfigured
         = 1;
         monitor.mstats->object.monitor.external.alarm.data.recv.limit = limit;
      }

      if (alarmside == NULL || *alarmside == SENDSIDE) {
         monitor.mstats->object.monitor.external.alarm.data.send.isconfigured
         = 1;
         monitor.mstats->object.monitor.external.alarm.data.send.limit = limit;
      }
   }
   else {
      if (alarmside == NULL)
         monitor.alarm_data_aggregate = ALARM_RECV | ALARM_SEND;

      if (alarmside == NULL || *alarmside == RECVSIDE) {
         monitorif->alarm.data.recv.isconfigured = 1;
         monitorif->alarm.data.recv.limit        = limit;
      }

      if (alarmside == NULL || *alarmside == SENDSIDE) {
         monitorif->alarm.data.send.isconfigured = 1;
         monitorif->alarm.data.send.limit        = limit;
      }
   }
#endif /* !SOCKS_CLIENT */
   }
#line 4203 "config_parse.c" /* yacc.c:1652  */
    break;

  case 208:
#line 1833 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   monitor.alarmsconfigured |= ALARM_TEST;

   if (monitorif == NULL) {
      monitor.mstats->object.monitor.internal.alarm.test.mtu.dotest = 1;
      monitor.mstats->object.monitor.external.alarm.test.mtu.dotest = 1;
   }
   else {
      monitorif->alarm.test.mtu.dotest = 1;
      monitorif->alarm.test.mtu.dotest = 1;
   }
#endif /* !SOCKS_CLIENT */
   }
#line 4222 "config_parse.c" /* yacc.c:1652  */
    break;

  case 209:
#line 1851 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   alarm_disconnect_limit_t limit;

   ASSIGN_NUMBER((yyvsp[-1].number), >, 0, limit.sessionc, 0);
   ASSIGN_NUMBER((yyvsp[-3].number), >, 0, limit.disconnectc, 0);
   ASSIGN_NUMBER((yyvsp[0].number), >, 0, limit.seconds, 1);

   if (monitor.alarm_disconnect_aggregate != 0)
      yyerrorx("one aggregated disconnect alarm has already been specified.  "
               "No more disconnect alarms can be specified in this monitor");

   monitor.alarmsconfigured |= ALARM_DISCONNECT;

   if (monitorif == NULL) {
      monitor.alarm_disconnect_aggregate = ALARM_INTERNAL | ALARM_EXTERNAL;

      monitor.mstats->object.monitor.internal.alarm.disconnect.isconfigured = 1;
      monitor.mstats->object.monitor.internal.alarm.disconnect.limit = limit;

        monitor.mstats->object.monitor.external.alarm.disconnect
      = monitor.mstats->object.monitor.internal.alarm.disconnect;
   }
   else {
      monitorif->alarm.disconnect.isconfigured = 1;
      monitorif->alarm.disconnect.limit        = limit;
   }
#endif /* !SOCKS_CLIENT */
   }
#line 4256 "config_parse.c" /* yacc.c:1652  */
    break;

  case 210:
#line 1882 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
               (yyval.number) = DEFAULT_ALARM_PERIOD;
#endif /* !SOCKS_CLIENT */
   }
#line 4266 "config_parse.c" /* yacc.c:1652  */
    break;

  case 211:
#line 1887 "config_parse.y" /* yacc.c:1652  */
    { (yyval.number) = (yyvsp[0].number); }
#line 4272 "config_parse.c" /* yacc.c:1652  */
    break;

  case 214:
#line 1892 "config_parse.y" /* yacc.c:1652  */
    { *hostidoption_isset = 1; }
#line 4278 "config_parse.c" /* yacc.c:1652  */
    break;

  case 216:
#line 1896 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 4284 "config_parse.c" /* yacc.c:1652  */
    break;

  case 218:
#line 1900 "config_parse.y" /* yacc.c:1652  */
    {
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
#line 4294 "config_parse.c" /* yacc.c:1652  */
    break;

  case 219:
#line 1905 "config_parse.y" /* yacc.c:1652  */
    {
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
#line 4304 "config_parse.c" /* yacc.c:1652  */
    break;

  case 221:
#line 1911 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 4314 "config_parse.c" /* yacc.c:1652  */
    break;

  case 223:
#line 1919 "config_parse.y" /* yacc.c:1652  */
    {

#if SOCKS_CLIENT || !HAVE_SOCKS_HOSTID
      yyerrorx("hostid is not supported on this system");
#endif /* SOCKS_CLIENT || !HAVE_SOCKS_HOSTID */

      objecttype = object_hrule;
}
#line 4327 "config_parse.c" /* yacc.c:1652  */
    break;

  case 224:
#line 1926 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      if (hostid.atype != SOCKS_ADDR_NOTSET)
         yyerrorx("it does not make sense to set the hostid address in a "
                  "hostid-rule.  Use the \"from\" address to match the hostid "
                  "of the client");

      *hostidoption_isset = 1;

      pre_addrule(&rule);
      addhostidrule(&rule);
      post_addrule();
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
   }
#line 4346 "config_parse.c" /* yacc.c:1652  */
    break;

  case 225:
#line 1944 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 4352 "config_parse.c" /* yacc.c:1652  */
    break;

  case 229:
#line 1952 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      addrinit(&hostid, 1);

#else /* HAVE_SOCKS_HOSTID */
      yyerrorx("hostid is not supported on this system");
#endif /* HAVE_SOCKS_HOSTID */

   }
#line 4366 "config_parse.c" /* yacc.c:1652  */
    break;

  case 231:
#line 1963 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
   ASSIGN_NUMBER((yyvsp[0].number), >=, 0, *hostindex, 0);
   ASSIGN_NUMBER((yyvsp[0].number), <=, HAVE_MAX_HOSTIDS, *hostindex, 0);

#else
   yyerrorx("hostid is not supported on this system");
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
}
#line 4380 "config_parse.c" /* yacc.c:1652  */
    break;

  case 232:
#line 1975 "config_parse.y" /* yacc.c:1652  */
    { objecttype = object_srule; }
#line 4386 "config_parse.c" /* yacc.c:1652  */
    break;

  case 233:
#line 1976 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
#if !HAVE_SOCKS_RULES
   yyerrorx("socks-rules are not used in %s", PRODUCT);
#endif /* !HAVE_SOCKS_RULES */

      pre_addrule(&rule);
      addsocksrule(&rule);
      post_addrule();
#endif /* !SOCKS_CLIENT */
   }
#line 4402 "config_parse.c" /* yacc.c:1652  */
    break;

  case 234:
#line 1990 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 4408 "config_parse.c" /* yacc.c:1652  */
    break;

  case 243:
#line 2002 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 4418 "config_parse.c" /* yacc.c:1652  */
    break;

  case 245:
#line 2011 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                        checkmodule("bandwidth");
                        bw_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 4429 "config_parse.c" /* yacc.c:1652  */
    break;

  case 253:
#line 2024 "config_parse.y" /* yacc.c:1652  */
    { *hostidoption_isset = 1; }
#line 4435 "config_parse.c" /* yacc.c:1652  */
    break;

  case 258:
#line 2029 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                     checkmodule("pac");
#endif /* !SOCKS_CLIENT */
   }
#line 4445 "config_parse.c" /* yacc.c:1652  */
    break;

  case 259:
#line 2034 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                     checkmodule("pac");
#endif /* !SOCKS_CLIENT */
   }
#line 4455 "config_parse.c" /* yacc.c:1652  */
    break;

  case 260:
#line 2039 "config_parse.y" /* yacc.c:1652  */
    {

#if !SOCKS_CLIENT

                     checkmodule("pac");

#endif /* !SOCKS_CLIENT */
   }
#line 4468 "config_parse.c" /* yacc.c:1652  */
    break;

  case 261:
#line 2047 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                     checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
#line 4478 "config_parse.c" /* yacc.c:1652  */
    break;

  case 262:
#line 2052 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
         if (rule.verdict == VERDICT_BLOCK && !socketopt.isinternalside)
            yyerrorx("it does not make sense to set a socket option for the "
                     "external side in a rule that blocks access; the external "
                     "side will never be accessed as the rule blocks access "
                     "to it");

         if (socketopt.isinternalside)
            if (socketopt.info != NULL && socketopt.info->calltype == preonly)
               yywarnx("to our knowledge the socket option \"%s\" can only be "
                       "correctly applied at pre-connection establishment "
                       "time, but by the time this rule is matched, the "
                       "connection will already have been established",
                       socketopt.info == NULL ? "unknown" :
                                                socketopt.info->name);

         if (!addedsocketoption(&rule.socketoptionc,
                                &rule.socketoptionv,
                                &socketopt))
            yywarn("could not add socketoption");
#endif /* !SOCKS_CLIENT */
   }
#line 4506 "config_parse.c" /* yacc.c:1652  */
    break;

  case 309:
#line 2128 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldapauthorisation->debug = (int)(yyvsp[0].number);
   }
#line 4516 "config_parse.c" /* yacc.c:1652  */
    break;

  case 310:
#line 2133 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthorisation->debug = (int)-(yyvsp[0].number);
 #else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4528 "config_parse.c" /* yacc.c:1652  */
    break;

  case 311:
#line 2142 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldapauthentication->debug = (int)(yyvsp[0].number);
   }
#line 4538 "config_parse.c" /* yacc.c:1652  */
    break;

  case 312:
#line 2147 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthentication->debug = (int)-(yyvsp[0].number);
 #else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4550 "config_parse.c" /* yacc.c:1652  */
    break;

  case 313:
#line 2156 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldapauthorisation.domain,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.domain) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4567 "config_parse.c" /* yacc.c:1652  */
    break;

  case 314:
#line 2170 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldapauthentication.domain,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthentication.domain) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4584 "config_parse.c" /* yacc.c:1652  */
    break;

  case 315:
#line 2184 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldapauthorisation->mdepth = (int)(yyvsp[0].number);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4598 "config_parse.c" /* yacc.c:1652  */
    break;

  case 316:
#line 2195 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldapauthorisation.certfile,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.certfile) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4615 "config_parse.c" /* yacc.c:1652  */
    break;

  case 317:
#line 2209 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldapauthentication.certfile,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthentication.certfile) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4632 "config_parse.c" /* yacc.c:1652  */
    break;

  case 318:
#line 2223 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldapauthorisation.certpath,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.certpath) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4649 "config_parse.c" /* yacc.c:1652  */
    break;

  case 319:
#line 2237 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldapauthentication.certpath,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthentication.certpath) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */

      yyerrorx_nolib("LDAP");

#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4668 "config_parse.c" /* yacc.c:1652  */
    break;

  case 320:
#line 2253 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthorisation.ldapurl, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4683 "config_parse.c" /* yacc.c:1652  */
    break;

  case 321:
#line 2265 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthentication.ldapurl, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
      if (sockscf.state.ldapauthentication.ldapurl == NULL)
         sockscf.state.ldapauthentication.ldapurl = state->ldapauthentication.ldapurl;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4700 "config_parse.c" /* yacc.c:1652  */
    break;

  case 322:
#line 2279 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthentication.ldapbasedn, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4715 "config_parse.c" /* yacc.c:1652  */
    break;

  case 323:
#line 2291 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthentication.ldapbasedn, hextoutf8((yyvsp[0].string), 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4730 "config_parse.c" /* yacc.c:1652  */
    break;

  case 324:
#line 2303 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthentication.ldapbasedn, hextoutf8((yyvsp[0].string), 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4745 "config_parse.c" /* yacc.c:1652  */
    break;

  case 325:
#line 2315 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthorisation.ldapbasedn, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4760 "config_parse.c" /* yacc.c:1652  */
    break;

  case 326:
#line 2327 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthorisation.ldapbasedn, hextoutf8((yyvsp[0].string), 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4775 "config_parse.c" /* yacc.c:1652  */
    break;

  case 327:
#line 2339 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthorisation.ldapbasedn, hextoutf8((yyvsp[0].string), 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4790 "config_parse.c" /* yacc.c:1652  */
    break;

  case 328:
#line 2351 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   ldapauthentication->port = (int)(yyvsp[0].number);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4804 "config_parse.c" /* yacc.c:1652  */
    break;

  case 329:
#line 2362 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   ldapauthorisation->port = (int)(yyvsp[0].number);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4818 "config_parse.c" /* yacc.c:1652  */
    break;

  case 330:
#line 2373 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   ldapauthentication->portssl = (int)(yyvsp[0].number);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4832 "config_parse.c" /* yacc.c:1652  */
    break;

  case 331:
#line 2384 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   ldapauthorisation->portssl = (int)(yyvsp[0].number);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4846 "config_parse.c" /* yacc.c:1652  */
    break;

  case 332:
#line 2395 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthorisation->ssl = 1;
   }
#line 4856 "config_parse.c" /* yacc.c:1652  */
    break;

  case 333:
#line 2400 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthorisation->ssl = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4868 "config_parse.c" /* yacc.c:1652  */
    break;

  case 334:
#line 2409 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthentication->ssl = 1;
   }
#line 4878 "config_parse.c" /* yacc.c:1652  */
    break;

  case 335:
#line 2414 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthentication->ssl = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4890 "config_parse.c" /* yacc.c:1652  */
    break;

  case 336:
#line 2423 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthorisation->auto_off = 1;
   }
#line 4900 "config_parse.c" /* yacc.c:1652  */
    break;

  case 337:
#line 2428 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthorisation->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4912 "config_parse.c" /* yacc.c:1652  */
    break;

  case 338:
#line 2437 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthentication->auto_off = 1;
   }
#line 4922 "config_parse.c" /* yacc.c:1652  */
    break;

  case 339:
#line 2442 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthentication->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4934 "config_parse.c" /* yacc.c:1652  */
    break;

  case 340:
#line 2451 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthorisation->certcheck = 1;
   }
#line 4944 "config_parse.c" /* yacc.c:1652  */
    break;

  case 341:
#line 2456 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthorisation->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4956 "config_parse.c" /* yacc.c:1652  */
    break;

  case 342:
#line 2465 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthentication->certcheck = 1;
   }
#line 4966 "config_parse.c" /* yacc.c:1652  */
    break;

  case 343:
#line 2470 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthentication->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 4978 "config_parse.c" /* yacc.c:1652  */
    break;

  case 344:
#line 2479 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      ldapauthorisation->keeprealm = 1;
   }
#line 4988 "config_parse.c" /* yacc.c:1652  */
    break;

  case 345:
#line 2484 "config_parse.y" /* yacc.c:1652  */
    {
      ldapauthorisation->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5000 "config_parse.c" /* yacc.c:1652  */
    break;

  case 346:
#line 2493 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKLEN(ldapauthorisation->filter, (yyvsp[0].string), sizeof(state->ldapauthorisation.filter) - 1, yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5014 "config_parse.c" /* yacc.c:1652  */
    break;

  case 347:
#line 2504 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKLEN(ldapauthentication->filter, (yyvsp[0].string), sizeof(state->ldapauthentication.filter) - 1, yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5028 "config_parse.c" /* yacc.c:1652  */
    break;

  case 348:
#line 2515 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldapauthorisation->filter_AD,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.filter_AD) - 1,
                      yyerrorx);

#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5046 "config_parse.c" /* yacc.c:1652  */
    break;

  case 349:
#line 2530 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKUTFLEN(ldapauthorisation->filter,
                          (yyvsp[0].string),
                          sizeof(state->ldapauthorisation.filter) - 1,
                          yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5063 "config_parse.c" /* yacc.c:1652  */
    break;

  case 350:
#line 2544 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKUTFLEN(ldapauthorisation->filter_AD,
                        (yyvsp[0].string),
                        sizeof(state->ldapauthorisation.filter_AD) - 1,
                        yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5080 "config_parse.c" /* yacc.c:1652  */
    break;

  case 351:
#line 2558 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldapauthorisation->attribute,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.attribute) - 1,
                      yyerrorx);

#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5098 "config_parse.c" /* yacc.c:1652  */
    break;

  case 352:
#line 2573 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldapauthorisation->attribute_AD,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.attribute_AD) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5115 "config_parse.c" /* yacc.c:1652  */
    break;

  case 353:
#line 2587 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKUTFLEN(ldapauthorisation->attribute,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.attribute) -1,
                      yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5132 "config_parse.c" /* yacc.c:1652  */
    break;

  case 354:
#line 2601 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKUTFLEN(ldapauthorisation->attribute_AD,
                      (yyvsp[0].string),
                      sizeof(state->ldapauthorisation.attribute_AD) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5149 "config_parse.c" /* yacc.c:1652  */
    break;

  case 355:
#line 2615 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8((yyvsp[0].string), 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5164 "config_parse.c" /* yacc.c:1652  */
    break;

  case 356:
#line 2627 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, hextoutf8((yyvsp[0].string), 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5181 "config_parse.c" /* yacc.c:1652  */
    break;

  case 357:
#line 2641 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, asciitoutf8((yyvsp[0].string))) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5198 "config_parse.c" /* yacc.c:1652  */
    break;

  case 358:
#line 2655 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthorisation.ldapserver, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5213 "config_parse.c" /* yacc.c:1652  */
    break;

  case 359:
#line 2667 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldapauthentication.ldapserver, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5228 "config_parse.c" /* yacc.c:1652  */
    break;

  case 360:
#line 2679 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_LDAP
#if SOCKS_SERVER
   STRCPY_CHECKLEN(state->ldapauthorisation.keytab,
                   (yyvsp[0].string),
                   sizeof(state->ldapauthorisation.keytab) - 1, yyerrorx);
#else
   yyerrorx("LDAP keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("LDAP");
#endif /* HAVE_LDAP */
   }
#line 5246 "config_parse.c" /* yacc.c:1652  */
    break;

  case 361:
#line 2694 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_LDAP
#if SOCKS_SERVER
   STRCPY_CHECKLEN(state->ldapauthentication.keytab,
                   (yyvsp[0].string),
                   sizeof(state->ldapauthentication.keytab) - 1, yyerrorx);
#else
   yyerrorx("LDAP keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("LDAP");
#endif /* HAVE_LDAP */
   }
#line 5264 "config_parse.c" /* yacc.c:1652  */
    break;

  case 362:
#line 2709 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_PAC
      char b64[MAX_BASE64_LEN];

      checkmodule("pac");

      if (sidtob64((yyvsp[0].string), b64, sizeof(b64)) != 0)
         yyerrorx("invalid input: %s)", (yyvsp[0].string));
      if (addlinkedname(&rule.objectsids, b64) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("PAC");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5285 "config_parse.c" /* yacc.c:1652  */
    break;

  case 363:
#line 2727 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_PAC
      char sid[MAX_BASE64_LEN];
      checkmodule("pac");

      /* attempt conversion to check if input makes sense */
      if (b64tosid((yyvsp[0].string), sid, sizeof(sid)) != 0)
         yyerrorx("invalid input: %s)", (yyvsp[0].string));
      if (addlinkedname(&rule.objectsids, (yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("PAC");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
#line 5306 "config_parse.c" /* yacc.c:1652  */
    break;

  case 364:
#line 2745 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
#if HAVE_PAC
      checkmodule("pac");
      rule.pacoff = 1;
   }
#line 5317 "config_parse.c" /* yacc.c:1652  */
    break;

  case 365:
#line 2751 "config_parse.y" /* yacc.c:1652  */
    {
      checkmodule("pac");
      rule.pacoff = 0;
#else /* !HAVE_PAC */
      yyerrorx_nolib("PAC");
#endif /* !HAVE_PAC */
#endif /* SOCKS_SERVER */
   }
#line 5330 "config_parse.c" /* yacc.c:1652  */
    break;

  case 367:
#line 2764 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
#line 5342 "config_parse.c" /* yacc.c:1652  */
    break;

  case 370:
#line 2778 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
#line 5352 "config_parse.c" /* yacc.c:1652  */
    break;

  case 371:
#line 2783 "config_parse.y" /* yacc.c:1652  */
    {
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
   }
#line 5362 "config_parse.c" /* yacc.c:1652  */
    break;

  case 375:
#line 2797 "config_parse.y" /* yacc.c:1652  */
    {
         state->command.bind = 1;
   }
#line 5370 "config_parse.c" /* yacc.c:1652  */
    break;

  case 376:
#line 2800 "config_parse.y" /* yacc.c:1652  */
    {
         state->command.connect = 1;
   }
#line 5378 "config_parse.c" /* yacc.c:1652  */
    break;

  case 377:
#line 2803 "config_parse.y" /* yacc.c:1652  */
    {
         state->command.udpassociate = 1;
   }
#line 5386 "config_parse.c" /* yacc.c:1652  */
    break;

  case 378:
#line 2809 "config_parse.y" /* yacc.c:1652  */
    {
         state->command.bindreply = 1;
   }
#line 5394 "config_parse.c" /* yacc.c:1652  */
    break;

  case 379:
#line 2813 "config_parse.y" /* yacc.c:1652  */
    {
         state->command.udpreply = 1;
   }
#line 5402 "config_parse.c" /* yacc.c:1652  */
    break;

  case 383:
#line 2826 "config_parse.y" /* yacc.c:1652  */
    {
      state->protocol.tcp = 1;
   }
#line 5410 "config_parse.c" /* yacc.c:1652  */
    break;

  case 384:
#line 2829 "config_parse.y" /* yacc.c:1652  */
    {
      state->protocol.udp = 1;
   }
#line 5418 "config_parse.c" /* yacc.c:1652  */
    break;

  case 396:
#line 2858 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
                        rule.ss_isinheritable = 1;
   }
#line 5427 "config_parse.c" /* yacc.c:1652  */
    break;

  case 397:
#line 2862 "config_parse.y" /* yacc.c:1652  */
    {
                        rule.ss_isinheritable = 0;
#endif /* !SOCKS_CLIENT */
   }
#line 5436 "config_parse.c" /* yacc.c:1652  */
    break;

  case 398:
#line 2868 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS((yyvsp[0].number), ss.object.ss.max, 0);
      ss.object.ss.max       = (yyvsp[0].number);
      ss.object.ss.max_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 5448 "config_parse.c" /* yacc.c:1652  */
    break;

  case 399:
#line 2877 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_THROTTLE_SECONDS((yyvsp[-2].number), ss.object.ss.throttle.limit.clients, 0);
      ASSIGN_THROTTLE_CLIENTS((yyvsp[0].number), ss.object.ss.throttle.limit.seconds, 0);
      ss.object.ss.throttle_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 5460 "config_parse.c" /* yacc.c:1652  */
    break;

  case 404:
#line 2892 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      if ((ss.keystate.key = string2statekey((yyvsp[0].string))) == key_unset)
         yyerrorx("%s is not a valid state key", (yyvsp[0].string));

      if (ss.keystate.key == key_hostid) {
#if HAVE_SOCKS_HOSTID

         *hostidoption_isset           = 1;
         ss.keystate.keyinfo.hostindex = DEFAULT_HOSTINDEX;

#else /* !HAVE_SOCKS_HOSTID */

         yyerrorx("hostid is not supported on this system");

#endif /* HAVE_SOCKS_HOSTID */
      }




#else /* SOCKS_CLIENT */

   SERRX(0);
#endif /* SOCKS_CLIENT */
   }
#line 5491 "config_parse.c" /* yacc.c:1652  */
    break;

  case 405:
#line 2920 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      hostindex = &ss.keystate.keyinfo.hostindex;
   }
#line 5500 "config_parse.c" /* yacc.c:1652  */
    break;

  case 406:
#line 2924 "config_parse.y" /* yacc.c:1652  */
    {
      hostindex = &rule.hostindex; /* reset */
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
   }
#line 5509 "config_parse.c" /* yacc.c:1652  */
    break;

  case 407:
#line 2931 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS((yyvsp[0].number), ss.object.ss.max_perstate, 0);
      ss.object.ss.max_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 5520 "config_parse.c" /* yacc.c:1652  */
    break;

  case 408:
#line 2939 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
   ASSIGN_THROTTLE_SECONDS((yyvsp[-2].number), ss.object.ss.throttle_perstate.limit.clients, 0);
   ASSIGN_THROTTLE_CLIENTS((yyvsp[0].number), ss.object.ss.throttle_perstate.limit.seconds, 0);
   ss.object.ss.throttle_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
}
#line 5532 "config_parse.c" /* yacc.c:1652  */
    break;

  case 409:
#line 2948 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
      ASSIGN_NUMBER((yyvsp[0].number), >=, 0, bw.object.bw.maxbps, 0);
      bw.object.bw.maxbps_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 5543 "config_parse.c" /* yacc.c:1652  */
    break;

  case 411:
#line 2960 "config_parse.y" /* yacc.c:1652  */
    {
#if !SOCKS_CLIENT
         rule.log.connect = 1;
   }
#line 5552 "config_parse.c" /* yacc.c:1652  */
    break;

  case 412:
#line 2964 "config_parse.y" /* yacc.c:1652  */
    {
         rule.log.data = 1;
   }
#line 5560 "config_parse.c" /* yacc.c:1652  */
    break;

  case 413:
#line 2967 "config_parse.y" /* yacc.c:1652  */
    {
         rule.log.disconnect = 1;
   }
#line 5568 "config_parse.c" /* yacc.c:1652  */
    break;

  case 414:
#line 2970 "config_parse.y" /* yacc.c:1652  */
    {
         rule.log.error = 1;
   }
#line 5576 "config_parse.c" /* yacc.c:1652  */
    break;

  case 415:
#line 2973 "config_parse.y" /* yacc.c:1652  */
    {
         rule.log.iooperation = 1;
   }
#line 5584 "config_parse.c" /* yacc.c:1652  */
    break;

  case 416:
#line 2976 "config_parse.y" /* yacc.c:1652  */
    {
         rule.log.tcpinfo = 1;
#endif /* !SOCKS_CLIENT */
   }
#line 5593 "config_parse.c" /* yacc.c:1652  */
    break;

  case 419:
#line 2987 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_PAM && (!SOCKS_CLIENT)
      STRCPY_CHECKLEN(state->pamservicename,
                      (yyvsp[0].string),
                      sizeof(state->pamservicename) -1,
                      yyerrorx);
#else
      yyerrorx_nolib("PAM");
#endif /* HAVE_PAM && (!SOCKS_CLIENT) */
   }
#line 5608 "config_parse.c" /* yacc.c:1652  */
    break;

  case 420:
#line 2999 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_BSDAUTH && SOCKS_SERVER
      STRCPY_CHECKLEN(state->bsdauthstylename,
                      (yyvsp[0].string),
                      sizeof(state->bsdauthstylename) - 1,
                      yyerrorx);
#else
      yyerrorx_nolib("bsdauth");
#endif /* HAVE_BSDAUTH && SOCKS_SERVER */
   }
#line 5623 "config_parse.c" /* yacc.c:1652  */
    break;

  case 421:
#line 3012 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_GSSAPI
      STRCPY_CHECKLEN(gssapiservicename,
                      (yyvsp[0].string),
                      sizeof(state->gssapiservicename) - 1,
                      yyerrorx);
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
#line 5638 "config_parse.c" /* yacc.c:1652  */
    break;

  case 422:
#line 3024 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_GSSAPI
#if SOCKS_SERVER
      STRCPY_CHECKLEN(gssapikeytab,
                       (yyvsp[0].string),
                       sizeof(state->gssapikeytab) - 1,
                       yyerrorx);
#else
      yyerrorx("gssapi keytab setting is only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
#line 5657 "config_parse.c" /* yacc.c:1652  */
    break;

  case 424:
#line 3043 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
#line 5668 "config_parse.c" /* yacc.c:1652  */
    break;

  case 425:
#line 3049 "config_parse.y" /* yacc.c:1652  */
    {
      gssapiencryption->clear = 1;
   }
#line 5676 "config_parse.c" /* yacc.c:1652  */
    break;

  case 426:
#line 3052 "config_parse.y" /* yacc.c:1652  */
    {
      gssapiencryption->integrity = 1;
   }
#line 5684 "config_parse.c" /* yacc.c:1652  */
    break;

  case 427:
#line 3055 "config_parse.y" /* yacc.c:1652  */
    {
      gssapiencryption->confidentiality = 1;
   }
#line 5692 "config_parse.c" /* yacc.c:1652  */
    break;

  case 428:
#line 3058 "config_parse.y" /* yacc.c:1652  */
    {
      yyerrorx("gssapi per-message encryption not supported");
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
#line 5703 "config_parse.c" /* yacc.c:1652  */
    break;

  case 432:
#line 3073 "config_parse.y" /* yacc.c:1652  */
    {
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
      struct request_info request;
      char tmp[LIBWRAPBUF];
      int errno_s, devnull;

      STRCPY_CHECKLEN(rule.libwrap,
                      (yyvsp[0].string),
                      sizeof(rule.libwrap) - 1,
                      yyerrorx);

      /* libwrap modifies the passed buffer, to test with a tmp one. */
      STRCPY_ASSERTSIZE(tmp, rule.libwrap);

      devnull = open("/dev/null", O_RDWR, 0);
      ++dry_run;
      errno_s = errno;

      errno = 0;

      request_init(&request, RQ_FILE, devnull, RQ_DAEMON, __progname, 0);
      if (setjmp(tcpd_buf) != 0)
         yyerror("bad libwrap line");
      process_options(tmp, &request);

      if (errno != 0)
         yywarn("possible libwrap/tcp-wrappers related configuration error");

      --dry_run;
      close(devnull);
      errno = errno_s;

#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

   }
#line 5745 "config_parse.c" /* yacc.c:1652  */
    break;

  case 437:
#line 3125 "config_parse.y" /* yacc.c:1652  */
    {
#if BAREFOOTD
      yyerrorx("redirecting \"to\" an address does not make any sense in %s.  "
               "Instead specify the address you wanted to \"redirect\" "
               "data to as the \"bounce to\" address, as normal",
               PRODUCT);
#endif /* BAREFOOT */
   }
#line 5758 "config_parse.c" /* yacc.c:1652  */
    break;

  case 449:
#line 3148 "config_parse.y" /* yacc.c:1652  */
    {
               if (!addedsocketoption(&route.socketoptionc,
                                      &route.socketoptionv,
                                      &socketopt))
                  yywarn("could not add socketoption");
   }
#line 5769 "config_parse.c" /* yacc.c:1652  */
    break;

  case 450:
#line 3156 "config_parse.y" /* yacc.c:1652  */
    { (yyval.string) = NULL; }
#line 5775 "config_parse.c" /* yacc.c:1652  */
    break;

  case 453:
#line 3163 "config_parse.y" /* yacc.c:1652  */
    {
      addrinit(&src, 1);
   }
#line 5783 "config_parse.c" /* yacc.c:1652  */
    break;

  case 454:
#line 3168 "config_parse.y" /* yacc.c:1652  */
    {
      addrinit(&dst, ipaddr_requires_netmask(to, objecttype));
   }
#line 5791 "config_parse.c" /* yacc.c:1652  */
    break;

  case 455:
#line 3173 "config_parse.y" /* yacc.c:1652  */
    {
      addrinit(&rdr_from, 1);
   }
#line 5799 "config_parse.c" /* yacc.c:1652  */
    break;

  case 456:
#line 3178 "config_parse.y" /* yacc.c:1652  */
    {
      addrinit(&rdr_to, 0);
   }
#line 5807 "config_parse.c" /* yacc.c:1652  */
    break;

  case 457:
#line 3183 "config_parse.y" /* yacc.c:1652  */
    {
#if BAREFOOTD
      addrinit(&bounceto, 0);
#endif /* BAREFOOTD */
   }
#line 5817 "config_parse.c" /* yacc.c:1652  */
    break;

  case 458:
#line 3191 "config_parse.y" /* yacc.c:1652  */
    {
      gwaddrinit(&gw);
   }
#line 5825 "config_parse.c" /* yacc.c:1652  */
    break;

  case 467:
#line 3211 "config_parse.y" /* yacc.c:1652  */
    { if (!netmask_required) yyerrorx_hasnetmask(); }
#line 5831 "config_parse.c" /* yacc.c:1652  */
    break;

  case 468:
#line 3212 "config_parse.y" /* yacc.c:1652  */
    { if (netmask_required)  yyerrorx_nonetmask();  }
#line 5837 "config_parse.c" /* yacc.c:1652  */
    break;

  case 469:
#line 3213 "config_parse.y" /* yacc.c:1652  */
    { if (!netmask_required) yyerrorx_hasnetmask(); }
#line 5843 "config_parse.c" /* yacc.c:1652  */
    break;

  case 470:
#line 3214 "config_parse.y" /* yacc.c:1652  */
    { if (netmask_required)  yyerrorx_nonetmask();  }
#line 5849 "config_parse.c" /* yacc.c:1652  */
    break;

  case 471:
#line 3215 "config_parse.y" /* yacc.c:1652  */
    { if (!netmask_required)
                                       yyerrorx_hasnetmask(); }
#line 5856 "config_parse.c" /* yacc.c:1652  */
    break;

  case 472:
#line 3217 "config_parse.y" /* yacc.c:1652  */
    { if (netmask_required)  yyerrorx_nonetmask();  }
#line 5862 "config_parse.c" /* yacc.c:1652  */
    break;

  case 475:
#line 3221 "config_parse.y" /* yacc.c:1652  */
    { /* for upnp; broadcasts on interface. */ }
#line 5868 "config_parse.c" /* yacc.c:1652  */
    break;

  case 479:
#line 3230 "config_parse.y" /* yacc.c:1652  */
    {
      *atype = SOCKS_ADDR_IPV4;

      if (socks_inet_pton(AF_INET, (yyvsp[0].string), ipv4, NULL) != 1)
         yyerror("bad %s: %s", atype2string(*atype), (yyvsp[0].string));
   }
#line 5879 "config_parse.c" /* yacc.c:1652  */
    break;

  case 480:
#line 3238 "config_parse.y" /* yacc.c:1652  */
    {
      if ((yyvsp[0].number) < 0 || (yyvsp[0].number) > 32)
         yyerrorx("bad %s netmask: %ld.  Legal range is 0 - 32",
                  atype2string(*atype), (long)(yyvsp[0].number));

      netmask_v4->s_addr = (yyvsp[0].number) == 0 ? 0 : htonl(IPV4_FULLNETMASK << (32 - (yyvsp[0].number)));
   }
#line 5891 "config_parse.c" /* yacc.c:1652  */
    break;

  case 481:
#line 3245 "config_parse.y" /* yacc.c:1652  */
    {
      if (socks_inet_pton(AF_INET, (yyvsp[0].string), netmask_v4, NULL) != 1)
         yyerror("bad %s netmask: %s", atype2string(*atype), (yyvsp[0].string));
   }
#line 5900 "config_parse.c" /* yacc.c:1652  */
    break;

  case 482:
#line 3251 "config_parse.y" /* yacc.c:1652  */
    {
      *atype = SOCKS_ADDR_IPV6;

      if (socks_inet_pton(AF_INET6, (yyvsp[0].string), ipv6, scopeid_v6) != 1)
         yyerror("bad %s: %s", atype2string(*atype), (yyvsp[0].string));
   }
#line 5911 "config_parse.c" /* yacc.c:1652  */
    break;

  case 483:
#line 3259 "config_parse.y" /* yacc.c:1652  */
    {
      if ((yyvsp[0].number) < 0 || (yyvsp[0].number) > IPV6_NETMASKBITS)
         yyerrorx("bad %s netmask: %d.  Legal range is 0 - %d",
                  atype2string(*atype), (int)(yyvsp[0].number), IPV6_NETMASKBITS);

      *netmask_v6 = (yyvsp[0].number);
   }
#line 5923 "config_parse.c" /* yacc.c:1652  */
    break;

  case 484:
#line 3268 "config_parse.y" /* yacc.c:1652  */
    {
      SASSERTX(strcmp((yyvsp[0].string), "0") == 0);

      *atype = SOCKS_ADDR_IPVANY;
      ipvany->s_addr = htonl(0);
   }
#line 5934 "config_parse.c" /* yacc.c:1652  */
    break;

  case 485:
#line 3276 "config_parse.y" /* yacc.c:1652  */
    {
      if ((yyvsp[0].number) != 0)
         yyerrorx("bad %s netmask: %d.  Only legal value is 0",
                  atype2string(*atype), (int)(yyvsp[0].number));

      netmask_vany->s_addr = htonl((yyvsp[0].number));
   }
#line 5946 "config_parse.c" /* yacc.c:1652  */
    break;

  case 486:
#line 3286 "config_parse.y" /* yacc.c:1652  */
    {
      *atype = SOCKS_ADDR_DOMAIN;
      STRCPY_CHECKLEN(domain, (yyvsp[0].string), MAXHOSTNAMELEN - 1, yyerrorx);
   }
#line 5955 "config_parse.c" /* yacc.c:1652  */
    break;

  case 487:
#line 3292 "config_parse.y" /* yacc.c:1652  */
    {
      *atype = SOCKS_ADDR_IFNAME;
      STRCPY_CHECKLEN(ifname, (yyvsp[0].string), MAXIFNAMELEN - 1, yyerrorx);
   }
#line 5964 "config_parse.c" /* yacc.c:1652  */
    break;

  case 488:
#line 3299 "config_parse.y" /* yacc.c:1652  */
    {
      *atype = SOCKS_ADDR_URL;
      STRCPY_CHECKLEN(url, (yyvsp[0].string), MAXURLLEN - 1, yyerrorx);
   }
#line 5973 "config_parse.c" /* yacc.c:1652  */
    break;

  case 489:
#line 3306 "config_parse.y" /* yacc.c:1652  */
    { (yyval.number) = 0; }
#line 5979 "config_parse.c" /* yacc.c:1652  */
    break;

  case 493:
#line 3312 "config_parse.y" /* yacc.c:1652  */
    { (yyval.number) = 0; }
#line 5985 "config_parse.c" /* yacc.c:1652  */
    break;

  case 497:
#line 3320 "config_parse.y" /* yacc.c:1652  */
    {
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerrorx("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
#line 5995 "config_parse.c" /* yacc.c:1652  */
    break;

  case 498:
#line 3328 "config_parse.y" /* yacc.c:1652  */
    {
      ASSIGN_PORTNUMBER((yyvsp[0].number), *port_tcp);
      ASSIGN_PORTNUMBER((yyvsp[0].number), *port_udp);
   }
#line 6004 "config_parse.c" /* yacc.c:1652  */
    break;

  case 499:
#line 3334 "config_parse.y" /* yacc.c:1652  */
    {
      ASSIGN_PORTNUMBER((yyvsp[0].number), ruleaddr->portend);
      ruleaddr->operator   = range;
   }
#line 6013 "config_parse.c" /* yacc.c:1652  */
    break;

  case 500:
#line 3340 "config_parse.y" /* yacc.c:1652  */
    {
      struct servent   *service;

      if ((service = getservbyname((yyvsp[0].string), "tcp")) == NULL) {
         if (state->protocol.tcp)
            yyerrorx("unknown tcp protocol: %s", (yyvsp[0].string));

         *port_tcp = htons(0);
      }
      else
         *port_tcp = (in_port_t)service->s_port;

      if ((service = getservbyname((yyvsp[0].string), "udp")) == NULL) {
         if (state->protocol.udp)
               yyerrorx("unknown udp protocol: %s", (yyvsp[0].string));

            *port_udp = htons(0);
      }
      else
         *port_udp = (in_port_t)service->s_port;

      if (*port_tcp == htons(0) && *port_udp == htons(0))
         yyerrorx("unknown tcp/udp protocol");

      /* if one protocol is unset, set to same as the other. */
      if (*port_tcp == htons(0))
         *port_tcp = *port_udp;
      else if (*port_udp == htons(0))
         *port_udp = *port_tcp;

      (yyval.number) = (size_t)*port_udp;
   }
#line 6050 "config_parse.c" /* yacc.c:1652  */
    break;

  case 501:
#line 3375 "config_parse.y" /* yacc.c:1652  */
    {
      *operator = string2operator((yyvsp[0].string));
   }
#line 6058 "config_parse.c" /* yacc.c:1652  */
    break;

  case 503:
#line 3384 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER((yyvsp[0].number), rule.udprange.start);
#endif /* SOCKS_SERVER */
   }
#line 6068 "config_parse.c" /* yacc.c:1652  */
    break;

  case 504:
#line 3391 "config_parse.y" /* yacc.c:1652  */
    {
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER((yyvsp[0].number), rule.udprange.end);
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerrorx("end port (%d) can not be less than start port (%u)",
               (int)(yyvsp[0].number), ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
#line 6083 "config_parse.c" /* yacc.c:1652  */
    break;

  case 505:
#line 3403 "config_parse.y" /* yacc.c:1652  */
    {
      addnumber(&numberc, &numberv, (yyvsp[0].number));
   }
#line 6091 "config_parse.c" /* yacc.c:1652  */
    break;


#line 6095 "config_parse.c" /* yacc.c:1652  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 3413 "config_parse.y" /* yacc.c:1918  */


#define INTERACTIVE      0

extern FILE *yyin;

int lex_dorestart; /* global for Lex. */

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

#else /* !SOCKS_CLIENT */
   SASSERTX(pidismainmother(sockscf.state.pid));

   if (sockscf.state.inited)
      /* in case we need something special to (re)open config-file. */
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
#endif /* !SOCKS_CLIENT */

   yyin = fopen(filename, "r");

#if !SOCKS_CLIENT
   if (sockscf.state.inited)
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
#endif /* SERVER */

   if (yyin == NULL
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         slog(sockscf.state.inited ? LOG_WARNING : LOG_ERR,
              "%s: could not open config file %s", function, filename);
      else
         slog((sockscf.state.inited || SOCKS_CLIENT) ? LOG_WARNING : LOG_ERR,
              "%s: config file %s is empty.  Not parsing", function, filename);

#if SOCKS_CLIENT

      if (yyin == NULL) {
         if (sockscf.option.directfallback)
            slog(LOG_DEBUG,
                 "%s: no %s, but direct fallback enabled, continuing",
                 function, filename);
         else
            exit(0);
      }
      else {
         slog(LOG_DEBUG, "%s: empty %s, assuming direct fallback wanted",
              function, filename);

         sockscf.option.directfallback = 1;
      }

      SASSERTX(sockscf.option.directfallback == 1);
#else /* !SOCKS_CLIENT */

      if (!sockscf.state.inited)
         sockdexit(EXIT_FAILURE);

      /*
       * Might possibly continue with old config.
       */

#endif /* !SOCKS_CLIENT */

      haveconfig = 0;
   }
   else {
#if YYDEBUG
      yydebug       = 0;
#endif /* YYDEBUG */

      yylineno      = 1;
      errno         = 0;   /* don't report old errors in yyparse(). */
      haveconfig    = 1;

      /*
       * Special and delayed as long as we can, till immediately before
       * parsing new config.
       * Want to keep a backup of old ones until we know there were no
       * errors adding new logfiles.
       */

#if !SOCKS_CLIENT
      old_log              = sockscf.log;
      old_errlog           = sockscf.errlog;
#endif /* !SOCKS_CLIENT */

      failed_to_add_errlog = failed_to_add_log = 0;

      slog(LOG_DEBUG, "%s: parsing config in file %s", function, filename);

      bzero(&sockscf.log,    sizeof(sockscf.log));
      bzero(&sockscf.errlog, sizeof(sockscf.errlog));

      lex_dorestart = 1;

      parsingconfig = 1;

#if SOCKSLIBRARY_DYNAMIC
      socks_markasnative("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

      yyparse();

#if SOCKSLIBRARY_DYNAMIC
      socks_markasnormal("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

      parsingconfig = 0;

#if !SOCKS_CLIENT
      CMDLINE_OVERRIDE(&sockscf.initial.cmdline, &sockscf.option);

#if !HAVE_PRIVILEGES
      if (!sockscf.state.inited) {
         /*
          * first time.
          */
         if (sockscf.uid.privileged_isset && !sockscf.option.verifyonly) {
            /*
             * If we created any logfiles (rather than just opened already
             * existing ones), they will have been created with the euid/egid
             * we are started with.  If logfiles created by that euid/egid are
             * not writable by our configured privileged userid (if any), it
             * means that upon SIGHUP we will be unable to re-open our own
             * logfiles.  We therefor check whether the logfile(s) were created
             * by ourselves, and if so, make sure they have the right owner.
             */
            logtype_t *logv[] = { &sockscf.log, &sockscf.errlog };
            size_t i;

            for (i = 0; i < ELEMENTS(logv); ++i) {
               size_t fi;

               for (fi = 0; fi < logv[i]->filenoc; ++fi) {
                  if (logv[i]->createdv[fi]) {
                     slog(LOG_DEBUG,
                          "%s: chown(2)-ing created logfile %s to %lu/%lu",
                          function,
                          logv[i]->fnamev[fi],
                          (unsigned long)sockscf.uid.privileged_uid,
                          (unsigned long)sockscf.uid.privileged_gid);

                     if (fchown(logv[i]->filenov[fi],
                                (unsigned long)sockscf.uid.privileged_uid,
                                (unsigned long)sockscf.uid.privileged_gid) != 0)
                        serr("%s: could not fchown(2) created logfile %s to "
                             "privileged uid/gid %lu/%lu.  This means that "
                             "upon SIGHUP, we would not be unable to re-open "
                             "our own logfiles.  This should not happen",
                             function,
                             logv[i]->fnamev[fi],
                             (unsigned long)sockscf.uid.privileged_uid,
                             (unsigned long)sockscf.uid.privileged_gid);
                  }
               }
            }
         }
      }
#endif /* !HAVE_PRIVILEGES */

      if (configure_privileges() != 0) {
         if (sockscf.state.inited) {
            swarn("%s: could not reinitialize privileges after SIGHUP.  "
                  "Will continue without privileges",
                  function);

            sockscf.state.haveprivs = 0;
         }
         else
            serr("%s: could not configure privileges", function);
      }
#endif /* !SOCKS_CLIENT */
   }

   if (yyin != NULL)
      fclose(yyin);

   errno = 0;
   return haveconfig ? 0 : -1;
}

static int
ipaddr_requires_netmask(context, objecttype)
   const addresscontext_t context;
   const objecttype_t objecttype;
{

   switch (objecttype) {
      case object_crule:
#if HAVE_SOCKS_RULES

         return 1;

#else /* !HAVE_SOCKS_RULES */

         switch (context) {
            case from:
               return 1;

            case to:
               return 0; /* address we accept clients on. */

            case bounce:
               return 0; /* address we connect to.        */

            default:
               SERRX(context);
         }
#endif /* !HAVE_SOCKS_RULES */


#if HAVE_SOCKS_HOSTID
      case object_hrule:
         return 1;
#endif /* HAVE_SOCKS_HOSTID */

#if HAVE_SOCKS_RULES
      case object_srule:
         return 1;
#endif /* HAVE_SOCKS_RULES */

      case object_route:
      case object_monitor:
         return 1;

      default:
         SERRX(objecttype);
   }


   /* NOTREACHED */
   return 0;
}


static void
addnumber(numberc, numberv, number)
   size_t *numberc;
   long long *numberv[];
   const long long number;
{
   const char *function = "addnumber()";

   if ((*numberv = realloc(*numberv, sizeof(**numberv) * ((*numberc) + 1)))
   == NULL)
      yyerror("%s: could not allocate %lu bytes of memory for adding "
              "number %lld",
              function, (unsigned long)(sizeof(**numberv) * ((*numberc) + 1)),
              number);

   (*numberv)[(*numberc)++] = number;
}


static void
addrinit(addr, _netmask_required)
   ruleaddr_t *addr;
   const int _netmask_required;
{

   atype            = &addr->atype;

   ipv4             = &addr->addr.ipv4.ip;
   netmask_v4       = &addr->addr.ipv4.mask;

   ipv6             = &addr->addr.ipv6.ip;
   netmask_v6       = &addr->addr.ipv6.maskbits;
   scopeid_v6       = &addr->addr.ipv6.scopeid;

   ipvany           = &addr->addr.ipvany.ip;
   netmask_vany     = &addr->addr.ipvany.mask;

   if (!_netmask_required) {
      netmask_v4->s_addr   = htonl(IPV4_FULLNETMASK);
      *netmask_v6          = IPV6_NETMASKBITS;
      netmask_vany->s_addr = htonl(IPV4_FULLNETMASK);
   }

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
   sockshost_t *addr;
{
   static enum operator_t operatormem;

   netmask_required = 0;

   atype            = &addr->atype;

   ipv4             = &addr->addr.ipv4;
   ipv6             = &addr->addr.ipv6.ip;
   domain           = addr->addr.domain;
   ifname           = addr->addr.ifname;
   url              = addr->addr.urlname;

   port_tcp         = &addr->port;
   port_udp         = &addr->port;
   operator         = &operatormem; /* no operator in gwaddr and not used. */
}

static void
routeinit(route)
   route_t *route;
{
   bzero(route, sizeof(*route));

   state               = &route->gw.state;
   extension           = &state->extension;

   cmethodv            = state->cmethodv;
   cmethodc            = &state->cmethodc;
   smethodv            = state->smethodv;
   smethodc            = &state->smethodc;

#if HAVE_GSSAPI
   gssapiservicename = state->gssapiservicename;
   gssapikeytab      = state->gssapikeytab;
   gssapiencryption  = &state->gssapiencryption;
#endif /* HAVE_GSSAPI */

#if !SOCKS_CLIENT && HAVE_LDAP
   ldapauthorisation              = &state->ldapauthorisation;
   ldapauthentication          = &state->ldapauthentication;
#endif /* !SOCKS_CLIENT && HAVE_LDAP*/

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   src.atype = SOCKS_ADDR_IPV4;
   dst.atype = SOCKS_ADDR_IPV4;

   bzero(&gw, sizeof(gw));
   bzero(&rdr_from, sizeof(rdr_from));
   bzero(&hostid, sizeof(hostid));
}


#if SOCKS_CLIENT
static void
parseclientenv(haveproxyserver)
   int *haveproxyserver;
{
   const char *function = "parseclientenv()";
   const char *fprintf_error = "could not write to tmpfile used to hold "
                               "settings set in environment for parsing";
   size_t i;
   FILE *fp;
   char *p, rdr_from[512], extrarouteinfo[sizeof(rdr_from) + sizeof("\n")],
        gw[MAXSOCKSHOSTLEN + sizeof(" port = 65535")];
   int fd;


#if 1

#if SOCKS_CLIENT
   p = "yaccenv-client-XXXXXX";
#else /* !SOCKS_CLIENT */
   p = "yaccenv-server-XXXXXX";
#endif /* !SOCKS_CLIENT */

   if ((fd = socks_mklock(p, NULL, 0)) == -1)
      yyerror("socks_mklock() failed to create tmpfile using base %s", p);

#else /* for debugging file-generation problems. */
   if ((fd = open("/tmp/dante-envfile",
                  O_CREAT | O_TRUNC | O_RDWR,
                  S_IRUSR | S_IWUSR)) == -1)
      serr("%s: could not open file", function);
#endif

   if ((fp = fdopen(fd, "r+")) == NULL)
      serr("%s: fdopen(fd %d) failed", function, fd);

   if ((p = socks_getenv(ENV_SOCKS_LOGOUTPUT, dontcare)) != NULL && *p != NUL)
      if (fprintf(fp, "logoutput: %s\n", p) == -1)
         serr("%s: %s", function, fprintf_error);

   if ((p = socks_getenv(ENV_SOCKS_ERRLOGOUTPUT, dontcare)) != NULL
   && *p != NUL)
      if (fprintf(fp, "errorlog: %s\n", p) == -1)
         serr("%s: %s", function, fprintf_error);

   if ((p = socks_getenv(ENV_SOCKS_DEBUG, dontcare)) != NULL && *p != NUL)
      if (fprintf(fp, "debug: %s\n", p) == -1)
         serr("%s: %s", function, fprintf_error);

   *rdr_from = NUL;
   if ((p = socks_getenv(ENV_SOCKS_REDIRECT_FROM, dontcare)) != NULL
   && *p != NUL) {
      const char *prefix = "redirect from";

      if (strlen(prefix) + strlen(p) + 1 > sizeof(rdr_from))
         serr("%s: %s value is too long.  Max length is %lu",
              function,
              ENV_SOCKS_REDIRECT_FROM,
              (unsigned long)sizeof(rdr_from) - (strlen(prefix) + 1));

      snprintf(rdr_from, sizeof(rdr_from), "%s: %s\n", prefix, p);
   }

   snprintf(extrarouteinfo, sizeof(extrarouteinfo),
            "%s", rdr_from);

   /*
    * Check if there is a proxy server configured in the environment.
    * Initially assume there is none.
    */

   *haveproxyserver = 0;

   i = 1;
   while (1) {
      /* 640 routes should be enough for anyone. */
      char name[sizeof(ENV_SOCKS_ROUTE_) + sizeof("640")];

      snprintf(name, sizeof(name), "%s%lu", ENV_SOCKS_ROUTE_, (unsigned long)i);

      if ((p = socks_getenv(name, dontcare)) == NULL)
         break;

      if (*p != NUL) {
         if (fprintf(fp, "route { %s }\n", p) == -1)
            serr("%s: %s", function, fprintf_error);

         *haveproxyserver = 1;
      }

      ++i;
   }

   if ((p = socks_getenv(ENV_SOCKS4_SERVER, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         proxyprotocol: socks_v4\n"
"         %s"
"}\n",            serverstring2gwstring(p, PROXY_SOCKS_V4, gw, sizeof(gw)),
                  extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_SOCKS5_SERVER, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         proxyprotocol: socks_v5\n"
"         %s"
"}\n",            serverstring2gwstring(p, PROXY_SOCKS_V5, gw, sizeof(gw)),
                  extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_SOCKS_SERVER, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         %s"
"}\n",            serverstring2gwstring(p, PROXY_SOCKS_V5, gw, sizeof(gw)),
                  extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_HTTP_PROXY, dontcare)) != NULL && *p != NUL) {
      struct sockaddr_storage sa;
      int gaierr;
      char emsg[512];

      if (urlstring2sockaddr(p, &sa, &gaierr, emsg, sizeof(emsg)) == NULL)
         serr("%s: could not convert to %s to an Internet address",
              function, p);

      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s port = %d\n"
"         proxyprotocol: http_v1.0\n"
"         %s"
"}\n",
                  sockaddr2string2(&sa, 0, NULL, 0),
                  ntohs(GET_SOCKADDRPORT(&sa)),
                  extrarouteinfo)
      == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_UPNP_IGD, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         proxyprotocol: upnp\n"
"         %s"
"}\n",            p, extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }


   /*
    * End of possible settings we want to parse with yacc/lex.
    */

   if (fseek(fp, 0, SEEK_SET) != 0)
      yyerror("fseek(3) on tmpfile used to hold environment-settings failed");

   yyin = fp;

   lex_dorestart             = 1;
   parsingconfig             = 1;
   p                         = sockscf.option.configfile;
   sockscf.option.configfile = "<generated socks.conf>";

#if SOCKSLIBRARY_DYNAMIC
   socks_markasnative("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

   yyparse();

#if SOCKSLIBRARY_DYNAMIC
   socks_markasnormal("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

   sockscf.option.configfile = p;
   parsingconfig             = 0;

   fclose(fp);

   if (socks_getenv(ENV_SOCKS_AUTOADD_LANROUTES, isfalse) == NULL) {
      /*
       * assume it's good to add direct routes for the lan also.
       */
      struct ifaddrs *ifap;

      slog(LOG_DEBUG, "%s: auto-adding direct routes for lan ...", function);

      if (getifaddrs(&ifap) == 0) {
         command_t commands;
         protocol_t protocols;
         struct ifaddrs *iface;

         bzero(&commands, sizeof(commands));
         bzero(&protocols, sizeof(protocols));

         protocols.tcp = 1;
         protocols.udp = 1;

         commands.connect      = 1;
         commands.udpassociate = 1;

         for (iface = ifap; iface != NULL; iface = iface->ifa_next)
            if (iface->ifa_addr            != NULL
            &&  iface->ifa_addr->sa_family == AF_INET) {
               if (iface->ifa_netmask == NULL) {
                  swarn("interface %s missing netmask, skipping",
                        iface->ifa_name);
                  continue;
               }

               socks_autoadd_directroute(&commands,
                                         &protocols,
                                         TOCSS(iface->ifa_addr),
                                         TOCSS(iface->ifa_netmask));
            }

         freeifaddrs(ifap);
      }
   }
   else
      slog(LOG_DEBUG, "%s: not auto-adding direct routes for lan", function);
}

static char *
serverstring2gwstring(serverstring, version, gw, gwsize)
   const char *serverstring;
   const int version;
   char *gw;
   const size_t gwsize;
{
   const char *function = "serverstring2gwstring()";
   char *sep, emsg[256];

   if (version != PROXY_SOCKS_V4 && version != PROXY_SOCKS_V5)
      return gw; /* should be in desired format already. */

   if (strlen(serverstring) >= gwsize)
      serrx("%s: value of proxyserver (%s) set in environment is too long.  "
            "Max length is %lu",
            function, serverstring, (unsigned long)(gwsize - 1));

   if ((sep = strrchr(serverstring, ':')) != NULL && *(sep + 1) != NUL) {
      long port;

      if ((port = string2portnumber(sep + 1, emsg, sizeof(emsg))) == -1)
         yyerrorx("%s: %s", function, emsg);

      memcpy(gw, serverstring, sep - serverstring);
      snprintf(&gw[sep - serverstring],
               gwsize - (sep - serverstring),
               " port = %u",
               (in_port_t)port);
   }
   else {
      char visbuf[256];

      yyerrorx("%s: could not find portnumber in %s serverstring \"%s\"",
               function,
               proxyprotocol2string(version),
               str2vis(sep == NULL ? serverstring : sep,
                       strlen(sep == NULL ? serverstring : sep),
                       visbuf,
                       sizeof(visbuf)));
   }

   return gw;
}

#else /* !SOCKS_CLIENT */

static void
pre_addrule(rule)
   rule_t *rule;
{

   rule->src   = src;
   rule->dst   = dst;

#if HAVE_SOCKS_HOSTID
   rule->hostid      = hostid;
#endif /* HAVE_SOCKS_HOSTID */

   rule->rdr_from    = rdr_from;
   rule->rdr_to      = rdr_to;

   if (session_isset) {
      if ((rule->ss = malloc(sizeof(*rule->ss))) == NULL)
         yyerror("failed to malloc(3) %lu bytes for session memory",
                 (unsigned long)sizeof(*rule->ss));

      *rule->ss = ss;
   }

   if (bw_isset) {
      if ((rule->bw = malloc(sizeof(*rule->bw))) == NULL)
         yyerror("failed to malloc(3) %lu bytes for bw memory",
                 (unsigned long)sizeof(*rule->bw));

      *rule->bw = bw;
   }
}


static void
post_addrule(void)
{

   timeout = &sockscf.timeout; /* default is global timeout, unless in a rule */
}

static void
ruleinit(rule)
   rule_t *rule;
{
   bzero(rule, sizeof(*rule));

   rule->linenumber  = yylineno;

#if HAVE_SOCKS_HOSTID

   rule->hostindex          = DEFAULT_HOSTINDEX;
   hostindex                = &rule->hostindex;

   rule->hostidoption_isset = 0;
   hostidoption_isset       = &rule->hostidoption_isset;

#endif /* HAVE_SOCKS_HOSTID */

   state          = &rule->state;

   cmethodv       = state->cmethodv;
   cmethodc       = &state->cmethodc;

   smethodv       = state->smethodv;
   smethodc       = &state->smethodc;

   /*
    * default values: same as global.
    */

   timeout       = &rule->timeout;
   *timeout      = sockscf.timeout;

#if HAVE_GSSAPI

   gssapiservicename = state->gssapiservicename;
   gssapikeytab      = state->gssapikeytab;
   gssapiencryption  = &state->gssapiencryption;

#endif /* HAVE_GSSAPI */

#if HAVE_LDAP

   ldapauthorisation              = &state->ldapauthorisation;
   ldapauthentication             = &state->ldapauthentication;

   ldapauthorisation->auto_off    = ldapauthentication->auto_off  = -1;
   ldapauthorisation->certcheck   = ldapauthentication->certcheck = -1;

   ldapauthorisation->debug       = ldapauthentication->debug
   = LDAP_UNSET_DEBUG_VALUE;

   ldapauthorisation->keeprealm                                   = -1;
   ldapauthorisation->mdepth                                      = -1;
   ldapauthorisation->port        = ldapauthentication->port      = -1;
   ldapauthorisation->portssl     = ldapauthentication->portssl   = -1;
   ldapauthorisation->ssl         = ldapauthentication->ssl       = -1;

   /*
    * Rest should be char arrays and NUL already due to bzero(3).
    */

#endif /* HAVE_LDAP */

#if HAVE_PAC

   rule->objectsids  = NULL;
   rule->pacoff      = 1;

#endif /* HAVE_PAC */

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   bzero(&hostid, sizeof(hostid));

   bzero(&rdr_from, sizeof(rdr_from));
   bzero(&rdr_to, sizeof(rdr_to));

#if BAREFOOTD
   bzero(&bounceto, sizeof(bounceto));
#endif /* BAREFOOTD */

   rule->bw_isinheritable   = rule->ss_isinheritable = 1;

   bzero(&ss, sizeof(ss));
   bzero(&bw, sizeof(bw));

   bw_isset = session_isset = 0;
   bw.type  = SHMEM_BW;
   ss.type  = SHMEM_SS;
}

void
alarminit(void)
{
    static int alarmside_mem;

   alarmside  = &alarmside_mem;
   *alarmside = 0;
}

static void
monitorinit(monitor)
   monitor_t *monitor;
{
   static int alarmside_mem;

   alarmside = &alarmside_mem;

   bzero(monitor, sizeof(*monitor));

   monitor->linenumber = yylineno;

   state                       = &monitor->state;

#if HAVE_SOCKS_HOSTID
   monitor->hostindex          = DEFAULT_HOSTINDEX;
   hostindex                   = &monitor->hostindex;

   monitor->hostidoption_isset = 0;
   hostidoption_isset          = &monitor->hostidoption_isset;
#endif /* HAVE_SOCKS_HOSTID */

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   bzero(&hostid, sizeof(hostid));

   if ((monitor->mstats = malloc(sizeof(*monitor->mstats))) == NULL)
      yyerror("failed to malloc(3) %lu bytes for monitor stats memory",
              (unsigned long)sizeof(*monitor->mstats));
   else
      bzero(monitor->mstats, sizeof(*monitor->mstats));

   monitor->mstats->type = SHMEM_MONITOR;
}

static void
pre_addmonitor(monitor)
   monitor_t *monitor;
{
   monitor->src    = src;
   monitor->dst    = dst;

#if HAVE_SOCKS_HOSTID
   monitor->hostid = hostid;
#endif /* HAVE_SOCKS_HOSTID */
}

static int
configure_privileges(void)
{
   const char *function = "configure_privileges()";
   static int isfirsttime = 1;

   if (sockscf.option.verifyonly)
      return 0;

#if !HAVE_PRIVILEGES
   uid_t uid; /* for debugging. */
   gid_t gid; /* for debugging. */

   SASSERTX(sockscf.state.euid == (uid = geteuid()));
   SASSERTX(sockscf.state.egid == (gid = getegid()));

   /*
    * Check all configured uids/gids work.
    */

   checkugid(&sockscf.uid.privileged_uid,
             &sockscf.uid.privileged_gid,
             &sockscf.uid.privileged_isset,
             "privileged");

   checkugid(&sockscf.uid.unprivileged_uid,
             &sockscf.uid.unprivileged_gid,
             &sockscf.uid.unprivileged_isset,
             "unprivileged");

#if HAVE_LIBWRAP
   if (!sockscf.uid.libwrap_isset
   &&  sockscf.uid.unprivileged_isset) {
      sockscf.uid.libwrap_uid   = sockscf.uid.unprivileged_uid;
      sockscf.uid.libwrap_gid   = sockscf.uid.unprivileged_gid;
      sockscf.uid.libwrap_isset = sockscf.uid.unprivileged_isset;
   }
   else
      checkugid(&sockscf.uid.libwrap_uid,
                &sockscf.uid.libwrap_gid,
                &sockscf.uid.libwrap_isset,
                "libwrap");
#endif /* HAVE_LIBWRAP */

   SASSERTX(sockscf.state.euid == (uid = geteuid()));
   SASSERTX(sockscf.state.egid == (gid = getegid()));

#endif /* !HAVE_PRIVILEGES */

   if (isfirsttime) {
      if (sockd_initprivs() != 0) {
         slog(HAVE_PRIVILEGES ? LOG_INFO : LOG_WARNING,
              "%s: could not initialize privileges (%s)%s",
              function,
              strerror(errno),
              geteuid() == 0 ?
                   "" : ".  Usually we need to be started by root if "
                        "special privileges are to be available");

#if HAVE_PRIVILEGES
         /*
          * assume failure in this case is not fatal; some privileges will
          * not be available to us, and perhaps that is the intention too.
          */
         return 0;

#else
         return -1;
#endif /* !HAVE_PRIVILEGES */
      }

      isfirsttime = 0;
   }

   return 0;
}

static int
checkugid(uid, gid, isset, type)
   uid_t *uid;
   gid_t *gid;
   unsigned char *isset;
   const char *type;
{
   const char *function = "checkugid()";

   SASSERTX(sockscf.state.euid == geteuid());
   SASSERTX(sockscf.state.egid == getegid());

   if (sockscf.option.verifyonly)
      return 0;

   if (!(*isset)) {
      *uid   = sockscf.state.euid;
      *gid   = sockscf.state.egid;
      *isset = 1;

      return 0;
   }

   if (*uid != sockscf.state.euid) {
      if (seteuid(*uid) != 0) {
         swarn("%s: could not seteuid(2) to %s uid %lu",
               function, type, (unsigned long)*uid);

         return -1;
      }

      (void)seteuid(0);

      if (seteuid(sockscf.state.euid) != 0) {
         swarn("%s: could not revert to euid %lu from euid %lu",
               function,
               (unsigned long)sockscf.state.euid,
               (unsigned long)geteuid());
         SWARN(0);

         sockscf.state.euid = geteuid();
         return -1;
      }
   }

   if (*gid != sockscf.state.egid) {
      (void)seteuid(0);

      if (setegid(*gid) != 0) {
         swarn("%s: could not setegid(2) to %s gid %lu",
               function, type, (unsigned long)*gid);

         return -1;
      }

      (void)seteuid(0);

      if (setegid(sockscf.state.egid) != 0) {
         swarn("%s: could not revert to egid %lu from euid %lu",
               function,
               (unsigned long)sockscf.state.egid,
               (unsigned long)geteuid());
         SWARN(0);

         sockscf.state.egid = getegid();
         return -1;
      }

      if (seteuid(sockscf.state.euid) != 0) {
         swarn("%s: could not revert to euid %lu from euid %lu",
               function,
               (unsigned long)sockscf.state.euid,
               (unsigned long)geteuid());
         SWARN(0);

         sockscf.state.euid = geteuid();
         return -1;
      }
   }

   SASSERTX(sockscf.state.euid == geteuid());
   SASSERTX(sockscf.state.egid == getegid());

   return 0;
}

#endif /* !SOCKS_CLIENT */
