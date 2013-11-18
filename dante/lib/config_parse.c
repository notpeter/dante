#include "common.h"
#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define yyparse socks_yyparse
#define yylex socks_yylex
#define yyerror socks_yyerror
#define yychar socks_yychar
#define yyval socks_yyval
#define yylval socks_yylval
#define yydebug socks_yydebug
#define yynerrs socks_yynerrs
#define yyerrflag socks_yyerrflag
#define yyss socks_yyss
#define yysslim socks_yysslim
#define yyssp socks_yyssp
#define yyvs socks_yyvs
#define yyvsp socks_yyvsp
#define yystacksize socks_yystacksize
#define yylhs socks_yylhs
#define yylen socks_yylen
#define yydefred socks_yydefred
#define yydgoto socks_yydgoto
#define yysindex socks_yysindex
#define yyrindex socks_yyrindex
#define yygindex socks_yygindex
#define yytable socks_yytable
#define yycheck socks_yycheck
#define yyname socks_yyname
#define yyrule socks_yyrule
#define YYPREFIX "socks_yy"
#line 46 "config_parse.y"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.703 2013/10/27 15:24:42 karls Exp $";

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

/*
 * Let commandline-options override configfile-options.
 * Currently there's only one such option.
 */
#define LOG_CMDLINE_OVERRIDE(name, newvalue, oldvalue, fmt)                    \
do {                                                                           \
   slog(LOG_NOTICE,                                                            \
        "%s commandline value \"" fmt "\" overrides "                          \
        "config-file value \"" fmt "\" set in file %s",                        \
        name, (newvalue), (oldvalue), sockscf.option.configfile);              \
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

/*
 * Globals because used by functions for reporting parsing errors in
 * parse_util.c
 */
unsigned char   *atype;         /* atype of new address.               */
unsigned char  parsingconfig;   /* currently parsing config?          */

/* for case we are unable to (re-)open logfiles operator specifies. */
#if !SOCKS_CLIENT
static logtype_t       old_log,           old_errlog;
#endif /* !SOCKS_CLIENT */
static int             failed_to_add_log, failed_to_add_errlog;

static unsigned char   add_to_errlog;   /* adding file to errlog or regular?  */

static objecttype_t    objecttype;      /* current object_type we are parsing.*/

#if !SOCKS_CLIENT
static monitor_t       monitor;       /* new monitor.                         */
static monitor_if_t    *monitorif;    /* new monitor interface.               */
static int             *alarmside;    /* data-side to monitor (read/write).   */

static int             cloglevel;     /* current loglevel.                    */
static interfaceside_t ifside;        /* current interface-side               */

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
static ldap_t          *ldap;        /* new ldap server details.              */
#endif /* SOCKS_SERVER && HAVE_LDAP */

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
#line 369 "config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
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
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 384 "config_parse.c"
#define ALARM 257
#define ALARMTYPE_DATA 258
#define ALARMTYPE_DISCONNECT 259
#define ALARMIF_INTERNAL 260
#define ALARMIF_EXTERNAL 261
#define CLIENTCOMPATIBILITY 262
#define NECGSSAPI 263
#define CLIENTRULE 264
#define HOSTIDRULE 265
#define SOCKSRULE 266
#define COMPATIBILITY 267
#define SAMEPORT 268
#define DRAFT_5_05 269
#define CONNECTTIMEOUT 270
#define TCP_FIN_WAIT 271
#define CPU 272
#define MASK 273
#define SCHEDULE 274
#define CPUMASK_ANYCPU 275
#define DEBUGGING 276
#define DEPRECATED 277
#define ERRORLOG 278
#define LOGOUTPUT 279
#define LOGFILE 280
#define LOGTYPE_ERROR 281
#define LOGIF_INTERNAL 282
#define LOGIF_EXTERNAL 283
#define ERRORVALUE 284
#define EXTENSION 285
#define BIND 286
#define PRIVILEGED 287
#define EXTERNAL_ROTATION 288
#define SAMESAME 289
#define GROUPNAME 290
#define HOSTID 291
#define HOSTINDEX 292
#define INTERFACE 293
#define SOCKETOPTION_SYMBOLICVALUE 294
#define INTERNAL 295
#define EXTERNAL 296
#define INTERNALSOCKET 297
#define EXTERNALSOCKET 298
#define IOTIMEOUT 299
#define IOTIMEOUT_TCP 300
#define IOTIMEOUT_UDP 301
#define NEGOTIATETIMEOUT 302
#define LIBWRAP_FILE 303
#define LOGLEVEL 304
#define SOCKSMETHOD 305
#define CLIENTMETHOD 306
#define METHOD 307
#define METHODNAME 308
#define NONE 309
#define BSDAUTH 310
#define GSSAPI 311
#define PAM_ADDRESS 312
#define PAM_ANY 313
#define PAM_USERNAME 314
#define RFC931 315
#define UNAME 316
#define MONITOR 317
#define PROCESSTYPE 318
#define PROC_MAXREQUESTS 319
#define REALM 320
#define REALNAME 321
#define RESOLVEPROTOCOL 322
#define REQUIRED 323
#define SCHEDULEPOLICY 324
#define SERVERCONFIG 325
#define CLIENTCONFIG 326
#define SOCKET 327
#define CLIENTSIDE_SOCKET 328
#define SNDBUF 329
#define RCVBUF 330
#define SOCKETPROTOCOL 331
#define SOCKETOPTION_OPTID 332
#define SRCHOST 333
#define NODNSMISMATCH 334
#define NODNSUNKNOWN 335
#define CHECKREPLYAUTH 336
#define USERNAME 337
#define USER_PRIVILEGED 338
#define USER_UNPRIVILEGED 339
#define USER_LIBWRAP 340
#define WORD__IN 341
#define ROUTE 342
#define VIA 343
#define GLOBALROUTEOPTION 344
#define BADROUTE_EXPIRE 345
#define MAXFAIL 346
#define PORT 347
#define NUMBER 348
#define BANDWIDTH 349
#define BOUNCE 350
#define BSDAUTHSTYLE 351
#define BSDAUTHSTYLENAME 352
#define COMMAND 353
#define COMMAND_BIND 354
#define COMMAND_CONNECT 355
#define COMMAND_UDPASSOCIATE 356
#define COMMAND_BINDREPLY 357
#define COMMAND_UDPREPLY 358
#define ACTION 359
#define FROM 360
#define TO 361
#define GSSAPIENCTYPE 362
#define GSSAPIENC_ANY 363
#define GSSAPIENC_CLEAR 364
#define GSSAPIENC_INTEGRITY 365
#define GSSAPIENC_CONFIDENTIALITY 366
#define GSSAPIENC_PERMESSAGE 367
#define GSSAPIKEYTAB 368
#define GSSAPISERVICE 369
#define GSSAPISERVICENAME 370
#define GSSAPIKEYTABNAME 371
#define IPV4 372
#define IPV6 373
#define IPVANY 374
#define DOMAINNAME 375
#define IFNAME 376
#define URL 377
#define LDAPATTRIBUTE 378
#define LDAPATTRIBUTE_AD 379
#define LDAPATTRIBUTE_HEX 380
#define LDAPATTRIBUTE_AD_HEX 381
#define LDAPBASEDN 382
#define LDAP_BASEDN 383
#define LDAPBASEDN_HEX 384
#define LDAPBASEDN_HEX_ALL 385
#define LDAPCERTFILE 386
#define LDAPCERTPATH 387
#define LDAPPORT 388
#define LDAPPORTSSL 389
#define LDAPDEBUG 390
#define LDAPDEPTH 391
#define LDAPAUTO 392
#define LDAPSEARCHTIME 393
#define LDAPDOMAIN 394
#define LDAP_DOMAIN 395
#define LDAPFILTER 396
#define LDAPFILTER_AD 397
#define LDAPFILTER_HEX 398
#define LDAPFILTER_AD_HEX 399
#define LDAPGROUP 400
#define LDAPGROUP_NAME 401
#define LDAPGROUP_HEX 402
#define LDAPGROUP_HEX_ALL 403
#define LDAPKEYTAB 404
#define LDAPKEYTABNAME 405
#define LDAPDEADTIME 406
#define LDAPSERVER 407
#define LDAPSERVER_NAME 408
#define LDAPSSL 409
#define LDAPCERTCHECK 410
#define LDAPKEEPREALM 411
#define LDAPTIMEOUT 412
#define LDAPCACHE 413
#define LDAPCACHEPOS 414
#define LDAPCACHENEG 415
#define LDAPURL 416
#define LDAP_URL 417
#define LDAP_FILTER 418
#define LDAP_ATTRIBUTE 419
#define LDAP_CERTFILE 420
#define LDAP_CERTPATH 421
#define LIBWRAPSTART 422
#define LIBWRAP_ALLOW 423
#define LIBWRAP_DENY 424
#define LIBWRAP_HOSTS_ACCESS 425
#define LINE 426
#define OPERATOR 427
#define PAMSERVICENAME 428
#define PROTOCOL 429
#define PROTOCOL_TCP 430
#define PROTOCOL_UDP 431
#define PROTOCOL_FAKE 432
#define PROXYPROTOCOL 433
#define PROXYPROTOCOL_SOCKS_V4 434
#define PROXYPROTOCOL_SOCKS_V5 435
#define PROXYPROTOCOL_HTTP 436
#define PROXYPROTOCOL_UPNP 437
#define REDIRECT 438
#define SENDSIDE 439
#define RECVSIDE 440
#define SERVICENAME 441
#define SESSION_INHERITABLE 442
#define SESSIONMAX 443
#define SESSIONTHROTTLE 444
#define SESSIONSTATE_KEY 445
#define SESSIONSTATE_MAX 446
#define SESSIONSTATE_THROTTLE 447
#define RULE_LOG 448
#define RULE_LOG_CONNECT 449
#define RULE_LOG_DATA 450
#define RULE_LOG_DISCONNECT 451
#define RULE_LOG_ERROR 452
#define RULE_LOG_IOOPERATION 453
#define RULE_LOG_TCPINFO 454
#define STATEKEY 455
#define UDPPORTRANGE 456
#define UDPCONNECTDST 457
#define USER 458
#define GROUP 459
#define VERDICT_BLOCK 460
#define VERDICT_PASS 461
#define YES 462
#define NO 463
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
  197,    0,    0,  119,  119,  118,  118,  118,  118,  118,
  117,  117,  116,  116,  116,  116,  116,  116,  116,  116,
  116,  116,  116,  116,  116,  116,  116,  116,  116,  116,
  116,  116,  116,  116,  116,  116,  116,  198,   98,  199,
   99,  100,  101,  101,  102,  131,  131,  131,  131,    5,
  200,  201,  145,  146,  146,   17,   18,   18,   18,   18,
   18,   19,   19,   33,   34,   35,   35,    7,    8,    9,
    9,   62,   63,   64,   64,   68,   69,   70,   71,   65,
   65,   65,   37,   37,   37,   37,   37,   37,   37,   36,
   36,  142,  142,  203,   97,  204,   96,  205,  202,  202,
   52,  137,  137,  137,  138,  139,  140,  141,  132,  132,
  132,  133,  134,  135,    6,   93,   93,   94,   95,   92,
   92,  136,  136,   56,   57,   57,   58,   58,   21,   22,
   22,   22,   59,   59,   60,   61,  206,   24,   25,   25,
   26,   26,   23,   23,   27,   28,   28,   28,   29,   29,
   20,  207,   67,  208,   66,   48,   49,   49,   50,   45,
   46,   46,   47,  209,  210,  111,  211,  172,   38,   38,
  114,  114,  114,   42,   42,   42,  212,   39,   40,   41,
   41,  112,  112,  112,  112,  113,  113,  173,  173,  173,
  173,  173,  174,  174,  213,  180,  181,  181,  214,  183,
  182,  215,  193,  195,  195,  194,  194,  194,  194,  194,
  194,  194,  194,  184,  184,  184,  184,  184,  184,  184,
  184,  184,  184,  184,  184,  184,  184,  184,  185,  185,
  185,  185,  185,  185,  185,  185,  185,  185,  185,  185,
  185,  185,  185,  185,  185,  185,  185,  185,  185,  185,
  185,  185,  185,  185,  185,  185,   80,   80,   87,   81,
   84,   85,  107,   72,   73,   74,   82,   83,  108,  108,
   79,   79,  109,  109,  110,  110,   88,   89,   90,   91,
   75,   76,   77,   78,  105,  106,  104,  103,   86,   53,
   54,   55,   55,  196,  196,    2,    3,    3,    4,    4,
    4,    4,    4,   14,   15,   15,   16,   16,  178,  179,
  115,  115,  115,  120,  120,  120,  122,  121,  121,  124,
  124,  123,  125,  126,  126,  126,  126,  127,  218,  128,
  130,  129,   51,  187,  189,  189,  189,  189,  189,  189,
  188,  188,   13,    1,   12,   11,   10,  220,  220,  220,
  220,  220,  219,  219,  170,  186,  167,  168,  169,  216,
  217,  144,  147,  147,  147,  147,  147,  147,  147,  147,
  147,  147,  147,  148,  148,  149,  176,  177,  221,  222,
  171,  143,  175,  175,  175,  175,  166,  166,  166,  156,
  157,  157,  157,  157,  157,  157,  164,  164,  164,  164,
  165,  165,  158,  190,  190,  159,  191,  160,  223,  161,
  162,  163,  150,  150,  150,  150,  151,  151,  154,  154,
  152,  153,  224,  155,  192,   30,   31,   32,   43,   44,
   44,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylen[] =
#else
short socks_yylen[] =
#endif
	{                                         2,
    0,    4,    3,    0,    2,    1,    1,    1,    1,    1,
    0,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    0,    8,    0,
    8,    1,    1,    2,    1,    1,    1,    1,    1,    1,
    0,    0,    9,    0,    2,    3,    1,    1,    1,    1,
    1,    1,    2,    3,    1,    1,    2,    3,    1,    1,
    2,    3,    1,    1,    2,    4,    0,    4,    0,    3,
    3,    3,    1,    1,    1,    1,    1,    1,    1,    0,
    2,    4,    4,    0,    4,    0,    4,    1,    1,    2,
    3,    1,    1,    1,    3,    3,    3,    1,    3,    3,
    3,    3,    3,    3,    3,    1,    1,    3,    3,    3,
    3,    3,    3,    3,    1,    1,    1,    2,    3,    1,
    1,    1,    1,    1,    9,    7,    0,    7,    1,    1,
    1,    1,    1,    1,    3,    1,    1,    1,    1,    2,
    3,    0,    4,    0,    4,    3,    1,    2,    1,    3,
    1,    2,    1,    0,    0,    8,    0,    8,    1,    1,
    0,    1,    1,    0,    1,    1,    0,    8,    7,    0,
    2,    1,    1,    1,    1,    0,    2,    1,    1,    1,
    1,    1,    0,    2,    0,    8,    1,    1,    0,    4,
    3,    0,    8,    0,    2,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    3,    4,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    1,    1,    2,    1,    1,    3,    1,    2,    1,    1,
    1,    1,    1,    3,    1,    2,    1,    1,    2,    2,
    3,    2,    2,    1,    1,    1,    1,    1,    1,    3,
    3,    3,    5,    1,    1,    1,    1,    3,    0,    4,
    3,    5,    3,    3,    1,    1,    1,    1,    1,    1,
    1,    2,    3,    3,    3,    3,    3,    1,    1,    1,
    1,    1,    1,    2,    4,    3,    3,    3,    3,    3,
    3,    3,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    2,    1,    0,    2,    3,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    2,
    3,    1,    3,    1,    3,    1,    2,    2,    1,    1,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    0,    3,    3,    2,    0,    3,    1,    1,
    3,    1,    1,    1,    1,    5,    1,    1,    1,    1,
    2,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    1,    0,    0,    0,    0,    0,    0,   50,    0,    0,
    0,    0,    0,    0,    0,    0,   84,   83,   88,   54,
    0,   87,   86,   89,   47,   48,   46,   49,   85,    0,
    0,   38,   40,    0,    0,   77,   79,  143,  144,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   17,   16,   31,   32,    0,   37,   33,   13,   14,
   15,  133,  134,   19,   21,   24,   23,   26,   20,   28,
   29,  116,  117,   30,   18,   27,   22,    0,    4,   34,
   35,   36,  102,  103,  104,   25,    0,    0,    0,   94,
   96,    0,    0,    0,    0,    0,    0,    0,    0,   91,
    0,    0,    0,    0,    0,    0,    0,    0,  154,  152,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   12,    0,  113,  114,  115,    0,    0,  109,  110,
  111,  112,  131,  132,  130,  129,    0,    0,   51,   55,
  125,  126,    0,  124,    0,    0,    0,    0,   73,    0,
   72,   81,   80,   82,    0,    0,    0,    0,  101,  151,
  146,  147,  148,    0,  145,  108,  105,  106,  107,  118,
  119,  120,  121,  122,  123,  137,  167,  195,  202,  164,
    9,    5,   10,    6,    7,    8,   98,   95,    0,   97,
   93,   92,    0,  128,    0,    0,   42,    0,    0,   75,
  403,  406,  408,  410,  411,   76,  387,    0,    0,    0,
  388,  389,    0,  383,  384,  385,  386,   78,  159,  155,
    0,  163,  153,    0,  150,    0,    0,    0,    0,    0,
  100,   52,    0,    0,    0,    0,    0,    0,    0,    0,
  390,  158,  162,  140,  139,    0,  294,  295,    0,    0,
    0,  165,    0,    0,    0,    0,    0,  404,  405,  391,
  407,  393,  409,  395,  422,  425,    0,  416,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  364,  370,  369,  368,  367,  371,
  373,  365,  366,    0,    0,  363,  429,    0,  136,    0,
    0,    0,  424,  420,  414,  419,    0,  415,  142,  141,
  138,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  217,
  218,  219,  220,  224,  189,  226,  228,  215,  216,  214,
  190,  225,  319,  191,  314,  318,  315,  316,  324,  325,
  326,  327,  227,  188,    0,    0,  221,  198,  197,  192,
  222,  223,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  206,  207,  210,  211,  213,  234,  235,
  236,  229,  230,  232,  231,  233,  240,  241,  249,  250,
  238,  239,  248,  242,  243,  244,  246,  245,  255,  252,
  253,  254,  256,  251,  237,  247,  317,  212,  208,  209,
    0,    0,  172,  173,  183,  185,  182,  169,  170,    0,
    0,    0,  184,    0,    0,    0,    0,    0,    0,    0,
    0,  379,  372,    0,  375,  377,    0,    0,    0,  431,
    0,   45,   39,    0,   41,  423,  421,  199,    0,    0,
    0,    0,  381,    0,    0,    0,  380,    0,  313,    0,
    0,    0,    0,  329,    0,    0,    0,    0,    0,    0,
  194,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  205,    0,  187,    0,  177,
    0,  291,    0,  290,  376,  299,  300,  301,  302,  303,
  296,    0,  348,  349,  350,  351,  352,  347,    0,  346,
  345,  307,  308,  304,    0,   57,   58,   59,   60,   61,
    0,   56,    0,  378,  309,    0,    0,  382,    0,    0,
  135,   44,    0,  201,  156,  160,  333,    0,  356,  343,
  311,    0,  320,  321,  322,    0,    0,  328,  331,    0,
  335,  336,  337,  338,  339,  340,  334,    0,   65,   66,
    0,   69,   70,    0,    0,  310,    0,    0,  344,  281,
  282,  283,  284,  264,  265,  266,  261,  262,  267,  268,
  257,    0,  260,  271,  272,  259,  277,  278,  279,  280,
  287,  285,  286,  289,  288,  269,  270,  273,  274,  275,
  276,  263,  427,    0,    0,    0,    0,    0,  293,  298,
  354,  306,   63,  360,    0,  357,    0,    0,  200,    0,
    0,  355,  361,    0,  330,    0,  342,   67,   71,  168,
  358,  196,  258,    0,  203,  166,  176,  175,    0,    0,
  359,  412,    0,    0,  399,  400,  362,   53,    0,  401,
  402,  323,  332,  428,  426,    0,    0,  397,  398,    0,
    0,    0,  418,    0,    0,  179,  178,  181,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
  394,  285,  541,  542,   17,   18,  330,  603,  604,  331,
  332,  333,  334,  335,  554,  555,  290,  561,  562,   54,
   19,  136,   56,  336,  246,  311,   58,  164,  165,  398,
  644,  695,  337,  600,  601,   20,   21,  437,  438,  439,
  706,  679,  298,  299,  338,  223,  224,  339,  220,  221,
  340,   59,  341,  533,  534,   60,  143,  144,   61,   62,
   63,  293,  150,  151,   65,   66,   67,   68,  107,   69,
  108,  399,  400,  401,  402,  403,  404,  405,  406,  407,
  408,  409,  410,  411,  412,  413,  414,  415,  416,  417,
  418,   70,   71,   72,   73,   22,   23,   76,   77,  198,
  463,  464,  419,  420,  421,  422,  423,  424,  425,  426,
  181,  440,  441,  442,  342,   78,   79,  182,  123,  343,
  344,  428,  345,  346,  347,  348,  349,  350,  351,  352,
  353,   25,   26,   27,   28,   81,   82,   83,   84,   85,
  167,   29,  569,  570,  140,   99,  294,  295,  296,  241,
  690,  268,  304,  305,  306,  206,  207,  208,  209,  210,
  211,  212,  686,  687,  662,  213,  457,  493,  565,  354,
  474,  184,  355,  356,  218,  458,  566,  459,  495,  185,
  357,  358,  359,  360,  430,  361,  362,  597,  598,  260,
  262,  270,  186,  431,  432,  249,    4,  103,  104,  193,
  253,  188,  127,  128,  189,  226,  158,  157,  230,  275,
  227,  647,  228,  573,  229,  453,  479,  587,  548,  549,
  454,  480,  264,  467,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -224,
    0, -186,    0, 3497,  -12,    3,   11,    0,   21,   25,
   59,   82,   99,  109,  117, -257,    0,    0,    0,    0,
 -186,    0,    0,    0,    0,    0,    0,    0,    0,  122,
   65,    0,    0,  125,  129,    0,    0,    0,    0,  134,
  136,  145,  170,  172,  190,  200,  225,  240,  241,  244,
  245,    0,    0,    0,    0,  -19,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, 3497,    0,    0,
    0,    0,    0,    0,    0,    0, -216,  -35,  -30,    0,
    0,  -28,  -27,  -26,  -25, -322,  278,  279,   -2,    0,
 -171, -151,  292,  293,   55, -237,  285,  286,    0,    0,
    2,   24, -190,   18,   18,   18,   54,   58, -325, -284,
  317,    0, -199,    0,    0,    0,   84,   84,    0,    0,
    0,    0,    0,    0,    0,    0,   17,   19,    0,    0,
    0,    0, -171,    0,  320,  322,   71,   71,    0,   55,
    0,    0,    0,    0, -156, -168,   64,   72,    0,    0,
    0,    0,    0, -190,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   84,    0,
    0,    0,  250,    0,   61,   63,    0,  330,  336,    0,
    0,    0,    0,    0,    0,    0,    0,  337,  339,  345,
    0,    0,   36,    0,    0,    0,    0,    0,    0,    0,
   64,    0,    0,   72,    0, -236, -276, -276, -276,  281,
    0,    0,  344,  356,  140,  141, -286,   67,   75,  -53,
    0,    0,    0,    0,    0,  359,    0,    0,  303,  304,
  305,    0, -227,   81,  106,  381,  382,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -314,    0,  396, -314,
 -244, 3460, 3460, 3561, -228,  385,  386,  387,  388,  391,
  392,  400,  401,  100,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -227,  101,    0,    0,   81,    0,  415,
  179,  179,    0,    0,    0,    0,  116,    0,    0,    0,
    0,  411,  412,  413,  414,  416,  112,  417,  418, -170,
  419,  420,  421,   48,  422,  423,  424,  425,  426,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, 3460,  101,    0,    0,    0,    0,
    0,    0,  101,  427,  428,  434,  439,  440,  444,  451,
  452,  455,  457,  458,  460,  461,  464,  465,  474,  475,
  479,  480,  481,  482,  483,  484,  485,  486,  487,  489,
  492,  494,  495,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 3561,  101,    0,    0,    0,    0,    0,    0,    0, -228,
  101,  -49,    0,  291,   64, -133, -132,  184,  186, -204,
 -222,    0,    0,  499,    0,    0,  198,  503,  220,    0,
  216,    0,    0,  179,    0,    0,    0,    0,  217,   64,
   72,  222,    0,  516,  149,  142,    0,  223,    0,  519,
 -226,  233,  237,    0,  131,  239,  246, -288,  251,  302,
    0, 3460,  198,  535, 3460,  243,  177,  180,  181,  182,
  219,  221,  247,  183,  185,  257,  264,  -31,  274, -217,
  248,  206,  224,  226,  228,  234,  249,  254,  236,  252,
 -211, -209, -202,  230,  300,    0, 3561,    0, -228,    0,
  576,    0,  291,    0,    0,    0,    0,    0,    0,    0,
    0, -133,    0,    0,    0,    0,    0,    0, -132,    0,
    0,    0,    0,    0, -204,    0,    0,    0,    0,    0,
 -222,    0, -156,    0,    0,  591, -156,    0,  598, -227,
    0,    0, -156,    0,    0,    0,    0, -176,    0,    0,
    0, -156,    0,    0,    0,  612,  369,    0,    0,  616,
    0,    0,    0,    0,    0,    0,    0, -288,    0,    0,
  251,    0,    0,  302,  539,    0, -156,  540,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  318,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  623,  544,  545, -201,  331,    0,    0,
    0,    0,    0,    0, -156,    0, -203,  553,    0,  333,
  333,    0,    0,  334,    0,  335,    0,    0,    0,    0,
    0,    0,    0,  341,    0,    0,    0,    0,  626,  634,
    0,    0,  333,  333,    0,    0,    0,    0,  263,    0,
    0,    0,    0,    0,    0,  343,  350,    0,    0, -314,
  351,  362,    0,  360,  361,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    4,    0,   68,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    4,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   68,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  704,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  710,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, 1413,    0,    0,    0,    0,    0,    0, 1237,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, 1506,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, 1595,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    9,  229,  435,
    0,    0,  637,    0,    0,    0,    0,    0,    0,    0,
  836,    0,    0, 1038,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  355,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  364,  364,  365, -221,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -104,    0,    0,    0, 1688,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -103,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -101,    0,    0,    0,    0,    0,    0,    0,    0, -105,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, 1797,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, 2417,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  594,    0,    0,  594,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  596,    0,  -99,    0,
    0,    0, 3262,    0,    0,    0,    0,    0,    0,    0,
    0, 2079,    0,    0,    0,    0,    0,    0, 2248,    0,
    0,    0,    0,    0, 1888,    0,    0,    0,    0,    0,
 2586,    0,    0,    0,    0,    0,    0,    0,    0,  597,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, 2755,    0,    0,
 2924,    0,    0, 3093,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  658,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 3295,
 3295,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, 1193, 1193,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -110,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0, -263,  187,    0,   -3,   43,    0,  124,    0, -246,
 -243, -240,    0, -245,  188,    0, -255,    0,  178,    0,
   52,    0,    0,   -4,    0,    0,    0,    0,  574,    0,
    0,    0,    0,  143,    0,  724,    0,    0,    0,    0,
    0,    0,    0,  448,    0, -193,    0,    0, -205,    0,
    0,    0, -235,    0,  214,    0,    0,  605,    0,    0,
    0,   53,    0,  599,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   69,   77,    0,    0,  602,
 -275,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -401,    0,    0,    0,  673,    0,    0, -238,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   74,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  126,   78,    0,    0,  630,    0,    0, -277,    0,    0,
 -584,    0,  518, -264,    0, -522, -538,  600,  603,    0,
 -154, -153,    0,    0,    0, -520,    0,    0,  267,    0,
    0,    0,    0, -248,    0,  398,    0, -312,    0,    0,
 -252,  176,    0, -231,    0,    0,    0,  166,    0,    0,
    0,   76,    0,    0, -403,   34,    0,    0,    0,    0,
    0,  -86,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  446,  289,    0,  227,    0,
    0,    0,    0,    0,
};
#define YYTABLESIZE 4020
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                      57,
   52,  216,  217,   90,  267,  308,  286,  289,  392,  287,
  395,  435,  288,  622,  180,  242,  455,  292,  397,  186,
  374,  193,  443,  204,  363,  186,  465,  526,  396,  436,
  243,  433,  434,  265,  276,  427,  171,  171,  528,  660,
  654,  190,  429,  492,  656,   87,   53,  286,  289,  309,
  287,  152,  659,  288,    8,   55,   64,   34,  292,  663,
   88,  258,  312,  313,  177,  178,  179,   11,   89,   38,
   39,  153,   74,   57,   52,   24,  691,   80,   90,  277,
   75,   86,   91,    5,    6,  259,  671,   97,   98,    7,
    8,    9,   10,  484,   24,  244,  141,  142,  698,  699,
    1,    2,  231,  310,  154,  485,  491,  133,  134,  135,
  102,  245,   11,   12,   13,   14,   92,  180,  683,  527,
   53,  145,  146,  645,  278,  278,  303,  646,  529,   55,
   64,  124,  681,  392,  279,   15,  172,  173,  186,   93,
  280,  281,  139,  161,  162,  163,   74,  180,  180,  180,
  180,   80,  171,  171,   75,   86,   94,   16,  171,  171,
  591,  592,  593,  594,  595,  596,   95,  395,  201,  202,
  203,  204,  205,  682,   96,  397,  435,  174,  175,  101,
  180,  180,  105,  247,  248,  396,  106,  443,  572,  452,
  477,  109,  427,  110,  436,  201,  202,  203,  204,  429,
  282,  282,  111,  201,  202,  283,  204,  205,  530,  531,
  284,  556,  557,  558,  559,  201,  202,  203,  204,  205,
  536,  537,  538,  539,  540,  552,  553,  112,  394,  113,
  543,  544,  545,  546,  547,  583,  584,  677,  678,  535,
  168,  169,  180,  605,  624,  625,  608,  114,  291,  180,
  636,  637,  638,  639,  186,  374,  193,  115,  204,  640,
  641,  250,  251,  395,  575,  435,  392,  392,  392,  392,
  392,  397,  392,  392,  392,  392,  443,  576,  392,  392,
  392,  396,  116,  436,  392,  392,  392,  392,  427,  291,
  392,  392,  658,  392,  265,  429,  392,  117,  118,  392,
  392,  119,  120,  392,  392,  392,  392,  392,  392,  392,
  392,  121,  125,  392,  392,  392,  621,  126,  180,  129,
  130,  131,  132,  286,  289,  392,  287,  392,  392,  288,
  392,   11,   11,   11,  292,  137,  138,  147,  148,  139,
  149,  392,  155,  156,  160,   90,  392,  392,  392,  159,
  392,  392,  392,  394,  166,  392,  170,  392,  392,  392,
  171,  392,  176,  187,  191,  195,  192,  196,  392,  392,
  392,  219,  232,  266,  197,  235,  392,  392,  233,  222,
  234,  236,  240,  237,   11,  238,  392,  392,  392,  392,
  392,  239,  392,  392,  392,  392,  392,  392,  392,  392,
  392,  254,  392,  252,  392,  392,  392,  392,  392,   11,
  392,  392,  392,  255,  261,  392,  271,  392,  392,  392,
  256,  257,  263,  661,  392,  272,  273,  274,  297,  300,
  392,  392,  392,  392,  396,  703,  392,  392,  301,  302,
  307,  392,  444,  445,  446,  447,  392,  560,  448,  449,
  392,  392,  392,  392,  392,  392,  392,  450,  451,  452,
  456,  461,  462,  466,  392,  392,  392,  392,  468,  469,
  470,  471,  473,  472,  475,  476,  481,  482,  483,  486,
  487,  488,  489,  490,  496,  497,  394,  394,  394,  394,
  394,  498,  394,  394,  394,  394,  499,  500,  394,  394,
  394,  501,  684,  685,  394,  394,  394,  394,  502,  503,
  394,  394,  504,  394,  505,  506,  394,  507,  508,  394,
  394,  509,  510,  394,  394,  394,  394,  394,  394,  394,
  394,  511,  512,  394,  394,  394,  513,  514,  515,  516,
  517,  518,  519,  520,  521,  394,  522,  394,  394,  523,
  394,  524,  525,  532,  550,  551,  563,  560,  564,  396,
  567,  394,  568,  571,  574,  291,  394,  394,  394,  577,
  394,  394,  394,  578,  579,  394,  582,  394,  394,  394,
  585,  394,  580,  477,  586,  588,  589,  599,  394,  394,
  394,  602,  607,  590,  609,  610,  394,  394,  611,  612,
  613,  614,  617,  615,  619,  618,  394,  394,  394,  394,
  394,  620,  394,  394,  394,  394,  394,  394,  394,  394,
  394,  623,  394,  627,  394,  394,  394,  394,  394,  616,
  394,  394,  394,  648,  631,  394,  413,  394,  394,  394,
  634,  628,  626,  629,  394,  630,  642,  643,  655,  632,
  394,  394,  394,  394,  633,  657,  394,  394,  664,  635,
  313,  394,  666,  670,  672,  673,  394,  674,  675,  676,
  394,  394,  394,  394,  394,  394,  394,  688,  680,  689,
  697,  692,  693,  696,  394,  394,  394,  394,  694,  266,
  701,  704,  396,  396,  396,  396,  396,  702,  396,  396,
  396,  396,  705,    3,  396,  396,  396,  707,  708,    2,
  396,  396,  396,  396,  374,  174,  396,  396,  193,  396,
  204,  374,  396,  193,  204,  396,  396,  669,  650,  396,
  396,  396,  396,  396,  396,  396,  396,  225,  653,  396,
  396,  396,  652,  668,  100,  460,  649,  194,  200,  199,
  122,  396,  183,  396,  396,  214,  396,  269,  215,  606,
  494,  413,  665,  667,  700,  478,  581,  396,    0,    0,
    0,    0,  396,  396,  396,  651,  396,  396,  396,    0,
    0,  396,    0,  396,  396,  396,    0,  396,    0,    0,
    0,    0,    0,    0,  396,  396,  396,    0,    0,    0,
    0,    0,  396,  396,    0,    0,    0,    0,    0,    0,
    0,    0,  396,  396,  396,  396,  396,    0,  396,  396,
  396,  396,  396,  396,  396,  396,  396,    0,  396,    0,
  396,  396,  396,  396,  396,  157,  396,  396,  396,    0,
    0,  396,    0,  396,  396,  396,    0,    0,    0,    0,
  396,    0,    0,    0,    0,    0,  396,  396,  396,  396,
    0,    0,  396,  396,    0,    0,    0,  396,    0,    0,
    0,    0,  396,    0,    0,    0,  396,  396,  396,  396,
  396,  396,  396,    0,    0,    0,    0,    0,    0,    0,
  396,  396,  396,  396,  413,  413,  413,  413,  413,    0,
  413,  413,  413,  413,    0,    0,  413,  413,  413,    0,
    0,    0,  413,  413,  413,  413,    0,    0,  413,  413,
    0,  413,    0,    0,  413,    0,    0,  413,  413,    0,
    0,  413,  413,  413,  413,  413,  413,  413,  413,    0,
    0,  413,  413,  413,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  413,    0,  413,  413,    0,  413,    0,
  157,    0,    0,    0,    0,    0,    0,    0,    0,  413,
    0,    0,    0,    0,  413,  413,  413,    0,  413,  413,
  413,    0,    0,    0,    0,  413,  413,  413,    0,  413,
    0,    0,    0,    0,    0,    0,  413,  413,  413,    0,
    0,    0,    0,    0,  413,  413,    0,    0,    0,    0,
    0,    0,    0,    0,  413,  413,  413,  413,  413,    0,
  413,  413,  413,  413,  413,  413,  413,  413,  413,    0,
  413,    0,  413,  413,  413,  413,  413,  161,  413,  413,
  413,    0,    0,  413,    0,  413,  413,  413,    0,    0,
    0,    0,  413,    0,    0,    0,    0,    0,  413,  413,
  413,  413,    0,    0,  413,  413,    0,    0,    0,  413,
    0,    0,    0,    0,  413,    0,    0,    0,  413,  413,
  413,  413,  413,  413,  413,    0,    0,    0,    0,    0,
    0,    0,  413,  413,  413,  413,    0,  157,    0,  157,
  157,  157,  157,    0,    0,  157,  157,  157,    0,    0,
    0,  157,  157,  157,  157,    0,    0,  157,  157,    0,
  157,    0,    0,  157,    0,    0,  157,  157,    0,    0,
  157,  157,  157,  157,  157,  157,  157,  157,    0,    0,
  157,  157,  157,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  157,    0,  157,  157,    0,  157,    0,    0,
    0,    0,  161,    0,    0,    0,    0,    0,  157,    0,
    0,    0,    0,  157,  157,  157,    0,  157,    0,  157,
    0,    0,    0,    0,  157,  157,  157,    0,  157,    0,
    0,    0,    0,    0,    0,  157,    0,  157,    0,    0,
    0,    0,    0,  157,  157,    0,    0,    0,    0,    0,
    0,    0,    0,  157,  157,  157,  157,  157,    0,  157,
  157,  157,  157,  157,  157,  157,  157,  157,    0,  157,
    0,  157,  157,  157,  157,  157,   74,  157,  157,  157,
    0,    0,  157,    0,  157,  157,  157,    0,    0,    0,
    0,  157,    0,    0,    0,    0,    0,  157,  157,  157,
  157,    0,    0,  157,  157,    0,    0,    0,  157,    0,
    0,    0,    0,  157,    0,    0,    0,  157,  157,  157,
  157,  157,  157,  157,    0,    0,    0,    0,    0,    0,
    0,  157,  157,  157,  157,    0,    0,    0,    0,  161,
    0,  161,  161,  161,  161,    0,    0,  161,  161,  161,
    0,    0,    0,  161,  161,  161,  161,  417,    0,  161,
  161,    0,  161,    0,    0,  161,    0,    0,  161,  161,
    0,    0,  161,  161,  161,  161,  161,  161,  161,  161,
    0,    0,  161,  161,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  161,    0,  161,  161,    0,  161,
    0,   74,    0,    0,    0,    0,    0,    0,    0,    0,
  161,    0,    0,    0,    0,  161,  161,  161,    0,  161,
    0,  161,    0,    0,    0,    0,  161,  161,  161,    0,
  161,    0,    0,    0,    0,    0,    0,  161,    0,  161,
    0,    0,    0,    0,    0,  161,  161,    0,    0,    0,
    0,    0,  127,    0,    0,  161,  161,  161,  161,  161,
    0,  161,  161,  161,  161,  161,  161,  161,  161,  161,
    0,  161,    0,  161,  161,  161,  161,  161,    0,  161,
  161,  161,    0,    0,  161,    0,  161,  161,  161,    0,
    0,    0,    0,  161,  417,    0,    0,    0,    0,  161,
  161,  161,  161,    0,    0,  161,  161,    0,    0,    0,
  161,    0,    0,    0,    0,  161,    0,  417,    0,  161,
  161,  161,  161,  161,  161,  161,    0,    0,    0,  417,
  417,    0,    0,  161,  161,  161,  161,    0,   74,  417,
   74,   74,   74,   74,    0,  149,   74,   74,   74,    0,
    0,    0,   74,   74,   74,   74,    0,    0,   74,   74,
    0,   74,    0,    0,   74,    0,    0,    0,    0,    0,
    0,   74,   74,   74,   74,   74,   74,   74,   74,    0,
    0,   74,   74,   74,    0,  417,    0,    0,    0,    0,
    0,    0,    0,   74,  417,   74,   74,    0,   74,    0,
  417,  417,    0,    0,    0,    0,    0,    0,    0,   74,
    0,    0,    0,    0,   74,   74,   74,    0,   74,    0,
   74,    0,    0,    0,    0,    0,    0,    0,    0,   74,
    0,    0,    0,    0,   99,    0,   74,    0,   74,    0,
    0,    0,    0,    0,   74,   74,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  417,    0,    0,    0,  417,    0,    0,    0,    0,
  417,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   74,
   74,   74,    0,    0,    0,   74,    0,    0,    0,   74,
    0,    0,    0,    0,   74,    0,  127,  127,  127,  127,
    0,    0,  127,  127,  127,    0,    0,  430,  127,  127,
  127,  127,    0,   74,  127,  127,    0,  127,    0,    0,
  127,    0,    0,    0,    0,    0,    0,  127,  127,  127,
  127,  127,  127,  127,  127,    0,    0,  127,  127,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  127,
    0,  127,  127,    0,  127,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  127,    0,    0,    0,    0,
  127,  127,  127,    0,  127,    0,  127,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  149,
  149,  149,  149,    0,    0,  149,  149,  149,    0,    0,
    0,  149,  149,  149,  149,    0,    0,  149,  149,    0,
  149,    0,    0,  149,    0,    0,   43,    0,    0,    0,
  149,  149,  149,  149,  149,  149,  149,  149,    0,    0,
  149,  149,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  149,    0,  149,  149,    0,  149,    0,    0,
    0,    0,    0,    0,    0,  127,  127,  127,  149,    0,
    0,    0,    0,  149,  149,  149,    0,  149,    0,  149,
    0,    0,    0,    0,    0,    0,    0,    0,   99,   99,
   99,   99,    0,    0,   99,   99,   99,    0,    0,  127,
   99,   99,   99,   99,    0,    0,   99,   99,    0,   99,
    0,    0,   99,    0,    0,    0,    0,    0,    0,   99,
   99,   99,   99,   99,   99,   99,   99,    0,    0,   99,
   99,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   99,    0,   99,   99,    0,   99,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   99,  149,  149,
  149,    0,   99,   99,   99,    0,   99,    0,   99,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  430,  430,  430,  430,    0,    0,  430,  430,  430,
    0,    0,  149,  430,  430,  430,  430,    0,    0,  430,
  430,    0,  430,    0,    0,  430,    0,    0,    0,    0,
    0,    0,  430,  430,  430,  430,  430,  430,  430,  430,
    0,    0,  430,  430,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  430,    0,  430,  430,    0,  430,
    0,    0,  305,    0,    0,    0,    0,   99,   99,   99,
  430,    0,    0,    0,    0,  430,  430,  430,    0,  430,
    0,  430,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   99,    0,    0,    0,    0,    0,    0,    0,    0,
   43,   43,   43,   43,    0,    0,   43,   43,   43,    0,
    0,    0,   43,   43,   43,   43,    0,    0,   43,   43,
    0,   43,    0,    0,   43,    0,    0,    0,    0,    0,
    0,   43,   43,   43,   43,   43,   43,   43,   43,    0,
    0,   43,   43,    0,    0,    0,    0,    0,    0,    0,
  430,  430,  430,   43,    0,   43,   43,    0,   43,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   43,
    0,    0,    0,    0,   43,   43,   43,    0,   43,    0,
   43,    0,    0,    0,  430,  305,  305,  305,  305,  305,
    0,    0,    0,    0,    0,    0,    0,  305,  305,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  305,    0,    0,    0,    0,    0,  305,  305,
    0,    0,    0,    0,  305,  305,  305,  305,  305,  305,
    0,    0,  305,  305,  305,    0,    0,    0,    0,    0,
    0,    0,    0,  297,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   43,
   43,   43,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  305,  305,  305,    0,
  305,    0,    0,    0,    0,    0,    0,  305,    0,  305,
    0,    0,    0,   43,    0,  305,  305,    0,    0,    0,
    0,    0,    0,    0,    0,  305,  305,  305,  305,  305,
    0,  305,  305,  305,  305,  305,  305,  305,  305,  305,
    0,  305,    0,  305,  305,  305,  305,  305,    0,  305,
  305,  305,    0,    0,  305,    0,  305,  305,  305,    0,
    0,    0,    0,  305,    0,    0,    0,    0,    0,  305,
    0,    0,    0,    0,    0,  305,  305,    0,    0,    0,
  305,    0,    0,    0,    0,  305,    0,    0,    0,  305,
  305,  305,  305,  305,  305,  305,  297,  297,  297,  297,
  297,    0,    0,  305,    0,  305,  305,    0,  297,  297,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  297,    0,    0,    0,    0,    0,  297,
  297,    0,  353,    0,    0,  297,  297,  297,  297,  297,
  297,    0,    0,  297,  297,  297,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  297,    0,  297,
    0,  297,    0,    0,    0,    0,    0,    0,  297,    0,
  297,    0,    0,    0,    0,    0,  297,  297,    0,    0,
    0,    0,    0,    0,    0,    0,  297,  297,  297,  297,
  297,    0,  297,  297,  297,  297,  297,  297,  297,  297,
  297,    0,  297,    0,  297,  297,  297,  297,  297,    0,
  297,  297,  297,    0,    0,  297,    0,  297,  297,  297,
    0,    0,    0,    0,  297,    0,    0,    0,    0,    0,
  297,    0,    0,    0,    0,    0,  297,  297,    0,  353,
    0,  297,    0,    0,    0,    0,  297,  353,  353,    0,
    0,  297,  297,  297,  297,  297,  297,    0,    0,    0,
    0,    0,  353,    0,  297,    0,  297,  297,  353,  353,
    0,  312,    0,    0,  353,  353,  353,  353,  353,  353,
    0,    0,  353,  353,  353,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  353,  353,  353,    0,
  353,    0,    0,    0,    0,    0,    0,  353,    0,  353,
    0,    0,    0,    0,    0,  353,  353,    0,    0,    0,
    0,    0,    0,    0,    0,  353,  353,  353,  353,  353,
    0,  353,  353,  353,  353,  353,  353,  353,  353,  353,
    0,  353,    0,  353,  353,  353,  353,  353,    0,  353,
  353,  353,    0,    0,  353,    0,  353,  353,  353,    0,
    0,    0,    0,  353,    0,    0,    0,    0,    0,  353,
    0,    0,    0,    0,    0,  353,  353,    0,  312,    0,
  353,    0,    0,    0,    0,  353,  312,  312,    0,  353,
  353,  353,  353,  353,  353,  353,    0,    0,    0,    0,
    0,    0,    0,  353,    0,  353,  353,  312,  312,    0,
   62,    0,    0,  312,  312,  312,  312,  312,  312,    0,
    0,  312,  312,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  312,  312,  312,    0,  312,
    0,    0,    0,    0,    0,    0,  312,    0,  312,    0,
    0,    0,    0,    0,  312,  312,    0,    0,    0,    0,
    0,    0,    0,    0,  312,  312,  312,  312,  312,    0,
  312,  312,  312,  312,  312,  312,  312,  312,  312,    0,
  312,    0,  312,  312,  312,  312,  312,    0,  312,  312,
  312,    0,    0,  312,    0,  312,  312,  312,    0,    0,
    0,    0,  312,    0,    0,    0,    0,    0,  312,    0,
    0,    0,    0,    0,  312,  312,    0,   62,    0,  312,
    0,    0,    0,    0,  312,   62,   62,    0,  312,  312,
  312,  312,  312,  312,  312,    0,    0,    0,    0,    0,
   62,    0,  312,    0,  312,  312,   62,   62,    0,  341,
    0,    0,   62,   62,   62,   62,   62,   62,    0,    0,
   62,   62,   62,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   62,    0,   62,    0,   62,    0,
    0,    0,    0,    0,    0,   62,    0,   62,    0,    0,
    0,    0,    0,   62,   62,    0,    0,    0,    0,    0,
    0,    0,    0,   62,   62,   62,   62,   62,    0,   62,
   62,   62,   62,   62,   62,   62,   62,   62,    0,   62,
    0,   62,   62,   62,   62,   62,    0,   62,   62,   62,
    0,    0,   62,    0,   62,   62,   62,    0,    0,    0,
    0,   62,    0,    0,    0,    0,    0,   62,    0,    0,
    0,    0,    0,   62,   62,    0,  341,    0,   62,    0,
    0,    0,    0,   62,  341,  341,    0,    0,   62,   62,
   62,   62,   62,   62,    0,    0,    0,    0,    0,    0,
    0,   62,    0,   62,   62,  341,  341,    0,   64,    0,
    0,  341,  341,  341,  341,  341,  341,    0,    0,  341,
  341,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  341,  341,  341,    0,  341,    0,    0,
    0,    0,    0,    0,  341,    0,  341,    0,    0,    0,
    0,    0,  341,  341,    0,    0,    0,    0,    0,    0,
    0,    0,  341,  341,  341,  341,  341,    0,  341,  341,
  341,  341,  341,  341,  341,  341,  341,    0,  341,    0,
  341,  341,  341,  341,  341,    0,  341,  341,  341,    0,
    0,  341,    0,  341,  341,  341,    0,    0,    0,    0,
  341,    0,    0,    0,    0,    0,  341,    0,    0,    0,
    0,    0,  341,  341,    0,   64,    0,  341,    0,    0,
    0,    0,  341,   64,   64,    0,  341,  341,  341,  341,
  341,  341,  341,    0,    0,    0,    0,    0,    0,    0,
  341,    0,  341,  341,   64,   64,    0,   68,    0,    0,
   64,   64,   64,   64,   64,   64,    0,    0,   64,   64,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   64,   64,   64,    0,   64,    0,    0,    0,
    0,    0,    0,   64,    0,   64,    0,    0,    0,    0,
    0,   64,   64,    0,    0,    0,    0,    0,    0,    0,
    0,   64,   64,   64,   64,   64,    0,   64,   64,   64,
   64,   64,   64,   64,   64,   64,    0,   64,    0,   64,
   64,   64,   64,   64,    0,   64,   64,   64,    0,    0,
   64,    0,   64,   64,   64,    0,    0,    0,    0,   64,
    0,    0,    0,    0,    0,   64,    0,    0,    0,    0,
    0,   64,   64,    0,   68,    0,   64,    0,    0,    0,
    0,   64,   68,   68,    0,   64,   64,   64,   64,   64,
   64,   64,    0,    0,    0,    0,    0,    0,    0,   64,
    0,   64,   64,   68,   68,    0,  292,    0,    0,   68,
   68,   68,   68,   68,   68,    0,    0,   68,   68,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  417,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   68,   68,   68,    0,   68,    0,    0,    0,    0,
    0,    0,   68,    0,   68,    0,    0,    0,    0,    0,
   68,   68,    0,    0,    0,    0,    0,    0,    0,    0,
   68,   68,   68,   68,   68,    0,   68,   68,   68,   68,
   68,   68,   68,   68,   68,    0,   68,    0,   68,   68,
   68,   68,   68,    0,   68,   68,   68,    0,    0,   68,
    0,   68,   68,   68,    0,    0,    0,    0,   68,    0,
    0,    0,    0,    0,   68,    0,    0,    0,    0,    0,
   68,   68,    0,  292,    0,   68,    0,    0,    0,    0,
   68,  292,  292,    0,   68,   68,   68,   68,   68,   68,
   68,    0,    0,    0,    0,    0,  292,    0,   68,    0,
   68,   68,  292,  292,    0,    0,  417,    0,  292,  292,
  292,  292,  292,  292,  417,  417,  292,  292,  292,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  417,  417,    0,    0,    0,
    0,  417,  417,  417,  417,  417,  417,    0,    0,  417,
  417,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  292,  292,    0,    0,  292,    0,    0,    0,    0,    0,
    0,  292,    0,  292,    0,    0,    0,    0,    0,  292,
  292,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  417,  417,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  417,    0,  417,    0,    0,    0,
    0,    0,  417,  417,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  292,    0,    0,    0,    0,    0,  292,
  292,    0,    0,    0,  292,    0,    0,    0,    0,  292,
    0,    0,    0,  292,  292,  292,  292,  292,  292,  292,
    0,    0,    0,    0,    0,    0,  417,    0,    0,  292,
  292,  276,  417,  417,    0,    0,    0,    0,    0,    5,
    6,    0,  417,    0,    0,    0,  417,  417,  417,  417,
  417,  417,  417,    0,    0,    0,    0,    0,    0,    0,
  312,  313,  417,  417,    0,    0,   38,   39,   11,   12,
   13,   14,    0,   30,  314,  315,    5,    6,   31,    0,
    0,    0,    7,    8,    9,   10,    0,    0,   32,   33,
    0,   34,    0,    0,   35,    0,    0,    0,    0,    0,
    0,   36,   37,   38,   39,   11,   12,   13,   14,    0,
    0,   40,   41,    0,    0,    0,    0,    0,  316,  317,
    0,    0,    0,    0,    0,   42,   43,    0,   15,    0,
    0,  279,    0,    0,    0,    0,    0,  280,  281,   44,
    5,    6,    0,    0,   45,   46,   47,    0,    0,    0,
   16,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  312,  313,    0,    0,    0,    0,   38,   39,   11,
   12,   13,   14,    0,    0,  314,  315,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  318,    0,    0,    0,    0,    0,  319,  282,    0,
    0,    0,    0,    0,    0,    0,    0,  320,    0,    0,
    0,  321,  322,  323,  324,  325,  326,  327,    0,  316,
    0,  364,    0,  278,    0,    0,    0,  328,  329,   48,
   49,   50,  279,    0,    0,    0,    0,    0,  280,  281,
    0,    0,    0,    0,    0,    0,    0,    0,  365,  366,
  367,  368,  369,    0,  370,  371,  372,  373,  374,  375,
  376,  377,  378,   51,  379,    0,  380,  381,  382,  383,
  384,    0,  385,  386,  387,    0,    0,  388,    0,  389,
  390,  391,    0,    0,    0,    0,  392,    0,    0,    0,
    0,    0,  318,    0,    0,    0,    0,    0,  319,  282,
    0,    0,    0,  283,    0,    0,    0,    0,  320,    0,
    0,    0,    0,  322,  323,  324,  325,  326,  327,    0,
    0,    0,    0,    0,    0,    0,  393,    0,  328,  329,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                       4,
    4,  156,  156,    0,   58,  270,  253,  253,    0,  253,
  274,  275,  253,   45,  125,  221,  294,  253,  274,  125,
  125,  125,  275,  125,  273,  125,  302,  431,  274,  275,
  224,  260,  261,  348,  262,  274,  258,  259,  440,  578,
  563,  128,  274,  356,  567,   58,    4,  294,  294,  294,
  294,  289,  573,  294,  277,    4,    4,  285,  294,  582,
   58,  348,  291,  292,  264,  265,  266,    0,   58,  297,
  298,  309,    4,   78,   78,    2,  661,    4,   58,  307,
    4,    4,   58,  270,  271,  372,  607,  345,  346,  276,
  277,  278,  279,   46,   21,  332,  268,  269,  683,  684,
  325,  326,  189,  348,  342,   58,  355,  430,  431,  432,
   46,  348,  299,  300,  301,  302,   58,  317,  657,  432,
   78,  273,  274,  527,  353,  353,  441,  529,  441,   78,
   78,  348,  655,  125,  362,  322,  462,  463,  360,   58,
  368,  369,  342,  334,  335,  336,   78,  258,  259,  260,
  261,   78,  258,  259,   78,   78,   58,  344,  258,  259,
  449,  450,  451,  452,  453,  454,   58,  431,  372,  373,
  374,  375,  376,  377,   58,  431,  440,  462,  463,   58,
  291,  292,   58,  460,  461,  431,   58,  440,  464,  360,
  361,   58,  431,   58,  440,  372,  373,  374,  375,  431,
  429,  429,   58,  372,  373,  433,  375,  376,  258,  259,
  438,  434,  435,  436,  437,  372,  373,  374,  375,  376,
  354,  355,  356,  357,  358,  430,  431,   58,    0,   58,
  363,  364,  365,  366,  367,  462,  463,  439,  440,  445,
  115,  116,  353,  492,  462,  463,  495,   58,  253,  360,
  462,  463,  462,  463,  360,  360,  360,   58,  360,  462,
  463,  228,  229,  527,  470,  529,  258,  259,  260,  261,
  262,  527,  264,  265,  266,  267,  529,  471,  270,  271,
  272,  527,   58,  529,  276,  277,  278,  279,  527,  294,
  282,  283,  570,  285,  348,  527,  288,   58,   58,  291,
  292,   58,   58,  295,  296,  297,  298,  299,  300,  301,
  302,  331,  348,  305,  306,  307,  348,  348,  429,  348,
  348,  348,  348,  570,  570,  317,  570,  319,  320,  570,
  322,  264,  265,  266,  570,   58,   58,   46,   46,  342,
  286,  333,   58,   58,  321,  342,  338,  339,  340,  348,
  342,  343,  344,  125,  337,  347,  303,  349,  350,  351,
  303,  353,   46,  280,  348,   46,  348,   46,  360,  361,
  362,  308,  123,  427,  304,   46,  368,  369,  318,  308,
  318,   46,  347,   47,  317,   47,  378,  379,  380,  381,
  382,   47,  384,  385,  386,  387,  388,  389,  390,  391,
  392,   58,  394,  123,  396,  397,  398,  399,  400,  342,
  402,  403,  404,   58,  348,  407,   58,  409,  410,  411,
  281,  281,  348,  578,  416,  123,  123,  123,  348,  324,
  422,  423,  424,  425,    0,  700,  428,  429,   58,   58,
   45,  433,   58,   58,   58,   58,  438,  451,   58,   58,
  442,  443,  444,  445,  446,  447,  448,   58,   58,  360,
  360,   47,  284,  348,  456,  457,  458,  459,   58,   58,
   58,   58,  361,   58,   58,   58,   58,   58,   58,   58,
   58,   58,   58,   58,   58,   58,  258,  259,  260,  261,
  262,   58,  264,  265,  266,  267,   58,   58,  270,  271,
  272,   58,  657,  657,  276,  277,  278,  279,   58,   58,
  282,  283,   58,  285,   58,   58,  288,   58,   58,  291,
  292,   58,   58,  295,  296,  297,  298,  299,  300,  301,
  302,   58,   58,  305,  306,  307,   58,   58,   58,   58,
   58,   58,   58,   58,   58,  317,   58,  319,  320,   58,
  322,   58,   58,  263,  371,  370,   58,  561,  361,  125,
   58,  333,  343,  348,  348,  570,  338,  339,  340,  348,
  342,  343,  344,   58,  426,  347,   58,  349,  350,  351,
  348,  353,  441,  361,  348,  455,  348,  337,  360,  361,
  362,  290,   58,  348,  352,  419,  368,  369,  419,  419,
  419,  383,  420,  383,  348,  421,  378,  379,  380,  381,
  382,  348,  384,  385,  386,  387,  388,  389,  390,  391,
  392,  348,  394,  418,  396,  397,  398,  399,  400,  383,
  402,  403,  404,   58,  401,  407,    0,  409,  410,  411,
  405,  418,  395,  418,  416,  418,  417,  348,   58,  401,
  422,  423,  424,  425,  401,   58,  428,  429,   47,  408,
  292,  433,   47,  125,  125,  348,  438,   45,  125,  125,
  442,  443,  444,  445,  446,  447,  448,  125,  348,  347,
   47,  348,  348,   58,  456,  457,  458,  459,  348,  427,
  348,  341,  258,  259,  260,  261,  262,  348,  264,  265,
  266,  267,  341,    0,  270,  271,  272,  348,  348,    0,
  276,  277,  278,  279,  360,   58,  282,  283,  125,  285,
  125,  125,  288,  360,  360,  291,  292,  604,  542,  295,
  296,  297,  298,  299,  300,  301,  302,  164,  561,  305,
  306,  307,  555,  601,   21,  298,  533,  143,  150,  148,
   78,  317,  123,  319,  320,  156,  322,  240,  156,  493,
  363,  125,  587,  598,  689,  320,  478,  333,   -1,   -1,
   -1,   -1,  338,  339,  340,  549,  342,  343,  344,   -1,
   -1,  347,   -1,  349,  350,  351,   -1,  353,   -1,   -1,
   -1,   -1,   -1,   -1,  360,  361,  362,   -1,   -1,   -1,
   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  378,  379,  380,  381,  382,   -1,  384,  385,
  386,  387,  388,  389,  390,  391,  392,   -1,  394,   -1,
  396,  397,  398,  399,  400,    0,  402,  403,  404,   -1,
   -1,  407,   -1,  409,  410,  411,   -1,   -1,   -1,   -1,
  416,   -1,   -1,   -1,   -1,   -1,  422,  423,  424,  425,
   -1,   -1,  428,  429,   -1,   -1,   -1,  433,   -1,   -1,
   -1,   -1,  438,   -1,   -1,   -1,  442,  443,  444,  445,
  446,  447,  448,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  456,  457,  458,  459,  258,  259,  260,  261,  262,   -1,
  264,  265,  266,  267,   -1,   -1,  270,  271,  272,   -1,
   -1,   -1,  276,  277,  278,  279,   -1,   -1,  282,  283,
   -1,  285,   -1,   -1,  288,   -1,   -1,  291,  292,   -1,
   -1,  295,  296,  297,  298,  299,  300,  301,  302,   -1,
   -1,  305,  306,  307,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  317,   -1,  319,  320,   -1,  322,   -1,
  125,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  333,
   -1,   -1,   -1,   -1,  338,  339,  340,   -1,  342,  343,
  344,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,  353,
   -1,   -1,   -1,   -1,   -1,   -1,  360,  361,  362,   -1,
   -1,   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  378,  379,  380,  381,  382,   -1,
  384,  385,  386,  387,  388,  389,  390,  391,  392,   -1,
  394,   -1,  396,  397,  398,  399,  400,    0,  402,  403,
  404,   -1,   -1,  407,   -1,  409,  410,  411,   -1,   -1,
   -1,   -1,  416,   -1,   -1,   -1,   -1,   -1,  422,  423,
  424,  425,   -1,   -1,  428,  429,   -1,   -1,   -1,  433,
   -1,   -1,   -1,   -1,  438,   -1,   -1,   -1,  442,  443,
  444,  445,  446,  447,  448,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  456,  457,  458,  459,   -1,  262,   -1,  264,
  265,  266,  267,   -1,   -1,  270,  271,  272,   -1,   -1,
   -1,  276,  277,  278,  279,   -1,   -1,  282,  283,   -1,
  285,   -1,   -1,  288,   -1,   -1,  291,  292,   -1,   -1,
  295,  296,  297,  298,  299,  300,  301,  302,   -1,   -1,
  305,  306,  307,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  317,   -1,  319,  320,   -1,  322,   -1,   -1,
   -1,   -1,  125,   -1,   -1,   -1,   -1,   -1,  333,   -1,
   -1,   -1,   -1,  338,  339,  340,   -1,  342,   -1,  344,
   -1,   -1,   -1,   -1,  349,  350,  351,   -1,  353,   -1,
   -1,   -1,   -1,   -1,   -1,  360,   -1,  362,   -1,   -1,
   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  378,  379,  380,  381,  382,   -1,  384,
  385,  386,  387,  388,  389,  390,  391,  392,   -1,  394,
   -1,  396,  397,  398,  399,  400,    0,  402,  403,  404,
   -1,   -1,  407,   -1,  409,  410,  411,   -1,   -1,   -1,
   -1,  416,   -1,   -1,   -1,   -1,   -1,  422,  423,  424,
  425,   -1,   -1,  428,  429,   -1,   -1,   -1,  433,   -1,
   -1,   -1,   -1,  438,   -1,   -1,   -1,  442,  443,  444,
  445,  446,  447,  448,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  456,  457,  458,  459,   -1,   -1,   -1,   -1,  262,
   -1,  264,  265,  266,  267,   -1,   -1,  270,  271,  272,
   -1,   -1,   -1,  276,  277,  278,  279,  125,   -1,  282,
  283,   -1,  285,   -1,   -1,  288,   -1,   -1,  291,  292,
   -1,   -1,  295,  296,  297,  298,  299,  300,  301,  302,
   -1,   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  317,   -1,  319,  320,   -1,  322,
   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  333,   -1,   -1,   -1,   -1,  338,  339,  340,   -1,  342,
   -1,  344,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,
  353,   -1,   -1,   -1,   -1,   -1,   -1,  360,   -1,  362,
   -1,   -1,   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,
   -1,   -1,    0,   -1,   -1,  378,  379,  380,  381,  382,
   -1,  384,  385,  386,  387,  388,  389,  390,  391,  392,
   -1,  394,   -1,  396,  397,  398,  399,  400,   -1,  402,
  403,  404,   -1,   -1,  407,   -1,  409,  410,  411,   -1,
   -1,   -1,   -1,  416,  262,   -1,   -1,   -1,   -1,  422,
  423,  424,  425,   -1,   -1,  428,  429,   -1,   -1,   -1,
  433,   -1,   -1,   -1,   -1,  438,   -1,  285,   -1,  442,
  443,  444,  445,  446,  447,  448,   -1,   -1,   -1,  297,
  298,   -1,   -1,  456,  457,  458,  459,   -1,  262,  307,
  264,  265,  266,  267,   -1,    0,  270,  271,  272,   -1,
   -1,   -1,  276,  277,  278,  279,   -1,   -1,  282,  283,
   -1,  285,   -1,   -1,  288,   -1,   -1,   -1,   -1,   -1,
   -1,  295,  296,  297,  298,  299,  300,  301,  302,   -1,
   -1,  305,  306,  307,   -1,  353,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  317,  362,  319,  320,   -1,  322,   -1,
  368,  369,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  333,
   -1,   -1,   -1,   -1,  338,  339,  340,   -1,  342,   -1,
  344,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  353,
   -1,   -1,   -1,   -1,    0,   -1,  360,   -1,  362,   -1,
   -1,   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  429,   -1,   -1,   -1,  433,   -1,   -1,   -1,   -1,
  438,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  423,
  424,  425,   -1,   -1,   -1,  429,   -1,   -1,   -1,  433,
   -1,   -1,   -1,   -1,  438,   -1,  264,  265,  266,  267,
   -1,   -1,  270,  271,  272,   -1,   -1,    0,  276,  277,
  278,  279,   -1,  457,  282,  283,   -1,  285,   -1,   -1,
  288,   -1,   -1,   -1,   -1,   -1,   -1,  295,  296,  297,
  298,  299,  300,  301,  302,   -1,   -1,  305,  306,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  317,
   -1,  319,  320,   -1,  322,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  333,   -1,   -1,   -1,   -1,
  338,  339,  340,   -1,  342,   -1,  344,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  264,
  265,  266,  267,   -1,   -1,  270,  271,  272,   -1,   -1,
   -1,  276,  277,  278,  279,   -1,   -1,  282,  283,   -1,
  285,   -1,   -1,  288,   -1,   -1,    0,   -1,   -1,   -1,
  295,  296,  297,  298,  299,  300,  301,  302,   -1,   -1,
  305,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  317,   -1,  319,  320,   -1,  322,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  423,  424,  425,  333,   -1,
   -1,   -1,   -1,  338,  339,  340,   -1,  342,   -1,  344,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  264,  265,
  266,  267,   -1,   -1,  270,  271,  272,   -1,   -1,  457,
  276,  277,  278,  279,   -1,   -1,  282,  283,   -1,  285,
   -1,   -1,  288,   -1,   -1,   -1,   -1,   -1,   -1,  295,
  296,  297,  298,  299,  300,  301,  302,   -1,   -1,  305,
  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  317,   -1,  319,  320,   -1,  322,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  333,  423,  424,
  425,   -1,  338,  339,  340,   -1,  342,   -1,  344,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  264,  265,  266,  267,   -1,   -1,  270,  271,  272,
   -1,   -1,  457,  276,  277,  278,  279,   -1,   -1,  282,
  283,   -1,  285,   -1,   -1,  288,   -1,   -1,   -1,   -1,
   -1,   -1,  295,  296,  297,  298,  299,  300,  301,  302,
   -1,   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  317,   -1,  319,  320,   -1,  322,
   -1,   -1,  125,   -1,   -1,   -1,   -1,  423,  424,  425,
  333,   -1,   -1,   -1,   -1,  338,  339,  340,   -1,  342,
   -1,  344,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  457,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  264,  265,  266,  267,   -1,   -1,  270,  271,  272,   -1,
   -1,   -1,  276,  277,  278,  279,   -1,   -1,  282,  283,
   -1,  285,   -1,   -1,  288,   -1,   -1,   -1,   -1,   -1,
   -1,  295,  296,  297,  298,  299,  300,  301,  302,   -1,
   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  423,  424,  425,  317,   -1,  319,  320,   -1,  322,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  333,
   -1,   -1,   -1,   -1,  338,  339,  340,   -1,  342,   -1,
  344,   -1,   -1,   -1,  457,  258,  259,  260,  261,  262,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  270,  271,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  285,   -1,   -1,   -1,   -1,   -1,  291,  292,
   -1,   -1,   -1,   -1,  297,  298,  299,  300,  301,  302,
   -1,   -1,  305,  306,  307,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  423,
  424,  425,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,
  353,   -1,   -1,   -1,   -1,   -1,   -1,  360,   -1,  362,
   -1,   -1,   -1,  457,   -1,  368,  369,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  378,  379,  380,  381,  382,
   -1,  384,  385,  386,  387,  388,  389,  390,  391,  392,
   -1,  394,   -1,  396,  397,  398,  399,  400,   -1,  402,
  403,  404,   -1,   -1,  407,   -1,  409,  410,  411,   -1,
   -1,   -1,   -1,  416,   -1,   -1,   -1,   -1,   -1,  422,
   -1,   -1,   -1,   -1,   -1,  428,  429,   -1,   -1,   -1,
  433,   -1,   -1,   -1,   -1,  438,   -1,   -1,   -1,  442,
  443,  444,  445,  446,  447,  448,  258,  259,  260,  261,
  262,   -1,   -1,  456,   -1,  458,  459,   -1,  270,  271,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  285,   -1,   -1,   -1,   -1,   -1,  291,
  292,   -1,  125,   -1,   -1,  297,  298,  299,  300,  301,
  302,   -1,   -1,  305,  306,  307,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  349,   -1,  351,
   -1,  353,   -1,   -1,   -1,   -1,   -1,   -1,  360,   -1,
  362,   -1,   -1,   -1,   -1,   -1,  368,  369,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  378,  379,  380,  381,
  382,   -1,  384,  385,  386,  387,  388,  389,  390,  391,
  392,   -1,  394,   -1,  396,  397,  398,  399,  400,   -1,
  402,  403,  404,   -1,   -1,  407,   -1,  409,  410,  411,
   -1,   -1,   -1,   -1,  416,   -1,   -1,   -1,   -1,   -1,
  422,   -1,   -1,   -1,   -1,   -1,  428,  429,   -1,  262,
   -1,  433,   -1,   -1,   -1,   -1,  438,  270,  271,   -1,
   -1,  443,  444,  445,  446,  447,  448,   -1,   -1,   -1,
   -1,   -1,  285,   -1,  456,   -1,  458,  459,  291,  292,
   -1,  125,   -1,   -1,  297,  298,  299,  300,  301,  302,
   -1,   -1,  305,  306,  307,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,
  353,   -1,   -1,   -1,   -1,   -1,   -1,  360,   -1,  362,
   -1,   -1,   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  378,  379,  380,  381,  382,
   -1,  384,  385,  386,  387,  388,  389,  390,  391,  392,
   -1,  394,   -1,  396,  397,  398,  399,  400,   -1,  402,
  403,  404,   -1,   -1,  407,   -1,  409,  410,  411,   -1,
   -1,   -1,   -1,  416,   -1,   -1,   -1,   -1,   -1,  422,
   -1,   -1,   -1,   -1,   -1,  428,  429,   -1,  262,   -1,
  433,   -1,   -1,   -1,   -1,  438,  270,  271,   -1,  442,
  443,  444,  445,  446,  447,  448,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  456,   -1,  458,  459,  291,  292,   -1,
  125,   -1,   -1,  297,  298,  299,  300,  301,  302,   -1,
   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,  353,
   -1,   -1,   -1,   -1,   -1,   -1,  360,   -1,  362,   -1,
   -1,   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  378,  379,  380,  381,  382,   -1,
  384,  385,  386,  387,  388,  389,  390,  391,  392,   -1,
  394,   -1,  396,  397,  398,  399,  400,   -1,  402,  403,
  404,   -1,   -1,  407,   -1,  409,  410,  411,   -1,   -1,
   -1,   -1,  416,   -1,   -1,   -1,   -1,   -1,  422,   -1,
   -1,   -1,   -1,   -1,  428,  429,   -1,  262,   -1,  433,
   -1,   -1,   -1,   -1,  438,  270,  271,   -1,  442,  443,
  444,  445,  446,  447,  448,   -1,   -1,   -1,   -1,   -1,
  285,   -1,  456,   -1,  458,  459,  291,  292,   -1,  125,
   -1,   -1,  297,  298,  299,  300,  301,  302,   -1,   -1,
  305,  306,  307,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  349,   -1,  351,   -1,  353,   -1,
   -1,   -1,   -1,   -1,   -1,  360,   -1,  362,   -1,   -1,
   -1,   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  378,  379,  380,  381,  382,   -1,  384,
  385,  386,  387,  388,  389,  390,  391,  392,   -1,  394,
   -1,  396,  397,  398,  399,  400,   -1,  402,  403,  404,
   -1,   -1,  407,   -1,  409,  410,  411,   -1,   -1,   -1,
   -1,  416,   -1,   -1,   -1,   -1,   -1,  422,   -1,   -1,
   -1,   -1,   -1,  428,  429,   -1,  262,   -1,  433,   -1,
   -1,   -1,   -1,  438,  270,  271,   -1,   -1,  443,  444,
  445,  446,  447,  448,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  456,   -1,  458,  459,  291,  292,   -1,  125,   -1,
   -1,  297,  298,  299,  300,  301,  302,   -1,   -1,  305,
  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  349,  350,  351,   -1,  353,   -1,   -1,
   -1,   -1,   -1,   -1,  360,   -1,  362,   -1,   -1,   -1,
   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  378,  379,  380,  381,  382,   -1,  384,  385,
  386,  387,  388,  389,  390,  391,  392,   -1,  394,   -1,
  396,  397,  398,  399,  400,   -1,  402,  403,  404,   -1,
   -1,  407,   -1,  409,  410,  411,   -1,   -1,   -1,   -1,
  416,   -1,   -1,   -1,   -1,   -1,  422,   -1,   -1,   -1,
   -1,   -1,  428,  429,   -1,  262,   -1,  433,   -1,   -1,
   -1,   -1,  438,  270,  271,   -1,  442,  443,  444,  445,
  446,  447,  448,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  456,   -1,  458,  459,  291,  292,   -1,  125,   -1,   -1,
  297,  298,  299,  300,  301,  302,   -1,   -1,  305,  306,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  349,  350,  351,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,  360,   -1,  362,   -1,   -1,   -1,   -1,
   -1,  368,  369,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  378,  379,  380,  381,  382,   -1,  384,  385,  386,
  387,  388,  389,  390,  391,  392,   -1,  394,   -1,  396,
  397,  398,  399,  400,   -1,  402,  403,  404,   -1,   -1,
  407,   -1,  409,  410,  411,   -1,   -1,   -1,   -1,  416,
   -1,   -1,   -1,   -1,   -1,  422,   -1,   -1,   -1,   -1,
   -1,  428,  429,   -1,  262,   -1,  433,   -1,   -1,   -1,
   -1,  438,  270,  271,   -1,  442,  443,  444,  445,  446,
  447,  448,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  456,
   -1,  458,  459,  291,  292,   -1,  125,   -1,   -1,  297,
  298,  299,  300,  301,  302,   -1,   -1,  305,  306,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  125,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  349,  350,  351,   -1,  353,   -1,   -1,   -1,   -1,
   -1,   -1,  360,   -1,  362,   -1,   -1,   -1,   -1,   -1,
  368,  369,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  378,  379,  380,  381,  382,   -1,  384,  385,  386,  387,
  388,  389,  390,  391,  392,   -1,  394,   -1,  396,  397,
  398,  399,  400,   -1,  402,  403,  404,   -1,   -1,  407,
   -1,  409,  410,  411,   -1,   -1,   -1,   -1,  416,   -1,
   -1,   -1,   -1,   -1,  422,   -1,   -1,   -1,   -1,   -1,
  428,  429,   -1,  262,   -1,  433,   -1,   -1,   -1,   -1,
  438,  270,  271,   -1,  442,  443,  444,  445,  446,  447,
  448,   -1,   -1,   -1,   -1,   -1,  285,   -1,  456,   -1,
  458,  459,  291,  292,   -1,   -1,  262,   -1,  297,  298,
  299,  300,  301,  302,  270,  271,  305,  306,  307,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  291,  292,   -1,   -1,   -1,
   -1,  297,  298,  299,  300,  301,  302,   -1,   -1,  305,
  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  349,  350,   -1,   -1,  353,   -1,   -1,   -1,   -1,   -1,
   -1,  360,   -1,  362,   -1,   -1,   -1,   -1,   -1,  368,
  369,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  349,  350,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  360,   -1,  362,   -1,   -1,   -1,
   -1,   -1,  368,  369,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  422,   -1,   -1,   -1,   -1,   -1,  428,
  429,   -1,   -1,   -1,  433,   -1,   -1,   -1,   -1,  438,
   -1,   -1,   -1,  442,  443,  444,  445,  446,  447,  448,
   -1,   -1,   -1,   -1,   -1,   -1,  422,   -1,   -1,  458,
  459,  262,  428,  429,   -1,   -1,   -1,   -1,   -1,  270,
  271,   -1,  438,   -1,   -1,   -1,  442,  443,  444,  445,
  446,  447,  448,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  291,  292,  458,  459,   -1,   -1,  297,  298,  299,  300,
  301,  302,   -1,  267,  305,  306,  270,  271,  272,   -1,
   -1,   -1,  276,  277,  278,  279,   -1,   -1,  282,  283,
   -1,  285,   -1,   -1,  288,   -1,   -1,   -1,   -1,   -1,
   -1,  295,  296,  297,  298,  299,  300,  301,  302,   -1,
   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,  349,  350,
   -1,   -1,   -1,   -1,   -1,  319,  320,   -1,  322,   -1,
   -1,  362,   -1,   -1,   -1,   -1,   -1,  368,  369,  333,
  270,  271,   -1,   -1,  338,  339,  340,   -1,   -1,   -1,
  344,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  291,  292,   -1,   -1,   -1,   -1,  297,  298,  299,
  300,  301,  302,   -1,   -1,  305,  306,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  422,   -1,   -1,   -1,   -1,   -1,  428,  429,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  438,   -1,   -1,
   -1,  442,  443,  444,  445,  446,  447,  448,   -1,  349,
   -1,  351,   -1,  353,   -1,   -1,   -1,  458,  459,  423,
  424,  425,  362,   -1,   -1,   -1,   -1,   -1,  368,  369,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  378,  379,
  380,  381,  382,   -1,  384,  385,  386,  387,  388,  389,
  390,  391,  392,  457,  394,   -1,  396,  397,  398,  399,
  400,   -1,  402,  403,  404,   -1,   -1,  407,   -1,  409,
  410,  411,   -1,   -1,   -1,   -1,  416,   -1,   -1,   -1,
   -1,   -1,  422,   -1,   -1,   -1,   -1,   -1,  428,  429,
   -1,   -1,   -1,  433,   -1,   -1,   -1,   -1,  438,   -1,
   -1,   -1,   -1,  443,  444,  445,  446,  447,  448,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  456,   -1,  458,  459,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 463
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const socks_yyname[] =
#else
char *socks_yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,"'-'","'.'","'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"ALARM",
"ALARMTYPE_DATA","ALARMTYPE_DISCONNECT","ALARMIF_INTERNAL","ALARMIF_EXTERNAL",
"CLIENTCOMPATIBILITY","NECGSSAPI","CLIENTRULE","HOSTIDRULE","SOCKSRULE",
"COMPATIBILITY","SAMEPORT","DRAFT_5_05","CONNECTTIMEOUT","TCP_FIN_WAIT","CPU",
"MASK","SCHEDULE","CPUMASK_ANYCPU","DEBUGGING","DEPRECATED","ERRORLOG",
"LOGOUTPUT","LOGFILE","LOGTYPE_ERROR","LOGIF_INTERNAL","LOGIF_EXTERNAL",
"ERRORVALUE","EXTENSION","BIND","PRIVILEGED","EXTERNAL_ROTATION","SAMESAME",
"GROUPNAME","HOSTID","HOSTINDEX","INTERFACE","SOCKETOPTION_SYMBOLICVALUE",
"INTERNAL","EXTERNAL","INTERNALSOCKET","EXTERNALSOCKET","IOTIMEOUT",
"IOTIMEOUT_TCP","IOTIMEOUT_UDP","NEGOTIATETIMEOUT","LIBWRAP_FILE","LOGLEVEL",
"SOCKSMETHOD","CLIENTMETHOD","METHOD","METHODNAME","NONE","BSDAUTH","GSSAPI",
"PAM_ADDRESS","PAM_ANY","PAM_USERNAME","RFC931","UNAME","MONITOR","PROCESSTYPE",
"PROC_MAXREQUESTS","REALM","REALNAME","RESOLVEPROTOCOL","REQUIRED",
"SCHEDULEPOLICY","SERVERCONFIG","CLIENTCONFIG","SOCKET","CLIENTSIDE_SOCKET",
"SNDBUF","RCVBUF","SOCKETPROTOCOL","SOCKETOPTION_OPTID","SRCHOST",
"NODNSMISMATCH","NODNSUNKNOWN","CHECKREPLYAUTH","USERNAME","USER_PRIVILEGED",
"USER_UNPRIVILEGED","USER_LIBWRAP","WORD__IN","ROUTE","VIA","GLOBALROUTEOPTION",
"BADROUTE_EXPIRE","MAXFAIL","PORT","NUMBER","BANDWIDTH","BOUNCE","BSDAUTHSTYLE",
"BSDAUTHSTYLENAME","COMMAND","COMMAND_BIND","COMMAND_CONNECT",
"COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","FROM",
"TO","GSSAPIENCTYPE","GSSAPIENC_ANY","GSSAPIENC_CLEAR","GSSAPIENC_INTEGRITY",
"GSSAPIENC_CONFIDENTIALITY","GSSAPIENC_PERMESSAGE","GSSAPIKEYTAB",
"GSSAPISERVICE","GSSAPISERVICENAME","GSSAPIKEYTABNAME","IPV4","IPV6","IPVANY",
"DOMAINNAME","IFNAME","URL","LDAPATTRIBUTE","LDAPATTRIBUTE_AD",
"LDAPATTRIBUTE_HEX","LDAPATTRIBUTE_AD_HEX","LDAPBASEDN","LDAP_BASEDN",
"LDAPBASEDN_HEX","LDAPBASEDN_HEX_ALL","LDAPCERTFILE","LDAPCERTPATH","LDAPPORT",
"LDAPPORTSSL","LDAPDEBUG","LDAPDEPTH","LDAPAUTO","LDAPSEARCHTIME","LDAPDOMAIN",
"LDAP_DOMAIN","LDAPFILTER","LDAPFILTER_AD","LDAPFILTER_HEX","LDAPFILTER_AD_HEX",
"LDAPGROUP","LDAPGROUP_NAME","LDAPGROUP_HEX","LDAPGROUP_HEX_ALL","LDAPKEYTAB",
"LDAPKEYTABNAME","LDAPDEADTIME","LDAPSERVER","LDAPSERVER_NAME","LDAPSSL",
"LDAPCERTCHECK","LDAPKEEPREALM","LDAPTIMEOUT","LDAPCACHE","LDAPCACHEPOS",
"LDAPCACHENEG","LDAPURL","LDAP_URL","LDAP_FILTER","LDAP_ATTRIBUTE",
"LDAP_CERTFILE","LDAP_CERTPATH","LIBWRAPSTART","LIBWRAP_ALLOW","LIBWRAP_DENY",
"LIBWRAP_HOSTS_ACCESS","LINE","OPERATOR","PAMSERVICENAME","PROTOCOL",
"PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL",
"PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_HTTP",
"PROXYPROTOCOL_UPNP","REDIRECT","SENDSIDE","RECVSIDE","SERVICENAME",
"SESSION_INHERITABLE","SESSIONMAX","SESSIONTHROTTLE","SESSIONSTATE_KEY",
"SESSIONSTATE_MAX","SESSIONSTATE_THROTTLE","RULE_LOG","RULE_LOG_CONNECT",
"RULE_LOG_DATA","RULE_LOG_DISCONNECT","RULE_LOG_ERROR","RULE_LOG_IOOPERATION",
"RULE_LOG_TCPINFO","STATEKEY","UDPPORTRANGE","UDPCONNECTDST","USER","GROUP",
"VERDICT_BLOCK","VERDICT_PASS","YES","NO",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const socks_yyrule[] =
#else
char *socks_yyrule[] =
#endif
	{"$accept : configtype",
"$$1 :",
"configtype : SERVERCONFIG $$1 serveroptions serverobjects",
"configtype : CLIENTCONFIG clientoptions routes",
"serverobjects :",
"serverobjects : serverobjects serverobject",
"serverobject : crule",
"serverobject : hrule",
"serverobject : srule",
"serverobject : monitor",
"serverobject : route",
"serveroptions :",
"serveroptions : serveroption serveroptions",
"serveroption : childstate",
"serveroption : compatibility",
"serveroption : cpu",
"serveroption : debugging",
"serveroption : deprecated",
"serveroption : errorlog",
"serveroption : extension",
"serveroption : external",
"serveroption : external_rotation",
"serveroption : external_logoption",
"serveroption : global_clientmethod",
"serveroption : global_socksmethod",
"serveroption : global_routeoption",
"serveroption : internal",
"serveroption : internal_logoption",
"serveroption : libwrap_hosts_access",
"serveroption : libwrapfiles",
"serveroption : logoutput",
"serveroption : realm",
"serveroption : resolveprotocol",
"serveroption : srchost",
"serveroption : timeout",
"serveroption : udpconnectdst",
"serveroption : userids",
"serveroption : socketoption",
"$$2 :",
"internal_logoption : LOGIF_INTERNAL $$2 '.' loglevel '.' LOGTYPE_ERROR ':' errors",
"$$3 :",
"external_logoption : LOGIF_EXTERNAL $$3 '.' loglevel '.' LOGTYPE_ERROR ':' errors",
"loglevel : LOGLEVEL",
"errors : errorobject",
"errors : errorobject errors",
"errorobject : ERRORVALUE",
"timeout : connecttimeout",
"timeout : iotimeout",
"timeout : negotiatetimeout",
"timeout : tcp_fin_timeout",
"deprecated : DEPRECATED",
"$$4 :",
"$$5 :",
"route : ROUTE $$4 '{' $$5 routeoptions fromto gateway routeoptions '}'",
"routes :",
"routes : routes route",
"proxyprotocol : PROXYPROTOCOL ':' proxyprotocols",
"proxyprotocolname : PROXYPROTOCOL_SOCKS_V4",
"proxyprotocolname : PROXYPROTOCOL_SOCKS_V5",
"proxyprotocolname : PROXYPROTOCOL_HTTP",
"proxyprotocolname : PROXYPROTOCOL_UPNP",
"proxyprotocolname : deprecated",
"proxyprotocols : proxyprotocolname",
"proxyprotocols : proxyprotocolname proxyprotocols",
"user : USER ':' usernames",
"username : USERNAME",
"usernames : username",
"usernames : usernames username",
"group : GROUP ':' groupnames",
"groupname : GROUPNAME",
"groupnames : groupname",
"groupnames : groupnames groupname",
"extension : EXTENSION ':' extensions",
"extensionname : BIND",
"extensions : extensionname",
"extensions : extensionname extensions",
"internal : INTERNAL internalinit ':' address",
"internalinit :",
"external : EXTERNAL externalinit ':' externaladdress",
"externalinit :",
"external_rotation : EXTERNAL_ROTATION ':' NONE",
"external_rotation : EXTERNAL_ROTATION ':' SAMESAME",
"external_rotation : EXTERNAL_ROTATION ':' ROUTE",
"clientoption : debugging",
"clientoption : deprecated",
"clientoption : global_routeoption",
"clientoption : errorlog",
"clientoption : logoutput",
"clientoption : resolveprotocol",
"clientoption : timeout",
"clientoptions :",
"clientoptions : clientoption clientoptions",
"global_routeoption : GLOBALROUTEOPTION MAXFAIL ':' NUMBER",
"global_routeoption : GLOBALROUTEOPTION BADROUTE_EXPIRE ':' NUMBER",
"$$6 :",
"errorlog : ERRORLOG ':' $$6 logoutputdevices",
"$$7 :",
"logoutput : LOGOUTPUT ':' $$7 logoutputdevices",
"logoutputdevice : LOGFILE",
"logoutputdevices : logoutputdevice",
"logoutputdevices : logoutputdevice logoutputdevices",
"childstate : PROC_MAXREQUESTS ':' NUMBER",
"userids : user_privileged",
"userids : user_unprivileged",
"userids : user_libwrap",
"user_privileged : USER_PRIVILEGED ':' userid",
"user_unprivileged : USER_UNPRIVILEGED ':' userid",
"user_libwrap : USER_LIBWRAP ':' userid",
"userid : USERNAME",
"iotimeout : IOTIMEOUT ':' NUMBER",
"iotimeout : IOTIMEOUT_TCP ':' NUMBER",
"iotimeout : IOTIMEOUT_UDP ':' NUMBER",
"negotiatetimeout : NEGOTIATETIMEOUT ':' NUMBER",
"connecttimeout : CONNECTTIMEOUT ':' NUMBER",
"tcp_fin_timeout : TCP_FIN_WAIT ':' NUMBER",
"debugging : DEBUGGING ':' NUMBER",
"libwrapfiles : libwrap_allowfile",
"libwrapfiles : libwrap_denyfile",
"libwrap_allowfile : LIBWRAP_ALLOW ':' LIBWRAP_FILE",
"libwrap_denyfile : LIBWRAP_DENY ':' LIBWRAP_FILE",
"libwrap_hosts_access : LIBWRAP_HOSTS_ACCESS ':' YES",
"libwrap_hosts_access : LIBWRAP_HOSTS_ACCESS ':' NO",
"udpconnectdst : UDPCONNECTDST ':' YES",
"udpconnectdst : UDPCONNECTDST ':' NO",
"compatibility : COMPATIBILITY ':' compatibilitynames",
"compatibilityname : SAMEPORT",
"compatibilityname : DRAFT_5_05",
"compatibilitynames : compatibilityname",
"compatibilitynames : compatibilityname compatibilitynames",
"resolveprotocol : RESOLVEPROTOCOL ':' resolveprotocolname",
"resolveprotocolname : PROTOCOL_FAKE",
"resolveprotocolname : PROTOCOL_TCP",
"resolveprotocolname : PROTOCOL_UDP",
"cpu : cpuschedule",
"cpu : cpuaffinity",
"cpuschedule : CPU '.' SCHEDULE '.' PROCESSTYPE ':' SCHEDULEPOLICY '/' NUMBER",
"cpuaffinity : CPU '.' MASK '.' PROCESSTYPE ':' numbers",
"$$8 :",
"socketoption : socketside SOCKETPROTOCOL '.' $$8 socketoptionname ':' socketoptionvalue",
"socketoptionname : NUMBER",
"socketoptionname : SOCKETOPTION_OPTID",
"socketoptionvalue : NUMBER",
"socketoptionvalue : SOCKETOPTION_SYMBOLICVALUE",
"socketside : INTERNALSOCKET",
"socketside : EXTERNALSOCKET",
"srchost : SRCHOST ':' srchostoptions",
"srchostoption : NODNSMISMATCH",
"srchostoption : NODNSUNKNOWN",
"srchostoption : CHECKREPLYAUTH",
"srchostoptions : srchostoption",
"srchostoptions : srchostoption srchostoptions",
"realm : REALM ':' REALNAME",
"$$9 :",
"global_clientmethod : CLIENTMETHOD ':' $$9 clientmethods",
"$$10 :",
"global_socksmethod : SOCKSMETHOD ':' $$10 socksmethods",
"socksmethod : SOCKSMETHOD ':' socksmethods",
"socksmethods : socksmethodname",
"socksmethods : socksmethodname socksmethods",
"socksmethodname : METHODNAME",
"clientmethod : CLIENTMETHOD ':' clientmethods",
"clientmethods : clientmethodname",
"clientmethods : clientmethodname clientmethods",
"clientmethodname : METHODNAME",
"$$11 :",
"$$12 :",
"monitor : MONITOR $$11 '{' $$12 monitoroptions fromto monitoroptions '}'",
"$$13 :",
"crule : CLIENTRULE $$13 verdict '{' cruleoptions fromto cruleoptions '}'",
"alarm : alarm_data",
"alarm : alarm_disconnect",
"monitorside :",
"monitorside : ALARMIF_INTERNAL",
"monitorside : ALARMIF_EXTERNAL",
"alarmside :",
"alarmside : RECVSIDE",
"alarmside : SENDSIDE",
"$$14 :",
"alarm_data : monitorside ALARMTYPE_DATA $$14 alarmside ':' NUMBER WORD__IN NUMBER",
"alarm_disconnect : monitorside ALARMTYPE_DISCONNECT ':' NUMBER '/' NUMBER alarmperiod",
"alarmperiod :",
"alarmperiod : WORD__IN NUMBER",
"monitoroption : alarm",
"monitoroption : command",
"monitoroption : hostidoption",
"monitoroption : protocol",
"monitoroptions :",
"monitoroptions : monitoroption monitoroptions",
"cruleoption : bounce",
"cruleoption : protocol",
"cruleoption : clientcompatibility",
"cruleoption : crulesessionoption",
"cruleoption : genericruleoption",
"cruleoptions :",
"cruleoptions : cruleoption cruleoptions",
"$$15 :",
"hrule : HOSTIDRULE $$15 verdict '{' cruleoptions hostid_fromto cruleoptions '}'",
"hostidoption : hostid",
"hostidoption : hostindex",
"$$16 :",
"hostid : HOSTID ':' $$16 address_without_port",
"hostindex : HOSTINDEX ':' NUMBER",
"$$17 :",
"srule : SOCKSRULE $$17 verdict '{' sruleoptions fromto sruleoptions '}'",
"sruleoptions :",
"sruleoptions : sruleoption sruleoptions",
"sruleoption : bsdauthstylename",
"sruleoption : command",
"sruleoption : genericruleoption",
"sruleoption : ldapoption",
"sruleoption : protocol",
"sruleoption : proxyprotocol",
"sruleoption : sockssessionoption",
"sruleoption : udpportrange",
"genericruleoption : bandwidth",
"genericruleoption : clientmethod",
"genericruleoption : socksmethod",
"genericruleoption : group",
"genericruleoption : gssapienctype",
"genericruleoption : gssapikeytab",
"genericruleoption : gssapiservicename",
"genericruleoption : hostidoption",
"genericruleoption : libwrap",
"genericruleoption : log",
"genericruleoption : pamservicename",
"genericruleoption : redirect",
"genericruleoption : socketoption",
"genericruleoption : timeout",
"genericruleoption : user",
"ldapoption : ldapattribute",
"ldapoption : ldapattribute_ad",
"ldapoption : ldapattribute_ad_hex",
"ldapoption : ldapattribute_hex",
"ldapoption : ldapauto",
"ldapoption : lbasedn",
"ldapoption : lbasedn_hex",
"ldapoption : lbasedn_hex_all",
"ldapoption : ldapcertcheck",
"ldapoption : ldapcertfile",
"ldapoption : ldapcertpath",
"ldapoption : ldapdebug",
"ldapoption : ldapdepth",
"ldapoption : ldapdomain",
"ldapoption : ldapfilter",
"ldapoption : ldapfilter_ad",
"ldapoption : ldapfilter_ad_hex",
"ldapoption : ldapfilter_hex",
"ldapoption : ldapkeeprealm",
"ldapoption : ldapkeytab",
"ldapoption : ldapport",
"ldapoption : ldapportssl",
"ldapoption : ldapssl",
"ldapoption : lgroup",
"ldapoption : lgroup_hex",
"ldapoption : lgroup_hex_all",
"ldapoption : lserver",
"ldapoption : lurl",
"ldapdebug : LDAPDEBUG ':' NUMBER",
"ldapdebug : LDAPDEBUG ':' '-' NUMBER",
"ldapdomain : LDAPDOMAIN ':' LDAP_DOMAIN",
"ldapdepth : LDAPDEPTH ':' NUMBER",
"ldapcertfile : LDAPCERTFILE ':' LDAP_CERTFILE",
"ldapcertpath : LDAPCERTPATH ':' LDAP_CERTPATH",
"lurl : LDAPURL ':' LDAP_URL",
"lbasedn : LDAPBASEDN ':' LDAP_BASEDN",
"lbasedn_hex : LDAPBASEDN_HEX ':' LDAP_BASEDN",
"lbasedn_hex_all : LDAPBASEDN_HEX_ALL ':' LDAP_BASEDN",
"ldapport : LDAPPORT ':' NUMBER",
"ldapportssl : LDAPPORTSSL ':' NUMBER",
"ldapssl : LDAPSSL ':' YES",
"ldapssl : LDAPSSL ':' NO",
"ldapauto : LDAPAUTO ':' YES",
"ldapauto : LDAPAUTO ':' NO",
"ldapcertcheck : LDAPCERTCHECK ':' YES",
"ldapcertcheck : LDAPCERTCHECK ':' NO",
"ldapkeeprealm : LDAPKEEPREALM ':' YES",
"ldapkeeprealm : LDAPKEEPREALM ':' NO",
"ldapfilter : LDAPFILTER ':' LDAP_FILTER",
"ldapfilter_ad : LDAPFILTER_AD ':' LDAP_FILTER",
"ldapfilter_hex : LDAPFILTER_HEX ':' LDAP_FILTER",
"ldapfilter_ad_hex : LDAPFILTER_AD_HEX ':' LDAP_FILTER",
"ldapattribute : LDAPATTRIBUTE ':' LDAP_ATTRIBUTE",
"ldapattribute_ad : LDAPATTRIBUTE_AD ':' LDAP_ATTRIBUTE",
"ldapattribute_hex : LDAPATTRIBUTE_HEX ':' LDAP_ATTRIBUTE",
"ldapattribute_ad_hex : LDAPATTRIBUTE_AD_HEX ':' LDAP_ATTRIBUTE",
"lgroup_hex : LDAPGROUP_HEX ':' LDAPGROUP_NAME",
"lgroup_hex_all : LDAPGROUP_HEX_ALL ':' LDAPGROUP_NAME",
"lgroup : LDAPGROUP ':' LDAPGROUP_NAME",
"lserver : LDAPSERVER ':' LDAPSERVER_NAME",
"ldapkeytab : LDAPKEYTAB ':' LDAPKEYTABNAME",
"clientcompatibility : CLIENTCOMPATIBILITY ':' clientcompatibilitynames",
"clientcompatibilityname : NECGSSAPI",
"clientcompatibilitynames : clientcompatibilityname",
"clientcompatibilitynames : clientcompatibilityname clientcompatibilitynames",
"verdict : VERDICT_BLOCK",
"verdict : VERDICT_PASS",
"command : COMMAND ':' commands",
"commands : commandname",
"commands : commandname commands",
"commandname : COMMAND_BIND",
"commandname : COMMAND_CONNECT",
"commandname : COMMAND_UDPASSOCIATE",
"commandname : COMMAND_BINDREPLY",
"commandname : COMMAND_UDPREPLY",
"protocol : PROTOCOL ':' protocols",
"protocols : protocolname",
"protocols : protocolname protocols",
"protocolname : PROTOCOL_TCP",
"protocolname : PROTOCOL_UDP",
"fromto : srcaddress dstaddress",
"hostid_fromto : hostid_srcaddress dstaddress",
"redirect : REDIRECT rdr_fromaddress rdr_toaddress",
"redirect : REDIRECT rdr_fromaddress",
"redirect : REDIRECT rdr_toaddress",
"sessionoption : sessionmax",
"sessionoption : sessionthrottle",
"sessionoption : sessionstate",
"sockssessionoption : sessionoption",
"crulesessionoption : sessioninheritable",
"crulesessionoption : sessionoption",
"sessioninheritable : SESSION_INHERITABLE ':' YES",
"sessioninheritable : SESSION_INHERITABLE ':' NO",
"sessionmax : SESSIONMAX ':' NUMBER",
"sessionthrottle : SESSIONTHROTTLE ':' NUMBER '/' NUMBER",
"sessionstate : sessionstate_key",
"sessionstate : sessionstate_keyinfo",
"sessionstate : sessionstate_throttle",
"sessionstate : sessionstate_max",
"sessionstate_key : SESSIONSTATE_KEY ':' STATEKEY",
"$$18 :",
"sessionstate_keyinfo : SESSIONSTATE_KEY '.' $$18 hostindex",
"sessionstate_max : SESSIONSTATE_MAX ':' NUMBER",
"sessionstate_throttle : SESSIONSTATE_THROTTLE ':' NUMBER '/' NUMBER",
"bandwidth : BANDWIDTH ':' NUMBER",
"log : RULE_LOG ':' logs",
"logname : RULE_LOG_CONNECT",
"logname : RULE_LOG_DATA",
"logname : RULE_LOG_DISCONNECT",
"logname : RULE_LOG_ERROR",
"logname : RULE_LOG_IOOPERATION",
"logname : RULE_LOG_TCPINFO",
"logs : logname",
"logs : logname logs",
"pamservicename : PAMSERVICENAME ':' SERVICENAME",
"bsdauthstylename : BSDAUTHSTYLE ':' BSDAUTHSTYLENAME",
"gssapiservicename : GSSAPISERVICE ':' GSSAPISERVICENAME",
"gssapikeytab : GSSAPIKEYTAB ':' GSSAPIKEYTABNAME",
"gssapienctype : GSSAPIENCTYPE ':' gssapienctypes",
"gssapienctypename : GSSAPIENC_ANY",
"gssapienctypename : GSSAPIENC_CLEAR",
"gssapienctypename : GSSAPIENC_INTEGRITY",
"gssapienctypename : GSSAPIENC_CONFIDENTIALITY",
"gssapienctypename : GSSAPIENC_PERMESSAGE",
"gssapienctypes : gssapienctypename",
"gssapienctypes : gssapienctypename gssapienctypes",
"bounce : BOUNCE bounceto ':' bouncetoaddress",
"libwrap : LIBWRAPSTART ':' LINE",
"srcaddress : from ':' address",
"hostid_srcaddress : from ':' address_without_port",
"dstaddress : to ':' address",
"rdr_fromaddress : rdr_from ':' address",
"rdr_toaddress : rdr_to ':' address",
"gateway : via ':' gwaddress",
"routeoption : routemethod",
"routeoption : command",
"routeoption : clientcompatibility",
"routeoption : extension",
"routeoption : protocol",
"routeoption : gssapiservicename",
"routeoption : gssapikeytab",
"routeoption : gssapienctype",
"routeoption : proxyprotocol",
"routeoption : REDIRECT rdr_fromaddress",
"routeoption : socketoption",
"routeoptions :",
"routeoptions : routeoption routeoptions",
"routemethod : METHOD ':' socksmethods",
"from : FROM",
"to : TO",
"rdr_from : FROM",
"rdr_to : TO",
"bounceto : TO",
"via : VIA",
"externaladdress : ipv4",
"externaladdress : ipv6",
"externaladdress : domain",
"externaladdress : ifname",
"address_without_port : ipaddress",
"address_without_port : domain",
"address_without_port : ifname",
"address : address_without_port port",
"ipaddress : ipv4 '/' netmask_v4",
"ipaddress : ipv4",
"ipaddress : ipv6 '/' netmask_v6",
"ipaddress : ipv6",
"ipaddress : ipvany '/' netmask_vany",
"ipaddress : ipvany",
"gwaddress : ipaddress gwport",
"gwaddress : domain gwport",
"gwaddress : ifname",
"gwaddress : url",
"bouncetoaddress : ipaddress gwport",
"bouncetoaddress : domain gwport",
"ipv4 : IPV4",
"netmask_v4 : NUMBER",
"netmask_v4 : IPV4",
"ipv6 : IPV6",
"netmask_v6 : NUMBER",
"ipvany : IPVANY",
"netmask_vany : NUMBER",
"domain : DOMAINNAME",
"ifname : IFNAME",
"url : URL",
"port :",
"port : PORT ':' portnumber",
"port : PORT portoperator portnumber",
"port : PORT portrange",
"gwport :",
"gwport : PORT portoperator portnumber",
"portnumber : portservice",
"portnumber : portstart",
"portrange : portstart '-' portend",
"portstart : NUMBER",
"portend : NUMBER",
"portservice : SERVICENAME",
"portoperator : OPERATOR",
"udpportrange : UDPPORTRANGE ':' udpportrange_start '-' udpportrange_end",
"udpportrange_start : NUMBER",
"udpportrange_end : NUMBER",
"number : NUMBER",
"numbers : number",
"numbers : number numbers",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 2855 "config_parse.y"

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
#endif

#if !SOCKS_CLIENT
   if (sockscf.state.inited)
      /* in case we need something special to (re)open config-file. */
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
#endif /* SERVER */

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
         sockdexit(0);

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
      yyparse();
      parsingconfig = 0;

      fclose(yyin);

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
   ldap              = &state->ldap;
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

   yyparse();

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
      if (pidismother(sockscf.state.pid) == 1) {
         if ((rule->ss = malloc(sizeof(*rule->ss))) == NULL)
            yyerror("failed to malloc(3) %lu bytes for session memory",
                    (unsigned long)sizeof(*rule->ss));

         *rule->ss = ss;
      }
      else
         rule->ss = &ss;
   }

   if (bw_isset) {
      if (pidismother(sockscf.state.pid) == 1) {
         if ((rule->bw = malloc(sizeof(*rule->bw))) == NULL)
            yyerror("failed to malloc(3) %lu bytes for bw memory",
                    (unsigned long)sizeof(*rule->bw));

         *rule->bw = bw;
      }
      else
         rule->bw = &bw;
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
   ldap              = &state->ldap;
#endif

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

   if (pidismother(sockscf.state.pid) == 1) {
      if ((monitor->mstats = malloc(sizeof(*monitor->mstats))) == NULL)
         yyerror("failed to malloc(3) %lu bytes for monitor stats memory",
                 (unsigned long)sizeof(*monitor->mstats));
      else
         bzero(monitor->mstats, sizeof(*monitor->mstats));
   }

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
#line 3237 "config_parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || defined(__STDC__)
yyparse(void)
#else
yyparse()
#endif
{
    int yym, yyn, yystate;
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
    const char *yys;
#else /* !(defined(__cplusplus) || defined(__STDC__)) */
    char *yys;
#endif /* !(defined(__cplusplus) || defined(__STDC__)) */

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
#line 583 "config_parse.y"
{
#if !SOCKS_CLIENT
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
break;
case 4:
#line 591 "config_parse.y"
{ yyval.string = NULL; }
break;
case 11:
#line 602 "config_parse.y"
{ yyval.string = NULL; }
break;
case 37:
#line 629 "config_parse.y"
{
      if (!addedsocketoption(&sockscf.socketoptionc,
                             &sockscf.socketoptionv,
                             &socketopt))
         yywarn("could not add socket option");
   }
break;
case 38:
#line 638 "config_parse.y"
{
#if !SOCKS_CLIENT

      ifside = INTERNALIF;

#endif /* !SOCKS_CLIENT */

   }
break;
case 40:
#line 648 "config_parse.y"
{
#if !SOCKS_CLIENT

      ifside = EXTERNALIF;

#endif /* !SOCKS_CLIENT */

   }
break;
case 42:
#line 658 "config_parse.y"
{
#if !SOCKS_CLIENT
   SASSERTX(yyvsp[0].number >= 0);
   SASSERTX(yyvsp[0].number < MAXLOGLEVELS);

   cloglevel = yyvsp[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 45:
#line 672 "config_parse.y"
{
#if !SOCKS_CLIENT

   if (yyvsp[0].error.valuev == NULL)
      yywarnx("unknown error symbol specified");
   else {
      logspecial_t *l;
      size_t *ec, ec_max, i;
      int *ev;

      if (ifside == INTERNALIF)
         l = &sockscf.internal.log;
      else {
         SASSERTX(ifside == EXTERNALIF);

         l = &sockscf.external.log;
      }


      switch (yyvsp[0].error.valuetype) {
         case VALUETYPE_ERRNO:
            ev     = l->errno_loglevelv[cloglevel];
            ec     = &l->errno_loglevelc[cloglevel];
            ec_max = ELEMENTS(l->errno_loglevelv[cloglevel]);
            break;

         case VALUETYPE_GAIERR:
            ev     = l->gaierr_loglevelv[cloglevel];
            ec     = &l->gaierr_loglevelc[cloglevel];
            ec_max = ELEMENTS(l->gaierr_loglevelv[cloglevel]);
            break;

         default:
            SERRX(yyvsp[0].error.valuetype);
      }

      for (i = 0; yyvsp[0].error.valuev[i] != 0; ++i) {
         /*
          * If the value is already set in the array, e.g. because some
          * errno-symbols have the same values, ignore this value.
          */
         size_t j;

         for (j = 0; j < *ec; ++j) {
            if (ev[j] == yyvsp[0].error.valuev[i])
               break;
         }

         if (j < *ec)
            continue; /* error-value already set in array. */

         SASSERTX(*ec < ec_max);

         ev[(*ec)] = yyvsp[0].error.valuev[i];
         ++(*ec);
      }
   }
#endif /* !SOCKS_CLIENT */
   }
break;
case 50:
#line 740 "config_parse.y"
{
      yyerrorx("given keyword \"%s\" is deprecated.  New keyword is %s.  "
               "Please see %s's manual for more information",
               yyvsp[0].deprecated.oldname, yyvsp[0].deprecated.newname, PRODUCT);
   }
break;
case 51:
#line 747 "config_parse.y"
{ objecttype = object_route; }
break;
case 52:
#line 748 "config_parse.y"
{ routeinit(&route); }
break;
case 53:
#line 748 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;

      route.rdr_from  = rdr_from;

      socks_addroute(&route, 1);
   }
break;
case 54:
#line 759 "config_parse.y"
{ yyval.string = NULL; }
break;
case 57:
#line 765 "config_parse.y"
{
         state->proxyprotocol.socks_v4 = 1;
   }
break;
case 58:
#line 768 "config_parse.y"
{
         state->proxyprotocol.socks_v5 = 1;
   }
break;
case 59:
#line 771 "config_parse.y"
{
         state->proxyprotocol.http     = 1;
   }
break;
case 60:
#line 774 "config_parse.y"
{
         state->proxyprotocol.upnp     = 1;
   }
break;
case 65:
#line 787 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 69:
#line 802 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 73:
#line 817 "config_parse.y"
{
         yywarnx("we are currently considering deprecating the Dante-specific "
                 "SOCKS bind extension.  If you are using it, please let us "
                 "know on the public dante-misc@inet.no mailinglist");

         extension->bind = 1;
   }
break;
case 76:
#line 830 "config_parse.y"
{
#if !SOCKS_CLIENT
#if BAREFOOTD
      yyerrorx("\"internal:\" specification is not used in %s", PRODUCT);
#endif /* BAREFOOTD */

      addinternal(ruleaddr, SOCKS_TCP);
#endif /* !SOCKS_CLIENT */
   }
break;
case 77:
#line 841 "config_parse.y"
{
#if !SOCKS_CLIENT
   static ruleaddr_t mem;
   struct servent   *service;

   bzero(&mem, sizeof(mem));

   addrinit(&mem, 0);

   /* set default port. */
   if ((service = getservbyname("socks", "tcp")) == NULL)
      *port_tcp = htons(SOCKD_PORT);
   else
      *port_tcp = (in_port_t)service->s_port;
#endif /* !SOCKS_CLIENT */
   }
break;
case 78:
#line 859 "config_parse.y"
{
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
break;
case 79:
#line 866 "config_parse.y"
{
#if !SOCKS_CLIENT
      static ruleaddr_t mem;

      bzero(&mem, sizeof(mem));
      addrinit(&mem, 0);
#endif /* !SOCKS_CLIENT */
   }
break;
case 80:
#line 876 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 81:
#line 880 "config_parse.y"
{
      sockscf.external.rotation = ROTATION_SAMESAME;
   }
break;
case 82:
#line 883 "config_parse.y"
{
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* SOCKS_SERVER */
   }
break;
case 90:
#line 898 "config_parse.y"
{ yyval.string = NULL; }
break;
case 92:
#line 902 "config_parse.y"
{
      if (yyvsp[0].number < 0)
         yyerrorx("max route fails can not be negative (%ld)  Use \"0\" to "
                  "indicate routes should never be marked as bad",
                  (long)yyvsp[0].number);

      sockscf.routeoptions.maxfail = yyvsp[0].number;
   }
break;
case 93:
#line 910 "config_parse.y"
{
      if (yyvsp[0].number < 0)
         yyerrorx("route failure expiry time can not be negative (%ld).  "
                  "Use \"0\" to indicate bad route marking should never expire",
                  (long)yyvsp[0].number);

      sockscf.routeoptions.badexpire = yyvsp[0].number;
   }
break;
case 94:
#line 920 "config_parse.y"
{ add_to_errlog = 1; }
break;
case 96:
#line 923 "config_parse.y"
{ add_to_errlog = 0; }
break;
case 98:
#line 926 "config_parse.y"
{
   int p;

   if ((add_to_errlog && failed_to_add_errlog)
   ||      (!add_to_errlog && failed_to_add_log)) {
      yywarnx("not adding logfile \"%s\"", yyvsp[0].string);

      slog(LOG_ALERT,
           "not trying to add logfile \"%s\" due to having already failed "
           "adding logfiles during this SIGHUP.  Only if all logfiles "
           "specified in the config can be added will we switch to using "
           "the new logfiles.  Until then, we will continue using only the "
           "old logfiles",
           yyvsp[0].string);
   }
   else {
      p = socks_addlogfile(add_to_errlog ? &sockscf.errlog : &sockscf.log,
                           yyvsp[0].string);

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
            slog(LOG_DEBUG, "added logfile \"%s\" to %s",
                 yyvsp[0].string, add_to_errlog ? "errlog" : "logoutput");
         }
      }

      if (p == -1)
         slog(LOG_ALERT, "could not (re)open logfile \"%s\": %s%s  %s",
              yyvsp[0].string,
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
         yywarn("failed to add logfile %s", yyvsp[0].string);
#endif /* SOCKS_CLIENT */
   }
}
break;
case 101:
#line 987 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, sockscf.child.maxrequests, 0);
#endif /* !SOCKS_CLIENT */
   }
break;
case 105:
#line 999 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged_uid   = yyvsp[0].uid.uid;
      sockscf.uid.privileged_gid   = yyvsp[0].uid.gid;
      sockscf.uid.privileged_isset = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
break;
case 106:
#line 1012 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged_uid   = yyvsp[0].uid.uid;
      sockscf.uid.unprivileged_gid   = yyvsp[0].uid.gid;
      sockscf.uid.unprivileged_isset = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
break;
case 107:
#line 1025 "config_parse.y"
{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)

#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");

#else
      sockscf.uid.libwrap_uid   = yyvsp[0].uid.uid;
      sockscf.uid.libwrap_gid   = yyvsp[0].uid.gid;
      sockscf.uid.libwrap_isset = 1;
#endif /* !HAVE_PRIVILEGES */

#else  /* !HAVE_LIBWRAP && (!SOCKS_CLIENT) */
      yyerrorx_nolib("libwrap");
#endif /* !HAVE_LIBWRAP (!SOCKS_CLIENT)*/
   }
break;
case 108:
#line 1044 "config_parse.y"
{
      struct passwd *pw;

      if ((pw = getpwnam(yyvsp[0].string)) == NULL)
         yyerror("getpwnam(3) says no such user \"%s\"", yyvsp[0].string);

      yyval.uid.uid = pw->pw_uid;

      if ((pw = getpwuid(yyval.uid.uid)) == NULL)
         yyerror("getpwuid(3) says no such uid %lu (from user \"%s\")",
                 (unsigned long)yyval.uid.uid, yyvsp[0].string);

      yyval.uid.gid = pw->pw_gid;
   }
break;
case 109:
#line 1060 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->tcpio, 1);
      timeout->udpio = timeout->tcpio;
   }
break;
case 110:
#line 1065 "config_parse.y"
{
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->tcpio, 1);
   }
break;
case 111:
#line 1068 "config_parse.y"
{
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->udpio, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 112:
#line 1074 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->negotiate, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 113:
#line 1081 "config_parse.y"
{
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->connect, 1);
   }
break;
case 114:
#line 1086 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->tcp_fin_wait, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 115:
#line 1094 "config_parse.y"
{
#if SOCKS_CLIENT

       sockscf.option.debug = (int)yyvsp[0].number;

#else /* !SOCKS_CLIENT */

      if (sockscf.initial.cmdline.debug_isset
      &&  sockscf.initial.cmdline.debug != yyvsp[0].number)
         LOG_CMDLINE_OVERRIDE("debug",
                              sockscf.initial.cmdline.debug,
                              (int)yyvsp[0].number,
                              "%d");
      else
         sockscf.option.debug = (int)yyvsp[0].number;

#endif /* !SOCKS_CLIENT */
   }
break;
case 118:
#line 1118 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_allow_table  = strdup(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "libwrap.allow: %s", hosts_allow_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 119:
#line 1132 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_deny_table  = strdup(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "libwrap.deny: %s", hosts_deny_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 120:
#line 1146 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerrorx("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
break;
case 121:
#line 1154 "config_parse.y"
{
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 122:
#line 1164 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
break;
case 123:
#line 1168 "config_parse.y"
{
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 125:
#line 1178 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
break;
case 126:
#line 1182 "config_parse.y"
{
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 130:
#line 1195 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 131:
#line 1198 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerrorx("resolveprotocol keyword not supported on this system");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 132:
#line 1205 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 135:
#line 1214 "config_parse.y"
{
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETSCHEDULER
      yyerrorx("cpu scheduling policy is not supported on this system");
#else /* HAVE_SCHED_SETSCHEDULER */
      cpusetting_t *cpusetting;

      switch (yyvsp[-4].number) {
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
            SERRX(yyvsp[-4].number);
      }

      bzero(&cpusetting->param, sizeof(cpusetting->param));

      cpusetting->scheduling_isset     = 1;
      cpusetting->policy               = yyvsp[-2].number;
      cpusetting->param.sched_priority = (int)yyvsp[0].number;
#endif /* HAVE_SCHED_SETSCHEDULER */
#endif /* !SOCKS_CLIENT */
   }
break;
case 136:
#line 1256 "config_parse.y"
{
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETAFFINITY
      yyerrorx("cpu scheduling affinity is not supported on this system");
#else /* HAVE_SCHED_SETAFFINITY */
      cpusetting_t *cpusetting;

      switch (yyvsp[-2].number) {
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
            SERRX(yyvsp[-2].number);
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
break;
case 137:
#line 1317 "config_parse.y"
{
#if !SOCKS_CLIENT
      socketopt.level = yyvsp[-1].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 139:
#line 1324 "config_parse.y"
{
#if !SOCKS_CLIENT
   socketopt.optname = yyvsp[0].number;
   socketopt.info    = optval2sockopt(socketopt.level, socketopt.optname);

   if (socketopt.info == NULL)
      slog(LOG_DEBUG, "unknown/unsupported socket option: level %d, value %d",
                      socketopt.level, socketopt.optname);
   else
      socketoptioncheck(&socketopt);
   }
break;
case 140:
#line 1335 "config_parse.y"
{
      socketopt.info           = optid2sockopt((size_t)yyvsp[0].number);
      SASSERTX(socketopt.info != NULL);

      socketopt.optname        = socketopt.info->value;

      socketoptioncheck(&socketopt);
#endif /* !SOCKS_CLIENT */
   }
break;
case 141:
#line 1346 "config_parse.y"
{
      socketopt.optval.int_val = (int)yyvsp[0].number;
      socketopt.opttype        = int_val;
   }
break;
case 142:
#line 1350 "config_parse.y"
{
      const sockoptvalsym_t *p;

      if (socketopt.info == NULL)
         yyerrorx("the given socket option is unknown, so can not lookup "
                  "symbolic option value");

      if ((p = optval2valsym(socketopt.info->optid, yyvsp[0].string)) == NULL)
         yyerrorx("symbolic value \"%s\" is unknown for socket option %s",
                  yyvsp[0].string, sockopt2string(&socketopt, NULL, 0));

      socketopt.optval  = p->symval;
      socketopt.opttype = socketopt.info->opttype;
   }
break;
case 143:
#line 1367 "config_parse.y"
{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 1;
   }
break;
case 144:
#line 1370 "config_parse.y"
{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 0;
   }
break;
case 146:
#line 1379 "config_parse.y"
{
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
break;
case 147:
#line 1383 "config_parse.y"
{
         sockscf.srchost.nodnsunknown = 1;
   }
break;
case 148:
#line 1386 "config_parse.y"
{
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 151:
#line 1396 "config_parse.y"
{
#if COVENANT
   STRCPY_CHECKLEN(sockscf.realmname,
                   yyvsp[0].string,
                   sizeof(sockscf.realmname) - 1,
                   yyerrorx);
#else /* !COVENANT */
   yyerrorx("unknown keyword \"%s\"", yyvsp[-2].string);
#endif /* !COVENANT */
}
break;
case 152:
#line 1408 "config_parse.y"
{
#if !SOCKS_CLIENT

   cmethodv  = sockscf.cmethodv;
   cmethodc  = &sockscf.cmethodc;
  *cmethodc  = 0; /* reset. */

#endif /* !SOCKS_CLIENT */
   }
break;
case 154:
#line 1419 "config_parse.y"
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
break;
case 159:
#line 1441 "config_parse.y"
{
      if (methodisvalid(yyvsp[0].method, object_srule))
         ADDMETHOD(yyvsp[0].method, *smethodc, smethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for socksmethods",
                  method2string(yyvsp[0].method), yyvsp[0].method);
   }
break;
case 163:
#line 1458 "config_parse.y"
{
      if (methodisvalid(yyvsp[0].method, object_crule))
         ADDMETHOD(yyvsp[0].method, *cmethodc, cmethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for clientmethods",
                  method2string(yyvsp[0].method), yyvsp[0].method);
   }
break;
case 164:
#line 1466 "config_parse.y"
{ objecttype = object_monitor; }
break;
case 165:
#line 1466 "config_parse.y"
{
#if !SOCKS_CLIENT
                        monitorinit(&monitor);
#endif /* !SOCKS_CLIENT */
}
break;
case 166:
#line 1471 "config_parse.y"
{
#if !SOCKS_CLIENT
   pre_addmonitor(&monitor);

   addmonitor(&monitor);
#endif /* !SOCKS_CLIENT */
}
break;
case 167:
#line 1483 "config_parse.y"
{ objecttype = object_crule; }
break;
case 168:
#line 1484 "config_parse.y"
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
break;
case 171:
#line 1516 "config_parse.y"
{
#if !SOCKS_CLIENT
         monitorif = NULL;
   }
break;
case 172:
#line 1520 "config_parse.y"
{
         monitorif = &monitor.mstats->object.monitor.internal;
   }
break;
case 173:
#line 1523 "config_parse.y"
{
         monitorif = &monitor.mstats->object.monitor.external;
#endif /* !SOCKS_CLIENT */
   }
break;
case 174:
#line 1529 "config_parse.y"
{
#if !SOCKS_CLIENT
      alarmside = NULL;
   }
break;
case 175:
#line 1533 "config_parse.y"
{
      *alarmside = RECVSIDE;
   }
break;
case 176:
#line 1536 "config_parse.y"
{
      *alarmside = SENDSIDE;
#endif /* !SOCKS_CLIENT */
   }
break;
case 177:
#line 1542 "config_parse.y"
{ alarminit(); }
break;
case 178:
#line 1543 "config_parse.y"
{
#if !SOCKS_CLIENT
   alarm_data_limit_t limit;

   ASSIGN_NUMBER(yyvsp[-2].number, >=, 0, limit.bytes, 0);
   ASSIGN_NUMBER(yyvsp[0].number, >, 0, limit.seconds, 1);

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
break;
case 179:
#line 1605 "config_parse.y"
{
#if !SOCKS_CLIENT
   alarm_disconnect_limit_t limit;

   ASSIGN_NUMBER(yyvsp[-1].number, >, 0, limit.sessionc, 0);
   ASSIGN_NUMBER(yyvsp[-3].number, >, 0, limit.disconnectc, 0);
   ASSIGN_NUMBER(yyvsp[0].number, >, 0, limit.seconds, 1);

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
break;
case 180:
#line 1636 "config_parse.y"
{
#if !SOCKS_CLIENT
               yyval.number = DEFAULT_ALARM_PERIOD;
#endif /* !SOCKS_CLIENT */
   }
break;
case 181:
#line 1641 "config_parse.y"
{ yyval.number = yyvsp[0].number; }
break;
case 184:
#line 1646 "config_parse.y"
{ *hostidoption_isset = 1; }
break;
case 186:
#line 1650 "config_parse.y"
{ yyval.string = NULL; }
break;
case 188:
#line 1654 "config_parse.y"
{
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 189:
#line 1659 "config_parse.y"
{
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 191:
#line 1665 "config_parse.y"
{
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 193:
#line 1674 "config_parse.y"
{ yyval.string = NULL; }
break;
case 195:
#line 1678 "config_parse.y"
{ objecttype = object_hrule; }
break;
case 196:
#line 1679 "config_parse.y"
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
#else /* !SOCKS_CLIENT && !HAVE_SOCKS_HOSTID */
      yyerrorx("hostid is not supported on this system");
#endif /* !HAVE_SOCKS_HOSTID */
   }
break;
case 199:
#line 1701 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      addrinit(&hostid, 1);

#else /* HAVE_SOCKS_HOSTID */
      yyerrorx("hostid is not supported on this system");
#endif /* HAVE_SOCKS_HOSTID */

   }
break;
case 201:
#line 1712 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
   ASSIGN_NUMBER(yyvsp[0].number, >=, 0, *hostindex, 0);
   ASSIGN_NUMBER(yyvsp[0].number, <=, HAVE_MAX_HOSTIDS, *hostindex, 0);

#else
   yyerrorx("hostid is not supported on this system");
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
}
break;
case 202:
#line 1724 "config_parse.y"
{ objecttype = object_srule; }
break;
case 203:
#line 1725 "config_parse.y"
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
break;
case 204:
#line 1739 "config_parse.y"
{ yyval.string = NULL; }
break;
case 212:
#line 1750 "config_parse.y"
{
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 214:
#line 1759 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("bandwidth");
         bw_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 221:
#line 1771 "config_parse.y"
{ *hostidoption_isset = 1; }
break;
case 225:
#line 1775 "config_parse.y"
{
#if !SOCKS_CLIENT
                  checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
break;
case 226:
#line 1780 "config_parse.y"
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
break;
case 257:
#line 1840 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->debug = (int)yyvsp[0].number;
   }
break;
case 258:
#line 1845 "config_parse.y"
{
      ldap->debug = (int)-yyvsp[0].number;
 #else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 259:
#line 1854 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldap.domain,
                      yyvsp[0].string,
                      sizeof(state->ldap.domain) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 260:
#line 1868 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->mdepth = (int)yyvsp[0].number;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 261:
#line 1879 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldap.certfile,
                      yyvsp[0].string,
                      sizeof(state->ldap.certfile) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 262:
#line 1893 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldap.certpath,
                      yyvsp[0].string,
                      sizeof(state->ldap.certpath) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 263:
#line 1907 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapurl, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 264:
#line 1919 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapbasedn, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 265:
#line 1931 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapbasedn, hextoutf8(yyvsp[0].string, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 266:
#line 1943 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapbasedn, hextoutf8(yyvsp[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 267:
#line 1955 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->port = (int)yyvsp[0].number;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 268:
#line 1966 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->portssl = (int)yyvsp[0].number;
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 269:
#line 1977 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->ssl = 1;
   }
break;
case 270:
#line 1982 "config_parse.y"
{
      ldap->ssl = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 271:
#line 1991 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->auto_off = 1;
   }
break;
case 272:
#line 1996 "config_parse.y"
{
      ldap->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 273:
#line 2005 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->certcheck = 1;
   }
break;
case 274:
#line 2010 "config_parse.y"
{
      ldap->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 275:
#line 2019 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->keeprealm = 1;
   }
break;
case 276:
#line 2024 "config_parse.y"
{
      ldap->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 277:
#line 2033 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKLEN(ldap->filter, yyvsp[0].string, sizeof(state->ldap.filter) - 1, yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 278:
#line 2044 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldap->filter_AD,
                      yyvsp[0].string,
                      sizeof(state->ldap.filter_AD) - 1,
                      yyerrorx);

#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 279:
#line 2059 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKUTFLEN(ldap->filter,
                          yyvsp[0].string,
                          sizeof(state->ldap.filter) - 1,
                          yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 280:
#line 2073 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKUTFLEN(ldap->filter_AD,
                        yyvsp[0].string,
                        sizeof(state->ldap.filter_AD) - 1,
                        yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 281:
#line 2087 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldap->attribute,
                      yyvsp[0].string,
                      sizeof(state->ldap.attribute) - 1,
                      yyerrorx);

#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 282:
#line 2102 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldap->attribute_AD,
                      yyvsp[0].string,
                      sizeof(state->ldap.attribute_AD) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 283:
#line 2116 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKUTFLEN(ldap->attribute,
                      yyvsp[0].string,
                      sizeof(state->ldap.attribute) -1,
                      yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 284:
#line 2130 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKUTFLEN(ldap->attribute_AD,
                      yyvsp[0].string,
                      sizeof(state->ldap.attribute_AD) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 285:
#line 2144 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8(yyvsp[0].string, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 286:
#line 2156 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, hextoutf8(yyvsp[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 287:
#line 2170 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, asciitoutf8(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 288:
#line 2184 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapserver, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 289:
#line 2196 "config_parse.y"
{
#if HAVE_LDAP
#if SOCKS_SERVER
   STRCPY_CHECKLEN(state->ldap.keytab,
                   yyvsp[0].string,
                   sizeof(state->ldap.keytab) - 1, yyerrorx);
#else
   yyerrorx("ldap keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("LDAP");
#endif /* HAVE_LDAP */
   }
break;
case 291:
#line 2214 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 294:
#line 2228 "config_parse.y"
{
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 295:
#line 2233 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
   }
break;
case 299:
#line 2247 "config_parse.y"
{
         state->command.bind = 1;
   }
break;
case 300:
#line 2250 "config_parse.y"
{
         state->command.connect = 1;
   }
break;
case 301:
#line 2253 "config_parse.y"
{
         state->command.udpassociate = 1;
   }
break;
case 302:
#line 2259 "config_parse.y"
{
         state->command.bindreply = 1;
   }
break;
case 303:
#line 2263 "config_parse.y"
{
         state->command.udpreply = 1;
   }
break;
case 307:
#line 2276 "config_parse.y"
{
      state->protocol.tcp = 1;
   }
break;
case 308:
#line 2279 "config_parse.y"
{
      state->protocol.udp = 1;
   }
break;
case 320:
#line 2308 "config_parse.y"
{
#if !SOCKS_CLIENT
                        rule.ss_isinheritable = 1;
   }
break;
case 321:
#line 2312 "config_parse.y"
{
                        rule.ss_isinheritable = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 322:
#line 2318 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS(yyvsp[0].number, ss.object.ss.max, 0);
      ss.object.ss.max       = yyvsp[0].number;
      ss.object.ss.max_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 323:
#line 2327 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_THROTTLE_SECONDS(yyvsp[-2].number, ss.object.ss.throttle.limit.clients, 0);
      ASSIGN_THROTTLE_CLIENTS(yyvsp[0].number, ss.object.ss.throttle.limit.seconds, 0);
      ss.object.ss.throttle_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 328:
#line 2342 "config_parse.y"
{
#if !SOCKS_CLIENT
      if ((ss.keystate.key = string2statekey(yyvsp[0].string)) == key_unset)
         yyerrorx("%s is not a valid state key", yyvsp[0].string);

#if HAVE_SOCKS_HOSTID
      if (ss.keystate.key == key_hostid) {
         *hostidoption_isset           = 1;
         ss.keystate.keyinfo.hostindex = DEFAULT_HOSTINDEX;
      }
#endif /* HAVE_SOCKS_HOSTID */

#else /* SOCKS_CLIENT */

   SERRX(0);
#endif /* SOCKS_CLIENT */
   }
break;
case 329:
#line 2361 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      hostindex = &ss.keystate.keyinfo.hostindex;
   }
break;
case 330:
#line 2365 "config_parse.y"
{
      hostindex = &rule.hostindex; /* reset */
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
   }
break;
case 331:
#line 2372 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS(yyvsp[0].number, ss.object.ss.max_perstate, 0);
      ss.object.ss.max_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 332:
#line 2380 "config_parse.y"
{
#if !SOCKS_CLIENT
   ASSIGN_THROTTLE_SECONDS(yyvsp[-2].number, ss.object.ss.throttle_perstate.limit.clients, 0);
   ASSIGN_THROTTLE_CLIENTS(yyvsp[0].number, ss.object.ss.throttle_perstate.limit.seconds, 0);
   ss.object.ss.throttle_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
}
break;
case 333:
#line 2389 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, bw.object.bw.maxbps, 0);
      bw.object.bw.maxbps_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 335:
#line 2401 "config_parse.y"
{
#if !SOCKS_CLIENT
         rule.log.connect = 1;
   }
break;
case 336:
#line 2405 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 337:
#line 2408 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 338:
#line 2411 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 339:
#line 2414 "config_parse.y"
{
         rule.log.iooperation = 1;
   }
break;
case 340:
#line 2417 "config_parse.y"
{
         rule.log.tcpinfo = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 343:
#line 2428 "config_parse.y"
{
#if HAVE_PAM && (!SOCKS_CLIENT)
      STRCPY_CHECKLEN(state->pamservicename,
                      yyvsp[0].string,
                      sizeof(state->pamservicename) -1,
                      yyerrorx);
#else
      yyerrorx_nolib("PAM");
#endif /* HAVE_PAM && (!SOCKS_CLIENT) */
   }
break;
case 344:
#line 2440 "config_parse.y"
{
#if HAVE_BSDAUTH && SOCKS_SERVER
      STRCPY_CHECKLEN(state->bsdauthstylename,
                      yyvsp[0].string,
                      sizeof(state->bsdauthstylename) - 1,
                      yyerrorx);
#else
      yyerrorx_nolib("bsdauth");
#endif /* HAVE_BSDAUTH && SOCKS_SERVER */
   }
break;
case 345:
#line 2453 "config_parse.y"
{
#if HAVE_GSSAPI
      STRCPY_CHECKLEN(gssapiservicename,
                      yyvsp[0].string,
                      sizeof(state->gssapiservicename) - 1,
                      yyerrorx);
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 346:
#line 2465 "config_parse.y"
{
#if HAVE_GSSAPI
#if SOCKS_SERVER
      STRCPY_CHECKLEN(gssapikeytab,
                       yyvsp[0].string,
                       sizeof(state->gssapikeytab) - 1,
                       yyerrorx);
#else
      yyerrorx("gssapi keytab setting is only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 348:
#line 2484 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 349:
#line 2490 "config_parse.y"
{
      gssapiencryption->clear = 1;
   }
break;
case 350:
#line 2493 "config_parse.y"
{
      gssapiencryption->integrity = 1;
   }
break;
case 351:
#line 2496 "config_parse.y"
{
      gssapiencryption->confidentiality = 1;
   }
break;
case 352:
#line 2499 "config_parse.y"
{
      yyerrorx("gssapi per-message encryption not supported");
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 356:
#line 2514 "config_parse.y"
{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
      struct request_info request;
      char tmp[LIBWRAPBUF];
      int errno_s, devnull;

      STRCPY_CHECKLEN(rule.libwrap,
                      yyvsp[0].string,
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
break;
case 361:
#line 2566 "config_parse.y"
{
#if BAREFOOTD
      yyerrorx("redirecting \"to\" an address does not make any sense in %s.  "
               "Instead specify the address you wanted to \"redirect\" "
               "data to as the \"bounce to\" address, as normal",
               PRODUCT);
#endif /* BAREFOOT */
   }
break;
case 373:
#line 2589 "config_parse.y"
{
               if (!addedsocketoption(&route.socketoptionc,
                                      &route.socketoptionv,
                                      &socketopt))
                  yywarn("could not add socketoption");
   }
break;
case 374:
#line 2597 "config_parse.y"
{ yyval.string = NULL; }
break;
case 377:
#line 2604 "config_parse.y"
{
      addrinit(&src, 1);
   }
break;
case 378:
#line 2609 "config_parse.y"
{
      addrinit(&dst, ipaddr_requires_netmask(to, objecttype));
   }
break;
case 379:
#line 2614 "config_parse.y"
{
      addrinit(&rdr_from, 1);
   }
break;
case 380:
#line 2619 "config_parse.y"
{
      addrinit(&rdr_to, 0);
   }
break;
case 381:
#line 2624 "config_parse.y"
{
#if BAREFOOTD
      addrinit(&bounceto, 0);
#endif /* BAREFOOTD */
   }
break;
case 382:
#line 2632 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 391:
#line 2652 "config_parse.y"
{ if (!netmask_required) yyerrorx_hasnetmask(); }
break;
case 392:
#line 2653 "config_parse.y"
{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 393:
#line 2654 "config_parse.y"
{ if (!netmask_required) yyerrorx_hasnetmask(); }
break;
case 394:
#line 2655 "config_parse.y"
{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 395:
#line 2656 "config_parse.y"
{ if (!netmask_required)
                                       yyerrorx_hasnetmask(); }
break;
case 396:
#line 2658 "config_parse.y"
{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 399:
#line 2662 "config_parse.y"
{ /* for upnp; broadcasts on interface. */ }
break;
case 403:
#line 2671 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (socks_inet_pton(AF_INET, yyvsp[0].string, ipv4, NULL) != 1)
         yyerror("bad %s: %s", atype2string(*atype), yyvsp[0].string);
   }
break;
case 404:
#line 2679 "config_parse.y"
{
      if (yyvsp[0].number < 0 || yyvsp[0].number > 32)
         yyerrorx("bad %s netmask: %ld.  Legal range is 0 - 32",
                  atype2string(*atype), (long)yyvsp[0].number);

      netmask_v4->s_addr = yyvsp[0].number == 0 ? 0 : htonl(IPV4_FULLNETMASK << (32 - yyvsp[0].number));
   }
break;
case 405:
#line 2686 "config_parse.y"
{
      if (socks_inet_pton(AF_INET, yyvsp[0].string, netmask_v4, NULL) != 1)
         yyerror("bad %s netmask: %s", atype2string(*atype), yyvsp[0].string);
   }
break;
case 406:
#line 2692 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV6;

      if (socks_inet_pton(AF_INET6, yyvsp[0].string, ipv6, scopeid_v6) != 1)
         yyerror("bad %s: %s", atype2string(*atype), yyvsp[0].string);
   }
break;
case 407:
#line 2700 "config_parse.y"
{
      if (yyvsp[0].number < 0 || yyvsp[0].number > IPV6_NETMASKBITS)
         yyerrorx("bad %s netmask: %d.  Legal range is 0 - %d",
                  atype2string(*atype), (int)yyvsp[0].number, IPV6_NETMASKBITS);

      *netmask_v6 = yyvsp[0].number;
   }
break;
case 408:
#line 2709 "config_parse.y"
{
      SASSERTX(strcmp(yyvsp[0].string, "0") == 0);

      *atype = SOCKS_ADDR_IPVANY;
      ipvany->s_addr = htonl(0);
   }
break;
case 409:
#line 2717 "config_parse.y"
{
      if (yyvsp[0].number != 0)
         yyerrorx("bad %s netmask: %d.  Only legal value is 0",
                  atype2string(*atype), (int)yyvsp[0].number);

      netmask_vany->s_addr = htonl(yyvsp[0].number);
   }
break;
case 410:
#line 2727 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;
      STRCPY_CHECKLEN(domain, yyvsp[0].string, MAXHOSTNAMELEN - 1, yyerrorx);
   }
break;
case 411:
#line 2733 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;
      STRCPY_CHECKLEN(ifname, yyvsp[0].string, MAXIFNAMELEN - 1, yyerrorx);
   }
break;
case 412:
#line 2740 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;
      STRCPY_CHECKLEN(url, yyvsp[0].string, MAXURLLEN - 1, yyerrorx);
   }
break;
case 413:
#line 2747 "config_parse.y"
{ yyval.number = 0; }
break;
case 417:
#line 2753 "config_parse.y"
{ yyval.number = 0; }
break;
case 421:
#line 2761 "config_parse.y"
{
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerrorx("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
break;
case 422:
#line 2769 "config_parse.y"
{
      ASSIGN_PORTNUMBER(yyvsp[0].number, *port_tcp);
      ASSIGN_PORTNUMBER(yyvsp[0].number, *port_udp);
   }
break;
case 423:
#line 2775 "config_parse.y"
{
      ASSIGN_PORTNUMBER(yyvsp[0].number, ruleaddr->portend);
      ruleaddr->operator   = range;
   }
break;
case 424:
#line 2781 "config_parse.y"
{
      struct servent   *service;

      if ((service = getservbyname(yyvsp[0].string, "tcp")) == NULL) {
         if (state->protocol.tcp)
            yyerrorx("unknown tcp protocol: %s", yyvsp[0].string);

         *port_tcp = htons(0);
      }
      else
         *port_tcp = (in_port_t)service->s_port;

      if ((service = getservbyname(yyvsp[0].string, "udp")) == NULL) {
         if (state->protocol.udp)
               yyerrorx("unknown udp protocol: %s", yyvsp[0].string);

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

      yyval.number = (size_t)*port_udp;
   }
break;
case 425:
#line 2816 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 427:
#line 2825 "config_parse.y"
{
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER(yyvsp[0].number, rule.udprange.start);
#endif /* SOCKS_SERVER */
   }
break;
case 428:
#line 2832 "config_parse.y"
{
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER(yyvsp[0].number, rule.udprange.end);
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerrorx("end port (%d) can not be less than start port (%u)",
               (int)yyvsp[0].number, ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
break;
case 429:
#line 2844 "config_parse.y"
{
      addnumber(&numberc, &numberv, yyvsp[0].number);
   }
break;
#line 5690 "config_parse.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
