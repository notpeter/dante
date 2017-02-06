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

#if !SOCKS_CLIENT

#include "monitor.h"

#endif /* !SOCKS_CLIENT */

static const char rcsid[] =
"$Id: config_parse.y,v 1.703.4.8.2.8 2017/01/31 08:17:38 karls Exp $";

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
#line 396 "config_parse.y"
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
#line 411 "config_parse.c"
#define ALARM 257
#define ALARMTYPE_DATA 258
#define ALARMTYPE_DISCONNECT 259
#define ALARMIF_INTERNAL 260
#define ALARMIF_EXTERNAL 261
#define TCPOPTION_DISABLED 262
#define ECN 263
#define SACK 264
#define TIMESTAMPS 265
#define WSCALE 266
#define MTU_ERROR 267
#define CLIENTCOMPATIBILITY 268
#define NECGSSAPI 269
#define CLIENTRULE 270
#define HOSTIDRULE 271
#define SOCKSRULE 272
#define COMPATIBILITY 273
#define SAMEPORT 274
#define DRAFT_5_05 275
#define CONNECTTIMEOUT 276
#define TCP_FIN_WAIT 277
#define CPU 278
#define MASK 279
#define SCHEDULE 280
#define CPUMASK_ANYCPU 281
#define DEBUGGING 282
#define DEPRECATED 283
#define ERRORLOG 284
#define LOGOUTPUT 285
#define LOGFILE 286
#define LOGTYPE_ERROR 287
#define LOGTYPE_TCP_DISABLED 288
#define LOGTYPE_TCP_ENABLED 289
#define LOGIF_INTERNAL 290
#define LOGIF_EXTERNAL 291
#define ERRORVALUE 292
#define EXTENSION 293
#define BIND 294
#define PRIVILEGED 295
#define EXTERNAL_PROTOCOL 296
#define INTERNAL_PROTOCOL 297
#define EXTERNAL_ROTATION 298
#define SAMESAME 299
#define GROUPNAME 300
#define HOSTID 301
#define HOSTINDEX 302
#define INTERFACE 303
#define SOCKETOPTION_SYMBOLICVALUE 304
#define INTERNAL 305
#define EXTERNAL 306
#define INTERNALSOCKET 307
#define EXTERNALSOCKET 308
#define IOTIMEOUT 309
#define IOTIMEOUT_TCP 310
#define IOTIMEOUT_UDP 311
#define NEGOTIATETIMEOUT 312
#define LIBWRAP_FILE 313
#define LOGLEVEL 314
#define SOCKSMETHOD 315
#define CLIENTMETHOD 316
#define METHOD 317
#define METHODNAME 318
#define NONE 319
#define BSDAUTH 320
#define GSSAPI 321
#define PAM_ADDRESS 322
#define PAM_ANY 323
#define PAM_USERNAME 324
#define RFC931 325
#define UNAME 326
#define MONITOR 327
#define PROCESSTYPE 328
#define PROC_MAXREQUESTS 329
#define REALM 330
#define REALNAME 331
#define RESOLVEPROTOCOL 332
#define REQUIRED 333
#define SCHEDULEPOLICY 334
#define SERVERCONFIG 335
#define CLIENTCONFIG 336
#define SOCKET 337
#define CLIENTSIDE_SOCKET 338
#define SNDBUF 339
#define RCVBUF 340
#define SOCKETPROTOCOL 341
#define SOCKETOPTION_OPTID 342
#define SRCHOST 343
#define NODNSMISMATCH 344
#define NODNSUNKNOWN 345
#define CHECKREPLYAUTH 346
#define USERNAME 347
#define USER_PRIVILEGED 348
#define USER_UNPRIVILEGED 349
#define USER_LIBWRAP 350
#define WORD__IN 351
#define ROUTE 352
#define VIA 353
#define GLOBALROUTEOPTION 354
#define BADROUTE_EXPIRE 355
#define MAXFAIL 356
#define PORT 357
#define NUMBER 358
#define BANDWIDTH 359
#define BOUNCE 360
#define BSDAUTHSTYLE 361
#define BSDAUTHSTYLENAME 362
#define COMMAND 363
#define COMMAND_BIND 364
#define COMMAND_CONNECT 365
#define COMMAND_UDPASSOCIATE 366
#define COMMAND_BINDREPLY 367
#define COMMAND_UDPREPLY 368
#define ACTION 369
#define FROM 370
#define TO 371
#define GSSAPIENCTYPE 372
#define GSSAPIENC_ANY 373
#define GSSAPIENC_CLEAR 374
#define GSSAPIENC_INTEGRITY 375
#define GSSAPIENC_CONFIDENTIALITY 376
#define GSSAPIENC_PERMESSAGE 377
#define GSSAPIKEYTAB 378
#define GSSAPISERVICE 379
#define GSSAPISERVICENAME 380
#define GSSAPIKEYTABNAME 381
#define IPV4 382
#define IPV6 383
#define IPVANY 384
#define DOMAINNAME 385
#define IFNAME 386
#define URL 387
#define LDAPATTRIBUTE 388
#define LDAPATTRIBUTE_AD 389
#define LDAPATTRIBUTE_HEX 390
#define LDAPATTRIBUTE_AD_HEX 391
#define LDAPBASEDN 392
#define LDAP_BASEDN 393
#define LDAPBASEDN_HEX 394
#define LDAPBASEDN_HEX_ALL 395
#define LDAPCERTFILE 396
#define LDAPCERTPATH 397
#define LDAPPORT 398
#define LDAPPORTSSL 399
#define LDAPDEBUG 400
#define LDAPDEPTH 401
#define LDAPAUTO 402
#define LDAPSEARCHTIME 403
#define LDAPDOMAIN 404
#define LDAP_DOMAIN 405
#define LDAPFILTER 406
#define LDAPFILTER_AD 407
#define LDAPFILTER_HEX 408
#define LDAPFILTER_AD_HEX 409
#define LDAPGROUP 410
#define LDAPGROUP_NAME 411
#define LDAPGROUP_HEX 412
#define LDAPGROUP_HEX_ALL 413
#define LDAPKEYTAB 414
#define LDAPKEYTABNAME 415
#define LDAPDEADTIME 416
#define LDAPSERVER 417
#define LDAPSERVER_NAME 418
#define LDAPSSL 419
#define LDAPCERTCHECK 420
#define LDAPKEEPREALM 421
#define LDAPTIMEOUT 422
#define LDAPCACHE 423
#define LDAPCACHEPOS 424
#define LDAPCACHENEG 425
#define LDAPURL 426
#define LDAP_URL 427
#define LDAP_FILTER 428
#define LDAP_ATTRIBUTE 429
#define LDAP_CERTFILE 430
#define LDAP_CERTPATH 431
#define LIBWRAPSTART 432
#define LIBWRAP_ALLOW 433
#define LIBWRAP_DENY 434
#define LIBWRAP_HOSTS_ACCESS 435
#define LINE 436
#define OPERATOR 437
#define PAMSERVICENAME 438
#define PROTOCOL 439
#define PROTOCOL_TCP 440
#define PROTOCOL_UDP 441
#define PROTOCOL_FAKE 442
#define PROXYPROTOCOL 443
#define PROXYPROTOCOL_SOCKS_V4 444
#define PROXYPROTOCOL_SOCKS_V5 445
#define PROXYPROTOCOL_HTTP 446
#define PROXYPROTOCOL_UPNP 447
#define REDIRECT 448
#define SENDSIDE 449
#define RECVSIDE 450
#define SERVICENAME 451
#define SESSION_INHERITABLE 452
#define SESSIONMAX 453
#define SESSIONTHROTTLE 454
#define SESSIONSTATE_KEY 455
#define SESSIONSTATE_MAX 456
#define SESSIONSTATE_THROTTLE 457
#define RULE_LOG 458
#define RULE_LOG_CONNECT 459
#define RULE_LOG_DATA 460
#define RULE_LOG_DISCONNECT 461
#define RULE_LOG_ERROR 462
#define RULE_LOG_IOOPERATION 463
#define RULE_LOG_TCPINFO 464
#define STATEKEY 465
#define UDPPORTRANGE 466
#define UDPCONNECTDST 467
#define USER 468
#define GROUP 469
#define VERDICT_BLOCK 470
#define VERDICT_PASS 471
#define YES 472
#define NO 473
#define YYERRCODE 256
const short socks_yylhs[] =
	{                                        -1,
  206,    0,    0,  126,  126,  125,  125,  125,  125,  125,
  124,  124,  123,  123,  123,  123,  123,  123,  123,  123,
  123,  123,  123,  123,  123,  123,  123,  123,  123,  123,
  123,  123,  123,  123,  123,  123,  123,  123,  123,  106,
  208,  106,  209,  106,  210,  104,  211,  105,  212,  204,
  213,  205,  107,  207,  207,  214,  214,  214,  214,  108,
  108,  109,  138,  138,  138,  138,    5,  215,  216,  152,
  153,  153,   19,   20,   20,   20,   20,   20,   21,   21,
   35,   36,   37,   37,    9,   10,   11,   11,   66,   67,
   68,   68,    8,    8,    7,    7,   75,   76,  217,   77,
   69,   70,  218,   71,   72,   72,   72,   39,   39,   39,
   39,   39,   39,   39,   38,   38,  149,  149,  220,  103,
  221,  102,  222,  219,  219,   56,  144,  144,  144,  145,
  146,  147,  148,  139,  139,  139,  140,  141,  142,    6,
   99,   99,  100,  101,   98,   98,  143,  143,   60,   61,
   61,   62,   62,   23,   24,   24,   24,   63,   63,   64,
   65,  223,   26,   27,   27,   28,   28,   25,   25,   29,
   30,   30,   30,   31,   31,   22,  224,   74,  225,   73,
   52,   53,   53,   54,   49,   50,   50,   51,  226,  227,
  118,  228,  179,   40,   40,   40,  121,  121,  121,   46,
   46,   46,  229,   41,   43,   44,   42,   45,   45,  119,
  119,  119,  119,  120,  120,  180,  180,  180,  180,  180,
  230,  187,  181,  181,  188,  188,  231,  190,  189,  232,
  200,  202,  202,  201,  201,  201,  201,  201,  201,  201,
  201,  191,  191,  191,  191,  191,  191,  191,  191,  191,
  191,  191,  191,  191,  191,  191,  191,  191,  192,  192,
  192,  192,  192,  192,  192,  192,  192,  192,  192,  192,
  192,  192,  192,  192,  192,  192,  192,  192,  192,  192,
  192,  192,  192,  192,  192,  192,   86,   86,   93,   87,
   90,   91,  114,   78,   79,   80,   88,   89,  115,  115,
   85,   85,  116,  116,  117,  117,   94,   95,   96,   97,
   81,   82,   83,   84,  112,  113,  111,  110,   92,   57,
   58,   59,   59,  203,  203,    2,    3,    3,    4,    4,
    4,    4,    4,   16,   17,   17,   18,   18,  185,  186,
  122,  122,  122,  127,  127,  127,  129,  128,  128,  131,
  131,  130,  132,  133,  133,  133,  133,  134,  235,  135,
  137,  136,   55,  194,  196,  196,  196,  196,  196,  196,
  195,  195,   15,    1,   14,   13,   12,  237,  237,  237,
  237,  237,  236,  236,  177,  193,  174,  175,  176,  233,
  234,  151,  154,  154,  154,  154,  154,  154,  154,  154,
  154,  154,  154,  155,  155,  156,  183,  184,  238,  239,
  178,  150,  182,  182,  182,  182,  173,  173,  173,  163,
  164,  164,  164,  164,  164,  164,  171,  171,  171,  171,
  172,  172,  165,  197,  197,  166,  198,  167,  240,  168,
  169,  170,  157,  157,  157,  157,  158,  158,  161,  161,
  159,  160,  241,  162,  199,   32,   33,   34,   47,   48,
   48,
};
const short socks_yylen[] =
	{                                         2,
    0,    4,    3,    0,    2,    1,    1,    1,    1,    1,
    0,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    3,
    0,    4,    0,    4,    0,    6,    0,    6,    0,    6,
    0,    6,    1,    1,    2,    1,    1,    1,    1,    1,
    2,    1,    1,    1,    1,    1,    1,    0,    0,    9,
    0,    2,    3,    1,    1,    1,    1,    1,    1,    2,
    3,    1,    1,    2,    3,    1,    1,    2,    3,    1,
    1,    2,    1,    2,    1,    1,    4,    0,    0,    4,
    4,    0,    0,    4,    3,    3,    3,    1,    1,    1,
    1,    1,    1,    1,    0,    2,    4,    4,    0,    4,
    0,    4,    1,    1,    2,    3,    1,    1,    1,    3,
    3,    3,    1,    3,    3,    3,    3,    3,    3,    3,
    1,    1,    3,    3,    3,    3,    3,    3,    3,    1,
    1,    1,    2,    3,    1,    1,    1,    1,    1,    9,
    7,    0,    7,    1,    1,    1,    1,    1,    1,    3,
    1,    1,    1,    1,    2,    3,    0,    4,    0,    4,
    3,    1,    2,    1,    3,    1,    2,    1,    0,    0,
    8,    0,    8,    1,    1,    1,    0,    1,    1,    0,
    1,    1,    0,    8,    4,    1,    7,    0,    2,    1,
    1,    1,    1,    0,    2,    1,    1,    1,    1,    1,
    0,    8,    0,    2,    1,    1,    0,    4,    3,    0,
    8,    0,    2,    1,    1,    1,    1,    1,    1,    1,
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
const short socks_yydefred[] =
	{                                      0,
    1,    0,    0,    0,    0,    0,    0,   67,    0,    0,
    0,    0,    0,    0,    0,    0,  109,  108,  113,   71,
    0,  112,  111,  114,   64,   65,   63,   66,  110,    0,
    0,   45,   47,    0,    0,    0,    0,   98,  102,  168,
  169,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   17,   16,   33,   34,    0,   39,   35,
   13,   14,   15,  158,  159,   19,   20,   21,   22,   25,
   24,   27,   28,   30,   31,  141,  142,   32,   18,   29,
   23,    0,    4,   36,   37,   38,  127,  128,  129,   26,
    0,    0,    0,  119,  121,    0,    0,    0,    0,    0,
    0,    0,    0,  116,    0,    0,    0,    0,    0,  103,
   99,    0,    0,    0,  179,  177,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   12,    0,  138,
  139,  140,    0,    0,  134,  135,  136,  137,  156,  157,
  155,  154,    0,    0,   68,   72,  150,  151,    0,  149,
    0,    0,    0,    0,   90,    0,   89,    0,    0,  106,
  105,  107,    0,    0,    0,    0,  126,  176,  171,  172,
  173,    0,  170,  133,  130,  131,  132,  143,  144,  145,
  146,  147,  148,  162,  192,  221,  230,  189,    9,    5,
   10,    6,    7,    8,  123,  120,    0,  122,  118,  117,
    0,  153,    0,    0,   53,    0,    0,   92,   95,   96,
    0,  104,  100,  433,  436,  438,  440,  441,   97,  417,
    0,    0,    0,  418,  419,    0,  413,  414,  415,  416,
  101,  184,  180,    0,  188,  178,    0,  175,    0,    0,
    0,    0,    0,  125,   69,    0,    0,    0,    0,   94,
    0,    0,    0,    0,  420,  183,  187,  165,  164,    0,
  324,  325,    0,    0,    0,  190,    0,    0,    0,    0,
    0,    0,   46,   48,  434,  435,  421,  437,  423,  439,
  425,  452,  455,    0,  446,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  394,  400,  399,  398,  397,  401,  403,  395,  396,
    0,    0,  393,  459,    0,  161,    0,    0,   41,   43,
  454,  450,  444,  449,    0,  445,  167,  166,  163,   49,
   51,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  246,
  247,  248,  249,  254,  217,  256,  258,  243,  244,  242,
  218,  255,  349,  219,  344,  348,  345,  346,  354,  355,
  356,  357,  257,  216,    0,    0,  250,  226,  225,  220,
  252,  253,  251,  245,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  234,  235,  238,  239,  241,
  264,  265,  266,  259,  260,  262,  261,  263,  270,  271,
  279,  280,  268,  269,  278,  272,  273,  274,  276,  275,
  285,  282,  283,  284,  286,  281,  267,  277,  347,  240,
  236,  237,    0,    0,  198,  199,  211,  213,  210,  194,
  195,  196,    0,    0,    0,  212,    0,    0,    0,    0,
    0,    0,    0,    0,  409,  402,    0,  405,  407,    0,
    0,    0,  461,    0,   62,   40,    0,    0,    0,  453,
  451,    0,    0,  227,    0,    0,    0,    0,  411,    0,
    0,    0,  410,    0,  343,    0,    0,    0,    0,    0,
  359,    0,    0,    0,    0,    0,  224,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  233,    0,  215,    0,    0,  203,    0,  321,    0,
  320,  406,  329,  330,  331,  332,  333,  326,    0,  378,
  379,  380,  381,  382,  377,    0,  376,  375,  337,  338,
  334,    0,   74,   75,   76,   77,   78,    0,   73,    0,
  408,  339,    0,    0,  412,    0,    0,  160,   61,   56,
   57,   58,   59,   42,    0,   44,    0,    0,    0,  229,
  181,  185,  363,    0,  386,  373,  341,    0,  350,  351,
  352,    0,  358,    0,  361,    0,  365,  366,  367,  368,
  369,  370,  364,    0,   82,   83,    0,   86,   87,    0,
    0,  340,    0,    0,  374,  311,  312,  313,  314,  294,
  295,  296,  291,  292,  297,  298,  287,    0,  290,  301,
  302,  289,  307,  308,  309,  310,  317,  315,  316,  319,
  318,  299,  300,  303,  304,  305,  306,  293,  457,    0,
    0,    0,    0,    0,    0,  323,  328,  384,  336,   80,
  390,    0,  387,    0,    0,   55,    0,    0,  228,    0,
    0,  385,  391,    0,  360,    0,  372,   84,   88,  193,
  388,  222,  288,    0,  231,  191,  206,  205,  202,  201,
    0,    0,  389,  442,    0,    0,  429,  430,  392,   70,
    0,    0,    0,  431,  432,  353,  362,  458,  456,    0,
    0,  427,  428,   50,   52,    0,    0,    0,  448,    0,
    0,  207,  204,  209,
};
const short socks_yydgoto[] =
	{                                       3,
  416,  302,  568,  569,   17,   18,  211,  212,  350,  639,
  640,  351,  352,  353,  354,  355,  581,  582,  307,  588,
  589,   56,   19,  142,   58,  356,  260,  329,   60,  172,
  173,  420,  680,  739,  357,  636,  637,   20,   21,  459,
  460,  461,  462,  718,  752,  721,  315,  316,  358,  236,
  237,  359,  233,  234,  360,   61,  361,  560,  561,   62,
  149,  150,   63,   64,   65,  310,  156,  157,   67,  114,
   68,   69,   70,   71,   72,  113,   73,  421,  422,  423,
  424,  425,  426,  427,  428,  429,  430,  431,  432,  433,
  434,  435,  436,  437,  438,  439,  440,   74,   75,   76,
   77,   22,   23,   80,   81,  273,  206,  486,  487,  441,
  442,  443,  444,  445,  446,  447,  448,  189,  463,  464,
  465,  362,   82,   83,  190,  129,  363,  364,  450,  365,
  366,  367,  368,  369,  370,  371,  372,  373,   25,   26,
   27,   28,   85,   86,   87,   88,   89,  175,   29,  596,
  597,  146,  103,  311,  312,  313,  255,  734,  285,  322,
  323,  324,  219,  220,  221,  222,  223,  224,  225,  728,
  729,  702,  226,  480,  519,  592,  374,  500,  192,  375,
  376,  231,  481,  593,  482,  521,  193,  377,  378,  379,
  380,  452,  381,  382,  633,  634,  277,  279,  287,  194,
  453,  454,  263,  383,  384,    4,  604,  488,  489,  107,
  108,  492,  493,  605,  201,  267,  159,  158,  196,  133,
  134,  197,  239,  166,  165,  243,  292,  240,  684,  241,
  609,  242,  476,  505,  624,  575,  576,  477,  506,  281,
  491,
};
const short socks_yysindex[] =
	{                                   -145,
    0, 1741,    0, 3926,   16,   23,   41,    0,   52,   54,
   60,   69,   78,   86,  101, -155,    0,    0,    0,    0,
 1741,    0,    0,    0,    0,    0,    0,    0,    0,  113,
    8,    0,    0,  129,  140,  150,  166,    0,    0,    0,
    0,  168,  176,  187,  195,  200,  202,  213,  228,  235,
  253,  268,  280,    0,    0,    0,    0, -248,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 3926,    0,    0,    0,    0,    0,    0,    0,    0,
 -107,  -18,    4,    0,    0,   11,   36,   42,   67, -337,
  296,  307,   28,    0,  -53,  -43,  364,  366,  124,    0,
    0, -230,  378,  379,    0,    0,   80,  112, -134,   97,
   97,   97,  134,  135, -216, -203,  403,    0, -163,    0,
    0,    0,  167,  167,    0,    0,    0,    0,    0,    0,
    0,    0,   96,   98,    0,    0,    0,    0,  -53,    0,
  411,  412,  152,  152,    0,  124,    0, -135, -135,    0,
    0,    0, -217, -244,  154,  159,    0,    0,    0,    0,
    0, -134,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  167,    0,    0,    0,
  347,    0,  151,  153,    0,  432,  434,    0,    0,    0,
 -135,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  435,  436,  437,    0,    0,  128,    0,    0,    0,    0,
    0,    0,    0,  154,    0,    0,  159,    0, -213, -150,
 -150, -150,  365,    0,    0,  431,  433, -105, -105,    0,
 -287,  132,  136,  -48,    0,    0,    0,    0,    0,  442,
    0,    0,  369,  370,  380,    0, -193,  143,  170,  444,
  447,  449,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -326,    0,  467, -326, -237, -225, -225,
 3977, -200,  455,  459,  460,  461,  466,  468,  469,  472,
  155,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -193,  171,    0,    0,  143,    0,  490,  246,    0,    0,
    0,    0,    0,    0,  184,    0,    0,    0,    0,    0,
    0,  493,  494,  498,  499,  500,  188,  502,  503,  -42,
  504,  505,  506,   22,  508,  511,  513,  514,  515,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -225,  171,    0,    0,    0,    0,
    0,    0,    0,    0,  171,  516,  517,  519,  520,  521,
  522,  524,  525,  526,  531,  536,  538,  542,  544,  545,
  546,  547,  548,  549,  553,  554,  555,  556,  557,  560,
  561,  562,  563,  564,  565,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, 3977,  171,    0,    0,    0,    0,    0,    0,
    0,    0, -200,  171,  -17,    0,  355,  154,  -19,   -2,
  244,  251,  -88, -250,    0,    0,  583,    0,    0,  272,
  591,  300,    0,  298,    0,    0,  246,  -60,  -60,    0,
    0,  614,  615,    0,  304,  154,  159,  305,    0,  607,
  230,  216,    0,  297,    0,  611, -140,  316,  317,  214,
    0,  320,  322, -286,  335,  383,    0, -225,  272,  626,
 -225,  323,  258,  259,  260,  269,  306,  308,  309,  267,
  282,  342,  345,  -27,  356,  -85,  311,  287,  289,  290,
  292,  314,  315,  319,  324,  313,  -82,  -80,  -50,  318,
  374,    0, 3977,    0, -200,  691,    0,  680,    0,  355,
    0,    0,    0,    0,    0,    0,    0,    0,  -19,    0,
    0,    0,    0,    0,    0,   -2,    0,    0,    0,    0,
    0,  -88,    0,    0,    0,    0,    0, -250,    0, -217,
    0,    0,  682, -217,    0,  685, -193,    0,    0,    0,
    0,    0,    0,    0,  -60,    0,  152,  152, -217,    0,
    0,    0,    0,   -1,    0,    0,    0, -217,    0,    0,
    0,  699,    0,  448,    0,  704,    0,    0,    0,    0,
    0,    0,    0, -286,    0,    0,  335,    0,    0,  383,
  629,    0, -217,  630,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  406,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  720,
  644,  645,  507,  -20,  413,    0,    0,    0,    0,    0,
    0, -217,    0, -167,  647,    0,  727,  729,    0,  419,
  419,    0,    0,  424,    0,  426,    0,    0,    0,    0,
    0,    0,    0,  427,    0,    0,    0,    0,    0,    0,
  719,  739,    0,    0,  419,  419,    0,    0,    0,    0,
 -105, -105,  350,    0,    0,    0,    0,    0,    0,  430,
  438,    0,    0,    0,    0, -326,  439,  440,    0,  457,
  458,    0,    0,    0,};
const short socks_yyrindex[] =
	{                                      0,
    0,    6,    0,   24,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    6,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   24,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  789,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  792,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, 1863,    0,
    0,    0,    0,    0,    0, 1684,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 1951,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, 2044,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 2137,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    7,  238,  451,    0,    0,  654,    0,    0,    0,    0,
    0,    0,    0,  862,    0,    0, 1065,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  423,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  425,  425,
  428, -212,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -108,    0,    0,    0, 2225,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  -96,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -94,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -97,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, 1273,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, 2865,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  672,    0,    0,
  672,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  677,    0, -102,    0,    0,    0,    0, 3710,
    0,    0,    0,    0,    0,    0,    0,    0, 2527,    0,
    0,    0,    0,    0,    0, 2696,    0,    0,    0,    0,
    0, 2325,    0,    0,    0,    0,    0, 3034,    0,    0,
    0,    0,    0,    0,    0,    0,  681,    0,    0,    0,
    0,    0,    0,    0, 1476,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, 3203,    0,    0, 3372,    0,    0, 3541,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  749,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 3738,
 3738,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, 2506, 2506,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -109,    0,    0,
    0,    0,    0,    0,};
const short socks_yygindex[] =
	{                                      0,
    0, -228,  240,    0,   -3,   35,    0,  -71,    0,  173,
    0, -262, -256, -255,    0, -254,  236,    0, -272,    0,
  229,    0,   37,    0,    0,   -4,    0,    0,    0,    0,
  648,    0,    0,    0,    0,  182,    0,  803,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  510,    0, -215,
    0,    0, -209,    0,    0,    0, -253,    0,  266,    0,
    0,  678,    0,    0,    0,   38,    0,  675,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   46,   49,    0,    0, -245, -139,  341,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -429,
    0,    0,    0,  750,    0,    0, -265,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   90,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  310,   55,    0,
    0,  705,    0,    0, -291,    0,    0, -628,    0,  579,
 -279,    0, -546, -578,  671,  673,    0, -162, -161,    0,
    0,    0, -547,    0,    0,  325,    0,    0,    0,    0,
 -269,    0,  453,    0, -341,    0,    0, -283,  212,    0,
 -251,    0,    0,    0,  220,    0,    0,    0,  123,    0,
    0, -423,  193,    0,    0,    0, -462,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -64,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  527,  362,    0,  293,    0,    0,    0,    0,
    0,
};
#define YYTABLESIZE 4446
const short socks_yytable[] =
	{                                      59,
   54,  229,  230,  274,  303,  115,  422,  326,  466,  284,
  304,  305,  306,  309,  207,  208,  404,  658,  419,  478,
  385,  257,  214,   11,  256,  449,  606,  214,  223,  552,
  232,  282,    8,  554,  518,  700,  418,  458,   55,  451,
   57,   66,  293,  691,  197,  197,  197,  693,  303,   78,
    5,    6,   79,  106,  304,  305,  306,  309,   90,  455,
  456,  699,  417,  457,  330,  331,  327,  511,  160,  198,
  275,  703,  735,   91,  293,  332,  333,   59,   54,  510,
   92,   40,   41,   11,   12,   13,   14,  213,  161,  334,
  335,   24,  127,   84,  276,  711,  742,  743,   93,   34,
  332,  333,  139,  140,  141,  517,  185,  186,  187,   94,
   24,   95,  553,   40,   41,  725,   55,   96,   57,   66,
  328,  162,  555,  294,  321,  682,   97,   78,  258,  681,
   79,  422,  244,  336,  337,   98,   90,  214,  215,  250,
  217,  218,  696,   99,  259,  723,  296,  208,  208,  208,
  208,  208,  297,  298,  197,  197,  197,  214,  100,  197,
  197,  197,  295,  188,  214,  215,  216,  217,  218,  295,
  105,   84,  627,  628,  629,  630,  631,  632,  296,  466,
  419,  270,  271,  272,  297,  298,  109,  449,  145,    1,
    2,  208,  208,  583,  584,  585,  586,  110,  418,  101,
  102,  451,  600,  601,  602,  603,  338,  111,  458,  169,
  170,  171,  339,  299,  214,  215,  216,  217,  218,  724,
  147,  148,  340,  112,  417,  115,  341,  342,  343,  344,
  345,  346,  347,  116,  457,  151,  152,  424,  299,  556,
  557,  558,  348,  349,  117,  299,  209,  210,  641,  300,
  130,  644,  118,  208,  301,  180,  181,  119,  562,  120,
  208,  404,  308,  422,  422,  422,  422,  422,  182,  183,
  121,  466,  214,  223,  422,  232,  422,  422,  422,  422,
  419,  612,  422,  422,  422,  122,  611,  449,  422,  422,
  422,  422,  123,   11,   11,   11,  422,  422,  418,  422,
  458,  451,  422,  422,  422,  695,  308,  422,  422,  282,
  124,  422,  422,  422,  422,  422,  422,  422,  422,  261,
  262,  422,  422,  422,  417,  125,  457,  475,  503,  208,
  657,  619,  620,  422,  303,  422,  422,  126,  422,  131,
  304,  305,  306,  309,  563,  564,  565,  566,  567,  422,
   11,  579,  580,  143,  422,  422,  422,  115,  422,  422,
  422,  132,  424,  422,  144,  422,  422,  422,  135,  422,
  570,  571,  572,  573,  574,   11,  422,  422,  422,  145,
  214,  215,  216,  217,  422,  422,  660,  661,  283,  672,
  673,  674,  675,  136,  422,  422,  422,  422,  422,  137,
  422,  422,  422,  422,  422,  422,  422,  422,  422,  153,
  422,  154,  422,  422,  422,  422,  422,  155,  422,  422,
  422,  676,  677,  422,  138,  422,  422,  422,  719,  720,
  176,  177,  422,  264,  265,  163,  164,  167,  422,  422,
  422,  422,  168,  174,  422,  422,  178,  179,  184,  422,
  426,  701,  195,  199,  422,  200,  203,  204,  422,  422,
  422,  422,  422,  422,  422,  205,  749,  697,  698,  245,
  587,  232,  422,  422,  422,  422,  235,  248,  246,  249,
  247,  251,  252,  253,  254,  744,  745,  266,  268,  278,
  269,  289,  290,  280,  424,  424,  424,  424,  424,  288,
  314,  318,  291,  317,  319,  424,  320,  424,  424,  424,
  424,  325,  467,  424,  424,  424,  468,  469,  470,  424,
  424,  424,  424,  471,  475,  472,  473,  424,  424,  474,
  424,  726,  727,  424,  424,  424,  484,  485,  424,  424,
  479,  490,  424,  424,  424,  424,  424,  424,  424,  424,
  494,  495,  424,  424,  424,  496,  497,  498,  499,  501,
  502,  507,  508,  509,  424,  512,  424,  424,  513,  424,
  514,  515,  516,  522,  523,  426,  524,  525,  526,  527,
  424,  528,  529,  530,  587,  424,  424,  424,  531,  424,
  424,  424,  308,  532,  424,  533,  424,  424,  424,  534,
  424,  535,  536,  537,  538,  539,  540,  424,  424,  424,
  541,  542,  543,  544,  545,  424,  424,  546,  547,  548,
  549,  550,  551,  559,  577,  424,  424,  424,  424,  424,
  578,  424,  424,  424,  424,  424,  424,  424,  424,  424,
  590,  424,  591,  424,  424,  424,  424,  424,  594,  424,
  424,  424,  595,  443,  424,  598,  424,  424,  424,  607,
  608,  610,  613,  424,  614,  615,  616,  503,  618,  424,
  424,  424,  424,  621,  622,  424,  424,  625,  623,  626,
  424,  635,  638,  643,  645,  424,  646,  647,  648,  424,
  424,  424,  424,  424,  424,  424,  653,  649,  650,  655,
  651,  652,  656,  424,  424,  424,  424,  426,  426,  426,
  426,  426,  654,  659,  663,  662,  664,  665,  426,  666,
  426,  426,  426,  426,  667,  668,  426,  426,  426,  669,
  671,  679,  426,  426,  426,  426,  683,  685,  670,  692,
  426,  426,  694,  426,  678,  704,  426,  426,  426,  333,
  706,  426,  426,  710,  712,  426,  426,  426,  426,  426,
  426,  426,  426,  713,  714,  426,  426,  426,  715,  716,
  722,  730,  731,  717,  732,  733,  740,  426,  443,  426,
  426,  736,  426,  737,  738,  741,  283,  747,    3,  750,
  751,    2,  404,  426,  223,  748,  223,  232,  426,  426,
  426,  232,  426,  426,  426,  404,  200,  426,  687,  426,
  426,  426,  709,  426,  753,  754,  690,  689,  708,  238,
  426,  426,  426,  104,  483,  686,  202,  599,  426,  426,
  208,  128,  286,  191,  227,  705,  228,  520,  426,  426,
  426,  426,  426,  642,  426,  426,  426,  426,  426,  426,
  426,  426,  426,  707,  426,  746,  426,  426,  426,  426,
  426,  182,  426,  426,  426,  617,  504,  426,  688,  426,
  426,  426,    0,    0,    0,    0,  426,    0,    0,    0,
    0,    0,  426,  426,  426,  426,    0,    0,  426,  426,
    0,    0,    0,  426,    0,    0,    0,    0,  426,    0,
    0,    0,  426,  426,  426,  426,  426,  426,  426,    0,
  443,  443,  443,  443,  443,    0,  426,  426,  426,  426,
    0,  443,    0,  443,  443,  443,  443,    0,    0,  443,
  443,  443,    0,    0,    0,  443,  443,  443,  443,    0,
    0,    0,    0,  443,  443,    0,  443,    0,    0,  443,
  443,  443,    0,    0,  443,  443,    0,    0,  443,  443,
  443,  443,  443,  443,  443,  443,    0,    0,  443,  443,
  443,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  443,    0,  443,  443,    0,  443,  182,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  443,    0,    0,    0,
    0,  443,  443,  443,    0,  443,  443,  443,    0,    0,
    0,    0,  443,  443,  443,    0,  443,    0,    0,    0,
    0,    0,    0,  443,  443,  443,    0,    0,    0,    0,
    0,  443,  443,    0,    0,    0,    0,    0,    0,    0,
    0,  443,  443,  443,  443,  443,    0,  443,  443,  443,
  443,  443,  443,  443,  443,  443,    0,  443,    0,  443,
  443,  443,  443,  443,  186,  443,  443,  443,    0,    0,
  443,    0,  443,  443,  443,    0,    0,    0,    0,  443,
    0,    0,    0,    0,    0,  443,  443,  443,  443,    0,
    0,  443,  443,    0,    0,    0,  443,    0,    0,    0,
    0,  443,    0,    0,    0,  443,  443,  443,  443,  443,
  443,  443,    0,    0,    0,    0,    0,    0,    0,  443,
  443,  443,  443,    0,    0,    0,    0,    0,    0,  182,
    0,  182,  182,  182,  182,    0,    0,  182,  182,  182,
    0,    0,    0,  182,  182,  182,  182,    0,    0,    0,
    0,  182,  182,    0,  182,    0,    0,  182,  182,  182,
    0,    0,  182,  182,    0,    0,  182,  182,  182,  182,
  182,  182,  182,  182,    0,    0,  182,  182,  182,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  182,  186,
  182,  182,    0,  182,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  182,    0,    0,    0,    0,  182,
  182,  182,    0,  182,    0,  182,    0,    0,    0,    0,
  182,  182,  182,    0,  182,    0,    0,    0,    0,    0,
    0,  182,    0,  182,    0,    0,    0,    0,    0,  182,
  182,    0,    0,    0,    0,    0,    0,    0,    0,  182,
  182,  182,  182,  182,    0,  182,  182,  182,  182,  182,
  182,  182,  182,  182,    0,  182,    0,  182,  182,  182,
  182,  182,   60,  182,  182,  182,    0,    0,  182,    0,
  182,  182,  182,    0,    0,    0,    0,  182,    0,    0,
    0,    0,    0,  182,  182,  182,  182,    0,    0,  182,
  182,    0,    0,    0,  182,    0,    0,    0,    0,  182,
    0,    0,    0,  182,  182,  182,  182,  182,  182,  182,
    0,    0,    0,    0,    0,    0,    0,  182,  182,  182,
  182,    0,  186,    0,  186,  186,  186,  186,    0,    0,
  186,  186,  186,    0,    0,    0,  186,  186,  186,  186,
    0,    0,    0,    0,  186,  186,    0,  186,    0,    0,
  186,  186,  186,    0,    0,  186,  186,    0,    0,  186,
  186,  186,  186,  186,  186,  186,  186,    0,    0,  186,
  186,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  186,    0,  186,  186,    0,  186,   60,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  186,    0,    0,
    0,    0,  186,  186,  186,    0,  186,    0,  186,    0,
    0,    0,    0,  186,  186,  186,    0,  186,    0,    0,
    0,    0,    0,    0,  186,    0,  186,    0,    0,    0,
    0,    0,  186,  186,    0,    0,    0,    0,    0,    0,
    0,    0,  186,  186,  186,  186,  186,    0,  186,  186,
  186,  186,  186,  186,  186,  186,  186,    0,  186,    0,
  186,  186,  186,  186,  186,   54,  186,  186,  186,    0,
    0,  186,    0,  186,  186,  186,    0,    0,    0,    0,
  186,    0,    0,    0,    0,    0,  186,  186,  186,  186,
    0,    0,  186,  186,    0,    0,    0,  186,    0,    0,
    0,    0,  186,    0,    0,    0,  186,  186,  186,  186,
  186,  186,  186,    0,    0,    0,    0,    0,    0,    0,
  186,  186,  186,  186,    0,    0,    0,    0,    0,    0,
   60,    0,   60,   60,   60,   60,    0,    0,   60,   60,
   60,    0,    0,    0,   60,   60,   60,   60,    0,    0,
    0,    0,   60,   60,    0,   60,    0,    0,   60,   60,
   60,    0,    0,   60,   60,    0,    0,   60,   60,   60,
   60,   60,   60,   60,   60,    0,    0,   60,   60,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   60,
   54,   60,   60,    0,   60,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   60,    0,    0,    0,    0,
   60,   60,   60,    0,   60,    0,   60,    0,    0,    0,
    0,   60,   60,   60,    0,   60,    0,    0,    0,    0,
    0,    0,   60,    0,   60,    0,    0,    0,    0,    0,
   60,   60,    0,    0,    0,    0,    0,    0,    0,    0,
   60,   60,   60,   60,   60,    0,   60,   60,   60,   60,
   60,   60,   60,   60,   60,    0,   60,    0,   60,   60,
   60,   60,   60,   91,   60,   60,   60,    0,    0,   60,
    0,   60,   60,   60,    0,    0,    0,    0,   60,    0,
    0,    0,    0,    0,   60,   60,   60,   60,    0,    0,
   60,   60,    0,    0,    0,   60,    0,    0,    0,    0,
   60,    0,    0,    0,   60,   60,   60,   60,   60,   60,
   60,    0,    0,    0,    0,    0,    0,    0,   60,   60,
   60,   60,    0,   54,    0,   54,   54,   54,   54,    0,
    0,   54,   54,   54,    0,    0,    0,   54,   54,   54,
   54,    0,    0,    0,    0,   54,   54,    0,   54,    0,
    0,   54,   54,   54,    0,    0,   54,   54,    0,    0,
   54,   54,   54,   54,   54,   54,   54,   54,    0,    0,
   54,   54,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   54,    0,   54,   54,    0,   54,   91,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   54,    0,
    0,    0,    0,   54,   54,   54,    0,   54,    0,   54,
    0,    0,    0,    0,   54,   54,   54,    0,   54,    0,
    0,    0,    0,    0,    0,   54,    0,   54,    0,    0,
    0,    0,    0,   54,   54,    0,    0,    0,    0,    0,
    0,    0,  152,   54,   54,   54,   54,   54,    0,   54,
   54,   54,   54,   54,   54,   54,   54,   54,    0,   54,
    0,   54,   54,   54,   54,   54,    0,   54,   54,   54,
    0,    0,   54,    0,   54,   54,   54,    0,    0,    0,
    0,   54,    0,    0,    0,    0,    0,   54,   54,   54,
   54,    0,    0,   54,   54,    0,    0,    0,   54,    0,
    0,    0,    0,   54,    0,    0,    0,   54,   54,   54,
   54,   54,   54,   54,    0,    0,    0,    0,    0,    0,
    0,   54,   54,   54,   54,    0,    0,    0,    0,    0,
  174,   91,    0,   91,   91,   91,   91,    0,    0,   91,
   91,   91,    0,    0,    0,   91,   91,   91,   91,    0,
    0,    0,    0,   91,   91,    0,   91,    0,    0,   91,
   91,   91,    0,    0,    0,    0,    0,    0,   91,   91,
   91,   91,   91,   91,   91,   91,    0,    0,   91,   91,
   91,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   91,    0,   91,   91,    0,   91,    5,    6,    0,    0,
    0,    0,    7,    8,    9,   10,   91,    0,    0,    0,
    0,   91,   91,   91,    0,   91,    0,   91,    0,    0,
    0,    0,    0,  124,    0,    0,   91,    0,    0,   11,
   12,   13,   14,   91,    0,   91,    0,    0,    0,    0,
    0,   91,   91,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   15,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   16,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   91,   91,   91,    0,
    0,    0,   91,    0,    0,    0,   91,    0,    0,    0,
    0,   91,  152,  152,  152,  152,   93,    0,  152,  152,
  152,    0,    0,    0,  152,  152,  152,  152,    0,    0,
   91,    0,  152,  152,    0,  152,    0,    0,  152,  152,
  152,    0,    0,    0,    0,    0,    0,  152,  152,  152,
  152,  152,  152,  152,  152,    0,    0,  152,  152,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  152,
    0,  152,  152,    0,  152,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  152,    0,    0,    0,    0,
  152,  152,  152,    0,  152,    0,  152,    0,    0,    0,
  174,  174,  174,  174,  460,    0,  174,  174,  174,    0,
    0,    0,  174,  174,  174,  174,    0,    0,    0,    0,
  174,  174,    0,  174,    0,    0,  174,  174,  174,    0,
    0,    0,    0,    0,    0,  174,  174,  174,  174,  174,
  174,  174,  174,    0,    0,  174,  174,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  174,    0,  174,
  174,    0,  174,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  174,    0,  152,  152,  152,  174,  174,
  174,    0,  174,    0,  174,    0,    0,    0,    0,    0,
    0,    0,    0,  124,  124,  124,  124,    0,    0,  124,
  124,  124,    0,    0,    0,  124,  124,  124,  124,  152,
    0,    0,    0,  124,  124,    0,  124,    0,    0,  124,
  124,  124,    0,    0,    0,    0,    0,    0,  124,  124,
  124,  124,  124,  124,  124,  124,    0,    0,  124,  124,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  124,    0,  124,  124,    0,  124,    0,    0,    0,    0,
    0,    0,    0,  174,  174,  174,  124,    0,    0,    0,
    0,  124,  124,  124,    0,  124,    0,  124,    0,    0,
    0,    0,    0,    0,    0,    0,   93,   93,   93,   93,
    0,    0,   93,   93,   93,    0,    0,  174,   93,   93,
   93,   93,    0,    0,    0,    0,   93,   93,    0,   93,
    0,    0,   93,   93,   93,    0,    0,    0,    0,    0,
    0,   93,   93,   93,   93,   93,   93,   93,   93,  335,
    0,   93,   93,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   93,    0,   93,   93,    0,   93,    0,
    0,    0,    0,    0,    0,    0,  124,  124,  124,   93,
    0,    0,    0,    0,   93,   93,   93,    0,   93,    0,
   93,    0,    0,    0,  460,  460,  460,  460,    0,    0,
  460,  460,  460,    0,    0,    0,  460,  460,  460,  460,
  124,    0,    0,    0,  460,  460,    0,  460,    0,    0,
  460,  460,  460,    0,    0,    0,    0,    0,    0,  460,
  460,  460,  460,  460,  460,  460,  460,    0,    0,  460,
  460,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  460,    0,  460,  460,    0,  460,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  460,    0,   93,
   93,   93,  460,  460,  460,    0,  460,    0,  460,    0,
    0,  335,  335,  335,  335,  335,    0,    0,    0,    0,
    0,    0,  335,    0,    0,    0,    0,    0,    0,    0,
  335,  335,    0,   93,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  335,  335,    0,  335,    0,    0,
    0,    0,    0,    0,    0,  335,  335,    0,    0,    0,
  447,  335,  335,  335,  335,  335,  335,    0,    0,  335,
  335,  335,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  327,    0,    0,    0,    0,    0,  460,  460,  460,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  335,  335,  335,    0,  335,    0,    0,
    0,  460,    0,    0,  335,    0,  335,    0,    0,    0,
    0,    0,  335,  335,    0,    0,    0,    0,    0,    0,
    0,    0,  335,  335,  335,  335,  335,    0,  335,  335,
  335,  335,  335,  335,  335,  335,  335,    0,  335,    0,
  335,  335,  335,  335,  335,    0,  335,  335,  335,    0,
    0,  335,    0,  335,  335,  335,    0,    0,    0,    0,
  335,    0,    0,    0,    0,    0,  335,    0,    0,    0,
    0,    0,  335,  335,    0,    0,    0,  335,    0,    0,
    0,    0,  335,  447,    0,    0,  335,  335,  335,  335,
  335,  335,  335,  327,  327,  327,  327,  327,    0,    0,
  335,    0,  335,  335,  327,    0,    0,    0,  447,    0,
    0,    0,  327,  327,    0,    0,    0,    0,    0,    0,
    0,    0,  447,  447,    0,    0,  327,  327,    0,  327,
  383,    0,  447,    0,    0,    0,    0,  327,  327,    0,
    0,    0,    0,  327,  327,  327,  327,  327,  327,    0,
    0,  327,  327,  327,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  447,    0,
    0,    0,    0,    0,    0,    0,    0,  447,    0,    0,
    0,    0,    0,  447,  447,  327,    0,  327,    0,  327,
    0,    0,    0,    0,    0,    0,  327,    0,  327,    0,
    0,    0,    0,    0,  327,  327,    0,    0,    0,    0,
    0,    0,    0,    0,  327,  327,  327,  327,  327,    0,
  327,  327,  327,  327,  327,  327,  327,  327,  327,    0,
  327,    0,  327,  327,  327,  327,  327,    0,  327,  327,
  327,    0,    0,  327,  447,  327,  327,  327,  447,    0,
    0,    0,  327,  447,    0,    0,    0,    0,  327,    0,
    0,    0,    0,  383,  327,  327,    0,    0,    0,  327,
    0,  383,  383,    0,  327,    0,    0,    0,    0,  327,
  327,  327,  327,  327,  327,  383,  383,    0,  383,  342,
    0,    0,  327,    0,  327,  327,  383,  383,    0,    0,
    0,    0,  383,  383,  383,  383,  383,  383,    0,    0,
  383,  383,  383,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  383,  383,  383,    0,  383,    0,
    0,    0,    0,    0,    0,  383,    0,  383,    0,    0,
    0,    0,    0,  383,  383,    0,    0,    0,    0,    0,
    0,    0,    0,  383,  383,  383,  383,  383,    0,  383,
  383,  383,  383,  383,  383,  383,  383,  383,    0,  383,
    0,  383,  383,  383,  383,  383,    0,  383,  383,  383,
    0,    0,  383,    0,  383,  383,  383,    0,    0,    0,
    0,  383,    0,    0,    0,    0,    0,  383,    0,    0,
    0,    0,  342,  383,  383,    0,    0,    0,  383,    0,
  342,  342,    0,  383,    0,    0,    0,  383,  383,  383,
  383,  383,  383,  383,  342,  342,    0,    0,   79,    0,
    0,  383,    0,  383,  383,  342,  342,    0,    0,    0,
    0,  342,  342,  342,  342,  342,  342,    0,    0,  342,
  342,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  342,  342,  342,    0,  342,    0,    0,
    0,    0,    0,    0,  342,    0,  342,    0,    0,    0,
    0,    0,  342,  342,    0,    0,    0,    0,    0,    0,
    0,    0,  342,  342,  342,  342,  342,    0,  342,  342,
  342,  342,  342,  342,  342,  342,  342,    0,  342,    0,
  342,  342,  342,  342,  342,    0,  342,  342,  342,    0,
    0,  342,    0,  342,  342,  342,    0,    0,    0,    0,
  342,    0,    0,    0,    0,    0,  342,    0,    0,    0,
    0,   79,  342,  342,    0,    0,    0,  342,    0,   79,
   79,    0,  342,    0,    0,    0,  342,  342,  342,  342,
  342,  342,  342,   79,   79,    0,   79,  371,    0,    0,
  342,    0,  342,  342,   79,   79,    0,    0,    0,    0,
   79,   79,   79,   79,   79,   79,    0,    0,   79,   79,
   79,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   79,    0,   79,    0,   79,    0,    0,    0,
    0,    0,    0,   79,    0,   79,    0,    0,    0,    0,
    0,   79,   79,    0,    0,    0,    0,    0,    0,    0,
    0,   79,   79,   79,   79,   79,    0,   79,   79,   79,
   79,   79,   79,   79,   79,   79,    0,   79,    0,   79,
   79,   79,   79,   79,    0,   79,   79,   79,    0,    0,
   79,    0,   79,   79,   79,    0,    0,    0,    0,   79,
    0,    0,    0,    0,    0,   79,    0,    0,    0,    0,
  371,   79,   79,    0,    0,    0,   79,    0,  371,  371,
    0,   79,    0,    0,    0,    0,   79,   79,   79,   79,
   79,   79,  371,  371,    0,    0,   81,    0,    0,   79,
    0,   79,   79,  371,  371,    0,    0,    0,    0,  371,
  371,  371,  371,  371,  371,    0,    0,  371,  371,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  371,  371,  371,    0,  371,    0,    0,    0,    0,
    0,    0,  371,    0,  371,    0,    0,    0,    0,    0,
  371,  371,    0,    0,    0,    0,    0,    0,    0,    0,
  371,  371,  371,  371,  371,    0,  371,  371,  371,  371,
  371,  371,  371,  371,  371,    0,  371,    0,  371,  371,
  371,  371,  371,    0,  371,  371,  371,    0,    0,  371,
    0,  371,  371,  371,    0,    0,    0,    0,  371,    0,
    0,    0,    0,    0,  371,    0,    0,    0,    0,   81,
  371,  371,    0,    0,    0,  371,    0,   81,   81,    0,
  371,    0,    0,    0,  371,  371,  371,  371,  371,  371,
  371,   81,   81,    0,    0,   85,    0,    0,  371,    0,
  371,  371,   81,   81,    0,    0,    0,    0,   81,   81,
   81,   81,   81,   81,    0,    0,   81,   81,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   81,   81,   81,    0,   81,    0,    0,    0,    0,    0,
    0,   81,    0,   81,    0,    0,    0,    0,    0,   81,
   81,    0,    0,    0,    0,    0,    0,    0,    0,   81,
   81,   81,   81,   81,    0,   81,   81,   81,   81,   81,
   81,   81,   81,   81,    0,   81,    0,   81,   81,   81,
   81,   81,    0,   81,   81,   81,    0,    0,   81,    0,
   81,   81,   81,    0,    0,    0,    0,   81,    0,    0,
    0,    0,    0,   81,    0,    0,    0,    0,   85,   81,
   81,    0,    0,    0,   81,    0,   85,   85,    0,   81,
    0,    0,    0,   81,   81,   81,   81,   81,   81,   81,
   85,   85,    0,    0,  322,    0,    0,   81,    0,   81,
   81,   85,   85,    0,    0,    0,    0,   85,   85,   85,
   85,   85,   85,    0,    0,   85,   85,    0,    0,    0,
    0,    0,  447,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   85,
   85,   85,    0,   85,    0,    0,    0,    0,    0,    0,
   85,    0,   85,    0,    0,    0,    0,    0,   85,   85,
    0,    0,    0,    0,    0,    0,    0,    0,   85,   85,
   85,   85,   85,    0,   85,   85,   85,   85,   85,   85,
   85,   85,   85,    0,   85,    0,   85,   85,   85,   85,
   85,    0,   85,   85,   85,    0,    0,   85,    0,   85,
   85,   85,    0,    0,    0,    0,   85,    0,    0,    0,
    0,    0,   85,    0,    0,    0,    0,  322,   85,   85,
    0,    0,    0,   85,    0,  322,  322,    0,   85,    0,
    0,    0,   85,   85,   85,   85,   85,   85,   85,  322,
  322,    0,  322,    0,    0,  447,   85,    0,   85,   85,
  322,  322,    0,  447,  447,    0,  322,  322,  322,  322,
  322,  322,    0,    0,  322,  322,  322,  447,  447,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  447,  447,
    0,    0,    0,    0,  447,  447,  447,  447,  447,  447,
    0,    0,  447,  447,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  322,  322,
    0,    0,  322,    0,    0,    0,    0,    0,    0,  322,
    0,  322,    0,    0,    0,    0,    0,  322,  322,    0,
    0,    0,    0,    0,    0,    0,  447,  447,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  447,    0,  447,
    0,    0,    0,    0,    0,  447,  447,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  322,    0,    0,    0,    0,    0,  322,  322,    0,
    0,    0,  322,    0,    0,    0,    0,  322,    0,    0,
    0,  322,  322,  322,  322,  322,  322,  322,    0,  447,
    0,    0,    0,    0,    0,  447,  447,  322,  322,    0,
    0,    0,    0,    0,    0,  447,    0,    0,    0,  447,
  447,  447,  447,  447,  447,  447,    0,    0,   30,    0,
    0,    5,    6,   31,    0,  447,  447,    7,    8,    9,
   10,    0,    0,    0,    0,   32,   33,    0,   34,    0,
    0,   35,   36,   37,    0,    0,    0,    0,    0,    0,
   38,   39,   40,   41,   11,   12,   13,   14,    0,    0,
   42,   43,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    5,    6,   44,   45,    0,   15,    0,    0,
    0,    0,    0,    0,    0,    0,  330,  331,   46,    0,
    0,    0,    0,   47,   48,   49,    0,  332,  333,   16,
    0,    0,    0,   40,   41,   11,   12,   13,   14,    0,
    0,  334,  335,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  336,    0,  386,    0,  295,
    0,    0,    0,    0,    0,    0,    0,    0,  296,    0,
    0,    0,    0,    0,  297,  298,    0,    0,   50,   51,
   52,    0,    0,    0,  387,  388,  389,  390,  391,    0,
  392,  393,  394,  395,  396,  397,  398,  399,  400,    0,
  401,    0,  402,  403,  404,  405,  406,    0,  407,  408,
  409,    0,   53,  410,    0,  411,  412,  413,    0,    0,
    0,    0,  414,    0,    0,    0,    0,    0,  338,    0,
    0,    0,    0,    0,  339,  299,    0,    0,    0,  300,
    0,    0,    0,    0,  340,    0,    0,    0,    0,  342,
  343,  344,  345,  346,  347,    0,    0,    0,    0,    0,
    0,    0,  415,    0,  348,  349,
};
const short socks_yycheck[] =
	{                                       4,
    4,  164,  164,  249,  267,    0,    0,  287,  292,   58,
  267,  267,  267,  267,  154,  125,  125,   45,  291,  311,
  290,  237,  125,    0,  234,  291,  489,  125,  125,  453,
  125,  358,  283,  463,  376,  614,  291,  292,    4,  291,
    4,    4,  268,  590,  257,  258,  259,  594,  311,    4,
  276,  277,    4,   46,  311,  311,  311,  311,    4,  260,
  261,  609,  291,  292,  290,  291,  304,   46,  299,  134,
  358,  618,  701,   58,  268,  301,  302,   82,   82,   58,
   58,  307,  308,  309,  310,  311,  312,  159,  319,  315,
  316,    2,  341,    4,  382,  643,  725,  726,   58,  293,
  301,  302,  440,  441,  442,  375,  270,  271,  272,   58,
   21,   58,  454,  307,  308,  694,   82,   58,   82,   82,
  358,  352,  464,  317,  451,  555,   58,   82,  342,  553,
   82,  125,  197,  359,  360,   58,   82,  382,  383,  211,
  385,  386,  605,   58,  358,  692,  372,  257,  258,  259,
  260,  261,  378,  379,  257,  258,  259,  370,   58,  257,
  258,  259,  363,  327,  382,  383,  384,  385,  386,  363,
   58,   82,  459,  460,  461,  462,  463,  464,  372,  463,
  453,  287,  288,  289,  378,  379,   58,  453,  352,  335,
  336,  301,  302,  444,  445,  446,  447,   58,  453,  355,
  356,  453,  263,  264,  265,  266,  432,   58,  463,  344,
  345,  346,  438,  439,  382,  383,  384,  385,  386,  387,
  274,  275,  448,   58,  453,   58,  452,  453,  454,  455,
  456,  457,  458,   58,  463,  279,  280,    0,  439,  257,
  258,  259,  468,  469,   58,  439,  382,  383,  518,  443,
  358,  521,   58,  363,  448,  472,  473,   58,  468,   58,
  370,  370,  267,  257,  258,  259,  260,  261,  472,  473,
   58,  555,  370,  370,  268,  370,  270,  271,  272,  273,
  553,  497,  276,  277,  278,   58,  496,  553,  282,  283,
  284,  285,   58,  270,  271,  272,  290,  291,  553,  293,
  555,  553,  296,  297,  298,  597,  311,  301,  302,  358,
   58,  305,  306,  307,  308,  309,  310,  311,  312,  470,
  471,  315,  316,  317,  553,   58,  555,  370,  371,  439,
  358,  472,  473,  327,  597,  329,  330,   58,  332,  358,
  597,  597,  597,  597,  364,  365,  366,  367,  368,  343,
  327,  440,  441,   58,  348,  349,  350,  352,  352,  353,
  354,  358,  125,  357,   58,  359,  360,  361,  358,  363,
  373,  374,  375,  376,  377,  352,  370,  371,  372,  352,
  382,  383,  384,  385,  378,  379,  472,  473,  437,  472,
  473,  472,  473,  358,  388,  389,  390,  391,  392,  358,
  394,  395,  396,  397,  398,  399,  400,  401,  402,   46,
  404,   46,  406,  407,  408,  409,  410,  294,  412,  413,
  414,  472,  473,  417,  358,  419,  420,  421,  449,  450,
  121,  122,  426,  241,  242,   58,   58,  358,  432,  433,
  434,  435,  331,  347,  438,  439,  313,  313,   46,  443,
    0,  614,  286,  358,  448,  358,   46,   46,  452,  453,
  454,  455,  456,  457,  458,  314,  746,  607,  608,  123,
  474,  318,  466,  467,  468,  469,  318,   46,  328,   46,
  328,   47,   47,   47,  357,  731,  732,  123,   58,  358,
   58,  123,  123,  358,  257,  258,  259,  260,  261,   58,
  358,   58,  123,  334,   58,  268,   58,  270,  271,  272,
  273,   45,   58,  276,  277,  278,   58,   58,   58,  282,
  283,  284,  285,   58,  370,   58,   58,  290,  291,   58,
  293,  694,  694,  296,  297,  298,   47,  292,  301,  302,
  370,  358,  305,  306,  307,  308,  309,  310,  311,  312,
   58,   58,  315,  316,  317,   58,   58,   58,  371,   58,
   58,   58,   58,   58,  327,   58,  329,  330,   58,  332,
   58,   58,   58,   58,   58,  125,   58,   58,   58,   58,
  343,   58,   58,   58,  588,  348,  349,  350,   58,  352,
  353,  354,  597,   58,  357,   58,  359,  360,  361,   58,
  363,   58,   58,   58,   58,   58,   58,  370,  371,  372,
   58,   58,   58,   58,   58,  378,  379,   58,   58,   58,
   58,   58,   58,  269,  381,  388,  389,  390,  391,  392,
  380,  394,  395,  396,  397,  398,  399,  400,  401,  402,
   58,  404,  371,  406,  407,  408,  409,  410,   58,  412,
  413,  414,  353,    0,  417,  358,  419,  420,  421,   46,
   46,  358,  358,  426,   58,  436,  451,  371,   58,  432,
  433,  434,  435,  358,  358,  438,  439,  358,  465,  358,
  443,  347,  300,   58,  362,  448,  429,  429,  429,  452,
  453,  454,  455,  456,  457,  458,  430,  429,  393,  358,
  393,  393,  358,  466,  467,  468,  469,  257,  258,  259,
  260,  261,  431,  358,  428,  405,  428,  428,  268,  428,
  270,  271,  272,  273,  411,  411,  276,  277,  278,  411,
  418,  358,  282,  283,  284,  285,   46,   58,  415,   58,
  290,  291,   58,  293,  427,   47,  296,  297,  298,  302,
   47,  301,  302,  125,  125,  305,  306,  307,  308,  309,
  310,  311,  312,  358,   45,  315,  316,  317,  125,  125,
  358,  125,   46,  267,   46,  357,   58,  327,  125,  329,
  330,  358,  332,  358,  358,   47,  437,  358,    0,  351,
  351,    0,  370,  343,  370,  358,  125,  370,  348,  349,
  350,  125,  352,  353,  354,  125,   58,  357,  569,  359,
  360,  361,  640,  363,  358,  358,  588,  582,  637,  172,
  370,  371,  372,   21,  315,  560,  149,  487,  378,  379,
  156,   82,  254,  129,  164,  624,  164,  385,  388,  389,
  390,  391,  392,  519,  394,  395,  396,  397,  398,  399,
  400,  401,  402,  634,  404,  733,  406,  407,  408,  409,
  410,    0,  412,  413,  414,  504,  340,  417,  576,  419,
  420,  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,   -1,
   -1,   -1,  432,  433,  434,  435,   -1,   -1,  438,  439,
   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,  448,   -1,
   -1,   -1,  452,  453,  454,  455,  456,  457,  458,   -1,
  257,  258,  259,  260,  261,   -1,  466,  467,  468,  469,
   -1,  268,   -1,  270,  271,  272,  273,   -1,   -1,  276,
  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,
   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,
  297,  298,   -1,   -1,  301,  302,   -1,   -1,  305,  306,
  307,  308,  309,  310,  311,  312,   -1,   -1,  315,  316,
  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  327,   -1,  329,  330,   -1,  332,  125,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,
   -1,  348,  349,  350,   -1,  352,  353,  354,   -1,   -1,
   -1,   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,
   -1,   -1,   -1,  370,  371,  372,   -1,   -1,   -1,   -1,
   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  388,  389,  390,  391,  392,   -1,  394,  395,  396,
  397,  398,  399,  400,  401,  402,   -1,  404,   -1,  406,
  407,  408,  409,  410,    0,  412,  413,  414,   -1,   -1,
  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,
   -1,   -1,   -1,   -1,   -1,  432,  433,  434,  435,   -1,
   -1,  438,  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,
   -1,  448,   -1,   -1,   -1,  452,  453,  454,  455,  456,
  457,  458,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,
  467,  468,  469,   -1,   -1,   -1,   -1,   -1,   -1,  268,
   -1,  270,  271,  272,  273,   -1,   -1,  276,  277,  278,
   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,   -1,
   -1,  290,  291,   -1,  293,   -1,   -1,  296,  297,  298,
   -1,   -1,  301,  302,   -1,   -1,  305,  306,  307,  308,
  309,  310,  311,  312,   -1,   -1,  315,  316,  317,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,  125,
  329,  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,   -1,  348,
  349,  350,   -1,  352,   -1,  354,   -1,   -1,   -1,   -1,
  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,
   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,
  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,
  389,  390,  391,  392,   -1,  394,  395,  396,  397,  398,
  399,  400,  401,  402,   -1,  404,   -1,  406,  407,  408,
  409,  410,    0,  412,  413,  414,   -1,   -1,  417,   -1,
  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,
   -1,   -1,   -1,  432,  433,  434,  435,   -1,   -1,  438,
  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,  448,
   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,  458,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,  467,  468,
  469,   -1,  268,   -1,  270,  271,  272,  273,   -1,   -1,
  276,  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,
   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,
  296,  297,  298,   -1,   -1,  301,  302,   -1,   -1,  305,
  306,  307,  308,  309,  310,  311,  312,   -1,   -1,  315,
  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  327,   -1,  329,  330,   -1,  332,  125,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,
   -1,   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,
   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,   -1,
   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,
   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,  395,
  396,  397,  398,  399,  400,  401,  402,   -1,  404,   -1,
  406,  407,  408,  409,  410,    0,  412,  413,  414,   -1,
   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,
  426,   -1,   -1,   -1,   -1,   -1,  432,  433,  434,  435,
   -1,   -1,  438,  439,   -1,   -1,   -1,  443,   -1,   -1,
   -1,   -1,  448,   -1,   -1,   -1,  452,  453,  454,  455,
  456,  457,  458,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  466,  467,  468,  469,   -1,   -1,   -1,   -1,   -1,   -1,
  268,   -1,  270,  271,  272,  273,   -1,   -1,  276,  277,
  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,
   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,  297,
  298,   -1,   -1,  301,  302,   -1,   -1,  305,  306,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,
  125,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,   -1,
  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,   -1,
   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,
  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  388,  389,  390,  391,  392,   -1,  394,  395,  396,  397,
  398,  399,  400,  401,  402,   -1,  404,   -1,  406,  407,
  408,  409,  410,    0,  412,  413,  414,   -1,   -1,  417,
   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,
   -1,   -1,   -1,   -1,  432,  433,  434,  435,   -1,   -1,
  438,  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,
  448,   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,
  458,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,  467,
  468,  469,   -1,  268,   -1,  270,  271,  272,  273,   -1,
   -1,  276,  277,  278,   -1,   -1,   -1,  282,  283,  284,
  285,   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,
   -1,  296,  297,  298,   -1,   -1,  301,  302,   -1,   -1,
  305,  306,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  327,   -1,  329,  330,   -1,  332,  125,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,
   -1,   -1,   -1,  348,  349,  350,   -1,  352,   -1,  354,
   -1,   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,
   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,    0,  388,  389,  390,  391,  392,   -1,  394,
  395,  396,  397,  398,  399,  400,  401,  402,   -1,  404,
   -1,  406,  407,  408,  409,  410,   -1,  412,  413,  414,
   -1,   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,
   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,  433,  434,
  435,   -1,   -1,  438,  439,   -1,   -1,   -1,  443,   -1,
   -1,   -1,   -1,  448,   -1,   -1,   -1,  452,  453,  454,
  455,  456,  457,  458,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  466,  467,  468,  469,   -1,   -1,   -1,   -1,   -1,
    0,  268,   -1,  270,  271,  272,  273,   -1,   -1,  276,
  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,
   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,
  297,  298,   -1,   -1,   -1,   -1,   -1,   -1,  305,  306,
  307,  308,  309,  310,  311,  312,   -1,   -1,  315,  316,
  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  327,   -1,  329,  330,   -1,  332,  276,  277,   -1,   -1,
   -1,   -1,  282,  283,  284,  285,  343,   -1,   -1,   -1,
   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,
   -1,   -1,   -1,    0,   -1,   -1,  363,   -1,   -1,  309,
  310,  311,  312,  370,   -1,  372,   -1,   -1,   -1,   -1,
   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  332,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  354,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  433,  434,  435,   -1,
   -1,   -1,  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,
   -1,  448,  270,  271,  272,  273,    0,   -1,  276,  277,
  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,
  467,   -1,  290,  291,   -1,  293,   -1,   -1,  296,  297,
  298,   -1,   -1,   -1,   -1,   -1,   -1,  305,  306,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,
   -1,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,   -1,
  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,   -1,
  270,  271,  272,  273,    0,   -1,  276,  277,  278,   -1,
   -1,   -1,  282,  283,  284,  285,   -1,   -1,   -1,   -1,
  290,  291,   -1,  293,   -1,   -1,  296,  297,  298,   -1,
   -1,   -1,   -1,   -1,   -1,  305,  306,  307,  308,  309,
  310,  311,  312,   -1,   -1,  315,  316,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,   -1,  329,
  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  343,   -1,  433,  434,  435,  348,  349,
  350,   -1,  352,   -1,  354,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  270,  271,  272,  273,   -1,   -1,  276,
  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,  467,
   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,
  297,  298,   -1,   -1,   -1,   -1,   -1,   -1,  305,  306,
  307,  308,  309,  310,  311,  312,   -1,   -1,  315,  316,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  327,   -1,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  433,  434,  435,  343,   -1,   -1,   -1,
   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  270,  271,  272,  273,
   -1,   -1,  276,  277,  278,   -1,   -1,  467,  282,  283,
  284,  285,   -1,   -1,   -1,   -1,  290,  291,   -1,  293,
   -1,   -1,  296,  297,  298,   -1,   -1,   -1,   -1,   -1,
   -1,  305,  306,  307,  308,  309,  310,  311,  312,  125,
   -1,  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  327,   -1,  329,  330,   -1,  332,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  433,  434,  435,  343,
   -1,   -1,   -1,   -1,  348,  349,  350,   -1,  352,   -1,
  354,   -1,   -1,   -1,  270,  271,  272,  273,   -1,   -1,
  276,  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,
  467,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,
  296,  297,  298,   -1,   -1,   -1,   -1,   -1,   -1,  305,
  306,  307,  308,  309,  310,  311,  312,   -1,   -1,  315,
  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  327,   -1,  329,  330,   -1,  332,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,  433,
  434,  435,  348,  349,  350,   -1,  352,   -1,  354,   -1,
   -1,  257,  258,  259,  260,  261,   -1,   -1,   -1,   -1,
   -1,   -1,  268,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  276,  277,   -1,  467,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  301,  302,   -1,   -1,   -1,
  125,  307,  308,  309,  310,  311,  312,   -1,   -1,  315,
  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  125,   -1,   -1,   -1,   -1,   -1,  433,  434,  435,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,   -1,
   -1,  467,   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,
   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,  395,
  396,  397,  398,  399,  400,  401,  402,   -1,  404,   -1,
  406,  407,  408,  409,  410,   -1,  412,  413,  414,   -1,
   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,
  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,
   -1,   -1,  438,  439,   -1,   -1,   -1,  443,   -1,   -1,
   -1,   -1,  448,  268,   -1,   -1,  452,  453,  454,  455,
  456,  457,  458,  257,  258,  259,  260,  261,   -1,   -1,
  466,   -1,  468,  469,  268,   -1,   -1,   -1,  293,   -1,
   -1,   -1,  276,  277,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  307,  308,   -1,   -1,  290,  291,   -1,  293,
  125,   -1,  317,   -1,   -1,   -1,   -1,  301,  302,   -1,
   -1,   -1,   -1,  307,  308,  309,  310,  311,  312,   -1,
   -1,  315,  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  372,   -1,   -1,
   -1,   -1,   -1,  378,  379,  359,   -1,  361,   -1,  363,
   -1,   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,
   -1,   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,
  394,  395,  396,  397,  398,  399,  400,  401,  402,   -1,
  404,   -1,  406,  407,  408,  409,  410,   -1,  412,  413,
  414,   -1,   -1,  417,  439,  419,  420,  421,  443,   -1,
   -1,   -1,  426,  448,   -1,   -1,   -1,   -1,  432,   -1,
   -1,   -1,   -1,  268,  438,  439,   -1,   -1,   -1,  443,
   -1,  276,  277,   -1,  448,   -1,   -1,   -1,   -1,  453,
  454,  455,  456,  457,  458,  290,  291,   -1,  293,  125,
   -1,   -1,  466,   -1,  468,  469,  301,  302,   -1,   -1,
   -1,   -1,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,
   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,
  395,  396,  397,  398,  399,  400,  401,  402,   -1,  404,
   -1,  406,  407,  408,  409,  410,   -1,  412,  413,  414,
   -1,   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,
   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,   -1,
   -1,   -1,  268,  438,  439,   -1,   -1,   -1,  443,   -1,
  276,  277,   -1,  448,   -1,   -1,   -1,  452,  453,  454,
  455,  456,  457,  458,  290,  291,   -1,   -1,  125,   -1,
   -1,  466,   -1,  468,  469,  301,  302,   -1,   -1,   -1,
   -1,  307,  308,  309,  310,  311,  312,   -1,   -1,  315,
  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,   -1,
   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,
   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,  395,
  396,  397,  398,  399,  400,  401,  402,   -1,  404,   -1,
  406,  407,  408,  409,  410,   -1,  412,  413,  414,   -1,
   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,
  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,
   -1,  268,  438,  439,   -1,   -1,   -1,  443,   -1,  276,
  277,   -1,  448,   -1,   -1,   -1,  452,  453,  454,  455,
  456,  457,  458,  290,  291,   -1,  293,  125,   -1,   -1,
  466,   -1,  468,  469,  301,  302,   -1,   -1,   -1,   -1,
  307,  308,  309,  310,  311,  312,   -1,   -1,  315,  316,
  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  359,   -1,  361,   -1,  363,   -1,   -1,   -1,
   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,
   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  388,  389,  390,  391,  392,   -1,  394,  395,  396,
  397,  398,  399,  400,  401,  402,   -1,  404,   -1,  406,
  407,  408,  409,  410,   -1,  412,  413,  414,   -1,   -1,
  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,
   -1,   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,
  268,  438,  439,   -1,   -1,   -1,  443,   -1,  276,  277,
   -1,  448,   -1,   -1,   -1,   -1,  453,  454,  455,  456,
  457,  458,  290,  291,   -1,   -1,  125,   -1,   -1,  466,
   -1,  468,  469,  301,  302,   -1,   -1,   -1,   -1,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,
  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  388,  389,  390,  391,  392,   -1,  394,  395,  396,  397,
  398,  399,  400,  401,  402,   -1,  404,   -1,  406,  407,
  408,  409,  410,   -1,  412,  413,  414,   -1,   -1,  417,
   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,
   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,  268,
  438,  439,   -1,   -1,   -1,  443,   -1,  276,  277,   -1,
  448,   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,
  458,  290,  291,   -1,   -1,  125,   -1,   -1,  466,   -1,
  468,  469,  301,  302,   -1,   -1,   -1,   -1,  307,  308,
  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,
   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,
  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,
  389,  390,  391,  392,   -1,  394,  395,  396,  397,  398,
  399,  400,  401,  402,   -1,  404,   -1,  406,  407,  408,
  409,  410,   -1,  412,  413,  414,   -1,   -1,  417,   -1,
  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,
   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,  268,  438,
  439,   -1,   -1,   -1,  443,   -1,  276,  277,   -1,  448,
   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,  458,
  290,  291,   -1,   -1,  125,   -1,   -1,  466,   -1,  468,
  469,  301,  302,   -1,   -1,   -1,   -1,  307,  308,  309,
  310,  311,  312,   -1,   -1,  315,  316,   -1,   -1,   -1,
   -1,   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  359,
  360,  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,   -1,
  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,  379,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,  389,
  390,  391,  392,   -1,  394,  395,  396,  397,  398,  399,
  400,  401,  402,   -1,  404,   -1,  406,  407,  408,  409,
  410,   -1,  412,  413,  414,   -1,   -1,  417,   -1,  419,
  420,  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,   -1,
   -1,   -1,  432,   -1,   -1,   -1,   -1,  268,  438,  439,
   -1,   -1,   -1,  443,   -1,  276,  277,   -1,  448,   -1,
   -1,   -1,  452,  453,  454,  455,  456,  457,  458,  290,
  291,   -1,  293,   -1,   -1,  268,  466,   -1,  468,  469,
  301,  302,   -1,  276,  277,   -1,  307,  308,  309,  310,
  311,  312,   -1,   -1,  315,  316,  317,  290,  291,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  301,  302,
   -1,   -1,   -1,   -1,  307,  308,  309,  310,  311,  312,
   -1,   -1,  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  359,  360,
   -1,   -1,  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,
   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,  379,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  359,  360,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,
   -1,   -1,   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  432,   -1,   -1,   -1,   -1,   -1,  438,  439,   -1,
   -1,   -1,  443,   -1,   -1,   -1,   -1,  448,   -1,   -1,
   -1,  452,  453,  454,  455,  456,  457,  458,   -1,  432,
   -1,   -1,   -1,   -1,   -1,  438,  439,  468,  469,   -1,
   -1,   -1,   -1,   -1,   -1,  448,   -1,   -1,   -1,  452,
  453,  454,  455,  456,  457,  458,   -1,   -1,  273,   -1,
   -1,  276,  277,  278,   -1,  468,  469,  282,  283,  284,
  285,   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,
   -1,  296,  297,  298,   -1,   -1,   -1,   -1,   -1,   -1,
  305,  306,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  276,  277,  329,  330,   -1,  332,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  290,  291,  343,   -1,
   -1,   -1,   -1,  348,  349,  350,   -1,  301,  302,  354,
   -1,   -1,   -1,  307,  308,  309,  310,  311,  312,   -1,
   -1,  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  359,   -1,  361,   -1,  363,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  372,   -1,
   -1,   -1,   -1,   -1,  378,  379,   -1,   -1,  433,  434,
  435,   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,
  394,  395,  396,  397,  398,  399,  400,  401,  402,   -1,
  404,   -1,  406,  407,  408,  409,  410,   -1,  412,  413,
  414,   -1,  467,  417,   -1,  419,  420,  421,   -1,   -1,
   -1,   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,
   -1,   -1,   -1,   -1,  438,  439,   -1,   -1,   -1,  443,
   -1,   -1,   -1,   -1,  448,   -1,   -1,   -1,   -1,  453,
  454,  455,  456,  457,  458,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  466,   -1,  468,  469,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 473
#if YYDEBUG
const char * const socks_yyname[] =
	{
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,"'-'","'.'","'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"ALARM",
"ALARMTYPE_DATA","ALARMTYPE_DISCONNECT","ALARMIF_INTERNAL","ALARMIF_EXTERNAL",
"TCPOPTION_DISABLED","ECN","SACK","TIMESTAMPS","WSCALE","MTU_ERROR",
"CLIENTCOMPATIBILITY","NECGSSAPI","CLIENTRULE","HOSTIDRULE","SOCKSRULE",
"COMPATIBILITY","SAMEPORT","DRAFT_5_05","CONNECTTIMEOUT","TCP_FIN_WAIT","CPU",
"MASK","SCHEDULE","CPUMASK_ANYCPU","DEBUGGING","DEPRECATED","ERRORLOG",
"LOGOUTPUT","LOGFILE","LOGTYPE_ERROR","LOGTYPE_TCP_DISABLED",
"LOGTYPE_TCP_ENABLED","LOGIF_INTERNAL","LOGIF_EXTERNAL","ERRORVALUE",
"EXTENSION","BIND","PRIVILEGED","EXTERNAL_PROTOCOL","INTERNAL_PROTOCOL",
"EXTERNAL_ROTATION","SAMESAME","GROUPNAME","HOSTID","HOSTINDEX","INTERFACE",
"SOCKETOPTION_SYMBOLICVALUE","INTERNAL","EXTERNAL","INTERNALSOCKET",
"EXTERNALSOCKET","IOTIMEOUT","IOTIMEOUT_TCP","IOTIMEOUT_UDP","NEGOTIATETIMEOUT",
"LIBWRAP_FILE","LOGLEVEL","SOCKSMETHOD","CLIENTMETHOD","METHOD","METHODNAME",
"NONE","BSDAUTH","GSSAPI","PAM_ADDRESS","PAM_ANY","PAM_USERNAME","RFC931",
"UNAME","MONITOR","PROCESSTYPE","PROC_MAXREQUESTS","REALM","REALNAME",
"RESOLVEPROTOCOL","REQUIRED","SCHEDULEPOLICY","SERVERCONFIG","CLIENTCONFIG",
"SOCKET","CLIENTSIDE_SOCKET","SNDBUF","RCVBUF","SOCKETPROTOCOL",
"SOCKETOPTION_OPTID","SRCHOST","NODNSMISMATCH","NODNSUNKNOWN","CHECKREPLYAUTH",
"USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","WORD__IN",
"ROUTE","VIA","GLOBALROUTEOPTION","BADROUTE_EXPIRE","MAXFAIL","PORT","NUMBER",
"BANDWIDTH","BOUNCE","BSDAUTHSTYLE","BSDAUTHSTYLENAME","COMMAND","COMMAND_BIND",
"COMMAND_CONNECT","COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","COMMAND_UDPREPLY",
"ACTION","FROM","TO","GSSAPIENCTYPE","GSSAPIENC_ANY","GSSAPIENC_CLEAR",
"GSSAPIENC_INTEGRITY","GSSAPIENC_CONFIDENTIALITY","GSSAPIENC_PERMESSAGE",
"GSSAPIKEYTAB","GSSAPISERVICE","GSSAPISERVICENAME","GSSAPIKEYTABNAME","IPV4",
"IPV6","IPVANY","DOMAINNAME","IFNAME","URL","LDAPATTRIBUTE","LDAPATTRIBUTE_AD",
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
const char * const socks_yyrule[] =
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
"serveroption : external_protocol",
"serveroption : external_rotation",
"serveroption : external_if_logoption",
"serveroption : global_clientmethod",
"serveroption : global_socksmethod",
"serveroption : global_routeoption",
"serveroption : internal",
"serveroption : internal_protocol",
"serveroption : internal_if_logoption",
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
"logspecial : LOGTYPE_ERROR ':' errors",
"$$2 :",
"logspecial : LOGTYPE_TCP_DISABLED ':' $$2 tcpoptions",
"$$3 :",
"logspecial : LOGTYPE_TCP_ENABLED ':' $$3 tcpoptions",
"$$4 :",
"internal_if_logoption : LOGIF_INTERNAL $$4 '.' loglevel '.' logspecial",
"$$5 :",
"external_if_logoption : LOGIF_EXTERNAL $$5 '.' loglevel '.' logspecial",
"$$6 :",
"rule_internal_logoption : LOGIF_INTERNAL $$6 '.' loglevel '.' logspecial",
"$$7 :",
"rule_external_logoption : LOGIF_EXTERNAL $$7 '.' loglevel '.' logspecial",
"loglevel : LOGLEVEL",
"tcpoptions : tcpoption",
"tcpoptions : tcpoption tcpoptions",
"tcpoption : ECN",
"tcpoption : SACK",
"tcpoption : TIMESTAMPS",
"tcpoption : WSCALE",
"errors : errorobject",
"errors : errorobject errors",
"errorobject : ERRORVALUE",
"timeout : connecttimeout",
"timeout : iotimeout",
"timeout : negotiatetimeout",
"timeout : tcp_fin_timeout",
"deprecated : DEPRECATED",
"$$8 :",
"$$9 :",
"route : ROUTE $$8 '{' $$9 routeoptions fromto gateway routeoptions '}'",
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
"ifprotocols : ifprotocol",
"ifprotocols : ifprotocol ifprotocols",
"ifprotocol : IPV4",
"ifprotocol : IPV6",
"internal : INTERNAL internalinit ':' address",
"internalinit :",
"$$10 :",
"internal_protocol : INTERNAL_PROTOCOL ':' $$10 ifprotocols",
"external : EXTERNAL externalinit ':' externaladdress",
"externalinit :",
"$$11 :",
"external_protocol : EXTERNAL_PROTOCOL ':' $$11 ifprotocols",
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
"$$12 :",
"errorlog : ERRORLOG ':' $$12 logoutputdevices",
"$$13 :",
"logoutput : LOGOUTPUT ':' $$13 logoutputdevices",
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
"$$14 :",
"socketoption : socketside SOCKETPROTOCOL '.' $$14 socketoptionname ':' socketoptionvalue",
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
"$$15 :",
"global_clientmethod : CLIENTMETHOD ':' $$15 clientmethods",
"$$16 :",
"global_socksmethod : SOCKSMETHOD ':' $$16 socksmethods",
"socksmethod : SOCKSMETHOD ':' socksmethods",
"socksmethods : socksmethodname",
"socksmethods : socksmethodname socksmethods",
"socksmethodname : METHODNAME",
"clientmethod : CLIENTMETHOD ':' clientmethods",
"clientmethods : clientmethodname",
"clientmethods : clientmethodname clientmethods",
"clientmethodname : METHODNAME",
"$$17 :",
"$$18 :",
"monitor : MONITOR $$17 '{' $$18 monitoroptions fromto monitoroptions '}'",
"$$19 :",
"crule : CLIENTRULE $$19 verdict '{' cruleoptions fromto cruleoptions '}'",
"alarm : alarm_data",
"alarm : alarm_disconnect",
"alarm : alarm_test",
"monitorside :",
"monitorside : ALARMIF_INTERNAL",
"monitorside : ALARMIF_EXTERNAL",
"alarmside :",
"alarmside : RECVSIDE",
"alarmside : SENDSIDE",
"$$20 :",
"alarm_data : monitorside ALARMTYPE_DATA $$20 alarmside ':' NUMBER WORD__IN NUMBER",
"alarm_test : monitorside ALARM '.' networkproblem",
"networkproblem : MTU_ERROR",
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
"$$21 :",
"hrule : HOSTIDRULE $$21 verdict '{' cruleoptions hostid_fromto cruleoptions '}'",
"cruleoptions :",
"cruleoptions : cruleoption cruleoptions",
"hostidoption : hostid",
"hostidoption : hostindex",
"$$22 :",
"hostid : HOSTID ':' $$22 address_without_port",
"hostindex : HOSTINDEX ':' NUMBER",
"$$23 :",
"srule : SOCKSRULE $$23 verdict '{' sruleoptions fromto sruleoptions '}'",
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
"genericruleoption : rule_external_logoption",
"genericruleoption : group",
"genericruleoption : gssapienctype",
"genericruleoption : gssapikeytab",
"genericruleoption : gssapiservicename",
"genericruleoption : hostidoption",
"genericruleoption : rule_internal_logoption",
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
"$$24 :",
"sessionstate_keyinfo : SESSIONSTATE_KEY '.' $$24 hostindex",
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
unsigned int yystacksize;
int yyparse(void);
#line 3072 "config_parse.y"

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
#line 3427 "config_parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    unsigned int newsize;
    long sslen;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    sslen = yyssp - yyss;
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
    yyssp = newss + sslen;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
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
yyparse(void)
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

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
#if defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(__GNUC__)
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
#line 617 "config_parse.y"
{
#if !SOCKS_CLIENT
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
break;
case 4:
#line 625 "config_parse.y"
{ yyval.string = NULL; }
break;
case 11:
#line 636 "config_parse.y"
{ yyval.string = NULL; }
break;
case 39:
#line 665 "config_parse.y"
{
      if (!addedsocketoption(&sockscf.socketoptionc,
                             &sockscf.socketoptionv,
                             &socketopt))
         yywarn("could not add socket option");
   }
break;
case 41:
#line 674 "config_parse.y"
{
#if !SOCKS_CLIENT
                                tcpoptions = &logspecial->protocol.tcp.disabled;
#endif /* !SOCKS_CLIENT */
          }
break;
case 43:
#line 679 "config_parse.y"
{
#if !SOCKS_CLIENT
                                tcpoptions = &logspecial->protocol.tcp.enabled;
#endif /* !SOCKS_CLIENT */
          }
break;
case 45:
#line 687 "config_parse.y"
{
#if !SOCKS_CLIENT

      logspecial = &sockscf.internal.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 47:
#line 697 "config_parse.y"
{
#if !SOCKS_CLIENT

      logspecial = &sockscf.external.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 49:
#line 707 "config_parse.y"
{
#if !SOCKS_CLIENT

      logspecial = &rule.internal.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 51:
#line 717 "config_parse.y"
{
#if !SOCKS_CLIENT

      logspecial = &rule.external.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 53:
#line 728 "config_parse.y"
{
#if !SOCKS_CLIENT
   SASSERTX(yyvsp[0].number >= 0);
   SASSERTX(yyvsp[0].number < MAXLOGLEVELS);

   cloglevel = yyvsp[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 56:
#line 742 "config_parse.y"
{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, ecn);
#endif /* !SOCKS_CLIENT */
   }
break;
case 57:
#line 749 "config_parse.y"
{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, sack);
#endif /* !SOCKS_CLIENT */
   }
break;
case 58:
#line 756 "config_parse.y"
{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, timestamps);
#endif /* !SOCKS_CLIENT */
   }
break;
case 59:
#line 763 "config_parse.y"
{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, wscale);
#endif /* !SOCKS_CLIENT */
   }
break;
case 62:
#line 776 "config_parse.y"
{
#if !SOCKS_CLIENT

   if (yyvsp[0].error.valuev == NULL)
      yywarnx("unknown error symbol specified");
   else {
      size_t *ec, ec_max, i;
      int *ev;

      switch (yyvsp[0].error.valuetype) {
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
case 67:
#line 834 "config_parse.y"
{
      yyerrorx("given keyword \"%s\" is deprecated.  New keyword is %s.  "
               "Please see %s's manual for more information",
               yyvsp[0].deprecated.oldname, yyvsp[0].deprecated.newname, PRODUCT);
   }
break;
case 68:
#line 841 "config_parse.y"
{ objecttype = object_route; }
break;
case 69:
#line 842 "config_parse.y"
{ routeinit(&route); }
break;
case 70:
#line 842 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;

      route.rdr_from  = rdr_from;

      socks_addroute(&route, 1);
   }
break;
case 71:
#line 853 "config_parse.y"
{ yyval.string = NULL; }
break;
case 74:
#line 859 "config_parse.y"
{
         state->proxyprotocol.socks_v4 = 1;
   }
break;
case 75:
#line 862 "config_parse.y"
{
         state->proxyprotocol.socks_v5 = 1;
   }
break;
case 76:
#line 865 "config_parse.y"
{
         state->proxyprotocol.http     = 1;
   }
break;
case 77:
#line 868 "config_parse.y"
{
         state->proxyprotocol.upnp     = 1;
   }
break;
case 82:
#line 881 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 86:
#line 896 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 90:
#line 911 "config_parse.y"
{
         yywarnx("we are currently considering deprecating the Dante-specific "
                 "SOCKS bind extension.  If you are using it, please let us "
                 "know on the public dante-misc@inet.no mailinglist");

         extension->bind = 1;
   }
break;
case 95:
#line 929 "config_parse.y"
{
#if !SOCKS_CLIENT
      ifproto->ipv4  = 1;
   }
break;
case 96:
#line 933 "config_parse.y"
{
      ifproto->ipv6  = 1;
#endif /* SOCKS_SERVER */
   }
break;
case 97:
#line 939 "config_parse.y"
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
break;
case 98:
#line 964 "config_parse.y"
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
break;
case 99:
#line 988 "config_parse.y"
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
break;
case 101:
#line 1013 "config_parse.y"
{
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
break;
case 102:
#line 1020 "config_parse.y"
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
break;
case 103:
#line 1042 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (sockscf.external.addrc > 0) {
         log_interfaceprotocol_set_too_late(EXTERNALIF);
         sockdexit(EXIT_FAILURE);
      }

      ifproto = &sockscf.external.protocol;
#endif /* !SOCKS_CLIENT */
   }
break;
case 105:
#line 1055 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 106:
#line 1059 "config_parse.y"
{
      sockscf.external.rotation = ROTATION_SAMESAME;
   }
break;
case 107:
#line 1062 "config_parse.y"
{
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* SOCKS_SERVER */
   }
break;
case 115:
#line 1077 "config_parse.y"
{ yyval.string = NULL; }
break;
case 117:
#line 1081 "config_parse.y"
{
      if (yyvsp[0].number < 0)
         yyerrorx("max route fails can not be negative (%ld)  Use \"0\" to "
                  "indicate routes should never be marked as bad",
                  (long)yyvsp[0].number);

      sockscf.routeoptions.maxfail = yyvsp[0].number;
   }
break;
case 118:
#line 1089 "config_parse.y"
{
      if (yyvsp[0].number < 0)
         yyerrorx("route failure expiry time can not be negative (%ld).  "
                  "Use \"0\" to indicate bad route marking should never expire",
                  (long)yyvsp[0].number);

      sockscf.routeoptions.badexpire = yyvsp[0].number;
   }
break;
case 119:
#line 1099 "config_parse.y"
{ add_to_errlog = 1; }
break;
case 121:
#line 1102 "config_parse.y"
{ add_to_errlog = 0; }
break;
case 123:
#line 1105 "config_parse.y"
{
   int p;

   if ((add_to_errlog && failed_to_add_errlog)
   ||      (!add_to_errlog && failed_to_add_log)) {
      yywarnx("not adding logfile \"%s\"", yyvsp[0].string);

      slog(LOG_ALERT,
           "%s: not trying to add logfile \"%s\" due to having already failed "
           "adding logfiles during this SIGHUP.  Only if all logfiles "
           "specified in the config can be added will we switch to using "
           "the new logfiles.  Until then, we will continue using only the "
           "old logfiles",
           function, yyvsp[0].string);
   }
   else {
      p = socks_addlogfile(add_to_errlog ? &sockscf.errlog : &sockscf.log, yyvsp[0].string);

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
                 function, yyvsp[0].string, add_to_errlog ? "errlog" : "logoutput");
         }
      }

      if (p == -1)
         slog(LOG_ALERT, "%s: could not (re)open logfile \"%s\": %s%s  %s",
              function,
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
case 126:
#line 1166 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, sockscf.child.maxrequests, 0);
#endif /* !SOCKS_CLIENT */
   }
break;
case 130:
#line 1178 "config_parse.y"
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
case 131:
#line 1191 "config_parse.y"
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
case 132:
#line 1204 "config_parse.y"
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
case 133:
#line 1223 "config_parse.y"
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
case 134:
#line 1239 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->tcpio, 1);
      timeout->udpio = timeout->tcpio;
   }
break;
case 135:
#line 1244 "config_parse.y"
{
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->tcpio, 1);
   }
break;
case 136:
#line 1247 "config_parse.y"
{
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->udpio, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 137:
#line 1253 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->negotiate, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 138:
#line 1260 "config_parse.y"
{
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->connect, 1);
   }
break;
case 139:
#line 1265 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, timeout->tcp_fin_wait, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 140:
#line 1273 "config_parse.y"
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
case 143:
#line 1297 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_allow_table  = strdup(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "%s: libwrap.allow: %s", function, hosts_allow_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 144:
#line 1311 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_deny_table  = strdup(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "%s: libwrap.deny: %s", function, hosts_deny_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 145:
#line 1325 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerrorx("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
break;
case 146:
#line 1333 "config_parse.y"
{
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 147:
#line 1343 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
break;
case 148:
#line 1347 "config_parse.y"
{
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 150:
#line 1357 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
break;
case 151:
#line 1361 "config_parse.y"
{
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 155:
#line 1374 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 156:
#line 1377 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerrorx("resolveprotocol keyword not supported on this system");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 157:
#line 1384 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 160:
#line 1393 "config_parse.y"
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
case 161:
#line 1435 "config_parse.y"
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
case 162:
#line 1496 "config_parse.y"
{
#if !SOCKS_CLIENT
      socketopt.level = yyvsp[-1].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 164:
#line 1503 "config_parse.y"
{
#if !SOCKS_CLIENT
   socketopt.optname = yyvsp[0].number;
   socketopt.info    = optval2sockopt(socketopt.level, socketopt.optname);

   if (socketopt.info == NULL)
      slog(LOG_DEBUG,
           "%s: unknown/unsupported socket option: level %d, value %d",
           function, socketopt.level, socketopt.optname);
   else
      socketoptioncheck(&socketopt);
   }
break;
case 165:
#line 1515 "config_parse.y"
{
      socketopt.info           = optid2sockopt((size_t)yyvsp[0].number);
      SASSERTX(socketopt.info != NULL);

      socketopt.optname        = socketopt.info->value;

      socketoptioncheck(&socketopt);
#endif /* !SOCKS_CLIENT */
   }
break;
case 166:
#line 1526 "config_parse.y"
{
      socketopt.optval.int_val = (int)yyvsp[0].number;
      socketopt.opttype        = int_val;
   }
break;
case 167:
#line 1530 "config_parse.y"
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
case 168:
#line 1547 "config_parse.y"
{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 1;
   }
break;
case 169:
#line 1550 "config_parse.y"
{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 0;
   }
break;
case 171:
#line 1559 "config_parse.y"
{
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
break;
case 172:
#line 1563 "config_parse.y"
{
         sockscf.srchost.nodnsunknown = 1;
   }
break;
case 173:
#line 1566 "config_parse.y"
{
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 176:
#line 1576 "config_parse.y"
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
case 177:
#line 1588 "config_parse.y"
{
#if !SOCKS_CLIENT

   cmethodv  = sockscf.cmethodv;
   cmethodc  = &sockscf.cmethodc;
  *cmethodc  = 0; /* reset. */

#endif /* !SOCKS_CLIENT */
   }
break;
case 179:
#line 1599 "config_parse.y"
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
case 184:
#line 1621 "config_parse.y"
{
      if (methodisvalid(yyvsp[0].method, object_srule))
         ADDMETHOD(yyvsp[0].method, *smethodc, smethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for socksmethods",
                  method2string(yyvsp[0].method), yyvsp[0].method);
   }
break;
case 188:
#line 1638 "config_parse.y"
{
      if (methodisvalid(yyvsp[0].method, object_crule))
         ADDMETHOD(yyvsp[0].method, *cmethodc, cmethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for clientmethods",
                  method2string(yyvsp[0].method), yyvsp[0].method);
   }
break;
case 189:
#line 1646 "config_parse.y"
{ objecttype = object_monitor; }
break;
case 190:
#line 1646 "config_parse.y"
{
#if !SOCKS_CLIENT
                        monitorinit(&monitor);
#endif /* !SOCKS_CLIENT */
}
break;
case 191:
#line 1651 "config_parse.y"
{
#if !SOCKS_CLIENT
   pre_addmonitor(&monitor);

   addmonitor(&monitor);
#endif /* !SOCKS_CLIENT */
}
break;
case 192:
#line 1663 "config_parse.y"
{ objecttype = object_crule; }
break;
case 193:
#line 1664 "config_parse.y"
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
case 197:
#line 1697 "config_parse.y"
{
#if !SOCKS_CLIENT
         monitorif = NULL;
   }
break;
case 198:
#line 1701 "config_parse.y"
{
         monitorif = &monitor.mstats->object.monitor.internal;
   }
break;
case 199:
#line 1704 "config_parse.y"
{
         monitorif = &monitor.mstats->object.monitor.external;
#endif /* !SOCKS_CLIENT */
   }
break;
case 200:
#line 1710 "config_parse.y"
{
#if !SOCKS_CLIENT
      alarmside = NULL;
   }
break;
case 201:
#line 1714 "config_parse.y"
{
      *alarmside = RECVSIDE;
   }
break;
case 202:
#line 1717 "config_parse.y"
{
      *alarmside = SENDSIDE;
#endif /* !SOCKS_CLIENT */
   }
break;
case 203:
#line 1723 "config_parse.y"
{ alarminit(); }
break;
case 204:
#line 1724 "config_parse.y"
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
case 206:
#line 1788 "config_parse.y"
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
break;
case 207:
#line 1806 "config_parse.y"
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
case 208:
#line 1837 "config_parse.y"
{
#if !SOCKS_CLIENT
               yyval.number = DEFAULT_ALARM_PERIOD;
#endif /* !SOCKS_CLIENT */
   }
break;
case 209:
#line 1842 "config_parse.y"
{ yyval.number = yyvsp[0].number; }
break;
case 212:
#line 1847 "config_parse.y"
{ *hostidoption_isset = 1; }
break;
case 214:
#line 1851 "config_parse.y"
{ yyval.string = NULL; }
break;
case 216:
#line 1855 "config_parse.y"
{
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 217:
#line 1860 "config_parse.y"
{
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 219:
#line 1866 "config_parse.y"
{
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 221:
#line 1874 "config_parse.y"
{

#if SOCKS_CLIENT || !HAVE_SOCKS_HOSTID
      yyerrorx("hostid is not supported on this system");
#endif /* SOCKS_CLIENT || !HAVE_SOCKS_HOSTID */

      objecttype = object_hrule;
}
break;
case 222:
#line 1881 "config_parse.y"
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
break;
case 223:
#line 1899 "config_parse.y"
{ yyval.string = NULL; }
break;
case 227:
#line 1907 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      addrinit(&hostid, 1);

#else /* HAVE_SOCKS_HOSTID */
      yyerrorx("hostid is not supported on this system");
#endif /* HAVE_SOCKS_HOSTID */

   }
break;
case 229:
#line 1918 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
   ASSIGN_NUMBER(yyvsp[0].number, >=, 0, *hostindex, 0);
   ASSIGN_NUMBER(yyvsp[0].number, <=, HAVE_MAX_HOSTIDS, *hostindex, 0);

#else
   yyerrorx("hostid is not supported on this system");
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
}
break;
case 230:
#line 1930 "config_parse.y"
{ objecttype = object_srule; }
break;
case 231:
#line 1931 "config_parse.y"
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
case 232:
#line 1945 "config_parse.y"
{ yyval.string = NULL; }
break;
case 240:
#line 1956 "config_parse.y"
{
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 242:
#line 1965 "config_parse.y"
{
#if !SOCKS_CLIENT
                        checkmodule("bandwidth");
                        bw_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 250:
#line 1978 "config_parse.y"
{ *hostidoption_isset = 1; }
break;
case 255:
#line 1983 "config_parse.y"
{
#if !SOCKS_CLIENT
                     checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
break;
case 256:
#line 1988 "config_parse.y"
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
case 287:
#line 2048 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->debug = (int)yyvsp[0].number;
   }
break;
case 288:
#line 2053 "config_parse.y"
{
      ldap->debug = (int)-yyvsp[0].number;
 #else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 289:
#line 2062 "config_parse.y"
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
case 290:
#line 2076 "config_parse.y"
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
case 291:
#line 2087 "config_parse.y"
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
case 292:
#line 2101 "config_parse.y"
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
case 293:
#line 2115 "config_parse.y"
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
case 294:
#line 2127 "config_parse.y"
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
case 295:
#line 2139 "config_parse.y"
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
case 296:
#line 2151 "config_parse.y"
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
case 297:
#line 2163 "config_parse.y"
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
case 298:
#line 2174 "config_parse.y"
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
case 299:
#line 2185 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->ssl = 1;
   }
break;
case 300:
#line 2190 "config_parse.y"
{
      ldap->ssl = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 301:
#line 2199 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->auto_off = 1;
   }
break;
case 302:
#line 2204 "config_parse.y"
{
      ldap->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 303:
#line 2213 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->certcheck = 1;
   }
break;
case 304:
#line 2218 "config_parse.y"
{
      ldap->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 305:
#line 2227 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->keeprealm = 1;
   }
break;
case 306:
#line 2232 "config_parse.y"
{
      ldap->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 307:
#line 2241 "config_parse.y"
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
case 308:
#line 2252 "config_parse.y"
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
case 309:
#line 2267 "config_parse.y"
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
case 310:
#line 2281 "config_parse.y"
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
case 311:
#line 2295 "config_parse.y"
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
case 312:
#line 2310 "config_parse.y"
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
case 313:
#line 2324 "config_parse.y"
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
case 314:
#line 2338 "config_parse.y"
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
case 315:
#line 2352 "config_parse.y"
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
case 316:
#line 2364 "config_parse.y"
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
case 317:
#line 2378 "config_parse.y"
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
case 318:
#line 2392 "config_parse.y"
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
case 319:
#line 2404 "config_parse.y"
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
case 321:
#line 2422 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 324:
#line 2436 "config_parse.y"
{
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 325:
#line 2441 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
   }
break;
case 329:
#line 2455 "config_parse.y"
{
         state->command.bind = 1;
   }
break;
case 330:
#line 2458 "config_parse.y"
{
         state->command.connect = 1;
   }
break;
case 331:
#line 2461 "config_parse.y"
{
         state->command.udpassociate = 1;
   }
break;
case 332:
#line 2467 "config_parse.y"
{
         state->command.bindreply = 1;
   }
break;
case 333:
#line 2471 "config_parse.y"
{
         state->command.udpreply = 1;
   }
break;
case 337:
#line 2484 "config_parse.y"
{
      state->protocol.tcp = 1;
   }
break;
case 338:
#line 2487 "config_parse.y"
{
      state->protocol.udp = 1;
   }
break;
case 350:
#line 2516 "config_parse.y"
{
#if !SOCKS_CLIENT
                        rule.ss_isinheritable = 1;
   }
break;
case 351:
#line 2520 "config_parse.y"
{
                        rule.ss_isinheritable = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 352:
#line 2526 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS(yyvsp[0].number, ss.object.ss.max, 0);
      ss.object.ss.max       = yyvsp[0].number;
      ss.object.ss.max_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 353:
#line 2535 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_THROTTLE_SECONDS(yyvsp[-2].number, ss.object.ss.throttle.limit.clients, 0);
      ASSIGN_THROTTLE_CLIENTS(yyvsp[0].number, ss.object.ss.throttle.limit.seconds, 0);
      ss.object.ss.throttle_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 358:
#line 2550 "config_parse.y"
{
#if !SOCKS_CLIENT
      if ((ss.keystate.key = string2statekey(yyvsp[0].string)) == key_unset)
         yyerrorx("%s is not a valid state key", yyvsp[0].string);

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
break;
case 359:
#line 2578 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      hostindex = &ss.keystate.keyinfo.hostindex;
   }
break;
case 360:
#line 2582 "config_parse.y"
{
      hostindex = &rule.hostindex; /* reset */
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
   }
break;
case 361:
#line 2589 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS(yyvsp[0].number, ss.object.ss.max_perstate, 0);
      ss.object.ss.max_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 362:
#line 2597 "config_parse.y"
{
#if !SOCKS_CLIENT
   ASSIGN_THROTTLE_SECONDS(yyvsp[-2].number, ss.object.ss.throttle_perstate.limit.clients, 0);
   ASSIGN_THROTTLE_CLIENTS(yyvsp[0].number, ss.object.ss.throttle_perstate.limit.seconds, 0);
   ss.object.ss.throttle_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
}
break;
case 363:
#line 2606 "config_parse.y"
{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yyvsp[0].number, >=, 0, bw.object.bw.maxbps, 0);
      bw.object.bw.maxbps_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 365:
#line 2618 "config_parse.y"
{
#if !SOCKS_CLIENT
         rule.log.connect = 1;
   }
break;
case 366:
#line 2622 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 367:
#line 2625 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 368:
#line 2628 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 369:
#line 2631 "config_parse.y"
{
         rule.log.iooperation = 1;
   }
break;
case 370:
#line 2634 "config_parse.y"
{
         rule.log.tcpinfo = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 373:
#line 2645 "config_parse.y"
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
case 374:
#line 2657 "config_parse.y"
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
case 375:
#line 2670 "config_parse.y"
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
case 376:
#line 2682 "config_parse.y"
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
case 378:
#line 2701 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 379:
#line 2707 "config_parse.y"
{
      gssapiencryption->clear = 1;
   }
break;
case 380:
#line 2710 "config_parse.y"
{
      gssapiencryption->integrity = 1;
   }
break;
case 381:
#line 2713 "config_parse.y"
{
      gssapiencryption->confidentiality = 1;
   }
break;
case 382:
#line 2716 "config_parse.y"
{
      yyerrorx("gssapi per-message encryption not supported");
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 386:
#line 2731 "config_parse.y"
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
case 391:
#line 2783 "config_parse.y"
{
#if BAREFOOTD
      yyerrorx("redirecting \"to\" an address does not make any sense in %s.  "
               "Instead specify the address you wanted to \"redirect\" "
               "data to as the \"bounce to\" address, as normal",
               PRODUCT);
#endif /* BAREFOOT */
   }
break;
case 403:
#line 2806 "config_parse.y"
{
               if (!addedsocketoption(&route.socketoptionc,
                                      &route.socketoptionv,
                                      &socketopt))
                  yywarn("could not add socketoption");
   }
break;
case 404:
#line 2814 "config_parse.y"
{ yyval.string = NULL; }
break;
case 407:
#line 2821 "config_parse.y"
{
      addrinit(&src, 1);
   }
break;
case 408:
#line 2826 "config_parse.y"
{
      addrinit(&dst, ipaddr_requires_netmask(to, objecttype));
   }
break;
case 409:
#line 2831 "config_parse.y"
{
      addrinit(&rdr_from, 1);
   }
break;
case 410:
#line 2836 "config_parse.y"
{
      addrinit(&rdr_to, 0);
   }
break;
case 411:
#line 2841 "config_parse.y"
{
#if BAREFOOTD
      addrinit(&bounceto, 0);
#endif /* BAREFOOTD */
   }
break;
case 412:
#line 2849 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 421:
#line 2869 "config_parse.y"
{ if (!netmask_required) yyerrorx_hasnetmask(); }
break;
case 422:
#line 2870 "config_parse.y"
{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 423:
#line 2871 "config_parse.y"
{ if (!netmask_required) yyerrorx_hasnetmask(); }
break;
case 424:
#line 2872 "config_parse.y"
{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 425:
#line 2873 "config_parse.y"
{ if (!netmask_required)
                                       yyerrorx_hasnetmask(); }
break;
case 426:
#line 2875 "config_parse.y"
{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 429:
#line 2879 "config_parse.y"
{ /* for upnp; broadcasts on interface. */ }
break;
case 433:
#line 2888 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (socks_inet_pton(AF_INET, yyvsp[0].string, ipv4, NULL) != 1)
         yyerror("bad %s: %s", atype2string(*atype), yyvsp[0].string);
   }
break;
case 434:
#line 2896 "config_parse.y"
{
      if (yyvsp[0].number < 0 || yyvsp[0].number > 32)
         yyerrorx("bad %s netmask: %ld.  Legal range is 0 - 32",
                  atype2string(*atype), (long)yyvsp[0].number);

      netmask_v4->s_addr = yyvsp[0].number == 0 ? 0 : htonl(IPV4_FULLNETMASK << (32 - yyvsp[0].number));
   }
break;
case 435:
#line 2903 "config_parse.y"
{
      if (socks_inet_pton(AF_INET, yyvsp[0].string, netmask_v4, NULL) != 1)
         yyerror("bad %s netmask: %s", atype2string(*atype), yyvsp[0].string);
   }
break;
case 436:
#line 2909 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV6;

      if (socks_inet_pton(AF_INET6, yyvsp[0].string, ipv6, scopeid_v6) != 1)
         yyerror("bad %s: %s", atype2string(*atype), yyvsp[0].string);
   }
break;
case 437:
#line 2917 "config_parse.y"
{
      if (yyvsp[0].number < 0 || yyvsp[0].number > IPV6_NETMASKBITS)
         yyerrorx("bad %s netmask: %d.  Legal range is 0 - %d",
                  atype2string(*atype), (int)yyvsp[0].number, IPV6_NETMASKBITS);

      *netmask_v6 = yyvsp[0].number;
   }
break;
case 438:
#line 2926 "config_parse.y"
{
      SASSERTX(strcmp(yyvsp[0].string, "0") == 0);

      *atype = SOCKS_ADDR_IPVANY;
      ipvany->s_addr = htonl(0);
   }
break;
case 439:
#line 2934 "config_parse.y"
{
      if (yyvsp[0].number != 0)
         yyerrorx("bad %s netmask: %d.  Only legal value is 0",
                  atype2string(*atype), (int)yyvsp[0].number);

      netmask_vany->s_addr = htonl(yyvsp[0].number);
   }
break;
case 440:
#line 2944 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;
      STRCPY_CHECKLEN(domain, yyvsp[0].string, MAXHOSTNAMELEN - 1, yyerrorx);
   }
break;
case 441:
#line 2950 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;
      STRCPY_CHECKLEN(ifname, yyvsp[0].string, MAXIFNAMELEN - 1, yyerrorx);
   }
break;
case 442:
#line 2957 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;
      STRCPY_CHECKLEN(url, yyvsp[0].string, MAXURLLEN - 1, yyerrorx);
   }
break;
case 443:
#line 2964 "config_parse.y"
{ yyval.number = 0; }
break;
case 447:
#line 2970 "config_parse.y"
{ yyval.number = 0; }
break;
case 451:
#line 2978 "config_parse.y"
{
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerrorx("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
break;
case 452:
#line 2986 "config_parse.y"
{
      ASSIGN_PORTNUMBER(yyvsp[0].number, *port_tcp);
      ASSIGN_PORTNUMBER(yyvsp[0].number, *port_udp);
   }
break;
case 453:
#line 2992 "config_parse.y"
{
      ASSIGN_PORTNUMBER(yyvsp[0].number, ruleaddr->portend);
      ruleaddr->operator   = range;
   }
break;
case 454:
#line 2998 "config_parse.y"
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
case 455:
#line 3033 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 457:
#line 3042 "config_parse.y"
{
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER(yyvsp[0].number, rule.udprange.start);
#endif /* SOCKS_SERVER */
   }
break;
case 458:
#line 3049 "config_parse.y"
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
case 459:
#line 3061 "config_parse.y"
{
      addnumber(&numberc, &numberv, yyvsp[0].number);
   }
break;
#line 6044 "config_parse.c"
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
