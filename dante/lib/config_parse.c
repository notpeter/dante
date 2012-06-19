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

#if 0 /* XXX automatically added at head of generated .c file */
#include "common.h"
#endif
#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.471 2012/06/01 20:23:05 karls Exp $";

#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
   extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

#define CHECKNUMBER(number, op, checkagainst)                                  \
do {                                                                           \
   if (!((number) op (checkagainst)))                                          \
      yyerror("number must be " #op " " #checkagainst " (%ld).  "              \
              "It can not be %ld",                                             \
              (long)(checkagainst), (long)(number));                           \
} while (0)

#define CHECKPORTNUMBER(portnumber)                                            \
do {                                                                           \
      CHECKNUMBER(portnumber, >=, 0);                                          \
      CHECKNUMBER(portnumber, <=, IP_MAXPORT);                                 \
} while (0)

static void
addnumber(size_t *numberc, ssize_t *numberv[], const ssize_t number);

static void
addrinit(ruleaddr_t *addr, const int netmask_required);

static void
gwaddrinit(sockshost_t *addr);

#if SOCKS_CLIENT
static void parseclientenv(int *haveproxyserver);
/*
 * parses client environment, if any.
 * If a proxy server is configured in environment, "haveproxyserver" is set
 * to true upon return.  If not, it is set to false.
 */

static void
addproxyserver(const char *proxyserver,
               const proxyprotocol_t *proxyprotocol);
/*
 * Adds a route for a proxy server with address "proxyserver" to our
 * routes.
 * "proxyprotocol" is the proxy protocols supported by the proxy server.
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
static void ruleinit(rule_t *rule);

#endif /* !SOCKS_CLIENT */

extern int yylineno;
extern char *yytext;

static int             parsingconfig;   /* currently parsing config?          */
static unsigned char   add_to_errorlog; /* adding logfile to errorlog?        */

#if !SOCKS_CLIENT
static rule_t          rule;          /* new rule.                     */
static protocol_t      protocolmem;   /* new protocolmem.              */
#if !HAVE_PRIVILEGES
static userid_t        olduserid;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */

static ssize_t         *numberv;
static size_t          numberc;

static timeout_t       *timeout = &sockscf.timeout;           /* default. */

static socketoption_t  socketopt;
size_t                 socketoptid;

static serverstate_t   state;
static route_t         route;         /* new route.                    */
static sockshost_t     gw;            /* new gateway.                  */

static ruleaddr_t      src;            /* new src.                     */
static ruleaddr_t      dst;            /* new dst.                     */
static ruleaddr_t      hostid;         /* new hostid.                  */
static ruleaddr_t      rdr_from;       /* new redirect from.           */
static ruleaddr_t      rdr_to;         /* new redirect to.             */

#if BAREFOOTD
static ruleaddr_t      bounceto;
#endif /* BAREFOOTD */

static ruleaddr_t      *ruleaddr;      /* current ruleaddr             */
static extension_t     *extension;     /* new extensions               */
static proxyprotocol_t *proxyprotocol; /* proxy protocol.              */

static unsigned char   *atype;         /* atype of new address.        */
static struct in_addr  *ipaddr;        /* new ip address               */
static struct in_addr  *netmask;       /* new netmask                  */
static int             netmask_required;/*
                                                * netmask required for this
                                                * address?
                                                */
static char            *domain;        /* new domain.                  */
static char            *ifname;        /* new ifname.                  */
static char            *url;           /* new url.                     */

static in_port_t       *port_tcp;      /* new TCP port number.         */
static in_port_t       *port_udp;      /* new UDP port number.         */
static int             *methodv;       /* new authmethods.             */
static size_t          *methodc;       /* number of them.              */
static protocol_t      *protocol;      /* new protocol.                */
static command_t       *command;       /* new command.                 */
static enum operator_t *operator;      /* new operator.                */

#if HAVE_GSSAPI
static char            *gssapiservicename; /* new gssapiservice.        */
static char            *gssapikeytab;      /* new gssapikeytab.         */
static gssapi_enc_t    *gssapiencryption;  /* new encryption status.    */
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
static ldap_t          *ldap;        /* new ldap server details.        */
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
                 (long)*methodc, (long)MAXMETHOD);                             \
      methodv[(*methodc)++] = method;                                          \
   }                                                                           \
} while (0)

#line 200 "config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
   char    *string;
   uid_t   uid;
   ssize_t number;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 201 "config_parse.c"
#define CPU 257
#define MASK 258
#define SCHEDULE 259
#define CPUMASK_ANYCPU 260
#define PROCESSTYPE 261
#define SCHEDULEPOLICY 262
#define SERVERCONFIG 263
#define CLIENTCONFIG 264
#define DEPRECATED 265
#define INTERFACE 266
#define SOCKETOPTION_SYMBOLICVALUE 267
#define SOCKETPROTOCOL 268
#define SOCKETOPTION_OPTID 269
#define CLIENTRULE 270
#define HOSTID 271
#define HOSTINDEX 272
#define REQUIRED 273
#define INTERNAL 274
#define EXTERNAL 275
#define INTERNALSOCKET 276
#define EXTERNALSOCKET 277
#define REALM 278
#define REALNAME 279
#define EXTERNAL_ROTATION 280
#define SAMESAME 281
#define DEBUGGING 282
#define RESOLVEPROTOCOL 283
#define SOCKET 284
#define CLIENTSIDE_SOCKET 285
#define SNDBUF 286
#define RCVBUF 287
#define SRCHOST 288
#define NODNSMISMATCH 289
#define NODNSUNKNOWN 290
#define CHECKREPLYAUTH 291
#define EXTENSION 292
#define BIND 293
#define PRIVILEGED 294
#define IOTIMEOUT 295
#define IOTIMEOUT_TCP 296
#define IOTIMEOUT_UDP 297
#define NEGOTIATETIMEOUT 298
#define CONNECTTIMEOUT 299
#define TCP_FIN_WAIT 300
#define METHOD 301
#define CLIENTMETHOD 302
#define NONE 303
#define GSSAPI 304
#define UNAME 305
#define RFC931 306
#define PAM 307
#define BSDAUTH 308
#define COMPATIBILITY 309
#define SAMEPORT 310
#define DRAFT_5_05 311
#define CLIENTCOMPATIBILITY 312
#define NECGSSAPI 313
#define USERNAME 314
#define GROUPNAME 315
#define USER_PRIVILEGED 316
#define USER_UNPRIVILEGED 317
#define USER_LIBWRAP 318
#define LIBWRAP_FILE 319
#define ERRORLOG 320
#define LOGOUTPUT 321
#define LOGFILE 322
#define CHILD_MAXIDLE 323
#define CHILD_MAXREQUESTS 324
#define ROUTE 325
#define VIA 326
#define BADROUTE_EXPIRE 327
#define MAXFAIL 328
#define VERDICT_BLOCK 329
#define VERDICT_PASS 330
#define PAMSERVICENAME 331
#define BSDAUTHSTYLENAME 332
#define BSDAUTHSTYLE 333
#define GSSAPISERVICE 334
#define GSSAPIKEYTAB 335
#define GSSAPIENCTYPE 336
#define GSSAPIENC_ANY 337
#define GSSAPIENC_CLEAR 338
#define GSSAPIENC_INTEGRITY 339
#define GSSAPIENC_CONFIDENTIALITY 340
#define GSSAPIENC_PERMESSAGE 341
#define GSSAPISERVICENAME 342
#define GSSAPIKEYTABNAME 343
#define PROTOCOL 344
#define PROTOCOL_TCP 345
#define PROTOCOL_UDP 346
#define PROTOCOL_FAKE 347
#define PROXYPROTOCOL 348
#define PROXYPROTOCOL_SOCKS_V4 349
#define PROXYPROTOCOL_SOCKS_V5 350
#define PROXYPROTOCOL_HTTP 351
#define PROXYPROTOCOL_UPNP 352
#define USER 353
#define GROUP 354
#define COMMAND 355
#define COMMAND_BIND 356
#define COMMAND_CONNECT 357
#define COMMAND_UDPASSOCIATE 358
#define COMMAND_BINDREPLY 359
#define COMMAND_UDPREPLY 360
#define ACTION 361
#define LINE 362
#define LIBWRAPSTART 363
#define LIBWRAP_ALLOW 364
#define LIBWRAP_DENY 365
#define LIBWRAP_HOSTS_ACCESS 366
#define OPERATOR 367
#define SOCKS_LOG 368
#define SOCKS_LOG_CONNECT 369
#define SOCKS_LOG_DATA 370
#define SOCKS_LOG_DISCONNECT 371
#define SOCKS_LOG_ERROR 372
#define SOCKS_LOG_IOOPERATION 373
#define IPADDRESS 374
#define DOMAINNAME 375
#define DIRECT 376
#define IFNAME 377
#define URL 378
#define SERVICENAME 379
#define PORT 380
#define NUMBER 381
#define FROM 382
#define TO 383
#define REDIRECT 384
#define BANDWIDTH 385
#define MAXSESSIONS 386
#define UDPPORTRANGE 387
#define UDPCONNECTDST 388
#define YES 389
#define NO 390
#define BOUNCE 391
#define LDAPURL 392
#define LDAP_URL 393
#define LDAPSSL 394
#define LDAPCERTCHECK 395
#define LDAPKEEPREALM 396
#define LDAPBASEDN 397
#define LDAP_BASEDN 398
#define LDAPBASEDN_HEX 399
#define LDAPBASEDN_HEX_ALL 400
#define LDAPSERVER 401
#define LDAPSERVER_NAME 402
#define LDAPGROUP 403
#define LDAPGROUP_NAME 404
#define LDAPGROUP_HEX 405
#define LDAPGROUP_HEX_ALL 406
#define LDAPFILTER 407
#define LDAPFILTER_AD 408
#define LDAPFILTER_HEX 409
#define LDAPFILTER_AD_HEX 410
#define LDAPATTRIBUTE 411
#define LDAPATTRIBUTE_AD 412
#define LDAPATTRIBUTE_HEX 413
#define LDAPATTRIBUTE_AD_HEX 414
#define LDAPCERTFILE 415
#define LDAPCERTPATH 416
#define LDAPPORT 417
#define LDAPPORTSSL 418
#define LDAP_FILTER 419
#define LDAP_ATTRIBUTE 420
#define LDAP_CERTFILE 421
#define LDAP_CERTPATH 422
#define LDAPDOMAIN 423
#define LDAP_DOMAIN 424
#define LDAPTIMEOUT 425
#define LDAPCACHE 426
#define LDAPCACHEPOS 427
#define LDAPCACHENEG 428
#define LDAPKEYTAB 429
#define LDAPKEYTABNAME 430
#define LDAPDEADTIME 431
#define LDAPDEBUG 432
#define LDAPDEPTH 433
#define LDAPAUTO 434
#define LDAPSEARCHTIME 435
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   75,    5,   78,   78,   79,   79,   79,   79,
    6,    6,    6,    6,   40,   41,   41,   77,   77,   76,
   76,   76,   76,   76,   76,   76,   76,   76,   76,   76,
   76,   76,   76,   76,   76,   74,   74,   74,   74,   74,
   74,   74,   74,   74,   46,   46,   46,   46,    7,  126,
   26,   20,   21,   21,   21,   21,   21,   22,   22,   37,
   38,   39,   39,    9,   10,   11,   11,   51,   52,   53,
   53,   54,   55,   56,   57,   58,   58,   58,   42,   42,
   42,   42,   42,   42,  125,  125,  170,   59,  171,   60,
   61,   62,   62,   85,   85,   85,   80,   80,   80,   81,
   82,   83,   84,   47,   47,   47,   48,   49,   50,    8,
   90,   90,   91,   92,   93,   93,   94,   94,   63,   64,
   64,   65,   65,   24,   25,   25,   25,   43,   43,   44,
   45,  172,   28,   29,   29,   30,   30,   27,   27,   15,
   15,   15,   15,   15,   15,   31,   32,   32,   32,   33,
   33,   23,   68,   69,   69,  173,   66,  174,   67,   70,
   70,   70,   70,   70,   70,  131,  132,  132,  133,  133,
  134,  135,  135,  175,  137,  136,  138,  139,  139,  139,
  139,  139,  140,  140,  141,  141,  141,  141,  141,  141,
  141,  141,  141,  141,  141,  141,  141,  141,  141,  141,
  141,  141,  141,  141,  141,  141,  141,  141,  141,  141,
  141,  141,  141,  141,  141,  141,  141,  141,  141,  141,
  141,  141,  141,  141,  141,  141,  141,  141,  141,  141,
  119,  119,  110,  120,  115,  116,   95,   99,  100,  101,
  121,  122,   96,   96,  118,  118,   97,   97,   98,   98,
  106,  107,  108,  109,  111,  112,  113,  114,  104,  105,
  103,  102,  117,   71,   72,   73,   73,  142,  142,    2,
    3,    3,    4,    4,    4,    4,    4,   17,   18,   18,
   19,   19,  143,   86,   86,   86,   88,   89,   87,  144,
  146,  146,  146,  146,  146,  145,  145,   16,    1,   14,
   13,   12,  179,  179,  179,  179,  179,  178,  178,  168,
  147,  148,  149,  176,  177,  128,  129,  129,  129,  129,
  129,  129,  129,  129,  129,  129,  130,  130,  158,  159,
  180,  181,  169,  127,  150,  150,  150,  151,  182,  151,
  151,  151,  153,  153,  153,  153,  153,  152,  160,  160,
  154,  155,  156,  157,  162,  162,  162,  162,  163,  163,
  166,  166,  164,  165,  183,  167,  161,   34,   35,   36,
  123,  124,  124,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylen[] =
#else
short socks_yylen[] =
#endif
	{                                         2,
    2,    2,    1,    2,    0,    2,    1,    1,    1,    1,
    0,    2,    2,    2,    1,    1,    1,    1,    2,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    8,
    0,    3,    1,    1,    1,    1,    1,    1,    2,    3,
    1,    1,    2,    3,    1,    1,    2,    3,    1,    1,
    2,    4,    0,    4,    0,    3,    3,    3,    1,    1,
    1,    1,    1,    1,    5,    5,    0,    4,    0,    4,
    1,    1,    2,    3,    3,    3,    1,    1,    1,    3,
    3,    3,    1,    3,    3,    3,    3,    3,    3,    3,
    1,    1,    3,    3,    3,    3,    3,    3,    3,    1,
    1,    1,    2,    3,    1,    1,    1,    1,    1,    9,
    7,    0,    7,    1,    1,    1,    1,    1,    1,    7,
    7,    7,    7,    7,    7,    3,    1,    1,    1,    1,
    2,    3,    3,    1,    2,    0,    4,    0,    4,    1,
    1,    1,    1,    1,    1,    7,    1,    1,    0,    2,
    7,    1,    1,    0,    4,    3,    6,    1,    1,    1,
    1,    1,    0,    2,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    3,    4,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    1,    1,    2,    1,    1,    3,
    1,    2,    1,    1,    1,    1,    1,    3,    1,    2,
    1,    1,    2,    3,    2,    2,    1,    3,    3,    3,
    1,    1,    1,    1,    1,    1,    2,    3,    3,    3,
    3,    3,    1,    1,    1,    1,    1,    1,    2,    4,
    3,    3,    3,    3,    3,    3,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    0,    2,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    4,    0,    3,
    2,    2,    2,    2,    2,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    0,    3,    3,    2,    0,    3,
    1,    1,    3,    1,    1,    1,    1,    5,    1,    1,
    1,    1,    2,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    3,   15,    0,   11,    0,    0,    0,   49,   73,   75,
  138,  139,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    1,   23,   22,   40,   41,   42,    0,   33,   43,
   37,  128,  129,   44,   46,   47,   45,   48,   38,   28,
   25,   26,   24,   31,   36,   20,   27,   32,   18,    0,
   35,   97,   98,   99,   21,   30,  111,  112,   29,   34,
   39,    0,   12,   17,   79,   83,   13,   16,   84,   81,
   82,   80,   14,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  156,  158,    0,    0,    0,    0,   87,   89,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  268,  269,
   19,    4,    0,   10,    7,    8,    9,    0,    0,    0,
    0,    0,    0,  152,   77,   76,   78,  110,  126,  127,
  125,  124,    0,    0,    0,    0,  147,  148,  149,    0,
  146,   69,    0,   68,  104,  105,  106,  107,  108,  109,
    0,    0,  120,  121,    0,  119,  103,  100,  101,  102,
    0,    0,   94,   95,   96,    0,    0,  113,  114,  115,
  116,  117,  118,  132,    0,    0,   51,    6,    0,    0,
    0,    0,  348,  351,  352,   72,    0,    0,    0,   74,
  335,  336,  337,    0,    0,    0,    0,  151,   71,  160,
  161,  162,  163,  164,  165,  157,    0,  159,  123,   91,
    0,   88,   90,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  188,  179,  190,
  191,  192,  193,  225,  181,  182,  227,  180,  230,  229,
  185,  189,  226,  186,  228,  287,  224,  217,  203,  213,
  195,  196,  197,  223,  218,  219,  220,  209,  210,  212,
  211,  208,  198,  199,  201,  200,  204,  205,  214,  202,
  206,  207,  215,  216,  194,  173,  172,    0,    0,  178,
  222,  221,  187,  318,  324,  323,  322,  321,  325,  326,
  320,  317,  319,    0,    0,    0,    0,    0,    0,    0,
  341,  342,    0,    0,    0,    0,    0,    0,  155,   93,
   86,   85,  135,  134,    0,  168,    0,    0,  167,    0,
  174,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  331,  332,    0,  286,
    0,    0,    0,    0,    0,  333,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  184,  329,    0,    0,    0,
  328,    0,    0,    0,  350,  349,    0,  340,  367,  364,
    0,    0,  358,    0,    0,    0,    0,    0,    0,    0,
    0,  170,    0,    0,    0,  176,  153,  265,    0,  264,
  298,  299,  300,  301,  303,  304,  305,  306,  307,  302,
    0,  281,  282,  278,    0,   53,   54,   55,   56,   57,
    0,   52,   61,    0,   60,   65,    0,   64,  273,  274,
  275,  276,  277,  270,    0,  311,  291,  292,  293,  294,
  295,  290,    0,  284,    0,    0,  289,  288,  369,    0,
    0,  237,  243,  244,  247,  248,  249,  250,  238,  239,
  240,  262,  261,  259,  260,  251,  252,  253,  254,  255,
  256,  257,  258,  235,  236,  241,  242,  233,  263,  231,
    0,  234,  245,  246,    0,  330,  283,    0,    0,  334,
    0,    0,  371,    0,  131,    0,  338,  366,  362,  356,
  361,  357,    0,  142,  140,  143,  141,  144,  145,  137,
  136,  133,    0,    0,  175,  267,  309,  280,   59,   63,
   67,  272,  297,  314,  315,    0,  310,  232,  177,    0,
  312,    0,    0,  373,    0,  365,  363,  166,  171,  370,
  368,  313,  353,  354,    0,  316,    0,    0,  347,  346,
   50,  130,    0,  343,  344,  345,    0,  360,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
  288,  289,  504,  505,   42,    6,   43,   44,  290,  497,
  498,  291,  292,  293,   45,  294,  376,  484,  485,  296,
  491,  492,   46,   47,  152,  139,   48,  297,  375,  582,
   50,  160,  161,  298,  520,  611,  299,  494,  495,    4,
   87,   88,   51,   52,   53,  300,   55,   56,   57,   58,
  351,  163,  164,   60,   95,   61,   96,   62,   63,   64,
  231,  232,   65,  175,  176,   66,   67,  301,  226,  227,
  302,  469,  470,   68,    5,   69,   70,  132,  133,   71,
   72,   73,   74,  178,   75,  303,  304,  305,  306,   76,
   77,   78,   79,   80,  307,  308,  309,  310,  311,  312,
  313,  314,  315,  316,  317,  318,  319,  320,  321,  322,
  323,  324,  325,  326,  327,  328,  329,  330,  331,  332,
  333,  334,  564,  565,   81,  134,  561,  562,  354,  355,
  135,  377,  378,  136,  335,  336,  337,  137,  338,  339,
  379,  138,  438,  341,  512,  513,  342,  439,  557,  210,
  206,  207,  616,  208,  209,  619,  620,  440,  558,  447,
  452,  361,  624,  453,  569,  570,  571,  343,  407,  181,
  182,  236,  171,  172,  465,  399,  400,  480,  481,  401,
  402,  359,  607,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -208,
    0,    0,    0,    0, 2700,  948,   21,    0,    0,    0,
    0,    0,  -17,   12,   24,   26,   41,   43,   38,   52,
   56,   74,   83,   90,   92,  104,  118,  123,  130,  131,
  133,  134,  135,  136,  139,  140,  155,  144,  145,  146,
  147,    0,    0,    0,    0,    0,    0,  -62,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 2625,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  155,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -164,  149,  150,  -70, -237, -170, -273,
 -223, -174, -213,  -81, -168, -167, -166, -165, -163, -162,
    0,    0, -191,  -97,  -97,  -97,    0,    0, -287, -161,
 -206,  -98,  -96, -265, -263,  176, -200, -200,    0,    0,
    0,    0, -232,    0,    0,    0,    0,  101,  102,  180,
  181, -332, -332,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  182,  183,  184,  190,    0,    0,    0, -213,
    0,    0,  -81,    0,    0,    0,    0,    0,    0,    0,
 -254, -254,    0,    0, -191,    0,    0,    0,    0,    0,
  -85,  -85,    0,    0,    0,  185,  186,    0,    0,    0,
    0,    0,    0,    0,  115,  116,    0,    0, 2312, -244,
  -21,  -20,    0,    0,    0,    0,  198, -130, -130,    0,
    0,    0,    0, -207, -194,  -94,  -92,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -254,    0,    0,    0,
  -85,    0,    0, -126, -125, -239, 2460, 2460,  199,  200,
  201,  203,  204,  206,  209,  210,  212,  214,  215,  216,
  217,  221,  227,  229, -229,  234,  235,  237,  -87,  239,
  241,  242,  251,  252,  253,  254,  255,  256,  258,  259,
  261,  262,  267,  270,  276,  280,  286,  287,  288,  290,
  293,  294,  295,  297,  298,  299,  300,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, 2312,  -19,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -244,  -19,  304,  306, -334, -130,  -34,
    0,    0,  307,  308,  310,  324,  325,  326,    0,    0,
    0,    0,    0,    0,  327,    0, 2460,  -19,    0,  -19,
    0,   14, -254,   86,   17,   72,   66,   67, -279, -190,
 -234,  111,  112, -251,   64, -236,    0,    0,   45,    0,
  372,  373,   51,   53,   55,    0,  379,   40, -212, -210,
 -205,   44,   46,   47,   48,   37,   50,   54,   27,   28,
   30,   32,   23,   35,   36,   49,   61,   63,   71,   76,
   59,   18,  -38,   78, -203,    0,    0, 2312,   81,  407,
    0,  151,   94,  224,    0,    0, -130,    0,    0,    0,
 -298, -298,    0,  444,  109,  120,  121,  122,  125,  126,
 -241,    0, 2460, 2460, -332,    0,    0,    0,   86,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -279,    0,    0,    0, -190,    0,    0,    0,    0,    0,
 -234,    0,    0,  111,    0,    0,  112,    0,    0,    0,
    0,    0,    0,    0, -251,    0,    0,    0,    0,    0,
    0,    0, -236,    0, -332, -332,    0,    0,    0,  454,
 -332,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  128,    0,    0,    0,  385,    0,    0,  446, -332,    0,
  453, -244,    0,   94,    0,  468,    0,    0,    0,    0,
    0,    0,  137,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  398,  399,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  152,    0,    0,    0, -332,
    0, -231,  403,    0,  153,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  156,    0,  156,  156,    0,    0,
    0,    0,  168,    0,    0,    0, -298,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  537,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  538,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  416,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  538,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  744,
    0,    0,  553,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  819,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  159,  160,
    0,    0,    0,    0,    0,    0,    6,  196,  196,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  375,    0,    0,    0,
  669,    0,    0,    0,    0,    0,  161,  161,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -117,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -116,    0,    0,    0,    0,  196,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -113,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, 1720,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  420,    0,    0,
    0,    0,    0,    0,    0,    0,  196,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  421,  421,    0,    0,    0,    0,  980,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 1128,    0,    0,    0, 1276,    0,    0,    0,    0,    0,
 1424,    0,    0, 1868,    0,    0, 2016,    0,    0,    0,
    0,    0,    0,    0, 1572,    0,    0,    0,    0,    0,
    0,    0, 2164,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  422,    0,  894,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -102,    0, -102, -102,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0, -195,   58,    0,    0,    0,   -4,  542,    0,    0,
   57, -186, -185, -184,    0,    0, -189,   70,    0, -183,
    0,   65,    0,  546,    0,    0,    0,   -5,    0,    0,
    0,    0,  405,    0,    0,    0,    0,    0,   73,    0,
    0,    0,    0,    0,    0,   29,    0,    0,    0,    0,
   31,    0,  395,    0,    0,    0,    0,    0,  560,  562,
    0, -145,    0,    0,  394,    0,    0, -182, -152,    0,
 -181,    0,  103,    0,    0,  500,    0,  438,    0,    0,
    0,    0,    0,   42,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    9,  568,  569,    0,    0,    0, -327,
    0,    0, -216,    0,    0,    0,    0,    0,    0, -310,
 -178,   39, -309,    0,   85,    0,    0,    0,    0,    0,
 -436, -142,    0, -140, -139,    0,    0,    0,    0,    0,
  -47, -196, -435,    0,  225, -427,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  178,  105,    0,    0,
    0,    0,    0,
};
#define YYTABLESIZE 3088
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                      49,
  211,   84,  212,  213,  344,  339,  551,  183,  327,  295,
  348,  169,  362,  345,  346,  347,  349,  352,  353,  228,
  340,  380,  359,  451,  572,  580,  441,  436,  585,  373,
    8,   11,   12,   54,   89,   59,  233,  127,  128,  445,
   97,  203,  204,  145,  205,  442,  446,   20,  220,  221,
  222,  223,  224,  225,    1,    2,  241,  475,  476,  477,
  478,  479,  153,  154,   49,  146,   94,  242,  463,   98,
  464,  149,  150,  151,  369,  157,  158,  159,  594,  595,
  568,   99,  450,  100,  597,  370,  101,  147,  102,  245,
  246,  247,  197,  140,  141,  103,  129,  130,   54,  248,
   59,  183,  184,  249,  499,  500,  501,  502,  503,  104,
  252,  155,  156,  105,  486,  487,  488,  489,  173,  174,
  186,  187,  601,  190,  191,  192,  193,  555,  129,  130,
  339,  106,  507,  508,  509,  510,  511,  363,  364,  581,
  107,  374,  203,  204,  613,  205,  614,  108,  295,  109,
  365,  366,  397,  398,  482,  483,  179,  180,  344,  340,
  462,  110,  448,  612,  348,  195,  196,  345,  346,  347,
  349,  352,  353,  359,  359,  111,  523,  524,  525,  526,
  112,  625,  626,  527,  528,  553,  554,  113,  114,  359,
  115,  116,  117,  118,  350,  355,  119,  120,  359,  628,
  121,  122,  123,  124,  125,  126,  142,  143,  144,  359,
  148,  162,  165,  166,  167,  168,  177,  169,  170,  185,
  188,  194,  189,  199,  200,  201,  202,  214,  215,  216,
  467,  359,  359,  359,  603,  217,  230,  237,  238,  356,
  357,  359,  234,  235,  358,  359,  583,  584,  295,  360,
  567,  367,  359,  368,  371,  372,  381,  382,  383,  340,
  384,  385,  339,  386,  183,  327,  387,  388,  169,  389,
  339,  390,  391,  392,  393,  339,  339,  339,  394,  339,
  339,  339,  339,  339,  395,  339,  396,  339,  339,  339,
  339,  403,  404,  339,  405,  406,  408,  339,  409,  410,
  339,  339,  339,  339,  339,  339,  339,  339,  411,  412,
  413,  414,  415,  416,  339,  417,  418,  339,  419,  420,
  355,  339,  339,  339,  421,  339,  339,  422,  339,  339,
  339,  339,  449,  423,  339,  339,  339,  424,  339,  339,
  339,  339,  550,  425,  426,  427,  450,  428,  350,  339,
  429,  430,  431,  339,  432,  433,  434,  435,  339,  339,
  339,  443,  437,  444,  455,  456,  344,  457,  339,  339,
  339,  339,  348,  339,  154,  345,  346,  347,  349,  352,
  353,  458,  459,  460,  461,  339,  490,  339,  339,  339,
  339,  339,  339,  339,  466,  471,  339,  339,  468,  339,
  339,  339,  339,  472,  339,  339,  339,  473,  339,  474,
  339,  339,  339,  339,  339,  339,  339,  339,  339,  339,
  339,  339,  339,  339,  493,  506,  496,  398,  339,  515,
  516,  517,  522,  518,  339,  519,  521,  339,  339,  339,
  533,  529,  540,  530,  531,  536,  537,  549,  538,  532,
  539,  546,  355,  534,  541,  542,  547,  535,  552,  615,
  355,  617,  618,  556,  559,  355,  355,  355,  543,  355,
  355,  355,  355,  355,  563,  355,  560,  355,  355,  355,
  355,  544,  548,  355,  545,  566,  490,  355,  573,  574,
  355,  355,  355,  355,  355,  355,  355,  355,  596,  154,
  575,  576,  577,  600,  355,  578,  579,  355,  598,  599,
  602,  355,  355,  355,  605,  355,  355,  606,  355,  355,
  355,  355,  608,  609,  355,  355,  355,  621,  355,  355,
  355,  355,  610,  622,  449,  623,    2,    5,   51,  355,
  183,  327,  169,  355,  183,  169,  327,   85,  355,  355,
  355,   86,   70,  591,  588,  589,  350,  219,  355,  355,
  355,  355,  592,  355,  218,   90,  590,   91,  229,  131,
  198,  586,  604,   92,   93,  627,  514,  355,  355,  355,
  355,  355,  355,  355,  454,  587,  355,  355,    0,  355,
  355,  355,  355,    0,  355,  355,  355,  593,  355,    0,
  355,  355,  355,  355,  355,  355,  355,  355,  355,  355,
  355,  355,  355,  355,    0,    0,    0,    0,  355,    0,
    0,    0,    0,    0,  355,    0,    0,  355,  355,  355,
    0,  154,    0,    0,    0,    0,    0,    0,    0,  154,
    0,    0,    0,    0,  154,  154,  154,    0,  154,  154,
  154,  154,  154,    0,  154,    0,  154,  154,  154,  154,
    0,    0,  154,    0,    0,    0,  154,    0,   92,  154,
  154,  154,  154,  154,  154,  154,  154,   70,   92,    0,
    0,    0,    0,  154,    0,    0,  154,    0,    0,    0,
  154,  154,  154,    0,  154,  154,    0,  154,  154,  154,
    0,    0,    0,  154,  154,  154,    0,  154,  154,  154,
  154,    0,    0,    0,    0,    0,    0,    0,  154,    0,
    0,    0,  154,    0,    0,    0,    0,  154,  154,  154,
    0,    0,    0,    0,    0,    0,    0,  154,  154,  154,
  154,    0,  154,  150,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  154,    0,  154,  154,
  154,  154,  154,    0,    0,  154,  154,    0,  154,  154,
  154,  154,    0,  154,  154,  154,    0,  154,    0,  154,
  154,  154,  154,  154,  154,  154,  154,  154,  154,  154,
  154,  154,  154,    0,    0,    0,    0,  154,    0,    0,
    0,    0,    0,  154,    0,    0,  154,  154,  154,   70,
    0,    0,    0,    0,    0,    0,    0,   70,  122,    0,
    0,    0,   70,   70,    0,    0,   70,   70,   70,   70,
   70,    0,   70,    0,   70,   70,   70,   70,    0,    0,
   70,    0,    0,    0,   70,    0,    0,   70,   70,   70,
   70,   70,   70,   70,   70,    0,    0,    0,    0,    0,
    0,   70,    0,    0,   70,    0,    0,    0,   70,   70,
   70,    0,   70,   70,    0,   70,   70,   70,    0,    0,
    0,   70,   70,    0,    0,    0,   70,   70,   70,    0,
    0,    0,    0,  372,    0,    0,   70,    0,    0,    0,
   70,    0,    0,    0,    0,    0,    0,   70,    0,    0,
    0,    0,    0,    0,    0,    0,   70,   70,   70,    0,
    0,    0,    0,    0,    0,   92,    0,    0,    0,    0,
    0,    0,    0,   92,   70,    0,    0,    0,   92,   92,
   70,    0,   92,   92,   92,   92,   92,    0,   92,    0,
   92,   92,   92,   92,    0,    0,   92,   83,    0,    0,
   92,    0,    0,   92,   92,   92,   92,   92,   92,   92,
   92,    0,    0,    0,    0,    0,    0,   92,    0,    0,
    0,    0,    0,    0,   92,   92,   92,    0,   92,   92,
    0,   92,   92,   92,    0,    0,    0,   92,   92,    0,
  150,    0,    0,    0,    0,    0,    0,    0,  150,    0,
    0,    0,    0,  150,  150,    0,    0,  150,  150,  150,
  150,  150,    0,  150,    0,  150,  150,  150,  150,    0,
    0,  150,   92,   92,   92,  150,    0,    0,  150,  150,
  150,  150,  150,  150,  150,  150,    0,    0,    0,    0,
    0,    0,  150,    0,    0,    0,   92,    0,    0,  150,
  150,  150,    0,  150,  150,    0,  150,  150,  150,    0,
    0,    0,  150,  150,    0,  122,    0,    0,    0,    0,
    0,    0,    0,  122,    0,    0,    0,    0,  122,  122,
    0,    0,  122,  122,  122,  122,  122,    0,  122,    0,
  122,  122,  122,  122,  266,    0,  122,  150,  150,  150,
  122,    0,    0,  122,  122,  122,  122,  122,  122,  122,
  122,    0,    0,    0,    0,    0,    0,  122,    0,    0,
    0,  150,    0,    0,  122,  122,  122,    0,  122,  122,
    0,  122,  122,  122,    0,    0,    0,  122,  122,    0,
  372,    0,    0,    0,    0,    0,    0,    0,  372,    0,
    0,    0,    0,  372,  372,    0,    0,  372,  372,  372,
  372,  372,    0,  372,    0,  372,  372,  372,  372,    0,
    0,  372,  122,  122,  122,  372,    0,    0,  372,  372,
  372,  372,  372,  372,  372,  372,    0,    0,    0,    0,
    0,    0,  372,    0,    0,    0,  122,    0,    0,  372,
  372,  372,    8,  372,  372,    0,  372,  372,  372,    0,
    0,    0,  372,  372,    0,    0,    0,    0,    0,   15,
   16,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   21,   22,   23,   24,   25,   26,    0,    0,
  266,  266,  308,    0,    0,  266,  266,  372,  372,  372,
    0,    0,    0,    0,    0,    0,    0,   33,   34,    0,
    0,  266,   82,    0,  266,  266,  266,  266,  266,  266,
  266,  372,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  266,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  266,    0,  266,  266,  266,  266,    0,    0,    0,    0,
    0,    0,    0,  266,    0,    0,    0,  266,    0,    0,
    0,    0,  266,  266,  266,    0,    0,    0,    0,    0,
    0,    0,  266,    0,    0,    0,    0,  266,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  266,    0,  266,  266,  266,  266,    0,    0,    0,
  266,  266,    0,  266,  266,  266,  266,    0,  266,  266,
  266,    0,  266,    0,  266,  266,  266,  266,  266,  266,
  266,  266,  266,  266,  266,  266,  266,  266,  308,  308,
  279,    0,  266,  308,  308,    0,    0,    0,  266,    0,
    0,  266,  266,  266,    0,    0,    0,    0,    0,  308,
    0,    0,  308,  308,  308,  308,  308,  308,  308,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  308,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  308,    0,
  308,  308,  308,  308,    0,    0,    0,    0,    0,    0,
    0,  308,    0,    0,    0,  308,    0,    0,    0,    0,
  308,  308,  308,    0,    0,    0,    0,    0,    0,    0,
  308,    0,    0,    0,    0,  308,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  308,
    0,  308,  308,  308,  308,    0,    0,    0,  308,  308,
    0,  308,  308,  308,  308,    0,  308,  308,  308,    0,
  308,    0,  308,  308,  308,  308,  308,  308,  308,  308,
  308,  308,  308,  308,  308,  308,  279,  279,   58,    0,
  308,  279,  279,    0,    0,    0,  308,    0,    0,  308,
  308,  308,    0,    0,    0,    0,    0,  279,    0,    0,
  279,  279,  279,  279,  279,  279,  279,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  279,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  279,    0,  279,  279,
  279,  279,    0,    0,    0,    0,    0,    0,    0,  279,
    0,    0,    0,  279,    0,    0,    0,    0,  279,  279,
  279,    0,    0,    0,    0,    0,    0,    0,  279,    0,
    0,    0,    0,  279,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  279,    0,  279,
  279,  279,  279,    0,    0,    0,  279,  279,    0,  279,
  279,  279,  279,    0,  279,  279,  279,    0,  279,    0,
  279,  279,  279,  279,  279,  279,  279,  279,  279,  279,
  279,  279,  279,  279,   58,   58,  271,    0,  279,   58,
   58,    0,    0,    0,  279,    0,    0,  279,  279,  279,
    0,    0,    0,    0,    0,   58,    0,    0,   58,   58,
   58,   58,   58,   58,   58,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   58,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   58,    0,   58,   58,   58,   58,
    0,    0,    0,    0,    0,    0,    0,   58,    0,    0,
    0,   58,    0,    0,    0,    0,   58,   58,   58,    0,
    0,    0,    0,    0,    0,    0,   58,    0,    0,    0,
    0,   58,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   58,    0,   58,   58,   58,
   58,    0,    0,    0,   58,   58,    0,   58,   58,   58,
   58,    0,   58,   58,   58,    0,   58,    0,   58,   58,
   58,   58,   58,   58,   58,   58,   58,   58,   58,   58,
   58,   58,  271,  271,  285,    0,   58,  271,  271,    0,
    0,    0,   58,    0,    0,   58,   58,   58,    0,    0,
    0,    0,    0,  271,    0,    0,  271,  271,  271,  271,
  271,  271,  271,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  271,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  271,    0,  271,  271,  271,  271,    0,    0,
    0,    0,    0,    0,    0,  271,    0,    0,    0,  271,
    0,    0,    0,    0,  271,  271,  271,    0,    0,    0,
    0,    0,    0,    0,  271,    0,    0,    0,    0,  271,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  271,    0,  271,  271,  271,  271,    0,
    0,    0,  271,  271,    0,  271,  271,  271,  271,    0,
  271,  271,  271,    0,  271,    0,  271,  271,  271,  271,
  271,  271,  271,  271,  271,  271,  271,  271,  271,  271,
  285,  285,   62,    0,  271,  285,  285,    0,    0,    0,
  271,    0,    0,  271,  271,  271,    0,    0,    0,    0,
    0,    0,    0,    0,  285,  285,  285,  285,  285,  285,
  285,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  285,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  285,    0,  285,  285,  285,  285,    0,    0,    0,    0,
    0,    0,    0,  285,    0,    0,    0,  285,    0,    0,
    0,    0,  285,  285,  285,    0,    0,    0,    0,    0,
    0,    0,  285,    0,    0,    0,    0,  285,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  285,    0,  285,  285,  285,  285,    0,    0,    0,
  285,  285,    0,  285,  285,  285,  285,    0,  285,  285,
  285,    0,  285,    0,  285,  285,  285,  285,  285,  285,
  285,  285,  285,  285,  285,  285,  285,  285,   62,   62,
   66,    0,  285,   62,   62,    0,    0,    0,  285,    0,
    0,  285,  285,  285,    0,    0,    0,    0,    0,    0,
    0,    0,   62,   62,   62,   62,   62,   62,   62,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   62,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   62,    0,
   62,   62,   62,   62,    0,    0,    0,    0,    0,    0,
    0,   62,    0,    0,    0,   62,    0,    0,    0,    0,
   62,   62,   62,    0,    0,    0,    0,    0,    0,    0,
   62,    0,    0,    0,    0,   62,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   62,
    0,   62,   62,   62,   62,    0,    0,    0,   62,   62,
    0,   62,   62,   62,   62,    0,   62,   62,   62,    0,
   62,    0,   62,   62,   62,   62,   62,   62,   62,   62,
   62,   62,   62,   62,   62,   62,   66,   66,  296,    0,
   62,   66,   66,    0,    0,    0,   62,    0,    0,   62,
   62,   62,    0,    0,    0,    0,    0,    0,    0,    0,
   66,   66,   66,   66,   66,   66,   66,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   66,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   66,    0,   66,   66,
   66,   66,    0,    0,    0,    0,    0,    0,    0,   66,
    0,    0,    0,   66,    0,    0,    0,    0,   66,   66,
   66,    0,    0,    0,    0,    0,    0,    0,   66,    0,
    0,    0,    0,   66,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   66,    0,   66,
   66,   66,   66,    0,    0,    0,   66,   66,    0,   66,
   66,   66,   66,    0,   66,   66,   66,    0,   66,    0,
   66,   66,   66,   66,   66,   66,   66,   66,   66,   66,
   66,   66,   66,   66,  296,  296,    0,    0,   66,  296,
  296,    0,    0,    0,   66,    0,    0,   66,   66,   66,
    0,    0,    0,    0,    0,    0,    0,    0,  296,  296,
  296,  296,  296,  296,  296,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  296,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  296,    0,  296,  296,  296,  296,
    0,    0,    0,    0,    0,    0,    0,  296,    0,    0,
    0,  296,    0,    0,    0,    0,  296,  296,  296,    0,
    0,    0,    0,    0,    0,    0,  296,    0,    0,    0,
    0,  296,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  296,    0,  296,  296,  296,
  296,    0,    0,    0,  296,  296,    0,  296,  296,  296,
  296,    0,  296,  296,  296,    0,  296,    0,  296,  296,
  296,  296,  296,  296,  296,  296,  296,  296,  296,  296,
  296,  296,  239,  240,    0,    0,  296,   11,   12,    0,
    0,    0,  296,    0,    0,  296,  296,  296,    0,    0,
    0,    0,    0,    0,    0,    0,   21,   22,   23,   24,
   25,   26,  241,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  242,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  243,    0,  244,  245,  246,  247,    0,    0,
    0,    0,    0,    0,    0,  248,    0,    0,    0,  249,
    0,    0,    0,    0,  250,  251,  252,    0,    0,    0,
    0,    0,    0,    0,  253,    0,    0,    0,    0,  254,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  255,  256,  257,  258,    0,
    0,    0,  259,  260,    0,  261,  262,  263,  264,    0,
  265,  266,  267,    0,  268,    0,  269,  270,  271,  272,
  273,  274,  275,  276,  277,  278,  279,  280,  281,  282,
  239,  240,    0,    0,  283,   11,   12,    0,    0,    0,
  284,    0,    0,  285,  286,  287,    0,    0,    0,    0,
    0,    0,    0,    0,   21,   22,   23,   24,   25,   26,
  241,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  242,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  243,    0,  244,  245,  246,  247,    0,    0,    0,    0,
    0,    0,    0,  248,    0,    0,    0,    0,    0,    0,
    0,    0,  250,  251,    0,    0,    0,    0,    0,    0,
    0,    0,  253,    0,    0,    0,    0,  254,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  255,  256,  257,    0,    0,    0,    0,
  259,  260,    0,  261,  262,  263,  264,    0,  265,  266,
  267,    0,  268,    0,  269,  270,  271,  272,  273,  274,
  275,  276,  277,  278,  279,  280,  281,  282,    0,    0,
    0,    7,  283,    0,    0,    0,    0,    0,  284,    8,
    0,  285,  286,  287,  127,  128,    0,    0,    9,   10,
   11,   12,   13,    0,   14,    0,   15,   16,   17,   18,
    0,    0,   19,    0,    0,    0,   20,    0,    0,   21,
   22,   23,   24,   25,   26,   27,   28,    0,    0,    0,
    0,    0,    0,   29,    0,    0,    0,    0,    0,    0,
   30,   31,   32,    0,   33,   34,    0,   35,   36,   82,
    0,    0,    0,  129,  130,    0,    7,    0,    0,    0,
    0,    0,    0,    0,    8,    0,    0,    0,    0,    0,
    0,    0,    0,    9,   10,   11,   12,   13,    0,   14,
    0,   15,   16,   17,   18,    0,    0,   19,   38,   39,
   40,   20,    0,    0,   21,   22,   23,   24,   25,   26,
   27,   28,    0,    0,    0,    0,    0,    0,   29,    0,
    0,    0,   41,    0,    0,   30,   31,   32,    0,   33,
   34,    0,   35,   36,   37,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   38,   39,   40,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   41,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                       5,
  143,    6,  143,  143,  200,    0,   45,  125,  125,  199,
  200,  125,  209,  200,  200,  200,  200,  200,  200,  172,
  199,  238,  125,   58,  452,  267,  354,  338,  465,  269,
  265,  276,  277,    5,    6,    5,  182,  270,  271,  374,
   58,  374,  375,  281,  377,  355,  381,  292,  303,  304,
  305,  306,  307,  308,  263,  264,  301,  337,  338,  339,
  340,  341,  286,  287,   70,  303,   46,  312,  378,   58,
  380,  345,  346,  347,  227,  289,  290,  291,  515,  516,
  379,   58,  381,   58,  521,  231,   46,  325,   46,  334,
  335,  336,  325,  258,  259,   58,  329,  330,   70,  344,
   70,  389,  390,  348,  356,  357,  358,  359,  360,   58,
  355,  286,  287,   58,  349,  350,  351,  352,  310,  311,
  327,  328,  559,  389,  390,  389,  390,  438,  329,  330,
  125,   58,  369,  370,  371,  372,  373,  345,  346,  381,
   58,  381,  374,  375,  376,  377,  378,   58,  338,   58,
  345,  346,  382,  383,  345,  346,  115,  116,  354,  338,
  377,   58,  359,  600,  354,  127,  128,  354,  354,  354,
  354,  354,  354,  276,  277,   58,  389,  390,  389,  390,
   58,  617,  618,  389,  390,  389,  390,   58,   58,  292,
   58,   58,   58,   58,  200,    0,   58,   58,  301,  627,
   46,   58,   58,   58,   58,  268,   58,   58,  279,  312,
  381,  293,  381,  381,  381,  381,  314,  381,  381,  381,
  319,   46,  319,  123,  123,   46,   46,   46,   46,   46,
  383,  334,  335,  336,  562,   46,  322,  123,  123,  261,
  261,  344,   58,   58,   47,  348,  463,  464,  438,  380,
  447,  346,  355,  346,  381,  381,   58,   58,   58,  438,
   58,   58,  257,   58,  382,  382,   58,   58,  382,   58,
  265,   58,   58,   58,   58,  270,  271,  272,   58,  274,
  275,  276,  277,  278,   58,  280,   58,  282,  283,  284,
  285,   58,   58,  288,   58,  383,   58,  292,   58,   58,
  295,  296,  297,  298,  299,  300,  301,  302,   58,   58,
   58,   58,   58,   58,  309,   58,   58,  312,   58,   58,
  125,  316,  317,  318,   58,  320,  321,   58,  323,  324,
  325,  326,  367,   58,  329,  330,  331,   58,  333,  334,
  335,  336,  381,   58,   58,   58,  381,   58,  354,  344,
   58,   58,   58,  348,   58,   58,   58,   58,  353,  354,
  355,   58,  382,   58,   58,   58,  562,   58,  363,  364,
  365,  366,  562,  368,    0,  562,  562,  562,  562,  562,
  562,   58,   58,   58,   58,  380,  391,  382,  383,  384,
  385,  386,  387,  388,  381,  379,  391,  392,  313,  394,
  395,  396,  397,  332,  399,  400,  401,  342,  403,  343,
  405,  406,  407,  408,  409,  410,  411,  412,  413,  414,
  415,  416,  417,  418,  314,  362,  315,  383,  423,   58,
   58,  381,  393,  381,  429,  381,   58,  432,  433,  434,
  404,  398,  420,  398,  398,  419,  419,  430,  419,  402,
  419,  381,  257,  404,  420,  420,  381,  404,  381,  602,
  265,  602,  602,  383,   58,  270,  271,  272,  420,  274,
  275,  276,  277,  278,  381,  280,  326,  282,  283,  284,
  285,  421,  424,  288,  422,  262,  491,  292,   45,  381,
  295,  296,  297,  298,  299,  300,  301,  302,   45,  125,
  381,  381,  381,   58,  309,  381,  381,  312,  381,  125,
   58,  316,  317,  318,   47,  320,  321,  381,  323,  324,
  325,  326,  125,  125,  329,  330,  331,  125,  333,  334,
  335,  336,  381,  381,  367,  380,    0,    0,  123,  344,
  382,  382,  382,  348,  125,  125,  125,    6,  353,  354,
  355,    6,    0,  497,  485,  491,  562,  163,  363,  364,
  365,  366,  505,  368,  160,    6,  494,    6,  175,   70,
  133,  469,  564,    6,    6,  623,  399,  382,  383,  384,
  385,  386,  387,  388,  360,  481,  391,  392,   -1,  394,
  395,  396,  397,   -1,  399,  400,  401,  513,  403,   -1,
  405,  406,  407,  408,  409,  410,  411,  412,  413,  414,
  415,  416,  417,  418,   -1,   -1,   -1,   -1,  423,   -1,
   -1,   -1,   -1,   -1,  429,   -1,   -1,  432,  433,  434,
   -1,  257,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  265,
   -1,   -1,   -1,   -1,  270,  271,  272,   -1,  274,  275,
  276,  277,  278,   -1,  280,   -1,  282,  283,  284,  285,
   -1,   -1,  288,   -1,   -1,   -1,  292,   -1,    0,  295,
  296,  297,  298,  299,  300,  301,  302,  125,   10,   -1,
   -1,   -1,   -1,  309,   -1,   -1,  312,   -1,   -1,   -1,
  316,  317,  318,   -1,  320,  321,   -1,  323,  324,  325,
   -1,   -1,   -1,  329,  330,  331,   -1,  333,  334,  335,
  336,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,
   -1,   -1,  348,   -1,   -1,   -1,   -1,  353,  354,  355,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,  364,  365,
  366,   -1,  368,    0,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  382,   -1,  384,  385,
  386,  387,  388,   -1,   -1,  391,  392,   -1,  394,  395,
  396,  397,   -1,  399,  400,  401,   -1,  403,   -1,  405,
  406,  407,  408,  409,  410,  411,  412,  413,  414,  415,
  416,  417,  418,   -1,   -1,   -1,   -1,  423,   -1,   -1,
   -1,   -1,   -1,  429,   -1,   -1,  432,  433,  434,  257,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  265,    0,   -1,
   -1,   -1,  270,  271,   -1,   -1,  274,  275,  276,  277,
  278,   -1,  280,   -1,  282,  283,  284,  285,   -1,   -1,
  288,   -1,   -1,   -1,  292,   -1,   -1,  295,  296,  297,
  298,  299,  300,  301,  302,   -1,   -1,   -1,   -1,   -1,
   -1,  309,   -1,   -1,  312,   -1,   -1,   -1,  316,  317,
  318,   -1,  320,  321,   -1,  323,  324,  325,   -1,   -1,
   -1,  329,  330,   -1,   -1,   -1,  334,  335,  336,   -1,
   -1,   -1,   -1,    0,   -1,   -1,  344,   -1,   -1,   -1,
  348,   -1,   -1,   -1,   -1,   -1,   -1,  355,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  364,  365,  366,   -1,
   -1,   -1,   -1,   -1,   -1,  257,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  265,  382,   -1,   -1,   -1,  270,  271,
  388,   -1,  274,  275,  276,  277,  278,   -1,  280,   -1,
  282,  283,  284,  285,   -1,   -1,  288,   10,   -1,   -1,
  292,   -1,   -1,  295,  296,  297,  298,  299,  300,  301,
  302,   -1,   -1,   -1,   -1,   -1,   -1,  309,   -1,   -1,
   -1,   -1,   -1,   -1,  316,  317,  318,   -1,  320,  321,
   -1,  323,  324,  325,   -1,   -1,   -1,  329,  330,   -1,
  257,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  265,   -1,
   -1,   -1,   -1,  270,  271,   -1,   -1,  274,  275,  276,
  277,  278,   -1,  280,   -1,  282,  283,  284,  285,   -1,
   -1,  288,  364,  365,  366,  292,   -1,   -1,  295,  296,
  297,  298,  299,  300,  301,  302,   -1,   -1,   -1,   -1,
   -1,   -1,  309,   -1,   -1,   -1,  388,   -1,   -1,  316,
  317,  318,   -1,  320,  321,   -1,  323,  324,  325,   -1,
   -1,   -1,  329,  330,   -1,  257,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  265,   -1,   -1,   -1,   -1,  270,  271,
   -1,   -1,  274,  275,  276,  277,  278,   -1,  280,   -1,
  282,  283,  284,  285,  125,   -1,  288,  364,  365,  366,
  292,   -1,   -1,  295,  296,  297,  298,  299,  300,  301,
  302,   -1,   -1,   -1,   -1,   -1,   -1,  309,   -1,   -1,
   -1,  388,   -1,   -1,  316,  317,  318,   -1,  320,  321,
   -1,  323,  324,  325,   -1,   -1,   -1,  329,  330,   -1,
  257,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  265,   -1,
   -1,   -1,   -1,  270,  271,   -1,   -1,  274,  275,  276,
  277,  278,   -1,  280,   -1,  282,  283,  284,  285,   -1,
   -1,  288,  364,  365,  366,  292,   -1,   -1,  295,  296,
  297,  298,  299,  300,  301,  302,   -1,   -1,   -1,   -1,
   -1,   -1,  309,   -1,   -1,   -1,  388,   -1,   -1,  316,
  317,  318,  265,  320,  321,   -1,  323,  324,  325,   -1,
   -1,   -1,  329,  330,   -1,   -1,   -1,   -1,   -1,  282,
  283,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  295,  296,  297,  298,  299,  300,   -1,   -1,
  271,  272,  125,   -1,   -1,  276,  277,  364,  365,  366,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  320,  321,   -1,
   -1,  292,  325,   -1,  295,  296,  297,  298,  299,  300,
  301,  388,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  312,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  331,   -1,  333,  334,  335,  336,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,   -1,  348,   -1,   -1,
   -1,   -1,  353,  354,  355,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  363,   -1,   -1,   -1,   -1,  368,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  382,   -1,  384,  385,  386,  387,   -1,   -1,   -1,
  391,  392,   -1,  394,  395,  396,  397,   -1,  399,  400,
  401,   -1,  403,   -1,  405,  406,  407,  408,  409,  410,
  411,  412,  413,  414,  415,  416,  417,  418,  271,  272,
  125,   -1,  423,  276,  277,   -1,   -1,   -1,  429,   -1,
   -1,  432,  433,  434,   -1,   -1,   -1,   -1,   -1,  292,
   -1,   -1,  295,  296,  297,  298,  299,  300,  301,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  312,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  331,   -1,
  333,  334,  335,  336,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  344,   -1,   -1,   -1,  348,   -1,   -1,   -1,   -1,
  353,  354,  355,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  363,   -1,   -1,   -1,   -1,  368,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  382,
   -1,  384,  385,  386,  387,   -1,   -1,   -1,  391,  392,
   -1,  394,  395,  396,  397,   -1,  399,  400,  401,   -1,
  403,   -1,  405,  406,  407,  408,  409,  410,  411,  412,
  413,  414,  415,  416,  417,  418,  271,  272,  125,   -1,
  423,  276,  277,   -1,   -1,   -1,  429,   -1,   -1,  432,
  433,  434,   -1,   -1,   -1,   -1,   -1,  292,   -1,   -1,
  295,  296,  297,  298,  299,  300,  301,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  312,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  331,   -1,  333,  334,
  335,  336,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   -1,   -1,  348,   -1,   -1,   -1,   -1,  353,  354,
  355,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,   -1,
   -1,   -1,   -1,  368,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  382,   -1,  384,
  385,  386,  387,   -1,   -1,   -1,  391,  392,   -1,  394,
  395,  396,  397,   -1,  399,  400,  401,   -1,  403,   -1,
  405,  406,  407,  408,  409,  410,  411,  412,  413,  414,
  415,  416,  417,  418,  271,  272,  125,   -1,  423,  276,
  277,   -1,   -1,   -1,  429,   -1,   -1,  432,  433,  434,
   -1,   -1,   -1,   -1,   -1,  292,   -1,   -1,  295,  296,
  297,  298,  299,  300,  301,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  312,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  331,   -1,  333,  334,  335,  336,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,  354,  355,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  363,   -1,   -1,   -1,
   -1,  368,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  382,   -1,  384,  385,  386,
  387,   -1,   -1,   -1,  391,  392,   -1,  394,  395,  396,
  397,   -1,  399,  400,  401,   -1,  403,   -1,  405,  406,
  407,  408,  409,  410,  411,  412,  413,  414,  415,  416,
  417,  418,  271,  272,  125,   -1,  423,  276,  277,   -1,
   -1,   -1,  429,   -1,   -1,  432,  433,  434,   -1,   -1,
   -1,   -1,   -1,  292,   -1,   -1,  295,  296,  297,  298,
  299,  300,  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  312,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  331,   -1,  333,  334,  335,  336,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,   -1,  348,
   -1,   -1,   -1,   -1,  353,  354,  355,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  363,   -1,   -1,   -1,   -1,  368,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  382,   -1,  384,  385,  386,  387,   -1,
   -1,   -1,  391,  392,   -1,  394,  395,  396,  397,   -1,
  399,  400,  401,   -1,  403,   -1,  405,  406,  407,  408,
  409,  410,  411,  412,  413,  414,  415,  416,  417,  418,
  271,  272,  125,   -1,  423,  276,  277,   -1,   -1,   -1,
  429,   -1,   -1,  432,  433,  434,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  295,  296,  297,  298,  299,  300,
  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  312,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  331,   -1,  333,  334,  335,  336,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,   -1,  348,   -1,   -1,
   -1,   -1,  353,  354,  355,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  363,   -1,   -1,   -1,   -1,  368,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  382,   -1,  384,  385,  386,  387,   -1,   -1,   -1,
  391,  392,   -1,  394,  395,  396,  397,   -1,  399,  400,
  401,   -1,  403,   -1,  405,  406,  407,  408,  409,  410,
  411,  412,  413,  414,  415,  416,  417,  418,  271,  272,
  125,   -1,  423,  276,  277,   -1,   -1,   -1,  429,   -1,
   -1,  432,  433,  434,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  295,  296,  297,  298,  299,  300,  301,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  312,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  331,   -1,
  333,  334,  335,  336,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  344,   -1,   -1,   -1,  348,   -1,   -1,   -1,   -1,
  353,  354,  355,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  363,   -1,   -1,   -1,   -1,  368,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  382,
   -1,  384,  385,  386,  387,   -1,   -1,   -1,  391,  392,
   -1,  394,  395,  396,  397,   -1,  399,  400,  401,   -1,
  403,   -1,  405,  406,  407,  408,  409,  410,  411,  412,
  413,  414,  415,  416,  417,  418,  271,  272,  125,   -1,
  423,  276,  277,   -1,   -1,   -1,  429,   -1,   -1,  432,
  433,  434,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  295,  296,  297,  298,  299,  300,  301,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  312,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  331,   -1,  333,  334,
  335,  336,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,
   -1,   -1,   -1,  348,   -1,   -1,   -1,   -1,  353,  354,
  355,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,   -1,
   -1,   -1,   -1,  368,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  382,   -1,  384,
  385,  386,  387,   -1,   -1,   -1,  391,  392,   -1,  394,
  395,  396,  397,   -1,  399,  400,  401,   -1,  403,   -1,
  405,  406,  407,  408,  409,  410,  411,  412,  413,  414,
  415,  416,  417,  418,  271,  272,   -1,   -1,  423,  276,
  277,   -1,   -1,   -1,  429,   -1,   -1,  432,  433,  434,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  295,  296,
  297,  298,  299,  300,  301,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  312,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  331,   -1,  333,  334,  335,  336,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,  354,  355,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  363,   -1,   -1,   -1,
   -1,  368,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  382,   -1,  384,  385,  386,
  387,   -1,   -1,   -1,  391,  392,   -1,  394,  395,  396,
  397,   -1,  399,  400,  401,   -1,  403,   -1,  405,  406,
  407,  408,  409,  410,  411,  412,  413,  414,  415,  416,
  417,  418,  271,  272,   -1,   -1,  423,  276,  277,   -1,
   -1,   -1,  429,   -1,   -1,  432,  433,  434,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  295,  296,  297,  298,
  299,  300,  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  312,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  331,   -1,  333,  334,  335,  336,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  344,   -1,   -1,   -1,  348,
   -1,   -1,   -1,   -1,  353,  354,  355,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  363,   -1,   -1,   -1,   -1,  368,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  384,  385,  386,  387,   -1,
   -1,   -1,  391,  392,   -1,  394,  395,  396,  397,   -1,
  399,  400,  401,   -1,  403,   -1,  405,  406,  407,  408,
  409,  410,  411,  412,  413,  414,  415,  416,  417,  418,
  271,  272,   -1,   -1,  423,  276,  277,   -1,   -1,   -1,
  429,   -1,   -1,  432,  433,  434,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  295,  296,  297,  298,  299,  300,
  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  312,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  331,   -1,  333,  334,  335,  336,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  344,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  353,  354,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  363,   -1,   -1,   -1,   -1,  368,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  384,  385,  386,   -1,   -1,   -1,   -1,
  391,  392,   -1,  394,  395,  396,  397,   -1,  399,  400,
  401,   -1,  403,   -1,  405,  406,  407,  408,  409,  410,
  411,  412,  413,  414,  415,  416,  417,  418,   -1,   -1,
   -1,  257,  423,   -1,   -1,   -1,   -1,   -1,  429,  265,
   -1,  432,  433,  434,  270,  271,   -1,   -1,  274,  275,
  276,  277,  278,   -1,  280,   -1,  282,  283,  284,  285,
   -1,   -1,  288,   -1,   -1,   -1,  292,   -1,   -1,  295,
  296,  297,  298,  299,  300,  301,  302,   -1,   -1,   -1,
   -1,   -1,   -1,  309,   -1,   -1,   -1,   -1,   -1,   -1,
  316,  317,  318,   -1,  320,  321,   -1,  323,  324,  325,
   -1,   -1,   -1,  329,  330,   -1,  257,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  265,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  274,  275,  276,  277,  278,   -1,  280,
   -1,  282,  283,  284,  285,   -1,   -1,  288,  364,  365,
  366,  292,   -1,   -1,  295,  296,  297,  298,  299,  300,
  301,  302,   -1,   -1,   -1,   -1,   -1,   -1,  309,   -1,
   -1,   -1,  388,   -1,   -1,  316,  317,  318,   -1,  320,
  321,   -1,  323,  324,  325,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  364,  365,  366,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 435
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const socks_yyname[] =
#else
char *socks_yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'-'","'.'","'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"CPU","MASK","SCHEDULE","CPUMASK_ANYCPU","PROCESSTYPE","SCHEDULEPOLICY",
"SERVERCONFIG","CLIENTCONFIG","DEPRECATED","INTERFACE",
"SOCKETOPTION_SYMBOLICVALUE","SOCKETPROTOCOL","SOCKETOPTION_OPTID","CLIENTRULE",
"HOSTID","HOSTINDEX","REQUIRED","INTERNAL","EXTERNAL","INTERNALSOCKET",
"EXTERNALSOCKET","REALM","REALNAME","EXTERNAL_ROTATION","SAMESAME","DEBUGGING",
"RESOLVEPROTOCOL","SOCKET","CLIENTSIDE_SOCKET","SNDBUF","RCVBUF","SRCHOST",
"NODNSMISMATCH","NODNSUNKNOWN","CHECKREPLYAUTH","EXTENSION","BIND","PRIVILEGED",
"IOTIMEOUT","IOTIMEOUT_TCP","IOTIMEOUT_UDP","NEGOTIATETIMEOUT","CONNECTTIMEOUT",
"TCP_FIN_WAIT","METHOD","CLIENTMETHOD","NONE","GSSAPI","UNAME","RFC931","PAM",
"BSDAUTH","COMPATIBILITY","SAMEPORT","DRAFT_5_05","CLIENTCOMPATIBILITY",
"NECGSSAPI","USERNAME","GROUPNAME","USER_PRIVILEGED","USER_UNPRIVILEGED",
"USER_LIBWRAP","LIBWRAP_FILE","ERRORLOG","LOGOUTPUT","LOGFILE","CHILD_MAXIDLE",
"CHILD_MAXREQUESTS","ROUTE","VIA","BADROUTE_EXPIRE","MAXFAIL","VERDICT_BLOCK",
"VERDICT_PASS","PAMSERVICENAME","BSDAUTHSTYLENAME","BSDAUTHSTYLE",
"GSSAPISERVICE","GSSAPIKEYTAB","GSSAPIENCTYPE","GSSAPIENC_ANY",
"GSSAPIENC_CLEAR","GSSAPIENC_INTEGRITY","GSSAPIENC_CONFIDENTIALITY",
"GSSAPIENC_PERMESSAGE","GSSAPISERVICENAME","GSSAPIKEYTABNAME","PROTOCOL",
"PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL",
"PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_HTTP",
"PROXYPROTOCOL_UPNP","USER","GROUP","COMMAND","COMMAND_BIND","COMMAND_CONNECT",
"COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE",
"LIBWRAPSTART","LIBWRAP_ALLOW","LIBWRAP_DENY","LIBWRAP_HOSTS_ACCESS","OPERATOR",
"SOCKS_LOG","SOCKS_LOG_CONNECT","SOCKS_LOG_DATA","SOCKS_LOG_DISCONNECT",
"SOCKS_LOG_ERROR","SOCKS_LOG_IOOPERATION","IPADDRESS","DOMAINNAME","DIRECT",
"IFNAME","URL","SERVICENAME","PORT","NUMBER","FROM","TO","REDIRECT","BANDWIDTH",
"MAXSESSIONS","UDPPORTRANGE","UDPCONNECTDST","YES","NO","BOUNCE","LDAPURL",
"LDAP_URL","LDAPSSL","LDAPCERTCHECK","LDAPKEEPREALM","LDAPBASEDN","LDAP_BASEDN",
"LDAPBASEDN_HEX","LDAPBASEDN_HEX_ALL","LDAPSERVER","LDAPSERVER_NAME",
"LDAPGROUP","LDAPGROUP_NAME","LDAPGROUP_HEX","LDAPGROUP_HEX_ALL","LDAPFILTER",
"LDAPFILTER_AD","LDAPFILTER_HEX","LDAPFILTER_AD_HEX","LDAPATTRIBUTE",
"LDAPATTRIBUTE_AD","LDAPATTRIBUTE_HEX","LDAPATTRIBUTE_AD_HEX","LDAPCERTFILE",
"LDAPCERTPATH","LDAPPORT","LDAPPORTSSL","LDAP_FILTER","LDAP_ATTRIBUTE",
"LDAP_CERTFILE","LDAP_CERTPATH","LDAPDOMAIN","LDAP_DOMAIN","LDAPTIMEOUT",
"LDAPCACHE","LDAPCACHEPOS","LDAPCACHENEG","LDAPKEYTAB","LDAPKEYTABNAME",
"LDAPDEADTIME","LDAPDEBUG","LDAPDEPTH","LDAPAUTO","LDAPSEARCHTIME",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const socks_yyrule[] =
#else
char *socks_yyrule[] =
#endif
	{"$accept : configtype",
"configtype : serverinit serverline",
"configtype : clientinit clientline",
"serverinit : SERVERCONFIG",
"serverline : serverconfigs rulesorroutes",
"rulesorroutes :",
"rulesorroutes : ruleorroute rulesorroutes",
"ruleorroute : clientrule",
"ruleorroute : hostidrule",
"ruleorroute : rule",
"ruleorroute : route",
"clientline :",
"clientline : clientline '\\n'",
"clientline : clientline clientconfig",
"clientline : clientline route",
"clientinit : CLIENTCONFIG",
"clientconfig : clientoption",
"clientconfig : deprecated",
"serverconfigs : serverconfig",
"serverconfigs : serverconfigs serverconfig",
"serverconfig : global_authmethod",
"serverconfig : childstate",
"serverconfig : debuging",
"serverconfig : deprecated",
"serverconfig : errorlog",
"serverconfig : external",
"serverconfig : external_rotation",
"serverconfig : global_clientauthmethod",
"serverconfig : internal",
"serverconfig : libwrap_hosts_access",
"serverconfig : libwrapfiles",
"serverconfig : logoutput",
"serverconfig : serveroption",
"serverconfig : socketoption",
"serverconfig : udpconnectdst",
"serverconfig : userids",
"serveroption : compatibility",
"serveroption : cpu",
"serveroption : extension",
"serveroption : global_routeoption",
"serveroption : oldsocketoption",
"serveroption : realm",
"serveroption : resolveprotocol",
"serveroption : srchost",
"serveroption : timeout",
"timeout : connecttimeout",
"timeout : iotimeout",
"timeout : negotiatetimeout",
"timeout : tcp_fin_timeout",
"deprecated : DEPRECATED",
"route : ROUTE routeinit '{' routeoptions fromto gateway routeoptions '}'",
"routeinit :",
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
"usernames : username usernames",
"group : GROUP ':' groupnames",
"groupname : GROUPNAME",
"groupnames : groupname",
"groupnames : groupname groupnames",
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
"clientoption : debuging",
"clientoption : global_routeoption",
"clientoption : errorlog",
"clientoption : logoutput",
"clientoption : resolveprotocol",
"clientoption : timeout",
"global_routeoption : ROUTE '.' MAXFAIL ':' NUMBER",
"global_routeoption : ROUTE '.' BADROUTE_EXPIRE ':' NUMBER",
"$$1 :",
"errorlog : ERRORLOG ':' $$1 logoutputdevices",
"$$2 :",
"logoutput : LOGOUTPUT ':' $$2 logoutputdevices",
"logoutputdevice : LOGFILE",
"logoutputdevices : logoutputdevice",
"logoutputdevices : logoutputdevice logoutputdevices",
"childstate : CHILD_MAXIDLE ':' YES",
"childstate : CHILD_MAXIDLE ':' NO",
"childstate : CHILD_MAXREQUESTS ':' NUMBER",
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
"debuging : DEBUGGING ':' NUMBER",
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
"$$3 :",
"socketoption : socketside SOCKETPROTOCOL '.' $$3 socketoptionname ':' socketoptionvalue",
"socketoptionname : NUMBER",
"socketoptionname : SOCKETOPTION_OPTID",
"socketoptionvalue : NUMBER",
"socketoptionvalue : SOCKETOPTION_SYMBOLICVALUE",
"socketside : INTERNALSOCKET",
"socketside : EXTERNALSOCKET",
"oldsocketoption : SOCKET '.' SNDBUF '.' PROTOCOL_UDP ':' NUMBER",
"oldsocketoption : SOCKET '.' RCVBUF '.' PROTOCOL_UDP ':' NUMBER",
"oldsocketoption : SOCKET '.' SNDBUF '.' PROTOCOL_TCP ':' NUMBER",
"oldsocketoption : SOCKET '.' RCVBUF '.' PROTOCOL_TCP ':' NUMBER",
"oldsocketoption : CLIENTSIDE_SOCKET '.' SNDBUF '.' PROTOCOL_UDP ':' NUMBER",
"oldsocketoption : CLIENTSIDE_SOCKET '.' RCVBUF '.' PROTOCOL_UDP ':' NUMBER",
"srchost : SRCHOST ':' srchostoptions",
"srchostoption : NODNSMISMATCH",
"srchostoption : NODNSUNKNOWN",
"srchostoption : CHECKREPLYAUTH",
"srchostoptions : srchostoption",
"srchostoptions : srchostoption srchostoptions",
"realm : REALM ':' REALNAME",
"authmethod : METHOD ':' authmethods",
"authmethods : authmethodname",
"authmethods : authmethodname authmethods",
"$$4 :",
"global_authmethod : METHOD ':' $$4 authmethods",
"$$5 :",
"global_clientauthmethod : CLIENTMETHOD ':' $$5 authmethods",
"authmethodname : NONE",
"authmethodname : GSSAPI",
"authmethodname : UNAME",
"authmethodname : RFC931",
"authmethodname : PAM",
"authmethodname : BSDAUTH",
"clientrule : CLIENTRULE verdict '{' clientruleoptions fromto clientruleoptions '}'",
"clientruleoption : option",
"clientruleoption : protocol",
"clientruleoptions :",
"clientruleoptions : clientruleoption clientruleoptions",
"hostidrule : HOSTID verdict '{' clientruleoptions fromto clientruleoptions '}'",
"hostidoption : hostid",
"hostidoption : hostindex",
"$$6 :",
"hostid : HOSTID ':' $$6 address",
"hostindex : HOSTINDEX ':' NUMBER",
"rule : verdict '{' ruleoptions fromto ruleoptions '}'",
"ruleoption : option",
"ruleoption : command",
"ruleoption : udpportrange",
"ruleoption : protocol",
"ruleoption : proxyprotocol",
"ruleoptions :",
"ruleoptions : ruleoption ruleoptions",
"option : authmethod",
"option : bandwidth",
"option : bounce",
"option : bsdauthstylename",
"option : clientcompatibility",
"option : group",
"option : gssapienctype",
"option : gssapikeytab",
"option : gssapiservicename",
"option : hostidoption",
"option : lbasedn",
"option : lbasedn_hex",
"option : lbasedn_hex_all",
"option : ldapattribute",
"option : ldapattribute_ad",
"option : ldapattribute_ad_hex",
"option : ldapattribute_hex",
"option : ldapauto",
"option : ldapcertcheck",
"option : ldapcertfile",
"option : ldapcertpath",
"option : ldapdebug",
"option : ldapdepth",
"option : ldapdomain",
"option : ldapfilter",
"option : ldapfilter_ad",
"option : ldapfilter_ad_hex",
"option : ldapfilter_hex",
"option : ldapkeeprealm",
"option : ldapkeytab",
"option : ldapport",
"option : ldapportssl",
"option : ldapssl",
"option : lgroup",
"option : lgroup_hex",
"option : lgroup_hex_all",
"option : libwrap",
"option : log",
"option : lserver",
"option : lurl",
"option : pamservicename",
"option : redirect",
"option : socketoption",
"option : session",
"option : timeout",
"option : user",
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
"redirect : REDIRECT rdr_fromaddress rdr_toaddress",
"redirect : REDIRECT rdr_fromaddress",
"redirect : REDIRECT rdr_toaddress",
"session : maxsessions",
"maxsessions : MAXSESSIONS ':' NUMBER",
"bandwidth : BANDWIDTH ':' NUMBER",
"log : SOCKS_LOG ':' logs",
"logname : SOCKS_LOG_CONNECT",
"logname : SOCKS_LOG_DATA",
"logname : SOCKS_LOG_DISCONNECT",
"logname : SOCKS_LOG_ERROR",
"logname : SOCKS_LOG_IOOPERATION",
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
"bounce : BOUNCE bounceto ':' address",
"libwrap : LIBWRAPSTART ':' LINE",
"srcaddress : from ':' address",
"dstaddress : to ':' address",
"rdr_fromaddress : rdr_from ':' address",
"rdr_toaddress : rdr_to ':' address",
"gateway : via ':' gwaddress",
"routeoption : authmethod",
"routeoption : command",
"routeoption : clientcompatibility",
"routeoption : extension",
"routeoption : protocol",
"routeoption : gssapiservicename",
"routeoption : gssapikeytab",
"routeoption : gssapienctype",
"routeoption : proxyprotocol",
"routeoption : socketoption",
"routeoptions :",
"routeoptions : routeoption routeoptions",
"from : FROM",
"to : TO",
"rdr_from : FROM",
"rdr_to : TO",
"bounceto : TO",
"via : VIA",
"externaladdress : ipaddress",
"externaladdress : domain",
"externaladdress : ifname",
"address : ipaddress '/' netmask port",
"$$7 :",
"address : ipaddress $$7 port",
"address : domain port",
"address : ifname port",
"gwaddress : ipaddress gwport",
"gwaddress : domain gwport",
"gwaddress : ifname gwport",
"gwaddress : url",
"gwaddress : direct",
"ipaddress : IPADDRESS",
"netmask : NUMBER",
"netmask : IPADDRESS",
"domain : DOMAINNAME",
"ifname : IFNAME",
"direct : DIRECT",
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
#line 2362 "config_parse.y"

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
      if (yyin != NULL)
         fclose(yyin);

      /* in case needed to reopen config-file. */
      sockd_priv(SOCKD_PRIV_INITIAL, PRIV_ON);
   }
#endif /* SERVER */

   yyin = fopen(filename, "r");

#if !SOCKS_CLIENT
   if (sockscf.state.inited)
      sockd_priv(SOCKD_PRIV_INITIAL, PRIV_OFF);
#endif /* SERVER */

   if (yyin == NULL
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         swarn("%s: could not open config file %s", function, filename);
      else
         swarnx("%s: not parsing empty config file %s", function, filename);

      haveconfig            = 0;
      sockscf.option.debug  = 1;
   }
   else {
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
       * to parse the config file.
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
      bufused = 0;

   vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (errno)
      swarn("%s", buf);
   else
      swarnx("%s", buf);
}

static void
addnumber(numberc, numberv, number)
   size_t *numberc;
   ssize_t *numberv[];
   const ssize_t number;
{
   const char *function = "addnumber()";

   if ((*numberv = realloc(*numberv, sizeof(**numberv) * (*numberc) + 1))
   == NULL)
      yyerror("%s: could not allocate %lu bytes of memory for adding "
              "number %ld",
              function, (unsigned long)(sizeof(**numberv) * (*numberc) + 1),
              (long)number);

   (*numberv)[(*numberc)++] = number;
}


static void
addrinit(addr, _netmask_required)
   ruleaddr_t *addr;
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
   sockshost_t *addr;
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
    * Check if there is a proxy server configured in the environment.
    * Initially assume there is none.
    */
   *haveproxyserver = 0;

   if ((proxyserver = socks_getenv(ENV_SOCKS4_SERVER, dontcare)) != NULL) {
      proxyprotocol_t proxyprotocol = { .socks_v4 = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv(ENV_SOCKS5_SERVER, dontcare)) != NULL) {
      proxyprotocol_t proxyprotocol = { .socks_v5 = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv(ENV_SOCKS_SERVER, dontcare)) != NULL) {
      proxyprotocol_t proxyprotocol = { .socks_v4 = 1, .socks_v5 = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv(ENV_HTTP_PROXY, dontcare)) != NULL) {
      proxyprotocol_t proxyprotocol = { .http = 1 };

      addproxyserver(proxyserver, &proxyprotocol);
      *haveproxyserver = 1;
   }

   if ((proxyserver = socks_getenv("UPNP_IGD", dontcare)) != NULL) {
      /*
       * Should be either an interface name (the interface to broadcast
       * for a response from the igd-device), "broadcast", to indicate
       * all interfaces, or a full url to the igd.
       */
      route_t route;

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
         struct sockaddr_storage addr, mask;

         if (ifname2sockaddr(proxyserver, 0, TOSA(&addr), TOSA(&mask)) == NULL)
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
            &&  iface->ifa_addr->sa_family == AF_INET) {
               if (iface->ifa_netmask == NULL) {
                  swarn("interface %s missing netmask, skipping",
                        iface->ifa_name);
                  continue;
               }
               socks_autoadd_directroute(
               TOCIN(iface->ifa_addr),
               TOCIN(iface->ifa_netmask));
            }

         freeifaddrs(ifap);
      }
   }
   else
      slog(LOG_DEBUG, "%s: not auto-adding direct routes for lan", function);
}

static void
addproxyserver(proxyserver, proxyprotocol)
   const char *proxyserver;
   const proxyprotocol_t *proxyprotocol;
{
   const char *function = "addproxyserver()";
   struct sockaddr_storage ss;
   route_t route;
   ruleaddr_t raddr;
   char ipstring[INET_ADDRSTRLEN], *portstring, proxyservervis[256];

   bzero(&route, sizeof(route));
   route.gw.state.proxyprotocol = *proxyprotocol;

   str2vis(proxyserver,
           strlen(proxyserver),
           proxyservervis,
           sizeof(proxyservervis));

   slog(LOG_DEBUG,
        "%s: have a %s proxy server set in environment, value %s",
        function,
        proxyprotocols2string(&route.gw.state.proxyprotocol, NULL, 0),
        proxyservervis);

   if (route.gw.state.proxyprotocol.http) {
      char emsg[256];

      if (urlstring2sockaddr(proxyserver, TOSA(&ss), emsg, sizeof(emsg))
      == NULL)
         serrx(EXIT_FAILURE,
               "%s: can't resolve/parse proxy server in string \"%s\": %s",
               function, proxyservervis, emsg);

   }
   else {
      if ((portstring = strchr(proxyserver, ':')) == NULL)
         serrx(EXIT_FAILURE, "%s: illegal format for port specification "
                             "in proxy server %s: missing ':' delimiter",
                             function, proxyservervis);

      if (atoi(portstring + 1) < 1 || atoi(portstring + 1) > 0xffff)
         serrx(EXIT_FAILURE, "%s: illegal value (%d) for port specification "
                             "in proxy server %s: must be between %d and %d",
                             function, atoi(portstring + 1),
                             proxyservervis, 1, 0xffff);

      if (portstring - proxyserver == 0
      || (size_t)(portstring - proxyserver) > sizeof(ipstring) - 1)
         serrx(EXIT_FAILURE,
               "%s: illegal format for ip address specification "
               "in proxy server %s: too short/long",
               function, proxyservervis);

      strncpy(ipstring, proxyserver, (size_t)(portstring - proxyserver));
      ipstring[portstring - proxyserver] = NUL;
      ++portstring;

      bzero(&ss, sizeof(ss));
      SET_SOCKADDR(TOSA(&ss), AF_INET);

      if (inet_pton(TOIN(&ss)->sin_family, ipstring, &TOIN(&ss)->sin_addr) != 1)
         serr(EXIT_FAILURE, "%s: illegal format for ip address "
                            "specification in proxy server %s",
                            function, proxyservervis);
      TOIN(&ss)->sin_port = htons(atoi(portstring));
   }

   route.src.atype                           = SOCKS_ADDR_IPV4;
   route.src.addr.ipv4.ip.s_addr             = htonl(0);
   route.src.addr.ipv4.mask.s_addr           = htonl(0);
   route.src.port.tcp                        = route.src.port.udp = htons(0);
   route.src.operator                        = none;

   route.dst = route.src;

   ruleaddr2sockshost(sockaddr2ruleaddr(TOSA(&ss), &raddr),
                      &route.gw.addr,
                      SOCKS_TCP);

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
   rule_t *rule;
{

   bzero(rule, sizeof(*rule));

   rule->linenumber  = yylineno;

#if HAVE_SOCKS_HOSTID
   rule->hostindex   = 1;
#endif /* HAVE_SOCKS_HOSTID */

   command       = &rule->state.command;
   methodv       = rule->state.methodv;
   methodc       = &rule->state.methodc;
   protocol      = &rule->state.protocol;
   proxyprotocol = &rule->state.proxyprotocol;

   /*
    * default values: same as global.
    */

   timeout       = &rule->timeout;
   *timeout      = sockscf.timeout;

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

   dst = hostid = rdr_from = rdr_to = src;

#if BAREFOOTD
   bounceto = src;
#endif /* BAREFOOTD */
}

#endif /* !SOCKS_CLIENT */
#line 2291 "config_parse.c"
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
case 3:
#line 381 "config_parse.y"
{
#if !SOCKS_CLIENT
      protocol  = &protocolmem;
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
break;
case 5:
#line 392 "config_parse.y"
{ yyval.string = NULL; }
break;
case 11:
#line 402 "config_parse.y"
{ yyval.string = NULL; }
break;
case 15:
#line 409 "config_parse.y"
{
   }
break;
case 33:
#line 433 "config_parse.y"
{
         if (!addedsocketoption(&sockscf.socketoptionc,
                                &sockscf.socketoptionv,
                                &socketopt))
            yywarn("could not add socket option");
   }
break;
case 49:
#line 460 "config_parse.y"
{
      yyerror("given keyword, \"%s\", is deprecated", yyvsp[0].string);
   }
break;
case 50:
#line 465 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;
      route.gw.state  = state;

      socks_addroute(&route, 1);
   }
break;
case 51:
#line 475 "config_parse.y"
{
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
      bzero(&hostid, sizeof(hostid));

      src.atype    = SOCKS_ADDR_IPV4;
      dst.atype    = SOCKS_ADDR_IPV4;
      hostid.atype = SOCKS_ADDR_NOTSET;
   }
break;
case 53:
#line 509 "config_parse.y"
{
         proxyprotocol->socks_v4    = 1;
   }
break;
case 54:
#line 512 "config_parse.y"
{
         proxyprotocol->socks_v5    = 1;
   }
break;
case 55:
#line 515 "config_parse.y"
{
         proxyprotocol->http        = 1;
   }
break;
case 56:
#line 518 "config_parse.y"
{
         proxyprotocol->upnp        = 1;
   }
break;
case 61:
#line 531 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 65:
#line 546 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 69:
#line 561 "config_parse.y"
{
         extension->bind = 1;
   }
break;
case 72:
#line 570 "config_parse.y"
{
#if !SOCKS_CLIENT
#if BAREFOOTD
      yyerror("\"internal:\" specification is not used in %s", PACKAGE);
#endif /* BAREFOOTD */

      addinternal(ruleaddr, SOCKS_TCP);
#endif /* !SOCKS_CLIENT */
   }
break;
case 73:
#line 581 "config_parse.y"
{
#if !SOCKS_CLIENT
   static ruleaddr_t mem;
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
break;
case 74:
#line 598 "config_parse.y"
{
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
break;
case 75:
#line 605 "config_parse.y"
{
#if !SOCKS_CLIENT
      static ruleaddr_t mem;

      addrinit(&mem, 0);
#endif /* !SOCKS_CLIENT */
   }
break;
case 76:
#line 614 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 77:
#line 618 "config_parse.y"
{
      sockscf.external.rotation = ROTATION_SAMESAME;
   }
break;
case 78:
#line 621 "config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
      yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
   }
break;
case 85:
#line 639 "config_parse.y"
{
      if (yyvsp[0].number < 0)
         yyerror("max route fails can not be negative (%ld)  Use \"0\" to "
                 "indicate routes should never be marked as bad",
                 (long)yyvsp[0].number);

      sockscf.routeoptions.maxfail = yyvsp[0].number;
   }
break;
case 86:
#line 647 "config_parse.y"
{
      if (yyvsp[0].number < 0)
         yyerror("route failure expiry time can not be negative (%ld).  "
                 "Use \"0\" to indicate bad route marking should never expire",
                 (long)yyvsp[0].number);

      sockscf.routeoptions.badexpire = yyvsp[0].number;
   }
break;
case 87:
#line 657 "config_parse.y"
{ add_to_errorlog = 1; }
break;
case 89:
#line 660 "config_parse.y"
{ add_to_errorlog = 0; }
break;
case 91:
#line 663 "config_parse.y"
{
   int p;
#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   const userid_t currentuserid = sockscf.uid;;
   userid_t zuid;

   bzero(&zuid, sizeof(zuid));
   if (memcmp(&zuid, &sockscf.uid, sizeof(zuid)) == 0)
      /*
       * We do not enforce that userid must be set before logfiles, so make sure
       * that the old userids, if any, are set before (re)opening logfiles.
       */
      sockscf.uid = olduserid;
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

#if !SOCKS_CLIENT
   sockd_priv(SOCKD_PRIV_INITIAL, PRIV_ON);
#endif /* !SOCKS_CLIENT */

   p = socks_addlogfile(add_to_errorlog ? &sockscf.errlog : &sockscf.log, yyvsp[0].string);

#if !SOCKS_CLIENT
   sockd_priv(SOCKD_PRIV_INITIAL, PRIV_OFF);
#endif /* !SOCKS_CLIENT */

#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   if (p != 0 && ERRNOISACCES(errno) && sockscf.state.inited) {
      /* try again with original euid, before giving up. */
      sockscf.uid.privileged       = sockscf.state.euid;
      sockscf.uid.privileged_isset = 1;

      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
      p= socks_addlogfile(add_to_errorlog ? &sockscf.errlog : &sockscf.log, yyvsp[0].string);
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
   }
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

   if (p != 0)
      /*
       * bad, but what else can we do?
       */
      yyerror("failed to add logfile %s", yyvsp[0].string);


#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   sockscf.uid = currentuserid;
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */
}
break;
case 94:
#line 716 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.child.maxidle.negotiate = SOCKD_FREESLOTS_NEGOTIATE * 2;
      sockscf.child.maxidle.request   = SOCKD_FREESLOTS_REQUEST   * 2;
      sockscf.child.maxidle.io        = SOCKD_FREESLOTS_IO        * 2;
   }
break;
case 95:
#line 722 "config_parse.y"
{
      bzero(&sockscf.child.maxidle, sizeof(sockscf.child.maxidle));
   }
break;
case 96:
#line 725 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.child.maxrequests = yyvsp[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 100:
#line 737 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged         = yyvsp[0].uid;
      sockscf.uid.privileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
break;
case 101:
#line 749 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged         = yyvsp[0].uid;
      sockscf.uid.unprivileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
break;
case 102:
#line 761 "config_parse.y"
{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.libwrap         = yyvsp[0].uid;
      sockscf.uid.libwrap_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#else  /* !HAVE_LIBWRAP && (!SOCKS_CLIENT) */
      yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP (!SOCKS_CLIENT)*/
   }
break;
case 103:
#line 776 "config_parse.y"
{
      struct passwd *pw;

      if ((pw = socks_getpwnam(yyvsp[0].string)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
      else
         yyval.uid = pw->pw_uid;
   }
break;
case 104:
#line 786 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      timeout->tcpio = yyvsp[0].number;
      timeout->udpio = timeout->tcpio;
   }
break;
case 105:
#line 792 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      timeout->tcpio = yyvsp[0].number;
   }
break;
case 106:
#line 796 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      timeout->udpio = yyvsp[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 107:
#line 803 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      timeout->negotiate = yyvsp[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 108:
#line 811 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      timeout->connect = yyvsp[0].number;
   }
break;
case 109:
#line 817 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      timeout->tcp_fin_wait = yyvsp[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 110:
#line 826 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (sockscf.option.debugrunopt == -1)
#endif /* !SOCKS_CLIENT */
          sockscf.option.debug = yyvsp[0].number;
   }
break;
case 113:
#line 838 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_allow_table = strdup(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
      slog(LOG_DEBUG, "libwrap.allow: %s", hosts_allow_table);
#else
      yyerror("libwrap.allow requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 114:
#line 851 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_deny_table = strdup(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
      slog(LOG_DEBUG, "libwrap.deny: %s", hosts_deny_table);
#else
      yyerror("libwrap.deny requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 115:
#line 864 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerror("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
break;
case 116:
#line 872 "config_parse.y"
{
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerror("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 117:
#line 882 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
break;
case 118:
#line 886 "config_parse.y"
{
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 120:
#line 896 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
break;
case 121:
#line 900 "config_parse.y"
{
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 125:
#line 913 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 126:
#line 916 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 127:
#line 923 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 130:
#line 932 "config_parse.y"
{
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETSCHEDULER
      yyerror("setting cpu scheduling policy is not supported on this "
               "platform");
#else /* HAVE_SCHED_SETSCHEDULER */
      cpusetting_t *cpusetting;

      switch (yyvsp[-4].number) {
         case CHILD_MOTHER:
            cpusetting = &sockscf.cpu.mother;
            break;

         case CHILD_NEGOTIATE:
            cpusetting = &sockscf.cpu.negotiate;
            break;

         case CHILD_REQUEST:
            cpusetting = &sockscf.cpu.request;
            break;

         case CHILD_IO:
            cpusetting = &sockscf.cpu.io;
            break;

         default:
            SERRX(yyvsp[-4].number);
      }

      cpusetting->scheduling_isset  = 1;
      cpusetting->policy = yyvsp[-2].number;
      bzero(&cpusetting->param, sizeof(cpusetting->param));
      cpusetting->param.sched_priority = (int)yyvsp[0].number;
#endif /* HAVE_SCHED_SETSCHEDULER */
#endif /* !SOCKS_CLIENT */
   }
break;
case 131:
#line 970 "config_parse.y"
{
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETAFFINITY
      yyerror("setting cpu scheduling affinity is not supported on this "
              "platform");
#else /* HAVE_SCHED_SETAFFINITY */
      cpusetting_t *cpusetting;

      switch (yyvsp[-2].number) {
         case CHILD_MOTHER:
            cpusetting = &sockscf.cpu.mother;
            break;

         case CHILD_NEGOTIATE:
            cpusetting = &sockscf.cpu.negotiate;
            break;

         case CHILD_REQUEST:
            cpusetting = &sockscf.cpu.request;
            break;

         case CHILD_IO:
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
            yyerror("invalid CPU number: %ld.  The CPU number can not be "
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
case 132:
#line 1028 "config_parse.y"
{
#if !SOCKS_CLIENT
      socketopt.level = yyvsp[-1].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 134:
#line 1035 "config_parse.y"
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
case 135:
#line 1046 "config_parse.y"
{
      socketopt.info           = optid2sockopt(yyvsp[0].number);
      SASSERTX(socketopt.info != NULL);

      socketopt.optname        = socketopt.info->value;

      socketoptioncheck(&socketopt);
#endif /* !SOCKS_CLIENT */
   }
break;
case 136:
#line 1057 "config_parse.y"
{
      socketopt.optval.int_val = (int)yyvsp[0].number;
      socketopt.opttype        = int_val;
   }
break;
case 137:
#line 1061 "config_parse.y"
{
      const sockoptvalsym_t *p;

      if (socketopt.info == NULL)
         yyerror("the given socket option is unknown, so can not lookup "
                 "symbolic option value");

      if ((p = optval2valsym(socketopt.info->optid, yyvsp[0].string)) == NULL)
         yyerror("symbolic value \"%s\" is unknown for socket option %s",
                 yyvsp[0].string, sockopt2string(&socketopt, NULL, 0));

      socketopt.optval  = p->symval;
      socketopt.opttype = socketopt.info->argtype;
   }
break;
case 138:
#line 1078 "config_parse.y"
{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 1;
   }
break;
case 139:
#line 1081 "config_parse.y"
{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 0;
   }
break;
case 140:
#line 1087 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.socket.udp.sndbuf = yyvsp[0].number;
   }
break;
case 141:
#line 1092 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.socket.udp.rcvbuf = yyvsp[0].number;
   }
break;
case 142:
#line 1096 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.socket.tcp.sndbuf = yyvsp[0].number;
   }
break;
case 143:
#line 1100 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.socket.tcp.rcvbuf = yyvsp[0].number;
#if BAREFOOTD
   }
break;
case 144:
#line 1105 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.socket.clientside_udp.sndbuf = yyvsp[0].number;
   }
break;
case 145:
#line 1109 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].number, >=, 0);
      sockscf.socket.clientside_udp.rcvbuf = yyvsp[0].number;
#endif /* BAREFOOTD */

#endif /* !SOCKS_CLIENT */
   }
break;
case 147:
#line 1122 "config_parse.y"
{
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
break;
case 148:
#line 1126 "config_parse.y"
{
         sockscf.srchost.nodnsunknown = 1;
   }
break;
case 149:
#line 1129 "config_parse.y"
{
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 152:
#line 1139 "config_parse.y"
{
#if COVENANT
   if (strlen(yyvsp[0].string) >= sizeof(sockscf.realmname))
      yyerror("realmname \"%s\" is too long.  Recompilation of %s required "
              "is required if you want to use a name longer than %d characters",
               yyvsp[0].string, PACKAGE,
               sizeof(sockscf.realmname) - 1);

   strcpy(sockscf.realmname, yyvsp[0].string);
#else /* !COVENANT */
   yyerror("unknown keyword \"%s\"", yyvsp[-2].string);
#endif /* !COVENANT */
}
break;
case 156:
#line 1161 "config_parse.y"
{
#if SOCKS_SERVER
      methodv  = sockscf.methodv;
      methodc  = &sockscf.methodc;
      *methodc = 0; /* reset. */
#else
      yyerror("\"clientmethod\" is used for the global method line in %s, "
              "not \"%s\"",
              PACKAGE, yyvsp[-1].string);
#endif /* !SOCKS_SERVER */
   }
break;
case 158:
#line 1174 "config_parse.y"
{
#if !SOCKS_CLIENT
   methodv  = sockscf.clientmethodv;
   methodc  = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif /* !SOCKS_CLIENT */
   }
break;
case 160:
#line 1183 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_NONE);
   }
break;
case 161:
#line 1186 "config_parse.y"
{
#if !HAVE_GSSAPI
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#else
      ADDMETHOD(AUTHMETHOD_GSSAPI);
#endif /* !HAVE_GSSAPI */
   }
break;
case 162:
#line 1193 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
break;
case 163:
#line 1196 "config_parse.y"
{
#if HAVE_LIBWRAP
      ADDMETHOD(AUTHMETHOD_RFC931);
#else
      yyerror("method %s requires libwrap library", AUTHMETHOD_RFC931s);
#endif /* HAVE_LIBWRAP */
   }
break;
case 164:
#line 1203 "config_parse.y"
{
#if HAVE_PAM
      ADDMETHOD(AUTHMETHOD_PAM);
#else /* !HAVE_PAM */
      yyerror("method %s requires pam library", AUTHMETHOD_PAMs);
#endif /* HAVE_PAM */
   }
break;
case 165:
#line 1210 "config_parse.y"
{
#if HAVE_BSDAUTH
      ADDMETHOD(AUTHMETHOD_BSDAUTH);
#else /* !HAVE_PAM */
      yyerror("method %s requires bsd authentication", AUTHMETHOD_BSDAUTHs);
#endif /* HAVE_PAM */
   }
break;
case 166:
#line 1225 "config_parse.y"
{

#if !SOCKS_CLIENT
      rule.src         = src;
      rule.dst         = dst;

#if HAVE_SOCKS_HOSTID
      rule.hostid      = hostid;
#endif /* HAVE_SOCKS_HOSTID */

      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

#if BAREFOOTD
      if (bounceto.atype == SOCKS_ADDR_NOTSET) {
         if (rule.verdict == VERDICT_PASS)
            yyerror("no address traffic should bounce to has been given");
         else {
            /*
             * allow no bounce-to if it is a block, as the bounce-to address
             * will not be used in any case then.
             */
            bounceto.atype                 = SOCKS_ADDR_IPV4;
            bounceto.addr.ipv4.ip.s_addr   = htonl(INADDR_ANY);
            bounceto.addr.ipv4.mask.s_addr = htonl(0xffffffff);
            bounceto.port.tcp              = bounceto.port.udp = htons(0);
            bounceto.operator              = none;
         }
      }

      rule.extra.bounceto = bounceto;
#endif /* BAREFOOTD */

      addclientrule(&rule);
      rulereset();
#endif /* !SOCKS_CLIENT */
   }
break;
case 168:
#line 1265 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 169:
#line 1272 "config_parse.y"
{ yyval.string = NULL; }
break;
case 171:
#line 1277 "config_parse.y"
{

#if !SOCKS_CLIENT
#if !HAVE_SOCKS_HOSTID
      yyerror("hostid rules are not supported on this system");
#else
      rule.src         = src;
      rule.dst         = dst;


      if (hostid.atype != SOCKS_ADDR_NOTSET)
         yyerror("it does not make sense to set the hostid address in a "
                 "hostid-rule.  Use the \"from\" address to match the hostid "
                 "of the client");

      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

      addhostidrule(&rule);
      rulereset();
#endif /* HAVE_SOCKS_HOSTID */
#endif /* !SOCKS_CLIENT */
   }
break;
case 174:
#line 1306 "config_parse.y"
{
#if !HAVE_SOCKS_HOSTID
      yyerror("hostid is not supported on this system");
#else /* HAVE_SOCKS_HOSTID */
      addrinit(&hostid, 1);
#endif /* HAVE_SOCKS_HOSTID */
   }
break;
case 176:
#line 1315 "config_parse.y"
{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
   rule.hostindex = yyvsp[0].number;
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
}
break;
case 177:
#line 1323 "config_parse.y"
{
#if !SOCKS_CLIENT
      rule.src         = src;
      rule.dst         = dst;

#if HAVE_SOCKS_HOSTID
      rule.hostid      = hostid;
#endif /* HAVE_SOCKS_HOSTID */

      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

#if !HAVE_SOCKS_RULES
   yyerror("socks-rules are not used in %s", PACKAGE);
#endif /* !HAVE_SOCKS_RULES */

      addsocksrule(&rule);
      rulereset();
#endif /* !SOCKS_CLIENT */
   }
break;
case 183:
#line 1353 "config_parse.y"
{ yyval.string = NULL; }
break;
case 186:
#line 1358 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("bandwidth");
#endif /* !SOCKS_CLIENT */
   }
break;
case 187:
#line 1363 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 226:
#line 1410 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
break;
case 227:
#line 1415 "config_parse.y"
{
#if !SOCKS_CLIENT
         if (rule.verdict == VERDICT_BLOCK && !socketopt.isinternalside)
            yyerror("it does not make sense to set a socket option for the "
                    "external side in a rule that blocks access; the external "
                    "side will never be accessed as the rule blocks access "
                    "to it");

         if (socketopt.isinternalside)
            if (socketopt.info != NULL && socketopt.info->calltype == preonly)
               yywarn("To our knowledge the socket option \"%s\" can only be "
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
case 228:
#line 1438 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("session");
#endif /* !SOCKS_CLIENT */
   }
break;
case 231:
#line 1447 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->debug = (int)yyvsp[0].number;
   }
break;
case 232:
#line 1452 "config_parse.y"
{
      ldap->debug = (int)-yyvsp[0].number;
 #else /* !HAVE_LDAP */
      yyerror("ldap debug support requires openldap support");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 233:
#line 1461 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.domain))
         yyerror("filter too long");
      strcpy(ldap->domain, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 234:
#line 1474 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->mdepth = (int)yyvsp[0].number;
#else /* !HAVE_LDAP */
      yyerror("ldap debug support requires openldap support");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 235:
#line 1485 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.certfile))
         yyerror("ca cert file name too long");
      strcpy(ldap->certfile, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 236:
#line 1498 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.certpath))
         yyerror("cert db path too long");
      strcpy(ldap->certpath, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 237:
#line 1511 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapurl, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 238:
#line 1523 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapbasedn, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 239:
#line 1535 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapbasedn, hextoutf8(yyvsp[0].string, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 240:
#line 1547 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.state.ldap.ldapbasedn, hextoutf8(yyvsp[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 241:
#line 1559 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->port = (int)yyvsp[0].number;
#else /* !HAVE_LDAP */
   yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 242:
#line 1570 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->portssl = (int)yyvsp[0].number;
#else /* !HAVE_LDAP */
   yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 243:
#line 1581 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->ssl = 1;
   }
break;
case 244:
#line 1586 "config_parse.y"
{
      ldap->ssl = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 245:
#line 1595 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->auto_off = 1;
   }
break;
case 246:
#line 1600 "config_parse.y"
{
      ldap->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 247:
#line 1609 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->certcheck = 1;
   }
break;
case 248:
#line 1614 "config_parse.y"
{
      ldap->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 249:
#line 1623 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->keeprealm = 1;
   }
break;
case 250:
#line 1628 "config_parse.y"
{
      ldap->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 251:
#line 1637 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.filter))
         yyerror("filter too long");
      strcpy(ldap->filter, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 252:
#line 1650 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.filter_AD))
         yyerror("AD filter too long");
      strcpy(ldap->filter_AD, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 253:
#line 1663 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string)/2 >= sizeof(state.ldap.filter))
         yyerror("filter too long");
      strcpy(ldap->filter, hextoutf8(yyvsp[0].string, 2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 254:
#line 1676 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string)/2 >= sizeof(state.ldap.filter_AD))
         yyerror("AD filter too long");
      strcpy(ldap->filter_AD, hextoutf8(yyvsp[0].string,2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 255:
#line 1689 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.attribute))
         yyerror("attribute too long");
      strcpy(ldap->attribute, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 256:
#line 1702 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.attribute_AD))
         yyerror("AD attribute too long");
      strcpy(ldap->attribute_AD, yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 257:
#line 1715 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) / 2 >= sizeof(state.ldap.attribute))
         yyerror("attribute too long");
      strcpy(ldap->attribute, hextoutf8(yyvsp[0].string, 2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 258:
#line 1728 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (strlen(yyvsp[0].string) / 2 >= sizeof(state.ldap.attribute_AD))
         yyerror("AD attribute too long");
      strcpy(ldap->attribute_AD, hextoutf8(yyvsp[0].string, 2));
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 259:
#line 1741 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8(yyvsp[0].string, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 260:
#line 1753 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, hextoutf8(yyvsp[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 261:
#line 1767 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, asciitoutf8(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 262:
#line 1781 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapserver, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 263:
#line 1793 "config_parse.y"
{
#if HAVE_LDAP
#if SOCKS_SERVER
      if (strlen(yyvsp[0].string) >= sizeof(state.ldap.keytab))
         yyerror("keytab name too long");
      strcpy(ldap->keytab, yyvsp[0].string);
#else
      yyerror("ldap keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* HAVE_LDAP */
   }
break;
case 265:
#line 1811 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#endif /* HAVE_GSSAPI */
   }
break;
case 268:
#line 1825 "config_parse.y"
{
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 269:
#line 1830 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
   }
break;
case 273:
#line 1844 "config_parse.y"
{
         command->bind = 1;
   }
break;
case 274:
#line 1847 "config_parse.y"
{
         command->connect = 1;
   }
break;
case 275:
#line 1850 "config_parse.y"
{
         command->udpassociate = 1;
   }
break;
case 276:
#line 1856 "config_parse.y"
{
         command->bindreply = 1;
   }
break;
case 277:
#line 1860 "config_parse.y"
{
         command->udpreply = 1;
   }
break;
case 281:
#line 1873 "config_parse.y"
{
      protocol->tcp = 1;
   }
break;
case 282:
#line 1876 "config_parse.y"
{
      protocol->udp = 1;
   }
break;
case 288:
#line 1893 "config_parse.y"
{
#if !SOCKS_CLIENT
   static shmem_object_t ssinit;

   CHECKNUMBER(yyvsp[0].number, >=, 0);

   if (pidismother(sockscf.state.pid) == 1) {
      if ((rule.ss = malloc(sizeof(*rule.ss))) == NULL)
         yyerror("failed to malloc %lu bytes for ss memory",
         (unsigned long)sizeof(*rule.ss));

      *rule.ss                       = ssinit;
      rule.ss->object.ss.maxsessions = yyvsp[0].number;
   }
   else
      rule.ss = &ssinit;

   rule.ss_fd = -1;
#endif /* !SOCKS_CLIENT */
}
break;
case 289:
#line 1915 "config_parse.y"
{
#if !SOCKS_CLIENT
   static shmem_object_t bwmeminit;

   CHECKNUMBER(yyvsp[0].number, >=, 0);

   if (pidismother(sockscf.state.pid) == 1) {
      if ((rule.bw = malloc(sizeof(*rule.bw))) == NULL)
         yyerror("failed to malloc %lu bytes for bw memory",
         (unsigned long)sizeof(*rule.bw));

      *rule.bw                  = bwmeminit;
      rule.bw->object.bw.maxbps = yyvsp[0].number;
   }
   else
      rule.bw = &bwmeminit;

   rule.bw_fd = -1;
#endif /* !SOCKS_CLIENT */
}
break;
case 291:
#line 1941 "config_parse.y"
{
#if !SOCKS_CLIENT
   rule.log.connect = 1;
   }
break;
case 292:
#line 1945 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 293:
#line 1948 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 294:
#line 1951 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 295:
#line 1954 "config_parse.y"
{
         rule.log.iooperation = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 298:
#line 1965 "config_parse.y"
{
#if HAVE_PAM && (!SOCKS_CLIENT)
      if (strlen(yyvsp[0].string) >= sizeof(rule.state.pamservicename))
         yyerror("servicename too long");
      strcpy(rule.state.pamservicename, yyvsp[0].string);
#else
      yyerror("pam support not compiled in");
#endif /* HAVE_PAM && (!SOCKS_CLIENT) */
   }
break;
case 299:
#line 1976 "config_parse.y"
{
#if HAVE_BSDAUTH && SOCKS_SERVER
      if (strlen(yyvsp[0].string) >= sizeof(rule.state.bsdauthstylename))
         yyerror("bsdauthstyle too long");
      strcpy(rule.state.bsdauthstylename, yyvsp[0].string);
#else
      yyerror("bsdauth support not compiled in");
#endif /* HAVE_BSDAUTH && SOCKS_SERVER */
   }
break;
case 300:
#line 1988 "config_parse.y"
{
#if HAVE_GSSAPI
      if (strlen(yyvsp[0].string) >= sizeof(state.gssapiservicename))
         yyerror("service name too long");
      strcpy(gssapiservicename, yyvsp[0].string);
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
break;
case 301:
#line 1999 "config_parse.y"
{
#if HAVE_GSSAPI
#if SOCKS_SERVER
      if (strlen(yyvsp[0].string) >= sizeof(state.gssapikeytab))
         yyerror("keytab name too long");
      strcpy(gssapikeytab, yyvsp[0].string);
#else
      yyerror("gssapi keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
break;
case 303:
#line 2017 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 304:
#line 2023 "config_parse.y"
{
      gssapiencryption->clear = 1;
   }
break;
case 305:
#line 2026 "config_parse.y"
{
      gssapiencryption->integrity = 1;
   }
break;
case 306:
#line 2029 "config_parse.y"
{
      gssapiencryption->confidentiality = 1;
   }
break;
case 307:
#line 2032 "config_parse.y"
{
      yyerror("gssapi per-message encryption not supported");
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
break;
case 311:
#line 2047 "config_parse.y"
{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
      struct request_info request;
      char libwrap[LIBWRAPBUF];
      int errno_s, devnull;

      if (strlen(yyvsp[0].string) >= sizeof(rule.libwrap))
         yyerror("libwrapline too long, make LIBWRAPBUF bigger");
      strcpy(rule.libwrap, yyvsp[0].string);

      /* libwrap modifies the passed buffer. */
      SASSERTX(strlen(rule.libwrap) < sizeof(libwrap));
      strcpy(libwrap, rule.libwrap);

      devnull = open("/dev/null", O_RDWR, 0);
      ++dry_run;
      errno_s = errno;

      errno = 0;

      request_init(&request, RQ_FILE, devnull, RQ_DAEMON, __progname, 0);
      if (setjmp(tcpd_buf) != 0)
         yyerror("bad libwrap line");
      process_options(libwrap, &request);

      if (errno != 0)
         yywarn("possible libwrap/tcp-wrappers related configuration error "
                "detected here:");
      --dry_run;
      close(devnull);
      errno = errno_s;

#else
      yyerror("libwrap support not compiled in");
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

   }
break;
case 326:
#line 2112 "config_parse.y"
{
         if (!addedsocketoption(&route.socketoptionc,
                                &route.socketoptionv,
                                &socketopt))
            yywarn("could not add socketoption");
   }
break;
case 327:
#line 2120 "config_parse.y"
{ yyval.string = NULL; }
break;
case 329:
#line 2124 "config_parse.y"
{
      addrinit(&src, 1);
   }
break;
case 330:
#line 2129 "config_parse.y"
{
      addrinit(&dst,
#if SOCKS_SERVER
               1
#else /* BAREFOOTD || COVENANT */
               0 /* the address the server should bind, so must be /32. */
#endif /*  BAREFOOTD || COVENANT */
      );
   }
break;
case 331:
#line 2140 "config_parse.y"
{
      addrinit(&rdr_from, 1);
   }
break;
case 332:
#line 2145 "config_parse.y"
{
      addrinit(&rdr_to, 1);
   }
break;
case 333:
#line 2150 "config_parse.y"
{
#if BAREFOOTD
      addrinit(&bounceto, 0);
#endif /* BAREFOOTD */
   }
break;
case 334:
#line 2158 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 339:
#line 2170 "config_parse.y"
{
         if (netmask_required)
            yyerror("no netmask given");
         else
            netmask->s_addr = htonl(0xffffffff);
       }
break;
case 348:
#line 2188 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton(yyvsp[0].string, ipaddr) != 1)
         yyerror("bad address: %s", yyvsp[0].string);
   }
break;
case 349:
#line 2197 "config_parse.y"
{
      if (yyvsp[0].number < 0 || yyvsp[0].number > 32)
         yyerror("bad netmask: %ld", (long)yyvsp[0].number);

      netmask->s_addr = yyvsp[0].number == 0 ? 0 : htonl(0xffffffff << (32 - yyvsp[0].number));
   }
break;
case 350:
#line 2203 "config_parse.y"
{
         if (!inet_aton(yyvsp[0].string, netmask))
            yyerror("bad netmask: %s", yyvsp[0].string);
   }
break;
case 351:
#line 2209 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");

      strcpy(domain, yyvsp[0].string);
   }
break;
case 352:
#line 2219 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
         yyerror("interface name too long");

      strcpy(ifname, yyvsp[0].string);
   }
break;
case 353:
#line 2230 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", yyvsp[0].string);
      strcpy(domain, yyvsp[0].string);

      proxyprotocol->direct = 1;
   }
break;
case 354:
#line 2241 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;

      if (strlen(yyvsp[0].string) >= MAXURLLEN)
         yyerror("url \"%s\" too long", yyvsp[0].string);

      strcpy(url, yyvsp[0].string);
   }
break;
case 355:
#line 2252 "config_parse.y"
{ yyval.number = 0; }
break;
case 359:
#line 2258 "config_parse.y"
{ yyval.number = 0; }
break;
case 363:
#line 2266 "config_parse.y"
{
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerror("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
break;
case 364:
#line 2274 "config_parse.y"
{
      CHECKPORTNUMBER(yyvsp[0].number);
      *port_tcp   = htons((in_port_t)yyvsp[0].number);
      *port_udp   = htons((in_port_t)yyvsp[0].number);
   }
break;
case 365:
#line 2281 "config_parse.y"
{
      CHECKPORTNUMBER(yyvsp[0].number);
      ruleaddr->portend    = htons((in_port_t)yyvsp[0].number);
      ruleaddr->operator   = range;
   }
break;
case 366:
#line 2288 "config_parse.y"
{
      struct servent   *service;

      if ((service = getservbyname(yyvsp[0].string, "tcp")) == NULL) {
         if (protocol->tcp)
            yyerror("unknown tcp protocol: %s", yyvsp[0].string);
         *port_tcp = htons(0);
      }
      else
         *port_tcp = (in_port_t)service->s_port;

      if ((service = getservbyname(yyvsp[0].string, "udp")) == NULL) {
         if (protocol->udp)
               yyerror("unknown udp protocol: %s", yyvsp[0].string);
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

      yyval.number = (size_t)*port_udp;
   }
break;
case 367:
#line 2321 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 369:
#line 2330 "config_parse.y"
{
#if SOCKS_SERVER
   CHECKPORTNUMBER(yyvsp[0].number);
   rule.udprange.start = htons((in_port_t)yyvsp[0].number);
#endif /* SOCKS_SERVER */
   }
break;
case 370:
#line 2338 "config_parse.y"
{
#if SOCKS_SERVER
   CHECKPORTNUMBER(yyvsp[0].number);
   rule.udprange.end = htons((in_port_t)yyvsp[0].number);
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerror("end port (%d) can not be less than start port (%u)",
              (int)yyvsp[0].number, ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
break;
case 371:
#line 2351 "config_parse.y"
{
      addnumber(&numberc, &numberv, yyvsp[0].number);
   }
break;
#line 4431 "config_parse.c"
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
