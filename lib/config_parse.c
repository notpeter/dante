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
#include "ifaddrs_compat.h"
#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.383 2011/05/12 17:14:34 michaels Exp $";

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
      CHECKNUMBER(portnumber, >, 0);                                           \
      CHECKNUMBER(portnumber, <, 65536);                                       \
} while (0)

static void
addrinit(struct ruleaddr_t *addr, const int netmask_required);

static void
gwaddrinit(gwaddr_t *addr);

#if SOCKS_CLIENT
/* parses client environment, if any. */
static void parseclientenv(void);


#else /* !SOCKS_CLIENT */

/*
 * Reset pointers to point away from rule-spesific memory to global
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

#line 179 "config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
   char   *string;
   uid_t   uid;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 179 "config_parse.c"
#define SERVERCONFIG 257
#define CLIENTCONFIG 258
#define DEPRECATED 259
#define CLIENTRULE 260
#define INTERNAL 261
#define EXTERNAL 262
#define REALM 263
#define REALNAME 264
#define EXTERNAL_ROTATION 265
#define SAMESAME 266
#define DEBUGGING 267
#define RESOLVEPROTOCOL 268
#define SOCKET 269
#define CLIENTSIDE_SOCKET 270
#define SNDBUF 271
#define RCVBUF 272
#define SRCHOST 273
#define NODNSMISMATCH 274
#define NODNSUNKNOWN 275
#define CHECKREPLYAUTH 276
#define EXTENSION 277
#define BIND 278
#define PRIVILEGED 279
#define IOTIMEOUT 280
#define IOTIMEOUT_TCP 281
#define IOTIMEOUT_UDP 282
#define NEGOTIATETIMEOUT 283
#define CONNECTTIMEOUT 284
#define TCP_FIN_WAIT 285
#define METHOD 286
#define CLIENTMETHOD 287
#define NONE 288
#define GSSAPI 289
#define UNAME 290
#define RFC931 291
#define PAM 292
#define BSDAUTH 293
#define COMPATIBILITY 294
#define SAMEPORT 295
#define DRAFT_5_05 296
#define CLIENTCOMPATIBILITY 297
#define NECGSSAPI 298
#define USERNAME 299
#define GROUPNAME 300
#define USER_PRIVILEGED 301
#define USER_UNPRIVILEGED 302
#define USER_LIBWRAP 303
#define LIBWRAP_FILE 304
#define ERRORLOG 305
#define LOGOUTPUT 306
#define LOGFILE 307
#define CHILD_MAXIDLE 308
#define CHILD_MAXREQUESTS 309
#define ROUTE 310
#define VIA 311
#define BADROUTE_EXPIRE 312
#define MAXFAIL 313
#define VERDICT_BLOCK 314
#define VERDICT_PASS 315
#define PAMSERVICENAME 316
#define BSDAUTHSTYLENAME 317
#define BSDAUTHSTYLE 318
#define GSSAPISERVICE 319
#define GSSAPIKEYTAB 320
#define GSSAPIENCTYPE 321
#define GSSAPIENC_ANY 322
#define GSSAPIENC_CLEAR 323
#define GSSAPIENC_INTEGRITY 324
#define GSSAPIENC_CONFIDENTIALITY 325
#define GSSAPIENC_PERMESSAGE 326
#define GSSAPISERVICENAME 327
#define GSSAPIKEYTABNAME 328
#define PROTOCOL 329
#define PROTOCOL_TCP 330
#define PROTOCOL_UDP 331
#define PROTOCOL_FAKE 332
#define PROXYPROTOCOL 333
#define PROXYPROTOCOL_SOCKS_V4 334
#define PROXYPROTOCOL_SOCKS_V5 335
#define PROXYPROTOCOL_HTTP 336
#define PROXYPROTOCOL_UPNP 337
#define USER 338
#define GROUP 339
#define COMMAND 340
#define COMMAND_BIND 341
#define COMMAND_CONNECT 342
#define COMMAND_UDPASSOCIATE 343
#define COMMAND_BINDREPLY 344
#define COMMAND_UDPREPLY 345
#define ACTION 346
#define LINE 347
#define LIBWRAPSTART 348
#define LIBWRAP_ALLOW 349
#define LIBWRAP_DENY 350
#define LIBWRAP_HOSTS_ACCESS 351
#define OPERATOR 352
#define SOCKS_LOG 353
#define SOCKS_LOG_CONNECT 354
#define SOCKS_LOG_DATA 355
#define SOCKS_LOG_DISCONNECT 356
#define SOCKS_LOG_ERROR 357
#define SOCKS_LOG_IOOPERATION 358
#define IPADDRESS 359
#define DOMAINNAME 360
#define DIRECT 361
#define IFNAME 362
#define URL 363
#define PORT 364
#define SERVICENAME 365
#define NUMBER 366
#define FROM 367
#define TO 368
#define REDIRECT 369
#define BANDWIDTH 370
#define MAXSESSIONS 371
#define UDPPORTRANGE 372
#define UDPCONNECTDST 373
#define YES 374
#define NO 375
#define BOUNCE 376
#define LDAPURL 377
#define LDAP_URL 378
#define LDAPSSL 379
#define LDAPCERTCHECK 380
#define LDAPKEEPREALM 381
#define LDAPBASEDN 382
#define LDAP_BASEDN 383
#define LDAPBASEDN_HEX 384
#define LDAPBASEDN_HEX_ALL 385
#define LDAPSERVER 386
#define LDAPSERVER_NAME 387
#define LDAPGROUP 388
#define LDAPGROUP_NAME 389
#define LDAPGROUP_HEX 390
#define LDAPGROUP_HEX_ALL 391
#define LDAPFILTER 392
#define LDAPFILTER_AD 393
#define LDAPFILTER_HEX 394
#define LDAPFILTER_AD_HEX 395
#define LDAPATTRIBUTE 396
#define LDAPATTRIBUTE_AD 397
#define LDAPATTRIBUTE_HEX 398
#define LDAPATTRIBUTE_AD_HEX 399
#define LDAPCERTFILE 400
#define LDAPCERTPATH 401
#define LDAPPORT 402
#define LDAPPORTSSL 403
#define LDAP_FILTER 404
#define LDAP_ATTRIBUTE 405
#define LDAP_CERTFILE 406
#define LDAP_CERTPATH 407
#define LDAPDOMAIN 408
#define LDAP_DOMAIN 409
#define LDAPTIMEOUT 410
#define LDAPCACHE 411
#define LDAPCACHEPOS 412
#define LDAPCACHENEG 413
#define LDAPKEYTAB 414
#define LDAPKEYTABNAME 415
#define LDAPDEADTIME 416
#define LDAPDEBUG 417
#define LDAPDEPTH 418
#define LDAPAUTO 419
#define LDAPSEARCHTIME 420
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   68,    1,   71,   71,   72,   72,   72,    2,
    2,    2,    2,   36,   37,   37,   70,   70,   69,   69,
   69,   69,   69,   69,   69,   69,   69,   69,   69,   69,
   69,   69,   69,   67,   67,   67,   67,   67,   67,   67,
   67,   39,   39,   39,   39,    3,  117,   30,    7,    8,
    8,    8,    8,    8,    9,    9,   10,   11,   12,   12,
   13,   14,   15,   15,   44,   45,   46,   46,   47,   48,
   49,   50,   51,   51,   51,   38,   38,   38,   38,   38,
  116,  116,  157,   52,  158,   53,   54,   55,   55,   78,
   78,   78,   73,   73,   73,   74,   75,   76,   77,   40,
   40,   40,   41,   42,   43,   34,   83,   83,   84,   85,
   86,   86,   87,   87,   56,   57,   57,   58,   58,   21,
   22,   22,   22,   23,   23,   23,   23,   23,   23,   24,
   25,   25,   25,   26,   26,   35,   61,   62,   62,  159,
   59,  160,   60,   63,   63,   63,   63,   63,   63,  125,
  126,  126,  126,  126,  127,  127,  122,  123,  123,  123,
  123,  123,  123,  123,  124,  124,  128,  128,  128,  128,
  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
  128,  128,  128,  128,  128,  128,  128,  128,  112,  112,
  103,  113,  108,  109,   88,   92,   93,   94,  114,  115,
   89,   89,  111,  111,   90,   90,   91,   91,   99,  100,
  101,  102,  104,  105,  106,  107,   97,   98,   96,   95,
  110,   64,   65,   66,   66,  129,  129,   27,   28,   28,
   29,   29,   29,   29,   29,    4,    5,    5,    6,    6,
  130,   79,   79,   79,   81,   82,   80,  131,  133,  133,
  133,  133,  133,  132,  132,   16,   17,   18,   19,   20,
  164,  164,  164,  164,  164,  163,  163,  155,  134,  135,
  136,  161,  162,  119,  120,  120,  120,  120,  120,  120,
  120,  120,  120,  121,  121,  145,  146,  165,  166,  156,
  118,  137,  137,  137,  138,  167,  138,  138,  138,  140,
  140,  140,  140,  140,  139,  147,  147,  141,  142,  143,
  144,  148,  148,  148,  148,  149,  149,  153,  153,  150,
  151,  168,  154,  152,   31,   32,   33,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylen[] =
#else
short socks_yylen[] =
#endif
	{                                         2,
    2,    2,    1,    2,    0,    2,    1,    1,    1,    0,
    2,    2,    2,    1,    1,    1,    1,    2,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    8,    0,    3,    1,
    1,    1,    1,    1,    1,    2,    3,    1,    1,    2,
    3,    1,    1,    2,    3,    1,    1,    2,    4,    0,
    4,    0,    3,    3,    3,    1,    1,    1,    1,    1,
    5,    5,    0,    4,    0,    4,    1,    1,    2,    3,
    3,    3,    1,    1,    1,    3,    3,    3,    1,    3,
    3,    3,    3,    3,    3,    3,    1,    1,    3,    3,
    3,    3,    3,    3,    3,    1,    1,    1,    2,    3,
    1,    1,    1,    7,    7,    7,    7,    7,    7,    3,
    1,    1,    1,    1,    2,    3,    3,    1,    2,    0,
    4,    0,    4,    1,    1,    1,    1,    1,    1,    7,
    1,    1,    1,    1,    0,    2,    6,    1,    1,    1,
    1,    1,    1,    1,    0,    2,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    3,    4,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    1,    1,    2,    1,    1,    3,    1,    2,
    1,    1,    1,    1,    1,    3,    1,    2,    1,    1,
    2,    3,    2,    2,    1,    3,    3,    3,    1,    1,
    1,    1,    1,    1,    2,    3,    3,    3,    3,    3,
    1,    1,    1,    1,    1,    1,    2,    4,    3,    3,
    3,    3,    3,    3,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    0,    2,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    4,    0,    3,    2,    2,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    0,    3,    3,    2,    0,    3,    1,    1,    3,
    1,    1,    1,    1,    5,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    3,   14,    0,   10,    0,    0,   46,   70,   72,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    1,   21,
   37,   39,   40,   30,   38,   41,   43,   44,   42,   45,
   35,   22,   23,   24,   25,   26,   34,   19,   20,   27,
   17,    0,   28,   93,   94,   95,   29,   31,  107,  108,
   32,   33,   36,    0,   11,   16,   79,   76,   12,   15,
   80,   78,   77,   13,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  140,  142,    0,    0,    0,    0,   83,   85,    0,    0,
    0,    0,    0,    0,    0,    0,  246,  247,   18,    4,
    0,    9,    8,    7,    0,    0,    0,    0,  136,   74,
   73,   75,  106,  122,  123,  121,  120,    0,    0,    0,
    0,  131,  132,  133,    0,  130,   66,    0,   65,  100,
  101,  102,  103,  104,  105,    0,    0,  116,  117,    0,
  115,   99,   96,   97,   98,    0,    0,   90,   91,   92,
    0,    0,  109,  110,  111,  112,  113,  114,    0,   48,
    6,    0,    0,  325,  328,  329,   69,    0,    0,    0,
   71,  312,  313,  314,    0,    0,    0,    0,  135,   68,
  144,  145,  146,  147,  148,  149,  141,    0,  143,  119,
   87,    0,   84,   86,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  162,  163,  204,  205,  171,  172,
  173,  174,  175,  160,  161,  206,  167,  168,  164,  159,
  208,  265,  176,  186,  187,  188,  181,  182,  183,  202,
  199,  200,  201,  189,  191,  193,  195,  178,  190,  192,
  194,  196,  197,  198,  203,  177,  179,  180,  184,  185,
    0,    0,  158,  170,  169,  207,  298,  302,  299,  300,
  301,  295,  297,  303,  296,    0,    0,    0,    0,    0,
  318,  319,    0,    0,    0,    0,    0,    0,  139,   89,
   82,   81,  153,  154,  152,    0,    0,  151,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  308,  309,    0,  264,    0,    0,    0,    0,
    0,  310,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  166,  306,    0,    0,    0,  305,    0,  327,  326,
    0,  317,  344,  341,    0,  335,    0,    0,    0,    0,
    0,    0,    0,    0,  156,    0,  137,  243,    0,  242,
  276,  277,  278,  279,  281,  282,  283,  284,  285,  280,
    0,  259,  260,  256,    0,   50,   51,   52,   53,   54,
    0,   49,   58,    0,   57,   62,    0,   61,  251,  252,
  253,  254,  255,  248,    0,  289,  269,  270,  271,  272,
  273,  268,    0,  262,    0,    0,  267,  266,  346,    0,
    0,  215,  221,  222,  225,  226,  227,  228,  216,  217,
  218,  240,  239,  237,  238,  229,  230,  231,  232,  233,
  234,  235,  236,  213,  214,  219,  220,  211,  241,  209,
    0,  212,  223,  224,    0,  307,  261,    0,    0,  311,
    0,    0,  315,  343,  339,  333,  338,    0,  334,  126,
  124,  127,  125,  128,  129,    0,  245,  287,  258,   56,
   60,   64,  250,  275,  292,  293,    0,  288,  210,  157,
    0,  290,    0,    0,  342,  340,  150,  347,  345,  291,
  330,  331,    0,  294,    0,    0,  324,  323,   47,    0,
  320,  321,  322,    0,  337,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
   39,    6,   40,  265,  444,  445,  266,  451,  452,  267,
  454,  455,  268,  457,  458,  269,  270,  271,  272,  273,
   41,  137,   42,   43,  145,  146,  274,  464,  465,  126,
  275,  480,  559,   44,   45,    4,   79,   80,  276,   47,
   48,   49,   50,  323,  148,  149,   52,   85,   53,   86,
   54,   55,   56,  212,  213,   57,  160,  161,   58,   59,
  277,  207,  208,  278,  429,  430,   60,    5,   61,   62,
  120,  121,   63,   64,   65,   66,  163,   67,  279,  280,
  281,  282,   68,   69,   70,   71,   72,  283,  284,  285,
  286,  287,  288,  289,  290,  291,  292,  293,  294,  295,
  296,  297,  298,  299,  300,  301,  302,  303,  304,  305,
  306,  307,  308,  309,  310,   73,  122,  521,  522,  326,
  327,  123,  311,  312,  124,  346,  347,  313,  125,  404,
  314,  472,  473,  315,  405,  517,  191,  187,  188,  564,
  189,  190,  567,  568,  406,  518,  411,  331,  571,  416,
  525,  418,  526,  527,  316,  373,  166,  167,  156,  157,
  365,  366,  440,  441,  367,  368,  329,  556,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -162,
    0,    0,    0,    0, 2365,  247,    0,    0,    0,  -23,
  -19,  -17,   -3,   11,   13,    3,   20,   41,   44,   53,
   57,   64,   73,   82,   88,   90,  103,  108,  110,  125,
  140,  150,  154,  172,  158,  164,  166,  168,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -217,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  172,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  182,  184, -193, -230, -276, -249,
 -171, -158, -132,  -35, -122, -121, -120, -119, -118, -116,
    0,    0, -186,  -48,  -48,  -48,    0,    0, -255, -114,
 -155,  -51,  -46, -203, -200, -136,    0,    0,    0,    0,
 -198,    0,    0,    0,  136,  137, -287, -287,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  215,  216,  222,
  224,    0,    0,    0, -132,    0,    0,  -35,    0,    0,
    0,    0,    0,    0,    0, -165, -165,    0,    0, -186,
    0,    0,    0,    0,    0,  -32,  -32,    0,    0,    0,
  218,  220,    0,    0,    0,    0,    0,    0,  156,    0,
    0, 2064, -156,    0,    0,    0,    0,  233,  -82,  -82,
    0,    0,    0,    0, -149, -145,  -39,  -38,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -165,    0,    0,
    0,  -32,    0,    0,  -83,  -72, 2204,  238,  239,  241,
  242,  244,  245,  246,  250,  253,  259,  263,  269,  270,
  271, -163,  273,  274,  277,  -30,  278,  281,  282,  283,
  301,  302,  303,  304,  305,  306,  307,  308,  309,  311,
  312,  320,  321,  324,  329,  333,  335,  350,  351,  352,
  353,  355,  356,  357,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 2064,   49,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -156,   49, -312,  -82,  -36,
    0,    0,  359,  361,  362,  366,  367,  376,    0,    0,
    0,    0,    0,    0,    0, 2204,   49,    0, -165,  138,
   76,  127,  115,  118, -187, -124, -231,  149,  160, -153,
  102, -161,    0,    0,   93,    0,  400,  404,   97,   99,
  100,    0,  410,   91, -154, -146, -143,   87,   94,  104,
   95,   85,  105,  106,   79,   89,   92,   96,  107,  111,
  112,  117,   86,   98,  132,  135,  116,  109,  -40,  141,
 -141,    0,    0, 2064,  134,  446,    0,  200,    0,    0,
  -82,    0,    0,    0, -152,    0,  468, -152,  167,  169,
  178,  179,  193,  208,    0, 2204,    0,    0,  138,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -187,    0,    0,    0, -124,    0,    0,    0,    0,    0,
 -231,    0,    0,  149,    0,    0,  160,    0,    0,    0,
    0,    0,    0,    0, -153,    0,    0,    0,    0,    0,
    0,    0, -161,    0, -287, -287,    0,    0,    0,  481,
 -287,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  209,    0,    0,    0,  409,    0,    0,  478, -287,    0,
  490, -156,    0,    0,    0,    0,    0,  210,    0,    0,
    0,    0,    0,    0,    0,  452,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  213,    0,    0,    0,
 -287,    0, -160,  455,    0,    0,    0,    0,    0,    0,
    0,    0,  217,    0,  217,  217,    0,    0,    0,  230,
    0,    0,    0, -152,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  583,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  585,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  463,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  585,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  658,    0,    0,  497,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  755,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  223,  225,    0,    0,    0,    0,    4,  170,  170,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  334,    0,    0,
    0,  598,    0,    0,    0,    0,  243,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -113,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -112,    0,    0,  170,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -111,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, 1504,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  466,    0,    0,    0,    0,    0,    0,
  170,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  475,    0,    0,  791,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  934,    0,    0,    0, 1077,    0,    0,    0,    0,    0,
 1220,    0,    0, 1644,    0,    0, 1784,    0,    0,    0,
    0,    0,    0,    0, 1363,    0,    0,    0,    0,    0,
    0,    0, 1924,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  480,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -110,    0, -110, -110,    0,    0,    0,    0,
    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,   -6, -177,  161,    0, -176,    0,  162,    0,
    0,  155,    0,    0,  173,    0,    0, -175, -174, -173,
  606,    0,    0,    0,    0,  479, -172,  176,    0,    0,
    0,    0,    0,  617,    0,    0,    0,    0,   25,    0,
    0,    0,    0,   32,    0,  477,    0,    0,    0,    0,
    0,    0,  620,    0, -133,    0,    0,  467,    0,    0,
 -166, -134,    0, -164,    0,  203,    0,    0,  567,    0,
  512,    0,    0,    0,    0,    0,  131,    0, -201, -199,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  628,  632,    0,    0,    0,
 -305,    0,    0, -286,    0,    0, -319, -191,  529, -298,
    0,  174,    0,    0,    0,    0,    0, -443, -127,    0,
 -126, -125,    0,    0,    0,    0,    0, -170, -327,    0,
  316,   81, -394,    0,    0,    0,    0,    0,    0,    0,
    0,  291,  219,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 2738
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                      76,
  192,  193,  194,  316,  511,  317,  318,  319,  320,  321,
  322,  165,  304,  155,  336,  344,  324,  345,  325,  332,
  407,  415,  209,  529,  402,  348,  425,    7,  408,   46,
   81,  545,  546,  214,   87,  130,   51,  548,   88,  343,
   89,    7,  116,    8,    9,   10,  409,   11,  426,   12,
   13,   14,   15,  410,   90,   16,   91,  131,   92,   17,
   93,  116,   18,   19,   20,   21,   22,   23,   24,   25,
  129,  184,  185,  339,  186,  552,   26,   94,  340,  132,
  134,  135,  136,   27,   28,   29,   46,   30,   31,  133,
   32,   33,   74,   51,    1,    2,  117,  118,   95,  138,
  139,   96,  446,  447,  448,  449,  536,  560,  158,  159,
   97,  180,  140,  141,   98,  117,  118,  515,  168,  169,
   17,   99,  201,  202,  203,  204,  205,  206,  316,  218,
  100,   35,   36,   37,  435,  436,  437,  438,  439,  101,
  219,  142,  143,  144,  344,  102,  345,  103,  317,  318,
  319,  320,  321,  322,  348,   38,  171,  172,  412,  324,
  104,  325,  222,  223,  224,  105,  336,  106,  343,  332,
  175,  176,  225,  177,  178,  336,  226,  117,  118,  575,
  333,  334,  107,  229,  335,  336,  336,  459,  460,  461,
  462,  463,  467,  468,  469,  470,  471,  108,  184,  185,
  561,  186,  562,  363,  364,  442,  443,  109,  336,  336,
  336,  110,  524,  414,  427,  112,  554,  111,  336,  483,
  484,  113,  336,  114,  344,  115,  345,  485,  486,  336,
  487,  488,  513,  514,  348,  164,  165,  572,  573,  127,
  523,  128,  147,  150,  151,  152,  153,  154,  343,  155,
  162,  170,  173,  165,  304,  155,   75,  174,  182,  183,
  195,  196,  316,  316,  316,  316,  316,  197,  316,  198,
  316,  316,  316,  316,  211,  215,  316,  216,  217,  328,
  316,  330,  341,  316,  316,  316,  316,  316,  316,  316,
  316,  337,  338,  342,  332,  349,  350,  316,  351,  352,
  316,  353,  354,  355,  316,  316,  316,  356,  316,  316,
  357,  316,  316,  316,  316,  413,  358,  316,  316,  316,
  359,  316,  316,  316,  316,  510,  360,  361,  362,  414,
  369,  370,  316,  138,  371,  374,  316,  372,  375,  376,
  377,  316,  316,  316,  317,  318,  319,  320,  321,  322,
  450,  316,  316,  316,  316,  324,  316,  325,  378,  379,
  380,  381,  382,  383,  384,  385,  386,  316,  387,  388,
  316,  316,  316,  316,  316,  316,  316,  389,  390,  316,
  316,  391,  316,  316,  316,  316,  392,  316,  316,  316,
  393,  316,  394,  316,  316,  316,  316,  316,  316,  316,
  316,  316,  316,  316,  316,  316,  316,  395,  396,  397,
  398,  316,  399,  400,  401,  403,  419,  316,  420,  421,
  316,  316,  316,  422,  423,  563,  565,  566,  332,  332,
  332,  332,  332,  424,  332,  428,  332,  332,  332,  332,
  431,  433,  332,  432,  450,  434,  332,  453,  466,  332,
  332,  332,  332,  332,  332,  332,  332,  475,  138,  456,
  364,  476,  477,  332,  478,  479,  332,  481,  482,  489,
  332,  332,  332,  493,  332,  332,  490,  332,  332,  332,
  332,  492,  496,  332,  332,  332,  491,  332,  332,  332,
  332,  504,  497,  494,  495,  498,   67,  506,  332,  499,
  507,  516,  332,  519,  505,    7,  512,  332,  332,  332,
  520,  500,  528,   12,   13,  501,  502,  332,  332,  332,
  332,  503,  332,  509,  508,  547,   18,   19,   20,   21,
   22,   23,  530,  550,  531,  551,  332,  332,  332,  332,
  332,  332,  332,  532,  533,  332,  332,  553,  332,  332,
  332,  332,   31,  332,  332,  332,   74,  332,  534,  332,
  332,  332,  332,  332,  332,  332,  332,  332,  332,  332,
  332,  332,  332,  535,  549,  555,  557,  332,  558,  569,
  570,  413,    2,  332,    5,   48,  332,  332,  332,  165,
  165,  304,  138,  138,  138,  138,  138,   88,  138,  155,
  138,  138,  138,  138,  304,  539,  138,   88,  541,  155,
  138,   77,  540,  138,  138,  138,  138,  138,  138,  138,
  138,   67,   78,  199,  200,   82,  210,  138,  119,  542,
  138,  537,  181,   83,  138,  138,  138,   84,  138,  138,
  543,  138,  138,  138,  179,  417,  544,  138,  138,  138,
  574,  138,  138,  138,  138,  474,    0,  134,    0,  538,
    0,    0,  138,    0,    0,    0,  138,    0,    0,    0,
    0,  138,  138,  138,    0,    0,    0,    0,    0,    0,
    0,  138,  138,  138,  138,    0,  138,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  138,    0,  138,  138,  138,  138,  138,    0,    0,  138,
  138,    0,  138,  138,  138,  138,    0,  138,  138,  138,
    0,  138,    0,  138,  138,  138,  138,  138,  138,  138,
  138,  138,  138,  138,  138,  138,  138,    0,    0,    0,
    0,  138,    0,    0,    0,    0,    0,  138,    0,    0,
  138,  138,  138,    0,  118,   67,   67,   67,   67,   67,
    0,   67,    0,   67,   67,   67,   67,    0,    0,   67,
    0,    0,    0,   67,    0,    0,   67,   67,   67,   67,
   67,   67,   67,   67,    0,    0,    0,    0,    0,    0,
   67,    0,    0,   67,    0,    0,    0,   67,   67,   67,
    0,   67,   67,    0,   67,   67,   67,    0,    0,    0,
   67,   67,    0,    0,    0,   67,   67,   67,    0,    0,
    0,    0,    0,    0,    0,   67,    0,    0,    0,   67,
    0,    0,    0,    0,    0,    0,   67,    0,    0,    0,
    0,    0,    0,    0,    0,   67,   67,   67,    0,    0,
    0,    0,    0,    0,    0,    0,   88,   88,   88,   88,
   88,    0,   88,   67,   88,   88,   88,   88,    0,   67,
   88,    0,    0,    0,   88,    0,    0,   88,   88,   88,
   88,   88,   88,   88,   88,    0,    0,    0,    0,    0,
    0,   88,    0,    0,    0,    0,    0,    0,   88,   88,
   88,    0,   88,   88,    0,   88,   88,   88,    0,    0,
    0,   88,   88,    0,    0,  244,  134,  134,  134,  134,
  134,    0,  134,    0,  134,  134,  134,  134,    0,    0,
  134,    0,    0,    0,  134,    0,    0,  134,  134,  134,
  134,  134,  134,  134,  134,    0,   88,   88,   88,    0,
    0,  134,    0,    0,    0,    0,    0,    0,  134,  134,
  134,    0,  134,  134,    0,  134,  134,  134,    0,    0,
   88,  134,  134,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  134,  134,  134,    0,
    0,    0,    0,  118,  118,  118,  118,  118,    0,  118,
    0,  118,  118,  118,  118,    0,    0,  118,    0,    0,
  134,  118,    0,    0,  118,  118,  118,  118,  118,  118,
  118,  118,    0,    0,    0,    0,    0,    0,  118,    0,
    0,    0,    0,    0,    0,  118,  118,  118,  286,  118,
  118,    0,  118,  118,  118,    0,    0,  244,  118,  118,
  244,  244,  244,  244,  244,  244,  244,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  244,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  118,  118,  118,  244,    0,  244,  244,
  244,  244,    0,    0,    0,    0,    0,    0,    0,  244,
    0,    0,    0,  244,    0,    0,    0,  118,  244,  244,
  244,    0,    0,    0,    0,    0,    0,    0,  244,    0,
    0,    0,    0,  244,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  244,    0,  244,
  244,  244,  244,    0,    0,    0,  244,  244,    0,  244,
  244,  244,  244,    0,  244,  244,  244,    0,  244,    0,
  244,  244,  244,  244,  244,  244,  244,  244,  244,  244,
  244,  244,  244,  244,    0,    0,    0,    0,  244,    0,
    0,  257,    0,    0,  244,    0,    0,  244,  244,  244,
  286,    0,    0,  286,  286,  286,  286,  286,  286,  286,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  286,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  286,
    0,  286,  286,  286,  286,    0,    0,    0,    0,    0,
    0,    0,  286,    0,    0,    0,  286,    0,    0,    0,
    0,  286,  286,  286,    0,    0,    0,    0,    0,    0,
    0,  286,    0,    0,    0,    0,  286,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  286,    0,  286,  286,  286,  286,    0,    0,    0,  286,
  286,    0,  286,  286,  286,  286,    0,  286,  286,  286,
    0,  286,    0,  286,  286,  286,  286,  286,  286,  286,
  286,  286,  286,  286,  286,  286,  286,    0,    0,    0,
    0,  286,    0,    0,   55,    0,    0,  286,    0,    0,
  286,  286,  286,  257,    0,    0,  257,  257,  257,  257,
  257,  257,  257,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  257,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  257,    0,  257,  257,  257,  257,    0,    0,
    0,    0,    0,    0,    0,  257,    0,    0,    0,  257,
    0,    0,    0,    0,  257,  257,  257,    0,    0,    0,
    0,    0,    0,    0,  257,    0,    0,    0,    0,  257,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  257,    0,  257,  257,  257,  257,    0,
    0,    0,  257,  257,    0,  257,  257,  257,  257,    0,
  257,  257,  257,    0,  257,    0,  257,  257,  257,  257,
  257,  257,  257,  257,  257,  257,  257,  257,  257,  257,
    0,    0,    0,    0,  257,    0,    0,  249,    0,    0,
  257,    0,    0,  257,  257,  257,   55,    0,    0,   55,
   55,   55,   55,   55,   55,   55,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   55,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   55,    0,   55,   55,   55,
   55,    0,    0,    0,    0,    0,    0,    0,   55,    0,
    0,    0,   55,    0,    0,    0,    0,   55,   55,   55,
    0,    0,    0,    0,    0,    0,    0,   55,    0,    0,
    0,    0,   55,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   55,    0,   55,   55,
   55,   55,    0,    0,    0,   55,   55,    0,   55,   55,
   55,   55,    0,   55,   55,   55,    0,   55,    0,   55,
   55,   55,   55,   55,   55,   55,   55,   55,   55,   55,
   55,   55,   55,    0,    0,    0,    0,   55,  263,    0,
    0,    0,    0,   55,    0,    0,   55,   55,   55,  249,
    0,    0,  249,  249,  249,  249,  249,  249,  249,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  249,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  249,    0,
  249,  249,  249,  249,    0,    0,    0,    0,    0,    0,
    0,  249,    0,    0,    0,  249,    0,    0,    0,    0,
  249,  249,  249,    0,    0,    0,    0,    0,    0,    0,
  249,    0,    0,    0,    0,  249,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  249,
    0,  249,  249,  249,  249,    0,    0,    0,  249,  249,
    0,  249,  249,  249,  249,    0,  249,  249,  249,    0,
  249,    0,  249,  249,  249,  249,  249,  249,  249,  249,
  249,  249,  249,  249,  249,  249,    0,    0,   59,    0,
  249,    0,    0,    0,    0,    0,  249,    0,    0,  249,
  249,  249,    0,  263,  263,  263,  263,  263,  263,  263,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  263,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  263,
    0,  263,  263,  263,  263,    0,    0,    0,    0,    0,
    0,    0,  263,    0,    0,    0,  263,    0,    0,    0,
    0,  263,  263,  263,    0,    0,    0,    0,    0,    0,
    0,  263,    0,    0,    0,    0,  263,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  263,    0,  263,  263,  263,  263,    0,    0,    0,  263,
  263,    0,  263,  263,  263,  263,    0,  263,  263,  263,
    0,  263,    0,  263,  263,  263,  263,  263,  263,  263,
  263,  263,  263,  263,  263,  263,  263,    0,   63,    0,
    0,  263,    0,    0,    0,    0,    0,  263,    0,    0,
  263,  263,  263,   59,   59,   59,   59,   59,   59,   59,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   59,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   59,
    0,   59,   59,   59,   59,    0,    0,    0,    0,    0,
    0,    0,   59,    0,    0,    0,   59,    0,    0,    0,
    0,   59,   59,   59,    0,    0,    0,    0,    0,    0,
    0,   59,    0,    0,    0,    0,   59,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   59,    0,   59,   59,   59,   59,    0,    0,    0,   59,
   59,    0,   59,   59,   59,   59,    0,   59,   59,   59,
    0,   59,    0,   59,   59,   59,   59,   59,   59,   59,
   59,   59,   59,   59,   59,   59,   59,    0,  274,    0,
    0,   59,    0,    0,    0,    0,    0,   59,    0,    0,
   59,   59,   59,   63,   63,   63,   63,   63,   63,   63,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   63,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   63,
    0,   63,   63,   63,   63,    0,    0,    0,    0,    0,
    0,    0,   63,    0,    0,    0,   63,    0,    0,    0,
    0,   63,   63,   63,    0,    0,    0,    0,    0,    0,
    0,   63,    0,    0,    0,    0,   63,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   63,    0,   63,   63,   63,   63,    0,    0,    0,   63,
   63,    0,   63,   63,   63,   63,    0,   63,   63,   63,
    0,   63,    0,   63,   63,   63,   63,   63,   63,   63,
   63,   63,   63,   63,   63,   63,   63,    0,    0,    0,
    0,   63,    0,    0,    0,    0,    0,   63,    0,    0,
   63,   63,   63,  274,  274,  274,  274,  274,  274,  274,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  274,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  274,
    0,  274,  274,  274,  274,    0,    0,    0,    0,    0,
    0,    0,  274,    0,    0,    0,  274,    0,    0,    0,
    0,  274,  274,  274,    0,    0,    0,    0,    0,    0,
    0,  274,    0,    0,    0,    0,  274,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  274,    0,  274,  274,  274,  274,    0,    0,    0,  274,
  274,    0,  274,  274,  274,  274,    0,  274,  274,  274,
    0,  274,    0,  274,  274,  274,  274,  274,  274,  274,
  274,  274,  274,  274,  274,  274,  274,    0,    0,    0,
    0,  274,    0,    0,    0,    0,    0,  274,    0,    0,
  274,  274,  274,   18,   19,   20,   21,   22,   23,  218,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  219,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  220,
    0,  221,  222,  223,  224,    0,    0,    0,    0,    0,
    0,    0,  225,    0,    0,    0,  226,    0,    0,    0,
    0,  227,  228,  229,    0,    0,    0,    0,    0,    0,
    0,  230,    0,    0,    0,    0,  231,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  232,  233,  234,  235,    0,    0,    0,  236,
  237,    0,  238,  239,  240,  241,    0,  242,  243,  244,
    0,  245,    0,  246,  247,  248,  249,  250,  251,  252,
  253,  254,  255,  256,  257,  258,  259,    0,    0,    0,
    0,  260,    0,    0,    0,    0,    0,  261,    0,    0,
  262,  263,  264,   18,   19,   20,   21,   22,   23,  218,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  219,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  220,
    0,  221,  222,  223,  224,    0,    0,    0,    0,    0,
    0,    0,  225,    0,    0,    0,    0,    0,    0,    0,
    0,  227,  228,    0,    0,    0,    0,    0,    0,    0,
    0,  230,    0,    0,    0,    0,  231,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  232,  233,  234,    0,    0,    0,    0,  236,
  237,    0,  238,  239,  240,  241,    0,  242,  243,  244,
    0,  245,    0,  246,  247,  248,  249,  250,  251,  252,
  253,  254,  255,  256,  257,  258,  259,    0,    0,    0,
    0,  260,    0,    0,    0,    0,    0,  261,    0,    0,
  262,  263,  264,    7,    0,    8,    9,   10,    0,   11,
    0,   12,   13,   14,   15,    0,    0,   16,    0,    0,
    0,   17,    0,    0,   18,   19,   20,   21,   22,   23,
   24,   25,    0,    0,    0,    0,    0,    0,   26,    0,
    0,    0,    0,    0,    0,   27,   28,   29,    0,   30,
   31,    0,   32,   33,   34,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   35,   36,   37,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   38,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                       6,
  128,  128,  128,    0,   45,  183,  183,  183,  183,  183,
  183,  125,  125,  125,  125,  217,  183,  217,  183,  190,
  326,   58,  157,  418,  311,  217,  346,  259,  327,    5,
    6,  475,  476,  167,   58,  266,    5,  481,   58,  217,
   58,  259,  260,  261,  262,  263,  359,  265,  347,  267,
  268,  269,  270,  366,   58,  273,   46,  288,   46,  277,
   58,  260,  280,  281,  282,  283,  284,  285,  286,  287,
  264,  359,  360,  208,  362,  519,  294,   58,  212,  310,
  330,  331,  332,  301,  302,  303,   62,  305,  306,  366,
  308,  309,  310,   62,  257,  258,  314,  315,   58,  271,
  272,   58,  334,  335,  336,  337,  426,  551,  295,  296,
   58,  310,  271,  272,   58,  314,  315,  404,  374,  375,
  277,   58,  288,  289,  290,  291,  292,  293,  125,  286,
   58,  349,  350,  351,  322,  323,  324,  325,  326,   58,
  297,  274,  275,  276,  346,   58,  346,   58,  326,  326,
  326,  326,  326,  326,  346,  373,  312,  313,  329,  326,
   58,  326,  319,  320,  321,   58,  277,   58,  346,    0,
  374,  375,  329,  374,  375,  286,  333,  314,  315,  574,
  330,  331,   58,  340,  330,  331,  297,  341,  342,  343,
  344,  345,  354,  355,  356,  357,  358,   58,  359,  360,
  361,  362,  363,  367,  368,  330,  331,   58,  319,  320,
  321,   58,  365,  366,  349,   58,  522,   46,  329,  374,
  375,   58,  333,   58,  426,   58,  426,  374,  375,  340,
  374,  375,  374,  375,  426,  105,  106,  565,  566,   58,
  411,   58,  278,  366,  366,  366,  366,  366,  426,  366,
  299,  366,  304,  367,  367,  367,   10,  304,  123,  123,
   46,   46,  259,  260,  261,  262,  263,   46,  265,   46,
  267,  268,  269,  270,  307,   58,  273,   58,  123,   47,
  277,  364,  366,  280,  281,  282,  283,  284,  285,  286,
  287,  331,  331,  366,  125,   58,   58,  294,   58,   58,
  297,   58,   58,   58,  301,  302,  303,   58,  305,  306,
   58,  308,  309,  310,  311,  352,   58,  314,  315,  316,
   58,  318,  319,  320,  321,  366,   58,   58,   58,  366,
   58,   58,  329,    0,   58,   58,  333,  368,   58,   58,
   58,  338,  339,  340,  522,  522,  522,  522,  522,  522,
  357,  348,  349,  350,  351,  522,  353,  522,   58,   58,
   58,   58,   58,   58,   58,   58,   58,  364,   58,   58,
  367,  368,  369,  370,  371,  372,  373,   58,   58,  376,
  377,   58,  379,  380,  381,  382,   58,  384,  385,  386,
   58,  388,   58,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   58,   58,   58,
   58,  408,   58,   58,   58,  367,   58,  414,   58,   58,
  417,  418,  419,   58,   58,  553,  553,  553,  259,  260,
  261,  262,  263,   58,  265,  298,  267,  268,  269,  270,
  365,  327,  273,  317,  451,  328,  277,  299,  347,  280,
  281,  282,  283,  284,  285,  286,  287,   58,  125,  300,
  368,   58,  366,  294,  366,  366,  297,   58,  378,  383,
  301,  302,  303,  389,  305,  306,  383,  308,  309,  310,
  311,  387,  404,  314,  315,  316,  383,  318,  319,  320,
  321,  406,  404,  389,  389,  404,    0,  366,  329,  404,
  366,  368,  333,   58,  407,  259,  366,  338,  339,  340,
  311,  405,   45,  267,  268,  405,  405,  348,  349,  350,
  351,  405,  353,  415,  409,   45,  280,  281,  282,  283,
  284,  285,  366,  125,  366,   58,  367,  368,  369,  370,
  371,  372,  373,  366,  366,  376,  377,   58,  379,  380,
  381,  382,  306,  384,  385,  386,  310,  388,  366,  390,
  391,  392,  393,  394,  395,  396,  397,  398,  399,  400,
  401,  402,  403,  366,  366,  366,  125,  408,  366,  125,
  364,  352,    0,  414,    0,  123,  417,  418,  419,  367,
  125,  367,  259,  260,  261,  262,  263,    0,  265,  125,
  267,  268,  269,  270,  125,  445,  273,   10,  454,  367,
  277,    6,  451,  280,  281,  282,  283,  284,  285,  286,
  287,  125,    6,  145,  148,    6,  160,  294,   62,  457,
  297,  429,  121,    6,  301,  302,  303,    6,  305,  306,
  465,  308,  309,  310,  116,  330,  473,  314,  315,  316,
  570,  318,  319,  320,  321,  365,   -1,    0,   -1,  441,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,  349,  350,  351,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  367,   -1,  369,  370,  371,  372,  373,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,   -1,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,   -1,    0,  259,  260,  261,  262,  263,
   -1,  265,   -1,  267,  268,  269,  270,   -1,   -1,  273,
   -1,   -1,   -1,  277,   -1,   -1,  280,  281,  282,  283,
  284,  285,  286,  287,   -1,   -1,   -1,   -1,   -1,   -1,
  294,   -1,   -1,  297,   -1,   -1,   -1,  301,  302,  303,
   -1,  305,  306,   -1,  308,  309,  310,   -1,   -1,   -1,
  314,  315,   -1,   -1,   -1,  319,  320,  321,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  329,   -1,   -1,   -1,  333,
   -1,   -1,   -1,   -1,   -1,   -1,  340,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  259,  260,  261,  262,
  263,   -1,  265,  367,  267,  268,  269,  270,   -1,  373,
  273,   -1,   -1,   -1,  277,   -1,   -1,  280,  281,  282,
  283,  284,  285,  286,  287,   -1,   -1,   -1,   -1,   -1,
   -1,  294,   -1,   -1,   -1,   -1,   -1,   -1,  301,  302,
  303,   -1,  305,  306,   -1,  308,  309,  310,   -1,   -1,
   -1,  314,  315,   -1,   -1,  125,  259,  260,  261,  262,
  263,   -1,  265,   -1,  267,  268,  269,  270,   -1,   -1,
  273,   -1,   -1,   -1,  277,   -1,   -1,  280,  281,  282,
  283,  284,  285,  286,  287,   -1,  349,  350,  351,   -1,
   -1,  294,   -1,   -1,   -1,   -1,   -1,   -1,  301,  302,
  303,   -1,  305,  306,   -1,  308,  309,  310,   -1,   -1,
  373,  314,  315,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  349,  350,  351,   -1,
   -1,   -1,   -1,  259,  260,  261,  262,  263,   -1,  265,
   -1,  267,  268,  269,  270,   -1,   -1,  273,   -1,   -1,
  373,  277,   -1,   -1,  280,  281,  282,  283,  284,  285,
  286,  287,   -1,   -1,   -1,   -1,   -1,   -1,  294,   -1,
   -1,   -1,   -1,   -1,   -1,  301,  302,  303,  125,  305,
  306,   -1,  308,  309,  310,   -1,   -1,  277,  314,  315,
  280,  281,  282,  283,  284,  285,  286,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  297,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  349,  350,  351,  316,   -1,  318,  319,
  320,  321,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  329,
   -1,   -1,   -1,  333,   -1,   -1,   -1,  373,  338,  339,
  340,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  348,   -1,
   -1,   -1,   -1,  353,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  367,   -1,  369,
  370,  371,  372,   -1,   -1,   -1,  376,  377,   -1,  379,
  380,  381,  382,   -1,  384,  385,  386,   -1,  388,   -1,
  390,  391,  392,  393,  394,  395,  396,  397,  398,  399,
  400,  401,  402,  403,   -1,   -1,   -1,   -1,  408,   -1,
   -1,  125,   -1,   -1,  414,   -1,   -1,  417,  418,  419,
  277,   -1,   -1,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  367,   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,   -1,   -1,
   -1,  408,   -1,   -1,  125,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  277,   -1,   -1,  280,  281,  282,  283,
  284,  285,  286,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  297,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  316,   -1,  318,  319,  320,  321,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  329,   -1,   -1,   -1,  333,
   -1,   -1,   -1,   -1,  338,  339,  340,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  348,   -1,   -1,   -1,   -1,  353,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  367,   -1,  369,  370,  371,  372,   -1,
   -1,   -1,  376,  377,   -1,  379,  380,  381,  382,   -1,
  384,  385,  386,   -1,  388,   -1,  390,  391,  392,  393,
  394,  395,  396,  397,  398,  399,  400,  401,  402,  403,
   -1,   -1,   -1,   -1,  408,   -1,   -1,  125,   -1,   -1,
  414,   -1,   -1,  417,  418,  419,  277,   -1,   -1,  280,
  281,  282,  283,  284,  285,  286,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  297,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  316,   -1,  318,  319,  320,
  321,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  329,   -1,
   -1,   -1,  333,   -1,   -1,   -1,   -1,  338,  339,  340,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  348,   -1,   -1,
   -1,   -1,  353,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  367,   -1,  369,  370,
  371,  372,   -1,   -1,   -1,  376,  377,   -1,  379,  380,
  381,  382,   -1,  384,  385,  386,   -1,  388,   -1,  390,
  391,  392,  393,  394,  395,  396,  397,  398,  399,  400,
  401,  402,  403,   -1,   -1,   -1,   -1,  408,  125,   -1,
   -1,   -1,   -1,  414,   -1,   -1,  417,  418,  419,  277,
   -1,   -1,  280,  281,  282,  283,  284,  285,  286,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  297,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,   -1,
  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,   -1,
  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  367,
   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,  377,
   -1,  379,  380,  381,  382,   -1,  384,  385,  386,   -1,
  388,   -1,  390,  391,  392,  393,  394,  395,  396,  397,
  398,  399,  400,  401,  402,  403,   -1,   -1,  125,   -1,
  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,  417,
  418,  419,   -1,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  367,   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,  125,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  367,   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,  125,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  367,   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,   -1,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  367,   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,   -1,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,  333,   -1,   -1,   -1,
   -1,  338,  339,  340,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  369,  370,  371,  372,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,   -1,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  280,  281,  282,  283,  284,  285,  286,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  297,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  316,
   -1,  318,  319,  320,  321,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  338,  339,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  348,   -1,   -1,   -1,   -1,  353,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  369,  370,  371,   -1,   -1,   -1,   -1,  376,
  377,   -1,  379,  380,  381,  382,   -1,  384,  385,  386,
   -1,  388,   -1,  390,  391,  392,  393,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  403,   -1,   -1,   -1,
   -1,  408,   -1,   -1,   -1,   -1,   -1,  414,   -1,   -1,
  417,  418,  419,  259,   -1,  261,  262,  263,   -1,  265,
   -1,  267,  268,  269,  270,   -1,   -1,  273,   -1,   -1,
   -1,  277,   -1,   -1,  280,  281,  282,  283,  284,  285,
  286,  287,   -1,   -1,   -1,   -1,   -1,   -1,  294,   -1,
   -1,   -1,   -1,   -1,   -1,  301,  302,  303,   -1,  305,
  306,   -1,  308,  309,  310,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  349,  350,  351,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  373,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 420
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
"SERVERCONFIG","CLIENTCONFIG","DEPRECATED","CLIENTRULE","INTERNAL","EXTERNAL",
"REALM","REALNAME","EXTERNAL_ROTATION","SAMESAME","DEBUGGING","RESOLVEPROTOCOL",
"SOCKET","CLIENTSIDE_SOCKET","SNDBUF","RCVBUF","SRCHOST","NODNSMISMATCH",
"NODNSUNKNOWN","CHECKREPLYAUTH","EXTENSION","BIND","PRIVILEGED","IOTIMEOUT",
"IOTIMEOUT_TCP","IOTIMEOUT_UDP","NEGOTIATETIMEOUT","CONNECTTIMEOUT",
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
"IFNAME","URL","PORT","SERVICENAME","NUMBER","FROM","TO","REDIRECT","BANDWIDTH",
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
"serverconfig : global_clientauthmethod",
"serverconfig : deprecated",
"serverconfig : internal",
"serverconfig : external",
"serverconfig : external_rotation",
"serverconfig : errorlog",
"serverconfig : logoutput",
"serverconfig : serveroption",
"serverconfig : userids",
"serverconfig : childstate",
"serverconfig : debuging",
"serverconfig : libwrapfiles",
"serverconfig : libwrap_hosts_access",
"serverconfig : udpconnectdst",
"serveroption : compatibility",
"serveroption : extension",
"serveroption : global_routeoption",
"serveroption : resolveprotocol",
"serveroption : realm",
"serveroption : socket",
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
"socket : SOCKET '.' SNDBUF '.' PROTOCOL_UDP ':' NUMBER",
"socket : SOCKET '.' RCVBUF '.' PROTOCOL_UDP ':' NUMBER",
"socket : SOCKET '.' SNDBUF '.' PROTOCOL_TCP ':' NUMBER",
"socket : SOCKET '.' RCVBUF '.' PROTOCOL_TCP ':' NUMBER",
"socket : CLIENTSIDE_SOCKET '.' SNDBUF '.' PROTOCOL_UDP ':' NUMBER",
"socket : CLIENTSIDE_SOCKET '.' RCVBUF '.' PROTOCOL_UDP ':' NUMBER",
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
"$$3 :",
"global_authmethod : METHOD ':' $$3 authmethods",
"$$4 :",
"global_clientauthmethod : CLIENTMETHOD ':' $$4 authmethods",
"authmethodname : NONE",
"authmethodname : GSSAPI",
"authmethodname : UNAME",
"authmethodname : RFC931",
"authmethodname : PAM",
"authmethodname : BSDAUTH",
"clientrule : CLIENTRULE verdict '{' clientruleoptions fromto clientruleoptions '}'",
"clientruleoption : option",
"clientruleoption : bandwidth",
"clientruleoption : protocol",
"clientruleoption : redirect",
"clientruleoptions :",
"clientruleoptions : clientruleoption clientruleoptions",
"rule : verdict '{' ruleoptions fromto ruleoptions '}'",
"ruleoption : option",
"ruleoption : bandwidth",
"ruleoption : command",
"ruleoption : udpportrange",
"ruleoption : protocol",
"ruleoption : proxyprotocol",
"ruleoption : redirect",
"ruleoptions :",
"ruleoptions : ruleoption ruleoptions",
"option : authmethod",
"option : clientcompatibility",
"option : libwrap",
"option : log",
"option : pamservicename",
"option : bsdauthstylename",
"option : gssapiservicename",
"option : gssapikeytab",
"option : gssapienctype",
"option : lurl",
"option : ldapauto",
"option : ldapdomain",
"option : ldapdebug",
"option : ldapdepth",
"option : lbasedn",
"option : lbasedn_hex",
"option : lbasedn_hex_all",
"option : ldapport",
"option : ldapportssl",
"option : ldapssl",
"option : ldapcertcheck",
"option : ldapkeeprealm",
"option : ldapfilter",
"option : ldapattribute",
"option : ldapfilter_ad",
"option : ldapattribute_ad",
"option : ldapfilter_hex",
"option : ldapattribute_hex",
"option : ldapfilter_ad_hex",
"option : ldapattribute_ad_hex",
"option : ldapcertfile",
"option : ldapcertpath",
"option : lgroup",
"option : lgroup_hex",
"option : lgroup_hex_all",
"option : lserver",
"option : ldapkeytab",
"option : user",
"option : group",
"option : timeout",
"option : bounce",
"option : session",
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
"bounce : BOUNCE bounce_to ':' address",
"libwrap : LIBWRAPSTART ':' LINE",
"srcaddress : from ':' address",
"dstaddress : to ':' address",
"rdr_fromaddress : rdr_from ':' address",
"rdr_toaddress : rdr_to ':' address",
"gateway : via ':' gwaddress",
"routeoption : command",
"routeoption : clientcompatibility",
"routeoption : extension",
"routeoption : protocol",
"routeoption : gssapiservicename",
"routeoption : gssapikeytab",
"routeoption : gssapienctype",
"routeoption : proxyprotocol",
"routeoption : authmethod",
"routeoptions :",
"routeoptions : routeoption routeoptions",
"from : FROM",
"to : TO",
"rdr_from : FROM",
"rdr_to : TO",
"bounce_to : TO",
"via : VIA",
"externaladdress : ipaddress",
"externaladdress : domain",
"externaladdress : ifname",
"address : ipaddress '/' netmask port",
"$$5 :",
"address : ipaddress $$5 port",
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
#line 2020 "config_parse.y"

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

#if !SOCKS_CLIENT
   if (sockscf.state.inited) {
      /* in case needed to read config-file or operations pertaining to it. */
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
   /*
    * uid, read from configfile.  But save olds one first, in case we
    * need them to reopen logfiles.
    */

   olduserid = sockscf.uid;
   bzero(&sockscf.uid, sizeof(sockscf.uid));
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

   if (yyin == NULL
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         swarn("%s: could not open %s", function, filename);

      havefile              = 0;
      sockscf.option.debug  = 1;
   }
   else {
      socks_parseinit = 0;
#if YYDEBUG
      yydebug         = 0;
#endif /* YYDEBUG */

      yylineno      = 1;
      errno         = 0;   /* don't report old errors in yyparse(). */
      havefile      = 1;

      parsingconfig = 1;
      yyparse();
      parsingconfig = 0;

#if SOCKS_CLIENT
      fclose(yyin);
#else
      /*
       * Leave it open so that if we get a sighup later, we are
       * always guranteed to have a descriptor we can close/reopen
       * to parse the configfile.
       */
      sockscf.configfd = fileno(yyin);
#endif
   }

   errno = 0;

#if SOCKS_CLIENT /* assume server admin can set things up correctly himself. */
   parseclientenv();
#endif

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
                         "%s: warning on line %d, near \"%.10s\": ",
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
parseclientenv(void)
{
   const char *function = "parseclientenv()";
   char *proxyserver, *logfile, *debug;

   if ((logfile = socks_getenv("SOCKS_LOGOUTPUT", dontcare)) != NULL)
      socks_addlogfile(&sockscf.log, logfile);

   if ((debug = socks_getenv("SOCKS_DEBUG", dontcare)) != NULL)
      sockscf.option.debug = atoi(debug);

   if ((proxyserver = socks_getenv("SOCKS4_SERVER", dontcare)) != NULL
   ||  (proxyserver = socks_getenv("SOCKS5_SERVER", dontcare)) != NULL
   ||  (proxyserver = socks_getenv("SOCKS_SERVER",  dontcare)) != NULL
   ||  (proxyserver = socks_getenv("HTTP_PROXY",    dontcare)) != NULL) {
      char ipstring[INET_ADDRSTRLEN], *portstring;
      struct sockaddr_in saddr;
      struct route_t route;
      struct ruleaddr_t raddr;

      slog(LOG_DEBUG, "%s: found proxyserver set in environment, value %s",
      function, proxyserver);

      if ((portstring = strchr(proxyserver, ':')) == NULL)
         serrx(EXIT_FAILURE, "%s: illegal format for port specification "
         "in proxy server %s: missing ':' delimiter", function, proxyserver);

      if (atoi(portstring + 1) < 1 || atoi(portstring + 1) > 0xffff)
         serrx(EXIT_FAILURE, "%s: illegal value for port specification "
         "in proxy server %s: must be between %d and %d",
         function, proxyserver, 1, 0xffff);

      if (portstring - proxyserver == 0
      || (size_t)(portstring - proxyserver) > sizeof(ipstring) - 1)
         serrx(EXIT_FAILURE, "%s: illegal format for ip address specification "
         "in proxy server %s: too short/long", function, proxyserver);

      strncpy(ipstring, proxyserver, (size_t)(portstring - proxyserver));
      ipstring[portstring - proxyserver] = NUL;
      ++portstring;

      bzero(&saddr, sizeof(saddr));
      saddr.sin_family = AF_INET;
      if (inet_pton(saddr.sin_family, ipstring, &saddr.sin_addr) != 1)
         serr(EXIT_FAILURE, "%s: illegal format for ip address specification "
         "in proxy server %s", function, ipstring);
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
         route.gw.state.proxyprotocol.http = 1;
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
#line 2036 "config_parse.c"
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
#line 347 "config_parse.y"
{
#if !SOCKS_CLIENT
      protocol  = &protocolmem;
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
break;
case 5:
#line 359 "config_parse.y"
{ yyval.string = NULL; }
break;
case 10:
#line 368 "config_parse.y"
{ yyval.string = NULL; }
break;
case 14:
#line 375 "config_parse.y"
{
   }
break;
case 46:
#line 419 "config_parse.y"
{
      yyerror("given keyword, \"%s\", is deprecated", yyvsp[0].string);
   }
break;
case 47:
#line 424 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;
      route.gw.state  = state;

      socks_addroute(&route, 1);
   }
break;
case 48:
#line 434 "config_parse.y"
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
      src.atype = SOCKS_ADDR_IPV4;
      dst.atype = SOCKS_ADDR_IPV4;
   }
break;
case 50:
#line 465 "config_parse.y"
{
         proxyprotocol->socks_v4    = 1;
   }
break;
case 51:
#line 468 "config_parse.y"
{
         proxyprotocol->socks_v5    = 1;
   }
break;
case 52:
#line 471 "config_parse.y"
{
         proxyprotocol->http        = 1;
   }
break;
case 53:
#line 474 "config_parse.y"
{
         proxyprotocol->upnp        = 1;
   }
break;
case 58:
#line 487 "config_parse.y"
{
#if !SOCKS_CLIENT 
      if (addlinkedname(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 62:
#line 502 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 66:
#line 517 "config_parse.y"
{
         extension->bind = 1;
   }
break;
case 69:
#line 526 "config_parse.y"
{
#if !SOCKS_CLIENT
#if BAREFOOTD
      yyerror("\"internal:\" specification is not used in %s", PACKAGE);
#endif /* BAREFOOTD */

      addinternal(ruleaddr, SOCKS_TCP);
#endif /* !SOCKS_CLIENT */
   }
break;
case 70:
#line 537 "config_parse.y"
{
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
break;
case 71:
#line 554 "config_parse.y"
{
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
break;
case 72:
#line 561 "config_parse.y"
{
#if !SOCKS_CLIENT
      static struct ruleaddr_t mem;

      addrinit(&mem, 0);
#endif /* !SOCKS_CLIENT */
   }
break;
case 73:
#line 570 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 74:
#line 574 "config_parse.y"
{
      sockscf.external.rotation = ROTATION_SAMESAME;
   }
break;
case 75:
#line 577 "config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
      yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
   }
break;
case 81:
#line 594 "config_parse.y"
{
      const int value = atoi(yyvsp[0].string);

      if (value < 0)
         yyerror("max route fails can not be negative (%d)  Use \"0\" to "
                 "indicate routes should never be marked as bad", 
                 value);

      sockscf.routeoptions.maxfail = value;
   }
break;
case 82:
#line 604 "config_parse.y"
{
      const int value = atoi(yyvsp[0].string);

      if (value < 0)
         yyerror("route failure expiry time can not be negative (%d).  "
                 "Use \"0\" to indicate bad route marking should never expire",
                 value);

      sockscf.routeoptions.badexpire = value;
   }
break;
case 83:
#line 616 "config_parse.y"
{ add_to_errorlog = 1; }
break;
case 85:
#line 619 "config_parse.y"
{ add_to_errorlog = 0; }
break;
case 87:
#line 622 "config_parse.y"
{
#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   /*
    * We dont enforce that userid must be set before logfiles, so make sure
    * that the old userid, if any, is stored before (re)opening logfiles.
    */
   const struct userid_t currentuserid = sockscf.uid;;
   sockscf.uid = olduserid;
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */

   socks_addlogfile(add_to_errorlog ? &sockscf.errlog : &sockscf.log, yyvsp[0].string);

#if !SOCKS_CLIENT && !HAVE_PRIVILEGES
   sockscf.uid = currentuserid;
#endif /* !SOCKS_CLIENT && !HAVE_PRIVILEGES */
}
break;
case 90:
#line 643 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.child.maxidle.negotiate = SOCKD_FREESLOTS_NEGOTIATE * 2;
      sockscf.child.maxidle.request   = SOCKD_FREESLOTS_REQUEST   * 2;
      sockscf.child.maxidle.io        = SOCKD_FREESLOTS_IO        * 2;
   }
break;
case 91:
#line 649 "config_parse.y"
{
      bzero(&sockscf.child.maxidle, sizeof(sockscf.child.maxidle));
   }
break;
case 92:
#line 652 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.child.maxrequests = (size_t)atol(yyvsp[0].string);
#endif /* !SOCKS_CLIENT */
   }
break;
case 96:
#line 664 "config_parse.y"
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
case 97:
#line 676 "config_parse.y"
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
case 98:
#line 688 "config_parse.y"
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
case 99:
#line 703 "config_parse.y"
{
      struct passwd *pw;

      if ((pw = socks_getpwnam(yyvsp[0].string)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
      else
         yyval.uid = pw->pw_uid;
   }
break;
case 100:
#line 713 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      timeout->tcpio = (size_t)atol(yyvsp[0].string);
      timeout->udpio = timeout->tcpio;
   }
break;
case 101:
#line 719 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      timeout->tcpio = (size_t)atol(yyvsp[0].string);
   }
break;
case 102:
#line 723 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      timeout->udpio = (size_t)atol(yyvsp[0].string);
#endif /* !SOCKS_CLIENT */
   }
break;
case 103:
#line 730 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      timeout->negotiate = (size_t)atol(yyvsp[0].string);
#endif /* !SOCKS_CLIENT */
   }
break;
case 104:
#line 738 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      timeout->connect = (size_t)atol(yyvsp[0].string);
   }
break;
case 105:
#line 744 "config_parse.y"
{
#if !SOCKS_CLIENT
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      timeout->tcp_fin_wait = (size_t)atol(yyvsp[0].string);
#endif /* !SOCKS_CLIENT */
   }
break;
case 106:
#line 753 "config_parse.y"
{
#if !SOCKS_CLIENT
      if (sockscf.option.debugrunopt == -1)
#endif /* !SOCKS_CLIENT */
          sockscf.option.debug = atoi(yyvsp[0].string);
   }
break;
case 109:
#line 765 "config_parse.y"
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
case 110:
#line 778 "config_parse.y"
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
case 111:
#line 791 "config_parse.y"
{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerror("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
break;
case 112:
#line 799 "config_parse.y"
{
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerror("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 113:
#line 809 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
break;
case 114:
#line 813 "config_parse.y"
{
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 116:
#line 823 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
break;
case 117:
#line 827 "config_parse.y"
{
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 121:
#line 840 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 122:
#line 843 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 123:
#line 850 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 124:
#line 855 "config_parse.y"
{
#if !SOCKS_CLIENT 
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.socket.udp.sndbuf = (size_t)atol(yyvsp[0].string);
   }
break;
case 125:
#line 860 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.socket.udp.rcvbuf = (size_t)atol(yyvsp[0].string);
   }
break;
case 126:
#line 864 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.socket.tcp.sndbuf = (size_t)atol(yyvsp[0].string);
   }
break;
case 127:
#line 868 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.socket.tcp.rcvbuf = (size_t)atol(yyvsp[0].string);
#if BAREFOOTD
   }
break;
case 128:
#line 873 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.socket.clientside_udp.sndbuf = (size_t)atol(yyvsp[0].string);
   }
break;
case 129:
#line 877 "config_parse.y"
{
      CHECKNUMBER(yyvsp[0].string, >=, 0);
      sockscf.socket.clientside_udp.rcvbuf = (size_t)atol(yyvsp[0].string);
#endif /* BAREFOOTD */

#endif /* !SOCKS_CLIENT */
   }
break;
case 131:
#line 890 "config_parse.y"
{
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
break;
case 132:
#line 894 "config_parse.y"
{
         sockscf.srchost.nodnsunknown = 1;
   }
break;
case 133:
#line 897 "config_parse.y"
{
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 136:
#line 907 "config_parse.y"
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
case 140:
#line 929 "config_parse.y"
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
case 142:
#line 942 "config_parse.y"
{
#if !SOCKS_CLIENT
   methodv  = sockscf.clientmethodv;
   methodc  = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif /* !SOCKS_CLIENT */
   }
break;
case 144:
#line 951 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_NONE);
   }
break;
case 145:
#line 954 "config_parse.y"
{
#if !HAVE_GSSAPI
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#else
      ADDMETHOD(AUTHMETHOD_GSSAPI);
#endif /* !HAVE_GSSAPI */
   }
break;
case 146:
#line 961 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
break;
case 147:
#line 964 "config_parse.y"
{
#if HAVE_LIBWRAP
      ADDMETHOD(AUTHMETHOD_RFC931);
#else
      yyerror("method %s requires libwrap library", AUTHMETHOD_RFC931s);
#endif /* HAVE_LIBWRAP */
   }
break;
case 148:
#line 971 "config_parse.y"
{
#if HAVE_PAM
      ADDMETHOD(AUTHMETHOD_PAM);
#else /* !HAVE_PAM */
      yyerror("method %s requires pam library", AUTHMETHOD_PAMs);
#endif /* HAVE_PAM */
   }
break;
case 149:
#line 978 "config_parse.y"
{
#if HAVE_BSDAUTH
      ADDMETHOD(AUTHMETHOD_BSDAUTH);
#else /* !HAVE_PAM */
      yyerror("method %s requires bsd authentication", AUTHMETHOD_BSDAUTHs);
#endif /* HAVE_PAM */
   }
break;
case 150:
#line 991 "config_parse.y"
{

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
break;
case 152:
#line 1027 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("bandwidth");
#endif /* !SOCKS_CLIENT */
   }
break;
case 153:
#line 1032 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 154:
#line 1037 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
break;
case 155:
#line 1044 "config_parse.y"
{ yyval.string = NULL; }
break;
case 157:
#line 1048 "config_parse.y"
{
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
break;
case 159:
#line 1067 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("bandwidth");
#endif /* !SOCKS_CLIENT */
   }
break;
case 164:
#line 1076 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
break;
case 165:
#line 1083 "config_parse.y"
{ yyval.string = NULL; }
break;
case 207:
#line 1127 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 208:
#line 1132 "config_parse.y"
{
#if !SOCKS_CLIENT
         checkmodule("session");
#endif /* !SOCKS_CLIENT */
   }
break;
case 209:
#line 1139 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->debug = atoi(yyvsp[0].string);
   }
break;
case 210:
#line 1144 "config_parse.y"
{
      ldap->debug = -atoi(yyvsp[0].string);
 #else /* !HAVE_LDAP */
      yyerror("ldap debug support requires openldap support");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 211:
#line 1153 "config_parse.y"
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
case 212:
#line 1166 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->mdepth = atoi(yyvsp[0].string);
#else /* !HAVE_LDAP */
      yyerror("ldap debug support requires openldap support");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 213:
#line 1177 "config_parse.y"
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
case 214:
#line 1190 "config_parse.y"
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
case 215:
#line 1203 "config_parse.y"
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
case 216:
#line 1215 "config_parse.y"
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
case 217:
#line 1227 "config_parse.y"
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
case 218:
#line 1239 "config_parse.y"
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
case 219:
#line 1251 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->port = atoi(yyvsp[0].string);
#else /* !HAVE_LDAP */
   yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 220:
#line 1262 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->portssl = atoi(yyvsp[0].string);
#else /* !HAVE_LDAP */
   yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 221:
#line 1273 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->ssl = 1;
   }
break;
case 222:
#line 1278 "config_parse.y"
{
      ldap->ssl = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 223:
#line 1287 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->auto_off = 1;
   }
break;
case 224:
#line 1292 "config_parse.y"
{
      ldap->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 225:
#line 1301 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->certcheck = 1;
   }
break;
case 226:
#line 1306 "config_parse.y"
{
      ldap->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 227:
#line 1315 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->keeprealm = 1;
   }
break;
case 228:
#line 1320 "config_parse.y"
{
      ldap->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 229:
#line 1329 "config_parse.y"
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
case 230:
#line 1342 "config_parse.y"
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
case 231:
#line 1355 "config_parse.y"
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
case 232:
#line 1368 "config_parse.y"
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
case 233:
#line 1381 "config_parse.y"
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
case 234:
#line 1394 "config_parse.y"
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
case 235:
#line 1407 "config_parse.y"
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
case 236:
#line 1420 "config_parse.y"
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
case 237:
#line 1433 "config_parse.y"
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
case 238:
#line 1445 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8(yyvsp[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 239:
#line 1457 "config_parse.y"
{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, asciitoutf8(yyvsp[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerror("no LDAP support configured for %s/server", PACKAGE);
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 240:
#line 1469 "config_parse.y"
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
case 241:
#line 1481 "config_parse.y"
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
case 243:
#line 1499 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#endif /* HAVE_GSSAPI */
   }
break;
case 246:
#line 1513 "config_parse.y"
{
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 247:
#line 1518 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
   }
break;
case 251:
#line 1532 "config_parse.y"
{
         command->bind = 1;
   }
break;
case 252:
#line 1535 "config_parse.y"
{
         command->connect = 1;
   }
break;
case 253:
#line 1538 "config_parse.y"
{
         command->udpassociate = 1;
   }
break;
case 254:
#line 1544 "config_parse.y"
{
         command->bindreply = 1;
   }
break;
case 255:
#line 1548 "config_parse.y"
{
         command->udpreply = 1;
   }
break;
case 259:
#line 1561 "config_parse.y"
{
      protocol->tcp = 1;
   }
break;
case 260:
#line 1564 "config_parse.y"
{
      protocol->udp = 1;
   }
break;
case 266:
#line 1581 "config_parse.y"
{
#if !SOCKS_CLIENT
   static shmem_object_t ssinit;

   CHECKNUMBER(yyvsp[0].string, >=, 0);

   if (pidismother(sockscf.state.pid) == 1) {
      if ((rule.ss = malloc(sizeof(*rule.ss))) == NULL)
         yyerror("failed to malloc %lu bytes for ss memory",
         (unsigned long)sizeof(*rule.ss));

      *rule.ss                       = ssinit;
      rule.ss->object.ss.maxsessions = (size_t)atol(yyvsp[0].string);
   }
   else
      rule.ss = &ssinit;

   rule.ss_fd = -1;
#endif /* !SOCKS_CLIENT */
}
break;
case 267:
#line 1603 "config_parse.y"
{
#if !SOCKS_CLIENT
   static shmem_object_t bwmeminit;

   CHECKNUMBER(yyvsp[0].string, >=, 0);

   if (pidismother(sockscf.state.pid) == 1) {
      if ((rule.bw = malloc(sizeof(*rule.bw))) == NULL)
         yyerror("failed to malloc %lu bytes for bw memory",
         (unsigned long)sizeof(*rule.bw));

      *rule.bw                  = bwmeminit;
      rule.bw->object.bw.maxbps = (size_t)atol(yyvsp[0].string);
   }
   else
      rule.bw = &bwmeminit;

   rule.bw_fd = -1;
#endif /* !SOCKS_CLIENT */
}
break;
case 269:
#line 1629 "config_parse.y"
{
#if !SOCKS_CLIENT
   rule.log.connect = 1;
   }
break;
case 270:
#line 1633 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 271:
#line 1636 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 272:
#line 1639 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 273:
#line 1642 "config_parse.y"
{
         rule.log.iooperation = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 276:
#line 1653 "config_parse.y"
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
case 277:
#line 1664 "config_parse.y"
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
case 278:
#line 1676 "config_parse.y"
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
case 279:
#line 1687 "config_parse.y"
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
case 281:
#line 1705 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 282:
#line 1711 "config_parse.y"
{
      gssapiencryption->clear = 1;
   }
break;
case 283:
#line 1714 "config_parse.y"
{
      gssapiencryption->integrity = 1;
   }
break;
case 284:
#line 1717 "config_parse.y"
{
      gssapiencryption->confidentiality = 1;
   }
break;
case 285:
#line 1720 "config_parse.y"
{
      yyerror("gssapi per-message encryption not supported");
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
break;
case 289:
#line 1735 "config_parse.y"
{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
      struct request_info request;
      char libwrap[LIBWRAPBUF];

      if (strlen(yyvsp[0].string) >= sizeof(rule.libwrap))
         yyerror("libwrapline too long, make LIBWRAPBUF bigger");
      strcpy(rule.libwrap, yyvsp[0].string);

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
break;
case 304:
#line 1789 "config_parse.y"
{ yyval.string = NULL; }
break;
case 306:
#line 1793 "config_parse.y"
{
      addrinit(&src, 1);
   }
break;
case 307:
#line 1798 "config_parse.y"
{
      addrinit(&dst, 
#if SOCKS_SERVER
               1
#else /* BAREFOOT || COVENANT */
               0 /* the address the server should bind, so must be /32. */
#endif /*  BAREFOOT || COVENANT */
      );
   }
break;
case 308:
#line 1809 "config_parse.y"
{
      addrinit(&rdr_from, 1);
   }
break;
case 309:
#line 1814 "config_parse.y"
{
      addrinit(&rdr_to, 1);
   }
break;
case 310:
#line 1819 "config_parse.y"
{
#if BAREFOOTD
      addrinit(&bounce_to, 0);
#endif /* BAREFOOTD */
   }
break;
case 311:
#line 1827 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 316:
#line 1839 "config_parse.y"
{ 
         if (netmask_required)
            yyerror("no netmask given");
         else
            netmask->s_addr = htonl(0xffffffff);
       }
break;
case 325:
#line 1857 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton(yyvsp[0].string, ipaddr) != 1)
         yyerror("bad address: %s", yyvsp[0].string);
   }
break;
case 326:
#line 1866 "config_parse.y"
{
      if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
         yyerror("bad netmask: %s", yyvsp[0].string);

      netmask->s_addr
      = atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
   }
break;
case 327:
#line 1873 "config_parse.y"
{
         if (!inet_aton(yyvsp[0].string, netmask))
            yyerror("bad netmask: %s", yyvsp[0].string);
   }
break;
case 328:
#line 1879 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");

      strcpy(domain, yyvsp[0].string);
   }
break;
case 329:
#line 1889 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
         yyerror("interface name too long");

      strcpy(ifname, yyvsp[0].string);
   }
break;
case 330:
#line 1900 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", yyvsp[0].string);
      strcpy(domain, yyvsp[0].string);

      proxyprotocol->direct = 1;
   }
break;
case 331:
#line 1911 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;

      if (strlen(yyvsp[0].string) >= MAXURLLEN)
         yyerror("url \"%s\" too long", yyvsp[0].string);

      strcpy(url, yyvsp[0].string);
   }
break;
case 332:
#line 1922 "config_parse.y"
{ yyval.string = NULL; }
break;
case 336:
#line 1928 "config_parse.y"
{ yyval.string = NULL; }
break;
case 340:
#line 1936 "config_parse.y"
{
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerror("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
break;
case 341:
#line 1944 "config_parse.y"
{
      CHECKPORTNUMBER(yyvsp[0].string);
      *port_tcp   = htons((in_port_t)atoi(yyvsp[0].string));
      *port_udp   = htons((in_port_t)atoi(yyvsp[0].string));
   }
break;
case 342:
#line 1951 "config_parse.y"
{
      CHECKPORTNUMBER(yyvsp[0].string);
      ruleaddr->portend    = htons((in_port_t)atoi(yyvsp[0].string));
      ruleaddr->operator   = range;
   }
break;
case 343:
#line 1958 "config_parse.y"
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
   }
break;
case 344:
#line 1989 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 346:
#line 1997 "config_parse.y"
{
#if SOCKS_SERVER
   CHECKPORTNUMBER(yyvsp[0].string);
   rule.udprange.start = htons((in_port_t)atoi(yyvsp[0].string));
#endif /* SOCKS_SERVER */
   }
break;
case 347:
#line 2005 "config_parse.y"
{
#if SOCKS_SERVER
   CHECKPORTNUMBER(yyvsp[0].string);
   rule.udprange.end = htons((in_port_t)atoi(yyvsp[0].string));
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerror("udp end port (%s) can not be less than udp start port (%u)",
      yyvsp[0].string, ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
break;
#line 3872 "config_parse.c"
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
