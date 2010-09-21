#include "common.h"
#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ >= 2
  __attribute__ ((unused))
#endif /* __GNUC__ >= 2 */
  = "$OpenBSD: skeleton.c,v 1.29 2008/07/08 15:06:50 otto Exp $";
#endif
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
"$Id: config_parse.y,v 1.292.2.7.2.2 2010/09/21 11:24:42 karls Exp $";

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
static struct in_addr         *ipaddr;        /* new ip address               */
static struct in_addr         *netmask;       /* new netmask                  */
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


#if DEBUG
#define YYDEBUG 1
#endif /* DEBUG */

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

#line 139 "config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
   char   *string;
   uid_t   uid;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 147 "config_parse.c"
#define SERVERCONFIG 257
#define CLIENTCONFIG 258
#define DEPRECATED 259
#define CLIENTRULE 260
#define INTERNAL 261
#define EXTERNAL 262
#define EXTERNAL_ROTATION 263
#define DEBUGING 264
#define RESOLVEPROTOCOL 265
#define SRCHOST 266
#define NOMISMATCH 267
#define NOUNKNOWN 268
#define CHECKREPLYAUTH 269
#define EXTENSION 270
#define BIND 271
#define PRIVILEGED 272
#define IOTIMEOUT 273
#define IOTIMEOUT_TCP 274
#define IOTIMEOUT_UDP 275
#define NEGOTIATETIMEOUT 276
#define METHOD 277
#define CLIENTMETHOD 278
#define NONE 279
#define GSSAPI 280
#define UNAME 281
#define RFC931 282
#define PAM 283
#define COMPATIBILITY 284
#define REUSEADDR 285
#define SAMEPORT 286
#define DRAFT_5_05 287
#define CLIENTCOMPATIBILITY 288
#define NECGSSAPI 289
#define USERNAME 290
#define GROUPNAME 291
#define USER_PRIVILEGED 292
#define USER_UNPRIVILEGED 293
#define USER_LIBWRAP 294
#define LOGOUTPUT 295
#define LOGFILE 296
#define CHILD_MAXIDLE 297
#define CHILD_MAXREQUESTS 298
#define ROUTE 299
#define VIA 300
#define VERDICT_BLOCK 301
#define VERDICT_PASS 302
#define PAMSERVICENAME 303
#define GSSAPISERVICE 304
#define GSSAPIKEYTAB 305
#define GSSAPIENCTYPE 306
#define GSSAPIENC_ANY 307
#define GSSAPIENC_CLEAR 308
#define GSSAPIENC_INTEGRITY 309
#define GSSAPIENC_CONFIDENTIALITY 310
#define GSSAPIENC_PERMESSAGE 311
#define GSSAPISERVICENAME 312
#define GSSAPIKEYTABNAME 313
#define PROTOCOL 314
#define PROTOCOL_TCP 315
#define PROTOCOL_UDP 316
#define PROTOCOL_FAKE 317
#define PROXYPROTOCOL 318
#define PROXYPROTOCOL_SOCKS_V4 319
#define PROXYPROTOCOL_SOCKS_V5 320
#define PROXYPROTOCOL_MSPROXY_V2 321
#define PROXYPROTOCOL_HTTP_V1_0 322
#define PROXYPROTOCOL_UPNP 323
#define USER 324
#define GROUP 325
#define COMMAND 326
#define COMMAND_BIND 327
#define COMMAND_CONNECT 328
#define COMMAND_UDPASSOCIATE 329
#define COMMAND_BINDREPLY 330
#define COMMAND_UDPREPLY 331
#define ACTION 332
#define LINE 333
#define LIBWRAPSTART 334
#define OPERATOR 335
#define SOCKS_LOG 336
#define SOCKS_LOG_CONNECT 337
#define SOCKS_LOG_DATA 338
#define SOCKS_LOG_DISCONNECT 339
#define SOCKS_LOG_ERROR 340
#define SOCKS_LOG_IOOPERATION 341
#define IPADDRESS 342
#define DOMAINNAME 343
#define DIRECT 344
#define IFNAME 345
#define URL 346
#define PORT 347
#define PORTNUMBER 348
#define SERVICENAME 349
#define NUMBER 350
#define FROM 351
#define TO 352
#define REDIRECT 353
#define BANDWIDTH 354
#define MAXSESSIONS 355
#define UDPPORTRANGE 356
#define UDPCONNECTDST 357
#define YES 358
#define NO 359
#define BOUNCE 360
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   66,    1,    1,    1,    1,    1,    1,    2,
    2,    2,    2,   38,   39,   39,   67,   67,   67,   67,
   67,   67,   67,   67,   67,   67,   67,   67,   65,   65,
   65,   65,   65,   65,    3,   74,   32,    7,    8,    8,
    8,    8,    8,    8,    9,    9,   10,   11,   12,   12,
   13,   14,   15,   15,   43,   44,   45,   45,   46,   47,
   48,   49,   50,   50,   40,   40,   40,   51,   52,   53,
   53,   73,   73,   73,   68,   68,   68,   69,   70,   71,
   72,   41,   41,   41,   42,   36,   37,   37,   54,   55,
   55,   55,   56,   56,   20,   21,   21,   21,   22,   23,
   23,   23,   24,   24,   59,  115,   57,  116,   58,   61,
   61,   61,   61,   61,   60,   60,   82,   83,   83,   83,
   83,   84,   84,   79,   80,   80,   80,   80,   80,   80,
   80,   81,   81,   85,   85,   85,   85,   85,   85,   85,
   85,   85,   85,   85,   85,   62,   63,   64,   64,   86,
   86,   25,   26,   26,   27,   27,   27,   27,   27,    4,
    5,    5,    6,    6,   87,   28,   28,   28,   30,   31,
   29,   88,   90,   90,   90,   90,   90,   89,   89,   16,
   17,   18,   19,  120,  120,  120,  120,  120,  119,  119,
  113,   91,   92,   93,  117,  118,   76,   77,   77,   77,
   77,   77,   77,   77,   77,   77,   78,   78,  103,  104,
  121,  122,  114,   75,   94,   94,   94,   95,   95,   95,
   96,   96,   96,   98,   98,   98,   98,   98,   97,  105,
  105,   99,  100,  101,  102,  106,  106,  106,  106,  107,
  107,  111,  111,  108,  109,  123,  112,  110,   33,   34,
   35,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylen[] =
#else
short socks_yylen[] =
#endif
	{                                         2,
    2,    2,    1,    0,    2,    2,    2,    2,    2,    0,
    2,    2,    2,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    8,    0,    3,    1,    1,
    1,    1,    1,    1,    1,    2,    3,    1,    1,    2,
    3,    1,    1,    2,    3,    1,    1,    2,    4,    0,
    4,    0,    3,    3,    1,    1,    1,    3,    1,    1,
    2,    3,    3,    3,    1,    1,    1,    3,    3,    3,
    1,    3,    3,    3,    3,    3,    3,    3,    3,    1,
    1,    1,    1,    2,    3,    1,    1,    1,    3,    1,
    1,    1,    1,    2,    3,    0,    4,    0,    4,    1,
    1,    1,    1,    1,    1,    2,    7,    1,    1,    1,
    1,    0,    2,    6,    1,    1,    1,    1,    1,    1,
    1,    0,    2,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    3,    1,    1,    2,    1,
    1,    3,    1,    2,    1,    1,    1,    1,    1,    3,
    1,    2,    1,    1,    2,    3,    2,    2,    1,    3,
    3,    3,    1,    1,    1,    1,    1,    1,    2,    3,
    3,    3,    3,    1,    1,    1,    1,    1,    1,    2,
    4,    3,    3,    3,    3,    3,    3,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    0,    2,    1,    1,
    1,    1,    1,    1,    2,    2,    2,    1,    1,    1,
    4,    2,    2,    2,    2,    2,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    0,    3,    3,    2,    0,
    3,    1,    1,    3,    1,    1,    1,    1,    5,    1,
    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    3,   14,    0,   10,    4,    0,    0,   35,    0,    0,
    0,   37,   11,   16,   67,   66,   12,   15,   65,   13,
    0,   60,   62,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  150,  151,
    0,    5,   19,   33,   34,   27,   28,   32,   30,   31,
   20,   21,   22,   23,   29,   17,   18,   24,    6,   25,
   75,   76,   77,   26,    9,    8,    7,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  106,  108,    0,    0,    0,    0,    0,    0,
    0,    0,   86,   97,   98,   96,   95,   69,    0,   68,
    0,    0,    0,    0,   63,   64,  100,  101,  102,    0,
   99,   56,    0,   55,   82,   83,   84,   85,    0,    0,
   90,   91,   92,    0,   89,   81,   78,   79,   80,   72,
   73,   74,   87,   88,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  129,  130,  142,  143,  138,  139,  140,  141,
  127,  131,  126,  145,  169,  128,  134,  135,    0,    0,
  125,  137,  136,  144,   71,  201,  205,  202,  203,  204,
  198,  200,  206,  199,    0,    0,  120,  121,  119,    0,
    0,  118,  229,  232,  233,   59,    0,    0,    0,   61,
  218,  219,  220,  104,   58,  110,  111,  112,  113,  114,
  107,    0,  109,   94,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  211,  212,    0,
  168,    0,    0,    0,    0,    0,  213,    0,  133,  209,
    0,    0,    0,  208,    0,  123,    0,    0,  215,  216,
  217,  116,  105,  147,    0,  146,  180,  181,  182,  184,
  185,  186,  187,  188,  183,    0,  163,  164,  160,    0,
   39,   40,   41,   42,   43,   44,    0,   38,   48,    0,
   47,   52,    0,   51,  155,  156,  157,  158,  159,  152,
    0,  192,  173,  174,  175,  176,  177,  172,    0,  166,
    0,    0,  171,  170,  250,    0,    0,    0,  210,  165,
    0,    0,  214,    0,    0,    0,  248,  245,    0,  239,
    0,    0,  149,  190,  162,   46,   50,   54,  154,  179,
  195,    0,    0,    0,  196,    0,  191,  124,    0,  193,
    0,    0,  117,  247,  243,  237,  242,    0,  238,    0,
  222,  223,  251,  249,  194,  234,  235,    0,  197,    0,
    0,  227,  228,   36,  246,  244,  231,  230,    0,    0,
  224,  225,  226,  221,    0,  241,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
    7,    6,  276,  153,  269,  270,  154,  277,  278,  155,
  280,  281,  156,  283,  284,  157,  158,  159,  160,   15,
   97,   45,  110,  111,  161,  290,  291,  162,  163,  164,
  165,   72,  166,  306,  354,   16,   47,    4,   17,   18,
   48,   49,  182,  113,  114,   51,   74,   52,   75,   53,
   19,   99,  100,   55,  124,  125,   56,   57,  167,  211,
  212,  168,  255,  256,   58,    5,   59,   60,   61,   62,
   63,  127,   64,   20,  314,  315,  185,  186,   66,  169,
  170,   67,  190,  191,  171,   68,  241,  172,  298,  299,
  173,  242,  310,  196,  200,  331,  332,  359,  333,  334,
  362,  363,  243,  311,  369,  249,  371,  320,  345,  322,
  346,  347,  174,  238,  119,  120,  230,  231,  265,  266,
  232,  233,  366,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -213,
    0,    0,    0,    0,    0,   -8,  364,    0,  -19,  -17,
   15,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -181,    0,    0,   17,   20,   40,   48,   56,   60,   80,
   90,  100,  104,  105,  106,  108,  110,  111,    0,    0,
  112,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   52, -173, -222,
 -118,   57,   59,  121,  130, -246, -186,  -79, -160, -157,
 -155, -154,    0,    0, -175,  -93,  -93,  -93, -235, -152,
 -226, -169,    0,    0,    0,    0,    0,    0, -118,    0,
 -234,  809, -266, -266,    0,    0,    0,    0,    0, -186,
    0,    0,  -79,    0,    0,    0,    0,    0, -231, -231,
    0,    0,    0, -175,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  141,  142,  143,  144,  145,  146,
  147,  148,  149,  150,  151,  155,  156, -212,  158,  159,
  160, -133,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -169, -130,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -234, -130,    0,    0,    0,  809,
 -130,    0,    0,    0,    0,    0, -124, -124, -124,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -231,    0,    0, -231,  -67, -116,  -72,  -71, -252,
 -174, -233,  -46,  -44, -267,  -83, -272,    0,    0, -107,
    0,  190,  191,  -97,  -96,  -68,    0,  194,    0,    0,
 -169,  -82,  197,    0,  -42,    0,  809,  -51,    0,    0,
    0,    0,    0,    0,  -67,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -252,    0,    0,    0, -174,
    0,    0,    0,    0,    0,    0, -233,    0,    0,  -46,
    0,    0,  -44,    0,    0,    0,    0,    0,    0,    0,
 -267,    0,    0,    0,    0,    0,    0,    0, -272,    0,
 -266, -266,    0,    0,    0,  223, -266,  157,    0,    0,
  214, -266,    0,  225, -234,  161,    0,    0, -205,    0,
  228, -205,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  234, -124, -124,    0,  -60,    0,    0, -266,    0,
 -215,  165,    0,    0,    0,    0,    0,  -56,    0, -304,
    0,    0,    0,    0,    0,    0,    0,  -39,    0,  -39,
  -39,    0,    0,    0,    0,    0,    0,    0, -124,  -34,
    0,    0,    0,    0, -205,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  309,  310,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  -40,    0,    0,    0,    0,    0,    0,  171,    0,
  -38,  -37,    0,    0,    0,    0,    0,    0,    0,  215,
    0,    0,  103,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  259,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -125,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -115,    0,    0,    0,    0, -113,
    0,    0,    0,    0,    0,    0,  320,  320,  320,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    1,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  664,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  187,    0,    0,    0,    0,    0,  192,    0,    0,    0,
    0,    0,    0,    0,  419,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  477,    0,    0,    0,  520,
    0,    0,    0,    0,    0,    0,  578,    0,    0,  722,
    0,    0,  765,    0,    0,    0,    0,    0,    0,    0,
  621,    0,    0,    0,    0,    0,    0,    0,  823,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  193,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  376,  376,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  -94,    0,  -94,
  -94,    0,    0,    0,    0,    0,    0,    0,  376,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,  140,  -88,   46,    0,  -86,    0,   44,    0,
    0,   42,    0,    0,   41,    0,  -85,  -84,  -81,  316,
    0,    0,    0,  218,  -80,   38,    0,  -75,  -74,    0,
    0,    0,    0,    0,    0,  324,    0,    0,    0,    0,
    0,    0,  325,    0,  220,    0,    0,    0,    0,    0,
  327,    0,  237,    0,    0,  216,    0,    0,  -78,  -90,
    0,  -76,    0,   83,    0,    0,    0,    0,    0,    0,
    0,   63,    0,  332,    0,    0,    0, -163,    0,    0,
 -145,    0,    0, -156,  -73,  321, -151,    0,   45,    0,
    0,    0,    0,    0,    0, -265, -100,    0,  -98,  -95,
    0,    0,    0,    0,    0, -180, -200,    0,   93,  -27,
 -290,    0,    0,    0,    0,    0,    0,  115,   81,    0,
    0,    0,    0,
};
#define YYTABLESIZE 1183
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                     132,
  115,   13,  197,  201,  198,  202,  319,  199,  203,  207,
  115,  122,  176,  187,  177,  178,  179,  250,  251,  180,
  181,  244,  183,  239,  184,    8,  188,  189,  192,  213,
  240,  349,  105,  246,  245,   26,  335,  367,   69,  247,
   70,  337,  135,    1,    2,  368,  340,  206,  207,  208,
  209,  210,  106,  136,  260,  261,  262,  263,  264,  285,
  286,  287,  288,  289,  293,  294,  295,  296,  297,  138,
  139,  140,   71,  355,   76,  193,  194,   77,  195,  141,
  107,  108,  109,  142,  376,  271,  272,  273,  274,  275,
  316,  145,   94,   95,   96,  308,  176,   78,  177,  178,
  179,  187,   57,  180,  181,   79,  183,  135,  184,  121,
  122,  123,   57,   80,  188,  189,  192,   81,  136,   39,
   40,  252,  130,  131,  253,  115,  193,  194,  356,  195,
  357,  133,  134,  137,  138,  139,  140,   82,  228,  229,
  267,  268,  318,  344,  141,   14,   43,   83,  142,  128,
  129,  342,  351,  352,  143,  144,  145,   84,  187,  372,
  373,   85,   86,   87,  146,   88,  147,   89,   90,   91,
   70,  188,  189,  192,   92,  240,   93,   98,  103,  101,
   70,  102,  240,  148,  149,  150,  151,  104,  374,  115,
  152,  112,  116,  240,  117,  118,  126,  132,  215,  216,
  217,  218,  219,  220,  221,  222,  223,  224,  225,  240,
  240,  240,  226,  227,  103,  234,  235,  236,  237,  240,
  240,  254,  248,  240,  103,  132,  176,   57,  177,  178,
  179,  240,  257,  180,  181,  207,  183,  122,  184,  258,
  358,  259,  360,  279,  229,  361,  282,  301,  302,  292,
    8,  307,  303,  304,  312,    9,   10,  313,   93,  115,
  115,  115,  115,  115,  115,  115,  115,  336,   93,  309,
  115,  339,  348,  115,  115,  115,  115,  115,  115,  305,
  350,  338,  341,  317,  115,  343,   11,  353,  115,  364,
   12,  365,  115,  115,  115,  115,  318,  115,  115,  115,
  317,  115,  115,  115,  115,  115,  115,  370,    2,    1,
  132,  132,  207,  122,  115,  325,  122,  207,  115,  236,
  326,  327,   44,  328,  115,  115,  115,  204,  329,  236,
   46,   50,  205,   54,  115,  175,  115,  323,   65,  214,
  321,   73,  375,  330,  300,    0,  324,    0,    0,    0,
    0,  115,    0,  115,  115,  115,  115,  115,    0,    0,
  115,   57,   57,   57,   57,   57,   57,   57,   57,    0,
    0,    0,   57,   42,    0,   57,   57,   57,   57,   57,
   57,    0,    0,    0,    0,    0,   57,    0,    0,    0,
   57,    0,    0,    0,   57,   57,   57,   57,    0,   57,
   57,   57,    0,   57,   57,    0,   57,   57,   57,    0,
    0,    0,    0,    0,    0,    0,   57,    0,    0,    0,
   57,    0,    0,    0,    0,    0,    0,    0,   57,   70,
   70,   70,   70,   70,   70,   70,   70,    0,    0,    0,
   70,    0,    0,   70,   70,   70,   70,   70,   70,    0,
    0,    0,    0,   57,   70,    0,    0,    0,    0,   57,
    0,    0,   70,   70,   70,   70,    0,   70,   70,   70,
    0,   70,   70,  103,  103,  103,  103,  103,  103,  103,
  103,    0,    0,    0,  103,    0,    0,  103,  103,  103,
  103,  103,  103,    0,    0,    0,    0,    0,  103,    0,
  236,    0,    0,    0,    0,    0,  103,  103,  103,  103,
    0,  103,  103,  103,    0,  103,  103,   93,   93,   93,
   93,   93,   93,   93,   93,    0,    0,   70,   93,    0,
    0,   93,   93,   93,   93,   93,   93,    0,    0,    0,
    0,    0,   93,  148,    0,    0,    0,    0,    0,    0,
   93,   93,   93,   93,    0,   93,   93,   93,    0,   93,
   93,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  103,    0,    0,    0,    0,    0,    0,  236,  236,
  236,  236,  236,  236,  236,  236,    0,    0,    0,  236,
    0,    0,  236,  236,  236,  236,  236,  236,    0,    0,
    0,  189,    0,  236,    0,    0,    0,    0,    0,    0,
    0,  236,  236,  236,  236,   93,  236,  236,  236,    0,
  236,  236,    8,   21,   22,   23,   24,    9,   10,   25,
    0,    0,    0,   26,    0,    0,   27,   28,   29,   30,
   31,   32,    0,    0,  161,    0,    0,   33,    0,    0,
    0,    0,  236,    0,    0,   34,   35,   36,   11,    0,
   37,   38,   12,  236,   39,   40,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  236,  236,    0,  236,  236,
  236,  236,    0,    0,    0,    0,    0,    0,  148,  236,
    0,    0,    0,  236,    0,  148,    0,    0,    0,  236,
  236,  236,   45,    0,    0,    0,  148,    0,    0,  236,
    0,  236,    0,    0,    0,    0,    0,    0,    0,    0,
   41,  148,  148,  148,  148,    0,  236,  236,  236,  236,
  236,  236,  148,    0,    0,  236,  148,    0,    0,    0,
    0,    0,  148,  148,  148,  153,  189,    0,    0,    0,
    0,    0,  148,  189,  148,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  189,    0,    0,    0,    0,  148,
    0,  148,  148,  148,  148,    0,    0,    0,  148,  189,
  189,  189,  189,    0,    0,    0,    0,    0,  167,  161,
  189,    0,    0,    0,  189,    0,  161,    0,    0,    0,
  189,  189,  189,    0,    0,    0,    0,  161,    0,    0,
  189,    0,  189,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  161,  161,  161,  161,    0,  189,    0,  189,
  189,  189,  189,  161,    0,    0,  189,  161,    0,    0,
    0,    0,    0,  161,  161,  161,   49,   45,    0,    0,
    0,    0,    0,  161,   45,  161,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   45,    0,    0,    0,    0,
  161,    0,  161,  161,  161,  161,    0,    0,    0,  161,
   45,   45,   45,   45,    0,    0,    0,    0,    0,   53,
  153,   45,    0,    0,    0,   45,    0,  153,    0,    0,
    0,   45,   45,   45,    0,    0,    0,    0,  153,    0,
    0,   45,    0,   45,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  153,  153,  153,  153,    0,   45,    0,
   45,   45,   45,   45,  153,    0,    0,   45,  153,    0,
  167,    0,    0,    0,  153,  153,  153,  178,    0,    0,
    0,  167,    0,    0,  153,    0,  153,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  167,  167,  167,  167,
    0,  153,    0,  153,  153,  153,  153,  167,    0,    0,
  153,  167,    0,    0,    0,    0,    0,  167,  167,  167,
    0,    0,    0,    0,    0,    0,    0,  167,   49,  167,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   49,
    0,    0,    0,    0,  167,    0,  167,  167,  167,  167,
    0,    0,    0,  167,   49,   49,   49,   49,    0,    0,
    0,    0,    0,    0,    0,   49,    0,    0,    0,   49,
    0,   53,    0,    0,    0,   49,   49,   49,    0,    0,
    0,    0,   53,    0,    0,   49,    0,   49,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   53,   53,   53,
   53,    0,   49,    0,   49,   49,   49,   49,   53,    0,
    0,   49,   53,    0,    0,  135,    0,    0,   53,   53,
   53,    0,    0,    0,    0,    0,  136,    0,   53,  178,
   53,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  178,  137,  138,  139,  140,   53,    0,   53,   53,   53,
   53,    0,  141,    0,   53,  178,  178,  178,  178,    0,
    0,    0,  143,  144,    0,    0,  178,    0,    0,    0,
  178,    0,  146,    0,  147,    0,  178,  178,  178,    0,
    0,    0,    0,    0,    0,    0,  178,    0,  178,    0,
    0,  148,  149,  150,    0,    0,    0,    0,  152,    0,
    0,    0,    0,  178,    0,  178,  178,  178,  178,    0,
    0,    0,  178,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                     125,
    0,   10,  103,  104,  103,  104,   58,  103,  104,  125,
   10,  125,  101,  102,  101,  101,  101,  198,  199,  101,
  101,  185,  101,  169,  101,  259,  102,  102,  102,  120,
  125,  322,  279,  190,  186,  270,  302,  342,   58,  191,
   58,  307,  277,  257,  258,  350,  312,  279,  280,  281,
  282,  283,  299,  288,  307,  308,  309,  310,  311,  327,
  328,  329,  330,  331,  337,  338,  339,  340,  341,  304,
  305,  306,   58,  339,   58,  342,  343,   58,  345,  314,
  267,  268,  269,  318,  375,  319,  320,  321,  322,  323,
  247,  326,  315,  316,  317,  241,  185,   58,  185,  185,
  185,  190,    0,  185,  185,   58,  185,  277,  185,  285,
  286,  287,   10,   58,  190,  190,  190,   58,  288,  301,
  302,  212,  358,  359,  215,  125,  342,  343,  344,  345,
  346,  358,  359,  303,  304,  305,  306,   58,  351,  352,
  315,  316,  348,  349,  314,    6,    7,   58,  318,   87,
   88,  315,  333,  334,  324,  325,  326,   58,  247,  360,
  361,   58,   58,   58,  334,   58,  336,   58,   58,   58,
    0,  247,  247,  247,  123,  270,  350,  296,   58,  123,
   10,  123,  277,  353,  354,  355,  356,   58,  369,  350,
  360,  271,  350,  288,  350,  350,  290,  350,   58,   58,
   58,   58,   58,   58,   58,   58,   58,   58,   58,  304,
  305,  306,   58,   58,    0,   58,   58,   58,  352,  314,
  351,  289,  347,  318,   10,  351,  315,  125,  315,  315,
  315,  326,  349,  315,  315,  351,  315,  351,  315,  312,
  341,  313,  341,  290,  352,  341,  291,   58,   58,  333,
  259,   58,  350,  350,   58,  264,  265,  300,    0,  259,
  260,  261,  262,  263,  264,  265,  266,   45,   10,  352,
  270,   58,   45,  273,  274,  275,  276,  277,  278,  348,
   47,  125,   58,  335,  284,  125,  295,  348,  288,  125,
  299,  348,  292,  293,  294,  295,  348,  297,  298,  299,
  335,  301,  302,  303,  304,  305,  306,  347,    0,    0,
  351,  125,  351,  351,  314,  270,  125,  125,  318,    0,
  277,  280,    7,  283,  324,  325,  326,  110,  291,   10,
    7,    7,  113,    7,  334,   99,  336,  255,    7,  124,
  248,   21,  370,  299,  230,   -1,  266,   -1,   -1,   -1,
   -1,  351,   -1,  353,  354,  355,  356,  357,   -1,   -1,
  360,  259,  260,  261,  262,  263,  264,  265,  266,   -1,
   -1,   -1,  270,   10,   -1,  273,  274,  275,  276,  277,
  278,   -1,   -1,   -1,   -1,   -1,  284,   -1,   -1,   -1,
  288,   -1,   -1,   -1,  292,  293,  294,  295,   -1,  297,
  298,  299,   -1,  301,  302,   -1,  304,  305,  306,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  314,   -1,   -1,   -1,
  318,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  326,  259,
  260,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,   -1,   -1,  273,  274,  275,  276,  277,  278,   -1,
   -1,   -1,   -1,  351,  284,   -1,   -1,   -1,   -1,  357,
   -1,   -1,  292,  293,  294,  295,   -1,  297,  298,  299,
   -1,  301,  302,  259,  260,  261,  262,  263,  264,  265,
  266,   -1,   -1,   -1,  270,   -1,   -1,  273,  274,  275,
  276,  277,  278,   -1,   -1,   -1,   -1,   -1,  284,   -1,
  125,   -1,   -1,   -1,   -1,   -1,  292,  293,  294,  295,
   -1,  297,  298,  299,   -1,  301,  302,  259,  260,  261,
  262,  263,  264,  265,  266,   -1,   -1,  357,  270,   -1,
   -1,  273,  274,  275,  276,  277,  278,   -1,   -1,   -1,
   -1,   -1,  284,  125,   -1,   -1,   -1,   -1,   -1,   -1,
  292,  293,  294,  295,   -1,  297,  298,  299,   -1,  301,
  302,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  357,   -1,   -1,   -1,   -1,   -1,   -1,  259,  260,
  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,  270,
   -1,   -1,  273,  274,  275,  276,  277,  278,   -1,   -1,
   -1,  125,   -1,  284,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  292,  293,  294,  295,  357,  297,  298,  299,   -1,
  301,  302,  259,  260,  261,  262,  263,  264,  265,  266,
   -1,   -1,   -1,  270,   -1,   -1,  273,  274,  275,  276,
  277,  278,   -1,   -1,  125,   -1,   -1,  284,   -1,   -1,
   -1,   -1,  277,   -1,   -1,  292,  293,  294,  295,   -1,
  297,  298,  299,  288,  301,  302,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  300,  357,   -1,  303,  304,
  305,  306,   -1,   -1,   -1,   -1,   -1,   -1,  270,  314,
   -1,   -1,   -1,  318,   -1,  277,   -1,   -1,   -1,  324,
  325,  326,  125,   -1,   -1,   -1,  288,   -1,   -1,  334,
   -1,  336,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  357,  303,  304,  305,  306,   -1,  351,  352,  353,  354,
  355,  356,  314,   -1,   -1,  360,  318,   -1,   -1,   -1,
   -1,   -1,  324,  325,  326,  125,  270,   -1,   -1,   -1,
   -1,   -1,  334,  277,  336,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  288,   -1,   -1,   -1,   -1,  351,
   -1,  353,  354,  355,  356,   -1,   -1,   -1,  360,  303,
  304,  305,  306,   -1,   -1,   -1,   -1,   -1,  125,  270,
  314,   -1,   -1,   -1,  318,   -1,  277,   -1,   -1,   -1,
  324,  325,  326,   -1,   -1,   -1,   -1,  288,   -1,   -1,
  334,   -1,  336,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  303,  304,  305,  306,   -1,  351,   -1,  353,
  354,  355,  356,  314,   -1,   -1,  360,  318,   -1,   -1,
   -1,   -1,   -1,  324,  325,  326,  125,  270,   -1,   -1,
   -1,   -1,   -1,  334,  277,  336,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  288,   -1,   -1,   -1,   -1,
  351,   -1,  353,  354,  355,  356,   -1,   -1,   -1,  360,
  303,  304,  305,  306,   -1,   -1,   -1,   -1,   -1,  125,
  270,  314,   -1,   -1,   -1,  318,   -1,  277,   -1,   -1,
   -1,  324,  325,  326,   -1,   -1,   -1,   -1,  288,   -1,
   -1,  334,   -1,  336,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  303,  304,  305,  306,   -1,  351,   -1,
  353,  354,  355,  356,  314,   -1,   -1,  360,  318,   -1,
  277,   -1,   -1,   -1,  324,  325,  326,  125,   -1,   -1,
   -1,  288,   -1,   -1,  334,   -1,  336,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  303,  304,  305,  306,
   -1,  351,   -1,  353,  354,  355,  356,  314,   -1,   -1,
  360,  318,   -1,   -1,   -1,   -1,   -1,  324,  325,  326,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,  277,  336,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  288,
   -1,   -1,   -1,   -1,  351,   -1,  353,  354,  355,  356,
   -1,   -1,   -1,  360,  303,  304,  305,  306,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  314,   -1,   -1,   -1,  318,
   -1,  277,   -1,   -1,   -1,  324,  325,  326,   -1,   -1,
   -1,   -1,  288,   -1,   -1,  334,   -1,  336,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  303,  304,  305,
  306,   -1,  351,   -1,  353,  354,  355,  356,  314,   -1,
   -1,  360,  318,   -1,   -1,  277,   -1,   -1,  324,  325,
  326,   -1,   -1,   -1,   -1,   -1,  288,   -1,  334,  277,
  336,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  288,  303,  304,  305,  306,  351,   -1,  353,  354,  355,
  356,   -1,  314,   -1,  360,  303,  304,  305,  306,   -1,
   -1,   -1,  324,  325,   -1,   -1,  314,   -1,   -1,   -1,
  318,   -1,  334,   -1,  336,   -1,  324,  325,  326,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,  336,   -1,
   -1,  353,  354,  355,   -1,   -1,   -1,   -1,  360,   -1,
   -1,   -1,   -1,  351,   -1,  353,  354,  355,  356,   -1,
   -1,   -1,  360,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 360
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const socks_yyname[] =
#else
char *socks_yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'-'",0,"'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"SERVERCONFIG","CLIENTCONFIG","DEPRECATED","CLIENTRULE","INTERNAL","EXTERNAL",
"EXTERNAL_ROTATION","DEBUGING","RESOLVEPROTOCOL","SRCHOST","NOMISMATCH",
"NOUNKNOWN","CHECKREPLYAUTH","EXTENSION","BIND","PRIVILEGED","IOTIMEOUT",
"IOTIMEOUT_TCP","IOTIMEOUT_UDP","NEGOTIATETIMEOUT","METHOD","CLIENTMETHOD",
"NONE","GSSAPI","UNAME","RFC931","PAM","COMPATIBILITY","REUSEADDR","SAMEPORT",
"DRAFT_5_05","CLIENTCOMPATIBILITY","NECGSSAPI","USERNAME","GROUPNAME",
"USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","LOGOUTPUT","LOGFILE",
"CHILD_MAXIDLE","CHILD_MAXREQUESTS","ROUTE","VIA","VERDICT_BLOCK",
"VERDICT_PASS","PAMSERVICENAME","GSSAPISERVICE","GSSAPIKEYTAB","GSSAPIENCTYPE",
"GSSAPIENC_ANY","GSSAPIENC_CLEAR","GSSAPIENC_INTEGRITY",
"GSSAPIENC_CONFIDENTIALITY","GSSAPIENC_PERMESSAGE","GSSAPISERVICENAME",
"GSSAPIKEYTABNAME","PROTOCOL","PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE",
"PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5",
"PROXYPROTOCOL_MSPROXY_V2","PROXYPROTOCOL_HTTP_V1_0","PROXYPROTOCOL_UPNP",
"USER","GROUP","COMMAND","COMMAND_BIND","COMMAND_CONNECT",
"COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE",
"LIBWRAPSTART","OPERATOR","SOCKS_LOG","SOCKS_LOG_CONNECT","SOCKS_LOG_DATA",
"SOCKS_LOG_DISCONNECT","SOCKS_LOG_ERROR","SOCKS_LOG_IOOPERATION","IPADDRESS",
"DOMAINNAME","DIRECT","IFNAME","URL","PORT","PORTNUMBER","SERVICENAME","NUMBER",
"FROM","TO","REDIRECT","BANDWIDTH","MAXSESSIONS","UDPPORTRANGE","UDPCONNECTDST",
"YES","NO","BOUNCE",
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
"serverline :",
"serverline : serverline '\\n'",
"serverline : serverline serverconfig",
"serverline : serverline clientrule",
"serverline : serverline rule",
"serverline : serverline route",
"clientline :",
"clientline : clientline '\\n'",
"clientline : clientline clientconfig",
"clientline : clientline route",
"clientinit : CLIENTCONFIG",
"clientconfig : clientoption",
"clientconfig : deprecated",
"serverconfig : global_authmethod",
"serverconfig : global_clientauthmethod",
"serverconfig : deprecated",
"serverconfig : internal",
"serverconfig : external",
"serverconfig : external_rotation",
"serverconfig : logoutput",
"serverconfig : serveroption",
"serverconfig : userids",
"serverconfig : childstate",
"serverconfig : debuging",
"serverconfig : udpconnectdst",
"serveroption : compatibility",
"serveroption : negotiatetimeout",
"serveroption : extension",
"serveroption : iotimeout",
"serveroption : resolveprotocol",
"serveroption : srchost",
"deprecated : DEPRECATED",
"route : ROUTE routeinit '{' routeoptions fromto gateway routeoptions '}'",
"routeinit :",
"proxyprotocol : PROXYPROTOCOL ':' proxyprotocols",
"proxyprotocolname : PROXYPROTOCOL_SOCKS_V4",
"proxyprotocolname : PROXYPROTOCOL_SOCKS_V5",
"proxyprotocolname : PROXYPROTOCOL_MSPROXY_V2",
"proxyprotocolname : PROXYPROTOCOL_HTTP_V1_0",
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
"internal : INTERNAL internalinit ':' internaladdress",
"internalinit :",
"external : EXTERNAL externalinit ':' externaladdress",
"externalinit :",
"external_rotation : EXTERNAL_ROTATION ':' NONE",
"external_rotation : EXTERNAL_ROTATION ':' ROUTE",
"clientoption : logoutput",
"clientoption : debuging",
"clientoption : resolveprotocol",
"logoutput : LOGOUTPUT ':' logoutputdevices",
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
"debuging : DEBUGING ':' NUMBER",
"udpconnectdst : UDPCONNECTDST ':' YES",
"udpconnectdst : UDPCONNECTDST ':' NO",
"compatibility : COMPATIBILITY ':' compatibilitynames",
"compatibilityname : REUSEADDR",
"compatibilityname : SAMEPORT",
"compatibilityname : DRAFT_5_05",
"compatibilitynames : compatibilityname",
"compatibilitynames : compatibilityname compatibilitynames",
"resolveprotocol : RESOLVEPROTOCOL ':' resolveprotocolname",
"resolveprotocolname : PROTOCOL_FAKE",
"resolveprotocolname : PROTOCOL_TCP",
"resolveprotocolname : PROTOCOL_UDP",
"srchost : SRCHOST ':' srchostoptions",
"srchostoption : NOMISMATCH",
"srchostoption : NOUNKNOWN",
"srchostoption : CHECKREPLYAUTH",
"srchostoptions : srchostoption",
"srchostoptions : srchostoption srchostoptions",
"authmethod : METHOD ':' authmethods",
"$$1 :",
"global_authmethod : METHOD ':' $$1 authmethods",
"$$2 :",
"global_clientauthmethod : CLIENTMETHOD ':' $$2 authmethods",
"authmethodname : NONE",
"authmethodname : GSSAPI",
"authmethodname : UNAME",
"authmethodname : RFC931",
"authmethodname : PAM",
"authmethods : authmethodname",
"authmethods : authmethodname authmethods",
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
"option : gssapiservicename",
"option : gssapikeytab",
"option : gssapienctype",
"option : user",
"option : group",
"option : bounce",
"option : session",
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
"internaladdress : ipaddress port",
"internaladdress : domain port",
"internaladdress : ifname port",
"externaladdress : ipaddress",
"externaladdress : domain",
"externaladdress : ifname",
"address : ipaddress '/' netmask port",
"address : domain port",
"address : ifname port",
"gwaddress : ipaddress gwport",
"gwaddress : domain gwport",
"gwaddress : ifname gwport",
"gwaddress : direct",
"gwaddress : url",
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
"portstart : PORTNUMBER",
"portend : PORTNUMBER",
"portservice : SERVICENAME",
"portoperator : OPERATOR",
"udpportrange : UDPPORTRANGE ':' udpportrange_start '-' udpportrange_end",
"udpportrange_start : PORTNUMBER",
"udpportrange_end : PORTNUMBER",
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
#line 1318 "config_parse.y"

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
#if YYDEBUG
      yydebug         = 0;
#endif /* YYDEBUG */
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
         serrx(EXIT_FAILURE, "%s: illegal format for ip address specification "
         "in SOCKS_SERVER %s: too short/long", function, proxyserver);

      strncpy(ipstring, proxyserver, (size_t)(portstring - proxyserver));
      ipstring[portstring - proxyserver] = NUL;
      ++portstring;

      bzero(&saddr, sizeof(saddr));
      saddr.sin_family = AF_INET;
      if (inet_pton(saddr.sin_family, ipstring, &saddr.sin_addr) != 1)
         serr(EXIT_FAILURE, "%s: illegal format for ip address specification "
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

   dst = rdr_from = rdr_to = src;
   *rule = ruleinitmem;
}

#endif /* SOCKS_SERVER || BAREFOOTD */
#line 1378 "config_parse.c"
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
#line 270 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      protocol       = &protocolmem;
      extension      = &sockscf.extension;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 4:
#line 279 "config_parse.y"
{ yyval.string = NULL; }
break;
case 10:
#line 287 "config_parse.y"
{ yyval.string = NULL; }
break;
case 14:
#line 294 "config_parse.y"
{
   }
break;
case 35:
#line 325 "config_parse.y"
{
      yyerror("given keyword \"%s\" is deprecated", yyvsp[0].string);
   }
break;
case 36:
#line 330 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;
      route.gw.state  = state;

      socks_addroute(&route, 1);
   }
break;
case 37:
#line 340 "config_parse.y"
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

      bzero(&state, sizeof(state));
      bzero(&route, sizeof(route));
      bzero(&gw, sizeof(gw));
      bzero(&src, sizeof(src));
      bzero(&dst, sizeof(dst));
      src.atype = SOCKS_ADDR_IPV4;
      dst.atype = SOCKS_ADDR_IPV4;
   }
break;
case 39:
#line 368 "config_parse.y"
{
         proxyprotocol->socks_v4    = 1;
   }
break;
case 40:
#line 371 "config_parse.y"
{
         proxyprotocol->socks_v5    = 1;
   }
break;
case 41:
#line 374 "config_parse.y"
{
         proxyprotocol->msproxy_v2  = 1;
   }
break;
case 42:
#line 377 "config_parse.y"
{
         proxyprotocol->http_v1_0   = 1;
   }
break;
case 43:
#line 380 "config_parse.y"
{
         proxyprotocol->upnp        = 1;
   }
break;
case 48:
#line 393 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      if (addlinkedname(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER  || BAREFOOTD */
   }
break;
case 52:
#line 408 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      if (addlinkedname(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER  || BAREFOOTD */
   }
break;
case 56:
#line 423 "config_parse.y"
{
         extension->bind = 1;
   }
break;
case 59:
#line 432 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      addinternal(ruleaddr);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 60:
#line 439 "config_parse.y"
{
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
break;
case 61:
#line 456 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      addexternal(ruleaddr);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 62:
#line 463 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      static struct ruleaddr_t mem;

      addrinit(&mem);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 63:
#line 472 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 64:
#line 476 "config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
      yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
   }
break;
case 69:
#line 494 "config_parse.y"
{
   socks_addlogfile(yyvsp[0].string);
}
break;
case 72:
#line 503 "config_parse.y"
{
#if !SOCKS_CLIENT
      sockscf.child.maxidle = SOCKD_FREESLOTS * 2;
   }
break;
case 73:
#line 507 "config_parse.y"
{
      sockscf.child.maxidle = 0;
   }
break;
case 74:
#line 510 "config_parse.y"
{
      sockscf.child.maxrequests = atoi(yyvsp[0].string);
#endif /* !SOCKS_CLIENT */
   }
break;
case 78:
#line 521 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged         = yyvsp[0].uid;
      sockscf.uid.privileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 79:
#line 533 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged         = yyvsp[0].uid;
      sockscf.uid.unprivileged_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 80:
#line 545 "config_parse.y"
{
#if HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD)
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.libwrap         = yyvsp[0].uid;
      sockscf.uid.libwrap_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#else  /* !HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD) */
      yyerror("libwrap support not compiled in");
#endif /* !HAVE_LIBWRAP (SOCKS_SERVER || BAREFOOTD)*/
   }
break;
case 81:
#line 560 "config_parse.y"
{
      struct passwd *pw;

      if ((pw = socks_getpwnam(yyvsp[0].string)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
      else
         yyval.uid = pw->pw_uid;
   }
break;
case 82:
#line 570 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.timeout.tcpio = (time_t)atol(yyvsp[0].string);
      sockscf.timeout.udpio = sockscf.timeout.tcpio;
   }
break;
case 83:
#line 575 "config_parse.y"
{
      sockscf.timeout.tcpio = (time_t)atol(yyvsp[0].string);
   }
break;
case 84:
#line 578 "config_parse.y"
{
      sockscf.timeout.udpio = (time_t)atol(yyvsp[0].string);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 85:
#line 584 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 86:
#line 591 "config_parse.y"
{
      sockscf.option.debug = atoi(yyvsp[0].string);
   }
break;
case 87:
#line 596 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.option.udpconnectdst = 1;
   }
break;
case 88:
#line 600 "config_parse.y"
{
      sockscf.option.udpconnectdst = 0;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 90:
#line 610 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.compat.reuseaddr = 1;
   }
break;
case 91:
#line 614 "config_parse.y"
{
      sockscf.compat.sameport = 1;
   }
break;
case 92:
#line 617 "config_parse.y"
{
      sockscf.compat.draft_5_05 = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 96:
#line 630 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 97:
#line 633 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 98:
#line 640 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 100:
#line 648 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_LIBWRAP
         sockscf.srchost.nomismatch = 1;
   }
break;
case 101:
#line 653 "config_parse.y"
{
         sockscf.srchost.nounknown = 1;
#else
      yyerror("srchostoption requires libwrap");
#endif /* HAVE_LIBWRAP */
   }
break;
case 102:
#line 659 "config_parse.y"
{
         sockscf.srchost.checkreplyauth = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 106:
#line 673 "config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.methodv;
   methodc = &sockscf.methodc;
   *methodc = 0; /* reset. */
#endif /* SOCKS_SERVER */
   }
break;
case 108:
#line 682 "config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.clientmethodv;
   methodc = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif /* SOCKS_SERVER */
   }
break;
case 110:
#line 691 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_NONE);
   }
break;
case 111:
#line 694 "config_parse.y"
{
#if !HAVE_GSSAPI
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#else
      ADDMETHOD(AUTHMETHOD_GSSAPI);
#endif /* !HAVE_GSSAPI */
   }
break;
case 112:
#line 701 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
break;
case 113:
#line 704 "config_parse.y"
{
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
break;
case 114:
#line 715 "config_parse.y"
{
#if HAVE_PAM
      ADDMETHOD(AUTHMETHOD_PAM);
#else /* !HAVE_PAM */
      yyerror("method %s requires pam library", AUTHMETHOD_PAMs);
#endif /* HAVE_PAM */
   }
break;
case 117:
#line 732 "config_parse.y"
{
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
break;
case 119:
#line 753 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("bandwidth");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 120:
#line 758 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 121:
#line 763 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("redirect");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 122:
#line 770 "config_parse.y"
{ yyval.string = NULL; }
break;
case 124:
#line 774 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

      addsocksrule(&rule);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 126:
#line 788 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("bandwidth");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 131:
#line 797 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("redirect");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 132:
#line 804 "config_parse.y"
{ yyval.string = NULL; }
break;
case 144:
#line 818 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 145:
#line 823 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("session");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 147:
#line 833 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#endif /* HAVE_GSSAPI */
   }
break;
case 150:
#line 847 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 151:
#line 852 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 155:
#line 867 "config_parse.y"
{
         command->bind = 1;
   }
break;
case 156:
#line 870 "config_parse.y"
{
         command->connect = 1;
   }
break;
case 157:
#line 873 "config_parse.y"
{
         command->udpassociate = 1;
   }
break;
case 158:
#line 879 "config_parse.y"
{
         command->bindreply = 1;
   }
break;
case 159:
#line 883 "config_parse.y"
{
         command->udpreply = 1;
   }
break;
case 163:
#line 896 "config_parse.y"
{
      protocol->tcp = 1;
   }
break;
case 164:
#line 899 "config_parse.y"
{
      protocol->udp = 1;
   }
break;
case 170:
#line 916 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
   static session_t ssinit;

  /*
   * temporarily allocate ordinary memory, later on point it to
   * the correct shared mem.
   */
   if ((rule.ss = malloc(sizeof(*rule.ss))) == NULL)
      serr(EXIT_FAILURE, NOMEM);
   *rule.ss = ssinit;
   if ((rule.ss->maxsessions = atoi(yyvsp[0].string)) < 0)
      yyerror("session value can not be less than 0");
#endif /* SOCKS_SERVER || BAREFOOTD */
}
break;
case 171:
#line 933 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      static bw_t bwmeminit;

     /*
      * temporarily allocate ordinary memory, later on point it to
      * the correct index in sockscf.bwv.
      */
      if ((rule.bw = malloc(sizeof(*rule.bw))) == NULL)
         serr(EXIT_FAILURE, NOMEM);

      *rule.bw = bwmeminit;

      if ((rule.bw->maxbps = atoi(yyvsp[0].string)) <= 0)
         yyerror("bandwidth value must be greater than 0");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 173:
#line 956 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
   rule.log.connect = 1;
   }
break;
case 174:
#line 960 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 175:
#line 963 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 176:
#line 966 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 177:
#line 969 "config_parse.y"
{
         rule.log.iooperation = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 180:
#line 980 "config_parse.y"
{
#if HAVE_PAM && (SOCKS_SERVER || BAREFOOTD)
      if (strlen(yyvsp[0].string) >= sizeof(rule.state.pamservicename))
         yyerror("servicename too long");
      strcpy(rule.state.pamservicename, yyvsp[0].string);
#else
      yyerror("pam support not compiled in");
#endif /* HAVE_PAM && (SOCKS_SERVER || BAREFOOTD) */
   }
break;
case 181:
#line 992 "config_parse.y"
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
case 182:
#line 1003 "config_parse.y"
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
case 184:
#line 1021 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 185:
#line 1027 "config_parse.y"
{
      gssapiencryption->clear = 1;
   }
break;
case 186:
#line 1030 "config_parse.y"
{
      gssapiencryption->integrity = 1;
   }
break;
case 187:
#line 1033 "config_parse.y"
{
      gssapiencryption->confidentiality = 1;
   }
break;
case 188:
#line 1036 "config_parse.y"
{
      yyerror("gssapi per-message encryption not supported");
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
break;
case 192:
#line 1051 "config_parse.y"
{
#if HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD)
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
      yyerror("libwrapsupport not compiled in");
#endif /* HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD) */
   }
break;
case 207:
#line 1105 "config_parse.y"
{ yyval.string = NULL; }
break;
case 209:
#line 1109 "config_parse.y"
{
      addrinit(&src);
   }
break;
case 210:
#line 1114 "config_parse.y"
{
      addrinit(&dst);
   }
break;
case 211:
#line 1119 "config_parse.y"
{
      addrinit(&rdr_from);
   }
break;
case 212:
#line 1124 "config_parse.y"
{
      addrinit(&rdr_to);
   }
break;
case 213:
#line 1129 "config_parse.y"
{
#if BAREFOOTD
      addrinit(&bounce_to);
#endif /* BAREFOOTD */
   }
break;
case 214:
#line 1137 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 229:
#line 1167 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton(yyvsp[0].string, ipaddr) != 1)
         yyerror("bad address: %s", yyvsp[0].string);
   }
break;
case 230:
#line 1176 "config_parse.y"
{
      if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
         yyerror("bad netmask: %s", yyvsp[0].string);

      netmask->s_addr
      = atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
   }
break;
case 231:
#line 1183 "config_parse.y"
{
         if (!inet_aton(yyvsp[0].string, netmask))
            yyerror("bad netmask: %s", yyvsp[0].string);
   }
break;
case 232:
#line 1189 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");
      strcpy(domain, yyvsp[0].string);
   }
break;
case 233:
#line 1198 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
         yyerror("interface name too long");
      strcpy(ifname, yyvsp[0].string);
   }
break;
case 234:
#line 1208 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", yyvsp[0].string);
      strcpy(domain, yyvsp[0].string);

      proxyprotocol->direct = 1;
   }
break;
case 235:
#line 1219 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;

      if (strlen(yyvsp[0].string) >= MAXURLLEN)
         yyerror("url \"%s\" too long", yyvsp[0].string);
      strcpy(url, yyvsp[0].string);
   }
break;
case 236:
#line 1229 "config_parse.y"
{ yyval.string = NULL; }
break;
case 240:
#line 1235 "config_parse.y"
{ yyval.string = NULL; }
break;
case 245:
#line 1247 "config_parse.y"
{
      *port_tcp   = htons((in_port_t)atoi(yyvsp[0].string));
      *port_udp   = htons((in_port_t)atoi(yyvsp[0].string));
   }
break;
case 246:
#line 1253 "config_parse.y"
{
      ruleaddr->portend    = htons((in_port_t)atoi(yyvsp[0].string));
      ruleaddr->operator   = range;
   }
break;
case 247:
#line 1259 "config_parse.y"
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
case 248:
#line 1290 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 250:
#line 1298 "config_parse.y"
{
#if SOCKS_SERVER
   rule.udprange.start = htons((in_port_t)atoi(yyvsp[0].string));
#endif /* SOCKS_SERVER */
   }
break;
case 251:
#line 1305 "config_parse.y"
{
#if SOCKS_SERVER
   rule.udprange.end = htons((in_port_t)atoi(yyvsp[0].string));
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerror("udp end port (%s) can not be less than udp start port (%u)",
      yyvsp[0].string, ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
break;
#line 2551 "config_parse.c"
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
