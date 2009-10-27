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
"$Id: config_parse.y,v 1.292 2009/10/23 11:43:36 karls Exp $";

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
#define ROUTE 298
#define VIA 299
#define VERDICT_BLOCK 300
#define VERDICT_PASS 301
#define PAMSERVICENAME 302
#define GSSAPISERVICE 303
#define GSSAPIKEYTAB 304
#define GSSAPIENCTYPE 305
#define GSSAPIENC_ANY 306
#define GSSAPIENC_CLEAR 307
#define GSSAPIENC_INTEGRITY 308
#define GSSAPIENC_CONFIDENTIALITY 309
#define GSSAPIENC_PERMESSAGE 310
#define GSSAPISERVICENAME 311
#define GSSAPIKEYTABNAME 312
#define PROTOCOL 313
#define PROTOCOL_TCP 314
#define PROTOCOL_UDP 315
#define PROTOCOL_FAKE 316
#define PROXYPROTOCOL 317
#define PROXYPROTOCOL_SOCKS_V4 318
#define PROXYPROTOCOL_SOCKS_V5 319
#define PROXYPROTOCOL_MSPROXY_V2 320
#define PROXYPROTOCOL_HTTP_V1_0 321
#define PROXYPROTOCOL_UPNP 322
#define USER 323
#define GROUP 324
#define COMMAND 325
#define COMMAND_BIND 326
#define COMMAND_CONNECT 327
#define COMMAND_UDPASSOCIATE 328
#define COMMAND_BINDREPLY 329
#define COMMAND_UDPREPLY 330
#define ACTION 331
#define LINE 332
#define LIBWRAPSTART 333
#define OPERATOR 334
#define LOG 335
#define LOG_CONNECT 336
#define LOG_DATA 337
#define LOG_DISCONNECT 338
#define LOG_ERROR 339
#define LOG_IOOPERATION 340
#define IPADDRESS 341
#define DOMAINNAME 342
#define DIRECT 343
#define IFNAME 344
#define URL 345
#define PORT 346
#define PORTNUMBER 347
#define SERVICENAME 348
#define NUMBER 349
#define FROM 350
#define TO 351
#define REDIRECT 352
#define BANDWIDTH 353
#define MAXSESSIONS 354
#define UDPPORTRANGE 355
#define UDPCONNECTDST 356
#define YES 357
#define NO 358
#define BOUNCE 359
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
   53,   73,   68,   68,   68,   69,   70,   71,   72,   41,
   41,   41,   42,   36,   37,   37,   54,   55,   55,   55,
   56,   56,   20,   21,   21,   21,   22,   23,   23,   23,
   24,   24,   59,  115,   57,  116,   58,   61,   61,   61,
   61,   61,   60,   60,   82,   83,   83,   83,   83,   84,
   84,   79,   80,   80,   80,   80,   80,   80,   80,   81,
   81,   85,   85,   85,   85,   85,   85,   85,   85,   85,
   85,   85,   85,   62,   63,   64,   64,   86,   86,   25,
   26,   26,   27,   27,   27,   27,   27,    4,    5,    5,
    6,    6,   87,   28,   28,   28,   30,   31,   29,   88,
   90,   90,   90,   90,   90,   89,   89,   16,   17,   18,
   19,  120,  120,  120,  120,  120,  119,  119,  113,   91,
   92,   93,  117,  118,   76,   77,   77,   77,   77,   77,
   77,   77,   77,   77,   78,   78,  103,  104,  121,  122,
  114,   75,   94,   94,   94,   95,   95,   95,   96,   96,
   96,   98,   98,   98,   98,   98,   97,  105,  105,   99,
  100,  101,  102,  106,  106,  106,  106,  107,  107,  111,
  111,  108,  109,  123,  112,  110,   33,   34,   35,
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
    2,    3,    1,    1,    1,    3,    3,    3,    1,    3,
    3,    3,    3,    3,    3,    3,    3,    1,    1,    1,
    1,    2,    3,    1,    1,    1,    3,    1,    1,    1,
    1,    2,    3,    0,    4,    0,    4,    1,    1,    1,
    1,    1,    1,    2,    7,    1,    1,    1,    1,    0,
    2,    6,    1,    1,    1,    1,    1,    1,    1,    0,
    2,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    3,    1,    1,    2,    1,    1,    3,
    1,    2,    1,    1,    1,    1,    1,    3,    1,    2,
    1,    1,    2,    3,    2,    2,    1,    3,    3,    3,
    1,    1,    1,    1,    1,    1,    2,    3,    3,    3,
    3,    1,    1,    1,    1,    1,    1,    2,    4,    3,
    3,    3,    3,    3,    3,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    0,    2,    1,    1,    1,    1,
    1,    1,    2,    2,    2,    1,    1,    1,    4,    2,
    2,    2,    2,    2,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    0,    3,    3,    2,    0,    3,    1,
    1,    3,    1,    1,    1,    1,    5,    1,    1,
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
    0,    0,    0,    0,    0,    0,    0,  148,  149,    0,
    5,   19,   33,   34,   27,   28,   32,   30,   31,   20,
   21,   22,   23,   29,   17,   18,   24,    6,   25,   73,
   74,   75,   26,    9,    8,    7,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  104,  106,    0,    0,    0,    0,    0,    0,    0,
   84,   95,   96,   94,   93,   69,    0,   68,    0,    0,
    0,    0,   63,   64,   98,   99,  100,    0,   97,   56,
    0,   55,   80,   81,   82,   83,    0,    0,   88,   89,
   90,    0,   87,   79,   76,   77,   78,   72,   85,   86,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  127,  128,
  140,  141,  136,  137,  138,  139,  125,  129,  124,  143,
  167,  126,  132,  133,    0,    0,  123,  135,  134,  142,
   71,  199,  203,  200,  201,  202,  196,  198,  204,  197,
    0,    0,  118,  119,  117,    0,    0,  116,  227,  230,
  231,   59,    0,    0,    0,   61,  216,  217,  218,  102,
   58,  108,  109,  110,  111,  112,  105,    0,  107,   92,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  209,  210,    0,  166,    0,    0,    0,
    0,    0,  211,    0,  131,  207,    0,    0,    0,  206,
    0,  121,    0,    0,  213,  214,  215,  114,  103,  145,
    0,  144,  178,  179,  180,  182,  183,  184,  185,  186,
  181,    0,  161,  162,  158,    0,   39,   40,   41,   42,
   43,   44,    0,   38,   48,    0,   47,   52,    0,   51,
  153,  154,  155,  156,  157,  150,    0,  190,  171,  172,
  173,  174,  175,  170,    0,  164,    0,    0,  169,  168,
  248,    0,    0,    0,  208,  163,    0,    0,  212,    0,
    0,    0,  246,  243,    0,  237,    0,    0,  147,  188,
  160,   46,   50,   54,  152,  177,  193,    0,    0,    0,
  194,    0,  189,  122,    0,  191,    0,    0,  115,  245,
  241,  235,  240,    0,  236,    0,  220,  221,  249,  247,
  192,  232,  233,    0,  195,    0,    0,  225,  226,   36,
  244,  242,  229,  228,    0,    0,  222,  223,  224,  219,
    0,  239,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
    7,    6,  272,  149,  265,  266,  150,  273,  274,  151,
  276,  277,  152,  279,  280,  153,  154,  155,  156,   15,
   95,   44,  108,  109,  157,  286,  287,  158,  159,  160,
  161,   71,  162,  302,  350,   16,   46,    4,   17,   18,
   47,   48,  178,  111,  112,   50,   73,   51,   74,   52,
   19,   97,   98,   54,  122,  123,   55,   56,  163,  207,
  208,  164,  251,  252,   57,    5,   58,   59,   60,   61,
   62,  125,   63,   20,  310,  311,  181,  182,   65,  165,
  166,   66,  186,  187,  167,   67,  237,  168,  294,  295,
  169,  238,  306,  192,  196,  327,  328,  355,  329,  330,
  358,  359,  239,  307,  365,  245,  367,  316,  341,  318,
  342,  343,  170,  234,  117,  118,  226,  227,  261,  262,
  228,  229,  362,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -219,
    0,    0,    0,    0,    0,   -8,  359,    0,   -9,   -7,
   20,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -247,    0,    0,   30,   39,   49,   51,   53,   60,   87,
   95,   96,   99,  107,  108,  109,  110,    0,    0,  114,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   52, -175, -224, -116,
   58,   66,  132,  134, -250, -203,  -78, -155, -154, -153,
 -149,    0,    0, -201,  -89,  -89,  -89, -143, -301, -230,
    0,    0,    0,    0,    0,    0, -116,    0, -236,  773,
 -298, -298,    0,    0,    0,    0,    0, -203,    0,    0,
  -78,    0,    0,    0,    0,    0, -220, -220,    0,    0,
    0, -201,    0,    0,    0,    0,    0,    0,    0,    0,
  150,  151,  152,  156,  157,  158,  160,  162,  163,  173,
  184,  186,  188, -280,  189,  190,  191,  -79,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -230,  -80,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -236,  -80,    0,    0,    0,  773,  -80,    0,    0,    0,
    0,    0,  -73,  -73,  -73,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -220,    0,    0,
 -220,  -20,  -66,  -31,  -29, -166, -200, -183,   -4,  -10,
 -180,  -44, -177,    0,    0,  -60,    0,  234,  242,  -42,
  -41,  -38,    0,  253,    0,    0, -230,  -39,  255,    0,
   16,    0,  773,  -50,    0,    0,    0,    0,    0,    0,
  -20,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -166,    0,    0,    0, -200,    0,    0,    0,    0,
    0,    0, -183,    0,    0,   -4,    0,    0,  -10,    0,
    0,    0,    0,    0,    0,    0, -180,    0,    0,    0,
    0,    0,    0,    0, -177,    0, -298, -298,    0,    0,
    0,  271, -298,  192,    0,    0,  261, -298,    0,  263,
 -236,  197,    0,    0, -216,    0,  278, -216,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  280,  -73,  -73,
    0,  -19,    0,    0, -298,    0, -158,  204,    0,    0,
    0,    0,    0,  -17,    0, -309,    0,    0,    0,    0,
    0,    0,    0,  -15,    0,  -15,  -15,    0,    0,    0,
    0,    0,    0,    0,  -73,   -2,    0,    0,    0,    0,
 -216,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  333,  335,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -13,
    0,    0,    0,    0,    0,    0,  169,    0,  -12,  -11,
    0,    0,    0,    0,    0,    0,    0,  212,    0,    0,
  102,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  258,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -118,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -113,    0,    0,    0,    0, -112,    0,    0,    0,    0,
    0,    0,  310,  310,  310,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    1,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  605,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  215,    0,    0,    0,
    0,    0,  216,    0,    0,    0,    0,    0,    0,    0,
 -100,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  414,    0,    0,    0,  473,    0,    0,    0,    0,
    0,    0,  517,    0,    0,  649,    0,    0,  692,    0,
    0,    0,    0,    0,    0,    0,  561,    0,    0,    0,
    0,    0,    0,    0,  735,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  217,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  370,  370,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -106,    0, -106, -106,    0,    0,    0,
    0,    0,    0,    0,  370,    0,    0,    0,    0,    0,
    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,  121,  -85,   77,    0,  -83,    0,   71,    0,
    0,   69,    0,    0,   67,    0,  -82,  -81,  -77,  340,
    0,    0,    0,  240,  -75,   62,    0,  -70,  -67,    0,
    0,    0,    0,    0,    0,  343,    0,    0,    0,    0,
    0,    0,  345,    0,  247,    0,    0,    0,    0,    0,
  352,    0,  273,    0,    0,  249,    0,    0,  -71,  -91,
    0,  -68,    0,  122,    0,    0,    0,    0,    0,    0,
    0,   47,    0,  367,    0,    0,    0, -181,    0,    0,
 -129,    0,    0, -163,  -65,  360, -145,    0,   88,    0,
    0,    0,    0,    0,    0, -253,  -98,    0,  -96,  -92,
    0,    0,    0,    0,    0, -174, -205,    0,  138,   18,
 -292,    0,    0,    0,    0,    0,    0,  159,  125,    0,
    0,    0,    0,
};
#define YYTABLESIZE 1132
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                     240,
  113,   13,  193,  197,  194,  198,  130,  315,  195,  199,
  113,  205,  120,  172,  183,  173,  174,  175,  238,  246,
  247,  176,  242,  177,  146,  345,  209,  179,  103,  184,
  180,  363,  185,   26,  188,  235,  241,    1,    2,  364,
  131,  243,  189,  190,  331,  191,  131,  104,   68,  333,
   69,  132,   38,   39,  336,  129,  130,  132,  202,  203,
  204,  205,  206,  105,  106,  107,  134,  135,  136,  224,
  225,  133,  134,  135,  136,    8,  137,   70,  372,  312,
  138,  351,  137,  119,  120,  121,  138,   75,  141,   92,
   93,   94,  139,  140,  141,  172,   76,  173,  174,  175,
  183,   57,  142,  176,  143,  177,   77,  304,   78,  179,
   79,   57,  180,  263,  264,  184,  248,   80,  185,  249,
  188,  144,  145,  146,  147,  113,   14,   42,  148,  338,
  314,  340,  126,  127,  267,  268,  269,  270,  271,  256,
  257,  258,  259,  260,   81,  281,  282,  283,  284,  285,
  368,  369,   82,   83,  347,  348,   84,  183,  289,  290,
  291,  292,  293,  238,   85,   86,   87,   88,   70,  146,
  238,   89,  184,   91,   90,  185,  146,  188,   70,   96,
   99,  238,  189,  190,  352,  191,  353,  146,  100,  101,
  370,  102,  110,  113,  114,  115,  238,  238,  238,  116,
  124,  146,  146,  146,  146,  128,  238,  211,  212,  213,
  238,  101,  146,  214,  215,  216,  146,  217,  238,  218,
  219,  101,  146,  146,  146,  172,   57,  173,  174,  175,
  220,  130,  146,  176,  146,  177,  205,  120,  354,  179,
  356,  221,  180,  222,  357,  223,  230,  231,  232,  146,
    8,  146,  146,  146,  146,    9,   10,   91,  146,  113,
  113,  113,  113,  113,  113,  113,  113,   91,  250,  236,
  113,  233,  244,  113,  113,  113,  113,  113,  113,  254,
  278,  253,  255,  313,  113,  275,   11,  288,  113,   12,
  225,  297,  113,  113,  113,  113,  314,  113,  113,  298,
  113,  113,  113,  113,  113,  113,  299,  300,  301,  234,
  303,  305,  308,  113,  309,  332,  334,  113,  335,  234,
  337,  339,  344,  113,  113,  113,  346,  349,  360,  361,
  366,  313,    2,  113,    1,  113,  130,  205,  120,  130,
  120,  205,  321,  322,  323,  324,   43,  200,  325,   45,
  113,   49,  113,  113,  113,  113,  113,  201,   53,  113,
   57,   57,   57,   57,   57,   57,   57,   57,   41,  171,
  210,   57,  319,   64,   57,   57,   57,   57,   57,   57,
   72,  317,  326,  371,  296,   57,  320,    0,    0,   57,
    0,    0,    0,   57,   57,   57,   57,    0,   57,   57,
    0,   57,   57,    0,   57,   57,   57,    0,    0,    0,
    0,    0,    0,    0,   57,    0,    0,    0,   57,    0,
    0,    0,    0,    0,    0,    0,   57,   70,   70,   70,
   70,   70,   70,   70,   70,    0,    0,    0,   70,    0,
    0,   70,   70,   70,   70,   70,   70,    0,    0,    0,
    0,   57,   70,    0,    0,    0,    0,   57,    0,    0,
   70,   70,   70,   70,    0,   70,   70,    0,   70,   70,
  101,  101,  101,  101,  101,  101,  101,  101,    0,    0,
    0,  101,    0,    0,  101,  101,  101,  101,  101,  101,
    0,    0,    0,    0,  234,  101,    0,    0,    0,    0,
    0,    0,    0,  101,  101,  101,  101,    0,  101,  101,
    0,  101,  101,    0,    0,    0,   91,   91,   91,   91,
   91,   91,   91,   91,   70,    0,    0,   91,    0,    0,
   91,   91,   91,   91,   91,   91,    0,    0,  187,    0,
    0,   91,    0,    0,    0,    0,    0,    0,    0,   91,
   91,   91,   91,    0,   91,   91,    0,   91,   91,    0,
    0,    0,    0,    0,    0,    0,    0,  101,  234,  234,
  234,  234,  234,  234,  234,  234,    0,    0,    0,  234,
    0,    0,  234,  234,  234,  234,  234,  234,    0,    0,
    0,    0,    0,  234,    0,    0,    0,  159,    0,    0,
    0,  234,  234,  234,  234,    0,  234,  234,    0,  234,
  234,    0,    0,   91,    0,    0,    0,    8,   21,   22,
   23,   24,    9,   10,   25,    0,    0,    0,   26,    0,
    0,   27,   28,   29,   30,   31,   32,    0,    0,    0,
    0,   45,   33,    0,    0,    0,  234,    0,    0,    0,
   34,   35,   36,   11,    0,   37,   12,  234,   38,   39,
    0,    0,    0,    0,    0,  234,    0,    0,  234,    0,
    0,  234,  234,  234,  234,    0,    0,    0,    0,    0,
    0,    0,  234,  187,    0,  151,  234,    0,    0,    0,
  187,    0,  234,  234,  234,    0,    0,    0,    0,    0,
    0,  187,  234,    0,  234,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   40,  187,  187,  187,  187,  234,
  234,  234,  234,  234,  234,    0,  187,    0,  234,  165,
  187,    0,    0,    0,    0,    0,  187,  187,  187,    0,
    0,    0,  159,    0,    0,    0,  187,    0,  187,  159,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  159,    0,    0,  187,    0,  187,  187,  187,  187,    0,
    0,    0,  187,   49,  159,  159,  159,  159,    0,    0,
    0,    0,    0,    0,    0,  159,   45,    0,    0,  159,
    0,    0,    0,   45,    0,  159,  159,  159,    0,    0,
    0,    0,    0,    0,   45,  159,    0,  159,    0,    0,
    0,    0,    0,    0,    0,    0,   53,    0,   45,   45,
   45,   45,  159,    0,  159,  159,  159,  159,    0,   45,
  151,  159,    0,   45,    0,    0,    0,  151,    0,   45,
   45,   45,    0,    0,    0,    0,    0,    0,  151,   45,
    0,   45,    0,    0,    0,    0,    0,    0,    0,  176,
    0,    0,  151,  151,  151,  151,   45,    0,   45,   45,
   45,   45,    0,  151,    0,   45,    0,  151,    0,    0,
    0,  165,    0,  151,  151,  151,    0,    0,    0,    0,
    0,    0,  165,  151,    0,  151,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  165,  165,  165,  165,
  151,    0,  151,  151,  151,  151,    0,  165,    0,  151,
    0,  165,    0,    0,    0,   49,    0,  165,  165,  165,
    0,    0,    0,    0,    0,    0,   49,  165,    0,  165,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   49,   49,   49,   49,  165,    0,  165,  165,  165,  165,
    0,   49,    0,  165,    0,   49,    0,    0,   53,    0,
    0,   49,   49,   49,    0,    0,    0,    0,    0,   53,
    0,   49,    0,   49,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   53,   53,   53,   53,    0,   49,    0,
   49,   49,   49,   49,   53,    0,    0,   49,   53,    0,
    0,  176,    0,    0,   53,   53,   53,    0,    0,    0,
    0,    0,  176,    0,   53,    0,   53,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  176,  176,  176,  176,
    0,   53,    0,   53,   53,   53,   53,  176,    0,  131,
   53,  176,    0,    0,    0,    0,    0,  176,  176,  176,
  132,    0,    0,    0,    0,    0,    0,  176,    0,  176,
    0,    0,    0,    0,  133,  134,  135,  136,    0,    0,
    0,    0,    0,    0,  176,  137,  176,  176,  176,  176,
    0,    0,    0,  176,    0,  139,  140,    0,    0,    0,
    0,    0,    0,    0,    0,  142,    0,  143,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  144,  145,  146,    0,    0,    0,
    0,  148,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                     181,
    0,   10,  101,  102,  101,  102,  125,   58,  101,  102,
   10,  125,  125,   99,  100,   99,   99,   99,  125,  194,
  195,   99,  186,   99,  125,  318,  118,   99,  279,  100,
   99,  341,  100,  270,  100,  165,  182,  257,  258,  349,
  277,  187,  341,  342,  298,  344,  277,  298,   58,  303,
   58,  288,  300,  301,  308,  357,  358,  288,  279,  280,
  281,  282,  283,  267,  268,  269,  303,  304,  305,  350,
  351,  302,  303,  304,  305,  259,  313,   58,  371,  243,
  317,  335,  313,  285,  286,  287,  317,   58,  325,  314,
  315,  316,  323,  324,  325,  181,   58,  181,  181,  181,
  186,    0,  333,  181,  335,  181,   58,  237,   58,  181,
   58,   10,  181,  314,  315,  186,  208,   58,  186,  211,
  186,  352,  353,  354,  355,  125,    6,    7,  359,  311,
  347,  348,   86,   87,  318,  319,  320,  321,  322,  306,
  307,  308,  309,  310,   58,  326,  327,  328,  329,  330,
  356,  357,   58,   58,  329,  330,   58,  243,  336,  337,
  338,  339,  340,  270,   58,   58,   58,   58,    0,  270,
  277,   58,  243,  349,  123,  243,  277,  243,   10,  296,
  123,  288,  341,  342,  343,  344,  345,  288,  123,   58,
  365,   58,  271,  349,  349,  349,  303,  304,  305,  349,
  290,  302,  303,  304,  305,  349,  313,   58,   58,   58,
  317,    0,  313,   58,   58,   58,  317,   58,  325,   58,
   58,   10,  323,  324,  325,  311,  125,  311,  311,  311,
   58,  350,  333,  311,  335,  311,  350,  350,  337,  311,
  337,   58,  311,   58,  337,   58,   58,   58,   58,  350,
  259,  352,  353,  354,  355,  264,  265,    0,  359,  259,
  260,  261,  262,  263,  264,  265,  266,   10,  289,  350,
  270,  351,  346,  273,  274,  275,  276,  277,  278,  311,
  291,  348,  312,  334,  284,  290,  295,  332,  288,  298,
  351,   58,  292,  293,  294,  295,  347,  297,  298,   58,
  300,  301,  302,  303,  304,  305,  349,  349,  347,    0,
   58,  351,   58,  313,  299,   45,  125,  317,   58,   10,
   58,  125,   45,  323,  324,  325,   47,  347,  125,  347,
  346,  334,    0,  333,    0,  335,  350,  350,  350,  125,
  125,  125,  266,  273,  276,  279,    7,  108,  287,    7,
  350,    7,  352,  353,  354,  355,  356,  111,    7,  359,
  259,  260,  261,  262,  263,  264,  265,  266,   10,   97,
  122,  270,  251,    7,  273,  274,  275,  276,  277,  278,
   21,  244,  295,  366,  226,  284,  262,   -1,   -1,  288,
   -1,   -1,   -1,  292,  293,  294,  295,   -1,  297,  298,
   -1,  300,  301,   -1,  303,  304,  305,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  313,   -1,   -1,   -1,  317,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  325,  259,  260,  261,
  262,  263,  264,  265,  266,   -1,   -1,   -1,  270,   -1,
   -1,  273,  274,  275,  276,  277,  278,   -1,   -1,   -1,
   -1,  350,  284,   -1,   -1,   -1,   -1,  356,   -1,   -1,
  292,  293,  294,  295,   -1,  297,  298,   -1,  300,  301,
  259,  260,  261,  262,  263,  264,  265,  266,   -1,   -1,
   -1,  270,   -1,   -1,  273,  274,  275,  276,  277,  278,
   -1,   -1,   -1,   -1,  125,  284,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  292,  293,  294,  295,   -1,  297,  298,
   -1,  300,  301,   -1,   -1,   -1,  259,  260,  261,  262,
  263,  264,  265,  266,  356,   -1,   -1,  270,   -1,   -1,
  273,  274,  275,  276,  277,  278,   -1,   -1,  125,   -1,
   -1,  284,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  292,
  293,  294,  295,   -1,  297,  298,   -1,  300,  301,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  356,  259,  260,
  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,  270,
   -1,   -1,  273,  274,  275,  276,  277,  278,   -1,   -1,
   -1,   -1,   -1,  284,   -1,   -1,   -1,  125,   -1,   -1,
   -1,  292,  293,  294,  295,   -1,  297,  298,   -1,  300,
  301,   -1,   -1,  356,   -1,   -1,   -1,  259,  260,  261,
  262,  263,  264,  265,  266,   -1,   -1,   -1,  270,   -1,
   -1,  273,  274,  275,  276,  277,  278,   -1,   -1,   -1,
   -1,  125,  284,   -1,   -1,   -1,  277,   -1,   -1,   -1,
  292,  293,  294,  295,   -1,  297,  298,  288,  300,  301,
   -1,   -1,   -1,   -1,   -1,  356,   -1,   -1,  299,   -1,
   -1,  302,  303,  304,  305,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  313,  270,   -1,  125,  317,   -1,   -1,   -1,
  277,   -1,  323,  324,  325,   -1,   -1,   -1,   -1,   -1,
   -1,  288,  333,   -1,  335,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  356,  302,  303,  304,  305,  350,
  351,  352,  353,  354,  355,   -1,  313,   -1,  359,  125,
  317,   -1,   -1,   -1,   -1,   -1,  323,  324,  325,   -1,
   -1,   -1,  270,   -1,   -1,   -1,  333,   -1,  335,  277,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  288,   -1,   -1,  350,   -1,  352,  353,  354,  355,   -1,
   -1,   -1,  359,  125,  302,  303,  304,  305,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  313,  270,   -1,   -1,  317,
   -1,   -1,   -1,  277,   -1,  323,  324,  325,   -1,   -1,
   -1,   -1,   -1,   -1,  288,  333,   -1,  335,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  125,   -1,  302,  303,
  304,  305,  350,   -1,  352,  353,  354,  355,   -1,  313,
  270,  359,   -1,  317,   -1,   -1,   -1,  277,   -1,  323,
  324,  325,   -1,   -1,   -1,   -1,   -1,   -1,  288,  333,
   -1,  335,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  125,
   -1,   -1,  302,  303,  304,  305,  350,   -1,  352,  353,
  354,  355,   -1,  313,   -1,  359,   -1,  317,   -1,   -1,
   -1,  277,   -1,  323,  324,  325,   -1,   -1,   -1,   -1,
   -1,   -1,  288,  333,   -1,  335,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  302,  303,  304,  305,
  350,   -1,  352,  353,  354,  355,   -1,  313,   -1,  359,
   -1,  317,   -1,   -1,   -1,  277,   -1,  323,  324,  325,
   -1,   -1,   -1,   -1,   -1,   -1,  288,  333,   -1,  335,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  302,  303,  304,  305,  350,   -1,  352,  353,  354,  355,
   -1,  313,   -1,  359,   -1,  317,   -1,   -1,  277,   -1,
   -1,  323,  324,  325,   -1,   -1,   -1,   -1,   -1,  288,
   -1,  333,   -1,  335,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  302,  303,  304,  305,   -1,  350,   -1,
  352,  353,  354,  355,  313,   -1,   -1,  359,  317,   -1,
   -1,  277,   -1,   -1,  323,  324,  325,   -1,   -1,   -1,
   -1,   -1,  288,   -1,  333,   -1,  335,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  302,  303,  304,  305,
   -1,  350,   -1,  352,  353,  354,  355,  313,   -1,  277,
  359,  317,   -1,   -1,   -1,   -1,   -1,  323,  324,  325,
  288,   -1,   -1,   -1,   -1,   -1,   -1,  333,   -1,  335,
   -1,   -1,   -1,   -1,  302,  303,  304,  305,   -1,   -1,
   -1,   -1,   -1,   -1,  350,  313,  352,  353,  354,  355,
   -1,   -1,   -1,  359,   -1,  323,  324,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  333,   -1,  335,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  352,  353,  354,   -1,   -1,   -1,
   -1,  359,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 359
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
"CHILD_MAXIDLE","ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS","PAMSERVICENAME",
"GSSAPISERVICE","GSSAPIKEYTAB","GSSAPIENCTYPE","GSSAPIENC_ANY",
"GSSAPIENC_CLEAR","GSSAPIENC_INTEGRITY","GSSAPIENC_CONFIDENTIALITY",
"GSSAPIENC_PERMESSAGE","GSSAPISERVICENAME","GSSAPIKEYTABNAME","PROTOCOL",
"PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL",
"PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2",
"PROXYPROTOCOL_HTTP_V1_0","PROXYPROTOCOL_UPNP","USER","GROUP","COMMAND",
"COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY",
"COMMAND_UDPREPLY","ACTION","LINE","LIBWRAPSTART","OPERATOR","LOG",
"LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR","LOG_IOOPERATION",
"IPADDRESS","DOMAINNAME","DIRECT","IFNAME","URL","PORT","PORTNUMBER",
"SERVICENAME","NUMBER","FROM","TO","REDIRECT","BANDWIDTH","MAXSESSIONS",
"UDPPORTRANGE","UDPCONNECTDST","YES","NO","BOUNCE",
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
"childstate : CHILD_MAXIDLE ':' NUMBER",
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
"log : LOG ':' logs",
"logname : LOG_CONNECT",
"logname : LOG_DATA",
"logname : LOG_DISCONNECT",
"logname : LOG_ERROR",
"logname : LOG_IOOPERATION",
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
   *rule = ruleinitmem;

   src.atype = SOCKS_ADDR_IPV4;
   src.addr.ipv4.ip.s_addr = htonl(INADDR_ANY);
   src.port.tcp = src.port.udp = src.portend = htons(0);

   dst = rdr_from = rdr_to = src;
}

#endif /* SOCKS_SERVER || BAREFOOTD */
#line 1364 "config_parse.c"
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
#line 269 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      protocol       = &protocolmem;
      extension      = &sockscf.extension;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 4:
#line 278 "config_parse.y"
{ yyval.string = NULL; }
break;
case 10:
#line 286 "config_parse.y"
{ yyval.string = NULL; }
break;
case 14:
#line 293 "config_parse.y"
{
   }
break;
case 35:
#line 324 "config_parse.y"
{
      yyerror("given keyword \"%s\" is deprecated", yyvsp[0].string);
   }
break;
case 36:
#line 329 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;
      route.gw.state  = state;

      socks_addroute(&route, 1);
   }
break;
case 37:
#line 339 "config_parse.y"
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
#line 367 "config_parse.y"
{
         proxyprotocol->socks_v4    = 1;
   }
break;
case 40:
#line 370 "config_parse.y"
{
         proxyprotocol->socks_v5    = 1;
   }
break;
case 41:
#line 373 "config_parse.y"
{
         proxyprotocol->msproxy_v2  = 1;
   }
break;
case 42:
#line 376 "config_parse.y"
{
         proxyprotocol->http_v1_0   = 1;
   }
break;
case 43:
#line 379 "config_parse.y"
{
         proxyprotocol->upnp        = 1;
   }
break;
case 48:
#line 392 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      if (addlinkedname(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER  || BAREFOOTD */
   }
break;
case 52:
#line 407 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      if (addlinkedname(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER  || BAREFOOTD */
   }
break;
case 56:
#line 422 "config_parse.y"
{
         extension->bind = 1;
   }
break;
case 59:
#line 431 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      addinternal(ruleaddr);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 60:
#line 438 "config_parse.y"
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
#line 455 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      addexternal(ruleaddr);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 62:
#line 462 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      static struct ruleaddr_t mem;

      addrinit(&mem);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 63:
#line 471 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 64:
#line 475 "config_parse.y"
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
#line 493 "config_parse.y"
{
   socks_addlogfile(yyvsp[0].string);
}
break;
case 72:
#line 503 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      yyerror("Sorry, child.maxidle is disabled due to a suspected bug");
      if (atoi(yyvsp[0].string) != 0 && atoi(yyvsp[0].string) < SOCKD_FREESLOTS)
         yyerror("%s (%s) can't be less than SOCKD_FREESLOTS (%d)",
         yyvsp[-2].string, yyvsp[0].string, SOCKD_FREESLOTS);
      sockscf.child.maxidle = atoi(yyvsp[0].string);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 76:
#line 520 "config_parse.y"
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
case 77:
#line 532 "config_parse.y"
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
case 78:
#line 544 "config_parse.y"
{
#if HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD)
#if HAVE_PRIVILEGES
      yyerror("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.libwrap         = yyvsp[0].uid;
      sockscf.uid.libwrap_isset   = 1;
#endif /* !HAVE_PRIVILEGES */
#else  /* !HAVE_LIBWRAP && (SOCKS_SERVER || BAREFOOTD) */
      yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP (SOCKS_SERVER || BAREFOOTD)*/
   }
break;
case 79:
#line 559 "config_parse.y"
{
      struct passwd *pw;

      if ((pw = socks_getpwnam(yyvsp[0].string)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
      else
         yyval.uid = pw->pw_uid;
   }
break;
case 80:
#line 569 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.timeout.tcpio = (time_t)atol(yyvsp[0].string);
      sockscf.timeout.udpio = sockscf.timeout.tcpio;
   }
break;
case 81:
#line 574 "config_parse.y"
{
      sockscf.timeout.tcpio = (time_t)atol(yyvsp[0].string);
   }
break;
case 82:
#line 577 "config_parse.y"
{
      sockscf.timeout.udpio = (time_t)atol(yyvsp[0].string);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 83:
#line 583 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 84:
#line 590 "config_parse.y"
{
      sockscf.option.debug = atoi(yyvsp[0].string);
   }
break;
case 85:
#line 595 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.option.udpconnectdst = 1;
   }
break;
case 86:
#line 599 "config_parse.y"
{
      sockscf.option.udpconnectdst = 0;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 88:
#line 609 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      sockscf.compat.reuseaddr = 1;
   }
break;
case 89:
#line 613 "config_parse.y"
{
      sockscf.compat.sameport = 1;
   }
break;
case 90:
#line 616 "config_parse.y"
{
      sockscf.compat.draft_5_05 = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 94:
#line 629 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 95:
#line 632 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 96:
#line 639 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 98:
#line 647 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
#if HAVE_LIBWRAP
         sockscf.srchost.nomismatch = 1;
   }
break;
case 99:
#line 652 "config_parse.y"
{
         sockscf.srchost.nounknown = 1;
#else
      yyerror("srchostoption requires libwrap");
#endif /* HAVE_LIBWRAP */
   }
break;
case 100:
#line 658 "config_parse.y"
{
         sockscf.srchost.checkreplyauth = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 104:
#line 672 "config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.methodv;
   methodc = &sockscf.methodc;
   *methodc = 0; /* reset. */
#endif /* SOCKS_SERVER */
   }
break;
case 106:
#line 681 "config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.clientmethodv;
   methodc = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif /* SOCKS_SERVER */
   }
break;
case 108:
#line 690 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_NONE);
   }
break;
case 109:
#line 693 "config_parse.y"
{
#if !HAVE_GSSAPI
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#else
      ADDMETHOD(AUTHMETHOD_GSSAPI);
#endif /* !HAVE_GSSAPI */
   }
break;
case 110:
#line 700 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
break;
case 111:
#line 703 "config_parse.y"
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
case 112:
#line 714 "config_parse.y"
{
#if HAVE_PAM
      ADDMETHOD(AUTHMETHOD_PAM);
#else /* !HAVE_PAM */
      yyerror("method %s requires pam library", AUTHMETHOD_PAMs);
#endif /* HAVE_PAM */
   }
break;
case 115:
#line 731 "config_parse.y"
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
case 117:
#line 752 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("bandwidth");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 118:
#line 757 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 119:
#line 762 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("redirect");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 120:
#line 769 "config_parse.y"
{ yyval.string = NULL; }
break;
case 122:
#line 773 "config_parse.y"
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
case 124:
#line 787 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("bandwidth");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 129:
#line 796 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("redirect");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 130:
#line 803 "config_parse.y"
{ yyval.string = NULL; }
break;
case 142:
#line 817 "config_parse.y"
{
#if !BAREFOOTD
         yyerror("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 143:
#line 822 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
         checkmodule("session");
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 145:
#line 832 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerror("method %s requires gssapi library", AUTHMETHOD_GSSAPIs);
#endif /* HAVE_GSSAPI */
   }
break;
case 148:
#line 846 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 149:
#line 851 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 153:
#line 866 "config_parse.y"
{
         command->bind = 1;
   }
break;
case 154:
#line 869 "config_parse.y"
{
         command->connect = 1;
   }
break;
case 155:
#line 872 "config_parse.y"
{
         command->udpassociate = 1;
   }
break;
case 156:
#line 878 "config_parse.y"
{
         command->bindreply = 1;
   }
break;
case 157:
#line 882 "config_parse.y"
{
         command->udpreply = 1;
   }
break;
case 161:
#line 895 "config_parse.y"
{
      protocol->tcp = 1;
   }
break;
case 162:
#line 898 "config_parse.y"
{
      protocol->udp = 1;
   }
break;
case 168:
#line 915 "config_parse.y"
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
case 169:
#line 932 "config_parse.y"
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
case 171:
#line 955 "config_parse.y"
{
#if SOCKS_SERVER || BAREFOOTD
   rule.log.connect = 1;
   }
break;
case 172:
#line 959 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 173:
#line 962 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 174:
#line 965 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 175:
#line 968 "config_parse.y"
{
         rule.log.iooperation = 1;
#endif /* SOCKS_SERVER || BAREFOOTD */
   }
break;
case 178:
#line 979 "config_parse.y"
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
case 179:
#line 991 "config_parse.y"
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
case 180:
#line 1002 "config_parse.y"
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
case 182:
#line 1020 "config_parse.y"
{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 183:
#line 1026 "config_parse.y"
{
      gssapiencryption->clear = 1;
   }
break;
case 184:
#line 1029 "config_parse.y"
{
      gssapiencryption->integrity = 1;
   }
break;
case 185:
#line 1032 "config_parse.y"
{
      gssapiencryption->confidentiality = 1;
   }
break;
case 186:
#line 1035 "config_parse.y"
{
      yyerror("gssapi per-message encryption not supported");
#else
      yyerror("gssapi support not compiled in");
#endif /* HAVE_GSSAPI */
   }
break;
case 190:
#line 1050 "config_parse.y"
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
case 205:
#line 1104 "config_parse.y"
{ yyval.string = NULL; }
break;
case 207:
#line 1108 "config_parse.y"
{
      addrinit(&src);
   }
break;
case 208:
#line 1113 "config_parse.y"
{
      addrinit(&dst);
   }
break;
case 209:
#line 1118 "config_parse.y"
{
      addrinit(&rdr_from);
   }
break;
case 210:
#line 1123 "config_parse.y"
{
      addrinit(&rdr_to);
   }
break;
case 211:
#line 1128 "config_parse.y"
{
#if BAREFOOTD
      addrinit(&bounce_to);
#endif /* BAREFOOTD */
   }
break;
case 212:
#line 1136 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 227:
#line 1166 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton(yyvsp[0].string, ipaddr) != 1)
         yyerror("bad address: %s", yyvsp[0].string);
   }
break;
case 228:
#line 1175 "config_parse.y"
{
      if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
         yyerror("bad netmask: %s", yyvsp[0].string);

      netmask->s_addr
      = atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
   }
break;
case 229:
#line 1182 "config_parse.y"
{
         if (!inet_aton(yyvsp[0].string, netmask))
            yyerror("bad netmask: %s", yyvsp[0].string);
   }
break;
case 230:
#line 1188 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");
      strcpy(domain, yyvsp[0].string);
   }
break;
case 231:
#line 1197 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
         yyerror("interface name too long");
      strcpy(ifname, yyvsp[0].string);
   }
break;
case 232:
#line 1207 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", yyvsp[0].string);
      strcpy(domain, yyvsp[0].string);

      proxyprotocol->direct = 1;
   }
break;
case 233:
#line 1218 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;

      if (strlen(yyvsp[0].string) >= MAXURLLEN)
         yyerror("url \"%s\" too long", yyvsp[0].string);
      strcpy(url, yyvsp[0].string);
   }
break;
case 234:
#line 1228 "config_parse.y"
{ yyval.string = NULL; }
break;
case 238:
#line 1234 "config_parse.y"
{ yyval.string = NULL; }
break;
case 243:
#line 1246 "config_parse.y"
{
      *port_tcp   = htons((in_port_t)atoi(yyvsp[0].string));
      *port_udp   = htons((in_port_t)atoi(yyvsp[0].string));
   }
break;
case 244:
#line 1252 "config_parse.y"
{
      ruleaddr->portend    = htons((in_port_t)atoi(yyvsp[0].string));
      ruleaddr->operator   = range;
   }
break;
case 245:
#line 1258 "config_parse.y"
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
case 246:
#line 1289 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 248:
#line 1297 "config_parse.y"
{
#if SOCKS_SERVER
   rule.udprange.start = htons((in_port_t)atoi(yyvsp[0].string));
#endif /* SOCKS_SERVER */
   }
break;
case 249:
#line 1304 "config_parse.y"
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
#line 2529 "config_parse.c"
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
