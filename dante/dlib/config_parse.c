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
#line 45 "../lib/config_parse.y"

#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.214 2008/12/14 13:21:14 michaels Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
   extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addrinit __P((struct ruleaddr_t *addr));

static void
gwaddrinit __P((gwaddr_t *addr));

#if SOCKS_SERVER
static void
ruleinit __P((struct rule_t *rule));

static void
fixconfig __P((void));

#endif

__END_DECLS

extern int yylineno;
extern char *yytext;

#if SOCKS_SERVER
static struct rule_t            ruleinitmem;
static struct rule_t            rule;            /* new rule.                     */
static struct protocol_t      protocolmem;   /* new protocolmem.               */
#endif

static struct serverstate_t   state;
static struct route_t         route;         /* new route.                     */
static gwaddr_t               gw;            /* new gateway.                  */

static struct ruleaddr_t      src;            /* new src.                        */
static struct ruleaddr_t      dst;            /* new dst.                        */
static struct ruleaddr_t      rdr_from;
static struct ruleaddr_t      rdr_to;

static struct ruleaddr_t      *ruleaddr;      /* current ruleaddr               */
static struct extension_t      *extension;      /* new extensions                  */
static struct proxyprotocol_t   *proxyprotocol;/* proxy protocol.               */

static char                     *atype;         /* atype of new address.         */
static struct in_addr         *ipaddr;         /* new ipaddress                  */
static struct in_addr         *netmask;      /* new netmask                     */
static char                     *domain;         /* new domain.                     */
static char                     *ifname;         /* new ifname.                     */
static char                     *url;            /* new url.                        */

static in_port_t               *port_tcp;      /* new TCP portnumber.            */
static in_port_t               *port_udp;      /* new UDP portnumber.            */
static int                     *methodv;      /* new authmethods.               */
static size_t                  *methodc;      /* number of them.               */
static struct protocol_t      *protocol;      /* new protocol.                  */
static struct command_t         *command;      /* new command.                  */
static enum operator_t         *operator;      /* new operator.                  */

static const struct {
   const char *name;
   const int value;
} syslogfacilityv[] = {
#ifdef LOG_AUTH
   { "auth",   LOG_AUTH      },
#endif /* LOG_AUTH */
#ifdef LOG_AUTHPRIV
   { "authpriv",   LOG_AUTHPRIV      },
#endif /* LOG_AUTHPRIV */
#ifdef LOG_DAEMON
   { "daemon",   LOG_DAEMON   },
#endif /* LOG_DAEMON */
#ifdef LOG_USER
   { "user",   LOG_USER      },
#endif /* LOG_USER */
#ifdef LOG_LOCAL0
   { "local0",   LOG_LOCAL0   },
#endif /* LOG_LOCAL0 */
#ifdef LOG_LOCAL1
   { "local1",   LOG_LOCAL1   },
#endif /* LOG_LOCAL1 */
#ifdef LOG_LOCAL2
   { "local2",   LOG_LOCAL2   },
#endif /* LOG_LOCAL2 */
#ifdef LOG_LOCAL3
   { "local3",   LOG_LOCAL3   },
#endif /* LOG_LOCAL3 */
#ifdef LOG_LOCAL4
   { "local4",   LOG_LOCAL4   },
#endif /* LOG_LOCAL4 */
#ifdef LOG_LOCAL5
   { "local5",   LOG_LOCAL5   },
#endif /* LOG_LOCAL5 */
#ifdef LOG_LOCAL6
   { "local6",   LOG_LOCAL6   },
#endif /* LOG_LOCAL6 */
#ifdef LOG_LOCAL7
   { "local7",   LOG_LOCAL7   }
#endif /* LOG_LOCAL7 */
};


#define YYDEBUG 1

#define ADDMETHOD(method)                                        \
do {                                                             \
   if (methodisset(method, methodv, *methodc))                   \
      yywarn("duplicate method: %s", method2string(method));    \
   else {                                                       \
      if (*methodc >= MAXMETHOD)                                 \
         yyerror("internal error, (%ld >= %ld)",               \
         (long)*methodc, (long)MAXMETHOD);                     \
      methodv[(*methodc)++] = method;                            \
   }                                                             \
} while (0)

#line 172 "../lib/config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
   char   *string;
   uid_t   uid;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 181 "config_parse.c"
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
#define EXTENSION 269
#define BIND 270
#define PRIVILEGED 271
#define IOTIMEOUT 272
#define CONNECTTIMEOUT 273
#define METHOD 274
#define CLIENTMETHOD 275
#define NONE 276
#define GSSAPI 277
#define UNAME 278
#define RFC931 279
#define PAM 280
#define COMPATIBILITY 281
#define REUSEADDR 282
#define SAMEPORT 283
#define USERNAME 284
#define GROUPNAME 285
#define USER_PRIVILEGED 286
#define USER_UNPRIVILEGED 287
#define USER_LIBWRAP 288
#define LOGOUTPUT 289
#define LOGFILE 290
#define CHILD_MAXIDLE 291
#define ROUTE 292
#define VIA 293
#define VERDICT_BLOCK 294
#define VERDICT_PASS 295
#define PAMSERVICENAME 296
#define PROTOCOL 297
#define PROTOCOL_TCP 298
#define PROTOCOL_UDP 299
#define PROTOCOL_FAKE 300
#define PROXYPROTOCOL 301
#define PROXYPROTOCOL_SOCKS_V4 302
#define PROXYPROTOCOL_SOCKS_V5 303
#define PROXYPROTOCOL_MSPROXY_V2 304
#define PROXYPROTOCOL_HTTP_V1_0 305
#define PROXYPROTOCOL_UPNP 306
#define USER 307
#define GROUP 308
#define COMMAND 309
#define COMMAND_BIND 310
#define COMMAND_CONNECT 311
#define COMMAND_UDPASSOCIATE 312
#define COMMAND_BINDREPLY 313
#define COMMAND_UDPREPLY 314
#define ACTION 315
#define LINE 316
#define LIBWRAPSTART 317
#define OPERATOR 318
#define LOG 319
#define LOG_CONNECT 320
#define LOG_DATA 321
#define LOG_DISCONNECT 322
#define LOG_ERROR 323
#define LOG_IOOPERATION 324
#define IPADDRESS 325
#define DOMAINNAME 326
#define DIRECT 327
#define IFNAME 328
#define URL 329
#define PORT 330
#define PORTNUMBER 331
#define SERVICENAME 332
#define NUMBER 333
#define FROM 334
#define TO 335
#define REDIRECT 336
#define BANDWIDTH 337
#define MAXSESSIONS 338
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   56,    1,    1,    1,    1,    1,    1,    2,
    2,    2,    2,   30,   31,   31,   57,   57,   57,   57,
   57,   57,   57,   57,   57,   57,   55,   55,   55,   55,
   55,   55,    3,   64,   29,    7,    8,    8,    8,    8,
    8,    8,    9,    9,   10,   11,   12,   12,   13,   14,
   15,   15,   36,   37,   38,   38,   39,   40,   41,   42,
   43,   43,   32,   32,   32,   44,   45,   46,   46,   63,
   58,   58,   58,   59,   60,   61,   62,   34,   35,   33,
   47,   48,   48,   49,   49,   17,   18,   18,   18,   19,
   20,   20,   21,   21,   52,  103,   50,  104,   51,   54,
   54,   54,   54,   54,   53,   53,   72,   73,   74,   74,
   69,   70,   70,   70,   70,   70,   70,   71,   71,   75,
   75,   75,   75,   75,   75,   75,   76,   76,   22,   24,
   24,   24,   24,   24,   23,   23,    4,    6,    6,    5,
    5,   77,   25,   25,   27,   28,   26,   78,   80,   80,
   80,   80,   80,   79,   79,   16,   81,   82,   83,  105,
  106,   66,   67,   67,   67,   67,   67,   68,   68,   93,
   94,  107,  108,   65,   84,   84,   84,   85,   85,   85,
   86,   86,   86,   88,   88,   88,   88,   88,   87,   95,
   95,   89,   90,   91,   92,   96,   96,   96,   97,   97,
  101,  101,   98,   99,  109,  102,  100,
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
    1,    1,    1,    8,    0,    3,    1,    1,    1,    1,
    1,    1,    1,    2,    3,    1,    1,    2,    3,    1,
    1,    2,    3,    1,    1,    2,    4,    0,    4,    0,
    3,    3,    1,    1,    1,    3,    1,    1,    2,    3,
    1,    1,    1,    3,    3,    3,    1,    3,    3,    3,
    3,    1,    1,    1,    2,    3,    1,    1,    1,    3,
    1,    1,    1,    2,    3,    0,    4,    0,    4,    1,
    1,    1,    1,    1,    1,    2,    7,    1,    0,    2,
    6,    1,    1,    1,    1,    1,    1,    0,    2,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    3,    1,
    1,    1,    1,    1,    1,    2,    3,    1,    1,    1,
    2,    2,    2,    2,    1,    3,    3,    3,    1,    1,
    1,    1,    1,    1,    2,    3,    3,    3,    3,    3,
    3,    3,    1,    1,    1,    1,    1,    0,    2,    1,
    1,    1,    1,    1,    2,    2,    2,    1,    1,    1,
    4,    2,    2,    2,    2,    2,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    0,    3,    2,    0,    3,
    1,    1,    3,    1,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    3,   14,    0,   10,    4,    0,    0,   33,    0,    0,
    0,   35,   11,   16,   65,   12,   15,   64,   63,   13,
    0,   58,   60,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  127,  128,    5,   19,   31,
   32,   30,   28,   29,   20,   21,   22,   23,   27,   17,
   18,   24,    6,   25,   71,   72,   73,   26,    9,    8,
    7,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   96,   98,    0,    0,    0,    0,
    0,    0,   80,   88,   89,   87,   86,   67,    0,   66,
    0,    0,    0,    0,   61,   62,   91,   92,    0,   90,
   54,    0,   53,   78,   79,    0,    0,   82,   83,    0,
   81,   77,   74,   75,   76,   70,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  115,  116,
  124,  125,  123,  114,  117,  113,  126,  145,  120,    0,
    0,  112,  122,  121,   69,  165,  166,  163,  164,  167,
    0,    0,    0,    0,  108,  189,  192,  193,   57,    0,
    0,    0,   59,  178,  179,  180,   94,   56,  100,  101,
  102,  103,  104,   97,    0,   99,   85,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  172,  173,  143,  144,
    0,    0,    0,    0,  119,  170,    0,    0,    0,  169,
    0,  110,    0,    0,  175,  176,  177,  106,   95,  156,
  138,  139,  137,    0,   37,   38,   39,   40,   41,   42,
    0,   36,   46,    0,   45,   50,    0,   49,  130,  131,
  132,  133,  134,  129,    0,  157,  149,  150,  151,  152,
  153,  148,    0,    0,    0,  147,  146,    0,  171,  142,
    0,    0,  174,    0,    0,    0,  207,  204,  198,    0,
    0,  141,   44,   48,   52,  136,  155,  160,    0,    0,
    0,  161,  111,    0,  158,    0,    0,  107,    0,  206,
  202,  197,  201,    0,  182,  183,  159,  194,  195,    0,
  162,    0,    0,  187,  188,   34,  205,  203,  191,  190,
    0,    0,  184,  185,  186,  181,    0,  200,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
    7,    6,  220,  129,  213,  214,  130,  221,  222,  131,
  224,  225,  132,  227,  228,  133,   15,   87,   41,   99,
  100,  134,  234,  235,  135,  136,  137,  138,   66,    4,
   16,   17,   18,   42,   43,  149,  102,  103,   45,   68,
   46,   69,   47,   19,   89,   90,   49,  110,  111,   50,
   51,  139,  174,  175,   52,    5,   53,   54,   55,   56,
   57,  113,   58,   20,  254,  255,  151,  152,   60,  140,
  141,   61,  153,  154,  142,   62,  197,  143,  242,  243,
  144,  198,  250,  159,  163,  268,  269,  291,  270,  271,
  294,  295,  199,  251,  301,  205,  303,  259,  281,  261,
  282,  283,  106,  107,  189,  190,  191,  192,  298,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -170,
    0,    0,    0,    0,    0,   -8,  281,    0,  -26,  -21,
  -18,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -199,    0,    0,   -7,    8,   12,   14,   20,   22,   24,
   32,   39,   55,   57,   60,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    2, -206, -239, -143,   25,   27,   93,   94, -248,
 -168, -115, -179, -177,    0,    0, -171, -127, -127, -127,
 -173, -244,    0,    0,    0,    0,    0,    0, -143,    0,
 -247, -240, -290, -290,    0,    0,    0,    0, -168,    0,
    0, -115,    0,    0,    0, -231, -231,    0,    0, -171,
    0,    0,    0,    0,    0,    0,  103,  104,  105,  106,
  107,  108,  109,  112,  115, -218,  116,  117,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -244,
 -157,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -247, -157, -240, -157,    0,    0,    0,    0,    0, -152,
 -152, -152,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -231,    0,    0, -231, -136, -160,
 -201,  -94,  -87, -204, -117, -200,    0,    0,    0,    0,
  133,  142, -131, -130,    0,    0, -244, -134,  146,    0,
  -88,    0, -240, -289,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -160,    0,    0,    0,    0,    0,    0,
 -201,    0,    0,  -94,    0,    0,  -87,    0,    0,    0,
    0,    0,    0,    0, -204,    0,    0,    0,    0,    0,
    0,    0, -200, -290, -290,    0,    0,   83,    0,    0,
  160, -290,    0,  161, -247,   95,    0,    0,    0,  176,
 -191,    0,    0,    0,    0,    0,    0,    0,  175, -152,
 -152,    0,    0, -290,    0, -192,   98,    0, -107,    0,
    0,    0,    0, -294,    0,    0,    0,    0,    0, -105,
    0, -105, -105,    0,    0,    0,    0,    0,    0,    0,
 -152,  -92,    0,    0,    0,    0, -191,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  227,  228,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -104,    0,    0,    0,    0,    0,    0,  132,    0,
 -103, -102,    0,    0,    0,    0,    0,    0,  169,    0,
    0,   81,    0,    0,    0,    0,    0,    0,    0,  207,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -120,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -119,    0, -118,    0,    0,    0,    0,    0,    0,  244,
  244,  244,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    1,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  110,    0,    0,    0,
    0,    0,  111,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  283,    0,    0,    0,    0,    0,    0,
  297,    0,    0,  395,    0,    0,  439,    0,    0,    0,
    0,    0,    0,    0,  349,    0,    0,    0,    0,    0,
    0,    0,  453,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  113,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -125,
 -125,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -116,
    0, -116, -116,    0,    0,    0,    0,    0,    0,    0,
 -125,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,  124,  -75,   15,    0,  -68,    0,   13,    0,
    0,    9,    0,    0,   10,    0,  232,    0,    0,    0,
  141,  -67,    6,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  235,    0,  143,    0,    0,
    0,    0,    0,  236,    0,  157,    0,    0,  137,    0,
    0,  -66,  -89,    0,    0,    0,    0,    0,    0,    0,
    0,   64,    0,  241,    0,    0,    0, -141,    0,    0,
 -123,    0,    0, -132,  -84,  229, -111,    0,   16,    0,
    0,    0,    0,    0,    0, -219,  -90,    0,  -81,  -79,
    0,    0,    0,    0,    0, -142, -147,    0,   45,  -50,
  -54,    0,    0,    0,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 791
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                     196,
  105,   13,  160,  164,  118,  168,  109,  155,  199,  200,
  105,  161,  165,  162,  166,  146,  195,  176,  206,  207,
  202,   26,  147,  148,  150,  272,  117,   95,  257,  117,
  299,   63,  275,  117,  156,  157,   64,  158,  300,   65,
  201,  258,  203,   96,  169,  170,  171,  172,  173,  119,
   70,  118,  119,  120,  287,  118,  120,    8,   84,   85,
   86,  123,  121,  122,  123,   71,  121,  122,  155,   72,
  256,   73,  124,  248,  125,  146,  124,   74,  125,   75,
   55,   76,  147,  148,  150,  208,    1,    2,  209,   77,
   55,  126,  127,  128,   36,   37,   78,  128,   97,   98,
  215,  216,  217,  218,  219,  229,  230,  231,  232,  233,
  108,  109,   79,  277,   80,  187,  188,   81,  155,  237,
  238,  239,  240,  241,   82,  105,   83,  285,  286,   14,
   39,   68,  156,  157,  288,  158,  289,  211,  212,  258,
  280,   68,  114,  115,  304,  305,   88,   91,  196,   92,
   93,   94,  199,  104,  101,  105,  112,  199,  306,  116,
  178,  179,  180,  181,  182,  183,  184,  196,   93,  185,
  196,  196,  186,  193,  194,  196,  196,  204,   93,  146,
  199,  196,  196,  196,  199,  290,  147,  148,  150,  223,
  244,  196,  199,  196,  292,  210,  293,  226,  236,  245,
  249,  246,  247,  252,  253,   55,   84,  273,  196,  196,
  196,  196,  196,  118,  168,  109,   84,  274,  276,  278,
  279,  284,  296,  297,  302,  257,    2,    1,  262,  118,
  168,  109,  264,  263,  118,  109,  265,  168,   40,  167,
  266,   44,   48,  196,  168,  145,  177,   59,  260,   67,
    8,  307,  308,  196,    0,    9,   10,    0,  267,  105,
  105,  105,  105,  105,    0,  105,  105,    0,    0,  105,
    0,    0,  105,  105,  105,  105,    0,    0,    0,    0,
   11,  105,    0,   12,    0,    0,  105,  105,  105,  105,
   38,  105,  105,    0,  105,  105,  105,  105,    0,    0,
    0,  105,    0,    0,    0,    0,    0,  105,  105,  105,
    0,    0,    0,    0,    0,    0,    0,  105,    0,  105,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  105,    0,  105,  105,  105,   55,
   55,   55,   55,   55,    0,   55,   55,    0,    0,   55,
    0,    0,   55,   55,   55,   55,    0,    0,    0,    0,
    0,   55,    0,    0,    0,    0,   55,   55,   55,   55,
    0,   55,   55,    0,   55,   55,    0,   55,    0,    0,
    0,   55,    0,    0,    0,    0,    0,    0,    0,   55,
   68,   68,   68,   68,   68,   68,   68,   68,    0,    0,
   68,    0,    0,   68,   68,   68,   68,  140,    0,    0,
    0,    0,   68,    0,   55,    0,    0,   68,   68,   68,
   68,   43,   68,   68,    0,   68,   68,   93,   93,   93,
   93,   93,    0,   93,   93,    0,    0,   93,    0,    0,
   93,   93,   93,   93,    0,    0,    0,    0,    0,   93,
    0,    0,    0,    0,   93,   93,   93,   93,    0,   93,
   93,    0,   93,   93,    0,   84,   84,   84,   84,   84,
    0,   84,   84,  135,    0,   84,    0,    0,   84,   84,
   84,   84,    0,    0,    0,    0,    0,   84,    0,    0,
    0,    0,   84,   84,   84,   84,    0,   84,   84,    0,
   84,   84,  196,  196,  196,  196,  196,    0,  196,  196,
    0,    0,  196,    0,    0,  196,  196,  196,  196,   47,
    0,    0,    0,    0,  196,    0,    0,    0,    0,  196,
  196,  196,  196,    0,  196,  196,    0,  196,  196,    8,
   21,   22,   23,   24,    0,   10,   25,    0,    0,   26,
    0,  140,   27,   28,   29,   30,  140,    0,    0,    0,
    0,   31,    0,   51,    0,   43,   32,   33,   34,   11,
   43,   35,   12,    0,   36,   37,    0,  154,  140,  140,
    0,    0,    0,  140,    0,    0,    0,    0,    0,  140,
  140,  140,   43,   43,    0,    0,    0,   43,    0,  140,
    0,  140,    0,   43,   43,   43,    0,    0,    0,    0,
    0,    0,    0,   43,    0,   43,  140,  135,  140,  140,
  140,    0,  135,    0,    0,    0,    0,    0,    0,    0,
   43,    0,   43,   43,   43,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  135,  135,    0,    0,    0,  135,
    0,    0,    0,    0,    0,  135,  135,  135,    0,    0,
    0,    0,    0,    0,    0,  135,    0,  135,   47,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  135,    0,  135,  135,  135,    0,    0,    0,
   47,   47,    0,    0,    0,   47,    0,    0,    0,    0,
    0,   47,   47,   47,    0,    0,    0,    0,    0,    0,
    0,   47,   51,   47,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  154,    0,   47,    0,
   47,   47,   47,    0,   51,   51,    0,    0,    0,   51,
    0,    0,    0,    0,    0,   51,   51,   51,  154,  154,
    0,    0,    0,  154,    0,   51,    0,   51,    0,  154,
  154,  154,    0,    0,    0,    0,    0,    0,    0,  154,
    0,  154,   51,    0,   51,   51,   51,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  154,    0,  154,  154,
  154,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                     125,
    0,   10,   93,   94,  125,  125,  125,   92,  125,  151,
   10,   93,   94,   93,   94,   91,  140,  107,  161,  162,
  153,  269,   91,   91,   91,  245,  274,  276,  318,  274,
  325,   58,  252,  274,  325,  326,   58,  328,  333,   58,
  152,  331,  154,  292,  276,  277,  278,  279,  280,  297,
   58,  296,  297,  301,  274,  296,  301,  259,  298,  299,
  300,  309,  307,  308,  309,   58,  307,  308,  153,   58,
  203,   58,  317,  197,  319,  151,  317,   58,  319,   58,
    0,   58,  151,  151,  151,  175,  257,  258,  178,   58,
   10,  336,  337,  338,  294,  295,   58,  338,  267,  268,
  302,  303,  304,  305,  306,  310,  311,  312,  313,  314,
  282,  283,   58,  255,   58,  334,  335,   58,  203,  320,
  321,  322,  323,  324,  123,  125,  333,  270,  271,    6,
    7,    0,  325,  326,  327,  328,  329,  298,  299,  331,
  332,   10,   79,   80,  292,  293,  290,  123,  274,  123,
   58,   58,  269,  333,  270,  333,  284,  274,  301,  333,
   58,   58,   58,   58,   58,   58,   58,  293,    0,   58,
  296,  297,   58,   58,   58,  301,  334,  330,   10,  255,
  297,  307,  308,  309,  301,  276,  255,  255,  255,  284,
   58,  317,  309,  319,  276,  332,  276,  285,  316,   58,
  335,  333,  333,   58,  293,  125,    0,  125,  334,  335,
  336,  337,  338,  334,  334,  334,   10,   58,   58,  125,
   45,   47,  125,  331,  330,  318,    0,    0,  214,  334,
  334,  334,  224,  221,  125,  125,  227,  125,    7,   99,
  235,    7,    7,    0,  102,   89,  110,    7,  204,   21,
  259,  302,  307,   10,   -1,  264,  265,   -1,  243,  259,
  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,
   -1,   -1,  272,  273,  274,  275,   -1,   -1,   -1,   -1,
  289,  281,   -1,  292,   -1,   -1,  286,  287,  288,  289,
   10,  291,  292,   -1,  294,  295,  296,  297,   -1,   -1,
   -1,  301,   -1,   -1,   -1,   -1,   -1,  307,  308,  309,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  317,   -1,  319,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  334,   -1,  336,  337,  338,  259,
  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,
   -1,   -1,  272,  273,  274,  275,   -1,   -1,   -1,   -1,
   -1,  281,   -1,   -1,   -1,   -1,  286,  287,  288,  289,
   -1,  291,  292,   -1,  294,  295,   -1,  297,   -1,   -1,
   -1,  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  309,
  259,  260,  261,  262,  263,  264,  265,  266,   -1,   -1,
  269,   -1,   -1,  272,  273,  274,  275,  125,   -1,   -1,
   -1,   -1,  281,   -1,  334,   -1,   -1,  286,  287,  288,
  289,  125,  291,  292,   -1,  294,  295,  259,  260,  261,
  262,  263,   -1,  265,  266,   -1,   -1,  269,   -1,   -1,
  272,  273,  274,  275,   -1,   -1,   -1,   -1,   -1,  281,
   -1,   -1,   -1,   -1,  286,  287,  288,  289,   -1,  291,
  292,   -1,  294,  295,   -1,  259,  260,  261,  262,  263,
   -1,  265,  266,  125,   -1,  269,   -1,   -1,  272,  273,
  274,  275,   -1,   -1,   -1,   -1,   -1,  281,   -1,   -1,
   -1,   -1,  286,  287,  288,  289,   -1,  291,  292,   -1,
  294,  295,  259,  260,  261,  262,  263,   -1,  265,  266,
   -1,   -1,  269,   -1,   -1,  272,  273,  274,  275,  125,
   -1,   -1,   -1,   -1,  281,   -1,   -1,   -1,   -1,  286,
  287,  288,  289,   -1,  291,  292,   -1,  294,  295,  259,
  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,
   -1,  269,  272,  273,  274,  275,  274,   -1,   -1,   -1,
   -1,  281,   -1,  125,   -1,  269,  286,  287,  288,  289,
  274,  291,  292,   -1,  294,  295,   -1,  125,  296,  297,
   -1,   -1,   -1,  301,   -1,   -1,   -1,   -1,   -1,  307,
  308,  309,  296,  297,   -1,   -1,   -1,  301,   -1,  317,
   -1,  319,   -1,  307,  308,  309,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  317,   -1,  319,  334,  269,  336,  337,
  338,   -1,  274,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  334,   -1,  336,  337,  338,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  296,  297,   -1,   -1,   -1,  301,
   -1,   -1,   -1,   -1,   -1,  307,  308,  309,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  317,   -1,  319,  274,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  334,   -1,  336,  337,  338,   -1,   -1,   -1,
  296,  297,   -1,   -1,   -1,  301,   -1,   -1,   -1,   -1,
   -1,  307,  308,  309,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  317,  274,  319,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  274,   -1,  334,   -1,
  336,  337,  338,   -1,  296,  297,   -1,   -1,   -1,  301,
   -1,   -1,   -1,   -1,   -1,  307,  308,  309,  296,  297,
   -1,   -1,   -1,  301,   -1,  317,   -1,  319,   -1,  307,
  308,  309,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  317,
   -1,  319,  334,   -1,  336,  337,  338,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,  336,  337,
  338,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 338
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
"NOUNKNOWN","EXTENSION","BIND","PRIVILEGED","IOTIMEOUT","CONNECTTIMEOUT",
"METHOD","CLIENTMETHOD","NONE","GSSAPI","UNAME","RFC931","PAM","COMPATIBILITY",
"REUSEADDR","SAMEPORT","USERNAME","GROUPNAME","USER_PRIVILEGED",
"USER_UNPRIVILEGED","USER_LIBWRAP","LOGOUTPUT","LOGFILE","CHILD_MAXIDLE",
"ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS","PAMSERVICENAME","PROTOCOL",
"PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL",
"PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2",
"PROXYPROTOCOL_HTTP_V1_0","PROXYPROTOCOL_UPNP","USER","GROUP","COMMAND",
"COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY",
"COMMAND_UDPREPLY","ACTION","LINE","LIBWRAPSTART","OPERATOR","LOG",
"LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR","LOG_IOOPERATION",
"IPADDRESS","DOMAINNAME","DIRECT","IFNAME","URL","PORT","PORTNUMBER",
"SERVICENAME","NUMBER","FROM","TO","REDIRECT","BANDWIDTH","MAXSESSIONS",
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
"serveroption : compatibility",
"serveroption : connecttimeout",
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
"connecttimeout : CONNECTTIMEOUT ':' NUMBER",
"debuging : DEBUGING ':' NUMBER",
"compatibility : COMPATIBILITY ':' compatibilitys",
"compatibilityname : REUSEADDR",
"compatibilityname : SAMEPORT",
"compatibilitys : compatibilityname",
"compatibilitys : compatibilityname compatibilitys",
"resolveprotocol : RESOLVEPROTOCOL ':' resolveprotocolname",
"resolveprotocolname : PROTOCOL_FAKE",
"resolveprotocolname : PROTOCOL_TCP",
"resolveprotocolname : PROTOCOL_UDP",
"srchost : SRCHOST ':' srchostoptions",
"srchostoption : NOMISMATCH",
"srchostoption : NOUNKNOWN",
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
"clientruleoptions :",
"clientruleoptions : clientruleoption clientruleoptions",
"rule : verdict '{' ruleoptions fromto ruleoptions '}'",
"ruleoption : option",
"ruleoption : bandwidth",
"ruleoption : command",
"ruleoption : protocol",
"ruleoption : proxyprotocol",
"ruleoption : redirect",
"ruleoptions :",
"ruleoptions : ruleoption ruleoptions",
"option : authmethod",
"option : libwrap",
"option : log",
"option : pamservicename",
"option : user",
"option : group",
"option : session",
"verdict : VERDICT_BLOCK",
"verdict : VERDICT_PASS",
"command : COMMAND ':' commands",
"commandname : COMMAND_BIND",
"commandname : COMMAND_CONNECT",
"commandname : COMMAND_UDPASSOCIATE",
"commandname : COMMAND_BINDREPLY",
"commandname : COMMAND_UDPREPLY",
"commands : commandname",
"commands : commandname commands",
"protocol : PROTOCOL ':' protocols",
"protocolname : PROTOCOL_TCP",
"protocolname : PROTOCOL_UDP",
"protocols : protocolname",
"protocols : protocolname protocols",
"fromto : srcaddress dstaddress",
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
"libwrap : LIBWRAPSTART ':' LINE",
"srcaddress : from ':' address",
"dstaddress : to ':' address",
"rdr_fromaddress : rdr_from ':' address",
"rdr_toaddress : rdr_to ':' address",
"gateway : via ':' gwaddress",
"routeoption : command",
"routeoption : extension",
"routeoption : protocol",
"routeoption : proxyprotocol",
"routeoption : authmethod",
"routeoptions :",
"routeoptions : routeoption routeoptions",
"from : FROM",
"to : TO",
"rdr_from : FROM",
"rdr_to : TO",
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
#line 1230 "../lib/config_parse.y"

#define INTERACTIVE      0

extern FILE *yyin;

int socks_parseinit;

int
readconfig(filename)
   const char *filename;
{
   const char *function = "readconfig()";

/*   yydebug            = 1;            */
   yylineno            = 1;
   socks_parseinit   = 0;

   if ((yyin = fopen(filename, "r")) == NULL) {
      swarn("%s: %s", function, filename);
      return -1;
   }

   errno = 0;   /* don't report old errors in yyparse(). */
   yyparse();
   fclose(yyin);

#if SOCKS_SERVER
   fixconfig();
#endif /* SOCKS_SERVER */

   errno = 0;

   return 0;
}


void
#ifdef STDC_HEADERS
yyerror(const char *fmt, ...)
#else
yyerror(fmt, va_alist)
   const char *fmt;
   va_dcl
#endif  /* STDC_HEADERS */
{
   va_list ap;
   char buf[2048];
   size_t bufused;

#ifdef STDC_HEADERS
      /* LINTED pointer casts may be troublesome */
      va_start(ap, fmt);
#else
      va_start(ap);
#endif  /* STDC_HEADERS */

   bufused = snprintfn(buf, sizeof(buf),
   "%s: error on line %d, near '%.10s': ",
   sockscf.option.configfile, yylineno,
   (yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);

   vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (errno)
      serr(EXIT_FAILURE, buf);
   serrx(EXIT_FAILURE, buf);
}

void
#ifdef STDC_HEADERS
yywarn(const char *fmt, ...)
#else
yywarn(fmt, va_alist)
   const char *fmt;
   va_dcl
#endif  /* STDC_HEADERS */
{
   va_list ap;
   char buf[2048];
   size_t bufused;

#ifdef STDC_HEADERS
      /* LINTED pointer casts may be troublesome */
      va_start(ap, fmt);
#else
      va_start(ap);
#endif  /* STDC_HEADERS */

   bufused = snprintfn(buf, sizeof(buf),
   "%s: warning on line %d, near '%.10s': ",
   sockscf.option.configfile, yylineno,
   (yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);

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

   atype         = &ruleaddr->atype;
   ipaddr      = &ruleaddr->addr.ipv4.ip;
   netmask      = &ruleaddr->addr.ipv4.mask;
   domain      = ruleaddr->addr.domain;
   ifname      = ruleaddr->addr.ifname;
   port_tcp      = &ruleaddr->port.tcp;
   port_udp      = &ruleaddr->port.udp;
   operator      = &ruleaddr->operator;
}

static void
gwaddrinit(addr)
   gwaddr_t *addr;
{
   static enum operator_t operatormem;

   atype         = &addr->atype;
   ipaddr      = &addr->addr.ipv4;
   domain      = addr->addr.domain;
   ifname      = addr->addr.ifname;
   url         = addr->addr.urlname;
   port_tcp      = &addr->port;
   port_udp      = &addr->port;
   operator      = &operatormem; /* no operator in gwaddr. */
}



#if SOCKS_SERVER
static void
ruleinit(rule)
   struct rule_t *rule;
{
   rule->linenumber = yylineno;

   command         = &rule->state.command;
   methodv         = rule->state.methodv;
   methodc         = &rule->state.methodc;
   protocol         = &rule->state.protocol;
   proxyprotocol   = &rule->state.proxyprotocol;

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   *rule = ruleinitmem;

   src.atype = SOCKS_ADDR_IPV4;
   src.addr.ipv4.ip.s_addr = htonl(INADDR_ANY);
   src.port.tcp = src.port.udp = src.portend = htons(0);

   dst = rdr_from = rdr_to = src;
}

static void
fixconfig(void)
{
   const char *function = "fixsettings()";
   int i;
   uid_t euid;

   /*
    * Check arguments and settings, do they make sense?
    */

   if (sockscf.clientmethodc == 0)
      sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;

#if !HAVE_DUMPCONF
   if (!sockscf.uid.privileged_isset)
      sockscf.uid.privileged = sockscf.state.euid;
   else {
      socks_seteuid(&euid, sockscf.uid.privileged);
      socks_reseteuid(sockscf.uid.privileged, euid);
   }

   if (!sockscf.uid.unprivileged_isset)
      sockscf.uid.unprivileged = sockscf.state.euid;
   else {
      socks_seteuid(&euid, sockscf.uid.unprivileged);
      socks_reseteuid(sockscf.uid.unprivileged, euid);
   }

#if HAVE_LIBWRAP
   if (!sockscf.uid.libwrap_isset)
      sockscf.uid.libwrap = sockscf.state.euid;
   else {
      socks_seteuid(&euid, sockscf.uid.libwrap);
      socks_reseteuid(sockscf.uid.libwrap, euid);
   }
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_DUMPCONF */

   if (sockscf.internalc == 0)
      serrx(EXIT_FAILURE, "%s: no internal address given", function);
   /* values will be used once and checked there. */

   if (sockscf.external.addrc == 0)
      serrx(EXIT_FAILURE, "%s: no external address given", function);
#if !HAVE_DUMPCONF
   for (i = 0; i < sockscf.external.addrc; ++i)
      if (!addressisbindable(&sockscf.external.addrv[i]))
         serrx(EXIT_FAILURE, NULL);
#endif /* !HAVE_DUMPCONF */

#if !HAVE_DUMPCONF 
   if (sockscf.methodc == 0)
      swarnx("%s: no methods enabled (total block)", function);

   if (sockscf.uid.unprivileged == 0)
      swarnx("%s: setting the unprivileged uid to %d is not recommended",
      function, sockscf.uid.unprivileged);

#if HAVE_LIBWRAP
   if (sockscf.uid.libwrap == 0)
      swarnx("%s: setting the libwrap uid to %d is not recommended",
      function, sockscf.uid.libwrap);
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_DUMPCONF */
}

#endif /* SOCKS_SERVER */
#line 1100 "config_parse.c"
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
#line 284 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      protocol         = &protocolmem;
      extension      = &sockscf.extension;
#endif
   }
break;
case 4:
#line 293 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 10:
#line 301 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 14:
#line 308 "../lib/config_parse.y"
{
   }
break;
case 33:
#line 337 "../lib/config_parse.y"
{
      yywarn("given keyword is deprecated");
   }
break;
case 34:
#line 341 "../lib/config_parse.y"
{
      route.src      = src;
      route.dst      = dst;
      route.gw.addr   = gw;
      route.gw.state   = state;

      socks_addroute(&route, 1);
   }
break;
case 35:
#line 351 "../lib/config_parse.y"
{
      command         = &state.command;
      extension      = &state.extension;
      methodv         = state.methodv;
      methodc         = &state.methodc;
      protocol         = &state.protocol;
      proxyprotocol   = &state.proxyprotocol;

      bzero(&state, sizeof(state));
      bzero(&route, sizeof(route));
      bzero(&gw, sizeof(gw));
      bzero(&src, sizeof(src));
      bzero(&dst, sizeof(dst));
      src.atype = SOCKS_ADDR_IPV4;
      dst.atype = SOCKS_ADDR_IPV4;
   }
break;
case 37:
#line 373 "../lib/config_parse.y"
{
         proxyprotocol->socks_v4      = 1;
   }
break;
case 38:
#line 376 "../lib/config_parse.y"
{
         proxyprotocol->socks_v5      = 1;
   }
break;
case 39:
#line 379 "../lib/config_parse.y"
{
         proxyprotocol->msproxy_v2   = 1;
   }
break;
case 40:
#line 382 "../lib/config_parse.y"
{
         proxyprotocol->http_v1_0   = 1;
   }
break;
case 41:
#line 385 "../lib/config_parse.y"
{
         proxyprotocol->upnp         = 1;
   }
break;
case 46:
#line 398 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      if (adduser(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER */
   }
break;
case 50:
#line 413 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      if (addgroup(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER */
   }
break;
case 54:
#line 428 "../lib/config_parse.y"
{
         extension->bind = 1;
   }
break;
case 57:
#line 438 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      addinternal(ruleaddr);
#endif
   }
break;
case 58:
#line 445 "../lib/config_parse.y"
{
#if SOCKS_SERVER
   static struct ruleaddr_t mem;
   struct servent   *service;

   addrinit(&mem);

   /* set default port. */
   if ((service = getservbyname("socks", "tcp")) == NULL)
      *port_tcp = htons(SOCKD_PORT);
   else
      *port_tcp = (in_port_t)service->s_port;
#endif
   }
break;
case 59:
#line 461 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      addexternal(ruleaddr);
#endif
   }
break;
case 60:
#line 468 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      static struct ruleaddr_t mem;

      addrinit(&mem);
#endif
   }
break;
case 61:
#line 477 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 62:
#line 481 "../lib/config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
      yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
   }
break;
case 67:
#line 499 "../lib/config_parse.y"
{
      const char *syslogname = "syslog";

      if (strncmp(yyvsp[0].string, syslogname, strlen(syslogname)) == 0
      && (yyvsp[0].string[strlen(syslogname)] == NUL || yyvsp[0].string[strlen(syslogname)] == '/')) {
         char *sl;

         sockscf.log.type |= LOGTYPE_SYSLOG;

         if (*(sl = &(yyvsp[0].string[strlen(syslogname)])) == '/') { /* facility. */
            size_t i;

            for (i = 0, ++sl; i < ELEMENTS(syslogfacilityv); ++i)
               if (strcmp(sl, syslogfacilityv[i].name) == 0)
                  break;

            if (i == ELEMENTS(syslogfacilityv))
               yyerror("unknown syslog facility \"%s\"", sl);

            sockscf.log.facility = syslogfacilityv[i].value;
            sockscf.log.facilityname = syslogfacilityv[i].name;
         }
         else {
            sockscf.log.facility = LOG_DAEMON; /* default. */
            sockscf.log.facilityname = "daemon";
         }
      }
      else /* filename. */
         if (!sockscf.state.init) {
            int flag;

            sockscf.log.type |= LOGTYPE_FILE;

            if ((sockscf.log.fpv = realloc(sockscf.log.fpv,
            sizeof(*sockscf.log.fpv) * (sockscf.log.fpc + 1))) == NULL
            || (sockscf.log.fplockv = realloc(sockscf.log.fplockv,
            sizeof(*sockscf.log.fplockv) * (sockscf.log.fpc + 1))) == NULL
            || (sockscf.log.fnamev = realloc(sockscf.log.fnamev,
            sizeof(*sockscf.log.fnamev) * (sockscf.log.fpc + 1)))
            == NULL)
               serrx(EXIT_FAILURE, NOMEM);

            if ((sockscf.log.fplockv[sockscf.log.fpc]
            = socks_mklock(SOCKS_LOCKFILE)) == -1)
               serr(EXIT_FAILURE, "socks_mklock()");

            if (strcmp(yyvsp[0].string, "stdout") == 0)
               sockscf.log.fpv[sockscf.log.fpc] = stdout;
            else if (strcmp(yyvsp[0].string, "stderr") == 0)
               sockscf.log.fpv[sockscf.log.fpc] = stderr;
            else
               if ((sockscf.log.fpv[sockscf.log.fpc] = fopen(yyvsp[0].string, "a"))
               == NULL)
                  yyerror("fopen(%s)", yyvsp[0].string);

            if ((flag = fcntl(fileno(sockscf.log.fpv[sockscf.log.fpc]),
            F_GETFD, 0)) == -1
            ||  fcntl(fileno(sockscf.log.fpv[sockscf.log.fpc]), F_SETFD,
            flag | FD_CLOEXEC) == -1)
               serr(EXIT_FAILURE, "fcntl(F_GETFD/F_SETFD)");

            if ((sockscf.log.fnamev[sockscf.log.fpc] = strdup(yyvsp[0].string)) == NULL)
               serr(EXIT_FAILURE, NOMEM);

            ++sockscf.log.fpc;
         }
         else {
            /*
             * Can't change filenames we log to after startup, so 
             * try to check and warn about that.
             */
            size_t i;

            for (i = 0; i < sockscf.log.fpc; ++i)
               if (strcmp(sockscf.log.fnamev[i], yyvsp[0].string) == 0) { /* same name. */
                  FILE *fp;

                  if (strcmp(sockscf.log.fnamev[i], "stdout") == 0
                  ||  strcmp(sockscf.log.fnamev[i], "stderr") == 0)
                     break; /* don't need to reopen these. */

                  /* reopen logfiles. */
                  if ((fp = fopen(sockscf.log.fnamev[i], "a")) == NULL)
                     yywarn("can't reopen %s, continuing to use existing", yyvsp[0].string);
                  else {
                     fclose(sockscf.log.fpv[i]);
                     sockscf.log.fpv[i] = fp;
                  }
                  break;
               }

            if (i == sockscf.log.fpc) /* no match found. */
               yywarn("can't change logoutput after startup");
         }
   }
break;
case 70:
#line 601 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      yyerror("Sorry, child.maxidle is disabled due to a suspected bug");
      if (atoi(yyvsp[0].string) != 0 && atoi(yyvsp[0].string) < SOCKD_FREESLOTS)
         yyerror("%s (%s) can't be less than SOCKD_FREESLOTS (%d)",
         yyvsp[-2].string, yyvsp[0].string, SOCKD_FREESLOTS);
      sockscf.child.maxidle = atoi(yyvsp[0].string);
#endif
   }
break;
case 74:
#line 618 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      sockscf.uid.privileged         = yyvsp[0].uid;
      sockscf.uid.privileged_isset   = 1;
#endif
   }
break;
case 75:
#line 626 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      sockscf.uid.unprivileged         = yyvsp[0].uid;
      sockscf.uid.unprivileged_isset   = 1;
#endif
   }
break;
case 76:
#line 634 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
      sockscf.uid.libwrap         = yyvsp[0].uid;
      sockscf.uid.libwrap_isset   = 1;
#else  /* HAVE_LIBWRAP */
      yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP */
   }
break;
case 77:
#line 645 "../lib/config_parse.y"
{
      struct passwd *pw;

      if ((pw = getpwnam(yyvsp[0].string)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
      else
         yyval.uid = pw->pw_uid;
   }
break;
case 78:
#line 655 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      sockscf.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
   }
break;
case 79:
#line 662 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      sockscf.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
   }
break;
case 80:
#line 669 "../lib/config_parse.y"
{
      sockscf.option.debug = atoi(yyvsp[0].string);
   }
break;
case 82:
#line 677 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      sockscf.compat.reuseaddr = 1;
   }
break;
case 83:
#line 681 "../lib/config_parse.y"
{
      sockscf.compat.sameport = 1;
#endif
   }
break;
case 87:
#line 694 "../lib/config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 88:
#line 697 "../lib/config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 89:
#line 704 "../lib/config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 91:
#line 712 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
         sockscf.srchost.nomismatch = 1;
   }
break;
case 92:
#line 716 "../lib/config_parse.y"
{
         sockscf.srchost.nounknown = 1;
#else
      yyerror("srchostoption requires libwrap");
#endif
   }
break;
case 96:
#line 732 "../lib/config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.methodv;
   methodc = &sockscf.methodc;
   *methodc = 0; /* reset. */
#endif
   }
break;
case 98:
#line 741 "../lib/config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.clientmethodv;
   methodc = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif
   }
break;
case 100:
#line 750 "../lib/config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_NONE);
   }
break;
case 101:
#line 753 "../lib/config_parse.y"
{
      yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
   }
break;
case 102:
#line 756 "../lib/config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
break;
case 103:
#line 759 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP 
#if SOCKS_SERVER
      ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !SOCKS_SERVER not a real socks method.  For client same as none. */
      ADDMETHOD(AUTHMETHOD_NONE);
#endif
#else /* !HAVE_LIBWRAP */
      yyerror("method %s requires libwraplibrary", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
   }
break;
case 104:
#line 770 "../lib/config_parse.y"
{
#if HAVE_PAM
#if SOCKS_SERVER
      ADDMETHOD(AUTHMETHOD_PAM);
#else /* !SOCKS_SERVER not a real socks method.  For client same as uname. */
      ADDMETHOD(AUTHMETHOD_UNAME);
#endif
#else /* HAVE_PAM */
      yyerror("method %s requires pamlibrary", AUTHMETHOD_PAMs);
#endif /* !HAVE_PAM */
   }
break;
case 107:
#line 790 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from   = rdr_from;
      rule.rdr_to      = rdr_to;

      addclientrule(&rule);

#endif
   }
break;
case 109:
#line 806 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 111:
#line 810 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from   = rdr_from;
      rule.rdr_to      = rdr_to;

      addsocksrule(&rule);
#endif
   }
break;
case 113:
#line 824 "../lib/config_parse.y"
{
#if SOCKS_SERVER
         checkmodule("bandwidth");
#endif
   }
break;
case 117:
#line 832 "../lib/config_parse.y"
{
#if SOCKS_SERVER
         checkmodule("redirect");
#endif
   }
break;
case 118:
#line 839 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 126:
#line 849 "../lib/config_parse.y"
{
#if SOCKS_SERVER
         checkmodule("session");
#endif
   }
break;
case 127:
#line 856 "../lib/config_parse.y"
{
#if SOCKS_SERVER
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 128:
#line 861 "../lib/config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif
   }
break;
case 130:
#line 872 "../lib/config_parse.y"
{
         command->bind = 1;
   }
break;
case 131:
#line 875 "../lib/config_parse.y"
{
         command->connect = 1;
   }
break;
case 132:
#line 878 "../lib/config_parse.y"
{
         command->udpassociate = 1;
   }
break;
case 133:
#line 884 "../lib/config_parse.y"
{
         command->bindreply = 1;
   }
break;
case 134:
#line 888 "../lib/config_parse.y"
{
         command->udpreply = 1;
   }
break;
case 138:
#line 900 "../lib/config_parse.y"
{
      protocol->tcp = 1;
   }
break;
case 139:
#line 903 "../lib/config_parse.y"
{
      protocol->udp = 1;
   }
break;
case 146:
#line 923 "../lib/config_parse.y"
{
#if SOCKS_SERVER
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
#endif /* SOCKS_SERVER */
}
break;
case 147:
#line 940 "../lib/config_parse.y"
{
#if SOCKS_SERVER
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
#endif /* SOCKS_SERVER */
   }
break;
case 149:
#line 961 "../lib/config_parse.y"
{
#if SOCKS_SERVER
   rule.log.connect = 1;
   }
break;
case 150:
#line 965 "../lib/config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 151:
#line 968 "../lib/config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 152:
#line 971 "../lib/config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 153:
#line 974 "../lib/config_parse.y"
{
         rule.log.iooperation = 1;
#endif
   }
break;
case 156:
#line 985 "../lib/config_parse.y"
{
#if HAVE_PAM && SOCKS_SERVER
      if (strlen(yyvsp[0].string) >= sizeof(rule.pamservicename))
         yyerror("servicename too long");
      strcpy(rule.pamservicename, yyvsp[0].string);
#else /* !HAVE_PAM */
      yyerror("pamsupport not compiled in");
#endif /* HAVE_PAM */
   }
break;
case 157:
#line 996 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
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

#else /* !HAVE_LIBWRAP */
      yyerror("libwrapsupport not compiled in");
#endif
   }
break;
case 168:
#line 1046 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 170:
#line 1050 "../lib/config_parse.y"
{
      addrinit(&src);
   }
break;
case 171:
#line 1055 "../lib/config_parse.y"
{
      addrinit(&dst);
   }
break;
case 172:
#line 1060 "../lib/config_parse.y"
{
      addrinit(&rdr_from);
   }
break;
case 173:
#line 1065 "../lib/config_parse.y"
{
      addrinit(&rdr_to);
   }
break;
case 174:
#line 1072 "../lib/config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 189:
#line 1102 "../lib/config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton(yyvsp[0].string, ipaddr) != 1)
         yyerror("bad address: %s", yyvsp[0].string);
   }
break;
case 190:
#line 1111 "../lib/config_parse.y"
{
      if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
         yyerror("bad netmask: %s", yyvsp[0].string);

      netmask->s_addr
      = atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
   }
break;
case 191:
#line 1118 "../lib/config_parse.y"
{
         if (!inet_aton(yyvsp[0].string, netmask))
            yyerror("bad netmask: %s", yyvsp[0].string);
   }
break;
case 192:
#line 1124 "../lib/config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");
      strcpy(domain, yyvsp[0].string);
   }
break;
case 193:
#line 1133 "../lib/config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
         yyerror("interfacename too long");
      strcpy(ifname, yyvsp[0].string);
   }
break;
case 194:
#line 1143 "../lib/config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", yyvsp[0].string);
      strcpy(domain, yyvsp[0].string);

      proxyprotocol->direct = 1;
   }
break;
case 195:
#line 1154 "../lib/config_parse.y"
{
      *atype = SOCKS_ADDR_URL;

      if (strlen(yyvsp[0].string) >= MAXURLLEN)
         yyerror("url \"%s\" too long", yyvsp[0].string);
      strcpy(url, yyvsp[0].string);
   }
break;
case 196:
#line 1164 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 199:
#line 1169 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 204:
#line 1181 "../lib/config_parse.y"
{
      *port_tcp   = htons((in_port_t)atoi(yyvsp[0].string));
      *port_udp   = htons((in_port_t)atoi(yyvsp[0].string));
   }
break;
case 205:
#line 1187 "../lib/config_parse.y"
{
      ruleaddr->portend      = htons((in_port_t)atoi(yyvsp[0].string));
      ruleaddr->operator   = range;
   }
break;
case 206:
#line 1193 "../lib/config_parse.y"
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
case 207:
#line 1224 "../lib/config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
#line 2153 "config_parse.c"
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
