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
#line 45 "config_parse.y"

#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.228 2009/01/12 14:04:54 michaels Exp $";

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
static struct rule_t          ruleinitmem;
static struct rule_t          rule;          /* new rule.                     */
static struct protocol_t      protocolmem;   /* new protocolmem.              */
#endif

static struct serverstate_t   state;
static struct route_t         route;         /* new route.                    */
static gwaddr_t               gw;            /* new gateway.                  */

static struct ruleaddr_t      src;            /* new src.                     */
static struct ruleaddr_t      dst;            /* new dst.                     */
static struct ruleaddr_t      rdr_from;
static struct ruleaddr_t      rdr_to;

static struct ruleaddr_t      *ruleaddr;      /* current ruleaddr             */
static struct extension_t     *extension;     /* new extensions               */
static struct proxyprotocol_t *proxyprotocol; /* proxy protocol.              */

static char                   *atype;         /* atype of new address.        */
static struct in_addr         *ipaddr;        /* new ipaddress                */
static struct in_addr         *netmask;       /* new netmask                  */
static char                   *domain;        /* new domain.                  */
static char                   *ifname;        /* new ifname.                  */
static char                   *url;           /* new url.                     */

static in_port_t             *port_tcp;       /* new TCP portnumber.          */
static in_port_t             *port_udp;       /* new UDP portnumber.          */
static int                   *methodv;        /* new authmethods.             */
static size_t                *methodc;        /* number of them.              */
static struct protocol_t     *protocol;       /* new protocol.                */
static struct command_t      *command;        /* new command.                 */
static enum operator_t       *operator;       /* new operator.                */

static const struct {
   const char *name;
   const int value;
} syslogfacilityv[] = {
#ifdef LOG_AUTH
   { "auth",   LOG_AUTH          },
#endif /* LOG_AUTH */
#ifdef LOG_AUTHPRIV
   { "authpriv",   LOG_AUTHPRIV  },
#endif /* LOG_AUTHPRIV */
#ifdef LOG_DAEMON
   { "daemon",   LOG_DAEMON      },
#endif /* LOG_DAEMON */
#ifdef LOG_USER
   { "user",   LOG_USER          },
#endif /* LOG_USER */
#ifdef LOG_LOCAL0
   { "local0",   LOG_LOCAL0      },
#endif /* LOG_LOCAL0 */
#ifdef LOG_LOCAL1
   { "local1",   LOG_LOCAL1      },
#endif /* LOG_LOCAL1 */
#ifdef LOG_LOCAL2
   { "local2",   LOG_LOCAL2      },
#endif /* LOG_LOCAL2 */
#ifdef LOG_LOCAL3
   { "local3",   LOG_LOCAL3      },
#endif /* LOG_LOCAL3 */
#ifdef LOG_LOCAL4
   { "local4",   LOG_LOCAL4      },
#endif /* LOG_LOCAL4 */
#ifdef LOG_LOCAL5
   { "local5",   LOG_LOCAL5      },
#endif /* LOG_LOCAL5 */
#ifdef LOG_LOCAL6
   { "local6",   LOG_LOCAL6      },
#endif /* LOG_LOCAL6 */
#ifdef LOG_LOCAL7
   { "local7",   LOG_LOCAL7      }
#endif /* LOG_LOCAL7 */
};


#define YYDEBUG 1

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

#line 172 "config_parse.y"
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
#define UDPRANGE 339
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   59,    1,    1,    1,    1,    1,    1,    2,
    2,    2,    2,   33,   34,   34,   60,   60,   60,   60,
   60,   60,   60,   60,   60,   60,   58,   58,   58,   58,
   58,   58,    3,   67,   29,    7,    8,    8,    8,    8,
    8,    8,    9,    9,   10,   11,   12,   12,   13,   14,
   15,   15,   39,   40,   41,   41,   42,   43,   44,   45,
   46,   46,   35,   35,   35,   47,   48,   49,   49,   66,
   61,   61,   61,   62,   63,   64,   65,   37,   38,   36,
   50,   51,   51,   52,   52,   17,   18,   18,   18,   19,
   20,   20,   21,   21,   55,  106,   53,  107,   54,   57,
   57,   57,   57,   57,   56,   56,   75,   76,   77,   77,
   72,   73,   73,   73,   73,   73,   73,   73,   74,   74,
   78,   78,   78,   78,   78,   78,   78,   79,   79,   22,
   24,   24,   24,   24,   24,   23,   23,    4,    6,    6,
    5,    5,   80,   25,   25,   27,   28,   26,   81,   83,
   83,   83,   83,   83,   82,   82,   16,   84,   85,   86,
  108,  109,   69,   70,   70,   70,   70,   70,   71,   71,
   96,   97,  110,  111,   68,   87,   87,   87,   88,   88,
   88,   89,   89,   89,   91,   91,   91,   91,   91,   90,
   98,   98,   92,   93,   94,   95,   99,   99,   99,  100,
  100,  104,  104,  101,  102,  112,  105,  103,   30,   31,
   32,
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
    6,    1,    1,    1,    1,    1,    1,    1,    0,    2,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    3,
    1,    1,    1,    1,    1,    1,    2,    3,    1,    1,
    1,    2,    2,    2,    2,    1,    3,    3,    3,    1,
    1,    1,    1,    1,    1,    2,    3,    3,    3,    3,
    3,    3,    3,    1,    1,    1,    1,    1,    0,    2,
    1,    1,    1,    1,    1,    2,    2,    2,    1,    1,
    1,    4,    2,    2,    2,    2,    2,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    0,    3,    2,    0,
    3,    1,    1,    3,    1,    1,    1,    1,    5,    1,
    1,
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
    0,    0,    0,    0,    0,  128,  129,    5,   19,   31,
   32,   30,   28,   29,   20,   21,   22,   23,   27,   17,
   18,   24,    6,   25,   71,   72,   73,   26,    9,    8,
    7,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   96,   98,    0,    0,    0,    0,
    0,    0,   80,   88,   89,   87,   86,   67,    0,   66,
    0,    0,    0,    0,   61,   62,   91,   92,    0,   90,
   54,    0,   53,   78,   79,    0,    0,   82,   83,    0,
   81,   77,   74,   75,   76,   70,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  116,
  117,  125,  126,  124,  114,  118,  113,  127,  146,  115,
  121,    0,    0,  112,  123,  122,   69,  166,  167,  164,
  165,  168,    0,    0,    0,    0,  108,  190,  193,  194,
   57,    0,    0,    0,   59,  179,  180,  181,   94,   56,
  100,  101,  102,  103,  104,   97,    0,   99,   85,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  173,  174,
  144,  145,    0,    0,    0,    0,    0,  120,  171,    0,
    0,    0,  170,    0,  110,    0,    0,  176,  177,  178,
  106,   95,  157,  139,  140,  138,    0,   37,   38,   39,
   40,   41,   42,    0,   36,   46,    0,   45,   50,    0,
   49,  131,  132,  133,  134,  135,  130,    0,  158,  150,
  151,  152,  153,  154,  149,    0,    0,    0,  148,  147,
  210,    0,    0,  172,  143,    0,    0,  175,    0,    0,
    0,  208,  205,  199,    0,    0,  142,   44,   48,   52,
  137,  156,  161,    0,    0,    0,  162,    0,  111,    0,
  159,    0,    0,  107,    0,  207,  203,  198,  202,    0,
  183,  184,  211,  209,  160,  195,  196,    0,  163,    0,
    0,  188,  189,   34,  206,  204,  192,  191,    0,    0,
  185,  186,  187,  182,    0,  201,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
    7,    6,  223,  130,  216,  217,  131,  224,  225,  132,
  227,  228,  133,  230,  231,  134,   15,   87,   41,   99,
  100,  135,  237,  238,  136,  137,  138,  139,   66,  140,
  252,  294,    4,   16,   17,   18,   42,   43,  151,  102,
  103,   45,   68,   46,   69,   47,   19,   89,   90,   49,
  110,  111,   50,   51,  141,  176,  177,   52,    5,   53,
   54,   55,   56,   57,  113,   58,   20,  259,  260,  153,
  154,   60,  142,  143,   61,  155,  156,  144,   62,  200,
  145,  245,  246,  146,  201,  255,  161,  165,  273,  274,
  299,  275,  276,  302,  303,  202,  256,  309,  208,  311,
  264,  287,  266,  288,  289,  106,  107,  191,  192,  193,
  194,  306,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -226,
    0,    0,    0,    0,    0,   -8,  284,    0,  -15,    6,
    8,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -200,    0,    0,   11,   30,   44,   69,   74,   76,   81,
   83,   84,   86,   87,   88,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   17, -185, -190, -139,   27,   31,   95,   97, -250,
 -156, -114, -176, -175,    0,    0, -169, -123, -123, -123,
 -174, -252,    0,    0,    0,    0,    0,    0, -139,    0,
 -178, -249, -265, -265,    0,    0,    0,    0, -156,    0,
    0, -114,    0,    0,    0, -242, -242,    0,    0, -169,
    0,    0,    0,    0,    0,    0,  102,  104,  105,  106,
  107,  108,  109,  115,  116, -219,  119,  120,  123,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -252, -145,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -178, -145, -249, -145,    0,    0,    0,    0,
    0, -135, -135, -135,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -242,    0,    0, -242,
 -141, -181, -231,  -88,  -86, -260, -116, -223,    0,    0,
    0,    0,  139,  144, -130, -129, -112,    0,    0, -252,
 -115,  147,    0,  -71,    0, -249, -291,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -181,    0,    0,    0,
    0,    0,    0, -231,    0,    0,  -88,    0,    0,  -86,
    0,    0,    0,    0,    0,    0,    0, -260,    0,    0,
    0,    0,    0,    0,    0, -223, -265, -265,    0,    0,
    0,  161,   96,    0,    0,  165, -265,    0,  166, -178,
  100,    0,    0,    0,  181, -211,    0,    0,    0,    0,
    0,    0,    0,  180, -135, -135,    0, -103,    0, -265,
    0, -222,  110,    0, -102,    0,    0,    0,    0, -292,
    0,    0,    0,    0,    0,    0,    0, -100,    0, -100,
 -100,    0,    0,    0,    0,    0,    0,    0, -135,  -85,
    0,    0,    0,    0, -211,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  231,  232,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  -98,    0,    0,    0,    0,    0,    0,  133,    0,
  -97,  -96,    0,    0,    0,    0,    0,    0,  170,    0,
    0,   82,    0,    0,    0,    0,    0,    0,    0,  208,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -119,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -118,    0, -117,    0,    0,    0,    0,    0,
    0,  245,  245,  245,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    1,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  114,
    0,    0,    0,    0,    0,  117,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  286,    0,    0,    0,
    0,    0,    0,  330,    0,    0,  400,    0,    0,  444,
    0,    0,    0,    0,    0,    0,    0,  376,    0,    0,
    0,    0,    0,    0,    0,  488,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  121,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -125, -125,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -122,    0, -122,
 -122,    0,    0,    0,    0,    0,    0,    0, -125,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,  118,  -75,   23,    0,  -74,    0,   10,    0,
    0,   14,    0,    0,   13,    0,  237,    0,    0,    0,
  148,  -72,   12,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  241,    0,
  150,    0,    0,    0,    0,    0,  242,    0,  164,    0,
    0,  149,    0,    0,  -70,  -87,    0,    0,    0,    0,
    0,    0,    0,    0,   50,    0,  247,    0,    0,    0,
 -138,    0,    0, -124,    0,    0, -126,  -78,  244, -108,
    0,   22,    0,    0,    0,    0,    0,    0, -218,  -89,
    0,  -84,  -81,    0,    0,    0,    0,    0, -140, -163,
    0,   51,  -41,  -44,    0,    0,    0,    0,    0,    0,
    0,    0,
};
#define YYTABLESIZE 827
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                     197,
  105,   13,  200,  162,  166,  119,  169,  109,  163,  167,
  105,  164,  168,  157,  203,  148,  149,  198,  150,  178,
  152,  117,  209,  210,  117,   95,  262,    8,  205,  277,
    1,    2,  307,  171,  172,  173,  174,  175,  281,  263,
  308,   96,   63,  118,  119,  204,  118,  206,  120,  232,
  233,  234,  235,  236,  121,  122,  123,  121,  122,  158,
  159,  295,  160,   64,  124,   65,  125,  124,   70,  125,
  218,  219,  220,  221,  222,  253,  157,  148,  149,  261,
  150,   55,  152,  126,  127,  128,  129,   71,  128,  211,
   26,   55,  212,   36,   37,  117,  240,  241,  242,  243,
  244,   72,  158,  159,  296,  160,  297,   84,   85,   86,
   97,   98,  108,  109,  189,  190,  214,  215,  119,  263,
  286,  283,  120,   14,   39,  105,   73,  157,  114,  115,
  123,   74,   68,   75,  291,  292,  312,  313,   76,   82,
   77,   78,   68,   79,   80,   81,  200,   83,  197,   91,
   88,  200,   93,   92,   94,  101,  104,  105,  116,  180,
  112,  181,  182,  183,  184,  185,  186,  197,  314,   93,
  197,  197,  187,  188,  200,  197,  195,  196,  200,   93,
  197,  197,  197,  197,  148,  149,  200,  150,  199,  152,
  213,  197,  298,  197,  207,  226,  247,  300,  229,  239,
  301,  248,  249,  250,  257,  278,   55,   84,  197,  197,
  197,  197,  197,  197,  119,  169,  109,   84,  251,  254,
  279,  258,  280,  282,  284,  285,  290,  293,  305,  310,
    2,    1,  262,  268,  304,  119,  169,  109,  119,  267,
  269,  109,  270,   40,  197,  169,  169,   44,   48,  271,
    8,  170,  147,   59,  197,    9,   10,  265,  179,  105,
  105,  105,  105,  105,   67,  105,  105,  272,  315,  105,
  316,    0,  105,  105,  105,  105,    0,    0,    0,    0,
   11,  105,    0,   12,    0,    0,  105,  105,  105,  105,
    0,  105,  105,   38,  105,  105,  105,  105,    0,    0,
    0,  105,    0,    0,    0,    0,    0,  105,  105,  105,
    0,    0,    0,    0,    0,    0,    0,  105,    0,  105,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  105,    0,  105,  105,  105,  105,
   55,   55,   55,   55,   55,    0,   55,   55,    0,    0,
   55,    0,    0,   55,   55,   55,   55,    0,    0,    0,
    0,    0,   55,    0,    0,    0,    0,   55,   55,   55,
   55,    0,   55,   55,    0,   55,   55,    0,   55,    0,
    0,    0,   55,    0,    0,    0,    0,    0,    0,    0,
   55,   68,   68,   68,   68,   68,   68,   68,   68,    0,
    0,   68,    0,    0,   68,   68,   68,   68,    0,    0,
  141,    0,    0,   68,    0,   55,    0,    0,   68,   68,
   68,   68,    0,   68,   68,    0,   68,   68,   93,   93,
   93,   93,   93,    0,   93,   93,    0,    0,   93,    0,
    0,   93,   93,   93,   93,    0,    0,    0,    0,    0,
   93,    0,    0,    0,   43,   93,   93,   93,   93,    0,
   93,   93,    0,   93,   93,    0,   84,   84,   84,   84,
   84,    0,   84,   84,    0,    0,   84,    0,    0,   84,
   84,   84,   84,    0,    0,    0,    0,    0,   84,    0,
    0,    0,    0,   84,   84,   84,   84,    0,   84,   84,
  136,   84,   84,  197,  197,  197,  197,  197,    0,  197,
  197,    0,    0,  197,    0,    0,  197,  197,  197,  197,
    0,    0,    0,    0,   47,  197,    0,    0,    0,    0,
  197,  197,  197,  197,    0,  197,  197,    0,  197,  197,
    0,    0,    8,   21,   22,   23,   24,    0,   10,   25,
    0,    0,   26,    0,  141,   27,   28,   29,   30,  141,
    0,    0,    0,    0,   31,    0,    0,    0,   51,   32,
   33,   34,   11,    0,   35,   12,    0,   36,   37,    0,
    0,  141,  141,    0,    0,    0,  141,    0,    0,    0,
    0,    0,  141,  141,  141,    0,    0,    0,   43,    0,
    0,    0,  141,   43,  141,    0,    0,    0,    0,    0,
    0,    0,  155,    0,    0,    0,    0,    0,    0,  141,
    0,  141,  141,  141,  141,   43,   43,    0,    0,    0,
   43,    0,    0,    0,    0,    0,   43,   43,   43,    0,
    0,    0,    0,    0,  136,    0,   43,    0,   43,  136,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   43,    0,   43,   43,   43,   43,    0,
    0,  136,  136,   47,    0,    0,  136,    0,    0,    0,
    0,    0,  136,  136,  136,    0,    0,    0,    0,    0,
    0,    0,  136,    0,  136,   47,   47,    0,    0,    0,
   47,    0,    0,    0,    0,    0,   47,   47,   47,  136,
    0,  136,  136,  136,  136,    0,   47,   51,   47,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   47,    0,   47,   47,   47,   47,   51,
   51,    0,    0,    0,   51,    0,    0,    0,    0,    0,
   51,   51,   51,    0,    0,    0,    0,    0,    0,    0,
   51,  155,   51,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   51,    0,   51,
   51,   51,   51,  155,  155,    0,    0,    0,  155,    0,
    0,    0,    0,    0,  155,  155,  155,    0,    0,    0,
    0,    0,    0,    0,  155,    0,  155,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  155,    0,  155,  155,  155,  155,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                     125,
    0,   10,  125,   93,   94,  125,  125,  125,   93,   94,
   10,   93,   94,   92,  153,   91,   91,  142,   91,  107,
   91,  274,  163,  164,  274,  276,  318,  259,  155,  248,
  257,  258,  325,  276,  277,  278,  279,  280,  257,  331,
  333,  292,   58,  296,  297,  154,  296,  156,  301,  310,
  311,  312,  313,  314,  307,  308,  309,  307,  308,  325,
  326,  280,  328,   58,  317,   58,  319,  317,   58,  319,
  302,  303,  304,  305,  306,  200,  155,  153,  153,  206,
  153,    0,  153,  336,  337,  338,  339,   58,  338,  177,
  269,   10,  180,  294,  295,  274,  320,  321,  322,  323,
  324,   58,  325,  326,  327,  328,  329,  298,  299,  300,
  267,  268,  282,  283,  334,  335,  298,  299,  297,  331,
  332,  260,  301,    6,    7,  125,   58,  206,   79,   80,
  309,   58,    0,   58,  275,  276,  300,  301,   58,  123,
   58,   58,   10,   58,   58,   58,  269,  333,  274,  123,
  290,  274,   58,  123,   58,  270,  333,  333,  333,   58,
  284,   58,   58,   58,   58,   58,   58,  293,  309,    0,
  296,  297,   58,   58,  297,  301,   58,   58,  301,   10,
   58,  307,  308,  309,  260,  260,  309,  260,  334,  260,
  332,  317,  282,  319,  330,  284,   58,  282,  285,  316,
  282,   58,  333,  333,   58,   45,  125,    0,  334,  335,
  336,  337,  338,  339,  334,  334,  334,   10,  331,  335,
  125,  293,   58,   58,  125,   45,   47,  331,  331,  330,
    0,    0,  318,  224,  125,  334,  334,  334,  125,  217,
  227,  125,  230,    7,    0,  125,   99,    7,    7,  238,
  259,  102,   89,    7,   10,  264,  265,  207,  110,  259,
  260,  261,  262,  263,   21,  265,  266,  246,  310,  269,
  315,   -1,  272,  273,  274,  275,   -1,   -1,   -1,   -1,
  289,  281,   -1,  292,   -1,   -1,  286,  287,  288,  289,
   -1,  291,  292,   10,  294,  295,  296,  297,   -1,   -1,
   -1,  301,   -1,   -1,   -1,   -1,   -1,  307,  308,  309,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  317,   -1,  319,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  334,   -1,  336,  337,  338,  339,
  259,  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,
  269,   -1,   -1,  272,  273,  274,  275,   -1,   -1,   -1,
   -1,   -1,  281,   -1,   -1,   -1,   -1,  286,  287,  288,
  289,   -1,  291,  292,   -1,  294,  295,   -1,  297,   -1,
   -1,   -1,  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  309,  259,  260,  261,  262,  263,  264,  265,  266,   -1,
   -1,  269,   -1,   -1,  272,  273,  274,  275,   -1,   -1,
  125,   -1,   -1,  281,   -1,  334,   -1,   -1,  286,  287,
  288,  289,   -1,  291,  292,   -1,  294,  295,  259,  260,
  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,   -1,
   -1,  272,  273,  274,  275,   -1,   -1,   -1,   -1,   -1,
  281,   -1,   -1,   -1,  125,  286,  287,  288,  289,   -1,
  291,  292,   -1,  294,  295,   -1,  259,  260,  261,  262,
  263,   -1,  265,  266,   -1,   -1,  269,   -1,   -1,  272,
  273,  274,  275,   -1,   -1,   -1,   -1,   -1,  281,   -1,
   -1,   -1,   -1,  286,  287,  288,  289,   -1,  291,  292,
  125,  294,  295,  259,  260,  261,  262,  263,   -1,  265,
  266,   -1,   -1,  269,   -1,   -1,  272,  273,  274,  275,
   -1,   -1,   -1,   -1,  125,  281,   -1,   -1,   -1,   -1,
  286,  287,  288,  289,   -1,  291,  292,   -1,  294,  295,
   -1,   -1,  259,  260,  261,  262,  263,   -1,  265,  266,
   -1,   -1,  269,   -1,  269,  272,  273,  274,  275,  274,
   -1,   -1,   -1,   -1,  281,   -1,   -1,   -1,  125,  286,
  287,  288,  289,   -1,  291,  292,   -1,  294,  295,   -1,
   -1,  296,  297,   -1,   -1,   -1,  301,   -1,   -1,   -1,
   -1,   -1,  307,  308,  309,   -1,   -1,   -1,  269,   -1,
   -1,   -1,  317,  274,  319,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,  334,
   -1,  336,  337,  338,  339,  296,  297,   -1,   -1,   -1,
  301,   -1,   -1,   -1,   -1,   -1,  307,  308,  309,   -1,
   -1,   -1,   -1,   -1,  269,   -1,  317,   -1,  319,  274,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,  336,  337,  338,  339,   -1,
   -1,  296,  297,  274,   -1,   -1,  301,   -1,   -1,   -1,
   -1,   -1,  307,  308,  309,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  317,   -1,  319,  296,  297,   -1,   -1,   -1,
  301,   -1,   -1,   -1,   -1,   -1,  307,  308,  309,  334,
   -1,  336,  337,  338,  339,   -1,  317,  274,  319,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  334,   -1,  336,  337,  338,  339,  296,
  297,   -1,   -1,   -1,  301,   -1,   -1,   -1,   -1,   -1,
  307,  308,  309,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  317,  274,  319,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  334,   -1,  336,
  337,  338,  339,  296,  297,   -1,   -1,   -1,  301,   -1,
   -1,   -1,   -1,   -1,  307,  308,  309,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  317,   -1,  319,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  334,   -1,  336,  337,  338,  339,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 339
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
"UDPRANGE",
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
"ruleoption : udprange",
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
"udprange : UDPRANGE ':' udprange_start '-' udprange_end",
"udprange_start : PORTNUMBER",
"udprange_end : PORTNUMBER",
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
#line 1267 "config_parse.y"

#define INTERACTIVE      0

extern FILE *yyin;

int socks_parseinit;

int
readconfig(filename)
   const char *filename;
{
   const char *function = "readconfig()";
   struct stat statbuf;

#if SOCKS_CLIENT
   char *proxyserver, *p;
#endif

/*   yydebug          = 1;             */
   yylineno        = 1;
   socks_parseinit = 0;

#if SOCKS_CLIENT
   if (!issetugid() 
	&&   ((proxyserver = getenv("SOCKS4_SERVER")) != NULL
     ||  (proxyserver = getenv("SOCKS5_SERVER")) != NULL
     ||  (proxyserver = getenv("HTTP_PROXY"))    != NULL)) {
      char ipstring[INET_ADDRSTRLEN], *portstring;
      struct sockaddr_in saddr;
      struct route_t route;
      struct ruleaddr_t raddr;

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

      strncpy(ipstring, proxyserver, portstring - proxyserver);
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

      if (getenv("SOCKS4_SERVER") != NULL)
         route.gw.state.proxyprotocol.socks_v4 = 1;
      else if (getenv("SOCKS5_SERVER") != NULL)
         route.gw.state.proxyprotocol.socks_v5 = 1;
      else if (getenv("HTTP_PROXY") != NULL)
         route.gw.state.proxyprotocol.http_v1_0 = 1;
		else
			SERRX(0);

      socks_addroute(&route, 1);
   }
   else if (!issetugid() && (proxyserver = getenv("UPNP_IGD")) != NULL) {
      /*
       * Should be either an interface name (the interface to broadcast
       * for a response from the igd-device), "broadcast", to indicate 
       * all interfaces, or a full url to the igd.
       */
      struct sockaddr_in saddr;
      struct ruleaddr_t raddr;
      struct route_t route;

      memset(&route, 0, sizeof(route));
      route.src.atype                 = SOCKS_ADDR_IPV4;
      route.src.addr.ipv4.ip.s_addr   = htonl(0);
      route.src.addr.ipv4.mask.s_addr = htonl(0);
      route.src.port.tcp              = route.src.port.udp = htons(0);
      route.src.operator              = none;

      /*
       * url or interface to broadcast for a response for?
       */
      if (strncasecmp(proxyserver, "http://", strlen("http://")) == 0) {
         if (urlstring2sockaddr(proxyserver, (struct sockaddr *)&saddr)
         == NULL)
            serrx(EXIT_FAILURE, "can't convert %s to sockaddr", proxyserver);

         sockaddr2ruleaddr((struct sockaddr *)&saddr, &route.dst);

         ruleaddr2gwaddr(sockaddr2ruleaddr((struct sockaddr *)&saddr, &raddr),
         &route.gw.addr);

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

         route.dst                           = route.src;
         route.gw.addr.atype                 = SOCKS_ADDR_IFNAME;
         route.gw.state.proxyprotocol.upnp = 1;

         if (getifaddrs(&ifap) == -1)
            serr(EXIT_FAILURE, "%s: getifaddrs() failed to get interfacelist", 
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
               serr(1, "%s: ifname %s is too long, max is %ld",
               function, iface->ifa_name,
               sizeof(route.gw.addr.addr.ifname) - 1);
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

         route.dst = route.src;

         route.gw.addr.atype = SOCKS_ADDR_IFNAME;

         if (strlen(proxyserver) > sizeof(route.gw.addr.addr.ifname) - 1)
            serr(1, "%s: ifname %s is too long, max is %ld",
            function, proxyserver, sizeof(route.gw.addr.addr.ifname) - 1);
         strcpy(route.gw.addr.addr.ifname, proxyserver);
         
         route.gw.state.proxyprotocol.upnp = 1;
         socks_addroute(&route, 1);
      }
   }

   if (issetugid()
   || (p = getenv("SOCKS_AUTOADD_LANROUTES")) == NULL
   ||  strcasecmp(p, "no") != 0) {
      /*
       * assume it's good to add direct routes for the lan also.
       */
      struct ifaddrs *ifap;

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
#endif /* SOCKS_CLIENT */

   if ((yyin = fopen(filename, "r")) == NULL 
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         swarn("%s: could not open %s", function, filename);

      sockscf.option.debug = 1;  
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



#if SOCKS_SERVER
static void
ruleinit(rule)
   struct rule_t *rule;
{
   rule->linenumber = yylineno;

   command       = &rule->state.command;
   methodv       = rule->state.methodv;
   methodc       = &rule->state.methodc;
   protocol      = &rule->state.protocol;
   proxyprotocol = &rule->state.proxyprotocol;

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
#line 1304 "config_parse.c"
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
#line 288 "config_parse.y"
{
#if SOCKS_SERVER
      protocol         = &protocolmem;
      extension      = &sockscf.extension;
#endif
   }
break;
case 4:
#line 297 "config_parse.y"
{ yyval.string = NULL; }
break;
case 10:
#line 305 "config_parse.y"
{ yyval.string = NULL; }
break;
case 14:
#line 312 "config_parse.y"
{
   }
break;
case 33:
#line 341 "config_parse.y"
{
      yywarn("given keyword is deprecated");
   }
break;
case 34:
#line 345 "config_parse.y"
{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;
      route.gw.state  = state;

      socks_addroute(&route, 1);
   }
break;
case 35:
#line 355 "config_parse.y"
{
      command       = &state.command;
      extension     = &state.extension;
      methodv       = state.methodv;
      methodc       = &state.methodc;
      protocol      = &state.protocol;
      proxyprotocol = &state.proxyprotocol;

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
#line 377 "config_parse.y"
{
         proxyprotocol->socks_v4    = 1;
   }
break;
case 38:
#line 380 "config_parse.y"
{
         proxyprotocol->socks_v5    = 1;
   }
break;
case 39:
#line 383 "config_parse.y"
{
         proxyprotocol->msproxy_v2  = 1;
   }
break;
case 40:
#line 386 "config_parse.y"
{
         proxyprotocol->http_v1_0   = 1;
   }
break;
case 41:
#line 389 "config_parse.y"
{
         proxyprotocol->upnp        = 1;
   }
break;
case 46:
#line 402 "config_parse.y"
{
#if SOCKS_SERVER
      if (adduser(&rule.user, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER */
   }
break;
case 50:
#line 417 "config_parse.y"
{
#if SOCKS_SERVER
      if (addgroup(&rule.group, yyvsp[0].string) == NULL)
         yyerror(NOMEM);
#endif /* SOCKS_SERVER */
   }
break;
case 54:
#line 432 "config_parse.y"
{
         extension->bind = 1;
   }
break;
case 57:
#line 442 "config_parse.y"
{
#if SOCKS_SERVER
      addinternal(ruleaddr);
#endif
   }
break;
case 58:
#line 449 "config_parse.y"
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
#line 465 "config_parse.y"
{
#if SOCKS_SERVER
      addexternal(ruleaddr);
#endif
   }
break;
case 60:
#line 472 "config_parse.y"
{
#if SOCKS_SERVER
      static struct ruleaddr_t mem;

      addrinit(&mem);
#endif
   }
break;
case 61:
#line 481 "config_parse.y"
{
#if SOCKS_SERVER
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 62:
#line 485 "config_parse.y"
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
#line 503 "config_parse.y"
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
      else { /* filename. */
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
            else {
               if ((sockscf.log.fpv[sockscf.log.fpc] = fopen(yyvsp[0].string, "a")) == NULL)
                  yyerror("fopen(%s)", yyvsp[0].string);

               if (setvbuf(sockscf.log.fpv[sockscf.log.fpc], NULL, _IOLBF, 0)
               != 0)
                  yyerror("setvbuf(_IOLBF)");
            }

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
               if (strcmp(sockscf.log.fnamev[i], yyvsp[0].string) == 0) {
                  /* same name; reopen. */
                  FILE *fp;

                  if (strcmp(sockscf.log.fnamev[i], "stdout") == 0
                  ||  strcmp(sockscf.log.fnamev[i], "stderr") == 0)
                     break; /* don't try to reopen these. */

                  if ((fp = fopen(sockscf.log.fnamev[i], "a")) == NULL)
                     yywarn("can't reopen %s, continuing to use existing", yyvsp[0].string);
                  else {
                     fclose(sockscf.log.fpv[i]);
                     sockscf.log.fpv[i] = fp;

                     if (setvbuf(sockscf.log.fpv[i], NULL, _IOLBF, 0) != 0)
                        yyerror("setvbuf(_IOLBF)");
                  }
                  break;
               }

            if (i == sockscf.log.fpc) /* no match found. */
               yywarn("can't change logoutput after startup");
         }

      }
   }
break;
case 70:
#line 614 "config_parse.y"
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
#line 631 "config_parse.y"
{
#if SOCKS_SERVER
      sockscf.uid.privileged         = yyvsp[0].uid;
      sockscf.uid.privileged_isset   = 1;
#endif
   }
break;
case 75:
#line 639 "config_parse.y"
{
#if SOCKS_SERVER
      sockscf.uid.unprivileged         = yyvsp[0].uid;
      sockscf.uid.unprivileged_isset   = 1;
#endif
   }
break;
case 76:
#line 647 "config_parse.y"
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
#line 658 "config_parse.y"
{
      struct passwd *pw;

      if ((pw = getpwnam(yyvsp[0].string)) == NULL)
         serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
      else
         yyval.uid = pw->pw_uid;
   }
break;
case 78:
#line 668 "config_parse.y"
{
#if SOCKS_SERVER
      sockscf.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
   }
break;
case 79:
#line 675 "config_parse.y"
{
#if SOCKS_SERVER
      sockscf.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
   }
break;
case 80:
#line 682 "config_parse.y"
{
      sockscf.option.debug = atoi(yyvsp[0].string);
   }
break;
case 82:
#line 690 "config_parse.y"
{
#if SOCKS_SERVER
      sockscf.compat.reuseaddr = 1;
   }
break;
case 83:
#line 694 "config_parse.y"
{
      sockscf.compat.sameport = 1;
#endif
   }
break;
case 87:
#line 707 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 88:
#line 710 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
         yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 89:
#line 717 "config_parse.y"
{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 91:
#line 725 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
         sockscf.srchost.nomismatch = 1;
   }
break;
case 92:
#line 729 "config_parse.y"
{
         sockscf.srchost.nounknown = 1;
#else
      yyerror("srchostoption requires libwrap");
#endif
   }
break;
case 96:
#line 745 "config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.methodv;
   methodc = &sockscf.methodc;
   *methodc = 0; /* reset. */
#endif
   }
break;
case 98:
#line 754 "config_parse.y"
{
#if SOCKS_SERVER
   methodv = sockscf.clientmethodv;
   methodc = &sockscf.clientmethodc;
   *methodc = 0; /* reset. */
#endif
   }
break;
case 100:
#line 763 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_NONE);
   }
break;
case 101:
#line 766 "config_parse.y"
{
      yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
   }
break;
case 102:
#line 769 "config_parse.y"
{
      ADDMETHOD(AUTHMETHOD_UNAME);
   }
break;
case 103:
#line 772 "config_parse.y"
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
#line 783 "config_parse.y"
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
#line 803 "config_parse.y"
{
#if SOCKS_SERVER
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

      addclientrule(&rule);

#endif
   }
break;
case 109:
#line 819 "config_parse.y"
{ yyval.string = NULL; }
break;
case 111:
#line 823 "config_parse.y"
{
#if SOCKS_SERVER
      rule.src         = src;
      rule.dst         = dst;
      rule.rdr_from    = rdr_from;
      rule.rdr_to      = rdr_to;

      addsocksrule(&rule);
#endif
   }
break;
case 113:
#line 837 "config_parse.y"
{
#if SOCKS_SERVER
         checkmodule("bandwidth");
#endif
   }
break;
case 118:
#line 846 "config_parse.y"
{
#if SOCKS_SERVER
         checkmodule("redirect");
#endif
   }
break;
case 119:
#line 853 "config_parse.y"
{ yyval.string = NULL; }
break;
case 127:
#line 863 "config_parse.y"
{
#if SOCKS_SERVER
         checkmodule("session");
#endif
   }
break;
case 128:
#line 870 "config_parse.y"
{
#if SOCKS_SERVER
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 129:
#line 875 "config_parse.y"
{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif
   }
break;
case 131:
#line 886 "config_parse.y"
{
         command->bind = 1;
   }
break;
case 132:
#line 889 "config_parse.y"
{
         command->connect = 1;
   }
break;
case 133:
#line 892 "config_parse.y"
{
         command->udpassociate = 1;
   }
break;
case 134:
#line 898 "config_parse.y"
{
         command->bindreply = 1;
   }
break;
case 135:
#line 902 "config_parse.y"
{
         command->udpreply = 1;
   }
break;
case 139:
#line 914 "config_parse.y"
{
      protocol->tcp = 1;
   }
break;
case 140:
#line 917 "config_parse.y"
{
      protocol->udp = 1;
   }
break;
case 147:
#line 937 "config_parse.y"
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
case 148:
#line 954 "config_parse.y"
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
case 150:
#line 975 "config_parse.y"
{
#if SOCKS_SERVER
   rule.log.connect = 1;
   }
break;
case 151:
#line 979 "config_parse.y"
{
         rule.log.data = 1;
   }
break;
case 152:
#line 982 "config_parse.y"
{
         rule.log.disconnect = 1;
   }
break;
case 153:
#line 985 "config_parse.y"
{
         rule.log.error = 1;
   }
break;
case 154:
#line 988 "config_parse.y"
{
         rule.log.iooperation = 1;
#endif
   }
break;
case 157:
#line 999 "config_parse.y"
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
case 158:
#line 1010 "config_parse.y"
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
case 169:
#line 1060 "config_parse.y"
{ yyval.string = NULL; }
break;
case 171:
#line 1064 "config_parse.y"
{
      addrinit(&src);
   }
break;
case 172:
#line 1069 "config_parse.y"
{
      addrinit(&dst);
   }
break;
case 173:
#line 1074 "config_parse.y"
{
      addrinit(&rdr_from);
   }
break;
case 174:
#line 1079 "config_parse.y"
{
      addrinit(&rdr_to);
   }
break;
case 175:
#line 1086 "config_parse.y"
{
      gwaddrinit(&gw);
   }
break;
case 190:
#line 1116 "config_parse.y"
{
      *atype = SOCKS_ADDR_IPV4;

      if (inet_aton(yyvsp[0].string, ipaddr) != 1)
         yyerror("bad address: %s", yyvsp[0].string);
   }
break;
case 191:
#line 1125 "config_parse.y"
{
      if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
         yyerror("bad netmask: %s", yyvsp[0].string);

      netmask->s_addr
      = atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
   }
break;
case 192:
#line 1132 "config_parse.y"
{
         if (!inet_aton(yyvsp[0].string, netmask))
            yyerror("bad netmask: %s", yyvsp[0].string);
   }
break;
case 193:
#line 1138 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domainname too long");
      strcpy(domain, yyvsp[0].string);
   }
break;
case 194:
#line 1147 "config_parse.y"
{
      *atype = SOCKS_ADDR_IFNAME;

      if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
         yyerror("interfacename too long");
      strcpy(ifname, yyvsp[0].string);
   }
break;
case 195:
#line 1157 "config_parse.y"
{
      *atype = SOCKS_ADDR_DOMAIN;

      if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
         yyerror("domain name \"%s\" too long", yyvsp[0].string);
      strcpy(domain, yyvsp[0].string);

      proxyprotocol->direct = 1;
   }
break;
case 196:
#line 1168 "config_parse.y"
{
      *atype = SOCKS_ADDR_URL;

      if (strlen(yyvsp[0].string) >= MAXURLLEN)
         yyerror("url \"%s\" too long", yyvsp[0].string);
      strcpy(url, yyvsp[0].string);
   }
break;
case 197:
#line 1178 "config_parse.y"
{ yyval.string = NULL; }
break;
case 200:
#line 1183 "config_parse.y"
{ yyval.string = NULL; }
break;
case 205:
#line 1195 "config_parse.y"
{
      *port_tcp   = htons((in_port_t)atoi(yyvsp[0].string));
      *port_udp   = htons((in_port_t)atoi(yyvsp[0].string));
   }
break;
case 206:
#line 1201 "config_parse.y"
{
      ruleaddr->portend    = htons((in_port_t)atoi(yyvsp[0].string));
      ruleaddr->operator   = range;
   }
break;
case 207:
#line 1207 "config_parse.y"
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
case 208:
#line 1238 "config_parse.y"
{
      *operator = string2operator(yyvsp[0].string);
   }
break;
case 210:
#line 1246 "config_parse.y"
{
#if SOCKS_SERVER
   rule.udprange.start = htons((in_port_t)atoi(yyvsp[0].string));
#endif
   }
break;
case 211:
#line 1253 "config_parse.y"
{
#if SOCKS_SERVER
   rule.udprange.end = htons((in_port_t)atoi(yyvsp[0].string));
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerror("udp end port (%s) can not be less than udp start port (%u)",
      yyvsp[0].string, ntohs(rule.udprange.start));
#endif
   }
break;
#line 2387 "config_parse.c"
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
