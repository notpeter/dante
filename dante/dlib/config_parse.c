#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ == 2
  __attribute__ ((unused))
#endif /* __GNUC__ == 2 */
  = "$OpenBSD: skeleton.c,v 1.15 2000/01/27 21:34:23 deraadt Exp $";
#endif
#include <stdlib.h>
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
"$Id: config_parse.y,v 1.140 2001/02/06 15:58:52 michaels Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

#if SOCKS_SERVER
static void
ruleinit __P((const struct rule_t *rule));
#endif

__END_DECLS

extern int yylineno;
extern char *yytext;

#if SOCKS_SERVER
static struct rule_t				ruleinitmem;
static struct rule_t				rule;				/* new rule.							*/
static struct protocol_t		protocolmem;	/* new protocolmem.					*/
struct linkedname_t				**userbase;		/* users rule applies to.			*/
#endif

#if SOCKS_CLIENT
static struct serverstate_t	state;
static struct route_t			route;			/* new route.							*/
static struct ruleaddress_t	gw;				/* new gateway.						*/
#endif


static struct ruleaddress_t	src;				/* new src.								*/
static struct ruleaddress_t	dst;				/* new dst.								*/
static struct ruleaddress_t	*ruleaddress;	/* current ruleaddress				*/
static struct extension_t		*extension;		/* new extensions						*/
static struct proxyprotocol_t	*proxyprotocol;/* proxy protocol.					*/

static char							*atype;			/* atype of new address.			*/
static struct in_addr			*ipaddr;			/* new ipaddress						*/
static struct in_addr			*netmask;		/* new netmask							*/
static char							*domain;			/* new domain.							*/
static char							*ifname;			/* new ifname.							*/

static in_port_t					*port_tcp;		/* new TCP portnumber.				*/
static in_port_t					*port_udp;		/* new UDP portnumber.				*/
static int							*methodv;		/* new authmethods.					*/
static int							*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/

static const struct {
	const char *name;
	const int value;
} syslogfacility[] = {
#ifdef LOG_AUTH
	{ "auth",	LOG_AUTH		},
#endif /* LOG_AUTH */
#ifdef LOG_AUTHPRIV
	{ "authpriv",	LOG_AUTHPRIV		},
#endif /* LOG_AUTHPRIV */
#ifdef LOG_DAEMON
	{ "daemon",	LOG_DAEMON	},
#endif /* LOG_DAEMON */
#ifdef LOG_USER
	{ "user",	LOG_USER		},
#endif /* LOG_USER */
#ifdef LOG_LOCAL0
	{ "local0",	LOG_LOCAL0	},
#endif /* LOG_LOCAL0 */
#ifdef LOG_LOCAL1
	{ "local1",	LOG_LOCAL1	},
#endif /* LOG_LOCAL1 */
#ifdef LOG_LOCAL2
	{ "local2",	LOG_LOCAL2	},
#endif /* LOG_LOCAL2 */
#ifdef LOG_LOCAL3
	{ "local3",	LOG_LOCAL3	},
#endif /* LOG_LOCAL3 */
#ifdef LOG_LOCAL4
	{ "local4",	LOG_LOCAL4	},
#endif /* LOG_LOCAL4 */
#ifdef LOG_LOCAL5
	{ "local5",	LOG_LOCAL5	},
#endif /* LOG_LOCAL5 */
#ifdef LOG_LOCAL6
	{ "local6",	LOG_LOCAL6	},
#endif /* LOG_LOCAL6 */
#ifdef LOG_LOCAL7
	{ "local7",	LOG_LOCAL7	}
#endif /* LOG_LOCAL7 */
};


#define YYDEBUG 1

#define ADDMETHOD(method) \
	do { \
		if (*methodc >= AUTHMETHOD_MAX)	\
			yyerror("internal error or duplicate methods given");	\
		methodv[(*methodc)++] = method; \
	} while (0)

#line 160 "config_parse.y"
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#line 165 "y.tab.c"
#define SERVERCONFIG 257
#define CLIENTCONFIG 258
#define DEPRECATED 259
#define CLIENTRULE 260
#define INTERNAL 261
#define EXTERNAL 262
#define DEBUGING 263
#define RESOLVEPROTOCOL 264
#define SRCHOST 265
#define NOMISMATCH 266
#define NOUNKNOWN 267
#define EXTENSION 268
#define BIND 269
#define PRIVILEGED 270
#define IOTIMEOUT 271
#define CONNECTTIMEOUT 272
#define METHOD 273
#define NONE 274
#define GSSAPI 275
#define UNAME 276
#define RFC931 277
#define COMPATIBILITY 278
#define REUSEADDR 279
#define SAMEPORT 280
#define USERNAME 281
#define USER_PRIVILEGED 282
#define USER_UNPRIVILEGED 283
#define USER_LIBWRAP 284
#define LOGOUTPUT 285
#define LOGFILE 286
#define ROUTE 287
#define VIA 288
#define VERDICT_BLOCK 289
#define VERDICT_PASS 290
#define PROTOCOL 291
#define PROTOCOL_TCP 292
#define PROTOCOL_UDP 293
#define PROTOCOL_FAKE 294
#define PROXYPROTOCOL 295
#define PROXYPROTOCOL_SOCKS_V4 296
#define PROXYPROTOCOL_SOCKS_V5 297
#define PROXYPROTOCOL_MSPROXY_V2 298
#define PROXYPROTOCOL_HTTP_V1_0 299
#define USER 300
#define COMMAND 301
#define COMMAND_BIND 302
#define COMMAND_CONNECT 303
#define COMMAND_UDPASSOCIATE 304
#define COMMAND_BINDREPLY 305
#define COMMAND_UDPREPLY 306
#define ACTION 307
#define LINE 308
#define LIBWRAPSTART 309
#define OPERATOR 310
#define LOG 311
#define LOG_CONNECT 312
#define LOG_DATA 313
#define LOG_DISCONNECT 314
#define LOG_ERROR 315
#define LOG_IOOPERATION 316
#define IPADDRESS 317
#define DOMAIN 318
#define DIRECT 319
#define IFNAME 320
#define PORT 321
#define PORTNUMBER 322
#define SERVICENAME 323
#define NUMBER 324
#define FROM 325
#define TO 326
#define YYERRCODE 256
short socks_yylhs[] = {                                        -1,
    0,    0,   45,    1,    1,    1,    1,    1,    2,    2,
    2,    2,   22,   23,   23,   46,   46,   46,   46,   46,
   46,   46,   44,   44,   44,   44,   44,   44,    3,   52,
   21,    7,    8,    8,    8,    8,    9,    9,   10,   11,
   12,   12,   28,   29,   30,   30,   31,   32,   78,   78,
   33,   34,   77,   77,   24,   24,   24,   35,   36,   37,
   37,   47,   47,   47,   48,   49,   50,   51,   26,   27,
   25,   38,   39,   39,   40,   40,   13,   14,   14,   14,
   15,   16,   16,   17,   17,   88,   41,   43,   43,   43,
   43,   42,   42,   60,   61,   61,   61,   61,   62,   62,
   57,   58,   58,   58,   58,   58,   58,   58,   59,   59,
   63,   63,   18,   20,   20,   20,   20,   20,   19,   19,
    4,    6,    6,    5,    5,   64,   65,   67,   67,   67,
   67,   67,   66,   66,   68,   69,   70,   54,   55,   55,
   55,   55,   55,   56,   56,   79,   80,   53,   71,   71,
   73,   73,   73,   72,   81,   81,   74,   75,   76,   82,
   82,   82,   86,   86,   83,   84,   89,   87,   85,
};
short socks_yylen[] = {                                         2,
    2,    2,    1,    0,    2,    2,    2,    2,    0,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    8,
    0,    3,    1,    1,    1,    1,    1,    2,    3,    1,
    1,    2,    3,    1,    1,    2,    4,    0,    2,    2,
    4,    0,    1,    1,    1,    1,    1,    3,    1,    1,
    2,    1,    1,    1,    3,    3,    3,    1,    3,    3,
    3,    3,    1,    1,    1,    2,    3,    1,    1,    1,
    3,    1,    1,    1,    2,    0,    4,    1,    1,    1,
    1,    1,    2,    7,    1,    1,    1,    1,    0,    2,
    6,    1,    1,    1,    1,    1,    1,    1,    0,    2,
    1,    1,    3,    1,    1,    1,    1,    1,    1,    2,
    3,    1,    1,    1,    2,    2,    3,    1,    1,    1,
    1,    1,    1,    2,    3,    3,    3,    3,    1,    1,
    1,    1,    1,    0,    2,    1,    1,    1,    4,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    0,
    3,    2,    1,    1,    3,    1,    1,    1,    1,
};
short socks_yydefred[] = {                                      0,
    3,   13,    0,    9,    4,    0,    0,   29,    0,    0,
    0,   31,   10,   15,   57,   11,   14,   56,   55,   12,
    0,   48,   52,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  111,  112,    5,   17,   27,   28,   26,   24,
   25,   18,   19,   20,   23,   16,   21,    6,   22,   62,
   63,   64,    8,    7,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   86,    0,    0,    0,
    0,    0,   71,   79,   80,   78,   77,   59,    0,   58,
    0,    0,    0,    0,   82,   83,    0,   81,   44,    0,
   43,   69,   70,    0,   73,   74,    0,   72,   68,   65,
   66,   67,    0,    0,    0,    0,    0,    0,  106,  107,
  108,  103,  102,    0,    0,  105,  104,   61,  141,  142,
  139,  140,  143,    0,    0,   98,   95,    0,    0,   97,
   96,  154,  158,    0,    0,   47,   53,   54,   51,   85,
   46,   88,   89,   90,   91,   87,    0,   76,    0,    0,
    0,    0,    0,    0,  110,  146,    0,    0,    0,  145,
    0,  100,    0,    0,   49,   50,   93,  122,  123,  121,
    0,   33,   34,   35,   36,    0,   32,   40,    0,   39,
  114,  115,  116,  117,  118,  113,    0,  135,  128,  129,
  130,  131,  132,  127,    0,    0,  147,  126,    0,    0,
  148,    0,    0,    0,  169,  166,  162,    0,    0,  125,
   38,   42,  120,  134,  101,    0,  157,  136,    0,    0,
    0,    0,   94,    0,  168,  164,  161,  163,  137,    0,
  150,  159,    0,  138,    0,  153,   30,  167,  165,  156,
  155,    0,  151,  152,  149,
};
short socks_yydgoto[] = {                                       3,
    7,    6,   14,  109,  170,  171,  110,  176,  177,  111,
  179,  180,   15,   77,   38,   87,   88,  112,  186,  187,
   59,    4,   16,   17,   18,   39,   40,  122,   90,   91,
   42,   61,   43,   62,   19,   79,   80,   45,   97,   98,
  113,  146,  147,   47,    5,   48,   49,   50,   51,   52,
  100,   20,  202,  203,  124,  125,   53,  114,  115,   54,
  128,  129,   55,  157,  116,  194,  195,  117,  158,  198,
  218,  219,  234,  220,  135,  236,  139,  136,  159,  199,
  242,  165,  207,  208,  209,  227,  228,   94,  239,
};
short socks_yysindex[] = {                                   -227,
    0,    0,    0,    0,    0,  -10,  228,    0,  -34,  -32,
   -4,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -241,    0,    0,    7,   12,   32,   40,   43,   49,   51,
   62,   63,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   -1, -200, -197, -159,    5,    6,
   72,   73, -182, -136, -189, -185,    0, -192, -141, -141,
 -141, -248,    0,    0,    0,    0,    0,    0, -159,    0,
 -223, -240, -234, -234,    0,    0, -182,    0,    0, -136,
    0,    0,    0, -235,    0,    0, -192,    0,    0,    0,
    0,    0,   83,   85,   87,   88,   89,   90,    0,    0,
    0,    0,    0, -248, -176,    0,    0,    0,    0,    0,
    0,    0,    0, -223, -176,    0,    0, -240, -176,    0,
    0,    0,    0, -170, -170,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -235,    0, -181, -217,
 -128, -268, -154, -239,    0,    0, -248, -171,   98,    0,
 -130,    0, -240, -294,    0,    0,    0,    0,    0,    0,
 -181,    0,    0,    0,    0, -217,    0,    0, -128,    0,
    0,    0,    0,    0,    0,    0, -268,    0,    0,    0,
    0,    0,    0,    0, -239,   34,    0,    0,  102, -204,
    0,  103, -223,   37,    0,    0,    0,  118, -206,    0,
    0,    0,    0,    0,    0, -204,    0,    0,  119, -170,
 -214,   42,    0, -153,    0,    0,    0,    0,    0, -295,
    0,    0, -170,    0, -170,    0,    0,    0,    0,    0,
    0, -170,    0,    0,    0,
};
short socks_yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,  170,  171,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -149,    0,    0,    0,    0,    0,    0,  100,    0,
 -142, -135,    0,    0,    0,    0,  132,    0,    0,   56,
    0,    0,    0,    0,    0,    0,  164,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -121,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -120,    0,    0,    0, -113,    0,    0,
    0,    0,    0,  196,  196,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    1,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   64,    0,    0,    0,
    0,    0,   66,    0,    0,    0,    0,    0,    0,    0,
 -116,    0,    0,    0,    0,  -81,    0,    0,  -93,    0,
    0,    0,    0,    0,    0,    0,  -74,    0,    0,    0,
    0,    0,    0,    0,   -2,    0,    0,    0,    0,    0,
    0,    0,   75,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -123,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   57,    0,   57,    0,    0,    0,    0,    0,
    0, -123,    0,    0,    0,
};
short socks_yygindex[] = {                                      0,
    0,    0,  190,  -78,   30,    0,  -67,    0,   35,  -69,
    0,   36,  215,    0,    0,    0,  136,  -66,   38,    0,
    0,    0,    0,    0,    0,    0,    0,  217,    0,  139,
    0,    0,    0,    0,  224,    0,  154,    0,    0,  137,
   10,   92,    0,    0,    0,    0,    0,    0,    0,    0,
   48,    0,    0,    0,    0, -114,    0,    0,  -95,    0,
    0, -108,  219, -102,  -64,   41,    0,  -61,    0,    0,
   25,  -77,    0,   21,  159,    0,    0,    0,    0,    0,
    0, -127,    0,   39,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 518
short socks_yytable[] = {                                      13,
   92,  160,  119,  109,  144,  134,  137,  166,  124,  160,
   92,   99,  126,  120,  121,  205,   46,  130,  155,  162,
  131,  240,  161,   56,   28,   57,  163,  206,  241,    1,
    2,   41,   28,  181,  182,  183,  184,  185,  142,  143,
  144,  145,  103,   37,   25,  119,  104,   33,   34,   28,
  119,  105,  106,   58,  204,   45,  120,  121,  126,  105,
  107,  196,  108,  130,   63,   45,  131,  103,  107,   64,
  108,  104,  189,  190,  191,  192,  193,  106,  172,  173,
  174,  175,  132,   85,   86,  133,   95,   96,  222,   65,
  123,  127,  231,  126,   74,   75,   76,   66,  130,   60,
   67,  131,  132,  217,  232,  243,   68,  244,   69,   60,
  168,  169,  132,  217,  245,  206,  225,  101,  102,   70,
   71,   72,  133,   73,  119,   92,   78,   81,   82,   83,
   84,   84,   89,  123,   92,  120,  121,  127,   93,   99,
  149,   84,  150,  233,  151,  152,  153,  154,  156,  160,
  164,  124,  178,  188,  197,  200,  124,  201,  215,  216,
  221,  223,  224,   75,  160,  230,  237,  160,  238,    2,
    1,  160,  127,   75,  124,  109,  160,  160,  124,   41,
   45,  160,  144,  124,  124,  160,   37,  160,  109,   99,
   99,   37,  124,  119,  124,  160,   36,   41,  119,  144,
  210,   41,  160,  109,  144,  160,   41,   41,  124,   37,
  211,   99,  123,   37,  212,   41,  119,   41,   37,   37,
  119,   37,  140,   41,  213,  119,  119,   37,  141,   37,
   44,   41,  118,  148,  119,  214,  119,   35,  167,   60,
  229,  235,  138,   37,    0,    0,    0,  226,    8,    0,
  119,    0,    9,   10,    0,    0,    0,    0,    0,   92,
   92,   92,   92,    0,   92,   92,    0,    0,   92,    0,
  133,   92,   92,   92,   11,    0,   12,    0,   92,    0,
    0,    0,   92,   92,   92,   92,    0,    0,  133,   92,
   92,   92,  133,    0,    0,   92,    0,  133,  133,    0,
   92,   92,    0,    0,    0,    0,  133,    0,  133,   92,
    0,   92,    0,    0,   45,   45,   45,   45,    0,   45,
   45,    0,  133,   45,  160,   92,   45,   45,   45,  160,
    0,    0,    0,   45,    0,    0,    0,   45,   45,   45,
   45,    0,    0,    0,   45,   45,   45,  160,    0,    0,
   45,  160,    0,    0,    0,    0,   45,  160,   60,   60,
   60,   60,   60,   60,   60,    0,    0,   60,    0,    0,
   60,   60,   60,    0,    0,    0,    0,   60,    0,    0,
   45,   60,   60,   60,   60,    0,   60,    0,   60,   60,
   84,   84,   84,   84,    0,   84,   84,    0,    0,   84,
    0,    0,   84,   84,   84,    0,    0,    0,    0,   84,
    0,    0,    0,   84,   84,   84,   84,    0,    0,    0,
   84,   84,   75,   75,   75,   75,    0,   75,   75,    0,
    0,   75,    0,    0,   75,   75,   75,    0,    0,    0,
    0,   75,    0,    0,    0,   75,   75,   75,   75,    0,
    0,    0,   75,   75,  160,  160,  160,  160,    0,  160,
  160,    0,    0,  160,    0,    0,  160,  160,  160,    0,
    0,    0,    0,  160,    0,    0,    0,  160,  160,  160,
  160,    0,    0,    0,  160,  160,    8,   21,   22,   23,
    0,   10,   24,    0,    0,   25,    0,    0,   26,   27,
   28,    0,    0,    0,    0,   29,    0,    0,    0,   30,
   31,   32,   11,    0,    0,    0,   33,   34,
};
short socks_yycheck[] = {                                      10,
    0,  125,   81,  125,  125,   83,   84,  135,  125,  124,
   10,  125,   82,   81,   81,  310,    7,   82,  114,  128,
   82,  317,  125,   58,  273,   58,  129,  322,  324,  257,
  258,  125,  273,  302,  303,  304,  305,  306,  274,  275,
  276,  277,  291,  125,  268,  124,  295,  289,  290,  273,
  125,  300,  301,   58,  163,    0,  124,  124,  128,  300,
  309,  157,  311,  128,   58,   10,  128,  291,  309,   58,
  311,  295,  312,  313,  314,  315,  316,  301,  296,  297,
  298,  299,  317,  266,  267,  320,  279,  280,  203,   58,
   81,   82,  220,  163,  292,  293,  294,   58,  163,    0,
   58,  163,  317,  318,  319,  233,   58,  235,   58,   10,
  292,  293,  317,  318,  242,  322,  323,   70,   71,   58,
   58,  123,  125,  324,  203,  125,  286,  123,  123,   58,
   58,    0,  269,  124,  324,  203,  203,  128,  324,  281,
   58,   10,   58,  221,   58,   58,   58,   58,  325,  273,
  321,  268,  281,  308,  326,   58,  273,  288,  125,   58,
   58,  125,   45,    0,  288,   47,  125,  291,  322,    0,
    0,  295,  163,   10,  291,  325,  300,  301,  295,  273,
  125,  125,  325,  300,  301,  309,  268,  311,  125,  325,
  125,  273,  309,  268,  311,    0,    7,  291,  273,  125,
  171,  295,  326,  325,  325,   10,  300,  301,  325,  291,
  176,  325,  203,  295,  179,  309,  291,  311,  300,  301,
  295,    7,   87,    7,  187,  300,  301,  309,   90,  311,
    7,  325,   79,   97,  309,  195,  311,   10,  147,   21,
  216,  221,   84,  325,   -1,   -1,   -1,  209,  259,   -1,
  325,   -1,  263,  264,   -1,   -1,   -1,   -1,   -1,  259,
  260,  261,  262,   -1,  264,  265,   -1,   -1,  268,   -1,
  273,  271,  272,  273,  285,   -1,  287,   -1,  278,   -1,
   -1,   -1,  282,  283,  284,  285,   -1,   -1,  291,  289,
  290,  291,  295,   -1,   -1,  295,   -1,  300,  301,   -1,
  300,  301,   -1,   -1,   -1,   -1,  309,   -1,  311,  309,
   -1,  311,   -1,   -1,  259,  260,  261,  262,   -1,  264,
  265,   -1,  325,  268,  268,  325,  271,  272,  273,  273,
   -1,   -1,   -1,  278,   -1,   -1,   -1,  282,  283,  284,
  285,   -1,   -1,   -1,  289,  290,  291,  291,   -1,   -1,
  295,  295,   -1,   -1,   -1,   -1,  301,  301,  259,  260,
  261,  262,  263,  264,  265,   -1,   -1,  268,   -1,   -1,
  271,  272,  273,   -1,   -1,   -1,   -1,  278,   -1,   -1,
  325,  282,  283,  284,  285,   -1,  287,   -1,  289,  290,
  259,  260,  261,  262,   -1,  264,  265,   -1,   -1,  268,
   -1,   -1,  271,  272,  273,   -1,   -1,   -1,   -1,  278,
   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,   -1,
  289,  290,  259,  260,  261,  262,   -1,  264,  265,   -1,
   -1,  268,   -1,   -1,  271,  272,  273,   -1,   -1,   -1,
   -1,  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,
   -1,   -1,  289,  290,  259,  260,  261,  262,   -1,  264,
  265,   -1,   -1,  268,   -1,   -1,  271,  272,  273,   -1,
   -1,   -1,   -1,  278,   -1,   -1,   -1,  282,  283,  284,
  285,   -1,   -1,   -1,  289,  290,  259,  260,  261,  262,
   -1,  264,  265,   -1,   -1,  268,   -1,   -1,  271,  272,
  273,   -1,   -1,   -1,   -1,  278,   -1,   -1,   -1,  282,
  283,  284,  285,   -1,   -1,   -1,  289,  290,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 326
#if YYDEBUG
char *socks_yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'-'",0,"'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"SERVERCONFIG","CLIENTCONFIG","DEPRECATED","CLIENTRULE","INTERNAL","EXTERNAL",
"DEBUGING","RESOLVEPROTOCOL","SRCHOST","NOMISMATCH","NOUNKNOWN","EXTENSION",
"BIND","PRIVILEGED","IOTIMEOUT","CONNECTTIMEOUT","METHOD","NONE","GSSAPI",
"UNAME","RFC931","COMPATIBILITY","REUSEADDR","SAMEPORT","USERNAME",
"USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","LOGOUTPUT","LOGFILE",
"ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS","PROTOCOL","PROTOCOL_TCP",
"PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4",
"PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2","PROXYPROTOCOL_HTTP_V1_0",
"USER","COMMAND","COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE",
"COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE","LIBWRAPSTART",
"OPERATOR","LOG","LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR",
"LOG_IOOPERATION","IPADDRESS","DOMAIN","DIRECT","IFNAME","PORT","PORTNUMBER",
"SERVICENAME","NUMBER","FROM","TO",
};
char *socks_yyrule[] = {
"$accept : configtype",
"configtype : serverinit serverline",
"configtype : clientinit clientline",
"serverinit : SERVERCONFIG",
"serverline :",
"serverline : serverline '\\n'",
"serverline : serverline serverconfig",
"serverline : serverline clientrule",
"serverline : serverline rule",
"clientline :",
"clientline : clientline '\\n'",
"clientline : clientline clientconfig",
"clientline : clientline route",
"clientinit : CLIENTCONFIG",
"clientconfig : clientoption",
"clientconfig : deprecated",
"serverconfig : authmethod",
"serverconfig : deprecated",
"serverconfig : internal",
"serverconfig : external",
"serverconfig : logoutput",
"serverconfig : serveroption",
"serverconfig : userids",
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
"proxyprotocols : proxyprotocolname",
"proxyprotocols : proxyprotocolname proxyprotocols",
"user : USER ':' usernames",
"username : USERNAME",
"usernames : username",
"usernames : username usernames",
"extension : EXTENSION ':' extensions",
"extensionname : BIND",
"extensions : extensionname",
"extensions : extensionname extensions",
"internal : INTERNAL internalinit ':' internaladdress",
"internalinit :",
"internaladdress : ipaddress port",
"internaladdress : ifname port",
"external : EXTERNAL externalinit ':' externaladdress",
"externalinit :",
"externaladdress : ipaddress",
"externaladdress : ifname",
"clientoption : logoutput",
"clientoption : debuging",
"clientoption : resolveprotocol",
"logoutput : LOGOUTPUT ':' logoutputdevices",
"logoutputdevice : LOGFILE",
"logoutputdevices : logoutputdevice",
"logoutputdevices : logoutputdevice logoutputdevices",
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
"$$1 :",
"authmethod : METHOD ':' $$1 authmethods",
"authmethodname : NONE",
"authmethodname : GSSAPI",
"authmethodname : UNAME",
"authmethodname : RFC931",
"authmethods : authmethodname",
"authmethods : authmethodname authmethods",
"clientrule : CLIENTRULE verdict '{' clientruleoptions fromto clientruleoptions '}'",
"clientruleoption : authmethod",
"clientruleoption : libwrap",
"clientruleoption : log",
"clientruleoption : user",
"clientruleoptions :",
"clientruleoptions : clientruleoption clientruleoptions",
"rule : verdict '{' ruleoptions fromto ruleoptions '}'",
"ruleoption : authmethod",
"ruleoption : command",
"ruleoption : libwrap",
"ruleoption : log",
"ruleoption : protocol",
"ruleoption : proxyprotocol",
"ruleoption : user",
"ruleoptions :",
"ruleoptions : ruleoption ruleoptions",
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
"log : LOG ':' logs",
"logname : LOG_CONNECT",
"logname : LOG_DATA",
"logname : LOG_DISCONNECT",
"logname : LOG_ERROR",
"logname : LOG_IOOPERATION",
"logs : logname",
"logs : logname logs",
"libwrap : LIBWRAPSTART ':' LINE",
"srcaddress : from ':' address",
"dstaddress : to ':' address",
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
"via : VIA",
"address : ipaddress '/' netmask port",
"address : domain port",
"gwaddress : ipaddress port",
"gwaddress : domain port",
"gwaddress : direct",
"ipaddress : IPADDRESS",
"netmask : NUMBER",
"netmask : IPADDRESS",
"domain : DOMAIN",
"ifname : IFNAME",
"direct : DIRECT",
"port :",
"port : PORT portoperator portnumber",
"port : PORT portrange",
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
#line 1020 "config_parse.y"

#define INTERACTIVE		0

#if SOCKS_SERVER
#define ELECTRICFENCE	0
#else
#define ELECTRICFENCE	0
#endif


#if ELECTRICFENCE
	extern int EF_PROTECT_FREE;
	extern int EF_ALLOW_MALLOC_0;
	extern int EF_ALIGNMENT;
	extern int EF_PROTECT_BELOW;
#endif /* ELECTRICFENCE */

extern FILE *yyin;

int parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";
	const int errno_s = errno;

#if ELECTRICFENCE
	EF_PROTECT_FREE         = 1;
	EF_ALLOW_MALLOC_0       = 1;
	EF_ALIGNMENT            = 0;
	EF_PROTECT_BELOW			= 0;
#endif /* ELECTRICFENCE */

/*	yydebug		= 1;        */
	yylineno		= 1;
	parseinit	= 0;

	if ((yyin = fopen(filename, "r")) == NULL) {
		swarn("%s: %s", function, filename);
		return -1;
	}

	yyparse();
	fclose(yyin);

	errno = errno_s; /* yacc for some reason alters errno sometimes. */

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
	config.option.configfile, yylineno,
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
	config.option.configfile, yylineno,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);

	vsnprintf(&buf[bufused], sizeof(buf) - bufused, fmt, ap);

	/* LINTED expression has null effect */
	va_end(ap);

	if (errno)
		swarn(buf);
	swarnx(buf);
}

static void
addressinit(address)
	struct ruleaddress_t *address;
{
		ruleaddress	= address;

		atype			= &ruleaddress->atype;
		ipaddr		= &ruleaddress->addr.ipv4.ip;
		netmask		= &ruleaddress->addr.ipv4.mask;
		domain		= ruleaddress->addr.domain;
		ifname		= ruleaddress->addr.ifname;
		port_tcp		= &ruleaddress->port.tcp;
		port_udp		= &ruleaddress->port.udp;
		operator		= &ruleaddress->operator;
}

#if SOCKS_SERVER
static void
ruleinit(rule)
	const struct rule_t *rule;
{
	rule->linenumber = yylineno;

	command			= &rule->state.command;
	methodv			= rule->state.methodv;
	methodc			= &rule->state.methodc;
	protocol			= &rule->state.protocol;
	proxyprotocol	= &rule->state.proxyprotocol;
	userbase			= &rule->user;
}
#endif
#line 867 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || __STDC__
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
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
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
#if defined(__cplusplus) || __STDC__
yyparse(void)
#else
yyparse()
#endif
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

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
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 3:
#line 255 "config_parse.y"
{
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &config.extension;
		methodv			= config.methodv;
		methodc			= &config.methodc;
#endif
	}
break;
case 4:
#line 266 "config_parse.y"
{ yyval.string = NULL; }
break;
case 9:
#line 273 "config_parse.y"
{ yyval.string = NULL; }
break;
case 13:
#line 280 "config_parse.y"
{
	}
break;
case 29:
#line 306 "config_parse.y"
{
		yywarn("given keyword is deprecated");
	}
break;
case 30:
#line 310 "config_parse.y"
{
#if SOCKS_CLIENT
		route.src		= src;
		route.dst		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
#endif
	}
break;
case 31:
#line 322 "config_parse.y"
{
#if SOCKS_CLIENT
		command			= &state.command;
		extension		= &state.extension;
		methodv			= state.methodv;
		methodc			= &state.methodc;
		protocol			= &state.protocol;
		proxyprotocol	= &state.proxyprotocol;

		bzero(&state, sizeof(state));
		bzero(&route, sizeof(route));
		bzero(&gw, sizeof(gw));
		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	}
break;
case 33:
#line 346 "config_parse.y"
{
			proxyprotocol->socks_v4 	= 1;
	}
break;
case 34:
#line 349 "config_parse.y"
{
			proxyprotocol->socks_v5 	= 1;
	}
break;
case 35:
#line 352 "config_parse.y"
{
			proxyprotocol->msproxy_v2 	= 1;
	}
break;
case 36:
#line 355 "config_parse.y"
{
			proxyprotocol->http_v1_0 	= 1;
	}
break;
case 40:
#line 367 "config_parse.y"
{
#if SOCKS_SERVER
#if !HAVE_LIBWRAP
		if (strcmp(yyvsp[0].string, method2string(AUTHMETHOD_RFC931)) == 0)
			yyerror("method %s requires libwrap", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
		if (adduser(userbase, yyvsp[0].string) == NULL)
			yyerror(NOMEM);
#endif /* SOCKS_SERVER */
	}
break;
case 44:
#line 386 "config_parse.y"
{
			extension->bind = 1;
	}
break;
case 47:
#line 396 "config_parse.y"
{
#if SOCKS_SERVER
		addinternal(ruleaddress);
#endif
	}
break;
case 48:
#line 403 "config_parse.y"
{
#if SOCKS_SERVER
	static struct ruleaddress_t mem;
	struct servent	*service;

	addressinit(&mem);

	/* set default port. */
	if ((service = getservbyname("socks", "tcp")) == NULL)
		*port_tcp = htons(SOCKD_PORT);
	else
		*port_tcp = (in_port_t)service->s_port;
#endif
	}
break;
case 51:
#line 423 "config_parse.y"
{
#if SOCKS_SERVER
		addexternal(ruleaddress);
#endif
	}
break;
case 52:
#line 430 "config_parse.y"
{
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		addressinit(&mem);
#endif
	}
break;
case 59:
#line 452 "config_parse.y"
{
		if (!config.state.init) {
			const char *syslogname = "syslog";

			if (strncmp(yyvsp[0].string, syslogname, strlen(syslogname)) == 0
			&& (yyvsp[0].string[strlen(syslogname)] == NUL || yyvsp[0].string[strlen(syslogname)] == '/')) {
				char *sl;

				config.log.type |= LOGTYPE_SYSLOG;

				if (*(sl = &(yyvsp[0].string[strlen(syslogname)])) == '/') { /* facility. */
					size_t i;

					for (i = 0, ++sl; i < ELEMENTS(syslogfacility); ++i)
						if (strcmp(sl, syslogfacility[i].name) == 0)
							break;

					if (i == ELEMENTS(syslogfacility))
						serrx(EXIT_FAILURE, "unknown syslog facility \"%s\"", sl);
					config.log.facility = syslogfacility[i].value;
				}
				else
					config.log.facility = LOG_DAEMON; /* default. */
			}
			else {
				config.log.type |= LOGTYPE_FILE;

				if ((config.log.fpv = (FILE **)realloc(config.log.fpv,
				sizeof(*config.log.fpv) * (config.log.fpc + 1))) == NULL
				|| (config.log.fplockv = (int *)realloc(config.log.fplockv,
				sizeof(*config.log.fplockv) * (config.log.fpc + 1))) == NULL)
					serrx(EXIT_FAILURE, NOMEM);

				if ((config.log.fplockv[config.log.fpc]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp(yyvsp[0].string, "stdout") == 0)
					config.log.fpv[config.log.fpc] = stdout;
				else if (strcmp(yyvsp[0].string, "stderr") == 0)
					config.log.fpv[config.log.fpc] = stderr;
				else {
					int flag;

					if ((config.log.fpv[config.log.fpc] = fopen(yyvsp[0].string, "a"))
					== NULL)
						serr(EXIT_FAILURE, "fopen(%s)", yyvsp[0].string);

					if ((flag = fcntl(fileno(config.log.fpv[config.log.fpc]),
					F_GETFD, 0)) == -1
					||  fcntl(fileno(config.log.fpv[config.log.fpc]), F_SETFD,
					flag | FD_CLOEXEC) == -1)
						serr(EXIT_FAILURE, "fcntl(F_GETFD/F_SETFD)");
				}
				++config.log.fpc;
			}
		}
		else
			;	/* XXX warn/exit if output changed. */
	}
break;
case 65:
#line 523 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.privileged			= yyvsp[0].uid;
		config.uid.privileged_isset	= 1;
#endif
	}
break;
case 66:
#line 531 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.unprivileged			= yyvsp[0].uid;
		config.uid.unprivileged_isset	= 1;
#endif
	}
break;
case 67:
#line 539 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		config.uid.libwrap			= yyvsp[0].uid;
		config.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 68:
#line 550 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	}
break;
case 69:
#line 560 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 70:
#line 567 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 71:
#line 574 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	}
break;
case 73:
#line 582 "config_parse.y"
{
#if SOCKS_SERVER
		config.compat.reuseaddr = 1;
	}
break;
case 74:
#line 586 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	}
break;
case 78:
#line 599 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
break;
case 79:
#line 602 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			config.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
break;
case 80:
#line 609 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
break;
case 82:
#line 617 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			config.srchost.nomismatch = 1;
	}
break;
case 83:
#line 621 "config_parse.y"
{
			config.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
break;
case 86:
#line 634 "config_parse.y"
{ *methodc = 0; /* reset. */ }
break;
case 88:
#line 637 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	}
break;
case 89:
#line 640 "config_parse.y"
{
		yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
	}
break;
case 90:
#line 643 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
break;
case 91:
#line 646 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method %s requires libwrap", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
	}
break;
case 94:
#line 662 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addclientrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinitmem;

		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	}
break;
case 99:
#line 685 "config_parse.y"
{ yyval.string = NULL; }
break;
case 101:
#line 689 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addsocksrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinitmem;

		src.atype	= SOCKS_ADDR_IPV4;
		dst.atype	= SOCKS_ADDR_IPV4;
#endif
	}
break;
case 109:
#line 716 "config_parse.y"
{ yyval.string = NULL; }
break;
case 111:
#line 720 "config_parse.y"
{
#if SOCKS_SERVER
		rule.verdict	= VERDICT_BLOCK;
		ruleinit(&rule);
	}
break;
case 112:
#line 725 "config_parse.y"
{
		rule.verdict	= VERDICT_PASS;
		ruleinit(&rule);
#endif
	}
break;
case 114:
#line 736 "config_parse.y"
{
			command->bind = 1;
	}
break;
case 115:
#line 739 "config_parse.y"
{
			command->connect = 1;
	}
break;
case 116:
#line 742 "config_parse.y"
{
			command->udpassociate = 1;
	}
break;
case 117:
#line 748 "config_parse.y"
{
			command->bindreply = 1;
	}
break;
case 118:
#line 752 "config_parse.y"
{
			command->udpreply = 1;
	}
break;
case 122:
#line 764 "config_parse.y"
{
		protocol->tcp = 1;
	}
break;
case 123:
#line 767 "config_parse.y"
{
		protocol->udp = 1;
	}
break;
case 128:
#line 783 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
break;
case 129:
#line 787 "config_parse.y"
{
			rule.log.data = 1;
	}
break;
case 130:
#line 790 "config_parse.y"
{
			rule.log.disconnect = 1;
	}
break;
case 131:
#line 793 "config_parse.y"
{
			rule.log.error = 1;
	}
break;
case 132:
#line 796 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	}
break;
case 135:
#line 807 "config_parse.y"
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
		yyerror("libwrap support not compiled in");
#endif
	}
break;
case 144:
#line 852 "config_parse.y"
{ yyval.string = NULL; }
break;
case 146:
#line 856 "config_parse.y"
{
		addressinit(&src);
	}
break;
case 147:
#line 862 "config_parse.y"
{
		addressinit(&dst);
	}
break;
case 148:
#line 868 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	}
break;
case 154:
#line 887 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address: %s", yyvsp[0].string);
	}
break;
case 155:
#line 896 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask: %d", yyvsp[0].string);

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	}
break;
case 156:
#line 903 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask: %s", yyvsp[0].string);
	}
break;
case 157:
#line 909 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);
	}
break;
case 158:
#line 918 "config_parse.y"
{
		*atype = SOCKS_ADDR_IFNAME;

		if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
			yyerror("interfacename too long");
		strcpy(ifname, yyvsp[0].string);
	}
break;
case 159:
#line 928 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);

#if SOCKS_CLIENT
		route.state.direct = 1;
#endif
	}
break;
case 160:
#line 941 "config_parse.y"
{ yyval.string = NULL; }
break;
case 166:
#line 954 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	}
break;
case 167:
#line 960 "config_parse.y"
{
		ruleaddress->portend		= htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator	= range;
	}
break;
case 168:
#line 966 "config_parse.y"
{
		struct servent	*service;
		struct protocol_t	protocolunset;
		int set;

		bzero(&protocolunset, sizeof(protocolunset));

		/* set all protocols if none set, default. */
		if (memcmp(protocol, &protocolunset, sizeof(*protocol)) == 0) {
			memset(protocol, UCHAR_MAX, sizeof(*protocol));
			set = 0;
		}
		else
			set = 1;

		if (protocol->tcp) {
			if ((service = getservbyname(yyvsp[0].string, "tcp")) == NULL) {
				if (set)
					yyerror("bad servicename for tcp: %s", yyvsp[0].string);
				else
					*port_tcp = htons(0);
			}
			else
				*port_tcp = (in_port_t)service->s_port;
		}

		if (protocol->udp) {
			if ((service = getservbyname(yyvsp[0].string, "udp")) == NULL) {
				if (set)
					yyerror("bad servicename for udp: %s", yyvsp[0].string);
				else
					*port_udp = htons(0);
			}
			else
				*port_udp = (in_port_t)service->s_port;
		}

		/* check we got both protocol ports set right. */
		if (*port_tcp == htons(0) && *port_udp == htons(0))
			yyerror("bad service name for tcp/udp");
		if (*port_tcp == htons(0))
			*port_tcp = *port_udp;
		else if (*port_udp == htons(0))
			*port_udp = *port_tcp;
	}
break;
case 169:
#line 1014 "config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	}
break;
#line 1732 "y.tab.c"
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
    return (1);
yyaccept:
    return (0);
}
