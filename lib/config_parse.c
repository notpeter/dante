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
"$Id: config_parse.y,v 1.132 2000/08/08 12:36:09 michaels Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

__END_DECLS

extern int yylineno;
extern char *yytext;

#if SOCKS_SERVER
static struct rule_t				ruleinit;
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


#line 155 "config_parse.y"
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#line 160 "y.tab.c"
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
#define PORT 320
#define PORTNUMBER 321
#define SERVICENAME 322
#define NUMBER 323
#define FROM 324
#define TO 325
#define YYERRCODE 256
short socks_yylhs[] = {                                        -1,
    0,    0,   45,    1,    1,    1,    1,    1,    2,    2,
    2,    2,   22,   23,   23,   46,   46,   46,   46,   46,
   46,   46,   44,   44,   44,   44,   44,   44,    3,   52,
   21,    7,    8,    8,    8,    8,    9,    9,   10,   11,
   12,   12,   28,   29,   30,   30,   31,   32,   33,   34,
   24,   24,   24,   35,   36,   37,   37,   47,   47,   47,
   48,   49,   50,   51,   26,   27,   25,   38,   39,   39,
   40,   40,   13,   14,   14,   14,   15,   16,   16,   17,
   17,   85,   41,   43,   43,   43,   43,   42,   42,   60,
   61,   61,   61,   61,   62,   62,   57,   58,   58,   58,
   58,   58,   58,   58,   59,   59,   63,   63,   18,   20,
   20,   20,   20,   20,   19,   19,    4,    6,    6,    5,
    5,   64,   65,   67,   67,   67,   67,   67,   66,   66,
   68,   69,   70,   54,   55,   55,   55,   55,   55,   56,
   56,   76,   77,   53,   71,   71,   73,   73,   73,   72,
   78,   78,   74,   75,   79,   79,   79,   83,   83,   80,
   81,   86,   84,   82,
};
short socks_yylen[] = {                                         2,
    2,    2,    1,    0,    2,    2,    2,    2,    0,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    8,
    0,    3,    1,    1,    1,    1,    1,    2,    3,    1,
    1,    2,    3,    1,    1,    2,    5,    0,    4,    0,
    1,    1,    1,    3,    1,    1,    2,    1,    1,    1,
    3,    3,    3,    1,    3,    3,    3,    3,    1,    1,
    1,    2,    3,    1,    1,    1,    3,    1,    1,    1,
    2,    0,    4,    1,    1,    1,    1,    1,    2,    7,
    1,    1,    1,    1,    0,    2,    6,    1,    1,    1,
    1,    1,    1,    1,    0,    2,    1,    1,    3,    1,
    1,    1,    1,    1,    1,    2,    3,    1,    1,    1,
    2,    2,    3,    1,    1,    1,    1,    1,    1,    2,
    3,    3,    3,    3,    1,    1,    1,    1,    1,    0,
    2,    1,    1,    1,    4,    2,    2,    2,    1,    1,
    1,    1,    1,    1,    0,    3,    2,    1,    1,    3,
    1,    1,    1,    1,
};
short socks_yydefred[] = {                                      0,
    3,   13,    0,    9,    4,    0,    0,   29,    0,    0,
    0,   31,   10,   15,   53,   11,   14,   52,   51,   12,
    0,   48,   50,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  107,  108,    5,   17,   27,   28,   26,   24,
   25,   18,   19,   20,   23,   16,   21,    6,   22,   58,
   59,   60,    8,    7,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   82,    0,    0,    0,
    0,    0,   67,   75,   76,   74,   73,   55,    0,   54,
    0,    0,    0,    0,   78,   79,    0,   77,   44,    0,
   43,   65,   66,    0,   69,   70,    0,   68,   64,   61,
   62,   63,    0,    0,    0,    0,    0,    0,  102,  103,
  104,   99,   98,    0,    0,  101,  100,   57,  137,  138,
  135,  136,  139,    0,    0,   94,   91,    0,    0,   93,
   92,  150,    0,   49,   81,   46,   84,   85,   86,   87,
   83,    0,   72,    0,    0,    0,    0,    0,    0,  106,
  142,    0,    0,    0,  141,    0,   96,    0,    0,   47,
   89,  118,  119,  117,    0,   33,   34,   35,   36,    0,
   32,   40,    0,   39,  110,  111,  112,  113,  114,  109,
    0,  131,  124,  125,  126,  127,  128,  123,    0,    0,
  143,  122,    0,    0,  144,    0,    0,    0,  164,  161,
  157,    0,    0,  121,   38,   42,  116,  130,   97,    0,
  153,  132,    0,    0,    0,    0,   90,    0,  163,  159,
  156,  158,  133,    0,  146,  154,    0,  134,    0,  149,
   30,  162,  160,  152,  151,    0,  147,  148,  145,
};
short socks_yydgoto[] = {                                       3,
    7,    6,   14,  109,  164,  165,  110,  170,  171,  111,
  173,  174,   15,   77,   38,   87,   88,  112,  180,  181,
   59,    4,   16,   17,   18,   39,   40,  122,   90,   91,
   42,   61,   43,   62,   19,   79,   80,   45,   97,   98,
  113,  141,  142,   47,    5,   48,   49,   50,   51,   52,
  100,   20,  196,  197,  124,  125,   53,  114,  115,   54,
  128,  129,   55,  152,  116,  188,  189,  117,  153,  192,
  212,  213,  228,  214,  230,  154,  193,  236,  160,  201,
  202,  203,  221,  222,   94,  233,
};
short socks_yysindex[] = {                                   -207,
    0,    0,    0,    0,    0,  -10,  226,    0,  -35,  -27,
  -25,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -229,    0,    0,  -12,   -4,    5,    8,   10,   38,   41,
   57,   60,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   -3, -204, -201, -165,    4,    6,
   66,   70, -190, -138, -189, -188,    0, -170, -148, -148,
 -148, -266,    0,    0,    0,    0,    0,    0, -165,    0,
 -254, -247, -179, -179,    0,    0, -190,    0,    0, -138,
    0,    0,    0, -187,    0,    0, -170,    0,    0,    0,
    0,    0,   81,   84,   85,   86,   87,   88,    0,    0,
    0,    0,    0, -266, -177,    0,    0,    0,    0,    0,
    0,    0,    0, -254, -177,    0,    0, -247, -177,    0,
    0,    0, -172,    0,    0,    0,    0,    0,    0,    0,
    0, -187,    0, -208, -195, -132, -231, -158, -233,    0,
    0, -266, -173,   95,    0, -134,    0, -247, -283,    0,
    0,    0,    0,    0, -208,    0,    0,    0,    0, -195,
    0,    0, -132,    0,    0,    0,    0,    0,    0,    0,
 -231,    0,    0,    0,    0,    0,    0,    0, -233,   30,
    0,    0,   99, -206,    0,  101, -254,   31,    0,    0,
    0,  115, -205,    0,    0,    0,    0,    0,    0, -206,
    0,    0,  114, -172, -212,   39,    0, -154,    0,    0,
    0,    0,    0, -281,    0,    0, -172,    0, -172,    0,
    0,    0,    0,    0,    0, -172,    0,    0,    0,
};
short socks_yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,  168,  174,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -149,    0,    0,    0,    0,    0,    0,   98,    0,
 -147, -142,    0,    0,    0,    0,  130,    0,    0,   55,
    0,    0,    0,    0,    0,    0,  162,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -117,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -115,    0,    0,    0, -113,    0,    0,
    0,    0,  194,    0,    0,    0,    0,    0,    0,    0,
    0,    1,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   51,    0,    0,    0,    0,    0,   58,    0,    0,
    0,    0,    0,    0, -110,    0,    0,    0,    0, -103,
    0,    0,   -2,    0,    0,    0,    0,    0,    0,    0,
  -68,    0,    0,    0,    0,    0,    0,    0,  222,    0,
    0,    0,    0,    0,    0,    0,   59,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -122,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  -56,    0,  -56,    0,
    0,    0,    0,    0,    0, -122,    0,    0,    0,
};
short socks_yygindex[] = {                                      0,
    0,    0,  179,  -75,   28,    0,  -72,    0,   25,  -80,
    0,   23,  195,    0,    0,    0,  126,  -65,   34,    0,
    0,    0,    0,    0,    0,    0,    0,  209,    0,  128,
    0,    0,    0,    0,  212,    0,  141,    0,    0,  125,
   13,   82,    0,    0,    0,    0,    0,    0,    0,    0,
   43,    0,    0,    0,    0, -111,    0,    0,  -96,    0,
    0, -100,  204,  -85,  -61,   37,    0,  -58,    0,    0,
   18,  -79,    0,   14,    0,    0,    0,    0, -197,    0,
   27,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 546
short socks_yytable[] = {                                      13,
   88,  126,  155,  133,  134,  119,   28,  105,  120,  140,
   88,   95,  155,   25,  120,  121,  225,  150,   28,   46,
  130,   37,   56,  131,  103,   28,  199,  157,  104,  237,
   57,  238,   58,  105,  106,  234,  103,  200,  239,  156,
  104,  235,  107,  158,  108,   63,  106,  126,  119,    1,
    2,  120,  105,   64,   45,  190,  115,  198,  121,   33,
   34,  107,   65,  108,   45,   66,  130,   67,  155,  131,
  175,  176,  177,  178,  179,   85,   86,  126,  183,  184,
  185,  186,  187,  162,  163,  216,  137,  138,  139,  140,
   74,   75,   76,  123,  127,   68,  130,   56,   69,  131,
  166,  167,  168,  169,  132,  211,  226,   56,   95,   96,
  132,  211,  101,  102,   70,  200,  219,   71,   73,   72,
   78,  119,   41,   83,  120,   88,   81,   84,   82,   80,
   89,  121,   99,   92,   93,  227,  123,  132,  144,   80,
  127,  145,  146,  147,  148,  149,  151,  159,  172,  182,
  155,  191,  194,  195,  209,  217,  210,  120,  215,  218,
  224,   71,  120,  231,   37,  155,  232,    2,  155,   37,
  127,   71,  155,    1,  105,  105,  140,  155,  155,   45,
  120,   95,   95,  140,  120,   36,  155,   37,  155,  120,
  120,   37,  204,  155,  205,  206,   37,   37,  120,  115,
  120,   37,  155,  155,  115,   37,  105,   37,  140,  123,
   95,  155,  135,  120,  207,   41,  155,  136,   44,  118,
   37,  143,  115,  161,   60,  208,  115,  223,  229,  220,
    0,  115,  115,    0,  155,   35,    0,    0,  155,    0,
  115,    0,  115,    0,  155,    0,    0,    0,    8,    0,
    0,    0,    9,   10,    0,  115,    0,    0,    0,   88,
   88,   88,   88,    0,   88,   88,    0,    0,   88,    0,
   41,   88,   88,   88,   11,    0,   12,    0,   88,    0,
    0,    0,   88,   88,   88,   88,    0,    0,   41,   88,
   88,   88,   41,    0,    0,   88,    0,   41,   41,    0,
   88,   88,    0,    0,    0,    0,   41,    0,   41,   88,
    0,   88,    0,   45,   45,   45,   45,    0,   45,   45,
    0,   41,   45,    0,   88,   45,   45,   45,    0,    0,
    0,    0,   45,    0,    0,    0,   45,   45,   45,   45,
    0,    0,    0,   45,   45,   45,  129,    0,    0,   45,
    0,    0,    0,    0,    0,   45,   56,   56,   56,   56,
   56,   56,   56,    0,    0,   56,    0,    0,   56,   56,
   56,    0,    0,    0,    0,   56,    0,    0,   45,   56,
   56,   56,   56,    0,   56,    0,   56,   56,   80,   80,
   80,   80,    0,   80,   80,    0,    0,   80,    0,    0,
   80,   80,   80,    0,    0,    0,    0,   80,    0,    0,
    0,   80,   80,   80,   80,    0,    0,    0,   80,   80,
   71,   71,   71,   71,    0,   71,   71,    0,    0,   71,
    0,    0,   71,   71,   71,    0,    0,    0,    0,   71,
    0,    0,    0,   71,   71,   71,   71,    0,    0,    0,
   71,   71,  155,  155,  155,  155,    0,  155,  155,    0,
    0,  155,    0,    0,  155,  155,  155,    0,    0,    0,
    0,  155,    0,    0,    0,  155,  155,  155,  155,    0,
    0,    0,  155,  155,    8,   21,   22,   23,    0,   10,
   24,    0,    0,   25,  129,    0,   26,   27,   28,    0,
    0,    0,    0,   29,    0,    0,    0,   30,   31,   32,
   11,    0,  129,    0,   33,   34,  129,    0,    0,    0,
    0,  129,  129,    0,    0,    0,    0,    0,    0,    0,
  129,    0,  129,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  129,
};
short socks_yycheck[] = {                                      10,
    0,   82,  125,   83,   84,   81,  273,  125,   81,  125,
   10,  125,  124,  268,  125,   81,  214,  114,  273,    7,
   82,  125,   58,   82,  291,  273,  310,  128,  295,  227,
   58,  229,   58,  300,  301,  317,  291,  321,  236,  125,
  295,  323,  309,  129,  311,   58,  301,  128,  124,  257,
  258,  124,  300,   58,    0,  152,  125,  158,  124,  289,
  290,  309,   58,  311,   10,   58,  128,   58,  125,  128,
  302,  303,  304,  305,  306,  266,  267,  158,  312,  313,
  314,  315,  316,  292,  293,  197,  274,  275,  276,  277,
  292,  293,  294,   81,   82,   58,  158,    0,   58,  158,
  296,  297,  298,  299,  317,  318,  319,   10,  279,  280,
  317,  318,   70,   71,   58,  321,  322,   58,  323,  123,
  286,  197,  125,   58,  197,  125,  123,   58,  123,    0,
  269,  197,  281,  323,  323,  215,  124,  317,   58,   10,
  128,   58,   58,   58,   58,   58,  324,  320,  281,  308,
  273,  325,   58,  288,  125,  125,   58,  268,   58,   45,
   47,    0,  273,  125,  268,  288,  321,    0,  291,  273,
  158,   10,  295,    0,  324,  125,  324,  300,  301,  125,
  291,  324,  125,  125,  295,    7,  309,  291,  311,  300,
  301,  295,  165,    0,  170,  173,  300,  301,  309,  268,
  311,    7,  325,   10,  273,  309,  324,  311,  324,  197,
  324,  268,   87,  324,  181,    7,  273,   90,    7,   79,
  324,   97,  291,  142,   21,  189,  295,  210,  215,  203,
   -1,  300,  301,   -1,  291,   10,   -1,   -1,  295,   -1,
  309,   -1,  311,   -1,  301,   -1,   -1,   -1,  259,   -1,
   -1,   -1,  263,  264,   -1,  324,   -1,   -1,   -1,  259,
  260,  261,  262,   -1,  264,  265,   -1,   -1,  268,   -1,
  273,  271,  272,  273,  285,   -1,  287,   -1,  278,   -1,
   -1,   -1,  282,  283,  284,  285,   -1,   -1,  291,  289,
  290,  291,  295,   -1,   -1,  295,   -1,  300,  301,   -1,
  300,  301,   -1,   -1,   -1,   -1,  309,   -1,  311,  309,
   -1,  311,   -1,  259,  260,  261,  262,   -1,  264,  265,
   -1,  324,  268,   -1,  324,  271,  272,  273,   -1,   -1,
   -1,   -1,  278,   -1,   -1,   -1,  282,  283,  284,  285,
   -1,   -1,   -1,  289,  290,  291,  125,   -1,   -1,  295,
   -1,   -1,   -1,   -1,   -1,  301,  259,  260,  261,  262,
  263,  264,  265,   -1,   -1,  268,   -1,   -1,  271,  272,
  273,   -1,   -1,   -1,   -1,  278,   -1,   -1,  324,  282,
  283,  284,  285,   -1,  287,   -1,  289,  290,  259,  260,
  261,  262,   -1,  264,  265,   -1,   -1,  268,   -1,   -1,
  271,  272,  273,   -1,   -1,   -1,   -1,  278,   -1,   -1,
   -1,  282,  283,  284,  285,   -1,   -1,   -1,  289,  290,
  259,  260,  261,  262,   -1,  264,  265,   -1,   -1,  268,
   -1,   -1,  271,  272,  273,   -1,   -1,   -1,   -1,  278,
   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,   -1,
  289,  290,  259,  260,  261,  262,   -1,  264,  265,   -1,
   -1,  268,   -1,   -1,  271,  272,  273,   -1,   -1,   -1,
   -1,  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,
   -1,   -1,  289,  290,  259,  260,  261,  262,   -1,  264,
  265,   -1,   -1,  268,  273,   -1,  271,  272,  273,   -1,
   -1,   -1,   -1,  278,   -1,   -1,   -1,  282,  283,  284,
  285,   -1,  291,   -1,  289,  290,  295,   -1,   -1,   -1,
   -1,  300,  301,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  309,   -1,  311,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  324,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 325
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
"LOG_IOOPERATION","IPADDRESS","DOMAIN","DIRECT","PORT","PORTNUMBER",
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
"internal : INTERNAL internalinit ':' ipaddress port",
"internalinit :",
"external : EXTERNAL externalinit ':' ipaddress",
"externalinit :",
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
#line 1047 "config_parse.y"

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

/*	yydebug		= 1;    */
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
yyerror(s)
	const char *s;
{

	serrx(EXIT_FAILURE, "%s: error on line %d, near '%.10s': %s",
	config.option.configfile, yylineno,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext, s);
}


void
yywarn(s)
	const char *s;
{
	swarnx("%s: warning on line %d, near '%.10s': %s",
	config.option.configfile, yylineno,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext, s);
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
		port_tcp		= &ruleaddress->port.tcp;
		port_udp		= &ruleaddress->port.udp;
		operator		= &ruleaddress->operator;
}
#line 792 "y.tab.c"
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
#line 250 "config_parse.y"
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
#line 261 "config_parse.y"
{ yyval.string = NULL; }
break;
case 9:
#line 268 "config_parse.y"
{ yyval.string = NULL; }
break;
case 13:
#line 275 "config_parse.y"
{
	}
break;
case 29:
#line 301 "config_parse.y"
{
		yywarn("given keyword is deprecated");
	}
break;
case 30:
#line 305 "config_parse.y"
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
#line 317 "config_parse.y"
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
		src.atype		= SOCKS_ADDR_IPV4;
		dst.atype		= SOCKS_ADDR_IPV4;
#endif
	}
break;
case 33:
#line 341 "config_parse.y"
{
			proxyprotocol->socks_v4 	= 1;
	}
break;
case 34:
#line 344 "config_parse.y"
{
			proxyprotocol->socks_v5 	= 1;
	}
break;
case 35:
#line 347 "config_parse.y"
{
			proxyprotocol->msproxy_v2 	= 1;
	}
break;
case 36:
#line 350 "config_parse.y"
{
			proxyprotocol->http_v1_0 	= 1;
	}
break;
case 40:
#line 362 "config_parse.y"
{
#if SOCKS_SERVER
#if !HAVE_LIBWRAP
		if (strcmp(yyvsp[0].string, method2string(AUTHMETHOD_RFC931)) == 0)
			yyerror("method rfc931 requires libwrap");
#endif /* !HAVE_LIBWRAP */
		if (adduser(userbase, yyvsp[0].string) == NULL)
			yyerror(NOMEM);
#endif /* SOCKS_SERVER */
	}
break;
case 44:
#line 381 "config_parse.y"
{
			extension->bind = 1;
	}
break;
case 47:
#line 391 "config_parse.y"
{
#if SOCKS_SERVER
		if (config.state.init) {
			int i;

			for (i = 0; i < config.internalc; ++i)
				if (config.internalv[i].addr.sin_addr.s_addr == ipaddr->s_addr
				&&	 config.internalv[i].addr.sin_port == *port_tcp)
					break;

			if (i == config.internalc)
				swarnx("can not change internal addresses once running");
		}
#endif /* SOCKS_SERVER */
	}
break;
case 48:
#line 408 "config_parse.y"
{
#if SOCKS_SERVER
	static struct ruleaddress_t mem;
	struct servent	*service;

	addressinit(&mem);

	if (!config.state.init) {
		if ((config.internalv = (struct listenaddress_t *)
		realloc(config.internalv, sizeof(*config.internalv) * ++config.internalc))
		== NULL)
			yyerror(NOMEM);

		bzero(&config.internalv[config.internalc - 1].addr,
		sizeof((*config.internalv).addr));
		config.internalv[config.internalc - 1].addr.sin_family = AF_INET;

		ipaddr		= &config.internalv[config.internalc - 1].addr.sin_addr;
		port_tcp		= &config.internalv[config.internalc - 1].addr.sin_port;
	}
	else { /* can only set internal addresses once. */
		static struct in_addr inaddrmem;
		static in_port_t portmem;

		ipaddr		= &inaddrmem;
		port_tcp		= &portmem;
	}

	/* set default port. */
	if ((service = getservbyname("socks", "tcp")) == NULL)
		*port_tcp = htons(SOCKD_PORT);
	else
		*port_tcp = (in_port_t)service->s_port;
#endif
	}
break;
case 49:
#line 445 "config_parse.y"
{
#if SOCKS_SERVER
		if (config.externalv[config.externalc - 1].sin_addr.s_addr
		== htonl(INADDR_ANY))
			yyerror("external address can't be a wildcard address");
#endif
		}
break;
case 50:
#line 454 "config_parse.y"
{
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		if ((config.externalv = (struct sockaddr_in *)realloc(config.externalv,
		sizeof(*config.externalv) * ++config.externalc)) == NULL)
			yyerror(NOMEM);

		bzero(&config.externalv[config.externalc - 1], sizeof(*config.externalv));
		config.externalv[config.externalc - 1].sin_family = AF_INET;

		addressinit(&mem);

		ipaddr = &config.externalv[config.externalc - 1].sin_addr;
#endif
	}
break;
case 55:
#line 480 "config_parse.y"
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
case 61:
#line 551 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.privileged			= yyvsp[0].uid;
		config.uid.privileged_isset	= 1;
#endif
	}
break;
case 62:
#line 559 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.unprivileged			= yyvsp[0].uid;
		config.uid.unprivileged_isset	= 1;
#endif
	}
break;
case 63:
#line 567 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		config.uid.libwrap			= yyvsp[0].uid;
		config.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrap support not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 64:
#line 578 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	}
break;
case 65:
#line 588 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 66:
#line 595 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 67:
#line 602 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	}
break;
case 69:
#line 610 "config_parse.y"
{
#if SOCKS_SERVER
		config.compat.reuseaddr = 1;
	}
break;
case 70:
#line 614 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	}
break;
case 74:
#line 627 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
break;
case 75:
#line 630 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			config.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
break;
case 76:
#line 637 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
break;
case 78:
#line 645 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			config.srchost.nomismatch = 1;
	}
break;
case 79:
#line 649 "config_parse.y"
{
			config.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
break;
case 82:
#line 662 "config_parse.y"
{ *methodc = 0; /* reset. */ }
break;
case 84:
#line 665 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	}
break;
case 85:
#line 668 "config_parse.y"
{
		yyerror("GSSAPI not supported");
	}
break;
case 86:
#line 671 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
break;
case 87:
#line 674 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method rfc931 requires libwrap");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 90:
#line 690 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addclientrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinit;

		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	}
break;
case 95:
#line 713 "config_parse.y"
{ yyval.string = NULL; }
break;
case 97:
#line 717 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addsocksrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinit;

		src.atype	= SOCKS_ADDR_IPV4;
		dst.atype	= SOCKS_ADDR_IPV4;
#endif
	}
break;
case 105:
#line 744 "config_parse.y"
{ yyval.string = NULL; }
break;
case 107:
#line 748 "config_parse.y"
{
#if SOCKS_SERVER
		rule.verdict	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
		userbase			= &rule.user;
	}
break;
case 108:
#line 758 "config_parse.y"
{
		rule.verdict	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
		userbase			= &rule.user;
#endif
	}
break;
case 110:
#line 773 "config_parse.y"
{
			command->bind = 1;
	}
break;
case 111:
#line 776 "config_parse.y"
{
			command->connect = 1;
	}
break;
case 112:
#line 779 "config_parse.y"
{
			command->udpassociate = 1;
	}
break;
case 113:
#line 785 "config_parse.y"
{
			command->bindreply = 1;
	}
break;
case 114:
#line 789 "config_parse.y"
{
			command->udpreply = 1;
	}
break;
case 118:
#line 801 "config_parse.y"
{
		protocol->tcp = 1;
	}
break;
case 119:
#line 804 "config_parse.y"
{
		protocol->udp = 1;
	}
break;
case 124:
#line 820 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
break;
case 125:
#line 824 "config_parse.y"
{
			rule.log.data = 1;
	}
break;
case 126:
#line 827 "config_parse.y"
{
			rule.log.disconnect = 1;
	}
break;
case 127:
#line 830 "config_parse.y"
{
			rule.log.error = 1;
	}
break;
case 128:
#line 833 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	}
break;
case 131:
#line 844 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		struct request_info request;
		char libwrap[LIBWRAPBUF];

		if (strlen(yyvsp[0].string) >= sizeof(rule.libwrap))
			yyerror("libwrap line too long, make LIBWRAPBUF bigger");
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
case 140:
#line 889 "config_parse.y"
{ yyval.string = NULL; }
break;
case 142:
#line 893 "config_parse.y"
{
		addressinit(&src);
	}
break;
case 143:
#line 899 "config_parse.y"
{
		addressinit(&dst);
	}
break;
case 144:
#line 905 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	}
break;
case 150:
#line 924 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address");
	}
break;
case 151:
#line 933 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask");

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	}
break;
case 152:
#line 940 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask");
	}
break;
case 153:
#line 946 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);
	}
break;
case 154:
#line 955 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);

#if SOCKS_CLIENT
		route.state.direct = 1;
#endif
	}
break;
case 155:
#line 968 "config_parse.y"
{ yyval.string = NULL; }
break;
case 161:
#line 981 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	}
break;
case 162:
#line 987 "config_parse.y"
{
		ruleaddress->portend		= htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator	= range;
	}
break;
case 163:
#line 993 "config_parse.y"
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
					yyerror("bad servicename for tcp");
				else
					*port_tcp = htons(0);
			}
			else
				*port_tcp = (in_port_t)service->s_port;
		}

		if (protocol->udp) {
			if ((service = getservbyname(yyvsp[0].string, "udp")) == NULL) {
				if (set)
					yyerror("bad servicename for udp");
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
case 164:
#line 1041 "config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	}
break;
#line 1699 "y.tab.c"
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
