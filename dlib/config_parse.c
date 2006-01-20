#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ >= 2
  __attribute__ ((unused))
#endif /* __GNUC__ >= 2 */
  = "$OpenBSD: skeleton.c,v 1.23 2004/03/12 13:39:50 henning Exp $";
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
#line 45 "../lib/config_parse.y"

#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.199 2006/01/20 12:59:06 michaels Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

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
static struct rule_t				ruleinitmem;
static struct rule_t				rule;				/* new rule.							*/
static struct protocol_t		protocolmem;	/* new protocolmem.					*/
#endif

static struct serverstate_t	state;
static struct route_t			route;			/* new route.							*/
static struct ruleaddress_t	gw;				/* new gateway.						*/

static struct ruleaddress_t	src;				/* new src.								*/
static struct ruleaddress_t	dst;				/* new dst.								*/
static struct ruleaddress_t	rdr_from;
static struct ruleaddress_t	rdr_to;

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
static size_t						*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/

static const struct {
	const char *name;
	const int value;
} syslogfacilityv[] = {
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
		if (methodisset(method, methodv, *methodc)) \
			yywarn("duplicate method: %s", method2string(method)); \
		else { \
			if (*methodc >= MAXMETHOD)	\
				yyerror("internal error, (%d >= %d)", *methodc, MAXMETHOD);	\
			methodv[(*methodc)++] = method; \
		} \
	} while (0)

#line 167 "../lib/config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 175 "config_parse.c"
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
#define USER_PRIVILEGED 285
#define USER_UNPRIVILEGED 286
#define USER_LIBWRAP 287
#define LOGOUTPUT 288
#define LOGFILE 289
#define CHILD_MAXIDLE 290
#define ROUTE 291
#define VIA 292
#define VERDICT_BLOCK 293
#define VERDICT_PASS 294
#define PAMSERVICENAME 295
#define PROTOCOL 296
#define PROTOCOL_TCP 297
#define PROTOCOL_UDP 298
#define PROTOCOL_FAKE 299
#define PROXYPROTOCOL 300
#define PROXYPROTOCOL_SOCKS_V4 301
#define PROXYPROTOCOL_SOCKS_V5 302
#define PROXYPROTOCOL_MSPROXY_V2 303
#define PROXYPROTOCOL_HTTP_V1_0 304
#define USER 305
#define COMMAND 306
#define COMMAND_BIND 307
#define COMMAND_CONNECT 308
#define COMMAND_UDPASSOCIATE 309
#define COMMAND_BINDREPLY 310
#define COMMAND_UDPREPLY 311
#define ACTION 312
#define LINE 313
#define LIBWRAPSTART 314
#define OPERATOR 315
#define LOG 316
#define LOG_CONNECT 317
#define LOG_DATA 318
#define LOG_DISCONNECT 319
#define LOG_ERROR 320
#define LOG_IOOPERATION 321
#define IPADDRESS 322
#define DOMAINNAME 323
#define DIRECT 324
#define IFNAME 325
#define PORT 326
#define PORTNUMBER 327
#define SERVICENAME 328
#define NUMBER 329
#define FROM 330
#define TO 331
#define REDIRECT 332
#define BANDWIDTH 333
#define MAXSESSIONS 334
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   53,    1,    1,    1,    1,    1,    1,    2,
    2,    2,    2,   27,   28,   28,   54,   54,   54,   54,
   54,   54,   54,   54,   54,   54,   52,   52,   52,   52,
   52,   52,    3,   61,   26,    7,    8,    8,    8,    8,
    8,    9,    9,   10,   11,   12,   12,   33,   34,   35,
   35,   36,   37,   38,   39,   40,   40,   29,   29,   29,
   41,   42,   43,   43,   60,   55,   55,   55,   56,   57,
   58,   59,   31,   32,   30,   44,   45,   45,   46,   46,
   14,   15,   15,   15,   16,   17,   17,   18,   18,   49,
   98,   47,   99,   48,   51,   51,   51,   51,   51,   50,
   50,   69,   70,   71,   71,   66,   67,   67,   67,   67,
   67,   67,   68,   68,   72,   72,   72,   72,   72,   72,
   73,   73,   19,   21,   21,   21,   21,   21,   20,   20,
    4,    6,    6,    5,    5,   74,   22,   22,   24,   25,
   23,   75,   77,   77,   77,   77,   77,   76,   76,   13,
   78,   79,   80,  100,  101,   63,   64,   64,   64,   64,
   64,   65,   65,   89,   90,  102,  103,   62,   81,   81,
   81,   82,   82,   82,   83,   83,   83,   85,   85,   85,
   84,   91,   91,   86,   87,   88,   92,   92,   92,   96,
   96,   93,   94,  104,   97,   95,
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
    1,    1,    2,    3,    1,    1,    2,    3,    1,    1,
    2,    4,    0,    4,    0,    3,    3,    1,    1,    1,
    3,    1,    1,    2,    3,    1,    1,    1,    3,    3,
    3,    1,    3,    3,    3,    3,    1,    1,    1,    2,
    3,    1,    1,    1,    3,    1,    1,    1,    2,    3,
    0,    4,    0,    4,    1,    1,    1,    1,    1,    1,
    2,    7,    1,    0,    2,    6,    1,    1,    1,    1,
    1,    1,    0,    2,    1,    1,    1,    1,    1,    1,
    1,    1,    3,    1,    1,    1,    1,    1,    1,    2,
    3,    1,    1,    1,    2,    2,    2,    2,    1,    3,
    3,    3,    1,    1,    1,    1,    1,    1,    2,    3,
    3,    3,    3,    3,    3,    3,    1,    1,    1,    1,
    1,    0,    2,    1,    1,    1,    1,    1,    2,    2,
    2,    1,    1,    1,    4,    2,    2,    2,    2,    1,
    1,    1,    1,    1,    1,    1,    0,    3,    2,    1,
    1,    3,    1,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    3,   14,    0,   10,    4,    0,    0,   33,    0,    0,
    0,   35,   11,   16,   60,   12,   15,   59,   58,   13,
    0,   53,   55,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  121,  122,    5,   19,   31,
   32,   30,   28,   29,   20,   21,   22,   23,   27,   17,
   18,   24,    6,   25,   66,   67,   68,   26,    9,    8,
    7,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   91,   93,    0,    0,    0,    0,
    0,    0,   75,   83,   84,   82,   81,   62,    0,   61,
    0,    0,    0,    0,   56,   57,   86,   87,    0,   85,
   49,    0,   48,   73,   74,    0,    0,   77,   78,    0,
   76,   72,   69,   70,   71,   65,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  110,  111,  119,
  118,  109,  112,  108,  120,  139,  115,    0,    0,  107,
  117,  116,   64,  159,  160,  157,  158,  161,    0,    0,
    0,    0,  103,  181,  184,  185,   52,    0,    0,    0,
   54,  172,  173,  174,   89,   51,   95,   96,   97,   98,
   99,   92,    0,   94,   80,    0,    0,    0,    0,    0,
    0,    0,    0,  166,  167,  137,  138,    0,    0,    0,
    0,  114,  164,    0,    0,    0,  163,    0,  105,    0,
    0,  169,  170,  171,  101,   90,  150,  132,  133,  131,
    0,   37,   38,   39,   40,   41,    0,   36,   45,    0,
   44,  124,  125,  126,  127,  128,  123,    0,  151,  143,
  144,  145,  146,  147,  142,    0,    0,    0,  141,  140,
    0,  165,  136,    0,    0,  168,    0,    0,    0,  196,
  193,  189,    0,    0,  135,   43,   47,  130,  149,  154,
    0,    0,    0,  155,  106,    0,  152,    0,    0,  102,
    0,  195,  191,  188,  190,    0,  176,  177,  153,  186,
    0,  156,    0,  180,   34,  194,  192,  183,  182,    0,
  178,  179,  175,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
    7,    6,  216,  128,  210,  211,  129,  217,  218,  130,
  220,  221,  131,   15,   87,   41,   99,  100,  132,  227,
  228,  133,  134,  135,  136,   66,    4,   16,   17,   18,
   42,   43,  147,  102,  103,   45,   68,   46,   69,   47,
   19,   89,   90,   49,  110,  111,   50,   51,  137,  172,
  173,   52,    5,   53,   54,   55,   56,   57,  113,   58,
   20,  247,  248,  149,  150,   60,  138,  139,   61,  151,
  152,  140,   62,  194,  141,  235,  236,  142,  195,  243,
  157,  161,  260,  261,  282,  262,  263,  284,  196,  244,
  290,  202,  252,  253,  254,  274,  275,  106,  107,  186,
  187,  188,  189,  287,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -199,
    0,    0,    0,    0,    0,  -10,  269,    0,  -28,  -22,
  -11,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -227,    0,    0,   10,   17,   26,   28,   51,   63,   66,
   75,   76,   78,   79,   81,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   18, -187, -264, -146,   21,   22,   88,   90, -254,
 -185, -121, -179, -178,    0,    0, -175, -131, -131, -131,
 -174, -243,    0,    0,    0,    0,    0,    0, -146,    0,
 -200, -235, -277, -277,    0,    0,    0,    0, -185,    0,
    0, -121,    0,    0,    0, -236, -236,    0,    0, -175,
    0,    0,    0,    0,    0,    0,   98,   99,  100,  102,
  104,  107,  108,  109, -233,  110,  111,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -243, -158,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -200, -158,
 -235, -158,    0,    0,    0,    0,    0, -150, -150, -150,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -236,    0,    0, -236, -142, -186, -209, -102,
 -206, -125, -203,    0,    0,    0,    0,  131,  135, -133,
 -126,    0,    0, -243, -127,  140,    0,  -87,    0, -235,
 -289,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -186,    0,    0,    0,    0,    0, -209,    0,    0, -102,
    0,    0,    0,    0,    0,    0,    0, -206,    0,    0,
    0,    0,    0,    0,    0, -203, -277, -277,    0,    0,
   91,    0,    0,  148, -277,    0,  163, -200,  103,    0,
    0,    0,  178, -205,    0,    0,    0,    0,    0,    0,
  177, -150, -150,    0,    0, -277,    0, -268,  105,    0,
 -100,    0,    0,    0,    0, -297,    0,    0,    0,    0,
 -150,    0, -150,    0,    0,    0,    0,    0,    0, -150,
    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  225,  229,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  -99,    0,    0,    0,    0,    0,    0,  125,    0,
  -96,  -95,    0,    0,    0,    0,    0,    0,  161,    0,
    0,   77,    0,    0,    0,    0,    0,    0,    0,  197,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -117,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -116,    0,
 -110,    0,    0,    0,    0,    0,    0,  233,  233,  233,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    1,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  112,    0,    0,    0,    0,    0,  113,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -115,    0,    0,    0,    0,    0,  271,    0,    0,  319,
    0,    0,    0,    0,    0,    0,    0,  278,    0,    0,
    0,    0,    0,    0,    0,  342,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  114,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -122, -122,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  -74,    0,  -74,    0,    0,    0,    0,    0,    0, -122,
    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,  121,  -85,   25,    0,  -84,    0,   23,    0,
    0,   24,    0,  234,    0,    0,    0,  143,  -73,   19,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  238,    0,  144,    0,    0,    0,    0,    0,
  241,    0,  162,    0,    0,  142,    0,    0,  -71,  -88,
    0,    0,    0,    0,    0,    0,    0,    0,   50,    0,
  243,    0,    0,    0, -135,    0,    0, -114,    0,    0,
 -128,  -90,  232, -123,    0,   20,    0,    0,    0,    0,
    0,    0, -217,  -89,    0,  -81,   38,    0,    0,    0,
    0, -143,    0,    3,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,
};
#define YYTABLESIZE 676
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                      13,
  100,  153,  187,  158,  162,  144,  145,  113,  162,  134,
  100,  159,  163,  197,  104,  203,  204,  146,  174,  148,
  264,   95,  199,  192,  288,  250,  198,  267,  200,   63,
  117,  289,   84,   85,   86,   64,   96,  251,  117,  167,
  168,  169,  170,  171,  154,  155,   65,  156,  279,    8,
  187,  118,  119,  154,  155,  280,  120,    1,    2,  118,
  153,  121,  122,  144,  145,   36,   37,   70,   26,  121,
  123,  249,  124,  117,   71,  146,   50,  148,  123,  241,
  124,   97,   98,   72,  205,   73,   50,  206,  125,  126,
  127,  212,  213,  214,  215,  119,  184,  185,  127,  120,
  222,  223,  224,  225,  226,  122,  108,  109,   74,  153,
  208,  209,  269,  230,  231,  232,  233,  234,  277,  278,
   75,  251,  272,   76,   63,  100,   14,   39,  114,  115,
  160,  164,   77,   78,   63,   79,   80,  291,   81,  292,
   82,   83,   88,   91,   92,   93,  293,   94,  101,  104,
  105,  187,  112,  134,  116,  176,  177,  178,  134,  179,
   88,  180,  144,  145,  181,  182,  183,  190,  191,  187,
   88,  193,  187,  187,  146,  201,  148,  187,  281,  134,
  134,  219,  187,  187,  134,  207,  283,  229,  237,  134,
  134,  187,  238,  187,  187,  239,   79,  245,  134,  187,
  134,   50,  240,  242,  246,  266,   79,  187,  187,  187,
  187,  187,  113,  162,  134,  265,  134,  134,  134,  104,
  268,  187,  271,  276,    2,  187,  286,  270,    1,  285,
  113,  187,  187,  162,  104,  255,  113,  104,  162,  256,
   40,  165,  187,  257,   44,  166,  258,   48,    8,   59,
  143,  175,   67,    9,   10,  259,  273,    0,    0,  100,
  100,  100,  100,  100,    0,  100,  100,    0,    0,  100,
    0,    0,  100,  100,  100,  100,    0,   11,   38,    0,
   12,  100,    0,    0,    0,  100,  100,  100,  100,    0,
  100,  100,    0,  100,  100,  100,  100,    0,    0,    0,
  100,    0,    0,    0,    0,  100,  100,    0,    0,    0,
    0,    0,    0,    0,  100,    0,  100,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  100,    0,  100,  100,  100,   50,   50,   50,   50,   50,
    0,   50,   50,    0,    0,   50,    0,    0,   50,   50,
   50,   50,    0,    0,    0,    0,    0,   50,    0,    0,
    0,   50,   50,   50,   50,    0,   50,   50,    0,   50,
   50,    0,   50,    0,    0,    0,   50,    0,    0,    0,
    0,    0,   50,   63,   63,   63,   63,   63,   63,   63,
   63,    0,    0,   63,    0,   42,   63,   63,   63,   63,
    0,    0,  129,    0,    0,   63,   50,    0,    0,   63,
   63,   63,   63,    0,   63,   63,    0,   63,   63,   88,
   88,   88,   88,   88,    0,   88,   88,    0,    0,   88,
    0,    0,   88,   88,   88,   88,    0,    0,    0,    0,
    0,   88,    0,   46,    0,   88,   88,   88,   88,    0,
   88,   88,    0,   88,   88,   79,   79,   79,   79,   79,
    0,   79,   79,    0,    0,   79,  148,    0,   79,   79,
   79,   79,    0,    0,    0,    0,    0,   79,    0,    0,
    0,   79,   79,   79,   79,    0,   79,   79,    0,   79,
   79,  187,  187,  187,  187,  187,    0,  187,  187,    0,
    0,  187,    0,    0,  187,  187,  187,  187,    0,    0,
    0,    0,    0,  187,    0,    0,    0,  187,  187,  187,
  187,    0,  187,  187,    0,  187,  187,    8,   21,   22,
   23,   24,    0,   10,   25,    0,    0,   26,    0,   42,
   27,   28,   29,   30,   42,    0,  129,    0,    0,   31,
    0,  129,    0,   32,   33,   34,   11,    0,   35,   12,
    0,   36,   37,    0,    0,   42,   42,    0,    0,    0,
   42,    0,  129,  129,    0,   42,   42,  129,    0,    0,
    0,    0,  129,  129,   42,    0,   42,    0,    0,    0,
    0,  129,   46,  129,    0,    0,    0,    0,    0,    0,
   42,    0,   42,   42,   42,    0,    0,  129,    0,  129,
  129,  129,    0,   46,   46,  148,    0,    0,   46,    0,
    0,    0,    0,   46,   46,    0,    0,    0,    0,    0,
    0,    0,   46,    0,   46,    0,  148,  148,    0,    0,
    0,  148,    0,    0,    0,    0,  148,  148,   46,    0,
   46,   46,   46,    0,    0,  148,    0,  148,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  148,    0,  148,  148,  148,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                      10,
    0,   92,  125,   93,   94,   91,   91,  125,  125,  125,
   10,   93,   94,  149,  125,  159,  160,   91,  107,   91,
  238,  276,  151,  138,  322,  315,  150,  245,  152,   58,
  274,  329,  297,  298,  299,   58,  291,  327,  274,  276,
  277,  278,  279,  280,  322,  323,   58,  325,  266,  259,
  125,  295,  296,  322,  323,  324,  300,  257,  258,  295,
  151,  305,  306,  149,  149,  293,  294,   58,  269,  305,
  314,  200,  316,  274,   58,  149,    0,  149,  314,  194,
  316,  267,  268,   58,  173,   58,   10,  176,  332,  333,
  334,  301,  302,  303,  304,  296,  330,  331,  334,  300,
  307,  308,  309,  310,  311,  306,  282,  283,   58,  200,
  297,  298,  248,  317,  318,  319,  320,  321,  262,  263,
   58,  327,  328,   58,    0,  125,    6,    7,   79,   80,
   93,   94,   58,   58,   10,   58,   58,  281,   58,  283,
  123,  329,  289,  123,  123,   58,  290,   58,  270,  329,
  329,  274,  284,  269,  329,   58,   58,   58,  274,   58,
    0,   58,  248,  248,   58,   58,   58,   58,   58,  292,
   10,  330,  295,  296,  248,  326,  248,  300,  268,  295,
  296,  284,  305,  306,  300,  328,  268,  313,   58,  305,
  306,  314,   58,  316,  269,  329,    0,   58,  314,  274,
  316,  125,  329,  331,  292,   58,   10,  330,  331,  332,
  333,  334,  330,  330,  330,  125,  332,  333,  334,  330,
   58,  296,   45,   47,    0,  300,  327,  125,    0,  125,
  330,  306,    0,  330,  330,  211,  125,  125,  125,  217,
    7,   99,   10,  220,    7,  102,  228,    7,  259,    7,
   89,  110,   21,  264,  265,  236,  254,   -1,   -1,  259,
  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,
   -1,   -1,  272,  273,  274,  275,   -1,  288,   10,   -1,
  291,  281,   -1,   -1,   -1,  285,  286,  287,  288,   -1,
  290,  291,   -1,  293,  294,  295,  296,   -1,   -1,   -1,
  300,   -1,   -1,   -1,   -1,  305,  306,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  314,   -1,  316,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  330,   -1,  332,  333,  334,  259,  260,  261,  262,  263,
   -1,  265,  266,   -1,   -1,  269,   -1,   -1,  272,  273,
  274,  275,   -1,   -1,   -1,   -1,   -1,  281,   -1,   -1,
   -1,  285,  286,  287,  288,   -1,  290,  291,   -1,  293,
  294,   -1,  296,   -1,   -1,   -1,  300,   -1,   -1,   -1,
   -1,   -1,  306,  259,  260,  261,  262,  263,  264,  265,
  266,   -1,   -1,  269,   -1,  125,  272,  273,  274,  275,
   -1,   -1,  125,   -1,   -1,  281,  330,   -1,   -1,  285,
  286,  287,  288,   -1,  290,  291,   -1,  293,  294,  259,
  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,
   -1,   -1,  272,  273,  274,  275,   -1,   -1,   -1,   -1,
   -1,  281,   -1,  125,   -1,  285,  286,  287,  288,   -1,
  290,  291,   -1,  293,  294,  259,  260,  261,  262,  263,
   -1,  265,  266,   -1,   -1,  269,  125,   -1,  272,  273,
  274,  275,   -1,   -1,   -1,   -1,   -1,  281,   -1,   -1,
   -1,  285,  286,  287,  288,   -1,  290,  291,   -1,  293,
  294,  259,  260,  261,  262,  263,   -1,  265,  266,   -1,
   -1,  269,   -1,   -1,  272,  273,  274,  275,   -1,   -1,
   -1,   -1,   -1,  281,   -1,   -1,   -1,  285,  286,  287,
  288,   -1,  290,  291,   -1,  293,  294,  259,  260,  261,
  262,  263,   -1,  265,  266,   -1,   -1,  269,   -1,  269,
  272,  273,  274,  275,  274,   -1,  269,   -1,   -1,  281,
   -1,  274,   -1,  285,  286,  287,  288,   -1,  290,  291,
   -1,  293,  294,   -1,   -1,  295,  296,   -1,   -1,   -1,
  300,   -1,  295,  296,   -1,  305,  306,  300,   -1,   -1,
   -1,   -1,  305,  306,  314,   -1,  316,   -1,   -1,   -1,
   -1,  314,  274,  316,   -1,   -1,   -1,   -1,   -1,   -1,
  330,   -1,  332,  333,  334,   -1,   -1,  330,   -1,  332,
  333,  334,   -1,  295,  296,  274,   -1,   -1,  300,   -1,
   -1,   -1,   -1,  305,  306,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  314,   -1,  316,   -1,  295,  296,   -1,   -1,
   -1,  300,   -1,   -1,   -1,   -1,  305,  306,  330,   -1,
  332,  333,  334,   -1,   -1,  314,   -1,  316,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  330,   -1,  332,  333,  334,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 334
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
"REUSEADDR","SAMEPORT","USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED",
"USER_LIBWRAP","LOGOUTPUT","LOGFILE","CHILD_MAXIDLE","ROUTE","VIA",
"VERDICT_BLOCK","VERDICT_PASS","PAMSERVICENAME","PROTOCOL","PROTOCOL_TCP",
"PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4",
"PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2","PROXYPROTOCOL_HTTP_V1_0",
"USER","COMMAND","COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE",
"COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE","LIBWRAPSTART",
"OPERATOR","LOG","LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR",
"LOG_IOOPERATION","IPADDRESS","DOMAINNAME","DIRECT","IFNAME","PORT",
"PORTNUMBER","SERVICENAME","NUMBER","FROM","TO","REDIRECT","BANDWIDTH",
"MAXSESSIONS",
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
"proxyprotocolname : deprecated",
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
"gwaddress : ipaddress port",
"gwaddress : domain port",
"gwaddress : direct",
"ipaddress : IPADDRESS",
"netmask : NUMBER",
"netmask : IPADDRESS",
"domain : DOMAINNAME",
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
#line 1182 "../lib/config_parse.y"

#define INTERACTIVE		0

extern FILE *yyin;

int socks_parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";

/*	yydebug				= 1;          */
	yylineno				= 1;
	socks_parseinit	= 0;

	if ((yyin = fopen(filename, "r")) == NULL) {
		swarn("%s: %s", function, filename);
		return -1;
	}

	errno = 0;	/* don't report old errors in yyparse(). */
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
	struct rule_t *rule;
{
	rule->linenumber = yylineno;

	command			= &rule->state.command;
	methodv			= rule->state.methodv;
	methodc			= &rule->state.methodc;
	protocol			= &rule->state.protocol;
	proxyprotocol	= &rule->state.proxyprotocol;

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
#line 1032 "config_parse.c"
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
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 3:
#line 275 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &sockscf.extension;
#endif
	}
break;
case 4:
#line 284 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 10:
#line 292 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 14:
#line 299 "../lib/config_parse.y"
{
	}
break;
case 33:
#line 328 "../lib/config_parse.y"
{
		yywarn("given keyword is deprecated");
	}
break;
case 34:
#line 332 "../lib/config_parse.y"
{
		route.src		= src;
		route.dst		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
	}
break;
case 35:
#line 342 "../lib/config_parse.y"
{
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
	}
break;
case 37:
#line 364 "../lib/config_parse.y"
{
			proxyprotocol->socks_v4		= 1;
	}
break;
case 38:
#line 367 "../lib/config_parse.y"
{
			proxyprotocol->socks_v5		= 1;
	}
break;
case 39:
#line 370 "../lib/config_parse.y"
{
			proxyprotocol->msproxy_v2	= 1;
	}
break;
case 40:
#line 373 "../lib/config_parse.y"
{
			proxyprotocol->http_v1_0	= 1;
	}
break;
case 45:
#line 386 "../lib/config_parse.y"
{
#if SOCKS_SERVER
#if !HAVE_LIBWRAP
		if (strcmp(yyvsp[0].string, method2string(AUTHMETHOD_RFC931)) == 0)
			yyerror("method %s requires libwrap", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
		if (adduser(&rule.user, yyvsp[0].string) == NULL)
			yyerror(NOMEM);
#endif /* SOCKS_SERVER */
	}
break;
case 49:
#line 405 "../lib/config_parse.y"
{
			extension->bind = 1;
	}
break;
case 52:
#line 415 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		addinternal(ruleaddress);
#endif
	}
break;
case 53:
#line 422 "../lib/config_parse.y"
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
case 54:
#line 438 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		addexternal(ruleaddress);
#endif
	}
break;
case 55:
#line 445 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		addressinit(&mem);
#endif
	}
break;
case 56:
#line 454 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		sockscf.external.rotation = ROTATION_NONE;
	}
break;
case 57:
#line 458 "../lib/config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
		yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
		sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
	}
break;
case 62:
#line 476 "../lib/config_parse.y"
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
		else /* adding/changing filename. */
			if (!sockscf.state.init) {
				int flag;

				sockscf.log.type |= LOGTYPE_FILE;

				if ((sockscf.log.fpv = (FILE **)realloc(sockscf.log.fpv,
				sizeof(*sockscf.log.fpv) * (sockscf.log.fpc + 1))) == NULL
				|| (sockscf.log.fplockv = (int *)realloc(sockscf.log.fplockv,
				sizeof(*sockscf.log.fplockv) * (sockscf.log.fpc + 1))) == NULL
				|| (sockscf.log.fnamev = (char **)realloc(sockscf.log.fnamev,
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
				 * Can't change filenames we log to after startup (well,
				 * to be exact, we can't add new filenames, but we complain
				 * about changing too for now since it's easier.
				 */
				size_t i;

				for (i = 0; i < sockscf.log.fpc; ++i)
					if (strcmp(sockscf.log.fnamev[i], yyvsp[0].string) == 0) { /* same name. */
						FILE *fp;

						if (strcmp(sockscf.log.fnamev[i], "stdout") == 0
						||  strcmp(sockscf.log.fnamev[i], "stderr") == 0)
							continue; /* don't need to close these, hard to reopen. */

						/* reopen logfiles. */
						if ((fp = fopen(sockscf.log.fnamev[i], "a")) == NULL)
							yyerror("fopen(%s)", yyvsp[0].string);

						fclose(sockscf.log.fpv[i]);
						sockscf.log.fpv[i] = fp;
						break;
					}

				if (i == sockscf.log.fpc) /* no match found. */
					yywarn("can't change logoutput after startup");
			}
	}
break;
case 65:
#line 578 "../lib/config_parse.y"
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
case 69:
#line 595 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		sockscf.uid.privileged			= yyvsp[0].uid;
		sockscf.uid.privileged_isset	= 1;
#endif
	}
break;
case 70:
#line 603 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		sockscf.uid.unprivileged			= yyvsp[0].uid;
		sockscf.uid.unprivileged_isset	= 1;
#endif
	}
break;
case 71:
#line 611 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		sockscf.uid.libwrap			= yyvsp[0].uid;
		sockscf.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 72:
#line 622 "../lib/config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	}
break;
case 73:
#line 632 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		sockscf.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 74:
#line 639 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		sockscf.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 75:
#line 646 "../lib/config_parse.y"
{
		sockscf.option.debug = atoi(yyvsp[0].string);
	}
break;
case 77:
#line 654 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		sockscf.compat.reuseaddr = 1;
	}
break;
case 78:
#line 658 "../lib/config_parse.y"
{
		sockscf.compat.sameport = 1;
#endif
	}
break;
case 82:
#line 671 "../lib/config_parse.y"
{
			sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
break;
case 83:
#line 674 "../lib/config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
break;
case 84:
#line 681 "../lib/config_parse.y"
{
			sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
break;
case 86:
#line 689 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			sockscf.srchost.nomismatch = 1;
	}
break;
case 87:
#line 693 "../lib/config_parse.y"
{
			sockscf.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
break;
case 91:
#line 709 "../lib/config_parse.y"
{
#if SOCKS_SERVER
	methodv = sockscf.methodv;
	methodc = &sockscf.methodc;
	*methodc = 0; /* reset. */
#endif
	}
break;
case 93:
#line 718 "../lib/config_parse.y"
{
#if SOCKS_SERVER
	methodv = sockscf.clientmethodv;
	methodc = &sockscf.clientmethodc;
	*methodc = 0; /* reset. */
#endif
	}
break;
case 95:
#line 727 "../lib/config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	}
break;
case 96:
#line 730 "../lib/config_parse.y"
{
		yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
	}
break;
case 97:
#line 733 "../lib/config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
break;
case 98:
#line 736 "../lib/config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method %s requires libwraplibrary", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
	}
break;
case 99:
#line 743 "../lib/config_parse.y"
{
#if !HAVE_PAM
		yyerror("method %s requires pamlibrary", AUTHMETHOD_PAMs);
#else /* HAVE_PAM */
		ADDMETHOD(AUTHMETHOD_PAM);
#endif /* !HAVE_PAM */
	}
break;
case 102:
#line 759 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		rule.src			= src;
		rule.dst			= dst;
		rule.rdr_from	= rdr_from;
		rule.rdr_to		= rdr_to;

		addclientrule(&rule);

#endif
	}
break;
case 104:
#line 775 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 106:
#line 779 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		rule.src			= src;
		rule.dst			= dst;
		rule.rdr_from	= rdr_from;
		rule.rdr_to		= rdr_to;

		addsocksrule(&rule);
#endif
	}
break;
case 108:
#line 793 "../lib/config_parse.y"
{
#if SOCKS_SERVER
			checkmodule("bandwidth");
#endif
	}
break;
case 112:
#line 801 "../lib/config_parse.y"
{
#if SOCKS_SERVER
			checkmodule("redirect");
#endif
	}
break;
case 113:
#line 808 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 120:
#line 817 "../lib/config_parse.y"
{
#if SOCKS_SERVER
			checkmodule("session");
#endif
	}
break;
case 121:
#line 824 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		ruleinit(&rule);
		rule.verdict	= VERDICT_BLOCK;
	}
break;
case 122:
#line 829 "../lib/config_parse.y"
{
		ruleinit(&rule);
		rule.verdict	= VERDICT_PASS;
#endif
	}
break;
case 124:
#line 840 "../lib/config_parse.y"
{
			command->bind = 1;
	}
break;
case 125:
#line 843 "../lib/config_parse.y"
{
			command->connect = 1;
	}
break;
case 126:
#line 846 "../lib/config_parse.y"
{
			command->udpassociate = 1;
	}
break;
case 127:
#line 852 "../lib/config_parse.y"
{
			command->bindreply = 1;
	}
break;
case 128:
#line 856 "../lib/config_parse.y"
{
			command->udpreply = 1;
	}
break;
case 132:
#line 868 "../lib/config_parse.y"
{
		protocol->tcp = 1;
	}
break;
case 133:
#line 871 "../lib/config_parse.y"
{
		protocol->udp = 1;
	}
break;
case 140:
#line 891 "../lib/config_parse.y"
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
case 141:
#line 908 "../lib/config_parse.y"
{
#if SOCKS_SERVER
		static bw_t bwmeminit;

     /*
		* temporarily allocate ordinary memory, later on point it to
		* the correct index in sockscf.bwv.
		*/
		if ((rule.bw = (bw_t *)malloc(sizeof(*rule.bw))) == NULL)
			serr(EXIT_FAILURE, NOMEM);
		*rule.bw = bwmeminit;
		if ((rule.bw->maxbps = atoi(yyvsp[0].string)) <= 0)
			yyerror("bandwidth value must be greater than 0");
#endif /* SOCKS_SERVER */
	}
break;
case 143:
#line 929 "../lib/config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
break;
case 144:
#line 933 "../lib/config_parse.y"
{
			rule.log.data = 1;
	}
break;
case 145:
#line 936 "../lib/config_parse.y"
{
			rule.log.disconnect = 1;
	}
break;
case 146:
#line 939 "../lib/config_parse.y"
{
			rule.log.error = 1;
	}
break;
case 147:
#line 942 "../lib/config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	}
break;
case 150:
#line 953 "../lib/config_parse.y"
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
case 151:
#line 964 "../lib/config_parse.y"
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
case 162:
#line 1014 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 164:
#line 1018 "../lib/config_parse.y"
{
		addressinit(&src);
	}
break;
case 165:
#line 1023 "../lib/config_parse.y"
{
		addressinit(&dst);
	}
break;
case 166:
#line 1028 "../lib/config_parse.y"
{
		addressinit(&rdr_from);
	}
break;
case 167:
#line 1033 "../lib/config_parse.y"
{
		addressinit(&rdr_to);
	}
break;
case 168:
#line 1040 "../lib/config_parse.y"
{
		addressinit(&gw);
	}
break;
case 181:
#line 1068 "../lib/config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address: %s", yyvsp[0].string);
	}
break;
case 182:
#line 1077 "../lib/config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask: %s", yyvsp[0].string);

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	}
break;
case 183:
#line 1084 "../lib/config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask: %s", yyvsp[0].string);
	}
break;
case 184:
#line 1090 "../lib/config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);
	}
break;
case 185:
#line 1099 "../lib/config_parse.y"
{
		*atype = SOCKS_ADDR_IFNAME;

		if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
			yyerror("interfacename too long");
		strcpy(ifname, yyvsp[0].string);
	}
break;
case 186:
#line 1109 "../lib/config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);

		route.state.direct = 1;
	}
break;
case 187:
#line 1120 "../lib/config_parse.y"
{ yyval.string = NULL; }
break;
case 193:
#line 1133 "../lib/config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	}
break;
case 194:
#line 1139 "../lib/config_parse.y"
{
		ruleaddress->portend		= htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator	= range;
	}
break;
case 195:
#line 1145 "../lib/config_parse.y"
{
		struct servent	*service;

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
case 196:
#line 1176 "../lib/config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	}
break;
#line 2040 "config_parse.c"
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
