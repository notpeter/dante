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
#line 45 "config_parse.y"

#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.184 2004/06/28 10:58:39 michaels Exp $";

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

#if SOCKS_CLIENT
static struct serverstate_t	state;
static struct route_t			route;			/* new route.							*/
static struct ruleaddress_t	gw;				/* new gateway.						*/
#endif


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
				yyerror("internal error");	\
			methodv[(*methodc)++] = method; \
		} \
	} while (0)

#line 170 "config_parse.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 178 "y.tab.c"
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
#define CHILD_MAXIDLENUMBER 290
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
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylhs[] =
#else
short socks_yylhs[] =
#endif
	{                                        -1,
    0,    0,   51,    1,    1,    1,    1,    1,    2,    2,
    2,    2,   25,   26,   26,   52,   52,   52,   52,   52,
   52,   52,   52,   52,   52,   50,   50,   50,   50,   50,
   50,    3,   59,   24,    7,    8,    8,    8,    8,    9,
    9,   10,   11,   12,   12,   31,   32,   33,   33,   34,
   35,   36,   37,   38,   38,   27,   27,   27,   39,   40,
   41,   41,   58,   53,   53,   53,   54,   55,   56,   57,
   29,   30,   28,   42,   43,   43,   44,   44,   14,   15,
   15,   15,   16,   17,   17,   18,   18,   47,   96,   45,
   97,   46,   49,   49,   49,   49,   49,   48,   48,   67,
   68,   69,   69,   64,   65,   65,   65,   65,   65,   65,
   66,   66,   70,   70,   70,   70,   70,   71,   71,   19,
   21,   21,   21,   21,   21,   20,   20,    4,    6,    6,
    5,    5,   72,   22,   22,   23,   73,   75,   75,   75,
   75,   75,   74,   74,   13,   76,   77,   78,   98,   99,
   61,   62,   62,   62,   62,   62,   63,   63,   87,   88,
  100,  101,   60,   79,   79,   79,   80,   80,   80,   81,
   81,   81,   83,   83,   83,   82,   89,   89,   84,   85,
   86,   90,   90,   90,   94,   94,   91,   92,  102,   95,
   93,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yylen[] =
#else
short socks_yylen[] =
#endif
	{                                         2,
    2,    2,    1,    0,    2,    2,    2,    2,    0,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    8,    0,    3,    1,    1,    1,    1,    1,
    2,    3,    1,    1,    2,    3,    1,    1,    2,    4,
    0,    4,    0,    3,    3,    1,    1,    1,    3,    1,
    1,    2,    3,    1,    1,    1,    3,    3,    3,    1,
    3,    3,    3,    3,    1,    1,    1,    2,    3,    1,
    1,    1,    3,    1,    1,    1,    2,    3,    0,    4,
    0,    4,    1,    1,    1,    1,    1,    1,    2,    7,
    1,    0,    2,    6,    1,    1,    1,    1,    1,    1,
    0,    2,    1,    1,    1,    1,    1,    1,    1,    3,
    1,    1,    1,    1,    1,    1,    2,    3,    1,    1,
    1,    2,    2,    2,    2,    3,    3,    1,    1,    1,
    1,    1,    1,    2,    3,    3,    3,    3,    3,    3,
    3,    1,    1,    1,    1,    1,    0,    2,    1,    1,
    1,    1,    1,    2,    2,    2,    1,    1,    1,    4,
    2,    2,    2,    2,    1,    1,    1,    1,    1,    1,
    1,    0,    3,    2,    1,    1,    3,    1,    1,    1,
    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydefred[] =
#else
short socks_yydefred[] =
#endif
	{                                      0,
    3,   13,    0,    9,    4,    0,    0,   32,    0,    0,
    0,   34,   10,   15,   58,   11,   14,   57,   56,   12,
    0,   51,   53,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  118,  119,    5,   18,   30,
   31,   29,   27,   28,   19,   20,   21,   22,   26,   16,
   17,   23,    6,   24,   64,   65,   66,   25,    8,    7,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   89,   91,    0,    0,    0,    0,    0,
    0,   73,   81,   82,   80,   79,   60,    0,   59,    0,
    0,    0,    0,   54,   55,   84,   85,    0,   83,   47,
    0,   46,   71,   72,    0,    0,   75,   76,    0,   74,
   70,   67,   68,   69,   63,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  108,  109,  117,  116,  107,
  110,  106,  113,    0,    0,  105,  115,  114,   62,  154,
  155,  152,  153,  156,    0,    0,    0,    0,  101,  176,
  179,  180,   50,    0,    0,    0,   52,  167,  168,  169,
   87,   49,   93,   94,   95,   96,   97,   90,    0,   92,
   78,    0,    0,    0,    0,    0,    0,    0,    0,  161,
  162,  134,  135,    0,    0,    0,  112,  159,    0,    0,
    0,  158,    0,  103,    0,    0,  164,  165,  166,   99,
   88,  145,  129,  130,  128,    0,   36,   37,   38,   39,
    0,   35,   43,    0,   42,  121,  122,  123,  124,  125,
  120,    0,  146,  138,  139,  140,  141,  142,  137,    0,
    0,    0,  136,    0,  160,  133,    0,    0,  163,    0,
    0,    0,  191,  188,  184,    0,    0,  132,   41,   45,
  127,  144,  149,    0,    0,    0,  150,  104,    0,  147,
    0,    0,  100,    0,  190,  186,  183,  185,    0,  171,
  172,  148,  181,    0,  151,    0,  175,   33,  189,  187,
  178,  177,    0,  173,  174,  170,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yydgoto[] =
#else
short socks_yydgoto[] =
#endif
	{                                       3,
    7,    6,   14,  126,  205,  206,  127,  211,  212,  128,
  214,  215,  129,   15,   86,   41,   98,   99,  130,  221,
  222,  131,  132,   65,    4,   16,   17,   18,   42,   43,
  143,  101,  102,   45,   67,   46,   68,   47,   19,   88,
   89,   49,  109,  110,   50,   51,  133,  168,  169,   52,
    5,   53,   54,   55,   56,   57,  112,   58,   20,  240,
  241,  145,  146,   59,  134,  135,   60,  147,  148,  136,
   61,  189,  137,  229,  230,  138,  190,  236,  153,  157,
  253,  254,  275,  255,  256,  277,  191,  237,  283,  197,
  245,  246,  247,  267,  268,  105,  106,  182,  183,  184,
  185,  280,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yysindex[] =
#else
short socks_yysindex[] =
#endif
	{                                   -152,
    0,    0,    0,    0,    0,  -10,  255,    0,  -29,  -26,
  -18,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -186,    0,    0,   -8,   -1,    3,    8,   18,   20,   43,
   62,   64,   73,   74,   75,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   11, -194, -199, -153,   14,   15,   81,   82, -250, -158,
 -129, -184, -183,    0,    0, -170, -141, -141, -141, -180,
 -252,    0,    0,    0,    0,    0,    0, -153,    0, -241,
 -256, -254, -254,    0,    0,    0,    0, -158,    0,    0,
 -129,    0,    0,    0, -193, -193,    0,    0, -170,    0,
    0,    0,    0,    0,    0,   90,   94,   95,   98,  100,
  101,  102,  103, -216,  104,    0,    0,    0,    0,    0,
    0,    0,    0, -252, -166,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -241, -166, -256, -166,    0,    0,
    0,    0,    0, -161, -161, -161,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -193,    0,
    0, -193, -159, -181, -266, -117, -219, -142, -224,    0,
    0,    0,    0,  115,  116, -150,    0,    0, -252, -147,
  131,    0, -102,    0, -256, -285,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -181,    0,    0,    0,    0,
 -266,    0,    0, -117,    0,    0,    0,    0,    0,    0,
    0, -219,    0,    0,    0,    0,    0,    0,    0, -224,
 -254, -254,    0,   66,    0,    0,  134, -254,    0,  139,
 -241,   76,    0,    0,    0,  153, -209,    0,    0,    0,
    0,    0,    0,  152, -161, -161,    0,    0, -254,    0,
 -277,   77,    0, -124,    0,    0,    0,    0, -295,    0,
    0,    0,    0, -161,    0, -161,    0,    0,    0,    0,
    0,    0, -161,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yyrindex[] =
#else
short socks_yyrindex[] =
#endif
	{                                      0,
    0,    0,    0,    0,    0,  204,  205,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -116,    0,    0,    0,    0,    0,    0,  111,    0, -115,
 -113,    0,    0,    0,    0,    0,    0,  147,    0,    0,
   63,    0,    0,    0,    0,    0,    0,    0,  183,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -123,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -122,    0, -121,    0,    0,    0,
    0,    0,    0,  219,  219,  219,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    1,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   91,    0,
    0,    0,    0,    0,   93,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  -74,    0,    0,    0,    0,
  257,    0,    0,  305,    0,    0,    0,    0,    0,    0,
    0,  264,    0,    0,    0,    0,    0,    0,    0,  328,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   99,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -120, -120,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -119,    0, -119,    0,    0,    0,    0,
    0,    0, -120,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yygindex[] =
#else
short socks_yygindex[] =
#endif
	{                                      0,
    0,    0,  199,  -78,   17,    0,  -75,    0,    9,    0,
    0,   13,    0,  218,    0,    0,    0,  130,  -73,   12,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  223,    0,  132,    0,    0,    0,    0,    0,  228,    0,
  148,    0,    0,  128,    0,    0,  -71,  -90,    0,    0,
    0,    0,    0,    0,    0,    0,   49,    0,    0,    0,
    0,    0, -138,    0,    0, -114,    0,    0, -139,  -70,
  217,  -44,    0,   16,    0,    0,    0,    0,    0,    0,
 -207,  -83,    0,  -79,   37,    0,    0,    0,    0, -132,
    0,   -6,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,
};
#define YYTABLESIZE 661
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yytable[] =
#else
short socks_yytable[] =
#endif
	{                                      13,
   98,  111,  157,  102,  182,  182,  192,  194,  154,  158,
   98,  140,  155,  159,  141,  170,  142,  116,  144,  187,
  149,  116,  198,  199,  257,   94,  281,   26,   62,  243,
  260,   63,  116,  282,  207,  208,  209,  210,  117,   64,
   95,  244,  117,  118,  150,  151,  273,  119,  120,   69,
  131,  272,  120,  121,  118,  242,   70,  122,  119,  123,
   71,  122,   48,  123,  121,   72,  140,  150,  151,  141,
  152,  142,   48,  144,  234,   73,  149,   74,  200,  124,
  125,  201,  163,  164,  165,  166,  167,  216,  217,  218,
  219,  220,  224,  225,  226,  227,  228,   83,   84,   85,
   75,  193,  262,  195,    1,    2,   36,   37,   96,   97,
   61,  107,  108,  180,  181,  203,  204,  244,  265,   76,
   61,   77,  270,  271,  149,   98,  113,  114,  156,  160,
   78,   79,   80,   81,   82,   87,   90,   91,   92,   93,
  100,  284,  111,  285,  103,  104,   86,  172,  115,  182,
  286,  173,  174,  182,  182,  175,   86,  176,  177,  178,
  179,  186,  140,  188,  196,  141,  213,  142,  202,  144,
  223,  182,  231,  232,  182,  182,  182,  274,  233,  182,
  182,  276,   77,  235,  182,  182,  182,   48,  238,  239,
  258,  259,   77,  182,  131,  182,  261,  264,  269,  131,
  263,  278,  279,    2,    1,   39,  111,  157,  102,  182,
  182,  182,  182,  111,  157,  111,  102,  102,  182,  249,
  131,  131,  248,  157,   40,  131,  250,  161,  182,   44,
  131,  131,  162,  251,   48,  139,  171,   66,    0,  131,
  266,  131,    0,    0,    0,  252,    0,    0,    8,    0,
    0,    0,    0,    9,   10,  131,    0,  131,  131,   98,
   98,   98,   98,   98,   38,   98,   98,    0,    0,   98,
    0,    0,   98,   98,   98,   98,    0,   11,    0,    0,
   12,   98,    0,    0,    0,   98,   98,   98,   98,    0,
   98,    0,    0,   98,   98,   98,   98,    0,    0,    0,
   98,    0,    0,    0,    0,   98,   98,    0,    0,    0,
    0,    0,    0,    0,   98,    0,   98,    0,    0,    0,
    0,   48,   48,   48,   48,   48,    0,   48,   48,    0,
   98,   48,   98,   98,   48,   48,   48,   48,    0,    0,
    0,    0,    0,   48,    0,    0,    0,   48,   48,   48,
   48,    0,   48,    0,    0,   48,   48,    0,   48,    0,
    0,    0,   48,    0,    0,    0,    0,    0,   48,   61,
   61,   61,   61,   61,   61,   61,   61,    0,    0,   61,
    0,   40,   61,   61,   61,   61,    0,    0,  126,    0,
    0,   61,   48,    0,    0,   61,   61,   61,   61,    0,
   61,   61,    0,   61,   61,   86,   86,   86,   86,   86,
    0,   86,   86,    0,    0,   86,    0,    0,   86,   86,
   86,   86,    0,    0,    0,    0,    0,   86,    0,   44,
    0,   86,   86,   86,   86,    0,   86,    0,    0,   86,
   86,   77,   77,   77,   77,   77,    0,   77,   77,    0,
    0,   77,  143,    0,   77,   77,   77,   77,    0,    0,
    0,    0,    0,   77,    0,    0,    0,   77,   77,   77,
   77,    0,   77,    0,    0,   77,   77,  182,  182,  182,
  182,  182,    0,  182,  182,    0,    0,  182,    0,    0,
  182,  182,  182,  182,    0,    0,    0,    0,    0,  182,
    0,    0,    0,  182,  182,  182,  182,    0,  182,    0,
    0,  182,  182,    8,   21,   22,   23,   24,    0,   10,
   25,    0,    0,   26,    0,   40,   27,   28,   29,   30,
   40,    0,  126,    0,    0,   31,    0,  126,    0,   32,
   33,   34,   11,    0,   35,    0,    0,   36,   37,    0,
    0,   40,   40,    0,    0,    0,   40,    0,  126,  126,
    0,   40,   40,  126,    0,    0,    0,    0,  126,  126,
   40,    0,   40,    0,    0,    0,    0,  126,   44,  126,
    0,    0,    0,    0,    0,    0,   40,    0,   40,   40,
    0,    0,    0,  126,    0,  126,  126,    0,    0,   44,
   44,  143,    0,    0,   44,    0,    0,    0,    0,   44,
   44,    0,    0,    0,    0,    0,    0,    0,   44,    0,
   44,    0,  143,  143,    0,    0,    0,  143,    0,    0,
    0,    0,  143,  143,   44,    0,   44,   44,    0,    0,
    0,  143,    0,  143,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  143,    0,  143,
  143,
};
#if defined(__cplusplus) || defined(__STDC__)
const short socks_yycheck[] =
#else
short socks_yycheck[] =
#endif
	{                                      10,
    0,  125,  125,  125,  125,  125,  145,  147,   92,   93,
   10,   90,   92,   93,   90,  106,   90,  274,   90,  134,
   91,  274,  155,  156,  232,  276,  322,  269,   58,  315,
  238,   58,  274,  329,  301,  302,  303,  304,  295,   58,
  291,  327,  295,  296,  322,  323,  324,  300,  305,   58,
  125,  259,  305,  306,  296,  195,   58,  314,  300,  316,
   58,  314,    0,  316,  306,   58,  145,  322,  323,  145,
  325,  145,   10,  145,  189,   58,  147,   58,  169,  332,
  333,  172,  276,  277,  278,  279,  280,  307,  308,  309,
  310,  311,  317,  318,  319,  320,  321,  297,  298,  299,
   58,  146,  241,  148,  257,  258,  293,  294,  267,  268,
    0,  282,  283,  330,  331,  297,  298,  327,  328,   58,
   10,   58,  255,  256,  195,  125,   78,   79,   92,   93,
   58,   58,   58,  123,  329,  289,  123,  123,   58,   58,
  270,  274,  284,  276,  329,  329,    0,   58,  329,  269,
  283,   58,   58,  274,  274,   58,   10,   58,   58,   58,
   58,   58,  241,  330,  326,  241,  284,  241,  328,  241,
  313,  292,   58,   58,  295,  296,  296,  261,  329,  300,
  300,  261,    0,  331,  305,  306,  306,  125,   58,  292,
  125,   58,   10,  314,  269,  316,   58,   45,   47,  274,
  125,  125,  327,    0,    0,    7,  330,  330,  330,  330,
  331,  332,  333,  330,  330,  125,  330,  125,    0,  211,
  295,  296,  206,  125,    7,  300,  214,   98,   10,    7,
  305,  306,  101,  222,    7,   88,  109,   21,   -1,  314,
  247,  316,   -1,   -1,   -1,  230,   -1,   -1,  259,   -1,
   -1,   -1,   -1,  264,  265,  330,   -1,  332,  333,  259,
  260,  261,  262,  263,   10,  265,  266,   -1,   -1,  269,
   -1,   -1,  272,  273,  274,  275,   -1,  288,   -1,   -1,
  291,  281,   -1,   -1,   -1,  285,  286,  287,  288,   -1,
  290,   -1,   -1,  293,  294,  295,  296,   -1,   -1,   -1,
  300,   -1,   -1,   -1,   -1,  305,  306,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  314,   -1,  316,   -1,   -1,   -1,
   -1,  259,  260,  261,  262,  263,   -1,  265,  266,   -1,
  330,  269,  332,  333,  272,  273,  274,  275,   -1,   -1,
   -1,   -1,   -1,  281,   -1,   -1,   -1,  285,  286,  287,
  288,   -1,  290,   -1,   -1,  293,  294,   -1,  296,   -1,
   -1,   -1,  300,   -1,   -1,   -1,   -1,   -1,  306,  259,
  260,  261,  262,  263,  264,  265,  266,   -1,   -1,  269,
   -1,  125,  272,  273,  274,  275,   -1,   -1,  125,   -1,
   -1,  281,  330,   -1,   -1,  285,  286,  287,  288,   -1,
  290,  291,   -1,  293,  294,  259,  260,  261,  262,  263,
   -1,  265,  266,   -1,   -1,  269,   -1,   -1,  272,  273,
  274,  275,   -1,   -1,   -1,   -1,   -1,  281,   -1,  125,
   -1,  285,  286,  287,  288,   -1,  290,   -1,   -1,  293,
  294,  259,  260,  261,  262,  263,   -1,  265,  266,   -1,
   -1,  269,  125,   -1,  272,  273,  274,  275,   -1,   -1,
   -1,   -1,   -1,  281,   -1,   -1,   -1,  285,  286,  287,
  288,   -1,  290,   -1,   -1,  293,  294,  259,  260,  261,
  262,  263,   -1,  265,  266,   -1,   -1,  269,   -1,   -1,
  272,  273,  274,  275,   -1,   -1,   -1,   -1,   -1,  281,
   -1,   -1,   -1,  285,  286,  287,  288,   -1,  290,   -1,
   -1,  293,  294,  259,  260,  261,  262,  263,   -1,  265,
  266,   -1,   -1,  269,   -1,  269,  272,  273,  274,  275,
  274,   -1,  269,   -1,   -1,  281,   -1,  274,   -1,  285,
  286,  287,  288,   -1,  290,   -1,   -1,  293,  294,   -1,
   -1,  295,  296,   -1,   -1,   -1,  300,   -1,  295,  296,
   -1,  305,  306,  300,   -1,   -1,   -1,   -1,  305,  306,
  314,   -1,  316,   -1,   -1,   -1,   -1,  314,  274,  316,
   -1,   -1,   -1,   -1,   -1,   -1,  330,   -1,  332,  333,
   -1,   -1,   -1,  330,   -1,  332,  333,   -1,   -1,  295,
  296,  274,   -1,   -1,  300,   -1,   -1,   -1,   -1,  305,
  306,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  314,   -1,
  316,   -1,  295,  296,   -1,   -1,   -1,  300,   -1,   -1,
   -1,   -1,  305,  306,  330,   -1,  332,  333,   -1,   -1,
   -1,  314,   -1,  316,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  330,   -1,  332,
  333,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 333
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
"USER_LIBWRAP","LOGOUTPUT","LOGFILE","CHILD_MAXIDLENUMBER","ROUTE","VIA",
"VERDICT_BLOCK","VERDICT_PASS","PAMSERVICENAME","PROTOCOL","PROTOCOL_TCP",
"PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4",
"PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2","PROXYPROTOCOL_HTTP_V1_0",
"USER","COMMAND","COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE",
"COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE","LIBWRAPSTART",
"OPERATOR","LOG","LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR",
"LOG_IOOPERATION","IPADDRESS","DOMAINNAME","DIRECT","IFNAME","PORT",
"PORTNUMBER","SERVICENAME","NUMBER","FROM","TO","REDIRECT","BANDWIDTH",
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
"childstate : CHILD_MAXIDLENUMBER ':' NUMBER",
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
#line 1180 "config_parse.y"

#define INTERACTIVE		0

extern FILE *yyin;

int socks_parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";
	const int errno_s = errno;

/*	yydebug				= 1;          */
	yylineno				= 1;
	socks_parseinit	= 0;

	if ((yyin = fopen(filename, "r")) == NULL) {
		swarn("%s: %s", function, filename);
		return -1;
	}

	yyparse();
	fclose(yyin);

#if SOCKS_SERVER
	fixconfig();
#endif /* SOCKS_SERVER */

	errno = errno_s; /* some buggy yacc's alter errno sometimes. */

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
#line 1023 "y.tab.c"
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
#line 276 "config_parse.y"
{
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &sockscf.extension;
#endif
	}
break;
case 4:
#line 285 "config_parse.y"
{ yyval.string = NULL; }
break;
case 9:
#line 292 "config_parse.y"
{ yyval.string = NULL; }
break;
case 13:
#line 299 "config_parse.y"
{
	}
break;
case 32:
#line 328 "config_parse.y"
{
		yywarn("given keyword is deprecated");
	}
break;
case 33:
#line 332 "config_parse.y"
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
case 34:
#line 344 "config_parse.y"
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
case 36:
#line 368 "config_parse.y"
{
			proxyprotocol->socks_v4		= 1;
	}
break;
case 37:
#line 371 "config_parse.y"
{
			proxyprotocol->socks_v5		= 1;
	}
break;
case 38:
#line 374 "config_parse.y"
{
			proxyprotocol->msproxy_v2	= 1;
	}
break;
case 39:
#line 377 "config_parse.y"
{
			proxyprotocol->http_v1_0	= 1;
	}
break;
case 43:
#line 389 "config_parse.y"
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
case 47:
#line 408 "config_parse.y"
{
			extension->bind = 1;
	}
break;
case 50:
#line 418 "config_parse.y"
{
#if SOCKS_SERVER
		addinternal(ruleaddress);
#endif
	}
break;
case 51:
#line 425 "config_parse.y"
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
case 52:
#line 441 "config_parse.y"
{
#if SOCKS_SERVER
		addexternal(ruleaddress);
#endif
	}
break;
case 53:
#line 448 "config_parse.y"
{
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		addressinit(&mem);
#endif
	}
break;
case 54:
#line 457 "config_parse.y"
{
#if SOCKS_SERVER
		sockscf.external.rotation = ROTATION_NONE;
	}
break;
case 55:
#line 461 "config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
		yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
		sockscf.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
	}
break;
case 60:
#line 479 "config_parse.y"
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
				/*
				 * Can't change filenames we log to after startup (well,
				 * to be exact, we can't add new filenames, but we complain
				 * about changing too for now since it's easier.
				 */
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
				size_t i;

				for (i = 0; i < sockscf.log.fpc; ++i)
					if (strcmp(sockscf.log.fnamev[i], yyvsp[0].string) == 0) {

						if (fileno(sockscf.log.fpv[i]) == fileno(stdout)
						||	 fileno(sockscf.log.fpv[i]) == fileno(stderr))
							break;

						/* reopen logfiles. */
						fclose(sockscf.log.fpv[i]);
						if ((sockscf.log.fpv[i]
						= fopen(sockscf.log.fnamev[i], "a")) == NULL)
							yyerror("fopen(%s)", yyvsp[0].string);
						break;
					}

				if (i == sockscf.log.fpc) /* no match found. */
					yywarn("can't change logoutput after startup");
			}
	}
break;
case 63:
#line 579 "config_parse.y"
{
#if SOCKS_SERVER
		if (atoi(yyvsp[0].string) < SOCKD_FREESLOTS)
			yyerror("child.maxidlenumber can't be less than SOCKD_FREESLOTS (%d)",
			SOCKD_FREESLOTS);

		sockscf.child.maxidlenumber = atoi(yyvsp[0].string);
#endif
	}
break;
case 67:
#line 596 "config_parse.y"
{
#if SOCKS_SERVER
		sockscf.uid.privileged			= yyvsp[0].uid;
		sockscf.uid.privileged_isset	= 1;
#endif
	}
break;
case 68:
#line 604 "config_parse.y"
{
#if SOCKS_SERVER
		sockscf.uid.unprivileged			= yyvsp[0].uid;
		sockscf.uid.unprivileged_isset	= 1;
#endif
	}
break;
case 69:
#line 612 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		sockscf.uid.libwrap			= yyvsp[0].uid;
		sockscf.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 70:
#line 623 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	}
break;
case 71:
#line 633 "config_parse.y"
{
#if SOCKS_SERVER
		sockscf.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 72:
#line 640 "config_parse.y"
{
#if SOCKS_SERVER
		sockscf.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 73:
#line 647 "config_parse.y"
{
		sockscf.option.debug = atoi(yyvsp[0].string);
	}
break;
case 75:
#line 655 "config_parse.y"
{
#if SOCKS_SERVER
		sockscf.compat.reuseaddr = 1;
	}
break;
case 76:
#line 659 "config_parse.y"
{
		sockscf.compat.sameport = 1;
#endif
	}
break;
case 80:
#line 672 "config_parse.y"
{
			sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
break;
case 81:
#line 675 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
break;
case 82:
#line 682 "config_parse.y"
{
			sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
break;
case 84:
#line 690 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			sockscf.srchost.nomismatch = 1;
	}
break;
case 85:
#line 694 "config_parse.y"
{
			sockscf.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
break;
case 89:
#line 710 "config_parse.y"
{
#if SOCKS_SERVER
	methodv = sockscf.methodv;
	methodc = &sockscf.methodc;
	*methodc = 0; /* reset. */
#endif
	}
break;
case 91:
#line 719 "config_parse.y"
{
#if SOCKS_SERVER
	methodv = sockscf.clientmethodv;
	methodc = &sockscf.clientmethodc;
	*methodc = 0; /* reset. */
#endif
	}
break;
case 93:
#line 728 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	}
break;
case 94:
#line 731 "config_parse.y"
{
		yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
	}
break;
case 95:
#line 734 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
break;
case 96:
#line 737 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method %s requires libwraplibrary", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
	}
break;
case 97:
#line 744 "config_parse.y"
{
#if !HAVE_PAM
		yyerror("method %s requires pamlibrary", AUTHMETHOD_PAMs);
#else /* HAVE_PAM */
		ADDMETHOD(AUTHMETHOD_PAM);
#endif /* !HAVE_PAM */
	}
break;
case 100:
#line 760 "config_parse.y"
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
case 102:
#line 776 "config_parse.y"
{ yyval.string = NULL; }
break;
case 104:
#line 780 "config_parse.y"
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
case 106:
#line 794 "config_parse.y"
{
#if SOCKS_SERVER
			checkmodule("bandwidth");
#endif
	}
break;
case 110:
#line 802 "config_parse.y"
{
#if SOCKS_SERVER
			checkmodule("redirect");
#endif
	}
break;
case 111:
#line 809 "config_parse.y"
{ yyval.string = NULL; }
break;
case 118:
#line 820 "config_parse.y"
{
#if SOCKS_SERVER
		ruleinit(&rule);
		rule.verdict	= VERDICT_BLOCK;
	}
break;
case 119:
#line 825 "config_parse.y"
{
		ruleinit(&rule);
		rule.verdict	= VERDICT_PASS;
#endif
	}
break;
case 121:
#line 836 "config_parse.y"
{
			command->bind = 1;
	}
break;
case 122:
#line 839 "config_parse.y"
{
			command->connect = 1;
	}
break;
case 123:
#line 842 "config_parse.y"
{
			command->udpassociate = 1;
	}
break;
case 124:
#line 848 "config_parse.y"
{
			command->bindreply = 1;
	}
break;
case 125:
#line 852 "config_parse.y"
{
			command->udpreply = 1;
	}
break;
case 129:
#line 864 "config_parse.y"
{
		protocol->tcp = 1;
	}
break;
case 130:
#line 867 "config_parse.y"
{
		protocol->udp = 1;
	}
break;
case 136:
#line 884 "config_parse.y"
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
case 138:
#line 906 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
break;
case 139:
#line 910 "config_parse.y"
{
			rule.log.data = 1;
	}
break;
case 140:
#line 913 "config_parse.y"
{
			rule.log.disconnect = 1;
	}
break;
case 141:
#line 916 "config_parse.y"
{
			rule.log.error = 1;
	}
break;
case 142:
#line 919 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	}
break;
case 145:
#line 930 "config_parse.y"
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
case 146:
#line 941 "config_parse.y"
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
case 157:
#line 991 "config_parse.y"
{ yyval.string = NULL; }
break;
case 159:
#line 995 "config_parse.y"
{
		addressinit(&src);
	}
break;
case 160:
#line 1000 "config_parse.y"
{
		addressinit(&dst);
	}
break;
case 161:
#line 1005 "config_parse.y"
{
		addressinit(&rdr_from);
	}
break;
case 162:
#line 1010 "config_parse.y"
{
		addressinit(&rdr_to);
	}
break;
case 163:
#line 1017 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	}
break;
case 176:
#line 1047 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address: %s", yyvsp[0].string);
	}
break;
case 177:
#line 1056 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask: %d", yyvsp[0].string);

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	}
break;
case 178:
#line 1063 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask: %s", yyvsp[0].string);
	}
break;
case 179:
#line 1069 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);
	}
break;
case 180:
#line 1078 "config_parse.y"
{
		*atype = SOCKS_ADDR_IFNAME;

		if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
			yyerror("interfacename too long");
		strcpy(ifname, yyvsp[0].string);
	}
break;
case 181:
#line 1088 "config_parse.y"
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
case 182:
#line 1101 "config_parse.y"
{ yyval.string = NULL; }
break;
case 188:
#line 1114 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	}
break;
case 189:
#line 1120 "config_parse.y"
{
		ruleaddress->portend		= htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator	= range;
	}
break;
case 190:
#line 1126 "config_parse.y"
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
case 191:
#line 1174 "config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	}
break;
#line 2029 "y.tab.c"
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
