#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ == 2
  __attribute__ ((unused))
#endif /* __GNUC__ == 2 */
  = "$OpenBSD: skeleton.c,v 1.16 2001/02/26 00:03:33 tholo Exp $";
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
"$Id: config_parse.y,v 1.176 2001/11/11 13:38:24 michaels Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

#if SOCKS_SERVER
static void
ruleinit __P((struct rule_t *rule));
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

#line 166 "config_parse.y"
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#line 171 "y.tab.c"
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
#define ROUTE 290
#define VIA 291
#define VERDICT_BLOCK 292
#define VERDICT_PASS 293
#define PAMSERVICENAME 294
#define PROTOCOL 295
#define PROTOCOL_TCP 296
#define PROTOCOL_UDP 297
#define PROTOCOL_FAKE 298
#define PROXYPROTOCOL 299
#define PROXYPROTOCOL_SOCKS_V4 300
#define PROXYPROTOCOL_SOCKS_V5 301
#define PROXYPROTOCOL_MSPROXY_V2 302
#define PROXYPROTOCOL_HTTP_V1_0 303
#define USER 304
#define COMMAND 305
#define COMMAND_BIND 306
#define COMMAND_CONNECT 307
#define COMMAND_UDPASSOCIATE 308
#define COMMAND_BINDREPLY 309
#define COMMAND_UDPREPLY 310
#define ACTION 311
#define LINE 312
#define LIBWRAPSTART 313
#define OPERATOR 314
#define LOG 315
#define LOG_CONNECT 316
#define LOG_DATA 317
#define LOG_DISCONNECT 318
#define LOG_ERROR 319
#define LOG_IOOPERATION 320
#define IPADDRESS 321
#define DOMAINNAME 322
#define DIRECT 323
#define IFNAME 324
#define PORT 325
#define PORTNUMBER 326
#define SERVICENAME 327
#define NUMBER 328
#define FROM 329
#define TO 330
#define REDIRECT 331
#define BANDWIDTH 332
#define YYERRCODE 256
short socks_yylhs[] = {                                        -1,
    0,    0,   51,    1,    1,    1,    1,    1,    2,    2,
    2,    2,   25,   26,   26,   52,   52,   52,   52,   52,
   52,   52,   52,   52,   50,   50,   50,   50,   50,   50,
    3,   58,   24,    7,    8,    8,    8,    8,    9,    9,
   10,   11,   12,   12,   31,   32,   33,   33,   34,   35,
   36,   37,   38,   38,   27,   27,   27,   39,   40,   41,
   41,   53,   53,   53,   54,   55,   56,   57,   29,   30,
   28,   42,   43,   43,   44,   44,   14,   15,   15,   15,
   16,   17,   17,   18,   18,   47,   95,   45,   96,   46,
   49,   49,   49,   49,   49,   48,   48,   66,   67,   68,
   68,   63,   64,   64,   64,   64,   64,   64,   65,   65,
   69,   69,   69,   69,   69,   70,   70,   19,   21,   21,
   21,   21,   21,   20,   20,    4,    6,    6,    5,    5,
   71,   22,   22,   23,   72,   74,   74,   74,   74,   74,
   73,   73,   13,   75,   76,   77,   97,   98,   60,   61,
   61,   61,   61,   61,   62,   62,   86,   87,   99,  100,
   59,   78,   78,   78,   79,   79,   79,   80,   80,   80,
   82,   82,   82,   81,   88,   88,   83,   84,   85,   89,
   89,   89,   93,   93,   90,   91,  101,   94,   92,
};
short socks_yylen[] = {                                         2,
    2,    2,    1,    0,    2,    2,    2,    2,    0,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    8,    0,    3,    1,    1,    1,    1,    1,    2,
    3,    1,    1,    2,    3,    1,    1,    2,    4,    0,
    4,    0,    3,    3,    1,    1,    1,    3,    1,    1,
    2,    1,    1,    1,    3,    3,    3,    1,    3,    3,
    3,    3,    1,    1,    1,    2,    3,    1,    1,    1,
    3,    1,    1,    1,    2,    3,    0,    4,    0,    4,
    1,    1,    1,    1,    1,    1,    2,    7,    1,    0,
    2,    6,    1,    1,    1,    1,    1,    1,    0,    2,
    1,    1,    1,    1,    1,    1,    1,    3,    1,    1,
    1,    1,    1,    1,    2,    3,    1,    1,    1,    2,
    2,    2,    2,    3,    3,    1,    1,    1,    1,    1,
    1,    2,    3,    3,    3,    3,    3,    3,    3,    1,
    1,    1,    1,    1,    0,    2,    1,    1,    1,    1,
    1,    2,    2,    2,    1,    1,    1,    4,    2,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    0,
    3,    2,    1,    1,    3,    1,    1,    1,    1,
};
short socks_yydefred[] = {                                      0,
    3,   13,    0,    9,    4,    0,    0,   31,    0,    0,
    0,   33,   10,   15,   57,   11,   14,   56,   55,   12,
    0,   50,   52,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  116,  117,    5,   18,   29,   30,
   28,   26,   27,   19,   20,   21,   22,   25,   16,   17,
   23,    6,   24,   62,   63,   64,    8,    7,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   87,   89,    0,    0,    0,    0,    0,   71,   79,
   80,   78,   77,   59,    0,   58,    0,    0,    0,    0,
   53,   54,   82,   83,    0,   81,   46,    0,   45,   69,
   70,    0,    0,   73,   74,    0,   72,   68,   65,   66,
   67,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  106,  107,  115,  114,  105,  108,  104,  111,    0,
    0,  103,  113,  112,   61,  152,  153,  150,  151,  154,
    0,    0,    0,    0,   99,  174,  177,  178,   49,    0,
    0,    0,   51,  165,  166,  167,   85,   48,   91,   92,
   93,   94,   95,   88,    0,   90,   76,    0,    0,    0,
    0,    0,    0,    0,    0,  159,  160,  132,  133,    0,
    0,    0,  110,  157,    0,    0,    0,  156,    0,  101,
    0,    0,  162,  163,  164,   97,   86,  143,  127,  128,
  126,    0,   35,   36,   37,   38,    0,   34,   42,    0,
   41,  119,  120,  121,  122,  123,  118,    0,  144,  136,
  137,  138,  139,  140,  135,    0,    0,    0,  134,    0,
  158,  131,    0,    0,  161,    0,    0,    0,  189,  186,
  182,    0,    0,  130,   40,   44,  125,  142,  147,    0,
    0,    0,  148,  102,    0,  145,    0,    0,   98,    0,
  188,  184,  181,  183,    0,  169,  170,  146,  179,    0,
  149,    0,  173,   32,  187,  185,  176,  175,    0,  171,
  172,  168,
};
short socks_yydgoto[] = {                                       3,
    7,    6,   14,  122,  201,  202,  123,  207,  208,  124,
  210,  211,  125,   15,   83,   40,   95,   96,  126,  217,
  218,  127,  128,   63,    4,   16,   17,   18,   41,   42,
  139,   98,   99,   44,   65,   45,   66,   46,   19,   85,
   86,   48,  106,  107,   49,   50,  129,  164,  165,   51,
    5,   52,   53,   54,   55,   56,  109,   20,  236,  237,
  141,  142,   57,  130,  131,   58,  143,  144,  132,   59,
  185,  133,  225,  226,  134,  186,  232,  149,  153,  249,
  250,  271,  251,  252,  273,  187,  233,  279,  193,  241,
  242,  243,  263,  264,  102,  103,  178,  179,  180,  181,
  276,
};
short socks_yysindex[] = {                                   -151,
    0,    0,    0,    0,    0,  -10,  249,    0,  -21,  -18,
  -15,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -182,    0,    0,   -9,   -4,    2,   16,   18,   23,   30,
   50,   60,   74,   75,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -65, -194,
 -245, -154,   13,   14,   80,   81, -248, -155, -130, -183,
 -181,    0,    0, -168, -142, -142, -142, -249,    0,    0,
    0,    0,    0,    0, -154,    0, -230, -226, -286, -286,
    0,    0,    0,    0, -155,    0,    0, -130,    0,    0,
    0, -186, -186,    0,    0, -168,    0,    0,    0,    0,
    0,   88,   90,   91,   94,   98,   99,  101,  102, -213,
  103,    0,    0,    0,    0,    0,    0,    0,    0, -249,
 -167,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -230, -167, -226, -167,    0,    0,    0,    0,    0, -161,
 -161, -161,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -186,    0,    0, -186, -158, -176,
 -270, -110, -211, -139, -215,    0,    0,    0,    0,  117,
  120, -143,    0,    0, -249, -144,  138,    0,  -94,    0,
 -226, -285,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -176,    0,    0,    0,    0, -270,    0,    0, -110,
    0,    0,    0,    0,    0,    0,    0, -211,    0,    0,
    0,    0,    0,    0,    0, -215, -286, -286,    0,   73,
    0,    0,  141, -286,    0,  142, -230,   78,    0,    0,
    0,  160, -202,    0,    0,    0,    0,    0,    0,  166,
 -161, -161,    0,    0, -286,    0, -237,   92,    0, -107,
    0,    0,    0,    0, -294,    0,    0,    0,    0, -161,
    0, -161,    0,    0,    0,    0,    0,    0, -161,    0,
    0,    0,
};
short socks_yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,  215,  216,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -106,    0,    0,
    0,    0,    0,    0,  109,    0, -103, -102,    0,    0,
    0,    0,    0,    0,  144,    0,    0,   62,    0,    0,
    0,    0,    0,    0,    0,  179,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -119,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -118,    0, -117,    0,    0,    0,    0,    0,    0,  214,
  214,  214,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    1,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   97,    0,    0,    0,    0,    0,
  100,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -111,    0,    0,    0,    0,  251,    0,    0,  310,
    0,    0,    0,    0,    0,    0,    0,  264,    0,    0,
    0,    0,    0,    0,    0,  325,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  104,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -123, -123,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -104,
    0, -104,    0,    0,    0,    0,    0,    0, -123,    0,
    0,    0,
};
short socks_yygindex[] = {                                      0,
    0,    0,  221,  -84,   28,    0,  -82,    0,   24,    0,
    0,   22,    0,  226,    0,    0,    0,  139,  -71,   17,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  229,    0,  140,    0,    0,    0,    0,    0,  230,    0,
  154,    0,    0,  134,    0,    0,  -70,  -88,    0,    0,
    0,    0,    0,    0,    0,    0,   52,    0,    0,    0,
    0, -137,    0,    0, -112,    0,    0, -124,  -64,  220,
  -81,    0,   19,    0,    0,    0,    0,    0,    0, -208,
  -80,    0,  -77,   41,    0,    0,    0,    0, -129,    0,
   -1,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,
};
#define YYTABLESIZE 657
short socks_yytable[] = {                                      13,
   96,  180,  136,  188,  137,  109,  155,  100,  150,  154,
   96,  151,  155,  129,  166,  138,  140,  183,  190,  253,
  180,  194,  195,  145,  112,  256,  277,   91,  239,  203,
  204,  205,  206,  278,  146,  147,   60,  148,   26,   61,
  240,   92,   62,  112,  113,  114,  268,  112,   67,  115,
   80,   81,   82,   68,  116,  117,  136,   78,  137,   69,
  189,   47,  191,  118,  114,  119,  238,  113,  115,  138,
  140,   47,  230,   70,  117,   71,  196,  116,  145,  197,
   72,  120,  121,  146,  147,  269,  118,   73,  119,  159,
  160,  161,  162,  163,  212,  213,  214,  215,  216,  258,
  220,  221,  222,  223,  224,    1,    2,   74,   60,   35,
   36,   93,   94,  104,  105,  176,  177,   75,   60,  199,
  200,  266,  267,  240,  261,   96,  145,  110,  111,  152,
  156,   76,   77,   79,   84,   87,   88,   89,   90,   97,
  280,  108,  281,   84,  100,  168,  101,  169,  170,  282,
  180,  171,  136,   84,  137,  172,  173,  129,  174,  175,
  182,  184,  129,  192,  180,  138,  140,  180,  198,  180,
  180,  180,  219,  209,  227,  180,  270,  228,   75,  272,
  180,  180,  129,  129,  229,  231,   47,  129,   75,  180,
  180,  180,  129,  129,  180,  234,  235,  254,  255,  257,
  180,  129,  259,  129,  260,  180,  180,  180,  180,  109,
  155,  100,  265,  180,    2,    1,  274,  129,  275,  129,
  129,  109,  109,  180,  100,  155,  100,   38,  155,  244,
  245,  246,   39,  157,  247,   43,   47,  158,  135,  167,
   64,  262,    0,    0,  248,    0,    0,    0,    8,    0,
    0,    0,    0,    9,   10,    0,    0,    0,   37,   96,
   96,   96,   96,   96,    0,   96,   96,    0,    0,   96,
    0,    0,   96,   96,   96,   96,    0,   11,    0,   12,
    0,   96,    0,    0,    0,   96,   96,   96,   96,    0,
    0,    0,   96,   96,   96,   96,    0,    0,    0,   96,
    0,    0,    0,    0,   96,   96,    0,    0,    0,    0,
    0,    0,    0,   96,    0,   96,    0,    0,    0,    0,
   47,   47,   47,   47,   47,    0,   47,   47,    0,   96,
   47,   96,   96,   47,   47,   47,   47,    0,    0,    0,
    0,    0,   47,    0,    0,    0,   47,   47,   47,   47,
    0,    0,    0,   47,   47,    0,   47,    0,    0,    0,
   47,    0,    0,    0,    0,    0,   47,   60,   60,   60,
   60,   60,   60,   60,   60,   39,    0,   60,    0,    0,
   60,   60,   60,   60,    0,    0,    0,    0,  124,   60,
   47,    0,    0,   60,   60,   60,   60,    0,   60,    0,
   60,   60,   84,   84,   84,   84,   84,    0,   84,   84,
    0,    0,   84,    0,    0,   84,   84,   84,   84,    0,
    0,    0,    0,    0,   84,    0,    0,    0,   84,   84,
   84,   84,    0,    0,   43,   84,   84,   75,   75,   75,
   75,   75,    0,   75,   75,    0,    0,   75,    0,  141,
   75,   75,   75,   75,    0,    0,    0,    0,    0,   75,
    0,    0,    0,   75,   75,   75,   75,    0,    0,    0,
   75,   75,  180,  180,  180,  180,  180,    0,  180,  180,
    0,    0,  180,    0,    0,  180,  180,  180,  180,    0,
    0,    0,    0,    0,  180,    0,    0,    0,  180,  180,
  180,  180,    0,    0,    0,  180,  180,    8,   21,   22,
   23,   24,    0,   10,   25,    0,    0,   26,    0,   39,
   27,   28,   29,   30,   39,    0,    0,    0,    0,   31,
    0,    0,  124,   32,   33,   34,   11,  124,    0,    0,
   35,   36,    0,    0,   39,   39,    0,    0,    0,   39,
    0,    0,    0,    0,   39,   39,    0,  124,  124,    0,
    0,    0,  124,   39,    0,   39,    0,  124,  124,    0,
    0,    0,    0,    0,    0,    0,  124,    0,  124,   39,
    0,   39,   39,   43,    0,    0,    0,    0,    0,    0,
    0,    0,  124,    0,  124,  124,    0,    0,  141,    0,
    0,    0,    0,   43,   43,    0,    0,    0,   43,    0,
    0,    0,    0,   43,   43,    0,    0,    0,  141,  141,
    0,    0,   43,  141,   43,    0,    0,    0,  141,  141,
    0,    0,    0,    0,    0,    0,    0,  141,   43,  141,
   43,   43,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  141,    0,  141,  141,
};
short socks_yycheck[] = {                                      10,
    0,  125,   87,  141,   87,  125,  125,  125,   89,   90,
   10,   89,   90,  125,  103,   87,   87,  130,  143,  228,
  125,  151,  152,   88,  274,  234,  321,  276,  314,  300,
  301,  302,  303,  328,  321,  322,   58,  324,  269,   58,
  326,  290,   58,  274,  294,  295,  255,  274,   58,  299,
  296,  297,  298,   58,  304,  305,  141,  123,  141,   58,
  142,    0,  144,  313,  295,  315,  191,  294,  299,  141,
  141,   10,  185,   58,  305,   58,  165,  304,  143,  168,
   58,  331,  332,  321,  322,  323,  313,   58,  315,  276,
  277,  278,  279,  280,  306,  307,  308,  309,  310,  237,
  316,  317,  318,  319,  320,  257,  258,   58,    0,  292,
  293,  267,  268,  282,  283,  329,  330,   58,   10,  296,
  297,  251,  252,  326,  327,  125,  191,   76,   77,   89,
   90,   58,   58,  328,  289,  123,  123,   58,   58,  270,
  270,  284,  272,    0,  328,   58,  328,   58,   58,  279,
  274,   58,  237,   10,  237,   58,   58,  269,   58,   58,
   58,  329,  274,  325,  269,  237,  237,  291,  327,  274,
  294,  295,  312,  284,   58,  299,  257,   58,    0,  257,
  304,  305,  294,  295,  328,  330,  125,  299,   10,  313,
  295,  315,  304,  305,  299,   58,  291,  125,   58,   58,
  305,  313,  125,  315,   45,  329,  330,  331,  332,  329,
  329,  329,   47,    0,    0,    0,  125,  329,  326,  331,
  332,  125,  329,   10,  125,  329,  329,    7,  125,  202,
  207,  210,    7,   95,  218,    7,    7,   98,   85,  106,
   21,  243,   -1,   -1,  226,   -1,   -1,   -1,  259,   -1,
   -1,   -1,   -1,  264,  265,   -1,   -1,   -1,   10,  259,
  260,  261,  262,  263,   -1,  265,  266,   -1,   -1,  269,
   -1,   -1,  272,  273,  274,  275,   -1,  288,   -1,  290,
   -1,  281,   -1,   -1,   -1,  285,  286,  287,  288,   -1,
   -1,   -1,  292,  293,  294,  295,   -1,   -1,   -1,  299,
   -1,   -1,   -1,   -1,  304,  305,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  313,   -1,  315,   -1,   -1,   -1,   -1,
  259,  260,  261,  262,  263,   -1,  265,  266,   -1,  329,
  269,  331,  332,  272,  273,  274,  275,   -1,   -1,   -1,
   -1,   -1,  281,   -1,   -1,   -1,  285,  286,  287,  288,
   -1,   -1,   -1,  292,  293,   -1,  295,   -1,   -1,   -1,
  299,   -1,   -1,   -1,   -1,   -1,  305,  259,  260,  261,
  262,  263,  264,  265,  266,  125,   -1,  269,   -1,   -1,
  272,  273,  274,  275,   -1,   -1,   -1,   -1,  125,  281,
  329,   -1,   -1,  285,  286,  287,  288,   -1,  290,   -1,
  292,  293,  259,  260,  261,  262,  263,   -1,  265,  266,
   -1,   -1,  269,   -1,   -1,  272,  273,  274,  275,   -1,
   -1,   -1,   -1,   -1,  281,   -1,   -1,   -1,  285,  286,
  287,  288,   -1,   -1,  125,  292,  293,  259,  260,  261,
  262,  263,   -1,  265,  266,   -1,   -1,  269,   -1,  125,
  272,  273,  274,  275,   -1,   -1,   -1,   -1,   -1,  281,
   -1,   -1,   -1,  285,  286,  287,  288,   -1,   -1,   -1,
  292,  293,  259,  260,  261,  262,  263,   -1,  265,  266,
   -1,   -1,  269,   -1,   -1,  272,  273,  274,  275,   -1,
   -1,   -1,   -1,   -1,  281,   -1,   -1,   -1,  285,  286,
  287,  288,   -1,   -1,   -1,  292,  293,  259,  260,  261,
  262,  263,   -1,  265,  266,   -1,   -1,  269,   -1,  269,
  272,  273,  274,  275,  274,   -1,   -1,   -1,   -1,  281,
   -1,   -1,  269,  285,  286,  287,  288,  274,   -1,   -1,
  292,  293,   -1,   -1,  294,  295,   -1,   -1,   -1,  299,
   -1,   -1,   -1,   -1,  304,  305,   -1,  294,  295,   -1,
   -1,   -1,  299,  313,   -1,  315,   -1,  304,  305,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  313,   -1,  315,  329,
   -1,  331,  332,  274,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  329,   -1,  331,  332,   -1,   -1,  274,   -1,
   -1,   -1,   -1,  294,  295,   -1,   -1,   -1,  299,   -1,
   -1,   -1,   -1,  304,  305,   -1,   -1,   -1,  294,  295,
   -1,   -1,  313,  299,  315,   -1,   -1,   -1,  304,  305,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  313,  329,  315,
  331,  332,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  329,   -1,  331,  332,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 332
#if YYDEBUG
#if defined(__cplusplus) || __STDC__
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
"USER_LIBWRAP","LOGOUTPUT","LOGFILE","ROUTE","VIA","VERDICT_BLOCK",
"VERDICT_PASS","PAMSERVICENAME","PROTOCOL","PROTOCOL_TCP","PROTOCOL_UDP",
"PROTOCOL_FAKE","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4",
"PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2","PROXYPROTOCOL_HTTP_V1_0",
"USER","COMMAND","COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE",
"COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE","LIBWRAPSTART",
"OPERATOR","LOG","LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR",
"LOG_IOOPERATION","IPADDRESS","DOMAINNAME","DIRECT","IFNAME","PORT",
"PORTNUMBER","SERVICENAME","NUMBER","FROM","TO","REDIRECT","BANDWIDTH",
};
#if defined(__cplusplus) || __STDC__
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
#line 1154 "config_parse.y"

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
	socksconfig.option.configfile, yylineno,
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
	socksconfig.option.configfile, yylineno,
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
#endif
#line 937 "y.tab.c"
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
#if defined(__cplusplus) || __STDC__
    register const char *yys;
#else /* !(defined(__cplusplus) || __STDC__) */
    register char *yys;
#endif /* !(defined(__cplusplus) || __STDC__) */

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
#line 270 "config_parse.y"
{
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &socksconfig.extension;
#endif
	}
break;
case 4:
#line 279 "config_parse.y"
{ yyval.string = NULL; }
break;
case 9:
#line 286 "config_parse.y"
{ yyval.string = NULL; }
break;
case 13:
#line 293 "config_parse.y"
{
	}
break;
case 31:
#line 321 "config_parse.y"
{
		yywarn("given keyword is deprecated");
	}
break;
case 32:
#line 325 "config_parse.y"
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
case 33:
#line 337 "config_parse.y"
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
case 35:
#line 361 "config_parse.y"
{
			proxyprotocol->socks_v4 	= 1;
	}
break;
case 36:
#line 364 "config_parse.y"
{
			proxyprotocol->socks_v5 	= 1;
	}
break;
case 37:
#line 367 "config_parse.y"
{
			proxyprotocol->msproxy_v2 	= 1;
	}
break;
case 38:
#line 370 "config_parse.y"
{
			proxyprotocol->http_v1_0 	= 1;
	}
break;
case 42:
#line 382 "config_parse.y"
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
case 46:
#line 401 "config_parse.y"
{
			extension->bind = 1;
	}
break;
case 49:
#line 411 "config_parse.y"
{
#if SOCKS_SERVER
		addinternal(ruleaddress);
#endif
	}
break;
case 50:
#line 418 "config_parse.y"
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
#line 434 "config_parse.y"
{
#if SOCKS_SERVER
		addexternal(ruleaddress);
#endif
	}
break;
case 52:
#line 441 "config_parse.y"
{
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		addressinit(&mem);
#endif
	}
break;
case 53:
#line 450 "config_parse.y"
{
#if SOCKS_SERVER
		socksconfig.external.rotation = ROTATION_NONE;
	}
break;
case 54:
#line 454 "config_parse.y"
{
#if !HAVE_ROUTE_SOURCE
		yyerror("don't have code to discover route/address source on platform");
#else /* !HAVE_ROUTE_SOURCE */
		socksconfig.external.rotation = ROTATION_ROUTE;
#endif /* HAVE_ROUTE_SOURCE */
#endif /* SOCKS_SERVER */
	}
break;
case 59:
#line 472 "config_parse.y"
{
		const char *syslogname = "syslog";

		if (strncmp(yyvsp[0].string, syslogname, strlen(syslogname)) == 0
		&& (yyvsp[0].string[strlen(syslogname)] == NUL || yyvsp[0].string[strlen(syslogname)] == '/')) {
			char *sl;

			socksconfig.log.type |= LOGTYPE_SYSLOG;

			if (*(sl = &(yyvsp[0].string[strlen(syslogname)])) == '/') { /* facility. */
				size_t i;

				for (i = 0, ++sl; i < ELEMENTS(syslogfacilityv); ++i)
					if (strcmp(sl, syslogfacilityv[i].name) == 0)
						break;

				if (i == ELEMENTS(syslogfacilityv))
					yyerror("unknown syslog facility \"%s\"", sl);

				socksconfig.log.facility 		= syslogfacilityv[i].value;
				socksconfig.log.facilityname = syslogfacilityv[i].name;
			}
			else {
				socksconfig.log.facility = LOG_DAEMON; /* default. */
				socksconfig.log.facilityname = "daemon";
			}
		}
		else /* adding/changing filename. */
			if (!socksconfig.state.init) {
				/*
				 * Can't change filenames we log to after startup (well, 
				 * to be exact, we can't add new filenames, but we complain
				 * about changing too for now since it's easier.
				 */
				int flag;

				socksconfig.log.type |= LOGTYPE_FILE;

				if ((socksconfig.log.fpv = (FILE **)realloc(socksconfig.log.fpv,
				sizeof(*socksconfig.log.fpv) * (socksconfig.log.fpc + 1))) == NULL
				|| (socksconfig.log.fplockv
				= (int *)realloc(socksconfig.log.fplockv,
				sizeof(*socksconfig.log.fplockv) * (socksconfig.log.fpc + 1)))
				== NULL
				|| (socksconfig.log.fnamev
				= (char **)realloc(socksconfig.log.fnamev,
				sizeof(*socksconfig.log.fnamev) * (socksconfig.log.fpc + 1)))
				== NULL)
					serrx(EXIT_FAILURE, NOMEM);

				if ((socksconfig.log.fplockv[socksconfig.log.fpc]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp(yyvsp[0].string, "stdout") == 0)
					socksconfig.log.fpv[socksconfig.log.fpc] = stdout;
				else if (strcmp(yyvsp[0].string, "stderr") == 0)
					socksconfig.log.fpv[socksconfig.log.fpc] = stderr;
				else
					if ((socksconfig.log.fpv[socksconfig.log.fpc] = fopen(yyvsp[0].string, "a"))
					== NULL)
						yyerror("fopen(%s)", yyvsp[0].string);

				if ((flag = fcntl(fileno(socksconfig.log.fpv[socksconfig.log.fpc]),
				F_GETFD, 0)) == -1
				||  fcntl(fileno(socksconfig.log.fpv[socksconfig.log.fpc]), F_SETFD,
				flag | FD_CLOEXEC) == -1)
					serr(EXIT_FAILURE, "fcntl(F_GETFD/F_SETFD)");

				if ((socksconfig.log.fnamev[socksconfig.log.fpc] = strdup(yyvsp[0].string))
				== NULL)
					serr(EXIT_FAILURE, NOMEM);

				++socksconfig.log.fpc;
			}
			else {
				size_t i;

				for (i = 0; i < socksconfig.log.fpc; ++i)
					if (strcmp(socksconfig.log.fnamev[i], yyvsp[0].string) == 0) {

						if (fileno(socksconfig.log.fpv[i]) == fileno(stdout)
						||	 fileno(socksconfig.log.fpv[i]) == fileno(stderr))
							break;

						/* reopen logfiles. */
						fclose(socksconfig.log.fpv[i]);
						if ((socksconfig.log.fpv[i]
						= fopen(socksconfig.log.fnamev[i], "a")) == NULL)
							yyerror("fopen(%s)", yyvsp[0].string);
						break;
					}	

				if (i == socksconfig.log.fpc) /* no match found. */
					yywarn("can't change logoutput after startup");
			}
	}
break;
case 65:
#line 580 "config_parse.y"
{
#if SOCKS_SERVER
		socksconfig.uid.privileged			= yyvsp[0].uid;
		socksconfig.uid.privileged_isset	= 1;
#endif
	}
break;
case 66:
#line 588 "config_parse.y"
{
#if SOCKS_SERVER
		socksconfig.uid.unprivileged			= yyvsp[0].uid;
		socksconfig.uid.unprivileged_isset	= 1;
#endif
	}
break;
case 67:
#line 596 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		socksconfig.uid.libwrap			= yyvsp[0].uid;
		socksconfig.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 68:
#line 607 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	}
break;
case 69:
#line 617 "config_parse.y"
{
#if SOCKS_SERVER
		socksconfig.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 70:
#line 624 "config_parse.y"
{
#if SOCKS_SERVER
		socksconfig.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 71:
#line 631 "config_parse.y"
{
		socksconfig.option.debug = atoi(yyvsp[0].string);
	}
break;
case 73:
#line 639 "config_parse.y"
{
#if SOCKS_SERVER
		socksconfig.compat.reuseaddr = 1;
	}
break;
case 74:
#line 643 "config_parse.y"
{
		socksconfig.compat.sameport = 1;
#endif
	}
break;
case 78:
#line 656 "config_parse.y"
{
			socksconfig.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
break;
case 79:
#line 659 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			socksconfig.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
break;
case 80:
#line 666 "config_parse.y"
{
			socksconfig.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
break;
case 82:
#line 674 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			socksconfig.srchost.nomismatch = 1;
	}
break;
case 83:
#line 678 "config_parse.y"
{
			socksconfig.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
break;
case 87:
#line 694 "config_parse.y"
{ 
#if SOCKS_SERVER
	methodv = socksconfig.methodv; 
	methodc = &socksconfig.methodc; 
	*methodc = 0; /* reset. */
#endif
	}
break;
case 89:
#line 703 "config_parse.y"
{ 
#if SOCKS_SERVER
	methodv = socksconfig.clientmethodv; 
	methodc = &socksconfig.clientmethodc; 
	*methodc = 0; /* reset. */
#endif
	}
break;
case 91:
#line 712 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	}
break;
case 92:
#line 715 "config_parse.y"
{
		yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
	}
break;
case 93:
#line 718 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
break;
case 94:
#line 721 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method %s requires libwraplibrary", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
	}
break;
case 95:
#line 728 "config_parse.y"
{
#if !HAVE_PAM
		yyerror("method %s requires pamlibrary", AUTHMETHOD_PAMs);
#else /* HAVE_PAM */
		ADDMETHOD(AUTHMETHOD_PAM);
#endif /* !HAVE_PAM */
	}
break;
case 98:
#line 744 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src 		= src;
		rule.dst 		= dst;
		rule.rdr_from	= rdr_from;
		rule.rdr_to		= rdr_to;

		addclientrule(&rule);

#endif
	}
break;
case 100:
#line 760 "config_parse.y"
{ yyval.string = NULL; }
break;
case 102:
#line 764 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src 		= src;
		rule.dst 		= dst;
		rule.rdr_from	= rdr_from;
		rule.rdr_to		= rdr_to;

		addsocksrule(&rule);
#endif
	}
break;
case 104:
#line 778 "config_parse.y"
{ checkmodule("bandwidth"); }
break;
case 108:
#line 782 "config_parse.y"
{ checkmodule("redirect"); }
break;
case 109:
#line 785 "config_parse.y"
{ yyval.string = NULL; }
break;
case 116:
#line 796 "config_parse.y"
{
#if SOCKS_SERVER
		ruleinit(&rule);
		rule.verdict	= VERDICT_BLOCK;
	}
break;
case 117:
#line 801 "config_parse.y"
{
		ruleinit(&rule);
		rule.verdict	= VERDICT_PASS;
#endif
	}
break;
case 119:
#line 812 "config_parse.y"
{
			command->bind = 1;
	}
break;
case 120:
#line 815 "config_parse.y"
{
			command->connect = 1;
	}
break;
case 121:
#line 818 "config_parse.y"
{
			command->udpassociate = 1;
	}
break;
case 122:
#line 824 "config_parse.y"
{
			command->bindreply = 1;
	}
break;
case 123:
#line 828 "config_parse.y"
{
			command->udpreply = 1;
	}
break;
case 127:
#line 840 "config_parse.y"
{
		protocol->tcp = 1;
	}
break;
case 128:
#line 843 "config_parse.y"
{
		protocol->udp = 1;
	}
break;
case 134:
#line 860 "config_parse.y"
{
#if SOCKS_SERVER && HAVE_MODULE_BANDWIDTH
		static bw_t bwmeminit;

     /* 
	 	* temporarly allocate ordinary memory, later on point it to
		* the correct index in socksconfig.bwv.
		*/
		if ((rule.bw = (bw_t *)malloc(sizeof(*rule.bw))) == NULL)
			serr(EXIT_FAILURE, NOMEM);
		*rule.bw = bwmeminit;
		rule.bw->maxbps = atoi(yyvsp[0].string);
#endif /* HAVE_MODULE_BANDWIDTH */
	}
break;
case 136:
#line 880 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
break;
case 137:
#line 884 "config_parse.y"
{
			rule.log.data = 1;
	}
break;
case 138:
#line 887 "config_parse.y"
{
			rule.log.disconnect = 1;
	}
break;
case 139:
#line 890 "config_parse.y"
{
			rule.log.error = 1;
	}
break;
case 140:
#line 893 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	}
break;
case 143:
#line 904 "config_parse.y"
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
case 144:
#line 915 "config_parse.y"
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
case 155:
#line 965 "config_parse.y"
{ yyval.string = NULL; }
break;
case 157:
#line 969 "config_parse.y"
{
		addressinit(&src);
	}
break;
case 158:
#line 974 "config_parse.y"
{
		addressinit(&dst);
	}
break;
case 159:
#line 979 "config_parse.y"
{
		addressinit(&rdr_from);
	}
break;
case 160:
#line 984 "config_parse.y"
{
		addressinit(&rdr_to);
	}
break;
case 161:
#line 991 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	}
break;
case 174:
#line 1021 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address: %s", yyvsp[0].string);
	}
break;
case 175:
#line 1030 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask: %d", yyvsp[0].string);

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	}
break;
case 176:
#line 1037 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask: %s", yyvsp[0].string);
	}
break;
case 177:
#line 1043 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);
	}
break;
case 178:
#line 1052 "config_parse.y"
{
		*atype = SOCKS_ADDR_IFNAME;

		if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
			yyerror("interfacename too long");
		strcpy(ifname, yyvsp[0].string);
	}
break;
case 179:
#line 1062 "config_parse.y"
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
case 180:
#line 1075 "config_parse.y"
{ yyval.string = NULL; }
break;
case 186:
#line 1088 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	}
break;
case 187:
#line 1094 "config_parse.y"
{
		ruleaddress->portend		= htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator	= range;
	}
break;
case 188:
#line 1100 "config_parse.y"
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
case 189:
#line 1148 "config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	}
break;
#line 1925 "y.tab.c"
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
