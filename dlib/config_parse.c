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
"$Id: config_parse.y,v 1.149 2001/05/13 14:26:47 michaels Exp $";

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
		if (methodisset(method, methodv, *methodc)) \
			yywarn("duplicate method: %s", method2string(method)); \
		else { \
			if (*methodc >= MAXMETHOD)	\
				yyerror("internal error");	\
			methodv[(*methodc)++] = method; \
		} \
	} while (0)

#line 164 "config_parse.y"
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#line 169 "y.tab.c"
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
#define CLIENTMETHOD 274
#define NONE 275
#define GSSAPI 276
#define UNAME 277
#define RFC931 278
#define PAM 279
#define COMPATIBILITY 280
#define REUSEADDR 281
#define SAMEPORT 282
#define USERNAME 283
#define USER_PRIVILEGED 284
#define USER_UNPRIVILEGED 285
#define USER_LIBWRAP 286
#define LOGOUTPUT 287
#define LOGFILE 288
#define ROUTE 289
#define VIA 290
#define VERDICT_BLOCK 291
#define VERDICT_PASS 292
#define PAMSERVICENAME 293
#define PROTOCOL 294
#define PROTOCOL_TCP 295
#define PROTOCOL_UDP 296
#define PROTOCOL_FAKE 297
#define PROXYPROTOCOL 298
#define PROXYPROTOCOL_SOCKS_V4 299
#define PROXYPROTOCOL_SOCKS_V5 300
#define PROXYPROTOCOL_MSPROXY_V2 301
#define PROXYPROTOCOL_HTTP_V1_0 302
#define USER 303
#define COMMAND 304
#define COMMAND_BIND 305
#define COMMAND_CONNECT 306
#define COMMAND_UDPASSOCIATE 307
#define COMMAND_BINDREPLY 308
#define COMMAND_UDPREPLY 309
#define ACTION 310
#define LINE 311
#define LIBWRAPSTART 312
#define OPERATOR 313
#define LOG 314
#define LOG_CONNECT 315
#define LOG_DATA 316
#define LOG_DISCONNECT 317
#define LOG_ERROR 318
#define LOG_IOOPERATION 319
#define IPADDRESS 320
#define DOMAIN 321
#define DIRECT 322
#define IFNAME 323
#define PORT 324
#define PORTNUMBER 325
#define SERVICENAME 326
#define NUMBER 327
#define FROM 328
#define TO 329
#define YYERRCODE 256
short socks_yylhs[] = {                                        -1,
    0,    0,   48,    1,    1,    1,    1,    1,    2,    2,
    2,    2,   23,   24,   24,   49,   49,   49,   49,   49,
   49,   49,   49,   47,   47,   47,   47,   47,   47,    3,
   55,   22,    7,    8,    8,    8,    8,    9,    9,   10,
   11,   12,   12,   29,   30,   31,   31,   32,   33,   81,
   81,   34,   35,   80,   80,   25,   25,   25,   36,   37,
   38,   38,   50,   50,   50,   51,   52,   53,   54,   27,
   28,   26,   39,   40,   40,   41,   41,   14,   15,   15,
   15,   16,   17,   17,   18,   18,   44,   91,   42,   92,
   43,   46,   46,   46,   46,   46,   45,   45,   63,   64,
   64,   64,   64,   64,   65,   65,   60,   61,   61,   61,
   61,   61,   61,   61,   61,   62,   62,   66,   66,   19,
   21,   21,   21,   21,   21,   20,   20,    4,    6,    6,
    5,    5,   67,   68,   70,   70,   70,   70,   70,   69,
   69,   13,   71,   72,   73,   57,   58,   58,   58,   58,
   58,   59,   59,   82,   83,   56,   74,   74,   76,   76,
   76,   75,   84,   84,   77,   78,   79,   85,   85,   85,
   89,   89,   86,   87,   93,   90,   88,
};
short socks_yylen[] = {                                         2,
    2,    2,    1,    0,    2,    2,    2,    2,    0,    2,
    2,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    8,    0,    3,    1,    1,    1,    1,    1,    2,    3,
    1,    1,    2,    3,    1,    1,    2,    4,    0,    2,
    2,    4,    0,    1,    1,    1,    1,    1,    3,    1,
    1,    2,    1,    1,    1,    3,    3,    3,    1,    3,
    3,    3,    3,    1,    1,    1,    2,    3,    1,    1,
    1,    3,    1,    1,    1,    2,    3,    0,    4,    0,
    4,    1,    1,    1,    1,    1,    1,    2,    7,    1,
    1,    1,    1,    1,    0,    2,    6,    1,    1,    1,
    1,    1,    1,    1,    1,    0,    2,    1,    1,    3,
    1,    1,    1,    1,    1,    1,    2,    3,    1,    1,
    1,    2,    2,    3,    1,    1,    1,    1,    1,    1,
    2,    3,    3,    3,    3,    3,    1,    1,    1,    1,
    1,    0,    2,    1,    1,    1,    4,    2,    2,    2,
    1,    1,    1,    1,    1,    1,    1,    0,    3,    2,
    1,    1,    3,    1,    1,    1,    1,
};
short socks_yydefred[] = {                                      0,
    3,   13,    0,    9,    4,    0,    0,   30,    0,    0,
    0,   32,   10,   15,   58,   11,   14,   57,   56,   12,
    0,   49,   53,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  118,  119,    5,   18,   28,   29,   27,
   25,   26,   19,   20,   21,   24,   16,   17,   22,    6,
   23,   63,   64,   65,    8,    7,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   88,   90,
    0,    0,    0,    0,    0,   72,   80,   81,   79,   78,
   60,    0,   59,    0,    0,    0,    0,   83,   84,    0,
   82,   45,    0,   44,   70,   71,    0,    0,   74,   75,
    0,   73,   69,   66,   67,   68,    0,    0,    0,    0,
    0,    0,    0,    0,  113,  114,  115,  112,  109,  108,
    0,    0,  111,  110,   62,  149,  150,  147,  148,  151,
    0,    0,  103,  104,  100,    0,    0,  102,  101,  162,
  166,    0,    0,   48,   54,   55,   52,   86,   47,   92,
   93,   94,   95,   96,   89,    0,   91,   77,    0,    0,
    0,    0,    0,    0,    0,    0,  117,  154,    0,    0,
    0,  153,    0,  106,    0,    0,   50,   51,   98,   87,
  142,  129,  130,  128,    0,   34,   35,   36,   37,    0,
   33,   41,    0,   40,  121,  122,  123,  124,  125,  120,
    0,  143,  135,  136,  137,  138,  139,  134,    0,    0,
  155,  133,    0,    0,  156,    0,    0,    0,  177,  174,
  170,    0,    0,  132,   39,   43,  127,  141,  107,    0,
  165,  144,    0,    0,    0,    0,   99,    0,  176,  172,
  169,  171,  145,    0,  158,  167,    0,  146,    0,  161,
   31,  175,  173,  164,  163,    0,  159,  160,  157,
};
short socks_yydgoto[] = {                                       3,
    7,    6,   14,  115,  184,  185,  116,  190,  191,  117,
  193,  194,  118,   15,   80,   39,   90,   91,  119,  200,
  201,   61,    4,   16,   17,   18,   40,   41,  129,   93,
   94,   43,   63,   44,   64,   19,   82,   83,   46,  101,
  102,   47,   48,  120,  155,  156,   49,    5,   50,   51,
   52,   53,   54,  104,   20,  216,  217,  131,  132,   55,
  121,  122,   56,  136,  137,   57,  169,  123,  208,  209,
  124,  170,  212,  232,  233,  248,  234,  143,  250,  147,
  144,  171,  213,  256,  177,  221,  222,  223,  241,  242,
   97,   98,  253,
};
short socks_yysindex[] = {                                   -219,
    0,    0,    0,    0,    0,  -10,  241,    0,    8,   15,
   31,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -235,    0,    0,   35,   37,   52,   58,   62,   64,   65,
   66,   67,   69,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  -65, -199, -244, -159,
    9,   10,   73,   77, -191, -132, -189, -181,    0,    0,
 -196, -130, -130, -130, -206,    0,    0,    0,    0,    0,
    0, -159,    0, -164, -233, -292, -292,    0,    0, -191,
    0,    0, -132,    0,    0,    0, -242, -242,    0,    0,
 -196,    0,    0,    0,    0,    0,   96,   97,   98,  100,
  101,  102,  104,  106,    0,    0,    0,    0,    0,    0,
 -206, -165,    0,    0,    0,    0,    0,    0,    0,    0,
 -164, -165,    0,    0,    0, -233, -165,    0,    0,    0,
    0, -158, -158,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -242,    0,    0, -242, -161,
 -205, -253, -115, -264, -139, -174,    0,    0, -206, -153,
  121,    0, -104,    0, -233, -293,    0,    0,    0,    0,
    0,    0,    0,    0, -205,    0,    0,    0,    0, -253,
    0,    0, -115,    0,    0,    0,    0,    0,    0,    0,
 -264,    0,    0,    0,    0,    0,    0,    0, -174,   60,
    0,    0,  132, -220,    0,  134, -164,   68,    0,    0,
    0,  155, -223,    0,    0,    0,    0,    0,    0, -220,
    0,    0,  154, -158, -238,   78,    0, -114,    0,    0,
    0,    0,    0, -298,    0,    0, -158,    0, -158,    0,
    0,    0,    0,    0,    0, -158,    0,    0,    0,
};
short socks_yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,  216,  218,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -108,    0,    0,    0,    0,    0,
    0,  105,    0, -103, -102,    0,    0,    0,    0,  139,
    0,    0,   59,    0,    0,    0,    0,    0,    0,    0,
  173,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -120,    0,    0,    0,    0,    0,    0,    0,    0,    0,
 -119,    0,    0,    0,    0, -118,    0,    0,    0,    0,
    0,  207,  207,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    1,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   99,    0,
    0,    0,    0,    0,  103,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -116,    0,    0,    0,    0,  -99,
    0,    0,  237,    0,    0,    0,    0,    0,    0,    0,
  -71,    0,    0,    0,    0,    0,    0,    0,  249,    0,
    0,    0,    0,    0,    0,    0,  109,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -123,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  -54,    0,  -54,    0,
    0,    0,    0,    0,    0, -123,    0,    0,    0,
};
short socks_yygindex[] = {                                      0,
    0,    0,  214,  -70,   46,    0,  -69,    0,   40,  -68,
    0,   42,  -64,  229,    0,    0,    0,  147,  -66,   38,
    0,    0,    0,    0,    0,    0,    0,    0,  231,    0,
  149,    0,    0,    0,    0,  238,    0,  164,    0,    0,
  146,    0,    0,  -81,  -79,    0,    0,    0,    0,    0,
    0,    0,    0,   45,    0,    0,    0,    0, -121,    0,
    0, -105,    0,    0, -112,  227, -107,  -62,   43,    0,
  -58,    0,    0,   25,  -74,    0,   21,  171,    0,    0,
    0,    0,    0,    0, -135,    0,   36,    0,    0,    0,
    0,    0,    0,
};
#define YYTABLESIZE 577
short socks_yytable[] = {                                      13,
   97,  168,  130,  135,  116,  152,  105,  178,  131,  172,
   97,  142,  145,  126,  127,  167,  133,  128,  157,  219,
  134,  254,  138,  174,  173,   38,  139,  140,  255,  175,
  141,  220,  150,  151,  152,  153,  154,    1,    2,  107,
  195,  196,  197,  198,  199,  186,  187,  188,  189,  130,
   77,   78,   79,  126,  135,   34,   35,   75,   46,  108,
  126,  127,  218,  210,  128,   58,  107,  133,   46,  111,
  168,  134,   59,  138,   88,   89,  179,  139,  113,  180,
  114,  140,  231,  246,   99,  100,  108,  109,   60,  182,
  183,  110,   65,  135,   66,  236,  111,  112,  245,  140,
  231,  220,  239,   25,   61,  113,  133,  114,  107,   67,
  134,  257,  138,  258,   61,   68,  139,  105,  106,   69,
  259,   70,   71,   72,   73,   97,   74,   76,   81,  109,
   86,   84,   85,  110,   87,  130,   92,   95,   85,  112,
  203,  204,  205,  206,  207,   96,  126,  127,   85,  168,
  128,  131,  103,  159,  160,  161,  131,  162,  163,  164,
  247,  165,  168,  166,  181,  176,  168,  192,   38,  168,
  168,  202,   76,   38,  168,  211,  131,  131,  214,  168,
  168,  131,   76,   46,  229,  215,  131,  131,  168,  230,
  168,  235,  237,   38,   38,  131,  126,  131,   38,  238,
  244,  126,  251,   38,   38,  168,  168,  116,  152,  105,
  252,  131,   38,  168,   38,    2,  168,    1,  168,  116,
   37,  126,  126,  116,  152,  105,  126,  105,   38,  225,
  224,  126,  126,  152,  226,   38,  148,   42,  227,  168,
  126,  149,  126,  168,   45,  125,  158,   62,    8,  168,
   36,  228,    9,   10,  243,  249,  126,  146,  240,   97,
   97,   97,   97,    0,   97,   97,    0,    0,   97,    0,
    0,   97,   97,   97,   97,    0,   11,    0,   12,    0,
   97,    0,    0,    0,   97,   97,   97,   97,    0,    0,
    0,   97,   97,   97,   97,    0,    0,    0,   97,    0,
    0,    0,    0,   97,   97,    0,    0,    0,    0,    0,
    0,    0,   97,    0,   97,    0,    0,   46,   46,   46,
   46,    0,   46,   46,    0,    0,   46,    0,   97,   46,
   46,   46,   46,    0,    0,    0,    0,    0,   46,    0,
    0,    0,   46,   46,   46,   46,    0,    0,    0,   46,
   46,    0,   46,    0,    0,    0,   46,    0,    0,    0,
    0,   42,   46,   61,   61,   61,   61,   61,   61,   61,
    0,    0,   61,  140,    0,   61,   61,   61,   61,    0,
    0,    0,    0,    0,   61,    0,   46,    0,   61,   61,
   61,   61,    0,   61,    0,   61,   61,   85,   85,   85,
   85,    0,   85,   85,    0,    0,   85,    0,    0,   85,
   85,   85,   85,    0,    0,    0,    0,    0,   85,    0,
    0,    0,   85,   85,   85,   85,    0,    0,    0,   85,
   85,   76,   76,   76,   76,    0,   76,   76,    0,    0,
   76,    0,    0,   76,   76,   76,   76,    0,    0,    0,
    0,    0,   76,    0,    0,    0,   76,   76,   76,   76,
    0,    0,    0,   76,   76,  168,  168,  168,  168,    0,
  168,  168,    0,    0,  168,    0,    0,  168,  168,  168,
  168,    0,    0,    0,    0,    0,  168,    0,    0,    0,
  168,  168,  168,  168,    0,    0,    0,  168,  168,    8,
   21,   22,   23,    0,   10,   24,    0,    0,   25,   42,
    0,   26,   27,   28,   29,    0,    0,    0,    0,    0,
   30,  140,    0,    0,   31,   32,   33,   11,    0,   42,
   42,   34,   35,    0,   42,    0,    0,    0,    0,   42,
   42,  140,  140,    0,    0,    0,  140,    0,   42,    0,
   42,  140,  140,    0,    0,    0,    0,    0,    0,    0,
  140,    0,  140,    0,   42,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  140,
};
short socks_yycheck[] = {                                      10,
    0,  125,   84,   85,  125,  125,  125,  143,  125,  131,
   10,   86,   87,   84,   84,  121,   85,   84,   98,  313,
   85,  320,   85,  136,  132,  125,   85,  320,  327,  137,
  323,  325,  275,  276,  277,  278,  279,  257,  258,  273,
  305,  306,  307,  308,  309,  299,  300,  301,  302,  131,
  295,  296,  297,  125,  136,  291,  292,  123,    0,  293,
  131,  131,  175,  169,  131,   58,  273,  136,   10,  303,
  125,  136,   58,  136,  266,  267,  156,  136,  312,  159,
  314,  320,  321,  322,  281,  282,  293,  294,   58,  295,
  296,  298,   58,  175,   58,  217,  303,  304,  234,  320,
  321,  325,  326,  268,    0,  312,  175,  314,  273,   58,
  175,  247,  175,  249,   10,   58,  175,   73,   74,   58,
  256,   58,   58,   58,   58,  125,   58,  327,  288,  294,
   58,  123,  123,  298,   58,  217,  269,  327,    0,  304,
  315,  316,  317,  318,  319,  327,  217,  217,   10,  273,
  217,  268,  283,   58,   58,   58,  273,   58,   58,   58,
  235,   58,  328,   58,  326,  324,  290,  283,  268,  293,
  294,  311,    0,  273,  298,  329,  293,  294,   58,  303,
  304,  298,   10,  125,  125,  290,  303,  304,  312,   58,
  314,   58,  125,  293,  294,  312,  268,  314,  298,   45,
   47,  273,  125,  303,  304,  329,    0,  328,  328,  328,
  325,  328,  312,  268,  314,    0,   10,    0,  273,  328,
    7,  293,  294,  125,  328,  328,  298,  125,  328,  190,
  185,  303,  304,  125,  193,    7,   90,    7,  201,  294,
  312,   93,  314,  298,    7,   82,  101,   21,  259,  304,
   10,  209,  263,  264,  230,  235,  328,   87,  223,  259,
  260,  261,  262,   -1,  264,  265,   -1,   -1,  268,   -1,
   -1,  271,  272,  273,  274,   -1,  287,   -1,  289,   -1,
  280,   -1,   -1,   -1,  284,  285,  286,  287,   -1,   -1,
   -1,  291,  292,  293,  294,   -1,   -1,   -1,  298,   -1,
   -1,   -1,   -1,  303,  304,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  312,   -1,  314,   -1,   -1,  259,  260,  261,
  262,   -1,  264,  265,   -1,   -1,  268,   -1,  328,  271,
  272,  273,  274,   -1,   -1,   -1,   -1,   -1,  280,   -1,
   -1,   -1,  284,  285,  286,  287,   -1,   -1,   -1,  291,
  292,   -1,  294,   -1,   -1,   -1,  298,   -1,   -1,   -1,
   -1,  125,  304,  259,  260,  261,  262,  263,  264,  265,
   -1,   -1,  268,  125,   -1,  271,  272,  273,  274,   -1,
   -1,   -1,   -1,   -1,  280,   -1,  328,   -1,  284,  285,
  286,  287,   -1,  289,   -1,  291,  292,  259,  260,  261,
  262,   -1,  264,  265,   -1,   -1,  268,   -1,   -1,  271,
  272,  273,  274,   -1,   -1,   -1,   -1,   -1,  280,   -1,
   -1,   -1,  284,  285,  286,  287,   -1,   -1,   -1,  291,
  292,  259,  260,  261,  262,   -1,  264,  265,   -1,   -1,
  268,   -1,   -1,  271,  272,  273,  274,   -1,   -1,   -1,
   -1,   -1,  280,   -1,   -1,   -1,  284,  285,  286,  287,
   -1,   -1,   -1,  291,  292,  259,  260,  261,  262,   -1,
  264,  265,   -1,   -1,  268,   -1,   -1,  271,  272,  273,
  274,   -1,   -1,   -1,   -1,   -1,  280,   -1,   -1,   -1,
  284,  285,  286,  287,   -1,   -1,   -1,  291,  292,  259,
  260,  261,  262,   -1,  264,  265,   -1,   -1,  268,  273,
   -1,  271,  272,  273,  274,   -1,   -1,   -1,   -1,   -1,
  280,  273,   -1,   -1,  284,  285,  286,  287,   -1,  293,
  294,  291,  292,   -1,  298,   -1,   -1,   -1,   -1,  303,
  304,  293,  294,   -1,   -1,   -1,  298,   -1,  312,   -1,
  314,  303,  304,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  312,   -1,  314,   -1,  328,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  328,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 329
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
"DEBUGING","RESOLVEPROTOCOL","SRCHOST","NOMISMATCH","NOUNKNOWN","EXTENSION",
"BIND","PRIVILEGED","IOTIMEOUT","CONNECTTIMEOUT","METHOD","CLIENTMETHOD","NONE",
"GSSAPI","UNAME","RFC931","PAM","COMPATIBILITY","REUSEADDR","SAMEPORT",
"USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","LOGOUTPUT",
"LOGFILE","ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS","PAMSERVICENAME",
"PROTOCOL","PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL",
"PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2",
"PROXYPROTOCOL_HTTP_V1_0","USER","COMMAND","COMMAND_BIND","COMMAND_CONNECT",
"COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","COMMAND_UDPREPLY","ACTION","LINE",
"LIBWRAPSTART","OPERATOR","LOG","LOG_CONNECT","LOG_DATA","LOG_DISCONNECT",
"LOG_ERROR","LOG_IOOPERATION","IPADDRESS","DOMAIN","DIRECT","IFNAME","PORT",
"PORTNUMBER","SERVICENAME","NUMBER","FROM","TO",
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
"clientruleoption : authmethod",
"clientruleoption : libwrap",
"clientruleoption : log",
"clientruleoption : user",
"clientruleoption : pamservicename",
"clientruleoptions :",
"clientruleoptions : clientruleoption clientruleoptions",
"rule : verdict '{' ruleoptions fromto ruleoptions '}'",
"ruleoption : authmethod",
"ruleoption : command",
"ruleoption : libwrap",
"ruleoption : log",
"ruleoption : pamservicename",
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
"pamservicename : PAMSERVICENAME ':' SERVICENAME",
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
#line 1064 "config_parse.y"

#define INTERACTIVE		0

extern FILE *yyin;

int parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";
	const int errno_s = errno;

/*	yydebug		= 1;         */
	yylineno		= 1;
	parseinit	= 0;

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
	struct rule_t *rule;
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
#line 880 "y.tab.c"
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
#line 262 "config_parse.y"
{
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &config.extension;
#endif
	}
break;
case 4:
#line 271 "config_parse.y"
{ yyval.string = NULL; }
break;
case 9:
#line 278 "config_parse.y"
{ yyval.string = NULL; }
break;
case 13:
#line 285 "config_parse.y"
{
	}
break;
case 30:
#line 312 "config_parse.y"
{
		yywarn("given keyword is deprecated");
	}
break;
case 31:
#line 316 "config_parse.y"
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
case 32:
#line 328 "config_parse.y"
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
case 34:
#line 352 "config_parse.y"
{
			proxyprotocol->socks_v4 	= 1;
	}
break;
case 35:
#line 355 "config_parse.y"
{
			proxyprotocol->socks_v5 	= 1;
	}
break;
case 36:
#line 358 "config_parse.y"
{
			proxyprotocol->msproxy_v2 	= 1;
	}
break;
case 37:
#line 361 "config_parse.y"
{
			proxyprotocol->http_v1_0 	= 1;
	}
break;
case 41:
#line 373 "config_parse.y"
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
case 45:
#line 392 "config_parse.y"
{
			extension->bind = 1;
	}
break;
case 48:
#line 402 "config_parse.y"
{
#if SOCKS_SERVER
		addinternal(ruleaddress);
#endif
	}
break;
case 49:
#line 409 "config_parse.y"
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
#line 429 "config_parse.y"
{
#if SOCKS_SERVER
		addexternal(ruleaddress);
#endif
	}
break;
case 53:
#line 436 "config_parse.y"
{
#if SOCKS_SERVER
		static struct ruleaddress_t mem;

		addressinit(&mem);
#endif
	}
break;
case 60:
#line 458 "config_parse.y"
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
case 66:
#line 529 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.privileged			= yyvsp[0].uid;
		config.uid.privileged_isset	= 1;
#endif
	}
break;
case 67:
#line 537 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.unprivileged			= yyvsp[0].uid;
		config.uid.unprivileged_isset	= 1;
#endif
	}
break;
case 68:
#line 545 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		config.uid.libwrap			= yyvsp[0].uid;
		config.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrapsupport not compiled in");
#endif /* !HAVE_LIBWRAP */
	}
break;
case 69:
#line 556 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	}
break;
case 70:
#line 566 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.io = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 71:
#line 573 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.negotiate = (time_t)atol(yyvsp[0].string);
#endif
	}
break;
case 72:
#line 580 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	}
break;
case 74:
#line 588 "config_parse.y"
{
#if SOCKS_SERVER
		config.compat.reuseaddr = 1;
	}
break;
case 75:
#line 592 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	}
break;
case 79:
#line 605 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	}
break;
case 80:
#line 608 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			config.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	}
break;
case 81:
#line 615 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_UDP;
	}
break;
case 83:
#line 623 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			config.srchost.nomismatch = 1;
	}
break;
case 84:
#line 627 "config_parse.y"
{
			config.srchost.nounknown = 1;
#else
		yyerror("srchostoption requires libwrap");
#endif
	}
break;
case 88:
#line 643 "config_parse.y"
{ 
#if SOCKS_SERVER
	methodv = config.methodv; 
	methodc = &config.methodc; 
	*methodc = 0; /* reset. */
#endif
	}
break;
case 90:
#line 652 "config_parse.y"
{ 
#if SOCKS_SERVER
	methodv = config.clientmethodv; 
	methodc = &config.clientmethodc; 
	*methodc = 0; /* reset. */
#endif
	}
break;
case 92:
#line 661 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	}
break;
case 93:
#line 664 "config_parse.y"
{
		yyerror("%s not supported", AUTHMETHOD_GSSAPIs);
	}
break;
case 94:
#line 667 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	}
break;
case 95:
#line 670 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method %s requires libwraplibrary", AUTHMETHOD_RFC931s);
#endif /* !HAVE_LIBWRAP */
	}
break;
case 96:
#line 677 "config_parse.y"
{
#if !HAVE_PAM
		yyerror("method %s requires pamlibrary", AUTHMETHOD_PAMs);
#else /* HAVE_PAM */
		ADDMETHOD(AUTHMETHOD_PAM);
#endif /* !HAVE_PAM */
	}
break;
case 99:
#line 693 "config_parse.y"
{
#if SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addclientrule(&rule);

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		rule = ruleinitmem; /* init for next rule. */

		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	}
break;
case 105:
#line 717 "config_parse.y"
{ yyval.string = NULL; }
break;
case 107:
#line 721 "config_parse.y"
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
case 116:
#line 749 "config_parse.y"
{ yyval.string = NULL; }
break;
case 118:
#line 753 "config_parse.y"
{
#if SOCKS_SERVER
		rule.verdict	= VERDICT_BLOCK;
		ruleinit(&rule);
	}
break;
case 119:
#line 758 "config_parse.y"
{
		rule.verdict	= VERDICT_PASS;
		ruleinit(&rule);
#endif
	}
break;
case 121:
#line 769 "config_parse.y"
{
			command->bind = 1;
	}
break;
case 122:
#line 772 "config_parse.y"
{
			command->connect = 1;
	}
break;
case 123:
#line 775 "config_parse.y"
{
			command->udpassociate = 1;
	}
break;
case 124:
#line 781 "config_parse.y"
{
			command->bindreply = 1;
	}
break;
case 125:
#line 785 "config_parse.y"
{
			command->udpreply = 1;
	}
break;
case 129:
#line 797 "config_parse.y"
{
		protocol->tcp = 1;
	}
break;
case 130:
#line 800 "config_parse.y"
{
		protocol->udp = 1;
	}
break;
case 135:
#line 816 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	}
break;
case 136:
#line 820 "config_parse.y"
{
			rule.log.data = 1;
	}
break;
case 137:
#line 823 "config_parse.y"
{
			rule.log.disconnect = 1;
	}
break;
case 138:
#line 826 "config_parse.y"
{
			rule.log.error = 1;
	}
break;
case 139:
#line 829 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	}
break;
case 142:
#line 840 "config_parse.y"
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
case 143:
#line 851 "config_parse.y"
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
case 152:
#line 896 "config_parse.y"
{ yyval.string = NULL; }
break;
case 154:
#line 900 "config_parse.y"
{
		addressinit(&src);
	}
break;
case 155:
#line 906 "config_parse.y"
{
		addressinit(&dst);
	}
break;
case 156:
#line 912 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	}
break;
case 162:
#line 931 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address: %s", yyvsp[0].string);
	}
break;
case 163:
#line 940 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask: %d", yyvsp[0].string);

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	}
break;
case 164:
#line 947 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask: %s", yyvsp[0].string);
	}
break;
case 165:
#line 953 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domainname too long");
		strcpy(domain, yyvsp[0].string);
	}
break;
case 166:
#line 962 "config_parse.y"
{
		*atype = SOCKS_ADDR_IFNAME;

		if (strlen(yyvsp[0].string) >= MAXIFNAMELEN)
			yyerror("interfacename too long");
		strcpy(ifname, yyvsp[0].string);
	}
break;
case 167:
#line 972 "config_parse.y"
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
case 168:
#line 985 "config_parse.y"
{ yyval.string = NULL; }
break;
case 174:
#line 998 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	}
break;
case 175:
#line 1004 "config_parse.y"
{
		ruleaddress->portend		= htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator	= range;
	}
break;
case 176:
#line 1010 "config_parse.y"
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
case 177:
#line 1058 "config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	}
break;
#line 1785 "y.tab.c"
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
