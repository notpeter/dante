
/*  A Bison parser, made from config_parse.y
 by  GNU Bison version 1.25
  */

#define YYBISON 1  /* Identify Bison output.  */

#define yyparse socks_yyparse
#define yylex socks_yylex
#define yyerror socks_yyerror
#define yylval socks_yylval
#define yychar socks_yychar
#define yydebug socks_yydebug
#define yynerrs socks_yynerrs
#define	SERVERCONFIG	258
#define	CLIENTCONFIG	259
#define	LOCALDOMAIN	260
#define	CLIENT	261
#define	INTERNAL	262
#define	EXTERNAL	263
#define	DEBUGING	264
#define	EXTENSION	265
#define	BIND	266
#define	PRIVILEGED	267
#define	IOTIMEOUT	268
#define	CONNECTTIMEOUT	269
#define	METHOD	270
#define	NONE	271
#define	GSSAPI	272
#define	UNAME	273
#define	COMPATIBILITY	274
#define	REUSEADDR	275
#define	SAMEPORT	276
#define	USERNAME	277
#define	USER_PRIVILEGED	278
#define	USER_UNPRIVILEGED	279
#define	USER_LIBWRAP	280
#define	LOGOUTPUT	281
#define	LOGFILE	282
#define	ROUTE	283
#define	VIA	284
#define	VERDICT_BLOCK	285
#define	VERDICT_PASS	286
#define	PROTOCOL	287
#define	PROTOCOL_TCP	288
#define	PROTOCOL_UDP	289
#define	PROXYPROTOCOL	290
#define	PROXYPROTOCOL_SOCKS_V4	291
#define	PROXYPROTOCOL_SOCKS_V5	292
#define	PROXYPROTOCOL_MSPROXY_V2	293
#define	COMMAND	294
#define	COMMAND_BIND	295
#define	COMMAND_CONNECT	296
#define	COMMAND_UDPASSOCIATE	297
#define	COMMAND_BINDREPLY	298
#define	ACTION	299
#define	AUTH	300
#define	AUTHMETHOD	301
#define	LINE	302
#define	LIBWRAPSTART	303
#define	OPERATOR	304
#define	LOG	305
#define	LOG_CONNECT	306
#define	LOG_DATA	307
#define	LOG_DISCONNECT	308
#define	LOG_ERROR	309
#define	LOG_IOOPERATION	310
#define	IPADDRESS	311
#define	DOMAIN	312
#define	DIRECT	313
#define	PORT	314
#define	SERVICENAME	315
#define	NUMBER	316
#define	FROM	317
#define	TO	318

#line 44 "config_parse.y"


static const char rcsid[] =
"$Id: config_parse.y,v 1.78 1999/02/20 19:18:49 michaels Exp $";

#include "common.h"

#include "yacconfig.h" 


__BEGIN_DECLS

static void
addressinit(struct ruleaddress_t *address);

static void
yyerror(const char *s);

__END_DECLS

/* hmm. */
extern int yylex();
extern int yyparse();

extern struct config_t config;

extern int yylineno;
extern char *yytext;

#ifdef SOCKS_SERVER
static struct rule_t				rule;				/* new rule.							*/
#endif

#ifdef SOCKS_CLIENT
static struct serverstate_t 	state;
static struct route_t 			route;			/* new route.							*/
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

static in_port_t					*port_tcp;		/* new tcp portnumber.				*/
static in_port_t					*port_udp;		/* new udp portnumber.				*/
static unsigned char 			*methodv;		/* new authmethods.					*/
static unsigned char 			*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/


#define YYDEBUG 1


#line 108 "config_parse.y"
typedef union {
	char 	*string;
	uid_t	uid;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		216
#define	YYFLAG		-32768
#define	YYNTBASE	70

#define YYTRANSLATE(x) ((unsigned)(x) <= 318 ? yytranslate[x] : 146)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    64,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,    69,     2,    68,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    67,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    65,     2,    66,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     2,     3,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
    26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
    36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
    46,    47,    48,    49,    50,    51,    52,    53,    54,    55,
    56,    57,    58,    59,    60,    61,    62,    63
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     3,     6,     8,     9,    12,    15,    18,    21,    22,
    25,    28,    31,    33,    35,    43,    48,    55,    56,    57,
    62,    64,    66,    68,    69,    72,    73,    78,    80,    81,
    84,    85,    92,    93,    98,    99,   103,   104,   109,   111,
   112,   115,   119,   123,   127,   128,   132,   134,   135,   139,
   140,   144,   145,   149,   153,   154,   159,   161,   163,   164,
   167,   168,   173,   174,   177,   179,   181,   183,   190,   193,
   200,   207,   209,   211,   212,   217,   218,   221,   223,   225,
   227,   229,   230,   235,   236,   239,   241,   243,   246,   247,
   252,   253,   256,   258,   260,   262,   264,   266,   267,   271,
   272,   274,   275,   279,   280,   284,   289,   295,   297,   299,
   301,   306,   309,   312,   315,   317,   319,   321,   323,   325,
   327,   328,   332,   335,   337,   339,   343,   345,   347,   349
};

static const short yyrhs[] = {    71,
    72,     0,    74,    73,     0,     3,     0,     0,    72,    64,
     0,    72,    76,     0,    72,   109,     0,    72,   111,     0,
     0,    73,    64,     0,    73,    75,     0,    73,    78,     0,
     4,     0,    90,     0,    91,    86,    88,   102,   106,    94,
    77,     0,   103,    83,   100,    99,     0,    28,    79,    65,
   120,   128,    66,     0,     0,     0,    35,    67,    81,    82,
     0,    36,     0,    37,     0,    38,     0,     0,    81,    82,
     0,     0,    10,    67,    84,    85,     0,    11,     0,     0,
    84,    85,     0,     0,     7,    87,    67,   135,   139,    86,
     0,     0,     8,    89,    67,   135,     0,     0,    91,   102,
   101,     0,     0,    26,    67,    92,    93,     0,    27,     0,
     0,    92,    93,     0,    95,    96,    97,     0,    23,    67,
    98,     0,    24,    67,    98,     0,     0,    25,    67,    98,
     0,    22,     0,     0,    13,    67,    61,     0,     0,    14,
    67,    61,     0,     0,     9,    67,    61,     0,     5,    67,
    47,     0,     0,    19,    67,   104,   105,     0,    20,     0,
    21,     0,     0,   104,   105,     0,     0,    15,    67,   108,
   107,     0,     0,   108,   107,     0,    16,     0,    17,     0,
    18,     0,     6,   113,    65,   120,   110,    66,     0,   124,
   121,     0,   113,    65,   117,   120,   112,    66,     0,   106,
   114,   124,   121,   125,    80,     0,    30,     0,    31,     0,
     0,    39,    67,   116,   115,     0,     0,   116,   115,     0,
    40,     0,    41,     0,    42,     0,    43,     0,     0,    32,
    67,   119,   118,     0,     0,   119,   118,     0,    33,     0,
    34,     0,   126,   127,     0,     0,    50,    67,   123,   122,
     0,     0,   123,   122,     0,    51,     0,    52,     0,    53,
     0,    54,     0,    55,     0,     0,    48,    67,    47,     0,
     0,    12,     0,     0,   130,    67,   133,     0,     0,   131,
    67,   133,     0,   132,    67,   134,   129,     0,   114,    83,
   117,    80,   106,     0,    62,     0,    63,     0,    29,     0,
   135,    68,   136,   139,     0,   137,   139,     0,   135,   139,
     0,   137,   139,     0,   138,     0,    56,     0,    61,     0,
    56,     0,    57,     0,    58,     0,     0,    59,   145,   140,
     0,    59,   141,     0,   143,     0,   142,     0,   142,    69,
   144,     0,    61,     0,    60,     0,    61,     0,    49,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   194,   195,   199,   211,   212,   213,   214,   215,   218,   219,
   220,   221,   225,   233,   237,   241,   245,   257,   279,   280,
   284,   287,   290,   296,   297,   300,   301,   305,   310,   311,
   316,   317,   334,   370,   373,   392,   396,   397,   401,   435,
   436,   439,   442,   449,   456,   463,   474,   484,   485,   492,
   493,   500,   501,   506,   519,   520,   523,   527,   533,   534,
   538,   539,   542,   543,   546,   549,   552,   560,   577,   582,
   600,   604,   613,   624,   625,   628,   629,   632,   635,   638,
   644,   650,   651,   654,   655,   659,   662,   668,   671,   672,
   675,   676,   679,   683,   686,   689,   692,   699,   700,   711,
   712,   719,   720,   724,   725,   729,   732,   736,   742,   748,
   756,   757,   761,   762,   763,   767,   776,   783,   789,   798,
   811,   812,   813,   816,   817,   820,   824,   830,   855,   861
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","SERVERCONFIG",
"CLIENTCONFIG","LOCALDOMAIN","CLIENT","INTERNAL","EXTERNAL","DEBUGING","EXTENSION",
"BIND","PRIVILEGED","IOTIMEOUT","CONNECTTIMEOUT","METHOD","NONE","GSSAPI","UNAME",
"COMPATIBILITY","REUSEADDR","SAMEPORT","USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED",
"USER_LIBWRAP","LOGOUTPUT","LOGFILE","ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS",
"PROTOCOL","PROTOCOL_TCP","PROTOCOL_UDP","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4",
"PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_MSPROXY_V2","COMMAND","COMMAND_BIND",
"COMMAND_CONNECT","COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","ACTION","AUTH",
"AUTHMETHOD","LINE","LIBWRAPSTART","OPERATOR","LOG","LOG_CONNECT","LOG_DATA",
"LOG_DISCONNECT","LOG_ERROR","LOG_IOOPERATION","IPADDRESS","DOMAIN","DIRECT",
"PORT","SERVICENAME","NUMBER","FROM","TO","'\\n'","'{'","'}'","':'","'/'","'-'",
"configtype","serverinit","serverline","clientline","clientinit","clientconfig",
"serverconfig","serveroption","route","routeinit","proxyprotocol","proxyprotocolname",
"proxyprotocol_list","extension","extensionname","extension_list","internal",
"internalinit","external","externalinit","clientoption","logoutput","logoutputdevice",
"logoutputdevice_list","users","user_privileged","user_unprivileged","user_libwrap",
"userid","iotimeout","connecttimeout","debuging","localdomain","compatibility",
"compatibilityname","compatibility_list","authmethod","authmethod_list","authmethodname",
"clientrule","clientruleoption","rule","ruleoption","verdict","command","command_list",
"commandname","protocol","protocol_list","protocolname","fromto","log","log_list",
"logname","libwrap","privileged","srcaddress","dstaddress","gateway","gatewayoption",
"from","to","via","address","gwaddress","ipaddress","netmask","domain","direct",
"port","portnumber","portrange","portstart","portservice","portend","portoperator", NULL
};
#endif

static const short yyr1[] = {     0,
    70,    70,    71,    72,    72,    72,    72,    72,    73,    73,
    73,    73,    74,    75,    76,    77,    78,    79,    80,    80,
    81,    81,    81,    82,    82,    83,    83,    84,    85,    85,
    86,    86,    87,    88,    89,    90,    91,    91,    92,    93,
    93,    94,    95,    96,    97,    97,    98,    99,    99,   100,
   100,   101,   101,   102,   103,   103,   104,   104,   105,   105,
   106,   106,   107,   107,   108,   108,   108,   109,   110,   111,
   112,   113,   113,   114,   114,   115,   115,   116,   116,   116,
   116,   117,   117,   118,   118,   119,   119,   120,   121,   121,
   122,   122,   123,   123,   123,   123,   123,   124,   124,   125,
   125,   126,   126,   127,   127,   128,   129,   130,   131,   132,
   133,   133,   134,   134,   134,   135,   136,   136,   137,   138,
   139,   139,   139,   140,   140,   141,   142,   143,   144,   145
};

static const short yyr2[] = {     0,
     2,     2,     1,     0,     2,     2,     2,     2,     0,     2,
     2,     2,     1,     1,     7,     4,     6,     0,     0,     4,
     1,     1,     1,     0,     2,     0,     4,     1,     0,     2,
     0,     6,     0,     4,     0,     3,     0,     4,     1,     0,
     2,     3,     3,     3,     0,     3,     1,     0,     3,     0,
     3,     0,     3,     3,     0,     4,     1,     1,     0,     2,
     0,     4,     0,     2,     1,     1,     1,     6,     2,     6,
     6,     1,     1,     0,     4,     0,     2,     1,     1,     1,
     1,     0,     4,     0,     2,     1,     1,     2,     0,     4,
     0,     2,     1,     1,     1,     1,     1,     0,     3,     0,
     1,     0,     3,     0,     3,     4,     5,     1,     1,     1,
     4,     2,     2,     2,     1,     1,     1,     1,     1,     1,
     0,     3,     2,     1,     1,     3,     1,     1,     1,     1
};

static const short yydefact[] = {     0,
     3,    13,     4,     9,    37,     2,     0,     0,    72,    73,
     5,     6,    31,     7,     8,     0,    18,    10,    11,    12,
    14,     0,     0,     0,    33,     0,    82,     0,     0,    52,
   102,    39,    40,     0,    35,     0,     0,   102,   102,     0,
     0,    36,   108,    98,   104,     0,    40,    38,     0,     0,
    61,     0,    61,     0,    54,     0,     0,     0,    89,   109,
    88,     0,     0,    41,   116,   121,     0,     0,     0,    86,
    87,    84,    74,     0,   110,     0,     0,    53,     0,    68,
     0,    69,     0,   119,   103,     0,   121,     0,    31,    34,
     0,     0,    55,     0,    83,    84,     0,    98,    70,    17,
     0,    99,     0,   105,     0,   112,   130,   127,   123,     0,
     0,    32,    65,    66,    67,    63,     0,     0,    15,    26,
     0,    45,    85,     0,    89,   120,    74,   121,   121,   115,
    93,    94,    95,    96,    97,    91,   118,   117,   121,     0,
   128,   122,   125,   124,    62,    63,    47,    43,     0,     0,
    50,     0,     0,    42,    78,    79,    80,    81,    76,   100,
    26,   106,   113,   114,    90,    91,   111,   129,   126,    64,
    57,    58,    59,     0,     0,    48,    44,     0,    75,    76,
   101,    19,    82,    92,    59,    56,    28,    29,     0,     0,
    16,    46,    77,     0,    71,    19,    60,    29,    27,    51,
     0,     0,    61,    30,    49,    21,    22,    23,    24,   107,
    24,    20,    25,     0,     0,     0
};

static const short yydefgoto[] = {   214,
     3,     5,     6,     4,    19,    12,   119,    20,    28,   195,
   211,   212,   151,   198,   199,    26,    34,    36,    50,    21,
    13,    47,    48,    93,    94,   122,   154,   148,   191,   176,
    42,    30,   120,   185,   186,    69,   145,   146,    14,    58,
    15,    74,    16,    98,   179,   180,    38,    95,    96,    44,
    82,   165,   166,    59,   182,    45,    61,    76,   162,    46,
    62,    77,    85,   127,    86,   139,    87,   130,    89,   142,
   109,   110,   144,   169,   111
};

static const short yypact[] = {     6,
-32768,-32768,-32768,-32768,     1,    -3,    11,   -43,-32768,-32768,
-32768,-32768,    26,-32768,-32768,   -11,-32768,-32768,-32768,-32768,
-32768,    21,    -6,    16,-32768,    52,    30,    -2,    -1,    55,
     5,-32768,    16,     3,-32768,    21,     4,     5,     5,    22,
     7,-32768,-32768,    20,     9,     8,    16,-32768,    17,    10,
    61,    13,    61,    49,-32768,    18,    14,    23,    33,-32768,
-32768,    15,    -8,-32768,-32768,    25,    17,    24,    57,-32768,
-32768,    13,    46,    27,-32768,    28,    29,-32768,    39,-32768,
    31,-32768,    -8,-32768,-32768,    34,    25,   -44,    26,-32768,
    12,    36,    68,    64,-32768,    13,    37,    20,-32768,-32768,
   -21,-32768,   -39,-32768,   -50,-32768,-32768,-32768,-32768,    38,
   -10,-32768,-32768,-32768,-32768,    12,    70,    41,-32768,    80,
    42,    72,-32768,   -22,    33,-32768,    46,    25,    25,-32768,
-32768,-32768,-32768,-32768,-32768,   -39,-32768,-32768,    25,    40,
-32768,-32768,-32768,-32768,-32768,    12,-32768,-32768,    32,    43,
    81,    70,    44,-32768,-32768,-32768,-32768,-32768,   -22,    87,
    80,-32768,-32768,-32768,-32768,   -39,-32768,-32768,-32768,-32768,
-32768,-32768,    32,    89,    45,    92,-32768,    70,-32768,   -22,
-32768,    71,    30,-32768,    32,-32768,-32768,    89,    53,    48,
-32768,-32768,-32768,    50,-32768,    71,-32768,    89,-32768,-32768,
    58,     2,    61,-32768,-32768,-32768,-32768,-32768,     2,-32768,
     2,-32768,-32768,   113,   116,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,   -78,
   -82,   -90,   -38,   -52,   -74,    47,-32768,-32768,-32768,-32768,
   119,   102,    82,-32768,-32768,-32768,-32768,  -144,-32768,-32768,
-32768,    91,-32768,   -19,   -57,   -53,   -15,    51,-32768,-32768,
-32768,-32768,   125,    35,   -47,    54,   -49,    56,    83,    19,
    59,   -29,    60,    62,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,    63,-32768,   -45,-32768,    65,-32768,   -84,-32768,
-32768,    66,-32768,-32768,-32768
};


#define	YYLAST		184


static const short yytable[] = {    73,
    -1,   -37,   106,    66,   107,   137,     7,   177,     1,     2,
   138,   131,   132,   133,   134,   135,   108,   155,   156,   157,
   158,    90,     8,    24,    17,    29,     8,   113,   114,   115,
     9,    10,    25,   192,    65,    84,   126,   206,   207,   208,
     9,    10,    32,   163,   164,    70,    71,    65,    84,   141,
   108,   171,   172,    27,   167,   128,    53,    54,    31,    35,
    18,    37,    39,    41,    11,    40,    43,    57,    55,    49,
    52,    60,    65,    56,    63,    68,    67,    75,    78,    92,
    79,    83,    81,    88,    97,   102,   118,   121,    80,   150,
    91,   147,    99,   100,   175,   101,   153,   103,   181,   187,
   168,   105,   117,   124,   190,   194,   140,   149,   152,   174,
   178,   189,   215,   200,   201,   216,   202,   203,   205,   209,
   213,   188,   183,   204,    22,    33,    51,   197,    64,   173,
   170,    23,   193,   196,    72,   112,   184,     0,     0,     0,
     0,   116,     0,     0,     0,   104,     0,     0,     0,   210,
     0,   123,     0,     0,     0,     0,     0,     0,     0,   125,
     0,   161,   136,     0,     0,   129,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,   143,   159,     0,     0,
     0,     0,     0,   160
};

static const short yycheck[] = {    53,
     0,     5,    87,    49,    49,    56,     6,   152,     3,     4,
    61,    51,    52,    53,    54,    55,    61,    40,    41,    42,
    43,    67,    26,    67,    28,     5,    26,    16,    17,    18,
    30,    31,     7,   178,    56,    57,    58,    36,    37,    38,
    30,    31,    27,   128,   129,    33,    34,    56,    57,    60,
    61,    20,    21,    65,   139,   101,    38,    39,    65,     8,
    64,    32,    65,     9,    64,    67,    62,    48,    47,    67,
    67,    63,    56,    67,    67,    15,    67,    29,    61,    23,
    67,    67,    50,    59,    39,    47,    19,    24,    66,    10,
    67,    22,    66,    66,    14,    67,    25,    67,    12,    11,
    61,    68,    67,    67,    13,    35,    69,    67,    67,    67,
    67,    67,     0,    61,    67,     0,    67,   196,    61,   202,
   211,   174,   161,   198,     6,    24,    36,   185,    47,   149,
   146,     7,   180,   183,    52,    89,   166,    -1,    -1,    -1,
    -1,    91,    -1,    -1,    -1,    83,    -1,    -1,    -1,   203,
    -1,    96,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    98,
    -1,   127,   103,    -1,    -1,   101,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    -1,   111,   124,    -1,    -1,
    -1,    -1,    -1,   125
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/local/share/bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

#ifndef alloca
#ifdef __GNUC__
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi)
#include <alloca.h>
#else /* not sparc */
#if defined (MSDOS) && !defined (__TURBOC__)
#include <malloc.h>
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
#include <malloc.h>
 #pragma alloca
#else /* not MSDOS, __TURBOC__, or _AIX */
#ifdef __hpux
#ifdef __cplusplus
extern "C" {
void *alloca (unsigned int);
};
#else /* not __cplusplus */
void *alloca ();
#endif /* not __cplusplus */
#endif /* __hpux */
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc.  */
#endif /* not GNU C.  */
#endif /* alloca not defined.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	return(0)
#define YYABORT 	return(1)
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
int yyparse (void);
#endif

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, int count)
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 196 "/usr/local/share/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
      yyss = (short *) alloca (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1, size * sizeof (*yyssp));
      yyvs = (YYSTYPE *) alloca (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1, size * sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) alloca (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1, size * sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 3:
#line 199 "config_parse.y"
{
#ifdef SOCKS_SERVER
		extension 	= &config.extension;	
		methodv		= config.methodv;
		methodc		= &config.methodc;
		src.atype 	= SOCKS_ADDR_IPV4;
		dst.atype 	= SOCKS_ADDR_IPV4;
#endif
	;
    break;}
case 4:
#line 211 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 9:
#line 218 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 13:
#line 225 "config_parse.y"
{
		/* abuse the fact that INADDR_ANY is 0. */
		src.atype 	= SOCKS_ADDR_IPV4;
		dst.atype 	= SOCKS_ADDR_IPV4;
	;
    break;}
case 17:
#line 245 "config_parse.y"
{
#ifdef SOCKS_CLIENT
		route.src		= src;
		route.dst 		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
#endif
	;
    break;}
case 18:
#line 257 "config_parse.y"
{
#ifdef SOCKS_CLIENT
		command			= &state.command;
		extension 		= &state.extension;	
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
	;
    break;}
case 19:
#line 279 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 21:
#line 284 "config_parse.y"
{
			proxyprotocol->socks_v4 = 1;
	;
    break;}
case 22:
#line 287 "config_parse.y"
{
			proxyprotocol->socks_v5 = 1;
	;
    break;}
case 23:
#line 290 "config_parse.y"
{
			proxyprotocol->msproxy_v2 = 1;
	;
    break;}
case 24:
#line 296 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 26:
#line 300 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 28:
#line 305 "config_parse.y"
{
			extension->bind = 1;
	;
    break;}
case 29:
#line 310 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 31:
#line 316 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 32:
#line 317 "config_parse.y"
{
#ifdef SOCKS_SERVER
		if (config.state.init) {
			int i;

			for (i = 0; i < config.internalc; ++i)
				if (config.internalv[i].addr.sin_addr.s_addr == ipaddr->s_addr
				&&	 config.internalv[i].addr.sin_port == *port_tcp)
					break;

			if (i == config.internalc)
				swarnx("can not change internal address' once running");
		}
#endif /* SOCKS_SERVER */
	;
    break;}
case 33:
#line 334 "config_parse.y"
{
#ifdef SOCKS_SERVER
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
		
		ipaddr 		= &config.internalv[config.internalc - 1].addr.sin_addr;
		port_tcp 	= &config.internalv[config.internalc - 1].addr.sin_port;

		if ((service = getservbyname("socks", "tcp")) == NULL)
			*port_tcp = htons(SOCKD_PORT);
		else
			*port_tcp = service->s_port;
	}
	else { /* can only set internal address' once. */
		static struct in_addr inaddrmem;
		static in_port_t portmem;

		ipaddr 		= &inaddrmem;
		port_tcp		= &portmem;
	}
#endif
	;
    break;}
case 35:
#line 373 "config_parse.y"
{
#ifdef SOCKS_SERVER
		static struct ruleaddress_t mem;

		if ((config.externalv = (struct sockaddr_in *)realloc(config.externalv,
		sizeof(*config.externalv) * ++config.externalc)) == NULL)
			yyerror(NOMEM);

		bzero(&config.externalv[config.externalc - 1], sizeof(*config.externalv));
		config.externalv[config.externalc - 1].sin_family = AF_INET;
		
		addressinit(&mem);

		ipaddr 	= &config.externalv[config.externalc - 1].sin_addr;
#endif
	;
    break;}
case 37:
#line 396 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 39:
#line 401 "config_parse.y"
{
		if (!config.state.init) {
			if (strcmp(yyvsp[0].string, "syslog") == 0)	
				config.log.type |= LOGTYPE_SYSLOG;
			else {
				config.log.type |= LOGTYPE_FILE;
				
				if ((config.log.fpv = (FILE **)realloc(config.log.fpv, 
				sizeof(*config.log.fpv) * config.log.fpc + 1)) == NULL
				|| (config.log.fplockv = (int *)realloc(config.log.fplockv,
				sizeof(*config.log.fplockv) * config.log.fpc + 1)) == NULL)
					serrx(EXIT_FAILURE, NOMEM);
				++config.log.fpc;

				if ((config.log.fplockv[config.log.fpc - 1]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp(yyvsp[0].string, "stdout") == 0)
					config.log.fpv[config.log.fpc - 1] = stdout;
				else if (strcmp(yyvsp[0].string, "stderr") == 0)
					config.log.fpv[config.log.fpc - 1] = stderr;
				else
					if ((config.log.fpv[config.log.fpc - 1] = fopen(yyvsp[0].string, "a"))
					== NULL)
						serr(EXIT_FAILURE, "fopen(%s)", yyvsp[0].string);
			}
		}
		else 
			;	/* XXX warn/exit if output changed. */
	;
    break;}
case 40:
#line 435 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 43:
#line 442 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.uid.privileged = yyvsp[0].uid;
#endif
	;
    break;}
case 44:
#line 449 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.uid.unprivileged = yyvsp[0].uid;
#endif
	;
    break;}
case 45:
#line 456 "config_parse.y"
{ 
#ifdef SOCKS_SERVER

#ifdef HAVE_LIBWRAP
		config.uid.libwrap = config.uid.unprivileged;	/* default. */
#endif  /* HAVE_LIBWRAP */
	;
    break;}
case 46:
#line 463 "config_parse.y"
{
#ifndef HAVE_LIBWRAP
		yyerror("libwrap support not compiled in");
#endif  /* HAVE_LIBWRAP */
		config.uid.libwrap = yyvsp[0].uid;

#endif /* SOCKS_SERVER */
	;
    break;}
case 47:
#line 474 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serr(EXIT_FAILURE, yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	;
    break;}
case 48:
#line 484 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 49:
#line 485 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.timeout.io = atol(yyvsp[0].string);
#endif
	;
    break;}
case 50:
#line 492 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 51:
#line 493 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.timeout.negotiate = atol(yyvsp[0].string);
#endif
	;
    break;}
case 52:
#line 500 "config_parse.y"
{	yyval.string = NULL; ;
    break;}
case 53:
#line 501 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	;
    break;}
case 54:
#line 506 "config_parse.y"
{
		const char *skip = "\t\n";

		/* lose whitespace from line. */
		yyvsp[0].string += strspn(yyvsp[0].string, skip);
		yyvsp[0].string[strcspn(yyvsp[0].string, skip)] = NUL; 

		if (strlen(yyvsp[0].string) >= sizeof(config.domain))
			yyerror("domainname too long");
		strcpy(config.domain, yyvsp[0].string);
	;
    break;}
case 55:
#line 519 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 57:
#line 523 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.compat.reuseaddr = 1;	
	;
    break;}
case 58:
#line 527 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	;
    break;}
case 59:
#line 533 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 61:
#line 538 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 63:
#line 542 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 65:
#line 546 "config_parse.y"
{
		methodv[(*methodc)++] = AUTHMETHOD_NONE; 
	;
    break;}
case 66:
#line 549 "config_parse.y"
{
		yyerror("GSSAPI not supported");	
	;
    break;}
case 67:
#line 552 "config_parse.y"
{
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
	;
    break;}
case 68:
#line 560 "config_parse.y"
{
#ifdef SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addclient(&rule); 

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		bzero(&rule, sizeof(rule));

		src.atype = SOCKS_ADDR_IPV4;
		dst.atype = SOCKS_ADDR_IPV4;
#endif
	;
    break;}
case 70:
#line 582 "config_parse.y"
{
#ifdef SOCKS_SERVER
		rule.src = src;
		rule.dst = dst;

		addrule(&rule); 

		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		bzero(&rule, sizeof(rule));

		src.atype	= SOCKS_ADDR_IPV4;
		dst.atype	= SOCKS_ADDR_IPV4;
#endif
	;
    break;}
case 72:
#line 604 "config_parse.y"
{
#ifdef SOCKS_SERVER
		rule.verdict 	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol 		= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
	;
    break;}
case 73:
#line 613 "config_parse.y"
{
		rule.verdict 	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol 		= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
#endif 
	;
    break;}
case 74:
#line 624 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 76:
#line 628 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 78:
#line 632 "config_parse.y"
{
			command->bind = 1;
	;
    break;}
case 79:
#line 635 "config_parse.y"
{
			command->connect = 1;
	;
    break;}
case 80:
#line 638 "config_parse.y"
{
			command->udpassociate = 1;
	;
    break;}
case 81:
#line 644 "config_parse.y"
{
			command->bindreply = 1;
	;
    break;}
case 82:
#line 650 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 84:
#line 654 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 86:
#line 659 "config_parse.y"
{
		protocol->tcp = 1;
	;
    break;}
case 87:
#line 662 "config_parse.y"
{
		protocol->udp = 1;
	;
    break;}
case 89:
#line 671 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 91:
#line 675 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 93:
#line 679 "config_parse.y"
{
#ifdef SOCKS_SERVER
	rule.log.connect = 1;
	;
    break;}
case 94:
#line 683 "config_parse.y"
{
			rule.log.data = 1;
	;
    break;}
case 95:
#line 686 "config_parse.y"
{
			rule.log.disconnect = 1;
	;
    break;}
case 96:
#line 689 "config_parse.y"
{
			rule.log.error = 1;
	;
    break;}
case 97:
#line 692 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	;
    break;}
case 98:
#line 699 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 99:
#line 700 "config_parse.y"
{
#if defined(HAVE_LIBWRAP) && defined(SOCKS_SERVER)
		if (strlen(yyvsp[0].string) >= sizeof(rule.libwrap))
			yyerror("libwrap line too long.  Make buffer bigger");
		strcpy(rule.libwrap, yyvsp[0].string);
#else		
		yyerror("libwrap support not compiled in");
#endif
	;
    break;}
case 100:
#line 711 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 101:
#line 712 "config_parse.y"
{
#ifdef SOCKSSERVER
		rule.privileged = 1;
#endif
	;
    break;}
case 102:
#line 719 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 104:
#line 724 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 108:
#line 736 "config_parse.y"
{
		addressinit(&src);
	;
    break;}
case 109:
#line 742 "config_parse.y"
{
		addressinit(&dst);
	;
    break;}
case 110:
#line 748 "config_parse.y"
{
#ifdef SOCKS_CLIENT
		addressinit(&gw);
#endif
	;
    break;}
case 116:
#line 767 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address");
	;
    break;}
case 117:
#line 776 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask");

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	;
    break;}
case 118:
#line 783 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask");
	;
    break;}
case 119:
#line 789 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);
	;
    break;}
case 120:
#line 798 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);

#ifdef SOCKS_CLIENT
		route.state.direct = 1;
#endif
	;
    break;}
case 121:
#line 811 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 127:
#line 824 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= *port_tcp;
	;
    break;}
case 128:
#line 830 "config_parse.y"
{
		struct servent	*service;
		struct protocol_t	protocolunset;
		
		bzero(&protocolunset, sizeof(protocolunset));

		/* set all protocols if none set, default. */
		if (memcmp(protocol, &protocolunset, sizeof(*protocol)) == 0)
			memset(protocol, UCHAR_MAX, sizeof(*protocol));

		if (protocol->tcp) {
			if ((service = getservbyname(yyvsp[0].string, "tcp")) == NULL)
				yyerror("bad servicename for tcp");
			*port_tcp = (in_port_t)service->s_port;
		}

		if (protocol->udp) {
			if ((service = getservbyname(yyvsp[0].string, "udp")) == NULL)
				yyerror("bad servicename for udp");
			*port_udp = (in_port_t)service->s_port;
		}
	;
    break;}
case 129:
#line 855 "config_parse.y"
{
		ruleaddress->portend = htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator = range;
	;
    break;}
case 130:
#line 861 "config_parse.y"
{
		*operator = string2operator(yyvsp[0].string);
	;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 498 "/usr/local/share/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;
}
#line 867 "config_parse.y"


#define INTERACTIVE 0

extern FILE *yyin;

int parseinit;

int
readconfig(fp)
	FILE *fp;
{

	yydebug = 0;
	parseinit = 0;

	yyin = fp;

	yyparse();

#ifdef SOCKS_CLIENT	/* client never rereads configfile. */
	fclose(yyin);
#endif

	errno = 0;	/* yacc for some reason alters errno atleast sometimes. */

	return 0;
}


static void
yyerror(s)
	const char *s;
{

	serrx(1, "%s: %d: %s near '%.50s'",
	config.option.configfile, yylineno, s,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);
}


static void
addressinit(address)
	struct ruleaddress_t *address;
{
		ruleaddress	= address;

		atype			= &ruleaddress->atype;
		ipaddr 		= &ruleaddress->addr.ipv4.ip;
		netmask 		= &ruleaddress->addr.ipv4.mask;
		domain		= ruleaddress->addr.domain;
		port_tcp 	= &ruleaddress->port.tcp;
		port_udp 	= &ruleaddress->port.udp;
		operator		= &ruleaddress->operator;
}
