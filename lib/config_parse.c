
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
#define	DEPRECATED	260
#define	CLIENTRULE	261
#define	INTERNAL	262
#define	EXTERNAL	263
#define	DEBUGING	264
#define	RESOLVEPROTOCOL	265
#define	SRCHOST	266
#define	NOMISMATCH	267
#define	NOUNKNOWN	268
#define	EXTENSION	269
#define	BIND	270
#define	PRIVILEGED	271
#define	IOTIMEOUT	272
#define	CONNECTTIMEOUT	273
#define	METHOD	274
#define	NONE	275
#define	GSSAPI	276
#define	UNAME	277
#define	COMPATIBILITY	278
#define	REUSEADDR	279
#define	SAMEPORT	280
#define	USERNAME	281
#define	USER_PRIVILEGED	282
#define	USER_UNPRIVILEGED	283
#define	USER_LIBWRAP	284
#define	LOGOUTPUT	285
#define	LOGFILE	286
#define	ROUTE	287
#define	VIA	288
#define	VERDICT_BLOCK	289
#define	VERDICT_PASS	290
#define	PROTOCOL	291
#define	PROTOCOL_TCP	292
#define	PROTOCOL_UDP	293
#define	PROTOCOL_FAKE	294
#define	PROXYPROTOCOL	295
#define	PROXYPROTOCOL_SOCKS_V4	296
#define	PROXYPROTOCOL_SOCKS_V5	297
#define	PROXYPROTOCOL_MSPROXY_V2	298
#define	COMMAND	299
#define	COMMAND_BIND	300
#define	COMMAND_CONNECT	301
#define	COMMAND_UDPASSOCIATE	302
#define	COMMAND_BINDREPLY	303
#define	ACTION	304
#define	LINE	305
#define	LIBWRAPSTART	306
#define	OPERATOR	307
#define	LOG	308
#define	LOG_CONNECT	309
#define	LOG_DATA	310
#define	LOG_DISCONNECT	311
#define	LOG_ERROR	312
#define	LOG_IOOPERATION	313
#define	IPADDRESS	314
#define	DOMAIN	315
#define	DIRECT	316
#define	PORT	317
#define	PORTNUMBER	318
#define	SERVICENAME	319
#define	NUMBER	320
#define	FROM	321
#define	TO	322

#line 44 "config_parse.y"


#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.97 1999/05/13 13:13:00 karls Exp $";

__BEGIN_DECLS

#if HAVE_LIBWRAP && SOCKS_SERVER
	extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && SOCKS_SERVER */

static void
addressinit __P((struct ruleaddress_t *address));

static void
yyerror __P((const char *s));
/*
 * Report a error related to (configfile) parsing.
*/

__END_DECLS

/* hmm. */
extern int yylex();
extern int yyparse();

extern struct config_t config;

extern int yylineno;
extern char *yytext;

#if SOCKS_SERVER
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
static struct ruleaddress_t	*ruleaddress;	/* current ruleaddress				*/
static struct extension_t		*extension;		/* new extensions						*/
static struct proxyprotocol_t	*proxyprotocol;/* proxy protocol.					*/

static char							*atype;			/* atype of new address.			*/
static struct in_addr			*ipaddr;			/* new ipaddress						*/
static struct in_addr			*netmask;		/* new netmask							*/
static char							*domain;			/* new domain.							*/

static in_port_t					*port_tcp;		/* new tcp portnumber.				*/
static in_port_t					*port_udp;		/* new udp portnumber.				*/
static char							*methodv;		/* new authmethods.					*/
static unsigned char				*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/


#define YYDEBUG 1


#line 115 "config_parse.y"
typedef union {
	char	*string;
	uid_t	uid;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		228
#define	YYFLAG		-32768
#define	YYNTBASE	74

#define YYTRANSLATE(x) ((unsigned)(x) <= 322 ? yytranslate[x] : 157)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    68,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,    73,     2,    72,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    71,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    69,     2,    70,     2,     2,     2,     2,     2,
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
    56,    57,    58,    59,    60,    61,    62,    63,    64,    65,
    66,    67
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     3,     6,     8,     9,    12,    15,    18,    21,    22,
    25,    28,    31,    33,    35,    37,    39,    41,    43,    45,
    47,    49,    51,    53,    55,    57,    59,    61,    63,    65,
    74,    75,    79,    81,    83,    85,    87,    90,    94,    96,
    98,   101,   107,   108,   113,   114,   116,   118,   120,   124,
   126,   128,   131,   133,   135,   137,   141,   145,   149,   151,
   155,   159,   163,   167,   169,   171,   173,   176,   180,   182,
   184,   186,   190,   192,   194,   196,   199,   203,   205,   207,
   209,   211,   214,   222,   224,   226,   227,   230,   237,   239,
   241,   243,   245,   247,   249,   250,   253,   255,   257,   261,
   263,   265,   267,   269,   271,   274,   278,   280,   282,   284,
   287,   290,   294,   296,   298,   300,   302,   304,   306,   309,
   313,   317,   321,   325,   327,   329,   331,   333,   335,   336,
   339,   341,   343,   345,   350,   353,   356,   359,   361,   363,
   365,   367,   369,   371,   372,   376,   379,   381,   383,   387,
   389,   391,   393
};

static const short yyrhs[] = {    75,
    76,     0,    78,    77,     0,     3,     0,     0,    76,    68,
     0,    76,    80,     0,    76,   118,     0,    76,   121,     0,
     0,    77,    68,     0,    77,    79,     0,    77,    83,     0,
     4,     0,    95,     0,    82,     0,   115,     0,    82,     0,
    91,     0,    93,     0,    96,     0,    81,     0,    99,     0,
   107,     0,   105,     0,    88,     0,   104,     0,   110,     0,
   112,     0,     5,     0,    32,    84,    69,   140,   131,   138,
   140,    70,     0,     0,    40,    71,    87,     0,    41,     0,
    42,     0,    43,     0,    86,     0,    86,    87,     0,    14,
    71,    90,     0,    15,     0,    89,     0,    89,    90,     0,
     7,    92,    71,   146,   150,     0,     0,     8,    94,    71,
   146,     0,     0,    96,     0,   106,     0,   110,     0,    30,
    71,    98,     0,    31,     0,    97,     0,    97,    98,     0,
   100,     0,   101,     0,   102,     0,    27,    71,   103,     0,
    28,    71,   103,     0,    29,    71,   103,     0,    26,     0,
    17,    71,    65,     0,    18,    71,    65,     0,     9,    71,
    65,     0,    23,    71,   109,     0,    24,     0,    25,     0,
   108,     0,   108,   109,     0,    10,    71,   111,     0,    39,
     0,    37,     0,    38,     0,    11,    71,   114,     0,    12,
     0,    13,     0,   113,     0,   113,   114,     0,    19,    71,
   117,     0,    20,     0,    21,     0,    22,     0,   116,     0,
   116,   117,     0,     6,   124,    69,   120,   131,   120,    70,
     0,   135,     0,   132,     0,     0,   119,   120,     0,   124,
    69,   123,   131,   123,    70,     0,   115,     0,   125,     0,
   135,     0,   132,     0,   128,     0,    85,     0,     0,   122,
   123,     0,    34,     0,    35,     0,    44,    71,   127,     0,
    45,     0,    46,     0,    47,     0,    48,     0,   126,     0,
   126,   127,     0,    36,    71,   130,     0,    37,     0,    38,
     0,   129,     0,   129,   130,     0,   136,   137,     0,    53,
    71,   134,     0,    54,     0,    55,     0,    56,     0,    57,
     0,    58,     0,   133,     0,   133,   134,     0,    51,    71,
    50,     0,   141,    71,   144,     0,   142,    71,   144,     0,
   143,    71,   145,     0,   125,     0,    88,     0,   128,     0,
    85,     0,   115,     0,     0,   139,   140,     0,    66,     0,
    67,     0,    33,     0,   146,    72,   147,   150,     0,   148,
   150,     0,   146,   150,     0,   148,   150,     0,   149,     0,
    59,     0,    65,     0,    59,     0,    60,     0,    61,     0,
     0,    62,   156,   151,     0,    62,   152,     0,   154,     0,
   153,     0,   153,    73,   155,     0,    63,     0,    64,     0,
    63,     0,    52,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   202,   203,   207,   218,   219,   220,   221,   222,   225,   226,
   227,   228,   232,   236,   237,   240,   241,   242,   243,   244,
   245,   246,   249,   250,   251,   252,   253,   254,   258,   262,
   274,   296,   299,   302,   305,   310,   311,   315,   318,   323,
   324,   328,   345,   381,   390,   408,   409,   410,   413,   416,
   449,   450,   453,   454,   455,   458,   466,   474,   487,   497,
   504,   511,   516,   519,   523,   529,   530,   533,   536,   539,
   542,   547,   550,   554,   562,   563,   567,   570,   573,   576,
   581,   582,   588,   605,   606,   609,   610,   613,   631,   632,
   633,   634,   635,   636,   639,   640,   643,   652,   663,   666,
   669,   672,   678,   683,   684,   687,   690,   693,   698,   699,
   703,   706,   709,   713,   716,   719,   722,   728,   729,   733,
   758,   762,   766,   769,   770,   771,   772,   773,   776,   777,
   780,   786,   792,   800,   801,   805,   806,   807,   811,   820,
   827,   833,   842,   855,   856,   857,   860,   861,   864,   868,
   874,   922,   928
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","SERVERCONFIG",
"CLIENTCONFIG","DEPRECATED","CLIENTRULE","INTERNAL","EXTERNAL","DEBUGING","RESOLVEPROTOCOL",
"SRCHOST","NOMISMATCH","NOUNKNOWN","EXTENSION","BIND","PRIVILEGED","IOTIMEOUT",
"CONNECTTIMEOUT","METHOD","NONE","GSSAPI","UNAME","COMPATIBILITY","REUSEADDR",
"SAMEPORT","USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","LOGOUTPUT",
"LOGFILE","ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS","PROTOCOL","PROTOCOL_TCP",
"PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5",
"PROXYPROTOCOL_MSPROXY_V2","COMMAND","COMMAND_BIND","COMMAND_CONNECT","COMMAND_UDPASSOCIATE",
"COMMAND_BINDREPLY","ACTION","LINE","LIBWRAPSTART","OPERATOR","LOG","LOG_CONNECT",
"LOG_DATA","LOG_DISCONNECT","LOG_ERROR","LOG_IOOPERATION","IPADDRESS","DOMAIN",
"DIRECT","PORT","PORTNUMBER","SERVICENAME","NUMBER","FROM","TO","'\\n'","'{'",
"'}'","':'","'/'","'-'","configtype","serverinit","serverline","clientline",
"clientinit","clientconfig","serverconfig","serveroption","deprecated","route",
"routeinit","proxyprotocol","proxyprotocolname","proxyprotocols","extension",
"extensionname","extensions","internal","internalinit","external","externalinit",
"clientoption","logoutput","logoutputdevice","logoutputdevices","users","user_privileged",
"user_unprivileged","user_libwrap","userid","iotimeout","connecttimeout","debuging",
"compatibility","compatibilityname","compatibilitys","resolveprotocol","resolveprotocolname",
"srchost","srchostoption","srchostoptions","authmethod","authmethodname","authmethods",
"clientrule","clientruleoption","clientruleoptions","rule","ruleoption","ruleoptions",
"verdict","command","commandname","commands","protocol","protocolname","protocols",
"fromto","log","logname","logs","libwrap","srcaddress","dstaddress","gateway",
"routeoption","routeoptions","from","to","via","address","gwaddress","ipaddress",
"netmask","domain","direct","port","portnumber","portrange","portstart","portservice",
"portend","portoperator", NULL
};
#endif

static const short yyr1[] = {     0,
    74,    74,    75,    76,    76,    76,    76,    76,    77,    77,
    77,    77,    78,    79,    79,    80,    80,    80,    80,    80,
    80,    80,    81,    81,    81,    81,    81,    81,    82,    83,
    84,    85,    86,    86,    86,    87,    87,    88,    89,    90,
    90,    91,    92,    93,    94,    95,    95,    95,    96,    97,
    98,    98,    99,    99,    99,   100,   101,   102,   103,   104,
   105,   106,   107,   108,   108,   109,   109,   110,   111,   111,
   111,   112,   113,   113,   114,   114,   115,   116,   116,   116,
   117,   117,   118,   119,   119,   120,   120,   121,   122,   122,
   122,   122,   122,   122,   123,   123,   124,   124,   125,   126,
   126,   126,   126,   127,   127,   128,   129,   129,   130,   130,
   131,   132,   133,   133,   133,   133,   133,   134,   134,   135,
   136,   137,   138,   139,   139,   139,   139,   139,   140,   140,
   141,   142,   143,   144,   144,   145,   145,   145,   146,   147,
   147,   148,   149,   150,   150,   150,   151,   151,   152,   153,
   154,   155,   156
};

static const short yyr2[] = {     0,
     2,     2,     1,     0,     2,     2,     2,     2,     0,     2,
     2,     2,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     8,
     0,     3,     1,     1,     1,     1,     2,     3,     1,     1,
     2,     5,     0,     4,     0,     1,     1,     1,     3,     1,
     1,     2,     1,     1,     1,     3,     3,     3,     1,     3,
     3,     3,     3,     1,     1,     1,     2,     3,     1,     1,
     1,     3,     1,     1,     1,     2,     3,     1,     1,     1,
     1,     2,     7,     1,     1,     0,     2,     6,     1,     1,
     1,     1,     1,     1,     0,     2,     1,     1,     3,     1,
     1,     1,     1,     1,     2,     3,     1,     1,     1,     2,
     2,     3,     1,     1,     1,     1,     1,     1,     2,     3,
     3,     3,     3,     1,     1,     1,     1,     1,     0,     2,
     1,     1,     1,     4,     2,     2,     2,     1,     1,     1,
     1,     1,     1,     0,     3,     2,     1,     1,     3,     1,
     1,     1,     1
};

static const short yydefact[] = {     0,
     3,    13,     4,     9,     1,     2,    29,     0,    43,    45,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,    97,    98,     5,     6,    21,    17,    25,    18,    19,
    20,    22,    53,    54,    55,    26,    24,    23,    27,    28,
    16,     7,     8,     0,     0,    31,    10,    11,    15,    12,
    14,    46,    47,    48,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,    95,     0,
     0,    86,     0,     0,    70,    71,    69,    68,    73,    74,
    75,    72,    39,    40,    38,    60,    61,    78,    79,    80,
    81,    77,    64,    65,    66,    63,    59,    56,    57,    58,
    50,    51,    49,     0,     0,     0,     0,     0,    94,    89,
    95,     0,    90,    93,    92,    91,    62,   129,    86,     0,
    85,    84,   139,   144,    44,    76,    41,    82,    67,    52,
     0,     0,     0,     0,     0,    96,   131,    95,     0,     0,
   127,   125,   128,   124,   126,   129,     0,    87,    86,     0,
    42,   107,   108,   109,   106,    33,    34,    35,    36,    32,
   100,   101,   102,   103,   104,    99,   120,   113,   114,   115,
   116,   117,   118,   112,     0,   132,   111,     0,     0,   130,
     0,     0,   153,   150,   146,     0,     0,   110,    37,   105,
   119,    88,     0,   142,   121,     0,   144,   133,   129,     0,
    83,     0,   151,   145,   148,   147,   122,     0,   135,     0,
     0,   152,   149,   141,   140,   144,    30,   143,   123,   144,
   144,   138,   134,   136,   137,     0,     0,     0
};

static const short yydefgoto[] = {   226,
     3,     5,     6,     4,    48,    25,    26,    27,    50,    71,
   109,   159,   160,   142,    84,    85,    29,    56,    30,    57,
    51,    31,   102,   103,    32,    33,    34,    35,    98,    36,
    37,    53,    38,    95,    96,    39,    78,    40,    81,    82,
   110,    91,    92,    42,   119,   120,    43,   111,   112,    44,
   113,   165,   166,   114,   154,   155,   138,   115,   173,   174,
   116,   139,   177,   199,   146,   147,   140,   178,   200,   195,
   219,   196,   216,   197,   222,   151,   204,   185,   186,   206,
   213,   187
};

static const short yypact[] = {   103,
-32768,-32768,-32768,-32768,     7,    34,-32768,    74,-32768,-32768,
   -60,   -55,   -52,   -48,   -44,   -31,   -12,    -9,    -6,    -3,
    -1,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,    32,     3,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,    51,    41,    52,    55,    98,    61,
    63,    64,    75,    90,    99,    99,    99,    93,    10,    65,
    62,     5,    73,    73,-32768,-32768,-32768,-32768,-32768,-32768,
    98,-32768,-32768,    61,-32768,-32768,-32768,-32768,-32768,-32768,
    75,-32768,-32768,-32768,    90,-32768,-32768,-32768,-32768,-32768,
-32768,    93,-32768,    66,    67,    69,    71,    72,-32768,-32768,
    10,    68,-32768,-32768,-32768,-32768,-32768,    33,     5,    68,
-32768,-32768,-32768,    82,-32768,-32768,-32768,-32768,-32768,-32768,
    79,    57,    43,    83,    24,-32768,-32768,    10,    78,    76,
-32768,-32768,-32768,-32768,-32768,    33,    68,-32768,     5,   -43,
-32768,-32768,-32768,    79,-32768,-32768,-32768,-32768,    57,-32768,
-32768,-32768,-32768,-32768,    43,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,    24,-32768,    80,-32768,-32768,    77,    59,-32768,
   102,    81,-32768,-32768,-32768,    84,    58,-32768,-32768,-32768,
-32768,-32768,    59,-32768,-32768,    86,    82,-32768,    33,    85,
-32768,    89,-32768,-32768,-32768,-32768,-32768,   -14,-32768,    91,
    44,-32768,-32768,-32768,-32768,    82,-32768,-32768,-32768,    82,
    82,-32768,-32768,-32768,-32768,   136,   146,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,   143,-32768,-32768,
  -115,-32768,    -4,   148,-32768,    70,-32768,-32768,-32768,-32768,
-32768,   153,-32768,    87,-32768,-32768,-32768,-32768,    60,-32768,
-32768,-32768,-32768,-32768,    88,   154,-32768,-32768,-32768,    92,
    -5,-32768,    94,-32768,-32768,  -111,-32768,-32768,   -89,   155,
  -114,-32768,     0,  -113,-32768,     8,   -92,   -66,-32768,    -7,
   -62,-32768,-32768,-32768,-32768,  -139,-32768,-32768,-32768,   -29,
-32768,   -72,-32768,   -42,-32768,  -149,-32768,-32768,   -20,-32768,
-32768,-32768
};


#define	YYLAST		194


static const short yytable[] = {    41,
   124,   125,   141,   144,   145,   121,   180,   148,   183,   122,
    58,     7,     8,     9,    10,    59,    11,    12,    60,   184,
    13,   136,    61,    14,    15,    16,    62,   149,    16,    17,
   141,   144,   145,    18,    19,    20,    21,   182,     7,    63,
    22,    23,    45,    11,   214,   104,    13,   209,   175,   105,
   215,    16,   121,   106,   181,   107,   122,   108,    64,   210,
   107,    65,   108,    21,    66,    46,   223,    67,   104,    68,
   224,   225,   105,    70,    24,    83,   106,   168,   169,   170,
   171,   172,   121,   141,   144,   145,   122,   161,   162,   163,
   164,    75,    76,    77,    88,    89,    90,   156,   157,   158,
    69,    47,   123,   194,   218,     1,     2,    22,    23,    79,
    80,    73,   143,    93,    94,   152,   153,   123,   194,    72,
   184,   203,    74,   101,    97,    99,   100,    86,    87,   117,
   118,   123,   167,   137,   198,   227,   131,   132,   220,   133,
   143,   134,   135,   150,   176,   228,   179,   193,    49,   192,
   201,   212,    28,   127,   189,   211,   202,   208,    52,    54,
   217,   188,    55,   207,   190,   191,   205,     0,   221,     0,
     0,     0,   126,     0,     0,     0,     0,     0,     0,     0,
     0,     0,   129,     0,   128,     0,     0,     0,   130,     0,
     0,     0,     0,   143
};

static const short yycheck[] = {     5,
    73,    74,   118,   118,   118,    72,   146,   119,    52,    72,
    71,     5,     6,     7,     8,    71,    10,    11,    71,    63,
    14,   111,    71,    17,    18,    19,    71,   120,    19,    23,
   146,   146,   146,    27,    28,    29,    30,   149,     5,    71,
    34,    35,     9,    10,    59,    36,    14,   197,   138,    40,
    65,    19,   119,    44,   147,    51,   119,    53,    71,   199,
    51,    71,    53,    30,    71,    32,   216,    71,    36,    71,
   220,   221,    40,    71,    68,    15,    44,    54,    55,    56,
    57,    58,   149,   199,   199,   199,   149,    45,    46,    47,
    48,    37,    38,    39,    20,    21,    22,    41,    42,    43,
    69,    68,    59,    60,    61,     3,     4,    34,    35,    12,
    13,    71,   118,    24,    25,    37,    38,    59,    60,    69,
    63,    64,    71,    31,    26,    66,    67,    65,    65,    65,
    69,    59,    50,    66,    33,     0,    71,    71,   211,    71,
   146,    71,    71,    62,    67,     0,    71,    71,     6,    70,
    70,    63,     5,    84,   159,    71,    73,    72,     6,     6,
    70,   154,     8,   193,   165,   173,   187,    -1,   211,    -1,
    -1,    -1,    81,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,    95,    -1,    91,    -1,    -1,    -1,   102,    -1,
    -1,    -1,    -1,   199
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
#line 207 "config_parse.y"
{
#if SOCKS_SERVER
		protocol			= &protocolmem;
		extension		= &config.extension;
		methodv			= config.methodv;
		methodc			= &config.methodc;
#endif
	;
    break;}
case 4:
#line 218 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 9:
#line 225 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 13:
#line 232 "config_parse.y"
{
	;
    break;}
case 29:
#line 258 "config_parse.y"
{
		yyerror("given keyword is deprecated");
	;
    break;}
case 30:
#line 262 "config_parse.y"
{
#if SOCKS_CLIENT
		route.src		= src;
		route.dst		= dst;
		ruleaddress2sockshost(&gw, &route.gw.host, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
#endif
	;
    break;}
case 31:
#line 274 "config_parse.y"
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
	;
    break;}
case 33:
#line 299 "config_parse.y"
{
			proxyprotocol->socks_v4 = 1;
	;
    break;}
case 34:
#line 302 "config_parse.y"
{
			proxyprotocol->socks_v5 = 1;
	;
    break;}
case 35:
#line 305 "config_parse.y"
{
			proxyprotocol->msproxy_v2 = 1;
	;
    break;}
case 39:
#line 318 "config_parse.y"
{
			extension->bind = 1;
	;
    break;}
case 42:
#line 328 "config_parse.y"
{
#if SOCKS_SERVER
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
case 43:
#line 345 "config_parse.y"
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

		if ((service = getservbyname("socks", "tcp")) == NULL)
			*port_tcp = htons(SOCKD_PORT);
		else
			*port_tcp = service->s_port;
	}
	else { /* can only set internal address' once. */
		static struct in_addr inaddrmem;
		static in_port_t portmem;

		ipaddr		= &inaddrmem;
		port_tcp		= &portmem;
	}
#endif
	;
    break;}
case 44:
#line 381 "config_parse.y"
{
#if SOCKS_SERVER
		if (config.externalv[config.externalc - 1].sin_addr.s_addr
		== htonl(INADDR_ANY))
			yyerror("external address can't be a wildcard address");
#endif
		;
    break;}
case 45:
#line 390 "config_parse.y"
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
	;
    break;}
case 50:
#line 416 "config_parse.y"
{
		if (!config.state.init) {
			if (strcmp(yyvsp[0].string, "syslog") == 0)
				config.log.type |= LOGTYPE_SYSLOG;
			else {
				config.log.type |= LOGTYPE_FILE;

				if ((config.log.fpv = (FILE **)realloc(config.log.fpv,
				sizeof(*config.log.fpv) * (config.log.fpc + 1))) == NULL
				|| (config.log.fplockv = (int *)realloc(config.log.fplockv,
				sizeof(*config.log.fplockv) * (config.log.fpc + 1))) == NULL)
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
case 56:
#line 458 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.privileged			= yyvsp[0].uid;
		config.uid.privileged_isset	= 1;
#endif
	;
    break;}
case 57:
#line 466 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.unprivileged			= yyvsp[0].uid;
		config.uid.unprivileged_isset	= 1;
#endif
	;
    break;}
case 58:
#line 474 "config_parse.y"
{
#if SOCKS_SERVER
#if !HAVE_LIBWRAP
		yyerror("libwrap support not compiled in");
#else  /* HAVE_LIBWRAP */
		config.uid.libwrap			= yyvsp[0].uid;
		config.uid.libwrap_isset	= 1;
#endif /* HAVE_LIBWRAP */
#endif /* SOCKS_SERVER */
	;
    break;}
case 59:
#line 487 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	;
    break;}
case 60:
#line 497 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.io = atol(yyvsp[0].string);
#endif
	;
    break;}
case 61:
#line 504 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.negotiate = atol(yyvsp[0].string);
#endif
	;
    break;}
case 62:
#line 511 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	;
    break;}
case 64:
#line 519 "config_parse.y"
{
#if SOCKS_SERVER
		config.compat.reuseaddr = 1;
	;
    break;}
case 65:
#line 523 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	;
    break;}
case 69:
#line 536 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	;
    break;}
case 70:
#line 539 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_TCP;
	;
    break;}
case 71:
#line 542 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_UDP;
	;
    break;}
case 73:
#line 550 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			config.srchost.nomismatch = 1;
	;
    break;}
case 74:
#line 554 "config_parse.y"
{
			config.srchost.nounknown = 1;
#else
		yyerror("libwrap support not compiled in");
#endif
	;
    break;}
case 78:
#line 570 "config_parse.y"
{
		methodv[(*methodc)++] = AUTHMETHOD_NONE;
	;
    break;}
case 79:
#line 573 "config_parse.y"
{
		yyerror("GSSAPI not supported");
	;
    break;}
case 80:
#line 576 "config_parse.y"
{
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
	;
    break;}
case 83:
#line 588 "config_parse.y"
{
#if SOCKS_SERVER
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
case 86:
#line 609 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 88:
#line 613 "config_parse.y"
{
#if SOCKS_SERVER
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
case 95:
#line 639 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 97:
#line 643 "config_parse.y"
{
#if SOCKS_SERVER
		rule.verdict	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
	;
    break;}
case 98:
#line 652 "config_parse.y"
{
		rule.verdict	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
#endif
	;
    break;}
case 100:
#line 666 "config_parse.y"
{
			command->bind = 1;
	;
    break;}
case 101:
#line 669 "config_parse.y"
{
			command->connect = 1;
	;
    break;}
case 102:
#line 672 "config_parse.y"
{
			command->udpassociate = 1;
	;
    break;}
case 103:
#line 678 "config_parse.y"
{
			command->bindreply = 1;
	;
    break;}
case 107:
#line 690 "config_parse.y"
{
		protocol->tcp = 1;
	;
    break;}
case 108:
#line 693 "config_parse.y"
{
		protocol->udp = 1;
	;
    break;}
case 113:
#line 709 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	;
    break;}
case 114:
#line 713 "config_parse.y"
{
			rule.log.data = 1;
	;
    break;}
case 115:
#line 716 "config_parse.y"
{
			rule.log.disconnect = 1;
	;
    break;}
case 116:
#line 719 "config_parse.y"
{
			rule.log.error = 1;
	;
    break;}
case 117:
#line 722 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	;
    break;}
case 120:
#line 733 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		struct request_info request;

		if (strlen(yyvsp[0].string) >= sizeof(rule.libwrap))
			yyerror("libwrap line too long.  Make buffer bigger");
		strcpy(rule.libwrap, yyvsp[0].string);

		if (config.option.debug)
			hosts_access_verbose = 1;

		++dry_run;
		request_init(&request, RQ_FILE, -1, RQ_DAEMON, __progname, 0);
		if (setjmp(tcpd_buf) != 0)
			yyerror("bad libwrap line");
		process_options(rule.libwrap, &request);
		--dry_run;

#else /* !HAVE_LIBWRAP */
		yyerror("libwrap support not compiled in");
#endif
	;
    break;}
case 129:
#line 776 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 131:
#line 780 "config_parse.y"
{
		addressinit(&src);
	;
    break;}
case 132:
#line 786 "config_parse.y"
{
		addressinit(&dst);
	;
    break;}
case 133:
#line 792 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	;
    break;}
case 139:
#line 811 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address");
	;
    break;}
case 140:
#line 820 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask");

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	;
    break;}
case 141:
#line 827 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask");
	;
    break;}
case 142:
#line 833 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);
	;
    break;}
case 143:
#line 842 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);

#if SOCKS_CLIENT
		route.state.direct = 1;
#endif
	;
    break;}
case 144:
#line 855 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 150:
#line 868 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	;
    break;}
case 151:
#line 874 "config_parse.y"
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
	;
    break;}
case 152:
#line 922 "config_parse.y"
{
		ruleaddress->portend = htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator = range;
	;
    break;}
case 153:
#line 928 "config_parse.y"
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
#line 933 "config_parse.y"


#define INTERACTIVE 0

extern FILE *yyin;

int parseinit;

int
readconfig(filename)
	const char *filename;
{
	const char *function = "readconfig()";

	yydebug = 0;
	parseinit = 0;

	if ((yyin = fopen(filename, "r")) == NULL) {
		swarn("%s: %s", function, filename);
		return -1;
	}

	yyparse();
	fclose(yyin);

	errno = 0; /* yacc for some reason alters errno sometimes. */

	return 0;
}


static void
yyerror(s)
	const char *s;
{

	serrx(1, "%s: %d: %s, near '%.50s'",
	config.option.configfile, yylineno, s,
	(yytext == NULL || *yytext == NUL) ? "'start of line'" : yytext);
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
