
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
#define	RFC931	278
#define	COMPATIBILITY	279
#define	REUSEADDR	280
#define	SAMEPORT	281
#define	USERNAME	282
#define	USER_PRIVILEGED	283
#define	USER_UNPRIVILEGED	284
#define	USER_LIBWRAP	285
#define	LOGOUTPUT	286
#define	LOGFILE	287
#define	ROUTE	288
#define	VIA	289
#define	VERDICT_BLOCK	290
#define	VERDICT_PASS	291
#define	PROTOCOL	292
#define	PROTOCOL_TCP	293
#define	PROTOCOL_UDP	294
#define	PROTOCOL_FAKE	295
#define	PROXYPROTOCOL	296
#define	PROXYPROTOCOL_SOCKS_V4	297
#define	PROXYPROTOCOL_SOCKS_V5	298
#define	PROXYPROTOCOL_MSPROXY_V2	299
#define	USER	300
#define	COMMAND	301
#define	COMMAND_BIND	302
#define	COMMAND_CONNECT	303
#define	COMMAND_UDPASSOCIATE	304
#define	COMMAND_BINDREPLY	305
#define	ACTION	306
#define	LINE	307
#define	LIBWRAPSTART	308
#define	OPERATOR	309
#define	LOG	310
#define	LOG_CONNECT	311
#define	LOG_DATA	312
#define	LOG_DISCONNECT	313
#define	LOG_ERROR	314
#define	LOG_IOOPERATION	315
#define	IPADDRESS	316
#define	DOMAIN	317
#define	DIRECT	318
#define	PORT	319
#define	PORTNUMBER	320
#define	SERVICENAME	321
#define	NUMBER	322
#define	FROM	323
#define	TO	324

#line 44 "config_parse.y"


#include "common.h"

#include "yacconfig.h"

static const char rcsid[] =
"$Id: config_parse.y,v 1.107 1999/07/02 13:26:34 michaels Exp $";

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
static struct rule_t 			ruleinit;	
static struct rule_t				rule;				/* new rule.							*/
static struct protocol_t		protocolmem;	/* new protocolmem.					*/
struct linkedname_t 				**userbase;		/* users rule applies to.			*/
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
static int							*methodv;		/* new authmethods.					*/
static int							*methodc;		/* number of them.					*/
static struct protocol_t		*protocol;		/* new protocol.						*/
static struct command_t			*command;		/* new command.						*/
static enum operator_t			*operator;		/* new operator.						*/


#define YYDEBUG 1

#define ADDMETHOD(method) \
	do { \
		if (*methodc >= AUTHMETHOD_MAX)	\
			yyerror("internal error or duplicate methods given");	\
		methodv[(*methodc)++] = method; \
	} while (0)



#line 113 "config_parse.y"
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



#define	YYFINAL		237
#define	YYFLAG		-32768
#define	YYNTBASE	76

#define YYTRANSLATE(x) ((unsigned)(x) <= 324 ? yytranslate[x] : 162)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    70,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,    75,     2,    74,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    73,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    71,     2,    72,     2,     2,     2,     2,     2,
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
    66,    67,    68,    69
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     3,     6,     8,     9,    12,    15,    18,    21,    22,
    25,    28,    31,    33,    35,    37,    39,    41,    43,    45,
    47,    49,    51,    53,    55,    57,    59,    61,    63,    65,
    74,    75,    79,    81,    83,    85,    87,    90,    94,    96,
    98,   101,   105,   107,   109,   112,   118,   119,   124,   125,
   127,   129,   131,   135,   137,   139,   142,   144,   146,   148,
   152,   156,   160,   162,   166,   170,   174,   178,   180,   182,
   184,   187,   191,   193,   195,   197,   201,   203,   205,   207,
   210,   214,   216,   218,   220,   222,   224,   227,   235,   237,
   239,   241,   242,   245,   252,   254,   256,   258,   260,   262,
   264,   266,   267,   270,   272,   274,   278,   280,   282,   284,
   286,   288,   291,   295,   297,   299,   301,   304,   307,   311,
   313,   315,   317,   319,   321,   323,   326,   330,   334,   338,
   342,   344,   346,   348,   350,   352,   353,   356,   358,   360,
   362,   367,   370,   373,   376,   378,   380,   382,   384,   386,
   388,   389,   393,   396,   398,   400,   404,   406,   408,   410
};

static const short yyrhs[] = {    77,
    78,     0,    80,    79,     0,     3,     0,     0,    78,    70,
     0,    78,    82,     0,    78,   123,     0,    78,   126,     0,
     0,    79,    70,     0,    79,    81,     0,    79,    85,     0,
     4,     0,   100,     0,    84,     0,   120,     0,    84,     0,
    96,     0,    98,     0,   101,     0,    83,     0,   104,     0,
   112,     0,   110,     0,    93,     0,   109,     0,   115,     0,
   117,     0,     5,     0,    33,    86,    71,   145,   136,   143,
   145,    72,     0,     0,    41,    73,    89,     0,    42,     0,
    43,     0,    44,     0,    88,     0,    88,    89,     0,    45,
    73,    92,     0,    27,     0,    91,     0,    91,    92,     0,
    14,    73,    95,     0,    15,     0,    94,     0,    94,    95,
     0,     7,    97,    73,   151,   155,     0,     0,     8,    99,
    73,   151,     0,     0,   101,     0,   111,     0,   115,     0,
    31,    73,   103,     0,    32,     0,   102,     0,   102,   103,
     0,   105,     0,   106,     0,   107,     0,    28,    73,   108,
     0,    29,    73,   108,     0,    30,    73,   108,     0,    27,
     0,    17,    73,    67,     0,    18,    73,    67,     0,     9,
    73,    67,     0,    24,    73,   114,     0,    25,     0,    26,
     0,   113,     0,   113,   114,     0,    10,    73,   116,     0,
    40,     0,    38,     0,    39,     0,    11,    73,   119,     0,
    12,     0,    13,     0,   118,     0,   118,   119,     0,    19,
    73,   122,     0,    20,     0,    21,     0,    22,     0,    23,
     0,   121,     0,   121,   122,     0,     6,   129,    71,   125,
   136,   125,    72,     0,   140,     0,   137,     0,    90,     0,
     0,   124,   125,     0,   129,    71,   128,   136,   128,    72,
     0,   120,     0,   130,     0,   140,     0,   137,     0,   133,
     0,    87,     0,    90,     0,     0,   127,   128,     0,    35,
     0,    36,     0,    46,    73,   132,     0,    47,     0,    48,
     0,    49,     0,    50,     0,   131,     0,   131,   132,     0,
    37,    73,   135,     0,    38,     0,    39,     0,   134,     0,
   134,   135,     0,   141,   142,     0,    55,    73,   139,     0,
    56,     0,    57,     0,    58,     0,    59,     0,    60,     0,
   138,     0,   138,   139,     0,    53,    73,    52,     0,   146,
    73,   149,     0,   147,    73,   149,     0,   148,    73,   150,
     0,   130,     0,    93,     0,   133,     0,    87,     0,   120,
     0,     0,   144,   145,     0,    68,     0,    69,     0,    34,
     0,   151,    74,   152,   155,     0,   153,   155,     0,   151,
   155,     0,   153,   155,     0,   154,     0,    61,     0,    67,
     0,    61,     0,    62,     0,    63,     0,     0,    64,   161,
   156,     0,    64,   157,     0,   159,     0,   158,     0,   158,
    75,   160,     0,    65,     0,    66,     0,    65,     0,    54,
     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   203,   204,   208,   219,   220,   221,   222,   223,   226,   227,
   228,   229,   233,   237,   238,   241,   242,   243,   244,   245,
   246,   247,   250,   251,   252,   253,   254,   255,   259,   263,
   275,   296,   299,   302,   305,   310,   311,   314,   317,   329,
   330,   333,   336,   341,   342,   346,   363,   400,   409,   427,
   428,   429,   432,   435,   468,   469,   472,   473,   474,   477,
   485,   493,   504,   514,   521,   528,   533,   536,   540,   546,
   547,   550,   553,   556,   563,   568,   571,   575,   583,   584,
   588,   591,   594,   597,   600,   609,   610,   616,   633,   634,
   635,   638,   639,   642,   660,   661,   662,   663,   664,   665,
   666,   669,   670,   673,   683,   695,   698,   701,   704,   710,
   715,   716,   719,   722,   725,   730,   731,   735,   738,   741,
   745,   748,   751,   754,   760,   761,   765,   792,   796,   800,
   803,   804,   805,   806,   807,   810,   811,   814,   820,   826,
   834,   835,   839,   840,   841,   845,   854,   861,   867,   876,
   889,   890,   891,   894,   895,   898,   902,   908,   956,   962
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","SERVERCONFIG",
"CLIENTCONFIG","DEPRECATED","CLIENTRULE","INTERNAL","EXTERNAL","DEBUGING","RESOLVEPROTOCOL",
"SRCHOST","NOMISMATCH","NOUNKNOWN","EXTENSION","BIND","PRIVILEGED","IOTIMEOUT",
"CONNECTTIMEOUT","METHOD","NONE","GSSAPI","UNAME","RFC931","COMPATIBILITY","REUSEADDR",
"SAMEPORT","USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","LOGOUTPUT",
"LOGFILE","ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS","PROTOCOL","PROTOCOL_TCP",
"PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL","PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5",
"PROXYPROTOCOL_MSPROXY_V2","USER","COMMAND","COMMAND_BIND","COMMAND_CONNECT",
"COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","ACTION","LINE","LIBWRAPSTART","OPERATOR",
"LOG","LOG_CONNECT","LOG_DATA","LOG_DISCONNECT","LOG_ERROR","LOG_IOOPERATION",
"IPADDRESS","DOMAIN","DIRECT","PORT","PORTNUMBER","SERVICENAME","NUMBER","FROM",
"TO","'\\n'","'{'","'}'","':'","'/'","'-'","configtype","serverinit","serverline",
"clientline","clientinit","clientconfig","serverconfig","serveroption","deprecated",
"route","routeinit","proxyprotocol","proxyprotocolname","proxyprotocols","user",
"username","usernames","extension","extensionname","extensions","internal","internalinit",
"external","externalinit","clientoption","logoutput","logoutputdevice","logoutputdevices",
"userids","user_privileged","user_unprivileged","user_libwrap","userid","iotimeout",
"connecttimeout","debuging","compatibility","compatibilityname","compatibilitys",
"resolveprotocol","resolveprotocolname","srchost","srchostoption","srchostoptions",
"authmethod","authmethodname","authmethods","clientrule","clientruleoption",
"clientruleoptions","rule","ruleoption","ruleoptions","verdict","command","commandname",
"commands","protocol","protocolname","protocols","fromto","log","logname","logs",
"libwrap","srcaddress","dstaddress","gateway","routeoption","routeoptions","from",
"to","via","address","gwaddress","ipaddress","netmask","domain","direct","port",
"portnumber","portrange","portstart","portservice","portend","portoperator", NULL
};
#endif

static const short yyr1[] = {     0,
    76,    76,    77,    78,    78,    78,    78,    78,    79,    79,
    79,    79,    80,    81,    81,    82,    82,    82,    82,    82,
    82,    82,    83,    83,    83,    83,    83,    83,    84,    85,
    86,    87,    88,    88,    88,    89,    89,    90,    91,    92,
    92,    93,    94,    95,    95,    96,    97,    98,    99,   100,
   100,   100,   101,   102,   103,   103,   104,   104,   104,   105,
   106,   107,   108,   109,   110,   111,   112,   113,   113,   114,
   114,   115,   116,   116,   116,   117,   118,   118,   119,   119,
   120,   121,   121,   121,   121,   122,   122,   123,   124,   124,
   124,   125,   125,   126,   127,   127,   127,   127,   127,   127,
   127,   128,   128,   129,   129,   130,   131,   131,   131,   131,
   132,   132,   133,   134,   134,   135,   135,   136,   137,   138,
   138,   138,   138,   138,   139,   139,   140,   141,   142,   143,
   144,   144,   144,   144,   144,   145,   145,   146,   147,   148,
   149,   149,   150,   150,   150,   151,   152,   152,   153,   154,
   155,   155,   155,   156,   156,   157,   158,   159,   160,   161
};

static const short yyr2[] = {     0,
     2,     2,     1,     0,     2,     2,     2,     2,     0,     2,
     2,     2,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     1,     1,     1,     1,     1,     1,     1,     1,     8,
     0,     3,     1,     1,     1,     1,     2,     3,     1,     1,
     2,     3,     1,     1,     2,     5,     0,     4,     0,     1,
     1,     1,     3,     1,     1,     2,     1,     1,     1,     3,
     3,     3,     1,     3,     3,     3,     3,     1,     1,     1,
     2,     3,     1,     1,     1,     3,     1,     1,     1,     2,
     3,     1,     1,     1,     1,     1,     2,     7,     1,     1,
     1,     0,     2,     6,     1,     1,     1,     1,     1,     1,
     1,     0,     2,     1,     1,     3,     1,     1,     1,     1,
     1,     2,     3,     1,     1,     1,     2,     2,     3,     1,
     1,     1,     1,     1,     1,     2,     3,     3,     3,     3,
     1,     1,     1,     1,     1,     0,     2,     1,     1,     1,
     4,     2,     2,     2,     1,     1,     1,     1,     1,     1,
     0,     3,     2,     1,     1,     3,     1,     1,     1,     1
};

static const short yydefact[] = {     0,
     3,    13,     4,     9,     1,     2,    29,     0,    47,    49,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,   104,   105,     5,     6,    21,    17,    25,    18,    19,
    20,    22,    57,    58,    59,    26,    24,    23,    27,    28,
    16,     7,     8,     0,     0,    31,    10,    11,    15,    12,
    14,    50,    51,    52,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,   102,     0,
     0,    92,     0,     0,    74,    75,    73,    72,    77,    78,
    79,    76,    43,    44,    42,    64,    65,    82,    83,    84,
    85,    86,    81,    68,    69,    70,    67,    63,    60,    61,
    62,    54,    55,    53,     0,     0,     0,     0,     0,     0,
   100,   101,    95,   102,     0,    96,    99,    98,    97,    66,
   136,    91,    92,     0,    90,    89,   146,   151,    48,    80,
    45,    87,    71,    56,     0,     0,     0,     0,     0,     0,
   103,   138,   102,     0,     0,   134,   132,   135,   131,   133,
   136,     0,    93,    92,     0,    46,   114,   115,   116,   113,
    33,    34,    35,    36,    32,    39,    40,    38,   107,   108,
   109,   110,   111,   106,   127,   120,   121,   122,   123,   124,
   125,   119,     0,   139,   118,     0,     0,   137,     0,     0,
   160,   157,   153,     0,     0,   117,    37,    41,   112,   126,
    94,     0,   149,   128,     0,   151,   140,   136,     0,    88,
     0,   158,   152,   155,   154,   129,     0,   142,     0,     0,
   159,   156,   148,   147,   151,    30,   150,   130,   151,   151,
   145,   141,   143,   144,     0,     0,     0
};

static const short yydefgoto[] = {   235,
     3,     5,     6,     4,    48,    25,    26,    27,    50,    71,
   111,   164,   165,   112,   167,   168,   147,    84,    85,    29,
    56,    30,    57,    51,    31,   103,   104,    32,    33,    34,
    35,    99,    36,    37,    53,    38,    96,    97,    39,    78,
    40,    81,    82,   113,    92,    93,    42,   123,   124,    43,
   114,   115,    44,   116,   173,   174,   117,   159,   160,   143,
   118,   181,   182,   119,   144,   185,   208,   151,   152,   145,
   186,   209,   204,   228,   205,   225,   206,   231,   156,   213,
   193,   194,   215,   222,   195
};

static const short yypact[] = {   108,
-32768,-32768,-32768,-32768,     8,    36,-32768,    28,-32768,-32768,
   -56,   -50,   -45,   -43,   -18,   -12,    -2,     0,    48,    53,
    54,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,   -59,    57,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,    12,    58,    63,    41,   101,   100,
     1,    65,    79,    92,   106,   106,   106,   102,    29,    68,
    66,    -3,    77,    77,-32768,-32768,-32768,-32768,-32768,-32768,
   101,-32768,-32768,   100,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,    79,-32768,-32768,-32768,    92,-32768,-32768,-32768,-32768,
-32768,-32768,   102,-32768,    67,    69,    70,    71,    72,    74,
-32768,-32768,-32768,    29,    73,-32768,-32768,-32768,-32768,-32768,
    10,-32768,    -3,    73,-32768,-32768,-32768,    75,-32768,-32768,
-32768,-32768,-32768,-32768,    81,    43,   122,    60,    98,    38,
-32768,-32768,    29,    82,    80,-32768,-32768,-32768,-32768,-32768,
    10,    73,-32768,    -3,   -44,-32768,-32768,-32768,    81,-32768,
-32768,-32768,-32768,    43,-32768,-32768,   122,-32768,-32768,-32768,
-32768,-32768,    60,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
    38,-32768,    83,-32768,-32768,    84,    61,-32768,   118,    86,
-32768,-32768,-32768,    85,    59,-32768,-32768,-32768,-32768,-32768,
-32768,    61,-32768,-32768,    87,    75,-32768,    10,    89,-32768,
    91,-32768,-32768,-32768,-32768,-32768,    -7,-32768,    93,    42,
-32768,-32768,-32768,-32768,    75,-32768,-32768,-32768,    75,    75,
-32768,-32768,-32768,-32768,   154,   159,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,   157,-32768,-32768,
  -118,-32768,     2,   -66,-32768,     3,   162,-32768,    88,-32768,
-32768,-32768,-32768,-32768,   158,-32768,    76,-32768,-32768,-32768,
-32768,    62,-32768,-32768,-32768,-32768,-32768,    78,   163,-32768,
-32768,-32768,    90,    -5,-32768,    94,-32768,-32768,  -114,-32768,
-32768,   -94,   160,  -117,-32768,     4,  -116,-32768,    14,   -93,
   -65,-32768,    -6,   -61,-32768,-32768,-32768,-32768,  -143,-32768,
-32768,-32768,   -26,-32768,   -72,-32768,   -42,-32768,  -153,-32768,
-32768,   -15,-32768,-32768,-32768
};


#define	YYLAST		203


static const short yytable[] = {    41,
   128,   129,   146,   149,   150,   122,   125,   188,   153,   191,
   126,    69,     7,     8,     9,    10,    58,    11,    12,   141,
   192,    13,    59,    13,    14,    15,    16,    60,    16,    61,
   154,    17,   146,   149,   150,    18,    19,    20,    21,   190,
     7,   107,    22,    23,    45,    11,   105,    16,   183,   109,
   106,   110,   218,   223,    62,   108,   122,   125,   189,   224,
    63,   126,    22,    23,   219,   105,    21,    86,    46,   106,
    64,   232,    65,   107,   108,   233,   234,    24,    75,    76,
    77,   109,    72,   110,   161,   162,   163,   122,   125,   146,
   149,   150,   126,   176,   177,   178,   179,   180,    88,    89,
    90,    91,   127,   203,   227,    47,   169,   170,   171,   172,
     1,     2,    79,    80,    83,   148,    94,    95,   157,   158,
    66,   127,   203,   192,   212,    67,    68,   100,   101,    70,
    73,    87,    98,   102,   120,    74,   121,   127,   155,   135,
   142,   136,   137,   138,   139,   148,   140,   229,   166,   175,
   184,   207,   187,   236,   201,   221,   202,   210,   237,   211,
   217,   220,    49,    52,   226,   197,    28,    55,    54,   198,
   130,   131,   196,   133,   200,   216,   199,   230,   134,   214,
     0,     0,     0,     0,     0,   132,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,   148
};

static const short yycheck[] = {     5,
    73,    74,   121,   121,   121,    72,    72,   151,   123,    54,
    72,    71,     5,     6,     7,     8,    73,    10,    11,   114,
    65,    14,    73,    14,    17,    18,    19,    73,    19,    73,
   124,    24,   151,   151,   151,    28,    29,    30,    31,   154,
     5,    45,    35,    36,     9,    10,    37,    19,   143,    53,
    41,    55,   206,    61,    73,    46,   123,   123,   152,    67,
    73,   123,    35,    36,   208,    37,    31,    67,    33,    41,
    73,   225,    73,    45,    46,   229,   230,    70,    38,    39,
    40,    53,    71,    55,    42,    43,    44,   154,   154,   208,
   208,   208,   154,    56,    57,    58,    59,    60,    20,    21,
    22,    23,    61,    62,    63,    70,    47,    48,    49,    50,
     3,     4,    12,    13,    15,   121,    25,    26,    38,    39,
    73,    61,    62,    65,    66,    73,    73,    66,    67,    73,
    73,    67,    27,    32,    67,    73,    71,    61,    64,    73,
    68,    73,    73,    73,    73,   151,    73,   220,    27,    52,
    69,    34,    73,     0,    72,    65,    73,    72,     0,    75,
    74,    73,     6,     6,    72,   164,     5,     8,     6,   167,
    81,    84,   159,    96,   181,   202,   173,   220,   103,   195,
    -1,    -1,    -1,    -1,    -1,    92,    -1,    -1,    -1,    -1,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    -1,    -1,   208
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
#line 208 "config_parse.y"
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
#line 219 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 9:
#line 226 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 13:
#line 233 "config_parse.y"
{
	;
    break;}
case 29:
#line 259 "config_parse.y"
{
		yyerror("given keyword is deprecated");
	;
    break;}
case 30:
#line 263 "config_parse.y"
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
#line 275 "config_parse.y"
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
#line 317 "config_parse.y"
{
#if SOCKS_SERVER
#if !HAVE_LIBWRAP
		if (strcmp(yyvsp[0].string, method2string(AUTHMETHOD_RFC931)) == 0)
			yyerror("user rfc931 requires libwrap");
#endif /* !HAVE_LIBWRAP */
		if (adduser(userbase, yyvsp[0].string) == NULL)
			yyerror(NOMEM);
#endif SOCKS_SERVER
	;
    break;}
case 43:
#line 336 "config_parse.y"
{
			extension->bind = 1;
	;
    break;}
case 46:
#line 346 "config_parse.y"
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
	;
    break;}
case 47:
#line 363 "config_parse.y"
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
		*port_tcp = service->s_port;
#endif
	;
    break;}
case 48:
#line 400 "config_parse.y"
{
#if SOCKS_SERVER
		if (config.externalv[config.externalc - 1].sin_addr.s_addr
		== htonl(INADDR_ANY))
			yyerror("external address can't be a wildcard address");
#endif
		;
    break;}
case 49:
#line 409 "config_parse.y"
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
case 54:
#line 435 "config_parse.y"
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

				if ((config.log.fplockv[config.log.fpc]
				= socks_mklock(SOCKS_LOCKFILE)) == -1)
					serr(EXIT_FAILURE, "socks_mklock()");

				if (strcmp(yyvsp[0].string, "stdout") == 0)
					config.log.fpv[config.log.fpc] = stdout;
				else if (strcmp(yyvsp[0].string, "stderr") == 0)
					config.log.fpv[config.log.fpc] = stderr;
				else
					if ((config.log.fpv[config.log.fpc] = fopen(yyvsp[0].string, "a"))
					== NULL)
						serr(EXIT_FAILURE, "fopen(%s)", yyvsp[0].string);
				++config.log.fpc;
			}
		}
		else
			;	/* XXX warn/exit if output changed. */
	;
    break;}
case 60:
#line 477 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.privileged			= yyvsp[0].uid;
		config.uid.privileged_isset	= 1;
#endif
	;
    break;}
case 61:
#line 485 "config_parse.y"
{
#if SOCKS_SERVER
		config.uid.unprivileged			= yyvsp[0].uid;
		config.uid.unprivileged_isset	= 1;
#endif
	;
    break;}
case 62:
#line 493 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		config.uid.libwrap			= yyvsp[0].uid;
		config.uid.libwrap_isset	= 1;
#else  /* HAVE_LIBWRAP */
		yyerror("libwrap support not compiled in");
#endif /* !HAVE_LIBWRAP */
	;
    break;}
case 63:
#line 504 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serrx(EXIT_FAILURE, "no such user \"%s\"", yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	;
    break;}
case 64:
#line 514 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.io = atol(yyvsp[0].string);
#endif
	;
    break;}
case 65:
#line 521 "config_parse.y"
{
#if SOCKS_SERVER
		config.timeout.negotiate = atol(yyvsp[0].string);
#endif
	;
    break;}
case 66:
#line 528 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	;
    break;}
case 68:
#line 536 "config_parse.y"
{
#if SOCKS_SERVER
		config.compat.reuseaddr = 1;
	;
    break;}
case 69:
#line 540 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	;
    break;}
case 73:
#line 553 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_FAKE;
	;
    break;}
case 74:
#line 556 "config_parse.y"
{
#if HAVE_NO_RESOLVESTUFF
			yyerror("resolveprotocol keyword not supported on this installation");
#else /* HAVE_NO_RESOLVESTUFF */
			config.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
	;
    break;}
case 75:
#line 563 "config_parse.y"
{
			config.resolveprotocol = RESOLVEPROTOCOL_UDP;
	;
    break;}
case 77:
#line 571 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
			config.srchost.nomismatch = 1;
	;
    break;}
case 78:
#line 575 "config_parse.y"
{
			config.srchost.nounknown = 1;
#else
		yyerror("libwrap support not compiled in");
#endif
	;
    break;}
case 82:
#line 591 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_NONE);
	;
    break;}
case 83:
#line 594 "config_parse.y"
{
		yyerror("GSSAPI not supported");
	;
    break;}
case 84:
#line 597 "config_parse.y"
{
		ADDMETHOD(AUTHMETHOD_UNAME);
	;
    break;}
case 85:
#line 600 "config_parse.y"
{
#if HAVE_LIBWRAP && SOCKS_SERVER
		ADDMETHOD(AUTHMETHOD_RFC931);
#else /* !HAVE_LIBWRAP */
		yyerror("method rfc931 requires libwrap");
#endif /* !HAVE_LIBWRAP */
	;
    break;}
case 88:
#line 616 "config_parse.y"
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
	;
    break;}
case 92:
#line 638 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 94:
#line 642 "config_parse.y"
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
	;
    break;}
case 102:
#line 669 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 104:
#line 673 "config_parse.y"
{
#if SOCKS_SERVER
		rule.verdict	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
		userbase			= &rule.user;
	;
    break;}
case 105:
#line 683 "config_parse.y"
{
		rule.verdict	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol			= &rule.state.protocol;
		proxyprotocol	= &rule.state.proxyprotocol;
		userbase			= &rule.user;
#endif
	;
    break;}
case 107:
#line 698 "config_parse.y"
{
			command->bind = 1;
	;
    break;}
case 108:
#line 701 "config_parse.y"
{
			command->connect = 1;
	;
    break;}
case 109:
#line 704 "config_parse.y"
{
			command->udpassociate = 1;
	;
    break;}
case 110:
#line 710 "config_parse.y"
{
			command->bindreply = 1;
	;
    break;}
case 114:
#line 722 "config_parse.y"
{
		protocol->tcp = 1;
	;
    break;}
case 115:
#line 725 "config_parse.y"
{
		protocol->udp = 1;
	;
    break;}
case 120:
#line 741 "config_parse.y"
{
#if SOCKS_SERVER
	rule.log.connect = 1;
	;
    break;}
case 121:
#line 745 "config_parse.y"
{
			rule.log.data = 1;
	;
    break;}
case 122:
#line 748 "config_parse.y"
{
			rule.log.disconnect = 1;
	;
    break;}
case 123:
#line 751 "config_parse.y"
{
			rule.log.error = 1;
	;
    break;}
case 124:
#line 754 "config_parse.y"
{
			rule.log.iooperation = 1;
#endif
	;
    break;}
case 127:
#line 765 "config_parse.y"
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
	;
    break;}
case 136:
#line 810 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 138:
#line 814 "config_parse.y"
{
		addressinit(&src);
	;
    break;}
case 139:
#line 820 "config_parse.y"
{
		addressinit(&dst);
	;
    break;}
case 140:
#line 826 "config_parse.y"
{
#if SOCKS_CLIENT
		addressinit(&gw);
#endif
	;
    break;}
case 146:
#line 845 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (inet_aton(yyvsp[0].string, ipaddr) != 1)
			yyerror("bad address");
	;
    break;}
case 147:
#line 854 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask");

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	;
    break;}
case 148:
#line 861 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask");
	;
    break;}
case 149:
#line 867 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);
	;
    break;}
case 150:
#line 876 "config_parse.y"
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
case 151:
#line 889 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 157:
#line 902 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= htons((in_port_t)atoi(yyvsp[0].string));
	;
    break;}
case 158:
#line 908 "config_parse.y"
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
case 159:
#line 956 "config_parse.y"
{
		ruleaddress->portend = htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator = range;
	;
    break;}
case 160:
#line 962 "config_parse.y"
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
#line 967 "config_parse.y"


#define INTERACTIVE 		0

#if SOCKS_SERVER
#define ELECTRICFENCE 	0
#else
#define ELECTRICFENCE 	0
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

#if ELECTRICFENCE
	EF_PROTECT_FREE         = 1;
	EF_ALLOW_MALLOC_0       = 1;
	EF_ALIGNMENT            = 0;
	EF_PROTECT_BELOW			= 0;
#endif /* ELECTRICFENCE */


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


void
yyerror(s)
	const char *s;
{

	serrx(1, "%s: error on line %d, near '%.10s': %s",
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
