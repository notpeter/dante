
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
#define	PROTOCOLVERSION	290
#define	COMMAND	291
#define	COMMAND_BIND	292
#define	COMMAND_CONNECT	293
#define	COMMAND_UDPASSOCIATE	294
#define	COMMAND_BINDREPLY	295
#define	ACTION	296
#define	AUTH	297
#define	AUTHMETHOD	298
#define	LINE	299
#define	LIBWRAPSTART	300
#define	OPERATOR	301
#define	LOG	302
#define	LOG_CONNECT	303
#define	LOG_DISCONNECT	304
#define	LOG_IOOPERATION	305
#define	LOG_DATA	306
#define	IPADDRESS	307
#define	DOMAIN	308
#define	DIRECT	309
#define	PORT	310
#define	SERVICENAME	311
#define	NUMBER	312
#define	FROM	313
#define	TO	314

#line 44 "config_parse.y"


static const char rcsid[] =
"$Id: config_parse.y,v 1.72 1998/11/13 21:18:10 michaels Exp $";

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
static struct version_t			*version;

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



#define	YYFINAL		213
#define	YYFLAG		-32768
#define	YYNTBASE	66

#define YYTRANSLATE(x) ((unsigned)(x) <= 314 ? yytranslate[x] : 142)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    60,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,    65,     2,    64,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    63,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    61,     2,    62,     2,     2,     2,     2,     2,
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
    56,    57,    58,    59
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     3,     6,     8,     9,    12,    15,    18,    21,    22,
    25,    28,    31,    33,    35,    43,    48,    55,    56,    57,
    62,    64,    65,    68,    69,    74,    76,    77,    80,    81,
    88,    89,    94,    95,    99,   100,   105,   107,   108,   111,
   115,   119,   123,   124,   128,   130,   131,   135,   136,   140,
   141,   145,   149,   150,   155,   157,   159,   160,   163,   164,
   169,   170,   173,   175,   177,   179,   186,   189,   196,   203,
   205,   207,   208,   213,   214,   217,   219,   221,   223,   225,
   226,   231,   232,   235,   237,   239,   242,   243,   248,   249,
   252,   254,   256,   258,   260,   261,   265,   266,   268,   269,
   273,   274,   278,   283,   289,   291,   293,   295,   300,   303,
   306,   309,   311,   313,   315,   317,   319,   321,   322,   326,
   329,   331,   333,   337,   339,   341,   343
};

static const short yyrhs[] = {    67,
    68,     0,    70,    69,     0,     3,     0,     0,    68,    60,
     0,    68,    72,     0,    68,   105,     0,    68,   107,     0,
     0,    69,    60,     0,    69,    71,     0,    69,    74,     0,
     4,     0,    86,     0,    87,    82,    84,    98,   102,    90,
    73,     0,    99,    79,    96,    95,     0,    28,    75,    61,
   116,   124,    62,     0,     0,     0,    35,    63,    77,    78,
     0,    57,     0,     0,    77,    78,     0,     0,    10,    63,
    80,    81,     0,    11,     0,     0,    80,    81,     0,     0,
     7,    83,    63,   131,   135,    82,     0,     0,     8,    85,
    63,   131,     0,     0,    87,    98,    97,     0,     0,    26,
    63,    88,    89,     0,    27,     0,     0,    88,    89,     0,
    91,    92,    93,     0,    23,    63,    94,     0,    24,    63,
    94,     0,     0,    25,    63,    94,     0,    22,     0,     0,
    13,    63,    57,     0,     0,    14,    63,    57,     0,     0,
     9,    63,    57,     0,     5,    63,    44,     0,     0,    19,
    63,   100,   101,     0,    20,     0,    21,     0,     0,   100,
   101,     0,     0,    15,    63,   104,   103,     0,     0,   104,
   103,     0,    16,     0,    17,     0,    18,     0,     6,   109,
    61,   116,   106,    62,     0,   120,   117,     0,   109,    61,
   113,   116,   108,    62,     0,   102,   110,   120,   117,   121,
    76,     0,    30,     0,    31,     0,     0,    36,    63,   112,
   111,     0,     0,   112,   111,     0,    37,     0,    38,     0,
    39,     0,    40,     0,     0,    32,    63,   115,   114,     0,
     0,   115,   114,     0,    33,     0,    34,     0,   122,   123,
     0,     0,    47,    63,   119,   118,     0,     0,   119,   118,
     0,    48,     0,    49,     0,    50,     0,    51,     0,     0,
    45,    63,    44,     0,     0,    12,     0,     0,   126,    63,
   129,     0,     0,   127,    63,   129,     0,   128,    63,   130,
   125,     0,   110,    79,   113,    76,   102,     0,    58,     0,
    59,     0,    29,     0,   131,    64,   132,   135,     0,   133,
   135,     0,   131,   135,     0,   133,   135,     0,   134,     0,
    52,     0,    57,     0,    52,     0,    53,     0,    54,     0,
     0,    55,   141,   136,     0,    55,   137,     0,   139,     0,
   138,     0,   138,    65,   140,     0,    57,     0,    56,     0,
    57,     0,    46,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   193,   194,   198,   210,   211,   212,   213,   214,   217,   218,
   219,   220,   224,   232,   236,   240,   244,   256,   278,   279,
   283,   299,   300,   303,   304,   308,   313,   314,   319,   320,
   334,   370,   373,   392,   396,   397,   401,   435,   436,   439,
   442,   449,   456,   463,   474,   484,   485,   492,   493,   500,
   501,   506,   519,   520,   523,   527,   533,   534,   538,   539,
   542,   543,   546,   549,   552,   560,   577,   582,   600,   604,
   613,   624,   625,   628,   629,   632,   635,   638,   644,   650,
   651,   654,   655,   659,   662,   668,   671,   672,   675,   676,
   679,   683,   686,   689,   696,   697,   708,   709,   716,   717,
   721,   722,   726,   729,   733,   739,   745,   753,   754,   758,
   759,   760,   764,   773,   780,   786,   795,   808,   809,   810,
   813,   814,   817,   821,   827,   852,   858
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","SERVERCONFIG",
"CLIENTCONFIG","LOCALDOMAIN","CLIENT","INTERNAL","EXTERNAL","DEBUGING","EXTENSION",
"BIND","PRIVILEGED","IOTIMEOUT","CONNECTTIMEOUT","METHOD","NONE","GSSAPI","UNAME",
"COMPATIBILITY","REUSEADDR","SAMEPORT","USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED",
"USER_LIBWRAP","LOGOUTPUT","LOGFILE","ROUTE","VIA","VERDICT_BLOCK","VERDICT_PASS",
"PROTOCOL","PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOLVERSION","COMMAND","COMMAND_BIND",
"COMMAND_CONNECT","COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","ACTION","AUTH",
"AUTHMETHOD","LINE","LIBWRAPSTART","OPERATOR","LOG","LOG_CONNECT","LOG_DISCONNECT",
"LOG_IOOPERATION","LOG_DATA","IPADDRESS","DOMAIN","DIRECT","PORT","SERVICENAME",
"NUMBER","FROM","TO","'\\n'","'{'","'}'","':'","'/'","'-'","configtype","serverinit",
"serverline","clientline","clientinit","clientconfig","serverconfig","serveroption",
"route","routeinit","protocolversion","protocolversionname","protocolversion_list",
"extension","extensionname","extension_list","internal","internalinit","external",
"externalinit","clientoption","logoutput","logoutputdevice","logoutputdevice_list",
"users","user_privileged","user_unprivileged","user_libwrap","userid","iotimeout",
"connecttimeout","debuging","localdomain","compatibility","compatibilityname",
"compatibility_list","authmethod","authmethod_list","authmethodname","clientrule",
"clientruleoption","rule","ruleoption","verdict","command","command_list","commandname",
"protocol","protocol_list","protocolname","fromto","log","log_list","logname",
"libwrap","privileged","srcaddress","dstaddress","gateway","gatewayoption","from",
"to","via","address","gwaddress","ipaddress","netmask","domain","direct","port",
"portnumber","portrange","portstart","service","portend","portoperator", NULL
};
#endif

static const short yyr1[] = {     0,
    66,    66,    67,    68,    68,    68,    68,    68,    69,    69,
    69,    69,    70,    71,    72,    73,    74,    75,    76,    76,
    77,    78,    78,    79,    79,    80,    81,    81,    82,    82,
    83,    84,    85,    86,    87,    87,    88,    89,    89,    90,
    91,    92,    93,    93,    94,    95,    95,    96,    96,    97,
    97,    98,    99,    99,   100,   100,   101,   101,   102,   102,
   103,   103,   104,   104,   104,   105,   106,   107,   108,   109,
   109,   110,   110,   111,   111,   112,   112,   112,   112,   113,
   113,   114,   114,   115,   115,   116,   117,   117,   118,   118,
   119,   119,   119,   119,   120,   120,   121,   121,   122,   122,
   123,   123,   124,   125,   126,   127,   128,   129,   129,   130,
   130,   130,   131,   132,   132,   133,   134,   135,   135,   135,
   136,   136,   137,   138,   139,   140,   141
};

static const short yyr2[] = {     0,
     2,     2,     1,     0,     2,     2,     2,     2,     0,     2,
     2,     2,     1,     1,     7,     4,     6,     0,     0,     4,
     1,     0,     2,     0,     4,     1,     0,     2,     0,     6,
     0,     4,     0,     3,     0,     4,     1,     0,     2,     3,
     3,     3,     0,     3,     1,     0,     3,     0,     3,     0,
     3,     3,     0,     4,     1,     1,     0,     2,     0,     4,
     0,     2,     1,     1,     1,     6,     2,     6,     6,     1,
     1,     0,     4,     0,     2,     1,     1,     1,     1,     0,
     4,     0,     2,     1,     1,     2,     0,     4,     0,     2,
     1,     1,     1,     1,     0,     3,     0,     1,     0,     3,
     0,     3,     4,     5,     1,     1,     1,     4,     2,     2,
     2,     1,     1,     1,     1,     1,     1,     0,     3,     2,
     1,     1,     3,     1,     1,     1,     1
};

static const short yydefact[] = {     0,
     3,    13,     4,     9,    35,     2,     0,     0,    70,    71,
     5,     6,    29,     7,     8,     0,    18,    10,    11,    12,
    14,     0,     0,     0,    31,     0,    80,     0,     0,    50,
    99,    37,    38,     0,    33,     0,     0,    99,    99,     0,
     0,    34,   105,    95,   101,     0,    38,    36,     0,     0,
    59,     0,    59,     0,    52,     0,     0,     0,    87,   106,
    86,     0,     0,    39,   113,   118,     0,     0,     0,    84,
    85,    82,    72,     0,   107,     0,     0,    51,     0,    66,
     0,    67,     0,   116,   100,     0,   118,     0,    29,    32,
     0,     0,    53,     0,    81,    82,     0,    95,    68,    17,
     0,    96,     0,   102,     0,   109,   127,   124,   120,     0,
     0,    30,    63,    64,    65,    61,     0,     0,    15,    24,
     0,    43,    83,     0,    87,   117,    72,   118,   118,   112,
    91,    92,    93,    94,    89,   115,   114,   118,     0,   125,
   119,   122,   121,    60,    61,    45,    41,     0,     0,    48,
     0,     0,    40,    76,    77,    78,    79,    74,    97,    24,
   103,   110,   111,    88,    89,   108,   126,   123,    62,    55,
    56,    57,     0,     0,    46,    42,     0,    73,    74,    98,
    19,    80,    90,    57,    54,    26,    27,     0,     0,    16,
    44,    75,     0,    69,    19,    58,    27,    25,    49,     0,
     0,    59,    28,    47,    21,    22,   104,    22,    20,    23,
     0,     0,     0
};

static const short yydefgoto[] = {   211,
     3,     5,     6,     4,    19,    12,   119,    20,    28,   194,
   208,   209,   150,   197,   198,    26,    34,    36,    50,    21,
    13,    47,    48,    93,    94,   122,   153,   147,   190,   175,
    42,    30,   120,   184,   185,    69,   144,   145,    14,    58,
    15,    74,    16,    98,   178,   179,    38,    95,    96,    44,
    82,   164,   165,    59,   181,    45,    61,    76,   161,    46,
    62,    77,    85,   127,    86,   138,    87,   130,    89,   141,
   109,   110,   143,   168,   111
};

static const short yypact[] = {    25,
-32768,-32768,-32768,-32768,     1,    -3,     7,   -41,-32768,-32768,
-32768,-32768,    17,-32768,-32768,   -35,-32768,-32768,-32768,-32768,
-32768,    40,    -9,    26,-32768,    46,    27,    -1,    -5,    53,
     5,-32768,    26,     2,-32768,    40,     3,     5,     5,    20,
     4,-32768,-32768,    23,    10,     8,    26,-32768,    18,     9,
    58,     6,    58,    45,-32768,    19,    14,    13,    31,-32768,
-32768,    16,   -11,-32768,-32768,    29,    18,    22,    57,-32768,
-32768,     6,    47,    24,-32768,    30,    32,-32768,    37,-32768,
    33,-32768,   -11,-32768,-32768,    34,    29,   -40,    17,-32768,
    -2,    36,    63,    64,-32768,     6,    38,    23,-32768,-32768,
   -34,-32768,   -39,-32768,   -44,-32768,-32768,-32768,-32768,    35,
   -13,-32768,-32768,-32768,-32768,    -2,    65,    39,-32768,    79,
    41,    66,-32768,    -4,    31,-32768,    47,    29,    29,-32768,
-32768,-32768,-32768,-32768,   -39,-32768,-32768,    29,    48,-32768,
-32768,-32768,-32768,-32768,    -2,-32768,-32768,    28,    43,    76,
    65,    44,-32768,-32768,-32768,-32768,-32768,    -4,    81,    79,
-32768,-32768,-32768,-32768,   -39,-32768,-32768,-32768,-32768,-32768,
-32768,    28,    83,    49,    84,-32768,    65,-32768,    -4,-32768,
    68,    27,-32768,    28,-32768,-32768,    83,    51,    50,-32768,
-32768,-32768,    52,-32768,    68,-32768,    83,-32768,-32768,    54,
    59,    58,-32768,-32768,-32768,    59,-32768,    59,-32768,-32768,
   109,   110,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,   -81,
   -84,   -90,   -38,   -54,   -77,    42,-32768,-32768,-32768,-32768,
   115,    99,    77,-32768,-32768,-32768,-32768,  -147,-32768,-32768,
-32768,    89,-32768,   -22,   -57,   -53,   -17,    55,-32768,-32768,
-32768,-32768,   122,    11,   -49,    15,   -50,    56,    82,    12,
    60,   -32,    61,    62,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,    67,-32768,   -46,-32768,    69,-32768,   -82,-32768,
-32768,    70,-32768,-32768,-32768
};


#define	YYLAST		185


static const short yytable[] = {    73,
    -1,   -35,    66,   176,   106,   107,     7,   136,   131,   132,
   133,   134,   137,   113,   114,   115,   108,    65,    84,   126,
    90,    24,     8,    25,    17,    27,     8,     1,     2,   191,
     9,    10,   154,   155,   156,   157,     9,    10,    70,    71,
    65,    84,   140,   108,    29,   162,   163,   170,   171,    53,
    54,    31,    32,    35,   128,   166,    18,    40,    37,    39,
    11,    41,    43,    55,    49,    52,    56,    57,    60,    65,
    63,    67,    68,    75,    80,    78,    79,    81,    83,    92,
   102,   118,    97,    88,    91,    99,   146,   121,   149,   174,
   152,   100,   180,   186,   101,   103,   189,   105,   117,   139,
   124,   148,   193,   151,   167,   173,   177,   199,   212,   213,
   204,   188,   200,   202,   201,   205,   206,   210,   187,   203,
    22,   182,    33,    64,    51,   172,   196,   169,    23,   192,
   112,   195,   183,    72,     0,     0,     0,   160,   158,     0,
     0,     0,     0,     0,     0,   116,     0,     0,   207,   104,
     0,   123,     0,     0,     0,     0,     0,     0,     0,   125,
     0,     0,     0,   135,     0,     0,     0,     0,     0,   129,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
   142,     0,     0,     0,   159
};

static const short yycheck[] = {    53,
     0,     5,    49,   151,    87,    46,     6,    52,    48,    49,
    50,    51,    57,    16,    17,    18,    57,    52,    53,    54,
    67,    63,    26,     7,    28,    61,    26,     3,     4,   177,
    30,    31,    37,    38,    39,    40,    30,    31,    33,    34,
    52,    53,    56,    57,     5,   128,   129,    20,    21,    38,
    39,    61,    27,     8,   101,   138,    60,    63,    32,    61,
    60,     9,    58,    44,    63,    63,    63,    45,    59,    52,
    63,    63,    15,    29,    62,    57,    63,    47,    63,    23,
    44,    19,    36,    55,    63,    62,    22,    24,    10,    14,
    25,    62,    12,    11,    63,    63,    13,    64,    63,    65,
    63,    63,    35,    63,    57,    63,    63,    57,     0,     0,
    57,    63,    63,   195,    63,    57,   201,   208,   173,   197,
     6,   160,    24,    47,    36,   148,   184,   145,     7,   179,
    89,   182,   165,    52,    -1,    -1,    -1,   127,   124,    -1,
    -1,    -1,    -1,    -1,    -1,    91,    -1,    -1,   202,    83,
    -1,    96,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    98,
    -1,    -1,    -1,   103,    -1,    -1,    -1,    -1,    -1,   101,
    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
   111,    -1,    -1,    -1,   125
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
#line 198 "config_parse.y"
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
#line 210 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 9:
#line 217 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 13:
#line 224 "config_parse.y"
{
		/* abuse the fact that INADDR_ANY is 0. */
		src.atype 	= SOCKS_ADDR_IPV4;
		dst.atype 	= SOCKS_ADDR_IPV4;
	;
    break;}
case 17:
#line 244 "config_parse.y"
{
#ifdef SOCKS_CLIENT
		route.src		= src;
		route.dst 		= dst;
		route.gw.host	= *ruleaddress2sockshost(&gw, SOCKS_TCP);
		route.gw.state	= state;

		addroute(&route);
#endif
	;
    break;}
case 18:
#line 256 "config_parse.y"
{
#ifdef SOCKS_CLIENT
		command		= &state.command;
		extension 	= &state.extension;	
		methodv		= state.methodv;
		methodc		= &state.methodc;
		protocol		= &state.protocol;
		version		= &state.version;

		bzero(&state, sizeof(state));
		bzero(&route, sizeof(route));
		bzero(&gw, sizeof(gw));
		bzero(&src, sizeof(src));
		bzero(&dst, sizeof(dst));
		src.atype	= SOCKS_ADDR_IPV4;
		dst.atype	= SOCKS_ADDR_IPV4;
#endif
	;
    break;}
case 19:
#line 278 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 21:
#line 283 "config_parse.y"
{
		switch (atoi(yyvsp[0].string)) {
			case 4:
				version->v4 = 1;
				break;

			case 5:
				version->v5 = 1;
				break;

			default:
				yyerror("unknown protocol version");
		}
	;
    break;}
case 22:
#line 299 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 24:
#line 303 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 26:
#line 308 "config_parse.y"
{
			extension->bind = 1;
	;
    break;}
case 27:
#line 313 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 29:
#line 319 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 30:
#line 320 "config_parse.y"
{
#ifdef SOCKS_SERVER
		if (config.state.init) {
			int i;

			for (i = 0; i < config.internalc; ++i)
				if (config.internalv[i].addr.sin_addr.s_addr != ipaddr->s_addr
				||	 config.internalv[i].addr.sin_port != *port_tcp)
					swarnx("can not change internal address' once running");
		}
#endif /* SOCKS_SERVER */
	;
    break;}
case 31:
#line 334 "config_parse.y"
{
#ifdef SOCKS_SERVER
	struct ruleaddress_t mem;
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
		struct in_addr inaddrmem;
		in_port_t portmem;

		ipaddr 		= &inaddrmem;
		port_tcp		= &portmem;
	}
#endif
	;
    break;}
case 33:
#line 373 "config_parse.y"
{
#ifdef SOCKS_SERVER
		struct ruleaddress_t mem;

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
case 35:
#line 396 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 37:
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
case 38:
#line 435 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 41:
#line 442 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.uid.privileged = yyvsp[0].uid;
#endif
	;
    break;}
case 42:
#line 449 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.uid.unprivileged = yyvsp[0].uid;
#endif
	;
    break;}
case 43:
#line 456 "config_parse.y"
{ 
#ifdef SOCKS_SERVER

#ifdef HAVE_LIBWRAP
		config.uid.libwrap = config.uid.unprivileged;	/* default. */
#endif  /* HAVE_LIBWRAP */
	;
    break;}
case 44:
#line 463 "config_parse.y"
{
#ifndef HAVE_LIBWRAP
		yyerror("libwrap support not compiled in");
#endif  /* HAVE_LIBWRAP */
		config.uid.libwrap = yyvsp[0].uid;

#endif /* SOCKS_SERVER */
	;
    break;}
case 45:
#line 474 "config_parse.y"
{
		struct passwd *pw;

		if ((pw = getpwnam(yyvsp[0].string)) == NULL)
			serr(EXIT_FAILURE, yyvsp[0].string);
		else
			yyval.uid = pw->pw_uid;
	;
    break;}
case 46:
#line 484 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 47:
#line 485 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.timeout.io = atol(yyvsp[0].string);
#endif
	;
    break;}
case 48:
#line 492 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 49:
#line 493 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.timeout.negotiate = atol(yyvsp[0].string);
#endif
	;
    break;}
case 50:
#line 500 "config_parse.y"
{	yyval.string = NULL; ;
    break;}
case 51:
#line 501 "config_parse.y"
{
		config.option.debug = atoi(yyvsp[0].string);
	;
    break;}
case 52:
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
case 53:
#line 519 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 55:
#line 523 "config_parse.y"
{
#ifdef SOCKS_SERVER
		config.compat.reuseaddr = 1;	
	;
    break;}
case 56:
#line 527 "config_parse.y"
{
		config.compat.sameport = 1;
#endif
	;
    break;}
case 57:
#line 533 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 59:
#line 538 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 61:
#line 542 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 63:
#line 546 "config_parse.y"
{
		methodv[(*methodc)++] = AUTHMETHOD_NONE; 
	;
    break;}
case 64:
#line 549 "config_parse.y"
{
		yyerror("GSSAPI not supported");	
	;
    break;}
case 65:
#line 552 "config_parse.y"
{
		methodv[(*methodc)++] = AUTHMETHOD_UNAME;
	;
    break;}
case 66:
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
case 68:
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
case 70:
#line 604 "config_parse.y"
{
#ifdef SOCKS_SERVER
		rule.verdict 	= VERDICT_BLOCK;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol 		= &rule.state.protocol;
		version			= &rule.state.version;
	;
    break;}
case 71:
#line 613 "config_parse.y"
{
		rule.verdict 	= VERDICT_PASS;
		command			= &rule.state.command;
		methodv			= rule.state.methodv;
		methodc			= &rule.state.methodc;
		protocol 		= &rule.state.protocol;
		version			= &rule.state.version;
#endif 
	;
    break;}
case 72:
#line 624 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 74:
#line 628 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 76:
#line 632 "config_parse.y"
{
		command->bind = 1;
	;
    break;}
case 77:
#line 635 "config_parse.y"
{
		command->connect = 1;
	;
    break;}
case 78:
#line 638 "config_parse.y"
{
		command->udpassociate = 1;
	;
    break;}
case 79:
#line 644 "config_parse.y"
{
		command->bindreply = 1;
	;
    break;}
case 80:
#line 650 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 82:
#line 654 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 84:
#line 659 "config_parse.y"
{
		protocol->tcp = 1;
	;
    break;}
case 85:
#line 662 "config_parse.y"
{
		protocol->udp = 1;
	;
    break;}
case 87:
#line 671 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 89:
#line 675 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 91:
#line 679 "config_parse.y"
{
#ifdef SOCKS_SERVER
	rule.log.connect = 1;
	;
    break;}
case 92:
#line 683 "config_parse.y"
{
			rule.log.disconnect = 1;
		;
    break;}
case 93:
#line 686 "config_parse.y"
{
			rule.log.iooperation = 1;
		;
    break;}
case 94:
#line 689 "config_parse.y"
{
			rule.log.data = 1;
#endif
		;
    break;}
case 95:
#line 696 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 96:
#line 697 "config_parse.y"
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
case 97:
#line 708 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 98:
#line 709 "config_parse.y"
{
#ifdef SOCKSSERVER
		rule.privileged = 1;
#endif
	;
    break;}
case 99:
#line 716 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 101:
#line 721 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 105:
#line 733 "config_parse.y"
{
		addressinit(&src);
	;
    break;}
case 106:
#line 739 "config_parse.y"
{
		addressinit(&dst);
	;
    break;}
case 107:
#line 745 "config_parse.y"
{
#ifdef SOCKS_CLIENT
		addressinit(&gw);
#endif
	;
    break;}
case 113:
#line 764 "config_parse.y"
{
		*atype = SOCKS_ADDR_IPV4;

		if (!inet_aton(yyvsp[0].string, ipaddr))
			yyerror("bad address");
	;
    break;}
case 114:
#line 773 "config_parse.y"
{
		if (atoi(yyvsp[0].string) < 0 || atoi(yyvsp[0].string) > 32)
			yyerror("bad netmask");

		netmask->s_addr
		= atoi(yyvsp[0].string) == 0 ? 0 : htonl(0xffffffff << (32 - atoi(yyvsp[0].string)));
	;
    break;}
case 115:
#line 780 "config_parse.y"
{
			if (!inet_aton(yyvsp[0].string, netmask))
				yyerror("bad netmask");
	;
    break;}
case 116:
#line 786 "config_parse.y"
{
		*atype = SOCKS_ADDR_DOMAIN;

		if (strlen(yyvsp[0].string) >= MAXHOSTNAMELEN)
			yyerror("domain too long");
		strcpy(domain, yyvsp[0].string);
	;
    break;}
case 117:
#line 795 "config_parse.y"
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
case 118:
#line 808 "config_parse.y"
{ yyval.string = NULL; ;
    break;}
case 124:
#line 821 "config_parse.y"
{
		*port_tcp	= htons((in_port_t)atoi(yyvsp[0].string));
		*port_udp	= *port_tcp;
	;
    break;}
case 125:
#line 827 "config_parse.y"
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
case 126:
#line 852 "config_parse.y"
{
		ruleaddress->portend = htons((in_port_t)atoi(yyvsp[0].string));
		ruleaddress->operator = range;
	;
    break;}
case 127:
#line 858 "config_parse.y"
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
#line 864 "config_parse.y"


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
