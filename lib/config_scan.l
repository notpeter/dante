/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2006, 2008,
 *               2009, 2010, 2011, 2012
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. The above copyright notice, this list of conditions and the following
 *    disclaimer must appear in all copies of the software, derivative works
 *    or modified versions, and any portions thereof, aswell as in all
 *    supporting documentation.
 * 2. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by
 *      Inferno Nettverk A/S, Norway.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Inferno Nettverk A/S requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  sdc@inet.no
 *  Inferno Nettverk A/S
 *  Oslo Research Park
 *  Gaustadalléen 21
 *  NO-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

%{

#if 0 /* XXX automatically added at head of generated .c file */
#include "common.h"
#endif

static const char rcsid[] =
"$Id: config_scan.l,v 1.184 2012/06/01 20:23:05 karls Exp $";

#include "yacconfig.h"
#include "config_parse.h"

static int shouldresetstate(const int current_state, const int next_token);
/*
 * If in state "current_state", and the next token is "next_token",
 * should we reset the current state?
 * Returns true if yes, false if not.
 */


extern int socks_parseinit;
extern const int socks_configtype;

static unsigned char ismask;

#define YY_STACK_USED 0
#define YY_ALWAYS_INTERACTIVE 0
#define YY_NEVER_INTERACTIVE 1
#define YY_MAIN 0

#if SOCKS_CLIENT
/*
 * stuff that is only defined in the server case, but which I don't know
 * how #ifdef out in the lex pattern matching code instead.  Is it possible?
 */
#define CHILD_MOTHER    0
#define CHILD_NEGOTIATE 0
#define CHILD_REQUEST   0
#define CHILD_IO        0

#endif /* SOCKS_CLIENT */

static int inrule, inroute;

%}

/*
 * yylineno nonoptimal under flex, reason for 'find_rule' 'yy_flex_realloc'
 * warnings.
 */
%option yylineno
%option noyywrap
%option nounput

/*%option debug                           */

   /* non-exclusive start conditions. */
%s start_address
%s start_port

   /* exclusive start conditions */
%x lineprefix
%x start_command
%x start_compatibility
%x start_line
%x start_log
%x start_logoutput
%x start_method
%x start_option
%x start_proxyprotocol
%x start_username
%x start_groupname
%x start_libwrapfile
%x start_cpuoption
%x start_hostindex

   /* ldap-stuff. */
%x start_ldapdomain
%x start_ldapbasedn
%x start_ldapurl
%x start_ldapfilter
%x start_ldapattribute
%x start_ldapservername
%x start_ldapgroupname
%x start_ldapkeytabname
%x start_ldapcertfile
%x start_ldapcertpath


%x start_srchost
%x start_protocol
%x start_servicename
%x start_portnumber
%x start_bsdauthstylename
%x start_gssapiservicename
%x start_gssapikeytabname
%x start_encryption
%x start_realmname

%x start_socketprotocol
%x start_socketoption
%x start_socketoptionvalue

%x start_processtype
%x start_schedulepolicy
%x start_schedulemask
%%

%{

   if (!socks_parseinit) {
      socks_parseinit = 1;

      switch (socks_configtype) {
         case CONFIGTYPE_SERVER:
            return SERVERCONFIG;

         case CONFIGTYPE_CLIENT:
            return CLIENTCONFIG;

         default:
            SERRX(socks_configtype);
      }
   }
%}



   /* start-condition dependent stuff. */

<start_servicename>[a-zA-Z]+[^: /\t\n]* {
   BEGIN(0);

   yylval.string = yytext;
   return SERVICENAME;
}

<start_proxyprotocol>socks_v4 {
   yylval.string = yytext;
   return PROXYPROTOCOL_SOCKS_V4;
}

<start_proxyprotocol>socks_v5 {
   yylval.string = yytext;
   return PROXYPROTOCOL_SOCKS_V5;
}

<start_proxyprotocol>http|http_v1.0 {
   yylval.string = yytext;
   return PROXYPROTOCOL_HTTP;
}

<start_proxyprotocol>upnp {
   yylval.string = yytext;
   return PROXYPROTOCOL_UPNP;
}

<start_command>bind {
   yylval.string = yytext;
   return COMMAND_BIND;
}

<start_command>connect {
   yylval.string = yytext;
   return COMMAND_CONNECT;
}

<start_command>udpassociate {
   yylval.string = yytext;
   return COMMAND_UDPASSOCIATE;
}

<start_command>bindreply {
   yylval.string = yytext;
   return COMMAND_BINDREPLY;
}

<start_command>udpreply {
   yylval.string = yytext;
   return COMMAND_UDPREPLY;
}


<start_address>direct {
   yylval.string = yytext;
   return DIRECT;
}

<start_address>(http|ftp)\:\/\/.* {
   yylval.string = yytext;
   return URL;
}

<start_address>\. {
   BEGIN(start_port);

   yylval.string = yytext;
   return DOMAINNAME;
}

<start_address>[^: \t\n][^/ \t\n]+ {
   struct sockaddr_storage addr;
   struct in_addr ipv4;

   BEGIN(start_port);

   yylval.string = yytext;

   /*
    * we don't have a reliable regex to differentiate between a
    * domainname and ifname on all systems.
    * With a very general regex like the above, it is not so easy
    * to exclude an ipaddress from matching it also.  So instead
    * of continuing to try and create a perfect regex, do a brute force
    * check to see what the text represents.
    */

   if (inet_pton(AF_INET, yytext, &ipv4) == 1)
      return IPADDRESS;

   if (ifname2sockaddr(yytext, 0, TOSA(&addr), NULL) != NULL)
      return IFNAME;

   return DOMAINNAME;
}

<start_port>port {
   yylval.string = yytext;
   return PORT;
}

   /*
    * cpu options.
    */

cpu {
   BEGIN(start_cpuoption);

   yylval.string = yytext;
   return CPU;
}

<start_cpuoption>schedule {
   BEGIN(start_processtype);

   ismask = 0;

   yylval.string = yytext;
   return SCHEDULE;
}

<start_cpuoption>mask {
   BEGIN(start_processtype);

   ismask = 1;

   yylval.string = yytext;
   return MASK;
}

<start_processtype>mother {
   BEGIN(ismask ? start_schedulemask : start_schedulepolicy);

   yylval.number = CHILD_MOTHER;
   return PROCESSTYPE;
}

<start_processtype>negotiate {
   BEGIN(ismask ? start_schedulemask : start_schedulepolicy);

   yylval.number = CHILD_NEGOTIATE;
   return PROCESSTYPE;
}

<start_processtype>request {
   BEGIN(ismask ? start_schedulemask : start_schedulepolicy);

   yylval.number = CHILD_REQUEST;
   return PROCESSTYPE;
}

<start_processtype>io {
   BEGIN(ismask ? start_schedulemask : start_schedulepolicy);

   yylval.number = CHILD_IO;
   return PROCESSTYPE;
}

<start_schedulemask>any {
   BEGIN(0);

   yylval.number = CPUMASK_ANYCPU;
   return NUMBER;
}

<start_schedulepolicy>[^: 0-9\t/]+ {
#if SOCKS_CLIENT
   SERRX(0);

#else /* !SOCKS_CLIENT */
#if HAVE_SCHED_SETAFFINITY

   BEGIN(0);

   if ((yylval.number = cpupolicy2numeric(yytext)) == -1)
      yyerror("unknown scheduling policy \"%s\"", yytext);

   return SCHEDULEPOLICY;
#else /* !HAVE_SCHED_SETAFFINITY */
	yyerror("setting the cpu scheduling policy is not supported on this platform");
#endif /* !HAVE_SCHED_SETAFFINITY */

#endif /* SOCKS_CLIENT */
}


   /*
     * socket option stuff.
     */

<start_socketprotocol>ip {
   BEGIN(start_socketoption);

   yylval.number = IPPROTO_IP;
   return SOCKETPROTOCOL;
}

<start_socketprotocol>socket {
   BEGIN(start_socketoption);

   yylval.number = SOL_SOCKET;
   return SOCKETPROTOCOL;
}

<start_socketprotocol>tcp {
   BEGIN(start_socketoption);

   yylval.number = IPPROTO_TCP;
   return SOCKETPROTOCOL;
}

<start_socketprotocol>udp {
   BEGIN(start_socketoption);

   yylval.number = IPPROTO_UDP;
   return SOCKETPROTOCOL;
}


<start_socketoption>[-a-zA-Z_][-a-zA-Z_\.]+ {
   const sockopt_t *sockopt;

   BEGIN(start_socketoptionvalue);

   if ((sockopt = optname2sockopt(yytext)) == NULL)
      yyerror("unknown socket option \"%s\"", yytext);

   yylval.number = (ssize_t)sockopt->optid;
   return SOCKETOPTION_OPTID;
}

<start_socketoptionvalue>[^: \t\n0-9][^ \t\n]+ {
   BEGIN(0);

   yylval.string = yytext;
   return SOCKETOPTION_SYMBOLICVALUE;
}

<start_log>connect {
   yylval.string = yytext;
   return SOCKS_LOG_CONNECT;
}

<start_log>data {
   yylval.string = yytext;
   return SOCKS_LOG_DATA;
}

<start_log>disconnect {
   yylval.string = yytext;
   return SOCKS_LOG_DISCONNECT;
}

<start_log>error {
   yylval.string = yytext;
   return SOCKS_LOG_ERROR;
}

<start_log>iooperation|ioop {
   yylval.string = yytext;
   return SOCKS_LOG_IOOPERATION;
}

<start_bsdauthstylename>[a-zA-Z]+[^: /\t\n]* {
   yylval.string = yytext;
   return BSDAUTHSTYLENAME;
}

<start_logoutput>[^: \t\n]+ {
   yylval.string = yytext;
   return LOGFILE;
}

<start_username>[^: \t\n]+ {
   yylval.string = yytext;
   return USERNAME;
}

<start_groupname>[^: \t\n]+ {
   yylval.string = yytext;
   return GROUPNAME;
}

<start_libwrapfile>[^: \t\n]+ {
   yylval.string = yytext;
   return LIBWRAP_FILE;
}

<start_ldapdomain>[^: \t\n]+[^\t\n]+ {
   yylval.string = yytext;
   return LDAP_DOMAIN;
}

<start_ldapbasedn>[^: \t\n]+[^\t\n]+ {
   yylval.string = yytext;
   return LDAP_BASEDN;
}

<start_ldapfilter>[^: \t\n]+[^\t\n]+ {
   yylval.string = yytext;
   return LDAP_FILTER;
}

<start_ldapurl>(ldap|ldaps)\:\/\/.* {
   yylval.string = yytext;
   return LDAP_URL;
}

<start_ldapattribute>[^: \t\n]+[^\t\n]+ {
   yylval.string = yytext;
   return LDAP_ATTRIBUTE;
}

<start_ldapgroupname>[^: \t\n]+[^\t\n]+ {
   yylval.string = yytext;
   return LDAPGROUP_NAME;
}

<start_ldapservername>[^: \t\n]+[^\t\n]+ {
   yylval.string = yytext;
   return LDAPSERVER_NAME;
}

<start_ldapcertfile>[^: \t\n]+ {
   yylval.string = yytext;
   return LDAP_CERTFILE;
}

<start_ldapcertpath>[^: \t\n]+ {
   yylval.string = yytext;
   return LDAP_CERTPATH;
}

<start_ldapkeytabname>[^: \t\n]+ {
   yylval.string = yytext;
   return LDAPKEYTABNAME;
}

<start_ldapkeytabname>FILE:[^ \t\n]+ {
   yylval.string = yytext;
   return LDAPKEYTABNAME;
}

<start_gssapikeytabname>[^: \t\n]+ {
   yylval.string = yytext;
   return GSSAPIKEYTABNAME;
}

<start_gssapikeytabname>FILE:[^ \t\n]+ {
   yylval.string = yytext;
   return GSSAPIKEYTABNAME;
}

<start_gssapiservicename>[^: \t\n]+ {
   yylval.string = yytext;
   return GSSAPISERVICENAME;
}

<lineprefix>: {
   BEGIN(start_line);

   yylval.string = yytext;
   return *yytext;
}

<start_line>.* {
   BEGIN(0);

   yylval.string = yytext;
   return LINE;
}

<start_srchost>nodnsmismatch {
   yylval.string = yytext;
   return NODNSMISMATCH;
}

<start_srchost>nodnsunknown {
   yylval.string = yytext;
   return NODNSUNKNOWN;
}

<start_srchost>checkreplyauth {
   yylval.string = yytext;
   return CHECKREPLYAUTH;
}

<start_protocol>tcp {
   yylval.string = yytext;
   return PROTOCOL_TCP;
}

<start_protocol>udp {
   yylval.string = yytext;
   return PROTOCOL_UDP;
}

<start_protocol>fake {
   yylval.string = yytext;
   return PROTOCOL_FAKE;
}

<start_encryption>any {
   yylval.string = yytext;
   return GSSAPIENC_ANY;
}

<start_encryption>clear {
   yylval.string = yytext;
   return GSSAPIENC_CLEAR;
}

<start_encryption>integrity {
   yylval.string = yytext;
   return GSSAPIENC_INTEGRITY;
}

<start_encryption>confidentiality {
   yylval.string = yytext;
   return GSSAPIENC_CONFIDENTIALITY;
}

<start_encryption>permessage {
   yylval.string = yytext;
   return GSSAPIENC_PERMESSAGE;
}

<start_realmname>[^: \t\n]+ {
   yylval.string = yytext;
   return REALNAME;
}

<start_method>none {
   yylval.string = yytext;
   return NONE;
}

<start_method>gssapi {
   yylval.string = yytext;
   return GSSAPI;
}

<start_method>username {
   yylval.string = yytext;
   return UNAME;
}

<start_method>rfc931 {
   yylval.string = yytext;
   return RFC931;
}

<start_method>pam {
   yylval.string = yytext;
   return PAM;
}

<start_method>bsdauth {
   yylval.string = yytext;
   return BSDAUTH;
}

   /* non-start condition dependents. */

eq|=|ne|!=|ge|>=|le|<=|gt|>|lt|< {
   BEGIN(start_servicename);

   yylval.string = yytext;
   return OPERATOR;
}


debug {
   yylval.string = yytext;
   return DEBUGGING;
}

route {
   yylval.string = yytext;
   return ROUTE;
}

maxfail {
   yylval.string = yytext;
   return MAXFAIL;
}

badexpire {
   yylval.string = yytext;
   return BADROUTE_EXPIRE;
}

resolveprotocol {
   BEGIN(start_protocol);

   yylval.string = yytext;
   return RESOLVEPROTOCOL;
}

srchost {
   BEGIN(start_srchost);

   yylval.string = yytext;
   return SRCHOST;
}

socket {
   yylval.string = yytext;
   return SOCKET;
}

clientsocket {
   yylval.string = yytext;
   return CLIENTSIDE_SOCKET;
}

sendbuf {
   BEGIN(start_protocol);

   yylval.string = yytext;
   return SNDBUF;
}

recvbuf {
   BEGIN(start_protocol);

   yylval.string = yytext;
   return RCVBUF;
}


proxyprotocol {
   BEGIN(start_proxyprotocol);

   yylval.string = yytext;
   return PROXYPROTOCOL;
}

errorlog {
   BEGIN(start_logoutput);

   yylval.string = yytext;
   return ERRORLOG;
}


logoutput {
   BEGIN(start_logoutput);

   yylval.string = yytext;
   return LOGOUTPUT;
}

protocol {
   BEGIN(start_protocol);

   yylval.string = yytext;
   return PROTOCOL;
}

command {
   BEGIN(start_command);

   yylval.string = yytext;
   return COMMAND;
}

udp\.portrange {
   yylval.string = yytext;
   return UDPPORTRANGE;
}

udp\.connectdst {
   yylval.string = yytext;
   return UDPCONNECTDST;
}

redirect {
   yylval.string = yytext;
   return REDIRECT;
}

bandwidth {
   yylval.string = yytext;
   return BANDWIDTH;
}

maxsessions {
   yylval.string = yytext;
   return MAXSESSIONS;
}

from {
   BEGIN(start_address);

   yylval.string = yytext;
   return FROM;
}

to {
   BEGIN(start_address);

   yylval.string = yytext;
   return TO;
}

via {
   BEGIN(start_address);

   yylval.string = yytext;
   return VIA;
}

yes {
   yylval.string = yytext;
   return YES;
}

no {
   yylval.string = yytext;
   return NO;
}

internal\. {
   BEGIN(start_socketprotocol);

   yylval.string = yytext;
   return INTERNALSOCKET;
}

internal {
   BEGIN(start_address);

   yylval.string = yytext;
   return INTERNAL;
}

external\.rotation {
   yylval.string = yytext;
   return EXTERNAL_ROTATION;
}

external\. {
   BEGIN(start_socketprotocol);

   yylval.string = yytext;
   return EXTERNALSOCKET;
}


external {
   BEGIN(start_address);

   yylval.string = yytext;
   return EXTERNAL;
}

none {
   yylval.string = yytext;
   return NONE;
}

same-same {
   yylval.string = yytext;
   return SAMESAME;
}


child\.maxidle {
   yylval.string = yytext;
   return CHILD_MAXIDLE;
}

child\.maxrequests {
   yylval.string = yytext;
   return CHILD_MAXREQUESTS;
}


user {
   BEGIN(start_username);

   yylval.string = yytext;
   return USER;
}

group {
   BEGIN(start_groupname);

   yylval.string = yytext;
   return GROUP;
}

user\.privileged {
   BEGIN(start_username);

   yylval.string = yytext;
   return USER_PRIVILEGED;
}

user\.unprivileged|user\.notprivileged {
   BEGIN(start_username);

   yylval.string = yytext;
   return USER_UNPRIVILEGED;
}

user\.libwrap {
   BEGIN(start_username);

   yylval.string = yytext;
   return USER_LIBWRAP;
}

timeout\.connect {
   yylval.string = yytext;
   return CONNECTTIMEOUT;
}

timeout\.tcp_fin_wait {
   yylval.string = yytext;
   return TCP_FIN_WAIT;
}


timeout\.io {
   yylval.string = yytext;
   return IOTIMEOUT;
}

timeout\.io\.tcp {
   yylval.string = yytext;
   return IOTIMEOUT_TCP;
}

timeout\.io\.udp {
   yylval.string = yytext;
   return IOTIMEOUT_UDP;
}

timeout\.negotiate {
   yylval.string = yytext;
   return NEGOTIATETIMEOUT;
}


compatibility {
   yylval.string = yytext;
   return COMPATIBILITY;
}

sameport {
   yylval.string = yytext;
   return SAMEPORT;
}

draft-5.05 {
   yylval.string = yytext;
   return DRAFT_5_05;
}

clientcompatibility {
   yylval.string = yytext;
   return CLIENTCOMPATIBILITY;
}

necgssapi {
   yylval.string = yytext;
   return NECGSSAPI;
}

extension {
   yylval.string = yytext;
   return EXTENSION;
}

bind {
   yylval.string = yytext;
   return BIND;
}

client {
   yylval.string = yytext;
   return CLIENTRULE;
}

hostid {
	if (inrule || inroute)
		BEGIN(start_address);

   yylval.string = yytext;
   return HOSTID;
}

hostindex {
   BEGIN(start_hostindex);

   yylval.string = yytext;
   return HOSTINDEX;
}

<start_hostindex>any {
   BEGIN(0);

   yylval.number = 0;
   return NUMBER;
}


method {
   BEGIN(start_method);

   yylval.string = yytext;
   return METHOD;
}

clientmethod {
   BEGIN(start_method);

   yylval.string = yytext;
   return CLIENTMETHOD;
}

   /* filterrules */

   /*
    * verdicts
    */

block {
	inrule = 1;

   yylval.string = yytext;
   return VERDICT_BLOCK;
}

pass {
	inrule = 1;

   yylval.string = yytext;
   return VERDICT_PASS;
}



   /*
    * logging
    */

log {
   BEGIN(start_log);

   yylval.string = yytext;
   return SOCKS_LOG;
}

libwrap {
   BEGIN(lineprefix);

   yylval.string = yytext;
   return LIBWRAPSTART;
}

libwrap\.allow {
   BEGIN(start_libwrapfile);

   yylval.string = yytext;
   return LIBWRAP_ALLOW;
}

libwrap\.deny {
   BEGIN(start_libwrapfile);

   yylval.string = yytext;
   return LIBWRAP_DENY;
}

libwrap\.hosts_access {
   yylval.string = yytext;
   return LIBWRAP_HOSTS_ACCESS;
}

pam\.servicename|pamservicename {
   BEGIN(start_servicename);

   yylval.string = yytext;
   return PAMSERVICENAME;
}

bsdauth\.stylename {
   BEGIN(start_bsdauthstylename);

   yylval.string = yytext;
   return BSDAUTHSTYLE;
}

gssapi\.servicename {
   BEGIN(start_gssapiservicename);

   yylval.string = yytext;
   return GSSAPISERVICE;
}

gssapi\.keytab {
       BEGIN(start_gssapikeytabname);

   yylval.string = yytext;
   return GSSAPIKEYTAB;
}

gssapi\.enctype {
       BEGIN(start_encryption);

   yylval.string = yytext;
   return GSSAPIENCTYPE;
}

ldap\.basedn {
       BEGIN(start_ldapbasedn);

   yylval.string = yytext;
   return LDAPBASEDN;
}

ldap\.basedn\.hex {
       BEGIN(start_ldapbasedn);

   yylval.string = yytext;
   return LDAPBASEDN_HEX;
}

ldap\.basedn\.hex\.all {
       BEGIN(start_ldapbasedn);

   yylval.string = yytext;
   return LDAPBASEDN_HEX_ALL;
}

ldap\.port {
   yylval.string = yytext;
   return LDAPPORT;
}

ldap\.port\.ssl {
   yylval.string = yytext;
   return LDAPPORTSSL;
}

ldap\.url {
       BEGIN(start_ldapurl);

   yylval.string = yytext;
   return LDAPURL;
}

ldap\.certfile {
   BEGIN(start_ldapcertfile);

   yylval.string = yytext;
   return LDAPCERTFILE;
}

ldap\.certpath {
   BEGIN(start_ldapcertpath);

   yylval.string = yytext;
   return LDAPCERTPATH;
}

ldap\.domain {
       BEGIN(start_ldapdomain);

   yylval.string = yytext;
   return LDAPDOMAIN;
}

ldap\.debug {
   yylval.string = yytext;
   return LDAPDEBUG;
}

ldap\.mdepth {
   yylval.string = yytext;
   return LDAPDEPTH;
}

ldap\.ssl {
   yylval.string = yytext;
   return LDAPSSL;
}

ldap\.auto\.off {
   yylval.string = yytext;
   return LDAPAUTO;
}

ldap\.certcheck {
   yylval.string = yytext;
   return LDAPCERTCHECK;
}

ldap\.keeprealm {
   yylval.string = yytext;
   return LDAPKEEPREALM;
}

ldap\.filter {
       BEGIN(start_ldapfilter);

   yylval.string = yytext;
   return LDAPFILTER;
}

ldap\.filter\.ad {
       BEGIN(start_ldapfilter);

   yylval.string = yytext;
   return LDAPFILTER_AD;
}

ldap\.filter\.hex {
       BEGIN(start_ldapfilter);

   yylval.string = yytext;
   return LDAPFILTER_HEX;
}

ldap\.filter\.ad\.hex {
       BEGIN(start_ldapfilter);

   yylval.string = yytext;
   return LDAPFILTER_AD_HEX;
}

ldap\.attribute {
       BEGIN(start_ldapattribute);

   yylval.string = yytext;
   return LDAPATTRIBUTE;
}

ldap\.attribute\.ad {
       BEGIN(start_ldapattribute);

   yylval.string = yytext;
   return LDAPATTRIBUTE_AD;
}

ldap\.attribute\.hex {
       BEGIN(start_ldapattribute);

   yylval.string = yytext;
   return LDAPATTRIBUTE_HEX;
}

ldap\.attribute\.ad\.hex {
       BEGIN(start_ldapattribute);

   yylval.string = yytext;
   return LDAPATTRIBUTE_AD_HEX;
}

ldap\.server {
   BEGIN(start_ldapservername);

   yylval.string = yytext;
   return LDAPSERVER;
}

ldap\.group {
   BEGIN(start_ldapgroupname);

   yylval.string = yytext;
   return LDAPGROUP;
}

ldap\.group\.hex {
   BEGIN(start_ldapgroupname);

   yylval.string = yytext;
   return LDAPGROUP_HEX;
}

ldap\.group\.hex\.all {
   BEGIN(start_ldapgroupname);

   yylval.string = yytext;
   return LDAPGROUP_HEX_ALL;
}

ldap\.keytab {
   BEGIN(start_ldapkeytabname);

   yylval.string = yytext;
   return LDAPKEYTAB;
}

bounce {
   yylval.string = yytext;
   return BOUNCE;
}

realm {
  BEGIN(start_realmname);

   yylval.string = yytext;
   return REALM;
}

 /*
  * global keywords that are no longer used.
  */

localdomain.*:.*|connecttimeout|iotimeout {
   yylval.string = yytext;
   return DEPRECATED;
}


   /* misc. generic stuff. */

	/*
	 * note that to support negative numbers we need to handle number ranges
	 * like port 1-65535 correctly also.
	 */

<*>([0-9]|0x[a-fA-F0-9])+ {
   char *ep;
   long lval;

   errno = 0;
   lval  = strtol(yytext, &ep, 0);
   if (*yytext == NUL || *ep != NUL)
      yyerror("confusing.  Thought we would have a number here");

   if (errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN))
      yyerror("number given is out of range");

   yylval.number = (ssize_t)lval;

   if (shouldresetstate(YYSTATE, NUMBER))
      BEGIN(0);

   return NUMBER;
}

   /* ignored */
<*>[[:blank:]]+ {
   ;
}

   /* shell style comment */
<*>#.* {
   BEGIN(0);
   ;
}

   /* state always ends at eol ... */
<*>\n {
   BEGIN(0);
}

   /* ... unless it's escaped. */
<*>\\\n {
   ;
}

<*>\} {
	inrule = inroute = 0;

   yylval.string = yytext;
   return *yytext;
}

<*>. {
   yylval.string = yytext;
   return *yytext;
}

%%

static int
shouldresetstate(current_state, next_token)
   const int current_state;
   const int next_token;
{
   switch (current_state) {
      case start_hostindex:
      case start_schedulemask:
      case start_servicename:
         switch (next_token) {
            case NUMBER:
               return 1;
         }
         break;
   }

   return 0;
}
