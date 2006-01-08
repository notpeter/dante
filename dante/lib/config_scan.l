/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004
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

#include "common.h"

#include "yacconfig.h"
#include "config_parse.h"

extern int socks_parseinit;
extern const int socks_configtype;

static const char rcsid[] =
"$Id: config_scan.l,v 1.76 2005/12/19 14:22:13 michaels Exp $";

#define YY_STACK_USED 0
#define YY_ALWAYS_INTERACTIVE 0
#define YY_NEVER_INTERACTIVE 1
#define YY_MAIN 0

%}


%option yylineno
%option noyywrap
/*%option debug             */

PORTNUMBER [0-9]{1,5}

	/* non-exclusive startconditions. */
%s start_address
%s start_port

	/* exclusive startconditions */
%x lineprefix
%x start_command
%x start_compatibility
%x start_line
%x start_log
%x start_logoutput
%x start_method
%x start_operator
%x start_option
%x start_proxyprotocol
%x start_username
%x start_portnumber
%x start_srchost
%x start_protocol
%x start_servicename
%%


	/*
	 * we can operate in more than one mode, find out which it is and
	 * let the parser know.
	 */


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


<start_proxyprotocol>socks_v4 {
	yylval.string = yytext;
	return PROXYPROTOCOL_SOCKS_V4;
}

<start_proxyprotocol>socks_v5 {
	yylval.string = yytext;
	return PROXYPROTOCOL_SOCKS_V5;
}

<start_proxyprotocol>msproxy_v2 {
	yylval.string = yytext;
	return DEPRECATED;
}

<start_proxyprotocol>http_v1.0 {
	yylval.string = yytext;
	return PROXYPROTOCOL_HTTP_V1_0;
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


<start_port>port {
	BEGIN(start_operator);

	yylval.string = yytext;
	return PORT;
}

<start_operator>eq|=|neq|!=|ge|>=|le|<=|gt|>|lt|< {
	BEGIN(start_portnumber);

	yylval.string = yytext;
	return OPERATOR;
}


<start_log>connect {
	yylval.string = yytext;
	return LOG_CONNECT;
}

<start_log>data {
	yylval.string = yytext;
	return LOG_DATA;
}

<start_log>disconnect {
	yylval.string = yytext;
	return LOG_DISCONNECT;
}

<start_log>error {
	yylval.string = yytext;
	return LOG_ERROR;
}

<start_log>iooperation {
	yylval.string = yytext;
	return LOG_IOOPERATION;
}

<start_portnumber,start_servicename>[a-zA-Z]+[^: /\t\n]* {
	BEGIN(INITIAL);

	yylval.string = yytext;
	return SERVICENAME;
}

<start_operator>{PORTNUMBER} {
	BEGIN(start_portnumber); /* no operator, first port in range then. */

	yylval.string = yytext;
	return PORTNUMBER;
}

<start_portnumber>{PORTNUMBER} {
	BEGIN(INITIAL);

	yylval.string = yytext;
	return PORTNUMBER;
}

<start_address>([a-zA-Z0-9-]*\.[a-zA-Z0-9-]+[a-zA-Z\.-]*|\.) {
	BEGIN(start_port);

	yylval.string = yytext;
	return DOMAINNAME;
}

<start_address>[a-zA-Z]+[0-9:]* {
	BEGIN(start_port);

	yylval.string = yytext;
	return IFNAME;
}

<start_logoutput>[^: \t\n]+ {
	yylval.string = yytext;
	return LOGFILE;
}

<start_username>[^: \t\n]+ {
	yylval.string = yytext;
	return USERNAME;
}

<lineprefix>: {
	BEGIN(start_line);

	yylval.string = yytext;
	return *yytext;
}

<start_line>.* {
	BEGIN(INITIAL);

	yylval.string = yytext;
	return LINE;
}

<start_srchost>nomismatch {
	yylval.string = yytext;
	return NOMISMATCH;
}

<start_srchost>nounknown {
	yylval.string = yytext;
	return NOUNKNOWN;
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


	/* non-startcondition dependents. */

debug {
	yylval.string = yytext;
	return DEBUGING;
}

route {
	yylval.string = yytext;
	return ROUTE;
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

proxyprotocol {
	BEGIN(start_proxyprotocol);

	yylval.string = yytext;
	return PROXYPROTOCOL;
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

	/* server configstuff */
internal {
	BEGIN(start_address);

	yylval.string = yytext;
	return INTERNAL;
}

external.rotation {
	yylval.string = yytext;
	return EXTERNAL_ROTATION;
}

route {
	yylval.string = yytext;
	return ROUTE;
}

none {
	yylval.string = yytext;
	return NONE;
}


external {
	BEGIN(start_address);

	yylval.string = yytext;
	return EXTERNAL;
}

child\.maxidle {
	yylval.string = yytext;
	return CHILD_MAXIDLE;
}

user {
	BEGIN(start_username);

	yylval.string = yytext;
	return USER;
}

user\.privileged {
	BEGIN(start_username);

	yylval.string = yytext;
	return USER_PRIVILEGED;
}

user\.notprivileged {
	BEGIN(start_username);

	yylval.string = yytext;
	return USER_UNPRIVILEGED;
}

user\.libwrap {
	BEGIN(start_username);

	yylval.string = yytext;
	return USER_LIBWRAP;
}

iotimeout {
	yylval.string = yytext;
	return IOTIMEOUT;
}

compatibility {
	yylval.string = yytext;
	return COMPATIBILITY;
}

reuseaddr {
	yylval.string = yytext;
	return REUSEADDR;
}

sameport {
	yylval.string = yytext;
	return SAMEPORT;
}


connecttimeout {
	yylval.string = yytext;
	return CONNECTTIMEOUT;
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


	/* filterrules */

	/*
	 * verdicts
	 */

block {
	yylval.string = yytext;
	return VERDICT_BLOCK;
}

pass {
	yylval.string = yytext;
	return VERDICT_PASS;
}



	/*
	 * logging
	 */

log {
	BEGIN(start_log);

	yylval.string = yytext;
	return LOG;
}


libwrap {
	BEGIN(lineprefix);

	yylval.string = yytext;
	return LIBWRAPSTART;
}

pam\.servicename|pamservicename {
	BEGIN(start_servicename);

	yylval.string = yytext;
	return PAMSERVICENAME;
}


 /*
  * Old keywords that are no longer used.
  */

localdomain.*:.* {
	yylval.string = yytext;
	return DEPRECATED;
}



	/* misc. generic stuff. */

<*>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
	BEGIN(start_port);

	yylval.string = yytext;
	return IPADDRESS;
}


<*>[0-9]+ {
	yylval.string = yytext;
	return NUMBER;
}


	/* ignored */
<*>[[:blank:]]+ {
	;
}

	/* shell style comment */
<*>[[:blank:]]*#.* {
	;
}

	/* state always ends at eol. */
<*>\n {
	BEGIN(INITIAL);
}

	/* unless it's escaped. */
<*>\\\n {
	;
}

<*>. {
	return *yytext;
}
