/*
 * Copyright (c) 1997, 1998
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
 *  Gaustadaléen 21
 *  N-0371 Oslo
 *  Norway
 * 
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

%{

static const char rcsid[] =
"$Id: config_scan.l,v 1.32 1998/12/08 19:34:23 michaels Exp $";

#include "common.h"

#include "yacconfig.h" 
#include "config_parse.h"


%}


%option yylineno
%option noyywrap
/* %option debug */


	/* startconditions */
%x lineprefix
%x start_address
%x start_command
%x start_compatibility
%x start_extension
%x start_line
%x start_log
%x start_logoutput
%x start_method
%x start_option
%x start_service
%x start_username
%%


	/*
	 * we can operate in more than one mode, find out which it is and
	 * let the parser know.
	*/


%{
	extern int parseinit;
	extern const int configtype;

	if (!parseinit) {
		parseinit = 1;

		switch (configtype) {
			case CONFIGTYPE_SERVER:
				return SERVERCONFIG;

			case CONFIGTYPE_CLIENT:
				return CLIENTCONFIG;

			default:
				SERR(configtype);
		}
	}
%}

	/*
	 * Config stuff. 
	*/




	/* generic */

debug {
	yylval.string = yytext;
	return DEBUGING;
}

route {
	yylval.string = yytext;
	return ROUTE;
}


protocolversion {
	yylval.string = yytext;
	return PROTOCOLVERSION;
}


logoutput {
	BEGIN(start_logoutput);

	yylval.string = yytext;
	return LOGOUTPUT;
}

<start_logoutput>[^: \t\n]* {
	yylval.string = yytext;
	return LOGFILE;
}

	/*
	 * protocol
	 */

protocol {
	yylval.string = yytext;
	return PROTOCOL; 
}


tcp {
	yylval.string = yytext;
	return PROTOCOL_TCP;
}

udp {
	yylval.string = yytext;
	return PROTOCOL_UDP;
}

command {
	BEGIN(start_command);

	yylval.string = yytext;
	return COMMAND; 
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



	/*
	 * addresses
	 */

<*>from {
	BEGIN(start_address);

	yylval.string = yytext;
	return FROM; 
}

<*>to {
	BEGIN(start_address);

	yylval.string = yytext;
	return TO; 
}

<*>via {
	BEGIN(start_address);

	yylval.string = yytext;
	return VIA; 
}



<start_address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ { 
	yylval.string = yytext;
	return IPADDRESS; 
}

	/* XXX check rfc for what constitutes a valid domain */
<start_address>[0-9A-Za-z]*\.[0-9A-Za-z]*[\.A-Za-z]*[a-z][a-z][a-z]? {
	yylval.string = yytext;
	return DOMAIN;
}

<start_address>direct {
	yylval.string = yytext;
	return DIRECT;
}


<start_address>port {
	BEGIN(start_service);

	yylval.string = yytext;
	return PORT; 
}

	/* compare */
<start_service>eq|=|neq|!=|ge|>=|le|<=|gt|>|lt|< {
	yylval.string = yytext;
	return OPERATOR; 
}

<start_service>[a-zA-Z]+ {
	BEGIN(0);

	yylval.string = yytext;
	return SERVICENAME;
}



	/*
	 * authentication
	*/

auth {
	BEGIN(start_method);	/* identical names to method */

	yylval.string = yytext;
	return AUTH; 
}




	/* server configstuff */

internal {
	BEGIN(start_address);

	yylval.string = yytext;
	return INTERNAL;
}

external {
	BEGIN(start_address);

	yylval.string = yytext;
	return EXTERNAL;
}


privileged {

	yylval.string = yytext;
	return PRIVILEGED;
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


<start_username>[a-zA-Z0-9]+ {
	BEGIN(0);
	
	yylval.string = yytext;
	return USERNAME;
}

iotimeout {
	yylval.string = yytext;
	return IOTIMEOUT;
}

compatibility {
	BEGIN(start_compatibility);

	yylval.string = yytext;
	return COMPATIBILITY;
}

<start_compatibility>reuseaddr {
	yylval.string = yytext;
	return REUSEADDR;
}

<start_compatibility>sameport {
	yylval.string = yytext;
	return SAMEPORT;
}


connecttimeout {
	yylval.string = yytext;
	return CONNECTTIMEOUT;
}

extension {
	BEGIN(start_extension);

	yylval.string = yytext;
	return EXTENSION;
}


<start_extension>bind {
	yylval.string = yytext;
	return BIND;
}



client {
	yylval.string = yytext;
	return CLIENT;
}


method {
	BEGIN(start_method);

	yylval.string = yytext;
	return METHOD;
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

libwrap {
	BEGIN(lineprefix); 

	yylval.string = yytext;
	return LIBWRAPSTART;
}

localdomain {
	BEGIN(lineprefix); 

	yylval.string = yytext;
	return LOCALDOMAIN;  
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





	/* misc generic stuff. */


<*>[0-9]+ {
	yylval.string = yytext;
	return NUMBER;
}


	/* ignored */
<*>[[:blank:]]+ {
	;
}

	/* shell style comment */
<*>#.* {
	;
}

	/* state always ends at eol. */
<*>\n {
	BEGIN(0);
}

	/* unless it's escaped. */
<*>\\\n {
	;
}

<*>. {
	return *yytext;
}


