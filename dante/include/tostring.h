/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003
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

/* $Id: tostring.h,v 1.8 2003/11/03 12:56:52 karls Exp $ */

#ifndef _TOSTRING_H_
#define _TOSTRING_H_
#endif

#if HAVE_DUMPCONF
#define QUOTE(a)	__CONCAT3("\"", a, "\"")
#define QUOTE0()	"\""
#else
#define QUOTE(a)	a
#define QUOTE0()	""
#endif /* HAVE_DUMPCONF */


enum operator_t
string2operator __P((const char *operator));
/*
 * Returns the enum for the string representation of a operator.
 * Can't fail.
 */

const char *
operator2string __P((enum operator_t operator));
/*
 * Returns the string representation of the operator.
 * Can't fail.
 */

const char *
ruleaddress2string __P((const struct ruleaddress_t *rule, char *string,
								size_t len));
/*
 * Writes "rule" out as a string.  The string is written to "string",
 * which is of length "len", including NUL termination.
 * Returns: "string".
 */

const char *
command2string __P((int command));
/*
 * Returns a printable representation of the socks command "command".
 * Can't fail.
 */

char *
commands2string __P((const struct command_t *command, char *str,
							size_t strsize));
/*
 * Returns a printable representation of "commands".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
methods2string __P((size_t methodc, const int *methodv, char *str,
							size_t strsize));
/*
 * Returns a printable representation of the methods "methodv", of
 * length "methodc".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */


const char *
protocol2string __P((int protocol));
/*
 * Returns a printable representation of "protocol".
 * Can't fail.
 */

char *
protocols2string __P((const struct protocol_t *protocols,
									 char *str, size_t strsize));
/*
 * Returns a printable representation of "protocols".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
proxyprotocols2string __P((const struct proxyprotocol_t *proxyprotocols,
									 char *str, size_t strsize));
/*
 * Returns a printable representation of "protocols".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
method2string __P((int method));
/*
 * Returns a printable representation of the authmethod "method".
 * Can't fail.
 */

int
string2method __P((const char *methodname));
/*
 * If "methodname" is the name of a supported method, the protocol
 * value of that method is returned.
 * Otherwise, -1 is returned.
 */

char *
sockshost2string __P((const struct sockshost_t *host, char *string,
							 size_t len));
/*
 * Writes "host" out as a string.  The string is written to "string",
 * which is of length "len", including NUL termination.
 * Returns: "string".
 */

char *
sockaddr2string __P((const struct sockaddr *address, char *string, size_t len));
/*
 * Returns the IP address and port in "address" on string form.
 * "address" is assumed to be on network form and it will be
 * converted to host form before written to "string".
 * "len" gives length of the NUL terminated string.
 * Returns: "string".
 */

struct udpheader_t *
string2udpheader __P((const char *data, size_t len,
							 struct udpheader_t *header));
/*
 * Converts "data" to udpheader_t representation.
 * "len" is length of "data".
 * "data" is assumed to be in network order.
 * Returns:
 *		On success: pointer to a udpheader_t in static memory.
 *		On failure: NULL ("data" is not a complete udppacket).
 */


const char *
socks_packet2string __P((const void *packet, int type));
/*
 * debug function; dumps socks packet content
 * "packet" is a socks packet, "type" indicates it's type.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

char *
extensions2string __P((const struct extension_t *extensions, char *str,
							  size_t strsize));
/*
 * Returns a printable representation of "extensions".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
resolveprotocol2string __P((int resolveprotocol));
/*
 * Returns a printable representation of "resolveprotocol".
 */

#if SOCKS_SERVER

char *
logtypes2string __P((const struct logtype_t *logtypes, char *str,
						   size_t strsize));
/*
 * Returns a printable representation of "logtypes".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */


char *
timeouts2string __P((const struct timeout_t *timeouts, const char *prefix,
							char *str, size_t strsize));
/*
 * Returns a printable representation of "timeouts".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
logs2string __P((const struct log_t *logs, char *str, size_t strsize));
/*
 * Returns a printable representation of "logs".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
userids2string __P((const struct userid_t *userids, const char *prefix,
						  char *str, size_t strsize));
/*
 * Returns a printable representation of "userids".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */


char *
options2string __P((const struct option_t *options, const char *prefix,
						  char *str, size_t strsize));
/*
 * Returns a printable representation of "options".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 * Returns: "str", NUL terminated.
 */


char *
compats2string __P((const struct compat_t *compats, char *str, size_t strsize));
/*
 * Returns a printable representation of "compats".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */


char *
users2string __P((const struct linkedname_t *user, char *str, size_t strsize));
/*
 * Returns a printable representation of "user".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */


const char * childtype2string __P((int type));
/*
 * returns the string representation of "type".
 */


const char *
verdict2string __P((int verdict));
/*
 * returns the string representation of "verdict".
 */

char *
srchosts2string __P((const struct srchost_t *srchosts, const char *prefix,
						   char *str, size_t strsize));
/*
 * Returns a printable representation of "srchosts".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
uid2name __P((uid_t uid));
/*
 * If there is a mapping from "uid" to name, returns the name.
 * Otherwise returns NULL.
*/

const char *
rotation2string __P((int rotation));
/*
 * Returns a printable representation of "rotation".
 */
#endif /* SOCKS_SERVER */
