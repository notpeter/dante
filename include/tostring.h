/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2003, 2006, 2008, 2009, 2010,
 *               2011
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

/* $Id: tostring.h,v 1.44 2011/08/01 09:04:36 michaels Exp $ */

#ifndef _TOSTRING_H_
#define _TOSTRING_H_

#if HAVE_DUMPCONF
#define QUOTE(a)   __CONCAT3("\"", a, "\"")
#define QUOTE0()   "\""
#else
#define QUOTE(a)   a
#define QUOTE0()   ""
#endif /* HAVE_DUMPCONF */

enum operator_t
string2operator(const char *operator);
/*
 * Returns the enum for the string representation of a operator.
 * Can't fail.
 */

const char *
operator2string(enum operator_t operator);
/*
 * Returns the string representation of the operator.
 * Can't fail.
 */

const char *
ruleaddr2string(const struct ruleaddr_t *rule, char *string, size_t len)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Writes "rule" out as a string.  The string is written to "string",
 * which is of length "len", including NUL termination.
 *
 * If "string" and "len" is NULL and zero, the function returns a
 * string that will be overwritten on the next call to this function.
 *
 * Returns: "string".
 */

const char *
command2string(int command);
/*
 * Returns a printable representation of the socks command "command".
 * Can't fail.
 */

char *
commands2string(const struct command_t *command, char *str, size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "commands".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
methods2string(size_t methodc, const int *methodv, char *str, size_t strsize)
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Returns a printable representation of the methods "methodv", of
 * length "methodc".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
protocol2string(int protocol);
/*
 * Returns a printable representation of "protocol".
 * Can't fail.
 */

char *
protocols2string(const struct protocol_t *protocols, char *str,
		 size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "protocols".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
proxyprotocols2string(const struct proxyprotocol_t *proxyprotocols, char *str,
      size_t strsize)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "protocols".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * If "str" and "strsize" is NULL and zero, the function returns a
 * string that will be overwritten on the next call to this function.
 *
 * Returns: "str", NUL terminated.
 */

const char *
method2string(int method);
/*
 * Returns a printable representation of the authmethod "method".
 */

const char *
gssapiprotection2string(const int protection);
/*
 * Returns a printable representation of the gssapi protection "protection".
 */

int
string2method(const char *methodname);
/*
 * If "methodname" is the name of a supported method, the protocol
 * value of that method is returned.
 * Otherwise, -1 is returned.
 */

char *
sockshost2string(const struct sockshost_t *host, char *string, size_t len)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Writes "host" out as a string.  The string is written to "string",
 * which is of length "len", including NUL termination.
 *
 * If "string" and "len" is NULL and zero, the function returns a
 * string that will be overwritten on the next call to this function.
 *
 * Returns: "string".
 */

char *
sockaddr2string(const struct sockaddr *addr, char *string, size_t len)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns the IP addr and port in "addr" on string form.
 * "addr" is assumed to be on network form and it will be
 * converted to host form before written to "string".
 * "len" gives length of the NUL terminated string.
 *
 * If "string" and "len" is NULL and zero, the function returns a
 * string that will be overwritten on the next call to this function.
 *
 * Returns: "string".
 */

struct udpheader_t *
string2udpheader(const char *data, size_t len, struct udpheader_t *header)
      __attribute__((__nonnull__(1)))
      __attribute__((__bounded__(__string__, 1, 2)));
/*
 * Converts "data" to udpheader_t representation.
 * "len" is length of "data".
 * "data" is assumed to be in network order.
 * Returns:
 *      On success: pointer to a udpheader_t in static memory.
 *      On failure: NULL ("data" is not a valid udp packet).  In this case,
 *                  udpheader is bzero(3)-ed.
 */

const char *
socks_packet2string(const void *packet, int isrequest);
/*
 * debug function; dumps socks packet content.
 * "packet" is a socks packet, "isrequest" is set if it is a request
 * packet, false otherwise.
 *
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

char *
extensions2string(const struct extension_t *extensions, char *str,
      size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "extensions".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
resolveprotocol2string(int resolveprotocol);
/*
 * Returns a printable representation of "resolveprotocol".
 */

char *
gwaddr2string(const gwaddr_t *gw, char *string, size_t len)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Writes a printable representation of "gw" to "string" and
 * returns a pointer to it.
 */

char *
str2upper(char *string);
/*
 * converts all characters in "string" to uppercase.
 * returns "string".
 */

char *
socket2string(const int s, char *buf, size_t buflen)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Prints out address info for the socket "s".
 * "buf" gives the buffer to write the address info to, "buflen" the
 * size of "buf".  If buflen is zero, a statically allocated buffer will
 * be used instead.
 *
 * Returns a pointer to buf.
 */

const char *
version2string(int version);
/*
 * Returns a printable representation of the proxy protocol version "version".
 */

const char *
atype2string(const atype_t atype);
/*
 * Returns a printable representation of the atype "atype".
 */

char *
routeoptions2string(const routeoptions_t *options, char *str, size_t strsize);
/*
 * Returns a printable representation of the atype "atype".
 * If "str" and "strsize" is NULL and zero, the function returns a
 * string that will be overwritten on the next call to this function.
 */


const char *loglevel2string(const int loglevel);
/*
 * returns a printable representation of the loglevel "loglevel".
 */

char *
logtypes2string(const struct logtype_t *logtypes, char *str, size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "logtypes".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

#if !SOCKS_CLIENT

char *
timeouts2string(const struct timeout_t *timeouts, const char *prefix,
      char *str, size_t strsize)
      __attribute__((__nonnull__(3)))
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Returns a printable representation of "timeouts".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
logs2string(const struct log_t *logs, char *str, size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "logs".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

#if !HAVE_PRIVILEGES
char *
userids2string(const struct userid_t *userids, const char *prefix, char *str,
      size_t strsize)
      __attribute__((__nonnull__(3)))
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Returns a printable representation of "userids".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */
#endif /* !HAVE_PRIVILEGES */

char *
options2string(const struct option_t *options, const char *prefix,
      char *str, size_t strsize)
      __attribute__((__nonnull__(3)))
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Returns a printable representation of "options".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 * Returns: "str", NUL terminated.
 */

char *
compats2string(const struct compat_t *compats, char *str, size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "compats".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

char *
list2string(const struct linkedname_t *list, char *str, size_t strsize)
      __attribute__((__nonnull__(2)))
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Returns a printable representation of "list".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
childtype2string(int type);
/*
 * returns the string representation of "type".
 */

const char *
verdict2string(int verdict);
/*
 * returns the string representation of "verdict".
 */

char *
srchosts2string(const struct srchost_t *srchosts, const char *prefix,
      char *str, size_t strsize)
      __attribute__((__nonnull__(3)))
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Returns a printable representation of "srchosts".
 * "prefix" is prefixed to every line written to "str".
 * "str" is the memory to write the printable representation into,
 * "strsize" is the size of the memory.
 *
 * Returns: "str", NUL terminated.
 */

const char *
uid2name(uid_t uid);
/*
 * If there is a mapping from "uid" to name, returns the name.
 * Otherwise returns NULL.
 */

const char *
rotation2string(int rotation);
/*
 * Returns a printable representation of "rotation".
 */

const char *
privop2string(const priv_op_t op);
/*
 * Returns a printable representation of "op".
 */

#if COVENANT
const char *httpcode2string(const int version, const int code);
/*
 * Returns a short printable representation of the http version
 * "version" response code "code"
 */

#endif /* COVENANT */
#endif /* !SOCKS_CLIENT */

#endif /* !_TOSTRING_H_ */
