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

#include "common.h"
#include "config_parse.h"

static const char rcsid[] =
"$Id: tostring.c,v 1.15 2006/01/01 16:45:02 michaels Exp $";

char *
proxyprotocols2string(proxyprotocols, str, strsize)
	const struct proxyprotocol_t *proxyprotocols;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (proxyprotocols->socks_v4)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(SOCKS_V4s));

	if (proxyprotocols->socks_v5)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(SOCKS_V5s));

	if (proxyprotocols->msproxy_v2)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(MSPROXY_V2s));

	if (proxyprotocols->http_v1_0)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(HTTP_V1_0s));

	return str;
}

char *
protocols2string(protocols, str, strsize)
	const struct protocol_t *protocols;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (protocols->tcp)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(PROTOCOL_TCPs));

	if (protocols->udp)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(PROTOCOL_UDPs));

	return str;
}


const char *
socks_packet2string(packet, type)
	  const void *packet;
	  int type;
{
	static char buf[1024];
	char hstring[MAXSOCKSHOSTSTRING];
	unsigned char version;
	const struct request_t *request = NULL;
	const struct response_t *response = NULL;

	switch (type) {
		case SOCKS_REQUEST:
			request = (const struct request_t *)packet;
			version = request->version;
			break;

		case SOCKS_RESPONSE:
			response = (const struct response_t *)packet;
			version	= response->version;
			break;

	  default:
		 SERRX(type);
  }

	switch (version) {
		case SOCKS_V4:
		case SOCKS_V4REPLY_VERSION:
			switch (type) {
				case SOCKS_REQUEST:
					snprintfn(buf, sizeof(buf),
					"(V4) VN: %d CD: %d address: %s",
					request->version, request->command,
					sockshost2string(&request->host, hstring, sizeof(hstring)));
					break;

				case SOCKS_RESPONSE:
					snprintfn(buf, sizeof(buf), "(V4) VN: %d CD: %d address: %s",
					response->version, response->reply,
					sockshost2string(&response->host, hstring, sizeof(hstring)));
					break;
			}
			break;

		case SOCKS_V5:
			switch (type) {
				case SOCKS_REQUEST:
					snprintfn(buf, sizeof(buf),
					"VER: %d CMD: %d FLAG: %d ATYP: %d address: %s",
					request->version, request->command, request->flag,
					request->host.atype,
					sockshost2string(&request->host, hstring, sizeof(hstring)));
					break;

				case SOCKS_RESPONSE:
					snprintfn(buf, sizeof(buf),
					"VER: %d REP: %d FLAG: %d ATYP: %d address: %s",
					response->version, response->reply, response->flag,
					response->host.atype,
					sockshost2string(&response->host, hstring, sizeof(hstring)));
					break;
			}
			break;

		default:
			SERRX(version);
  }

	return buf;
}


enum operator_t
string2operator(string)
	const char *string;
{

	if (strcmp(string, "eq") == 0 || strcmp(string, "=") == 0)
		return eq;

	if (strcmp(string, "neq") == 0 || strcmp(string, "!=") == 0)
		return neq;

	if (strcmp(string, "ge") == 0 || strcmp(string, ">=") == 0)
		return ge;

	if (strcmp(string, "le") == 0 || strcmp(string, "<=") == 0)
		return le;

	if (strcmp(string, "gt") == 0 || strcmp(string, ">") == 0)
		return gt;

	if (strcmp(string, "lt") == 0 || strcmp(string, "<") == 0)
		return lt;

	/* parser should make sure this never happens. */
	SERRX(string);

	/* NOTREACHED */
}



const char *
operator2string(operator)
	enum operator_t operator;
{

	switch (operator) {
		case none:
			return QUOTE("none");

		case eq:
			return QUOTE("eq");

		case neq:
			return QUOTE("neq");

		case ge:
			return QUOTE("ge");

		case le:
			return QUOTE("le");

		case gt:
			return QUOTE("gt");

		case lt:
			return QUOTE("lt");

		case range:
			return QUOTE("range");

		default:
			SERRX(operator);
	}

	/* NOTREACHED */
}


const char *
ruleaddress2string(address, string, len)
	const struct ruleaddress_t *address;
	char *string;
	size_t len;
{

	/* for debugging. */
	if (string == NULL) {
		static char addrstring[MAXRULEADDRSTRING];

		string = addrstring;
		len = sizeof(addrstring);
	}

	switch (address->atype) {
		case SOCKS_ADDR_IPV4: {
			char *a;

			snprintfn(string, len,
			"%s/%d%s, %s: %s%d%s, %s: %s%d%s, %s: %s, %s: %s%d",
			strcheck(a = strdup(inet_ntoa(address->addr.ipv4.ip))),
			bitcount((unsigned long)address->addr.ipv4.mask.s_addr),
			QUOTE0(),
			QUOTE("tcp"),
			QUOTE0(),
			ntohs(address->port.tcp),
			QUOTE0(),
			QUOTE("udp"),
			QUOTE0(),
			ntohs(address->port.udp),
			QUOTE0(),
			QUOTE("op"),
			operator2string(address->operator),
			QUOTE("end"),
			QUOTE0(),
			ntohs(address->portend));

			free(a);
			break;
		}

		case SOCKS_ADDR_DOMAIN:
			snprintfn(string, len,
			"%s%s, %s: %s%d%s, %s: %s%d%s, %s: %s, %s: %s%d",
			address->addr.domain,
			QUOTE0(),
			QUOTE("tcp"),
			QUOTE0(),
			ntohs(address->port.tcp),
			QUOTE0(),
			QUOTE("udp"),
			QUOTE0(),
			ntohs(address->port.udp),
			QUOTE0(),
			QUOTE("op"),
			operator2string(address->operator),
			QUOTE("end"),
			QUOTE0(),
			ntohs(address->portend));
			break;

		case SOCKS_ADDR_IFNAME:
			snprintfn(string, len,
			"%s%s, %s: %s%d%s, %s : %s%d%s, %s: %s, %s: %s%d",
			address->addr.ifname,
			QUOTE0(),
			QUOTE("tcp"),
			QUOTE0(),
			ntohs(address->port.tcp),
			QUOTE0(),
			QUOTE("udp"),
			QUOTE0(),
			ntohs(address->port.udp),
			QUOTE0(),
			QUOTE("op"),
			operator2string(address->operator),
			QUOTE("end"),
			QUOTE0(),
			ntohs(address->portend));
			break;

		default:
			SERRX(address->atype);
	}

	return string;
}


const char *
protocol2string(protocol)
	int protocol;
{

	switch (protocol) {
		case SOCKS_TCP:
			return QUOTE(PROTOCOL_TCPs);

		case SOCKS_UDP:
			return QUOTE(PROTOCOL_UDPs);

		default:
			SERRX(protocol);
	}

	/* NOTREACHED */
}

const char *
resolveprotocol2string(resolveprotocol)
	int resolveprotocol;
{
	switch (resolveprotocol) {
		case RESOLVEPROTOCOL_TCP:
			return QUOTE(PROTOCOL_TCPs);

		case RESOLVEPROTOCOL_UDP:
			return QUOTE(PROTOCOL_UDPs);

		case RESOLVEPROTOCOL_FAKE:
			return QUOTE("fake");

		default:
			SERRX(resolveprotocol);
	}

	/* NOTREACHED */
}


const char *
command2string(command)
	int command;
{

	switch (command) {
		case SOCKS_BIND:
			return QUOTE(SOCKS_BINDs);

		case SOCKS_CONNECT:
			return QUOTE(SOCKS_CONNECTs);

		case SOCKS_UDPASSOCIATE:
			return QUOTE(SOCKS_UDPASSOCIATEs);

		/* pseudo commands. */
		case SOCKS_ACCEPT:
			return QUOTE(SOCKS_ACCEPTs);

		case SOCKS_BINDREPLY:
			return QUOTE(SOCKS_BINDREPLYs);

		case SOCKS_UDPREPLY:
			return QUOTE(SOCKS_UDPREPLYs);

		case SOCKS_DISCONNECT:
			return QUOTE(SOCKS_DISCONNECTs);

		case SOCKS_UNKNOWN:
			return QUOTE(SOCKS_UNKNOWNs);

		default:
			SERRX(command);
	}

	/* NOTREACHED */
}

char *
commands2string(command, str, strsize)
	const struct command_t *command;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (command->bind)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		command2string(SOCKS_BIND));

	if (command->bindreply)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		command2string(SOCKS_BINDREPLY));

	if (command->connect)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		command2string(SOCKS_CONNECT));

	if (command->udpassociate)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		command2string(SOCKS_UDPASSOCIATE));

	if (command->udpreply)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		command2string(SOCKS_UDPREPLY));

	return str;
}

const char *
method2string(method)
	int method;
{

	switch (method) {
		case AUTHMETHOD_NOTSET:
			return QUOTE(AUTHMETHOD_NOTSETs);

		case AUTHMETHOD_NONE:
			return QUOTE(AUTHMETHOD_NONEs);

		case AUTHMETHOD_GSSAPI:
			return QUOTE(AUTHMETHOD_GSSAPIs);

		case AUTHMETHOD_UNAME:
			return QUOTE(AUTHMETHOD_UNAMEs);

		case AUTHMETHOD_NOACCEPT:
			return QUOTE(AUTHMETHOD_NOACCEPTs);

		case AUTHMETHOD_RFC931:
			return QUOTE(AUTHMETHOD_RFC931s);

		case AUTHMETHOD_PAM:
			return QUOTE(AUTHMETHOD_PAMs);

		default:
			SERRX(method);
	}

	/* NOTREACHED */
}

char *
methods2string(methodc, methodv, str, strsize)
	size_t methodc;
	const int *methodv;
	char *str;
	size_t strsize;
{
	size_t strused;
	size_t i;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;
	for (i = 0; i < methodc; ++i)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		method2string(methodv[i]));

	return str;
}

int
string2method(methodname)
	const char *methodname;
{
	struct {
		char	*methodname;
		int	method;
	} method[] = {
		{ AUTHMETHOD_NONEs,		AUTHMETHOD_NONE	},
		{ AUTHMETHOD_UNAMEs,		AUTHMETHOD_UNAME	},
		{ AUTHMETHOD_RFC931s,	AUTHMETHOD_RFC931	},
		{ AUTHMETHOD_PAMs,		AUTHMETHOD_PAM		}
	};
	size_t i;

	for (i = 0; i < ELEMENTS(method); ++i)
		if (strcmp(method[i].methodname, methodname) == 0)
			return method[i].method;

	return -1;
}


char *
sockshost2string(host, string, len)
	const struct sockshost_t *host;
	char *string;
	size_t len;
{

	if (string == NULL) { /* to ease debugging. */
		static char hstring[MAXSOCKSHOSTSTRING];

		string = hstring;
		len = sizeof(hstring);
	}

	switch (host->atype) {
		case SOCKS_ADDR_IPV4:
			snprintfn(string, len, "%s.%d",
			inet_ntoa(host->addr.ipv4), ntohs(host->port));
			break;

		case SOCKS_ADDR_IPV6:
				snprintfn(string, len, "%s.%d",
				"<IPv6 address not supported>", ntohs(host->port));
				break;

		case SOCKS_ADDR_DOMAIN: {
			snprintfn(string, len, "%s.%d",
			host->addr.domain, ntohs(host->port));
			break;
		}

		default:
			SERRX(host->atype);
	}

	return string;
}


char *
sockaddr2string(address, string, len)
	const struct sockaddr *address;
	char *string;
	size_t len;
{

	/* for debugging. */
	if (string == NULL) {
		static char addrstring[MAXSOCKADDRSTRING];

		string = addrstring;
		len = sizeof(addrstring);
	}

	switch (address->sa_family) {
		case AF_UNIX: {
			/* LINTED pointer casts may be troublesome */
			const struct sockaddr_un *addr = (const struct sockaddr_un *)address;

			strncpy(string, addr->sun_path, len - 1);
			string[len - 1] = NUL;
			break;
		}

		case AF_INET: {
			/* LINTED pointer casts may be troublesome */
			const struct sockaddr_in *addr = TOCIN(address);

			snprintfn(string, len, "%s.%d",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
			break;
		}

		default:
			SERRX(address->sa_family);
	}

	return string;
}

struct udpheader_t *
string2udpheader(data, len, header)
	const char *data;
	size_t len;
	struct udpheader_t *header;
{

	bzero(header, sizeof(*header));

	if (len < sizeof(header->flag))
		return NULL;
	memcpy(&header->flag, data, sizeof(header->flag));
	data += sizeof(header->flag);
	len -= sizeof(header->flag);

	if (len < sizeof(header->frag))
		return NULL;
	memcpy(&header->frag, data, sizeof(header->frag));
	data += sizeof(header->frag);
	len -= sizeof(header->frag);

	if ((data = (const char *)mem2sockshost(&header->host,
	(const unsigned char *)data, len, SOCKS_V5)) == NULL)
		return NULL;

	return header;
}

char *
extensions2string(extensions, str, strsize)
	const struct extension_t *extensions;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (extensions->bind)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE("bind"));

	return str;
}


#if SOCKS_SERVER

char *
logtypes2string(logtypes, str, strsize)
	const struct logtype_t *logtypes;
	char *str;
	size_t strsize;
{
	size_t strused;
	size_t i;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (logtypes->type & LOGTYPE_SYSLOG)
		strused += snprintfn(&str[strused], strsize - strused, "\"syslog.%s\", ",
		logtypes->facilityname);

	if (logtypes->type & LOGTYPE_FILE)
		for (i = 0; i < logtypes->fpc; ++i)
			strused += snprintfn(&str[strused], strsize - strused, "\"%s\", ",
			logtypes->fnamev[i]);

	return str;
}

char *
options2string(options, prefix, str, strsize)
	const struct option_t *options;
	const char *prefix;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%sconfigfile\": \"%s\",\n", prefix, options->configfile == NULL ?
	SOCKD_CONFIGFILE : options->configfile);

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%sdaemon\": \"%d\",\n", prefix, options->daemon);

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%sdebug\": \"%d\",\n", prefix, options->debug);

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%skeepalive\": \"%d\",\n", prefix, options->keepalive);

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%slinebuffer\": \"%d\",\n", prefix, options->debug);

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%sservercount\": \"%d\",\n", prefix, options->serverc);

	return str;
}


char *
logs2string(logs, str, strsize)
	const struct log_t *logs;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (logs->connect)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(LOG_CONNECTs));

	if (logs->disconnect)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(LOG_DISCONNECTs));

	if (logs->data)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(LOG_DATAs));

	if (logs->error)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(LOG_ERRORs));

	if (logs->iooperation)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE(LOG_IOOPERATIONs));

	return str;
}

const char *
childtype2string(type)
	int type;
{

	switch (type) {
		case CHILD_IO:
			return "io";

		case CHILD_MOTHER:
			return "mother";

		case CHILD_NEGOTIATE:
			return "negotiator";

		case CHILD_REQUEST:
			return "request";

		default:
			SERRX(type);
	}

	/* NOTREACHED */
}

const char *
verdict2string(verdict)
	int verdict;
{

	return verdict == VERDICT_PASS ?
	QUOTE(VERDICT_PASSs) : QUOTE(VERDICT_BLOCKs);
}

char *
users2string(user, str, strsize)
	const struct linkedname_t *user;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	for (; user != NULL; user = user->next)
		strused += snprintfn(&str[strused], strsize - strused, "\"%s\", ",
		user->name);

	return str;
}

char *
compats2string(compats, str, strsize)
	const struct compat_t *compats;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (compats->reuseaddr)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE("reuseaddr"));

	if (compats->sameport)
		strused += snprintfn(&str[strused], strsize - strused, "%s, ",
		QUOTE("sameport"));

	return str;
}

char *
srchosts2string(srchost, prefix, str, strsize)
	const struct srchost_t *srchost;
	const char *prefix;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	if (srchost->nomismatch)
		strused += snprintfn(&str[strused], strsize - strused,
		"\"%snomismatch\", ", prefix);

	if (srchost->nounknown)
		strused += snprintfn(&str[strused], strsize - strused,
		"\"%snounknown\",", prefix);

	return str;
}

const char *
uid2name(uid)
	uid_t uid;
{
	struct passwd *pw;

	if ((pw = getpwuid(uid)) == NULL)
		return NULL;

	return pw->pw_name;
}

char *
userids2string(userids, prefix, str, strsize)
	const struct userid_t *userids;
	const char *prefix;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%sprivileged\": \"%s\",\n", prefix, uid2name(userids->privileged));

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%snotprivileged\": \"%s\",\n", prefix, uid2name(userids->unprivileged));

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%slibwrap\": \"%s\",\n", prefix, uid2name(userids->libwrap));

	return str;
}

char *
timeouts2string(timeouts, prefix, str, strsize)
	const struct timeout_t *timeouts;
	const char *prefix;
	char *str;
	size_t strsize;
{
	size_t strused;

	if (strsize)
		*str = NUL; /* make sure we return a NUL terminated string. */
	else
		return str;

	strused = 0;

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%sconnecttimeout\": \"%ld\",\n", prefix, (long)timeouts->negotiate);

	strused += snprintfn(&str[strused], strsize - strused,
	"\"%siotimeout\": \"%ld\",\n", prefix, (long)timeouts->io);

	return str;
}

const char *
rotation2string(rotation)
	int rotation;
{

	switch (rotation) {
		case ROTATION_NONE:
			return "none";

		case ROTATION_ROUTE:
			return "route";

		default:
			SERRX(rotation);
	}

	/* NOTREACHED */
}

#endif /* SOCKS_SERVER */
