/*
 * Copyright (c) 1997, 1998, 1999
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
 *  N-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

#include "common.h"

#define SOCKS_DEBUGER	0

/* XXX */
#if HAVE_STRVIS
#include <vis.h>
#else
#include "compat.h"
#endif  /* HAVE_STRVIS */

static const char rcsid[] =
"$Id: util.c,v 1.76 1999/05/14 13:14:44 michaels Exp $";

/* fake "ip address", for clients without dns access. */
static char **ipv;
static in_addr_t ipc;

const char *
strcheck(string)
	const char *string;
{
	return string == NULL ? NOMEM : string;
}

char *
sockshost2string(host, string, len)
	const struct sockshost_t *host;
	char *string;
	size_t len;
{

	if (string == NULL) {
		static char hstring[MAXSOCKSHOSTSTRING];

		string = hstring;
		len = sizeof(hstring);
	}

	switch (host->atype) {
		case SOCKS_ADDR_IPV4:
			snprintf(string, len, "%s.%d",
			inet_ntoa(host->addr.ipv4), ntohs(host->port));
			break;

		case SOCKS_ADDR_IPV6:
				snprintf(string, len, "%s.%d",
				"<IPV6 address not supported>", ntohs(host->port));
				break;

		case SOCKS_ADDR_DOMAIN:
			snprintf(string, len, "%s.%d",
			host->addr.domain, ntohs(host->port));
			break;

		default:
			SERRX(host->atype);
	}

	return string;
}

const char *
command2string(command)
	int command;
{

	switch (command) {
		case SOCKS_BIND:
			return SOCKS_BINDs;

		case SOCKS_CONNECT:
			return SOCKS_CONNECTs;

		case SOCKS_UDPASSOCIATE:
			return SOCKS_UDPASSOCIATEs;

		/* pseudo commands. */
		case SOCKS_ACCEPT:
			return SOCKS_ACCEPTs;

		case SOCKS_BINDREPLY:
			return SOCKS_BINDREPLYs;

		case SOCKS_DISCONNECT:
			return SOCKS_DISCONNECTs;

		default:
			SERRX(command);
	}

	/* NOTREACHED */
}

const char *
method2string(method)
	int method;
{

	switch (method) {
		case AUTHMETHOD_NONE:
			return AUTHMETHOD_NONEs;

		case AUTHMETHOD_GSSAPI:
			return AUTHMETHOD_GSSAPIs;

		case AUTHMETHOD_UNAME:
			return AUTHMETHOD_UNAMEs;

		case AUTHMETHOD_NOACCEPT:
			return AUTHMETHOD_NOACCEPTs;

		default:
			SERRX(method);
	}

	/* NOTREACHED */
}


int
sockscode(version, code)
	int version;
	int code;
{

	switch (version) {
		case SOCKS_V4:
		case SOCKS_V4REPLY_VERSION:
			switch (code) {
				case SOCKS_SUCCESS:
					return SOCKSV4_SUCCESS;

				default:
					return SOCKSV4_FAIL;		/* v4 is not very specific. */
			}
		/* NOTREACHED */

		case SOCKS_V5:
			switch (code) {
				default:
					return code;	/* current codes are all V5. */
			}
		/* NOTREACHED */

		case MSPROXY_V2:
			switch (code) {
				case SOCKS_SUCCESS:
					return MSPROXY_SUCCESS;

				case SOCKS_FAILURE:
					return MSPROXY_FAILURE;

				default:
					SERRX(code);
			}
		/* NOTREACHED */

		default:
			SERRX(version);
	}

	/* NOTREACHED */
}

int
errno2reply(errnum, version)
	int errnum;
	int version;
{

	switch (errnum) {
		case ENETUNREACH:
			return sockscode(version, SOCKS_NETUNREACH);

		case EHOSTUNREACH:
			return sockscode(version, SOCKS_HOSTUNREACH);

		case ECONNREFUSED:
			return sockscode(version, SOCKS_CONNREFUSED);

		case ETIMEDOUT:
			return sockscode(version, SOCKS_TTLEXPIRED);
	}

	return sockscode(version, SOCKS_FAILURE);
}


struct sockaddr *
sockshost2sockaddr(host, addr)
	const struct sockshost_t *host;
	struct sockaddr *addr;
{
	const char *function = "sockshost2sockaddr()";

	bzero(addr, sizeof(*addr));
	/* LINTED pointer casts may be troublesome */
	((struct sockaddr_in *)addr)->sin_family = AF_INET;

	switch (host->atype) {
		case SOCKS_ADDR_IPV4:
			/* LINTED pointer casts may be troublesome */
			((struct sockaddr_in *)addr)->sin_addr = host->addr.ipv4;
			break;

		case SOCKS_ADDR_DOMAIN: {
			struct hostent *hostent;
			struct in_addr fakeaddr;

			if (socks_getfakeip(host->addr.domain, &fakeaddr) == 1) {
				/* LINTED pointer casts may be troublesome */
				((struct sockaddr_in *)addr)->sin_addr = fakeaddr;
				break;
			}

			if ((hostent = gethostbyname(host->addr.domain)) == NULL) {
				/* LINTED pointer casts may be troublesome */
				swarnx("%s: gethostbyname(%s): %s",
				function, host->addr.domain, hstrerror(h_errno));

				/* LINTED pointer casts may be troublesome */
				((struct sockaddr_in *)addr)->sin_addr.s_addr = htonl(INADDR_ANY);

				break;
			}

			if (inet_aton(hostent->h_addr_list[0],
			/* LINTED pointer casts may be troublesome */
			&((struct sockaddr_in *)addr)->sin_addr) != 1)
				swarn("%s: inet_aton(%s)", function, hostent->h_addr_list[0]);
			break;
		}

		default:
			SERRX(host->atype);
	}
	/* LINTED pointer casts may be troublesome */
	((struct sockaddr_in *)addr)->sin_port = host->port;

	/* LINTED pointer casts may be troublesome */
	return addr;
}

struct sockshost_t *
sockaddr2sockshost(addr, host)
	const struct sockaddr *addr;
	struct sockshost_t *host;
{

	switch (addr->sa_family) {
		case AF_INET:
			host->atype			= SOCKS_ADDR_IPV4;
			/* LINTED pointer casts may be troublesome */
			host->addr.ipv4	= ((const struct sockaddr_in *)addr)->sin_addr;
			/* LINTED pointer casts may be troublesome */
			host->port			= ((const struct sockaddr_in *)addr)->sin_port;
			break;

		default:
			SERRX(addr->sa_family);
	}

	return host;
}

const char *
operator2string(operator)
	enum operator_t operator;
{

	switch (operator) {
		case none:
			return "none";

		case eq:
			return "eq";

		case neq:
			return "neq";

		case ge:
			return "ge";

		case le:
			return "le";

		case gt:
			return "gt";

		case lt:
			return "lt";

		case range:
			return "range";

		default:
			SERRX(operator);
	}

	/* NOTREACHED */
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
ruleaddress2string(address, string, len)
	const struct ruleaddress_t *address;
	char *string;
	size_t len;
{

	switch (address->atype) {
		case SOCKS_ADDR_IPV4: {
			char *a, *b;

			snprintf(string, len, "%s/%s, tcp port: %d, udp port: %d op: %s %d",
			strcheck(a = strdup(inet_ntoa(address->addr.ipv4.ip))),
			strcheck(b = strdup(inet_ntoa(address->addr.ipv4.mask))),
			ntohs(address->port.tcp), ntohs(address->port.udp),
			operator2string(address->operator),
			ntohs(address->portend));
			free(a);
			free(b);
			break;
		}

		case SOCKS_ADDR_DOMAIN:
			snprintf(string, len, "%s, tcp port: %d, udp port: %d op: %s %d",
			address->addr.domain,
			ntohs(address->port.tcp), ntohs(address->port.udp),
			operator2string(address->operator),
			ntohs(address->portend));
			break;

		default:
			SERRX(address->atype);
	}

	return string;
}

struct sockshost_t *
ruleaddress2sockshost(address, host, protocol)
	const struct ruleaddress_t *address;
	struct sockshost_t *host;
	int protocol;
{

	switch (host->atype = address->atype) {
		case SOCKS_ADDR_IPV4:
			host->addr.ipv4 = address->addr.ipv4.ip;
			break;

		case SOCKS_ADDR_DOMAIN:
			SASSERTX(strlen(address->addr.domain) < sizeof(host->addr.domain));
			strcpy(host->addr.domain, address->addr.domain);
			break;

		default:
			SERRX(address->atype);
	}

	switch (protocol) {
		case SOCKS_TCP:
			host->port = address->port.tcp;
			break;

		case SOCKS_UDP:
			host->port = address->port.udp;
			break;

		default:
			SERRX(protocol);
	}

	return host;
}

struct ruleaddress_t *
sockshost2ruleaddress(host, addr)
	const struct sockshost_t *host;
	struct ruleaddress_t *addr;
{

	switch (addr->atype = host->atype) {
		case SOCKS_ADDR_IPV4:
			addr->addr.ipv4.ip				= host->addr.ipv4;
			addr->addr.ipv4.mask.s_addr	= htonl(0xffffffff);
			break;

		case SOCKS_ADDR_DOMAIN:
			SASSERTX(strlen(host->addr.domain) < sizeof(addr->addr.domain));
			strcpy(addr->addr.domain, host->addr.domain);
			break;

		default:
			SERRX(host->atype);
	}

	addr->port.tcp		= host->port;
	addr->port.udp		= host->port;
	addr->portend		= host->port;
	addr->operator		= none;

	return addr;
}

struct ruleaddress_t *
sockaddr2ruleaddress(addr, ruleaddr)
	const struct sockaddr *addr;
	struct ruleaddress_t *ruleaddr;
{
	struct sockshost_t host;

	sockaddr2sockshost(addr, &host);
	sockshost2ruleaddress(&host, ruleaddr);

	return ruleaddr;
}

const char *
protocol2string(protocol)
	int protocol;
{

	switch (protocol) {
		case SOCKS_TCP:
			return PROTOCOL_TCPs;

		case SOCKS_UDP:
			return PROTOCOL_UDPs;

		default:
			SERRX(protocol);
	}

	/* NOTREACHED */
}


char *
sockaddr2string(address, string, len)
	const struct sockaddr *address;
	char *string;
	size_t len;
{

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
			const struct sockaddr_in *addr = (const struct sockaddr_in *)address;

			snprintf(string, len, "%s.%d",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
			break;
		}

		default:
			SERRX(address->sa_family);
	}

	return string;
}


void
#ifdef STDC_HEADERS
serr(int eval, const char *fmt, ...)
#else
serr(eval, fmt, va_alist)
	int eval;
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;
	char buf[2048];
	size_t bufused;

	if (fmt != NULL) {
#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

		bufused = vsnprintf(buf, sizeof(buf), fmt, ap);

		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused,
		": %s (errno = %d)",
		strerror(errno), errno);

		slog(LOG_ERR, buf);

		/* LINTED expression has null effect */
		va_end(ap);
	}

#if SOCKS_SERVER
	sockdexit(-eval);
#else
	if (config.state.pid == 0 || config.state.pid == getpid())
		exit(eval);
	_exit(eval);
#endif
}

void
#ifdef STDC_HEADERS
serrx(int eval, const char *fmt, ...)
#else
serrx(eval, fmt, va_alist)
      int eval;
      const char *fmt;
      va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;

	if (fmt != NULL) {
#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */
		vslog(LOG_ERR, fmt, ap);

		/* LINTED expression has null effect */
		va_end(ap);
	}

#if SOCKS_SERVER
	sockdexit(-eval);
#else
	if (config.state.pid == 0 || config.state.pid == getpid())
		exit(eval);
	_exit(eval);
#endif
}

void
#ifdef STDC_HEADERS
swarn(const char *fmt, ...)
#else
swarn(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;
	char buf[2048];
	size_t bufused;

	if (fmt != NULL) {
#ifdef STDC_HEADERS
	/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

		bufused = vsnprintf(buf, sizeof(buf), fmt, ap);

		bufused += snprintf(&buf[bufused], sizeof(buf) - bufused,
		": %s (errno = %d)", strerror(errno), errno);

		slog(LOG_ERR, buf);

		/* LINTED expression has null effect */
		va_end(ap);
	}
}

void
#ifdef STDC_HEADERS
swarnx(const char *fmt, ...)
#else
swarnx(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;

	if (fmt != NULL) {
#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

		vslog(LOG_ERR, fmt, ap);

		/* LINTED expression has null effect */
		va_end(ap);
	}
}

in_addr_t
socks_addfakeip(host)
	const char *host;
{
	const char *function = "socks_addfakeip()";
	char **tmpmem;
	struct in_addr addr;

	if (socks_getfakeip(host, &addr) == 1)
		return addr.s_addr;

	if (ipc >= FAKEIP_END - FAKEIP_START) {
		swarnx("%s: fakeip range (%d - %d) exhausted",
		function, FAKEIP_START, FAKEIP_END);
		return INADDR_NONE;
	}

	if ((tmpmem = (char **)realloc(ipv, sizeof(*ipv) * (ipc + 1))) == NULL
	|| (tmpmem[ipc] = (char *)malloc(sizeof(char) * (strlen(host) + 1)))
	== NULL) {
		swarnx("%s: %s", function, NOMEM);
		return INADDR_NONE;
	}
	ipv = tmpmem;

	strcpy(ipv[ipc], host);

	return htonl(ipc++ + FAKEIP_START);
}

const char *
socks_getfakehost(addr)
	in_addr_t addr;
{

	if (ntohl(addr) - FAKEIP_START < ipc)
		return ipv[ntohl(addr) - FAKEIP_START];
	return NULL;
}

int
socks_getfakeip(host, addr)
	const char *host;
	struct in_addr *addr;
{
	unsigned int i;

	for (i = 0; i < ipc; ++i)
		if (strcasecmp(host, ipv[i]) == 0) {
			addr->s_addr = htonl(i + FAKEIP_START);
			return 1;
		}

	return 0;
}


const char *
socks_packet2string(packet, type)
	  const void *packet;
	  int type;
{
	static char buf[1024];
	char hstring[MAXSOCKSHOSTSTRING];
	unsigned char version;
	const struct request_t *request;
	const struct response_t *response;

	switch (type) {
		case SOCKS_REQUEST:
			request = (const struct request_t *)packet;
			version = request->version;
			break;

		case SOCKS_RESPONSE:
			response = (const struct response_t *)packet;
			version = response->version;
			break;

	  default:
		 SERRX(type);
  }

	switch (version) {
		case SOCKS_V4:
		case SOCKS_V4REPLY_VERSION:
			switch (type) {
				case SOCKS_REQUEST:
					snprintf(buf, sizeof(buf),
					"(V4) VN: %d CD: %d address: %s",
					request->version, request->command,
					sockshost2string(&request->host, hstring, sizeof(hstring)));
					break;

				case SOCKS_RESPONSE:
					snprintf(buf, sizeof(buf), "(V4) VN: %d CD: %d address: %s",
					response->version, response->reply,
					sockshost2string(&response->host, hstring, sizeof(hstring)));
					break;
			}
			break;

		case SOCKS_V5:
			switch (type) {
				case SOCKS_REQUEST:
					snprintf(buf, sizeof(buf),
					"VER: %d CMD: %d FLAG: %d ATYP: %d address: %s",
					request->version, request->command, request->flag,
					request->host.atype,
					sockshost2string(&request->host, hstring, sizeof(hstring)));
					break;

				case SOCKS_RESPONSE:
					snprintf(buf, sizeof(buf),
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

int
socks_logmatch(d, log)
	unsigned int d;
	const struct logtype_t *log;
{
	int i;

	for (i = 0; i < log->fpc; ++i)
		if (d == log->fplockv[i])
			return 1;
		else if (d == fileno(log->fpv[i]))
			return 1;

	return 0;
}

int
sockaddrcmp(a, b)
	const struct sockaddr *a;
	const struct sockaddr *b;
{

	if (a->sa_family != b->sa_family)
		return -1;

	switch (a->sa_family) {
		case AF_INET: {
			/* LINTED pointer casts may be troublesome */
			const struct sockaddr_in *in_a = (const struct sockaddr_in *)a;
			/* LINTED pointer casts may be troublesome */
			const struct sockaddr_in *in_b = (const struct sockaddr_in *)b;

			if (in_a->sin_addr.s_addr != in_b->sin_addr.s_addr
			||  in_a->sin_port != in_b->sin_port)
				return -1;
			return 0;
		}

		default:
			SERRX(a->sa_family);
	}

	/* NOTREACHED */
}


fd_set *
fdsetop(nfds, a, b, op)
	int nfds;
	const fd_set *a;
	const fd_set *b;
	int op;
{
	static fd_set result;
	int i;

	FD_ZERO(&result);

	switch (op) {
		case '^':
			for (i = 0; i < nfds; ++i)
				if (FD_ISSET(i, a) != FD_ISSET(i, b))
					FD_SET(i, &result);
			break;

		default:
			SERRX(op);
	}

	return &result;
}

int
methodisset(method, methodv, methodc)
	int method;
	const char *methodv;
	size_t methodc;
{
	if (memchr(methodv, method, methodc) != NULL)
		return 1;
	return 0;
}

int
socketoptdup(s)
	int s;
{
	const char *function = "socketoptdup()";
	unsigned int i;
	int flags, new_s;
	socklen_t len;
	union {
		int					int_val;
		struct linger		linger_val;
		struct timeval		timeval_val;
		struct in_addr		in_addr_val;
		u_char				u_char_val;
		struct sockaddr	sockaddr_val;
		struct ipoption	ipoption;
	} val;
	int levelname[][2] = {

		/* socket options */

#ifdef SO_BROADCAST
		{ SOL_SOCKET,	SO_BROADCAST		},
#endif

#ifdef SO_DEBUG
		{ SOL_SOCKET,	SO_DEBUG				},
#endif

#ifdef SO_DONTROUTE
		{ SOL_SOCKET,	SO_DONTROUTE		},
#endif

#ifdef SO_ERROR
		{ SOL_SOCKET,	SO_ERROR				},
#endif

#ifdef SO_KEEPALIVE
		{ SOL_SOCKET,	SO_KEEPALIVE		},
#endif

#ifdef SO_LINGER
		{ SOL_SOCKET,	SO_LINGER			},
#endif

#ifdef SO_OOBINLINE
		{ SOL_SOCKET,	SO_OOBINLINE		},
#endif

#ifdef SO_RCVBUF
		{ SOL_SOCKET,	SO_RCVBUF			},
#endif

#ifdef SO_SNDBUF
		{ SOL_SOCKET,	SO_SNDBUF			},
#endif

#ifdef SO_RCVLOWAT
		{ SOL_SOCKET,	SO_RCVLOWAT			},
#endif

#ifdef SO_SNDLOWAT
		{ SOL_SOCKET,	SO_SNDLOWAT			},
#endif

#ifdef SO_RCVTIMEO
		{ SOL_SOCKET,	SO_RCVTIMEO			},
#endif

#ifdef SO_SNDTIMEO
		{ SOL_SOCKET,	SO_SNDTIMEO			},
#endif

#ifdef SO_REUSEADDR
		{ SOL_SOCKET,	SO_REUSEADDR		},
#endif

#ifdef SO_REUSEPORT
		{ SOL_SOCKET,	SO_REUSEPORT		},
#endif

#ifdef SO_USELOOPBACK
		{ SOL_SOCKET,	SO_USELOOPBACK		},
#endif

		/* IP options */

#ifdef IP_HDRINCL
		{ IPPROTO_IP,	IP_HDRINCL			},
#endif

#ifdef IP_OPTIONS
		{ IPPROTO_IP,	IP_OPTIONS			},
#endif

#ifdef IP_RECVDSTADDR
		{ IPPROTO_IP,	IP_RECVDSTADDR		},
#endif

#ifdef IP_RECVIF
		{ IPPROTO_IP,	IP_RECVIF			},
#endif

#ifdef IP_TOS
		{ IPPROTO_IP,	IP_TOS				},
#endif

#ifdef IP_TTL
		{ IPPROTO_IP,	IP_TTL				},
#endif

#ifdef IP_MULTICAST_IF
		{ IPPROTO_IP,	IP_MULTICAST_IF	},
#endif

#ifdef IP_MULTICAST_TTL
		{ IPPROTO_IP,	IP_MULTICAST_TTL	},
#endif

#ifdef IP_MULTICAST_LOOP
		{ IPPROTO_IP,	IP_MULTICAST_LOOP	},
#endif

		/* TCP options */

#ifdef TCP_KEEPALIVE
		{ IPPROTO_TCP,	TCP_KEEPALIVE		},
#endif

#ifdef TCP_MAXRT
		{ IPPROTO_TCP,	TCP_MAXRT			},
#endif

#ifdef TCP_MAXSEG
		{ IPPROTO_TCP,	TCP_MAXSEG			},
#endif

#ifdef TCP_NODELAY
		{ IPPROTO_TCP,	TCP_NODELAY			},
#endif

#ifdef TCP_STDURG
		{ IPPROTO_TCP,	TCP_STDURG			}
#endif

	};


	len = sizeof(val);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) == -1)
		return -1;

	if ((new_s = socket(AF_INET, val.int_val, 0)) == -1)
		return -1;

	for (i = 0; i < ELEMENTS(levelname); ++i) {
		len = sizeof(val);
		if (getsockopt(s, levelname[i][0], levelname[i][1], &val, &len) == -1) {
			if (config.option.debug)
				swarn("%s: getsockopt(%d, %d)",
				function, levelname[i][0], levelname[i][1]);
			continue;
		}

		if (setsockopt(new_s, levelname[i][0], levelname[i][1], &val, len) == -1)
			swarn("%s: setsockopt(%d, %d)",
			function, levelname[i][0], levelname[i][1]);
	}

	if ((flags = fcntl(s, F_GETFL, 0)) == -1
	||  fcntl(new_s, F_SETFL, flags) == -1)
		swarn("%s: fcntl()", function);

	return new_s;
}

char *
str2vis(string, len)
	const char *string;
	size_t len;
{
	const int visflag = VIS_TAB | VIS_NL | VIS_CSTYLE | VIS_OCTAL;
	char *visstring;

	/* see vis(3) for "* 4" */
	if ((visstring = (char *)malloc((sizeof(char) * len * 4) + sizeof(char)))
	!= NULL)
		strvisx(visstring, string, len, visflag);

	return visstring;
}

int
socks_mklock(template)
	const char *template;
{
	const char *function = "socks_mklock()";
	char *prefix, *newtemplate;
	int s;
	size_t len;

	if ((prefix = getenv("TMPDIR")) != NULL)
		if (*prefix == NUL)
			prefix = NULL;

	if (prefix == NULL)
		prefix = "/tmp";

	len = strlen(prefix) + strlen("/") + strlen(template) + 1;
	if ((newtemplate = (char *)malloc(sizeof(char) * len)) == NULL)
		return -1;

	snprintf(newtemplate, len, "%s/%s", prefix, template);

	if ((s = mkstemp(newtemplate)) == -1) {
		swarn("%s: mkstemp(%s)", function, newtemplate);
		free(newtemplate);
		return -1;
	}

	if (unlink(newtemplate) == -1) {
		swarn("%s: unlink(%s)", function, newtemplate);
		free(newtemplate);
		return -1;
	}

	free(newtemplate);

	return s;
}


int
socks_lock(descriptor, type, timeout)
	int descriptor;
	int type;
	int timeout;
{
	const char *function = "socks_lock()";
	struct flock lock;
	int rc;

	lock.l_type		= (short)type;
	lock.l_start	= 0;
	lock.l_whence	= SEEK_SET;
	lock.l_len		= 0;

	SASSERTX(timeout <= 0);

#if 0 /* missing some bits here to handle racecondition. */
	if (timeout > 0) {
		struct sigaction sigact;

#if SOCKS_CLIENT
		if (sigaction(SIGALRM, NULL, &sigact) != 0)
			return -1;

		/* if handler already set for signal, don't override. */
		if (sigact.sa_handler == SIG_DFL || sigact.sa_handler == SIG_IGN) {
#else	/* !SOCKS_CLIENT */
		/* CONSTCOND */
		if (1) {
#endif /* !SOCKS_CLIENT */

			sigemptyset(&sigact.sa_mask);
			sigact.sa_flags	= 0;
			sigact.sa_handler = SIG_IGN;

			if (sigaction(SIGALRM, &sigact, NULL) != 0)
				return -1;
		}

		alarm((unsigned int)timeout);
	}
#endif

	do
		rc = fcntl(descriptor, timeout ? F_SETLKW : F_SETLK, &lock);
	while (rc == -1 && timeout == -1 && errno == EINTR);

	if (rc == -1)
		switch (errno) {
			case EACCES:
			case EAGAIN:
			case EINTR:
				break;

			case ENOLCK:
				swarn("%s: fcntl()", function);
				break;

			default:
				SERR(descriptor);
		}

#if 0
	if (timeout > 0)
		alarm(0);
#endif

	return rc == -1 ? rc : 0;
}

int
socks_unlock(descriptor, timeout)
	int descriptor;
	int timeout;
{

	return socks_lock(descriptor, F_UNLCK, timeout);
}


int
socks_socketisbound(s)
	int s;
{
	struct sockaddr_in addr;
	socklen_t len;

	len = sizeof(addr);
	/* LINTED pointer casts may be troublesome */
	if (getsockname(s, (struct sockaddr *)&addr, &len) != 0)
		return -1;

	return ADDRISBOUND(addr);
}

int
freedescriptors(message)
	const char *message;
{
	const int errno_s = errno;
	int i, freed, max;

	/* LINTED expression has null effect */
	for (freed = 0, i = 0, max = getdtablesize(); i < max; ++i)
		if (!fdisopen(i))
			++freed;

	if (message != NULL)
		slog(LOG_DEBUG, "freedescriptors(%s): %d/%d", message, freed, max);

	errno = errno_s;

	return freed;
}

int
fdisopen(fd)
	int fd;
{
	if (fcntl(fd, F_GETFD, 0) == 0)
		return 1;
	return 0;
}

ssize_t
strnlen(s, len)
	const char *s;
	size_t len;
{
	const char *p;

	if ((p = memchr(s, NUL, len)) == NULL)
		return -1;

	return p - s;
}

void
socks_seteuid(old, new)
	uid_t *old;
	uid_t new;
{
	const char *function = "socks_seteuid()";
	uid_t oldmem;

	if (old == NULL)
		old = &oldmem;

	if ((*old = geteuid()) == new)
		return;

#if !SOCKS_DEBUGER
	if (seteuid(new) != 0)
		serr(EXIT_FAILURE, "%s: seteuid(%d)", function, new);
#endif
}

void
socks_reseteuid(uid)
	uid_t uid;
{

#if !SOCKS_DEBUGER
	if (seteuid(uid) != 0)
		SERR(uid);
#endif
}

#if SOCKS_DEBUGER
int
setuid(uid)
	uid_t uid;
{
	return 0;
};
#endif /* SOCKS_DEBUGER */


void
closev(array, count)
	int *array;
	int count;
{

	for (--count; count >= 0; --count)
		if (array[count] >= 0)
			if (close(array[count]) != 0)
				SERR(-1);
}
