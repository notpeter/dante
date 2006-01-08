/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004
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

static const char rcsid[] =
"$Id: clientprotocol.c,v 1.51 2005/12/28 18:22:41 michaels Exp $";

static int
recv_sockshost __P((int s, struct sockshost_t *host, int version,
						  struct authmethod_t *auth));
/*
 * Fills "host" based on data read from "s".  "version" is the version
 * the remote peer is expected to send data in.
 *
 * Returns:
 *		On success: 0
 *		On failure: -1
 */


int
socks_sendrequest(s, request)
	int s;
	const struct request_t *request;
{
	const char *function = "socks_sendrequest()";
	unsigned char requestmem[sizeof(*request)];
	unsigned char *p = requestmem;

	switch (request->version) {
		case SOCKS_V4:
			/*
			 * VN   CD  DSTPORT DSTIP USERID   0
			 *  1 + 1  +   2   +  4  +  ?    + 1  = 9 + USERID
			 */

			/* VN */
			memcpy(p, &request->version, sizeof(request->version));
			p += sizeof(request->version);

			/* CD */
			memcpy(p, &request->command, sizeof(request->command));
			p += sizeof(request->command);

			p = sockshost2mem(&request->host, p, request->version);

			*p++ = 0; /* not bothering to send any userid.  Should we? */

			break; /* SOCKS_V4 */

		 case SOCKS_V5:
			/*
			 * rfc1928 request:
			 *
			 *	+----+-----+-------+------+----------+----------+
			 *	|VER | CMD |  FLAG | ATYP | DST.ADDR | DST.PORT |
			 *	+----+-----+-------+------+----------+----------+
			 *	| 1  |  1  |   1   |  1   | Variable |    2     |
			 *	+----+-----+-------+------+----------+----------+
			 *	  1	   1     1      1       > 0         2
			 *
			 *	Which gives a fixed size of minimum 7 octets.
			 *	The first octet of DST.ADDR when it is SOCKS_ADDR_DOMAINNAME
			 *	contains the length of DST.ADDR.
			 */

			/* VER */
			memcpy(p, &request->version, sizeof(request->version));
			p += sizeof(request->version);

			/* CMD */
			memcpy(p, &request->command, sizeof(request->command));
			p += sizeof(request->command);

			/* FLAG */
			memcpy(p, &request->flag, sizeof(request->flag));
			p += sizeof(request->flag);

			p = sockshost2mem(&request->host, p, request->version);

			break;

		 default:
			SERRX(request->version);
	}

	slog(LOG_DEBUG, "%s: sending request: %s",
	function, socks_packet2string(request, SOCKS_REQUEST));

	/*
	 * Send the request to the server.
	 */
	if (writen(s, requestmem, (size_t)(p - requestmem), request->auth)
	!= p - requestmem) {
		swarn("%s: writen()", function);
		return -1;
	}

	return 0;
}

int
socks_recvresponse(s, response, version)
	int s;
	struct response_t	*response;
	int version;
{
	const char *function = "socks_recvresponse()";

	/* get the versionspecific data. */
	switch (version) {
		case SOCKS_V4: {
			/*
			 * The socks V4 reply length is fixed:
			 * VN   CD  DSTPORT  DSTIP
			 *  1 + 1  +   2   +   4
			 */
			char responsemem[ sizeof(response->version)
								 + sizeof(response->reply)
								 ];
			char *p = responsemem;

			if (readn(s, responsemem, sizeof(responsemem), response->auth)
			!= sizeof(responsemem)) {
				swarn("%s: readn()", function);
				return -1;
			}

			/* VN */
			memcpy(&response->version, p, sizeof(response->version));
			p += sizeof(response->version);
			if (response->version != SOCKS_V4REPLY_VERSION) {
				swarnx("%s: unexpected version from server (%d != %d)",
				function, response->version, SOCKS_V4REPLY_VERSION);
				return -1;
			}

			/* CD */
			memcpy(&response->reply, p, sizeof(response->reply));
			p += sizeof(response->reply);
			break;
		}

		case SOCKS_V5: {
			/*
			 * rfc1928 reply:
			 *
			 * +----+-----+-------+------+----------+----------+
			 * |VER | REP |  FLAG | ATYP | BND.ADDR | BND.PORT |
			 * +----+-----+-------+------+----------+----------+
			 * | 1  |  1  |   1   |  1   |  > 0     |    2     |
			 * +----+-----+-------+------+----------+----------+
			 *
			 *	Which gives a size of >= 7 octets.
			 *
			 */
			char responsemem[sizeof(response->version)
								+ sizeof(response->reply)
								+ sizeof(response->flag)
								];
			char *p = responsemem;

			if (readn(s, responsemem, sizeof(responsemem), response->auth)
			!= sizeof(responsemem)) {
				swarn("%s: readn()", function);
				return -1;
			}

			/* VER */
			memcpy(&response->version, p, sizeof(response->version));
			p += sizeof(response->version);
			if (version != response->version) {
				swarnx("%s: unexpected version from server (%d != %d)",
				function, version, response->version);
				return -1;
			}

			/* REP */
			memcpy(&response->reply, p, sizeof(response->reply));
			p += sizeof(response->reply);

			/* FLAG */
			memcpy(&response->flag, p, sizeof(response->flag));
			p += sizeof(response->flag);

			break;
		}

		default:
			SERRX(version);
	}

	if (recv_sockshost(s, &response->host, version, response->auth) != 0)
		return -1;

	slog(LOG_DEBUG, "%s: received response: %s",
	function, socks_packet2string(response, SOCKS_RESPONSE));

	return 0;
}


/* ARGSUSED */
int
socks_negotiate(s, control, packet, route)
	int s;
	int control;
	struct socks_t	*packet;
	struct route_t *route;
{

	switch (packet->req.version) {
		case SOCKS_V5:
			if (negotiate_method(control, packet) != 0)
				return -1;
			/* FALLTHROUGH */ /* rest is like v4, which doesn't have method. */

		case SOCKS_V4:
			packet->req.auth = &packet->auth;
			packet->res.auth = &packet->auth;

			if (socks_sendrequest(control, &packet->req) != 0)
				return -1;

			if (socks_recvresponse(control, &packet->res, packet->req.version)
			!= 0)
				return -1;
			break;

#if SOCKS_CLIENT
		case MSPROXY_V2:
			if (msproxy_negotiate(s, control, packet) != 0)
				return -1;
			break;
#endif

		case HTTP_V1_0:
			if (httpproxy_negotiate(control, packet) != 0)
				return -1;
			break;

		default:
			SERRX(packet->req.version);
	}

	if (!serverreplyisok(packet->res.version, packet->res.reply, route))
		return -1;
	return 0;
}


static int
recv_sockshost(s, host, version, auth)
	int s;
	struct sockshost_t *host;
	int version;
	struct authmethod_t *auth;
{
	const char *function = "recv_sockshost()";

	switch (version) {
		case SOCKS_V4: 
		case SOCKS_V4REPLY_VERSION: {
			/*
			 * DSTPORT  DSTIP
			 *   2    +   4
			 */
			char hostmem[ sizeof(host->port)
						   + sizeof(host->addr.ipv4)
							];
			char *p = hostmem;

			if (readn(s, hostmem, sizeof(hostmem), auth) != sizeof(hostmem)) {
				swarn("%s: readn()", function);
				return -1;
			}

			host->atype = SOCKS_ADDR_IPV4;

			/* BND.PORT */
			memcpy(&host->port, p, sizeof(host->port));
			p += sizeof(host->port);

			/* BND.ADDR */
			memcpy(&host->addr.ipv4, p, sizeof(host->addr.ipv4));
			p += sizeof(host->addr.ipv4);

			break;
		}

		case SOCKS_V5:
			/*
			 * +------+----------+----------+
			 * | ATYP | BND.ADDR | BND.PORT |
			 * +------+----------+----------+
			 * |  1   |  > 0     |    2     |
			 * +------+----------+----------+
			 */

			/* ATYP */
			if (readn(s, &host->atype, sizeof(host->atype), auth)
			!= sizeof(host->atype))
				return -1;

			switch(host->atype) {
				case SOCKS_ADDR_IPV4:
					if (readn(s, &host->addr.ipv4, sizeof(host->addr.ipv4), auth)
					!= sizeof(host->addr.ipv4)) {
						swarn("%s: readn()", function);
						return -1;
					}
					break;

				case SOCKS_ADDR_IPV6:
					if (readn(s, host->addr.ipv6, sizeof(host->addr.ipv6), auth)
					!= sizeof(host->addr.ipv6)) {
						swarn("%s: readn()", function);
						return -1;
					}
					break;

				case SOCKS_ADDR_DOMAIN: {
					unsigned char alen;

					/* read length of domainname. */
					if (readn(s, &alen, sizeof(alen), auth) < (ssize_t)sizeof(alen))
						return -1;

					OCTETIFY(alen);

#if MAXHOSTNAMELEN < 0xff
					SASSERTX(alen < sizeof(host->addr.domain));
#endif

					/* BND.ADDR, alen octets */
					if (readn(s, host->addr.domain, (size_t)alen, auth)
					!= (ssize_t)alen) {
						swarn("%s: readn()", function);
						return -1;
					}
					host->addr.domain[alen] = NUL;

					break;
				}

				default:
					swarnx("%s: unsupported address format %d in reply",
					function, host->atype);
					return -1;
			}

			/* BND.PORT */
			if (readn(s, &host->port, sizeof(host->port), auth)
			!= sizeof(host->port))
				return -1;
			break;
	}

	return 0;
}


int
serverreplyisok(version, reply, route)
	int version;
	int reply;
	struct route_t *route;
{
	const char *function = "serverreplyisok()";

	slog(LOG_DEBUG, "%s: version %d, reply %d", function, version, reply);

	switch (version) {
		case SOCKS_V4REPLY_VERSION:
			switch (reply) {
				case SOCKSV4_SUCCESS:
					return 1;

				case SOCKSV4_FAIL:
					errno = ECONNREFUSED;
					break;

				case SOCKSV4_NO_IDENTD:
					swarnx("%s: proxyserver failed to get your identd response",
					function);
					errno = ECONNREFUSED;
					return 0;

				case SOCKSV4_BAD_ID:
					swarnx("%s: proxyserver claims username/ident mismatch",
					function);
					errno = ECONNREFUSED;
					return 0;

				default:
					swarnx("%s: unknown v%d reply from proxyserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					break;
			}
			break;

		case SOCKS_V5:
			switch (reply) {
				case SOCKS_SUCCESS:
					return 1;

				case SOCKS_FAILURE:
					swarnx("%s: unknown proxyserver failure", function);
					errno = ECONNREFUSED;
					break;

				case SOCKS_NOTALLOWED:
					swarnx("%s: connection denied by proxyserver", function);
					errno = ECONNREFUSED;
					return 0;

				case SOCKS_NETUNREACH:
					errno = ENETUNREACH;
					return 0;

				case SOCKS_HOSTUNREACH:
					errno = EHOSTUNREACH;
					return 0;

				case SOCKS_CONNREFUSED:
					errno = ECONNREFUSED;
					return 0;

				case SOCKS_TTLEXPIRED:
					errno = ETIMEDOUT;
					return 0;

				case SOCKS_CMD_UNSUPP:
					swarnx("%s: command not supported by proxyserver", function);
					errno = ECONNREFUSED;
					break;

				case SOCKS_ADDR_UNSUPP:
					swarnx("%s: address type not supported by proxyserver",
					function);
					errno = ECONNREFUSED;
					break;

				default:
					swarnx("%s: unknown v%d reply from proxyserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					break;
			}
			break;

		case MSPROXY_V2:
			switch (reply) {
				case MSPROXY_SUCCESS:
					return 1;

				case MSPROXY_FAILURE:
				case MSPROXY_CONNREFUSED:
					errno = ECONNREFUSED;
					return 0;

				case MSPROXY_NOTALLOWED:
					swarnx("%s: connection denied by proxyserver: authenticated?",
					function);
					errno = ECONNREFUSED;
					return 0;

				default:
					swarnx("%s: unknown v%d reply from proxyserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					return 0;
			}

		case HTTP_V1_0:
			switch (reply) {
				case HTTP_SUCCESS:
					return 1;

				default:
					errno = ECONNREFUSED;
					return 0;
			}
			/* NOTREACHED */
			break;

		default:
			SERRX(version);
	}

	if (route != NULL)
		socks_badroute(route);

	return 0;
}

/* ARGSUSED */
int
clientmethod_uname(s, host, version, name, password)
	int s;
	const struct sockshost_t *host;
	int version;
	unsigned char *name, *password;
{
	const char *function = "clientmethod_uname()";
	static struct authmethod_uname_t uname;	/* cached userinfo.					*/
#if SOCKS_CLIENT
	static struct sockshost_t unamehost;		/* host cache was gotten for.		*/
#endif
	static int unameisok;							/* cached data is ok?				*/
	unsigned char *offset;
	unsigned char request[ 1					/* version.				*/
								+ 1					/* username length.	*/
								+ MAXNAMELEN		/* username.			*/
								+ 1					/* password length.	*/
								+ MAXPWLEN			/* password.			*/
	];
	unsigned char response[ 1 /* version.	*/
								 +	1 /* status.	*/
	];


	switch (version) {
		case SOCKS_V5:
			break;

		default:
			SERRX(version);
	}

#if SOCKS_CLIENT
	if (memcmp(&unamehost, host, sizeof(unamehost)) != 0)
		unameisok = 0;	/* not same host as cache was gotten for. */
#endif


	/* fill in request. */

	offset = request;
	*offset++ = (unsigned char)SOCKS_UNAMEVERSION;

	if (!unameisok) {
#if SOCKS_CLIENT
		if (name == NULL
		&& (name = (unsigned char *)socks_getusername(host, (char *)offset + 1,
		MAXNAMELEN)) == NULL) {
			swarn("%s: could not determine username of client", function);
			return -1;
		}
#endif
		SASSERTX(strlen((char *)name) < sizeof(uname.name));
		strcpy((char *)uname.name, (char *)name);
	}
	else
		name = uname.name;

	/* first byte gives length. */
	*offset = (unsigned char)strlen((char *)name);
	OCTETIFY(*offset);
	strcpy((char *)offset + 1, (char *)name);
	offset += *offset + 1;

	if (!unameisok) {
#if SOCKS_CLIENT
		if (password == NULL
		&& (password = (unsigned char *)socks_getpassword(host, (char *)name,
		(char *)offset + 1, MAXPWLEN)) == NULL) {
			swarn("%s: could not determine password of client", function);
			return -1;
		}
#endif
		SASSERTX(strlen((char *)password) < sizeof(uname.password));
		strcpy((char *)uname.password, (char *)password);
	}
	else
		password = uname.password;

	/* first byte gives length. */
	*offset = (unsigned char)strlen((char *)password);
	OCTETIFY(*offset);
	strcpy((char *)offset + 1, (char *)password);
	offset += *offset + 1;

	if (writen(s, request, (size_t)(offset - request), NULL)
	!= offset - request) {
		swarn("%s: writen()", function);
		return -1;
	}

	if (readn(s, response, sizeof(response), NULL) != sizeof(response)) {
		swarn("%s: readn()", function);
		return -1;
	}

	if (request[UNAME_VERSION] != response[UNAME_VERSION]) {
		swarnx("%s: sent v%d, got v%d",
		function, request[UNAME_VERSION], response[UNAME_VERSION]);
		return -1;
	}

	if (response[UNAME_STATUS] == 0) { /* server accepted. */
#if SOCKS_CLIENT
		unamehost = *host;
		unameisok = 1;
#endif
	}

	return response[UNAME_STATUS];
}
