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
 *  N-0371 Oslo
 *  Norway
 * 
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

static const char rcsid[] =
"$Id: Rconnect.c,v 1.90 1999/03/11 16:59:31 karls Exp $";

#include "common.h"

int
Rconnect(s, name, namelen)
	int s;
#ifdef HAVE_FAULTY_CONNECTPROTO
	struct sockaddr *name;
#else
	const struct sockaddr *name;
#endif  /* HAVE_FAULTY_CONNECTPROTO */
	socklen_t namelen;
{
	struct sockshost_t src, dst;
	struct socksfd_t socksfd;
	struct socks_t packet;
	socklen_t len;
	int type, p;

	if (name->sa_family != AF_INET)
		return connect(s, name, namelen);

	if (socks_addrisok((unsigned int)s)) {
		struct socksfd_t *socksfdp;

		socksfdp = socks_getaddr((unsigned int)s);

		switch (socksfdp->state.command) {
			case SOCKS_BIND:
				/*
				 * Our guess; the client has succeeded to bind to a specific
				 * address and is now trying to connect out from it.
				 * That also indicates the socksserver is listening on a port 
				 * for this client.  Can't accept() on a connected socket so
				 * lets close the connection to the server so it can stop
				 * listening on our behalf and we continue as if this was an
				 * ordinary connect().  Can only hope the server will use
				 * same port as we for connecting out.
				*/
				socks_rmaddr((unsigned int)s);  
				break;

			case SOCKS_CONNECT:
				if (socksfdp->state.inprogress)
					if (socksfdp->state.err != 0) /* connect failed. */
						errno = socksfdp->state.err;
					else
						errno = EALREADY;
				else
					errno = EISCONN;	/* can't connect tcpsocket twice */

				return -1;
			
			case SOCKS_UDPASSOCIATE:
				/* 
				 * Trying to connect a udp socket again?  ok, delete old
				 * socksfd and continue as usual.
				*/
				socks_rmaddr((unsigned int)s);  
				break;

			default:
				SERRX(socksfdp->state.command);
		}
	}
	else {
		bzero(&socksfd, sizeof(socksfd));
		socks_rmaddr((unsigned int)s);
	}

	len = sizeof(type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
		return -1;

	switch (type) {
		case SOCK_DGRAM: {
			struct socksfd_t *socksfdp;

			if (udpsetup(s, name, SOCKS_SEND) == 0) {
				socksfdp = socks_getaddr((unsigned int)s);
				SASSERTX(socksfdp != NULL);

				if (connect(s, &socksfdp->reply, sizeof(socksfdp->reply)) != 0) {
					socks_rmaddr((unsigned int)s);
					return -1;
				}
					
				socksfdp->state.udpconnect		= 1;
				socksfdp->connected 				= *name;

				return 0;
			}
			else {
				if (errno == 0)
					/* not a network error, try standard connect. */
					return connect(s, name, namelen);
				else
					return -1;
			}
		}
	}


	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0)
		return -1;

	src.atype		= SOCKS_ADDR_IPV4;
	/* LINTED pointer casts may be troublesome */
	src.addr.ipv4	= ((const struct sockaddr_in *)&socksfd.local)->sin_addr;
	/* LINTED pointer casts may be troublesome */
	src.port			= ((const struct sockaddr_in *)&socksfd.local)->sin_port;

	/* LINTED pointer casts may be troublesome */
	if (socks_getfakehost(((const struct sockaddr_in *)name)->sin_addr.s_addr) 
	!= NULL) {
		const char *ipname
		/* LINTED pointer casts may be troublesome */
		= socks_getfakehost(((const struct sockaddr_in *)name)->sin_addr.s_addr);

		SASSERTX(ipname != NULL);
		SASSERTX(strlen(ipname) < sizeof(dst.addr.domain));

		dst.atype = SOCKS_ADDR_DOMAIN;
		strcpy(dst.addr.domain, ipname);
	}
	else {
		dst.atype		= SOCKS_ADDR_IPV4;
		/* LINTED pointer casts may be troublesome */
		dst.addr.ipv4	= ((const struct sockaddr_in *)name)->sin_addr;
	}
	/* LINTED pointer casts may be troublesome */
	dst.port	= ((const struct sockaddr_in *)name)->sin_port;

	bzero(&packet, sizeof(packet));
	packet.req.host 		= dst;
	packet.req.version 	= SOCKS_V5;
	packet.req.command 	= SOCKS_CONNECT;

	if (socks_requestpolish(&packet.req, &src, &dst) == NULL)
		return connect(s, name, namelen);

	switch (packet.req.version) {
		case SOCKS_V4:
		case SOCKS_V5:
			socksfd.control = s;	
			break;

		case MSPROXY_V2:
			/* needs a separate controlchannel always. */
			if ((socksfd.control = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
				return -1;
			break;
			
		default:
			SERRX(packet.req.version);
	}

	if ((p = fcntl(s, F_GETFL, 0)) == -1)
		return -1;

	if (p & NONBLOCKING) {
		if ((socksfd.route = socks_nbconnectroute(s, socksfd.control, &packet,
		&src, &dst)) == NULL) {
			if (s != socksfd.control)
				close(socksfd.control);
			return errno == 0 ? connect(s, name, namelen) : -1;
		}

		return -1; /* got route, non-blocking connect in progress. */
	}
	else
		/* LINTED pointer casts may be troublesome */
		if ((socksfd.route
		= socks_connectroute(socksfd.control, &packet, &src, &dst)) == NULL) {
			if (s != socksfd.control)
				close(socksfd.control);

			return errno == 0 ? connect(s, name, namelen) : -1;
		}

	if (socks_negotiate(s, socksfd.control, &packet) != 0)
		return -1;

	socksfd.state.auth 				= packet.auth;
	socksfd.state.command 			= packet.req.command;
	socksfd.state.version 			= packet.req.version;
	socksfd.state.protocol.tcp		= 1;
	socksfd.state.msproxy			= packet.state.msproxy;
	sockshost2sockaddr(&packet.res.host, &socksfd.remote);
	socksfd.connected 				= *name;

	/* LINTED pointer casts may be troublesome */
	if (((struct sockaddr_in *)&socksfd.local)->sin_port != htons(0)
	&&  ((struct sockaddr_in *)&socksfd.local)->sin_port != 
		 ((struct sockaddr_in *)&socksfd.remote)->sin_port) {
		/*
		 * unfortunate; the client is trying to connect from a specific
		 * port, a port it has successfully bound, but the port is currently
		 * in use on the serverside.
		*/

		/* LINTED pointer casts may be troublesome */
		slog(LOG_DEBUG, "failed to get wanted port: %d", 
		ntohs(((struct sockaddr_in *)&socksfd.local)->sin_port));
	}

	len = sizeof(socksfd.server);
	if (getpeername(s, &socksfd.server, &len) != 0) {
		if (s != socksfd.control)
			close(socksfd.control);
		return -1;
	}

	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0) {
		if (s != socksfd.control)
			close(socksfd.control);
		return -1;
	}

	socks_addaddr((unsigned int)s, &socksfd);
	
	config.state.lastconnect = *name;	/* needed for standard socks bind. */

	return 0;
}
