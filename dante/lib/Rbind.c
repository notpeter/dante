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
"$Id: Rbind.c,v 1.84 1999/03/11 16:59:30 karls Exp $";

#include "common.h"

int
Rbind(s, name, namelen)
	int s;
#ifdef HAVE_FAULTY_BINDPROTO
	struct sockaddr *name;
#else
	const struct sockaddr *name;
#endif  /* HAVE_FAULTY_BINDPROTO */
	socklen_t namelen;
{
	struct socks_t packet;
	struct socksfd_t socksfd;
	int type;
	socklen_t len;

	/*
	 * Nothing can be called before Rbind(), delete any old cruft.
	*/
	socks_rmaddr((unsigned int)s);

	if (name->sa_family != AF_INET)
		return bind(s, name, namelen);

	if (bind(s, name, namelen) != 0) {
		switch (errno) {
			case EADDRNOTAVAIL: {
				/* LINTED pointer casts may be troublesome */
				struct sockaddr_in newname = *(const struct sockaddr_in *)name;

				/* 
				 * We try to make the client think it's address is the address
				 * the server is using on it's behalf.  Some clients might try
				 * bind that ip address (with a different port, presumably)
				 * themselves though, in that case, use INADDR_ANY.
				 */
				
				newname.sin_addr.s_addr = htonl(INADDR_ANY);
				/* LINTED pointer casts may be troublesome */
				if (bind(s, (struct sockaddr *)&newname, sizeof(newname)) != 0)
					return -1;
				break;
			}
			
			case EINVAL: 
				/*
				 * Somehow the socket has been bound locally already.
				 * Best guess is probably to keep that and attempt a
				 * remote server binding aswell.
				*/
				break;

			default:
				return -1;
		}
	}
				
	len = sizeof(type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
		return -1;

	switch (type) {
		case SOCK_DGRAM: {
			/*
			 * bad; protocol does not support binding udp sockets.
			*/
			slog(LOG_DEBUG,
				  "binding UDP sockets is not supported by socks protocol.\n"
				  "Contact Inferno Nettverk A/S for more information.");
			errno = EPROTOTYPE;
			return -1;
#if 0
			/* LINTED pointer casts may be troublesome */
			if (udpconnect((unsigned int)s, name, SOCKS_RECV) != 0)
				return -1;

			bzero(&to, sizeof(to));
			to.sin_family 			= AF_INET;
			to.sin_addr.s_addr	= htonl(0);
			to.sin_port 			= htons(0);
			
			/* LINTED pointer casts may be troublesome */
			if ((s = Rsendto(s, NULL, 0, 0, (struct sockaddr *)&to, sizeof(to)))
			!= 0)
				return -1;
			return 0;
#endif				
		}
	}

	bzero(&socksfd, sizeof(socksfd));

	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0) {
		close(socksfd.control);
		return -1;
	}

	bzero(&packet, sizeof(packet));
	packet.req.version  					= SOCKS_V5;
	packet.req.command 					= SOCKS_BIND;
	/* try to get a server that supports our bindextension. */
	packet.req.host.atype 				= SOCKS_ADDR_IPV4;
	packet.req.host.addr.ipv4.s_addr = htonl(0);
	/* LINTED pointer casts may be troublesome */
	packet.req.host.port 				=
	((struct sockaddr_in *)&socksfd.local)->sin_port;

	if (socks_requestpolish(&packet.req, NULL, NULL) == NULL)
		return 0;	/* socket bound, assume ok. */

	switch (packet.req.version) {
		case SOCKS_V4:
		case SOCKS_V5:
			if ((socksfd.control = socketoptdup(s)) == -1)
				return -1;

			if (PORTRESERVED(packet.req.host.port)) {
				struct sockaddr_in controladdr;
				
				/* 
				 * Our caller has gotten a reserved port.  It is possible the 
				 * server will differentiate between requests coming from 
				 * privileged ports and those not so try to connect to server
				 * from a privileged port.
				*/

				bzero(&controladdr, sizeof(controladdr));
				controladdr.sin_family			= AF_INET;
				controladdr.sin_addr.s_addr 	= htonl(INADDR_ANY);
				controladdr.sin_port				= htons(0);

				if (bindresvport(socksfd.control, &controladdr) == -1) {
					close(socksfd.control);
					return -1;
				}
			}

			break;

		case MSPROXY_V2:
			if ((socksfd.control = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
				return -1;
			break;
			
		default:
			SERRX(packet.req.version);
	}


	if ((socksfd.route
	= socks_connectroute(socksfd.control, &packet, NULL, NULL)) == NULL) {
		close(socksfd.control);
		return 0;	/* have done a normal bind and no route, assume local. */
	}

	if (socks_negotiate(s, socksfd.control, &packet) != 0) {
		close(socksfd.control);
		return -1;
	}

	socksfd.state.auth 				= packet.auth;
	socksfd.state.command			= SOCKS_BIND;
	socksfd.state.protocol.tcp		= 1;
	socksfd.state.version			= packet.req.version;
	sockshost2sockaddr(&packet.res.host, &socksfd.remote);
	switch (packet.req.version) {
		case SOCKS_V4:
		case SOCKS_V5:
			socksfd.reply						= socksfd.remote;	/* same ip address. */
			socksfd.state.acceptpending	= socksfd.route->gw.state.extension.bind;
			break;

		case MSPROXY_V2:
			socksfd.state.acceptpending 	= 1; /* separate data connection. */
			socksfd.state.msproxy			= packet.state.msproxy;
			/* don't know what address connection will be forwarded from. */
			break;

		default:
			SERRX(packet.req.version);
	}

	/* did we get the requested port? */
	/* LINTED pointer casts may be troublesome */
	if (((struct sockaddr_in *)name)->sin_port != htons(0)
	&& ((struct sockaddr_in *)name)->sin_port
	!= ((struct sockaddr_in *)&socksfd.remote)->sin_port) { /* no. */
		/*
		 * Since the socket is already bound locally, "unbind" it so caller
		 * doesn't get confused.
		*/
		int new_s;

		close(socksfd.control);
		if ((new_s = socketoptdup(s)) == -1)
			return -1;
		dup2(new_s, s);
		close(new_s);
		errno = EADDRINUSE;
		return -1;
	}

	len = sizeof(socksfd.server);
	if (getpeername(socksfd.control, &socksfd.server, &len) != 0) {
		close(socksfd.control);
		return -1;
	}

	switch (socksfd.state.version) {
		case SOCKS_V4:
		case SOCKS_V5:
			socks_addaddr((unsigned int)s, &socksfd);
			break;

		case MSPROXY_V2:
			/* more talk will have to occur before we can perform a accept(). */
			socksfd.state.inprogress = 1;

			socks_addaddr((unsigned int)s, &socksfd);
			if (msproxy_sigio(s) != 0) {
				socks_rmaddr((unsigned int)s);
				return -1;
			}

			break;

		default:
			SERRX(socksfd.state.version);
	}

	return 0;
}
