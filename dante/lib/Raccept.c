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

static const char rcsid[] =
"$Id: Raccept.c,v 1.48 1998/12/07 18:43:04 michaels Exp $";

#include "common.h"

int
Raccept(s, addr, addrlen)
	int s;
	struct sockaddr *addr;
	socklen_t *addrlen;
{
	const char *function = "Raccept()";
	struct socks_t packet;
	struct socksfd_t *socksfd;
	fd_set rset;
	int fdbits, p, iotype, remote;

	/* can't call Raccept() on unknown descriptors. */
	if (!socks_addrisok((unsigned int)s)) {
		socks_rmaddr((unsigned int)s);
		return accept(s, addr, addrlen);
	}

	socksfd = socks_getaddr((unsigned int)s);
	SASSERTX(socksfd != NULL);

	bzero(&packet, sizeof(packet));
	packet.version = (unsigned char)socksfd->state.version;

	if ((iotype = fcntl(s, F_GETFL, 0)) == -1)
		return -1;

#ifdef SOCKS_TRYHARDER
	/* 
	 * Perhaps overkill, but try to be as compatible as possible. 
	 * BSD supports multiple process' calling accept(2) on
	 * the same descriptor, try to support that functionality by locking
	 * the socksfd object ourself in this function, so another process
	 * calling Raccept() on this object will fail.
	*/

	if (iotype & NONBLOCKING)
		p = socks_lock(socksfd->state.lock, F_WRLCK, 0);
	else
		p = socks_lock(socksfd->state.lock, F_WRLCK, -1);

	if (p != 0)
		return -1;
#endif /* SOCKS_TRYHARDER */

	FD_ZERO(&rset);
	fdbits = -1;

	/* check socket we listen on because we support ordinary connects. */
	FD_SET(s, &rset);
	fdbits = MAX(fdbits, s);
	
	/* connection to server, for forwarded connections or errors. */
	FD_SET(socksfd->s, &rset);
	fdbits = MAX(fdbits, socksfd->s);

	SASSERTX(fdbits >= 0);

	++fdbits;
	
	if (iotype & NONBLOCKING) {
		struct timeval timeout;

		timeout.tv_sec 	= 0;
		timeout.tv_usec	= 0;

		if ((p = select(fdbits, &rset, NULL, NULL, &timeout)) == 0) {
			errno = EWOULDBLOCK;
			p = -1;
		}
	}
	else
		p = select(fdbits, &rset, NULL, NULL, NULL);

	if (p == -1) {
#ifdef SOCKS_TRYHARDER
		if (socks_unlock(socksfd->state.lock, -1) != 0)
			return -1;
#endif /* SOCKS_TRYHARDER */
		return -1;
	}

	SASSERTX(p > 0);

	if (FD_ISSET(s, &rset)) { /* a pending connection. */
		int len;

		len = sizeof(socksfd->accepted);
		if ((remote = accept(s, &socksfd->accepted, &len)) == -1) {
#ifdef SOCKS_TRYHARDER
			socks_unlock(socksfd->state.lock, -1);
#endif /* SOCKS_TRYHARDER */
			return -1;
		}

		/* this is a separate socket and it has it's own remote address. */
		socksfd = socks_addaddr((unsigned int)remote, socksfd);
		
		/* it will have a different local address if INADDR_ANY was bound. */
		len = sizeof(socksfd->local);
		if (getsockname(remote, &socksfd->local, &len) != 0)
			swarn("%s: getsockname(remote)", function);

		if (socksfd->state.acceptpending) {
			/*
			 * accepted a connection forwarded by socksserver or a ordinary
			 * connect?
			*/
			/* LINTED pointer casts may be troublesome */
			if (((struct sockaddr_in *)&socksfd->reply)->sin_addr.s_addr
			==  ((struct sockaddr_in *)&socksfd->remote)->sin_addr.s_addr) {
				/* matches socksservers ip address, could be forwarded; ask. */

				packet.req.version	= (char)socksfd->state.version;
				packet.req.command  	= SOCKS_BIND;
				packet.req.flag		= 0;
				sockaddr2sockshost(&socksfd->accepted, &packet.req.host);
				packet.req.auth		= &socksfd->state.auth;
	 
				if (socks_sendrequest(socksfd->s, &packet.req) != 0)
					return -1;

				if (socks_recvresponse(socksfd->s, &packet.res, packet.req.version)
				!= 0)
					return -1;

				if (packet.res.host.atype != SOCKS_ADDR_IPV4) {
					swarnx("%s: unexpected atype in bindquery response from "
					"server: %d",
					function, packet.res.host.atype);
					return -1;
				}

				if (packet.res.host.addr.ipv4.s_addr != htonl(INADDR_ANY))
					/* forwarded from socksserver. */
					sockshost2sockaddr(&packet.res.host, &socksfd->accepted);

				/* else; ordinary connect. */
			}
		}
		/* else; not bind extension, must be a ordinary connect. */
	}
	else { /* no pending connection, server wants to forward to us then. */
		SASSERTX(FD_ISSET(socksfd->s, &rset));

		if (socks_recvresponse(socksfd->s, &packet.res, packet.version) != 0)
			return -1;
		sockshost2sockaddr(&packet.res.host, &socksfd->accepted);
		remote = socksfd->s;
	}

#ifdef SOCKS_TRYHARDER
	if (socks_unlock(socksfd->state.lock, 0) != 0)
		return -1;
#endif

	if (addr != NULL) {
		*addrlen = MIN(*addrlen, sizeof(socksfd->accepted));
		memcpy(addr, &socksfd->accepted, (size_t)*addrlen);
	}

	return remote;
}
