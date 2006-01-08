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
"$Id: udp.c,v 1.132 2005/10/11 13:17:13 michaels Exp $";

/* ARGSUSED */
ssize_t
Rsendto(s, msg, len, flags, to, tolen)
	int s;
	const void *msg;
	size_t len;
	int flags;
	const struct sockaddr *to;
	socklen_t tolen;
{
	const char *function = "Rsendto()";
	struct socksfd_t *socksfd;
	struct sockshost_t host;
	char srcstring[MAXSOCKADDRSTRING], dststring[sizeof(srcstring)];
	char *nmsg;
	size_t nlen;
	ssize_t n;

	clientinit();

	if (to != NULL && to->sa_family != AF_INET) {
		slog(LOG_DEBUG,
		"%s: unsupported address family '%d', fallback to system sendto()",
		function, to->sa_family);
		return sendto(s, msg, len, flags, to, tolen);
	}

	if (udpsetup(s, to, SOCKS_SEND) != 0)
		return errno == 0 ? sendto(s, msg, len, flags, to, tolen) : -1;

	socksfd = socks_getaddr((unsigned int)s);
	SASSERTX(socksfd != NULL);

	if (to == NULL)
		if (socksfd->state.udpconnect)
			to = &socksfd->forus.connected;
		else { /* tcp. */
			n =  sendto(s, msg, len, flags, NULL, 0);

			slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
			function, protocol2string(SOCKS_TCP),
			sockaddr2string(&socksfd->local, dststring, sizeof(dststring)),
			sockaddr2string(&socksfd->server, srcstring, sizeof(srcstring)),
			(unsigned long)n);

			return n;
		}

	/* prefix a UDP header to the msg */
	nlen = len;
	/* LINTED warning: cast discards 'const' from pointer target type */
	if ((nmsg = udpheader_add(fakesockaddr2sockshost(to, &host),
	(const char *)msg, &nlen, 0)) == NULL) {
		errno = ENOBUFS;
		return -1;
	}

	n = sendto(s, nmsg, nlen, flags,
	socksfd->state.udpconnect ? NULL : &socksfd->reply,
	socksfd->state.udpconnect ? 0		: sizeof(socksfd->reply));
	n -= nlen - len;

	free(nmsg);

	slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
	function, protocol2string(SOCKS_TCP),
	sockaddr2string(&socksfd->local, dststring, sizeof(dststring)),
	sockaddr2string(&socksfd->reply, srcstring, sizeof(srcstring)),
	(unsigned long)n);

	return MAX(-1, n);
}

ssize_t
Rrecvfrom(s, buf, len, flags, from, fromlen)
	int s;
	void *buf;
	size_t len;
	int flags;
	struct sockaddr *from;
	socklen_t *fromlen;
{
	const char *function = "Rrecvfrom()";
	struct socksfd_t *socksfd;
	struct udpheader_t header;
	struct sockaddr newfrom;
	char srcstring[MAXSOCKADDRSTRING], dststring[sizeof(srcstring)];
	socklen_t newfromlen;
	char *newbuf;
	size_t newlen;
	ssize_t n;

	if (!socks_addrisok((unsigned int)s)) {
		socks_rmaddr((unsigned int)s);
		return recvfrom(s, buf, len, flags, from, fromlen);
	}

	if (udpsetup(s, from, SOCKS_RECV) != 0)
		return errno == 0 ? recvfrom(s, buf, len, flags, from, fromlen) : -1;

	socksfd = socks_getaddr((unsigned int)s);
	SASSERTX(socksfd != NULL);

	if (socksfd->state.protocol.tcp) {
		struct sockaddr *forus;

		if (socksfd->state.err != 0) {
			errno = socksfd->state.err;
			return -1;
		}
		else
			if (socksfd->state.inprogress) {
				errno = ENOTCONN;
				return -1;
			}

		n = recvfrom(s, buf, len, flags, from, fromlen);

		switch (socksfd->state.command) {
			case SOCKS_CONNECT:
				forus = &socksfd->forus.connected;
				break;

			case SOCKS_BIND:
				forus = &socksfd->forus.accepted;
				break;

			default:
				SERRX(socksfd->state.command);
		}

		slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
		function, protocol2string(SOCKS_TCP),
		sockaddr2string(forus, srcstring, sizeof(srcstring)),
		sockaddr2string(&socksfd->local, dststring, sizeof(dststring)),
		(unsigned long)n);

		return n;
	}

	SASSERTX(socksfd->state.protocol.udp);

	/* udp.  If packet is from socksserver it will be prefixed with a header. */
	newlen = len + sizeof(header);
	if ((newbuf = (char *)malloc(sizeof(*newbuf) * newlen)) == NULL) {
		errno = ENOBUFS;
		return -1;
	}

	newfromlen = sizeof(newfrom);
	if ((n = recvfrom(s, newbuf, newlen, flags, &newfrom, &newfromlen)) == -1) {
		free(newbuf);
		return n;
	}
	SASSERTX(newfromlen > 0);

	if (sockaddrareeq(&newfrom, &socksfd->reply)) {
		/*
		 * packet is from socksserver.
		*/

		if (string2udpheader(newbuf, (size_t)n, &header) == NULL) {
			char badfrom[MAXSOCKADDRSTRING];

			swarnx("%s: unrecognized socks udppacket from %s",
			function, sockaddr2string(&newfrom, badfrom, sizeof(badfrom)));
			errno = EAGAIN;
			return -1;	/* don't know if callee wants to retry. */
		}

		/* if connected udpsocket, only forward from "connected" source. */
		if (socksfd->state.udpconnect) {
			struct sockshost_t host;

			if (!sockshostareeq(&header.host,
			fakesockaddr2sockshost(&socksfd->forus.connected, &host))) {
				char a[MAXSOCKSHOSTSTRING];
				char b[MAXSOCKSHOSTSTRING];

				/*
				 * We have a problem here ...  If we failed to resolve
				 * address we gave to the socksserver and instead gave a
				 * hostname to it, sockshostareeq() will fail unless the server
				 * sends the address it is forwarding from as the sockshost too.
				 *
				 * It is better to place safe than sorry though, so
				 * we have to drop the packet in that case, even if it
				 * is from the correct source since we can not verify it.
				 */

				free(newbuf);

				slog(LOG_DEBUG, "%s: expected udpreply from %s, got it from %s",
				function,
				sockshost2string(fakesockaddr2sockshost(&socksfd->forus.connected,
				&host), a, sizeof(a)),
				sockshost2string(&header.host, b, sizeof(b)));

				/*
				 * Not sure what to do now, return error or retry?
				 * Going with returning error for now.
				 */

#if 0
				if ((p = fcntl(s, F_GETFL, 0)) == -1)
					return -1;

				if (p & NONBLOCKING) {
#endif

					errno = EAGAIN;
					return -1;

#if 0
				}
				/* else; assume the best thing is to retry. */
				return Rrecvfrom(s, buf, len, flags, from, fromlen);
#endif
			}
		}

		/* replace "newfrom" with the address socksserver says packet is from. */
		fakesockshost2sockaddr(&header.host, &newfrom);

		/* callee doesn't get socksheader. */
		n -= PACKETSIZE_UDP(&header);
		SASSERTX(n >= 0);
		memcpy(buf, &newbuf[PACKETSIZE_UDP(&header)], MIN(len, (size_t)n));
	}
	else /* ordinary udppacket, not from socksserver. */
		memcpy(buf, newbuf, MIN(len, (size_t)n));

	free(newbuf);

	slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
	function, protocol2string(SOCKS_UDP),
	sockaddr2string(&newfrom, srcstring, sizeof(srcstring)),
	sockaddr2string(&socksfd->local, dststring, sizeof(dststring)), 
	(unsigned long)n);

	if (from != NULL) {
		*fromlen = MIN(*fromlen, newfromlen);
		memcpy(from, &newfrom, (size_t)*fromlen);
	}

	return MIN(len, (size_t)n);
}


int
udpsetup(s, to, type)
	int s;
	const struct sockaddr *to;
	int type;
{
	const char *function = "udpsetup()";
	struct socks_t packet;
	struct socksfd_t socksfd;
	struct sockaddr_in newto;
	struct sockshost_t src, dst;
	socklen_t len;
	int p;

	slog(LOG_DEBUG, "%s: s = %d", function, s);

	if (!socks_addrisok((unsigned int)s))
		socks_rmaddr((unsigned int)s);

	if (socks_getaddr((unsigned int)s) != NULL)
		return 0; /* all set up. */

	/*
	 * if this socket has not previously been used we need to
	 * make a new connection to the socksserver for it.
	 */

	errno = 0;
	switch (type) {
		case SOCKS_RECV:
			/*
			 * problematic, trying to receive on socket not sent on.
			 */

			bzero(&newto, sizeof(newto));
			newto.sin_family			= AF_INET;
			newto.sin_addr.s_addr	= htonl(INADDR_ANY);
			newto.sin_port				= htons(0);

			/* LINTED pointer casts may be troublesome */
			to = (struct sockaddr *)&newto;

			break;

		case SOCKS_SEND:
			if (to == NULL)
				return -1; /* no address and unknown socket, no idea. */
			break;

		default:
			SERRX(type);
	}

	/*
	 * we need to send the socksserver our address.
	 * First check if the socket already has a name, if so
	 * use that, otherwise assign the name ourselves.
	 */

	bzero(&socksfd, sizeof(socksfd));

	len = sizeof(socksfd.local);
	if (getsockname(s, &socksfd.local, &len) != 0)
		return -1;
	sockaddr2sockshost(&socksfd.local, &src);

	fakesockaddr2sockshost(to, &dst);

	bzero(&packet, sizeof(packet));
	packet.version				= SOCKS_V5;
	packet.auth.method		= AUTHMETHOD_NOTSET;
	packet.req.version		= packet.version;
	packet.req.command		= SOCKS_UDPASSOCIATE;
	packet.req.flag			|= SOCKS_USECLIENTPORT;
/*	packet.req.flag			|= SOCKS_INTERFACEREQUEST; */
	packet.req.host			= src;

	if ((socksfd.control = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return -1;

	if ((socksfd.route
	= socks_connectroute(socksfd.control, &packet, &src, &dst)) == NULL) {
		close(socksfd.control);
		return -1;
	}

	/* LINTED  pointer casts may be troublesome */
	if ((TOIN((&socksfd.local))->sin_addr.s_addr == htonl(INADDR_ANY))
	/* LINTED  pointer casts may be troublesome */
	|| TOIN((&socksfd.local))->sin_port == htons(0)) {
		/*
		 * local name not fixed, set it, port may be bound, we need to bind
		 * IP too however.
		 */

		/* LINTED  pointer casts may be troublesome */
		const in_port_t port = TOIN((&socksfd.local))->sin_port;

		if (port != htons(0)) {
			/*
			 * port is bound.  We will try to unbind and then rebind same port
			 * but now also bind IP address.  XXX Dangerous stuff.
			 */

			if ((p = socketoptdup(s)) == -1) {
				close(socksfd.control);
				return -1;
			}

			if (dup2(p, s) == -1) {
				close(socksfd.control);
				close(p);
				return -1;
			}
			close(p);
		}

		/*
		 * don't have much of an idea on what IP address to use so might as
		 * well use same as tcp connection to socksserver uses.
		 */
		len = sizeof(socksfd.local);
		if (getsockname(socksfd.control, &socksfd.local, &len) != 0) {
			close(socksfd.control);
			return -1;
		}
		/* LINTED  pointer casts may be troublesome */
		TOIN(&socksfd.local)->sin_port = port;

		if (bind(s, &socksfd.local, sizeof(socksfd.local)) != 0) {
			close(socksfd.control);
			return -1;
		}

		if (getsockname(s, &socksfd.local, &len) != 0) {
			close(socksfd.control);
			return -1;
		}

		sockaddr2sockshost(&socksfd.local, &packet.req.host);
	}

/*	packet.req.host.addr.ipv4.s_addr = htonl(INADDR_ANY); */
/*	packet.req.host.port = htons(0); */

	if (socks_negotiate(s, socksfd.control, &packet, socksfd.route) != 0)
		return -1;

	socksfd.state.auth				= packet.auth;
	socksfd.state.version			= packet.version;
	socksfd.state.command			= SOCKS_UDPASSOCIATE;
	socksfd.state.protocol.udp		= 1;
	sockshost2sockaddr(&packet.res.host, &socksfd.reply);

	len = sizeof(socksfd.server);
	if (getpeername(socksfd.control, &socksfd.server, &len) != 0) {
		close(socksfd.control);
		return -1;
	}

	if (socks_addaddr((unsigned int)s, &socksfd) == NULL) {
		close(socksfd.control);
		errno = ENOBUFS;
		return -1;
	}

	return 0;
}
