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

#define _NO_FUNCTION_REDIFINE

#include "common.h"

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC

#undef sendmsg
#if HAVE_EXTRA_OSF_SYMBOLS
#define sendmsg(s, msg, flags)			sys_Esendmsg(s, msg, flags)
#else
#define sendmsg(s, msg, flags)			sys_sendmsg(s, msg, flags)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#undef recvmsg
#if HAVE_EXTRA_OSF_SYMBOLS
#define recvmsg(s, msg, flags)			sys_Erecvmsg(s, msg, flags)
#else
#define recvmsg(s, msg, flags)			sys_recvmsg(s, msg, flags)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

/* XXX needed on AIX apparently */
#ifdef recvmsg_system
#undef recvmsg
#define recvmsg recvmsg_system
#endif /* recvmsg_system */

#ifdef sendmsg_system
#undef sendmsg
#define sendmsg sendmsg_system
#endif /* sendmsg_system */

#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */


static const char rcsid[] =
"$Id: Rcompat.c,v 1.23 2005/01/24 10:24:21 karls Exp $";

int
Rselect(nfds, readfds, writefds, exceptfds, timeout)
	int nfds;
	fd_set *readfds;
	fd_set *writefds;
	fd_set *exceptfds;
	struct timeval *timeout;
{
	return select(nfds, readfds, writefds, exceptfds, timeout);
}

int
Rlisten(s, backlog)
	int s;
	int backlog;
{

	return listen(s, backlog);
}


ssize_t
Rwrite(d, buf, nbytes)
	int d;
	const void *buf;
	size_t nbytes;
{
	const char *function = "Rwrite()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	return Rsend(d, buf, nbytes, 0);
}

ssize_t
Rwritev(d, iov, iovcnt)
	int d;
	const struct iovec *iov;
	int iovcnt;
{
	static const struct msghdr msginit;
	struct msghdr msg;
	const char *function = "Rwritev()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	msg = msginit;
	/* LINTED operands have incompatible pointer types */
	msg.msg_iov			= (struct iovec *)iov;
	msg.msg_iovlen		= iovcnt;

	return Rsendmsg(d, &msg, 0);
}

ssize_t
Rsend(s, msg, len, flags)
	int s;
	const void *msg;
	size_t len;
	int flags;
{
	static const struct msghdr msghdrinit;
	struct msghdr msghdr;
	struct iovec iov;
	const char *function = "Rsend()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	/* LINTED operands have incompatible pointer types */
	iov.iov_base		= msg;
	iov.iov_len			= len;

	msghdr = msghdrinit;
	msghdr.msg_iov			= &iov;
	msghdr.msg_iovlen		= 1;

	return Rsendmsg(s, &msghdr, flags);
}

ssize_t
Rsendmsg(s, msg, flags)
	int s;
	const struct msghdr *msg;
	int flags;
{
	size_t sent, ioc;
	ssize_t rc;
	struct sockaddr name;
	socklen_t namelen;
	const char *function = "Rsendmsg()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	namelen = sizeof(name);
	if (getsockname(s, &name, &namelen) == -1) {
		errno = 0;
		return writev(s, msg->msg_iov, (int)msg->msg_iovlen);
	}

	switch (name.sa_family) {
		case AF_INET:
			break;

#ifdef AF_INET6
		case AF_INET6:
			break;
#endif /* AF_INET6 */

		default:
			return sendmsg(s, msg, flags);
	}

	for (sent = ioc = rc = 0; ioc < msg->msg_iovlen; ++ioc) {
		/* LINTED pointer casts may be troublesome */
		if ((rc = Rsendto(s, msg->msg_iov[ioc].iov_base,
		msg->msg_iov[ioc].iov_len, flags, (struct sockaddr *)msg->msg_name,
		msg->msg_namelen)) == -1)
			break;

		sent += rc;

		if (rc != (ssize_t)msg->msg_iov[ioc].iov_len)
			break;
	}

	if (sent == 0)
		return rc;
	return sent;
}

ssize_t
Rread(d, buf, nbytes)
	int d;
	void *buf;
	size_t nbytes;
{
	const char *function = "Rread()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	return Rrecv(d, buf, nbytes, 0);
}

ssize_t
Rreadv(d, iov, iovcnt)
	int d;
	const struct iovec *iov;
	int iovcnt;
{
	static const struct msghdr msghdrinit;
	struct msghdr msg;
	const char *function = "Rreadv()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	msg = msghdrinit;
	/* LINTED operands have incompatible pointer types */
	msg.msg_iov		= (struct iovec *)iov;
	msg.msg_iovlen	= iovcnt;

	return Rrecvmsg(d, &msg, 0);
}

ssize_t
Rrecv(s, msg, len, flags)
	int s;
	void *msg;
	size_t len;
	int flags;
{
	static const struct msghdr msghdrinit;
	struct msghdr msghdr;
	struct iovec iov;
	const char *function = "Rrecv()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	/* LINTED cast discards 'const' from pointer target type */
	iov.iov_base		= (void *)msg;
	iov.iov_len			= len;

	msghdr = msghdrinit;
	msghdr.msg_iov			= &iov;
	msghdr.msg_iovlen		= 1;

	return Rrecvmsg(s, &msghdr, flags);
}

ssize_t
Rrecvmsg(s, msg, flags)
	int s;
	struct msghdr *msg;
	int flags;
{
	size_t received, ioc;
	ssize_t rc;
	struct sockaddr name;
	socklen_t namelen;
	const char *function = "Rrecvmsg()";

	clientinit();

	slog(LOG_DEBUG, "%s", function);

	namelen = sizeof(name);
	if (getsockname(s, &name, &namelen) == -1) {
		errno = 0;
		return readv(s, msg->msg_iov, (int)msg->msg_iovlen);
	}

	switch (name.sa_family) {
		case AF_INET:
			break;

#ifdef AF_INET6
		case AF_INET6:
			break;
#endif /* AF_INET6 */

		default:
			return recvmsg(s, msg, flags);
	}

	for (received = ioc = rc = 0; ioc < msg->msg_iovlen; ++ioc) {
		/* LINTED pointer casts may be troublesome */
		if ((rc = Rrecvfrom(s, msg->msg_iov[ioc].iov_base,
		msg->msg_iov[ioc].iov_len, flags, (struct sockaddr *)msg->msg_name,
		&msg->msg_namelen)) == -1)
			break;

		received += rc;

		if (rc != (ssize_t)msg->msg_iov[ioc].iov_len)
			break;
	}

	if (received == 0)
		return rc;
	return received;
}
