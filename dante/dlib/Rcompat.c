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
"$Id: Rcompat.c,v 1.6 1999/03/11 16:59:31 karls Exp $";

#include "common.h"

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
	return Rsend(d, buf, nbytes, 0);
}

ssize_t
Rwritev(d, iov, iovcnt)
	int d;
	const struct iovec *iov;
	int iovcnt;
{
	struct msghdr msg;

	bzero(&msg, sizeof(msg));
	msg.msg_name 		= NULL;
	msg.msg_namelen 	= 0;
	/* LINTED cast discards 'const' from pointer target type */
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
	struct msghdr msghdr;
	struct iovec iov;

	/* LINTED cast discards 'const' from pointer target type */
	iov.iov_base		= (void *)msg;
	iov.iov_len			= len;

	bzero(&msg, sizeof(msg));
	msghdr.msg_name 		= NULL;
	msghdr.msg_namelen 	= 0;
	/* LINTED cast discards 'const' from pointer target type */
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
	size_t sent;
	ssize_t ioc, rc;
	struct sockaddr name;
	int namelen;

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

	for (sent = 0, ioc = 0, rc = 0; ioc < msg->msg_iovlen; ++ioc) {
		/* LINTED pointer casts may be troublesome */
		if ((rc = Rsendto(s, msg->msg_iov[ioc].iov_base,
		msg->msg_iov[ioc].iov_len, flags, (struct sockaddr *)msg->msg_name,
		msg->msg_namelen)) == -1)
			break;

		sent += rc;

		if (rc != msg->msg_iov[ioc].iov_len)
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
	return Rrecv(d, buf, nbytes, 0);
}

ssize_t
Rreadv(d, iov, iovcnt)
	int d;
	const struct iovec *iov;
	int iovcnt;
{
	struct msghdr msg;

	bzero(&msg, sizeof(msg));
	msg.msg_name 		= NULL;
	msg.msg_namelen 	= 0;
	/* LINTED cast discards 'const' from pointer target type */
	msg.msg_iov			= (struct iovec *)iov;
	msg.msg_iovlen		= iovcnt;

	return Rrecvmsg(d, &msg, 0);
}

ssize_t
Rrecv(s, msg, len, flags)
	int s;
	void *msg;
	size_t len;
	int flags;
{
	struct msghdr msghdr;
	struct iovec iov;

	/* LINTED cast discards 'const' from pointer target type */
	iov.iov_base		= (void *)msg;
	iov.iov_len			= len;

	bzero(&msghdr, sizeof(msghdr));
	msghdr.msg_name 		= NULL;
	msghdr.msg_namelen 	= 0;
	/* LINTED warning: cast discards 'const' from pointer target type */
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
	size_t received;
	ssize_t ioc, rc;
	struct sockaddr name;
	int namelen;

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

	for (received = 0, ioc = 0, rc = 0; ioc < msg->msg_iovlen; ++ioc) {
		/* LINTED pointer casts may be troublesome */
		if ((rc = Rrecvfrom(s, msg->msg_iov[ioc].iov_base,
		msg->msg_iov[ioc].iov_len, flags, (struct sockaddr *)msg->msg_name,
		&msg->msg_namelen)) == -1)
			break;

		received += rc;

		if (rc != msg->msg_iov[ioc].iov_len)
			break;
	}

	if (received == 0)
		return rc;
	return received;
}
