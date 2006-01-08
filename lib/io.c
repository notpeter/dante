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

static const char rcsid[] =
"$Id: io.c,v 1.67 2005/10/11 13:17:12 michaels Exp $";

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

ssize_t
readn(d, buf, nbytes, auth)
	int d;
	void *buf;
	size_t nbytes;
	struct authmethod_t *auth;
{
	const char *function = "readn()";
	ssize_t p;
	size_t left = nbytes;

	do {
		if ((p = socks_recvfrom(d, &((char *)buf)[nbytes - left], left, 0, NULL,
		NULL, auth)) == -1) {
#if SOCKS_SERVER
			if (errno == EINTR)
				continue;
#else /* SOCKS_CLIENT; retry. */
			if (errno == EAGAIN) {
				fd_set rset;

				FD_ZERO(&rset);
				FD_SET(d, &rset);
				if (select(d + 1, &rset, NULL, NULL, NULL) == -1)
					swarn("%s: select()", function);

				continue;
			}
#endif
			break;
		}
		else if (p == 0)
			break;
		left -= p;
	} while (left > 0);

	if (left == nbytes)
		return p;	/* nothing read. */
	return nbytes - left;
}


ssize_t
writen(d, buf, nbytes, auth)
	int d;
	const void *buf;
	size_t nbytes;
	struct authmethod_t *auth;
{
	const char *function = "writen()";
	ssize_t p;
	size_t left = nbytes;

	do {
		if ((p = socks_sendto(d, &((const char *)buf)[nbytes - left], left, 0,
		NULL, 0, auth)) == -1) {
#if SOCKS_SERVER
			if (errno == EINTR)
				continue;
#endif
			if (errno == EAGAIN) {
				fd_set wset;

				FD_ZERO(&wset);
				FD_SET(d, &wset);
				if (select(d + 1, NULL, &wset , NULL, NULL) == -1)
					swarn("%s: select()", function);

				continue;
			}

			break;
		}
		left -= p;
	} while (left > 0);

	if (left == nbytes)
		return p;	/* nothing written. */
	return nbytes - left;
}

ssize_t
socks_recvfrom(s, buf, len, flags, from, fromlen, auth)
	int s;
	void *buf;
	size_t len;
	int flags;
	struct sockaddr *from;
	socklen_t *fromlen;
	struct authmethod_t *auth;
{

	if (auth != NULL)
		switch (auth->method) {
			case AUTHMETHOD_NOTSET:
			case AUTHMETHOD_NONE:
			case AUTHMETHOD_UNAME:
			case AUTHMETHOD_NOACCEPT:
			case AUTHMETHOD_RFC931:
			case AUTHMETHOD_PAM:
				break;

			default:
				SERRX(auth->method);
		}

	if (from == NULL && flags == 0)
		/* may not be a socket and read(2) will work just as well then. */
		return read(s, buf, len);
	return recvfrom(s, buf, len, flags, from, fromlen);
}

ssize_t
socks_sendto(s, msg, len, flags, to, tolen, auth)
	int s;
	const void *msg;
	size_t len;
	int flags;
	const struct sockaddr *to;
	socklen_t tolen;
	struct authmethod_t *auth;
{

	if (auth != NULL)
		switch (auth->method) {
			case AUTHMETHOD_NOTSET:
			case AUTHMETHOD_NONE:
			case AUTHMETHOD_UNAME:
			case AUTHMETHOD_NOACCEPT:
			case AUTHMETHOD_RFC931:
			case AUTHMETHOD_PAM:
				break;

			default:
				SERRX(auth->method);
		}

	if (to == NULL && flags == 0)
		/* may not be a socket and write(2) will work just as well then. */
		return write(s, msg, len);
	return sendto(s, msg, len, flags, to, tolen);
}


ssize_t
recvmsgn(s, msg, flags)
	int s;
	struct msghdr *msg;
	int flags;
{
	const char *function = "recvmsgn()";
	ssize_t p;
	size_t len, left;

	for (p = len = 0; p < (ssize_t)msg->msg_iovlen; ++p)
		len += msg->msg_iov[p].iov_len;

	while ((p = recvmsg(s, msg, flags)) == -1 && errno == EINTR)
#if SOCKS_SERVER
		;
#else
		return -1;
#endif

#if HAVE_SOLARIS_BUGS
	if (p == -1 && (errno == EMFILE || errno == ENFILE)) {
		/*
		 * Even if Solaris (2.5.1) fails on recvmsg() it may still have
		 * gotten a descriptor or more as ancillary data which it neglects
		 * to get rid of, so we have to check for it ourselves and close it,
		 * else it just gets lost in the void.
		 */
		size_t leaked;
		int d;

		for (leaked = 0; CMSG_SPACE(leaked * sizeof(d)) < CMSG_TOTLEN(*msg); ++leaked) {
			CMSG_GETOBJECT(d, CMSG_CONTROLDATA(*msg), leaked * sizeof(d));
			close(d);
		}
	}
#endif /* HAVE_SOLARIS_BUGS */

	if (p <= 0)
		return p;
	left = len - p;

	if (left > 0) {
		size_t i, count, done;

		/*
		 * Can't call recvmsg() again since we could be getting ancillary data,
		 * read the elements one by one.
		 */

		SASSERTX(p >= 0);

		done = p;
		i = count = p = 0;
		while (i < msg->msg_iovlen && left > 0) {
			const struct iovec *io = &msg->msg_iov[i];

			count += io->iov_len;
			if (count > done) { /* didn't read all of this iovec. */
				if ((p = readn(s,
				&((char *)(io->iov_base))[io->iov_len - (count - done)],
				count - done, NULL)) != ((ssize_t)(count - done))) {
					/*
					 * Failed to read all data, close any descriptors we
					 * may have gotten then.
					 */
					size_t leaked;
					int d;

					swarn("%s: %d bytes left", function, left);

					for (leaked = 0;
					CMSG_SPACE(leaked * sizeof(d)) < (size_t)CMSG_TOTLEN(*msg);
					++leaked) {
						CMSG_GETOBJECT(d, CMSG_CONTROLDATA(*msg), leaked * sizeof(d));
						close(d);
					}

					break;
				}

				left -= p;
				done += p;
			}

			++i;
		}
	}

	if (left == len)
		return p; /* nothing read. */
	return len - left;
}

ssize_t
sendmsgn(s, msg, flags)
	int s;
	const struct msghdr *msg;
	int flags;
{
	const char *function = "sendmsgn()";
	ssize_t p;
	size_t len, left;

	for (p = len = 0; p < (ssize_t)msg->msg_iovlen; ++p)
		len += msg->msg_iov[p].iov_len;

	while ((p = sendmsg(s, msg, flags)) == -1 && errno == EINTR)
#if SOCKS_SERVER
		;
#else
		return -1;
#endif

	if (p <= 0)
		return p;
	left = len - p;

	if (left > 0) {
		size_t i, count, done;

		/*
		 * Can't call sendmsg() again since we could be sending ancillary data,
		 * send the elements one by one.
		 */

		SASSERTX(p >= 0);

		done = p;
		i = count = p = 0;
		while (i < msg->msg_iovlen && left > 0) {
			const struct iovec *io = &msg->msg_iov[i];

			count += io->iov_len;
			if (count > done) { /* didn't send all of this iovec. */
				while ((p = writen(s,
				&((char *)(io->iov_base))[io->iov_len - (count - done)],
				count - done, NULL)) != ((ssize_t)(count - done))) {
					/*
					 * yes, we only re-try once.  What errors should we
					 * retry again on?
					 */
					swarn("%s: failed on re-try", function);
					break;
				}

				left -= p;
				done += p;
			}

			++i;
		}
	}

	if (left == len)
		return p; /* nothing read. */
	return len - left;
}


int
closen(d)
	int d;
{
	int rc;

	while ((rc = close(d)) == -1 && errno == EINTR)
		;

#if DIAGNOSTIC
	SASSERT(rc == 0 || d >= 0);
#endif

	return rc;
}

int
selectn(nfds, readfds, writefds, exceptfds, timeout)
	int nfds;
	fd_set *readfds;
	fd_set *writefds;
	fd_set *exceptfds;
	struct timeval *timeout;
{
	const char *function = "selectn()";

	/* const */ fd_set rset = readfds	== NULL ? rset : *readfds;
	/* const */ fd_set wset = writefds	== NULL ? wset : *writefds;
	/* const */ fd_set eset = exceptfds	== NULL ? eset : *exceptfds;
	/* const */ struct timeval tout = timeout == NULL ? tout : *timeout;
	int rc;

	if (timeout != NULL)
		slog(LOG_DEBUG, "%s, tv_sec = %ld, tv_usec = %ld",
		function, timeout->tv_sec, timeout->tv_usec);
	else
		slog(LOG_DEBUG, "%s, timeout = NULL", function);


	while ((rc = select(nfds, readfds, writefds, exceptfds, timeout)) == -1
	&& errno == EINTR) {
		if (readfds != NULL)
			*readfds = rset;

		if (writefds != NULL)
			*writefds = wset;

		if (exceptfds != NULL)
			*exceptfds = eset;

		if (timeout != NULL)
			*timeout = tout;
	}

	return rc;
}
