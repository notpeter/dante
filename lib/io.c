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

static const char rcsid[] =
"$Id: io.c,v 1.39 1999/09/02 10:41:37 michaels Exp $";

/* this file defines the functions. */
#undef select
#undef close


ssize_t
readn(d, buf, nbytes)
	int d;
	void *buf;
	size_t nbytes;
{
	ssize_t p;
	size_t left = nbytes;

	do {
		if ((p = read(d, &((char *)buf)[nbytes - left], left)) == -1) {
#if SOCKS_SERVER
			if (errno == EINTR)
				continue;
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
writen(d, buf, nbytes)
	int d;
	const void *buf;
	size_t nbytes;
{
	ssize_t p;
	size_t left = nbytes;

	do {
		if ((p = write(d, &((const char *)buf)[nbytes - left], left)) == -1) {
#if SOCKS_SERVER
			if (errno == EINTR)
				continue;
#endif
			break;
		}
		left -= p;
	} while (left > 0);

	if (left == nbytes)
		return p;	/* nothing written. */
	return nbytes - left;
}


ssize_t
recvmsgn(s, msg, flags, len)
	int s;
	struct msghdr *msg;
	int flags;
	size_t len;
{
	size_t left = len;
	ssize_t p;

	while ((p = recvmsg(s, msg, flags)) == -1 && errno == EINTR)
#if SOCKS_SERVER
		;
#else
		return -1;
#endif

#if HAVE_SOLARIS_BUGS
	if (p == -1 && (errno == EMFILE || errno == ENFILE)) {
		/*
		 * Even if solaris (2.5.1) fails on recvmsg() it may still have
		 * gotten a descriptor or more as ancillary data which it neglects
		 * to get rid of, so we have to check for it ourselves and close it,
		 * else it just gets lost in the void.
		 */
		int i, leaked;
		caddr_t mem;

		mem = msg->msg_accrights;
		for (i = 0; i * sizeof(leaked) < msg->msg_accrightslen; ++i) {
			memcpy(&leaked, mem, sizeof(leaked));
			mem += sizeof(leaked);
			close(leaked);
		}
	}
#endif /* HAVE_SOLARIS_BUGS */

	if (p <= 0)
		return p;
	left -= p;

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
			if (count > done) {
				if ((p = readn(s, &((char *)(io->iov_base))[io->iov_len -
				(count - done)], count - done)) != ((ssize_t)(count - done)))
					break;

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
	/* const */ fd_set rset = readfds	== NULL ? rset : *readfds;
	/* const */ fd_set wset = writefds	== NULL ? wset : *writefds;
	/* const */ fd_set eset = exceptfds	== NULL ? eset : *exceptfds;
	/* const */ struct timeval tout = timeout == NULL ? tout : *timeout;
	int rc;

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
