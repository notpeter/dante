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
"$Id: sockd_negotiate.c,v 1.45 1998/12/13 16:01:06 michaels Exp $";

#include "common.h"

__BEGIN_DECLS

static int
send_negotiate __P((const struct sockd_mother_t *mother,
						  const struct sockd_negotiate_t *neg));
/*
 * Sends "neg" to "s".  Also ack's that we have freed a slot to "s".
 * Returns:
 *		On success: 0
 *		On failure: -1
 *		If some other problem prevented success: > 0
*/


static int
recv_negotiate __P((const struct sockd_mother_t *mother));
/*
 * Tries to receive a client from mother "s".
 * Returns:
 *		On success: 0
 * 	If a error happened to connection with "s": -1
 *		If some other problem prevented success: > 0
*/

static void
delete_negotiate __P((const struct sockd_mother_t *mother,
							 struct sockd_negotiate_t *neg));
/*
 * Frees any state occupied by "neg", including closing any
 * descriptors and sending a ack that we have deleted a "negotiate"
 * object to "mother".
*/


static int
neg_fillset __P((fd_set *set));
/*
 * Sets all descriptors in our list in the set "set". 
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors open currently.
*/

static void
neg_clearset __P((struct sockd_negotiate_t *neg, fd_set *set));
/*
 * Clears all filedescriptors in "neg" from "set".
*/


static struct sockd_negotiate_t *
neg_getset __P((fd_set *set));
/*
 * Goes through our list until it finds a negotiate object where atleast
 * one of the descriptors is set.
 * Returns:
 *		On success: pointer to the found object.
 *		On failure: NULL.
*/

static int
allocated __P((void));
/*
 * Returns the number of allocated (active) objects.
*/

static int
completed __P((void));
/*
 * Returns the number of objects completed and ready to be sent currently.
*/
	
static void
proctitleupdate __P((void));
/*
 * Updates the title of this process.  
*/

static struct timeval *
neg_gettimeout __P((struct timeval *timeout));
/*
 * If there is a timeout on the current clients to finish negotiation,
 * this function fills in "timeout" with the appropriate timeout.
 * Returns:
 *		If there is a timeout: pointer to filled in "timeout".
 *		If there is no timeout: NULL.
*/

static struct sockd_negotiate_t *
neg_gettimedout __P((void));
/*
 * Scans all clients for one that has timed out according to config
 * settings.
 * Returns:
 *		If timed out client found: pointer to it.
 *		Else: NULL.
*/

__END_DECLS


static struct sockd_negotiate_t negv[SOCKD_IOMAX];/* each child has these. */
static int negc = ELEMENTS(negv);


void
run_negotiate(mother)
	struct sockd_mother_t *mother;
{

	proctitleupdate();

	/* CONSTCOND */
	while (1) {
		fd_set rset, wsetmem, *wset = NULL;
		int fdbits, p;
		struct sockd_negotiate_t *neg;
		struct timeval timeout;

		fdbits = neg_fillset(&rset);
		FD_SET(mother->s, &rset);
		fdbits = MAX(fdbits, mother->s);

		/* if we have a completed request check whether we can send to mother. */
		if (completed() > 0) {
			FD_ZERO(&wsetmem);
			FD_SET(mother->s, &wsetmem);
			wset = &wsetmem;
		}
			
		++fdbits;
		switch (select(fdbits, &rset, wset, NULL, neg_gettimeout(&timeout))) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0: {
				const char *reason = "negotiation timed out";

				if ((neg = neg_gettimedout()) == NULL)
					continue; /* should only be possible if sighup received. */

				iolog(&neg->rule, &neg->state, OPERATION_ABORT, &neg->src,
				&neg->dst, reason, strlen(reason));

				delete_negotiate(mother, neg);

				continue;
			}
		}

		if (FD_ISSET(mother->s, &rset)) {
			if (recv_negotiate(mother) == -1)
				sockdexit(-EXIT_FAILURE);
			FD_CLR(mother->s, &rset);
		}

		while ((neg = neg_getset(&rset)) != NULL) {

			neg_clearset(neg, &rset);

			if ((p = recv_request(neg->s, &neg->req, &neg->negstate)) <= 0) {
				const char *reason = NULL;	/* init or gcc complains. */

				switch (p) {
					case 0:
						reason = "eof from client";
						break;

					case -1:
						switch (errno) {
							case 0:
								reason = "socks protocol error";
								break;

							case EINTR:
							case EAGAIN:
#if EAGAIN != EWOULDBLOCK
							case EWOULDBLOCK:
#endif
								continue; /* ok, retry. */
							
							default:
								reason = strerror(errno);
						}
				}

				iolog(&neg->rule, &neg->state, OPERATION_ABORT, &neg->src,
				&neg->dst, reason, strlen(reason));

				delete_negotiate(mother, neg);
			}
			else if (wset != NULL && FD_ISSET(mother->s, wset)) {
				/* read a complete request, try and send to mother. */
				switch (send_negotiate(mother, neg)) {
					case -1:
						sockdexit(-EXIT_FAILURE);
						/* NOTREACHED */

					case 0:
						delete_negotiate(mother, neg); /* sent to mother ok. */
						break;
				}
			}
		}
	}
}


static int
send_negotiate(mother, neg)
	const struct sockd_mother_t *mother;
	const struct sockd_negotiate_t *neg;
{
	const char *function = "send_negotiate()";
#ifdef HAVE_CMSGHDR
	union {
		char cmsgmem[sizeof(struct cmsghdr) + sizeof(int)];
		struct cmsghdr align;
	} cmsgmem;
	struct cmsghdr *cmsg = &cmsgmem.align;
	int fdsendt = 0;
#endif  /* HAVE_CMSGHDR */
	struct iovec iovec[1];
	struct msghdr msg;
	struct sockd_request_t req;
	int w;

#ifdef HAVE_SENDMSG_DEADLOCK
	if (socks_lock(mother->lock, F_WRLCK, 0) != 0)
		return 1;
#endif /* HAVE_SENDMSG_DEADLOCK */


	/* copy needed fields from negotiate */
	req.req	= neg->req;
	req.auth	= neg->auth;
	req.rule = neg->rule;
	/* LINTED pointer casts may be troublesome */
	sockshost2sockaddr(&neg->src, (struct sockaddr *)&req.from);
	/* LINTED pointer casts may be troublesome */
	sockshost2sockaddr(&neg->dst, (struct sockaddr *)&req.to);

#ifdef HAVE_CMSGHDR
	/* LINTED pointer casts may be troublesome */
	*(int *)(CMSG_DATA(cmsg) + sizeof(req.s) * fdsendt++) = neg->s;
#else
	msg.msg_accrights 	= (caddr_t) &neg->s;
	msg.msg_accrightslen = sizeof(int);
#endif  /* HAVE_CMSGHDR */

	iovec[0].iov_base		= &req;
	iovec[0].iov_len		= sizeof(req);

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

#ifdef HAVE_CMSGHDR
	/* LINTED pointer casts may be troublesome */
	msg.msg_control		= (caddr_t)cmsg;
	msg.msg_controllen	= sizeof(cmsgmem);

	cmsg->cmsg_level		= SOL_SOCKET;
	cmsg->cmsg_type		= SCM_RIGHTS;
	cmsg->cmsg_len			= sizeof(cmsgmem);
#endif  /* HAVE_CMSGHDR */

	slog(LOG_DEBUG, "sending request to mother");
	if ((w = sendmsg(mother->s, &msg, 0)) != sizeof(req))
		switch (errno) {
			case EAGAIN:
			case ENOBUFS:
				w = 1;	/* temporal error. */
				break;

			default:
				swarn("%s: sendmsg(): %d of %d", function, w, sizeof(req));
		}

#ifdef HAVE_SENDMSG_DEADLOCK
	if (socks_unlock(mother->lock, -1) != 0)
		SERR(errno);
#endif /* HAVE_SENDMSG_DEADLOCK */

	return w == sizeof(req) ? 0 : w;
}


static int
recv_negotiate(mother)
	const struct sockd_mother_t *mother;
{
	const char *function = "recv_negotiate()";
#ifdef HAVE_CMSGHDR
	union {
		char cmsgmem[sizeof(struct cmsghdr) + sizeof(int)];
		struct cmsghdr align;
	} cmsgmem;
	struct cmsghdr *cmsg = &cmsgmem.align;
#else
	int desc;
#endif  /* HAVE_CMSGHDR */
	struct iovec iovec[1];
	struct msghdr msg;
	struct sockd_negotiate_t *neg;
	struct sockaddr addr;
	unsigned char command;
	int permit, i, r, len;


	iovec[0].iov_base		= &command;
	iovec[0].iov_len		= sizeof(command);

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;
#ifdef HAVE_CMSGHDR
	/* LINTED pointer casts may be troublesome */
	msg.msg_control		= (caddr_t)cmsg;
	msg.msg_controllen 	= sizeof(cmsgmem);
#else
	msg.msg_accrights		= (caddr_t) &desc;
	msg.msg_accrightslen	= sizeof(int);
#endif  /* HAVE_CMSGHDR */

	if ((r = recvmsgn(mother->s, &msg, 0, sizeof(command))) != sizeof(command)) {
		switch (r) {
			case -1:
				swarn("%s: recvmsg()", function);
				break;

			case 0:
				swarnx("%s: recvmsg(): mother closed connection", function);
				break;
				
			default:
				swarnx("%s: recvmsg(): unexpected %d/%d bytes from mother",
				function, r, sizeof(command));
		}

		return -1;
	}

	SASSERTX(command == SOCKD_NEWREQUEST);

#ifdef HAVE_CMSGHDR
#ifndef HAVE_DEFECT_RECVMSG
	if (msg.msg_flags & MSG_CTRUNC)
		SERRX(0);
#endif /* !HAVE_DEFECT_RECVMSG */
#endif  /* HAVE_CMSGHDR */

	/* find a free slot. */
	for (i = 0, neg = NULL; i < negc; ++i)
		if (!negv[i].allocated) {
			neg = &negv[i];
			break;
		}

	if (neg == NULL) {
		/* mother has miscalculated and should be the one to crash... */ 
		SWARNX(allocated());
		return 1;
	}

#ifdef HAVE_CMSGHDR
#ifndef HAVE_DEFECT_RECVMSG
	SASSERTX(msg.msg_controllen == sizeof(cmsgmem));
#endif /* !HAVE_DEFECT_RECVMSG */
#else
	SASSERTX(msg.msg_accrightslen == sizeof(int));
#endif  /* HAVE_CMSGHDR */

#ifdef HAVE_CMSGHDR
	/* LINTED pointer casts may be troublesome */
	neg->s = *(int *)(CMSG_DATA(cmsg));
#else
	neg->s = desc;
#endif  /* HAVE_CMSGHDR */

	/* get local and remote peer address. */

	len = sizeof(addr);
	if (getpeername(neg->s, &addr, &len) != 0) {
		swarn("%s: getpeername(): client dropped", function);
		return 1;
	}
	sockaddr2sockshost(&addr, &neg->src);

	len = sizeof(addr);
	if (getsockname(neg->s, &addr, &len) != 0) {
		swarn("%s: getsockname(): client dropped", function);
		return 1;
	}
	sockaddr2sockshost(&addr, &neg->dst);

	neg->state.command 		= SOCKS_ACCEPT;
	neg->state.protocol 		= SOCKS_TCP;
	neg->state.auth.method	= AUTHMETHOD_NONE;
	/* pointer fixup */
	neg->req.auth = &neg->auth;
	neg->allocated = 1;

	permit = clientaddressisok(neg->s, &neg->src, &neg->dst, neg->state.protocol,
	&neg->rule);

	iolog(&neg->rule, &neg->state, OPERATION_ACCEPT, &neg->src, &neg->dst,
	NULL, 0);

	if (!permit) {
		delete_negotiate(mother, neg);
		return 0;
	}

	if (time(&neg->start) == (time_t)-1)
		SERR((time_t)-1);

	proctitleupdate();

	return 0;
}

static void
delete_negotiate(mother, neg)
	const struct sockd_mother_t *mother;
	struct sockd_negotiate_t *neg;
{
	const char *function = "delete_negotiate()";
	static const struct sockd_negotiate_t neginit;
	const char command = SOCKD_FREESLOT;

	SASSERTX(neg->allocated);

	terminate_connection(neg->s, neg->req.auth);

	*neg = neginit;

	/* ack we have freed a slot. */
	if (writen(mother->ack, &command, sizeof(command)) != sizeof(command))
		swarn("%s: writen()", function);

	proctitleupdate();
}


static int
neg_fillset(set)
	fd_set *set;
{
	int i, max;

	FD_ZERO(set);

	for (i = 0, max = -1; i < negc; ++i)
		if (negv[i].allocated) {
			negv[i].ignore = 0;
			FD_SET(negv[i].s, set);
			max = MAX(max, negv[i].s);
		}

	return max;
}

static void
neg_clearset(neg, set)
	struct sockd_negotiate_t *neg;
	fd_set *set;
{

	FD_CLR(neg->s, set);
	neg->ignore = 1;
}


static struct sockd_negotiate_t *
neg_getset(set)
	fd_set *set;
{
	int i;

	for (i = 0; i < negc; ++i)
		if (negv[i].allocated) {
			if (negv[i].ignore)
				continue;

			if (negv[i].negstate.complete)
				return &negv[i];

			if (FD_ISSET(negv[i].s, set))
				return &negv[i];

		}

	return NULL;
}

static int
allocated(void)
{
	int i, alloc;

	for (i = 0, alloc = 0; i < negc; ++i)
		if (negv[i].allocated)
			++alloc;

	return alloc;
}

static int
completed(void)
{
	int i, completec;

	for (i = 0, completec = 0; i < negc; ++i)
		if (negv[i].allocated && negv[i].negstate.complete)
			++completec;

	return completec;
}


static void
proctitleupdate(void)
{

	setproctitle("negotiator: %d/%d", allocated(), SOCKD_NEGOTIATEMAX);
}

static struct timeval *
neg_gettimeout(timeout)
	struct timeval *timeout;
{
	time_t timenow;
	int i;

	if ((allocated() == completed()) || config.timeout.negotiate == 0)
		return NULL;

	timeout->tv_sec 	= config.timeout.negotiate;
	timeout->tv_usec 	= 0;

	if (time(&timenow) == (time_t)-1)
		SERR((time_t)-1);

	for (i = 0; i < negc; ++i)
		if (!negv[i].allocated)
			continue;
		else
			timeout->tv_sec = MAX(0, MIN(timeout->tv_sec,
			config.timeout.negotiate - (timenow - negv[i].start)));

	return timeout;
}

static struct sockd_negotiate_t *
neg_gettimedout(void)
{
	int i;
	time_t timenow;

	if (config.timeout.negotiate == 0)
		return NULL;

	if (time(&timenow) == (time_t)-1)
		SERR((time_t)-1);

	for (i = 0; i < negc; ++i) {
		if (!negv[i].allocated)
			continue;
		if (negv[i].ignore)
			continue;
		else
			if (timenow - negv[i].start >= config.timeout.negotiate)
				return &negv[i];
	}

	return NULL;
}
