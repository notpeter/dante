/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003
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
"$Id: sockd_child.c,v 1.146 2005/12/25 17:22:17 michaels Exp $";

#define MOTHER	0	/* descriptor mother reads/writes on.	*/
#define CHILD	1	/* descriptor child reads/writes on.	*/

__BEGIN_DECLS

static int
setchildtype __P((int type, struct sockd_child_t ***childv, int **childc,
						void (**function)(struct sockd_mother_t *mother)));
/*
 * Sets "childv", "childc" and "function" to the correct value depending
 * on "type".
 */


static int
findchild __P((pid_t pid, int childc, const struct sockd_child_t *childv));
/*
 * Finds the child with pid "pid" in the array "childv".  Searching
 * Elements in "childv" is given by "childc".
 * Returns:
 *		On success: the index of the child in "childv".
 *		On failure: -1.
 */

__END_DECLS


static struct sockd_child_t *iochildv;				/* all our iochildren			*/
static int iochildc;

static struct sockd_child_t *negchildv;			/* all our negotiatorchildren */
static int negchildc;

static struct sockd_child_t *reqchildv;			/* all our requestchildren		*/
static int reqchildc;


struct sockd_child_t *
addchild(type)
	int type;
{
	const char *function = "addchild()";
	/*
	 * It is better to reserve some descriptors for temporary use
	 * than to get errors when passing them and thus lose clients.
	 */
	const int reserved = FDPASS_MAX	/* max descriptors we pass.			*/
							 + 1				/* need a descriptor for accept().	*/
							 + 2;				/* for each new child.					*/
	struct sockd_mother_t mother;
	struct sockd_child_t **childv;
	int *childc;
	void (*childfunction)(struct sockd_mother_t *mother);
	pid_t pid;
	const pid_t ourpid = sockscf.state.pid;
	int optval, flags;
	int pipev[] = { -1, -1 };
	int ackpipev[] = { -1, -1 };

	/*
	 * XXX This is a expensive test which shouldn't be hard to optimize
	 * away.  It only happens when we are running low on slots though,
	 * so assume it's "good enough" until I get the time to fix it.
	 */
	if (freedescriptors(NULL) < reserved) {
		errno = EMFILE;
		swarn(function);
		return NULL;
	}

	/* create datapipe. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pipev) != 0) {
		swarn("%s: socketpair(AF_LOCAL, SOCK_STREAM)", function);
		return NULL;
	}

	/* and ackpipe. */
	if (pipe(ackpipev) != 0) {
		swarn("%s: pipe()", function);
		closev(pipev, ELEMENTS(pipev));
		return NULL;
	}

	/*
	 * Try to set socketbuffer and watermarks to a optimal size.
	 */
	switch (type = setchildtype(type, &childv, &childc, &childfunction)) {
		case CHILD_NEGOTIATE:
			/*
			 * A negotiator child receives only descriptors, so mothers
			 * send buffer can be small, and so can the child's receive buffer.
			 * The child sends a sockd_request_t struct back to mother, so
			 * mothers recv buffer has to be considerably bigger, as does
			 * childs send buffer.
			 */

			/* negotiator shouldn't block on sending to mother. */
			if ((flags = fcntl(pipev[CHILD], F_GETFL, 0)) == -1
			||  fcntl(pipev[CHILD], F_SETFL, flags | O_NONBLOCK) == -1)
				swarn("%s: fcntl()", function);

#if HAVE_SENDMSG_DEADLOCK
			if ((mother.lock = socks_mklock(SOCKS_LOCKFILE)) == -1) {
				swarn("%s: socks_mklock()", function);
				closev(pipev, ELEMENTS(pipev));
				closev(ackpipev, ELEMENTS(ackpipev));
				return NULL;
			}
#endif /* HAVE_SENDMSG_DEADLOCK */

			optval = sizeof(struct sockd_request_t) * (SOCKD_NEGOTIATEMAX + 1);
			if (setsockopt(pipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &optval,
			sizeof(optval)) != 0
			||  setsockopt(pipev[CHILD], SOL_SOCKET, SO_SNDBUF, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_RCVBUF/SO_SNDBUF)", function);

#if HAVE_SO_SNDLOWAT
			optval = sizeof(struct sockd_request_t) * LOWATSKEW;
			if (setsockopt(pipev[CHILD], SOL_SOCKET, SO_SNDLOWAT, &optval,
			sizeof(optval)) != 0
			|| setsockopt(pipev[MOTHER], SOL_SOCKET, SO_RCVLOWAT, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_SNDLOWAT/SO_RCVLOWAT)", function);
#endif
			break;

		case CHILD_REQUEST:
			/*
			 * A request child receives a sockd_request_t structure,
			 * it sends back a sockd_io_t structure.
			 */

#if HAVE_SENDMSG_DEADLOCK
			mother.lock = -1;	/* doesn't need lock. */
#endif /* HAVE_SENDMSG_DEADLOCK */

			optval = sizeof(struct sockd_request_t) * (SOCKD_REQUESTMAX + 1);
			if (setsockopt(pipev[MOTHER], SOL_SOCKET, SO_SNDBUF, &optval,
			sizeof(optval)) != 0
			||  setsockopt(pipev[CHILD], SOL_SOCKET, SO_RCVBUF, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt()", function);

			optval = sizeof(struct sockd_io_t) * (SOCKD_REQUESTMAX + 1);
			if (setsockopt(pipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &optval,
			sizeof(optval)) != 0
			||  setsockopt(pipev[CHILD], SOL_SOCKET, SO_SNDBUF, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt()", function);

#if HAVE_SO_SNDLOWAT
			optval = sizeof(struct sockd_request_t) * LOWATSKEW;
			if (setsockopt(pipev[CHILD], SOL_SOCKET, SO_RCVLOWAT, &optval,
			sizeof(optval)) != 0
			|| setsockopt(pipev[MOTHER], SOL_SOCKET, SO_SNDLOWAT, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_RCVLOWAT)", function);

			optval = sizeof(struct sockd_io_t) * LOWATSKEW;
			if (setsockopt(pipev[CHILD], SOL_SOCKET, SO_SNDLOWAT, &optval,
			sizeof(optval)) != 0
			|| setsockopt(pipev[MOTHER], SOL_SOCKET, SO_RCVLOWAT, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_RCVLOWAT/SO_SNDLOWAT)", function);
#endif
			break;

		case CHILD_IO:
			/*
			 * A io child receives a sockd_io_t structure,
			 * it sends back only a ack.
			 */

#if HAVE_SENDMSG_DEADLOCK
			mother.lock = -1;	/* doesn't need lock. */
#endif /* HAVE_SENDMSG_DEADLOCK */

			optval = sizeof(struct sockd_io_t) * (SOCKD_IOMAX + 1);
			if (setsockopt(pipev[MOTHER], SOL_SOCKET, SO_SNDBUF, &optval,
			sizeof(optval)) != 0
			||  setsockopt(pipev[CHILD], SOL_SOCKET, SO_RCVBUF, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_SNDBUF/SO_RCVBUF)", function);

			optval = sizeof(int) * (SOCKD_IOMAX + 1);
			if (setsockopt(pipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &optval,
			sizeof(optval)) != 0
			||  setsockopt(pipev[CHILD], SOL_SOCKET, SO_SNDBUF, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_RCVBUF/SO_SNDBUF)", function);

#if HAVE_SO_SNDLOWAT
			optval = sizeof(struct sockd_io_t) * LOWATSKEW;
			if (setsockopt(pipev[CHILD], SOL_SOCKET, SO_RCVLOWAT, &optval,
			sizeof(optval)) != 0
			|| setsockopt(pipev[MOTHER], SOL_SOCKET, SO_SNDLOWAT, &optval,
			sizeof(optval)) != 0)
				swarn("%s: setsockopt(SO_RCVLOWAT)", function);
#endif
			break;

		default:
			SERRX(type);
	}

	/* so slog() doesn't log wrong pid if we termintate here. */
	sockscf.state.pid = 0;

	switch ((pid = fork())) {
		case -1:
			sockscf.state.pid = ourpid;

			swarn("%s: fork()", function);
			closev(pipev, ELEMENTS(pipev));
			closev(ackpipev, ELEMENTS(ackpipev));

#if HAVE_SENDMSG_DEADLOCK
			if (mother.lock != -1)
				close(mother.lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

			return NULL;

		case 0: {
			size_t i, maxfd;
			struct sigaction sigact;

			newprocinit();

			sockscf.state.type	= type;
			slog(LOG_INFO, "created new %schild", childtype2string(type));
#if 0
			slog(LOG_DEBUG, "sleeping...");
			sleep(20);
#endif

			mother.s		= pipev[CHILD];
			mother.ack	= ackpipev[CHILD];

			/*
			 * It would be nice to be able to lose all privileges here
			 * but unfortunately we can't, yet.
			 *
			 * negotiation children:
			 *		could need privileges to check password.
			 *
			 * request children:
			 *		could need privileges to bind port.
			 *
			 * io children:
			 *		could need privileges to bind port if using redirect()
			 *		module, also SIGHUP performs misc. seteuid() tests that
			 *    could fail if we lose privileges.
			 */

			switch (type) {
				case CHILD_NEGOTIATE:
#if HAVE_LIBWRAP
#if SOCKD_NEGOTIATEMAX > 1
					resident = 1;
#endif /* SOCKD_NEGOTIATEMAX > 1 */
#endif  /* HAVE_LIBWRAP */
					break;

				case CHILD_REQUEST:
#if HAVE_LIBWRAP
#if SOCKD_REQUESTMAX > 1
					resident = 1;
#endif /* SOCKD_REQUESTMAX > 1 */
#endif  /* HAVE_LIBWRAP */
					break;

				case CHILD_IO:
#if HAVE_LIBWRAP
#if SOCKD_IOMAX > 1
					resident = 1;
#endif /* SOCKD_IOMAX > 1 */
#endif  /* HAVE_LIBWRAP */
					break;

				default:
					SERRX(type);
			}

			sigemptyset(&sigact.sa_mask);
			sigact.sa_flags	= 0;

			/* signals mother has set up but which we ignore at this point. */
			sigact.sa_handler = SIG_IGN;

#if HAVE_SIGNAL_SIGINFO
			if (sigaction(SIGINFO, &sigact, NULL) != 0)
				swarn("%s: sigaction(SIGINFO)", function);
#endif  /* HAVE_SIGNAL_SIGINFO */

			if (sigaction(SIGUSR1, &sigact, NULL) != 0)
				swarn("%s: sigaction(USR1)", function);

			/* delete everything we got from parent. */
			for (i = 0, maxfd = getdtablesize(); i < maxfd; ++i) {
				/* exceptions */
				if (i == (size_t)mother.s
#if HAVE_SENDMSG_DEADLOCK
				||	i == (size_t)mother.lock
#endif /* HAVE_SENDMSG_DEADLOCK */
				||	i == (size_t)mother.ack)
					continue;

				if (descriptorisreserved((int)i))
					continue;

				close((int)i);
			}
			errno = 0;
			newprocinit(); /* called after closing, since it may open it's own. */

			childfunction(&mother);
			/* NOTREACHED */
		}

		default: {
			struct sockd_child_t *newchildv;

			sockscf.state.pid = ourpid;

			if ((newchildv = (struct sockd_child_t *)realloc(*childv,
			sizeof(**childv) * (*childc + 1))) == NULL) {
				slog(LOG_WARNING, "%s: %s", function, NOMEM);
				closev(pipev, ELEMENTS(pipev));
				closev(ackpipev, ELEMENTS(ackpipev));
				return NULL;
			}
			*childv = newchildv;

			(*childv)[*childc].type	= type;
			(*childv)[*childc].pid	= pid;
			(*childv)[*childc].s		= pipev[MOTHER];
#if HAVE_SENDMSG_DEADLOCK
			(*childv)[*childc].lock	= mother.lock;
#endif /* HAVE_SENDMSG_DEADLOCK */
			(*childv)[*childc].ack	= ackpipev[MOTHER];

			close(pipev[CHILD]);
			close(ackpipev[CHILD]);

			switch ((*childv)[*childc].type) {
				case CHILD_NEGOTIATE:
					(*childv)[*childc].freec = SOCKD_NEGOTIATEMAX;
					break;

				case CHILD_REQUEST:
					(*childv)[*childc].freec = SOCKD_REQUESTMAX;
					break;

				case CHILD_IO:
					(*childv)[*childc].freec = SOCKD_IOMAX;
					break;

				default:
					SERRX((*childv)[*childc].type);
			}

			return &(*childv)[(*childc)++];
		}
	}
}

int
childcheck(type)
	int type;
{
	int child, proxyc;
	int min, max, idle;
	struct sockd_child_t **childv;
	int *childc;

	switch (type) {
		case -CHILD_NEGOTIATE:
		case CHILD_NEGOTIATE:
			childc	= &negchildc;
			childv	= &negchildv;
			min		= SOCKD_FREESLOTS;
			max		= SOCKD_NEGOTIATEMAX;
			break;

		case -CHILD_REQUEST:
		case CHILD_REQUEST:
			childc	= &reqchildc;
			childv	= &reqchildv;
			min		= SOCKD_FREESLOTS;
			max		= SOCKD_REQUESTMAX;
			break;

		case -CHILD_IO:
		case CHILD_IO:
			childc	= &iochildc;
			childv	= &iochildv;
			/* attempt to keep in a state where we can accept all requests. */
			min		= MAX(SOCKD_FREESLOTS, childcheck(-CHILD_REQUEST));
			max		= SOCKD_IOMAX;
			break;

		default:
			SERRX(type);
	}

	/*
	 * get a estimate over how many (new) clients our children are able to
	 * accept in total.
    */
	for (child = idle = proxyc = 0; child < *childc; ++child) {
		SASSERTX((*childv)[child].freec <= max);
		proxyc += type < 0 ? max : (*childv)[child].freec;

		if ((*childv)[child].freec == max) {
			++idle;

			if (sockscf.child.maxidle > 0 && idle > sockscf.child.maxidle) {
				/* will remove this next, no longer part of free slots pool. */
				proxyc -= type < 0 ? max : (*childv)[child].freec;

				removechild((*childv)[child].pid);
				--idle;
				--child; /* everything was shifted once to the left. */
			}
		}
	}

	if (type >= 0)
		if (proxyc < min && sockscf.child.addchild)
			if (addchild(type) != NULL)
				return childcheck(type);
			else
				sockscf.child.addchild = 0;	/* don't retry until a child dies. */

	return proxyc;
}

int
fillset(set)
	fd_set *set;
{
	const char *function = "fillset()";
	int negc, reqc, ioc;
	int i, dbits;

	/*
	 * There is no point in setting data descriptor of child N unless
	 * child N+1 is able to accept the data from child N.  So find
	 * out if we have slots of the various types available .
	 */

	ioc	= childcheck(CHILD_IO);
	reqc	= childcheck(CHILD_REQUEST);
	negc	= childcheck(CHILD_NEGOTIATE);

	FD_ZERO(set);
	dbits = -1;

	/* new clients we accept. */
	if (negc > 0)
		for (i = 0; i < sockscf.internalc; ++i) {
			SASSERTX(sockscf.internalv[i].s >= 0);
			FD_SET(sockscf.internalv[i].s, set);
			dbits = MAX(dbits, sockscf.internalv[i].s);
		}
	else
		swarn("can't accept new clients, no free negotiate slots");

	/* negotiator children. */
	for (i = 0; i < negchildc; ++i) {
		if (reqc > 0) {
			SASSERTX(negchildv[i].s >= 0);
			FD_SET(negchildv[i].s, set);
			dbits = MAX(dbits, negchildv[i].s);
		}

		/* we can always accept an ack ofcourse. */
		SASSERTX(negchildv[i].ack >= 0);
		FD_SET(negchildv[i].ack, set);
		dbits = MAX(dbits, negchildv[i].ack);
	}

	/* request children. */
	for (i = 0; i < reqchildc; ++i) {
		if (ioc > 0) {
			SASSERTX(reqchildv[i].s >= 0);
			FD_SET(reqchildv[i].s, set);
			dbits = MAX(dbits, reqchildv[i].s);
		}

		/* we can always accept an ack ofcourse. */
		SASSERTX(reqchildv[i].ack >= 0);
		FD_SET(reqchildv[i].ack, set);
		dbits = MAX(dbits, reqchildv[i].ack);
	}

	/* io children, last in chain. */
	for (i = 0; i < iochildc; ++i) {
		SASSERTX(iochildv[i].s >= 0);
		FD_SET(iochildv[i].s, set);
		dbits = MAX(dbits, iochildv[i].s);

		SASSERTX(iochildv[i].ack >= 0);
		FD_SET(iochildv[i].ack, set);
		dbits = MAX(dbits, iochildv[i].ack);
	}

	return dbits;
}

void
clearset(type, child, set)
	int type;
	const struct sockd_child_t *child;
	fd_set *set;
{

	switch (type) {
		case SOCKD_FREESLOT:
			FD_CLR(child->ack, set);
			break;

		case SOCKD_NEWREQUEST:
			FD_CLR(child->s, set);
			break;

		default:
			SERRX(type);
	}
}


struct sockd_child_t *
getset(type, set)
	int type;
	fd_set *set;
{
	int i;

	/* check negotiator children for match. */
	for (i = 0; i < negchildc; ++i)
		switch (type) {
			case SOCKD_NEWREQUEST:
				if (FD_ISSET(negchildv[i].s, set))
					return &negchildv[i];
				break;

			case SOCKD_FREESLOT:
				if (FD_ISSET(negchildv[i].ack, set))
					return &negchildv[i];
				break;
		}

	/* check request children for match. */
	for (i = 0; i < reqchildc; ++i)
		switch (type) {
			case SOCKD_NEWREQUEST:
				if (FD_ISSET(reqchildv[i].s, set))
					return &reqchildv[i];
				break;

			case SOCKD_FREESLOT:
				if (FD_ISSET(reqchildv[i].ack, set))
					return &reqchildv[i];
				break;
		}

	/* check io children for match. */
	for (i = 0; i < iochildc; ++i)
		switch (type) {
			case SOCKD_NEWREQUEST:
				if (FD_ISSET(iochildv[i].s, set))
					return &iochildv[i];
				break;

			case SOCKD_FREESLOT:
				if (FD_ISSET(iochildv[i].ack, set))
					return &iochildv[i];
				break;
		}

	return NULL;
}


int
removechild(pid)
	pid_t pid;
{
	const char *function = "removechild()";
	struct sockd_child_t **childv;
	struct sockd_child_t *newchildv;
	int *childc;
	int child;

	slog(LOG_DEBUG, "%s: %d", function, (int)pid);

	setchildtype(childtype(pid), &childv, &childc, NULL);

	child = findchild(pid, *childc, *childv);
	SASSERTX(child >= 0);

	close((*childv)[child].s);
	close((*childv)[child].ack);

	/* shift all following one down */
	while (child < *childc - 1) {
		(*childv)[child] = (*childv)[child + 1];
		++child;
	}
	--*childc;

	if ((newchildv = (struct sockd_child_t *)realloc(*childv,
	sizeof(**childv) * (*childc + 1))) == NULL) {
		slog(LOG_WARNING, NOMEM);
		return -1;
	}
	*childv = newchildv;

	return 0;
}

struct sockd_child_t *
nextchild(type)
	int type;
{
	const char *function = "nextchild()";
	struct timeval timeout;
	struct sockd_child_t **childv;
	int *childc;
	int i, maxd;
	fd_set wset;

	setchildtype(type, &childv, &childc, NULL);

	FD_ZERO(&wset);
	for (i = 0, maxd = -1; i < *childc; ++i)
		if ((*childv)[i].freec > 0) {
			FD_SET((*childv)[i].s, &wset);
			maxd = MAX(maxd, (*childv)[i].s);
		}

	if (maxd < 0)
		return NULL;
	++maxd;

	timeout.tv_sec		= 0;
	timeout.tv_usec	= 0;

	switch (selectn(maxd, NULL, &wset, NULL, &timeout)) {
		case -1:
			SERR(-1);
			/* NOTREACHED */

		case 0:
			slog(LOG_DEBUG, "%s: no child writable", function);
			return NULL;
	}

	return getset(SOCKD_NEWREQUEST, &wset);
}


static int
setchildtype(type, childv, childc, function)
	int type;
	struct sockd_child_t ***childv;
	int **childc;
	void (**function)(struct sockd_mother_t *mother);
{

	switch (type) {
		case CHILD_IO:
			if (childv != NULL)
				*childv = &iochildv;

			if (childc != NULL)
				*childc = &iochildc;

			if (function != NULL)
				*function = &run_io;

			break;

		case CHILD_NEGOTIATE:
			if (childv != NULL)
				*childv = &negchildv;

			if (childc != NULL)
				*childc = &negchildc;

			if (function != NULL)
				*function = &run_negotiate;

			break;

		case CHILD_REQUEST:
			if (childv != NULL)
				*childv = &reqchildv;

			if (childc != NULL)
				*childc = &reqchildc;

			if (function != NULL)
				*function = &run_request;

			break;

		default:
			SASSERTX(type);
	}

	return type;
}

int
childtype(pid)
	pid_t pid;
{

	if (findchild(pid, iochildc, iochildv) != -1)
		return CHILD_IO;

	if (findchild(pid, negchildc, negchildv) != -1)
		return CHILD_NEGOTIATE;

	if (findchild(pid, reqchildc, reqchildv) != -1)
		return CHILD_REQUEST;

	if (pidismother(pid))
		return CHILD_MOTHER;

	SERRX(pid);
	/* NOTREACHED */
}

static int
findchild(pid, childc, childv)
	pid_t pid;
	int childc;
	const struct sockd_child_t *childv;
{
	int i;

	for (i = 0; i < childc; ++i)
		if (childv[i].pid == pid)
			return i;

	return -1;
}

struct sockd_child_t *
getchild(pid)
	pid_t pid;
{
	int child, type;
	int *childc;
	struct sockd_child_t **childv;

	switch (type = childtype(pid)) {
		case CHILD_IO:
		case CHILD_NEGOTIATE:
		case CHILD_REQUEST:
			break;

		case CHILD_MOTHER:
			return NULL;

		default:
			SERRX(type);
	}

	setchildtype(type, &childv, &childc, NULL);

	if ((child = findchild(pid, *childc, *childv)) != -1)
		return &(*childv)[child];
	return NULL;
}

int
send_io(s, io)
	int s;
	const struct sockd_io_t *io;
{
	const char *function = "send_io()";
	struct iovec iovec[1];
	struct msghdr msg;
	int w, fdsent, length;
	CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);


	length = 0;
	/* LINTED operands have incompatible pointer types */
	iovec[0].iov_base		= (void *)io;
	iovec[0].iov_len		= sizeof(*io);
	length				  += iovec[0].iov_len;

	fdsent = 0;
	CMSG_ADDOBJECT(io->src.s, cmsg, sizeof(io->src.s) * fdsent++);
	CMSG_ADDOBJECT(io->dst.s, cmsg, sizeof(io->dst.s) * fdsent++);

	switch (io->state.command) {
		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (!io->state.extension.bind)
				break;
			/* else: */ /* FALLTHROUGH */

		case SOCKS_UDPASSOCIATE:
			CMSG_ADDOBJECT(io->control.s, cmsg, sizeof(io->control.s) * fdsent++);
			break;

		case SOCKS_CONNECT:
			break;

		default:
			SERRX(io->state.command);
	}

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

	CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

	if ((w = sendmsg(s, &msg, 0)) != length)	{
		swarn("%s: sendmsg(): %d of %d", function, w, length);
		return -1;
	}

#if HARDCORE_DEBUG
	printfd(io, "sent");
#endif

	return 0;
}


int
send_client(s, client)
	int s;
	int client;
{
	const char *function = "send_client()";
	const char command = SOCKD_NEWREQUEST;
	struct iovec iovec[1];
	struct msghdr msg;
	CMSG_AALLOC(cmsg, sizeof(int));
	int fdsent;

	/* LINTED operands have incompatible pointer types */
	iovec[0].iov_base		= (void *)&command;
	iovec[0].iov_len		= sizeof(command);

	fdsent = 0;
	CMSG_ADDOBJECT(client, cmsg, sizeof(client) * fdsent++);

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

	CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

	if (sendmsg(s, &msg, 0) != sizeof(command))	{
		swarn("%s: sendmsg()", function);
		return -1;
	}

	return 0;
}

int
send_req(s, req)
	int s;
	const struct sockd_request_t *req;
{
	const char *function = "send_req()";
	struct iovec iovec[1];
	struct msghdr msg;
	int fdsent;
	CMSG_AALLOC(cmsg, sizeof(int));

	/* LINTED operands have incompatible pointer types */
	iovec[0].iov_base		= (void *)req;
	iovec[0].iov_len		= sizeof(*req);

	fdsent = 0;
	CMSG_ADDOBJECT(req->s, cmsg, sizeof(req->s) * fdsent++);

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

	CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

	if (sendmsg(s, &msg, 0) != sizeof(*req))	{
		swarn("%s: sendmsg()", function);
		return -1;
	}

	return 0;
}

void
sigchildbroadcast(sig, childtype)
	int sig;
	int childtype;
{
	int i;

	if (childtype & CHILD_NEGOTIATE)
		for (i = 0; i < negchildc; ++i)
			kill(negchildv[i].pid, sig);

	if (childtype & CHILD_REQUEST)
		for (i = 0; i < reqchildc; ++i)
			kill(reqchildv[i].pid, sig);

	if (childtype & CHILD_IO)
		for (i = 0; i < iochildc; ++i)
			kill(iochildv[i].pid, sig);
}

#if DEBUG
void
printfd(io, prefix)
	const struct sockd_io_t *io;
	const char *prefix;
{
	const char *function = "printfd()";
	struct sockaddr name;
	socklen_t namelen;
	char namestring[MAXSOCKADDRSTRING];

	bzero(&name, sizeof(name));
	namelen = sizeof(name);
	/* LINTED pointer casts may be troublesome */
	if (getsockname(io->src.s, &name, &namelen) != 0)
		swarn("%s: getsockname(io->src)", function);
	else
		slog(LOG_DEBUG, "%s: io->src (%d), name: %s", prefix,
		io->src.s, sockaddr2string(&name, namestring, sizeof(namestring)));

	bzero(&name, sizeof(name));
	namelen = sizeof(name);
	/* LINTED pointer casts may be troublesome */
	if (getsockname(io->dst.s, &name, &namelen) != 0)
		swarn("%s: getsockname(io->dst)", function);
	else
		slog(LOG_DEBUG, "%s: io->dst (%d), name: %s", prefix, io->dst.s,
		sockaddr2string(&name, namestring, sizeof(namestring)));

	switch (io->state.command) {
		case SOCKS_BIND:
		case SOCKS_BINDREPLY:
			if (!io->state.extension.bind)
				break;
			/* else: */ /* FALLTHROUGH */

		case SOCKS_UDPASSOCIATE:
			bzero(&name, sizeof(name));
			namelen = sizeof(name);
			/* LINTED pointer casts may be troublesome */
			if (getpeername(io->control.s, &name, &namelen)
			!= 0)
				swarn("%s: getpeername(io->control)", function);
			else  {
				if (namelen == 0)
					slog(LOG_DEBUG, "%s: io->control (%d), name: <none>",
					prefix, io->control.s);
				else
					slog(LOG_DEBUG, "%s: io->control (%d), name: %s",
					prefix, io->control.s,
					sockaddr2string(&name, namestring, sizeof(namestring)));
			}
			break;

		case SOCKS_CONNECT:
			break;

		default:
			SERRX(io->state.command);
	}
}
#endif
