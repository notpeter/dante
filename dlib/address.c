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
"$Id: address.c,v 1.83 2003/07/01 13:21:24 michaels Exp $";

__BEGIN_DECLS

static struct socksfd_t socksfdinit;
static int *dv;
static unsigned int dc;
static struct socksfd_t *socksfdv;
static unsigned int socksfdc;

static int
socks_sigblock __P((sigset_t *oldmask));
/*
 * Blocks signals that can change socksfdv, writing the old
 *	signalmask to "oldmask".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

__END_DECLS

struct socksfd_t *
socks_addaddr(clientfd, socksfd)
	unsigned int clientfd;
	struct socksfd_t *socksfd;
{
	const char *function = "socks_addaddr()";

#if 0 /* DEBUG */
	if (socksfd->state.command != -1 && !socksfd->state.system)
		slog(LOG_DEBUG, "%s: %d", function, clientfd);
#endif

	SASSERTX(socksfd->state.command		== -1
	||	 socksfd->state.command				== SOCKS_BIND
	||	 socksfd->state.command				== SOCKS_CONNECT
	||	 socksfd->state.command				== SOCKS_UDPASSOCIATE);

	if (socks_addfd(clientfd) != 0)
		serrx(EXIT_FAILURE, "%s: error adding descriptor %d", function, clientfd);

	if (socksfdc < dc) { /* init/reallocate */
		sigset_t oldmask;

		if (socksfdinit.control == 0) {	/* not initialized */
			socksfdinit.control = -1;
			/* other members have ok default value. */
		}

		if (socks_sigblock(&oldmask) != 0)
			return NULL;

		if ((socksfdv = (struct socksfd_t *)realloc(socksfdv,
		sizeof(*socksfdv) * dc)) == NULL)
			serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);

		/* init new objects */
		while (socksfdc < dc)
			socksfdv[socksfdc++] = socksfdinit;

		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
			swarn("%s: sigprocmask()", function);
	}

	switch (socksfd->state.command) {
		case SOCKS_BIND:
#if SOCKS_TRYHARDER
			if ((socksfd->state.lock = socks_mklock(SOCKS_LOCKFILE)) == -1)
				swarn("%s: socks_mklock()", function);
#endif
			break;
	}

	socksfdv[clientfd] = *socksfd;
	socksfdv[clientfd].allocated = 1;

	return &socksfdv[clientfd];
}


struct socksfd_t *
socks_getaddr(d)
	unsigned int d;
{
	if (socks_isaddr(d))
		return &socksfdv[d];
	return NULL;
}

void
socks_rmaddr(d)
	unsigned int d;
{
/*	const char *function = "socks_rmaddr()";  */

#if 0 /* DEBUG */
	if (!socks_isaddr(d)
	|| (!socksfdv[d].state.command != -1 && !socksfdv[d].state.system))
		slog(LOG_DEBUG, "%s: %d", function, d);
#endif

	if (!socks_isaddr(d))
		return;

	socks_rmfd(d);

	switch (socksfdv[d].state.version) {
		case MSPROXY_V2:
			if (socksfdv[d].control != -1)
				close(socksfdv[d].control);
			break;

		case SOCKS_V4:
		case SOCKS_V5:
		case HTTP_V1_0:
			if (!socksfdv[d].state.system)
				switch (socksfdv[d].state.command) {
					case SOCKS_BIND:
						if (socksfdv[d].control == -1
						||  socksfdv[d].control == (int)d)
							break;

						/*
						 * If we are using the bind extension it's possible
						 * that this controlconnection is shared with other
						 * (accept()'ed) addresses, if so we must leave it
						 * open for the other connections.
						*/
						if (socks_addrcontrol(&socksfdv[d].local, &socksfdv[d].remote)
						== -1)
							break;

						close(socksfdv[d].control);
						break;

					case SOCKS_CONNECT:
						break; /* no separate controlconnection. */

					case SOCKS_UDPASSOCIATE:
						if (socksfdv[d].control != -1)
							close(socksfdv[d].control);
						break;

					default:
						SERRX(socksfdv[d].state.command);
				}

			switch (socksfdv[d].state.command) {
				case SOCKS_BIND:
#if SOCKS_TRYHARDER
					if (close(socksfdv[d].state.lock) != 0)
						swarn("socks_rmaddr()");
#endif
					break;
			}
	}

	socksfdv[d] = socksfdinit;
}

int
socks_isaddr(d)
	unsigned int d;
{

	if (d < socksfdc && socksfdv[d].allocated)
		return 1;
	return 0;
}

int
socks_addrisok(s)
	unsigned int s;
{
	const char *function = "socks_addrisok()";
	const int errno_s = errno;
	int matched;
	sigset_t oldmask;

	if (socks_sigblock(&oldmask) != 0)
		return 0;

	matched = 0;
	do {
		struct socksfd_t *socksfd;
		struct sockaddr local;
		socklen_t locallen;

		locallen = sizeof(local);
		if (getsockname((int)s, &local, &locallen) != 0)
			break;

		socksfd = socks_getaddr(s);

		if (socksfd != NULL) {
			if (!sockaddrareeq(&local, &socksfd->local))
				break;

			/* check remote endpoint too? */

			matched = 1;
		}
		else { /* unknown descriptor.  Try to check whether it's a dup. */
			int duped;

			if ((duped = socks_addrmatch(&local, NULL, NULL)) != -1) {
				struct socksfd_t nsocksfd;

				socksfd = socksfddup(socks_getaddr((unsigned int)duped), &nsocksfd);

				if (socksfd == NULL) {
					swarn("%s: socksfddup()", function);
					break;
				}

				socks_addaddr(s, socksfd);
				matched = 1;
			}
			break;
		}
	/* CONSTCOND */
	} while (0);

	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
		swarn("%s: sigprocmask()", function);

	errno = errno_s;

	return matched;
}

int
socks_addrcontrol(local, remote)
	const struct sockaddr *local;
	const struct sockaddr *remote;
{
	unsigned int i;

	for (i = 0; i < socksfdc; ++i) {
		struct sockaddr localcontrol, remotecontrol;

		if (!socks_isaddr((unsigned int)i))
			continue;

		if (local != NULL) {
			socklen_t len = sizeof(localcontrol);
			if (getsockname(socksfdv[i].control, &localcontrol, &len) != 0)
				continue;

			if (!sockaddrareeq(local, &localcontrol))
				continue;
		}

		if (remote != NULL) {
			socklen_t len = sizeof(remotecontrol);
			if (getpeername(socksfdv[i].control, &remotecontrol, &len) != 0)
				continue;

			if (!sockaddrareeq(remote, &remotecontrol))
				continue;
		}

		return i;
	}

	return -1;
}

int
socks_addrmatch(local, remote, state)
	const struct sockaddr *local;
	const struct sockaddr *remote;
	const struct socksstate_t *state;
{
	unsigned int i;

	for (i = 0; i < socksfdc; ++i) {
		if (!socks_isaddr(i))
			continue;

		/*
		 * only compare fields that have a valid value in request to compare
		 * against.
		 */

		if (local != NULL)
			if (!sockaddrareeq(local, &socksfdv[i].local))
				continue;

		if (remote != NULL)
			if (!sockaddrareeq(remote, &socksfdv[i].remote))
				continue;

		if (state != NULL) {
			if (state->version != -1)
				if (state->version != socksfdv[i].state.version)
					continue;

			if (state->command != -1)
				if (state->command != socksfdv[i].state.command)
					continue;

			if (state->inprogress != -1)
				if (state->inprogress != socksfdv[i].state.inprogress)
					continue;

			if (state->acceptpending != -1)
				if (state->acceptpending != socksfdv[i].state.acceptpending)
					continue;
		}

		return i;
	}

	return -1;
}


int
socks_addfd(d)
	unsigned int d;
{
	const char *function = "socks_addfd()";

	if (d + 1 < d) /* integer overflow. */
		return -1;

	if (d >= dc)	{ /* init/reallocate */
		sigset_t oldmask;
		int *newfdv;
		unsigned int newfdc;

		if (socks_sigblock(&oldmask) != 0)
			return -1;

		newfdc = MAX(d + 1, (unsigned int)getdtablesize());
		if ((newfdv = (int *)realloc(dv, sizeof(*dv) * newfdc)) == NULL)
			serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
		dv = newfdv;

		/* init all to -1, a illegal value for a d. */
		while (dc < newfdc)
			dv[dc++] = -1;

		if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
			swarn("%s: sigprocmask()", function);
	}

	dv[d] = d;

	return 0;
}

int
socks_isfd(d)
	unsigned int d;
{
	if (d >= dc || dv[d] == -1)
		return 0;
	return 1;
}

void
socks_rmfd(d)
	unsigned int d;
{
	if (socks_isfd(d))
		dv[d] = -1;
}

struct socksfd_t *
socksfddup(old, new)
	const struct socksfd_t *old;
	struct socksfd_t *new;
{

	*new = *old;	/* init most stuff. */

	switch (old->state.command) {
		case SOCKS_BIND:
		case SOCKS_UDPASSOCIATE:
			if ((new->control = socketoptdup(old->control)) == -1)
				return NULL;
			break;

		case SOCKS_CONNECT:
			/* only descriptor for connect is the one client has. */
			break;

		default:
			SERRX(old->state.command);
	}

	return new;
}

static int
socks_sigblock(oldmask)
	sigset_t *oldmask;
{
	const char *function = "socks_sigblock()";
	sigset_t newmask;

	/*
	 * block signals that might change socksfd.
	 */

	sigemptyset(&newmask);
	sigaddset(&newmask, SIGIO);
	sigaddset(&newmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &newmask, oldmask) != 0) {
		swarn("%s: sigprocmask()", function);
		return -1;
	}

	return 0;
}

#if 0
void
ccinit(void)
{
	const char *function = "cc()";
	struct sigaction sigact;
	struct itimerval itimer;

	slog(LOG_DEBUG, function);

	if (sigaction(SIGALRM, NULL, &sigact) != 0) {
		swarn("%s: sigaction(SIGALRM)", function);
		return;
	}

	if (sigact.sa_handler != SIG_DFL
	&&  sigact.sa_handler != SIG_IGN) {
		swarnx("%s: could not install signalhandler for SIGALRM, already set",
		function);
		return;
	}

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_RESTART;
	sigact.sa_handler = cc_socksfdv;

	if (sigaction(SIGALRM, &sigact, NULL) != 0) {
		swarn("%s: sigaction(SIGALRM)", function);
		return;
	}

	itimer.it_interval.tv_sec		= 1;
	itimer.it_interval.tv_usec		= 0;
	itimer.it_value.tv_sec			= 1;
	itimer.it_value.tv_usec			= 1;

	if (setitimer(ITIMER_REAL, &itimer, NULL) != 0)
		swarn("%s: setitimer()", function);
}
#endif

#if DIAGNOSTIC
void
cc_socksfdv(sig)
	int sig;
{
	unsigned int i;

	for (i = 0; i < socksfdc; ++i) {
		if (!socksfdv[i].allocated)
			continue;

		if (socksfdv[i].state.system)
			SERRX(i);
	}
}
#endif /* DIAGNOSTIC */
