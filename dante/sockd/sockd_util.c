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
"$Id: sockd_util.c,v 1.47 1999/07/05 07:04:40 michaels Exp $";

#define SOCKS_DEBUGER	0

#define CM2IM(charmethodv, methodc, intmethodv) \
	do { \
		int cm2im = methodc; \
		while (--cm2im >= 0) \
			intmethodv[cm2im] = charmethodv[cm2im]; \
	} while (lintnoloop_sockd_h) \

int
selectmethod(methodv, methodc)
	const unsigned char *methodv;
	size_t methodc;
{
	const char stdmethodv[] = {AUTHMETHOD_NONE, AUTHMETHOD_UNAME};
	int i;

	for (i = 0; i < config.methodc; ++i) {

		if (config.methodv[i] > AUTHMETHOD_NOACCEPT) { /* pseudo method */
			int intmethodv[AUTHMETHOD_MAX];

			CM2IM(methodv, methodc, intmethodv);

			switch (config.methodv[i]) {
				case AUTHMETHOD_RFC931: {
					/* can select any standard method. */
					size_t ii;
					
					for (ii = 0; ii < ELEMENTS(stdmethodv); ++i)
						if (methodisset(stdmethodv[i], intmethodv, methodc))
							return stdmethodv[i];
					break;
				}

				default:
					SERRX(config.methodv[i]);
			}
		}

		if (memchr(methodv, (unsigned char)config.methodv[i], (size_t)methodc)
		!= NULL)
			return config.methodv[i];
	}

	return AUTHMETHOD_NOACCEPT;
}

void
setsockoptions(s)
	int s;
{
	const char *function = "setsockoptions()";
	socklen_t len;
	int type, val;

	len = sizeof(type);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len) != 0)
		return;

	switch (type) {
		case SOCK_STREAM:
			val = 1;
			if (setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &val, sizeof(val))
			!= 0)
				swarn("%s: setsockopt(SO_OOBINLINE)", function);

			if (config.option.keepalive) {
				val = 1;
				if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &val,
				sizeof(val)) != 0)
					swarn("%s: setsockopt(SO_KEEPALIVE)", function);
			}

		break;
	}

#ifdef SO_BSDCOMPAT
	val = 1;
	if (setsockopt(s, SOL_SOCKET, SO_BSDCOMPAT, &val, sizeof(val)) != 0)
		swarn("%s: setsockopt(SO_BSDCOMPAT)", function);
#endif /* SO_BSDCOMPAT */

}

void
sockdexit(sig)
	int sig;
{
	int i;

	if (sig > 0)
		slog(LOG_ALERT, "terminating on signal %d", sig);

	for (i = 0;  i < config.log.fpc; ++i) {
		fclose(config.log.fpv[i]);
		close(config.log.fplockv[i]);
	}

	if (sig > 0)
		switch (sig) {
			/* ok signals. */
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				exit(EXIT_FAILURE);
				/* NOTREACHED */

			/* bad signals. */
			default:
				abort();
		}
	else
		if (*config.state.motherpidv == config.state.pid) /* main mother. */
			exit(-sig);
		else
			_exit(-sig);
}

void
socks_seteuid(old, new)
	uid_t *old;
	uid_t new;
{
	const char *function = "socks_seteuid()";
	uid_t oldmem;

	if (old == NULL)
		old = &oldmem;
	*old = geteuid();

	slog(LOG_DEBUG, "%s: old: %lu, new: %lu", function, *old, new); 

	if (*old == new)
		return;

#if !SOCKS_DEBUGER
	if (*old != config.state.euid)
		/* need to revert back to original (presumably 0) euid before changing. */
		if (seteuid(config.state.euid) != 0) {
			slog(LOG_ERR, "running linux are we?");
			SERR(config.state.euid);
		}

	if (seteuid(new) != 0)
		serr(EXIT_FAILURE, "%s: seteuid(%d)", function, new);
#endif /* !SOCKS_DEBUGER */
}

void
socks_reseteuid(current, new)
	uid_t current;
	uid_t new;
{
	const char *function = "socks_reseteuid()"; 

	slog(LOG_DEBUG, "%s: current: %lu, new: %lu", function, current, new); 

#if !SOCKS_DEBUGER && DIAGNOSTIC 
	SASSERTX(current == geteuid());
#endif /* DIAGNOSTIC */

	if (current == new)
		return;

#if !SOCKS_DEBUGER
	if (new != config.state.euid)
		/* need to revert back to original (presumably 0) euid before changing. */
		if (seteuid(config.state.euid) != 0)
			SERR(config.state.euid);

	if (seteuid(new) != 0)
		SERR(new);
#endif
}

#if SOCKS_DEBUGER
/* ARGSUSED */
int
setuid(uid)
	uid_t uid;
{
	return 0;
}
#endif /* SOCKS_DEBUGER */

int
passwordmatch(name, clearpassword)
	const char *name;
	const char *clearpassword;
{
/*	const char *function = "passwordmatch()"; */
	struct passwd *pw;
	char *salt, *password;
	uid_t euid;
	int match;

	socks_seteuid(&euid, config.uid.privileged);
	if ((pw = getpwnam(name)) == NULL) {
		/* XXX waste cycles correctly? */
		salt 		= "*";
		password = "*";
		match = 0;
	}
	else {
		salt 		= pw->pw_passwd;
		password = pw->pw_passwd;
		match 	= 1;
	}
	socks_reseteuid(config.uid.privileged, euid);

	if (clearpassword != NULL)
		if (strcmp(crypt(clearpassword, salt), password) == 0)
			match = 1;
		else
			match = 0;

	if (!match)
		/* XXX should get passed higher up somehow. */
		if (pw == NULL)
			slog(LOG_INFO, "denied non-existing user access: %s", name);
		else
			slog(LOG_INFO, "password authentication failed for user: %s", name);

	return match;
}

