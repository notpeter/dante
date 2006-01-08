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
"$Id: accesscheck.c,v 1.23 2005/10/28 13:33:04 michaels Exp $";


int
usermatch(auth, userlist)
	const struct authmethod_t *auth;
	const struct linkedname_t *userlist;
{
/*	const char *function = "usermatch()"; */
	const char *name;

	switch (auth->method) {
		case AUTHMETHOD_UNAME:
			name		= (const char *)auth->mdata.uname.name;
			break;

		case AUTHMETHOD_RFC931:
			name		= (const char *)auth->mdata.rfc931.name;
			break;

		case AUTHMETHOD_PAM:
			name		= (const char *)auth->mdata.pam.name;
			break;

		default:
			/*
			 * adding non-username based methods to rules requiring usernames
			 * should not be possible.
			*/
			SERRX(auth->method);
	}

	do
		if (strcmp(name, userlist->name) == 0)
			break;
	while ((userlist = userlist->next) != NULL);

	if (userlist == NULL)
		return 0; /* no match. */
	return 1;
}


/* ARGSUSED */
int
accesscheck(s, auth, src, dst, emsg, emsgsize)
	int s;
	struct authmethod_t *auth;
	const struct sockaddr *src, *dst;
	char *emsg;
	size_t emsgsize;
{
	const char *function = "accesscheck()";
	char srcstr[MAXSOCKADDRSTRING], dststr[sizeof(srcstr)];
	int match;

	slog(LOG_DEBUG, "%s: method: %s, %s -> %s ",
	function, method2string(auth->method),
	src == NULL ? "<unknown>" : sockaddr2string(src, srcstr, sizeof(srcstr)),
	dst == NULL ? "<unknown>" : sockaddr2string(dst, dststr, sizeof(dststr)));

	/*
	 * We don't want to re-check the same method.  This could
	 * happen in several cases:
	 *  - was checked as client-rule, is now checked as socks-rule.
	 *  - a different rule with the same method.
	*/

	if (methodisset(auth->method, auth->methodv, (size_t)auth->methodc))
		return 1; /* already checked, matches. */

	if (methodisset(auth->method, auth->badmethodv, (size_t)auth->badmethodc))
		return 0; /* already checked, won't match. */

	match = 0;
	switch (auth->method) {
		case AUTHMETHOD_NONE:
			match = 1;
			break;

		case AUTHMETHOD_UNAME:
			if (passwordcheck((const char *)auth->mdata.uname.name,
			(const char *)auth->mdata.uname.password, emsg, emsgsize) == 0)
				match = 1;
			break;

		case AUTHMETHOD_RFC931:
			if (passwordcheck((const char *)auth->mdata.rfc931.name, NULL, emsg,
			emsgsize) == 0)
				match = 1;
			break;

#if HAVE_PAM
		case AUTHMETHOD_PAM: {
#if DIAGNOSTIC
			const int freec = freedescriptors(sockscf.option.debug ?
			"start" : NULL);
#endif /* DIAGNOSTIC */

			if (pam_passwordcheck(s, src, dst, &auth->mdata.pam, emsg, emsgsize)
			== 0)
				match = 1;

#if DIAGNOSTIC
			if (freec != freedescriptors(sockscf.option.debug ?  "end" : NULL))
				serrx(EXIT_FAILURE,
				"the PAM library/module code on your system seems to be messing "
				"with our descriptors, can't cope with that.  Get the PAM code "
				"on your system fixed");
#endif /* DIAGNOSTIC */
			break;
		}
#endif /* HAVE_PAM */

		default:
			SERRX(auth->method);
	}

	switch (auth->method) {
		/*
		 * Some methods can be called with different values for the
		 * same client, others can not.  Mark those who can't as
		 * "tried" so we don't waste time on re-trying them.
		 */
#if HAVE_PAM
		case AUTHMETHOD_PAM:
			if (sockscf.state.pamservicename == NULL) /* varies. */
				break;
			/* else; */ /* FALLTHROUGH */
#endif

		case AUTHMETHOD_NONE:
		case AUTHMETHOD_UNAME:
		case AUTHMETHOD_RFC931:
			if (match) {
				SASSERTX(auth->methodc + 1 <= sizeof(auth->methodv));
				auth->methodv[auth->methodc++] = auth->method;
			}
			else {
				SASSERTX(auth->badmethodc + 1 <= sizeof(auth->badmethodv));
				auth->badmethodv[auth->badmethodc++] = auth->method;
			}

			/*
			 * We might have wanted to bzero() the password here, but
			 * then we wouldn't be able to use the password if we
			 * at a later point needed to check for access against
			 * a different method.  (For instance, PAM on setup,
			 * UNAME on UDP packet.  Strange, but in theory possible.)
			 */
			break;
	}

	return match;
}
