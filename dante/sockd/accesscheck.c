/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001
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
"$Id: accesscheck.c,v 1.12 2001/12/11 14:31:31 karls Exp $";


/* ARGSUSED */
int
accessmatch(s, auth, src, dst, userlist, emsg, emsgsize)
	int s;
	struct authmethod_t *auth;
	const struct sockaddr *src, *dst;
	const struct linkedname_t *userlist;
	char *emsg;
	size_t emsgsize;
{
	const char *function = "accessmatch()";
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
		return 1; /* already matched. */

	if (methodisset(auth->method, auth->badmethodv, (size_t)auth->badmethodc))
		return 0; /* already checked, won't match. */

	if (userlist != NULL) {
		const struct linkedname_t *ruleuser;
		const char *name;

		/*
		 * The userlist names restricts access further, only names
		 * appearing there are checked.
		 */

		ruleuser = userlist;
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
			if (strcmp(name, ruleuser->name) == 0)
				break;
		while ((ruleuser = ruleuser->next) != NULL);

		if (ruleuser == NULL)
			return 0; /* no match. */
	}

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
		case AUTHMETHOD_PAM:
			if (pam_passwordcheck(s, src, dst, &auth->mdata.pam, emsg, emsgsize)
			== 0)
				match = 1;
			break;
#endif /* HAVE_PAM */

		default:
			SERRX(auth->method);
	}

	if (match) {
		SASSERTX(auth->methodc + 1 <= sizeof(auth->methodv));
		auth->methodv[auth->methodc++] = auth->method;
	}
	else {
		/*
		 * Some methods can be called with different values for the
		 * same client, others can not.  Mark those who can't as
		 * "bad" so we don't waste time on re-trying them.
		 */
		switch (auth->method) {
			case AUTHMETHOD_PAM:
				if (sockscf.state.unfixedpamdata)
					break;
				/* else; */ /* FALLTHROUGH */

			case AUTHMETHOD_NONE:
			case AUTHMETHOD_UNAME:
			case AUTHMETHOD_RFC931:
				SASSERTX(auth->badmethodc + 1 <= sizeof(auth->badmethodv));
				auth->badmethodv[auth->badmethodc++] = auth->method;
				break;
		}
	}

	return match;
}
