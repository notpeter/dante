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
"$Id: userio.c,v 1.23 2003/07/01 13:21:33 michaels Exp $";

/* ARGSUSED */
char *
socks_getusername(host, buf, buflen)
	const struct sockshost_t *host;
	char *buf;
	size_t buflen;
{
	const char *function = "socks_getusername()";
	char *name;

	if ((name = getenv("SOCKS_USERNAME"))	!= NULL
	||  (name = getenv("SOCKS_USER"))		!= NULL
	||  (name = getenv("SOCKS5_USER"))		!= NULL)
		;
	else if ((name = getlogin()) != NULL)
		;
	else {
		struct passwd *pw;

		if ((pw = getpwuid(getuid())) != NULL)
			name = pw->pw_name;
	}

	if (name == NULL)
		return NULL;

	if (strlen(name) >= buflen) {
		swarnx("%s: socks username %d characters too long, truncated",
		function, (strlen(name) + 1) - buflen);
		name[buflen - 1] = NUL;
	}

	strcpy(buf, name);

	return buf;
}

char *
socks_getpassword(host, user, buf, buflen)
	const struct sockshost_t *host;
	const char *user;
	char *buf;
	size_t buflen;
{
	const char *function = "socks_getpassword()";
	char *password;

	if ((password = getenv("SOCKS_PASSWORD"))		!= NULL
	||  (password = getenv("SOCKS_PASSWD"))		!= NULL
	||  (password = getenv("SOCKS5_PASSWD"))		!= NULL)
		;
	else {
		char prompt[256 + MAXSOCKSHOSTSTRING];
		char hstring[MAXSOCKSHOSTSTRING];

		snprintfn(prompt, sizeof(prompt), "%s@%s sockspassword: ",
		user, sockshost2string(host, hstring, sizeof(hstring)));
		password = getpass(prompt);
	}

	if (password == NULL)
		return NULL;

	if (strlen(password) >= buflen) {
		swarnx("%s: socks password %d characters too long, truncated",
		function, (strlen(password) + 1) - buflen);
		password[buflen - 1] = NUL;
	}

	strcpy(buf, password);
	bzero(password, strlen(password));

	return buf;
}
