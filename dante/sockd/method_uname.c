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
"$Id: method_uname.c,v 1.38 2001/04/20 13:11:27 michaels Exp $";

__BEGIN_DECLS

static int
recv_unamever __P((int s, struct request_t *request,
						 struct negotiate_state_t *state));

static int
recv_ulen __P((int s, struct request_t *request,
					struct negotiate_state_t *state));

static int
recv_uname __P((int s, struct request_t *request,
					 struct negotiate_state_t *state));

static int
recv_plen __P((int s, struct request_t *request,
					struct negotiate_state_t *state));

static int
recv_passwd __P((int s, struct request_t *request,
					  struct negotiate_state_t *state));

__END_DECLS

int
method_uname(s, request, state)
	int s;
	struct request_t *request;
	struct negotiate_state_t *state;

{

	state->rcurrent = recv_unamever;
	return state->rcurrent(s, request, state);
}

static int
recv_unamever(s, request, state)
	int s;
	struct request_t *request;
	struct negotiate_state_t *state;
{

	INIT(sizeof(request->auth->mdata.uname.version));
	CHECK(&request->auth->mdata.uname.version, request->auth, NULL);

	switch (request->auth->mdata.uname.version) {
		case SOCKS_UNAMEVERSION:
			break;

		default:
			slog(LOG_DEBUG, "unknown version on uname packet from client: %d",
			request->auth->mdata.uname.version);
			return -1;
	}

	state->rcurrent = recv_ulen;
	return state->rcurrent(s, request, state);
}


static int
recv_ulen(s, request, state)
	int s;
	struct request_t *request;
	struct negotiate_state_t *state;
{

	INIT(sizeof(*request->auth->mdata.uname.name));
	CHECK(request->auth->mdata.uname.name, request->auth, NULL);

	/* LINTED conversion from 'int' may lose accuracy */
	OCTETIFY(*request->auth->mdata.uname.name);

	state->rcurrent = recv_uname;

	return state->rcurrent(s, request, state);
}


static int
recv_uname(s, request, state)
	int s;
	struct request_t *request;
	struct negotiate_state_t *state;
{
	const size_t ulen = (size_t)*request->auth->mdata.uname.name;

	INIT(ulen);
	CHECK(request->auth->mdata.uname.name + 1, request->auth, NULL);

	/* convert to string. */
	memcpy(request->auth->mdata.uname.name, request->auth->mdata.uname.name + 1,
	ulen);
	request->auth->mdata.uname.name[ulen] = NUL;

	state->rcurrent = recv_plen;

	return state->rcurrent(s, request, state);
}

static int
recv_plen(s, request, state)
	int s;
	struct request_t *request;
	struct negotiate_state_t *state;
{

	INIT(sizeof(*request->auth->mdata.uname.password));
	CHECK(request->auth->mdata.uname.password, request->auth, NULL);

	/* LINTED conversion from 'int' may lose accuracy */
	OCTETIFY(*request->auth->mdata.uname.password);

	state->rcurrent = recv_passwd;

	return state->rcurrent(s, request, state);
}


static int
recv_passwd(s, request, state)
	int s;
	struct request_t *request;
	struct negotiate_state_t *state;
{
/*	const char *function = "recv_passwd()"; */
	const size_t plen = (size_t)*request->auth->mdata.uname.password;
	unsigned char response[1				/* version. */
								+ 1				/* status.	*/
	];

	INIT(plen);
	CHECK(request->auth->mdata.uname.password + 1, request->auth, NULL);

	/* convert to string. */
	memcpy(request->auth->mdata.uname.password,
	request->auth->mdata.uname.password + 1, plen);
	request->auth->mdata.uname.password[plen] = NUL;

	/*
	 * Very sadly we can't do any checking of the username/password here since
	 * we don't know what database to use, it depends on what the socks
	 request is.
	*/
	response[UNAME_VERSION] = request->auth->mdata.uname.version;
	response[UNAME_STATUS]	= (unsigned char)0;

	if (writen(s, response, sizeof(response), request->auth)
	!= sizeof(response))
		return -1;

	state->rcurrent = recv_sockspacket;
	return state->rcurrent(s, request, state);
}
