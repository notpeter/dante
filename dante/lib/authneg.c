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
"$Id: authneg.c,v 1.59 2005/10/13 12:17:17 michaels Exp $";

int
negotiate_method(s, packet)
	int s;
	struct socks_t *packet;
{
	const char *function = "negotiate_method()";
	unsigned char *name = NULL, *password = NULL;
	int rc;
	unsigned char request[ 1						/* version					*/
								+ 1						/* number of methods.	*/
								+ AUTHMETHOD_MAX		/* the methods.			*/
								];
	size_t requestlen = 0;	

	unsigned char response[ 1	/* version.				*/
								 + 1	/* selected method.	*/
								 ];

	SASSERTX(packet->gw.state.methodc > 0);

	/* create request packet. */

	request[requestlen++] = packet->req.version;

	if (packet->auth.method != AUTHMETHOD_NOTSET) {
		/* authmethod already fixed. */
		request[requestlen++] = (unsigned char)1;
		request[requestlen++] = (unsigned char)packet->auth.method;

		switch (packet->auth.method) {
			case AUTHMETHOD_UNAME:
				name 		= packet->auth.mdata.uname.name;
				password = packet->auth.mdata.uname.password;
				break;
		}
	}
	else {
		request[requestlen++]	= (unsigned char)packet->gw.state.methodc;
		for (rc = 0; rc < (int)packet->gw.state.methodc; ++rc)
			request[requestlen++] 
			= (unsigned char)packet->gw.state.methodv[rc];
	}

	/* send list over methods we support */
	if (writen(s, request, requestlen, &packet->auth) != (ssize_t)requestlen)
		return -1;

	/* read servers response for method it wants to use */
	if ((rc = readn(s, response, sizeof(response), &packet->auth))
	!= sizeof(response)){
		swarn("%s: readn(), %d out of %d", function,rc, sizeof(response));
		return -1;
	}

	if (request[AUTH_VERSION] != response[AUTH_VERSION]) {
		swarnx("%s: got replyversion %d, expected %d",
      function, response[AUTH_VERSION], request[AUTH_VERSION]);
		errno = ECONNREFUSED;
		return -1;
	}

	packet->version		= request[AUTH_VERSION];
	packet->auth.method	= response[AUTH_METHOD];

	switch (packet->auth.method) {
		case AUTHMETHOD_NONE:
			rc = 0;
			break;

		case AUTHMETHOD_UNAME:
			if (clientmethod_uname(s, &packet->gw.host, packet->req.version, name,
			password) == 0)
				rc = 0;
			else
				rc = -1;
			break;

		case AUTHMETHOD_NOACCEPT:
			swarnx("%s: server accepted no authentication method", function);
			rc = -1;
			break;

		default:
			swarnx("%s: server selected method not offered: %d",
			function, response[AUTH_METHOD]);
			rc = -1;
	}

	if (rc == 0) {
		slog(LOG_DEBUG,
		"%s: established socks v%d connection using authentication method %d",
		function, packet->version, packet->auth.method);
	}
	else
		errno = ECONNREFUSED;

	return rc;
}
