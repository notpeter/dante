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
"$Id: authneg.c,v 1.33 1998/11/13 21:18:01 michaels Exp $";

#include "common.h"

int
negotiate_method(s, packet)
	int s;
	struct socks_t *packet;
{
	const char *function = "negotiate_method()";
	int rc;

	/* version, number of methods, the methods. */
	char request[1 + 1 + METHODS_MAX];

	/* length of actual request; version, nmethods, methods. */
	const size_t requestlen = 1 + 1 + *packet->methodc;

	/* reply; version, selected method. */
	unsigned char response[1 + 1];


	SASSERTX(*packet->methodc > 0);

	/* create request packet. */
	request[AUTH_VERSION] 	= packet->req.version;
	request[AUTH_NMETHODS]	= *packet->methodc;
	memcpy(&request[AUTH_METHODS], packet->methodv, (size_t)*packet->methodc);

	/* send list over methods we support */
	if (writen(s, request, requestlen) != requestlen)
		return -1;

	/* read servers response for method to use */
	if (readn(s, response, sizeof(response)) != sizeof(response))
		return -1;

	if (request[AUTH_VERSION] != response[AUTH_VERSION]) {
		swarnx("%s: got reply version %d, expected %d",
      function, response[AUTH_VERSION], request[AUTH_VERSION]);
		errno = ECONNREFUSED;
		return -1;
	}
	packet->version = request[AUTH_VERSION];

	switch (packet->auth->method = response[AUTH_METHOD]) {
		case AUTHMETHOD_NONE: 
			rc = 0;
			break;

		case AUTHMETHOD_UNAME:
			if (clientmethod_uname(s, packet->req.version) == 0)
				rc = 0;
			else
				rc = -1;
			break;

		case AUTHMETHOD_NOACCEPT: 
			swarnx("%s: server accepted no authentication method",
			function);
			rc = -1;
			break;

		default:
			swarnx("%s: server selected wrong method: %d", 
			function, response[AUTH_METHOD]);
			rc = -1;
	}

	if (rc == 0) {
		slog(LOG_DEBUG,
		"%s: established SOCKS v%d connection using authentication method %d",
		function, packet->version, packet->auth->method);
	}
	else
		errno = ECONNREFUSED;

	return rc;
}
