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
"$Id: client.c,v 1.42 1999/09/02 10:41:25 michaels Exp $";

#if !HAVE_PROGNAME
	char *__progname = "danteclient";
#endif

int
SOCKSinit(progname)
	char *progname;
{

	__progname = progname;
	return 0;
}

void
clientinit(void)
{
/*	const char *function = "clientinit()"; */

	if (config.state.init)
		return;

	config.state.pid = getpid();

	if (issetugid())
		config.option.configfile = SOCKS_CONFIGFILE;
	else
		if ((config.option.configfile = getenv("SOCKS_CONF")) == NULL)
			config.option.configfile = SOCKS_CONFIGFILE;

	/*
	 * initialize misc options to sensible default.
 	 */
	config.resolveprotocol		= RESOLVEPROTOCOL_UDP;
	config.option.lbuf			= 1;

	genericinit();

	slog(LOG_INFO, "%s/client v%s running", PACKAGE, VERSION);
}


int
serverreplyisok(version, reply, route)
	int version;
	int reply;
	struct route_t *route;
{
	const char *function = "serverreplyisok()";

	switch (version) {
		case SOCKS_V4:
			switch (reply) {
				case SOCKSV4_SUCCESS:
					return 1;

				case SOCKSV4_FAIL:
					errno = ECONNREFUSED;
					break;

				case SOCKSV4_NO_IDENTD:
					swarnx("%s: proxyserver failed to get your identd response",
					function);
					errno = ECONNREFUSED;
					return 0;

				case SOCKSV4_BAD_ID:
					swarnx("%s: proxyserver claims username/ident mismatch",
					function);
					errno = ECONNREFUSED;
					return 0;

				default:
					swarnx("%s: unknown v%d reply from proxyserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					break;
			}
			break;

		case SOCKS_V5:
			switch (reply) {
				case SOCKS_SUCCESS:
					return 1;

				case SOCKS_FAILURE:
					swarnx("%s: unknown proxyserver failure", function);
					errno = ECONNREFUSED;
					break;

				case SOCKS_NOTALLOWED:
					swarnx("%s: connection denied by proxyserver", function);
					errno = ECONNREFUSED;
					return 0;

				case SOCKS_NETUNREACH:
					errno = ENETUNREACH;
					return 0;

				case SOCKS_HOSTUNREACH:
					errno = EHOSTUNREACH;
					return 0;

				case SOCKS_CONNREFUSED:
					errno = ECONNREFUSED;
					return 0;

				case SOCKS_TTLEXPIRED:
					errno = ETIMEDOUT;
					return 0;

				case SOCKS_CMD_UNSUPP:
					swarnx("%s: command not supported by proxyserver", function);
					errno = ECONNREFUSED;
					break;

				case SOCKS_ADDR_UNSUPP:
					swarnx("%s: address type not supported by proxyserver",
					function);
					errno = ECONNREFUSED;
					break;

				default:
					swarnx("%s: unknown v%d reply from proxyserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					break;
			}
			break;

		case MSPROXY_V2:
			switch (reply) {
				case MSPROXY_SUCCESS:
					return 1;

				case MSPROXY_FAILURE:
				case MSPROXY_CONNREFUSED:
					errno = ECONNREFUSED;
					return 0;

				case MSPROXY_NOTALLOWED:
					swarnx("%s: connection denied by proxyserver: authenticated?",
					function);
					errno = ECONNREFUSED;
					return 0;

				default:
					swarnx("%s: unknown v%d reply from proxyserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					return 0;
			}

		default:
			SERRX(version);
	}

	if (route != NULL)
		socks_badroute(route);

	return 0;
}
