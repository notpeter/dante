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
"$Id: client.c,v 1.24 1999/02/20 19:18:46 michaels Exp $";

#include "common.h"

struct config_t config;
const int configtype = CONFIGTYPE_CLIENT;

int
SOCKSinit(progname)
	char *progname;
{

#ifdef HAVE_PROGNAME
	extern char *__progname;

	__progname = progname;
#endif /* HAVE_PROGNAME */

	return 0;
}

void
clientinit(void)
{
	const char *function = "clientinit()";
	int i;
	FILE *fp;

	if (config.state.init)
		return;

	if (issetugid()) 
		config.option.configfile = SOCKS_CONFIGFILE;
	else
		if ((config.option.configfile = getenv("SOCKS_CONF")) == NULL)
			config.option.configfile = SOCKS_CONFIGFILE;

	if ((fp = fopen(config.option.configfile, "r")) == NULL)
		serr(1, "%s: %s", function, config.option.configfile);

	if (readconfig(fp) != 0)
		return;
	
	config.option.lbuf = 1;
	if (config.option.lbuf)
		for (i = 0; i < config.log.fpc; ++i)
			if (setvbuf(config.log.fpv[i], NULL, _IONBF, 0) != 0)
				swarnx("%s: setvbuf()", function);

	config.state.pid  				= getpid();
	config.state.init 				= 1;
}


int
serverreplyisok(version, reply)
	int version;
	int reply;
{
	const char *function = "serverreplyisok()";

	switch (version) {
		case SOCKS_V4:
			switch (reply) {
				case SOCKSV4_SUCCESS:
					return 1;

				case SOCKSV4_FAIL:
					errno = ECONNREFUSED;
					return 0;

				case SOCKSV4_NO_IDENTD:
					swarnx("%s: socksserver failed to get your identd response",
					function);
					errno = ECONNREFUSED;
					return 0;

				case SOCKSV4_BAD_ID:
					swarnx("%s: socksserver claims username/ident mismatch",
					function);
					errno = ECONNREFUSED;
					return 0;

				default:
					swarnx("%s: unknown v%d reply from socksserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					return 0;
			}

		case SOCKS_V5:
			switch (reply) {
				case SOCKS_SUCCESS: 
					return 1;
					
				case SOCKS_FAILURE:
					swarnx("%s: unknown socksserver failure", function);
					errno = ECONNREFUSED;
					return 0;
					
				case SOCKS_NOTALLOWED:
					swarnx("%s: connection denied by socksserver", function);
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
					swarnx("%s: command not supported by socksserver", function);
					errno = ECONNREFUSED;
					return 0;
						 
				case SOCKS_ADDR_UNSUPP:
					swarnx("%s: address type not supported by remote socksserver",
					function);
					errno = ECONNREFUSED;
					return 0;
					
				default:
					swarnx("%s: unknown v%d reply from socksserver: %d",
					function, version, reply);
					errno = ECONNREFUSED;
					return 0;
			}

		case MSPROXY_V2:
			switch (reply) {
				case MSPROXY_SUCCESS:
					return 1;

				case MSPROXY_FAILURE: 
					return 0;
				
				default:
					SERRX(reply);
			}
			break;

		default:
			SERRX(version);
	}

	/* NOTREACHED */
}
