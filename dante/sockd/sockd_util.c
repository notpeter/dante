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
"$Id: sockd_util.c,v 1.27 1998/11/13 21:19:02 michaels Exp $";

#include "common.h"

extern char *__progname;

int
selectmethod(methodv, methodc)
	const unsigned char *methodv;
	int methodc;
{
	int i;

	for (i = 0; i < config.methodc; ++i)		
		if (memchr(methodv, config.methodv[i], (size_t)methodc) != NULL)
			return config.methodv[i];

	return AUTHMETHOD_NOACCEPT;	/* no acceptable method found. */
}

void
initlog(void)
{

	if (config.log.type & LOGTYPE_SYSLOG) {
		closelog();
		if (config.option.debug)
#ifdef HAVE_OPENLOG_LOG_PERROR
			(void) openlog(__progname, LOG_PID | LOG_PERROR, LOG_DAEMON);
#else
			(void) openlog(__progname, LOG_PID, LOG_DAEMON);
#endif  /* HAVE_OPENLOG_LOG_PERROR */
		else
			(void) openlog(__progname, LOG_PID, LOG_DAEMON);

	}

	if (config.log.type & LOGTYPE_FILE)
		;
}

void
terminate_connection(s, auth)
	int s;
	const struct authmethod_t *auth;
{

	close(s);
}

