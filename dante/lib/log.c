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
 *  N-0371 Oslo
 *  Norway
 * 
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

static const char rcsid[] =
"$Id: log.c,v 1.26 1999/03/11 16:59:33 karls Exp $";

#include "common.h"

#ifdef HAVE_PROGNAME
extern char *__progname;
#endif  /* HAVE_PROGNAME */

__BEGIN_DECLS

static char *
logformat __P((int priority, char *buf, size_t buflen, const char *message,
			 va_list ap));
/*
 * formats "message" as appropriate.  The formated message is stored 
 * in the buffer "buf", which is of size "buflen".
 * Returns:
 * 	On success: pointer to "buf"
 *		On failure: NULL.
*/

__END_DECLS

void
#ifdef STDC_HEADERS
slog(int priority, const char *message, ...)
#else
slog(priority, message, va_alist)
	int priority;
	char *message;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;

#ifdef STDC_HEADERS
	/* LINTED pointer casts may be troublesome */
	va_start(ap, message);
#else
	va_start(ap);
#endif  /* STDC_HEADERS */

	vslog(priority, message, ap);

	/* LINTED expression has null effect */
	va_end(ap);
}

void
vslog(priority, message, ap)
	int priority;
	const char *message;
	va_list ap;
{
	const int errno_s = errno;
	char buf[2048];
	
	if (!config.state.init) {
		if (logformat(priority, buf, sizeof(buf), message, ap) != NULL)
			fprintf(stdout, "%s\n", buf);
		return;
	}

	if (config.log.type & LOGTYPE_SYSLOG) 
		vsyslog(priority, message, ap);

	if (config.log.type & LOGTYPE_FILE) {
		int i;

		if (logformat(priority, buf, sizeof(buf), message, ap) == NULL)
			return;

		for (i = 0; i < config.log.fpc; ++i) {
			if (socks_lock(config.log.fplockv[i], F_WRLCK, -1) != 0)
				continue; /* XXX need some way to log this. */
			fprintf(config.log.fpv[i], "%s\n", buf);
			socks_unlock(config.log.fplockv[i], 0);
		}
	}

	errno = errno_s;
}

char *
logformat(priority, buf, buflen, message, ap)
	int priority;
	char *buf;
	size_t buflen;
	const char *message;
	va_list ap;
{
	const char *prefix;
	time_t timenow;
	size_t bufused;

	/* not sure if we should use this. */
	switch (priority) {
		case LOG_EMERG:
			prefix = "*** EMERGENCY: ";
			break;

		case LOG_ALERT:
			prefix = "*** ALERT: ";
			break;

		case LOG_CRIT:
			prefix = "*** Critical: ";
			break;

		case LOG_ERR:
			prefix = "error: ";
			break;

		case LOG_WARNING:
			prefix = "warning: ";
			break;

		case LOG_NOTICE:
			prefix = "notice: ";
			break;

		case LOG_INFO:
			prefix = "info: ";
			break;

		case LOG_DEBUG:
			if (config.state.init && !config.option.debug)
				return NULL;

			prefix = "debug: ";
			break;

		default:
			prefix = "";
	}

	time(&timenow);
	bufused = strftime(buf, buflen, "%h %e %T ", localtime(&timenow));

#ifdef HAVE_PROGNAME
	bufused += snprintf(&buf[bufused], buflen - bufused, "%s[%lu]: ",
	__progname, (unsigned long)getpid());
#else
	bufused += snprintf(&buf[bufused], buflen - bufused, "[%lu]: ",
	(unsigned long)getpid());
#endif  /* HAVE_PROGNAME */

	vsnprintf(&buf[bufused], buflen - bufused, message, ap);

	return buf;
}
