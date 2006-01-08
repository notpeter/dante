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
"$Id: log.c,v 1.68 2005/12/31 17:56:55 michaels Exp $";

__BEGIN_DECLS

static char *
logformat __P((int priority, char *buf, size_t buflen, const char *message,
				   va_list ap));
/*
 * formats "message" as appropriate.  The formated message is stored
 * in the buffer "buf", which is of size "buflen".  
 * If no newline is present at the end of the string, one is added.
 * Returns:
 *		On success: pointer to "buf".
 *		On failure: NULL.
 */

__END_DECLS

void
newprocinit(void)
{

#if SOCKS_SERVER	/* don't want to override original clients stuff. */
	sockscf.state.pid = getpid();

	if (sockscf.log.type & LOGTYPE_SYSLOG) {
		closelog();

		/*
		 * LOG_NDELAY so we don't end up in a situation where we
		 * have no free descriptors and haven't yet syslog-ed anything.
		 */
		openlog(__progname, LOG_NDELAY | LOG_PID, sockscf.log.facility);
	}
#endif /* SOCKS_SERVER */

#if SOCKSLIBRARY_DYNAMIC
	symbolcheck();
#endif
}

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
	int logged = 0;


	if (sockscf.log.type & LOGTYPE_SYSLOG)
		if ((sockscf.state.init && priority != LOG_DEBUG)
		|| (priority == LOG_DEBUG && sockscf.option.debug)) {
			vsyslog(priority, message, ap);
			logged = 1;
		}

	if (sockscf.log.type & LOGTYPE_FILE) {
		size_t i;

		if (logformat(priority, buf, sizeof(buf), message, ap) == NULL)
			return;

		for (i = 0; i < sockscf.log.fpc; ++i) {
#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC /* XXX should not need SOCKS_CLIENT. */
			SYSCALL_START(fileno(sockscf.log.fpv[i]));
#endif

#if DEBUG
			if (getenv("NO_SLOG_LOCK") == NULL)
#endif
				socks_lock(sockscf.log.fplockv[i], F_WRLCK, -1);

			fprintf(sockscf.log.fpv[i], "%s", buf);

#if DEBUG
			if (getenv("NO_SLOG_LOCK") == NULL)
#endif
				socks_unlock(sockscf.log.fplockv[i]);
			logged = 1;

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
			SYSCALL_END(fileno(sockscf.log.fpv[i]));
#endif
		}
	}

	if (!logged && !sockscf.state.init) { /* may not have set-up logfiles yet. */
#if SOCKS_SERVER /* log to stdout for now. */
		if (logformat(priority, buf, sizeof(buf), message, ap) != NULL)
			fprintf(stdout, "%s", buf);
		return;
#else /* SOCKS_CLIENT */ /* no idea where stdout points to in client case. */
#endif /* SOCKS_SERVER */
	}

	errno = errno_s;
}

static char *
logformat(priority, buf, buflen, message, ap)
	int priority;
	char *buf;
	size_t buflen;
	const char *message;
	va_list ap;
{
	size_t bufused;
	time_t timenow;
	pid_t pid;

	if (sockscf.state.pid == 0)
		pid = getpid();
	else
		pid = sockscf.state.pid;

	switch (priority) {
		case LOG_DEBUG:
			if (sockscf.state.init && !sockscf.option.debug)
				return NULL;
			break;

	}

	time(&timenow);
	bufused = strftime(buf, buflen, "%h %e %T ", localtime(&timenow));

	bufused += snprintfn(&buf[bufused], buflen - bufused, "(%ld) %s[%lu]: ",
	(long)timenow, __progname, (unsigned long)pid);


	vsnprintf(&buf[bufused], buflen - bufused, message, ap);
	bufused = strlen(buf);

	if (buf[bufused - 1] != '\n') { /* add ending newline. */
		bufused = MIN(bufused, buflen - 2); /* silently truncate. */
		buf[bufused++] = '\n';
		buf[bufused++] = NUL;
	}

	return buf;
}
