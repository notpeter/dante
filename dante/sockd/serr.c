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
"$Id: serr.c,v 1.7 2003/07/01 13:21:31 michaels Exp $";

void
#ifdef STDC_HEADERS
serr(int eval, const char *fmt, ...)
#else
serr(eval, fmt, va_alist)
	int eval;
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{

	if (fmt != NULL) {
		va_list ap;
		char buf[2048];
		size_t bufused;

#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

		bufused = vsnprintf(buf, sizeof(buf), fmt, ap);

		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused,
		": %s (errno = %d)", strerror(errno), errno);

		slog(LOG_ERR, "%s", buf);

		/* LINTED expression has null effect */
		va_end(ap);
	}

#if SOCKS_SERVER
	sockdexit(-eval);
#else
	exit(eval);
#endif
}

void
#ifdef STDC_HEADERS
serrx(int eval, const char *fmt, ...)
#else
serrx(eval, fmt, va_alist)
      int eval;
      const char *fmt;
      va_dcl
#endif  /* STDC_HEADERS */
{

	if (fmt != NULL) {
		va_list ap;

#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */
		vslog(LOG_ERR, fmt, ap);

		/* LINTED expression has null effect */
		va_end(ap);
	}

#if SOCKS_SERVER
	sockdexit(-eval);
#else
	exit(eval);
#endif
}

void
#ifdef STDC_HEADERS
swarn(const char *fmt, ...)
#else
swarn(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{

	if (fmt != NULL) {
		va_list ap;
		char buf[2048];
		size_t bufused;

#ifdef STDC_HEADERS
	/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

		bufused = vsnprintf(buf, sizeof(buf), fmt, ap);

		bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused,
		": %s (errno = %d)", strerror(errno), errno);

		slog(LOG_ERR, "%s", buf);

		/* LINTED expression has null effect */
		va_end(ap);
	}
}

void
#ifdef STDC_HEADERS
swarnx(const char *fmt, ...)
#else
swarnx(fmt, va_alist)
	const char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{

	if (fmt != NULL) {
		va_list ap;

#ifdef STDC_HEADERS
		/* LINTED pointer casts may be troublesome */
		va_start(ap, fmt);
#else
		va_start(ap);
#endif  /* STDC_HEADERS */

		vslog(LOG_ERR, fmt, ap);

		/* LINTED expression has null effect */
		va_end(ap);
	}
}
