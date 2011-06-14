/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2008, 2009, 2010
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
"$Id: serr.c,v 1.36 2011/06/13 09:55:00 michaels Exp $";

#if SOCKS_CLIENT
/* for errors, we want it logged. */
#undef SOCKS_IGNORE_SIGNALSAFETY
#define SOCKS_IGNORE_SIGNALSAFETY (1)
#endif /* SOCKS_CLIENT */

void
serr(int eval, const char *fmt, ...)
{

   if (fmt != NULL) {
      va_list ap;
      char buf[2048];
      int bufused;

      va_start(ap, fmt);

      bufused = vsnprintf(buf, sizeof(buf), fmt, ap);
      va_end(ap);

      if (errno != 0)
         snprintf(&buf[bufused], sizeof(buf) - bufused,
                  ": %s (errno = %d)",
                  strerror(errno), errno);

      slog(LOG_ERR, "%s", buf);
   }

#if SOCKS_CLIENT
   exit(eval);
#else
   sockdexit(eval);
#endif /* SOCKS_CLIENT */
}

void
serrx(int eval, const char *fmt, ...)
{

   if (fmt != NULL) {
      va_list ap, apcopy;

      va_start(ap, fmt);
      va_start(apcopy, fmt);

      vslog(LOG_ERR, fmt, ap, apcopy);

      /* LINTED expression has null effect */
      va_end(apcopy);
      va_end(ap);
   }

#if SOCKS_CLIENT
   exit(eval);
#else
   sockdexit(eval);
#endif /* SOCKS_CLIENT */
}

void
swarn(const char *fmt, ...)
{

   if (fmt != NULL) {
      va_list ap;
      char buf[2048];
      int bufused;

   /* LINTED pointer casts may be troublesome */
      va_start(ap, fmt);

      bufused = vsnprintf(buf, sizeof(buf), fmt, ap);

      if (errno != 0)
         snprintf(&buf[bufused], sizeof(buf) - bufused,
                  ": %s (errno = %d)",
                  strerror(errno), errno);

      slog(LOG_WARNING, "%s", buf);

      /* LINTED expression has null effect */
      va_end(ap);
   }
}

void
swarnx(const char *fmt, ...)
{

   if (fmt != NULL) {
      va_list ap, apcopy;

      /* LINTED pointer casts may be troublesome */
      va_start(ap, fmt);
      va_start(apcopy, fmt);

      vslog(LOG_WARNING, fmt, ap, apcopy);

      /* LINTED expression has null effect */
      va_end(apcopy);
      va_end(ap);
   }
}
