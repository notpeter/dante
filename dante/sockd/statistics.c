/*
 * Copyright (c) 2011, 2012
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
"$Id: statistics.c,v 1.7 2012/06/01 20:23:06 karls Exp $";

/*
 * If it takes longer than this from the time the request child sends the
 * client to mother til we receive the client from mother we are probably
 * overloaded.
 */
static const struct timeval maxdelay = { 0, 100000 };

int sockd_isoverloaded(description, tsent, treceived, tnow)
   const char *description;
   const struct timeval *tsent;
   const struct timeval *treceived;
   const struct timeval *tnow;
{
   const char *function = "sockd_isoverloaded()";
   struct timeval tdiff;

   timersub(treceived, tsent, &tdiff);
   if (timercmp(&tdiff, &maxdelay, >)) {
      static struct timeval tlastwarn;
      struct timeval tsincelastwarn;

      timersub(tnow, &tlastwarn, &tsincelastwarn);
      if (tsincelastwarn.tv_sec >= 1) {
         slog(LOG_INFO, "%s: overload condition detected regarding %s.  "
                        "Used %ld.%06lds to receive a new client object, but "
                        "the maximum expected delay is %ld.%06lds.",
                        function, description,
                        (long)tdiff.tv_sec, (long)tdiff.tv_usec,
                        (long)maxdelay.tv_sec, (long)maxdelay.tv_usec);

         tlastwarn = *tnow;
         return 1;
      }
   }

   return 0;
}
