/*
 * Copyright (c) 1997, 1998, 1999, 2001, 2003, 2008
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
"$Id: sockd_socket.c,v 1.51 2009/10/02 17:55:05 michaels Exp $";

int
sockd_bind(s, addr, retries)
   int s;
   struct sockaddr *addr;
   size_t retries;
{
   const char *function = "sockd_bind()";
   int p;

   errno = 0;
   while (1) { /* CONSTCOND */
      /* LINTED pointer casts may be troublesome */
      if (PORTISRESERVED(TOIN(addr)->sin_port)) {
         sockd_priv(SOCKD_PRIV_NET_ADDR, PRIV_ON);
         p = bind(s, addr, sizeof(*addr));
         sockd_priv(SOCKD_PRIV_NET_ADDR, PRIV_OFF);
      }
      else
         p = bind(s, addr, sizeof(*addr));

      if (p == 0) {
         socklen_t addrlen = sizeof(*addr);
         p = getsockname(s, addr, &addrlen);

         break;
      }

      /* else;  non-fatal error and retry? */
      switch (errno) {
         case EINTR:
            continue; /* don't count this attempt. */

         case EADDRINUSE:
            slog(LOG_DEBUG, "%s: failed to bind %s: %s%s",
            function, sockaddr2string(addr, NULL, 0), strerror(errno),
            retries ? ", retrying" : "");

            if (retries--) {
               sleep(1);
               continue;
            }
            break;

         case EACCES:
            slog(LOG_DEBUG,
                 "%s: failed to bind %s: %s",
                 function, sockaddr2string(addr, NULL, 0), strerror(errno));
            break;
      }

      break;
   }

   return p;
}

int
sockd_bindinrange(s, addr, first, last, op)
   int s;
   struct sockaddr *addr;
   in_port_t first, last;
   const enum operator_t op;
{
   const char *function = "sockd_bindinrange()";
   in_port_t port;
   int exhausted;

   slog(LOG_DEBUG, "%s: %s %u %s %u",
                   function, sockaddr2string(addr, NULL, 0),
                   ntohs(first), operator2string(op), ntohs(last));


   /*
    * use them in hostorder to make it easier, only convert before bind.
    */
   port       = 0;
   first      = ntohs(first);
   last       = ntohs(last);
   exhausted  = 0;
   do {
      if (port + 1 == 0) /* wrapped. */
         exhausted = 1;

      /* find next port to try. */
      switch (op) {
         case none:
            port = 0; /* any port is good. */
            break;

         case eq:
            port = first;
            break;

         case neq:
            if (++port == first)
               ++port;
            break;

         case ge:
            if (port < first)
               port = first;
            else
               ++port;
            break;

         case gt:
            if (port <= first)
               port = first + 1;
            else
               ++port;
            break;

         case le:
            if (++port > first)
               exhausted = 1;
            break;

         case lt:
            if (++port >= first)
               exhausted = 1;
            break;

         case range:
            if (port < first)
               port = first;
            else
               ++port;

            if (port > last)
               exhausted = 1;
            break;

         default:
            SERRX(op);
      }

      if (exhausted) {
         slog(LOG_DEBUG, "%s: exhausted search for port to bind in range "
                         "%u %s %u",
                         function, first, operator2string(op), last);
         return -1;
      }

      TOIN(addr)->sin_port = htons(port);
      if (sockd_bind(s, addr, 0) == 0)
         return 0;

      if (op == eq || op == none)
         break; /* nothnig to retrying on these. */
   } while (!exhausted);

   return -1;
}
