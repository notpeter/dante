/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2005, 2008, 2009
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
"$Id: authneg.c,v 1.89 2009/09/25 09:47:22 michaels Exp $";

int
negotiate_method(s, packet, route)
   int s;
   struct socks_t *packet;
   struct route_t *route;
{
   const char *function = "negotiate_method()";
   size_t requestlen;
   unsigned char *name = NULL, *password = NULL;
   unsigned char request[ 1                  /* version              */
                        + 1                  /* number of methods.   */
                        + AUTHMETHOD_MAX     /* the methods.         */
                        ];
   unsigned char response[ 1   /* version.            */
                         + 1   /* selected method.   */
                         ];
   char buf[256];
   int rc, intmethodv[MAXMETHOD];

   if (sockscf.option.debug)
      slog(LOG_DEBUG, "%s: socket %d, %s",
      function, s, socket2string(s, buf, sizeof(buf)));

   SASSERTX(packet->gw.state.methodc > 0);

   /*
    * create request packet.
    */

   requestlen            = 0;
   request[requestlen++] = packet->req.version;

   if (packet->req.auth->method == AUTHMETHOD_NOTSET) {
      /* send list over all methods we support. */
      request[requestlen++] = (unsigned char)packet->gw.state.methodc;
      for (rc = 0; rc < (int)packet->gw.state.methodc; ++rc)
         request[requestlen++] = (unsigned char)packet->gw.state.methodv[rc];
   }
   else {
      /* authmethod already fixed. */
      request[requestlen++] = (unsigned char)1;
      request[requestlen++] = (unsigned char)packet->req.auth->method;
   }

   CM2IM(request[AUTH_NMETHODS], &request[AUTH_METHODS], intmethodv);
   slog(LOG_DEBUG, "%s: offering proxy server %d method%s: %s",
   function, request[AUTH_NMETHODS], request[AUTH_NMETHODS] == 1 ? "" : "s",
   methods2string(request[AUTH_NMETHODS], intmethodv, buf, sizeof(buf)));

   if (socks_sendton(s, request, requestlen, requestlen, 0, NULL, 0,
   packet->req.auth) != (ssize_t)requestlen) {
      swarn("%s: could not send list over methods to socks server", function);
      return -1;
   }

   if ((rc = socks_recvfromn(s, response, sizeof(response), sizeof(response),
   0, NULL, NULL, packet->req.auth)) != sizeof(response)) {
      swarn("%s: could not read server response for method to use, read %d/%ld",
      function, rc, (long)sizeof(response));

      socks_blacklist(route);

      if (errno == 0)
         errno = ECONNREFUSED; /* if nothing else ... something is wrong. */

      return -1;
   }

   /*
    * sanitycheck servers reply.
    */

   if (request[AUTH_VERSION] != response[AUTH_VERSION]) {
      swarnx("%s: got replyversion %d, expected %d",
      function, response[AUTH_VERSION], request[AUTH_VERSION]);

      errno = ECONNREFUSED;
      socks_blacklist(route);

      return -1;
   }
   packet->version = request[AUTH_VERSION];

   if (!methodisset(response[AUTH_METHOD], intmethodv, request[AUTH_NMETHODS]))
   {
      if (response[AUTH_METHOD] == AUTHMETHOD_NOACCEPT)
         slog(LOG_DEBUG, "%s: server said we did not offer any acceptable "
                         "authentication method",
              function);
      else
         swarnx("%s: proxy server selected method 0x%x, but that is not among "
                "the methods we offered it",
                function, response[AUTH_METHOD]);

      errno = ECONNREFUSED;
      socks_blacklist(route);

      return -1;
   }

   slog(LOG_DEBUG, "%s: proxy server selected method %s",
   function, method2string(response[AUTH_METHOD]));

   switch (response[AUTH_METHOD]) {
      case AUTHMETHOD_NONE:
         rc = 0;
         break;

#if HAVE_GSSAPI
      case AUTHMETHOD_GSSAPI:
         if (clientmethod_gssapi(s, packet->req.protocol, &packet->gw,
         packet->req.version, packet->req.auth) == 0)
            rc = 0;
         else
            rc = -1;
         break;
#endif /* HAVE_GSSAPI */

      case AUTHMETHOD_UNAME: {
         struct sockshost_t host;

         gwaddr2sockshost(&packet->gw.addr, &host);
         if (clientmethod_uname(s, &host, packet->req.version, name, password)
         == 0)
            rc = 0;
         else
            rc = -1;
         break;
      }

      case AUTHMETHOD_NOACCEPT:
#if SOCKS_SERVER
         slog(LOG_DEBUG, "%s: server accepted no offered authentication method",
         function);
#else
         swarnx("%s: server accepted no authentication method", function);
         socks_blacklist(route);
#endif /* SOCKS_SERVER */

         rc = -1;
         break;

      default:
         SERRX(packet->req.auth->method);
   }

   packet->req.auth->method = response[AUTH_METHOD];

   if (rc == 0) {
      slog(LOG_DEBUG, "%s: established v%d connection using method %d",
      function, packet->version, packet->req.auth->method);

      errno = 0; /* all is ok. */
   }
   else {
      slog(LOG_DEBUG, "%s: failed to establish v%d connection using method %d",
      function, packet->version, packet->req.auth->method);

      if (errno == 0) /* set something to indicate an error. */
         errno = ECONNREFUSED;
   }

   return rc;
}
