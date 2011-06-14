/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2005, 2008, 2009, 2010, 2011
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
"$Id: httpproxy.c,v 1.46 2011/05/18 13:48:46 karls Exp $";

int
httpproxy_negotiate(s, packet)
   int s;
   struct socks_t *packet;
{
   const char *function = "httpproxy_negotiate()";
   char buf[MAXHOSTNAMELEN + 512] /* The + 512 is for http babble. */,
        visbuf[sizeof(buf) * 4 + 1];
   char host[MAXSOCKSHOSTSTRING];
   int checked, eof;
   ssize_t len, rc;
   size_t readsofar;
   struct sockaddr addr;
   socklen_t addrlen;

   slog(LOG_DEBUG, "%s", function);

   sockshost2string(&packet->req.host, host, sizeof(host));

   /*
    * replace the dot that sockshost2string uses to separate port from host
    * with http's ':'.
    */
   *strrchr(host, '.') = ':';

   len = snprintf(buf, sizeof(buf),
                  "CONNECT %s %s\r\n"
                  "User-agent: %s/client v%s\r\n"
                  "\r\n\r\n",
                  host, version2string(packet->req.version),
                  PACKAGE, VERSION);

   slog(LOG_DEBUG, "%s: sending: %s", function, buf);
   if ((rc = socks_sendton(s, buf, (size_t)len, (size_t)len, 0, NULL, 0, NULL))
   != len) {
      swarn("%s: wrote %ld/%ld byte%s",
      function, (long)rc, (long)len, len == 1 ? "" : "s");

      return -1;
   }

   /*
    * read til we get the eof response so there's no junk left in buffer
    * for client, then return the response code.
    */
   eof = checked = readsofar = 0;
   do {
      const char *eofresponse_str = "\r\n\r\n";
      const char *eol_str = "\r\n";
      char *eol, *bufp;
      size_t linelen;

      if ((len = read(s, &buf[readsofar], sizeof(buf) - readsofar - 1)) <= 0) {
         swarn("%s: read() returned %ld after having read %lu bytes",
         function, (long)len, (unsigned long)readsofar);

         return -1;
      }

      buf[readsofar + len] = NUL;
      slog(LOG_DEBUG, "%s: read: %s",
           function, str2vis(&buf[readsofar], len, visbuf, sizeof(visbuf)));
      readsofar += len;

      if ((strstr(buf, eofresponse_str)) == NULL)
         continue; /* don't bother to start parsing til we've got it all. */
      else
         eof = 1;

      bufp = buf;
      while ((eol = strstr(bufp, eol_str)) != NULL) {
         /* check each line for the response we are looking for. */
         *eol   = NUL;
         linelen = eol - bufp;

         slog(LOG_DEBUG, "%s: checking line \"%s\"",
              function, str2vis(bufp, linelen, visbuf, sizeof(visbuf)));

         if (!checked) {
            int error = 0;

            switch (packet->req.version) {
               case PROXY_HTTP_10:
               case PROXY_HTTP_11: {
                  const char *ver_str = version2string(packet->req.version);
                  size_t offset       = strlen(ver_str);

                  if (linelen < offset + strlen(" 200")) {
                     swarnx("%s: response from server (\"%s\") is too short",
                            function,
                            str2vis(bufp, linelen, visbuf, sizeof(visbuf)));

                     error = 1;
                     break;
                  }

                  if (strncmp(bufp, ver_str, offset) != 0) {
                     swarnx("%s: version in response from server (\"%s\") "
                            "does not match expected (\"%s\").  Continuing "
                            "anyway and hoping for the best ...",
                            function,
                            str2vis(bufp,
                                    MIN(offset, linelen),
                                    visbuf,
                                    sizeof(visbuf)),
                            ver_str);
                  }

                  while (isspace(bufp[offset]))
                        ++offset;

                  if (!isdigit(bufp[offset])) {
                     swarnx("%s: response from server (%s) does not match "
                            "expected (<a number>)",
                            function,
                            str2vis(&bufp[offset],
                                    linelen - offset,
                                    visbuf,
                                    sizeof(visbuf)));

                     error = 1;
                     break;
                  }

                  packet->res.version = packet->req.version;

                  rc = atoi(&bufp[offset]);
                  slog(LOG_DEBUG, "%s: reply code from http server is %ld",
                  function, (long)rc);

                  socks_set_responsevalue(&packet->res, rc);

                  /*
                   * we have no idea what address the server will use on
                   * our behalf, so set it to what we use.  Better than
                   * nothing, perhaps. :-/
                   */
                  addrlen = sizeof(addr);
                  if (getsockname(s, &addr, &addrlen) != 0)
                     SWARN(s);
                  sockaddr2sockshost(&addr, &packet->res.host);

                  checked = 1;
                  break;
               }

               default:
                  SERRX(packet->req.version);
            }

            if (error) {
               swarnx("%s: unknown response: \"%s\"",
               function, str2vis(bufp, linelen, visbuf, sizeof(visbuf)));

               errno = ECONNREFUSED;
               return -1;
            }
         }

         /* shift out the line we just parsed, nothing of interest there. */
         bufp += linelen;
      }
   } while (!eof);

   if (checked)
      return socks_get_responsevalue(&packet->res) == HTTP_SUCCESS ? 0 : -1;

   slog(LOG_DEBUG, "%s: didn't get status code from proxy", function);
   return -1;   /* proxyserver doing something strange/unknown. */
}
