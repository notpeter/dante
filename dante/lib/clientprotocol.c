/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2004, 2005, 2008, 2009, 2010
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

 /*
  * The gssapi code was contributed by
  * Markus Moeller (markus_moeller at compuserve.com).
  */


#include "common.h"
#include "interposition.h"

static const char rcsid[] =
"$Id: clientprotocol.c,v 1.125.2.3 2010/05/25 05:13:29 michaels Exp $";

static int
recv_sockshost(int s, struct sockshost_t *host, int version,
      struct authmethod_t *auth);
/*
 * Fills "host" based on data read from "s".  "version" is the version
 * the remote peer is expected to send data in.
 *
 * Returns:
 *      On success: 0
 *      On failure: -1
 */


int
socks_sendrequest(s, request)
   int s;
   const struct request_t *request;
{
   const char *function = "socks_sendrequest()";
   unsigned char requestmem[sizeof(*request)];
   unsigned char *p = requestmem;

   switch (request->version) {
      case PROXY_SOCKS_V4:
         /*
          * VN   CD  DSTPORT DSTIP USERID   0
          *  1 + 1  +   2   +  4  +  ?    + 1  = 9 + USERID
          */

         /* VN */
         memcpy(p, &request->version, sizeof(request->version));
         p += sizeof(request->version);

         /* CD */
         memcpy(p, &request->command, sizeof(request->command));
         p += sizeof(request->command);

         p = sockshost2mem(&request->host, p, request->version);

         *p++ = 0; /* not bothering to send any userid.  Should we? */

         break; /* SOCKS_V4 */

       case PROXY_SOCKS_V5:
         /*
          * rfc1928 request:
          *
          *   +----+-----+-------+------+----------+----------+
          *   |VER | CMD |  FLAG | ATYP | DST.ADDR | DST.PORT |
          *   +----+-----+-------+------+----------+----------+
          *   | 1  |  1  |   1   |  1   | Variable |    2     |
          *   +----+-----+-------+------+----------+----------+
          *     1      1     1      1       > 0         2
          *
          *   Which gives a fixed size of minimum 7 octets.
          *   The first octet of DST.ADDR when it is SOCKS_ADDR_DOMAINNAME
          *   contains the length of DST.ADDR.
          */

         /* VER */
         memcpy(p, &request->version, sizeof(request->version));
         p += sizeof(request->version);

         /* CMD */
         memcpy(p, &request->command, sizeof(request->command));
         p += sizeof(request->command);

         /* FLAG */
         memcpy(p, &request->flag, sizeof(request->flag));
         p += sizeof(request->flag);

         p = sockshost2mem(&request->host, p, request->version);

         break;

       default:
         SERRX(request->version);
   }

   slog(LOG_DEBUG, "%s: sending request: %s",
   function, socks_packet2string(request, SOCKS_REQUEST));

   /*
    * Send the request to the server.
    */
   if (socks_sendton(s, requestmem, (size_t)(p - requestmem),
   (size_t)(p - requestmem), 0, NULL, 0, request->auth) != p - requestmem) {
      swarn("%s: socks_sendton()", function);
      return -1;
   }

   return 0;
}

int
socks_recvresponse(s, response, version)
   int s;
   struct response_t   *response;
   int version;
{
   const char *function = "socks_recvresponse()";
   ssize_t rc;

   /* get the version specific data. */
   switch (version) {
      case PROXY_SOCKS_V4: {
         /*
          * The socks V4 reply length is fixed:
          * VN   CD  DSTPORT  DSTIP
          *  1 + 1  +   2   +   4
          */
         char responsemem[ sizeof(response->version)
                         + sizeof(response->reply)
                         ];
         char *p = responsemem;

         if ((rc = socks_recvfromn(s, responsemem, sizeof(responsemem),
         sizeof(responsemem), 0, NULL, NULL, response->auth))
         != (ssize_t)sizeof(responsemem)) {
            swarn("%s: got %ld size response from server, expected %lu bytes",
            function, (long)rc, (unsigned long)sizeof(responsemem));
            return -1;
         }

         /* VN */
         memcpy(&response->version, p, sizeof(response->version));
         p += sizeof(response->version);
         if (response->version != PROXY_SOCKS_V4REPLY_VERSION) {
            swarnx("%s: unexpected version from server (%d, not %d)",
            function, response->version, PROXY_SOCKS_V4REPLY_VERSION);
            return -1;
         }

         /* CD */
         memcpy(&response->reply, p, sizeof(response->reply));
         p += sizeof(response->reply);
         break;
      }

      case PROXY_SOCKS_V5: {
         /*
          * rfc1928 reply:
          *
          * +----+-----+-------+------+----------+----------+
          * |VER | REP |  FLAG | ATYP | BND.ADDR | BND.PORT |
          * +----+-----+-------+------+----------+----------+
          * | 1  |  1  |   1   |  1   |  > 0     |    2     |
          * +----+-----+-------+------+----------+----------+
          *
          *   Which gives a size of >= 7 octets.
          *
          */
         char responsemem[sizeof(response->version)
                        + sizeof(response->reply)
                        + sizeof(response->flag)
                        ];
         char *p = responsemem;

         if ((rc = socks_recvfromn(s, responsemem, sizeof(responsemem),
         sizeof(responsemem), 0, NULL, NULL, response->auth))
         != (ssize_t)sizeof(responsemem)) {
            swarn("%s: got %ld size response from server, expected %lu bytes",
            function, (long)rc, (unsigned long)sizeof(responsemem));
            return -1;
         }

         /* VER */
         memcpy(&response->version, p, sizeof(response->version));
         p += sizeof(response->version);
         if (version != response->version) {
            swarnx("%s: unexpected version from server (%d != %d)",
            function, version, response->version);
            return -1;
         }

         /* REP */
         memcpy(&response->reply, p, sizeof(response->reply));
         p += sizeof(response->reply);

         /* FLAG */
         memcpy(&response->flag, p, sizeof(response->flag));
         p += sizeof(response->flag);

         break;
      }

      default:
         SERRX(version);
   }

   if (recv_sockshost(s, &response->host, version, response->auth) != 0)
      return -1;

   slog(LOG_DEBUG, "%s: received response: %s",
   function, socks_packet2string(response, SOCKS_RESPONSE));

   return 0;
}

/* ARGSUSED */
int
socks_negotiate(s, control, packet, route)
   int s;
   int control;
   struct socks_t *packet;
   struct route_t *route;
{

   packet->res.auth = packet->req.auth;
   switch (packet->req.version) {
      case PROXY_SOCKS_V5:
         /*
          * Whatever these file descriptor-indexes were used for before, we
          * need to reset them now.
          */
#if SOCKS_CLIENT
         socks_rmaddr(s, 1);
         socks_rmaddr(control, 1);
#endif /* SOCKS_CLIENT */

         if (negotiate_method(control, packet, route) != 0)
            return -1;

         /* FALLTHROUGH */ /* rest is like v4, which doesn't have method. */

      case PROXY_SOCKS_V4:
         if (packet->req.command == SOCKS_BIND) {
            if (route != NULL && route->gw.state.extension.bind)
               packet->req.host.addr.ipv4.s_addr = htonl(BINDEXTENSION_IPADDR);
#if SOCKS_CLIENT
            else
               if (packet->req.version == PROXY_SOCKS_V4)
                /* v4/v5 difference.  We always set up for v5. */
               packet->req.host.port
               = TOIN(&sockscf.state.lastconnect)->sin_port;
#endif /* SOCKS_CLIENT */
         }

         if (socks_sendrequest(control, &packet->req) != 0)
            return -1;

         if (socks_recvresponse(control, &packet->res, packet->req.version)
         != 0) {
            socks_blacklist(route);

            if (errno == 0)
               errno = ECONNREFUSED; /* something wrong.  If nothing else ... */

            return -1;
         }
         break;

#if SOCKS_CLIENT
      case PROXY_MSPROXY_V2:
         if (msproxy_negotiate(s, control, packet) != 0) {
            if (errno == 0)
               errno = ECONNREFUSED; /* something wrong.  If nothing else ... */
            return -1;
         }
         break;
#endif /* SOCKS_CLIENT */

      case PROXY_HTTP_V1_0:
         if (httpproxy_negotiate(control, packet) != 0) {
            if (errno == 0)
               errno = ECONNREFUSED; /* something wrong.  If nothing else ... */
            return -1;
         }
         break;

#if HAVE_LIBMINIUPNP
      case PROXY_UPNP:
         if (upnp_negotiate(s, packet, &route->gw.state.data) != 0) {
            if (errno == 0)
               errno = ECONNREFUSED; /* something wrong.  If nothing else ... */
            return -1;
         }
         break;
#endif /* HAVE_LIBMINIUPNP */

      default:
         SERRX(packet->req.version);
   }

   if (!serverreplyisok(packet->res.version, packet->res.reply, route))
      return -1;
   else {
      if (fdisblocking(control))
         errno = 0; /* OpenBSD 4.5's thread-stuff sometimes sets this. :-/ */
      else {
         if (!ERRNOISINPROGRESS(errno))
            errno = 0;
      }
   }

   return 0;
}

static int
recv_sockshost(s, host, version, auth)
   int s;
   struct sockshost_t *host;
   int version;
   struct authmethod_t *auth;
{
   const char *function = "recv_sockshost()";
   ssize_t rc;

   switch (version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V4REPLY_VERSION: {
         /*
          * DSTPORT  DSTIP
          *   2    +   4
          */
         char hostmem[ sizeof(host->port)
                     + sizeof(host->addr.ipv4)
                     ];
         char *p = hostmem;

         if ((rc = socks_recvfromn(s, hostmem, sizeof(hostmem), sizeof(hostmem),
         0, NULL, NULL, auth)) != (ssize_t)sizeof(hostmem)) {
            swarn("%s: socks_recvfromn(): %ld/%ld",
            function, (long)rc, (long)sizeof(hostmem));

            return -1;
         }

         host->atype = SOCKS_ADDR_IPV4;

         /* BND.PORT */
         memcpy(&host->port, p, sizeof(host->port));
         p += sizeof(host->port);

         /* BND.ADDR */
         memcpy(&host->addr.ipv4, p, sizeof(host->addr.ipv4));
         p += sizeof(host->addr.ipv4);

         break;
      }

      case PROXY_SOCKS_V5:
         /*
          * +------+----------+----------+
          * | ATYP | BND.ADDR | BND.PORT |
          * +------+----------+----------+
          * |  1   |  > 0     |    2     |
          * +------+----------+----------+
          */

         /* ATYP */
         if ((rc = socks_recvfromn(s, &host->atype, sizeof(host->atype),
         sizeof(host->atype), 0, NULL, NULL, auth))
         != (ssize_t)sizeof(host->atype)) {
            swarn("%s: socks_recvfromn(): %ld/%ld",
            function, (long)rc, (long)sizeof(host->atype));

            return -1;
         }

         switch(host->atype) {
            case SOCKS_ADDR_IPV4:
               if ((rc = socks_recvfromn(s, &host->addr.ipv4,
               sizeof(host->addr.ipv4), sizeof(host->addr.ipv4), 0, NULL,
               NULL, auth)) != (ssize_t)sizeof(host->addr.ipv4)) {
                  swarn("%s: socks_recvfromn(): %ld/%ld",
                  function, (long)rc, (long)sizeof(host->addr.ipv4));

                  return -1;
               }
               break;

            case SOCKS_ADDR_IPV6:
               if ((rc = socks_recvfromn(s, host->addr.ipv6,
               sizeof(host->addr.ipv6), sizeof(host->addr.ipv6), 0, NULL,
               NULL, auth)) != (ssize_t)sizeof(host->addr.ipv6)) {
                  swarn("%s: socks_recvfromn(): %ld/%ld",
                  function, (long)rc, (long)sizeof(host->addr.ipv6));

                  return -1;
               }
               break;

            case SOCKS_ADDR_DOMAIN: {
               unsigned char alen;

               /* read length of domain name. */
               if ((rc = socks_recvfromn(s, &alen, sizeof(alen), sizeof(alen),
               0, NULL, NULL, auth)) != (ssize_t)sizeof(alen)) {
                  swarn("%s: socks_recvfromn(): %ld/%ld",
                  function, (long)rc, (long)sizeof(alen));

                  return -1;
               }

               OCTETIFY(alen);

#if MAXHOSTNAMELEN < 0xff
               SASSERTX(alen < sizeof(host->addr.domain));
#endif /* MAXHOSTNAMELEN < 0xff */

               /* BND.ADDR, alen octets */
               if ((rc = socks_recvfromn(s, host->addr.domain, (size_t)alen,
               (size_t)alen, 0, NULL, NULL, auth)) != (ssize_t)alen) {
                  swarn("%s: socks_recvfromn(): %ld/%ld",
                  function, (long)rc, (long)alen);

                  return -1;
               }
               host->addr.domain[alen] = NUL;

               break;
            }

            default:
               swarnx("%s: unsupported address format %d in reply",
               function, host->atype);
               return -1;
         }

         /* BND.PORT */
         if ((rc = socks_recvfromn(s, &host->port, sizeof(host->port),
         sizeof(host->port), 0, NULL, NULL, auth))
         != (ssize_t)sizeof(host->port)) {
            swarn("%s: socks_recvfromn(): %ld/%ld",
            function, (long)rc, (long)sizeof(host->port));

            return -1;
         }

         break;
   }

   return 0;
}

int
serverreplyisok(version, reply, route)
   int version;
   int reply;
   struct route_t *route;
{
   const char *function = "serverreplyisok()";

   slog(LOG_DEBUG, "%s: version %d, reply %d", function, version, reply);

   switch (version) {
      case PROXY_SOCKS_V4REPLY_VERSION:
         switch (reply) {
            case SOCKSV4_SUCCESS:
               socks_clearblacklist(route);
               return 1;

            case SOCKSV4_FAIL:
               socks_clearblacklist(route);
               errno = ECONNREFUSED;
               return 0;

            case SOCKSV4_NO_IDENTD:
               swarnx("%s: proxy server failed to get your identd response",
               function);
               socks_blacklist(route);
               errno = ECONNREFUSED;
               return 0;

            case SOCKSV4_BAD_ID:
               swarnx("%s: proxy server claims username/ident mismatch",
               function);
               socks_blacklist(route);
               errno = ECONNREFUSED;
               return 0;

            default:
               swarnx("%s: unknown v%d reply from proxy server: %d",
               function, version, reply);
               socks_clearblacklist(route);
               errno = ECONNREFUSED;
         }
         break;

      case PROXY_SOCKS_V5:
         switch (reply) {
            case SOCKS_SUCCESS:
               socks_clearblacklist(route);
               return 1;

            case SOCKS_FAILURE:
               swarnx("%s: generic proxy server failure", function);
               socks_blacklist(route);
               errno = ECONNREFUSED;
               return 0;

            case SOCKS_NOTALLOWED:
               swarnx("%s: connection denied by proxy server", function);
               socks_clearblacklist(route);
               errno = ECONNREFUSED;
               return 0;

            case SOCKS_NETUNREACH:
               socks_clearblacklist(route);
               errno = ENETUNREACH;
               return 0;

            case SOCKS_HOSTUNREACH:
               socks_clearblacklist(route);
               errno = EHOSTUNREACH;
               return 0;

            case SOCKS_CONNREFUSED:
               socks_clearblacklist(route);
               errno = ECONNREFUSED;
               return 0;

            case SOCKS_TTLEXPIRED:
               socks_clearblacklist(route);
               errno = ETIMEDOUT;
               return 0;

            case SOCKS_CMD_UNSUPP:
               swarnx("%s: command not supported by proxy server", function);
               socks_blacklist(route);
               errno = ECONNREFUSED;
               return 0;

            case SOCKS_ADDR_UNSUPP:
               swarnx("%s: address type not supported by proxy", function);
               socks_blacklist(route);
               errno = ECONNREFUSED;
               return 0;

            default:
               swarnx("%s: unknown v%d reply from proxy server: %d",
               function, version, reply);
               errno = ECONNREFUSED;
         }
         break;

      case PROXY_MSPROXY_V2:
         switch (reply) {
            case MSPROXY_SUCCESS:
               return 1;

            case MSPROXY_FAILURE:
               errno = ECONNREFUSED;
               socks_blacklist(route);
               return 0;

            case MSPROXY_CONNREFUSED:
               errno = ECONNREFUSED;
               return 0;

            case MSPROXY_NOTALLOWED:
               swarnx("%s: connection denied by proxy server: authenticated?",
               function);
               socks_blacklist(route);
               errno = ECONNREFUSED;
               return 0;

            default:
               swarnx("%s: unknown v%d reply from proxy server: %d",
               function, version, reply);
               errno = ECONNREFUSED;
         }
         break;

      case PROXY_HTTP_V1_0:
         switch (reply) {
            case HTTP_SUCCESS:
               socks_clearblacklist(route);
               return 1;

            default:
               socks_blacklist(route);
               errno = ECONNREFUSED;
         }
         break;

      case PROXY_UPNP:
         switch (reply) {
            case UPNP_SUCCESS:
               socks_clearblacklist(route);
               return 1;

            default:
               socks_blacklist(route);
               errno = ECONNREFUSED;
         }
         break;


      default:
         slog(LOG_DEBUG, "%s: unknown version %d", function, version);
   }

   return 0;
}

/* ARGSUSED */
int
clientmethod_uname(s, host, version, name, password)
   int s;
   const struct sockshost_t *host;
   int version;
   unsigned char *name, *password;
{
   const char *function = "clientmethod_uname()";
   static struct authmethod_uname_t uname;   /* cached userinfo.              */
   static struct sockshost_t unamehost;      /* host cache was gotten for.    */
   static int unameisok;                     /* cached data is ok?            */
   ssize_t rc;
   unsigned char *offset;
   unsigned char request[ 1               /* version.          */
                        + 1               /* username length.  */
                        + MAXNAMELEN      /* username.         */
                        + 1               /* password length.  */
                        + MAXPWLEN        /* password.         */
   ];
   unsigned char response[ 1 /* version.  */
                         + 1 /* status.   */
   ];

   switch (version) {
      case PROXY_SOCKS_V5:
         break;

      default:
         SERRX(version);
   }

   if (memcmp(&unamehost, host, sizeof(unamehost)) != 0)
      unameisok = 0;   /* not same host as cache was gotten for. */

   /* fill in request. */

   offset  = request;
   *offset = (unsigned char)SOCKS_UNAMEVERSION;
   ++offset;

   if (!unameisok) {
      if (name == NULL
      && (name = (unsigned char *)socks_getusername(host, (char *)offset + 1,
      MAXNAMELEN)) == NULL) {
         swarn("%s: could not determine username of client", function);
         return -1;
      }

      SASSERTX(strlen((char *)name) < sizeof(uname.name));
      strcpy((char *)uname.name, (char *)name);
   }

   slog(LOG_DEBUG, "%s: unameisok %d, name \"%s\"",
   function, unameisok, uname.name);

   /* first byte gives length. */
   *offset = (unsigned char)strlen((char *)uname.name);
   OCTETIFY(*offset);
   strcpy((char *)offset + 1, (char *)uname.name);
   offset += *offset + 1;

   if (!unameisok) {
      if (password == NULL
      && (password = (unsigned char *)socks_getpassword(host, (char *)name,
      (char *)offset + 1, MAXPWLEN)) == NULL) {
         slog(LOG_DEBUG, "%s: could not determine password of client, "
                         "trying empty password", function);

         password = (unsigned char *)"";
      }

      SASSERTX(strlen((char *)password) < sizeof(uname.password));
      strcpy((char *)uname.password, (char *)password);
   }

   /* first byte gives length. */
   *offset = (unsigned char)strlen((char *)uname.password);
   OCTETIFY(*offset);
   strcpy((char *)offset + 1, (char *)uname.password);
   offset += *offset + 1;

   slog(LOG_DEBUG, "%s: offering username \"%s\", password %s to server",
   function, uname.name, (*uname.password == NUL) ? "\"\"" : "********");

   if ((rc = socks_sendton(s, request, (size_t)(offset - request),
   (size_t)(offset - request), 0, NULL, 0, NULL)) != offset - request) {
      swarn("%s: send of username/password failed, sent %d/%d",
      function, (int)rc, (int)(offset - request));

      return -1;
   }

   if ((rc = socks_recvfromn(s, response, sizeof(response), sizeof(response),
   0, NULL, NULL, NULL)) != sizeof(response)) {
      swarn("%s: failed to receive socks server request, received %ld/%lu",
      function, (long)rc, (unsigned long)sizeof(response));

      return -1;
   }

   slog(LOG_DEBUG, "%s: received response: 0x%x, 0x%x",
   function, response[0], response[1]);

   if (request[UNAME_VERSION] != response[UNAME_VERSION]) {
      swarnx("%s: sent v%d, got v%d", function, request[0], response[1]);
      return -1;
   }

   if (response[UNAME_STATUS] == 0) { /* server accepted. */
      unamehost = *host;
      unameisok = 1;
   }

   return response[UNAME_STATUS];
}

#if HAVE_GSSAPI
 /*
  * This code was contributed by
  * Markus Moeller (markus_moeller at compuserve.com).
  */

int
clientmethod_gssapi(s, protocol, gw, version, auth)
   int s;
   int protocol;
   const struct gateway_t *gw;
   int version;
   struct authmethod_t *auth;
{
   const char *function = "clientmethod_gssapi()";

   OM_uint32 ret_flags;
   OM_uint32 major_status, minor_status;
   gss_name_t            client_name       = GSS_C_NO_NAME;
   gss_name_t            server_name       = GSS_C_NO_NAME;
   gss_cred_id_t         server_creds      = GSS_C_NO_CREDENTIAL;
   gss_buffer_desc       service           = GSS_C_EMPTY_BUFFER;
   gss_buffer_desc       input_token       = GSS_C_EMPTY_BUFFER;
   gss_buffer_desc       output_token      = GSS_C_EMPTY_BUFFER;
   gss_buffer_desc       gss_context_token = GSS_C_EMPTY_BUFFER;
   gss_buffer_desc       *context_token    = GSS_C_NO_BUFFER;
   unsigned short        token_length;
   unsigned char request[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
   unsigned char response[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
   char nameinfo[MAXNAMELEN + MAXNAMELEN], buf[sizeof(nameinfo)], emsg[512];
   ssize_t rc;
   unsigned char gss_server_enc, gss_enc;
   int conf_state;

#if SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT
   /*
    * Make sure the gssapi functions use the native connect(2)/bind(2)
    * and sendto(2)/recvfrom(2) system calls, even if the user has not
    * created a direct route for the related addresses.
    *
    * During the process of establishing a socks gssapi session with
    * server X, we will need to contact the kdc for a ticket to
    * use with server X, but if our only route to the kdc is via
    * server X, that doesn't work of course.  The correct thing
    * is for the user to create a direct route to kdc, but helping
    * him this way will hopefully save a ton of grief.
    *
    * It will not work in the (hopefully very rare) case where the
    * user actually has set things up correctly, but the route to
    * the kdc is via another, non-gssapi proxy though.
    *
    * Based on an idea by Markus Moeller for forcing connect(2) to the
    * Kerberos kdc to use the native connect(2), rather than most
    * likely create a routing loop when the user neglects to mark
    * the route to the kdc as "direct" in socks.conf.
    */
   socks_mark_gssapi_io_as_native();
#endif /* SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT */

   version = version;
   if (gw) {
      switch (gw->addr.atype) {
         case SOCKS_ADDR_IPV4: {
            struct sockaddr_in addr;

            bzero(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr   = gw->addr.addr.ipv4;

            if ((rc = getnameinfo((struct sockaddr *)&addr, sizeof(addr),
            nameinfo, sizeof(nameinfo), NULL, 0, NI_NAMEREQD)) != 0) {
               swarnx("%s: getnameinfo(%s) failed with error %ld\n",
               function, inet_ntoa(addr.sin_addr), (long)rc);

#if SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT
               socks_mark_gssapi_io_as_normal();
#endif /* SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT */

               return -1;
            }
            break;
         }

         case SOCKS_ADDR_DOMAIN:
            strcpy(nameinfo, gw->addr.addr.domain);
            break;

         default:
            SERRX(gw->addr.atype);
      }
   }
   else {
#if SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT
      socks_mark_gssapi_io_as_normal();
#endif /* SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT */

      return -1;
   }

   snprintf(buf, sizeof(buf), "%s@%s", gw->state.gssapiservicename, nameinfo);
   service.value  = buf;
   service.length = strlen((char *)service.value);

   major_status = gss_import_name(&minor_status, &service, gss_nt_service_name,
                                  &server_name);

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      swarnx("%s: gss_import_name() %s", function, emsg);
      goto error;
   }

   request[GSSAPI_VERSION]     = SOCKS_GSSAPI_VERSION;
   auth->mdata.gssapi.state.id = GSS_C_NO_CONTEXT;

   while (1) {
      major_status = gss_init_sec_context(&minor_status,
                                          GSS_C_NO_CREDENTIAL,
                                          &auth->mdata.gssapi.state.id,
                                          server_name,
                                          GSS_C_NULL_OID,
                                          GSS_C_MUTUAL_FLAG
                                          | GSS_C_REPLAY_FLAG
                                          | (unsigned int)((protocol
                                          == SOCKS_TCP ?
                                            GSS_C_SEQUENCE_FLAG : 0)),
                                          /*
                                           * | GSS_C_DELEG_FLAG
                                           * RFC 1961 says GSS_C_DELEG_FLAG
                                           * should also be set, but I can't
                                           * see any reason why the client
                                           * should want to forward it's
                                           * tickets to a socks server ...
                                           *
                                           * Don't set unless until we find
                                           * a reason to do so.
                                           */
                                          0,
                                          GSS_C_NO_CHANNEL_BINDINGS,
                                          context_token,
                                          NULL,
                                          &output_token,
                                          &ret_flags,
                                          NULL);

      switch (major_status) {
         case GSS_S_COMPLETE:
            slog(LOG_DEBUG, "%s: gssapi negotiation completed", function);
            break;

         case GSS_S_CONTINUE_NEEDED:
            slog(LOG_DEBUG, "%s: gssapi negotiation to be continued", function);
            break;

         default:
            if (!gss_err_isset(major_status, minor_status, emsg, sizeof(emsg)))
               snprintf(emsg, sizeof(emsg), "unknown gss major_status %d",
               major_status);

            swarnx("%s: gss_init_sec_context(): %s", function, emsg);
            goto error;
      }

      if(output_token.length != 0) {
         request[GSSAPI_STATUS]  = SOCKS_GSSAPI_AUTHENTICATION;

         token_length = htons((unsigned short)output_token.length);
         memcpy(request + GSSAPI_TOKEN_LENGTH, &token_length, sizeof(short));

         SASSERTX(output_token.length <= sizeof(request) - GSSAPI_HLEN);
         memcpy(request + GSSAPI_HLEN, output_token.value, output_token.length);

         if ((rc = socks_sendton(s, request, GSSAPI_HLEN + output_token.length,
         GSSAPI_HLEN + output_token.length, 0, NULL, 0, NULL))
         != (ssize_t)(GSSAPI_HLEN + output_token.length))  {
            swarn("%s: send of request failed, sent %ld/%ld",
            function, (long)rc, (long)(GSSAPI_HLEN + output_token.length));
            goto error;
         }

         CLEAN_GSS_TOKEN(output_token);
      }

      if (major_status == GSS_S_COMPLETE)
         break;

      if ((rc = socks_recvfromn(s, response, GSSAPI_HLEN, GSSAPI_HLEN, 0,
      NULL, NULL, NULL)) != GSSAPI_HLEN) {
         swarn("%s: read of response failed, read %ld/%ld",
         function, (long)rc, (long)GSSAPI_HLEN);
         goto error;
      }

      if(response[GSSAPI_VERSION] != SOCKS_GSSAPI_VERSION) {
         swarnx("%s: invalid GSSAPI authentication response type (%d, %d)",
         function, response[GSSAPI_VERSION], response[GSSAPI_STATUS]);
         goto error;
      }

      if (response[GSSAPI_STATUS] == 0xff) {
         slog(LOG_DEBUG,"%s: user was rejected by SOCKS server (%d, %d).",
         function, response[GSSAPI_VERSION], response[GSSAPI_STATUS]);
         goto error;
      }

      if(response[GSSAPI_STATUS] != SOCKS_GSSAPI_AUTHENTICATION) {
         swarnx("%s: invalid GSSAPI authentication response type (%d, %d)",
         function, response[GSSAPI_VERSION], response[GSSAPI_STATUS]);
         goto error;
      }

      memcpy(&token_length, &response[GSSAPI_TOKEN_LENGTH], sizeof(short));
      token_length = ntohs(token_length);

      input_token.value  = response + GSSAPI_HLEN;
      if ((input_token.length = token_length) > sizeof(response) - GSSAPI_HLEN){
         swarnx("%s: server sent illegal token length of %u, max is %lu",
         function, token_length, (long unsigned)sizeof(response) - GSSAPI_HLEN);
         goto error;
      }

      if ((rc = socks_recvfromn(s, input_token.value, input_token.length,
      input_token.length, 0, NULL, NULL, NULL)) != (ssize_t)input_token.length){
         swarn("%s: read of response failed, read %ld/%ld",
         function, (long)rc, (long)input_token.length);

         goto error;
      }

      context_token = &input_token;
   }

   CLEAN_GSS_TOKEN(gss_context_token);
   CLEAN_GSS_TOKEN(output_token);
   CLEAN_GSS_AUTH(client_name, server_name, server_creds);

   request[GSSAPI_STATUS] = SOCKS_GSSAPI_ENCRYPTION;

   if (gw->state.gssapiencryption.clear)
      gss_enc = SOCKS_GSSAPI_CLEAR;

   if (gw->state.gssapiencryption.integrity)
      gss_enc = SOCKS_GSSAPI_INTEGRITY;

   if (gw->state.gssapiencryption.confidentiality)
      gss_enc = SOCKS_GSSAPI_CONFIDENTIALITY;

   if (gw->state.gssapiencryption.nec) {
      const size_t tosend = GSSAPI_HLEN + 1, toread = tosend;

      slog(LOG_DEBUG, "%s: running in nec gssapi mode", function);

      token_length = htons(1);
      memcpy(&request[GSSAPI_TOKEN_LENGTH], &token_length, sizeof(short));
      memcpy(request + GSSAPI_HLEN, &gss_enc, 1);

      if ((rc = socks_sendton(s, request, tosend, tosend, 0, NULL, 0, NULL))
      != (ssize_t)tosend) {
         swarn("%s: send of request failed, sent %ld/%ld",
         function, (long)rc, (long)tosend);
         goto error;
      }

      if ((rc = socks_recvfromn(s, response, toread, toread, 0, NULL, NULL,
      NULL)) != (ssize_t)toread) {
         swarn("%s: read of response failed, read %ld/%ld",
         function, (long)rc, (long)(GSSAPI_HLEN + 1));
         goto error;
      }

      if (response[GSSAPI_STATUS] != SOCKS_GSSAPI_ENCRYPTION) {
         swarnx("%s: invalid GSSAPI encryption response type (%d, %d).",
         function, response[GSSAPI_VERSION], response[GSSAPI_STATUS]);
         goto error;
      }

      memcpy(&token_length, &response[GSSAPI_TOKEN_LENGTH], sizeof(short));
      token_length = ntohs(token_length);

      if (token_length != 1) {
         swarnx("%s: Invalid encryption token length", function);
         goto error;
      }

      gss_server_enc = response[GSSAPI_HLEN + 1];
   }
   else {
      slog(LOG_DEBUG, "%s: running in rfc 1961 gssapi mode", function);

      input_token.length = 1;
      input_token.value  = response;
      memcpy(input_token.value, &gss_enc, input_token.length);

      major_status = gss_wrap(&minor_status, auth->mdata.gssapi.state.id,
                              0, GSS_C_QOP_DEFAULT, &input_token, &conf_state,
                              &output_token);

      if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
         swarnx("%s: gss_wrap() %s", function, emsg);
         goto error;
      }

      token_length = htons((short)output_token.length);
      memcpy(&request[GSSAPI_TOKEN_LENGTH], &token_length, sizeof(short));

      if ((rc = socks_sendton(s, request, GSSAPI_TOKEN, GSSAPI_TOKEN, 0, NULL,
      0, NULL)) != GSSAPI_TOKEN)  {
         swarn("%s: send of request failed, sent %ld/%ld",
         function, (long)rc, (long)GSSAPI_TOKEN);
         goto error;
      }

      if ((rc = socks_sendton(s, output_token.value, output_token.length,
      output_token.length, 0, NULL, 0, NULL)) != (ssize_t)output_token.length) {
         swarn("%s: send of request failed, sent %ld/%ld",
         function, (long)rc, (long)output_token.length);
         goto error;
      }

      CLEAN_GSS_TOKEN(gss_context_token);
      CLEAN_GSS_TOKEN(output_token);

      if ((rc = socks_recvfromn(s, response, GSSAPI_HLEN, GSSAPI_HLEN,
      0, NULL, NULL, NULL)) != GSSAPI_HLEN) {
         swarn("%s: read of response failed, read %ld/%d",
         function, (long)rc, GSSAPI_HLEN);
         goto error;
      }

      if (response[GSSAPI_STATUS] != SOCKS_GSSAPI_ENCRYPTION) {
         swarnx("%s: invalid GSSAPI encryption response type (%d, %d).",
         function, response[GSSAPI_VERSION], response[GSSAPI_STATUS]);
         goto error;
      }

      memcpy(&token_length, response + GSSAPI_TOKEN_LENGTH, sizeof(short));
      input_token.length = ntohs(token_length);

      if (input_token.length > sizeof(response) - GSSAPI_HLEN) {
         swarnx("%s: server sent too big a token; length %u, but max is %lu",
         function, token_length, (long unsigned)sizeof(response) - GSSAPI_HLEN);
         goto error;
      }

      input_token.value = response + GSSAPI_HLEN;

      if ((rc = socks_recvfromn(s, input_token.value, input_token.length,
      input_token.length, 0, NULL, NULL, NULL)) != (ssize_t)input_token.length){
         swarn("%s: read of response failed, read %ld/%ld",
         function, (long)rc, (long)input_token.length);
         goto error;
      }

      major_status = gss_unwrap(&minor_status, auth->mdata.gssapi.state.id,
                                &input_token, &output_token, 0,
                                GSS_C_QOP_DEFAULT);

      if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
         swarnx("%s: gss_unwrap() %s", function, emsg);
         goto error;
      }

      if (output_token.length != 1)  {
         swarnx("%s: gssapi encryption output_token.length is not 1, but %lu",
         function, (unsigned long)output_token.length);

         goto error;
      }

      gss_server_enc = *(unsigned char *)output_token.value;

      CLEAN_GSS_TOKEN(gss_context_token);
      CLEAN_GSS_TOKEN(output_token);
   }

   if ((gss_server_enc == SOCKS_GSSAPI_CLEAR
     && !gw->state.gssapiencryption.clear)
   ||  (gss_server_enc == SOCKS_GSSAPI_INTEGRITY
     && !gw->state.gssapiencryption.integrity)
   ||  (gss_server_enc == SOCKS_GSSAPI_CONFIDENTIALITY
     && !gw->state.gssapiencryption.confidentiality)
   ||  (gss_server_enc == SOCKS_GSSAPI_PERMESSAGE) ) {
       swarnx("%s: server responded with different encryption than requested:",
       function);

       swarnx("%s: client accepts: clear/%d, integrity/%d, confidentiality/%d, "
       "per message/%d",
       function,
       gw->state.gssapiencryption.clear,
       gw->state.gssapiencryption.integrity,
       gw->state.gssapiencryption.confidentiality,
       gw->state.gssapiencryption.permessage);

       swarnx("%s: server offers: %s", function,
       (gss_server_enc == SOCKS_GSSAPI_CLEAR) ?
       "clear"           : (gss_server_enc == SOCKS_GSSAPI_INTEGRITY)       ?
       "integrity"       : (gss_server_enc == SOCKS_GSSAPI_CONFIDENTIALITY) ?
       "confidentiality" : (gss_server_enc == SOCKS_GSSAPI_PERMESSAGE)      ?
       "per message"     : "unknown");

       goto error;
   }

   if (gss_server_enc == SOCKS_GSSAPI_CLEAR
   && gw->state.gssapiencryption.clear)
      gss_enc = SOCKS_GSSAPI_CLEAR;
   else if (gss_server_enc == SOCKS_GSSAPI_INTEGRITY
   && gw->state.gssapiencryption.integrity)
      gss_enc = SOCKS_GSSAPI_INTEGRITY;
   else if (gss_server_enc == SOCKS_GSSAPI_CONFIDENTIALITY
   && gw->state.gssapiencryption.confidentiality)
      gss_enc = SOCKS_GSSAPI_CONFIDENTIALITY;

   slog(LOG_INFO, "%s: use %s protection",
   function, gssapiprotection2string(gss_enc));

   auth->mdata.gssapi.state.protection = gss_enc;
   if (auth->mdata.gssapi.state.protection)
       auth->mdata.gssapi.state.encryption = GSSAPI_ENCRYPT;

   major_status
   = gss_wrap_size_limit(&minor_status,
                         auth->mdata.gssapi.state.id,
                         auth->mdata.gssapi.state.protection
                         == GSSAPI_CONFIDENTIALITY ?
                         GSS_REQ_CONF : GSS_REQ_INT,
                         GSS_C_QOP_DEFAULT,
                         MAXGSSAPITOKENLEN - GSSAPI_HLEN,
                         &auth->mdata.gssapi.state.maxgssdata);

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg)))
      serrx(EXIT_FAILURE, "%s: gss_wrap_size_limit() failed: %s",
      function, emsg);
   else {
      slog(LOG_DEBUG, "%s: max length of gssdata before encoding: %lu",
      function, (unsigned long)auth->mdata.gssapi.state.maxgssdata);

      if ((unsigned long)auth->mdata.gssapi.state.maxgssdata == 0)
          swarnx("%s: invalid max length, the kerberos library might not "
                 "fully support the configured encoding type",
                 function);
   }

#if SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT
   socks_mark_gssapi_io_as_normal();
#endif /* SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT */

   return 0;

error:
   CLEAN_GSS_TOKEN(gss_context_token);
   CLEAN_GSS_TOKEN(output_token);
   CLEAN_GSS_AUTH(client_name, server_name, server_creds);

#if SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT
   socks_mark_gssapi_io_as_normal();
#endif /* SOCKSLIBRARY_DYNAMIC && SOCKS_CLIENT */

   return -1;
}
#endif /* HAVE_GSSAPI */
