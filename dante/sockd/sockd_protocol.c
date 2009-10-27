/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009
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
"$Id: sockd_protocol.c,v 1.134 2009/10/23 10:37:27 karls Exp $";

static int
recv_v4req(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_v5req(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_methods(int s, struct request_t *request,
             struct negotiate_state_t *state);

static int
recv_ver(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_cmd(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_flag(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_sockshost(int s, struct request_t *request,
      struct negotiate_state_t *state);

static int
recv_atyp(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_port(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_address(int s, struct request_t *request,
      struct negotiate_state_t *state);

static int
recv_domain(int s, struct request_t *request, struct negotiate_state_t *state);

static int
recv_username(int s, struct request_t *request,
      struct negotiate_state_t *state);

static int
methodnegotiate(int s, struct request_t *request,
      struct negotiate_state_t *state);


int
recv_request(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
   int rc;

   if (state->complete)
      return 1;

   if (state->rcurrent != NULL)   /* not first call on this client. */
      rc = state->rcurrent(s, request, state);
   else {
      INIT(sizeof(request->version));
      CHECK(&request->version, request->auth, NULL);

      switch (request->version) {
         case PROXY_SOCKS_V4:
            state->rcurrent = recv_v4req;
            break;

         case PROXY_SOCKS_V5:
            state->rcurrent = recv_v5req;
            break;

         default:
            slog(LOG_DEBUG, "unknown version %d in request", request->version);
            return -1;
      }

      rc = state->rcurrent(s, request, state);
   }

   state->complete = rc > 0; /* complete request read? */

   return rc;
}

int
recv_sockspacket(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   return recv_ver(s, request, state);
}

static int
recv_v4req (s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   /*
    * v4 request:
    * VN   CD   DSTPORT  DSTIP  USERID   NUL
    * 1  + 1  +  2     +  4   +  ?     +  1
    *
    * so minimum length is 9.
    */

   /* CD */
   state->rcurrent = recv_cmd;
   return state->rcurrent(s, request, state);

}

static int
recv_v5req (s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   /*
    * method negotiation;
    *      client first sends method selection message:
    *
    *   +----+----------+----------+
    *   |VER | NMETHODS | METHODS  |
    *   +----+----------+----------+
    *   | 1  |    1     | 1 to 255 |
    *   +----+----------+----------+
    */

   /*
    * then the request:
    *
    *   +----+-----+-------+------+----------+----------+
    *   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    *   +----+-----+-------+------+----------+----------+
    *   | 1  |  1  | X'00' |  1   | Variable |    2     |
    *   +----+-----+-------+------+----------+----------+
    *
    *     1     1      1      1        ?          2
    *
    * Since the request can contain different address types
    * we do not know how long the request is before we have
    * read the address type (ATYP) field.
    *
    */

   /* NMETHODS */
   INIT(sizeof(char));
   CHECK(&state->mem[start], request->auth, NULL);
   /* LINTED conversion from 'int' may lose accuracy */
   OCTETIFY(state->mem[start]);

   state->rcurrent = recv_methods;

   return state->rcurrent(s, request, state);
}

static int
recv_methods(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;

{
   const char *function = "recv_methods()";
   const unsigned char methodc = state->mem[state->reqread - 1];  /* NMETHODS */
   unsigned char reply[ 1 /* VERSION   */
                      + 1 /* METHOD    */
                      ];
   char buf[256 * (sizeof("0x00") + sizeof(", ")) + 1];
   size_t bufused;
   int i;

   INIT(methodc);
   CHECK(&state->mem[start], request->auth, NULL);

   for (i = bufused = 0; i < methodc; ++i)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "0x%x, ",
      state->mem[start + i]);

   STRIPTRAILING(buf, bufused);

   slog(LOG_DEBUG, "%s: client offered %d authentication method%s: %s",
   function, methodc, methodc == 1 ? "" : "s", buf);

   switch (request->auth->method) {
      case AUTHMETHOD_GSSAPI: {
         /*
          * Socks-methods that can be decided for use before we receive
          * the actual request.  So far only gssapi.
          */
         size_t i;

         slog(LOG_DEBUG, "%s: method %d already chosen for this rule, "
                         "not selecting again",
         function, request->auth->method);

         for (i = 0; i < methodc; ++i)
            if (state->mem[start + i] == request->auth->method)
               break;

         if (i >= methodc)
            request->auth->method = AUTHMETHOD_NOACCEPT;

         break;
      }

      default:
         slog(LOG_DEBUG, "%s: method set to %d, selecting new",
         function, request->auth->method);

         request->auth->method = selectmethod(sockscf.methodv, sockscf.methodc,
         &state->mem[start], (size_t)methodc);

         break;
   }

   /* send reply:
    *
    *   +----+--------+
    *   |VER | METHOD |
    *   +----+--------+
    *   | 1  |   1    |
    *   +----+--------+
    */

   slog(LOG_DEBUG, "%s: sending authentication reply: VER: %d METHOD: %d",
   function, request->version, request->auth->method);

   reply[AUTH_VERSION]  = request->version;
   reply[AUTH_METHOD]   = (unsigned char)request->auth->method;

   if (socks_sendton(s, reply, sizeof(reply), sizeof(reply), 0, NULL,
   0, request->auth) != sizeof(reply))
      return -1;

   if (request->auth->method == AUTHMETHOD_NOACCEPT) {
      snprintf(state->emsg, sizeof(state->emsg),
      "client offered no acceptable authentication method");
      errno = EPROTO;
      return -1;
   }

   state->rcurrent = methodnegotiate;
   return state->rcurrent(s, request, state);
}

static int
methodnegotiate(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   /* authentication method dependent negotiation */
   switch (request->auth->method) {
      case AUTHMETHOD_NONE:
         state->rcurrent = recv_sockspacket;
         break;

#if HAVE_GSSAPI
      case AUTHMETHOD_GSSAPI:
         state->rcurrent = method_gssapi;
         break;
#endif /* HAVE_GSSAPI */

      case AUTHMETHOD_UNAME:
         state->rcurrent = method_uname;
         break;

      default:
         SERRX(request->auth->method);
   }

   return state->rcurrent(s, request, state);
}

static int
recv_ver(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   /* VER */
   {
      INIT(sizeof(request->version));
      CHECK(&request->version, request->auth, NULL);

      switch (request->version) {
         case PROXY_SOCKS_V4:
         case PROXY_SOCKS_V5:
            break;

         default:
            slog(LOG_DEBUG, "unknown version %d in request", request->version);
            return -1;
      }
   }

   state->rcurrent = recv_cmd;
   return state->rcurrent(s, request, state);
}

static int
recv_cmd(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
   const char *function = "recv_cmd()";

   INIT(sizeof(request->command));
   CHECK(&request->command, request->auth, NULL);

   switch (request->command) {
      case SOCKS_BIND:
      case SOCKS_CONNECT:
         request->protocol = SOCKS_TCP;
         break;

      case SOCKS_UDPASSOCIATE:
         request->protocol = SOCKS_UDP;
         break;

      default:
         swarnx("%s: unknown command: %d", function, request->command);
   }

   switch (request->version) {
      case PROXY_SOCKS_V4:
         state->rcurrent = recv_sockshost;
         break;

      case PROXY_SOCKS_V5:
         state->rcurrent = recv_flag;
         break;

      default:
         SERRX(request->version);
   }

   return state->rcurrent(s, request, state);
}

static int
recv_flag(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   INIT(sizeof(request->flag));
   CHECK(&request->flag, request->auth, recv_sockshost);

   SERRX(0); /* NOTREACHED */
}

static int
recv_sockshost(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
   switch (request->version) {
      case PROXY_SOCKS_V4:
         state->rcurrent = recv_port;
         break;

      case PROXY_SOCKS_V5:
         state->rcurrent = recv_atyp;
         break;

      default:
         SERRX(request->version);
   }

   return state->rcurrent(s, request, state);
}

static int
recv_atyp(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   INIT(sizeof(request->host.atype));
   CHECK(&request->host.atype, request->auth, recv_address);

   SERRX(0); /* NOTREACHED */
}

static int
recv_address(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   switch (request->version) {
      case PROXY_SOCKS_V4: {
         INIT(sizeof(request->host.addr.ipv4));

         request->host.atype = SOCKS_ADDR_IPV4; /* only one supported in v4. */

         CHECK(&request->host.addr.ipv4, request->auth, recv_username);
         SERRX(0); /* NOTREACHED */
      }

      case PROXY_SOCKS_V5:
         switch(request->host.atype) {
            case SOCKS_ADDR_IPV4: {
               INIT(sizeof(request->host.addr.ipv4));
               CHECK(&request->host.addr.ipv4, request->auth, recv_port);
               SERRX(0); /* NOTREACHED */
            }

            case SOCKS_ADDR_IPV6: {
               INIT(sizeof(request->host.addr.ipv6));
               CHECK(&request->host.addr.ipv6, request->auth, recv_port);
               SERRX(0); /* NOTREACHED */
            }

            case SOCKS_ADDR_DOMAIN: {
               INIT(sizeof(*request->host.addr.domain));
               CHECK(request->host.addr.domain, request->auth, NULL);

               /* LINTED conversion from 'int' may lose accuracy */
               OCTETIFY(*request->host.addr.domain);

               state->rcurrent = recv_domain;
               return state->rcurrent(s, request, state);
            }

            default:
               slog(LOG_DEBUG, "unknown address format %d in reply",
               request->host.atype);
               return -1;
         }

      default:
         SERRX(request->version);
   }

   SERRX(0); /* NOTREACHED */
}

static int
recv_domain(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
   unsigned char alen;
   /* first byte gives length. */
   INIT((unsigned char)*request->host.addr.domain);
   CHECK(request->host.addr.domain + 1, request->auth, NULL);

   alen = *request->host.addr.domain;

   /* convert to C string. */
   memmove(request->host.addr.domain, request->host.addr.domain + 1,
   (size_t)alen);
   request->host.addr.domain[alen] = NUL;

   state->rcurrent = recv_port;
   return state->rcurrent(s, request, state);
}

static int
recv_port(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   INIT(sizeof(request->host.port));
   CHECK(&request->host.port, request->auth, NULL);

   switch (request->version) {
      case PROXY_SOCKS_V4:
         state->rcurrent = recv_address;   /* in v4, address after port. */
         return state->rcurrent(s, request, state);

      case PROXY_SOCKS_V5:
         return 1;   /* all done. */

      default:
         SERRX(request->version);
   }

   SERRX(0); /* NOTREACHED */
}

static int
recv_username(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
   const char *function = "recv_username()";
   char *username = (char *)&state->mem[sizeof(request->version)
                                       + sizeof(request->command)
                                       + sizeof(request->host.port)
                                       + sizeof(request->host.addr.ipv4)];
   /* read until 0. */
   do {
      INIT(MIN(1, MEMLEFT()));

      if (MEMLEFT() == 0) {
         char visstring[MAXNAMELEN * 4 + 1];

         /*
          * Normally this would indicate an internal error and thus
          * be caught in CHECK(), but for the v4 case it could be
          * someone sending a really long username, which is strange
          * enough to log a warning about, but not an internal error.
          */

         state->mem[state->reqread - 1] = NUL;

         swarnx("%s: username too long (> %ld): \"%s\"", function,
         (unsigned long)strlen(username),
         str2vis(username, strlen(username), visstring, sizeof(visstring)));

         return -1;
      }

      CHECK(&state->mem[start], request->auth, NULL);

      /*
       * Since we don't know how long the username is, we can only read one
       * byte at a time.  We don't want CHECK() to set state->rcurrent to
       * NULL after each successful read of that one byte, since
       * recv_request() will then think we are starting from the beginning
       * next time we call it.
       */
      state->rcurrent = recv_username;
   } while (state->mem[state->reqread - 1] != 0);
   state->mem[state->reqread - 1] = NUL;   /* style. */

   slog(LOG_DEBUG, "%s: got socks v4 username: \"%s\"", function, username);

   state->rcurrent = NULL;
   return 1;   /* end of request. */
}

int
send_response(s, response)
   int s;
   const struct response_t *response;
{
#if !BAREFOOTD
   const char *function = "send_response()";
   ssize_t sendt;
   size_t length;
   unsigned char responsemem[sizeof(*response)];
   unsigned char *p = responsemem;

   switch (response->version) {
      case PROXY_SOCKS_V4REPLY_VERSION:
         /*
          * socks V4 reply packet:
          *
          *  VN   CD  DSTPORT  DSTIP
          *  1  + 1  +  2    +  4
          *
          *  Always 8 octets long.
          */

         memcpy(p, &response->version, sizeof(response->version));
         p += sizeof(response->version);

         /* CD (reply) */
         memcpy(p, &response->reply, sizeof(response->reply));
         p += sizeof(response->reply);

         break;

      case PROXY_SOCKS_V5:
         /*
          * socks V5 reply:
          *
          * +----+-----+-------+------+----------+----------+
          * |VER | REP |  FLAG | ATYP | BND.ADDR | BND.PORT |
          * +----+-----+-------+------+----------+----------+
          * | 1  |  1  |   1   |  1   | Variable |    2     |
          * +----+-----+-------+------+----------+----------+
          *   1     1      1      1                   2
          *
          * Which gives a fixed size of at least 6 octets.
          * The first octet of DST.ADDR when it is SOCKS_ADDR_DOMAINNAME
          * contains the length.
          *
          */

         /* VER */
         memcpy(p, &response->version, sizeof(response->version));
         p += sizeof(response->version);

         /* REP */
         memcpy(p, &response->reply, sizeof(response->reply));
         p += sizeof(response->reply);

         /* FLAG */
         memcpy(p, &response->flag, sizeof(response->flag));
         p += sizeof(response->flag);

         break;

      default:
         SERRX(response->version);
   }

   p = sockshost2mem(&response->host, p, response->version);
   length = p - responsemem;

   slog(LOG_DEBUG, "%s: sending response: %s",
   function, socks_packet2string(response, SOCKS_RESPONSE));

   if ((sendt = socks_sendton(s, responsemem, length, 1, 0, NULL, 0,
   response->auth)) != (ssize_t)length) {
      slog(LOG_DEBUG, "%s: socks_sendton(): %ld/%lu: %s",
      function, (long)sendt, (long unsigned)length, strerror(errno));
      return -1;
   }
#endif /* !BAREFOOTD */
   return 0;
}
