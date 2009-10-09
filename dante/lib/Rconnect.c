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
"$Id: Rconnect.c,v 1.167 2009/10/04 13:46:08 michaels Exp $";

int
Rconnect(s, name, namelen)
   int s;
   const struct sockaddr *name;
   socklen_t namelen;
{
   const char *function = "Rconnect()";
   struct socksfd_t socksfd;
   struct sockshost_t src, dst;
   struct authmethod_t auth;
   struct socks_t packet;
   socklen_t len;
   char namestr[MAXSOCKADDRSTRING];
   int val, nbconnect, savederrno;

   clientinit();

   if (name == NULL) {
      slog(LOG_DEBUG,
      "%s: sockaddr argument NULL, fallback to system connect()", function);
      return connect(s, name, namelen);
   }

   if (name->sa_family != AF_INET) {
      slog(LOG_DEBUG,
      "%s: unsupported address family '%d', fallback to system connect()",
      function, name->sa_family);
      return connect(s, name, namelen);
   }

   if (socks_socketisforlan(s)) {
      slog(LOG_DEBUG, "%s: socket is for lan only, system connect fallback",
      function);
      return connect(s, name, namelen);
   }

   slog(LOG_DEBUG, "%s: socket %d, address %s",
   function, s, sockaddr2string(name, namestr, sizeof(namestr)));

   if (socks_addrisours(s, 1)) {
      socksfd = *socks_getaddr(s, 1);

      slog(LOG_DEBUG, "%s: socket is a %s socket, err = %d, inprogress = %d",
                      function, version2string(socksfd.state.version),
                      socksfd.state.err, socksfd.state.inprogress);

      switch (socksfd.state.command) {
         case SOCKS_BIND:
            if (socksfd.state.protocol.tcp) {
               /*
                * Our guess; the client has succeeded to bind a specific
                * address and is now trying to connect out from it.
                * That also indicates the socks server is listening on a port
                * for this client.
                * Can't accept() on a connected socket so lets close the
                * connection to the server so it can stop listening on our
                * behalf, and we continue as if this was an ordinary connect().
                * Can only hope the server will use same port as we for
                * connecting out.
                *
                * Client might get problems if it has done a getsockname(2)
                * already, and thus thinks it knows it's local address,
                * as this Rconnect() will have to change it.
                */
               int tmp_s;

               slog(LOG_DEBUG, "%s: continuing with Rconnect() after Rbind() "
                               "on socket %d",
                               function, s);

               if (socksfd.state.version == PROXY_UPNP)
                  upnpcleanup(s);
               else {
                  /*
                   * socket must have connected to proxy before for Rbind().
                   * Need a new one.
                   */
                  if ((tmp_s = socketoptdup(s)) == -1)
                     break;
                  if (dup2(tmp_s, s) == -1)
                     break;
                  close(tmp_s);
                  socks_rmaddr(s, 1);
               }
            }
            else if (socksfd.state.protocol.udp) {
               /*
                * Previously bound the udp socket, and now want to
                * connect out on the same socket.  In this case
                * we want to keep the port bound on the server, and
                * just add a connect to the peer, so let udpsetup() do
                * it's thing.
                */
            }
            else
               SERRX(0);

            break;

         case SOCKS_CONNECT:
            if (socksfd.state.version == PROXY_UPNP) {
               val = connect(s, name, namelen);

               slog(LOG_DEBUG, "%s: connect(2) called again on upnp socket "
                               "returned %d, errno = %d (%s)", 
                               function, val, errno, strerror(errno));

               return val;
            }

            if (socksfd.state.err != 0)
               errno = socksfd.state.err;
            else {
               if (socksfd.state.inprogress)
                  errno = EALREADY;
               else
                  errno = EISCONN;
            }

            return -1;

         case SOCKS_UDPASSOCIATE:
            /*
             * Trying to connect a udp socket (to a new address)?
             * Just continue as usual, udpsetup() will reuse existing
             * setup and we just assign the new ("connected") address.
             */
            break;

         default:
            SERRX(socksfd.state.command);
      }
   }
   else {
      slog(LOG_DEBUG, "%s: doing socks_rmaddr(%d) before continuing ...",
      function, s);

      socks_rmaddr(s, 1);
   }

   bzero(&packet, sizeof(packet));

   len = sizeof(val);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) != 0) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return -1;
   }

   switch (val) {
      case SOCK_DGRAM: {
         struct route_t *route;

         if ((route = udpsetup(s, name, SOCKS_SEND)) == NULL)
            return -1;

         if (route->gw.state.proxyprotocol.direct)
            return connect(s, name, namelen);

         socksfd = *socks_getaddr(s, 1);

         if (socksfd.state.version == PROXY_SOCKS_V5) {
            if (connect(s, &socksfd.reply, sizeof(socksfd.reply)) != 0) {
               swarn("%s: connecting socket %d to %s failed",
               function, s,
               sockaddr2string(&socksfd.reply, namestr, sizeof(namestr)));

               socks_rmaddr(s, 1);
               return -1;
            }
         }
         else if (socksfd.state.version == PROXY_UPNP) {
            int p;

            if ((p = connect(s, name, namelen)) != 0) {
               swarn("%s: connect(%s)",
               function, sockaddr2string(name, namestr, sizeof(namestr)));

               return p;
            }
         }

         socksfd.state.udpconnect = 1;
         socksfd.forus.connected  = *name;
         socks_addaddr(s, &socksfd, 1);

         return 0;
      }

      case SOCK_STREAM:
         packet.req.protocol = SOCKS_TCP;
         break;

      default:
         swarnx("%s: unknown protocoltype %d, falling back to system connect",
         function, val);
         return connect(s, name, namelen);
   }

   bzero(&socksfd, sizeof(socksfd));
   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0)
      return -1;

   bzero(&src, sizeof(src)); /* silence valgrind warning */
   src.atype     = SOCKS_ADDR_IPV4;
   /* LINTED pointer casts may be troublesome */
   src.addr.ipv4 = TOIN(&socksfd.local)->sin_addr;
   /* LINTED pointer casts may be troublesome */
   src.port      = TOIN(&socksfd.local)->sin_port;

   bzero(&dst, sizeof(dst)); /* silence valgrind warning */
   fakesockaddr2sockshost(name, &dst);

   bzero(&auth, sizeof(auth));
   auth.method        = AUTHMETHOD_NOTSET;

   packet.req.version = PROXY_DIRECT;
   packet.req.command = SOCKS_CONNECT;
   packet.req.host    = dst;
   packet.req.auth    = &auth;

   if (socks_requestpolish(&packet.req, &src, &dst) == NULL)
      return -1;

   if (packet.req.version == PROXY_DIRECT) {
      int rc;

      slog(LOG_DEBUG, "%s: using direct systemcalls for socket %d",
      function, s);

      rc = connect(s, name, namelen);

      slog(LOG_DEBUG, "%s: direct connect on socket %d returned %d: (%s)",
      function, s, rc, strerror(errno));

      return rc;
   }

   switch (packet.version = packet.req.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
      case PROXY_HTTP_V1_0:
      case PROXY_UPNP:
         socksfd.control = s;
         break;

      case PROXY_MSPROXY_V2:
         /* always needs a separate controlchannel. */
         if ((socksfd.control = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
            return -1;
         break;

      default:
         SERRX(packet.req.version);
   }

   if (packet.version == PROXY_UPNP)
      /*
       * no negotiation to do before the connect, so we don't need
       * to care here whether the socket is blocking or not.
       * We need to care concerning the return value from this function
       * though, as if non-blocking, after socks_negotiate(),
       * the socket may still not be connected.
       */
      nbconnect = 0;
   else
      /*
       * Check if the socket is non-blocking.  If so, fork a child
       * to negotiate with the proxy server and establish the connection.
       * In the case of UPNP, no negotiation is done, so don't waste
       * time on that.
       */
      nbconnect = !fdisblocking(s);

   errno = 0;
   if (nbconnect)
      socksfd.route
      = socks_nbconnectroute(s, socksfd.control, &packet, &src, &dst);
   else
      socksfd.route = socks_connectroute(socksfd.control, &packet, &src, &dst);

   slog(LOG_DEBUG, "%s: route for socket %d %s, errno = %d",
   function, s, socksfd.route == NULL ? "not found" : "found", errno);

   if (socksfd.route == NULL) {
      if (s != socksfd.control)
         close(socksfd.control);

      switch (errno) {
         case EADDRINUSE: {
            /*
             * This problem can arise when we are socksifying
             * a server application that does several outbound
             * connections from the same address (e.g. ftpd) to the
             * same socks server.
             * It has by now successfully bound the address (it thinks)
             * and is not expecting this error.
             * Not sure what is best to do, just failing here prevents
             * ftpd from working for clients using the PORT command.
             *
             * For now, lets retry with a new socket.
             * This means the server no longer has bound the address
             * it (may) think it has ofcourse, so not sure how smart this
             * really is.
             */
            int tmp_s;

            swarn("%s: server socksified?  trying to work around problem...",
            function);

            if ((tmp_s = socketoptdup(s)) == -1)
               break;
            if (dup2(tmp_s, s) == -1)
               break;
            close(tmp_s);

            /*
             * if s was bound to a privileged port, try to bind the new
             * s too to a privileged port.
             */
            /* LINTED pointer casts may be troublesome */
            if (PORTISRESERVED(TOIN(&socksfd.local)->sin_port)) {
               /* LINTED pointer casts may be troublesome */
               TOIN(&socksfd.local)->sin_port = htons(0);

               /* LINTED pointer casts may be troublesome */
               bindresvport(s, TOIN(&socksfd.local));
            }

            return Rconnect(s, name, namelen);
         }

         default:
            return -1;
      }
   }

   if (nbconnect) {
      slog(LOG_DEBUG, "got route, nonblocking connect in progress, "
      "errno = %d (%s)", errno, strerror(errno));

      return -1;
   }

   if (socks_negotiate(s, socksfd.control, &packet, socksfd.route) != 0)
      return -1;

   savederrno = errno;
   slog(LOG_DEBUG, "%s: errno after successfull socks_negotiate() is %d",
   function, savederrno);

   socksfd.state.auth            = auth;
   socksfd.state.command         = packet.req.command;
   socksfd.state.version         = packet.res.version;
   socksfd.state.protocol.tcp    = 1;
   socksfd.state.msproxy         = packet.state.msproxy;
   sockshost2sockaddr(&packet.res.host, &socksfd.remote);
   socksfd.forus.connected       = *name;

   /* LINTED pointer casts may be troublesome */
   if (TOIN(&socksfd.local)->sin_port != htons(0)
   &&  TOIN(&socksfd.local)->sin_port != TOIN(&socksfd.remote)->sin_port){
      /*
       * unfortunate; the client is trying to connect from a specific
       * port, a port it has successfully bound, but the port is currently
       * in use on the serverside or the server doesn't care.
       */

      /* LINTED pointer casts may be troublesome */
      slog(LOG_DEBUG, "failed to get wanted port %d, but got %d and continuing",
      ntohs(TOIN(&socksfd.local)->sin_port),
      ntohs(TOIN(&socksfd.remote)->sin_port));
   }

   len = sizeof(socksfd.server);
   if (getpeername(s, &socksfd.server, &len) != 0)
      if (packet.version != PROXY_UPNP || fdisblocking(s))
         slog(LOG_DEBUG, "%s: getpeername(s): %s", function, strerror(errno));

   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0)
      slog(LOG_DEBUG, "%s: getsockname(s): %s", function, strerror(errno));


   socks_addaddr(s, &socksfd, 1);
   sockscf.state.lastconnect = *name;   /* needed for standard socks bind. */

   slog(LOG_DEBUG, "%s: returning ... errno is %d", function, savederrno);

   errno = savederrno;

   if (errno != 0) /* something happened, but could just be EINPROGRESS. */
      return -1;

   return 0;
}
