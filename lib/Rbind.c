/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2004, 2005, 2006, 2008, 2009,
 *               2010, 2011
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
"$Id: Rbind.c,v 1.169 2011/07/10 15:00:33 michaels Exp $";

int
Rbind(s, name, namelen)
   int s;
   const struct sockaddr *name;
   socklen_t namelen;
{
   const char *function = "Rbind()";
   struct authmethod_t auth;
   struct socks_t packet;
   struct socksfd_t socksfd;
   socklen_t len;
   int val, rc, flags;

   clientinit();

   slog(LOG_DEBUG, "%s, socket %d, address %s",
   function, s, sockaddr2string(name, NULL, 0));

   /*
    * Nothing can be called before Rbind(), delete any old cruft.
    */
   socks_rmaddr(s, 1);

   rc = bind(s, name, namelen);
   slog(LOG_DEBUG, "%s: local bind returned %d", function, rc);

   if (name->sa_family != AF_INET) {
      slog(LOG_DEBUG, "%s: socket %d, unsupported af '%d', system fallback",
      function, s, name->sa_family);

      return rc;
   }

   if (socks_socketisforlan(s)) {
      slog(LOG_DEBUG, "%s: socket %d is for lan only, system bind fallback",
      function, s);

      return rc;
   }

   if (rc != 0) {
      slog(LOG_DEBUG, "%s: bind(%d) failed: %s", function, s, strerror(errno));

      switch (errno) {
         case EADDRNOTAVAIL: {
            /* LINTED pointer casts may be troublesome */
            struct sockaddr_in newname = *TOCIN(name);

            /*
             * We try to make the client think it's address is the address
             * the server is using on it's behalf.  Some clients might try
             * bind that IP address (with a different port, presumably)
             * themselves though, in that case, use INADDR_ANY.
             */

            slog(LOG_DEBUG, "%s: retrying bind with INADDR_ANY", function);

            newname.sin_addr.s_addr = htonl(INADDR_ANY);
            /* LINTED pointer casts may be troublesome */
            if (bind(s, (struct sockaddr *)&newname, sizeof(newname)) != 0)
               return -1;
            break;
         }

         case EINVAL: {
            struct sockaddr_in addr;
            socklen_t addrlen;
            int errno_s = errno;

            /*
             * Do a little testing on what caused the error.
            */

            addrlen = sizeof(addr);
            /* LINTED pointer casts may be troublesome */
            if (getsockname(s, (struct sockaddr *)&addr, &addrlen) != 0
            ||  addr.sin_port == htons(0)) {
               errno = errno_s;
               return -1;
            }

            /*
             * Somehow the socket has been bound locally already,
             * perhaps due to bindresvport(3).
             * Best guess is probably to keep that and attempt a
             * remote server binding aswell.
             */
            break;
         }

         default:
            return -1;
      }
   }

   /* hack for performance testing. */
   if (socks_getenv("SOCKS_BINDLOCALONLY", dontcare) != NULL)
      return rc;

   bzero(&socksfd, sizeof(socksfd));
   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0) {
      close(socksfd.control);
      return -1;
   }

   bzero(&auth, sizeof(auth));
   auth.method               = AUTHMETHOD_NOTSET;

   bzero(&packet, sizeof(packet));
   packet.req.version        = PROXY_DIRECT;
   packet.req.command        = SOCKS_BIND;
   packet.req.host.atype     = (unsigned char)SOCKS_ADDR_IPV4;
   packet.req.host.addr.ipv4 = TOIN(&sockscf.state.lastconnect)->sin_addr;
   /* LINTED pointer casts may be troublesome */
   packet.req.host.port      = TOIN(&socksfd.local)->sin_port;
   packet.req.auth           = &auth;

   len = sizeof(val);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) != 0) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return -1;
   }
   switch (val) {
      case SOCK_DGRAM:
         packet.req.protocol = SOCKS_UDP;
         break;

      case SOCK_STREAM:
         packet.req.protocol = SOCKS_TCP;
         break;

      default:
         swarnx("%s: unknown protocol type %d, falling back to system bind",
         function, val);
         return rc;
   }

   if (socks_requestpolish(&packet.req, NULL, NULL) == NULL)
      return -1;

   if (packet.req.version == PROXY_DIRECT) {
      slog(LOG_DEBUG, "%s: using direct system calls for socket %d",
      function, s);

      return 0;
   }

   packet.version = packet.req.version;

   if (packet.req.protocol == SOCKS_UDP) {
      /* not all proxy protocols support udp. */
      switch (packet.version) {
         case PROXY_UPNP:
            break; /* ok, udp supported. */

         default:
            slog(LOG_DEBUG, "%s: binding udp sockets is not supported by "
            "proxy protocol %s, hoping local bind is good enough\n",
            function, version2string(packet.req.version));

            return 0;
      }
   }

   /*
    * Create a separate socket for the control connection, so that if
    * e.g the connect(2) to the socks server fails, it doesn't mess up
    * things for caller.  After everything is ok, dup the control connection
    * over to be the same socket as caller passed us.
    */
   switch (packet.req.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5: {
         int portisreserved, haveboundaddr;
         struct sockaddr saddr;

         if ((socksfd.control = socketoptdup(s)) == -1)
            return -1;

         switch (packet.req.version) {
            case PROXY_SOCKS_V4:
               /*
                * v4 can only specify wanted port by using bind extension.
                * XXX
                */

               SASSERTX(packet.req.host.atype
               == (unsigned char)SOCKS_ADDR_IPV4);

               if (packet.req.host.addr.ipv4.s_addr == ntohl(0))
                  portisreserved = PORTISRESERVED(packet.req.host.port);
               else
                  portisreserved = 0;
               break;

            case PROXY_SOCKS_V5:
               portisreserved = PORTISRESERVED(packet.req.host.port);
               break;

            default:
               SERRX(packet.req.version);
         }

         /*
          * Make sure the control-connection is bound to the same
          * ip address as 's', or the bind extension will not work if
          * we connect to the socks server from a different ip address
          * than the one we bound.
          */
         saddr                  = socksfd.local;
         TOIN(&saddr)->sin_port = htons(0);

         haveboundaddr = 0;
         if (portisreserved) {
            /*
             * Our caller has gotten a reserved port.  It is possible the
             * server will differentiate between requests coming from
             * privileged ports and those not so try to connect to server
             * from a privileged port.
             */
            slog(LOG_DEBUG, "%s: caller has a privileged port ... then we "
                            "should probably also try to bind a privileged "
                            "port locally",
                            function);

            if (bindresvport(socksfd.control, (struct sockaddr_in *)&saddr)
            == 0)
               haveboundaddr = 1;
            else
               slog(LOG_DEBUG,
                    "%s: failed to locally bind a privileged port "
                    "using address %s.  Errno = %d (%s)",
                    function,
                    sockaddr2string(&saddr, NULL, 0),
                    errno,
                    strerror(errno));
         }

         if (!haveboundaddr)
            if (bind(socksfd.control, &saddr, sizeof(saddr)) != 0) {
               swarn("%s: failed to bind address for control-socket", function);
               close(socksfd.control);

               return -1;
            }

         break;
      }

      case PROXY_UPNP:
         socksfd.control = s; /* no separate control socket. */
         break;

      default:
         SERRX(packet.req.version);
   }

   /*
    * we're not interested the extra hassle of negotiating over
    * a non-blocking socket, so make sure it's blocking while we
    * use it.
    */
   if ((flags = fcntl(socksfd.control, F_GETFL, 0))                  == -1
   ||           fcntl(socksfd.control, F_SETFL, flags & ~O_NONBLOCK) == -1)
      swarn("%s: fcntl(s)", function);

   if ((socksfd.route
   = socks_connectroute(socksfd.control, &packet, NULL, NULL)) == NULL
   || socksfd.route->gw.state.proxyprotocol.direct) {
      if (socksfd.control != s)
         close(socksfd.control);
      return 0;   /* have done a normal bind and no route, assume local. */
   }

   if (socks_negotiate(s, socksfd.control, &packet, socksfd.route) != 0) {
      if (socksfd.control != s)
         close(socksfd.control);
      return -1;
   }

   /* back to original. */
   if (flags != -1)
      if (fcntl(socksfd.control, F_SETFL, flags) == -1)
         swarn("%s: fcntl(s)", function);

   socksfd.state.auth    = auth;
   socksfd.state.command = packet.req.command;

   if (packet.req.protocol == SOCKS_TCP)
      socksfd.state.protocol.tcp = 1;
   else if (packet.req.protocol == SOCKS_UDP)
      socksfd.state.protocol.udp = 1;

   socksfd.state.version = packet.req.version;
   sockshost2sockaddr(&packet.res.host, &socksfd.remote);

   switch (packet.req.version) {
      case PROXY_SOCKS_V4:
         /* LINTED pointer casts may be troublesome */
         if (TOIN(&socksfd.remote)->sin_addr.s_addr == htonl(0)) {
            /*
             * v4 specific; server doesn't say, so should set it to address
             * we connected to for the control connection.
             */
            struct sockaddr_in addr;

            len = sizeof(addr);
            /* LINTED pointer casts may be troublesome */
            if (getpeername(socksfd.control, (struct sockaddr *)&addr, &len)
            != 0)
               SERR(-1);

            /* LINTED pointer casts may be troublesome */
            TOIN(&socksfd.remote)->sin_addr = addr.sin_addr;
         }
         /* FALLTHROUGH */

      case PROXY_SOCKS_V5:
         socksfd.reply                = socksfd.remote;   /* same IP address. */
         socksfd.state.acceptpending  = socksfd.route->gw.state.extension.bind;
         break;

      case PROXY_UPNP:
         socksfd.state.acceptpending = 1; /* separate data connection. */
         /* don't know what address connection will be forwarded from. */
         break;

      default:
         SERRX(packet.req.version);
   }

   /* did we get the requested port? */
   /* LINTED pointer casts may be troublesome */
   if (TOCIN(name)->sin_port != htons(0)
   &&  TOCIN(name)->sin_port != TOIN(&socksfd.remote)->sin_port) { /* no. */
      int new_s;

      socks_freebuffer(socksfd.control);

      if (socksfd.control != s) {
         /*
          * Since the socket is already bound locally, "unbind" it so
          * later error messages on the same socket make sense to the caller.
          */
         slog(LOG_DEBUG,
         "%s: failed to bind requested port %u on gateway, \"unbinding\"",
         function, ntohs(TOCIN(name)->sin_port));

         close(socksfd.control);
      }

      if ((new_s = socketoptdup(s)) == -1)
         return -1;

      dup2(new_s, s);
      close(new_s);

      errno = EADDRINUSE;
      return -1;
   }

   if (socksfd.control != s) {
      len = sizeof(socksfd.server);
      if (getpeername(socksfd.control, &socksfd.server, &len) != 0) {
         if (socksfd.control != s)
            close(socksfd.control);
         return -1;
      }
   }

   if (socksfd.state.acceptpending)
      /* will accept(2) connection on 's', don't need to do anything more.  */
      socks_freebuffer(socksfd.control);
   else { /* dup socksfd.control over to 's', control and data is the same. */
      slog(LOG_DEBUG, "will accept bind data over control socket ... "
                      "dup(2)ing %d to %d",
                       socksfd.control, s);

      if (dup2(socksfd.control, s) == -1) {
         swarn("dup2(socksfd.control, s) failed");
         return -1;
      }

      /*
       * won't be using a buffer for the socket we listen on, but
       * may have to use it for the one we accepted the bind reply on.
       */
      socks_reallocbuffer(socksfd.control, s);

      close(socksfd.control);
      socksfd.control = s;

      len = sizeof(socksfd.local);
      if (getsockname(s, &socksfd.local, &len) != 0) {
         swarn("getsockname(s) failed");
         close(socksfd.control);
         socks_freebuffer(socksfd.control);
         return -1;
      }
   }

   switch (socksfd.state.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
      case PROXY_UPNP:
         socks_addaddr(s, &socksfd, 1);
         break;

      default:
         SERRX(socksfd.state.version);
   }

   return 0;
}
