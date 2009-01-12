/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2009
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
"$Id: Rbind.c,v 1.134 2009/01/10 22:59:34 michaels Exp $";

int
Rbind(s, name, namelen)
   int s;
   const struct sockaddr *name;
   socklen_t namelen;
{
   const char *function = "Rbind()";
   struct socks_t packet;
   struct socksfd_t socksfd;
   socklen_t len;
   int val, rc;

   clientinit();

   slog(LOG_DEBUG, "%s, s = %d", function, s);

   /*
    * Nothing can be called before Rbind(), delete any old cruft.
    */
   socks_rmaddr((unsigned int)s, 0);

   rc = bind(s, name, namelen);

   if (name->sa_family != AF_INET) {
      slog(LOG_DEBUG, "%s: socket %d, unsupported af '%d', system fallback",
      function, s, name->sa_family);
      return rc;
   }

   /*
    * We need a way to know whether the socket is to be used by e.g.
    * miniupnp for i/o with devices on the lan, but how can we know
    * that, when all we have to decide on is the address to bind?
    * At the moment this works, because miniupnp will bind the socket
    * to an interface (when we use it as we do), but this is not
    * reliable. XXX
    */
   if (socks_socketisforlan(s)) {
      slog(LOG_DEBUG, "%s: socket %d is for lan only, system bind fallback",
      function, s);

      return rc;
   }

   if (rc != 0) {
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
             * Somehow the socket has been bound locally already.
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
   if (getenv("SOCKS_BINDLOCALONLY") != NULL)
      return rc;

   bzero(&socksfd, sizeof(socksfd));
   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0) {
      close(socksfd.control);
      return -1;
   }

   bzero(&packet, sizeof(packet));
   packet.req.version        = PROXY_DIRECT;
   packet.auth.method        = AUTHMETHOD_NOTSET;
   packet.req.command        = SOCKS_BIND;
   packet.req.host.atype     = SOCKS_ADDR_IPV4;
   packet.req.host.addr.ipv4 = TOIN(&sockscf.state.lastconnect)->sin_addr;
   /* LINTED pointer casts may be troublesome */
   packet.req.host.port      = TOIN(&socksfd.local)->sin_port;

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
         swarnx("%s: unknown protocoltype %d, falling back to system bind",
         function, val);
         return rc;
   }

   if (socks_requestpolish(&packet.req, NULL, NULL) == NULL
   ||  packet.req.version == PROXY_DIRECT)
      return 0; /* no route, socket bound, hope local bind is enough. */

   packet.version = packet.req.version;

   if (packet.req.protocol == SOCKS_UDP)
      /* not all proxyprotocols support udp. */
      switch (packet.version) {
         case PROXY_UPNP:
         case PROXY_MSPROXY_V2:
            break; /* ok, udp supported. */

         default:
            slog(LOG_DEBUG, "%s: binding udp sockets is not supported by "
            "proxyprotocol v%d, hoping local bind is good enough\n",
            function, packet.req.version); 

            return 0;
      }

   /*
    * Create a separate socket for the control connection, so that if
    * e.g the connect(2) to the sockeserver fails, it doesn't mess up
    * things for caller.  After everything is ok, dup the control connection
    * over to be the same socket as caller passed us.
    */
   switch (packet.req.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5: {
         int portisreserved;
         struct sockaddr saddr;

         if ((socksfd.control = socketoptdup(s)) == -1)
            return -1;

         /*
          * Make sure the control-connection is bound to the same
          * ipaddress as 's', or the bind extension will not work if
          * we connect to the socksserver from a different ipaddress
          * than the one we bound.
          */
         saddr = socksfd.local;
         TOIN(&saddr)->sin_port = htons(0);
         if (bind(socksfd.control, &saddr, sizeof(saddr)) != 0) {
            swarn("%s: failed to bind control-socket", function);
            return -1;
         }

         switch (packet.req.version) {
            case PROXY_SOCKS_V4:
               /*
                * v4 can only specify wanted port by using bind extension.
                * XXX
                */

               SASSERTX(packet.req.host.atype == SOCKS_ADDR_IPV4);
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

         if (portisreserved) {
            int p;
            struct sockaddr_in controladdr;

            /*
             * Our caller has gotten a reserved port.  It is possible the
             * server will differentiate between requests coming from
             * privileged ports and those not so try to connect to server
             * from a privileged port.
             */

            bzero(&controladdr, sizeof(controladdr));
            controladdr.sin_family      = AF_INET;
            controladdr.sin_addr.s_addr = htonl(INADDR_ANY);
            controladdr.sin_port        = htons(0);

            if ((p = bindresvport(socksfd.control, &controladdr)) != 0) {
               controladdr.sin_port = htons(0);
               /* LINTED pointer casts may be troublesome */
               p = bind(socksfd.control, (struct sockaddr *)&controladdr,
               sizeof(controladdr));
            }

            if (p != 0) {
               close(socksfd.control);
               return -1;
            }
         }

         break;
      }

      case PROXY_MSPROXY_V2:
         if ((socksfd.control = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
            return -1;
         break;

      case PROXY_UPNP:
         socksfd.control = s; /* no separate controlsocket. */
         break;

      default:
         SERRX(packet.req.version);
   }

   if ((socksfd.route
   = socks_connectroute(socksfd.control, &packet, NULL, NULL)) == NULL) {
      if (socksfd.control != s)
         close(socksfd.control);
      return 0;   /* have done a normal bind and no route, assume local. */
   }

   if (socks_negotiate(s, socksfd.control, &packet, socksfd.route) != 0) {
      if (socksfd.control != s)
         close(socksfd.control);
      return -1;
   }

   socksfd.state.auth    = packet.auth;
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
             * we connected to for the controlconnection.
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

      case PROXY_MSPROXY_V2:
         socksfd.state.acceptpending  = 1; /* separate data connection. */
         socksfd.state.msproxy        = packet.state.msproxy;
         /* don't know what address connection will be forwarded from yet. */
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

      if (socksfd.control != s) {
         /*
          * Since the socket is already bound locally, "unbind" it so
          * later error messages on the same socket make sense to the caller.
          */
         slog(LOG_DEBUG,
         "%s: failed to bind requested port %d on gateway, \"unbinding\"",
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
      /*
       * will accept(2) connection on 's', don't need to do anything more.
       */
      ;
   else { /* dup socksfd.control over to 's', control and data is the same. */
      slog(LOG_DEBUG,
      "will accept bind data over controlsocket ... dup(2)ing to %d", s);

      if (dup2(socksfd.control, s) == -1) {
         swarn("dup2(socksfd.control, s) failed");
         return -1;
      }

      close(socksfd.control);
      socksfd.control = s; 

      len = sizeof(socksfd.local);
      if (getsockname(s, &socksfd.local, &len) != 0) {
         swarn("getsockname(s) failed");
         close(socksfd.control);
         return -1;
      }
   }

   switch (socksfd.state.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
         socks_addaddr((unsigned int)s, &socksfd, 0);
         break;

      case PROXY_MSPROXY_V2:
         /* more talk will have to occur before we can perform a accept(). */
         socksfd.state.inprogress = 1;

         socks_addaddr((unsigned int)s, &socksfd, 0);
         if (msproxy_sigio(s) != 0) {
            socks_rmaddr((unsigned int)s, 0);
            return -1;
         }

         break;

      case PROXY_UPNP:
         socks_addaddr((unsigned int)s, &socksfd, 0);
         break;

      default:
         SERRX(socksfd.state.version);
   }

   return 0;
}
