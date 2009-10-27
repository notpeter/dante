/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2004, 2005, 2008, 2009
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
"$Id: Raccept.c,v 1.116 2009/10/23 11:43:33 karls Exp $";

static int
addforwarded(const int local, const int remote,
             const struct sockaddr *remoteaddr,
             const struct sockaddr *virtualremoteaddr);
/*
 * Adds a proxy-forwarded remote client to our list over proxied
 * clients.
 * "local" gives the local socket we listen on,
 * "remote" is the socket connected to the remote client,
 * "remoteaddr" is the physical peer of "remote" (the proxyserver),
 * and "virtualremoteaddr" is the address the proxy claims to be
 * forwarding.
 *
 * Returns 0 if the remote client was successfully added, or -1 if not.
 */
int
Raccept(s, addr, addrlen)
   int s;
   struct sockaddr *addr;
   socklen_t *addrlen;
{
   const char *function = "Raccept()";
   static fd_set *rset;
   struct socksfd_t socksfd;
   char addrstring[MAXSOCKADDRSTRING];
   struct sockaddr accepted;
   struct socks_t packet;
   int fdbits, p, remote;

   clientinit();

   slog(LOG_DEBUG, "%s, socket %d", function, s);

   /* can't call Raccept() on unknown descriptors. */
   if (!socks_addrisours(s, 1)) {
      slog(LOG_DEBUG, "%s: socket %d is unknown, going direct", function, s);
      socks_rmaddr(s, 1);

      return accept(s, addr, addrlen);
   }

   socksfd = *socks_getaddr(s, 1);

   bzero(&packet, sizeof(packet));
   packet.version = (unsigned char)socksfd.state.version;

   if (rset == NULL)
      rset = allocate_maxsize_fdset();

   FD_ZERO(rset);
   fdbits = -1;

   /* check socket we listen on because we may support ordinary accepts. */
   FD_SET(s, rset);
   fdbits = MAX(fdbits, s);

   switch (packet.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
         /* connection to server, for forwarded connections or errors. */
         FD_SET(socksfd.control, rset);
         fdbits = MAX(fdbits, socksfd.control);
         break;

      case PROXY_MSPROXY_V2:
         break;   /* controlconnection checked asynchronously. */

      case PROXY_UPNP:
         /* ordinary accept(2). */
         return accept(s, addr, addrlen);

      default:
         SERRX(packet.version);
   }

   SASSERTX(fdbits >= 0);

   ++fdbits;

   if (!fdisblocking(s)) {
      struct timeval timeout;

      timeout.tv_sec      = 0;
      timeout.tv_usec   = 0;

      if ((p = selectn(fdbits, rset, NULL, NULL, NULL, NULL, &timeout)) == 0) {
         errno = EWOULDBLOCK;
         p = -1;
      }
   }
   else
      p = selectn(fdbits, rset, NULL, NULL, NULL, NULL, NULL);

   if (p == -1)
      return -1;

   SASSERTX(p > 0);

   if (FD_ISSET(socksfd.control, rset)) { /* check this first.  */
      /* pending connection on controlchannel, server wants to forward addr. */
      SASSERTX(FD_ISSET(socksfd.control, rset));

      switch (packet.version) {
         case PROXY_SOCKS_V4:
         case PROXY_SOCKS_V5: {
            struct socksfd_t sfddup;

            packet.res.auth = &socksfd.state.auth;
            if (socks_recvresponse(socksfd.control, &packet.res,
            packet.version) != 0)
               return -1;
            fakesockshost2sockaddr(&packet.res.host, &accepted);

            socksfd = *socks_getaddr(s, 1);
            socksfd.forus.accepted = accepted;
            socks_addaddr(s, &socksfd, 1);

            if ((remote = dup(socksfd.control)) == -1) {
               swarn("%s: dup()", function);
               return -1;
            }

            if (socks_addrdup(&socksfd, &sfddup) == NULL) {
               swarn("%s: socks_addrdup()", function);

               if (errno == EBADF)
                  socks_rmaddr(s, 0);

               return -1;
            }

            socks_addaddr(remote, &sfddup, 1);
            socks_reallocbuffer(socksfd.control, remote);

            break;
         }

         case PROXY_MSPROXY_V2:
            SERRX(0); /* should not be checked, so not checked either. */
            break;

         default:
            SERRX(packet.version);
      }
   }
   else { /* pending connection on datasocket. */
      socklen_t len;

      len = sizeof(accepted);
      if ((remote = accept(s, &accepted, &len)) == -1)
         return -1;

      slog(LOG_DEBUG, "%s: accepted: %s",
      function, sockaddr2string(&accepted, addrstring, sizeof(addrstring)));

      if (socksfd.state.acceptpending) {
         /*
          * connection forwarded by server, or a ordinary connect?
          */

         /* LINTED pointer casts may be troublesome */
         if (TOIN(&accepted)->sin_addr.s_addr
         ==  TOIN(&socksfd.reply)->sin_addr.s_addr) {
            /* matches servers IP address, assume forwarded connection. */
            int forwarded;

            switch (socksfd.state.version) {
               case PROXY_SOCKS_V4:
               case PROXY_SOCKS_V5: {
                  struct authmethod_t auth = socksfd.state.auth;

                  packet.req.version   = (unsigned char)socksfd.state.version;
                  packet.req.command   = SOCKS_BIND;
                  packet.req.flag      = 0;
                  sockaddr2sockshost(&accepted, &packet.req.host);
                  packet.req.auth      = &auth;

                  if (socks_sendrequest(socksfd.control, &packet.req) != 0) {
                     close(remote);
                     return -1;
                  }

                  if (socks_recvresponse(socksfd.control, &packet.res,
                  packet.req.version) != 0) {
                     close(remote);
                     return -1;
                  }

                  if (packet.res.host.atype != SOCKS_ADDR_IPV4) {
                     swarnx("%s: unexpected atype in bindquery response: %d",
                     function, packet.res.host.atype);
                     close(remote);
                     errno = ECONNABORTED;
                     return -1;
                  }

                  if (packet.res.host.addr.ipv4.s_addr == htonl(0))
                     forwarded = 0;
                  else
                     forwarded = 1;
                  break;
               }

               case PROXY_MSPROXY_V2:
                  if (sockaddrareeq(&socksfd.reply, &accepted)) {
                     /* socksfd.forus.accepted filled in by sigio(). */
                     accepted = socksfd.forus.accepted;
                     sockaddr2sockshost(&socksfd.forus.accepted,
                     &packet.res.host);

                     socksfd = *socks_getaddr(s, 1);
                     /* seems to support only one forward. */
                     socksfd.state.acceptpending = 0;
                     socks_addaddr(s, &socksfd, 1);
                     forwarded = 1;
                  }
                  else
                     forwarded = 0;
                  break;

               default:
                  SERRX(socksfd.state.version);
            }

            if (forwarded) {
               struct sockaddr fakeaddr;

               fakesockshost2sockaddr(&packet.res.host, &fakeaddr);

               if (addforwarded(s, remote, &accepted, &fakeaddr) != 0)
                  return -1;
            }
            /* else; ordinary remote connect, nothing to do. */
         }
      }
      else
         SWARNX(0);
   }

   if (addr != NULL) {
      *addrlen = MIN(*addrlen, (socklen_t)sizeof(accepted));
      memcpy(addr, &accepted, (size_t)*addrlen);
   }

   return remote;
}

static int
addforwarded(local, remote, remoteaddr, virtualremoteaddr)
   const int local;
   const int remote;
   const struct sockaddr *remoteaddr;
   const struct sockaddr *virtualremoteaddr;
{
   const char *function = "addforwarded()";
   socklen_t len;
   struct socksfd_t rfd;

   slog(LOG_DEBUG, "%s: registering socket %d as accepted from socket %d",
   function, remote, local);

   if (socks_addrdup(socks_getaddr(local, 1), &rfd) == NULL) {
      swarn("%s: socks_addrdup()", function);

      if (errno == EBADF)
         socks_rmaddr(local, 1);

      return -1;
   }

   /*
    * a separate socket with it's own remote address and possibly different
    * local address too, so need to add it to the socksfd table.
    */

   rfd.state.acceptpending = 0;
   rfd.remote              = *remoteaddr;
   rfd.forus.accepted      = *virtualremoteaddr;

   /* has a local address now if unbound before. */
   /* LINTED pointer casts may be troublesome */
   if (!ADDRISBOUND(TOIN(&rfd.local))) {
      len = sizeof(rfd.local);
      if (getsockname(remote, &rfd.local, &len) != 0)
         swarn("%s: getsockname(remote)", function);
   }

   socks_addaddr(remote, &rfd, 1);

   return 0;
}
