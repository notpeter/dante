/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004
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
"$Id: Raccept.c,v 1.86 2008/07/25 08:48:53 michaels Exp $";

int
Raccept(s, addr, addrlen)
   int s;
   struct sockaddr *addr;
   socklen_t *addrlen;
{
   const char *function = "Raccept()";
   struct socksfd_t socksfd;
   char addrstring[MAXSOCKADDRSTRING];
   struct sockaddr accepted;
   struct socks_t packet;
   fd_set rset;
   int fdbits, p, iotype, remote;

   clientinit();

   slog(LOG_DEBUG, "%s, s = %d", function, s);

   /* can't call Raccept() on unknown descriptors. */
   if (!socks_addrisok((unsigned int)s, 0)) {
      socks_rmaddr((unsigned int)s, 0);
      return accept(s, addr, addrlen);
   }

   socksfd = *socks_getaddr((unsigned int)s, 0);

   bzero(&packet, sizeof(packet));
   packet.version       = (unsigned char)socksfd.state.version;
   packet.auth.method   = AUTHMETHOD_NOTSET;

   if ((iotype = fcntl(s, F_GETFL, 0)) == -1)
      return -1;

   FD_ZERO(&rset);
   fdbits = -1;

   /* check socket we listen on because we support ordinary connects. */
   FD_SET(s, &rset);
   fdbits = MAX(fdbits, s);

   switch (packet.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
         /* connection to server, for forwarded connections or errors. */
         FD_SET(socksfd.control, &rset);
         fdbits = MAX(fdbits, socksfd.control);
         break;

      case PROXY_MSPROXY_V2:
         break;   /* controlconnection checked asynchronously. */

      case PROXY_UPNP:
         return accept(s, addr, addrlen); /* ordinary accept(2). */
         
      default:
         SERRX(packet.version);
   }

   SASSERTX(fdbits >= 0);

   ++fdbits;

   if (iotype & NONBLOCKING) {
      struct timeval timeout;

      timeout.tv_sec      = 0;
      timeout.tv_usec   = 0;

      if ((p = selectn(fdbits, &rset, NULL, NULL, &timeout)) == 0) {
         errno = EWOULDBLOCK;
         p = -1;
      }
   }
   else
      p = selectn(fdbits, &rset, NULL, NULL, NULL);

   if (p == -1)
      return -1;

   SASSERTX(p > 0);

   if (FD_ISSET(socksfd.control, &rset)) { /* check this first.  */
      /* pending connection on controlchannel, server wants to forward addr. */
      SASSERTX(FD_ISSET(socksfd.control, &rset));

      switch (packet.version) {
         case PROXY_SOCKS_V4:
         case PROXY_SOCKS_V5:

            if (socks_recvresponse(socksfd.control, &packet.res,
            packet.version) != 0)
               return -1;

            fakesockshost2sockaddr(&packet.res.host, &accepted);

            socks_addrlock(F_WRLCK);

            socksfd = *socks_getaddr((unsigned int)s, 1);
            socksfd.forus.accepted = accepted;
            socks_addaddr((unsigned int)s, &socksfd, 1);

            socks_addrunlock();

            remote = dup(socksfd.control);
            break;

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
          * connection forwarded by server or a ordinary connect?
          */

         /* LINTED pointer casts may be troublesome */
         if (TOIN(&accepted)->sin_addr.s_addr
         ==  TOIN(&socksfd.reply)->sin_addr.s_addr) {
            /* matches servers IP address, could be forwarded. */
            int forwarded;

            switch (socksfd.state.version) {
               case PROXY_SOCKS_V4:
               case PROXY_SOCKS_V5: {
                  struct authmethod_t auth = socksfd.state.auth;

                  packet.req.version   = (char)socksfd.state.version;
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

                     socks_addrlock(F_WRLCK);

                     socksfd = *socks_getaddr((unsigned int)s, 1);
                     /* seems to support only one forward. */
                     socksfd.state.acceptpending = 0;
                     socks_addaddr((unsigned int)s, &socksfd, 1);

                     socks_addrunlock();

                     forwarded = 1;
                  }
                  else
                     forwarded = 0;
                  break;

               default:
                  SERRX(socksfd.state.version);
            }

            if (forwarded) {

               socks_addrlock(F_WRLCK);

               /* a separate socket with it's own remote address. */
               socks_addaddr((unsigned int)remote, &socksfd, 1);

               fakesockshost2sockaddr(&packet.res.host, &accepted);

               socksfd.forus.accepted = accepted;
               socks_addaddr((unsigned int)s, &socksfd, 1);

               /* has a different local address if INADDR_ANY was bound. */
               /* LINTED pointer casts may be troublesome */
               if (TOIN(&socksfd.local)->sin_addr.s_addr
               == htonl(INADDR_ANY)) {
                  len = sizeof(socksfd.local);
                  if (getsockname(remote, &socksfd.local, &len) != 0)
                     swarn("%s: getsockname(remote)", function);

                  socks_addaddr((unsigned int)s, &socksfd, 1);

                  socks_addrunlock();

               }
            }
            /* else; ordinary connect. */
         }
      }
      /* else; not bind extension, must be a ordinary connect. */
   }

   if (addr != NULL) {
      *addrlen = MIN(*addrlen, (socklen_t)sizeof(accepted));
      memcpy(addr, &accepted, (size_t)*addrlen);
   }

   return remote;
}
