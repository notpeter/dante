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
"$Id: udp.c,v 1.199 2009/10/05 15:25:45 michaels Exp $";

/* ARGSUSED */
ssize_t
Rsendto(s, msg, len, flags, to, tolen)
   int s;
   const void *msg;
   size_t len;
   int flags;
   const struct sockaddr *to;
   socklen_t tolen;
{
   const char *function = "Rsendto()";
   struct socksfd_t socksfd;
   struct sockshost_t host;
   char srcstring[MAXSOCKADDRSTRING], dststring[sizeof(srcstring)];
   void *nmsg;
   size_t nlen;
   ssize_t n;

   clientinit();

   slog(LOG_DEBUG, "%s: socket %d, len %lu, address %s",
   function, s, (long unsigned)len,
   to == NULL ? "<none given>" : sockaddr2string(to, NULL, 0));

   if (to != NULL && to->sa_family != AF_INET) {
      slog(LOG_DEBUG, "%s: unsupported address family '%d', system fallback",
      function, to->sa_family);

      return sendto(s, msg, len, flags, to, tolen);
   }

   if ((socksfd.route = udpsetup(s, to, SOCKS_SEND)) == NULL) {
      slog(LOG_DEBUG, "%s: udpsetup() failed for socket %d", function, s);
      return -1;
   }

   slog(LOG_DEBUG, "%s: route returned by udpsetup() is a %s route",
   function,
   proxyprotocols2string(&socksfd.route->gw.state.proxyprotocol, NULL, 0));

   if (socksfd.route->gw.state.proxyprotocol.direct) {
      slog(LOG_DEBUG, "%s: using direct systemcalls for socket %d",
      function, s);

      return sendto(s, msg, len, flags, to, tolen);
   }

   socksfd = *socks_getaddr(s, 1);

   if (socksfd.state.issyscall
   ||  socksfd.state.version == PROXY_UPNP)
      return sendto(s, msg, len, flags, to, tolen);

   if (socksfd.state.err != 0) {
      slog(LOG_DEBUG, "%s: session on socket %d has previously failed with "
                      "errno %d", function, s, socksfd.state.err);

      errno = socksfd.state.err;
      return -1;
   }

   if (to == NULL) {
      if (socksfd.state.udpconnect)
         to = &socksfd.forus.connected;
      else { /* tcp. */
         n = socks_sendto(s, msg, len, flags, NULL, 0, &socksfd.state.auth);

         slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
         function, protocol2string(SOCKS_TCP),
         sockaddr2string(&socksfd.local, dststring, sizeof(dststring)),
         sockaddr2string(&socksfd.server, srcstring, sizeof(srcstring)),
         (long)n);

         return n;
      }
   }

   /* prefix a UDP header to the msg */
   nlen = len;
   /* LINTED warning: cast discards 'const' from pointer target type */
   if ((nmsg = udpheader_add(fakesockaddr2sockshost(to, &host), msg, &nlen,
   len)) == NULL) {
      errno = ENOBUFS;
      return -1;
   }

   n = socks_sendto(s, nmsg, nlen, flags,
   socksfd.state.udpconnect ? NULL : &socksfd.reply,
   socksfd.state.udpconnect ? (socklen_t)0 : sizeof(socksfd.reply),
   &socksfd.state.auth);

   n -= (ssize_t)(nlen - len);

   if (msg != nmsg)
      free(nmsg);

   slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
   function, protocol2string(SOCKS_UDP),
   sockaddr2string(&socksfd.local, dststring, sizeof(dststring)),
   sockaddr2string(&socksfd.reply, srcstring, sizeof(srcstring)),
   (unsigned long)n);

   return MAX(-1, n);
}

ssize_t
Rrecvfrom(s, buf, len, flags, from, fromlen)
   int s;
   void *buf;
   size_t len;
   int flags;
   struct sockaddr *from;
   socklen_t *fromlen;
{
   const char *function = "Rrecvfrom()";
   struct socksfd_t socksfd;
   struct udpheader_t header;
   struct sockaddr newfrom;
   socklen_t newfromlen;
   char srcstring[MAXSOCKADDRSTRING], dststring[sizeof(srcstring)], *newbuf;
   size_t newlen;
   ssize_t n;

   slog(LOG_DEBUG, "%s: socket %d, len %lu", function, s, (long unsigned)len);

   if (!socks_addrisours(s, 1)) {
      socks_rmaddr(s, 1);
      return recvfrom(s, buf, len, flags, from, fromlen);
   }

   if ((socksfd.route = udpsetup(s, from, SOCKS_RECV)) == NULL) {
      slog(LOG_DEBUG, "%s: udpsetup() failed for socket %d", function, s);
      return -1;
   }

   if (socksfd.route->gw.state.proxyprotocol.direct) {
      slog(LOG_DEBUG, "%s: using direct systemcalls for socket %d",
      function, s);

      return recvfrom(s, buf, len, flags, from, fromlen);
   }

   socksfd = *socks_getaddr(s, 1);

   if (socksfd.state.issyscall
   ||  socksfd.state.version == PROXY_UPNP)
      return recvfrom(s, buf, len, flags, from, fromlen);

   if (socksfd.state.err != 0) {
      slog(LOG_DEBUG, "%s: session on socket %d has previously failed with "
                      "errno %d", function, s, socksfd.state.err);

      errno = socksfd.state.err;
      return -1;
   }

   if (socksfd.state.protocol.tcp) {
      const struct sockaddr *forus;

      if (socksfd.state.err != 0) {
         errno = socksfd.state.err;
         return -1;
      }
      else {
         if (socksfd.state.inprogress) {
            errno = ENOTCONN;
            return -1;
         }
      }

      n = socks_recvfromn(s, buf, len, 0, flags, from, fromlen,
      &socksfd.state.auth);

      switch (socksfd.state.command) {
         case SOCKS_CONNECT:
            forus = &socksfd.forus.connected;
            break;

         case SOCKS_BIND:
            forus = &socksfd.forus.accepted;

            if (forus->sa_family == 0) {
               swarnx("%s: strange ... trying to read from socket %d, "
                      "which is for bind, but no bind-reply received yet ...",
                      function, s);
               forus = NULL;
            }
            break;

         default:
            SERRX(socksfd.state.command);
      }

      slog(LOG_DEBUG, "%s: %s: %s -> %s (%ld: %s)",
      function, protocol2string(SOCKS_TCP),
      forus == NULL ?
      "<NULL>" : sockaddr2string(forus, srcstring, sizeof(srcstring)),
      sockaddr2string(&socksfd.local, dststring, sizeof(dststring)),
      (long)n, strerror(errno));

      return n;
   }

   SASSERTX(socksfd.state.protocol.udp);

   /* udp.  If packet is from socks server it will be prefixed with a header. */
   newlen = len + sizeof(header);
   if ((newbuf = malloc(sizeof(*newbuf) * newlen)) == NULL) {
      errno = ENOBUFS;
      return -1;
   }

   newfromlen = sizeof(newfrom);
   if ((n = socks_recvfrom(s, newbuf, newlen, flags, &newfrom, &newfromlen,
   &socksfd.state.auth)) == -1) {
      free(newbuf);
      return n;
   }
   SASSERTX(newfromlen > 0);

   if (sockaddrareeq(&newfrom, &socksfd.reply)) { /* from socks server. */
      if (string2udpheader(newbuf, (size_t)n, &header) == NULL) {
         char badfrom[MAXSOCKADDRSTRING];

         swarnx("%s: unrecognized socks udppacket from %s",
         function, sockaddr2string(&newfrom, badfrom, sizeof(badfrom)));

         errno = EAGAIN;
         free(newbuf);
         return -1;
      }

      /* replace "newfrom" with the address socks server says packet is from. */
      fakesockshost2sockaddr(&header.host, &newfrom);

      /* callee doesn't want socksheader. */
      n -= (ssize_t)PACKETSIZE_UDP(&header);
      SASSERTX(n >= 0);
      memcpy(buf, &newbuf[PACKETSIZE_UDP(&header)], MIN(len, (size_t)n));
   }
   else /* ordinary udppacket, not from socks server. */
      memcpy(buf, newbuf, MIN(len, (size_t)n));

   free(newbuf);

   slog(LOG_DEBUG, "%s: %s: %s -> %s (%ld)",
   function, protocol2string(SOCKS_UDP),
   sockaddr2string(&newfrom, srcstring, sizeof(srcstring)),
   sockaddr2string(&socksfd.local, dststring, sizeof(dststring)),
   (long)n);

   if (from != NULL) {
      *fromlen = MIN(*fromlen, newfromlen);
      memcpy(from, &newfrom, (size_t)*fromlen);
   }

   return MIN(len, (size_t)n);
}

struct route_t *
udpsetup(s, to, type)
   int s;
   const struct sockaddr *to;
   int type;
{
   const char *function = "udpsetup()";
   static struct route_t directroute;
   const struct socksfd_t *socksfdptr;
   struct socksfd_t socksfd;
   struct authmethod_t auth;
   struct socks_t packet;
   struct sockshost_t src, dst;
   struct sockaddr addr;
   socklen_t len;
   int shouldconnect = 0;

   /*
    * we need to send the socks server our address.
    * First check if the socket already has a name, if so
    * use that, otherwise assign the name ourselves.
    */
   bzero(&socksfd, sizeof(socksfd));
   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0)
      return &directroute;

   switch (socksfd.local.sa_family) {
      case AF_INET:
         break;

      default:
         slog(LOG_DEBUG, "%s: unsupported af %d",
         function, socksfd.local.sa_family);

         return &directroute;
   }
   sockaddr2sockshost(&socksfd.local, &src);


   slog(LOG_DEBUG, "%s: socket %d, type = %s",
   function, s, type == SOCKS_RECV ? "receive" : "send");

   /*
    * don't bother setting it fully up, not expecting anybody to access
    * any other fields.
    */
   directroute.gw.state.proxyprotocol.direct = 1;

   if (!socks_addrisours(s, 1))
      socks_rmaddr(s, 1);

   if ((socksfdptr = socks_getaddr(s, 1)) != NULL) {
      slog(LOG_DEBUG, "%s: route already setup for socket %d", function, s);
      return socksfdptr->route; /* all set up. */
   }

   if (socks_socketisforlan(s)) {
      slog(LOG_DEBUG, "%s: socket %d is for lan only, system fallback",
      function, s);

      return &directroute;
   }

   errno = 0;
   switch (type) {
      case SOCKS_RECV:
         /*
          * problematic, trying to receive on socket not sent on.
          * Only UPNP supports that, and in that case, the socket
          * should already have been bound, so socks_addrisours()
          * should have been true.
          */
         swarnx("%s: receive on udp socket not previously sent on is "
                "not supported by the socks protocol, returing direct route",
                function);

         return &directroute;

      case SOCKS_SEND:
         if (to == NULL) {
            /*
             * no address and unknown socket.  Has a connect(2) been done
             * but not been caught by us?
             */
            socklen_t addrlen = sizeof(addr);
            if (getpeername(s, &addr, &addrlen) == 0) {
               int val;

               len = sizeof(val);
               if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) != 0) {
                  slog(LOG_DEBUG, "%s: getsockopt(SO_TYPE): %s",
                  function, strerror(errno));

                  return &directroute;
               }

               switch (val) {
                  case SOCK_DGRAM:
                     break;

                  case SOCK_STREAM:
                     slog(LOG_INFO,
                          "%s: socket %d is unknown, but has a stream "
                          "peer (%s), returning direct route",
                          function, s, sockaddr2string(&addr, NULL, 0));
                     return &directroute;

                  default:
                     swarnx("%s: unknown protocoltype %d", function, val);
                     return &directroute;
               }

               slog(LOG_INFO,
                    "%s: socket %d is unknown, but has a datagram peer (%s).  "
                    "Trying to accomodate ... ",
                    function, s, sockaddr2string(&addr, NULL, 0));

               to            = &addr;
               shouldconnect = 1;
            }
            else {
               slog(LOG_DEBUG,
                    "%s: unknown socket %d and no destination address, "
                    "returning direct route",
                    function, s);

               return &directroute;
            }
         }
         break;

      default:
         SERRX(type);
   }

   fakesockaddr2sockshost(to, &dst);

   bzero(&auth, sizeof(auth));
   auth.method          = AUTHMETHOD_NOTSET;

   bzero(&packet, sizeof(packet));
   packet.version       = PROXY_DIRECT;;
   packet.req.version   = packet.version;
   packet.req.command   = SOCKS_UDPASSOCIATE;
#if 0 /*
       * some (nec-based) socks-server missinterpret this to mean something
       * completly different.
       */
   packet.req.flag     |= SOCKS_USECLIENTPORT;
#endif
   packet.req.host      = src;
   packet.req.protocol  = SOCKS_UDP;
   packet.req.auth      = &auth;

   if (socks_requestpolish(&packet.req, &src, &dst) == NULL)
      return NULL;

   if (packet.req.version == PROXY_DIRECT) {
      slog(LOG_DEBUG, "%s: using direct systemcalls for socket %d",
      function, s);

      return &directroute;
   }

   slog(LOG_DEBUG, "%s: socket %d, need to set up a new session for send",
   function, s);

   /* only ones we support udp via. */
   switch (packet.version = packet.req.version) {
      case PROXY_SOCKS_V5:
      case PROXY_UPNP:
         if ((socksfd.control = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            swarn("%s: failed to create control socket", function);
            return NULL;
         }
         break;

      default:
         SERRX(packet.version);
   }

   if ((socksfd.route
   = socks_connectroute(socksfd.control, &packet, &src, &dst)) == NULL) {
      close(socksfd.control);
      return NULL;
   }

   if (!ADDRISBOUND(TOIN(&socksfd.local))
   &&  !PORTISBOUND(TOIN(&socksfd.local))) {
      /*
       * local addr not fixed, so set it.  Port may remain unbound, but
       * we would like to bind the ip so we can tell it to the socks-server.
       */

      /*
       * don't have much of an idea on what IP address to use so might as
       * well use same as tcp connection to socks server uses.
       */
      len = sizeof(socksfd.local);
      if (getsockname(socksfd.control, &socksfd.local, &len) != 0) {
         swarn("%s: getsockname(socksfd.control)", function);

         close(socksfd.control);
         return NULL;
      }
      /* LINTED  pointer casts may be troublesome */
      TOIN(&socksfd.local)->sin_port = htons(0);

      if (bind(s, &socksfd.local, sizeof(socksfd.local)) != 0) {
         swarn("%s: bind(%s)", function,
         sockaddr2string(&socksfd.local, NULL, 0));

         close(socksfd.control);
         return NULL;
      }
   }

   if (getsockname(s, &socksfd.local, &len) != 0) {
      swarn("%s: getsockname(s)", function);

      close(socksfd.control);
      return NULL;
   }
   sockaddr2sockshost(&socksfd.local, &packet.req.host);

   if (socks_negotiate(s, socksfd.control, &packet, socksfd.route) != 0) {
      close(socksfd.control);
      return NULL;
   }

   socksfd.state.auth            = auth;
   socksfd.state.version         = packet.version;
   socksfd.state.command         = packet.req.command;
   socksfd.state.protocol.udp    = 1;

   if (socksfd.state.version == PROXY_UPNP)
      sockshost2sockaddr(&packet.res.host, &socksfd.remote);
   else {
      sockshost2sockaddr(&packet.res.host, &socksfd.reply);

      len = sizeof(socksfd.server);
      if (getpeername(socksfd.control, &socksfd.server, &len) != 0) {
         swarn("%s: getpeername()", function);
         close(socksfd.control);
         return NULL;
      }
   }

   if (shouldconnect) {
      socksfd.state.udpconnect = 1;
      socksfd.forus.connected  = *to;
   }

   if (socksfd.state.version == PROXY_UPNP) {
      close(socksfd.control); /* is a one-time thing, nothing more expected.  */
      socksfd.control = s;

      return socksfd.route;
   }

   if (socks_addaddr(s, &socksfd, 1) == NULL) {
      close(socksfd.control);
      errno = ENOBUFS;

      return NULL;
   }

   return socksfd.route;
}
