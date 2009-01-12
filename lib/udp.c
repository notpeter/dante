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
"$Id: udp.c,v 1.148 2009/01/02 14:06:06 michaels Exp $";

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
   
   slog(LOG_DEBUG, "%s: socket %d", function, s);

   if (to != NULL && to->sa_family != AF_INET) {
      slog(LOG_DEBUG,
      "%s: unsupported address family '%d', system fallback",
      function, to->sa_family);
      return sendto(s, msg, len, flags, to, tolen);
   }

   errno = 0;
   if (udpsetup(s, to, SOCKS_SEND) != 0)
      return errno == 0 ? sendto(s, msg, len, flags, to, tolen) : -1;

   socksfd = *socks_getaddr((unsigned int)s, 0);

   if (socksfd.state.issyscall
   ||  socksfd.state.version == PROXY_UPNP)
      return sendto(s, msg, len, flags, to, tolen);

   if (to == NULL) {
      if (socksfd.state.udpconnect)
         to = &socksfd.forus.connected;
      else { /* tcp. */
         n = sendto(s, msg, len, flags, NULL, 0);

         slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
         function, protocol2string(SOCKS_TCP),
         sockaddr2string(&socksfd.local, dststring, sizeof(dststring)),
         sockaddr2string(&socksfd.server, srcstring, sizeof(srcstring)),
         (unsigned long)n);

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

   n = sendto(s, nmsg, nlen, flags,
   socksfd.state.udpconnect ? NULL : &socksfd.reply,
   socksfd.state.udpconnect ? 0    : sizeof(socksfd.reply));
   n -= nlen - len;

   if (msg != nmsg)
      free(nmsg);

   slog(LOG_DEBUG, "%s: %s: %s -> %s (%lu)",
   function, protocol2string(SOCKS_TCP),
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
   char srcstring[MAXSOCKADDRSTRING], dststring[sizeof(srcstring)];
   socklen_t newfromlen;
   char *newbuf;
   size_t newlen;
   ssize_t n;

   slog(LOG_DEBUG, "%s: socket %d", function, s);

   if (!socks_addrisok((unsigned int)s, 0)) {
      socks_rmaddr((unsigned int)s, 0);
      return recvfrom(s, buf, len, flags, from, fromlen);
   }

   errno = 0;
   if (udpsetup(s, from, SOCKS_RECV) != 0)
      return errno == 0 ? recvfrom(s, buf, len, flags, from, fromlen) : -1;

   socksfd = *socks_getaddr((unsigned int)s, 0);

   if (socksfd.state.issyscall
   ||  socksfd.state.version == PROXY_UPNP)
      return recvfrom(s, buf, len, flags, from, fromlen);

   if (socksfd.state.protocol.tcp) {
      const struct sockaddr *forus;

      if (socksfd.state.err != 0) {
         errno = socksfd.state.err;
         return -1;
      }
      else
         if (socksfd.state.inprogress) {
            errno = ENOTCONN;
            return -1;
         }

      n = recvfrom(s, buf, len, flags, from, fromlen);

      switch (socksfd.state.command) {
         case SOCKS_CONNECT:
            forus = &socksfd.forus.connected;
            break;

         case SOCKS_BIND:
            forus = &socksfd.forus.accepted;
            break;

         default:
            SERRX(socksfd.state.command);
      }

      slog(LOG_DEBUG, "%s: %s: %s -> %s (%ld)",
      function, protocol2string(SOCKS_TCP),
      sockaddr2string(forus, srcstring, sizeof(srcstring)),
      sockaddr2string(&socksfd.local, dststring, sizeof(dststring)),
      (long)n);

      return n;
   }

   SASSERTX(socksfd.state.protocol.udp);

   /* udp.  If packet is from socksserver it will be prefixed with a header. */
   newlen = len + sizeof(header);
   if ((newbuf = malloc(sizeof(*newbuf) * newlen)) == NULL) {
      errno = ENOBUFS;
      return -1;
   }

   newfromlen = sizeof(newfrom);
   if ((n = recvfrom(s, newbuf, newlen, flags, &newfrom, &newfromlen)) == -1) {
      free(newbuf);
      return n;
   }
   SASSERTX(newfromlen > 0);

   if (sockaddrareeq(&newfrom, &socksfd.reply)) { /* from socksserver. */
      if (string2udpheader(newbuf, (size_t)n, &header) == NULL) {
         char badfrom[MAXSOCKADDRSTRING];

         swarnx("%s: unrecognized socks udppacket from %s",
         function, sockaddr2string(&newfrom, badfrom, sizeof(badfrom)));

         errno = EAGAIN;
         free(newbuf);
         return -1;
      }

      /* replace "newfrom" with the address socksserver says packet is from. */
      fakesockshost2sockaddr(&header.host, &newfrom);

      /* callee doesn't want socksheader. */
      n -= PACKETSIZE_UDP(&header);
      SASSERTX(n >= 0);
      memcpy(buf, &newbuf[PACKETSIZE_UDP(&header)], MIN(len, (size_t)n));
   }
   else /* ordinary udppacket, not from socksserver. */
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


int
udpsetup(s, to, type)
   int s;
   const struct sockaddr *to;
   int type;
{
   const char *function = "udpsetup()";
   struct socks_t packet;
   struct socksfd_t socksfd;
   struct sockshost_t src, dst;
   socklen_t len;
   int p;

   slog(LOG_DEBUG, "%s: s = %d", function, s);

   if (!socks_addrisok((unsigned int)s, 0))
      socks_rmaddr((unsigned int)s, 0);

   if (socks_getaddr((unsigned int)s, 0) != NULL)
      return 0; /* all set up. */

   if (socks_socketisforlan(s)) {
      slog(LOG_DEBUG, "%s: socket %d is for lan only, system fallback",
      function, s);
      return -1;
   }


   slog(LOG_DEBUG, "%s: s = %d, need to set up a new session", function, s);

   errno = 0;
   switch (type) {
      case SOCKS_RECV:
         /*
          * problematic, trying to receive on socket not sent on.
          * Only UPNP supports that, and in that case, the socket
          * should already have been bound, so socks_addrisok()
          * should have been true.
          */
         swarnx("%s: receive on udp socket not previously sent on."
         "Not supported by the socks protocol", function);
         break;

      case SOCKS_SEND:
         if (to == NULL)
            return -1; /* no address and unknown socket, no idea. */
         break;

      default:
         SERRX(type);
   }

   /*
    * we need to send the socksserver our address.
    * First check if the socket already has a name, if so
    * use that, otherwise assign the name ourselves.
    */
   bzero(&socksfd, sizeof(socksfd));
   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0)
      return -1;
   
   switch (socksfd.local.sa_family) {
      case AF_INET:
         break;

      default:
         slog(LOG_DEBUG, "%s: unsupported af %d",
         function, socksfd.local.sa_family);
         return -1;
   }

   sockaddr2sockshost(&socksfd.local, &src);

   fakesockaddr2sockshost(to, &dst);

   bzero(&packet, sizeof(packet));
   packet.version       = PROXY_DIRECT;;
   packet.auth.method   = AUTHMETHOD_NOTSET;
   packet.req.version   = packet.version;
   packet.req.command   = SOCKS_UDPASSOCIATE;
   packet.req.flag     |= SOCKS_USECLIENTPORT;
   packet.req.host      = src;
   packet.req.protocol  = SOCKS_UDP;

   if (socks_requestpolish(&packet.req, &src, &dst) == NULL
   ||  packet.req.version == PROXY_DIRECT)
      return -1;

   /* only ones we support udp via. */
   switch (packet.version = packet.req.version) {
      case PROXY_SOCKS_V5:
      case PROXY_UPNP:
         if ((socksfd.control = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            swarn("%s: failed to create control socket", function);
            return -1;
         }
         break;

      default:
         SERRX(packet.version);
   }

   if ((socksfd.route
   = socks_connectroute(socksfd.control, &packet, &src, &dst)) == NULL) {
      close(socksfd.control);
      return -1;
   }

   /* LINTED  pointer casts may be troublesome */
   if ((TOIN((&socksfd.local))->sin_addr.s_addr == htonl(INADDR_ANY))
   /* LINTED  pointer casts may be troublesome */
   || TOIN((&socksfd.local))->sin_port == htons(0)) {
      /*
       * local name not fixed, set it, port may be bound, we need to bind
       * IP too however.
       */

      /* LINTED  pointer casts may be troublesome */
      const in_port_t port = TOIN((&socksfd.local))->sin_port;

      if (port != htons(0)) {
         /*
          * port is bound.  We will try to unbind and then rebind same port
          * but now also bind IP address.  XXX Dangerous stuff.
          */

         if ((p = socketoptdup(s)) == -1) {
            close(socksfd.control);
            return -1;
         }

         if (dup2(p, s) == -1) {
            close(socksfd.control);
            close(p);
            return -1;
         }
         close(p);
      }

      /*
       * don't have much of an idea on what IP address to use so might as
       * well use same as tcp connection to socksserver uses.
       */
      len = sizeof(socksfd.local);
      if (getsockname(socksfd.control, &socksfd.local, &len) != 0) {
         close(socksfd.control);
         return -1;
      }
      /* LINTED  pointer casts may be troublesome */
      TOIN(&socksfd.local)->sin_port = port;

      if (bind(s, &socksfd.local, sizeof(socksfd.local)) != 0) {
         close(socksfd.control);
         return -1;
      }

      if (getsockname(s, &socksfd.local, &len) != 0) {
         close(socksfd.control);
         return -1;
      }

      sockaddr2sockshost(&socksfd.local, &packet.req.host);
   }

   if (socks_negotiate(s, socksfd.control, &packet, socksfd.route) != 0) {
      close(socksfd.control);
      return -1;
   }

   socksfd.state.auth            = packet.auth;
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
         return -1;
      }
   }

   if (socks_addaddr((unsigned int)s, &socksfd, 0) == NULL) {
      close(socksfd.control);
      errno = ENOBUFS;
      return -1;
   }

   if (socksfd.state.version == PROXY_UPNP) {
      close(socksfd.control); /* is a one-time thing, nothing more expected.  */
      socksfd.control = s;
   }

   return 0;
}
