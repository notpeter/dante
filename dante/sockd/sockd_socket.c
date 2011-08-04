/*
 * Copyright (c) 1997, 1998, 1999, 2001, 2003, 2008, 2009, 2010, 2011
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
"$Id: sockd_socket.c,v 1.79 2011/07/27 13:19:19 michaels Exp $";

int
sockd_bind(s, addr, retries)
   int s;
   struct sockaddr *addr;
   size_t retries;
{
   const char *function = "sockd_bind()";
   int p;

   slog(LOG_DEBUG, "%s: trying to bind address %s, retries is %lu",
   function, sockaddr2string(addr, NULL, 0), (unsigned long)retries);

   errno = 0;
   while (1) { /* CONSTCOND */
      /* LINTED pointer casts may be troublesome */
      if (PORTISRESERVED(TOIN(addr)->sin_port)) {
         sockd_priv(SOCKD_PRIV_NET_ADDR, PRIV_ON);
         p = bind(s, addr, sizeof(*addr));
         sockd_priv(SOCKD_PRIV_NET_ADDR, PRIV_OFF);
      }
      else
         p = bind(s, addr, sizeof(*addr));

      if (p == 0) {
         socklen_t addrlen = sizeof(*addr);
         p                 = getsockname(s, addr, &addrlen);
         break;
      }

      /*
       * else;  non-fatal error and retry?
       */

      slog(LOG_DEBUG, "%s: failed to bind %s (%s)",
      function, sockaddr2string(addr, NULL, 0), strerror(errno));

      switch (errno) {
         case EINTR:
            continue; /* don't count this attempt. */

         case EADDRINUSE:
            if (retries--) {
               sleep(1);
               continue;
            }
            break;
      }

      break;
   }

   if (p == 0)
      slog(LOG_DEBUG, "%s: bound address %s",
           function, sockaddr2string(addr, NULL, 0));

   return p;
}

int
socks_unconnect(s)
   const int s;
{
   const char *function = "socks_unconnect()";
   struct sockaddr local, remote;
   socklen_t addrlen;
   char remotestr[MAXSOCKADDRSTRING];

   addrlen = sizeof(local);
   if (getsockname(s, &local, &addrlen) != 0) {
      swarn("%s: getsockname()", function);
      return -1;
   }

   if (getpeername(s, &remote, &addrlen) != 0) {
      SWARN(0); /* not bound?  Should not happen. */
      return 0;
   }

   slog(LOG_DEBUG, "%s: unconnecting socket %d, currently connected to %s",
   function, s, sockaddr2string(&remote, remotestr, sizeof(remotestr)));

   bzero(&remote, sizeof(remote));
   remote.sa_family = AF_UNSPEC;
   if (connect(s, &remote, sizeof(remote)) != 0)
      slog(LOG_DEBUG, "%s: \"unconnect\" of socket returned %s",
      function, strerror(errno));

   /*
    * Need to re-bind the socket to make sure we get the same address
    * as we had before; some systems only keep the portnumber if not.
    */
   if (sockd_bind(s, &local, 1) != 0) {
      struct sockaddr new_local;
      int new_s;

      addrlen = sizeof(new_local);
      if (getsockname(s, &new_local, &addrlen) != 0) {
         swarn("%s: getsockname() after unconnect failed", function);
         return -1;
      }

      slog(LOG_DEBUG, "%s: re-bind after unconnecting failed: %s.  "
                      "Current address is %s.  Trying to create a new socket "
                      "instead",
                      function,
                      strerror(errno),
                      sockaddr2string(&new_local, NULL, 0));

      /*
       * There is an unfortunate race here, as while we create the new 
       * socket packets could come in on the old socket, and those packets
       * will be lost.  There is probably not much else we could do though,
       * as long as user has enabled conneting udp sockets to destination.
       */

      new_s = 1;
      if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &new_s, sizeof(new_s)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);


      if ((new_s = socketoptdup(s)) == -1) {
         swarn("%s: socketoptdup(%d) failed", function, s);
         return -1;
      }

      if (sockd_bind(new_s, &local, 1) != 0) {
         slog(LOG_DEBUG, "%s: bind of new socket also failed: %s", 
              function, strerror(errno));

         close(new_s);
         return 0;
      }

      slog(LOG_DEBUG, "%s: bind of new socket to address %s succeeded",
           function, sockaddr2string(&local, NULL, 0));

      if (dup2(new_s, s) == -1) {
         swarn("%s: dup2() failed", function);

         close(new_s);
         return 0;
      }
   }

   return 0;
}


int
sockd_bindinrange(s, addr, first, last, op)
   int s;
   struct sockaddr *addr;
   in_port_t first, last;
   const enum operator_t op;
{
   const char *function = "sockd_bindinrange()";
   in_port_t port;
   int exhausted;

   slog(LOG_DEBUG, "%s: %s %u %s %u",
                   function, sockaddr2string(addr, NULL, 0),
                   ntohs(first), operator2string(op), ntohs(last));

   /*
    * use them in host order to make it easier, only convert before bind.
    */
   port       = 0;
   first      = ntohs(first);
   last       = ntohs(last);
   exhausted  = 0;
   do {
      if (port + 1 == 0) /* wrapped. */
         exhausted = 1;

      /* find next port to try. */
      switch (op) {
         case none:
            port = 0; /* any port is good. */
            break;

         case eq:
            port = first;
            break;

         case neq:
            if (++port == first)
               ++port;
            break;

         case ge:
            if (port < first)
               port = first;
            else
               ++port;
            break;

         case gt:
            if (port <= first)
               port = first + 1;
            else
               ++port;
            break;

         case le:
            if (++port > first)
               exhausted = 1;
            break;

         case lt:
            if (++port >= first)
               exhausted = 1;
            break;

         case range:
            if (port < first)
               port = first;
            else
               ++port;

            if (port > last)
               exhausted = 1;
            break;

         default:
            SERRX(op);
      }

      if (exhausted) {
         slog(LOG_DEBUG, "%s: exhausted search for port to bind in range "
                         "%u %s %u",
                         function, first, operator2string(op), last);
         return -1;
      }

      TOIN(addr)->sin_port = htons(port);
      if (sockd_bind(s, addr, 0) == 0)
         return 0;

      if (errno == EACCES) {
         if  (op == gt || op == ge || op == range)
            port = 1023; /* short-circut to first possibility - 1. */
         else if (op == lt || op == le)
            exhausted = 1; /* going down, will get same error for all. */
      }

      if (op == eq || op == none)
         break; /* nothing to retry for these. */
   } while (!exhausted);

   return -1;
}

int
bindinternal(protocol)
   const int protocol;
{
   const char *function = "bindinternal()";
   size_t i;

   for (i = 0; i < sockscf.internalc; ++i) {
      struct listenaddress_t *l = &sockscf.internalv[i];
      int val;

      if (l->protocol != protocol)
         continue;

      if (l->s != -1) {
         slog(LOG_DEBUG, "%s: address %s should be bound to socket %d already",
         function, sockaddr2string(&l->addr, NULL, 0), l->s);

         SASSERTX(fdisopen(l->s));
         continue;
      }

      if ((l->s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
         swarn("%s: socket(SOCK_STREAM) failed", function);
         return -1;
      }

      setsockoptions(l->s, SOCK_STREAM, 1);

      val = 1;
      if (setsockopt(l->s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);

      if (sockd_bind(l->s, (struct sockaddr *)&l->addr, 1) != 0) {
         char badbind[MAXSOCKADDRSTRING];

         /* LINTED pointer casts may be troublesome */
         swarn("%s: bind of address %s failed",
               function,
               sockaddr2string((struct sockaddr *)&l->addr,
               badbind, sizeof(badbind)));

         return -1;
      }

      val = 1;
      if (setsockopt(l->s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);

      if (listen(l->s, SOCKD_MAXCLIENTQUE) == -1) {
         swarn("%s: listen(%d) failed", function, SOCKD_MAXCLIENTQUE);
         return -1;
      }

      /*
       * We want to accept(2) the client on a non-blocking descriptor.
       */
      if ((val = fcntl(l->s, F_GETFL, 0))               == -1
      ||         fcntl(l->s, F_SETFL, val | O_NONBLOCK) == -1) {
         swarn("%s: fcntl() failed", function);
         return -1;
      }

#if NEED_ACCEPTLOCK
      if (sockscf.option.serverc > 1)
         if ((l->lock = socks_mklock(SOCKS_LOCKFILE, NULL, 0)) == -1) {
            swarn("%s: socks_mklock() failed", function);
            return -1;
         }
#endif /* NEED_ACCEPTLOCK */
   }

   return 0;
}

void
setsockoptions(s, type, isclientside)
   const int s;
   const int type;
   const int isclientside;
{
   const char *function = "setsockoptions()";
   socklen_t vallen;
   int val, sndbuf, rcvbuf;

   slog(LOG_DEBUG, "%s: socket %d, type = %d, isclientside = %d",
   function, s, type, isclientside);

   switch (type) {
      case SOCK_STREAM:
         rcvbuf = sockscf.socket.tcp.rcvbuf;
         sndbuf = sockscf.socket.tcp.sndbuf;

         val = 1;
         if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != 0)
            swarn("%s: setsockopt(TCP_NODELAY)", function);

         val = 1;
         if (setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &val, sizeof(val)) != 0)
            swarn("%s: setsockopt(SO_OOBINLINE)", function);

         if (sockscf.option.keepalive) {
            val = 1;
            if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) != 0)
               swarn("%s: setsockopt(SO_KEEPALIVE)", function);
         }
         break;

      case SOCK_DGRAM:
#if BAREFOOTD
         if (isclientside) {
            sndbuf = sockscf.socket.clientside_udp.sndbuf;
            rcvbuf = sockscf.socket.clientside_udp.rcvbuf;
         }
         else {
            sndbuf = sockscf.socket.udp.sndbuf;
            rcvbuf = sockscf.socket.udp.rcvbuf;
         }

#else /* !BAREFOOTD */

         sndbuf = sockscf.socket.udp.sndbuf;
         rcvbuf = sockscf.socket.udp.rcvbuf;
#endif /* !BAREFOOTD */

         val = 1;
         if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val)) != 0)
            if (errno != ENOPROTOOPT)
               swarn("%s: setsockopt(SO_BROADCAST)", function);
         break;

      default:
         SERRX(type);
   }

   if ((val = sndbuf) != 0)
      if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)) != 0)
         swarn("%s: setsockopt(SO_SNDBUF, %lu) failed",
         function, (unsigned long)val);

   if ((val = rcvbuf) != 0)
      if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) != 0)
         swarn("%s: setsockopt(SO_RCVBUF, %lu) failed",
         function, (unsigned long)val);

   if (sockscf.option.debug > 0) {
      vallen = sizeof(val);
      if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &val, &vallen) != 0)
         swarn("%s: getsockopt(SO_SNDBUF)", function);
      else
         slog(LOG_DEBUG, "%s: SO_SNDBUF of socket %d: %d",
         function, s, val);

      if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &val, &vallen) != 0)
         swarn("%s: getsockopt(SO_RCVBUF)", function);
      else
         slog(LOG_DEBUG, "%s: SO_RCVBUF of socket %d: %d",
         function, s, val);
   }

   if ((val = fcntl(s, F_GETFL, 0))         == -1
   ||   fcntl(s, F_SETFL, val | O_NONBLOCK) == -1)
      swarn("%s: fcntl() failed to set descriptor to non-blocking", function);

#if HAVE_LIBWRAP
   if ((val = fcntl(s, F_GETFD, 0))       == -1
   || fcntl(s, F_SETFD, val | FD_CLOEXEC) == -1)
      swarn("%s: fcntl(F_GETFD/F_SETFD)", function);
#endif /* HAVE_LIBWRAP */
}
