/*
 * Copyright (c) 1997, 1998, 1999, 2001, 2003, 2008, 2009, 2010, 2011, 2012
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
"$Id: sockd_socket.c,v 1.116 2012/06/03 15:15:03 michaels Exp $";

#define MAXSOCKETOPTIONS ( 1 /* TCP_NODELAY || SO_BROADCAST */    \
                         + 1 /* SO_TIMESTAMP                */    \
                         + 1 /* SO_OOBINLINE                */    \
                         + 1 /* SO_KEEPALIVE                */    \
                         + 1 /* SO_SNDBUF                   */    \
                         + 1 /* SO_RCVBUF                   */)
#define MAXOPTIONNAME   (16) /* max length of any of the option names above. */
typedef struct {
   int    level;
   int    optname;
   int    optval;
   size_t optlen;
   char   textname[MAXOPTIONNAME];
} socketoptions_t;

static size_t
getoptions(const int type, const int isclientside,
           socketoptions_t *optionsv, const size_t optionsc);
/*
 * Fills in "optionsv" with the correct values for a socket of type "type".
 * "isclientside" indicates if the socket is to be used on the client side
 * or not.
 *
 * Returns the number of options set, <= MAXSOCKETOPTIONS.
 */

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
      slog(LOG_DEBUG, "%s: bound address %s on socket %d",
           function, sockaddr2string(addr, NULL, 0), s);

   return p;
}

int
socks_unconnect(s)
   const int s;
{
   const char *function = "socks_unconnect()";
   struct sockaddr_storage local, remote, newlocal;
   socklen_t addrlen;
   char buf[MAXSOCKADDRSTRING];

   addrlen = sizeof(local);
   if (getsockname(s, TOSA(&local), &addrlen) != 0) {
      swarn("%s: getsockname()", function);
      return -1;
   }

   if (getpeername(s, TOSA(&remote), &addrlen) != 0) {
      SWARN(0); /* not bound?  Should not happen. */
      return 0;
   }

   slog(LOG_DEBUG, "%s: unconnecting socket %d, currently connected to %s",
        function, s, sockaddr2string(TOSA(&remote), buf, sizeof(buf)));

   bzero(&remote, sizeof(remote));
   SET_SOCKADDR(TOSA(&remote), AF_UNSPEC);
   if (connect(s, TOSA(&remote), sockaddr2salen(TOSA(&remote))) != 0)
      slog(LOG_DEBUG, "%s: \"unconnect\" of socket returned %s",
           function, strerror(errno));

   /*
    * May need to re-bind the socket after unconnect to make sure we get the
    * same address as we had before, as some systems only keep the portnumber
    * if not. :-/  Check first.
    */
   addrlen = sizeof(newlocal);
   if (getsockname(s, TOSA(&newlocal), &addrlen) != 0) {
      swarn("%s: getsockname() failed the second time", function);
      return -1;
   }

   if (sockaddrareeq(TOSA(&local), TOSA(&newlocal)))
      return 0; /* ok, no problem on this system. */

   /*
    * Ack, need to try to rebind the socket. :-/
    */

   if (sockd_bind(s, TOSA(&local), 1) != 0) {
      char a[MAXSOCKADDRSTRING], b[MAXSOCKADDRSTRING];
      int new_s;

      slog(LOG_DEBUG, "%s: re-bind(2) after unconnecting failed: %s.  "
                      "Current address is %s (was %s).  Trying to create a "
                      "new socket instead, though we might loose some packets "
                      "doing so",
                      function,
                      strerror(errno),
                      sockaddr2string(TOSA(&newlocal), a, sizeof(a)),
                      sockaddr2string(TOSA(&local), b, sizeof(b)));

      /*
       * There is an unfortunate race here, as while we create the new
       * socket packets could come in on the old socket, and those packets
       * will be lost.  There is probably not much else we could do though,
       * as long as user has enabled connecting udp sockets to destination.
       */

      new_s = 1;
      if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &new_s, sizeof(new_s)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);

      if ((new_s = socketoptdup(s)) == -1) {
         swarn("%s: socketoptdup(%d) failed", function, s);
         return -1;
      }

      if (sockd_bind(new_s, TOSA(&local), 1) != 0) {
         slog(LOG_DEBUG, "%s: bind of new socket also failed: %s",
              function, strerror(errno));

         close(new_s);
         return 0;
      }

      slog(LOG_DEBUG, "%s: bind of new socket to address %s succeeded",
           function, sockaddr2string(TOSA(&local), NULL, 0));

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
            port = 1023; /* short-circuit to first possibility - 1. */
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
      listenaddress_t *l = &sockscf.internalv[i];
      int val;

      if (l->protocol != protocol)
         continue;


      if (l->s != -1) {
         slog(LOG_DEBUG, "%s: address %s should be bound to socket %d already",
         function, sockaddr2string(TOSA(&l->addr), NULL, 0), l->s);

         SASSERTX(fdisopen(l->s));

         /*
          * config-based socket options need to be (re)set though.
          * XXX missing code to unset any previously set options.
          */
         setconfsockoptions(l->s,
                            -1,
                            SOCKS_TCP,
                            1,
                            0,
                            NULL,
                            0,
                            SOCKETOPT_PRE | SOCKETOPT_ANYTIME);

         continue;
      }

      if ((l->s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
         swarn("%s: socket(SOCK_STREAM) failed", function);
         return -1;
      }

      setsockoptions(l->s, SOCK_STREAM, 1);

      /*
       * This breaks the principle that we should only set socket options
       * on sockets used for data (rather than sockets used for the control
       * messages), but some options can only be set at pre-connect time,
       * so if we do not set them here, we will never be able to set them.
       * Possibly we should limit the settings here to the options that
       * can _only_ be set at pre-connect time, so that at least other
       * options are not set unnecessarily.
       */

       /* XXX missing code to unset any previously set options. */
      setconfsockoptions(l->s,
                         -1,
                         SOCKS_TCP,
                         1,
                         0,
                         NULL,
                         0,
                         SOCKETOPT_PRE | SOCKETOPT_ANYTIME);

      val = 1;
      if (setsockopt(l->s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);

      if (sockd_bind(l->s, TOSA(&l->addr), 1) != 0) {
         char badbind[MAXSOCKADDRSTRING];

         swarn("%s: bind of address %s failed",
               function,
               sockaddr2string(TOSA(&l->addr),
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
   socketoptions_t optionsv[MAXSOCKETOPTIONS];
   size_t optc, i;
   int val;

   slog(LOG_DEBUG, "%s: socket %d, type = %d, isclientside = %d",
        function, s, type, isclientside);

   /*
    * Our default builtin options.
    */
   optc = getoptions(type, isclientside, optionsv, ELEMENTS(optionsv));
   for (i = 0; i < optc; ++i) {
      SASSERTX(optionsv[i].textname != NULL);

      if (setsockopt(s,
                     optionsv[i].level,
                     optionsv[i].optname,
                     &optionsv[i].optval,
                     optionsv[i].optlen) != 0) {
         if (optionsv[i].optname == SO_BROADCAST
         &&  type                == SOCK_DGRAM
         &&  errno               == EPROTO)
            ; /* SO_BROADCAST is not always supported. */
         else
            swarn("%s: setsockopt(%s) to value %d on socket %d failed",
                  function,
                  optionsv[i].textname,
                  optionsv[i].optval,
                  s);
      }
   }

   if ((val = fcntl(s, F_GETFL, 0))         == -1
   ||   fcntl(s, F_SETFL, val | O_NONBLOCK) == -1)
      swarn("%s: fcntl() failed to set descriptor to non-blocking", function);

   if (sockscf.option.debug) {
      socklen_t len;
      int sndbuf, rcvbuf;

      len = sizeof(sndbuf);
      if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len) != 0) {
         swarn("%s: could not get the size of SO_SNDBUF for socket %d",
               function, s);

         return;
      }

      len = sizeof(rcvbuf);
      if (getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len) != 0) {
         swarn("%s: could not get the size of SO_RCVBUF for socket %d",
               function, s);

         return;
      }

      slog(LOG_DEBUG,
           "%s: buffer sizes for socket %d are: SO_SNDBUF: %d, SO_RCVBUF: %d",
           function, s, sndbuf, rcvbuf);
   }

#if DIAGNOSTIC
   checksockoptions(s, type, isclientside);
#endif /* DIAGNOSTIC */
}


static size_t
getoptions(type, isclientside, optionsv, optionsc)
   const int type;
   const int isclientside;
   socketoptions_t *optionsv;
   const size_t optionsc;
{
   int sndbuf, rcvbuf;
   size_t optc;

   optc = 0;
   switch (type) {
      case SOCK_STREAM:
         optionsv[optc].level   = IPPROTO_TCP;
         optionsv[optc].optname = TCP_NODELAY;
         optionsv[optc].optval  = 1;
         optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
         strcpy(optionsv[optc].textname, "TCP_NODELAY");
         ++optc;
         SASSERTX(optc <= optionsc);

         optionsv[optc].level   = SOL_SOCKET;
         optionsv[optc].optname = SO_OOBINLINE;
         optionsv[optc].optval  = 1;
         optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
         strcpy(optionsv[optc].textname, "SO_OOBINLINE");
         ++optc;
         SASSERTX(optc <= optionsc);

         if (sockscf.option.keepalive) {
            optionsv[optc].level   = SOL_SOCKET;
            optionsv[optc].optname = SO_KEEPALIVE;
            optionsv[optc].optval  = 1;
            optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
            strcpy(optionsv[optc].textname, "SO_KEEPALIVE");
            ++optc;
            SASSERTX(optc <= optionsc);
         }

         sndbuf = sockscf.socket.tcp.sndbuf;
         rcvbuf = sockscf.socket.tcp.rcvbuf;

         break;

      case SOCK_DGRAM:
         optionsv[optc].level   = SOL_SOCKET;
         optionsv[optc].optname = SO_BROADCAST;
         optionsv[optc].optval  = 1;
         optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
         strcpy(optionsv[optc].textname, "SO_BROADCAST");
         ++optc;
         SASSERTX(optc <= optionsc);

#if HAVE_SO_TIMESTAMP
         optionsv[optc].level   = SOL_SOCKET;
         optionsv[optc].optname = SO_TIMESTAMP;
         optionsv[optc].optval  = 1;
         optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
         strcpy(optionsv[optc].textname, "SO_TIMESTAMP");
         ++optc;
         SASSERTX(optc <= optionsc);
#endif /* HAVE_SO_TIMESTAMP */

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

         break;

      default:
         SERRX(type);
   }

   if (sndbuf != 0) {
      optionsv[optc].level   = SOL_SOCKET;
      optionsv[optc].optname = SO_SNDBUF;
      optionsv[optc].optval  = sndbuf;
      optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
      strcpy(optionsv[optc].textname, "SO_SNDBUF");
      ++optc;
      SASSERTX(optc <= optionsc);
   }

   if (rcvbuf != 0) {
      optionsv[optc].level   = SOL_SOCKET;
      optionsv[optc].optname = SO_RCVBUF;
      optionsv[optc].optval  = rcvbuf;
      optionsv[optc].optlen  = sizeof(optionsv[optc].optval);
      strcpy(optionsv[optc].textname, "SO_RCVBUF");
      ++optc;
      SASSERTX(optc <= optionsc);
   }

   SASSERTX(optc <= optionsc);
   return optc;
}

#if DIAGNOSTIC
void
checksockoptions(s, type, isclientside)
   const int s;
   const int type;
   const int isclientside;
{
   const char *function = "checksockoptions()";
   socketoptions_t optionsv[MAXSOCKETOPTIONS];
   size_t optc, i;
   int val;

   slog(LOG_DEBUG, "%s: socket %d, type = %d, isclientside = %d",
        function, s, type, isclientside);

   optc = getoptions(type, isclientside, optionsv, ELEMENTS(optionsv));
   for (i = 0; i < optc; ++i) {
      socklen_t vallen = sizeof(val);

      if (getsockopt(s,
                     optionsv[i].level,
                     optionsv[i].optname,
                     &val,
                     &vallen) != 0) {
         if (type == SOCK_STREAM && errno == ECONNRESET)
            continue;  /* presumably failed while transferring the descriptor. */

         if (optionsv[i].optname == SO_BROADCAST
         &&  type                == SOCK_DGRAM
         &&  errno               == EPROTO)
            continue; /* SO_BROADCAST is not always supported. */

         swarn("%s: could not get socket option %s on socket %d",
               function, optionsv[i].textname, s);
      }

      if (val != optionsv[i].optval) {
         if ((optionsv[i].optval == 1) && val)
            ; /* assume it's a boolean; true, but not necessarily 1. */
         else if ((   optionsv[i].optname == SO_SNDBUF
                   || optionsv[i].optname == SO_RCVBUF)) {
            if (val < optionsv[i].optval)
               slog(LOG_INFO,
                    "%s: socketoption %s on socket %d should be %d, but is %d",
                    function,
                    optionsv[i].textname,
                    s,
                    optionsv[i].optval,
                    val);
         }
         else
            slog((type == SOCK_DGRAM && optionsv[i].optname == SO_BROADCAST) ?
                 LOG_DEBUG : LOG_WARNING,
                 "%s: socket option %s on socket %d should be %d, but is %d",
                 function,
                 optionsv[i].textname,
                 s,
                 optionsv[i].optval,
                 val);
      }
   }

   if ((val = fcntl(s, F_GETFL, 0)) == -1)
      swarn("%s: fcntl() failed to get descriptor flags of socket %d",
            function, s);
   else {
      if (! (val & O_NONBLOCK))
         swarn("%s: socket %d is blocking", function, s);
   }
}

#endif /* DIAGNOSTIC */
