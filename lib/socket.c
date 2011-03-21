/*
 * Copyright (c) 1997, 1998, 1999, 2001, 2005, 2008, 2009
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
"$Id: socket.c,v 1.65.6.1 2011/03/02 06:03:49 michaels Exp $";

int
socks_connecthost(s, host)
   int s;
   const struct sockshost_t *host;
{
   const char *function = "socks_connecthost()";
   struct hostent *hostent;
   struct sockaddr_in address;
   socklen_t len;
   char **ip, addrstr[MAXSOCKADDRSTRING], hoststr[MAXSOCKSHOSTSTRING];
   int failed;

   slog(LOG_DEBUG, "%s: to %s on socket %d\n",
        function, sockshost2string(host, hoststr, sizeof(hoststr)), s);

   bzero(&address, sizeof(address));
   address.sin_family   = AF_INET;
   address.sin_port     = host->port;

   switch (host->atype) {
      case SOCKS_ADDR_IPV4: {
         struct sockaddr_in localaddr;
         char localaddrstr[MAXSOCKADDRSTRING];
         int rc;

         address.sin_addr = host->addr.ipv4;

         /* LINTED pointer casts may be troublesome */
         rc = connect(s, (struct sockaddr *)&address, sizeof(address));

#if !SOCKS_CLIENT /* client may have setup e.g. an alarm for this. */
         if (rc != 0)
            slog(LOG_DEBUG, "%s: connect() returned %d (%s)",
            function, rc, strerror(errno));

         while (rc == -1 && errno == EINTR) {
            socklen_t len;
            fd_set wset;

            FD_ZERO(&wset);
            FD_SET(s, &wset);

            if ((rc = select(s + 1, NULL, &wset, NULL, NULL)) == -1
            &&  errno == EINTR)
               continue;

            len = sizeof(errno);
            if ((rc = getsockopt(s, SOL_SOCKET, SO_ERROR, &errno, &len)) == -1){
               swarn("%s: getsockopt()", function);
               break;
            }

            if (errno == 0)
               rc = 0;
            else
               rc = -1;
         }
#endif /* !SOCKS_CLIENT */

         if (rc == 0)
            /*
             * OpenBSD 4.5. sometimes sets errno even though the
             * connect was successful.  Seems to be an artifact
             * of the threads library, where it does a select(2)/poll(2)
             * after making the socket non-blocking, but forgets to
             * reset errno.
             */
            errno = 0;

         if (rc == -1 && !ERRNOISINPROGRESS(errno))
            /* connect failed, don't change errno. */
            snprintf(localaddrstr, sizeof(localaddrstr), "0.0.0.0");
         else {
            len = sizeof(localaddr);
            if (getsockname(s, (struct sockaddr *)&localaddr, &len) == -1) {
               slog(LOG_DEBUG, "%s: getsockname(2) failed: %s",
               function, strerror(errno));

               return -1;
            }

            sockaddr2string((struct sockaddr *)&localaddr, localaddrstr,
            sizeof(localaddrstr));
         }

         slog(LOG_DEBUG, "%s: connect to %s from %s on socket %d %s (%s)",
                         function,
                         sockaddr2string((struct sockaddr *)&address, addrstr,
                                         sizeof(addrstr)),
                         localaddrstr,
                         s,
                         rc == 0 ? "ok" :
                         ERRNOISINPROGRESS(errno) ? "in progress" : "failed",
                         strerror(errno));

         return rc;
      }

      case SOCKS_ADDR_DOMAIN:
         if ((hostent = gethostbyname(host->addr.domain)) == NULL)
            slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
            function, host->addr.domain, hstrerror(h_errno));
         break;

      default:
         SERRX(host->atype);
   }

   if (hostent == NULL || (ip = hostent->h_addr_list) == NULL)
      return -1;

   failed = 0;
   do {
      if (failed) { /* previously failed, need to create a new socket. */
         struct sockaddr name;
         socklen_t namelen;
         int new_s;

         /* will also try to get the same port binding. */
         namelen = sizeof(name);
         if (getsockname(s, &name, &namelen) != 0)
            return -1;

         if ((new_s = socketoptdup(s)) == -1)
            return -1;

         if (dup2(new_s, s) == -1) {
            close(new_s);
            return -1;
         }
         close(new_s); /* s is now a new socket but keeps the same index. */

#if SOCKS_CLIENT
         if (bind(s, &name, namelen) != 0)
            return -1;
#else /* SOCKS_SERVER */
         if (sockd_bind(s, &name, 1) != 0)
            return -1;
#endif /* SOCKS_SERVER */
      }

      address.sin_addr = *((struct in_addr *)*ip);

      if (connect(s, (struct sockaddr *)&address, sizeof(address)) == 0
      ||  ERRNOISINPROGRESS(errno)) {
         slog(LOG_DEBUG, "%s: connected to %s",
         function, sockaddr2string((struct sockaddr *)&address, addrstr,
         sizeof(addrstr)));

         break;
       }
       else
         slog(LOG_DEBUG, "%s: failed connecting to %s: %s", function,
         sockaddr2string((struct sockaddr *)&address, addrstr, sizeof(addrstr)),
         strerror(errno));

#if !SOCKS_CLIENT /* clients may have set up alarms to interrupt. */
      if (errno == EINTR) {
         static fd_set *rset;

         if (rset == NULL)
            rset = allocate_maxsize_fdset();

         FD_ZERO(rset);
         FD_SET(s, rset);

         if (selectn(s + 1, rset, NULL, NULL, NULL, NULL, NULL) != 1)
            SERR(0);

         if (read(s, NULL, 0) == 0) {
            errno = 0;
            break;
         }
         /*
          * else; errno should be set and we can handle it as there was no
          * interrupt.
          */
      }
#endif /* !SOCKS_CLIENT */

      /*
       * Only retry/try next address if errno indicates server/network error.
       */
      switch (errno) {
         case ETIMEDOUT:
         case EINVAL:
         case ECONNREFUSED:
         case ENETUNREACH:
         case EHOSTUNREACH:
            failed = 1;
            break;

         default:
            return -1;
      }
   } while (*++ip != NULL);

   if (*ip == NULL)
      return -1; /* list exhausted, no successful connect. */

   return 0;
}

int
acceptn(s, addr, addrlen)
   int s;
   struct sockaddr *addr;
   socklen_t *addrlen;
{
   int rc;

   while ((rc = accept(s, addr, addrlen)) == -1 && errno == EINTR)
      ;

   return rc;
}

int
socks_socketisforlan(s)
   const int s;
{
   const char *function = "socks_socketisforlan()";
   struct in_addr addr;
   socklen_t len;
   unsigned char ttl;
   const int errno_s = errno;

   /*
    * make an educated guess as to whether the socket is intended for
    * lan-only use or not.
    */

   len = sizeof(addr);
   if (getsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &addr, &len) != 0) {
      slog(LOG_DEBUG, "%s: getsockopt(IP_MULTICAST_IF) failed: %s",
      function, strerror(errno));

      errno = errno_s;
      return 0;
   }

   if (addr.s_addr == htonl(INADDR_ANY))
      return 0;

   len = sizeof(ttl);
   if (getsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, &len) != 0) {
      swarn("%s: getsockopt(IP_MULTICAST_TTL)", function);

      errno = errno_s;
      return 0;
   }

   return ttl == 1;
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
      swarn("%s: getpeername()", function);
      return -1;
   }

   slog(LOG_DEBUG, "%s: unconnecting socket currently connected to %s",
   function, sockaddr2string(&remote, remotestr, sizeof(remotestr)));

   bzero(&remote, sizeof(remote));
   remote.sa_family = AF_UNSPEC;

   if (connect(s, &remote, sizeof(remote)) != 0)
      slog(LOG_DEBUG, "%s: unconnect of socket returned %s",
      function, strerror(errno));

   /*
    * Linux, and possible others, fail to receive on the
    * socket until the local address has been "re-bound",
    * e.g. by sending a packet out.  Since we are not
    * sure the received packet will be allowed out by
    * the rules, re-bind the socket here to be sure we
    * don't miss replies in the meantime.
    */
   if (bind(s, &local, sizeof(local)) != 0)
      slog(LOG_DEBUG, "%s: re-bind after unconnecting: %s",
      function, strerror(errno));

   return 0;
}
