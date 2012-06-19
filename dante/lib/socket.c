/*
 * Copyright (c) 1997, 1998, 1999, 2001, 2005, 2008, 2009, 2010, 2011, 2012
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
"$Id: socket.c,v 1.123 2012/06/01 20:23:05 karls Exp $";

int
socks_connecthost(s, host, saddr, timeout, emsg, emsglen)
   int s;
   const sockshost_t *host;
   struct sockaddr *saddr;
   const long timeout;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "socks_connecthost()";
   struct hostent *hostent;
   struct sockaddr_storage laddr, saddrmem;
   socklen_t len;
   char **ip, addrstr[MAXSOCKADDRSTRING], hoststr[MAXSOCKSHOSTSTRING],
              laddrstr[MAXSOCKADDRSTRING];
   int failed, rc;
   static fd_set *wset;

   /*
    * caller depends on errno to know whether the connect(2) failed
    * permanently, or whether things are now in progress, so make
    * sure errno is correct upon return, and definitely not some old
    * residue.
    */
   errno = 0;

   if (emsglen > 0)
      *emsg = NUL; /* init. */

   if (wset == NULL)
      wset = allocate_maxsize_fdset();

   len = sizeof(laddr);
   if (getsockname(s, TOSA(&laddr), &len) == -1) {
      snprintf(emsg, emsglen, "getsockname(2) failed: %s", strerror(errno));
      return -1;
   }
   sockaddr2string(TOSA(&laddr), laddrstr, sizeof(laddrstr));

   slog(LOG_DEBUG, "%s: connect to %s from %s, on socket %d.  Timeout is %ld\n",
        function,
        sockshost2string(host, hoststr, sizeof(hoststr)),
        laddrstr,
        s,
        timeout);

   if (saddr == NULL)
      saddr = TOSA(&saddrmem);

   bzero(saddr, sizeof(*saddr));
   SET_SOCKADDR(TOSA(saddr), AF_INET);
   TOIN(saddr)->sin_port = host->port;

   switch (host->atype) {
      case SOCKS_ADDR_IPV4: {
         int connect_errno, flags, changed_to_nonblocking;

         changed_to_nonblocking = 0;
         flags                  = -1;
         if (timeout != -1) {
            if ((flags = fcntl(s, F_GETFL, 0)) == -1) {
               snprintf(emsg, emsglen, "fcntl(F_GETFL) failed: %s",
                        strerror(errno));

               return -1;
            }

            if (!(flags & O_NONBLOCK)) {
               slog(LOG_DEBUG, "%s: temporarily changing fd %d to nonblocking "
                               "in order to facilitate the specified connect "
                               "timeout",
                               function, s);

               if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
                  snprintf(emsg, emsglen,
                           "could not change fd to nonblocking: %s",
                           strerror(errno));

                  return -1;
               }

               changed_to_nonblocking = 1;
            }
         }

         TOIN(saddr)->sin_addr = host->addr.ipv4;
         rc                    = connect(s, saddr, sockaddr2salen(TOSA(saddr)));
         connect_errno         = errno;

         slog(LOG_DEBUG, "%s: connect(2) to %s returned %d (%s)",
              function, sockaddr2string(saddr, NULL, 0), rc, strerror(errno));

         if (changed_to_nonblocking) {
            SASSERTX(flags != -1);

            if (fcntl(s, F_SETFL, flags & ~O_NONBLOCK) == -1)
               swarn("%s: failed reverting fd %d back to blocking",
               function, s);
         }

         if (rc == 0)
            /*
             * OpenBSD 4.5 sometimes sets errno even though the
             * connect was successful.  Seems to be an artifact of the
             * buggy threads library, where it does a select(2)/poll(2)
             * after making the socket non-blocking, but forgets to
             * reset errno.
             */
            connect_errno = 0;

         errno = connect_errno;

#if SOCKS_CLIENT
         /*
          * if errno is EINTR, it may be due to the client having set up an
          * alarm for this.  We can't know for sure, so better not
          * retry in that case.
          */
          if (rc == -1) {
            if (errno == EINTR)
               return rc;

            if (!changed_to_nonblocking)
               /*
                * was passed a non-blocking fd by the client, so client does
                * not want to wait for the connect to complete.  Let the
                * connect child handle this then, if applicable.
                */
               return rc;
         }
#endif /* SOCKS_CLIENT */

         while (timeout != 0
         &&     rc      == -1
         &&   (  errno == EINPROGRESS
#if SOCKS_CLIENT
              || errno == EINTR
#endif /* SOCKS_CLIENT */
         )) {
            struct timeval tval = { timeout, (long)0 };
            socklen_t len;

            FD_ZERO(wset);
            FD_SET(s, wset);

            rc = select(s + 1, NULL, wset, NULL, timeout >= 0 ? &tval : NULL);
            if (rc == -1 && errno == EINTR)
               continue;

            if (rc == 0)
               errno = ETIMEDOUT;
            else {
               len = sizeof(errno);
               getsockopt(s, SOL_SOCKET, SO_ERROR, &errno, &len);
            }

            if (errno == 0)
               rc = 0;
            else
               rc = -1;
         }

         if (rc == 0 || errno == EINPROGRESS) {
            /*
             * if address was incomplete before, it should be complete now.
             */
            len = sizeof(laddr);
            if (getsockname(s, TOSA(&laddr), &len) == -1) {
               snprintf(emsg, emsglen,
                        "getsockname(2) after connect(2) failed: %s",
                        strerror(errno));

               return -1;
            }

            sockaddr2string(TOSA(&laddr), laddrstr, sizeof(laddrstr));
         }

         slog(LOG_DEBUG, "%s: connect to %s from %s on socket %d %s (%s)",
                         function,
                         sockaddr2string(saddr, addrstr, sizeof(addrstr)),
                         laddrstr,
                         s,
                         rc == 0 ? "ok" :
                         errno == EINPROGRESS ? "in progress" : "failed",
                         strerror(errno));

         if (rc == -1) {
            if (ERRNOISNOROUTE(errno)) {
               /* specialcased because customer wants warning. */
               snprintf(emsg, emsglen, "no route to %s",
                        sockaddr2string(saddr, NULL, 0));
               swarn("%s: %s", function, emsg);
            }
            else if (errno != EINPROGRESS)
               snprintf(emsg, emsglen, strerror(errno));
         }

         return rc;
      }

      case SOCKS_ADDR_DOMAIN:
         hostent = gethostbyname(host->addr.domain);
         if (hostent == NULL || (ip = hostent->h_addr_list) == NULL) {
            snprintf(emsg, emsglen, "could not resolve hostname \"%s\": %s",
                     host->addr.domain, hstrerror(h_errno));

            errno = EHOSTUNREACH; /* anything but EINPROGRESS. */
            return -1;
         }
         break;

      default:
         SERRX(host->atype);
   }

   SASSERTX(host->atype == SOCKS_ADDR_DOMAIN);
   SASSERTX(hostent != NULL && ip != NULL);

   failed = 0;
   do { /* try all ip addresses hostname resolves to. */
      sockshost_t newhost;

      if (failed) { /* previously failed, need to create a new socket. */
         int new_s;

         if ((new_s = socketoptdup(s)) == -1) {
            snprintf(emsg, emsglen, "socketoptdup() failed: %s",
                     strerror(errno));

            return -1;
         }

         if (dup2(new_s, s) == -1) {
            snprintf(emsg, emsglen, "dup2() failed: %s", strerror(errno));
            close(new_s);

            return -1;
         }
         close(new_s); /* s is now a new socket but keeps the same index. */

         /* try to bind the same address/port. */
#if SOCKS_CLIENT
         if (bind(s, TOSA(&laddr), sockaddr2salen(TOSA(&laddr))) != 0) {
            snprintf(emsg, emsglen, "bind() failed: %s", strerror(errno));
            return -1;
         }
#else /* SOCKS_SERVER */
         if (sockd_bind(s, TOSA(&laddr), 1) != 0) {
            snprintf(emsg, emsglen, "sockd_bind() failed: %s", strerror(errno));
            return -1;
         }
#endif /* SOCKS_SERVER */
      }

      TOIN(saddr)->sin_addr = *((struct in_addr *)*ip);
      sockaddr2sockshost(saddr, &newhost);

      if (*(ip + 1) == NULL)
         /*
          * no more ip addresses to try.  That means we can simply call
          * socks_connecthost() with the timeout as received.
          * If not, we will need to disregard the passed in timeout and
          * connect to one address at a time and await the result. :-/
          *
          * XXX improve this by keeping track of how much time we've used
          * so far, so we can decrement the timeout on each connecthost()
          * call?
          */
         rc = socks_connecthost(s, &newhost, saddr, timeout, emsg, emsglen);
      else
         rc = socks_connecthost(s,
                                &newhost,
                                saddr,
                                sockscf.timeout.connect ?
                                /* LINTED cast from unsigned to signed. */
                                (long)sockscf.timeout.connect : -1,
                                emsg,
                                emsglen);

      if (rc == 0)
         return 0;

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
   } while (*(++ip) != NULL);

   snprintf(emsg, emsglen, strerror(errno));
   return -1; /* list exhausted, no successful connect. */
}

int
acceptn(s, addr, addrlen)
   int s;
   struct sockaddr *addr;
   socklen_t *addrlen;
{
   int rc;

   while ((rc = accept(s, addr, addrlen)) == -1 && errno == EINTR)
#if !SOCKS_CLIENT
      /*
       * XXX only here because request children block on accept(2).
       * Remove it if we some day improve the request children so they no
       * longer do that.
       */
      sockd_handledsignals();
#else /* SOCKS_CLIENT */
      ;
#endif /* SOCKS_CLIENT */

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
