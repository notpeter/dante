/*
 * Copyright (c) 1997, 1998, 1999, 2001, 2005, 2008, 2009, 2010, 2011
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
"$Id: socket.c,v 1.99 2011/05/27 10:24:28 michaels Exp $";

int
socks_connecthost(s, host, saddr, timeout, emsg, emsglen)
   int s;
   const struct sockshost_t *host;
   struct sockaddr *saddr;
   const long timeout;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "socks_connecthost()";
   struct hostent *hostent;
   struct sockaddr laddr, saddrmem;
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
   if (getsockname(s, &laddr, &len) == -1) {
      snprintf(emsg, emsglen, "getsockname(2) failed: %s", errnostr(errno));
      return -1;
   }
   sockaddr2string(&laddr, laddrstr, sizeof(laddrstr));

   slog(LOG_DEBUG, "%s: connect to %s from %s, on socket %d.  Timeout is %ld\n",
        function,
        sockshost2string(host, hoststr, sizeof(hoststr)),
        laddrstr,
        s,
        timeout);

   if (saddr == NULL)
      saddr = &saddrmem;

   bzero(saddr, sizeof(*saddr));
   TOIN(saddr)->sin_family = AF_INET;
   TOIN(saddr)->sin_port   = host->port;

   switch (host->atype) {
      case SOCKS_ADDR_IPV4: {
         int connect_errno, flags, changed_to_nonblocking;

         changed_to_nonblocking = 0;
         if (timeout != -1) {
            if ((flags = fcntl(s, F_GETFL, 0)) == -1) {
               snprintf(emsg, emsglen, "fcntl(F_GETFL) failed: %s",
                        errnostr(errno));

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
                           errnostr(errno));

                  return -1;
               }

               changed_to_nonblocking = 1;
            }
         }

         TOIN(saddr)->sin_addr = host->addr.ipv4;

         /* LINTED pointer casts may be troublesome */
         rc            = connect(s, saddr, sizeof(*saddr));
         connect_errno = errno;

         slog(LOG_DEBUG, "%s: connect() returned %d (%s)",
         function, rc, errnostr(errno));

         if (changed_to_nonblocking)
            if (fcntl(s, F_SETFL, flags & ~O_NONBLOCK) == -1)
               swarn("%s: failed reverting fd %d back to blocking",
               function, s);

         if (rc == 0)
            /*
             * OpenBSD 4.5 sometimes sets errno even though the
             * connect was successful.  Seems to be an artifact
             * of the threads library, where it does a select(2)/poll(2)
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
                * connectchild handle this then, if applicable.
                */
               return rc;
         }
#endif /* SOCKS_CLIENT */

         if (timeout == 0)
            return rc;

         while (rc == -1
         &&    (   errno == EINPROGRESS
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
            if (getsockname(s, &laddr, &len) == -1) {
               snprintf(emsg, emsglen,
                        "getsockname(2) after connect(2) failed: %s",
                        errnostr(errno));

               return -1;
            }

            sockaddr2string(&laddr, laddrstr, sizeof(laddrstr));
         }

         slog(LOG_DEBUG, "%s: connect to %s from %s on socket %d %s (%s)",
                         function,
                         sockaddr2string(saddr, addrstr, sizeof(addrstr)),
                         laddrstr,
                         s,
                         rc == 0 ? "ok" :
                         errno == EINPROGRESS ? "in progress" : "failed",
                         errnostr(errno));

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

   SASSERTX(host->atype == (unsigned char)SOCKS_ADDR_DOMAIN);
   SASSERTX(hostent != NULL && ip != NULL);
   SASSERTX(ADDRISBOUND(TOIN(&laddr)));

   failed = 0;
   do { /* try all ip addresses hostname resolves to. */
      struct sockshost_t newhost;

      if (failed) { /* previously failed, need to create a new socket. */
         int new_s;

         if ((new_s = socketoptdup(s)) == -1) {
            snprintf(emsg, emsglen, "socketoptdup() failed: %s",
                     errnostr(errno));

            return -1;
         }

         if (dup2(new_s, s) == -1) {
            snprintf(emsg, emsglen, "dup2() failed: %s", errnostr(errno));
            close(new_s);

            return -1;
         }
         close(new_s); /* s is now a new socket but keeps the same index. */

         /* try to bind the same address/port. */
#if SOCKS_CLIENT
         if (bind(s, &laddr, sizeof(laddr)) != 0) {
            snprintf(emsg, emsglen, "bind() failed: %s", strerror(errno));
            return -1;
         }
#else /* SOCKS_SERVER */
         if (sockd_bind(s, &laddr, 1) != 0) {
            snprintf(emsg, emsglen, "sockd_bind() failed: %s", errnostr(errno));
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

   snprintf(emsg, emsglen, "%s", errnostr(errno));
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
      slog(LOG_DEBUG, "%s: \"unconnect\" of socket returned %s",
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

int
socketoptdup(s)
   int s;
{
   const char *function = "socketoptdup()";
   unsigned int i;
   int flags, new_s, errno_s;
   socklen_t len;
   union {
      int               int_val;
      struct linger     linger_val;
      struct timeval    timeval_val;
      struct in_addr    in_addr_val;
      u_char            u_char_val;
      struct sockaddr   sockaddr_val;
      struct ipoption   ipoption;
   } val;
   int levelname[][2] = {

      /* socket options */

#ifdef SO_BROADCAST
      { SOL_SOCKET,   SO_BROADCAST      },
#endif /* SO_BROADCAST */

#ifdef SO_DEBUG
      { SOL_SOCKET,   SO_DEBUG          },
#endif /* SO_DEBUG */

#ifdef SO_DONTROUTE
      { SOL_SOCKET,   SO_DONTROUTE      },
#endif /* SO_DONTROUTE */

#ifdef SO_KEEPALIVE
      { SOL_SOCKET,   SO_KEEPALIVE      },
#endif /* SO_KEEPALIVE */

#ifdef SO_LINGER
      { SOL_SOCKET,   SO_LINGER         },
#endif /* SO_LINGER */

#ifdef SO_OOBINLINE
      { SOL_SOCKET,   SO_OOBINLINE      },
#endif /* SO_OOBINLINE */

#ifdef SO_RCVBUF
      { SOL_SOCKET,   SO_RCVBUF         },
#endif /* SO_RCVBUF */

#ifdef SO_SNDBUF
      { SOL_SOCKET,   SO_SNDBUF         },
#endif /* SO_SNDBUF */

#ifdef SO_RCVLOWAT
      { SOL_SOCKET,   SO_RCVLOWAT       },
#endif /* SO_RCVLOWAT */

#ifdef SO_SNDLOWAT
      { SOL_SOCKET,   SO_SNDLOWAT       },
#endif /* SO_SNDLOWAT */

#ifdef SO_RCVTIMEO
      { SOL_SOCKET,   SO_RCVTIMEO       },
#endif /* SO_RCVTIMEO */

#ifdef SO_SNDTIMEO
      { SOL_SOCKET,   SO_SNDTIMEO       },
#endif /* SO_SNDTIMEO */

#ifdef SO_REUSEADDR
      { SOL_SOCKET,   SO_REUSEADDR      },
#endif /* SO_REUSEADDR */

#ifdef SO_REUSEPORT
      { SOL_SOCKET,   SO_REUSEPORT      },
#endif /* SO_REUSEPORT */

#ifdef SO_USELOOPBACK
      { SOL_SOCKET,   SO_USELOOPBACK    },
#endif /* SO_USELOOPBACK */

      /* IP options */

#ifdef IP_HDRINCL
      { IPPROTO_IP,   IP_HDRINCL        },
#endif /* IP_HDRINCL */

#ifdef IP_OPTIONS
      { IPPROTO_IP,   IP_OPTIONS        },
#endif /* IP_OPTIONS */

#ifdef IP_RECVDSTADDR
      { IPPROTO_IP,   IP_RECVDSTADDR    },
#endif/* IP_RECVDSTADDR */

#ifdef IP_RECVIF
      { IPPROTO_IP,   IP_RECVIF         },
#endif /* IP_RECVIF */

#ifdef IP_TOS
      { IPPROTO_IP,   IP_TOS            },
#endif /* IP_TOS */

#ifdef IP_TTL
      { IPPROTO_IP,   IP_TTL            },
#endif /* IP_TTL */

#ifdef IP_MULTICAST_IF
      { IPPROTO_IP,   IP_MULTICAST_IF   },
#endif /* IP_MULTICAST_IF */

#ifdef IP_MULTICAST_TTL
      { IPPROTO_IP,   IP_MULTICAST_TTL  },
#endif /* IP_MULTICAST_TTL */

#ifdef IP_MULTICAST_LOOP
      { IPPROTO_IP,   IP_MULTICAST_LOOP },
#endif /* IP_MULTICAST_LOOP */

      /* TCP options */

#ifdef TCP_KEEPALIVE
      { IPPROTO_TCP,   TCP_KEEPALIVE    },
#endif /* TCP_KEEPALIVE */

#ifdef TCP_MAXRT
      { IPPROTO_TCP,   TCP_MAXRT        },
#endif /* TCP_MAXRT */

#ifdef TCP_MAXSEG
      { IPPROTO_TCP,   TCP_MAXSEG       },
#endif /* TCP_MAXSEG */

#ifdef TCP_NODELAY
      { IPPROTO_TCP,   TCP_NODELAY      },
#endif /* TCP_NODELAY */

#ifdef TCP_STDURG
      { IPPROTO_TCP,   TCP_STDURG       }
#endif /* TCP_STDURG */

   };

   errno_s = errno;

   len = sizeof(val);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) == -1) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return -1;
   }

   if ((new_s = socket(AF_INET, val.int_val, 0)) == -1) {
      swarn("%s: socket(AF_INET, %d)", function, val.int_val);
      return -1;
   }

   for (i = 0; i < ELEMENTS(levelname); ++i) {
      len = sizeof(val);
      if (getsockopt(s, levelname[i][0], levelname[i][1], &val, &len) == -1) {
         if (errno != ENOPROTOOPT)
            slog(LOG_DEBUG, "%s: getsockopt(%d, %d) failed: %s",
            function, levelname[i][0], levelname[i][1], strerror(errno));

         continue;
      }

      if (setsockopt(new_s, levelname[i][0], levelname[i][1], &val, len) == -1)
         if (errno != ENOPROTOOPT)
            slog(LOG_DEBUG, "%s: setsockopt(%d, %d) failed: %s",
            function, levelname[i][0], levelname[i][1], strerror(errno));
   }

   if ((flags = fcntl(s, F_GETFL, 0))          == -1
   ||           fcntl(new_s, F_SETFL, flags)   == -1)
      swarn("%s: fcntl(F_GETFL/F_SETFL)", function);

#if !SOCKS_CLIENT && HAVE_LIBWRAP
   if ((s = fcntl(new_s, F_GETFD, 0))             == -1
   ||       fcntl(new_s, F_SETFD, s | FD_CLOEXEC) == -1)
      swarn("%s: fcntl(F_GETFD/F_SETFD)", function);
#endif /* SOCKS_SERVER */

   errno = errno_s;

   return new_s;
}


#if DEBUG
void
printsocketopts(s)
   const int s;
{
   const char *function = "printsocketopts()";
   unsigned int i;
   int flags, errno_s;
   socklen_t len;
   union {
      int               int_val;
      struct linger     linger_val;
      struct timeval    timeval_val;
      struct in_addr    in_addr_val;
      u_char            u_char_val;
      struct sockaddr   sockaddr_val;
      struct ipoption   ipoption;
   } val;
   struct {
      int level;
      int optname;
      char *optstr;
   } option[] = {
      /* socket options */

#ifdef SO_BROADCAST
      { SOL_SOCKET, SO_BROADCAST, "SO_BROADCAST"      },
#endif /* SO_BROADCAST */

#ifdef SO_DEBUG
      { SOL_SOCKET, SO_DEBUG, "SO_DEBUG"          },
#endif /* SO_DEBUG */

#ifdef SO_DONTROUTE
      { SOL_SOCKET, SO_DONTROUTE, "SO_DONTROUTE"      },
#endif /* SO_DONTROUTE */

#ifdef SO_KEEPALIVE
      { SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE"      },
#endif /* SO_KEEPALIVE */

#ifdef SO_LINGER
      { SOL_SOCKET, SO_LINGER, "SO_LINGER"         },
#endif /* SO_LINGER */

#ifdef SO_OOBINLINE
      { SOL_SOCKET, SO_OOBINLINE, "SO_OOBINLINE"      },
#endif /* SO_OOBINLINE */

#ifdef SO_RCVBUF
      { SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF"         },
#endif /* SO_RCVBUF */

#ifdef SO_SNDBUF
      { SOL_SOCKET, SO_SNDBUF, "SO_SNDBUF"         },
#endif /* SO_SNDBUF */

#ifdef SO_RCVLOWAT
      { SOL_SOCKET, SO_RCVLOWAT, "SO_RCVLOWAT"       },
#endif /* SO_RCVLOWAT */

#ifdef SO_SNDLOWAT
      { SOL_SOCKET, SO_SNDLOWAT, "SO_SNDLOWAT"       },
#endif /* SO_SNDLOWAT */

#ifdef SO_RCVTIMEO
      { SOL_SOCKET, SO_RCVTIMEO, "SO_RCVTIMEO"       },
#endif /* SO_RCVTIMEO */

#ifdef SO_SNDTIMEO
      { SOL_SOCKET, SO_SNDTIMEO, "SO_SNDTIMEO"       },
#endif /* SO_SNDTIMEO */

#ifdef SO_REUSEADDR
      { SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR"      },
#endif /* SO_REUSEADDR */

#ifdef SO_REUSEPORT
      { SOL_SOCKET, SO_REUSEPORT, "SO_REUSEPORT"      },
#endif /* SO_REUSEPORT */

#ifdef SO_USELOOPBACK
      { SOL_SOCKET, SO_USELOOPBACK, "SO_USELOOPBACK"    },
#endif /* SO_USELOOPBACK */

      /* IP options */

#ifdef IP_HDRINCL
      { IPPROTO_IP, IP_HDRINCL, "IP_HDRINCL"        },
#endif /* IP_HDRINCL */

#ifdef IP_OPTIONS
      { IPPROTO_IP, IP_OPTIONS, "IP_OPTIONS"        },
#endif /* IP_OPTIONS */

#ifdef IP_RECVDSTADDR
      { IPPROTO_IP, IP_RECVDSTADDR, "IP_RECVDSTADDR"    },
#endif/* IP_RECVDSTADDR */

#ifdef IP_RECVIF
      { IPPROTO_IP, IP_RECVIF, "IP_RECVIF"         },
#endif /* IP_RECVIF */

#ifdef IP_TOS
      { IPPROTO_IP, IP_TOS, "IP_TOS"            },
#endif /* IP_TOS */

#ifdef IP_TTL
      { IPPROTO_IP, IP_TTL, "IP_TTL"            },
#endif /* IP_TTL */

#ifdef IP_MULTICAST_IF
      { IPPROTO_IP, IP_MULTICAST_IF, "IP_MULTICAST_IF"   },
#endif /* IP_MULTICAST_IF */

#ifdef IP_MULTICAST_TTL
      { IPPROTO_IP, IP_MULTICAST_TTL, "IP_MULTICAST_TTL"  },
#endif /* IP_MULTICAST_TTL */

#ifdef IP_MULTICAST_LOOP
      { IPPROTO_IP, IP_MULTICAST_LOOP, "IP_MULTICAST_LOOP" },
#endif /* IP_MULTICAST_LOOP */

      /* TCP options */

#ifdef TCP_KEEPALIVE
      { IPPROTO_TCP, TCP_KEEPALIVE, "TCP_KEEPALIVE"    },
#endif /* TCP_KEEPALIVE */

#ifdef TCP_MAXRT
      { IPPROTO_TCP, TCP_MAXRT, "TCP_MAXRT"        },
#endif /* TCP_MAXRT */

#ifdef TCP_MAXSEG
      { IPPROTO_TCP, TCP_MAXSEG, "TCP_MAXSEG"       },
#endif /* TCP_MAXSEG */

#ifdef TCP_NODELAY
      { IPPROTO_TCP, TCP_NODELAY, "TCP_NODELAY"      },
#endif /* TCP_NODELAY */

#ifdef TCP_STDURG
      { IPPROTO_TCP, TCP_STDURG, "TCP_STDURG"       }
#endif /* TCP_STDURG */
   };

   errno_s = errno;

   len = sizeof(val);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) == -1) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return;
   }

   for (i = 0; i < ELEMENTS(option); ++i) {
      len = sizeof(val);
      if (getsockopt(s, option[i].level, option[i].optname, &val, &len) == -1) {
         if (errno != ENOPROTOOPT)
            swarn("%s: getsockopt(%s) failed", function, option[i].optstr);
         continue;
      }

      slog(LOG_DEBUG, "%s: value of socketoption %s is %d\n",
      function, option[i].optstr, val.int_val);
   }

   if ((flags = fcntl(s, F_GETFL, 0)) == -1)
      swarn("%s: fcntl(F_GETFL)", function);
   else
      slog(LOG_DEBUG, "%s: value of file status flags is %d\n",
      function, flags);

   if ((flags = fcntl(s, F_GETFD, 0)) == -1)
      swarn("fcntl(F_GETFD)");
   else
      slog(LOG_DEBUG, "%s: value of file descriptor flags is %d\n",
      function, flags);

   errno = errno_s;
}

#endif /* DEBUG */
