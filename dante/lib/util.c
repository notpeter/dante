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

/* XXX */
#if HAVE_STRVIS
#include <vis.h>
#else
#include "compat.h"
#endif  /* HAVE_STRVIS */

static const char rcsid[] =
"$Id: util.c,v 1.164 2009/01/12 14:08:40 michaels Exp $";

const char *
strcheck(string)
   const char *string;
{
   return string == NULL ? NOMEM : string;
}

unsigned char
sockscode(version, code)
   int version;
   int code;
{

   switch (version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V4REPLY_VERSION:
         switch (code) {
            case SOCKS_SUCCESS:
               return SOCKSV4_SUCCESS;

            default:
               return SOCKSV4_FAIL; /* v4 is not very specific. */
         }
      /* NOTREACHED */

      case PROXY_SOCKS_V5:
         switch (code) {
            default:
               return (unsigned char)code; /* current codes are all V5. */
         }
      /* NOTREACHED */

      case PROXY_MSPROXY_V2:
         switch (code) {
            case SOCKS_SUCCESS:
               return MSPROXY_SUCCESS;

            case SOCKS_FAILURE:
               return MSPROXY_FAILURE;

            default:
               SERRX(code);
         }
         /* NOTREACHED */

      case PROXY_HTTP_V1_0:
         switch (code) {
            case SOCKS_SUCCESS:
               return HTTP_SUCCESS;

            case SOCKS_FAILURE:
               /* LINTED constant argument to NOT */
               return !HTTP_SUCCESS;

            default:
               SERRX(code);
         }
         /* NOTREACHED */

      case PROXY_UPNP:
         switch (code) {
            case SOCKS_SUCCESS:
               return UPNP_SUCCESS;

            case SOCKS_FAILURE:
               return UPNP_FAILURE;

            default:
               SERRX(code);
         }
         /* NOTREACHED */


      default:
         SERRX(version);
   }

   /* NOTREACHED */
}

unsigned char
errno2reply(errnum, version)
   int errnum;
   int version;
{

   switch (errnum) {
      case ENETUNREACH:
         return sockscode(version, SOCKS_NETUNREACH);

      case EHOSTUNREACH:
         return sockscode(version, SOCKS_HOSTUNREACH);

      case ECONNREFUSED:
         return sockscode(version, SOCKS_CONNREFUSED);

      case ETIMEDOUT:
         return sockscode(version, SOCKS_TTLEXPIRED);
   }

   return sockscode(version, SOCKS_FAILURE);
}


struct sockaddr *
sockshost2sockaddr(host, addr)
   const struct sockshost_t *host;
   struct sockaddr *addr;
{
   const char *function = "sockshost2sockaddr()";
   uint8_t sa_length;

   bzero(addr, sizeof(*addr));

   switch (host->atype) {
      case SOCKS_ADDR_IPV4:
         addr->sa_family = AF_INET;
         sa_length = sizeof(struct sockaddr_in);

         /* LINTED pointer casts may be troublesome */
         TOIN(addr)->sin_addr = host->addr.ipv4;
         break;

      case SOCKS_ADDR_DOMAIN: {
         struct hostent *hostent;

         addr->sa_family = AF_INET;
         sa_length = sizeof(struct sockaddr_in);

         if ((hostent = gethostbyname(host->addr.domain)) == NULL
         ||   hostent->h_addr_list == NULL) {
            /* LINTED pointer casts may be troublesome */
            swarnx("%s: gethostbyname(%s): %s",
            function, host->addr.domain, hstrerror(h_errno));

            /* LINTED pointer casts may be troublesome */
            TOIN(addr)->sin_addr.s_addr = htonl(INADDR_ANY);

            break;
         }

         /* LINTED pointer casts may be troublesome */
         TOIN(addr)->sin_addr = *(struct in_addr *)(*hostent->h_addr_list);

         break;
      }

      default:
         SERRX(host->atype);
   }

#if HAVE_SOCKADDR_SA_LEN
   addr->sa_len = sa_length;
#endif /* HAVE_SOCKADDR_SA_LEN */

   /* LINTED pointer casts may be troublesome */
   TOIN(addr)->sin_port = host->port;

   return addr;
}

struct sockshost_t *
sockaddr2sockshost(addr, host)
   const struct sockaddr *addr;
   struct sockshost_t *host;
{

   switch (addr->sa_family) {
      case AF_INET:
         host->atype     = SOCKS_ADDR_IPV4;
         /* LINTED pointer casts may be troublesome */
         host->addr.ipv4 = TOCIN(addr)->sin_addr;
         /* LINTED pointer casts may be troublesome */
         host->port      = TOCIN(addr)->sin_port;
         break;

      default:
         SERRX(addr->sa_family);
   }

   return host;
}

struct sockshost_t *
ruleaddr2sockshost(address, host, protocol)
   const struct ruleaddr_t *address;
   struct sockshost_t *host;
   int protocol;
{

   switch (host->atype = address->atype) {
      case SOCKS_ADDR_IPV4:
         host->addr.ipv4 = address->addr.ipv4.ip;
         break;

      case SOCKS_ADDR_DOMAIN:
         SASSERTX(strlen(address->addr.domain) < sizeof(host->addr.domain));
         strcpy(host->addr.domain, address->addr.domain);
         break;

      default:
         SERRX(address->atype);
   }

   switch (protocol) {
      case SOCKS_TCP:
         host->port = address->port.tcp;
         break;

      case SOCKS_UDP:
         host->port = address->port.udp;
         break;

      default:
         SERRX(protocol);
   }

   return host;
}

gwaddr_t *
ruleaddr2gwaddr(address, gw)
   const struct ruleaddr_t *address;
   gwaddr_t *gw;
{

   switch (gw->atype = address->atype) {
      case SOCKS_ADDR_IPV4:
         gw->addr.ipv4 = address->addr.ipv4.ip;
         break;

      case SOCKS_ADDR_DOMAIN:
         SASSERTX(strlen(address->addr.domain) < sizeof(gw->addr.domain));
         strcpy(gw->addr.domain, address->addr.domain);
         break;

      case SOCKS_ADDR_IFNAME:
         SASSERTX(strlen(address->addr.ifname) < sizeof(gw->addr.ifname));
         strcpy(gw->addr.ifname, address->addr.ifname);
         break;

      default:
         SERRX(address->atype);
   }

   gw->port = address->port.tcp;

   return gw;
}


struct sockshost_t *
gwaddr2sockshost(gw, host)
   const gwaddr_t *gw;
   struct sockshost_t *host;
{

   switch (gw->atype) {
      case SOCKS_ADDR_IPV4:
         host->atype     = gw->atype;
         host->addr.ipv4 = gw->addr.ipv4;
         break;

      case SOCKS_ADDR_DOMAIN:
         host->atype = gw->atype;
         SASSERTX(strlen(gw->addr.domain) < sizeof(gw->addr.domain));
         strcpy(host->addr.domain, gw->addr.domain);
         break;

      case SOCKS_ADDR_IFNAME: {
         struct sockaddr saddr;

         if (ifname2sockaddr(gw->addr.ifname, 0, &saddr, NULL) == NULL) 
            serrx(1, "can't find interface named %s with ip configured",
				gw->addr.ifname);
         
         sockaddr2sockshost(&saddr, host);
         host->port = gw->port;
         break;
      }

      case SOCKS_ADDR_URL: {
         struct sockaddr saddr;

         if (urlstring2sockaddr(gw->addr.urlname, &saddr) == NULL)
            serrx(1, "can't convert %s to sockaddr", gw->addr.urlname);

         sockaddr2sockshost(&saddr, host);
         break;
      }

      default:
         SERRX(gw->atype);
   }

   host->port = gw->port;
   return host;
}

struct ruleaddr_t *
sockshost2ruleaddr(host, addr)
   const struct sockshost_t *host;
   struct ruleaddr_t *addr;
{

   switch (addr->atype = host->atype) {
      case SOCKS_ADDR_IPV4:
         addr->addr.ipv4.ip            = host->addr.ipv4;
         addr->addr.ipv4.mask.s_addr   = htonl(0xffffffff);
         break;

      case SOCKS_ADDR_DOMAIN:
         SASSERTX(strlen(host->addr.domain) < sizeof(addr->addr.domain));
         strcpy(addr->addr.domain, host->addr.domain);
         break;

      default:
         SERRX(host->atype);
   }

   addr->port.tcp      = host->port;
   addr->port.udp      = host->port;
   addr->portend      = host->port;

   if (host->port == htons(0))
      addr->operator   = none;
   else
      addr->operator = eq;

   return addr;
}

struct ruleaddr_t *
sockaddr2ruleaddr(addr, ruleaddr)
   const struct sockaddr *addr;
   struct ruleaddr_t *ruleaddr;
{
   struct sockshost_t host;

   sockaddr2sockshost(addr, &host);
   sockshost2ruleaddr(&host, ruleaddr);

   return ruleaddr;
}

struct sockaddr *
hostname2sockaddr(name, index, addr)
   const char *name;
   int index;
   struct sockaddr *addr;
{
   struct hostent *hostent;
   int i;


   if ((hostent = gethostbyname(name)) == NULL)
      return NULL;

   for (i = 0; hostent->h_addr_list[i] != NULL; ++i)
      if (i == index) {
         bzero(addr, sizeof(*addr));
         addr->sa_family = (uint8_t)hostent->h_addrtype;
#if HAVE_SOCKADDR_SA_LEN
         addr->sa_len = hostent->h_length;
#endif /* HAVE_SOCKADDR_SA_LEN */
         SASSERTX(addr->sa_family == AF_INET);
         /* LINTED pointer casts may be troublesome */
         TOIN(addr)->sin_addr = *(struct in_addr *)hostent->h_addr_list[i];
         /* LINTED pointer casts may be troublesome */
         TOIN(addr)->sin_port = htons(0);

         return addr;
      }

   return NULL;
}

struct sockaddr *
ifname2sockaddr(ifname, index, addr, mask)
   const char *ifname;
   int index;
   struct sockaddr *addr;
   struct sockaddr *mask;
{
   int i;
   struct ifaddrs ifa, *ifap = &ifa, *iface;

   if (getifaddrs(&ifap) != 0)
      return NULL;

   for (iface = ifap, i = 0; i <= index && iface != NULL;
   iface = iface->ifa_next)
      if (strcmp(iface->ifa_name, ifname) == 0
      && iface->ifa_addr != NULL && iface->ifa_addr->sa_family == AF_INET) {
         if (i++ != index)
            continue;

         *addr = *iface->ifa_addr;
         if (mask != NULL)
            *mask = *iface->ifa_netmask;
         freeifaddrs(ifap);

         return addr;
      }

   freeifaddrs(ifap);
   return NULL;
}

int
socks_logmatch(d, log)
   unsigned int d;
   const struct logtype_t *log;
{
   size_t i;

   for (i = 0; i < log->fpc; ++i)
      if (d == (unsigned int)log->fplockv[i]
      ||    d == (unsigned int)fileno(log->fpv[i]))
         return 1;
   return 0;
}

int
sockaddrareeq(a, b)
   const struct sockaddr *a;
   const struct sockaddr *b;
{
   
   
#if HAVE_SOCKADDR_SA_LEN
   if (a->sa_len != b->sa_len)
      return 0;
   return memcmp(a, b, a->sa_len) == 0;
#else
   return memcmp(a, b, sizeof(*a)) == 0;
#endif /* HAVE_SOCKADDR_SA_LEN */
}

int
sockshostareeq(a, b)
   const struct sockshost_t *a;
   const struct sockshost_t *b;
{

   if (a->atype != b->atype)
      return 0;

   switch (a->atype) {
      case SOCKS_ADDR_IPV4:
         if (memcmp(&a->addr.ipv4, &b->addr.ipv4, sizeof(a->addr.ipv4)) != 0)
            return 0;
         break;

      case SOCKS_ADDR_IPV6:
         if (memcmp(a->addr.ipv6, b->addr.ipv6, sizeof(a->addr.ipv6)) != 0)
            return 0;
         break;

      case SOCKS_ADDR_DOMAIN:
         if (strcmp(a->addr.domain, b->addr.domain) != 0)
            return 0;
         break;

      default:
         SERRX(a->atype);
   }

   if (a->port != b->port)
      return 0;
   return 1;
}

int
fdsetop(nfds, op, a, b, result)
   int nfds;
   int op;
   const fd_set *a;
   const fd_set *b;
   fd_set *result;
{
   int i, bits;

   FD_ZERO(result);
   bits = -1;

   switch (op) {
      case '&':
         for (i = 0; i < nfds; ++i)
            if (FD_ISSET(i, a) && FD_ISSET(i, b)) {
               FD_SET(i, result);
               bits = MAX(i, bits);
            }
         break;

      case '^':
         for (i = 0; i < nfds; ++i)
            if (FD_ISSET(i, a) != FD_ISSET(i, b)) {
               FD_SET(i, result);
               bits = MAX(i, bits);
            }
         break;

      default:
         SERRX(op);
   }

   return bits;
}

int
methodisset(method, methodv, methodc)
   int method;
   const int *methodv;
   size_t methodc;
{
   size_t i;

   for (i = 0; i < methodc; ++i)
      if (methodv[i] == method)
         return 1;
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

#ifdef SO_ERROR
      { SOL_SOCKET,   SO_ERROR          },
#endif /* SO_ERROR */

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

#if HAVE_SO_SNDLOWAT
#ifdef SO_RCVLOWAT
      { SOL_SOCKET,   SO_RCVLOWAT       },
#endif /* SO_RCVLOWAT */
#endif /* HAVE_SO_SNDLOWAT */

#if HAVE_SO_SNDLOWAT
#ifdef SO_SNDLOWAT
      { SOL_SOCKET,   SO_SNDLOWAT       },
#endif /* SO_SNDLOWAT */
#endif /* HAVE_SO_SNDLOWAT */

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
            swarn("%s: getsockopt(%d, %d)",
            function, levelname[i][0], levelname[i][1]);

         continue;
      }

      if (setsockopt(new_s, levelname[i][0], levelname[i][1], &val, len) == -1)
         if (errno != ENOPROTOOPT)
            swarn("%s: setsockopt(%d, %d)",
            function, levelname[i][0], levelname[i][1]);
   }

   if ((flags = fcntl(s, F_GETFL, 0))          == -1
   ||           fcntl(new_s, F_SETFL, flags)   == -1)
      swarn("%s: fcntl(F_GETFL/F_SETFL)", function);

#if SOCKS_SERVER && HAVE_LIBWRAP
   if ((s = fcntl(new_s, F_GETFD, 0))             == -1
   ||       fcntl(new_s, F_SETFD, s | FD_CLOEXEC) == -1)
      swarn("%s: fcntl(F_GETFD/F_SETFD)", function);
#endif /* SOCKS_SERVER */

   errno = errno_s;

   return new_s;
}

char *
str2vis(string, len)
   const char *string;
   size_t len;
{
   const int visflag = VIS_TAB | VIS_NL | VIS_CSTYLE | VIS_OCTAL;
   char *visstring;

   /* see vis(3) for "* 4" */
   if ((visstring = malloc((sizeof(*visstring) * len * 4) + 1)) != NULL)
      strvisx(visstring, string, len, visflag);
   return visstring;
}

int
socks_mklock(template)
   const char *template;
{
   const char *function = "socks_mklock()";
   char *prefix, *newtemplate;
   int s, flag;
   size_t len;

   if ((prefix = getenv("TMPDIR")) != NULL)
      if (*prefix == NUL)
         prefix = NULL;

   if (prefix == NULL)
      prefix = "/tmp";

   len = strlen(prefix) + strlen("/") + strlen(template) + 1;
   if ((newtemplate = malloc(sizeof(*newtemplate) * len)) == NULL)
      return -1;

   snprintfn(newtemplate, len, "%s/%s", prefix, template);
   if (strstr(newtemplate, "XXXXXX") != NULL)
      s = mkstemp(newtemplate);
   else
      s = open(newtemplate, O_RDWR | O_CREAT | O_EXCL);

   if (s == -1) {
      swarn("%s: mkstemp(%s)", function, newtemplate);
      free(newtemplate);
      return -1;
   }

   if (unlink(newtemplate) == -1) {
      swarn("%s: unlink(%s)", function, newtemplate);
      free(newtemplate);
      return -1;
   }

   free(newtemplate);

   if ((flag = fcntl(s, F_GETFD, 0))       == -1
   || fcntl(s, F_SETFD, flag | FD_CLOEXEC) == -1)
      swarn("%s: fcntl(F_GETFD/F_SETFD)", function);

   return s;
}


int
socks_lock(descriptor, type, timeout)
   int descriptor;
   int type;
   int timeout;
{
   const char *function = "socks_lock()";
   struct flock lock;
   int rc;

/*   slog(LOG_DEBUG, "%s: %d", function, descriptor);  */

   SASSERTX(timeout <= 0);

   lock.l_type   = (short)type;
   lock.l_start  = 0;
   lock.l_whence = SEEK_SET;
   lock.l_len    = 0;

#if 0 /* missing some bits here to handle racecondition. */
   if (timeout > 0) {
      struct sigaction sigact;

#if SOCKS_CLIENT
      if (sigaction(SIGALRM, NULL, &sigact) != 0)
         return -1;

      /* if handler already set for signal, don't override. */
      if (sigact.sa_handler == SIG_DFL || sigact.sa_handler == SIG_IGN) {
#else   /* !SOCKS_CLIENT */
      /* CONSTCOND */
      if (1) {
#endif /* !SOCKS_CLIENT */

         sigemptyset(&sigact.sa_mask);
         sigact.sa_flags   = 0;
         sigact.sa_handler = SIG_IGN;

         if (sigaction(SIGALRM, &sigact, NULL) != 0)
            return -1;
      }

      alarm((unsigned int)timeout);
   }
#endif

retry:
   do
      rc = fcntl(descriptor, timeout ? F_SETLKW : F_SETLK, &lock);
   while (rc == -1 && timeout == -1 && errno == EINTR);

   if (rc == -1)
      switch (errno) {
         case EACCES:
         case EAGAIN:
         case EINTR:
            break;

         case ENOLCK:
            swarn("%s: fcntl()", function);
            sleep(1);
            goto retry; /* don't exhaust the stack by calling socks_lock(). */

         default:
            SERR(descriptor);
      }

#if 0
   if (timeout > 0)
      alarm(0);
#endif

   if (rc != 0 && timeout == -1)
      abort();

   return rc == -1 ? rc : 0;
}

void
socks_unlock(d)
   int d;
{
/*   const char *function = "socks_unlock()";  */

/*   slog(LOG_DEBUG, "%s: %d", function, d);  */

   socks_lock(d, F_UNLCK, -1);
}


int
socks_socketisbound(s)
   int s;
{
   struct sockaddr_in addr;
   socklen_t len;

   len = sizeof(addr);
   /* LINTED pointer casts may be troublesome */
   if (getsockname(s, (struct sockaddr *)&addr, &len) != 0)
      return -1;

   return ADDRISBOUND(addr);
}

int
freedescriptors(message)
   const char *message;
{
   const int errno_s = errno;
   int i, freed, max;

   /* LINTED expression has null effect */
   for (freed = 0, i = 0, max = getdtablesize(); i < max; ++i)
      if (!fdisopen(i))
         ++freed;

   if (message != NULL)
      slog(LOG_DEBUG, "freedescriptors(%s): %d/%d", message, freed, max);

   errno = errno_s;

   return freed;
}

int
fdisopen(fd)
   int fd;
{

   return fcntl(fd, F_GETFD, 0) != -1;
}

void
closev(array, count)
   int *array;
   int count;
{

   for (--count; count >= 0; --count)
      if (array[count] >= 0)
         if (close(array[count]) != 0)
            SERR(-1);
}

int
#ifdef STDC_HEADERS
snprintfn(char *str, size_t size, const char *format, ...)
#else
snprintfn(str, size, format, va_alist
   char *str;
   size_t size;
   const char *format;
   va_dcl
#endif /* STDC_HEADERS */
{
   va_list ap;
   int rc;

#ifdef STDC_HEADERS
   /* LINTED pointer casts may be troublesome */
   va_start(ap, format);
#else
   va_start(ap);
#endif  /* STDC_HEADERS */

   rc = vsnprintf(str, size, format, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   if (rc == -1) {
      *str = NUL;
      return 0;
   }

   return MIN(rc, (int)(size - 1));
}

/*
 * Posted by Kien Ha (Kien_Ha@Mitel.COM) in comp.lang.c once upon a
 * time.
*/
int
bitcount(number)
   unsigned long number;
{
   int bitsset;

   for (bitsset = 0; number > 0; number >>= 1)
      if (number & 1)
         ++bitsset;

   return bitsset;
}

struct sockaddr *
urlstring2sockaddr(string, saddr)
   const char *string;
   struct sockaddr *saddr;
{
   const char *httpprefix = "http://";
   char *port, buf[INET_ADDRSTRLEN];

   if (strstr(string, httpprefix) == NULL) {
      swarnx("could not find httpprefix in http address \"%s\"", string);
      return NULL;
   }
   
   snprintf(buf, sizeof(buf), "%s",
   strstr(string, httpprefix) + strlen(httpprefix));

   if (strchr(buf, ':') == NULL) {
      swarnx("could not find portseperator in %s", string);
      return NULL;
   }
   *strchr(buf, ':') = NUL;

   bzero(saddr, sizeof(*saddr));
   saddr->sa_family = AF_INET;
   if (inet_pton(saddr->sa_family, buf, &(TOIN(saddr)->sin_addr)) != 1) {
      swarn("could not convert %s to network address", buf);
      return NULL;
   }
   
   if ((port = strrchr(string, ':')) == NULL) {
      swarnx("could not find start of portnumber in %s", string);
      return NULL;
   }
   ++port; /* skip ':' */

   TOIN(saddr)->sin_port = htons(atoi(port));

   return saddr;
}
