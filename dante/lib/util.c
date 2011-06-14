/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2008,
 *               2009, 2010, 2011
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

#ifdef STANDALONE_UNIT_TEST
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <string.h>
#include <stdio.h>

#else /* STANDALONE_UNIT_TEST */

#include "vis_compat.h"
#include "ifaddrs_compat.h"

static const char rcsid[] =
"$Id: util.c,v 1.263 2011/05/26 08:39:33 michaels Exp $";

const char *
strcheck(string)
   const char *string;
{
   return string == NULL ? NOMEM : string;
}

unsigned int
sockscode(version, code)
   const int version;
   const int code;
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
         return (unsigned char)code; /* current codes are all V5. */

      case PROXY_HTTP_10:
      case PROXY_HTTP_11:
         switch (code) {
            case SOCKS_SUCCESS:
               return HTTP_SUCCESS;

            case SOCKS_FAILURE:
               return HTTP_FAILURE;

            case SOCKS_NOTALLOWED:
               return HTTP_NOTALLOWED;

            case SOCKS_NETUNREACH:
            case SOCKS_HOSTUNREACH:
            case SOCKS_CONNREFUSED:
               return HTTP_HOSTUNREACH;

            default:
               return HTTP_FAILURE;
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

unsigned int
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
      case ECONNRESET:
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
         sa_length       = sizeof(struct sockaddr_in);

         TOIN(addr)->sin_addr = host->addr.ipv4;
         TOIN(addr)->sin_port = host->port;
         break;

      case SOCKS_ADDR_DOMAIN: {
         struct hostent *hostent;

         addr->sa_family = AF_INET;
         sa_length       = sizeof(struct sockaddr_in);

         if ((hostent = gethostbyname(host->addr.domain)) == NULL
         ||   hostent->h_addr_list == NULL) {
            slog(LOG_DEBUG, "%s: gethostbyname(%s): %s",
            function, host->addr.domain, hstrerror(h_errno));

            /* LINTED pointer casts may be troublesome */
            TOIN(addr)->sin_addr.s_addr = htonl(INADDR_ANY);
         }
         else {
            TOIN(addr)->sin_addr = *(struct in_addr *)(*hostent->h_addr_list);
            TOIN(addr)->sin_port = host->port;
         }

         break;
      }

      default:
         SERRX(host->atype);
   }

#if HAVE_SOCKADDR_SA_LEN
   addr->sa_len = sa_length;
#endif /* HAVE_SOCKADDR_SA_LEN */

   return addr;
}

struct sockshost_t *
sockaddr2sockshost(addr, host)
   const struct sockaddr *addr;
   struct sockshost_t *host;
{

   switch (addr->sa_family) {
      case AF_INET:
         host->atype     = (unsigned char)SOCKS_ADDR_IPV4;
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

struct sockaddr *
ruleaddr2sockaddr(address, sa, protocol)
   const struct ruleaddr_t *address;
   struct sockaddr *sa;
   const int protocol;
{
   struct sockshost_t host;

   ruleaddr2sockshost(address, &host, protocol);
   return sockshost2sockaddr(&host, sa);
}


struct sockshost_t *
ruleaddr2sockshost(address, host, protocol)
   const struct ruleaddr_t *address;
   struct sockshost_t *host;
   int protocol;
{
   const char *function = "ruleaddr2sockshost()";

   switch (host->atype = (unsigned char)address->atype) {
      case SOCKS_ADDR_IPV4:
         host->addr.ipv4 = address->addr.ipv4.ip;
         break;

      case SOCKS_ADDR_DOMAIN:
         SASSERTX(strlen(address->addr.domain) < sizeof(host->addr.domain));
         strcpy(host->addr.domain, address->addr.domain);
         break;

      case SOCKS_ADDR_IFNAME: {
         struct sockaddr addr;

         host->atype = (unsigned char)SOCKS_ADDR_IPV4;

         if (ifname2sockaddr(address->addr.ifname, 0, &addr, NULL) == NULL) {
            swarnx("%s: can't find interface named %s with ip configured, "
                   "using INADDR_ANY",
                   function, address->addr.ifname);

            host->addr.ipv4.s_addr = htonl(INADDR_ANY);
         }
         else
            host->addr.ipv4 = TOIN(&addr)->sin_addr;
         break;
      }

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
   const char *function = "gwaddr2sockshost()";

   switch (gw->atype) {
      case SOCKS_ADDR_IPV4:
         host->atype     = (unsigned char)gw->atype;
         host->addr.ipv4 = gw->addr.ipv4;
         break;

      case SOCKS_ADDR_DOMAIN:
         host->atype = (unsigned char)gw->atype;
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
         char emsg[256];

         if (urlstring2sockaddr(gw->addr.urlname, &saddr, emsg, sizeof(emsg))
         == NULL)
            serrx(1, "%s: can't convert ulrstring to sockaddr: %s",
                      function,  
                      emsg);

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

   switch (addr->atype = (atype_t)host->atype) {
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
   size_t index;
   struct sockaddr *addr;
{
   struct hostent *hostent;
   size_t i;

   if ((hostent = gethostbyname(name)) == NULL)
      return NULL;

   for (i = 0; hostent->h_addr_list[i] != NULL; ++i)
      if (i == index) {
         bzero(addr, sizeof(*addr));
         addr->sa_family = (uint8_t)hostent->h_addrtype;

#if HAVE_SOCKADDR_SA_LEN
         switch (addr->sa_family) {
            case AF_INET:
               SASSERTX(hostent->h_length == sizeof(struct in_addr));
               addr->sa_len = sizeof(struct sockaddr_in);
               break;

            default:
               SERRX(addr->sa_family);
         }
#endif /* HAVE_SOCKADDR_SA_LEN */

         SASSERTX(addr->sa_family == AF_INET);
         TOIN(addr)->sin_addr = *(struct in_addr *)hostent->h_addr_list[i];
         TOIN(addr)->sin_port = htons(0);

         return addr;
      }

   return NULL;
}

struct sockaddr *
ifname2sockaddr(ifname, index, addr, mask)
   const char *ifname;
   size_t index;
   struct sockaddr *addr;
   struct sockaddr *mask;
{
   const char *function = "ifname2sockaddr()";
   struct ifaddrs ifa, *ifap = &ifa, *iface;
   size_t i;
   int foundifname, foundbutnoipv4;

   if (getifaddrs(&ifap) != 0) {
      swarn("%s: getifaddrs() failed", function);
      return NULL;
   }

   foundbutnoipv4 = 0;
   foundifname    = 0;
   for (iface = ifap, i = 0;
        i <= index && iface != NULL;
        iface = iface->ifa_next) {
      if (strcmp(iface->ifa_name, ifname) != 0)
         continue;

      if (iface->ifa_addr == NULL || iface->ifa_addr->sa_family != AF_INET) {
         foundbutnoipv4 = 1;
         continue;
      }

      foundbutnoipv4 = 0;
      if (i++ != index)
         continue;

      foundifname = 1;

      *addr = *iface->ifa_addr;

      if (mask != NULL)
         *mask = *iface->ifa_netmask;

      break;
   }

   freeifaddrs(ifap);

   if (index == 0 && foundbutnoipv4) {
      swarnx("%s: ifname %s has no ipv4 addresses configured.  Not usable",
      function, ifname);

      return NULL;
   }

   if (!foundifname) {
      if (index == 0)
         slog(LOG_DEBUG, "%s: no interface with the name \"%s\" found",
         function, ifname);

      return NULL;
   }

   return addr;
}

const char *
sockaddr2ifname(_addr, ifname, iflen)
   struct sockaddr *_addr;
   char *ifname;
   size_t iflen;
{
   const char *function = "sockaddr2ifname()";
   struct sockaddr addr = *_addr;
   struct ifaddrs ifa, *ifap = &ifa, *iface;

   if (ifname == NULL || iflen == 0) {
      static char ifname_mem[MAXIFNAMELEN];

      ifname = ifname_mem;
      iflen  = sizeof(ifname_mem);
   }

   bzero(ifname, iflen);
   TOIN(&addr)->sin_port = htons(0);

   if (getifaddrs(&ifap) != 0)
      return NULL;

   for (iface = ifap; iface != NULL; iface = iface->ifa_next)
      if (iface->ifa_addr != NULL && sockaddrareeq(iface->ifa_addr, &addr)) {
         strncpy(ifname, iface->ifa_name, iflen - 1);
         ifname[iflen - 1] = NUL;

         slog(LOG_DEBUG, "%s: address %s belongs to interface %s",
         function, sockaddr2string(&addr, NULL, 0), ifname);

         freeifaddrs(ifap);
         return ifname;
      }
      else
         slog(LOG_DEBUG, "%s: address %s does not belong to interface %s",
         function, sockaddr2string(&addr, NULL, 0), iface->ifa_name);

   freeifaddrs(ifap);
   return NULL;
}

int
socks_logmatch(d, log)
   unsigned int d;
   const struct logtype_t *log;
{
   size_t i;

   for (i = 0; i < log->filenoc; ++i)
      if (d == (unsigned int)log->filenov[i])
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
fdsetop(highestfd, op, a, b, result)
   int highestfd;
   int op;
   const fd_set *a;
   const fd_set *b;
   fd_set *result;
{
   int i, bits;

   bits = -1;
   switch (op) {
      case '&':
         FD_ZERO(result);
         for (i = 0; i <= highestfd; ++i)
            if (FD_ISSET(i, a) && FD_ISSET(i, b)) {
               FD_SET(i, result);
               bits = MAX(i, bits);
            }

         break;

      case '^':
         FD_ZERO(result);
         for (i = 0; i <= highestfd; ++i)
            if (FD_ISSET(i, a) != FD_ISSET(i, b)) {
               FD_SET(i, result);
               bits = MAX(i, bits);
            }
            else
               FD_CLR(i, result);

         break;

      case '|':
         /*
          * no FD_ZERO() required.  Allows caller to call us without using
          * a temporary object for result if he wants to do result = a | b.
          */
         for (i = 0; i <= highestfd; ++i)
            if (FD_ISSET(i, a) || FD_ISSET(i, b)) {
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
   const char *function = "methodisset()";
   size_t i;

   if (sockscf.option.debug)
      slog(LOG_DEBUG, "%s: checking if method %s is set in the list \"%s\"",
                      function,
                      method2string(method),
                      methods2string(methodc, methodv, NULL, 0));

   for (i = 0; i < methodc; ++i)
      if (methodv[i] == method)
         return 1;

   return 0;
}

char *
str2vis(string, len, visstring, vislen)
   const char *string;
   size_t len;
   char *visstring;
   size_t vislen;
{
   const int visflag = VIS_TAB | VIS_NL | VIS_CSTYLE | VIS_OCTAL;

   if (visstring == NULL) {
      SASSERTX(0); /* should never be used. */

      /* see vis(3) for "* 4" */
      if ((visstring = malloc((sizeof(*visstring) * len * 4) + 1)) == NULL)
         return NULL;

      vislen = len * 4 + 1;
   }

   len = MIN(len, (vislen / 4) - 1);
   strvisx(visstring, string, len, visflag);

   return visstring;
}

int
socks_mklock(template, newname, newnamelen)
   const char *template;
   char *newname;
   const size_t newnamelen;
{
   const char *function = "socks_mklock()";
   static char newtemplate[PATH_MAX];
   size_t len;
   char *prefix;
   int s, flag;

   if ((prefix = socks_getenv("TMPDIR", dontcare)) != NULL)
      if (*prefix == NUL)
         prefix = NULL;

   if (prefix == NULL)
      prefix = "";

   len = strlen(prefix) + strlen("/") + strlen(template) + 1;
   if (len > sizeof(newtemplate))
      serr(EXIT_FAILURE, "%s: the combination of \"%s\" (%lu) and \"%s\""
                         "is longer than the system max path length of %lu",
                         function,
                         prefix,
                         (unsigned long)strlen(prefix),
                         template,
                         (unsigned long)sizeof(newtemplate));

   if (newnamelen != 0 && len > newnamelen)
      serr(EXIT_FAILURE, "%s: the combination of \"%s\" (%lu) and \"%s\""
                         "is longer than the passed maxlength length of %lu",
                         function, prefix, (unsigned long)strlen(prefix),
                         template, (unsigned long)newnamelen);

   if (*prefix != NUL)
      snprintf(newtemplate, len, "%s/%s", prefix, template);
   else
      snprintf(newtemplate, len, "%s", template);

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: newtemplate = \"%s\", prefix = \"%s\" "
      "uid = %d, euid = %d, gid = %d, egid = %d",
      function, newtemplate, prefix,
      (int)getuid(), (int)geteuid(),
      (int)getgid(), (int)getegid());

   if (strstr(newtemplate, "XXXXXX") != NULL) {
      s = mkstemp(newtemplate);
#if HAVE_SOLARIS_BUGS
      if (s == -1 && *newtemplate == NUL) {
          /*
           * Solaris 5.11 sometimes loses the template on failure. :-/
           */
         if (*prefix != NUL)
            snprintf(newtemplate, len, "%s/%s", prefix, template);
         else
            snprintf(newtemplate, len, "%s", template);
      }
#endif /* HAVE_SOLARIS_BUGS */
   }
   else
      s = open(newtemplate, O_RDWR | O_CREAT | O_EXCL, 0600);

   if (s == -1) {
      if (*prefix == NUL) {
         slog(LOG_DEBUG, "%s: failed to create \"%s\" (%s) and TMPDIR is not "
                         "set.  Trying again with TMPDIR set to \"/tmp\"",
                         function, newtemplate, strerror(errno));

         if (setenv("TMPDIR", "/tmp", 1) != 0)
            serr(EXIT_FAILURE, "%s: could not setenv(\"TMPDIR\", \"/tmp\")",
            function);

         SASSERT(socks_getenv("TMPDIR", dontcare) != NULL);
         return socks_mklock(template, newname, newnamelen);
      }

      swarn("%s: open(%s)", function, newtemplate);
      return -1;
   }
   else
      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: created file %s", function, newtemplate);

   if (newnamelen == 0) {
      if (unlink(newtemplate) == -1) {
         swarn("%s: unlink(%s)", function, newtemplate);
         return -1;
      }
   }
   else
      strcpy(newname, newtemplate);

   if ((flag = fcntl(s, F_GETFD, 0))       == -1
   || fcntl(s, F_SETFD, flag | FD_CLOEXEC) == -1)
      swarn("%s: fcntl(F_GETFD/F_SETFD)", function);

   return s;
}

int
socks_lock(d, exclusive, wait)
   const int d;
   const int exclusive;
   const int wait;
{
/*   const char *function = "socks_lock()"; */
   struct flock lock;
   int rc;

/*   slog(LOG_DEBUG, "%s: %d", function, d);  */

   lock.l_start  = 0;
   lock.l_len    = 0;
   lock.l_whence = SEEK_SET;

   if (exclusive)
      lock.l_type = F_WRLCK;
   else
      lock.l_type = F_RDLCK;

   do
      rc = fcntl(d, wait ? F_SETLKW : F_SETLK, &lock);
   while (rc == -1 && ERRNOISTMP(errno) && wait);

   if (rc == -1) {
      if (!ERRNOISTMP(errno))
         SERR(d);

      if (wait)
         SERR(d);
   }

   return rc;
}

void
socks_unlock(d)
   int d;
{
/*   const char *function = "socks_unlock()";  */
   struct flock lock;

/*   slog(LOG_DEBUG, "%s: %d", function, d);  */

   lock.l_start  = 0;
   lock.l_len    = 0;
   lock.l_type   = F_UNLCK;
   lock.l_whence = SEEK_SET;

   if (fcntl(d, F_SETLK, &lock) == -1)
      SERR(errno);
}

int
freedescriptors(message)
   const char *message;
{
   const int errno_s = errno;
   size_t i, freed, max;

   /* LINTED expression has null effect */
   for (freed = 0, i = 0, max = sockscf.state.maxopenfiles; i < max; ++i)
      if (!fdisopen((int)i))
         ++freed;

   if (message != NULL)
      slog(LOG_DEBUG, "freedescriptors(%s): %ld/%ld",
            message, (long)freed, (long)max);

   errno = errno_s;
   return freed;
}

int
fdisopen(fd)
   const int fd;
{

   return fcntl(fd, F_GETFD, 0) != -1;
}

int
fdisblocking(fd)
   const int fd;
{
   const char *function = "fdisblocking()";
   int p;

   if ((p = fcntl(fd, F_GETFL, 0)) == -1) {
      swarn("%s: fcntl(F_GETFL)", function);
      return 1;
   }

   return !(p & O_NONBLOCK);
}

void
closev(array, i)
   int *array;
   int i;
{

   for (--i; i >= 0; --i)
      if (array[i] >= 0)
         if (close(array[i]) != 0)
            SERR(array[i]);
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

fd_set *
allocate_maxsize_fdset(void)
{
   const char *function = "allocate_maxsize_fdset()";
   fd_set *set;

   if ((sockscf.state.maxopenfiles = getmaxofiles(hardlimit)) == RLIM_INFINITY)
      /*
       * In the client the softlimit can vary at any time, so this is not
       * 100%, but see no other practical solution at the moment.
       */
      sockscf.state.maxopenfiles = getmaxofiles(softlimit);

   if (sockscf.state.maxopenfiles == RLIM_INFINITY)
      swarnx("%s: maxopenfiles is RLIM_INFINITY (%lu)",
      function, (unsigned long)RLIM_INFINITY);

   if ((set = malloc(SOCKD_FD_SIZE())) == NULL)
      serr(EXIT_FAILURE, "%s: malloc() of %lu bytes for fd_set failed",
      function, (unsigned long)SOCKD_FD_SIZE());

#if DEBUG
   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: allocated %lu bytes",
      function, (unsigned long)SOCKD_FD_SIZE());
#endif /* DEBUG */

   return set;
}

rlim_t
getmaxofiles(limittype_t type)
{
   struct rlimit rlimit;

   if (getrlimit(RLIMIT_OFILE, &rlimit) != 0)
         serr(EXIT_FAILURE, "getrlimit(RLIMIT_OFILE)");

   if (type == softlimit)
      return rlimit.rlim_cur;

   if (type == hardlimit)
#if HAVE_DARWIN /* documented os x bug.  What on earth are they thinking? */
      return MIN(rlimit.rlim_max, OPEN_MAX);
#else /* !HAVE_DARWIN */
      return rlimit.rlim_max;
#endif /* !HAVE_DARWIN */

   SERR(type); /* NOTREACHED */
}

void
socks_sigblock(sig, oldset)
   const int sig;
   sigset_t *oldset;
{
   const char *function = "socks_sigblock()";
   sigset_t newmask;

   if (sig == -1)
      (void)sigfillset(&newmask);
   else {
      (void)sigemptyset(&newmask);
      (void)sigaddset(&newmask, sig);
   }

   if (sigprocmask(SIG_BLOCK, &newmask, oldset) != 0)
      swarn("%s: sigprocmask()", function);
}

void
socks_sigunblock(oldset)
   const sigset_t *oldset;
{
   const char *function = "socks_sigunblock()";

   if (sigprocmask(SIG_SETMASK, oldset, NULL) != 0)
      swarn("%s: sigprocmask()", function);
}


int
socks_msghaserrors(prefix, msg)
   const char *prefix;
   const struct msghdr *msg;
{
   if (msg->msg_flags & MSG_TRUNC) {
      swarnx("%s: msg is truncated ... message discarded", prefix);

      if (CMSG_TOTLEN(*msg) > 0)
         swarnx("%s: XXX should close received descriptors", prefix);

      return 1;
   }

   if (msg->msg_flags & MSG_CTRUNC) {
      swarnx("%s: cmsg was truncated ... message discarded", prefix);
      return 1;
   }

   return 0;
}

void
seconds2days(seconds, days, hours, minutes)
   unsigned long *seconds;
   unsigned long *days;
   unsigned long *hours;
   unsigned long *minutes;
{

   if (*seconds >= 3600 * 24) {
      *days     = *seconds / (3600 * 24);
      *seconds -= *days * 3600 * 24;
   }
   else
      *days = 0;

   if (*seconds >= 3600) {
      *hours    = *seconds / 3600;
      *seconds -= *hours * 3600;
   }
   else
      *hours = 0;

   if (*seconds >= 60) {
      *minutes  = *seconds / 60;
      *seconds -= *minutes * 60;
   }
   else
      *minutes = 0;

}
#endif /* !STANDALONE_UNIT_TEST */

struct sockaddr *
urlstring2sockaddr(string, saddr, emsg, emsglen)
   const char *string;
   struct sockaddr *saddr;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "urlstring2sockaddr()";
   const char *httpprefix = "http://";
   char *port, buf[MAX(INET_ADDRSTRLEN, 256)], *s;
   int p;

   if ((s = strstr(string, httpprefix)) == NULL) {
      p = snprintf(buf, sizeof(buf), 
                   "could not find http prefix in http address \"%.80s\"",
                   string);
      str2vis(buf, p, emsg, emsglen);

      return NULL;
   }

   snprintf(buf, sizeof(buf), "%s", s + strlen(httpprefix));

   if ((s = strchr(buf, ':')) == NULL) {
      p = snprintf(buf, sizeof(buf),
                  "could not find port separator in \"%.80s\"",
                  string);
      str2vis(buf, p, emsg, emsglen);

      return NULL;
   }
   *s = NUL;

   if (*buf == NUL) {
      p = snprintf(buf, sizeof(buf),
                  "could not find address string in \"%.80s\"",
                  string);
      str2vis(buf, p, emsg, emsglen);

      return NULL;
   }

   slog(LOG_DEBUG, "%s: address is %s", function, buf);

   bzero(saddr, sizeof(*saddr));
   saddr->sa_family = AF_INET;
   if (inet_pton(saddr->sa_family, buf, &(TOIN(saddr)->sin_addr)) != 1) {
      struct hostent *hostent;
      long lval;
      char *ep, buf2[256];

      errno = 0;
      lval = strtol(buf, &ep, 10);
      if (*ep == NUL) { /* only digits, but inet_pton() failed. */
         p = snprintf(buf2, sizeof(buf2),
                     "\"%.80s\" does not appear to be a valid IP address",
                     buf);
         str2vis(buf2, p, emsg, emsglen);

         return NULL;
      }

      if ((hostent = gethostbyname(buf)) == NULL 
      ||   hostent->h_addr               == NULL) {
         p = snprintf(buf2, sizeof(buf2),
                      "could not resolve hostname \"%.80s\"",
                      buf);
         str2vis(buf2, p, emsg, emsglen);

         return NULL;
      }

      memcpy(&TOIN(saddr)->sin_addr, hostent->h_addr, hostent->h_length);
   }

   if ((port = strrchr(string, ':')) == NULL) {
      p = snprintf(buf, sizeof(buf), 
                  "could not find start of port number in \"%.80s\"",
                  string);
      str2vis(buf, p, emsg, emsglen);

      return NULL;
   }
   ++port; /* skip ':' */

   TOIN(saddr)->sin_port = htons((in_port_t)atoi(port));

   return saddr;
}

#ifndef STANDALONE_UNIT_TEST

#undef snprintf
size_t
snprintfn(char *str, size_t size, const char *format, ...)
{
   const int errno_s = errno;
   va_list ap;
   ssize_t rc;

   if (size <= 0)
      return 0;

   /* LINTED pointer casts may be troublesome */
   va_start(ap, format);

   rc = vsnprintf(str, size, format, ap);

   /* LINTED expression has null effect */
   va_end(ap);

   errno = errno_s; /* don't want snprintf(3) to change errno. */

   if (rc == -1) {
      *str = NUL;
      return 0;
   }

   return MIN((size_t)rc, size - 1);
}
#endif /* !STANDALONE_UNIT_TEST */
