/*
 * $Id: getoutaddr.c,v 1.72 2011/05/18 13:48:46 karls Exp $
 *
 * Copyright (c) 2001, 2002, 2006, 2008, 2009, 2010, 2011
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

/*
 * The Linux code originated from Tom Chan <tchan@austin.rr.com>.
 * The BSD code came from Christoph Badura <bad@bsd.de> and W. R. Stevens
 * UNP book.
 *
 * Thanks, guys.
 */

#include "common.h"

static const char rcsid[] =
"$Id: getoutaddr.c,v 1.72 2011/05/18 13:48:46 karls Exp $";

#if HAVE_NET_IF_DL_H
#include   <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */
#include   <net/route.h>           /* RTA_xxx constants */
#if HAVE_ROUTEINFO_LINUX
#include   <asm/types.h>
#include   <linux/netlink.h>
#include   <linux/rtnetlink.h>
#endif /* HAVE_ROUTEINFO_LINUX */

static struct in_addr
getdefaultexternal(void);
/*
 * Returns the default IP address to use for external connections.
 */

static int
isonexternal(const struct sockaddr *addr);
/*
 * Returns true if "addr" is configured for the external interface,
 * otherwise false.
 */


#if HAVE_ROUTEINFO_LINUX
typedef unsigned char uchar_t;

struct in_addr
getoutaddr(src, dst)
   const struct in_addr src;
   const struct in_addr dst;
{
   const char *function = "getoutaddr()";
   struct {
      struct nlmsghdr nh;
      struct rtmsg   rt;
      char           attrbuf[512];
   } req;
   struct rtattr *rta;
   char buf[BUFSIZ], a[MAXSOCKADDRSTRING];
   struct nlmsghdr *rhdr;
   struct rtmsg *rrt;
   struct rtattr *rrta;
   struct sockaddr raddr;
   int attrlen;
   int rtnetlink_sk;

   if (sockscf.external.addrc <= 1
   ||  sockscf.external.rotation == ROTATION_NONE)
      return getdefaultexternal();

   if (sockscf.external.rotation == ROTATION_SAMESAME) {
      if (addrindex_on_externallist(&sockscf.external, src) != -1)
         return src;
      else
         return getdefaultexternal();
   }

   sockd_priv(SOCKD_PRIV_NET_ROUTESOCKET, PRIV_ON);
   rtnetlink_sk = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
   sockd_priv(SOCKD_PRIV_NET_ROUTESOCKET, PRIV_OFF);

   if (rtnetlink_sk == -1) {
      swarn("%s: socket(NETLINK_ROUTE)", function);
      return getdefaultexternal();
   }

   /*
    * Build the necessary data structures to get routing info.
    * The structures are:
    *   nlmsghdr - message header for netlink requests
    *      It specifies RTM_GETROUTE for get routing table info
    *   rtmsg - for routing table requests
    *   rtattr - Specifies RTA_DST indicating that the payload contains a
    *      destination address
    * the payload - the destination address
    */
   bzero(&req, sizeof(req));
   req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
   req.nh.nlmsg_flags = NLM_F_REQUEST;
   req.nh.nlmsg_type = RTM_GETROUTE;

   req.rt.rtm_family = AF_INET;
   req.rt.rtm_dst_len = 0;
   req.rt.rtm_src_len = 0;
   req.rt.rtm_tos = 0;
   req.rt.rtm_table = RT_TABLE_UNSPEC;
   req.rt.rtm_protocol = RTPROT_UNSPEC;
   req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
   req.rt.rtm_type = RTN_UNICAST;
   req.rt.rtm_flags = 0;

   rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
   rta->rta_type = RTA_DST;
   rta->rta_len = RTA_LENGTH(sizeof(dst));

   req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;

   /* send the request and get the response. */
   memcpy(RTA_DATA(rta), &dst, sizeof(dst));
   if (send(rtnetlink_sk, &req, req.nh.nlmsg_len, 0)
   != (ssize_t)req.nh.nlmsg_len) {
      swarn("%s: send() to netlink failed", function);
      close(rtnetlink_sk);
      return getdefaultexternal();
   }

   if (recv(rtnetlink_sk, &buf, sizeof(buf), 0) == -1) {
      swarn("%s: recv() from netlink failed", function);
      close(rtnetlink_sk);
      return getdefaultexternal();
   }

   /*
    * Walk the response structures to find the one that contains
    * RTA_PREFSRC in order to get the local source address to bind to.
    */
   rhdr = (struct nlmsghdr *)buf;
   rrt = (struct rtmsg *)NLMSG_DATA(rhdr);
   attrlen = sizeof(buf) - sizeof(struct nlmsghdr) - sizeof(struct rtmsg);

   bzero(&raddr, sizeof(raddr));
   raddr.sa_family = AF_INET;

   for (rrta = (struct rtattr *)((char *)rrt + sizeof(struct rtmsg));
        RTA_OK(rrta, attrlen);
        rrta = (struct rtattr *)RTA_NEXT(rrta, attrlen)) {
      if (rrta->rta_type == RTA_PREFSRC) {
         TOIN(&raddr)->sin_addr = *(struct in_addr *)RTA_DATA(rrta);

         if (!isonexternal(&raddr)) {
            swarn("%s: address %s selected, but not set on external",
            function, sockaddr2string(&raddr, a, sizeof(a)));

            close(rtnetlink_sk);
            return getdefaultexternal();
         }

         slog(LOG_DEBUG, "%s: address %s selected for dst %s",
         function, sockaddr2string(&raddr, a, sizeof(a)), inet_ntoa(dst));

         close(rtnetlink_sk);
         return TOIN(&raddr)->sin_addr;
      }
   }

   slog(LOG_DEBUG, "%s: can't find a gateway for %s, using default external",
   function, inet_ntoa(dst));
   close(rtnetlink_sk);
   return getdefaultexternal();
}
#elif HAVE_ROUTEINFO_BSD /* !HAVE_ROUTEINFO_LINUX */

#if HAVE_SOCKADDR_SA_LEN

#define NEXT_SA(ap) ap = (struct sockaddr *)                                   \
   ((caddr_t)ap + (ap->sa_len ?                                                \
   ROUNDUP(ap->sa_len, sizeof(unsigned long)) : sizeof(unsigned long)))

#else /* !HAVE_SOCKADDR_SA_LEN */

#define NEXT_SA(ap) ap = (struct sockaddr *)                                   \
   ((caddr_t)ap + (ifa_sa_len(ap->sa_family) ?                                 \
    ROUNDUP(ifa_sa_len(ap->sa_family), sizeof(unsigned long))                  \
  : sizeof(unsigned long)))

#endif /* !HAVE_SOCKADDR_SA_LEN */

#define BUFLEN   (  sizeof(struct rt_msghdr) \
                  + sizeof(struct sockaddr_storage) * RTAX_MAX)

#define SEQ   9999

#ifndef RTAX_GATEWAY
#define RTAX_GATEWAY 1
#endif /* !RTAX_GATEWAY */

#ifndef RTAX_IFA
#define RTAX_IFA RTA_IFA
#endif /* !RTAX_IFA */

#ifndef RTAX_MAX
#define RTAX_MAX RTA_NUMBITS
#endif /* !RTAX_MAX */

static void get_rtaddrs(const int addrs, struct sockaddr *sa,
                        struct sockaddr **rti_info);
#if !HAVE_SOCKADDR_SA_LEN
static size_t ifa_sa_len(const sa_family_t family);
#endif /* !HAVE_SOCKADDR_SA_LEN */

struct in_addr
getoutaddr(src, dst)
   const struct in_addr src;
   const struct in_addr dst;
{
   const char *function = "getoutaddr()";
   struct rt_msghdr *rtm;
   struct sockaddr *sa, *rti_info[RTAX_MAX];
   char rtmbuf[BUFLEN], a[MAXSOCKADDRSTRING];
   ssize_t rc;
   int sockfd;

   if (sockscf.external.addrc <= 1
   ||  sockscf.external.rotation == ROTATION_NONE)
      return getdefaultexternal();

   if (sockscf.external.rotation == ROTATION_SAMESAME) {
      if (addrindex_on_externallist(&sockscf.external, src) != -1)
         return src;
      else
         return getdefaultexternal();
   }

   sockd_priv(SOCKD_PRIV_NET_ROUTESOCKET, PRIV_ON);
   sockfd = socket(AF_ROUTE, SOCK_RAW, 0);
   sockd_priv(SOCKD_PRIV_NET_ROUTESOCKET, PRIV_OFF);

   if (sockfd == -1) {
      swarn("%s: socket(AF_ROUTE)", function);
      return getdefaultexternal();
   }

   /*
    * Build the necessary data structures to get routing info.
    * The structures are:
    *   rt_msghdr - specifies RTM_GET for getting routing table info.
    *   sockaddr  - contains the destination address.
    */
   bzero(rtmbuf, sizeof(rtmbuf));
   rtm                     = (struct rt_msghdr *)rtmbuf;
   rtm->rtm_msglen         = sizeof(struct rt_msghdr)
                           + sizeof(struct sockaddr_in);
   rtm->rtm_version        = RTM_VERSION;
   rtm->rtm_type           = RTM_GET;
   rtm->rtm_addrs          = RTA_DST | RTA_IFA;
   rtm->rtm_pid            = sockscf.state.pid;
   rtm->rtm_seq            = SEQ;
   rtm->rtm_flags          = RTF_UP | RTF_HOST | RTF_GATEWAY;

   sa = (struct sockaddr *) (rtm + 1);
   TOIN(sa)->sin_family    = AF_INET;
   TOIN(sa)->sin_addr      = dst;
   TOIN(sa)->sin_port      = htons(0);
#if HAVE_SOCKADDR_SA_LEN
   sa->sa_len              = sizeof(struct sockaddr_in);
#endif /* HAVE_SOCKADDR_SA_LEN */

   if ((rc = write(sockfd, rtm, (size_t)rtm->rtm_msglen)) != rtm->rtm_msglen) {
      swarn("%s: write() to AF_ROUTE failed (wrote %ld/%ld)",
      function, (long)rc, (long)rtm->rtm_msglen);

      close(sockfd);
      return getdefaultexternal();
   }

   bzero(rtmbuf, sizeof(rtmbuf));
   do {
      if ((rc = read(sockfd, rtm, sizeof(rtmbuf))) == -1) {
         swarn("%s: read from AF_ROUTE failed (read %ld)",
         function, (long)rc);

         close(sockfd);
         return getdefaultexternal();
      }
   } while (rtm->rtm_type != RTM_GET
         || rtm->rtm_seq  != SEQ
         || rtm->rtm_pid  != sockscf.state.pid);

   close(sockfd);

   sa  = (struct sockaddr *)(rtm + 1);
   get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

   if (rti_info[RTAX_GATEWAY] == NULL) {
      swarnx("%s: can't find gateway for %s, using default external",
      function, inet_ntoa(dst));

      return getdefaultexternal();
   }

   if (rti_info[RTAX_IFA] == NULL) {
     swarnx("%s: can't find ifa for %s, using default external",
     function, inet_ntoa(dst));

     return getdefaultexternal();
   }

   sa = rti_info[RTAX_IFA];
   if (sa->sa_family != AF_INET) {
      swarnx("%s: got unexpected/unsupported address family %d for %s",
      function, sa->sa_family, sockaddr2string(sa, a, sizeof(a)));

      return getdefaultexternal();
   }

   if (!isonexternal(sa)) {
      swarnx("%s: address %s selected, but not set for external interface",
      function, sockaddr2string(sa, a, sizeof(a)));

      return getdefaultexternal();
   }

   slog(LOG_DEBUG, "%s: address %s selected for dst %s",
   function, sockaddr2string(sa, a, sizeof(a)), inet_ntoa(dst));

   return TOIN(sa)->sin_addr;
}

static void
get_rtaddrs(addrs, sa, rti_info)
   const int addrs;
   struct sockaddr *sa;
   struct sockaddr **rti_info;
{
   const char *function = "get_rtaddrs()";
   int i;

   for (i = 0; i < RTAX_MAX; ++i) {
      if (addrs & (1 << i)) {
/*         slog(LOG_DEBUG, "%s: bit %d is set", function, i); */

         rti_info[i] = sa;
         NEXT_SA(sa);
      }
      else
         rti_info[i] = NULL;
   }
}

#if !HAVE_SOCKADDR_SA_LEN
static size_t
ifa_sa_len(family)
   const sa_family_t family;
{
   const char *function = "ifa_sa_len()";

   switch (family) {
      case AF_INET:
         return sizeof(struct sockaddr_in);

      case AF_INET6:
         return sizeof(struct sockaddr_in6);

      case AF_LINK:
         return sizeof(struct sockaddr_dl);
   }

   swarnx("%s: unknown socket family: %d", function, family);
   SWARNX(family);

   return sizeof(struct sockaddr);
}
#endif /* !HAVE_SOCKADDR_SA_LEN */

#else /* !HAVE_ROUTEINFO_BSD */
struct in_addr
getoutaddr(dst)
   struct in_addr dst;
{
   return getdefaultexternal();
}
#endif /* HAVE_ROUTEINFO_BSD */

static struct in_addr
getdefaultexternal(void)
{
   const char *function = "getdefaultexternal()";
   struct sockaddr bound;

   slog(LOG_DEBUG, "%s", function);

   /* find address to bind on clients behalf */
   switch ((*sockscf.external.addrv).atype) {
      case SOCKS_ADDR_IFNAME:
         if (ifname2sockaddr((*sockscf.external.addrv).addr.ifname, 0,
         &bound, NULL) == NULL) {
            swarnx("%s: can't find external interface/address: %s",
            function, (*sockscf.external.addrv).addr.ifname);

            /* LINTED pointer casts may be troublesome */
            TOIN(&bound)->sin_addr.s_addr = htonl(INADDR_NONE);
         }
         else
            slog(LOG_DEBUG, "%s: address for %s is %s",
                 function,
                 (*sockscf.external.addrv).addr.ifname,
                 sockaddr2string(&bound, NULL, 0));

         break;

      case SOCKS_ADDR_IPV4: {
         struct sockshost_t host;

         sockshost2sockaddr(ruleaddr2sockshost(&*sockscf.external.addrv,
         &host, SOCKS_TCP), &bound);
         break;
      }

      default:
         SERRX((*sockscf.external.addrv).atype);
   }

   return TOIN(&bound)->sin_addr;
}

static int
isonexternal(addr)
   const struct sockaddr *addr;
{
/*   const char *function = "isonexternal()"; */
   size_t i;

   for (i = 0; i < sockscf.external.addrc; ++i) {
      struct sockaddr check;
      int match = 0;

      switch (sockscf.external.addrv[i].atype) {
         case SOCKS_ADDR_IFNAME: {
            int ifi;

            ifi = 0;
            while (ifname2sockaddr(sockscf.external.addrv[i].addr.ifname,
            ifi++, &check, NULL) != NULL)
               /* LINTED pointer casts may be troublesome */
               if (TOIN(&check)->sin_addr.s_addr
               == TOCIN(addr)->sin_addr.s_addr) {
                  match = 1;
                  break;
               }
            }
            break;

         case SOCKS_ADDR_IPV4:
            /* LINTED pointer casts may be troublesome */
            if (sockscf.external.addrv[i].addr.ipv4.ip.s_addr
            == TOCIN(addr)->sin_addr.s_addr)
               match = 1;
            break;

         default:
            SERRX((*sockscf.external.addrv).atype);
      }

      if (match)
         break;
   }

   if (i == sockscf.external.addrc)
      return 0;

   return 1;
}
