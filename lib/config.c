/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009, 2010,
 *               2011
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
"$Id: config.c,v 1.318 2011/05/31 18:14:17 michaels Exp $";

void
genericinit(void)
{
   const char *function = "genericinit()";
#if BAREFOOTD
   struct rule_t *rule;
#endif /* BAREFOOTD */
#if !SOCKS_CLIENT
   sigset_t set, oset;
#endif /* !SOCKS_CLIENT */

#if SOCKS_CLIENT
   SASSERTX(sockscf.loglock == -1);
#else /* !SOCKS_CLIENT */
   if (sockscf.loglock == -1)
      if ((sockscf.loglock = socks_mklock(SOCKS_LOCKFILE, NULL, 0)) == -1)
         serr(EXIT_FAILURE, "%s: could not create lockfile for logging",
         function);
#endif

   if (!sockscf.state.inited) {
#if !HAVE_SETPROCTITLE
      /* create a backup to avoid setproctitle replacement overwriting it. */
      if ((__progname = strdup(__progname)) == NULL)
         serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
#endif /* !HAVE_SETPROCTITLE */
   }

#if !SOCKS_CLIENT
   sigemptyset(&set);
   sigaddset(&set, SIGHUP);
   sigaddset(&set, SIGTERM);
   if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
      swarn("%s: sigprocmask(SIG_BLOCK)", function);

   resetconfig(0);
#endif /* !SOCKS_CLIENT */

   optioninit();

   if (parseconfig(sockscf.option.configfile) != 0)
      return;

#if !SOCKS_CLIENT
   if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK)", function);

#endif /* SOCKS_SERVER */

#if !HAVE_NO_RESOLVESTUFF
   if (!(_res.options & RES_INIT)) {
      res_init();
      _res.options = RES_DEFAULT;
   }
#endif /* !HAVE_NO_RESOLVSTUFF */

   switch (sockscf.resolveprotocol) {
      case RESOLVEPROTOCOL_TCP:
#if !HAVE_NO_RESOLVESTUFF
         _res.options |= RES_USEVC;
#else /* HAVE_NO_RESOLVESTUFF */
         SERRX(sockscf.resolveprotocol);
#endif /* HAVE_NO_RESOLVESTUFF */
         break;

      case RESOLVEPROTOCOL_UDP:
      case RESOLVEPROTOCOL_FAKE:
         break;

      default:
         SERRX(sockscf.resolveprotocol);
   }

#if BAREFOOTD
   sockscf.state.alludpbounced = 1; /* default.  Change later if bouncing udp */
   rule = sockscf.crule;
   while (rule != NULL) {
      if (rule->state.protocol.udp) {
         sockscf.state.alludpbounced = 0;
         break;
      }

      rule = rule->next;
   }
#endif /* BAREFOOTD */

#if SOCKSLIBRARY_DYNAMIC
   symbolcheck();
#endif /* SOCKSLIBRARY_DYNAMIC */
}

struct route_t *
socks_addroute(newroute, last)
   const struct route_t *newroute;
   const int last;
{
   const char *function = "socks_addroute()";
   struct serverstate_t nilstate;
   struct route_t *route, *nextroute;
   struct sockaddr addr, mask;
   struct ruleaddr_t dst;
   size_t i;
   int ifb;

   if ((route = malloc(sizeof(*route))) == NULL)
      yyerror("%s: %s", function, NOMEM);

   *route = *newroute;
   bzero(&nilstate, sizeof(nilstate));

   /* if no proxy protocol set, set socks v5. */
   if (memcmp(&nilstate.proxyprotocol, &route->gw.state.proxyprotocol,
   sizeof(nilstate.proxyprotocol)) == 0) {
      memset(&route->gw.state.proxyprotocol, 0,
      sizeof(route->gw.state.proxyprotocol));

      route->gw.state.proxyprotocol.socks_v5 = 1;
   }
   else { /* proxy protocol set, do they make sense? */
      struct proxyprotocol_t proxy;

      if (route->gw.state.proxyprotocol.direct) {
         memset(&proxy, 0, sizeof(proxy));
         proxy.direct = 1;

         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1,
            "%s: can't combine proxy protocol direct with other protocols",
            function);
      }
      else if (route->gw.state.proxyprotocol.socks_v4
      ||       route->gw.state.proxyprotocol.socks_v5) {
         if (route->gw.state.proxyprotocol.http
         ||  route->gw.state.proxyprotocol.upnp)
         serrx(1, "%s: can't combine proxy protocol socks with other protocols",
         function);
      }
      else if (route->gw.state.proxyprotocol.http) {
         memset(&proxy, 0, sizeof(proxy));
         proxy.http = 1;

         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1,
            "%s: can't combine proxy protocol http with other protocols",
            function);
      }
      else if (route->gw.state.proxyprotocol.upnp) {
#if !HAVE_LIBMINIUPNP
         serrx(1, "%s: not configured for using upnp", function);
#endif /* !HAVE_LIBMINIUPNP */
         memset(&proxy, 0, sizeof(proxy));
         proxy.upnp = 1;

         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1, "%s: can't combine proxy protocol upnp with other "
                     "protocols",
                     function);
      }
   }

   if (memcmp(&nilstate.command, &route->gw.state.command,
   sizeof(nilstate.command)) == 0) {
      if (route->gw.state.proxyprotocol.direct) {
#if SOCKS_CLIENT
         route->gw.state.command.udpassociate   = 1;
         route->gw.state.command.udpreply       = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.command.connect        = 1;

         /*
          * in a normal client configuration, it makes more sense
          * to not enable bind for direct routes, unless the user
          * explicitly enables it.
          * If not, bind(2) will always be local, which in most
          * cases is probably not what the user wanted, even
          * though he implied it by not specifying what commands
          * the direct route should handle, meaning "all".
          */
         route->gw.state.command.bind            = 0;
         route->gw.state.command.bindreply       = 0;
      }

      /*
       * Now go through the proxy protocol(s) supported by this route,
       * and enable the appropriate protocols and commands, if the
       * user has not already done so.
       */
      if (route->gw.state.proxyprotocol.socks_v5) {
#if SOCKS_CLIENT
         route->gw.state.command.udpassociate  = 1;
         route->gw.state.command.udpreply      = 1;
         route->gw.state.command.bind          = 1;
         route->gw.state.command.bindreply     = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.command.connect       = 1;
      }

      if (route->gw.state.proxyprotocol.socks_v4) {
#if SOCKS_CLIENT
         route->gw.state.command.bind       = 1;
         route->gw.state.command.bindreply  = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.command.connect    = 1;
      }

      if (route->gw.state.proxyprotocol.http) {
         route->gw.state.command.connect = 1;
      }

      if (route->gw.state.proxyprotocol.upnp) {
#if SOCKS_CLIENT
         route->gw.state.command.udpassociate = 1;
         route->gw.state.command.udpreply     = 1;
         route->gw.state.command.bind         = 1;
         route->gw.state.command.bindreply    = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.command.connect      = 1;
      }

   }
#if !SOCKS_CLIENT
   else {
      if (!route->gw.state.proxyprotocol.direct) {
         if (route->gw.state.command.bind
         ||  route->gw.state.command.bindreply
         ||  route->gw.state.command.udpassociate
         ||  route->gw.state.command.udpreply
         ||  route->gw.state.protocol.udp)
            yyerror("serverchaining only supported for connect command");
      }
   }
#endif /* !SOCKS_CLIENT */

   if (memcmp(&nilstate.protocol, &route->gw.state.protocol,
   sizeof(nilstate.protocol)) == 0) {
      if (route->gw.state.proxyprotocol.direct) {
#if SOCKS_CLIENT
         route->gw.state.protocol.udp = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.socks_v5) {
#if SOCKS_CLIENT
         route->gw.state.protocol.udp = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.socks_v4) {
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.http) {
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.upnp) {
#if SOCKS_CLIENT
         route->gw.state.protocol.udp = 1;
#endif /* SOCKS_CLIENT */
         route->gw.state.protocol.tcp = 1;
      }
   }

#if HAVE_GSSAPI
   /*
    * if no gssapienctype set, or only nec-compatibility set,
    * set all except per-message.
    */
   if (route->gw.state.gssapiencryption.clear            == 0
   &&  route->gw.state.gssapiencryption.integrity        == 0
   &&  route->gw.state.gssapiencryption.confidentiality  == 0
   &&  route->gw.state.gssapiencryption.permessage       == 0) {
      route->gw.state.gssapiencryption.clear           = 1;
      route->gw.state.gssapiencryption.integrity       = 1;
      route->gw.state.gssapiencryption.confidentiality = 1;
      route->gw.state.gssapiencryption.permessage      = 0;
   }

   /* if no gssapiservicename set, set to default. */
   if (strcmp((char *)&nilstate.gssapiservicename,
   (char *)&route->gw.state.gssapiservicename) == 0)
      strcpy(route->gw.state.gssapiservicename, DEFAULT_GSSAPISERVICENAME);

   /* if no gssapiservicename set, set to default. */
   if (strcmp((char *)&nilstate.gssapikeytab,
   (char *)&route->gw.state.gssapikeytab) == 0)
      strcpy(route->gw.state.gssapikeytab, DEFAULT_GSSAPIKEYTAB);
#endif /* HAVE_GSSAPI */

   /* if no method set, set all we support for the set proxy protocols. */
   if (route->gw.state.methodc == 0) {
      int *methodv    =  route->gw.state.methodv;
      size_t *methodc = &route->gw.state.methodc;

      methodv[(*methodc)++] = AUTHMETHOD_NONE;

#if HAVE_GSSAPI
      if (route->gw.state.proxyprotocol.socks_v5)
         methodv[(*methodc)++] = AUTHMETHOD_GSSAPI;
#endif /* HAVE_GSSAPI */

      if (route->gw.state.proxyprotocol.socks_v5)
         methodv[(*methodc)++] = AUTHMETHOD_UNAME;
   }

   /* Checks the methods set make sense for the given proxy protocols. */
   for (i = 0; i < route->gw.state.methodc; ++i)
      switch (route->gw.state.methodv[i]) {
         case AUTHMETHOD_NONE:
            break;

         case AUTHMETHOD_GSSAPI:
         case AUTHMETHOD_UNAME:
            if (!route->gw.state.proxyprotocol.socks_v5)
               yyerror("rule specifies method %s, but that is not supported "
                       "by given proxy protocol(s) %s",
                       method2string(route->gw.state.methodv[i]),
                       proxyprotocols2string(&route->gw.state.proxyprotocol,
                                             NULL, 0));
            break;

         case AUTHMETHOD_PAM:
         case AUTHMETHOD_BSDAUTH:
         case AUTHMETHOD_RFC931:
            yyerror("method %s is only valid for server rules",
            method2string(route->gw.state.methodv[i]));
            break; /* NOTREACHED */

         default:
            SERRX(route->gw.state.methodv[i]);
      }

   if (route->gw.state.proxyprotocol.upnp) {
      if (route->gw.addr.atype != SOCKS_ADDR_IFNAME
      &&  route->gw.addr.atype != SOCKS_ADDR_URL)
         yyerror("gateway for upnp proxy has to be an interface or url.  "
                 "A %s is not a valid address type",
                 atype2string(route->gw.addr.atype));

      if (route->gw.addr.port == htons(0)) {
         slog(LOG_DEBUG, "%s: port for upnp gw not set, using default (%d)",
         function, DEFAULT_SSDP_PORT);
         route->gw.addr.port = htons(DEFAULT_SSDP_PORT);
      }
      else if (route->gw.addr.port != htons(DEFAULT_SSDP_PORT))
         yyerror("sorry, the upnp library Dante currently uses does "
                 "not support setting the upnp/ssdp port");
   }
   else
      switch (route->gw.addr.atype) {
         case SOCKS_ADDR_IPV4:
         case SOCKS_ADDR_DOMAIN:
            break;

         default:
            serrx(EXIT_FAILURE, "address type of gateway must be ip address or "
                                "qualified domainname, but is a %s\n",
                                atype2string(route->gw.addr.atype));
      }

   if (route->src.atype == SOCKS_ADDR_IFNAME)
      yyerror("interface names not supported for src address");

   if (route->dst.atype == SOCKS_ADDR_IFNAME)
      if (ifname2sockaddr(route->dst.addr.ifname, 0, &addr, &mask) == NULL)
         yyerror("can find interface named %s with ip configured",
         route->dst.addr.ifname);

   ifb = 1;
   nextroute = NULL;
   dst = route->dst;
   do {
      /*
       * This needs to be a loop to handle the case where route->dst
       * (now saved in dst) expands to multiple ip addresses, which can
       * happen when it is e.g. a ifname with several addresses configured
       * on it.
       */

      if (nextroute == NULL)
         nextroute = route; /* first iteration. */
      else
         *nextroute = *route;/* stays same, but if ifname, ipaddr can change. */

      if (dst.atype == SOCKS_ADDR_IFNAME) {
         sockaddr2ruleaddr(&addr, &nextroute->dst);
         nextroute->dst.addr.ipv4.mask = TOIN(&mask)->sin_addr;
      }

      /*
       * place rule in list.  Last or first?
       */
      if (!last || sockscf.route == NULL) { /* first */
         struct route_t *p;
         size_t i;

         nextroute->next = sockscf.route;
         sockscf.route = nextroute;

         if (nextroute->state.autoadded)
            nextroute->number = 0;
         else
            if (ifb == 1) {
               /*
                * only update following route numbers for first
                * ip-block on interface.
                */
               for (i = 1, p = sockscf.route; p != NULL; p = p->next, ++i)
                  p->number = i;
            }
      }
      else { /* last */
         struct route_t *lastroute;

         lastroute = sockscf.route;
         if (nextroute->state.autoadded)
            nextroute->number = 0;
         else {
            while (lastroute->next != NULL)
               lastroute = lastroute->next;

            if (ifb == 1)
               /*
                * only update route numbers for first
                * ip-block on interface.
                */
               nextroute->number = lastroute->number + 1;
         }

         lastroute->next = nextroute;
         nextroute->next = NULL;
      }

   } while (ifname2sockaddr(dst.addr.ifname, ifb++, &addr, &mask) != NULL
   &&       (nextroute = malloc(sizeof(*nextroute)))              != NULL);

   if (!route->gw.state.proxyprotocol.direct) {
      /*
       * A proxy, so make sure we add a direct route to it also.
       */
      struct sockaddr_in saddr, smask;

      bzero(&smask, sizeof(smask));
      smask.sin_family      = AF_INET;
      smask.sin_port        = htons(0);
      smask.sin_addr.s_addr = htonl(0xffffffff);

      if (route->gw.state.proxyprotocol.upnp
      &&  route->gw.addr.atype == SOCKS_ADDR_IFNAME) {
         /*
          * Add direct route for the SSDP broadcast addr, only reachable
          * by lan, so should always be there.
          */
         static int already_done;

         if (!already_done) {
            struct servent *service;

            bzero(&saddr, sizeof(saddr));
            saddr.sin_family      = AF_INET;
            saddr.sin_addr.s_addr = inet_addr(DEFAULT_SSDP_BROADCAST_ADDR);

            if ((service = getservbyname("ssdp", "udp")) == NULL)
               saddr.sin_port = htons(DEFAULT_SSDP_PORT);
            else
               saddr.sin_port = service->s_port;

            socks_autoadd_directroute(&saddr, &smask);
            already_done = 1;
         }
      }
      else {
         struct sockshost_t shost;

         sockshost2sockaddr(gwaddr2sockshost(&route->gw.addr, &shost),
         (struct sockaddr *)&saddr);

         socks_autoadd_directroute(&saddr, &smask);
      }
   }

   return route;
}

struct route_t *
socks_autoadd_directroute(saddr, netmask)
   const struct sockaddr_in *saddr;
   const struct sockaddr_in *netmask;
{
   struct route_t route;

   memset(&route, 0, sizeof(route));

   route.src.atype                            = SOCKS_ADDR_IPV4;
   route.src.addr.ipv4.ip.s_addr              = htonl(0);
   route.src.addr.ipv4.mask.s_addr            = htonl(0);
   route.src.port.tcp                         = route.src.port.udp = htons(0);
   route.src.operator                         = none;

   route.dst.atype                            = SOCKS_ADDR_IPV4;
   route.dst.addr.ipv4.ip                     = saddr->sin_addr;
   route.dst.addr.ipv4.mask.s_addr            = netmask->sin_addr.s_addr;
   route.dst.port.tcp = route.dst.port.udp    = saddr->sin_port;
   route.dst.operator                         = htons(saddr->sin_port)
                                                == 0 ? none : eq;

   route.gw.addr.atype                        = SOCKS_ADDR_DOMAIN;
   SASSERTX(sizeof(route.gw.addr.addr.domain) >= sizeof("direct"));
   strcpy(route.gw.addr.addr.domain, "direct");
   route.gw.state.command.connect             = 1;
   route.gw.state.command.udpassociate        = 1;
   route.gw.state.proxyprotocol.direct        = 1;

   route.state.autoadded                      = 1;

   return socks_addroute(&route, 0);
}

void
showtimeout(timeout)
   const struct timeout_t *timeout;
{

   slog(LOG_DEBUG, "connect timeout: %lus%s",
        timeout->connect,
        timeout->connect == 0 ? " (use kernel default)": "");

#if !SOCKS_CLIENT
   slog(LOG_DEBUG, "negotiate timeout: %lus%s",
        timeout->negotiate,
        timeout->negotiate == 0 ? " (use kernel default)" : "");

   slog(LOG_DEBUG, "i/o timeout: tcp: %lus, udp: %lus",
                   timeout->tcpio, timeout->udpio);
   slog(LOG_DEBUG, "tcp fin-wait-2 timeout: %lus%s",
        timeout->tcp_fin_wait,
        timeout->tcp_fin_wait == 0 ? " (use kernel default)" : "");
#endif /* !SOCKS_CLIENT */

}


void
socks_showroute(route)
   const struct route_t *route;
{
   char gwstring[MAXGWSTRING];
   char addr[MAXRULEADDRSTRING];

   slog(LOG_DEBUG, "route #%d", route->number);

   slog(LOG_DEBUG, "src: %s",
   ruleaddr2string(&route->src, addr, sizeof(addr)));

   slog(LOG_DEBUG, "dst: %s",
   ruleaddr2string(&route->dst, addr, sizeof(addr)));

   slog(LOG_DEBUG, "gateway: %s",
   gwaddr2string(&route->gw.addr, gwstring, sizeof(gwstring)));

   slog(LOG_DEBUG, "route state: autoadded: %s, failed: %lu, badtime: %ld",
                   route->state.autoadded ? "yes" : "no",
                   (long)route->state.failed,
                   (long)route->state.badtime);

   showstate(&route->gw.state, 0);
}

struct route_t *
socks_getroute(req, src, dst)
   const struct request_t *req;
   const struct sockshost_t *src;
   const struct sockshost_t *dst;
{
   const char *function = "socks_getroute()";
   struct route_t *route;
   int protocol;
   char srcbuf[MAXSOCKSHOSTSTRING], dstbuf[MAXSOCKSHOSTSTRING];

#if SOCKS_CLIENT
   clientinit();
#endif /* SOCKS_CLIENT */

   slog(LOG_DEBUG,
   "%s: searching for %s route for %s, protocol %s, src %s, dst %s, ...",
   function, version2string(req->version),
   command2string(req->command), protocol2string(req->protocol),
   src == NULL ? "<NONE>" : sockshost2string(src, srcbuf, sizeof(srcbuf)),
   dst == NULL ? "<NONE>" : sockshost2string(dst, dstbuf, sizeof(dstbuf)));

   for (route = sockscf.route; route != NULL; route = route->next) {
      socks_showroute(route);

      /* CONSTCOND */
      if (sockscf.routeoptions.maxfail != 0 &&
          route->state.failed >= sockscf.routeoptions.maxfail) {
         if (sockscf.routeoptions.badexpire == 0
         ||  difftime(time(NULL), route->state.badtime)
                      <= sockscf.routeoptions.badexpire) {
            slog(LOG_DEBUG, "%s: route does not match; badtime", function);
            continue;
         }
         else
            route->state.failed = 0; /* reset. */
      }

      switch (req->version) {
         /*
          * First check if this rule can provide requested proxyprotocol
          * version with necessary functionality.
          */

         case PROXY_SOCKS_V4:
            if (!route->gw.state.proxyprotocol.socks_v4) {
               slog(LOG_DEBUG, "%s: route does not match; version", function);
               continue;
            }

            if (!methodisset(AUTHMETHOD_NONE, route->gw.state.methodv,
            route->gw.state.methodc)) {
               slog(LOG_DEBUG, "%s: route does not match; method", function);
               continue;
            }

            switch (req->host.atype) {
               case SOCKS_ADDR_IPV4:
                  break;

               default:
                  slog(LOG_DEBUG, "%s: route does not match; atype", function);
                  continue;  /* not supported by v4. */
            }

            switch (req->command) {
               case SOCKS_BIND:
               case SOCKS_CONNECT:
                  break;

               default:
                  slog(LOG_DEBUG, "%s: route does not match; cmd", function);
                  continue; /* not supported by v4. */
            }

            break;

         case PROXY_SOCKS_V5:
            if (!route->gw.state.proxyprotocol.socks_v5) {
               slog(LOG_DEBUG, "%s: route does not match; version", function);
               continue;
            }

            switch (req->host.atype) {
               case SOCKS_ADDR_IPV4:
               case SOCKS_ADDR_IPV6:
               case SOCKS_ADDR_DOMAIN:
                  break;

               default:
                  SERRX(req->host.atype); /* failure, nothing else exists. */
            }
            break;

         case PROXY_HTTP_10:
         case PROXY_HTTP_11:
            if (!route->gw.state.proxyprotocol.http) {
               slog(LOG_DEBUG, "%s: route does not match; version", function);
               continue;
            }

            if (!methodisset(AUTHMETHOD_NONE, route->gw.state.methodv,
            route->gw.state.methodc)) {
               slog(LOG_DEBUG, "%s: route does not match; method", function);
               continue;
            }

            switch (req->command) {
               case SOCKS_CONNECT:
                  break;

               default:
                  slog(LOG_DEBUG, "%s: route does not match; cmd", function);
                  continue; /* not supported by http. */
            }

            break;

         case PROXY_UPNP:
            if (!route->gw.state.proxyprotocol.upnp) {
               slog(LOG_DEBUG, "%s: route does not match; version", function);
               continue;
            }
            break;

         case PROXY_DIRECT:
            if (!route->gw.state.proxyprotocol.direct) {
               slog(LOG_DEBUG, "%s: route does not match; version", function);
               continue;
            }
            break;

         default:
            SERRX(req->version);
      }

      switch (req->command) {
         case SOCKS_BIND:
            if (!route->gw.state.command.bind) {
               slog(LOG_DEBUG, "%s: route does not match; cmd", function);
               continue;
            }
            break;

         case SOCKS_CONNECT:
            if (!route->gw.state.command.connect) {
               slog(LOG_DEBUG, "%s: route does not match; cmd", function);
               continue;
            }
            break;

         case SOCKS_UDPASSOCIATE:
            if (!route->gw.state.command.udpassociate) {
               slog(LOG_DEBUG, "%s: route does not match; cmd", function);
               continue;
            }
            break;

         default:
            SERRX(req->command);
      }

      /* server supports protocol? */
      switch (req->command) {
         case SOCKS_BIND:
         case SOCKS_CONNECT:
            if (!route->gw.state.protocol.tcp) {
               slog(LOG_DEBUG, "%s: route does not match; protocol", function);
               continue;
            }

            protocol = SOCKS_TCP;
            break;

         case SOCKS_UDPASSOCIATE:
            if (!route->gw.state.protocol.udp) {
               slog(LOG_DEBUG, "%s: route does not match; protocol", function);
               continue;
            }

            protocol = SOCKS_UDP;
            break;

         default:
            SERRX(req->command);
      }

      if (req->auth != NULL) /* find server that supports method in use. */
         switch (req->auth->method) {
            case AUTHMETHOD_NOTSET:
               break;

            default:
               if (!methodisset(req->auth->method, route->gw.state.methodv,
               route->gw.state.methodc)) {
                  slog(LOG_DEBUG, "%s: route does not match; method", function);
                  continue; /* does not support the method in use. */
               }
         }

      if (src != NULL) {
         slog(LOG_DEBUG, "%s: checking for src match ...", function);
         if (!addrmatch(&route->src, src, protocol, 0)) {
            slog(LOG_DEBUG, "%s: route does not match; src addr", function);
            continue;
         }
      }

      if (dst != NULL) {
         slog(LOG_DEBUG, "%s: checking for dst match ...", function);
         if (!addrmatch(&route->dst, dst, protocol, 0)) {
            slog(LOG_DEBUG, "%s: route does not match; dst addr", function);
            continue;
         }
      }

      break;   /* all matched */
   }

   if (route == NULL)
      slog(LOG_DEBUG, "%s: no %s route found",
      function, version2string(req->version));
   else {
      slog(LOG_DEBUG, "%s: %s route found, route #%d",
      function, version2string(req->version), route->number);

      if (!route->gw.state.proxyprotocol.direct
      &&  dst != NULL) { /* simple attempt at check for routing loop. */
         struct sockshost_t gwhost;

         gwaddr2sockshost(&route->gw.addr, &gwhost);
         if (sockshostareeq(&gwhost, dst))
            serrx(1, "%s: route to gw %s is self.  Route loop in config\n",
            function, sockshost2string(&gwhost, NULL, 0));
      }
   }

   return route;
}

struct route_t *
socks_connectroute(s, packet, src, dst)
   int s;
   struct socks_t *packet;
   const struct sockshost_t *src;
   const struct sockshost_t *dst;
{
   const char *function = "socks_connectroute()";
   struct route_t *route;
   int sdup, current_s, errno_s;

   /*
    * This is a little tricky since we attempt to support trying
    * more than one socks server.  If the first one fails, we try
    * the next, etc.  Of course, if connect() on one socket fails,
    * that socket can no longer be used, so we need to be able to
    * copy/dup the original socket as much as possible.  Later,
    * if it turned out a connection failed and we had to use a
    * different socket than the original 's', we try to dup the
    * differently numbered socket to 's' and hope the best.
    *
    * sdup:         copy of the original socket.  Need to create this
    *               before the first connect attempt since the connect attempt
    *               could prevent us from doing it later, depending on failure
    *               reason.
    *
    * current_s:    socket to use for next connection attempt.  For the
    *               first attempt this is the same as 's'.
    */

   slog(LOG_DEBUG, "%s: socket %d", function, s);

   current_s   = s;
   sdup        = -1;

   while ((route = socks_getroute(&packet->req, src, dst)) != NULL) {
      char gwstring[MAXGWSTRING], dststring[MAXSOCKSHOSTSTRING], emsg[256];
      struct sockshost_t host;

      slog(LOG_DEBUG, "%s: found %s route (route #%d) to %s via %s",
                      function,
                      proxyprotocols2string(&route->gw.state.proxyprotocol,
                                            NULL, 0),
                      route->number,
                      dst == NULL ?
                      "<UNKNOWN>"
                      : sockshost2string(dst, dststring, sizeof(dststring)),
                      gwaddr2string(&route->gw.addr, gwstring,
                                    sizeof(gwstring)));

      if (route->gw.state.proxyprotocol.direct)
         return route; /* nothing more to do. */

#if HAVE_LIBMINIUPNP
      if (route->gw.state.proxyprotocol.upnp) {
         if (socks_initupnp(&route->gw.addr, &route->gw.state.data) == 0)
            /*
             * nothing more to do for now.  Once we get the actual request
             * (connect(2), bind(2), etc.) we will need to setup the rest.
             */
            break;
         else {
            socks_blacklist(route);
            continue;
         }
      }
#endif /* HAVE_LIBMINIUPNP */

      /* inside loop since if no route, no need for it. */
      if (sdup == -1)
         sdup = socketoptdup(s);

      if (current_s == -1)
         if ((current_s = socketoptdup(sdup == -1 ? s : sdup)) == -1)
            return NULL;

      if (socks_connecthost(current_s,
                            gwaddr2sockshost(&route->gw.addr, &host),
                            NULL,
                            sockscf.timeout.connect ?
                            /* LINTED cast from unsigned to signed. */
                            (long)sockscf.timeout.connect : -1,
                            emsg,
                            sizeof(emsg)) == 0)
         break;
      else {
         /*
          * Check whether the error indicates bad socks server or
          * something else.
          */
         if (errno == EINPROGRESS) {
            SASSERTX(current_s == s);
            break;
         }
         else if (errno == EADDRINUSE) {
            /* see Rbind() for explanation. */
            SASSERTX(current_s == s);
            route = NULL;
            break;
         }
         else {
            slog(LOG_DEBUG, "%s: socks_connecthost(%s) failed: %s",
                 function,
                 gwaddr2string(&route->gw.addr, gwstring, sizeof(gwstring)),
                 emsg);

            if (errno == EINVAL) {
               struct sockaddr_in laddr;
               socklen_t len = sizeof(laddr);

               if (getsockname(s, (struct sockaddr *)&laddr, &len) == 0
               &&  laddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
                  slog(LOG_DEBUG, "%s: failed to connect route, but that "
                                  "appears to be due to the socket having "
                                  "been bound to the loopback interface, so "
                                  "presumably this socket should not proxied",
                                  function);

                  SASSERTX(current_s == s);
                  route = NULL;
                  break;
               }
            }

            if (errno != EINTR)
               socks_blacklist(route);

            /*
             * can't have client select() or wait for this, as no
             * socks negotiation has been done.
             */
            close(current_s);
            current_s = -1;
         }
      }
   }

   errno_s = errno;

   if (sdup != -1)
      close(sdup);

   if (current_s != s && current_s != -1)   {
      /* created a new socket for connect, need to make it same descriptor #. */
      if (dup2(current_s, s) == -1) {
         close(current_s);
         return NULL;
      }
      close(current_s);
   }

   if (route != NULL)
      packet->gw = route->gw;

   errno = errno_s;
   return route;
}

void
socks_clearblacklist(route)
   struct route_t *route;
{

   if (route != NULL)
      route->state.failed = route->state.badtime = 0;
}

void
socks_blacklist(route)
   struct route_t *route;
{
   const char *function = "socks_blacklist()";

   if (route == NULL || sockscf.routeoptions.maxfail == 0)
      return;

   slog(LOG_DEBUG, "%s: blacklisting %sroute #%d, blacklisted %lu times before",
   function, route->state.autoadded ? "autoadded " : "",
   route->number, (long unsigned)route->state.failed);

#if HAVE_LIBMINIUPNP
   bzero(&route->gw.state.data, sizeof(route->gw.state.data));
#endif /* HAVE_LIBMINIUPNP */

   ++route->state.failed;
   time(&route->state.badtime);
}

struct request_t *
socks_requestpolish(req, src, dst)
   struct request_t *req;
   const struct sockshost_t *src;
   const struct sockshost_t *dst;
{
   const char *function = "socks_requestpolish()";
   const unsigned char originalversion = req->version;

#if !SOCKS_CLIENT
   switch (req->command) {
      case SOCKS_CONNECT: /* only one supported for serverchaining. */
         break;

      default:
         req->version = PROXY_DIRECT;
         return req;
   }
#endif /* !SOCKS_CLIENT */

   if (socks_getroute(req, src, dst) != NULL)
      return req;

   /*
    * no route found.  Can we "polish" the request and then find a route?
    * Try all proxy protocols we support.
    */

   /*
    * To simplify making sure we are trying all versions, for now,
    * make an assumption about what we start with.
    */
   SASSERTX(req->version == PROXY_DIRECT);

   req->version = PROXY_SOCKS_V4;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_SOCKS_V5;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_HTTP_10;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_HTTP_11;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_UPNP;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = originalversion;

   if (sockscf.option.directfallback) {
      slog(LOG_DEBUG, "%s: no route found, assuming direct fallback is ok",
      function);

      req->version = PROXY_DIRECT;
      return req;
   }

   slog(LOG_DEBUG, "%s: no route found to handle request and "
                   "direct route fallback disabled.  Nothing we can do.",
                   function);

   errno = ENETUNREACH;
   return NULL;
}

void
showstate(state, isclientrule)
   const struct serverstate_t *state;
   const int isclientrule;
{
   char buf[1024];
   size_t bufused;

   if (!isclientrule) {
      slog(LOG_DEBUG, "command(s): %s",
      commands2string(&state->command, buf, sizeof(buf)));

      bufused = snprintf(buf, sizeof(buf), "extension(s): ");
      if (state->extension.bind)
         snprintf(&buf[bufused], sizeof(buf) - bufused, "bind");
      slog(LOG_DEBUG, "%s", buf);
   }

   bufused = snprintf(buf, sizeof(buf), "protocol(s): ");
   protocols2string(&state->protocol,
   &buf[bufused], sizeof(buf) - bufused);
   slog(LOG_DEBUG, "%s", buf);

   showmethod(state->methodc, state->methodv);

   if (!isclientrule)
      slog(LOG_DEBUG, "proxyprotocol(s): %s",
      proxyprotocols2string(&state->proxyprotocol, buf, sizeof(buf)));

#if HAVE_GSSAPI
   if (methodisset(AUTHMETHOD_GSSAPI, state->methodv, state->methodc)) {
      if (*state->gssapiservicename != NUL)
         slog(LOG_DEBUG, "gssapi.servicename: %s", state->gssapiservicename);

      if (*state->gssapikeytab != NUL)
         slog(LOG_DEBUG, "gssapi.keytab: %s", state->gssapikeytab);

      if (state->gssapiencryption.clear
      ||  state->gssapiencryption.integrity
      ||  state->gssapiencryption.confidentiality
      || state->gssapiencryption.permessage)
         slog(LOG_DEBUG, "gssapi.encryption:%s%s%s%s",
         state->gssapiencryption.clear?           " clear"           :"",
         state->gssapiencryption.integrity?       " integrity"       :"",
         state->gssapiencryption.confidentiality? " confidentiality" :"",
         state->gssapiencryption.permessage?      " permessage"      :"");

      if (state->gssapiencryption.nec)
         slog(LOG_DEBUG, "clientcompatibility: necgssapi enabled");
   }
#endif /* HAVE_GSSAPI */
}

void
showmethod(methodc, methodv)
   size_t methodc;
   const int *methodv;
{
   char buf[1024];

   slog(LOG_DEBUG, "method(s): %s",
   methods2string(methodc, methodv, buf, sizeof(buf)));
}

void
optioninit(void)
{
   /*
    * initialize misc. options to sensible default.  Some may be
    * overridden later by user in the sockd.conf.
    */

   sockscf.resolveprotocol       = RESOLVEPROTOCOL_UDP;

#if SOCKS_DIRECTROUTE_FALLBACK
   if (socks_getenv("SOCKS_DIRECTROUTE_FALLBACK", isfalse) != NULL)
      sockscf.option.directfallback = 0;
   else
      sockscf.option.directfallback = 1;
#else /* !SOCKS_DIRECTROUTE_FALLBACK */
   if (socks_getenv("SOCKS_DIRECTROUTE_FALLBACK", istrue) != NULL)
      sockscf.option.directfallback = 1;
   else
      sockscf.option.directfallback = 0;
#endif /* SOCKS_DIRECTROUTE_FALLBACK */

   sockscf.routeoptions.maxfail   = 1;
   sockscf.routeoptions.badexpire = 60 * 5;

#if !SOCKS_CLIENT
   sockscf.option.keepalive      = 1;

   sockscf.udpconnectdst         = 1;

   sockscf.timeout.connect       = SOCKD_CONNECTTIMEOUT;
   sockscf.timeout.negotiate     = SOCKD_NEGOTIATETIMEOUT;
   sockscf.timeout.tcpio         = SOCKD_IOTIMEOUT_TCP;
   sockscf.timeout.udpio         = SOCKD_IOTIMEOUT_UDP;
   sockscf.timeout.tcp_fin_wait  = SOCKD_FIN_WAIT_2_TIMEOUT;

   sockscf.socket.tcp.rcvbuf     = SOCKS_SOCKET_RCVBUF_TCP;
   sockscf.socket.tcp.sndbuf     = SOCKS_SOCKET_SNDBUF_TCP;
   sockscf.socket.udp.rcvbuf     = SOCKS_SOCKET_RCVBUF_UDP;
   sockscf.socket.udp.sndbuf     = SOCKS_SOCKET_SNDBUF_UDP;

#if BAREFOOTD
   sockscf.socket.clientside_udp.rcvbuf = SOCKS_SOCKET_RCVBUF_UDP_CLIENTSIDE;
   sockscf.socket.clientside_udp.sndbuf = SOCKS_SOCKET_SNDBUF_UDP_CLIENTSIDE;
#endif /* BAREFOOTD */

   sockscf.external.rotation     = ROTATION_NONE;

#if HAVE_PAM
   sockscf.state.pamservicename     = DEFAULT_PAMSERVICENAME;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
   sockscf.state.gssapiservicename  = DEFAULT_GSSAPISERVICENAME;
   sockscf.state.gssapikeytab       = DEFAULT_GSSAPIKEYTAB;
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
   sockscf.state.ldapkeytab        = DEFAULT_GSSAPIKEYTAB;
   sockscf.state.ldapfilter        = DEFAULT_LDAP_FILTER;
   sockscf.state.ldapfilter_AD     = DEFAULT_LDAP_FILTER_AD;
   sockscf.state.ldapattribute     = DEFAULT_LDAP_ATTRIBUTE;
   sockscf.state.ldapattribute_AD  = DEFAULT_LDAP_ATTRIBUTE_AD;
   sockscf.state.ldapcertfile      = DEFAULT_LDAP_CACERTFILE;
   sockscf.state.ldapcertpath      = DEFAULT_LDAP_CERTDBPATH;
#endif /* HAVE_LDAP */

#if !SOCKS_SERVER
   /*
    * Enable all methods that are not socks-dependent, so that regardless
    * of what method user sets in clientmethod (the only one supported in
    * barefoot), the socks-rules will also allow it.
    */
   sockscf.methodc = 0;
   sockscf.methodv[sockscf.methodc++] = AUTHMETHOD_NONE;
   sockscf.methodv[sockscf.methodc++] = AUTHMETHOD_PAM;
   sockscf.methodv[sockscf.methodc++] = AUTHMETHOD_RFC931;

   /* also enable all methods in client-rules. */
   sockscf.clientmethodc = 0;
   sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;
   sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_PAM;
   sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_RFC931;
#endif /* !SOCKS_SERVER */

#if BAREFOOTD
   /* initially there is no udp traffic to bounce. */
   sockscf.state.alludpbounced = 1;
#endif /* BAREFOOTD */

   sockscf.child.maxidle.negotiate  = SOCKD_FREESLOTS_NEGOTIATE * 2;
   sockscf.child.maxidle.request    = SOCKD_FREESLOTS_REQUEST * 2;
   sockscf.child.maxidle.io         = SOCKD_FREESLOTS_IO * 2;

#endif /* !SOCKS_CLIENT */
}

void
showconfig(sockscf)
   const struct config_t *sockscf;
{
   char buf[1024];

#if !SOCKS_CLIENT
   char address[MAXRULEADDRSTRING];
   size_t i, bufused;

   slog(LOG_DEBUG, "cmdline options:\n%s",
   options2string(&sockscf->option, "", buf, sizeof(buf)));

   slog(LOG_DEBUG, "internal addresses (%lu):",
   (unsigned long)sockscf->internalc);
   for (i = 0; i < sockscf->internalc; ++i)
      slog(LOG_DEBUG, "\t%s %s",
      protocol2string(sockscf->internalv[i].protocol),
      sockaddr2string(&sockscf->internalv[i].addr, address,
      sizeof(address)));

   slog(LOG_DEBUG, "external addresses (%lu):",
   (unsigned long)sockscf->external.addrc);
   for (i = 0; i < sockscf->external.addrc; ++i) {
      ruleaddr2string(&sockscf->external.addrv[i], address,
      sizeof(address));

      slog(LOG_DEBUG, "\t%s", address);
   }
   slog(LOG_DEBUG, "external address rotation: %s",
   rotation2string(sockscf->external.rotation));

   slog(LOG_DEBUG, "compatibility options: %s",
   compats2string(&sockscf->compat, buf, sizeof(buf)));

   slog(LOG_DEBUG, "extensions enabled: %s",
   extensions2string(&sockscf->extension, buf, sizeof(buf)));

   slog(LOG_DEBUG, "connect udp sockets to destination: %s",
   sockscf->udpconnectdst ? "yes" : "no");
#endif /* !SOCKS_CLIENT */

   slog(LOG_DEBUG, "logoutput goes to: %s",
   logtypes2string(&sockscf->log, buf, sizeof(buf)));

   slog(LOG_DEBUG, "resolveprotocol: %s",
   resolveprotocol2string(sockscf->resolveprotocol));

   showtimeout(&sockscf->timeout);

#if !SOCKS_CLIENT
   slog(LOG_DEBUG, "global route options: %s",
   routeoptions2string(&sockscf->routeoptions, buf, sizeof(buf)));

   slog(LOG_DEBUG, "direct route fallback: %s",
   sockscf->option.directfallback ? "enabled" : "disabled");

   srchosts2string(&sockscf->srchost, "", buf, sizeof(buf));
   if (*buf != NUL)
      slog(LOG_DEBUG, "srchost:\n%s", buf);

   slog(LOG_DEBUG, "socket options:\n"
                   "\ttcp.rcvbuf: %lu, tcp.sndbuf: %lu\n"
                   "\tudp.rcvbuf: %lu, udp.sndbuf: %lu\n"
#if BAREFOOTD
                   "\tclientsideudp.rcvbuf: %lu, clientsideudp.sndbuf: %lu\n"
#endif /* BAREFOOTD */
                   ,
                   (unsigned long)sockscf->socket.tcp.rcvbuf,
                   (unsigned long)sockscf->socket.tcp.sndbuf,
                   (unsigned long)sockscf->socket.udp.rcvbuf,
                   (unsigned long)sockscf->socket.udp.sndbuf
#if BAREFOOTD
                   ,
                   (unsigned long)sockscf->socket.clientside_udp.rcvbuf,
                   (unsigned long)sockscf->socket.clientside_udp.sndbuf
#endif /* BAREFOOTD */
                  );


#if COVENANT
   slog(LOG_DEBUG, "proxy realm: %s", sockscf->realmname);
#endif /* COVENANT */

#if HAVE_LIBWRAP
   if (sockscf->option.hosts_access)
      slog(LOG_DEBUG, "libwrap.hosts_access: yes");
   else
      slog(LOG_DEBUG, "libwrap.hosts_access: no");
#endif /* HAVE_LIBWRAP */

   slog(LOG_DEBUG, "euid: %d", sockscf->state.euid);

#if !HAVE_PRIVILEGES
   slog(LOG_DEBUG, "userid:\n%s",
   userids2string(&sockscf->uid, "", buf, sizeof(buf)));
#endif /* !HAVE_PRIVILEGES */

   slog(LOG_DEBUG, "child.maxidle.negotiate: %lu",
       (unsigned long)sockscf->child.maxidle.negotiate);
   slog(LOG_DEBUG, "child.maxidle.request: %lu",
       (unsigned long)sockscf->child.maxidle.request);
   slog(LOG_DEBUG, "child.maxidle.io: %lu",
       (unsigned long)sockscf->child.maxidle.io);

   bufused = snprintf(buf, sizeof(buf), "method(s): ");
   for (i = 0; (size_t)i < sockscf->methodc; ++i)
      bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s%s",
      i > 0 ? ", " : "", method2string(sockscf->methodv[i]));

   slog(LOG_DEBUG, "%s", buf);

   bufused = snprintf(buf, sizeof(buf), "clientmethod(s): ");
   for (i = 0; (size_t)i < sockscf->clientmethodc; ++i)
      bufused += snprintf(&buf[bufused], sizeof(buf) - bufused, "%s%s",
      i > 0 ? ", " : "", method2string(sockscf->clientmethodv[i]));

   slog(LOG_DEBUG, "%s", buf);
#endif /* !SOCKS_CLIENT */


   if (sockscf->option.debug) {
      struct route_t *route;
      int c;
#if !SOCKS_CLIENT
      struct rule_t *rule;

      for (c = 0, rule = sockscf->crule; rule != NULL; rule = rule->next)
         ++c;
      slog(LOG_DEBUG, "client-rules (%d): ", c);
      for (rule = sockscf->crule; rule != NULL; rule = rule->next)
         showrule(rule, 1);

      for (c = 0, rule = sockscf->srule; rule != NULL; rule = rule->next)
         ++c;
      slog(LOG_DEBUG, "socks-rules (%d): ", c);
      for (rule = sockscf->srule; rule != NULL; rule = rule->next)
         showrule(rule, 0);
#endif /* !SOCKS_CLIENT */

      for (c = 0, route = sockscf->route; route != NULL; route = route->next)
         ++c;
      slog(LOG_DEBUG, "routes (%d): ", c);
      for (route = sockscf->route; route != NULL; route = route->next)
         socks_showroute(route);
   }
}
