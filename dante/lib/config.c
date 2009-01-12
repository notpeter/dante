/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2009
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
"$Id: config.c,v 1.204 2009/01/12 14:08:40 michaels Exp $";

void
genericinit(void)
{
   const char *function = "genericinit()";
#if SOCKS_SERVER
   sigset_t set, oset;
#endif /* SOCKS_SERVER */

   if (!sockscf.state.init) {
#if !HAVE_SETPROCTITLE
      /* create a backup to avoid setproctitle replacement overwriting it. */
      if ((__progname = strdup(__progname)) == NULL)
         serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
#endif /* !HAVE_SETPROCTITLE */
   }

   
#if SOCKS_SERVER
   sigemptyset(&set);
   sigaddset(&set, SIGHUP);
   sigaddset(&set, SIGTERM);
   if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
      swarn("%s: sigprocmask(SIG_BLOCK)", function);
#endif /* SOCKS_SERVER */

   if (readconfig(sockscf.option.configfile) != 0) {
#if SOCKS_SERVER
      exit(EXIT_FAILURE);
#else /* SOCKS_CLIENT */
      sockscf.state.init = 1;
      return;
#endif /* SOCKS_SERVER */
   }

#if SOCKS_SERVER
   if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK)", function);
#endif /* SOCKS_SERVER */

   newprocinit();

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

   sockscf.state.init = 1;
}

struct route_t *
socks_addroute(newroute, last)
   const struct route_t *newroute;
   const int last;
{
   static const struct serverstate_t state;
   const char *function = "socks_addroute()";
   struct route_t *route, *nextroute;
   struct sockaddr addr, mask;
   struct ruleaddr_t dst;
   int ifb;

   if ((route = malloc(sizeof(*route))) == NULL)
      serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
   *route = *newroute;

   /* if no proxyprotocol set, set all socks protocols. */
   if (memcmp(&state.proxyprotocol, &route->gw.state.proxyprotocol,
   sizeof(state.proxyprotocol)) == 0) {
      memset(&route->gw.state.proxyprotocol, 0,
      sizeof(route->gw.state.proxyprotocol));

      route->gw.state.proxyprotocol.socks_v4 = 1;
      route->gw.state.proxyprotocol.socks_v5 = 1;
   }
   else { /* proxyprotocol set, do they make sense? */
      struct proxyprotocol_t proxy;
      
      if (route->gw.state.proxyprotocol.direct) {
         memset(&proxy, 0, sizeof(proxy));
         proxy.direct = 1;
         
         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1,
            "%s: can't combine proxyprotocol direct with other protocols",
            function);   
      }
      else if (route->gw.state.proxyprotocol.socks_v4 
      ||  route->gw.state.proxyprotocol.socks_v5) {
         if (route->gw.state.proxyprotocol.msproxy_v2
         ||  route->gw.state.proxyprotocol.http_v1_0
         ||  route->gw.state.proxyprotocol.upnp)
         serrx(1, "%s: can't combine proxyprotocol socks with other protocols",
         function);   
      }
      else if (route->gw.state.proxyprotocol.msproxy_v2) {
         memset(&proxy, 0, sizeof(proxy));
         proxy.msproxy_v2 = 1;
         
         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1,
            "%s: can't combine proxyprotocol msproxy with other protocols",
            function);   
      }
      else if (route->gw.state.proxyprotocol.http_v1_0) {
         memset(&proxy, 0, sizeof(proxy));
         proxy.http_v1_0 = 1;
         
         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1,
            "%s: can't combine proxyprotocol http_v1_0 with other protocols",
            function);   
      }
      else if (route->gw.state.proxyprotocol.upnp) {
#if !HAVE_LIBMINIUPNP
         serrx(1, "%s: not configured for using upnp", function);
#endif /* !HAVE_LIBMINIUPNP */
         memset(&proxy, 0, sizeof(proxy));
         proxy.upnp = 1;
         
         if (memcmp(&proxy, &route->gw.state.proxyprotocol, sizeof(proxy)) != 0)
            serrx(1,"%s: can't combine proxyprotocol upnp with other protocols",
            function);   
      }
   }

   /*
    * Now go through the proxyprotocol(s) supported by this route,
    * and enable the appropriate protcols and commands, if the
    * user has not already done so.
    */

   if (memcmp(&state.command, &route->gw.state.command, sizeof(state.command))
   == 0) {
      if (route->gw.state.proxyprotocol.direct) {
#if !SOCKS_SERVER
         route->gw.state.command.udpassociate   = 1;
         route->gw.state.command.udpreply       = 1;
#endif /* !SOCKS_SERVER */
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

      if (route->gw.state.proxyprotocol.socks_v5) {
#if !SOCKS_SERVER
         route->gw.state.command.udpassociate  = 1;
         route->gw.state.command.udpreply      = 1;
#endif /* !SOCKS_SERVER */
         route->gw.state.command.bind          = 1;
         route->gw.state.command.bindreply     = 1;
         route->gw.state.command.connect       = 1;
      }

      if (route->gw.state.proxyprotocol.socks_v4) {
         route->gw.state.command.bind       = 1;
         route->gw.state.command.bindreply  = 1;
         route->gw.state.command.connect    = 1;
      }

      if (route->gw.state.proxyprotocol.http_v1_0) {
         route->gw.state.command.connect = 1;
      }

      if (route->gw.state.proxyprotocol.upnp) {
#if !SOCKS_SERVER
         route->gw.state.command.udpassociate = 1;
         route->gw.state.command.udpreply     = 1;
#endif /* !SOCKS_SERVER */
         route->gw.state.command.bind         = 1;
         route->gw.state.command.bindreply    = 1;
         route->gw.state.command.connect      = 1;
      }

      if (route->gw.state.proxyprotocol.msproxy_v2) {
         route->gw.state.command.bind      = 1;
         route->gw.state.command.bindreply = 1;
         route->gw.state.command.connect   = 1;
      }
   }
#if SOCKS_SERVER
   else {
      if (!route->gw.state.proxyprotocol.direct) {
         if (route->gw.state.command.bind
         ||  route->gw.state.command.bindreply
         ||  route->gw.state.command.udpassociate
         ||  route->gw.state.command.udpreply
         ||  route->gw.state.protocol.udp)
            swarnx("%s: serverchaining only supported for connect command",
            function);
      }
   }
#endif /* SOCKS_SERVER */


   if (memcmp(&state.protocol, &route->gw.state.protocol,
   sizeof(state.protocol)) == 0) {
      if (route->gw.state.proxyprotocol.direct) {
#if !SOCKS_SERVER
         route->gw.state.protocol.udp = 1;
#endif /* !SOCKS_SERVER */
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.socks_v5) {
#if !SOCKS_SERVER
         route->gw.state.protocol.udp = 1;
#endif /* !SOCKS_SERVER */
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.socks_v4) {
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.http_v1_0) {
         route->gw.state.protocol.tcp = 1;
      }

      if (route->gw.state.proxyprotocol.upnp) {
#if !SOCKS_SERVER
         route->gw.state.protocol.udp = 1;
#endif /* !SOCKS_SERVER */
         route->gw.state.protocol.tcp = 1;
      }


      if (route->gw.state.proxyprotocol.msproxy_v2) {
         route->gw.state.protocol.tcp = 1;
      }
   }

   /* if no method set, set all we support. */
   if (route->gw.state.methodc == 0) {
      int *methodv    =  route->gw.state.methodv;
      size_t *methodc = &route->gw.state.methodc;

      methodv[(*methodc)++] = AUTHMETHOD_NONE;
      methodv[(*methodc)++] = AUTHMETHOD_UNAME;
   }

   if (route->gw.state.proxyprotocol.upnp) {
      if (route->gw.addr.atype != SOCKS_ADDR_IFNAME
      &&  route->gw.addr.atype != SOCKS_ADDR_URL)
         yyerror("gateway for upnp proxy has to be an interface or url");

      if (route->gw.addr.port == htons(0)) {
         slog(LOG_DEBUG, "%s: port for upnp gw not set, using default (%d)",
         function, DEFAULT_SSDP_PORT);
         route->gw.addr.port = htons(DEFAULT_SSDP_PORT);
      }
      else if (route->gw.addr.port != htons(DEFAULT_SSDP_PORT))
         yyerror("sorry, the upnplibrary Dante currently uses does "
                 "not support setting the upnp/ssdp port");
   }         
   
   if (route->src.atype == SOCKS_ADDR_IFNAME)
      yyerror("interfacenames not supported for src address");

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
       * (now saved in dst) expands to multiple ipaddresses, which can
       * happen when it is e.g. a ifname with several addresses configured 
       * on it.
       */
      char srcstr[MAXRULEADDRSTRING], dststr[MAXRULEADDRSTRING],
           gwstr[MAXRULEADDRSTRING], buf[1024];

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
                * only update following routenumbers for first
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
                * only update routenumbers for first
                * ip-block on interface.
                */
               nextroute->number = lastroute->number + 1;
         }

         lastroute->next = nextroute;
         nextroute->next = NULL;
      }

      slog(LOG_DEBUG,
      "%s: adding route #%d for src %s, dst %s, gw %s, proxyprotocol: %s", 
      function,
      nextroute->number,
      ruleaddr2string(&nextroute->src, srcstr, sizeof(srcstr)),
      ruleaddr2string(&nextroute->dst, dststr, sizeof(dststr)),
      gwaddr2string(&nextroute->gw.addr, gwstr, sizeof(gwstr)),
      proxyprotocols2string(&nextroute->gw.state.proxyprotocol, buf,
      sizeof(buf)));

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
   route.dst.operator                         = eq;
   
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
socks_showroute(route)
   const struct route_t *route;
{
   char gwstring[MAXGWSTRING];
   char addr[MAXRULEADDRSTRING];

   slog(LOG_INFO, "route #%d", route->number);

   slog(LOG_INFO, "src: %s",
   ruleaddr2string(&route->src, addr, sizeof(addr)));

   slog(LOG_INFO, "dst: %s",
   ruleaddr2string(&route->dst, addr, sizeof(addr)));

   slog(LOG_INFO, "gateway: %s",
   gwaddr2string(&route->gw.addr, gwstring, sizeof(gwstring)));

   showstate(&route->gw.state);
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
      /* CONSTCOND */
      if (MAX_ROUTE_FAILS != 0 && route->state.failed >= MAX_ROUTE_FAILS) {
         if (BADROUTE_EXPIRE == 0 
         ||  difftime(time(NULL), route->state.badtime) <= BADROUTE_EXPIRE)
            continue;
         else
            route->state.failed = 0; /* reset. */
      }

      switch (req->version) {
         case PROXY_SOCKS_V4:
            if (!route->gw.state.proxyprotocol.socks_v4)
               continue;

            switch (req->host.atype) {
               case SOCKS_ADDR_IPV4:
                  break;

               case SOCKS_ADDR_IPV6:
               case SOCKS_ADDR_DOMAIN:
                  continue; /* not failure, just checking. */

               default:
                  SERRX(req->host.atype); /* failure, nothing else exists. */
            }
            break;

         case PROXY_SOCKS_V5:
            if (!route->gw.state.proxyprotocol.socks_v5)
               continue;

            switch (req->host.atype) {
               case SOCKS_ADDR_IPV4:
               case SOCKS_ADDR_IPV6:
               case SOCKS_ADDR_DOMAIN:
                  break;

               default:
                  SERRX(req->host.atype); /* failure, nothing else exists. */
            }
            break;

         case PROXY_MSPROXY_V2:
            if (!route->gw.state.proxyprotocol.msproxy_v2)
               continue;
            break;

         case PROXY_HTTP_V1_0:
            if (!route->gw.state.proxyprotocol.http_v1_0)
               continue;
            break;

         case PROXY_UPNP:
            if (!route->gw.state.proxyprotocol.upnp)
               continue;
            break;

         case PROXY_DIRECT:
            if (!route->gw.state.proxyprotocol.direct)
               continue;
            break;

         default:
            SERRX(req->version);
      }

      switch (req->command) {
         case SOCKS_BIND:
            if (!route->gw.state.command.bind)
               continue;
            break;

         case SOCKS_CONNECT:
            if (!route->gw.state.command.connect)
               continue;
            break;

         case SOCKS_UDPASSOCIATE:
            if (!route->gw.state.command.udpassociate)
               continue;
            break;

         default:
            SERRX(req->command);
      }

      /* server supports protocol? */
      switch (req->command) {
         case SOCKS_BIND:
         case SOCKS_CONNECT:
            if (!route->gw.state.protocol.tcp)
               continue;
            protocol = SOCKS_TCP;
            break;

         case SOCKS_UDPASSOCIATE:
            if (!route->gw.state.protocol.udp)
               continue;
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
               route->gw.state.methodc))
                  continue; /* does not support the method in use. */
         }

      if (src != NULL)
         if (!addressmatch(&route->src, src, protocol, 0))
            continue;

      if (dst != NULL)
         if (!addressmatch(&route->dst, dst, protocol, 0))
            continue;

      break;   /* all matched */
   }

   if (route == NULL)
      slog(LOG_DEBUG, "%s: no route found", function);
   else {
      slog(LOG_DEBUG, "%s: v%d route found, route #%d",
      function, req->version, route->number);

      if (!route->gw.state.proxyprotocol.direct
      &&  dst != NULL) { /* simple check for routing loop. */
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
   int sdup, current_s, errno_s;
   struct route_t *route;

   /*
    * This is a little tricky since we attempt to support trying
    * more than one socksserver.  If the first one fails, we try
    * the next, etc.  Of course, if connect() on one socket fails,
    * that socket can no longer be used, so we need to be able to
    * copy/dup the original socket as much as possible.  Later,
    * if it turned out a connection failed and we had to use a
    * different socket than the orignal 's', we try to dup the
    * differently numbered socket to 's' and hope the best.
    *
    * sdup:         copy of the original socket.  Need to create this
    *               before the first connectattempt since the connectattempt
    *               could prevent us from doing it later, depending on failure
    *               reason.
    *
    * current_s:   socket to use for next connection attempt.  For the
    *               first attempt this is 's'.
    */

   slog(LOG_DEBUG, "%s: s = %d", function, s);

   current_s   = s;
   sdup        = -1;

   while ((route = socks_getroute(&packet->req, src, dst)) != NULL) {
      char gwstring[MAXGWSTRING], dststring[MAXSOCKSHOSTSTRING];
      struct sockshost_t host;

      if (route->gw.state.proxyprotocol.direct)
         return NULL;

      slog(LOG_DEBUG, "%s: found %s route #%d to %s via %s",
      function, proxyprotocols2string(&route->gw.state.proxyprotocol, NULL, 0),
      route->number, dst == NULL ?
      "<UNKNOWN>" : sockshost2string(dst, dststring, sizeof(dststring)),
      gwaddr2string(&route->gw.addr, gwstring, sizeof(gwstring)));

      if (route->gw.state.proxyprotocol.upnp) {
         if (socks_initupnp(&route->gw.addr, &route->gw.state.data) == 0)
            /*
             * nothing more to do for now.  Once we get the actual request
             * (connect(2), bind(2), etc.) we will need to setup the rest.
             */
            break;
         else { 
            socks_badroute(route);
            continue;
         }
      }

      /* inside loop since if no route, no need for it. */
      if (sdup == -1)
         sdup = socketoptdup(s);

      if (current_s == -1)
         if ((current_s = socketoptdup(sdup == -1 ? s : sdup)) == -1)
            return NULL;

      if (socks_connect(current_s, gwaddr2sockshost(&route->gw.addr, &host))
      == 0)
         break;
      else
         /*
          * Check whether the error indicates bad socksserver or
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
#if SOCKS_CLIENT
            swarn("%s: socks_connect(%s)",
            function, gwaddr2string(&route->gw.addr, gwstring,
            sizeof(gwstring)));
#endif /* SOCKS_CLIENT */

            socks_badroute(route);
            close(current_s);
            current_s = -1;
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

   if (route != NULL) {
#if SOCKS_CLIENT
      static int init;
#endif /* SOCKS_CLIENT */

      packet->gw = route->gw;

#if SOCKS_CLIENT
      /* need to set up misc. crap for msproxy stuff. */
      if (!init && route->gw.state.proxyprotocol.msproxy_v2) {
         msproxy_init();
         init = 1;
      }
#endif /* SOCKS_CLIENT */
   }

   errno = errno_s;
   return route;
}

void
socks_badroute(route)
   struct route_t *route;
{
   const char *function = "socks_badroute()";

   if (route == NULL || MAX_ROUTE_FAILS == 0)
      return;

   slog(LOG_DEBUG, "%s: badrouting %sroute #%d",
   function, route->state.autoadded ? "autoadded " : "", route->number);

   bzero(&route->gw.state, sizeof(route->gw.state));
   ++route->state.failed;
   time(&route->state.badtime);
}


#if SOCKS_CLIENT
struct request_t *
socks_requestpolish(req, src, dst)
   struct request_t *req;
   const struct sockshost_t *src;
   const struct sockshost_t *dst;
{
   const char *function = "socks_requestpolish()";
   const unsigned char originalversion = req->version;

   if (socks_getroute(req, src, dst) != NULL)
      return req;

   /*
    * no route found.  Can we "polish" the request and then find a route?
    * Try all proxyprotocols we support.
    */

   SASSERTX(req->version == PROXY_DIRECT);

   req->version = PROXY_SOCKS_V5;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_SOCKS_V4;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_HTTP_V1_0;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_UPNP;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = PROXY_MSPROXY_V2;
   if (socks_getroute(req, src, dst) != NULL)
      return req;

   req->version = originalversion;

   slog(LOG_DEBUG, "%s: no route found to handle request", function);
   return NULL;
}
#endif /* SOCKS_CLIENT */

void
showstate(state)
   const struct serverstate_t *state;
{
   char buf[1024];
   size_t bufused;

   bufused = snprintfn(buf, sizeof(buf), "command(s): ");
   if (state->command.bind)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
      SOCKS_BINDs);
   if (state->command.bindreply)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
      SOCKS_BINDREPLYs);
   if (state->command.connect)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
      SOCKS_CONNECTs);
   if (state->command.udpassociate)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
      SOCKS_UDPASSOCIATEs);
   if (state->command.udpreply)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s, ",
      SOCKS_UDPREPLYs);
   slog(LOG_INFO, buf);

   bufused = snprintfn(buf, sizeof(buf), "extension(s): ");
   if (state->extension.bind)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "bind");
   slog(LOG_INFO, buf);

   bufused = snprintfn(buf, sizeof(buf), "protocol(s): ");
   protocols2string(&state->protocol,
   &buf[bufused], sizeof(buf) - bufused);
   slog(LOG_INFO, buf);

   showmethod(state->methodc, state->methodv);

   bufused = snprintfn(buf, sizeof(buf), "proxyprotocol(s): ");
   proxyprotocols2string(&state->proxyprotocol,
   &buf[bufused], sizeof(buf) - bufused);
   slog(LOG_INFO, buf);

}

void
showmethod(methodc, methodv)
   size_t methodc;
   const int *methodv;
{
   char buf[1024];

   slog(LOG_INFO, "method(s): %s",
   methods2string(methodc, methodv, buf, sizeof(buf)));
}
