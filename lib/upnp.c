/*
 * Copyright (c) 2008
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

static const char rcsid[] =
"$Id: upnp.c,v 1.30 2008/12/11 17:34:59 michaels Exp $";

#include "common.h"

#if HAVE_LIBMINIUPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#else
#include "upnp.h"
#endif /* HAVE_LIBMINIUPNP */


#if HAVE_LIBMINIUPNP
#if SOCKS_CLIENT
/*
 * if caller already has a signal handler for the signal, save it
 * so we can call it from our own handler if something other than 
 * our own child dies, for compatibility with caller.
 */
static struct sigaction oldsig;
static void sighandler(int sig);
#endif /* SOCKS_CLIENT */

/* adds a direct route for "saddr". */
static struct route_t *add_directroute(const struct sockaddr_in *saddr);

/* do we have a direct upnp broadcast route? */
static int socks_have_direct_upnpbroadcastroute(void);

#endif /* HAVE_LIBMINIUPNP */

int
socks_initupnp(gw, state)
   const gwaddr_t *gw;
   proxystate_t *state;
{
   const char *function = "socks_initupnp()";
#if HAVE_LIBMINIUPNP
   struct sockshost_t host;
   struct UPNPDev *dev;
   struct UPNPUrls url;
   struct IGDdatas data;
   char myaddr[INET_ADDRSTRLEN], gwstring[MAXGWSTRING],
        addrstring[MAXSOCKSHOSTSTRING];
   int devtype, rc;
#endif /* HAVE_LIBMINIUPNP */

   slog(LOG_DEBUG, function);

#if !HAVE_LIBMINIUPNP
   return -1;
#else /* HAVE_LIBMINIUPNP */
   if (*state->upnp.controlurl != NULL)
      return 0;

   if (gw->atype == SOCKS_ADDR_URL) {
      slog(LOG_DEBUG, "%s: using IGD at \"%s\"\n", function, gw->addr.urlname);

      if (UPNP_GetIGDFromUrl(gw->addr.urlname, &url, &data, myaddr,
      sizeof(myaddr)) != 1) {
         swarnx("%s: failed to get IGD from fixed url: %s\n",
         function, gw->addr.urlname);
         return -1;
      }

      rc = 0;
   }
   else {
      gwaddr2sockshost(gw, &host);
      SASSERTX(host.atype == SOCKS_ADDR_IPV4);
      inet_ntop(AF_INET, &host.addr.ipv4, addrstring, sizeof(addrstring));

      slog(LOG_DEBUG, "%s: doing upnp discover on the interface for %s (%s)",
      function, addrstring, gwaddr2string(gw, gwstring, sizeof(gwstring)));

      if ((dev = upnpDiscover(UPNP_DISCOVERYTIME_MS, addrstring, NULL, 0))
      == NULL) {
         slog(LOG_DEBUG, "no upnp devices found");
         return -1;
      }

      if (socks_have_direct_upnpbroadcastroute()) {
         /*
          * If we have a direct route for upnp broadcast, assume we
          * should add direct routes for all upnp devices found also.
          */
         struct UPNPDev *p;

         slog(LOG_DEBUG,
         "%s: upnp devices found, adding direct routes for them", function);

         for (p = dev; p != NULL; p = p->pNext) {
            struct sockaddr saddr;

            if (urlstring2sockaddr(p->descURL, &saddr) == NULL)
               continue;
            add_directroute((struct sockaddr_in *)&saddr);
         }
      }
      else
         slog(LOG_DEBUG, "%s: upnp devices found, but not adding direct "
         "routes for them since no direct upnp broadcast route", function);

      switch (devtype = UPNP_GetValidIGD(dev, &url, &data, myaddr,
      sizeof(myaddr))) {
         case UPNP_NO_IGD:
            slog(LOG_DEBUG, "no IGD found");
            rc = -1;
            break;

         case UPNP_CONNECTED_IGD:
            slog(LOG_DEBUG, "IGD found at %s", dev->descURL);
            rc = 0;
            break; 

         case UPNP_DISCONNECTED_IGD:
            slog(LOG_DEBUG, "IGD found, but it is not connected");
            rc = -1;
            break;

         case UPNP_UNKNOWN_DEVICE:
            slog(LOG_DEBUG, "unknown upnp device found at %s", url.controlURL);
            rc = -1;
         
         default:
            swarnx("%s: unknown returncode from UPNP_GetValidIGD(): %d",
            function, devtype);
            rc = -1;
      }

      freeUPNPDevlist(dev);
   }

   SASSERTX(strlen(url.controlURL) < sizeof(state->upnp.controlurl));
   strcpy(state->upnp.controlurl, url.controlURL);
   SASSERTX(strlen(data.servicetype) < sizeof(state->upnp.servicetype));
   strcpy(state->upnp.servicetype, data.servicetype);

   FreeUPNPUrls(&url);

   return rc;
#endif /* HAVE_LIBMINIUPNP */
}

int
upnp_negotiate(s, packet, state)
   const int s;
   struct socks_t *packet;
   const proxystate_t *state;
{
   const char *function = "upnp_negotiate()";
#if HAVE_LIBMINIUPNP
   struct sockaddr_in addr;
   socklen_t addrlen;
   char straddr[INET_ADDRSTRLEN], strport[sizeof("65535")];
   int rc;
#endif

   slog(LOG_DEBUG, function);

#if !HAVE_LIBMINIUPNP
   SERRX(0);
#else
   packet->res.version = PROXY_UPNP;

   switch (packet->req.command) {
      case SOCKS_CONNECT:
         /*
          * Can only find out what the external ip address of the device is.
          *
          * We could fetch the address here, but if the client never intends
          * to find out what it's local address is, that's a waste of time. 
          * Therefor postpone it to the Rgetsockname() call, if it ever
          * comes.
          *
          * For the socksserver case (server chained) we need to fetch
          * it here though, since it is part of the response returned
          * to the socks client.
          */

         if (socks_connect(s, &packet->req.host) != 0)
            if (errno != EINPROGRESS) {
               slog(LOG_DEBUG, "%s: socks_connect(%s): %s", 
               function, sockshost2string(&packet->req.host, NULL, 0), 
               strerror(errno));

               packet->res.reply = UPNP_FAILURE;
               return -1;
            }

         /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE:
         /*
          * if it was a bind, it would be handled the same as the 
          * tcp bind, so this means the client starts by wanting
          * to send a udp packet
          *
          * Similarly to a connect, the only information we can provide 
          * here is the external ip address of the controldevice.
          * Postponed for the same reason as for connect.
          */

         packet->res.host.atype              = SOCKS_ADDR_IPV4;
         /* will be filled in with real values if user does a getsockname(2). */
#if SOCKS_CLIENT
         packet->res.host.addr.ipv4.s_addr = htonl(INADDR_ANY); 
#else /* SOCKS_SERVER */
         if ((rc = UPNP_GetExternalIPAddress(state->upnp.controlurl,
         state->upnp.servicetype, straddr)) != UPNPCOMMAND_SUCCESS) {
            swarnx("failed to get external ip address of upnp device: %d", rc);
            packet->res.reply   = UPNP_FAILURE;
            return -1;  
         }

         inet_pton(AF_INET, straddr, &packet->res.host.addr.ipv4);
#endif /* SOCKS_SERVER */

         addrlen = sizeof(addr);
         if (getsockname(s, (struct sockaddr *)&addr, &addrlen) != 0) {
            swarn("%s: getsockname()", function);
            rc = -1;
            break;
         }
         packet->res.host.port = TOIN(&addr)->sin_port;
         slog(LOG_DEBUG, "%s: will never know for sure, but hoping IGD "
                         "will use same port as we (%d)",
                         function, ntohs(packet->res.host.port));

         rc = 0;
         break;


      case SOCKS_BIND: {
         /*
          * Need tell the device to create a portmapping, mapping an
          * address on it's side to the address we have bound.
          * Then we need to get the ip address the device is using
          * on the external side.
          */
#if SOCKS_CLIENT
         static int atexit_registered;
#endif /* SOCKS_CLIENT */
         char buf[256], protocol[16];
         int len, val;

         addrlen = sizeof(addr);
         if (getsockname(s, (struct sockaddr *)&addr, &addrlen) != 0) {
            swarn("getsockname()");
            packet->res.reply = UPNP_FAILURE;
            return -1;
         }

         if ((rc = UPNP_GetExternalIPAddress(state->upnp.controlurl,
         state->upnp.servicetype, straddr)) != UPNPCOMMAND_SUCCESS) {
            swarnx("failed to get external ip address of upnp device: %d", rc);
            packet->res.reply   = UPNP_FAILURE;
            return -1;  
         }
         else {
            struct sockaddr_in extaddr = addr;

            inet_pton(extaddr.sin_family, straddr, &extaddr.sin_addr);
            sockaddr2sockshost((struct sockaddr *)&extaddr, &packet->res.host);
         }

         slog(LOG_DEBUG, "%s: upnp controlpoint's external ip address is %s",
         function, straddr);

         if (addr.sin_addr.s_addr == htonl(INADDR_ANY)) {
            /*
             * Address not bound.  Not bound is good enough for us if 
             * it it's good enough for caller, but we do need to tell the 
             * controlpoint what address it should forward the connection to.
             */
             struct sockaddr tmpaddr;

             switch (packet->gw.addr.atype) {
                case SOCKS_ADDR_IFNAME: {

                   if (ifname2sockaddr(packet->gw.addr.addr.ifname, 0, &tmpaddr,
                   NULL) == NULL) {
                     swarn("ifname2sockaddr(%s)", packet->gw.addr.addr.ifname); 
                     packet->res.reply = UPNP_FAILURE;
                     return -1;
                  }

                  /* just want the ipaddr.  Portnumber etc. remains the same. */
                  addr.sin_addr = TOIN(&tmpaddr)->sin_addr;   
                  break;
               }

                case SOCKS_ADDR_URL: {
                  socklen_t tmpaddrlen;
                  int ss;

                  if (urlstring2sockaddr(packet->gw.addr.addr.urlname, &tmpaddr)
                  == NULL) {
                     packet->res.reply = UPNP_FAILURE;
                     return -1;
                  }

                  /*
                   * What we need to find out now is, what is the address
                   * this host uses to communicate with the controlpoint?
                   * That is the address we need to tell it to forward
                   * the connection to.  Could use getifa(), but we
                   * are not guaranteed that always works as desired,
                   * so do a regular connect(2) to know for sure.
                   */

                  if ((ss = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                     swarn("%s: socket()", function);
                     packet->res.reply = UPNP_FAILURE;
                     return -1;
                  }

                  if (connect(ss, &tmpaddr, sizeof(tmpaddr)) != 0) {
                     swarn("%s: connect(%s)",
                     function, sockaddr2string(&tmpaddr, NULL, 0));
                     packet->res.reply = UPNP_FAILURE;
                     close(ss);
                     return -1;
                  }

                  tmpaddrlen = sizeof(tmpaddr);
                  if (getsockname(ss, &tmpaddr, &tmpaddrlen) != 0) {
                     swarn("%s: getsockname()", function);
                     packet->res.reply = UPNP_FAILURE;
                     close(ss);
                     return -1;
                  }

                  close(ss);
                  addr.sin_addr = TOIN(&tmpaddr)->sin_addr;   

                  break;
               }

               default:
                  SERRX(packet->gw.addr.atype);
            }
         }

         if (inet_ntop(addr.sin_family, &addr.sin_addr, straddr,
         sizeof(straddr)) == NULL) {
            swarn("inet_ntop()");
            packet->res.reply = UPNP_FAILURE;
            return -1;
         }

         len = sizeof(val);
         if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) != 0) {
            swarn("getsockopt()");
            packet->res.reply = UPNP_FAILURE;
            return -1;
         }
         switch (val) {
            case SOCK_DGRAM:
               snprintf(protocol, sizeof(protocol), PROTOCOL_UDPs);
               break;

            case SOCK_STREAM:
               snprintf(protocol, sizeof(protocol), PROTOCOL_TCPs);
               break;
            
            default:
               swarn("unknown protocoltype %d", val);
               packet->res.reply = UPNP_FAILURE;
               return -1;
         }

         snprintf(strport, sizeof(strport), "%d", ntohs(addr.sin_port));
         snprintf(buf, sizeof(buf), "%s (%s/client v%s via libminiupnpc)",
         __progname, PACKAGE, VERSION);

         slog(LOG_DEBUG,
         "trying to add %s portmapping on upnp device at %s: %s -> %s.%s",
         protocol, state->upnp.controlurl, strport, straddr, strport);

         str2upper(protocol); /* seems to fail if not. */
         if ((rc = UPNP_AddPortMapping(state->upnp.controlurl,
         state->upnp.servicetype, strport, strport, straddr, buf, protocol))
          != UPNPCOMMAND_SUCCESS) {
               swarnx("%s: UPNP_AddPortMapping() failed: %s",
               function, strupnperror(rc));
               packet->res.reply = UPNP_FAILURE;

               return -1;
         }

#if SOCKS_CLIENT
         if (!atexit_registered) {
            struct sigaction oursig;
            size_t i;
            int signalv[] = { SIGINT };

            slog(LOG_DEBUG, "%s: registering cleanup function with atexit(3)",
            function);

            if (atexit(upnpcleanup) != 0) {
               swarn("%s: atexit() failed to register upnp cleanup function",
               function);
               break;
            }

            atexit_registered = 1;

            for (i = 0; i < ELEMENTS(signalv); ++i) {
               if (sigaction(signalv[i], NULL, &oldsig) != 0) {
                  swarn("%s: sigaction(%d)", function, signalv[i]);
                  break;
               }

               oursig = oldsig;
               oursig.sa_handler = sighandler;
               if (sigaction(signalv[i], &oursig, NULL) != 0) {
                  swarn("%s: sigaction(%d)", function, signalv[i]);
                  break;
               }
            }
         }
#endif /* SOCKS_CLIENT */
         break;
      }

      default:
         SERRX(packet->req.command);
   }

   packet->res.reply = UPNP_SUCCESS;

   return 0;
#endif /* !HAVE_LIBMINIUPNP */
}

#if HAVE_LIBMINIUPNP

#if SOCKS_CLIENT
static void
sighandler(sig)
   int sig;
{
   const char *function = "sighandler()";

   slog(LOG_DEBUG, function);
   upnpcleanup();

   /* reinstall original signalhandler. */
   if (sigaction(SIGINT, &oldsig, NULL) != 0)
      serr(1, "%s: restoring old signalhandler failed", function);

   raise(SIGINT);
}
#endif /* SOCKS_CLIENT */

static struct route_t *
add_directroute(saddr)
   const struct sockaddr_in *saddr;
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
   route.dst.addr.ipv4.mask.s_addr            = htonl(32);
   route.dst.port.tcp = route.dst.port.udp    = saddr->sin_port;
   route.dst.operator                         = eq;
   
   route.gw.addr.atype                        = SOCKS_ADDR_DOMAIN;
   SASSERTX(sizeof(route.gw.addr.addr.domain) >= sizeof("direct"));
   strcpy(route.gw.addr.addr.domain, "direct");
   route.gw.state.command.connect             = 1;
   route.gw.state.command.udpassociate        = 1;
   route.gw.state.proxyprotocol.direct        = 1;

   route.state.autoadded                      = 1;

   slog(LOG_DEBUG, "adding direct route for upnp device at %s",
   sockaddr2string((const struct sockaddr *)saddr, NULL, 0));

   return socks_addroute(&route, 0);
}

static int
socks_have_direct_upnpbroadcastroute(void)
{
   const char *function = "socks_have_direct_upnpbroadcastroute()";
   struct route_t *route;
   struct sockshost_t host;

   host.atype    = SOCKS_ADDR_IPV4;
   host.port   = htons(DEFAULT_SSDP_PORT);
   if (inet_pton(AF_INET, DEFAULT_SSDP_BROADCAST_ADDR, &host.addr.ipv4) != 1)
      serr(1, "%s: inet_pton(%s)", function, DEFAULT_SSDP_BROADCAST_ADDR);

   for (route = sockscf.route; route != NULL; route = route->next) {
      static in_port_t ssdp_port;

      if (!route->gw.state.proxyprotocol.direct)
         continue;

      if (ssdp_port == 0) {
         struct servent *service;
         
         if ((service = getservbyname("ssdp", "udp")) == NULL)
            ssdp_port = htons(DEFAULT_SSDP_PORT);
         else
            ssdp_port = service->s_port;
      }

      if (addressmatch(&route->dst, &host, SOCKS_UDP, 0)) {
         slog(LOG_DEBUG, "%s: have direct upnp broadcast route", function);
         return 1;
      }
   }

   return 0;
}

#if SOCKS_CLIENT
void
upnpcleanup(void)
{
   const char *function = "upnpcleanup()";
   const struct socksfd_t *socksfd;
   int left, rc;
   
   slog(LOG_DEBUG, function);

   for (left = getdtablesize() - 1; left >= 0; --left) {
      char port[sizeof("65535")], protocol[sizeof("TCP")];

      if ((socksfd = socks_getaddr(left, 0)) == NULL)
         continue;

      if (socksfd->state.version != PROXY_UPNP)
         continue;

      slog(LOG_DEBUG, "%s: have upnp session set up for command %s",
      function, command2string(socksfd->state.command));

      if (socksfd->state.command != SOCKS_BIND)
         continue;
      
      snprintf(port, sizeof(port), "%d",
      ntohs(TOCIN(&socksfd->remote)->sin_port));

      if (socksfd->state.protocol.tcp)
         snprintf(protocol, sizeof(protocol), PROTOCOL_TCPs);
      else if (socksfd->state.protocol.udp)
         snprintf(protocol, sizeof(protocol), PROTOCOL_UDPs);
      else
         swarnx("%s: neither tcp nor udp set in protocol for descriptor %d",
         function, left);

      slog(LOG_DEBUG, "%s: deleting portmapping for external %s port %s",
      function, protocol, port);

      str2upper(protocol);

      if ((rc =
      UPNP_DeletePortMapping(socksfd->route->gw.state.data.upnp.controlurl,
      socksfd->route->gw.state.data.upnp.servicetype, port, protocol))
      != UPNPCOMMAND_SUCCESS)
            swarnx("%s: UPNP_DeletePortMapping(%s, %s) failed: %s",
            function, port, protocol, strupnperror(rc));
   }
}
#endif /* SOCKS_CLIENT */
#endif /* !HAVE_LIBMINIUPNP */
