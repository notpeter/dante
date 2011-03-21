/*
 * Copyright (c) 2008, 2009, 2010
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
"$Id: upnp.c,v 1.62.2.2.4.1 2011/03/04 13:46:17 michaels Exp $";

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
static struct sigaction oldsig;
static void sighandler(int sig);
static void atexit_upnpcleanup(void);
#endif /* SOCKS_CLIENT */

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
#else
   if (*state->upnp.controlurl != NUL)
      return 0;

   bzero(&url, sizeof(url));
   bzero(&data, sizeof(data));

   if (gw->atype == SOCKS_ADDR_URL) {
      slog(LOG_DEBUG, "%s: using IGD at \"%s\"\n", function, gw->addr.urlname);

      if (UPNP_GetIGDFromUrl(gw->addr.urlname, &url, &data, myaddr,
      sizeof(myaddr)) != 1) {
         swarnx("%s: failed to get IGD from fixed url %s\n",
         function, gw->addr.urlname);

         if (errno == 0)
            errno = ENETUNREACH;

         return -1;
      }

      rc = 0;
   }
   else {
      struct UPNPDev *p;

      gwaddr2sockshost(gw, &host);
      SASSERTX(host.atype == SOCKS_ADDR_IPV4);
      inet_ntop(AF_INET, &host.addr.ipv4, addrstring, sizeof(addrstring));

      slog(LOG_DEBUG, "%s: doing upnp discovery on interface of addr %s (%s)",
      function, addrstring, gwaddr2string(gw, gwstring, sizeof(gwstring)));

      if ((dev = upnpDiscover(UPNP_DISCOVERYTIME_MS, addrstring, NULL, 0))
      == NULL) {
         slog(LOG_DEBUG, "no upnp devices found");

         if (errno == 0)
            errno = ENETUNREACH;

         return -1;
      }

      slog(LOG_DEBUG,
      "%s: upnp devices found, adding direct routes for them", function);

      for (p = dev; p != NULL; p = p->pNext) {
         struct sockaddr saddr;
         struct sockaddr_in smask;

         if (urlstring2sockaddr(p->descURL, &saddr) == NULL)
            continue;

         bzero(&smask, sizeof(smask));
         smask.sin_family      = AF_INET;
         smask.sin_port        = htons(0);
         smask.sin_addr.s_addr = htonl(0xffffffff);
         socks_autoadd_directroute((struct sockaddr_in *)&saddr, &smask);
      }

      switch (devtype = UPNP_GetValidIGD(dev, &url, &data, myaddr,
      sizeof(myaddr))) {
         case UPNP_NO_IGD:
            slog(LOG_DEBUG, "no IGD found");

            if (errno == 0)
               errno = ENETUNREACH;

            rc = -1;
            break;

         case UPNP_CONNECTED_IGD:
            slog(LOG_DEBUG, "IGD found at %s", dev->descURL);
            rc = 0;
            break;

         case UPNP_DISCONNECTED_IGD:
            slog(LOG_DEBUG, "IGD found, but it is not connected");

            if (errno == 0)
               errno = ENETUNREACH;

            rc = -1;
            break;

         case UPNP_UNKNOWN_DEVICE:
            slog(LOG_DEBUG, "unknown upnp device found at %s", url.controlURL);

            if (errno == 0)
               errno = ENETUNREACH;

            rc = -1;
            break;

         default:
            swarnx("%s: unknown return code from UPNP_GetValidIGD(): %d",
            function, devtype);

            if (errno == 0)
               errno = ENETUNREACH;

            rc = -1;
      }

      freeUPNPDevlist(dev);
   }

   if (rc == 0) {
      SASSERTX(strlen(url.controlURL) < sizeof(state->upnp.controlurl));
      strcpy(state->upnp.controlurl, url.controlURL);
      SASSERTX(strlen(data.servicetype) < sizeof(state->upnp.servicetype));
      strcpy(state->upnp.servicetype, data.servicetype);
   }

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
#endif /* HAVE_LIBMINIUPNP */

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
          * For the socks server case (server chained) we need to fetch
          * it here though, since it is part of the response returned
          * to the socks client.
          */

         if (socks_connecthost(s, &packet->req.host) != 0)
            if (!ERRNOISINPROGRESS(errno)) {
               slog(LOG_DEBUG, "%s: socks_connecthost(%s) failed: %s",
               function, sockshost2string(&packet->req.host, NULL, 0),
               strerror(errno));

               packet->res.reply = UPNP_FAILURE;
               return -1;
            }

         /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE: {
         /*
          * if it was a bind, it would be handled the same as the
          * tcp bind, so this means the client starts by wanting
          * to send a udp packet, or we just did a connect(2).
          *
          * Similarly to a connect, the only information we can provide
          * here is the external ip address of the control device.
          * Postponed for the same reason as for connect.
          */
         const int errno_s = errno;

         packet->res.host.atype              = SOCKS_ADDR_IPV4;

#if SOCKS_CLIENT
         /* will be filled with real value if user ever does getsockname(2). */
         packet->res.host.addr.ipv4.s_addr = htonl(INADDR_ANY);
#else /* SOCKS_SERVER.  Server needs to know now so it can tell client. */
         if ((rc = UPNP_GetExternalIPAddress(state->upnp.controlurl,
         state->upnp.servicetype, straddr)) != UPNPCOMMAND_SUCCESS) {
            swarnx("failed to get external ip address of upnp device: %d", rc);
            packet->res.reply = UPNP_FAILURE;

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

         rc    = 0;
         errno = errno_s;
         break;
      }

      case SOCKS_BIND: {
         /*
          * Need tell the device to create a port mapping, mapping an
          * address on it's side to the address we have bound.
          * Then we need to get the ip address the device is using
          * on the external side.
          */
#if SOCKS_CLIENT
         static int atexit_registered;
#endif /* SOCKS_CLIENT */
         char buf[256], protocol[16];
         int val;
         socklen_t len;

         addrlen = sizeof(addr);
         if (getsockname(s, (struct sockaddr *)&addr, &addrlen) != 0) {
            swarn("getsockname()");
            packet->res.reply = UPNP_FAILURE;
            return -1;
         }

         if ((rc = UPNP_GetExternalIPAddress(state->upnp.controlurl,
         state->upnp.servicetype, straddr)) != UPNPCOMMAND_SUCCESS) {
            swarnx("failed to get external ip address of upnp device: %d", rc);
            packet->res.reply = UPNP_FAILURE;
            return -1;
         }
         else {
            struct sockaddr_in extaddr = addr;

            inet_pton(extaddr.sin_family, straddr, &extaddr.sin_addr);
            sockaddr2sockshost((struct sockaddr *)&extaddr, &packet->res.host);
         }

         slog(LOG_DEBUG, "%s: upnp control point's external ip address is %s",
         function, straddr);

         if (!ADDRISBOUND(&addr)) {
            /*
             * Address not bound.  Not bound is good enough for us if
             * it it's good enough for caller, but we do need to tell the
             * igd what address it should forward the connection to.
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

                  /* just want the ipaddr.  Port number etc. remains the same. */
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
               swarn("unknown protocol type %d", val);
               packet->res.reply = UPNP_FAILURE;
               return -1;
         }

         snprintf(strport, sizeof(strport), "%d", ntohs(addr.sin_port));
         snprintf(buf, sizeof(buf), "%s (%s/client v%s via libminiupnpc)",
         __progname, PACKAGE, VERSION);

         slog(LOG_DEBUG, "%s: trying to add %s port mapping for socket %d on "
                         "upnp device at %s: %s -> %s.%s",
                         function, protocol, s,
                         state->upnp.controlurl, strport, straddr, strport);

         str2upper(protocol); /* seems to fail if not. */
         if ((rc = UPNP_AddPortMapping(state->upnp.controlurl,
         state->upnp.servicetype, strport, strport, straddr, buf, protocol,
         NULL)) != UPNPCOMMAND_SUCCESS) {
               swarnx("%s: UPNP_AddPortMapping() failed: %s",
               function, strupnperror(rc));

               packet->res.reply = UPNP_FAILURE;
               return -1;
         }
         else
            slog(LOG_DEBUG, "%s: addition of port mapping succeeded", function);

#if SOCKS_CLIENT
         if (!atexit_registered) {
            struct sigaction oursig;
            size_t i;
            int signalv[] = { SIGINT };

            slog(LOG_DEBUG, "%s: registering cleanup function with atexit(3)",
            function);

            if (atexit(atexit_upnpcleanup) != 0) {
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
   /* NOTREACHED */
}

#if HAVE_LIBMINIUPNP

#if SOCKS_CLIENT
static void
sighandler(sig)
   int sig;
{
   const char *function = "sighandler()";

   slog(LOG_DEBUG, function);
   upnpcleanup(-1);

   /* reinstall original signalhandler. */
   if (sigaction(SIGINT, &oldsig, NULL) != 0)
      serr(1, "%s: restoring old signalhandler failed", function);

   raise(SIGINT);
}
#endif /* SOCKS_CLIENT */

#if SOCKS_CLIENT
void
upnpcleanup(s)
   const int s;
{
   const char *function = "upnpcleanup()";
   struct socksfd_t *socksfd;
   int rc, current, last;

   slog(LOG_DEBUG, "%s: socket %d", function, s);

   if (s == -1) {
      current = 0;
      last    = getmaxofiles(softlimit) - 1;
   }
   else {
      current  = s;
      last     = s;
   }

   for (; current <= last; ++current) {
      static int deleting;
      char port[sizeof("65535")], protocol[sizeof("TCP")];

      if (deleting == current)
         continue;

      if ((socksfd = socks_getaddr(current, 0 /* XXX */)) == NULL)
         continue;

      if (socksfd->state.version != PROXY_UPNP)
         continue;

      slog(LOG_DEBUG, "%s: socket %d has upnp session set up for command "
                      "%s, accept pending: %d",
                      function, current, command2string(socksfd->state.command),
                      socksfd->state.acceptpending);

      if (socksfd->state.command != SOCKS_BIND)
         continue;

      /*
       * Is this the socket we listened on?  Or just a client we accept(2)'ed?
       * The port mapping is just created for the first case.
       */
      if (!socksfd->state.acceptpending)
         continue; /* just a client we accepted. */

      snprintf(port, sizeof(port), "%d",
      ntohs(TOCIN(&socksfd->remote)->sin_port));

      if (socksfd->state.protocol.tcp)
         snprintf(protocol, sizeof(protocol), PROTOCOL_TCPs);
      else if (socksfd->state.protocol.udp)
         snprintf(protocol, sizeof(protocol), PROTOCOL_UDPs);
      else {
         SWARNX(0);
         continue;
      }

      slog(LOG_DEBUG, "%s: deleting port mapping for external %s port %s",
      function, protocol, port);

      str2upper(protocol);

      /*
       * needed to avoid recursion, as the below delete-call might
       * very well end up calling us again, which makes us try
       * to delete the port mapping twice.
       */
      deleting = current;

      if ((rc
      = UPNP_DeletePortMapping(socksfd->route->gw.state.data.upnp.controlurl,
                               socksfd->route->gw.state.data.upnp.servicetype,
                               port, protocol, NULL)) != UPNPCOMMAND_SUCCESS)
            swarnx("%s: UPNP_DeletePortMapping(%s, %s) failed: %s",
            function, port, protocol, strupnperror(rc));
      else
         slog(LOG_DEBUG, "%s: deleted port mapping for external %s port %s",
         function, protocol, port);

      deleting = -1;
   }
}

static void
atexit_upnpcleanup(void)
{
   const char *function = "atexit_upnpcleanup()";

   slog(LOG_DEBUG, function);
   upnpcleanup(-1);
}
#endif /* SOCKS_CLIENT */
#else /* !HAVE_LIBMINIUPNP */
void
upnpcleanup(s)
   const int s;
{
      return;
}
#endif /* !HAVE_LIBMINIUPNP */
