/*
 * $Id: getoutaddr.c,v 1.126 2013/07/27 19:03:46 michaels Exp $
 *
 * Copyright (c) 2001, 2002, 2006, 2008, 2009, 2010, 2011, 2012
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
"$Id: getoutaddr.c,v 1.126 2013/07/27 19:03:46 michaels Exp $";

static sa_family_t
get_external_safamily(const struct sockaddr_storage *client,
                      const int command, const sockshost_t *reqhost);
/*
 * Returns the sa_family_t that should be used for a client with address
 * "client", requesting the SOCKS command "command" with the reqest host
 * "reqhost".
 * 
 * On success the sa_family_t that shpuld be used.
 * On failure returns AF_UNSPEC.
 */


static struct sockaddr_storage *
getdefaultexternal(const sa_family_t safamily, struct sockaddr_storage *addr);
/*
 * Returns the default IP address of sa_family_t "safamily" to use for 
 * external connections.  The portnumber in the address returned should 
 * be ignored.
 *
 * "safamily" can be set to AF_UNSPEC if the function can return an
 * address of any sa_family_t.  If there is no address of type safamily
 * available, the semantics are the same as if safamily was set to AF_UNSPEC.
 *
 * The default ipaddress is stored in "addr", and a pointer to it is returned.
 */

struct sockaddr_storage *
getoutaddr(laddr, client, cmd, reqhost, emsg, emsglen)
   struct sockaddr_storage *laddr;
   const struct sockaddr_storage *client;
   const int cmd;
   const sockshost_t *reqhost;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "getoutaddr()";
   struct sockaddr_storage raddr;
   char addrstr[MAXSOCKADDRSTRING], raddrstr[MAXSOCKSHOSTSTRING];

   slog(LOG_DEBUG,
        "%s: client %s, cmd %s, reqhost %s, external.rotation = %s",
        function,
        sockaddr2string(client, addrstr, sizeof(addrstr)),
        command2string(cmd),
        sockshost2string(reqhost, raddrstr, sizeof(raddrstr)),
        rotation2string(sockscf.external.rotation));

   bzero(&raddr, sizeof(raddr)); 

   /*
    * First figure out what /type/ of address (ipv4 or ipv6) we need to 
    * bind on the external side.
    */
   switch (cmd) {
      case SOCKS_BIND:
         if (reqhost->atype            == SOCKS_ADDR_IPV4
         &&  reqhost->addr.ipv4.s_addr == htonl(BINDEXTENSION_IPADDR))
            SET_SOCKADDR(&raddr, external_has_global_safamily(AF_INET) ? 
                                 AF_INET : AF_INET6);
         else if (reqhost->atype == SOCKS_ADDR_IPV4
         ||       reqhost->atype == SOCKS_ADDR_IPV6) {
            if (external_has_global_safamily(atype2safamily(reqhost->atype)))
               sockshost2sockaddr(reqhost, &raddr);
            else {
               snprintf(emsg, emsglen, 
                        "bind of an %s requested, but no %s configured for "
                        "our usage on the external interface",
                        atype2string(reqhost->atype),
                        atype2string(reqhost->atype));

               return NULL;
            }
         }
         else {
            /*
             * Have to expect the bindreply from an address given as a 
             * hostname by the client.  Since we may have multiple address 
             * families configured on the external interface on which we
             * can accept the bindreply on, we need to bind an address of 
             * the correct type.
             *
             * For now we assume that the type of address returned first
             * is the type of address we should bind.
             */
            int gaierr;

            SASSERTX(reqhost->atype == SOCKS_ADDR_DOMAIN);

            sockshost2sockaddr2(reqhost, &raddr, &gaierr, emsg, emsglen);
            if (gaierr != 0) {
               log_resolvefailed(reqhost->addr.domain, EXTERNALIF, gaierr);
               return NULL;
            }
         }

         break;

      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE: {
         int gaierr;

         sockshost2sockaddr2(reqhost, &raddr, &gaierr, emsg, emsglen);
         if (gaierr != 0) {
            SASSERTX(reqhost->atype == SOCKS_ADDR_DOMAIN);

            log_resolvefailed(reqhost->addr.domain, EXTERNALIF, gaierr);
            return NULL;
         }

         break;
      }

      default:
         SERRX(cmd);
   }

   switch (sockscf.external.rotation) {
      case ROTATION_NONE:
         getdefaultexternal(raddr.ss_family, laddr);
         break;

      case ROTATION_SAMESAME:
         *laddr = *client;
         break;

      case ROTATION_ROUTE: {
         if (IPADDRISBOUND(&raddr)) {
            /*
             * Connect a udp socket and check what local address was chosen 
             * by the kernel for connecting to dst.  Idea from Quagga source.
             */
            sockshost_t host;
            int s;

            if ((s = socket(raddr.ss_family, SOCK_DGRAM, 0)) == -1) {
               snprintf(emsg, emsglen, 
                        "could not create new %s UDP socket with socket(2): %s",
                        safamily2string(raddr.ss_family), strerror(errno));

               swarn("%s: %s", function, emsg);
               return NULL;
            }

            if (!PORTISBOUND(&raddr)) 
               /* set any valid portnumber; this is just a dry-run */
               SET_SOCKADDRPORT(&raddr, 1);

            sockaddr2sockshost(&raddr, &host);
            if (socks_connecthost(s, 
                                  EXTERNALIF,
                                  &host,
                                  laddr,
                                  NULL,
                                  -1,
                                  emsg,
                                  emsglen) == -1) {
               slog(LOG_DEBUG, "%s: %s", function, emsg);
               close(s);

               if (cmd == SOCKS_UDPASSOCIATE)
                  return NULL;

               /*
                * Else: continue.
                * While highly unliklely it will work later, when we actually 
                * do try to connect/send data, it could be the local 
                * configuration is to block udp packets to this destination,
                * but allow tcp.
                */
               getdefaultexternal(get_external_safamily(client, cmd, reqhost),
                                  laddr);
               break;
            }

            close(s);
         }
         else
            getdefaultexternal(get_external_safamily(client, cmd, reqhost),
                               laddr);

         break;
      }

      default:
         SERRX(sockscf.external.rotation);
   }

   if (addrindex_on_externallist(&sockscf.external, laddr) != -1)
      slog(LOG_DEBUG,
           "%s: local address %s selected for forwarding from %s to %s",
           function,
           sockaddr2string2(laddr,  0, addrstr,  sizeof(addrstr)),
           sockaddr2string(client, NULL,     0),
           sockaddr2string(&raddr, raddrstr, sizeof(raddrstr)));
   else {
      snprintf(emsg, emsglen,
               "local address %s selected for forwarding from %s to %s "
               "(external.rotation = %s), but that local address is not "
               "configured on our external interface(s).  "
               "%s configuration error?",
               sockaddr2string2(laddr,  0, addrstr,  sizeof(addrstr)),
               sockaddr2string(client, NULL,     0),
               sockaddr2string(&raddr, raddrstr, sizeof(raddrstr)),
               rotation2string(sockscf.external.rotation),
               sockscf.option.configfile);

      slog(external_has_safamily(laddr->ss_family) ? LOG_WARNING : LOG_DEBUG, 
           "%s: %s", function, emsg);

      return NULL;
   }

   /*
    * Try to set the local port to the best value also, though this is mostly
    * just guessing for all but the bind-case.
    */
   switch (cmd) {
#if SOCKS_SERVER
      case SOCKS_BIND:
         if (reqhost->atype            == SOCKS_ADDR_IPV4
         &&  reqhost->addr.ipv4.s_addr == htonl(BINDEXTENSION_IPADDR))
            SET_SOCKADDRPORT(laddr, GET_SOCKADDRPORT(client));
         else if (  (raddr.ss_family == AF_INET 
                  && TOIN(&raddr)->sin_addr.s_addr == htonl(INADDR_ANY))
               ||    (raddr.ss_family == AF_INET6 
                  && memcmp(&TOIN6(&raddr)->sin6_addr, 
                            &in6addr_any,
                            sizeof(in6addr_any)) == 0))
            SET_SOCKADDRPORT(laddr, reqhost->port);
         else
            SET_SOCKADDRPORT(laddr, htons(0));

         break;
#endif /* SOCKS_SERVER */

      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE: /* reqhost is the target of the first packet. */
         SET_SOCKADDRPORT(laddr, GET_SOCKADDRPORT(client));
         break;

      default:
         SERRX(cmd);
   }

   SASSERTX(IPADDRISBOUND(laddr));

   return laddr;
}

struct sockaddr_storage *
getinaddr(laddr, _client, emsg, emsglen)
   struct sockaddr_storage *laddr;
   const struct sockaddr_storage *_client;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "getinaddr()";
   struct sockaddr_storage client;
   size_t i;

   slog(LOG_DEBUG, "%s: client %s", 
        function, sockaddr2string(_client, NULL, 0));

   SASSERTX(_client->ss_family == AF_INET || _client->ss_family == AF_INET6);
   sockaddrcpy(&client, _client, sizeof(client));


   /*
    * Just return the first address of the appropriate type from our internal 
    * list and hope the best.
    */
   for (i = 0; i < sockscf.internal.addrc; ++i) {
      if (sockscf.internal.addrv[i].addr.ss_family == client.ss_family) {
         sockaddrcpy(laddr, &sockscf.internal.addrv[i].addr, sizeof(*laddr));

         slog(LOG_DEBUG, "%s: address %s selected",
              function, sockaddr2string(laddr, NULL, 0));

         return laddr;
      }
   }

   snprintf(emsg, emsglen, "no %s found on our internal address list",
            safamily2string(client.ss_family));

   slog(LOG_DEBUG, "%s: %s", function, emsg);
  
   return NULL;
}

static struct sockaddr_storage *
getdefaultexternal(safamily, addr)
   const sa_family_t safamily;
   struct sockaddr_storage *addr;
{
   const char *function = "getdefaultexternal()";
   const char *safamilystring = (safamily == AF_UNSPEC ? 
                                   "<any address>" : safamily2string(safamily));
   size_t i, addrfound;

   slog(LOG_DEBUG, "%s: looking for an %s", function, safamilystring);

   for (i = 0, addrfound = 0; i < sockscf.external.addrc && !addrfound; ++i) {
      switch (sockscf.external.addrv[i].atype) {
         case SOCKS_ADDR_IFNAME: {
            struct sockaddr_storage mask;
            size_t ii;;

            ii = 0;
            while (ifname2sockaddr(sockscf.external.addrv[i].addr.ifname,
                                   ii,
                                   addr,
                                   &mask) != NULL) {
               if (safamily == AF_UNSPEC || addr->ss_family == safamily) {
                  addrfound = 1;
                  break;
               }

               ++ii;
            }

            break;
         }

         case SOCKS_ADDR_IPV4:
            if (safamily == AF_UNSPEC || safamily == AF_INET) {
               sockshost_t host;

               sockshost2sockaddr(
                  ruleaddr2sockshost(&sockscf.external.addrv[i],
                                     &host,
                                     SOCKS_TCP),
                                     addr);
               addrfound = 1;
            }
            break;
         
         case SOCKS_ADDR_IPV6: 
            if (safamily == AF_UNSPEC || safamily == AF_INET6) {
               sockshost_t host;

               sockshost2sockaddr(
                  ruleaddr2sockshost(&sockscf.external.addrv[i],
                                     &host,
                                     SOCKS_TCP),
                                     addr);
               addrfound = 1;
            }
            break;

         default:
            SERRX((*sockscf.external.addrv).atype);
      }
   }

   if (addrfound)
      slog(LOG_DEBUG, "%s: matched %s is %s",
           function, safamilystring, sockaddr2string(addr, NULL, 0));
   else {
      slog(LOG_DEBUG,
           "%s: no matching %s found on external list, using INADDR_ANY",
           function, safamilystring);

      bzero(addr, sizeof(*addr));
      SET_SOCKADDR(addr, safamily == AF_UNSPEC ? AF_INET : safamily);
   }

   return addr;
}

sa_family_t
get_external_safamily(client, command, reqhost)
   const struct sockaddr_storage *client;
   const int command;
   const sockshost_t *reqhost;
{
   const char *function = "get_external_safamily()";
   sa_family_t safamily;

   switch (command) {
      case SOCKS_BIND:
      case SOCKS_UDPASSOCIATE:
         switch (reqhost->atype) {
            case SOCKS_ADDR_IPV4:
               safamily = AF_INET;
               break;

            case SOCKS_ADDR_IPV6:
               safamily = AF_INET6;
               break;

            case SOCKS_ADDR_DOMAIN: {
               struct sockaddr_storage p;

               sockshost2sockaddr(reqhost, &p);
               if (IPADDRISBOUND(&p))
                  safamily = p.ss_family;
               else 
                  safamily = client->ss_family;

               break;
            }

            default:
               SERRX(reqhost->atype);
         }
         break;

      case SOCKS_CONNECT: {
         struct sockaddr_storage p;

         sockshost2sockaddr(reqhost, &p);
         if (IPADDRISBOUND(&p))
            safamily = p.ss_family;
         else 
            safamily = client->ss_family;

         break;
      }

      default: 
         SERRX(command);
   }
  
   if (external_has_safamily(safamily))
      return safamily;

   /* 
    * Do not have the optimal safamily.  Anything else we can try?
    */
   switch (safamily) {
      case AF_INET:
         if (external_has_safamily(AF_INET6))
            return AF_INET6;

         break;

      case AF_INET6:
         if (external_has_safamily(AF_INET))
            return AF_INET;

         break;

      default:
         SERRX(safamily);
   }

   swarnx("%s: strange ... could not find any address to bind on external side "
          "for command %s from client %s.  Reqhost is %s.  "
          "Have IPv4? %s.  IPv6? %s",
          function,
          command2string(command),
          sockaddr2string(client, NULL, 0),
          sockshost2string(reqhost, NULL, 0),
          external_has_safamily(AF_INET)  ? "Yes" : "No",
          external_has_safamily(AF_INET6) ?
                 external_has_global_safamily(AF_INET6) ? 
                    "Yes (global)" : "Yes (local only)"
              :  "No");
         
   return AF_UNSPEC;
}

