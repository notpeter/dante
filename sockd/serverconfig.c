/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011, 2012, 2013
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
"$Id: serverconfig.c,v 1.567 2013/10/27 15:24:42 karls Exp $";

struct config sockscf;        /* current config.   */

#define NEWEXTERNAL(argc, argv)                                                \
do {                                                                           \
   if (((argv) = realloc((argv), sizeof((*argv)) * ((++(*(argc)))))) == NULL)  \
      yyerror(NOMEM);                                                          \
   bzero(&((argv)[(*(argc)) - 1]), sizeof((*argv)));                           \
} while (/*CONSTCOND*/ 0)

#define NEWINTERNAL(argc, argv, ifname, sa, protocol)                          \
do {                                                                           \
   slog(LOG_DEBUG, "%s: adding address %s on nic %s to the internal list",     \
        function, sockaddr2string(&sa, NULL, 0), ifname);                      \
                                                                               \
   if (((argv) = realloc((argv), sizeof((*argv)) * ((++(*argc))))) == NULL)    \
      yyerror(NOMEM);                                                          \
   bzero(&((argv)[(*(argc)) - 1]), sizeof((*argv)));                           \
                                                                               \
   (argv)[(*(argc)) - 1].addr     = sa;                                        \
   (argv)[(*(argc)) - 1].protocol = protocol;                                  \
   (argv)[(*(argc)) - 1].s        = -1;                                        \
} while (/*CONSTCOND*/ 0)


static void
add_more_old_shmem(struct config *config, const size_t memc,
                   const oldshmeminfo_t memv[]);
/*
 * Adds "memv" to the list of old shmem entries stored in "config".
 */


void
addinternal(addr, protocol)
   const ruleaddr_t *addr;
   const int protocol;
{
   const char *function = "addinternal()";
   struct sockaddr_storage sa;
   char ifname[MAXIFNAMELEN];
   int changesupported;

   if (sockscf.option.serverc == 1
   ||  sockscf.state.inited   == 0
   ||  protocol               == SOCKS_UDP)
      changesupported = 1;
   else
      changesupported = 0;

   slog(LOG_DEBUG, "%s: (%s, %s).  Change supported: %d",
        function,
        ruleaddr2string(addr,
                        ADDRINFO_PORT | ADDRINFO_ATYPE,
                        NULL,
                        0),
        protocol2string(protocol),
        changesupported);

   switch (addr->atype) {
       case SOCKS_ADDR_IPV4:
       case SOCKS_ADDR_IPV6:
         if (addr->atype == SOCKS_ADDR_IPV4)
           SASSERTX(addr->addr.ipv4.mask.s_addr == htonl(IPV4_FULLNETMASK));
         else if (addr->atype == SOCKS_ADDR_IPV6)
           SASSERTX(addr->addr.ipv6.maskbits    == IPV6_NETMASKBITS);

         ruleaddr2sockaddr(addr, &sa, protocol);
         if (!PORTISBOUND(&sa))
            yyerrorx("%s: address %s does not specify a portnumber to bind",
                     function, sockaddr2string(&sa, NULL, 0));

         if (addrindex_on_listenlist(sockscf.internal.addrc,
                                     sockscf.internal.addrv,
                                     &sa,
                                     protocol) == -1) {
            if (!changesupported) {
               yywarnx("cannot change internal addresses once running. "
                       "%s looks like a new address and will be ignored",
                       sockaddr2string(&sa, NULL, 0));

               break;
            }
         }
         else
            break;

         if (sa.ss_family == AF_INET
         &&  TOIN(&sa)->sin_addr.s_addr == htonl(INADDR_ANY))
            STRCPY_ASSERTSIZE(ifname, "<any IPv4-interface>");
         else if (sa.ss_family == AF_INET6
         &&  memcmp(&TOIN6(&sa)->sin6_addr,
                    &in6addr_any,
                    sizeof(in6addr_any)) == 0)
            STRCPY_ASSERTSIZE(ifname, "<any IPv6-interface>");
         else if (sockaddr2ifname(&sa, ifname, sizeof(ifname)) == NULL) {
            /*
             * Probably config-error, but could be a bug in sockaddr2ifname(),
             * so don't error out yet.  Will know for sure when we try to bind
             * the address later.
             */
            strncpy(ifname, "<unknown>", sizeof(ifname) - 1);
            ifname[sizeof(ifname) - 1] = NUL;

            yywarn("%s: could not find address %s on any network interface",
                   function, sockaddr2string2(&sa, 0, NULL, 0));
         }

         NEWINTERNAL(&sockscf.internal.addrc,
                     sockscf.internal.addrv,
                     ifname,
                     sa,
                     protocol);
         break;

      case SOCKS_ADDR_DOMAIN: {
         ssize_t p;
         size_t i;

         for (i = 0;
         hostname2sockaddr(addr->addr.domain, i, &sa) != NULL;
         ++i) {
            SET_SOCKADDRPORT(&sa,
                             protocol == SOCKS_TCP ?
                                       addr->port.tcp : addr->port.udp);

            if ((p = addrindex_on_listenlist(sockscf.internal.addrc,
                                             sockscf.internal.addrv,
                                             &sa,
                                             protocol)) == -1) {
               if (!changesupported) {
                  swarnx("cannot change internal addresses once running "
                         "and %s looks like a new address.  Ignored",
                         sockaddr2string(&sa, NULL, 0));

                  continue;
               }
            }
            else {
               if (changesupported)
                  slog(LOG_DEBUG,
                       "%s: address %s, resolved from \"%s\", is already on "
                       "the internal list (#%ld) for addresses to accept "
                       "clients on.  Ignored",
                       function,
                       sockaddr2string(&sa, NULL, 0),
                       addr->addr.domain,
                       (long)p);

               continue;
            }

            if (sockaddr2ifname(&sa, ifname, sizeof(ifname)) == NULL) {
               /*
                * Probably config-error, but could be bug in our
                * sockaddr2ifname().
                * Will know for sure when we try to bind the address later,
                * so don't error out quite yet.
                */

               yywarn("%s: could not find address %s (resolved from %s) on "
                      "any network interface",
                      function,
                      sockaddr2string(&sa, NULL, 0),
                      addr->addr.domain);

               STRCPY_ASSERTSIZE(ifname, "<unknown>");
            }

            NEWINTERNAL(&sockscf.internal.addrc,
                        sockscf.internal.addrv,
                        ifname,
                        sa,
                        protocol);
         }

         if (i == 0)
            yyerrorx("could not resolve name \"%s\": %s",
                     addr->addr.domain, hstrerror(h_errno));

         break;
      }

      case SOCKS_ADDR_IFNAME: {
         struct ifaddrs *ifap, *iface;
         int isvalidif;

         if (getifaddrs(&ifap) != 0)
            serr("getifaddrs()");

         for (isvalidif = 0, iface = ifap;
         iface != NULL;
         iface = iface->ifa_next) {
            if (iface->ifa_addr == NULL)
               continue;

            if (!safamily_issupported(iface->ifa_addr->sa_family))
               continue;

            if (strcmp(iface->ifa_name, addr->addr.ifname) != 0)
               continue;

            isvalidif = 1;

            sockaddrcpy(&sa, TOSS(iface->ifa_addr), sizeof(sa));

            SET_SOCKADDRPORT(&sa, protocol == SOCKS_TCP ?
                                       addr->port.tcp : addr->port.udp);

            if (addrindex_on_listenlist(sockscf.internal.addrc,
                                        sockscf.internal.addrv,
                                        &sa,
                                        protocol) == -1) {
               if (!changesupported) {
                  swarnx("cannot change internal addresses once running, "
                         "and %s, expanded from the ifname \"%s\" looks "
                         "like a new address.  Ignored",
                         sockaddr2string(&sa, NULL, 0),
                         addr->addr.ifname);

                  continue;
               }
            }
            else {
               if (changesupported)
                  slog(LOG_DEBUG,
                       "%s: address %s, expanded  from the ifname \"%s\", "
                       "is already on the internal list for addresses to "
                       "accept clients on.  Ignored",
                       function,
                       sockaddr2string(&sa, NULL, 0),
                       addr->addr.ifname);
               continue;
            }

            NEWINTERNAL(&sockscf.internal.addrc,
                        sockscf.internal.addrv,
                        addr->addr.ifname,
                        sa,
                        protocol);
         }

         freeifaddrs(ifap);

         if (!isvalidif)
            swarnx("cannot find interface/address for %s", addr->addr.ifname);

         break;
      }

      default:
         SERRX(addr->atype);
   }
}

void
addexternal(addr)
   const ruleaddr_t *addr;
{
   int added_ipv4 = 0, added_ipv6 = 0, added_ipv6_gs = 0;

   switch (addr->atype) {
      case SOCKS_ADDR_DOMAIN: {
         /*
          * XXX this is not good.  It is be better to not resolve this now,
          * but resolve it when using.  Since we have a hostcache, that
          * should not add too much expense.  Sending servers a SIGHUP
          * when local addresses change is quite common though, so
          * assume it's good enough for now.
          */
         struct sockaddr_storage sa;
         size_t i;

         for (i = 0;
         hostname2sockaddr(addr->addr.domain, i, &sa) != NULL;
         ++i) {

            NEWEXTERNAL(&sockscf.external.addrc, sockscf.external.addrv);

            SET_SOCKADDRPORT(&sa, addr->port.tcp);

            sockaddr2ruleaddr(&sa,
                           &sockscf.external.addrv[sockscf.external.addrc - 1]);

            switch (sa.ss_family) {
               case AF_INET:
                  added_ipv4 = 1;
                  break;

               case AF_INET6:
                  added_ipv6 = 1;

                  if (!IN6_IS_ADDR_LINKLOCAL(&TOIN6(&sa)->sin6_addr))
                     added_ipv6_gs = 1;

                  break;

               default:
                  SERRX(sa.ss_family);
            }
         }

         if (i == 0)
            yyerrorx("could not resolve name \"%s\": %s",
                     addr->addr.domain, hstrerror(h_errno));

         break;
      }

      case SOCKS_ADDR_IPV4:
         if (addr->addr.ipv4.ip.s_addr == htonl(INADDR_ANY))
            yyerrorx("external address (%s) to connect out from cannot "
                     "be a wildcard address",
                     ruleaddr2string(addr, 0, NULL, 0));

         NEWEXTERNAL(&sockscf.external.addrc, sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         sockscf.external.addrv[sockscf.external.addrc - 1]
         .addr.ipv4.mask.s_addr = htonl(IPV4_FULLNETMASK);

         added_ipv4 = 1;
         break;

      case SOCKS_ADDR_IPV6:
         if (memcmp(&addr->addr.ipv6.ip, &in6addr_any, sizeof(in6addr_any))
         == 0)
            yyerrorx("external address (%s) cannot be a wildcard address",
                     ruleaddr2string(addr, 0, NULL, 0));

         NEWEXTERNAL(&sockscf.external.addrc, sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         sockscf.external.addrv[sockscf.external.addrc - 1]
         .addr.ipv6.maskbits = IPV6_NETMASKBITS;

         added_ipv6 = 1;

         if (!IN6_IS_ADDR_LINKLOCAL(&addr->addr.ipv6.ip))
            added_ipv6_gs = 1;

         break;

      case SOCKS_ADDR_IFNAME: {
         /*
          * Would be nice if this could be cached, e.g. by monitoring a
          * routing socket for changes.  Have no code for that however.
          */
         struct sockaddr_storage sa, t;
         size_t i;

         for (i = 0;
         ifname2sockaddr(addr->addr.ifname, i, &sa, &t) != NULL;
         ++i) {
            switch (sa.ss_family) {
               case AF_INET:
                  added_ipv4 = 1;
                  break;

               case AF_INET6:
                  added_ipv6 = 1;

                  if (!IN6_IS_ADDR_LINKLOCAL(&TOIN6(&sa)->sin6_addr))
                     added_ipv6_gs = 1;

                  break;

               default:
                  SERRX(sa.ss_family);
            }
         }

         NEWEXTERNAL(&sockscf.external.addrc, sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         break;
      }

      default:
         SERRX(addr->atype);
   }

   if (added_ipv4)
      sockscf.shmeminfo->state.external_hasipv4 = 1;

   if (added_ipv6) {
      sockscf.shmeminfo->state.external_hasipv6 = 1;

      if (added_ipv6_gs)
         sockscf.shmeminfo->state.external_hasipv6_globalscope = 1;
   }
}

#if 0
/*
 * not used yet, but if at some point we have to code to monitor interfaces
 * we use for changes ...  XXX move to a different file also.  interface.c?
 */
void
external_set_safamily(hasipv4, hasipv6, hasipv6_gs)
   unsigned char *hasipv4;
   unsigned char *hasipv6;
   unsigned char *hasipv6_gs;
{
   size_t i;

   if (hasipv4 != NULL)
      *hasipv4 = 0;

   if (hasipv6 != NULL)
      *hasipv6 = 0;

   if (hasipv6_gs != NULL)
      *hasipv6_gs = 0;

   for (i = 0; i < sockscf.external.addrc; ++i) {
      const ruleaddr_t *addr = &sockscf.external.addrv[i];

      /*
       * loop through array until we've found at least one match for
       * each address-family asked for.
       */
      if ((hasipv4 == NULL || *hasipv4)
      &&  (hasipv6 == NULL || *hasipv6))
         return;

      switch (addr->atype) {
         case SOCKS_ADDR_IPV4:
            if (hasipv4 != NULL)
               *hasipv4 = 1;
            break;

         case SOCKS_ADDR_IPV6:
            if (hasipv6 != NULL)
               *hasipv6 = 1;

#warning "add code for hasipv6_gs"

            break;

         case SOCKS_ADDR_IFNAME: {
            struct sockaddr_storage sa, mask;
            size_t ai = 0;

            while (ifname2sockaddr(addr->addr.ifname, ai, &sa, &mask) != NULL) {
               switch (sa.ss_family) {
                  case AF_INET:
                     if (hasipv4 != NULL)
                        *hasipv4 = 1;
                     break;

                  case AF_INET6:
                     if (hasipv6 != NULL)
                        *hasipv6 = 1;
                     break;
               }

               ++ai;
            }

            break;
         }

         default:
            SERRX(addr->atype);
      }
   }
}
#endif

void
resetconfig(config, exiting)
   struct config *config;
   const int exiting;
{
   const char *function = "resetconfig()";
   const int ismainmother = (pidismother(config->state.pid) == 1);
   rule_t *rulev[] = { config->crule, config->hrule, config->srule };
   monitor_t *monitor;
   size_t oldc, i;

   slog(LOG_DEBUG, "%s: exiting? %s, ismainmother? %s",
        function,
        exiting ?       "yes" : "no",
        ismainmother?   "yes" : "no");

   if (!exiting) {
#if !HAVE_NO_RESOLVESTUFF
      _res.options = config->initial.res_options;
#endif /* !HAVE_NO_RESOLVSTUFF */
   }

   switch (sockscf.state.type) {
      case PROC_MOTHER:
         mother_preconfigload();
         break;

      case PROC_MONITOR:
         monitor_preconfigload();
         break;

      case PROC_NEGOTIATE:
         negotiate_preconfigload();
         break;

      case PROC_REQUEST:
         request_preconfigload();
         break;

      case PROC_IO:
         io_preconfigload();
         break;
   }

   /* can always be changed from config. */
   bzero(&config->cpu, sizeof(config->cpu));

   if (config->option.serverc == 1) { /* don't support change if more. */
      free(config->internal.addrv);
      config->internal.addrv = NULL;
      config->internal.addrc = 0;
   }

#if HAVE_LIBWRAP
   if (config->hosts_allow_original != NULL
   && hosts_allow_table != config->hosts_allow_original) {
      free(hosts_allow_table);
      hosts_allow_table = config->hosts_allow_original;
   }

   if (config->hosts_deny_original != NULL
   && hosts_deny_table != config->hosts_deny_original) {
      free(hosts_deny_table);
      hosts_deny_table = config->hosts_deny_original;
   }
#endif /* HAVE_LIBWRAP */

   /* external addresses can always be changed. */
   free(config->external.addrv);
   config->external.addrv = NULL;
   config->external.addrc = 0;

   free(config->socketoptionv);
   config->socketoptionv = NULL;
   config->socketoptionc = 0;

   for (i = 0; i < ELEMENTS(rulev); ++i) {
      rule_t *rule, *next;

      rule = rulev[i];
      while (rule != NULL) {
         /*
          * Free normal process-local memory.
          */

#if !HAVE_SOCKS_RULES
         if (rule->type == object_srule) {
            /*
             * All pointers are pointers to the same memory in the clientrule,
             * so it has already been freed and only the rule itself remains
             * to be freed.
             */
            next = rule->next;
            free(rule);
            rule = next;

            continue;
         }
#endif /* !HAVE_SOCKS_RULES */

         freelinkedname(rule->user);
         rule->user = NULL;

         freelinkedname(rule->group);
         rule->group = NULL;

         free(rule->socketoptionv);
         rule->socketoptionv = NULL;
         rule->socketoptionc = 0;

         if (ismainmother) {
            /*
             * Next go through the shmem in this rule.  It's possible
             * we have children that are still using, or about to use,
             * these segments, so don't delete them now, but save
             * them for later.  Only upon exit we delete them all.
             *
             * This means we may have a lot of unneeded shmem segments
             * laying around, but since they are just files, rather
             * than the, on some systems very scarce, sysv-style shmem
             * segments, that should not be any problem.  It allows
             * us to ignore a lot of nasty locking issues.
             */
            size_t moreoldshmemc = 0;
            oldshmeminfo_t moreoldshmemv[   1 /* bw             */
                                          + 1 /* session        */
                                          + 1 /* session state. */
                                        ];

            if (rule->bw_shmid != 0) {
               moreoldshmemv[moreoldshmemc].id   = rule->bw_shmid;
               moreoldshmemv[moreoldshmemc].key  = key_unset;
               moreoldshmemv[moreoldshmemc].type = SHMEM_BW;

               ++moreoldshmemc;
            }

            if (rule->ss_shmid != 0) {
               /*
                * session-module supports statekeys too, so need to save that
                * too.
                */
               if (sockd_shmat(rule, SHMEM_SS) == 0) {
                  moreoldshmemv[moreoldshmemc].id   = rule->ss_shmid;
                  moreoldshmemv[moreoldshmemc].key  = rule->ss->keystate.key;
                  moreoldshmemv[moreoldshmemc].type = SHMEM_SS;

                  ++moreoldshmemc;

                  sockd_shmdt(rule, SHMEM_SS);
               }
            }

            if (moreoldshmemc > 0)
               add_more_old_shmem(config, moreoldshmemc, moreoldshmemv);
         }

         next = rule->next;
         free(rule);
         rule = next;
      }
   }

   config->crule = config->hrule = config->srule = NULL;

   /* and routes. */
   freeroutelist(config->route);
   config->route = NULL;

   /* and monitors. */
   monitor = sockscf.monitor;
   while (monitor != NULL) {
      monitor_t *next = monitor->next;

      if (ismainmother && monitor->mstats_shmid != 0) {
         oldshmeminfo_t moreoldshmemv[   1 /* just the monitor shmid. */ ];

         moreoldshmemv[0].id    = monitor->mstats_shmid;
         moreoldshmemv[0].key   = key_unset;
         moreoldshmemv[0].type  = SHMEM_MONITOR;

         add_more_old_shmem(config, ELEMENTS(moreoldshmemv), moreoldshmemv);
      }

      free(monitor);
      monitor = next;
   }
   config->monitor = NULL;

   /* routeoptions, read from config file. */
   bzero(&config->routeoptions, sizeof(config->routeoptions));

   /* compat, read from config file. */
   bzero(&config->compat, sizeof(config->compat));

   /* extensions, read from config file. */
   bzero(&config->extension, sizeof(config->extension));

   bzero(&config->internal.log, sizeof(config->internal.log));
   bzero(&config->external.log, sizeof(config->external.log));

   /*
    * log, errlog; handled specially when parsing.
    */

   /*
    * option; some only settable at commandline, some only read from config
    * file.  Those only read from config file will be reset to default in
    * optioninit().
    */

   /* resolveprotocol, read from config file. */
   bzero(&config->resolveprotocol, sizeof(config->resolveprotocol));

   /*
    * socketconfig, read from config file, but also has defaults set by
    * optioninit(), so don't need to touch it.
    */

   /* srchost, read from config file. */
   bzero(&config->srchost, sizeof(config->srchost));

   /* stat: keep it. */

   /*
    * state; keep most of it.
    */

   /* don't want to have too much code for tracking this, so regen now. */
   config->state.highestfdinuse = 0;

#if HAVE_SOLARIS_PRIVS
   /* uid; special.  Need to clear, but need to reopen config file first. */
#endif /* HAVE_SOLARIS_PRIVS */

   /*
    * methods, read from config file.
    */

   bzero(config->cmethodv, sizeof(config->cmethodv));
   config->cmethodc = 0;

   bzero(config->smethodv, sizeof(config->smethodv));
   config->smethodc = 0;

   /* timeout, read from config file. */
   bzero(&config->timeout, sizeof(config->timeout));

   if (exiting && ismainmother && config->oldshmemc > 0) {
      /*
       * Go through the list of saved segments and delete them.
       * Any (io) children using them should already have them open,
       * and nobody not already using them should need to attach to them
       * after we exit.  The exception is clients using the session module,
       * where we do not keep attached to the segment, but who need to attach
       * to it when removing the client.  Unfortunately failure to attach
       * to a shmem segment is normally a serious error and logged as thus,
       * but if mother has removed the segment, then obviously the other
       * processes can not attach to it again.
       *
       * There is some code to only debug log failure to attach to the
       * shmem segments (or rather, failure to open the file) if mother
       * does not exist (presumably having deleted the files before exiting),
       * rather than warn.  It depends on mother having exited before the
       * child process tries to remove the client though, which may not
       * be the case even though we do a little work to increase the odds.
       * Worst case is that we end up with some useless warnings though,
       * so not worth going overboard with it.
       */

      SASSERTX(ismainmother);
      SASSERTX(sockscf.state.type == PROC_MOTHER);

      /*
       * Lock to increase the chance of us having time to exit before
       * any children try to attach/detach (they will be blocked waiting for
       * the lock).  Don't unlock ourselves, but let the kernel release the
       * lock when we exit, further reducing gap between us exiting and
       * a child process being able to detect it.
       */
      socks_lock(config->shmemfd, 0, 0, 1, 1);

      slog(LOG_DEBUG, "%s: %ld old shmem entr%s saved.  Deleting now",
                      function, (unsigned long)config->oldshmemc,
                      config->oldshmemc == 1 ? "y" : "ies");

      for (oldc = 0; oldc < config->oldshmemc; ++oldc) {
         char fname[PATH_MAX];

         snprintf(fname, sizeof(fname), "%s",
                  sockd_getshmemname(config->oldshmemv[oldc].id, key_unset));

         slog(LOG_DEBUG,
              "%s: deleting shmem segment shmid %lu in file %s at index #%lu",
              function,
              (unsigned long)config->oldshmemv[oldc].id,
              fname,
              (unsigned long)oldc);

         if (unlink(fname) != 0)
            swarn("%s: failed to unlink shmem segment %ld in file %s",
                  function, config->oldshmemv[oldc].id, fname);

         if (config->oldshmemv[oldc].key != key_unset) {
            snprintf(fname, sizeof(fname), "%s",
                     sockd_getshmemname(config->oldshmemv[oldc].id,
                                        config->oldshmemv[oldc].key));

            slog(LOG_DEBUG,
                 "%s: deleting shmem segment shmid %lu/key %lu in file %s",
                 function,
                 (unsigned long)config->oldshmemv[oldc].id,
                 (unsigned long)config->oldshmemv[oldc].key,
                 fname);

            if (unlink(fname) != 0)
               swarn("%s: failed to unlink shmem segment %ld.%d in file %s",
                     function,
                     config->oldshmemv[oldc].id,
                     (int)config->oldshmemv[oldc].key,
                     fname);
         }
      }
   }
}

void
freeroutelist(routehead)
   route_t *routehead;
{

   while (routehead != NULL) {
      route_t *next = routehead->next;

      free(routehead->socketoptionv);
      free(routehead);
      routehead = next;
   }
}

int
addrisbindable(addr)
   const ruleaddr_t *addr;
{
   const char *function = "addrisbindable()";
   struct sockaddr_storage saddr;
   int rc, s;

   switch (addr->atype) {
      case SOCKS_ADDR_IPV4:
      case SOCKS_ADDR_IPV6:
         sockshost2sockaddr(ruleaddr2sockshost(addr, NULL, SOCKS_TCP), &saddr);
         break;

      case SOCKS_ADDR_IFNAME: {
         struct sockaddr_storage mask;

         if (ifname2sockaddr(addr->addr.ifname, 0, &saddr, &mask) == NULL) {
            swarn("%s: cannot find interface named %s with ip configured",
                  function, addr->addr.ifname);

            return 0;
         }

         break;
      }

      case SOCKS_ADDR_DOMAIN: {
         sockshost_t host;

         sockshost2sockaddr(ruleaddr2sockshost(addr, &host, SOCKS_TCP), &saddr);
         if (!IPADDRISBOUND(&saddr)) {
            swarnx("%s can not resolve host %s: %s",
                  function,
                  sockshost2string(&host, NULL, 0),
                  hstrerror(h_errno));

            return 0;
         }

         break;
      }

      default:
         SERRX(addr->atype);
   }

   if ((s = socket(saddr.ss_family, SOCK_STREAM, 0)) == -1) {
      swarn("%s: socket(SOCK_STREAM)", function);
      return 0;
   }

   rc = socks_bind(s, &saddr, 0);
   close(s);

   if (rc != 0)
      swarn("%s: cannot bind address: %s (from address specification %s)",
            function,
            sockaddr2string(&saddr, NULL, 0),
            ruleaddr2string(addr, 0, NULL, 0));

   return rc == 0;
}

int
isreplycommandonly(command)
   const command_t *command;
{

   if ((command->bindreply || command->udpreply)
   && !(command->connect || command->bind || command->udpassociate))
      return 1;
   else
      return 0;
}

int
hasreplycommands(command)
   const command_t *command;
{

   if (command->bindreply || command->udpreply)
      return 1;
   else
      return 0;
}


ssize_t
addrindex_on_listenlist(listc, listv, _addr, protocol)
   const size_t listc;
   const listenaddress_t *listv;
   const struct sockaddr_storage *_addr;
   const int protocol;
{
   size_t i;

   for (i = 0; i < listc; ++i) {
      struct sockaddr_storage addr = *(const struct sockaddr_storage *)_addr;

      if (listv[i].protocol != protocol)
         continue;

      if (GET_SOCKADDRPORT(&addr) == htons(0)) /* match any internal port. */
         SET_SOCKADDRPORT(&addr, GET_SOCKADDRPORT(&listv[i].addr));

      if (sockaddrareeq(&addr, &listv[i].addr, 0))
         return (ssize_t)i;
   }

   return (ssize_t)-1;
}

ssize_t
addrindex_on_externallist(external, _addr)
   const externaladdress_t *external;
   const struct sockaddr_storage *_addr;
{
   const char *function = "addrindex_on_externallist()";
   struct sockaddr_storage sa, addr;
   size_t i;

   /*
    * Not interested in comparing portnumber.
    */
   sockaddrcpy(&addr, _addr, sizeof(addr));
   SET_SOCKADDRPORT(&addr, htons(0));

   for (i = 0; i < external->addrc; ++i) {
      switch (external->addrv[i].atype) {
         case SOCKS_ADDR_IPV4:
         case SOCKS_ADDR_IPV6: {
            sockshost_t host;

            sockshost2sockaddr(ruleaddr2sockshost(&external->addrv[i],
                                                  &host,
                                                  SOCKS_TCP),
                               &sa);

            if (sockaddrareeq(&addr, &sa, 0))
               return (ssize_t)i;

            break;
         }
         case SOCKS_ADDR_DOMAIN: {
            size_t ii;

            ii = 0;
            while (hostname2sockaddr(external->addrv[i].addr.domain, ii++, &sa)
            != NULL)
               if (sockaddrareeq(&addr, &sa, 0))
                  return (ssize_t)i;

            break;
         }

         case SOCKS_ADDR_IFNAME: {
            struct sockaddr_storage mask;
            size_t ii;

            ii = 0;
            while (ifname2sockaddr(external->addrv[i].addr.domain,
                                   ii++,
                                   &sa,
                                   &mask) != NULL)
               if (sockaddrareeq(&addr, &sa, 0))
                  return (ssize_t)i;

            break;
         }

         default:
            SERRX(external->addrv[i].atype);
      }
   }

   return (ssize_t)-1;
}

void
checkconfig(void)
{
   const char *function = "checkconfig()";

#if HAVE_PAM
   char *pamservicename = NULL;
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   char *bsdauthstylename = NULL;
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
   char *gssapiservicename = NULL, *gssapikeytab = NULL;
#endif /* HAVE_GSSAPI */

   /* XXX add same for LDAP */

   rule_t *rulebasev[]   =  { sockscf.crule,
                              sockscf.hrule,
                              sockscf.srule
                            };

#if HAVE_PAM || HAVE_BSDAUTH || HAVE_GSSAPI
   int *methodbasev[]    =  { sockscf.cmethodv,
                              sockscf.cmethodv,
                              sockscf.smethodv
                            };

   size_t *methodbasec[] =  { &sockscf.cmethodc,
                              &sockscf.cmethodc,
                              &sockscf.smethodc
                            };
#endif /* HAVE_PAM || HAVE_BSDAUTH || HAVE_GSSAPI */

   size_t i, basec;
   int usinglibwrap = 0;

   for (i = 0; i < sockscf.cmethodc; ++i) {
      SASSERTX(sockscf.cmethodv[i] >= AUTHMETHOD_NONE);
      SASSERTX(sockscf.cmethodv[i] <= AUTHMETHOD_MAX);

      SASSERTX(methodisvalid(sockscf.cmethodv[i], object_crule));

      if (sockscf.cmethodv[i] == AUTHMETHOD_RFC931)
         usinglibwrap = 1;
   }

#if HAVE_SOCKS_RULES
   if (sockscf.smethodc == 0)
      swarnx("%s: no socks authentication methods enabled.  This means all "
             "socks requests will be blocked after negotiation.  "
             "Perhaps this is not intended?",
             function);
   else {
      for (i = 0; i < sockscf.smethodc; ++i) {
         SASSERTX(sockscf.smethodv[i] >= AUTHMETHOD_NONE);
         SASSERTX(sockscf.smethodv[i] <= AUTHMETHOD_MAX);

         if (sockscf.smethodv[i] == AUTHMETHOD_RFC931)
            usinglibwrap = 1;

         if (sockscf.smethodv[i] == AUTHMETHOD_NONE
         &&  i + 1               < sockscf.smethodc)
            yywarnx("authentication method \"%s\" is configured in the "
                    "global socksmethod list, but since authentication "
                    "methods are selected by the priority given, we will "
                    "never try to match any of the subsequent authentication "
                    "methods.  I.e., no match will ever be attempted on the "
                    "next method, method \"%s\"",
                    method2string(sockscf.smethodv[i]),
                    method2string(sockscf.smethodv[i + 1]));

      }
   }
#endif /* HAVE_SOCKS_RULES */

   /*
    * Check rules, including if some rule-specific settings vary across
    * rules.  If they don't, we can optimize things when running.
    */
   basec = 0;
   while (basec < ELEMENTS(rulebasev)) {
      rule_t *rule = rulebasev[basec++];

      if (rule == NULL)
         continue;

      for (; rule != NULL; rule = rule->next) {
         size_t methodc;
         int *methodv;


#if HAVE_LIBWRAP
         if (*rule->libwrap != NUL)
            usinglibwrap = 1;
#endif /* HAVE_LIBWRAP */

         /*
          * What methods do we need to check?  clientmethods for
          * client-rules, socksmethods for socks-rules.
          */
         switch (rule->type) {
            case object_crule:
#if HAVE_SOCKS_HOSTID
            case object_hrule:
#endif /* HAVE_SOCKS_HOSTID */
               methodc = rule->state.cmethodc;
               methodv = rule->state.cmethodv;
               break;

            case object_srule:
               methodc = rule->state.smethodc;
               methodv = rule->state.smethodv;
               break;

            default:
               SERRX(rule->type);
         }

         for (i = 0; i < methodc; ++i) {
            switch (methodv[i]) {
#if HAVE_PAM
               case AUTHMETHOD_PAM_ANY:
               case AUTHMETHOD_PAM_ADDRESS:
               case AUTHMETHOD_PAM_USERNAME:
                  if (*sockscf.state.pamservicename == NUL)
                     break; /* already found to vary. */

                  if (pamservicename == NULL) /* first pam rule. */
                     pamservicename = rule->state.pamservicename;
                  else if (strcmp(pamservicename, rule->state.pamservicename)
                  != 0) {
                     slog(LOG_DEBUG, "%s: pam.servicename varies, %s ne %s",
                          function,
                          pamservicename,
                          rule->state.pamservicename);

                     *sockscf.state.pamservicename = NUL;
                  }

                  break;
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
               case AUTHMETHOD_BSDAUTH:
                  if (*sockscf.state.bsdauthstylename == NUL)
                     break; /* already found to vary. */

                  if (bsdauthstylename == NULL) /* first bsdauth rule. */
                     bsdauthstylename = rule->state.bsdauthstylename;
                  else if (strcmp(bsdauthstylename,
                                  rule->state.bsdauthstylename) != 0) {
                     slog(LOG_DEBUG,
                          "%s: bsdauth.stylename varies, %s ne %s",
                          function,
                          bsdauthstylename,
                          rule->state.bsdauthstylename);

                     *sockscf.state.bsdauthstylename = NUL;
                  }

                  break;
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
               case AUTHMETHOD_GSSAPI:
                  if (*sockscf.state.gssapiservicename != NUL) {
                     if (gssapiservicename == NULL) /* first gssapi rule. */
                        gssapiservicename = rule->state.gssapiservicename;
                     else if (strcmp(gssapiservicename,
                              rule->state.gssapiservicename) != 0) {
                        slog(LOG_DEBUG,
                             "%s: gssapi.servicename varies, %s ne %s",
                              function,
                              gssapiservicename,
                              rule->state.gssapiservicename);

                        *sockscf.state.gssapiservicename = NUL;
                     }
                  }
                  /* else; already found to vary. */

                  if (*sockscf.state.gssapikeytab != NUL) {
                     if (gssapikeytab == NULL) /* first gssapi rule. */
                        gssapikeytab = rule->state.gssapikeytab;
                     else if (strcmp(gssapikeytab, rule->state.gssapikeytab)
                     != 0) {
                        slog(LOG_DEBUG, "%s: gssapi.keytab varies, %s ne %s",
                             function,
                             gssapikeytab,
                             rule->state.gssapikeytab);

                        *sockscf.state.gssapikeytab = NUL;
                     }
                  }
                  /* else; already found to vary. */

                  break;
#endif /* HAVE_GSSAPI */

               default:
                  break;
            }
         }

#if BAREFOOTD
         if (rule->type == object_crule) {
            if (rule->state.protocol.tcp)
               /*
                * Add all "to:" addresses to the list of internal interfaces;
                * barefootd doesn't use a separate "internal:" keyword for it.
                */
                addinternal(&rule->dst, SOCKS_TCP);

            if (rule->state.protocol.udp)
               sockscf.state.alludpbounced = 0;
         }
#endif /* BAREFOOTD */

      }
   }

   /*
    * Check that the main configured privileges work.
    */
   sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
   sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);

   sockd_priv(SOCKD_PRIV_UNPRIVILEGED, PRIV_ON);
   sockd_priv(SOCKD_PRIV_UNPRIVILEGED, PRIV_OFF);

   sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_ON);
   sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_OFF);

#if !HAVE_PRIVILEGES
   SASSERTX(sockscf.state.euid == geteuid());
   SASSERTX(sockscf.state.egid == getegid());

   if (sockscf.uid.unprivileged_uid == 0)
      swarnx("%s: setting the unprivileged uid to %d is not recommended "
             "for security reasons",
             function, sockscf.uid.unprivileged_uid);

#if HAVE_LIBWRAP
   if (usinglibwrap && sockscf.uid.libwrap_uid == 0)
      swarnx("%s: setting the libwrap uid to %d is almost never needed, and "
             "is not recommended for security reasons",
             function, sockscf.uid.libwrap_uid);
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_PRIVILEGES */

#if HAVE_PAM
   if (*sockscf.state.pamservicename != NUL
   &&  pamservicename                != NULL) {
      /*
       * pamservicename does not vary, but is not necessarily the
       * the same as sockscf.state.pamservicename (default).
       * If it is not, set sockscf.state.pamservicename to
       * what the user used in one or more of the rules, since
       * it is the same in all rules, i.e. making it that value
       * we use to make passworddbisunique() work as expected.
       *
       * Likewise for bsdauth, gssapi, etc.
      */

      if (strcmp(pamservicename, sockscf.state.pamservicename) != 0)
         STRCPY_CHECKLEN(sockscf.state.pamservicename,
                         pamservicename,
                         sizeof(sockscf.state.pamservicename) - 1,
                         yyerrorx);
   }
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   if (*sockscf.state.bsdauthstylename != NUL
   &&  bsdauthstylename                != NULL) {
      if (strcmp(bsdauthstylename, sockscf.state.bsdauthstylename) != 0)
         STRCPY_CHECKLEN(sockscf.state.bsdauthstylename,
                         bsdauthstylename,
                         sizeof(sockscf.state.bsdauthstylename) - 1,
                         yyerrorx);
   }
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
   if (*sockscf.state.gssapiservicename != NUL
   &&  gssapiservicename                != NULL) {
      if (strcmp(gssapiservicename, sockscf.state.gssapiservicename) != 0)
         STRCPY_CHECKLEN(sockscf.state.gssapiservicename,
                         gssapiservicename,
                         sizeof(sockscf.state.gssapiservicename) - 1,
                         yyerrorx);
   }

   if (*sockscf.state.gssapikeytab != NUL
   &&  gssapikeytab                != NULL) {
      if (strcmp(gssapikeytab, sockscf.state.gssapikeytab) != 0)
         STRCPY_CHECKLEN(sockscf.state.gssapikeytab,
                         gssapikeytab,
                         sizeof(sockscf.state.gssapikeytab) - 1,
                         yyerrorx);
   }
#endif /* HAVE_GSSAPI */

   /*
    * Go through all rules again and set default values for
    * authentication-methods based on the global method-lines, if none set.
    */
   basec = 0;
   while (basec < ELEMENTS(rulebasev)) {
#if HAVE_PAM || HAVE_BSDAUTH || HAVE_GSSAPI
      const int *methodv    = methodbasev[basec];
      const size_t methodc  = *methodbasec[basec];
#endif /* HAVE_PAM || HAVE_BSDAUTH || HAVE_GSSAPI */

      rule_t *rule = rulebasev[basec];
      ++basec;

      if (rule == NULL)
         continue;

      for (; rule != NULL; rule = rule->next) {
#if HAVE_PAM
         if (methodisset(AUTHMETHOD_PAM_ANY,      methodv, methodc)
         ||  methodisset(AUTHMETHOD_PAM_ADDRESS,  methodv, methodc)
         ||  methodisset(AUTHMETHOD_PAM_USERNAME, methodv, methodc))
            if (*rule->state.pamservicename == NUL) /* set to default. */
               STRCPY_ASSERTSIZE(rule->state.pamservicename,
                                 sockscf.state.pamservicename);
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
         if (methodisset(AUTHMETHOD_BSDAUTH, methodv, methodc))
            if (*rule->state.bsdauthstylename == NUL) { /* set to default. */
               if (*sockscf.state.bsdauthstylename != NUL)
                  STRCPY_ASSERTSIZE(rule->state.bsdauthstylename,
                                   sockscf.state.bsdauthstylename);
            }
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
         if (methodisset(AUTHMETHOD_GSSAPI, methodv, methodc)) {
            if (*rule->state.gssapiservicename == NUL) /* set to default. */
               STRCPY_ASSERTSIZE(rule->state.gssapiservicename,
                                sockscf.state.gssapiservicename);

            if (*rule->state.gssapikeytab == NUL) /* set to default. */
               STRCPY_ASSERTSIZE(rule->state.gssapikeytab,
                                sockscf.state.gssapikeytab);

            /*
             * can't do memcmp since we don't want to include
             * gssapiencryption.nec in the compare.
             */
            if (rule->state.gssapiencryption.clear           == 0
            &&  rule->state.gssapiencryption.integrity       == 0
            &&  rule->state.gssapiencryption.confidentiality == 0
            &&  rule->state.gssapiencryption.permessage      == 0) {
               rule->state.gssapiencryption.clear           = 1;
               rule->state.gssapiencryption.integrity       = 1;
               rule->state.gssapiencryption.confidentiality = 1;
               rule->state.gssapiencryption.permessage      = 0;
            }
         }
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
         if (*rule->state.ldap.keytab == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.keytab, DEFAULT_GSSAPIKEYTAB);

         if (*rule->state.ldap.filter == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.filter, DEFAULT_LDAP_FILTER);

         if (*rule->state.ldap.filter_AD == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.filter_AD,
                             DEFAULT_LDAP_FILTER_AD);

         if (*rule->state.ldap.attribute == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.attribute,
                             DEFAULT_LDAP_ATTRIBUTE);

         if (*rule->state.ldap.attribute_AD == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.attribute_AD,
                             DEFAULT_LDAP_ATTRIBUTE_AD);

         if (*rule->state.ldap.certfile == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.certfile,
                             DEFAULT_LDAP_CACERTFILE);

         if (*rule->state.ldap.certpath == NUL) /* set to default. */
            STRCPY_ASSERTSIZE(rule->state.ldap.certpath,
                             DEFAULT_LDAP_CERTDBPATH);

         if (rule->state.ldap.port == 0) /* set to default */
            rule->state.ldap.port = SOCKD_EXPLICIT_LDAP_PORT;

         if (rule->state.ldap.portssl == 0) /* set to default */
            rule->state.ldap.portssl = SOCKD_EXPLICIT_LDAPS_PORT;
#endif /* HAVE_LDAP */
      }
   }

#if BAREFOOTD
   if (sockscf.internal.addrc == 0 && ALL_UDP_BOUNCED())
      serrx("%s: no client-rules to accept clients on specified", function);

#else /* !BAREFOOTD */
   if (sockscf.internal.addrc == 0)
      serrx("%s: no internal address given for server to listen for clients on",
            function);
#endif /* !BAREFOOTD */


   if (sockscf.external.addrc == 0)
      serrx("%s: no external address specified for server to use when "
            "forwarding data on behalf of clients",
            function);

   if (sockscf.external.rotation == ROTATION_SAMESAME
   &&  sockscf.external.addrc    == 1)
      swarnx("%s: rotation for external addresses is set to same-same, but "
             "the number of external addresses is only one, so this does "
             "not make sense",
             function);

   if (sockscf.routeoptions.maxfail == 0 && sockscf.routeoptions.badexpire != 0)
      swarnx("%s: it does not make sense to set \"route.badexpire\" "
             "when \"route.maxfail\" is set to zero",
             function);

#if COVENANT
   if (*sockscf.realmname == NUL)
      STRCPY_ASSERTSIZE(sockscf.realmname, DEFAULT_REALMNAME);
#endif /* COVENANT */

#if HAVE_SCHED_SETAFFINITY
{
   const cpusetting_t *cpuv[] = { &sockscf.cpu.mother,
                                  &sockscf.cpu.monitor,
                                  &sockscf.cpu.negotiate,
                                  &sockscf.cpu.request,
                                  &sockscf.cpu.io };

   const int proctypev[]      = { PROC_MOTHER,
                                  PROC_MONITOR,
                                  PROC_NEGOTIATE,
                                  PROC_REQUEST,
                                  PROC_IO };
   size_t i;

   for (i = 0; i < ELEMENTS(cpuv); ++i)
   if (cpuv[i]->affinity_isset && !sockd_cpuset_isok(&cpuv[i]->mask))
      serrx("%s: invalid cpu mask configured for %s process: %s",
            function,
            childtype2string(proctypev[i]),
            cpuset2string(&cpuv[i]->mask, NULL, 0));
}
#endif /* HAVE_SCHED_SETAFFINITY */

   for (i = 0; i < sockscf.external.addrc; ++i)
      if (!addrisbindable(&sockscf.external.addrv[i]))
         serrx("%s: cannot bind external address #%ld: %s",
               function,
               (long)i,
               ruleaddr2string(&sockscf.external.addrv[i], 0, NULL, 0));
}



static void
add_more_old_shmem(config, memc, memv)
   struct config *config;
   const size_t memc;
   const oldshmeminfo_t memv[];
{
   const char *function = "add_more_old_shmem()";
   void *p;
   size_t i;

   if ((p = realloc(config->oldshmemv,
                    sizeof(*config->oldshmemv) * (config->oldshmemc + memc)))
   == NULL) {
      swarn("%s: could not allocate %lu bytes of memory to "
            "hold old shmids for later removal",
            function,
            (unsigned long)(sizeof(*config->oldshmemv)
                            * (config->oldshmemc + memc)));
      return;
   }
   config->oldshmemv = p;

   for (i = 0; i < memc; ++i) {
      const char *type;

      switch (memv[i].type) {
         case SHMEM_BW:
            type = "bw";
            break;

         case SHMEM_MONITOR:
            type = "monitor";
            break;

         case SHMEM_SS:
            type = "session";
            break;

         default:
            SERRX(memv[i].type);
      }

      slog(LOG_DEBUG,
           "%s: saving old shmem-object of type %lu (%s), with "
           "shmid %lu/key %lu, at index #%lu, for removal upon exit",
           function,
           (unsigned long)memv[i].type,
           type,
           (unsigned long)memv[i].id,
           (unsigned long)memv[i].key,
           (unsigned long)i);

      config->oldshmemv[config->oldshmemc++] = memv[i];
   }
}
