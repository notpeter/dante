/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011, 2012
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
"$Id: serverconfig.c,v 1.435 2012/06/01 20:23:06 karls Exp $";

struct config sockscf;
const int socks_configtype = CONFIGTYPE_SERVER;


#define NEWEXTERNAL(argc, argv)                                                \
do {                                                                           \
   if (((argv) = realloc((argv), sizeof((*argv)) * ((++argc)))) == NULL)       \
      yyerror(NOMEM);                                                          \
   bzero(&((argv)[(argc) - 1]), sizeof((*argv)));                              \
} while (/*CONSTCOND*/ 0)

#if NEED_ACCEPTLOCK
#define NEWINTERNAL(argc, argv, ifname, sa, protocol)                          \
do {                                                                           \
   slog(LOG_DEBUG, "%s: adding address %s on nic %s to the internal list",     \
        function, sockaddr2string(TOSA(&sa), NULL, 0), ifname);                \
                                                                               \
   if (((argv) = realloc((argv), sizeof((*argv)) * ((++argc)))) == NULL)       \
      yyerror(NOMEM);                                                          \
   bzero(&((argv)[(argc) - 1]), sizeof((*argv)));                              \
                                                                               \
   (argv)[(argc) - 1].addr     = sa;                                           \
   (argv)[(argc) - 1].protocol = protocol;                                     \
   (argv)[(argc) - 1].s        = -1;                                           \
   (argv)[(argc) - 1].lock     = -1;                                           \
} while (/*CONSTCOND*/ 0)
#else /* !NEED_ACCEPTLOCK */
#define NEWINTERNAL(argc, argv, ifname, sa, protocol)                          \
do {                                                                           \
   slog(LOG_DEBUG, "%s: adding address %s on nic %s to the internal list",     \
        function, sockaddr2string(TOSA(&sa), NULL, 0), ifname);                \
                                                                               \
   if (((argv) = realloc((argv), sizeof((*argv)) * ((++argc)))) == NULL)       \
      yyerror(NOMEM);                                                          \
   bzero(&((argv)[(argc) - 1]), sizeof((*argv)));                              \
                                                                               \
   (argv)[(argc) - 1].addr     = sa;                                           \
   (argv)[(argc) - 1].protocol = protocol;                                     \
   (argv)[(argc) - 1].s        = -1;                                           \
} while (/*CONSTCOND*/ 0)
#endif /* !NEED_ACCEPTLOCK */

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
        ruleaddr2string(addr, NULL, 0),
        protocol2string(protocol),
        changesupported);

   switch (addr->atype) {
       case SOCKS_ADDR_IPV4: {
         sockshost_t host;

         if (addr->addr.ipv4.mask.s_addr != htonl(0xffffffff))
            yyerror("no netmask is necessary for an internal address, "
                    "but if a mask is given it must be 32, not %d",
                    bitcount(addr->addr.ipv4.mask.s_addr));

         sockshost2sockaddr(ruleaddr2sockshost(addr, &host, protocol),
                            TOSA(&sa));
         if (!ADDRISBOUND(TOIN(&sa)))
            yyerror("%s: address %s is not a valid internal address",
                    function, sockshost2string(&host, NULL, 0));

         if (addrindex_on_listenlist(sockscf.internalc,
                                     sockscf.internalv,
                                     TOSA(&sa),
                                     protocol) == -1) {
            if (!changesupported) {
               swarnx("can't change internal addresses once running, "
                      "and %s looks like a new address.  Ignored",
                      sockaddr2string(TOSA(&sa), NULL, 0));

               break;
            }
         }
         else
            break;

         sockaddr2ifname(TOSA(&sa), ifname, sizeof(ifname));
         NEWINTERNAL(sockscf.internalc,
                     sockscf.internalv,
                     ifname,
                     sa,
                     protocol);
         break;
      }

      case SOCKS_ADDR_DOMAIN: {
         int i, p;

         for (i = 0;
              hostname2sockaddr(addr->addr.domain, i, TOSA(&sa)) != NULL;
              ++i) {

            TOIN(&sa)->sin_port = (protocol == SOCKS_TCP ?
                                       addr->port.tcp : addr->port.udp);

            if ((p = addrindex_on_listenlist(sockscf.internalc,
                                             sockscf.internalv,
                                             TOSA(&sa),
                                             protocol)) == -1) {
               if (!changesupported) {
                  swarnx("can't change internal addresses once running "
                         "and %s looks like a new address.  Ignored",
                         sockaddr2string(TOSA(&sa), NULL, 0));

                  continue;
               }
            }
            else {
               if (changesupported)
                  slog(LOG_DEBUG, "%s: address %s, resolved from \"%s\", is "
                                  "already on the internal list (#%d) for "
                                  "addresses to accept clients on.  Ignored",
                                  function,
                                  sockaddr2string(TOSA(&sa), NULL, 0),
                                  addr->addr.domain,
                                  p);
               continue;
            }

            sockaddr2ifname(TOSA(&sa), ifname, sizeof(ifname));
            NEWINTERNAL(sockscf.internalc,
                        sockscf.internalv,
                        ifname,
                        sa,
                        protocol);
         }

         if (i == 0)
            swarnx("could not resolve name %s: %s",
            addr->addr.domain, hstrerror(h_errno));

         break;
      }

      case SOCKS_ADDR_IFNAME: {
         struct ifaddrs *ifap, *iface;
         int isvalidif;

         if (getifaddrs(&ifap) != 0)
            serr(EXIT_FAILURE, "getifaddrs()");

         for (isvalidif = 0, iface = ifap;
         iface != NULL; iface = iface->ifa_next) {
            if (strcmp(iface->ifa_name, addr->addr.ifname) == 0
            && iface->ifa_addr != NULL
            && iface->ifa_addr->sa_family == AF_INET) {
               isvalidif = 1;

               sockaddrcpy(TOSA(&sa), iface->ifa_addr, sizeof(sa));
               TOIN(&sa)->sin_port
               = protocol == SOCKS_TCP ? addr->port.tcp : addr->port.udp;

               if (addrindex_on_listenlist(sockscf.internalc,
               sockscf.internalv, TOSA(&sa), protocol) == -1) {
                  if (!changesupported) {
                     swarnx("can't change internal addresses once running, "
                            "and %s, expanded from the ifname \"%s\" looks "
                            "like a new address.  Ignored",
                            sockaddr2string(TOSA(&sa), NULL, 0),
                            addr->addr.ifname);

                     continue;
                  }
               }
               else {
                  if (changesupported)
                     slog(LOG_DEBUG, "%s: address %s, expanded  from the "
                                     "ifname \"%s\", is already on the "
                                     "internal list for addresses to accept "
                                     "clients on.  Ignored",
                                     function,
                                     sockaddr2string(TOSA(&sa), NULL, 0),
                                     addr->addr.ifname);
                  continue;
               }

               NEWINTERNAL(sockscf.internalc,
                           sockscf.internalv,
                           addr->addr.ifname,
                           sa,
                           protocol);

               continue; /* XXX why not break in this loop? */
            }
         }

         freeifaddrs(ifap);

         if (!isvalidif)
            swarnx("can't find interface/address for %s", addr->addr.ifname);

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

   switch (addr->atype) {
         case SOCKS_ADDR_DOMAIN: {
            struct sockaddr_storage sa;
            int i;

            for (i = 0;
                 hostname2sockaddr(addr->addr.domain, i, TOSA(&sa)) != NULL;
                 ++i) {
               NEWEXTERNAL(sockscf.external.addrc, sockscf.external.addrv);

               /* LINTED pointer casts may be troublesome */
               TOIN(&sa)->sin_port = addr->port.tcp;
               sockaddr2ruleaddr(TOSA(&sa),
               &sockscf.external.addrv[sockscf.external.addrc - 1]);
            }

            if (i == 0)
               yyerror("could not resolve %s: %s",
                        addr->addr.domain, hstrerror(h_errno));
            break;
         }

      case SOCKS_ADDR_IPV4: {
         if (addr->addr.ipv4.ip.s_addr == htonl(INADDR_ANY))
            yyerror("external address (%s) can't be a wildcard address",
            ruleaddr2string(addr, NULL, 0));

         NEWEXTERNAL(sockscf.external.addrc, sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         sockscf.external.addrv[sockscf.external.addrc - 1]
         .addr.ipv4.mask.s_addr = htonl(0xffffffff);

         break;

      case SOCKS_ADDR_IFNAME:
         NEWEXTERNAL(sockscf.external.addrc, sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         break;
      }

      default:
         SERRX(addr->atype);
   }
}

void
resetconfig(exiting)
   const int exiting;
{
   const char *function = "resetconfig()";
   const int ismainmother = (pidismother(sockscf.state.pid) == 1);
#if HAVE_SCHED_SETSCHEDULER || HAVE_SCHED_SETAFFINITY
   const cpusetting_t *cpusetting;
#endif /* HAVE_SCHED_SETSCHEDULER || HAVE_SCHED_SETAFFINITY */

   route_t *route;
   rule_t *rulev[]       = { sockscf.crule, sockscf.srule };
#if !HAVE_SOCKS_RULES
   int isclientrulev[]   = { 1,             0             };
#endif /* !HAVE_SOCKS_RULES */
   size_t oldc, i;
   void *tmpmem;
   int doreset;

   if (sockscf.option.serverc == 1) { /* don't support changing if more. */
      free(sockscf.internalv);
      sockscf.internalv = NULL;
      sockscf.internalc = 0;
   }

   /* external addresses can always be changed. */
   free(sockscf.external.addrv);
   sockscf.external.addrv = NULL;
   sockscf.external.addrc = 0;

   free(sockscf.socketoptionv);
   sockscf.socketoptionv = NULL;
   sockscf.socketoptionc = 0;

#if HAVE_SCHED_SETSCHEDULER || HAVE_SCHED_SETAFFINITY
   switch (sockscf.state.type) {
      case CHILD_MOTHER:
         cpusetting = &sockscf.cpu.mother;
         break;

      case CHILD_NEGOTIATE:
         cpusetting = &sockscf.cpu.negotiate;
         break;

      case CHILD_REQUEST:
         cpusetting = &sockscf.cpu.request;
         break;

      case CHILD_IO:
         cpusetting = &sockscf.cpu.io;
         break;

      default:
         SERRX(sockscf.state.type);
   }
#endif /* HAVE_SCHED_SETSCHEDULER || HAVE_SCHED_SETAFFINITY */

   doreset = 0;


#if HAVE_SCHED_SETSCHEDULER
   if (cpusetting->scheduling_isset)
      doreset = 1;
#endif /* HAVE_SCHED_SETSCHEDULER */

#if HAVE_SCHED_SETAFFINITY
   if (cpusetting->affinity_isset)
      doreset = 1;
#endif /* HAVE_SCHED_SETAFFINITY */

   if (exiting)
      doreset = 0;

   if (doreset) {
      slog(LOG_DEBUG, "%s: resetting to initial cpu settings", function);
      sockd_setcpusettings(&sockscf.initial.cpu);
   }

   bzero(&sockscf.cpu, sizeof(sockscf.cpu));

   /*
    * delete all old rules, and if we are main mother, also save the list
    * of shared memory segments referenced in the rules, so we can delete
    * them on exit.
    */
   for (i = 0; i < ELEMENTS(rulev); ++i) {
      rule_t *rule, *next;

      rule = rulev[i];
      while (rule != NULL) {
         /*
          * Free normal process-local memory.
          */

#if !HAVE_SOCKS_RULES
         if (!isclientrulev[i]) {
            /*
             * All pointers are pointers to the same as in the clientrule,
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
             * them for later.  Upon exit, delete them all.
             *
             * This means we may have a lot of unneeded shmem segments
             * laying around, but since they are mmap-ed files, rather
             * than the, on some systems very scarce, sysv-style shmem
             * segments, that should not be any problem, and it allows
             * us to ignore a lot of nasty locking issues.
             */
            size_t moreoldshmemc;
            oldshmeminfo_t moreoldshmemv[3]; /* bw, session, singleauth. */

            moreoldshmemc = 0;
            if (rule->bw_shmid)
               moreoldshmemv[moreoldshmemc++].id = rule->bw_shmid;

            if (rule->ss_shmid)
               moreoldshmemv[moreoldshmemc++].id = rule->ss_shmid;

            if (moreoldshmemc > 0) {
               if ((tmpmem = realloc(sockscf.oldshmemv,
                                     sizeof(*sockscf.oldshmemv)
                                     * (sockscf.oldshmemc + moreoldshmemc)))
               == NULL)
                  swarn("%s: could not allocate memory for old shmids",
                        function);
               else {
                  size_t i;

                  sockscf.oldshmemv = tmpmem;

                  for (i = 0; i < moreoldshmemc; ++i) {
                     sockscf.oldshmemv[sockscf.oldshmemc++] = moreoldshmemv[i];

                     slog(LOG_DEBUG, "%s: saving shmid %ld for later",
                          function, moreoldshmemv[i].id);
                  }
               }
            }
         }

         next = rule->next;
         free(rule);
         rule = next;
      }
   }

   sockscf.crule = NULL;
   sockscf.srule = NULL;

   if (ismainmother && exiting) {
      /*
       * Go through the list of saved segments and delete them.
       * Any (io) children using them should already have them open,
       * and nobody not already using them should need to attach to them
       * after we exit.  The exception is udp-clients in barefoot, but
       * we remove all the udp clients when mother exits, so we just need
       * to cope with the possible failure in the time frame between
       * mother exiting and deleting the segments, and the io-child
       * detecting it.
       */

      slog(LOG_DEBUG, "%s: %ld old shmem entr%s saved.  Deleting now",
                      function, (unsigned long)sockscf.oldshmemc,
                      sockscf.oldshmemc == 1 ? "y" : "ies");

      for (oldc = 0; oldc < sockscf.oldshmemc; ++oldc) {
         char fname[PATH_MAX];

         snprintf(fname, sizeof(fname), "%s",
                  sockd_getshmemname(sockscf.oldshmemv[oldc].id));

         slog(LOG_INFO, "%s: deleting shmem segment %ld in file %s",
              function, sockscf.oldshmemv[oldc].id, fname);

         if (unlink(fname) != 0)
            swarn("%s: failed to unlink shmem segment %ld in file %s",
                  function, sockscf.oldshmemv[oldc].id, fname);
      }
   }

   /* and routes. */
   route = sockscf.route;
   while (route != NULL) {
      route_t *next = route->next;

      free(route->socketoptionv);
      route->socketoptionv = NULL;
      route->socketoptionc = 0;

      free(route);
      route = next;
   }
   sockscf.route = NULL;

   /* routeoptions, read from config file. */
   bzero(&sockscf.routeoptions, sizeof(sockscf.routeoptions));

   /* compat, read from config file. */
   bzero(&sockscf.compat, sizeof(sockscf.compat));

   /* extensions, read from config file. */
   bzero(&sockscf.extension, sizeof(sockscf.extension));

   /* log; read from config file, but keep lockfile (sockscf.loglock). */
   for (i = 0; i < sockscf.log.filenoc; ++i) {
      free(sockscf.log.fnamev[i]);

      if (!FD_IS_RESERVED_EXTERNAL(sockscf.log.filenov[i]))
         close(sockscf.log.filenov[i]);
   }
   free(sockscf.log.fnamev);
   free(sockscf.log.filenov);
   bzero(&sockscf.log, sizeof(sockscf.log));

   for (i = 0; i < sockscf.errlog.filenoc; ++i) {
      free(sockscf.errlog.fnamev[i]);

      if (!FD_IS_RESERVED_EXTERNAL(sockscf.errlog.filenov[i]))
         close(sockscf.errlog.filenov[i]);
   }
   free(sockscf.errlog.fnamev);
   free(sockscf.errlog.filenov);
   bzero(&sockscf.errlog, sizeof(sockscf.errlog));

   /*
    * option; some only settable at commandline, some only read from config file.
    * Those only read from config file will be reset to default in optioninit().
    */

   /* resolveprotocol, read from config file. */
   bzero(&sockscf.resolveprotocol, sizeof(sockscf.resolveprotocol));

   /*
    * socketconfig, read from config file, but also has defaults set by
    * optioninit(), so don't need to touch it.
    */

   /* srchost, read from config file. */
   bzero(&sockscf.srchost, sizeof(sockscf.srchost));

   /* stat: keep it. */

   /* state; keep it. */

#if HAVE_SOLARIS_PRIVS
   /* uid; need to clear, but need to reopen config file first. */
#endif /* HAVE_SOLARIS_PRIVS */

   /* methods, read from config file. */
   bzero(sockscf.methodv, sizeof(sockscf.methodv));
   sockscf.methodc = 0;

   bzero(sockscf.clientmethodv, sizeof(sockscf.clientmethodv));
   sockscf.clientmethodc = 0;

   /* timeout, read from config file. */
   bzero(&sockscf.timeout, sizeof(sockscf.timeout));

   /* childstate, most read from config file, but some not. */
   bzero(&sockscf.child.maxidle, sizeof(sockscf.child.maxidle));
}

int
addrisbindable(addr)
   const ruleaddr_t *addr;
{
   const char *function = "addrisbindable()";
   struct sockaddr_storage saddr;
   char saddrs[MAX(MAXSOCKSHOSTSTRING, MAXSOCKADDRSTRING)];
   int s;

   if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      swarn("%s: socket(SOCK_STREAM)", function);
      return 0;
   }

   switch (addr->atype) {
      case SOCKS_ADDR_IPV4: {
         sockshost_t host;

         sockshost2sockaddr(ruleaddr2sockshost(addr, &host, SOCKS_TCP),
                            TOSA(&saddr));

         if (sockd_bind(s, TOSA(&saddr), 0) != 0) {
            swarn("%s: can't bind address: %s",
            function, sockaddr2string(TOSA(&saddr), saddrs, sizeof(saddrs)));

            close(s);
            return 0;
         }
         break;
      }

      case SOCKS_ADDR_IFNAME:
         if (ifname2sockaddr(addr->addr.ifname, 0, TOSA(&saddr), NULL) == NULL) {
            swarnx("%s: can't find interface named %s with ip configured",
            function, addr->addr.ifname);

            close(s);
            return 0;
         }

         if (sockd_bind(s, TOSA(&saddr), 0) != 0) {
            swarn("%s: can't bind address %s of interface %s",
            function, sockaddr2string(TOSA(&saddr), saddrs, sizeof(saddrs)),
            addr->addr.ifname);

            close(s);
            return 0;
         }
         break;

      case SOCKS_ADDR_DOMAIN: {
         sockshost_t host;

         sockshost2sockaddr(ruleaddr2sockshost(addr, &host, SOCKS_TCP), TOSA(&saddr));
         if (!ADDRISBOUND(TOIN(&saddr)))
            serrx(EXIT_FAILURE, "%s can not resolve host %s",
            function, sockshost2string(&host, NULL, 0));

         if (sockd_bind(s, TOSA(&saddr), 0) != 0) {
            swarn("%s: can't bind address %s from hostname %s",
            function, sockaddr2string(TOSA(&saddr), saddrs, sizeof(saddrs)),
            addr->addr.domain);

            close(s);
            return 0;
         }
         break;
      }

      default:
         SERRX(addr->atype);
   }

   close(s);
   return 1;
}

int
isreplycommandonly(command)
   const command_t *command;
{

   if ((command->bindreply || command->udpreply)
   && !(command->connect || command->bind || command->udpassociate))
      return 1;

   return 0;
}

ssize_t
addrindex_on_listenlist(listc, listv, addr, protocol)
   const size_t listc;
   const listenaddress_t *listv;
   const struct sockaddr *addr;
   const int protocol;
{
   size_t i;

   for (i = 0; i < listc; ++i) {
      if (listv[i].protocol != protocol)
         continue;

      if (sockaddrareeq(addr, TOCSA(&listv[i].addr)))
         return (ssize_t)i;
   }

   return (ssize_t)-1;
}

ssize_t
addrindex_on_externallist(external, _addr)
   const externaladdress_t *external;
   const struct in_addr _addr;
{
   const char *function = "addrindex_on_externallist()";
   size_t i;
   struct sockaddr_storage sa, addr;

   bzero(&addr, sizeof(addr));
   SET_SOCKADDR(TOSA(&addr), AF_INET);
   TOIN(&addr)->sin_addr   = _addr;
   TOIN(&addr)->sin_port   = htons(0);

   for (i = 0; i < external->addrc; ++i) {
      switch (external->addrv[i].atype) {
         case SOCKS_ADDR_IPV4: {
            sockshost_t host;

            sockshost2sockaddr(ruleaddr2sockshost(&external->addrv[i], &host,
                                                 SOCKS_TCP),
                               TOSA(&sa));

            if (sockaddrareeq(TOSA(&addr), TOSA(&sa)))
               return (ssize_t)i;

            break;
         }
         case SOCKS_ADDR_DOMAIN: {
            size_t ii;

            ii = 0;
            while (hostname2sockaddr(external->addrv[i].addr.domain, ii++, TOSA(&sa))
            != NULL)
               if (sockaddrareeq(TOSA(&addr), TOSA(&sa)))
                  return (ssize_t)i;

            break;
         }

         case SOCKS_ADDR_IFNAME: {
            size_t ii;

            ii = 0;
            while (ifname2sockaddr(external->addrv[i].addr.domain, ii++, TOSA(&sa),
            NULL) != NULL)
               if (sockaddrareeq(TOSA(&addr), TOSA(&sa)))
                  return (ssize_t)i;

            break;
         }

         default:
            SERRX(external->addrv[i].atype);
      }
   }

   return (ssize_t)-1;
}
