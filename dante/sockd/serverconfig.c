/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009
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

#include "ifaddrs_compat.h"
#include "config_parse.h"

static const char rcsid[] =
"$Id: serverconfig.c,v 1.305 2009/10/27 12:04:22 karls Exp $";

static void
showlist(const struct linkedname_t *list, const char *prefix);
/*
 * shows user names in "list".
 */

static void
showlog(const struct log_t *log);
/*
 * shows what type of logging is specified in "log".
 */

#if HAVE_LIBWRAP
   extern jmp_buf tcpd_buf;

static void
libwrapinit(int s, struct request_info *request);
/*
 * Initializes "request" for later usage via libwrap.
 */

static int
connectisok(struct request_info *request, const struct rule_t *rule);
#else /* !HAVE_LIBWRAP */
static int
connectisok(void *request, const struct rule_t *rule);
#endif /* !HAVE_LIBWRAP */
/*
 * Checks the connection on "s".
 * "rule" is the rule that matched the connection.
 * This function should be called after each rulecheck for a new
 * connection/packet.
 *
 * Returns:
 *      If connection is acceptable: true
 *      If connection is not acceptable: false
 */

static struct rule_t *
addrule(const struct rule_t *newrule, struct rule_t **rulebase,
        const int isclientrule);
/*
 * Appends a copy of "newrule" to "rulebase", setting sensible
 * defaults where appropriate.
 * If "client" is true, "newrule" is a clientrule.
 * Returns a pointer to the added rule (not "newrule").
 */

static void
checkrule(const struct rule_t *rule, const int isclientrule);
/*
 * Check that the rule "rule" makes sense.
 * If "isclientrule" is true, "rule" is a client-rule.  Otherwise,
 * it's a socks-rule.
 */

struct config_t sockscf;
const int socks_configtype = CONFIGTYPE_SERVER;

#if HAVE_LIBWRAP
int allow_severity, deny_severity;
#endif /* HAVE_LIBWRAP */

/* expand array by one, increment argc. */
#define NEWINTERNAL_EXTERNAL(argc, argv)                       \
do {                                                           \
   if ((argv = realloc(argv, sizeof(*argv) * ++argc)) == NULL) \
      yyerror(NOMEM);                                          \
   bzero(&argv[argc - 1], sizeof(*argv));                      \
} while (/*CONSTCOND*/0)

void
addinternal(addr)
   const struct ruleaddr_t *addr;
{

   if (sockscf.state.init) {
#if 0 /* XXX don't know how to do this now, seems like too much work. */
      int i;

      for (i = 0; i < sockscf.internalc; ++i)
         if (memcmp(&sockscf.internalv[i], addr, sizeof(addr)) == 0)
            break;

      if (i == sockscf.internalc)
         swarnx("can't change internal addresses once running");
#endif
   }
   else
      switch (addr->atype) {
         case SOCKS_ADDR_IPV4: {
            struct sockshost_t host;

            NEWINTERNAL_EXTERNAL(sockscf.internalc, sockscf.internalv);

            sockshost2sockaddr(ruleaddr2sockshost(addr, &host, SOCKS_TCP),
            &sockscf.internalv[sockscf.internalc - 1].addr);
            break;
         }

         case SOCKS_ADDR_DOMAIN: {
            struct sockaddr sa;
            int i;

            i = 0;
            while (hostname2sockaddr(addr->addr.domain, i, &sa) != NULL) {
               NEWINTERNAL_EXTERNAL(sockscf.internalc,
               sockscf.internalv);

               /* LINTED pointer casts may be troublesome */
               TOIN(&sa)->sin_port = addr->port.tcp;
               sockscf.internalv[sockscf.internalc - 1].addr = sa;
               ++i;
            }

            if (i == 0)
               yyerror("could not resolve name %s: %s",
               addr->addr.domain, hstrerror(h_errno));
            break;
         }

         case SOCKS_ADDR_IFNAME: {
            struct ifaddrs *ifap, *iface;
            int m;

            if (getifaddrs(&ifap) != 0)
               serr(EXIT_FAILURE, "getifaddrs()");

            for (m = 0, iface = ifap; iface != NULL; iface = iface->ifa_next)
               if (strcmp(iface->ifa_name, addr->addr.ifname) == 0
               && iface->ifa_addr != NULL
               && iface->ifa_addr->sa_family == AF_INET) {
                  NEWINTERNAL_EXTERNAL(sockscf.internalc,
                  sockscf.internalv);

                  /* LINTED pointer casts may be troublesome */
                  TOIN(iface->ifa_addr)->sin_port = addr->port.tcp;

                  sockscf.internalv[sockscf.internalc - 1].addr
                  = *iface->ifa_addr;

                  m = 1;
               }
            freeifaddrs(ifap);

            if (!m)
               yyerror("can't find interface/address: %s", addr->addr.ifname);
            break;
         }

         default:
            SERRX(addr->atype);
      }
}

void
addexternal(addr)
   const struct ruleaddr_t *addr;
{

   switch (addr->atype) {
         case SOCKS_ADDR_DOMAIN: {
            struct sockaddr sa;
            int i;

            i = 0;
            while (hostname2sockaddr(addr->addr.domain, i, &sa) != NULL) {
               NEWINTERNAL_EXTERNAL(sockscf.external.addrc,
               sockscf.external.addrv);

               /* LINTED pointer casts may be troublesome */
               TOIN(&sa)->sin_port = addr->port.tcp;
               sockaddr2ruleaddr(&sa,
               &sockscf.external.addrv[sockscf.external.addrc - 1]);
               ++i;
            }

            if (i == 0)
               yyerror("could not resolve name %s: %s",
               addr->addr.domain, hstrerror(h_errno));
            break;
         }

      case SOCKS_ADDR_IPV4: {
         if (addr->addr.ipv4.ip.s_addr == htonl(INADDR_ANY))
            yyerror("external address (%s) can't be a wildcard address",
            ruleaddr2string(addr, NULL, 0));

         NEWINTERNAL_EXTERNAL(sockscf.external.addrc,
         sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         sockscf.external.addrv[sockscf.external.addrc - 1]
         .addr.ipv4.mask.s_addr = htonl(0xffffffff);

         break;

      case SOCKS_ADDR_IFNAME:
         NEWINTERNAL_EXTERNAL(sockscf.external.addrc,
         sockscf.external.addrv);
         sockscf.external.addrv[sockscf.external.addrc - 1] = *addr;
         break;
      }

      default:
         SERRX(addr->atype);
   }
}

struct rule_t *
addclientrule(newrule)
   const struct rule_t *newrule;
{
   struct rule_t *rule, ruletoadd;

   ruletoadd = *newrule; /* for const. */

   rule = addrule(&ruletoadd, &sockscf.crule, 1);

   checkrule(rule, 1);

#if BAREFOOTD
   /*
    * Barefoot only has client-rules, so auto-add a socks-rule(s) that
    * matches the given client-rule.
    */
   if (rule->state.protocol.udp) {
      struct rule_t srule;

      /* most things in the socks-rule are the same. */
      srule = *rule;

      bzero(&srule.state.protocol, sizeof(srule.state.protocol));
      bzero(&srule.state.command, sizeof(srule.state.command));

      srule.state.protocol.udp         = 1;

      /* add a rule for letting the packet from the client out ... */
      srule.bounced                    = 0;
      srule.dst                        = rule->bounce_to;
      srule.state.command.udpassociate = 1;
      srule.ss                         = rule->ss;
      rule->ss = NULL;

      srule.crule = rule; /* need to know which crule generated this srule. */

      addsocksrule(&srule);

      /* ... and a rule allowing the reply back in. */

      bzero(&srule.state.command, sizeof(srule.state.command));

      srule.bounced = 1; /* reply-rule has no bounce to setup. */
      srule.ss = NULL;   /* only limiting on the client-side. */

      if (sockscf.option.udpconnectdst) /* only allow replies from dst. */
         srule.src = rule->bounce_to;
      else { /* allow replies from everyone. */
         bzero(&srule.src, sizeof(srule.src));
         srule.src.atype                         = SOCKS_ADDR_IPV4;
         srule.src.addr.ipv4.ip.s_addr           = htonl(0);
         srule.src.addr.ipv4.mask.s_addr         = htonl(0);
         srule.src.port.tcp = srule.src.port.udp = htons(0);
      }

      if (rule->bw != NULL) {
         /*
          * need to duplicate it for reply-rule too.  Afterwards,
          * clear it from client-rule.  Copied to socks-rule, and only
          * needed there.
          */

         if ((srule.bw = malloc(sizeof(*srule.bw))) == NULL)
            yyerror(NOMEM);

         *srule.bw = *rule->bw;
         rule->bw  = NULL;
      }

      if (rule->ss != NULL) {
         /*
          * move it from client-rule to socks-rule; barefoot has no
          * negotiation.  We could get the same result, but faster,
          * by keeping it in the client-rule and limit on that only,
          * but requires #ifdef code in the children.
          */

         srule.ss = rule->ss;
         rule->ss = NULL;
      }

      srule.dst                    = rule->src;
      srule.state.command.udpreply = 1;

      addsocksrule(&srule);
   }

   if (rule->state.protocol.tcp) {
      struct rule_t srule;

      /* most things in the socks-rule are the same. */
      srule = *rule;

      bzero(&srule.state.protocol, sizeof(srule.state.protocol));
      bzero(&srule.state.command, sizeof(srule.state.command));

      srule.state.protocol.tcp         = 1;
      srule.dst                        = rule->bounce_to;
      srule.state.command.connect      = 1;
      srule.ss                         = NULL; /* copied later, if needed. */
      /* record which crule generated this srule. */
      srule.crule                      = rule;

      if (rule->bw != NULL) { /* move to socks-rule, only needed there. */
         srule.bw = rule->bw;
         rule->bw = NULL;
      }

      if (rule->ss != NULL) {
         /*
          * move it from client-rule to socks-rule; barefoot has no
          * negotiation.  We could get the same result, but faster,
          * by keeping it in the client-rule and limit on that only,
          * but requires #ifdef code in the children.
          */

         srule.ss = rule->ss;
         rule->ss = NULL;
      }

      addsocksrule(&srule);
   }
#endif /* BAREFOOTD */

   return rule;
}

struct rule_t *
addsocksrule(newrule)
   const struct rule_t *newrule;
{
   struct rule_t *rule;

   rule = addrule(newrule, &sockscf.srule, 0);
   checkrule(rule, 0);

   /* LINTED cast discards 'const' from pointer target type */
   return (struct rule_t *)rule;
}

struct linkedname_t *
addlinkedname(linkedname, name)
   struct linkedname_t **linkedname;
   const char *name;
{
   struct linkedname_t *user, *last;

   for (user = *linkedname, last = NULL; user != NULL; user = user->next)
      last = user;

   if ((user = malloc(sizeof(*user))) == NULL)
      return NULL;

   if ((user->name = strdup(name)) == NULL) {
      free(user);
      return NULL;
   }

   user->next = NULL;

   if (*linkedname == NULL)
      *linkedname = user;
   else
      last->next = user;

   return *linkedname;
}

void
showrule(rule)
   const struct rule_t *rule;
{
   char addr[MAXRULEADDRSTRING];

   slog(LOG_INFO, "socks-rule #%lu, line #%lu",
   (unsigned long)rule->number, (unsigned long)rule->linenumber);

   slog(LOG_INFO, "verdict: %s", verdict2string(rule->verdict));

   slog(LOG_INFO, "src: %s",
   ruleaddr2string(&rule->src, addr, sizeof(addr)));

   slog(LOG_INFO, "dst: %s",
   ruleaddr2string(&rule->dst, addr, sizeof(addr)));

   if (rule->udprange.op == range)
      slog(LOG_INFO, "udp port range: %u - %u",
      ntohs(rule->udprange.start), ntohs(rule->udprange.end));

   if (rule->rdr_from.addr.ipv4.ip.s_addr != htonl(INADDR_ANY))
      slog(LOG_INFO, "redirect from: %s",
      ruleaddr2string(&rule->rdr_from, addr, sizeof(addr)));

   if (rule->rdr_to.addr.ipv4.ip.s_addr != htonl(INADDR_ANY))
      slog(LOG_INFO, "redirect to: %s",
      ruleaddr2string(&rule->rdr_to, addr, sizeof(addr)));

   if (rule->bw != NULL)
      slog(LOG_INFO, "max bandwidth allowed: %ld B/s", rule->bw->maxbps);

   if (rule->ss != NULL)
      slog(LOG_INFO, "max sessions allowed: %d", rule->ss->maxsessions);

   showlist(rule->user, "user: ");
   showlist(rule->group, "group: ");

#if HAVE_PAM
   if (methodisset(AUTHMETHOD_PAM, rule->state.methodv, rule->state.methodc))
      slog(LOG_INFO, "pam.servicename: %s", rule->state.pamservicename);
#endif /* HAVE_PAM */

   showstate(&rule->state);
   showlog(&rule->log);

#if HAVE_LIBWRAP
   if (*rule->libwrap != NUL)
      slog(LOG_INFO, "libwrap: %s", rule->libwrap);
#endif /* HAVE_LIBWRAP */
}

void
showclient(rule)
   const struct rule_t *rule;
{
   char addr[MAXRULEADDRSTRING];

   slog(LOG_INFO, "client-rule #%lu, line #%lu",
   (unsigned long)rule->number, (unsigned long)rule->linenumber);

   slog(LOG_INFO, "verdict: %s", verdict2string(rule->verdict));

   slog(LOG_INFO, "src: %s",
   ruleaddr2string(&rule->src, addr, sizeof(addr)));

   slog(LOG_INFO, "dst: %s",
   ruleaddr2string(&rule->dst, addr, sizeof(addr)));

#if BAREFOOTD
   slog(LOG_INFO, "bounce to: %s",
   ruleaddr2string(&rule->bounce_to, addr, sizeof(addr)));
#endif /* BAREFOOTD */

   showmethod(rule->state.methodc, rule->state.methodv);

#if !BAREFOOTD
   showlist(rule->user, "user: ");
   showlist(rule->group, "group: ");
#endif /* !BAREFOOTD */

#if HAVE_PAM
   if (methodisset(AUTHMETHOD_PAM, rule->state.methodv, rule->state.methodc))
      slog(LOG_INFO, "pam.servicename: %s", rule->state.pamservicename);
#endif /* HAVE_PAM */

   showlog(&rule->log);
   showstate(&rule->state);

   if (rule->bw != NULL)
      slog(LOG_INFO, "max bandwidth allowed: %ld B/s", rule->bw->maxbps);

   if (rule->ss != NULL)
      slog(LOG_INFO, "max sessions allowed: %d", rule->ss->maxsessions);

#if HAVE_LIBWRAP
   if (*rule->libwrap != NUL)
      slog(LOG_INFO, "libwrap: %s", rule->libwrap);
#endif /* HAVE_LIBWRAP */
}

void
showconfig(sockscf)
   const struct config_t *sockscf;
{
   char address[MAXRULEADDRSTRING], buf[1024];
   size_t i, bufused;

   slog(LOG_DEBUG, "internal addresses (%lu):",
   (unsigned long)sockscf->internalc);
   for (i = 0; i < sockscf->internalc; ++i)
      slog(LOG_DEBUG, "\t%s",
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

   slog(LOG_DEBUG, "logoutput goes to: %s",
   logtypes2string(&sockscf->log, buf, sizeof(buf)));

   slog(LOG_DEBUG, "cmdline options:\n%s",
   options2string(&sockscf->option, "", buf, sizeof(buf)));

   slog(LOG_DEBUG, "resolveprotocol: %s",
   resolveprotocol2string(sockscf->resolveprotocol));

   slog(LOG_DEBUG, "direct route fallback: %s",
   sockscf->option.directfallback ? "enabled" : "disabled");

   slog(LOG_DEBUG, "srchost:\n%s",
   srchosts2string(&sockscf->srchost, "", buf, sizeof(buf)));

   slog(LOG_DEBUG, "negotiate timeout: %lds",
   (long)sockscf->timeout.negotiate);
   slog(LOG_DEBUG, "i/o timeout: tcp: %lds, udp: %lds",
   (long)sockscf->timeout.tcpio, (long)sockscf->timeout.udpio);

   slog(LOG_DEBUG, "euid: %d", sockscf->state.euid);

#if !HAVE_PRIVILEGES
   slog(LOG_DEBUG, "userid:\n%s",
   userids2string(&sockscf->uid, "", buf, sizeof(buf)));
#endif /* !HAVE_PRIVILEGES */

   slog(LOG_DEBUG, "child.maxidle: %d",
   sockscf->child.maxidle);

   bufused = snprintfn(buf, sizeof(buf), "method(s): ");
   for (i = 0; (size_t)i < sockscf->methodc; ++i)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s%s",
      i > 0 ? ", " : "", method2string(sockscf->methodv[i]));
   slog(LOG_DEBUG, buf);

   bufused = snprintfn(buf, sizeof(buf), "clientmethod(s): ");
   for (i = 0; (size_t)i < sockscf->clientmethodc; ++i)
      bufused += snprintfn(&buf[bufused], sizeof(buf) - bufused, "%s%s",
      i > 0 ? ", " : "", method2string(sockscf->clientmethodv[i]));
   slog(LOG_DEBUG, buf);

   if (sockscf->option.debug) {
      struct rule_t *rule;
      struct route_t *route;
      int count;

      for (count = 0, rule = sockscf->crule; rule != NULL; rule = rule->next)
         ++count;
      slog(LOG_DEBUG, "client-rules (%d): ", count);
      for (rule = sockscf->crule; rule != NULL; rule = rule->next)
         showclient(rule);

      for (count = 0, rule = sockscf->srule; rule != NULL; rule = rule->next)
         ++count;
      slog(LOG_DEBUG, "socks-rules (%d): ", count);
      for (rule = sockscf->srule; rule != NULL; rule = rule->next)
         showrule(rule);

      for (count = 0, route = sockscf->route; route != NULL;
      route = route->next)
         ++count;

      slog(LOG_DEBUG, "routes (%d): ", count);
      for (route = sockscf->route; route != NULL; route = route->next)
         socks_showroute(route);
   }
}

void
resetconfig(void)
{
   struct rule_t *rule;
   struct route_t *route;

   /*
    * internal; don't touch, only settable at start.
    */

   /* external addresses can be changed. */
   free(sockscf.external.addrv);
   sockscf.external.addrv = NULL;
   sockscf.external.addrc = 0;

   /* delete all old socks rules */
   rule = sockscf.srule;
   while (rule != NULL) {
      struct rule_t *next = rule->next;
      struct linkedname_t *user, *nextuser;

      user = rule->user;
      while (user != NULL) {
         nextuser = user->next;
         free(user);
         user = nextuser;
      }

      free(rule);
      rule = next;
   }
   sockscf.srule = NULL;

   /* clientrules too. */
   rule = sockscf.crule;
   while (rule != NULL) {
      struct rule_t *next = rule->next;
      struct linkedname_t *user, *nextuser;

      user = rule->user;
      while (user != NULL) {
         nextuser = user->next;
         free(user);
         user = nextuser;
      }

      free(rule);
      rule = next;
   }
   sockscf.crule = NULL;

   /* and routes. */
   route = sockscf.route;
   while (route != NULL) {
      struct route_t *next = route->next;

      free(route);
      route = next;
   }
   sockscf.route = NULL;

   /* compat, read from configfile. */
   bzero(&sockscf.compat, sizeof(sockscf.compat));

   /* extensions, read from configfile. */
   bzero(&sockscf.extension, sizeof(sockscf.extension));

   /* log; only settable at start. */

   /*
    * option; some only setable at commandline, some only read from configfile.
    * Those read from configfile will be reset to default in optioninit().
    */

   /* resolveprotocol, read from configfile. */
   bzero(&sockscf.resolveprotocol, sizeof(sockscf.resolveprotocol));

   /* srchost, read from configfile. */
   bzero(&sockscf.srchost, sizeof(sockscf.srchost));

   /* stat: keep it. */

   /* state; keep it. */

   /* methods, read from configfile. */
   bzero(sockscf.methodv, sizeof(sockscf.methodv));
   sockscf.methodc = 0;

   bzero(sockscf.clientmethodv, sizeof(sockscf.clientmethodv));
   sockscf.clientmethodc = 0;

   /* timeout, read from configfile. */
   bzero(&sockscf.timeout, sizeof(sockscf.timeout));

#if !HAVE_PRIVILEGES
   /* uid, read from configfile. */
   bzero(&sockscf.uid, sizeof(sockscf.uid));
#endif /* !HAVE_PRIVILEGES */

   /* childstate, most read from configfile, but some not. */
   sockscf.child.maxidle = 0;
}

void
iolog(rule, state, operation, src, srcauth, dst, dstauth, data, count)
   struct rule_t *rule;
   const struct connectionstate_t *state;
   int operation;
   const struct sockshost_t *src;
   const struct authmethod_t *srcauth;
   const struct sockshost_t *dst;
   const struct authmethod_t *dstauth;
   const char *data;
   size_t count;
{
   /* CONSTCOND */
   char srcstring[MAXSOCKSHOSTSTRING + MAXAUTHINFOLEN];
   char dststring[sizeof(srcstring)];
   char rulecommand[256];
   int p;

   authinfo(srcauth, srcstring, sizeof(srcstring));
   p = strlen(srcstring);
   sockshost2string(src, &srcstring[p], sizeof(srcstring) - p);

   authinfo(dstauth, dststring, sizeof(dststring));
   p = strlen(dststring);
   sockshost2string(dst, &dststring[p], sizeof(dststring) - p);

   snprintfn(rulecommand, sizeof(rulecommand), "%s(%lu): %s/%s",
   verdict2string(rule->verdict),
   (unsigned long)rule->number,
   protocol2string(state->protocol),
   command2string(state->command));

   switch (operation) {
      case OPERATION_ACCEPT:
      case OPERATION_CONNECT:
         if (rule->log.connect)
            slog(LOG_INFO, "%s [: %s -> %s%s%s",
            rulecommand, srcstring, dststring,
            (data == NULL || *data == NUL) ? "" : ": ",
            (data == NULL || *data == NUL) ? "" : data);
         break;

      case OPERATION_ABORT:
         if (rule->log.disconnect || rule->log.error)
            slog(LOG_INFO, "%s ]: %s -> %s: %s",
            rulecommand, srcstring, dststring,
            (data == NULL || *data == NUL) ? strerror(errno) : data);
         break;

      case OPERATION_ERROR:
         if (rule->log.error)
            slog(LOG_INFO, "%s ]: %s -> %s: %s",
            rulecommand, srcstring, dststring,
            (data == NULL || *data == NUL) ? strerror(errno) : data);
         break;

      case OPERATION_TMPERROR:
         if (rule->log.error)
            slog(LOG_INFO, "%s -: %s -> %s: %s",
            rulecommand, srcstring, dststring,
            (data == NULL || *data == NUL) ? strerror(errno) : data);
         break;

      case OPERATION_IO:
         if (rule->log.data && count != 0) {
            char visdata[SOCKD_BUFSIZE * 4 + 1];

            slog(LOG_INFO, "%s -: %s -> %s (%lu): %s",
            rulecommand, srcstring, dststring, (unsigned long)count,
            str2vis(data, count, visdata, sizeof(visdata)));

            break;
         }

         if (rule->log.iooperation || rule->log.data)
            slog(LOG_INFO, "%s -: %s -> %s (%lu)",
            rulecommand, srcstring, dststring, (unsigned long)count);
         break;

      default:
         SERRX(operation);
   }
}

int
rulespermit(s, peer, local, clientauth, match, srcauth, state,
            src, dst, msg, msgsize)
   int s;
   const struct sockaddr *peer, *local;
   struct authmethod_t *clientauth;
   struct rule_t *match;
   struct authmethod_t *srcauth;
   const struct connectionstate_t *state;
   const struct sockshost_t *src;
   const struct sockshost_t *dst;
   char *msg;
   size_t msgsize;
{
   const char *function = "rulespermit()";
   static int init;
   static struct rule_t defrule;
   struct rule_t *rule;
   struct authmethod_t oldauth;
   int *methodv, methodc;
#if HAVE_LIBWRAP
   struct request_info libwraprequest;

   libwrapinit(s, &libwraprequest);
#else /* !HAVE_LIBWRAP */
   void *libwraprequest = NULL;
#endif /* !HAVE_LIBWRAP */

   /* make a somewhat sensible default rule for entries with no match. */
   if (!init) {
      defrule.verdict                     = VERDICT_BLOCK;
      defrule.number                      = 0;

      defrule.src.atype                   = SOCKS_ADDR_IPV4;
      defrule.src.addr.ipv4.ip.s_addr     = htonl(INADDR_ANY);
      defrule.src.addr.ipv4.mask.s_addr   = htonl(0);
      defrule.src.port.tcp                = htons(0);
      defrule.src.port.udp                = htons(0);
      defrule.src.portend                 = htons(0);
      defrule.src.operator                = none;

      defrule.dst                         = defrule.src;

      memset(&defrule.log, 0, sizeof(defrule.log));
      defrule.log.connect     = 1;
      defrule.log.iooperation = 1; /* blocked iooperations. */

      if (sockscf.option.debug) {
         defrule.log.disconnect = 1;
         defrule.log.error      = 1;
      }

      memset(&defrule.state.command, UCHAR_MAX, sizeof(defrule.state.command));

      defrule.state.methodc = 0;

      memset(&defrule.state.protocol, UCHAR_MAX,
      sizeof(defrule.state.protocol));

      memset(&defrule.state.proxyprotocol, UCHAR_MAX,
      sizeof(defrule.state.proxyprotocol));

#if HAVE_LIBWRAP
      *defrule.libwrap = NUL;
#endif /* HAVE_LIBWRAP */

      init = 1;
   }

   if (src != NULL)
      slog(LOG_DEBUG, "%s: src is %s\n",
      function, sockshost2string(src, NULL, 0));

   if (dst != NULL)
      slog(LOG_DEBUG, "%s: dst is %s\n",
      function, sockshost2string(dst, NULL, 0));

   if (state->extension.bind && !sockscf.extension.bind) {
      snprintf(msg, msgsize, "client requested disabled extension: bind");
      *match         = defrule;
      match->verdict = VERDICT_BLOCK;

      return 0; /* will never succeed. */
   }

   if (msgsize > 0)
      *msg = NUL;

   /* what rulebase to use. */
   switch (state->command) {
      case SOCKS_ACCEPT:
         /* clientrule. */
         rule      = sockscf.crule;
         methodv   = sockscf.clientmethodv;
         methodc   = sockscf.clientmethodc;
         break;

      default:
         /* everyone else, socksrules. */
         rule      = sockscf.srule;
         methodv   = sockscf.methodv;
         methodc   = sockscf.methodc;
         break;
   }

   /*
    * let srcauth be unchanged from original unless we actually get a match.
    */
   for (oldauth = *srcauth;
   rule != NULL;
   rule = rule->next, *srcauth = oldauth) {
      int i;

      /* current rule covers desired command? */
      switch (state->command) {
         /* client-rule commands. */
         case SOCKS_ACCEPT:
            break;

         /* socks-rule commands. */
         case SOCKS_BIND:
            if (!rule->state.command.bind)
               continue;
            break;

         case SOCKS_CONNECT:
            if (!rule->state.command.connect)
               continue;
            break;

         case SOCKS_UDPASSOCIATE:
            if (!rule->state.command.udpassociate)
               continue;
            break;

         /* pseudo commands. */

         case SOCKS_BINDREPLY:
            if (!rule->state.command.bindreply)
               continue;
            break;

         case SOCKS_UDPREPLY:
            if (!rule->state.command.udpreply)
               continue;
            break;

         default:
            SERRX(state->command);
      }

      /* current rule covers desired protocol? */
      switch (state->protocol) {
         case SOCKS_TCP:
            if (!rule->state.protocol.tcp)
               continue;
            break;

         case SOCKS_UDP:
            if (!rule->state.protocol.udp)
               continue;
            break;

         default:
            SERRX(state->protocol);
      }

      /* current rule covers desired version? */
      if (state->command != SOCKS_ACCEPT) /* no version possible for accept. */
         switch (state->version) {
            case PROXY_SOCKS_V4:
               if (!rule->state.proxyprotocol.socks_v4)
                  continue;
               break;

            case PROXY_SOCKS_V5:
               if (!rule->state.proxyprotocol.socks_v5)
                  continue;
               break;

            default:
               SERRX(state->version);
         }

      /*
       * This is a little tricky.  For some commands we may not have
       * all info at time of (preliminary) rulechecks.  What we want
       * to do if there is no (complete) address given is to see if
       * there's any chance at all the rules will permit this request
       * when the address (later) becomes available.  We therefore
       * continue to scan the rules until we either get a pass
       * (ignoring peer with missing info), or the default block is
       * triggered.
       *
       * This is the case for e.g. bindreply and udp, where we will
       * have to call this function again when we get the addresses in
       * question.
       */

      /*
       * XXX why addrmatch() without alias?
       * If e.g. /etc/hosts has localhost localhost.example.com,
       * we fail to match 127.0.0.1 against localhost.example.com.
       */
      if (src != NULL) {
         if (!addrmatch(&rule->src, src, state->protocol, 0))
            continue;
      }
      else
         if (rule->verdict == VERDICT_BLOCK)
            continue; /* don't have complete address. */

      if (dst != NULL) {
          if (!addrmatch(&rule->dst, dst, state->protocol, 0))
            continue;
      }
      else
         if (rule->verdict == VERDICT_BLOCK)
            continue; /* don't have complete address. */

      /*
       * Does this rule's authentication match authentication in use?
       */
      if ((state->command == SOCKS_BINDREPLY
        || state->command == SOCKS_UDPREPLY)
      && !sockscf.srchost.checkreplyauth) {
         /*
          * To be consistent, we should insist that the user specifies
          * authmethod none for replies, unless he really wants to use
          * an authmethod in these cases also, which is possible (e.g.
          * method rfc931, or ip-only based pam), though probably
          * extremely unlikely.
          *
          * That can make the configfile look weird though; if the
          * user e.g. wants all access to be password-authenticated,
          * and thus specifies method "uname" on the global
          * method-line, he can not do that without also adding method
          * "none", as the global method-line is a superset of the
          * methods specified in the individual rules.  That means he
          * then needs to set the method on a rule-by-rule basis;
          * "none" for replies, and "username" for all others.  With
          * more than a few rules, this can become quite a hassle, is
          * unexpected, and only needed because the server supports
          * this probably quite unusual and rarely used feature.
          *
          * We therefor try to be more user-friendly about this, so
          * unless "checkreplyauth" is set in "srchost:", assume
          * authmethod should not be checked for replies also.
          */
          srcauth->method = AUTHMETHOD_NONE; /* don't bother checking. */
      }
      else if (!methodisset(srcauth->method, rule->state.methodv,
      rule->state.methodc)) {
         /*
          * No.  There are however some methods which it's possible to get
          * a match on, even if above check failed.
          * I.e. it's possible to change/upgrade the method.
          * E.g. PAM is based on UNAME; if we have UNAME, we _may_ be
          * able to get PAM, using the data gotten in UNAME.
          *
          * We therefore look at what methods this rule wants and see
          * if can match it with what the client _can_ provide, if we
          * do some more work to get that information.
          *
          * Currently these methods are: gssapi (only during negotiation),
          * AUTHMETHOD_NOTSET, rfc931, and pam.
          */

         /*
          * This variable only says if current client has provided the
          * necessary information to check it's access with one of the
          * methods required by the current rule.  It does not mean the
          * information was checked.  I.e. if it's AUTHMETHOD_RFC931,
          * and methodischeckable is set, it means we were able to retrieve
          * rfc931 info, but not that we checked the retrieved information
          * against the passsword database.
          *
          * XXX would be nice to cache this, so we don't have to
          * copy memory around each time.
          */
         size_t methodischeckable = 0;

         for (i = 0; i < methodc; ++i) {
            if (methodisset(methodv[i], rule->state.methodv,
            rule->state.methodc)) {
               slog(LOG_DEBUG, "%s: trying to find match for %s, "
                               "for command %s ...",
                               function, method2string(methodv[i]),
                               command2string(state->command));

               switch (methodv[i]) {
                  case AUTHMETHOD_NONE:
                     methodischeckable = 1; /* anything is good enough. */
                     break;

#if HAVE_LIBWRAP
                  case AUTHMETHOD_RFC931:
                     if (clientauth        != NULL
                     && clientauth->method == AUTHMETHOD_RFC931) {
                        slog(LOG_DEBUG, "%s: already have rfc931 name %s from "
                                        "clientauthentication done before",
                                        function,
                                        clientauth->mdata.rfc931.name);

                        srcauth->mdata.rfc931 = clientauth->mdata.rfc931;
                     }
                     else { /* need to do a tcp lookup. */
                        slog(LOG_DEBUG, "%s: doing a tcp lookup to get rfc931 "
                                        "name ...",
                                        function);


                        strncpy((char *)srcauth->mdata.rfc931.name,
                        eval_user(&libwraprequest),
                        sizeof(srcauth->mdata.rfc931.name) - 1);

                        /* libwrap sets it to unknown if no identreply. */
                        if (strcmp((char *)srcauth->mdata.rfc931.name,
                        STRING_UNKNOWN) == 0) {
                           *srcauth->mdata.rfc931.name = NUL;
                           slog(LOG_DEBUG, "%s: no rfc931 name", function);
                        }
                        else if (srcauth->mdata.rfc931.name[
                        sizeof(srcauth->mdata.rfc931.name) - 1] != NUL) {
                           srcauth->mdata.rfc931.name[
                              sizeof(srcauth->mdata.rfc931.name) - 1] = NUL;

                           swarnx("%s: rfc931 name \"%s\" truncated",
                           function, srcauth->mdata.rfc931.name);

                           *srcauth->mdata.rfc931.name = NUL; /* unusable */
                        }
                     }

                     if (*srcauth->mdata.rfc931.name != NUL)
                        methodischeckable = 1;
                     break;
#endif /* HAVE_LIBWRAP */

#if HAVE_PAM
                  case AUTHMETHOD_PAM:
                     /*
                      * PAM can support username/password, just username,
                      * or neither username nor password (i.e. based on
                      * only ip address).
                      */
                     switch (srcauth->method) {
                        case AUTHMETHOD_UNAME: {
                           /* it's a union, make a copy first. */
                           const struct authmethod_uname_t uname
                           = srcauth->mdata.uname;

                           /*
                            * similar enough, just copy name/password.
                            */

                           strcpy((char *)srcauth->mdata.pam.name,
                           (const char *)uname.name);

                           strcpy((char *)srcauth->mdata.pam.password,
                           (const char *)uname.password);

                           methodischeckable = 1;
                           break;
                        }

#if HAVE_LIBWRAP
                        case AUTHMETHOD_RFC931: {
                             /* it's a union, make a copy first. */
                             const struct authmethod_rfc931_t rfc931
                             = srcauth->mdata.rfc931;

                            /*
                             * no password, but we can check for the username
                             * we got from ident, with an empty password.
                             */

                            strcpy((char *)srcauth->mdata.pam.name,
                            (const char *)rfc931.name);

                           *srcauth->mdata.pam.password = NUL;

                           methodischeckable = 1;
                           break;
                        }
#endif /* HAVE_LIBWRAP */

                        case AUTHMETHOD_NOTSET:
                        case AUTHMETHOD_NONE:
                           /*
                            * PAM can also support no username/password.
                            */

                           *srcauth->mdata.pam.name     = NUL;
                           *srcauth->mdata.pam.password = NUL;

                           methodischeckable = 1;
                           break;

                     }

                     strcpy(srcauth->mdata.pam.servicename,
                     rule->state.pamservicename);

                     break;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
                  case AUTHMETHOD_GSSAPI:
                     /*
                      * GSSAPI can only be checked/established during
                      * negotiation (command = SOCKS_ACCEPT).
                      * After that stage has completed, we either have
                      * it or we don't.
                      */
                     if (state->command != SOCKS_ACCEPT)
                        continue;

                     strcpy(srcauth->mdata.gssapi.servicename,
                     rule->state.gssapiservicename);

                     strcpy(srcauth->mdata.gssapi.keytab,
                     rule->state.gssapikeytab);

                     srcauth->mdata.gssapi.encryption.nec
                     = rule->state.gssapiencryption.nec;

                     srcauth->mdata.gssapi.encryption.clear
                     = rule->state.gssapiencryption.clear;

                     srcauth->mdata.gssapi.encryption.integrity
                     = rule->state.gssapiencryption.integrity;

                     srcauth->mdata.gssapi.encryption.confidentiality
                     = rule->state.gssapiencryption.confidentiality;

                     methodischeckable = 1;
                     break;
#endif /* HAVE_GSSAPI */
               }

               if (methodischeckable) {
                  slog(LOG_DEBUG, "%s: changing authmethod from %d to %d",
                  function, srcauth->method, methodv[i]);

                  srcauth->method = methodv[i]; /* changing method. */
                  break;
               }
            }
         }

         if (i == methodc)
            /*
             * current rules methods differs from what client can
             * provide us with.  Go to next rule.
             */
            continue;
      }

      SASSERTX(state->command == SOCKS_BINDREPLY
      ||       state->command == SOCKS_UDPREPLY
      ||       methodisset(srcauth->method, rule->state.methodv,
                           rule->state.methodc));

      if (srcauth->method != AUTHMETHOD_NONE && rule->user != NULL) {
         /* rule requires user.  Covers current? */
         if (!usermatch(srcauth, rule->user)) {
            slog(LOG_DEBUG,
            "%s: username \"%s\" did not match rule #%lu for command %s",
            function,
            authname(srcauth) == NULL ? "<null>" : authname(srcauth),
            (unsigned long)rule->number,
            command2string(state->command));

            continue; /* no match. */
         }
      }

      if (srcauth->method != AUTHMETHOD_NONE && rule->group != NULL) {
         /* rule requires group.  Current included? */
         if (!groupmatch(srcauth, rule->group)) {
            slog(LOG_DEBUG,
            "%s: groupname \"%s\" did not match rule #%lu for command %s",
            function,
            authname(srcauth) == NULL ? "<null>" : authname(srcauth),
            (unsigned long)rule->number,
            command2string(state->command));

            continue; /* no match. */
         }
      }

      /* last step.  Does the authentication match? */
      i = accesscheck(s, srcauth, peer, local, msg, msgsize);

      /*
       * two fields we want to copy.  This is to speed things up so
       * we don't re-check the same method.
      */
      memcpy(oldauth.methodv, srcauth->methodv,
      srcauth->methodc * sizeof(*srcauth->methodv));

      oldauth.methodc = srcauth->methodc;
      memcpy(oldauth.badmethodv, srcauth->badmethodv,
      srcauth->badmethodc * sizeof(*srcauth->badmethodv));

      oldauth.badmethodc = srcauth->badmethodc;

      if (!i) {
         *match         = defrule;
         match->verdict = VERDICT_BLOCK;

         return 0;
      }

      break;
   }

   if (rule == NULL) /* no rules matched; match default rule. */
      rule = &defrule;

   *match = *rule;

   /*
    * got our rule, now check connection.  Connectioncheck
    * requires the rule matched so needs to be delayed til here.
    */

   if (!connectisok(&libwraprequest, match))
      match->verdict = VERDICT_BLOCK;

   return match->verdict == VERDICT_PASS;
}

const char *
authname(auth)
   const struct authmethod_t *auth;
{

   if (auth == NULL)
      return NULL;

   switch (auth->method) {
      case AUTHMETHOD_NOTSET:
      case AUTHMETHOD_NONE:
      case AUTHMETHOD_NOACCEPT: /* closing connection next presumably. */
         return NULL;

      case AUTHMETHOD_UNAME:
         return (const char *)auth->mdata.uname.name;

#if HAVE_LIBWRAP
      case AUTHMETHOD_RFC931:
         return (const char *)auth->mdata.rfc931.name;
#endif /* HAVE_LIBWRAP */

#if HAVE_PAM
      case AUTHMETHOD_PAM:
         return (const char *)auth->mdata.pam.name;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
      case AUTHMETHOD_GSSAPI:
         return (const char *)auth->mdata.gssapi.name;
#endif /* HAVE_GSSAPI */

      default:
         SERRX(auth->method);
   }

   /* NOTREACHED */
}

const char *
authinfo(auth, info, infolen)
   const struct authmethod_t *auth;
   char *info;
   size_t infolen;
{
   const char *name, *method, *methodinfo = NULL;

   if (auth != NULL) {
      name   = authname(auth);
      method = method2string(auth->method);

#if HAVE_GSSAPI
      if (auth->method == AUTHMETHOD_GSSAPI)
         methodinfo
         = gssapiprotection2string(auth->mdata.gssapi.state.protection);
#endif /* HAVE_GSSAPI */
   }
   else
      name = method = NULL;

   if (name == NULL || *name == NUL)
      *info = NUL;
   else
      snprintfn(info, infolen, "%s%s%s%%%s@",
                method,
                methodinfo == NULL ? "" : "/",
                methodinfo == NULL ? "" : methodinfo,
                name);

   return info;
}

int
addressisbindable(addr)
   const struct ruleaddr_t *addr;
{
   const char *function = "addressisbindable()";
   struct sockaddr saddr;
   char saddrs[MAX(MAXSOCKSHOSTSTRING, MAXSOCKADDRSTRING)];
   int s;

   if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      swarn("%s: socket(SOCK_STREAM)", function);
      return 0;
   }

   switch (addr->atype) {
      case SOCKS_ADDR_IPV4: {
         struct sockshost_t host;

         sockshost2sockaddr(ruleaddr2sockshost(addr, &host, SOCKS_TCP),
         &saddr);

         if (sockd_bind(s, &saddr, 0) != 0) {
            swarn("%s: can't bind address: %s",
            function, sockaddr2string(&saddr, saddrs, sizeof(saddrs)));

            close(s);
            return 0;
         }
         break;
      }

      case SOCKS_ADDR_IFNAME:
         if (ifname2sockaddr(addr->addr.ifname, 0, &saddr, NULL) == NULL) {
            swarnx("%s: can't find interface named %s with ip configured",
            function, addr->addr.ifname);

            close(s);
            return 0;
         }

         if (sockd_bind(s, &saddr, 0) != 0) {
            swarn("%s: can't bind address %s of interface %s",
            function, sockaddr2string(&saddr, saddrs, sizeof(saddrs)),
            addr->addr.ifname);

            close(s);
            return 0;
         }
         break;

      case SOCKS_ADDR_DOMAIN: {
         struct sockshost_t host;

         sockshost2sockaddr(ruleaddr2sockshost(addr, &host, SOCKS_TCP),
         &saddr);

         if (TOIN(&saddr)->sin_addr.s_addr == htonl(INADDR_ANY)) {
            swarn("%s: can't resolve %s to an ip address",
            function, addr->addr.domain);

            close(s);
            return 0;
         }

         if (sockd_bind(s, &saddr, 0) != 0) {
            swarn("%s: can't bind address %s from hostname %s",
            function, sockaddr2string(&saddr, saddrs, sizeof(saddrs)),
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
   const struct command_t *command;
{

   if ((command->bindreply || command->udpreply)
   && !(command->connect || command->bind || command->udpassociate))
      return 1;

   return 0;
}


static struct rule_t *
addrule(newrule, rulebase, isclientrule)
   const struct rule_t *newrule;
   struct rule_t **rulebase;
   const int isclientrule;
{
   static const struct serverstate_t state;
   const char *function = "addrule()";
   struct rule_t *rule;
   size_t i;
   int *methodv;
   size_t methodc;

   if (isclientrule) {
      methodv = sockscf.clientmethodv;
      methodc = sockscf.clientmethodc;
   }
   else {
      methodv = sockscf.methodv;
      methodc = sockscf.methodc;
   }

   if ((rule = malloc(sizeof(*rule))) == NULL)
      serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
   *rule = *newrule;

   if (rule->src.atype == SOCKS_ADDR_IFNAME) {
      struct sockaddr addr, mask;

      if (ifname2sockaddr(rule->src.addr.ifname, 0, &addr, &mask) == NULL)
         yyerror("no ip address found on interface %s", rule->src.addr.ifname);

      if (rule->src.operator == none || rule->src.operator == eq)
         TOIN(&addr)->sin_port
         = rule->state.protocol.tcp ? rule->src.port.tcp : rule->src.port.udp;

      sockaddr2ruleaddr(&addr, &rule->src);
      rule->src.addr.ipv4.mask = TOIN(&mask)->sin_addr;

      if (ifname2sockaddr(rule->src.addr.ifname, 1, &addr, &mask) != NULL)
         yywarn("interfacenames with multiple ip addresses not yet supported "
                "in rules.  Will only use first address on interface");
   }

   if (rule->dst.atype == SOCKS_ADDR_IFNAME) {
      struct sockaddr addr, mask;

      if (ifname2sockaddr(rule->dst.addr.ifname, 0, &addr, &mask) == NULL)
         yyerror("no ip address found on interface %s", rule->dst.addr.ifname);

      if (rule->dst.operator == none || rule->dst.operator == eq)
         TOIN(&addr)->sin_port
         = rule->state.protocol.tcp ? rule->dst.port.tcp : rule->dst.port.udp;

      sockaddr2ruleaddr(&addr, &rule->dst);
      rule->dst.addr.ipv4.mask = TOIN(&mask)->sin_addr;

      if (ifname2sockaddr(rule->dst.addr.ifname, 1, &addr, &mask) != NULL)
         yywarn("interface names with multiple ip addresses not yet supported "
                "in rules.  Will only use first address on interface");
   }

   /*
    * try to set values not set to a sensible default.
    */

   if (sockscf.option.debug) {
      rule->log.connect       = 1;
      rule->log.disconnect    = 1;
      rule->log.error         = 1;
      rule->log.iooperation   = 1;
   }
   /* else; don't touch logging, no logging is ok. */


   /* if no command set, set all. */
   if (memcmp(&state.command, &rule->state.command, sizeof(state.command)) == 0)
      memset(&rule->state.command, UCHAR_MAX, sizeof(rule->state.command));

   /*
    * If no method set, set all set from global methodline that make sense.
    */
   if (rule->state.methodc == 0) {
      for (i = 0; i < methodc; ++i) {
         switch (methodv[i]) {
            case AUTHMETHOD_NONE:
               if (rule->user == NULL && rule->group == NULL)
                  rule->state.methodv[rule->state.methodc++] = methodv[i];
               break;

            case AUTHMETHOD_GSSAPI:
               /*
                * GSSAPI is a little quirky.  Settings are in
                * client-rules, but some fields can only be checked
                * as part of socks-rules (user/group-settings).
                */

               if (isreplycommandonly(&rule->state.command))
                  continue;

               if (isclientrule)
                  if (rule->user != NULL || rule->group != NULL) {
                     if (methodc == 1)
                        slog(LOG_DEBUG, "%s: let checkrules() error out about "
                                        "username in gssapi-based client-rule",
                                        function);
                     else
                        break;
                  }

               rule->state.methodv[rule->state.methodc++] = methodv[i];
               break;

           case AUTHMETHOD_UNAME:
               if (isreplycommandonly(&rule->state.command))
                  continue;

               rule->state.methodv[rule->state.methodc++] = methodv[i];

            default:
               rule->state.methodv[rule->state.methodc++] = methodv[i];
         }
      }
   }


   for (i = 0; i < rule->state.methodc; ++i)
      if (!methodisset(rule->state.methodv[i], methodv, methodc))
         yyerror("method \"%s\" set in local rule, but not in global "
                 "%smethod specification",
                 method2string(rule->state.methodv[i]),
                 methodv == sockscf.clientmethodv ? "isclientrule" : "");

#if !BAREFOOTD
   /* if no protocol is set, set all for socks-rules, tcp for client-rules. */
   if (memcmp(&state.protocol, &rule->state.protocol, sizeof(state.protocol))
   == 0) {
      if (isclientrule)
         rule->state.protocol.tcp = 1;
      else
         memset(&rule->state.protocol, UCHAR_MAX, sizeof(rule->state.protocol));
   }
#endif /* !BAREFOOTD */

   /* if no proxyprotocol set, set all socks protocols. */
   if (memcmp(&state.proxyprotocol, &rule->state.proxyprotocol,
   sizeof(state.proxyprotocol)) == 0) {
      rule->state.proxyprotocol.socks_v4 = 1;
      rule->state.proxyprotocol.socks_v5 = 1;
   }

   /*
    * Set default values for some authentication-methods, if none
    * set.  Note that this needs to be set regardless of what the
    * method set in the rule is, as checkconfig() might add methods
    * to the rules as part of it's operation.  This happens e.g. when
    * adding default methods to the global clientmethod line, if appropriate,
    * and then adding the same methods to the client-rules, if the rules
    * do not already have a method.
    */

#if HAVE_PAM
   if (*rule->state.pamservicename == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_PAMSERVICENAME)
      <= sizeof(rule->state.pamservicename));

      strcpy(rule->state.pamservicename, DEFAULT_PAMSERVICENAME);
   }
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
   if (*rule->state.gssapiservicename == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_GSSAPISERVICENAME)
      <= sizeof(rule->state.gssapiservicename));

      strcpy(rule->state.gssapiservicename, DEFAULT_GSSAPISERVICENAME);
   }

   if (*rule->state.gssapikeytab == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_GSSAPIKEYTAB)
      <= sizeof(rule->state.gssapikeytab));
      strcpy(rule->state.gssapikeytab, DEFAULT_GSSAPIKEYTAB);
   }

   /*
    * can't do memcmp since we don't want to include
    * gssapiencryption.nec in the compare.
    */
   if (rule->state.gssapiencryption.clear           == 0
   &&  rule->state.gssapiencryption.integrity       == 0
   &&  rule->state.gssapiencryption.confidentiality == 0
   &&  rule->state.gssapiencryption.permessage      == 0) {
      rule->state.gssapiencryption.clear          = 1;
      rule->state.gssapiencryption.integrity      = 1;
      rule->state.gssapiencryption.confidentiality= 1;
      rule->state.gssapiencryption.permessage     = 0;
   }
#endif /* HAVE_GSSAPI */

   if (*rulebase == NULL) {
      *rulebase = rule;
      (*rulebase)->number = 1;
   }
   else {
      struct rule_t *lastrule;

      /* append this rule to the end of our list. */

      lastrule = *rulebase;
      while (lastrule->next != NULL)
         lastrule = lastrule->next;

      rule->number = lastrule->number + 1;
      lastrule->next = rule;
   }

   rule->next = NULL;

   return rule;
}

static void
checkrule(rule, isclientrule)
   const struct rule_t *rule;
   const int isclientrule;
{
/*   const char *function = "checkrule()"; */
   size_t i;
   struct ruleaddr_t ruleaddr;

   if (isclientrule) {
      for (i = 0; i < rule->state.methodc; ++i) {
         switch (rule->state.methodv[i]) {
            case AUTHMETHOD_NONE:
            case AUTHMETHOD_GSSAPI:
            case AUTHMETHOD_RFC931:
            case AUTHMETHOD_PAM:
               break;

            default:
               yyerror("method %s is not valid for clientrules",
               method2string(rule->state.methodv[i]));
         }
      }
   }

   if (rule->user != NULL || rule->group != NULL) {
      /* check that any methods given in rule provide usernames. */
      for (i = 0; i < rule->state.methodc; ++i) {
         switch (rule->state.methodv[i]) {
            case AUTHMETHOD_UNAME:
            case AUTHMETHOD_RFC931:
            case AUTHMETHOD_PAM:
               break;

            case AUTHMETHOD_GSSAPI:
               if (isclientrule)
                  yyerror("user/group-names are not supported for method \"%s\""
                          " in client-rules.  Move the name(s) to a socks-rule",
                          method2string(rule->state.methodv[i]));

               break;

            default:
               yyerror("method \"%s\" can not provide usernames",
               method2string(rule->state.methodv[i]));
         }
      }
   }

   if (rule->rdr_from.atype != 0) {
      switch (rule->rdr_from.atype) {
         case SOCKS_ADDR_IPV4:
         case SOCKS_ADDR_IFNAME:
         case SOCKS_ADDR_DOMAIN:
            break;

         default:
            yyerror("redirect from address can not be a %s",
            atype2string(rule->rdr_from.atype));
      }

      ruleaddr          = rule->rdr_from;
      ruleaddr.port.tcp = htons(0); /* any port is good for testing. */

      if (!addressisbindable(&ruleaddr)) {
         char addr[MAXRULEADDRSTRING];

         yyerror("%s is not bindable",
         ruleaddr2string(&ruleaddr, addr, sizeof(addr)));
      }
   }

   if (rule->rdr_to.atype == SOCKS_ADDR_IFNAME) {
      switch (rule->rdr_to.atype) {
         case SOCKS_ADDR_IPV4:
         case SOCKS_ADDR_DOMAIN:
            break;

         default:
            yyerror("redirect to a %s-type address is not supported "
                    "(or meaningful?)",
                    atype2string(rule->rdr_to.atype));
      }
   }

}

static void
showlist(list, prefix)
   const struct linkedname_t *list;
   const char *prefix;
{
   char buf[10240];

   list2string(list, buf, sizeof(buf));
   if (strlen(buf) > 0)
      slog(LOG_INFO, "%s%s", prefix, buf);
}

static void
showlog(log)
   const struct log_t *log;
{
   char buf[1024];

   slog(LOG_INFO, "log: %s", logs2string(log, buf, sizeof(buf)));
}


#if HAVE_LIBWRAP
static void
libwrapinit(s, request)
   int s;
   struct request_info *request;
{
   const int errno_s = errno;

   request_init(request, RQ_FILE, s, RQ_DAEMON, __progname, 0);
   fromhost(request);

   errno = errno_s;
}
#endif /* HAVE_LIBWRAP */

static int
connectisok(request, rule)
#if HAVE_LIBWRAP
   struct request_info *request;
#else
   void *request;
#endif /* HAVE_LIBWRAP */
   const struct rule_t *rule;
{

#if HAVE_LIBWRAP

   /* do we need to involve libwrap for this rule? */
   if (*rule->libwrap != NUL
   ||  sockscf.srchost.nomismatch
   ||  sockscf.srchost.nounknown) {
      const char *function = "connectisok()";
      char libwrap[LIBWRAPBUF];

      /* libwrap modifies the passed buffer. */
      SASSERTX(strlen(rule->libwrap) < sizeof(libwrap));
      strcpy(libwrap, rule->libwrap);

      /* Wietse Venema says something along the lines of: */
      if (setjmp(tcpd_buf) != 0) {
         sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_OFF);

         swarnx("%s: failed libwrap line: %s", function, libwrap);
         return 0;   /* something got screwed up. */
      }

      sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_ON);
      process_options(libwrap, request);
      sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_OFF);

      if (sockscf.srchost.nounknown)
         if (strcmp(eval_hostname(request->client), STRING_UNKNOWN) == 0) {
            slog(LOG_INFO, "%s: srchost unknown",
            eval_hostaddr(request->client));

            return 0;
         }

      if (sockscf.srchost.nomismatch)
         if (strcmp(eval_hostname(request->client), STRING_PARANOID) == 0) {
            slog(LOG_INFO, "%s: srchost ip/host mismatch",
            eval_hostaddr(request->client));

            return 0;
      }
   }
#endif /* !HAVE_LIBWRAP */

   return 1;
}
