/*
 * Copyright (c) 2010, 2011
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
#include "config_parse.h"

static const char rcsid[] =
"$Id: rule.c,v 1.74 2011/07/27 12:16:53 michaels Exp $";

#if HAVE_LIBWRAP
extern jmp_buf tcpd_buf;
int allow_severity, deny_severity;

static void
libwrapinit(int s, struct sockaddr *local, struct sockaddr *peer,
            struct request_info *request);
/*
 * Initializes "request" for later usage via libwrap.
 * "s" is the socket the connection from "peer" was accepted on, with
 * the local address of "s" beeing "local".
 */

static int
libwrap_hosts_access(struct request_info *request,
                     const struct sockaddr *peer);
/*
 * Perform libwrap hosts_access() check on client.
 */
#endif /* !HAVE_LIBWRAP */

static int
srchostisok(const struct sockaddr *peer, char *msg, size_t msgsize);
/*
 * Checks whether the connection/packet from "peer" is ok, according
 * to srchost-settings.  If the connection/packet is not ok, "msg" is filled
 * in with the reason why not.
 *
 * This function should be called after each rule check for a new
 * connection/packet.
 *
 * Returns:
 *      If connection is acceptable: true
 *      If connection is not acceptable: false
 */

static void
showlog(const struct log_t *log);
/*
 * shows what type of logging is specified in "log".
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


void
addclientrule(newrule)
   const struct rule_t *newrule;
{
   const char *function = "addclientrule()";
   struct rule_t *rule, ruletoadd;

   ruletoadd = *newrule; /* for const. */

   rule = addrule(&ruletoadd, &sockscf.crule, 1);

   checkrule(rule, 1);

#if BAREFOOTD
   if (rule->state.protocol.udp) {
      /*
       * Only one level of acls, so we need to autogenerate the second level
       * ourselves as the first acl level can only handle tcp, but we
       * need to check each udp packet against rulespermit(), and for that,
       * a second level acl (socks-rule) is needed.
       *
       * In the tcp-case, we don't need any socks-rules, the client-rule
       * is enough as the endpoints get fixed at session-establishment
       * and we can just short-circuit the process as we knows the
       * session is allowed if it gets past the client-rule state.
       */
      struct rule_t srule;
      struct sockaddr sa;

      /*
       * so we know there may be udp traffic to bounce (may, since this may
       * be a sighup and the same rule being reloaded).
       */
      sockscf.state.alludpbounced = 0;

      /*
       * most things in the socks-rule are the same.
       */
      srule = *rule;

      /* udp will use the resource-limits from the client-rule. */
      SHMEM_CLEAR(&srule, 1);

      /*
       * no socks-rules to configure for user means no auth also; if
       * the client-rule passes, socks-rule should to.
       * This remains correct as long as there are no udp-based auth methods.
       */
      srule.state.methodc                        = 0;
      srule.state.methodv[srule.state.methodc++] = AUTHMETHOD_NONE;

      bzero(&srule.bounce_to, sizeof(srule.bounce_to));

      /*
       * these socks-rules are only for udp.
       */

      bzero(&srule.state.protocol, sizeof(srule.state.protocol));
      srule.state.protocol.udp = 1;

      bzero(&srule.state.command, sizeof(srule.state.command));
      srule.state.command.udpassociate           = 1;

      /* need to know which internal address this rule applies to. */
      srule.internal = rule->dst;

      /*
       * add a rule for letting the packet from the client out ...
       */

      srule.dst = rule->bounce_to;

      /* need to know which crule generated this srule. */
      srule.crule = rule;
      addsocksrule(&srule);

      /*
       * ... and a rule allowing the reply back in.
       */

      bzero(&srule.state.command, sizeof(srule.state.command));
      srule.state.command.udpreply = 1;

      if (sockscf.udpconnectdst) /* only allow replies from dst. */
         srule.src = rule->bounce_to;
      else { /* allow replies from everyone. */
         bzero(&srule.src, sizeof(srule.src));
         srule.src.atype                         = SOCKS_ADDR_IPV4;
         srule.src.addr.ipv4.ip.s_addr           = htonl(INADDR_ANY);
         srule.src.addr.ipv4.mask.s_addr         = htonl(0);
         srule.src.port.tcp = srule.src.port.udp = htons(0);
      }

      srule.dst = rule->src;

      addsocksrule(&srule);

      if (addrindex_on_listenlist(sockscf.internalc,
                                  sockscf.internalv,
                                  ruleaddr2sockaddr(&rule->dst, &sa, SOCKS_UDP),
                                  SOCKS_UDP) == -1)
         /* add address to internal list also; need to listen for packets. */
         addinternal(&rule->dst, SOCKS_UDP);
      else {
         slog(LOG_DEBUG, "%s: not adding address %s from rule #%lu to internal "
                         "list; address already there",
                         function,
                         sockaddr2string(&sa, NULL, 0),
                         (unsigned long)rule->number);

         rule->bounced = 1; /* don't need to bounce the same address twice. */
      }
   }
#endif /* BAREFOOTD */
}

void
addsocksrule(newrule)
   const struct rule_t *newrule;
{
   struct rule_t *rule;

   rule = addrule(newrule, &sockscf.srule, 0);
   checkrule(rule, 0);
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
showrule(_rule, isclientrule)
   const struct rule_t *_rule;
   const int isclientrule;
{
   struct rule_t rule = *_rule; /* shmat()/shmdt() changes rule. */
   char addr[MAXRULEADDRSTRING];

   slog(LOG_DEBUG, "%s-rule #%lu, line #%lu",
        isclientrule ? "client" : "socks", (unsigned long)rule.number,
        (unsigned long)rule.linenumber);

   slog(LOG_DEBUG, "verdict: %s", verdict2string(rule.verdict));

   slog(LOG_DEBUG, "src: %s",
   ruleaddr2string(&rule.src, addr, sizeof(addr)));

   slog(LOG_DEBUG, "dst: %s",
   ruleaddr2string(&rule.dst, addr, sizeof(addr)));

#if BAREFOOTD
   if (isclientrule)
      slog(LOG_DEBUG, "bounce to: %s",
      ruleaddr2string(&rule.bounce_to, addr, sizeof(addr)));
   else {
      SASSERTX(rule.state.protocol.udp && !rule.state.protocol.tcp);

      slog(LOG_DEBUG, "valid for udp packets accepted on: %s",
      ruleaddr2string(&rule.internal, addr, sizeof(addr)));
   }
#endif /* BAREFOOTD */


   /* only show if timeout differs from default. */
   if (memcmp(&rule.timeout, &sockscf.timeout, sizeof(rule.timeout)) != 0)
      showtimeout(&rule.timeout);

   if (rule.udprange.op == range)
      slog(LOG_DEBUG, "udp port range: %u - %u",
      ntohs(rule.udprange.start), ntohs(rule.udprange.end));

   if (rule.rdr_from.atype != SOCKS_ADDR_NOTSET)
      slog(LOG_DEBUG, "redirect from: %s",
      ruleaddr2string(&rule.rdr_from, addr, sizeof(addr)));

   if (rule.rdr_to.atype != SOCKS_ADDR_NOTSET)
      slog(LOG_DEBUG, "redirect to: %s",
      ruleaddr2string(&rule.rdr_to, addr, sizeof(addr)));

   sockd_shmat(&rule, SHMEM_ALL);

   if (rule.bw_shmid != 0)
      slog(LOG_DEBUG, "max bandwidth allowed: %lu B/s",
      (unsigned long)rule.bw->object.bw.maxbps);

   if (rule.ss_shmid != 0)
      slog(LOG_DEBUG, "max sessions allowed: %lu",
      (unsigned long)rule.ss->object.ss.maxsessions);

   sockd_shmdt(&rule, SHMEM_ALL);

   showlist(rule.user, "user: ");
   showlist(rule.group, "group: ");

#if HAVE_PAM
   if (methodisset(AUTHMETHOD_PAM, rule.state.methodv, rule.state.methodc))
      slog(LOG_DEBUG, "pam.servicename: %s", rule.state.pamservicename);
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   if (methodisset(AUTHMETHOD_BSDAUTH, rule.state.methodv, rule.state.methodc))
      slog(LOG_DEBUG, "bsdauth.stylename: %s", rule.state.bsdauthstylename);
#endif /* HAVE_BSDAUTH */

#if HAVE_LDAP
   showlist(rule.ldapgroup, "ldap.group: ");
   if (rule.ldapgroup) {
      if (*rule.state.ldap.domain != NUL)
         slog(LOG_DEBUG, "ldap.domain: %s",rule.state.ldap.domain);

      slog(LOG_DEBUG, "ldap.auto.off: %s",
      rule.state.ldap.auto_off ? "yes" : "no");
#if HAVE_OPENLDAP
      slog(LOG_DEBUG, "ldap.debug: %d", rule.state.ldap.debug);
#endif
      slog(LOG_DEBUG, "ldap.keeprealm: %s",
      rule.state.ldap.keeprealm ? "yes" : "no");

      if (*rule.state.ldap.keytab != NUL)
         slog(LOG_DEBUG, "ldap.keytab: %s", rule.state.ldap.keytab);

      showlist(rule.state.ldap.ldapurl, "ldap.url: ");

      showlist(rule.state.ldap.ldapbasedn, "ldap.basedn: ");

      if (*rule.state.ldap.filter != NUL)
         slog(LOG_DEBUG, "ldap.filter: %s", rule.state.ldap.filter);

      if (*rule.state.ldap.filter_AD != NUL)
         slog(LOG_DEBUG, "ldap.filter.ad: %s", rule.state.ldap.filter_AD);

      if (*rule.state.ldap.attribute != NUL)
         slog(LOG_DEBUG, "ldap.attribute: %s", rule.state.ldap.attribute);

      if (*rule.state.ldap.attribute_AD != NUL)
         slog(LOG_DEBUG, "ldap.attribute.ad: %s",
         rule.state.ldap.attribute_AD);

      slog(LOG_DEBUG, "ldap.mdepth: %d", rule.state.ldap.mdepth);
      slog(LOG_DEBUG, "ldap.port: %d", rule.state.ldap.port);
      slog(LOG_DEBUG, "ldap.ssl: %s", rule.state.ldap.ssl ? "yes" : "no");
      slog(LOG_DEBUG, "ldap.certcheck: %s",
      rule.state.ldap.certcheck ? "yes" : "no");
      if (*rule.state.ldap.certfile != NUL)
         slog(LOG_DEBUG, "ldap.certfile: %s", rule.state.ldap.certfile);

      if (*rule.state.ldap.certpath != NUL)
         slog(LOG_DEBUG, "ldap.certpath: %s", rule.state.ldap.certpath);
   }
#endif /* HAVE_LDAP */

   showstate(&rule.state, isclientrule);
   showlog(&rule.log);

#if HAVE_LIBWRAP
   if (*rule.libwrap != NUL)
      slog(LOG_DEBUG, "libwrap: %s", rule.libwrap);
#endif /* HAVE_LIBWRAP */
}

int
rulespermit(s, peer, local, clientauth, srcauth, match, state,
            src, dst, msg, msgsize)
   int s;
   const struct sockaddr *peer, *local;
   const struct authmethod_t *clientauth;
   struct authmethod_t *srcauth;
   struct rule_t *match;
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
#if HAVE_LIBWRAP
   struct request_info libwraprequest;
   struct sockaddr _local = *local, _peer = *peer; /* libwrap wants non-const */
   unsigned char libwrapinited = 0;
#endif /* !HAVE_LIBWRAP */
   int *methodv, methodc, isclientrule;
   char srcstr[MAXSOCKSHOSTSTRING], dststr[MAXSOCKSHOSTSTRING],
        lstr[MAXSOCKADDRSTRING], pstr[MAXSOCKADDRSTRING];

   sockd_handledsignals();

   slog(LOG_DEBUG,
        "%s: %s -> %s, command %s, socket %d (from %s, accepted on %s)",
        function,
        src == NULL ? "0.0.0.0" : sockshost2string(src, srcstr, sizeof(srcstr)),
        dst == NULL ? "0.0.0.0" : sockshost2string(dst, dststr, sizeof(dststr)),
        command2string(state->command),
        s,
        peer == NULL  ? "0.0.0.0" : sockaddr2string(peer, pstr, sizeof(pstr)),
        local == NULL ? "0.0.0.0" : sockaddr2string(local, lstr, sizeof(lstr)));


   if (msgsize > 0)
      *msg = NUL;

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

#if BAREFOOTD
      defrule.bounce_to                   = defrule.src;
#endif /* BAREFOOTD */

      memset(&defrule.log, 0, sizeof(defrule.log));

      if (sockscf.option.debug) {
         defrule.log.connect     = 1;
         defrule.log.disconnect  = 1;
         defrule.log.error       = 1;
         defrule.log.iooperation = 1;
      }

      memset(&defrule.state.command, UCHAR_MAX, sizeof(defrule.state.command));

      defrule.state.methodc = 0;

      memset(&defrule.state.protocol,
             UCHAR_MAX,
             sizeof(defrule.state.protocol));

      memset(&defrule.state.proxyprotocol,
             UCHAR_MAX,
             sizeof(defrule.state.proxyprotocol));

#if HAVE_LIBWRAP
      *defrule.libwrap = NUL;
#endif /* HAVE_LIBWRAP */

      init = 1;
   }

#if HAVE_LIBWRAP
   if (s != -1  && sockscf.option.hosts_access) {
      libwrapinit(s, &_local, &_peer, &libwraprequest);
      libwrapinited = 1;

      if (libwrap_hosts_access(&libwraprequest, peer) == 0) {
         *match = defrule;

         /* disable block logging for hosts_access() check. */
         bzero(&match->log, sizeof(match->log));

         return 0;
      }
   }
#endif /* HAVE_LIBWRAP */

   if (state->extension.bind && !sockscf.extension.bind) {
      snprintf(msg, msgsize, "client requested disabled extension: bind");
      *match         = defrule;
      match->verdict = VERDICT_BLOCK;

      return 0; /* will never succeed. */
   }

   /* what rulebase to use. */
   switch (state->command) {
      case SOCKS_ACCEPT:
      case SOCKS_BOUNCETO:
         /* clientrule. */
         isclientrule = 1;
         rule         = sockscf.crule;
         methodv      = sockscf.clientmethodv;
         methodc      = sockscf.clientmethodc;
         break;

      default:
         /* everyone else, socksrules. */
         isclientrule = 0;
         rule         = sockscf.srule;
         methodv      = sockscf.methodv;
         methodc      = sockscf.methodc;
         break;
   }

   /*
    * let srcauth be unchanged from original unless we actually get a match.
    */
   for (oldauth = *srcauth;
   rule != NULL;
   rule = rule->next, *srcauth = oldauth) {
      int i;

      slog(LOG_DEBUG, "%s: trying to match against %s-rule #%lu, verdict = %s",
                      function,
                      isclientrule ? "client" : "socks",
                      (unsigned long)rule->number,
                      verdict2string(rule->verdict));

      /* current rule covers desired command? */
      switch (state->command) {
         /* client-rule commands. */
         case SOCKS_ACCEPT:
         case SOCKS_BOUNCETO:
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

         /*
          * pseudo commands.
          */

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

            case PROXY_HTTP_10:
            case PROXY_HTTP_11:
               if (!rule->state.proxyprotocol.http)
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

#if BAREFOOTD
      /*
       * In barefootd's case, we can have several socks-rules with
       * the same from and to address, and the differentiating factor
       * will be the address the udp packet was accepted on.
       */

      if (local != NULL && !isclientrule) {
         struct sockshost_t localhost;

         SASSERTX(state->protocol == SOCKS_UDP);

         if (!addrmatch(&rule->internal,
                        sockaddr2sockshost(local, &localhost),
                        state->protocol, 0))
            continue;
      }
#endif /* BAREFOOTD */

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
            /*
             * don't have complete address, so see if it's possible to find a 
             * pass rule matching what info we have.
             */
            continue;

      /*
       * Does this rule's authentication requirements match the current
       * authentication in use by the client?
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
          * That can make the configure look weird though; if the
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
          * I.e. it's possible to "change/upgrade" the method.
          * E.g. if the client is using method NONE (or any other),
          * it might still be possible to change the authentication to
          * RFC931, or PAM.  Likewise, if the current method is
          * AUTHMETHOD_NOTSET, it can be "upgraded" to AUTHMETHOD_NONE.
          *
          * We therefore look at what methods this rule requires and see
          * if can match it with what the client _can_ provide, if we
          * do some more work to get that information.
          *
          * Currently these methods are: gssapi (only during negotiation),
          * AUTHMETHOD_NOTSET, rfc931, and pam.
          */

         /*
          * This variable only says if current client has provided the
          * necessary information to check it's access with one of the
          * methods required by the current rule.  It does *not* mean the
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
               if (sockscf.option.debug >= DEBUG_VERBOSE)
                  slog(LOG_DEBUG,
                       "%s: no match yet for method %s, command %s ...",
                       function,
                       method2string(methodv[i]),
                       command2string(state->command));

               switch (methodv[i]) {
                  case AUTHMETHOD_NONE:
                     methodischeckable = 1; /* anything is good enough. */
                     break;

#if HAVE_LIBWRAP
                  case AUTHMETHOD_RFC931: {
                     if (clientauth        != NULL
                     && clientauth->method == AUTHMETHOD_RFC931) {
                        slog(LOG_DEBUG, "%s: already have rfc931 name %s from "
                                        "clientauthentication done before, "
                                        "not doing lookup again",
                                        function,
                                        clientauth->mdata.rfc931.name);

                        srcauth->mdata.rfc931 = clientauth->mdata.rfc931;
                     }
                     else { /* need to do a tcp lookup. */
                        if (state->protocol != SOCKS_TCP) {
                           slog(LOG_DEBUG,
                                "%s: protocol is not tcp (is %s), can't do "
                                "ident lookup",
                                function, protocol2string(state->protocol));

                           break;
                        }

                        if (!libwrapinited) {
                           libwrapinit(s, &_local, &_peer, &libwraprequest);
                           libwrapinited = 1;
                        }

                        slog(LOG_DEBUG,
                             "%s: doing lookup to get rfc931 name ...",
                             function);

                        strncpy((char *)srcauth->mdata.rfc931.name,
                                eval_user(&libwraprequest),
                                sizeof(srcauth->mdata.rfc931.name) - 1);
                
                        /* libwrap sets this if no identreply. */
                        if (strcmp((char *)srcauth->mdata.rfc931.name,
                        STRING_UNKNOWN) == 0) {
                           *srcauth->mdata.rfc931.name = NUL;
                           slog(LOG_DEBUG, "%s: no rfc931 name", function);
                        }
                        else if (srcauth->mdata.rfc931.name[
                               sizeof(srcauth->mdata.rfc931.name) - 1] != NUL) {
                           srcauth->mdata.rfc931.name[
                              sizeof(srcauth->mdata.rfc931.name) - 1] = NUL;

                           slog(LOG_INFO, "%s: rfc931 name \"%s...\" too long",
                                function, srcauth->mdata.rfc931.name);

                           *srcauth->mdata.rfc931.name = NUL; /* unusable. */
                        }
                        else
                           slog(LOG_DEBUG, "%s: rfc931 name gotten is \"%s\"",
                                function, srcauth->mdata.rfc931.name);
                     }

                     if (*srcauth->mdata.rfc931.name != NUL)
                        methodischeckable = 1;
                     break;
                  }
#endif /* HAVE_LIBWRAP */

#if HAVE_PAM
                  case AUTHMETHOD_PAM: {
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
                  }
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
                  case AUTHMETHOD_BSDAUTH: {
                     /*
                      * Requires username and password, but assume
                      * the password can be empty.
                      */

                     switch (srcauth->method) {
                        case AUTHMETHOD_UNAME: {
                           /* it's a union, make a copy first. */
                           const struct authmethod_uname_t uname
                           = srcauth->mdata.uname;

                           /*
                            * similar enough, just copy name/password.
                            */

                           strcpy((char *)srcauth->mdata.bsd.name,
                           (const char *)uname.name);

                           strcpy((char *)srcauth->mdata.bsd.password,
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

                            strcpy((char *)srcauth->mdata.bsd.name,
                            (const char *)rfc931.name);

                           *srcauth->mdata.bsd.password = NUL;

                           methodischeckable = 1;
                           break;
                        }
#endif /* HAVE_LIBWRAP */
                     }

                     strcpy(srcauth->mdata.bsd.style,
                     rule->state.bsdauthstylename);
                     break;
                  }
#endif /* HAVE_BSDAUTH */


#if SOCKS_SERVER
#if HAVE_GSSAPI
                  case AUTHMETHOD_GSSAPI: {
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
                  }
#endif /* HAVE_GSSAPI */
#endif /* SOCKS_SERVR */
               }

               if (methodischeckable) {
                  slog(LOG_DEBUG, "%s: changing authmethod from %d to %d",
                  function, srcauth->method, methodv[i]);

                  srcauth->method = methodv[i]; /* changing method. */
                  break;
               }
            }
         }

         if (i == methodc) {
#if COVENANT
            /*
             * Respond to the client that it must provide proxy
             * authentication, which means we can go from no authentication
             * to "any" authentication, if the client goes on to provide
             * authentication later.
             */
            if (methodc > 0) { /* yes, there actually is a method configured. */
               match->verdict                   = VERDICT_BLOCK;
               match->whyblock.missingproxyauth = 1;

               return 0;
            }
#else /* !COVENANT */
            /*
             * the methods of the current rule differs from what client can
             * provide us with.  Go to next rule.
             */
            continue;
#endif /* !COVENANT */
         }
      }

      SASSERTX(state->command == SOCKS_BINDREPLY
      ||       state->command == SOCKS_UDPREPLY
      ||       methodisset(srcauth->method, rule->state.methodv,
                           rule->state.methodc));

      if (srcauth->method != AUTHMETHOD_NONE && rule->user != NULL) {
         /* rule requires user.  Covers current? */
         if (!usermatch(srcauth, rule->user)) {
            slog(LOG_DEBUG,
                 "%s: username \"%s\" did not match rule #%lu for %s",
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
                 "%s: groupname \"%s\" did not match rule #%lu for %s",
                 function,
                 authname(srcauth) == NULL ? "<null>" : authname(srcauth),
                 (unsigned long)rule->number,
                 command2string(state->command));

            continue; /* no match. */
         }
      }

#if HAVE_LDAP
      /* rule requires a group, and covers current user? */
      if (srcauth->method != AUTHMETHOD_NONE && rule->ldapgroup != NULL) {
         if (!ldapgroupmatch(srcauth, (const struct rule_t *)rule))  {
               slog(LOG_DEBUG,
                    "%s: username \"%s\" did not match rule #%lu for %s",
                    function,
                    authname(srcauth) == NULL ? "<null>" : authname(srcauth),
                    (unsigned long)rule->number,
                    command2string(state->command));

               continue; /* no match. */
         }
      }
#endif

      if (!accesscheck(s, srcauth, peer, local, msg, msgsize)) {
         *match         = *rule;

         match->verdict = VERDICT_BLOCK;
         return 0;
      }

      break;
   }

   if (rule == NULL) {
      snprintf(msg, msgsize, "no rules matched, using default block rule");
      slog(LOG_DEBUG, "%s: %s", function, msg);

      rule = &defrule;
   }
   else 
      slog(LOG_DEBUG, "%s: rule matched: %lu",
           function, (unsigned long)rule->number);

   *match = *rule;

   /*
    * got our rule, now check connection.  Connectioncheck
    * requires the rule matched so needs to be delayed til here.
    */
   if (match->verdict == VERDICT_PASS)
      if (!srchostisok(peer, msg, msgsize)) {
         match->verdict = VERDICT_BLOCK;
         return 0;
      }

#if HAVE_LIBWRAP
   if (s != -1 && *rule->libwrap != NUL) {
      char libwrapcmd[LIBWRAPBUF];

      if (!libwrapinited) {
         libwrapinit(s, &_local, &_peer, &libwraprequest);
         libwrapinited = 1;
      }

      /* libwrap modifies the passed buffer. */
      SASSERTX(strlen(rule->libwrap) < sizeof(libwrapcmd));
      strcpy(libwrapcmd, rule->libwrap);

      /* Wietse Venema says something along the lines of: */
      if (setjmp(tcpd_buf) != 0) {
         sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_OFF);

         swarnx("%s: failed libwrap line: \"%s\"", function, libwrapcmd);
         return 0;   /* something got screwed up. */
      }

      slog(LOG_DEBUG, "%s: executing libwrap command: \"%s\"",
      function, libwrapcmd);

      sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_ON);
      process_options(libwrapcmd, &libwraprequest);
      sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_OFF);

      if (match->verdict == VERDICT_BLOCK
      &&  strstr(rule->libwrap, "banners ") != NULL) {
         /*
          * see RFC 2525 2.17 "Failure to RST on close with data pending".
          * We don't want the kernel to RST this connection upon our 
          * subsequent close(2) without us having sent the whole banner to
          * the client first.  But if the kernel wants to send RST while 
          * we have data not yet sent, it will discard the data not yet
          * sent.  We therefor drain the data, trying to make sure the
          * kernel does not discard the data in the outbuffer when we
          * close(2).  Note that this changes the RST to FIN.
          *
          * Also note there is a race here, as the client could send us data
          * between our last read(2) call and us closing the session later, 
          * but not much to do about that.  Fsync(2) would be nice, but 
          * even if it had worked on socket, this is not important enough
          * to block for.
          */
          char buf[1024];
          ssize_t p;

          while ((p = read(s, buf, sizeof(buf))) > 0)
            slog(LOG_DEBUG, "%s: read %ld bytes.  Discarding so banner is sent",
                 function, (long)p);
      }
   }
#endif /* !HAVE_LIBWRAP */

   return match->verdict == VERDICT_PASS;
}

void
showlist(list, prefix)
   const struct linkedname_t *list;
   const char *prefix;
{
   char buf[10240];

   list2string(list, buf, sizeof(buf));
   if (strlen(buf) > 0)
      slog(LOG_DEBUG, "%s%s", prefix, buf);
}

static int
srchostisok(peer, msg, msgsize)
   const struct sockaddr *peer;
   char *msg;
   size_t msgsize;
{
   const char *function = "srchostisok()";

   if (sockscf.srchost.nodnsmismatch || sockscf.srchost.nodnsunknown) {
      struct hostent *hostent;

      hostent = gethostbyaddr(&(TOCIN(peer))->sin_addr,
                              sizeof(TOCIN(peer)->sin_addr),
                              AF_INET);

      if (hostent == NULL) {
         snprintf(msg, msgsize, "srchost %s does not have a dns entry",
         sockaddr2string(peer, NULL, 0));

         return 0;
      }

      slog(LOG_DEBUG, "%s: %s has a dns entry: %s",
      function, sockaddr2string(peer, NULL, 0), hostent->h_name);

      if (sockscf.srchost.nodnsmismatch) {
         struct ruleaddr_t addr;
         struct sockshost_t resolvedhost;
         struct sockaddr_in peeraddr = *TOCIN(peer);

         peeraddr.sin_port = htons(0);
         sockaddr2ruleaddr((struct sockaddr *)&peeraddr, &addr);

         resolvedhost.atype = (unsigned char)SOCKS_ADDR_DOMAIN;
         if (strlen(hostent->h_name) >= sizeof(resolvedhost.addr.domain)) {
            swarnx("%s: ipaddress %s resolved to a ""hostname (%s) "
                   "that is too large.  %lu is the known max.",
                   function,
                   sockaddr2string((struct sockaddr *)&peeraddr,
                                   NULL, 0),
                  hostent->h_name,
                  (unsigned long)sizeof(resolvedhost.addr.domain));

            return 0;
         }
         resolvedhost.port = peeraddr.sin_port;
         strcpy(resolvedhost.addr.domain, hostent->h_name);

         if (!addrmatch(&addr, &resolvedhost, SOCKS_TCP, 0)) {
            snprintf(msg, msgsize,
                     "dns ip/host mismatch.  \"%s\" does not match resolved "
                     "addresses for \"%s\"",
                     ruleaddr2string(&addr, NULL, 0),
                     sockshost2string(&resolvedhost, NULL, 0));

            return 0;
         }
      }
   }

   return 1;
}

#if HAVE_LIBWRAP
static void
libwrapinit(s, local, peer, request)
   int s;
   struct sockaddr *local;
   struct sockaddr *peer;
   struct request_info *request;
{
   const char *function = "libwrapinit()";
   const int errno_s = errno;
   struct hostent *hostent;

   slog(LOG_DEBUG, "%s: initing libwrap with socket %d", function, s);

   hostent = gethostbyaddr(&(TOIN(local)->sin_addr),
                           sizeof(TOIN(local)->sin_addr),
                           AF_INET);
   request_init(request,
                RQ_FILE, s,
                RQ_DAEMON, __progname,
                RQ_CLIENT_SIN, peer,
                RQ_SERVER_SIN, local,
                RQ_SERVER_NAME, hostent != NULL ? hostent->h_name : "",
                0);

   hostent = gethostbyaddr(&(TOIN(peer)->sin_addr),
                           sizeof(TOIN(peer)->sin_addr),
                           AF_INET);
   request_set(request,
               RQ_CLIENT_NAME, hostent != NULL ? hostent->h_name : "",
               0);

   /* apparently some obscure libwrap bug requires this call. */
   sock_methods(request);

   errno = errno_s;
}

static int
libwrap_hosts_access(request, peer)
   struct request_info *request;
   const struct sockaddr *peer;
{
   const char *function = "libwrap_hosts_access()";
   int allow;

   sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_ON);
   allow = hosts_access(request) != 0;
   sockd_priv(SOCKD_PRIV_LIBWRAP, PRIV_OFF);

   slog(LOG_DEBUG, "%s: libwrap hosts_access(): '%s': %s",
        function, allow ? "allow" : "deny", sockaddr2string(peer, NULL, 0));

   if (allow)
      return 1;

   return 0;
}
#endif /* HAVE_LIBWRAP */

static struct rule_t *
addrule(newrule, rulebase, isclientrule)
   const struct rule_t *newrule;
   struct rule_t **rulebase;
   const int isclientrule;
{
   const char *function = "addrule()";
   struct serverstate_t zstate;
   struct rule_t *rule;
   size_t i;
   int *methodv;
   size_t *methodc;

   bzero(&zstate, sizeof(zstate));

   if (isclientrule) {
      methodv = sockscf.clientmethodv;
      methodc = &sockscf.clientmethodc;
   }
   else {
      methodv = sockscf.methodv;
      methodc = &sockscf.methodc;
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

      rule->src.atype          = SOCKS_ADDR_IPV4;
      rule->src.addr.ipv4.ip   = TOIN(&addr)->sin_addr;
      rule->src.addr.ipv4.mask = TOIN(&mask)->sin_addr;

      if (ifname2sockaddr(rule->src.addr.ifname, 1, &addr, &mask) != NULL)
         yywarn("interface names with multiple ip addresses not yet supported "
                "in rules.  Will only use first address on interface");
   }

   if (rule->dst.atype == SOCKS_ADDR_IFNAME) {
      struct sockaddr addr, mask;

      if (ifname2sockaddr(rule->dst.addr.ifname, 0, &addr, &mask) == NULL)
         yyerror("no ip address found on interface %s", rule->dst.addr.ifname);

      if (rule->dst.operator == none || rule->dst.operator == eq)
         TOIN(&addr)->sin_port
         = rule->state.protocol.tcp ? rule->dst.port.tcp : rule->dst.port.udp;

      rule->dst.atype          = SOCKS_ADDR_IPV4;
      rule->dst.addr.ipv4.ip   = TOIN(&addr)->sin_addr;

#if SOCKS_SERVER
      rule->dst.addr.ipv4.mask        = TOIN(&mask)->sin_addr;
#else /* BAREFOOTD || COVENANT; dst is the address the client connects to. */
      rule->dst.addr.ipv4.mask.s_addr = htonl(0xffffffff);
#endif

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


   /*
    * protocol and commands are two sides of the same coin.
    * If only protocol is set, set all commands that can apply to that
    * protocol.
    * If only command is set, set all protocols that can apply to that
    * command.
    * If none are set, set all protocols and commands.
    * If both are set, don't touch; user has explicitly set what he wants.
    */

   if (memcmp(&zstate.protocol, &rule->state.protocol, sizeof(zstate.protocol))
   != 0
   && memcmp(&zstate.command, &rule->state.command, sizeof(zstate.command))
   == 0) { /* only protocol is set.  Add all applicable commands. */
      if (!isclientrule) {
         if (rule->state.protocol.tcp) {
            rule->state.command.bind       = 1;
            rule->state.command.bindreply  = 1;
            rule->state.command.connect    = 1;
         }

         if (rule->state.protocol.udp) {
            rule->state.command.udpassociate = 1;
            rule->state.command.udpreply     = 1;
         }
      }
   }
   else if (memcmp(&zstate.command, &rule->state.command,
            sizeof(zstate.command)) != 0
   && memcmp(&zstate.protocol, &rule->state.protocol, sizeof(zstate.protocol))
   == 0) { /* only command is set.  Add all applicable protocols. */
      if (isclientrule) {
#if SOCKS_SERVER  || COVENANT /* tcp only for client-rule. */
         rule->state.protocol.tcp = 1;
#else /* BAREFOOT */
         memset(&rule->state.protocol, UCHAR_MAX, sizeof(rule->state.protocol));
#endif /* SOCKS_SERVER */
      }
      else {
         if (rule->state.command.bind
         ||  rule->state.command.bindreply
         ||  rule->state.command.connect)
            rule->state.protocol.tcp = 1;

         if (rule->state.command.udpassociate
         ||  rule->state.command.udpreply
         ||  rule->state.command.connect)
            rule->state.protocol.udp = 1;
      }
   }
   else if (memcmp(&zstate.command, &rule->state.command,
            sizeof(zstate.command)) == 0
   && memcmp(&zstate.protocol, &rule->state.protocol, sizeof(zstate.protocol))
   == 0) { /* nothing is set.  Set all. */
      if (isclientrule) {
#if SOCKS_SERVER  || COVENANT /* tcp only for client-rule. */
         rule->state.protocol.tcp = 1;
#else /* BAREFOOT */
         memset(&rule->state.protocol, UCHAR_MAX, sizeof(rule->state.protocol));
#endif /* SOCKS_SERVER */
      }
      else {
         memset(&rule->state.protocol, UCHAR_MAX, sizeof(rule->state.protocol));
         memset(&rule->state.command, UCHAR_MAX, sizeof(rule->state.command));
      }
   }
   else { /* both are set.  Don't touch. */
      SASSERTX(memcmp(&zstate.command, &rule->state.command,
               sizeof(zstate.command)) != 0);
      SASSERTX(memcmp(&zstate.protocol, &rule->state.protocol,
               sizeof(zstate.protocol)) != 0);
   }

   if (sockscf.clientmethodc == 0)
      /*
       * No methods set by user, at least so far.  Set AUTHMETHOD_NONE
       * ourselves in this case, so as to not always require the user
       * having to deal with it.
       */
      sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;

   if (methodisset(AUTHMETHOD_GSSAPI, sockscf.methodv, sockscf.methodc)
   && !methodisset(AUTHMETHOD_GSSAPI, sockscf.clientmethodv,
   sockscf.clientmethodc)) {
      /*
       * GSSAPI is a socks-method, but must be set in the client-rule
       * as the gssapi-settings must be known when establishing the
       * the session with the client.  Thus if the socks-method supports,
       * gssapi, make sure the client-method also does it.
       */
      slog(LOG_DEBUG, "%s: automatically adding method %s to global "
                      "clientmethods",
                      function, method2string(AUTHMETHOD_GSSAPI));

      /*
       * make gssapi be the preferred method.  If user wants it different,
       * he needs to configure clientmethod correctly, including gssapi.
       */
      memmove(&sockscf.clientmethodv[1],
              &sockscf.clientmethodv[0],
              sizeof(*sockscf.clientmethodv) * sockscf.clientmethodc);

      sockscf.clientmethodv[0] = AUTHMETHOD_GSSAPI;
      ++sockscf.clientmethodc;
   }

   /*
    * If no method set, set all set from global method line that make sense.
    */
   if (rule->state.methodc == 0) {
      for (i = 0; i < *methodc; ++i) {
         switch (methodv[i]) {
            case AUTHMETHOD_NONE:
               if (rule->user == NULL && rule->group == NULL)
                  rule->state.methodv[rule->state.methodc++] = methodv[i];
               break;

#if SOCKS_SERVER
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
                     if (*methodc == 1) {
                        if (sockscf.option.debug >= DEBUG_VERBOSE)
                           slog(LOG_DEBUG, "%s: let checkrules() error out "
                                           "about username in gssapi-based "
                                           "client-rule",
                                           function);
                     }
                     else
                        break;
                  }

               rule->state.methodv[rule->state.methodc++] = methodv[i];
               break;

            case AUTHMETHOD_UNAME:
            case AUTHMETHOD_BSDAUTH:
               if (isreplycommandonly(&rule->state.command))
                  continue;

               rule->state.methodv[rule->state.methodc++] = methodv[i];
               break;
#endif /* SOCKS_SERVER */

            case AUTHMETHOD_RFC931:
               /*
                * This is a bit quirky.  If both udpassociate (forward) and
                * udpreply (reverse) is set, assume what the user wants is
                * to do a rfc931 lookup on the forward (control connection),
                * but not on the reverse (where it is impossible).
                * If he has only set udpreply (reverse) for this rule though,
                * assume it's configuration error if this rule ends up without
                * any methods.
                */
               if (!rule->state.command.udpreply
               || (rule->state.command.udpreply
                && rule->state.command.udpassociate))
                  rule->state.methodv[rule->state.methodc++] = methodv[i];
               break;

            default:
               rule->state.methodv[rule->state.methodc++] = methodv[i];
         }
      }
   }

   for (i = 0; i < rule->state.methodc; ++i)
      if (!methodisset(rule->state.methodv[i], methodv, *methodc))
         yyerror("method \"%s\" is set in the rule, but not in the global "
                 "%smethod specification (%s)",
                 method2string(rule->state.methodv[i]),
                 methodv == sockscf.clientmethodv ? "client" : "",
                 methods2string(*methodc, methodv, NULL, 0));

   /* if no proxy protocol set, set appropriate. */
   if (memcmp(&zstate.proxyprotocol, &rule->state.proxyprotocol,
   sizeof(zstate.proxyprotocol)) == 0) {
#if SOCKS_SERVER
      rule->state.proxyprotocol.socks_v4 = 1;
      rule->state.proxyprotocol.socks_v5 = 1;
#elif BAREFOOTD /* !SOCKS_SERVER */
      rule->state.proxyprotocol.socks_v5 = 1;
#elif COVENANT
      rule->state.proxyprotocol.http     = 1;
#endif /* COVENANT */
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

#if HAVE_BSDAUTH
   if (*rule->state.bsdauthstylename == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_BSDAUTHSTYLENAME)
      <= sizeof(rule->state.bsdauthstylename));

      strcpy(rule->state.bsdauthstylename, DEFAULT_BSDAUTHSTYLENAME);
   }
#endif /* HAVE_BSDAUTH */

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

#if HAVE_LDAP
   if (*rule->state.ldap.keytab == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_GSSAPIKEYTAB)
      <= sizeof(rule->state.ldap.keytab));
      strcpy(rule->state.ldap.keytab, DEFAULT_GSSAPIKEYTAB);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (*rule->state.ldap.filter == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_LDAP_FILTER)
      <= sizeof(rule->state.ldap.filter));
      strcpy(rule->state.ldap.filter, DEFAULT_LDAP_FILTER);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (*rule->state.ldap.filter_AD == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_LDAP_FILTER_AD)
      <= sizeof(rule->state.ldap.filter_AD));
      strcpy(rule->state.ldap.filter_AD, DEFAULT_LDAP_FILTER_AD);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (*rule->state.ldap.attribute == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_LDAP_ATTRIBUTE)
      <= sizeof(rule->state.ldap.attribute));
      strcpy(rule->state.ldap.attribute, DEFAULT_LDAP_ATTRIBUTE);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (*rule->state.ldap.attribute_AD == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_LDAP_ATTRIBUTE_AD)
      <= sizeof(rule->state.ldap.attribute_AD));
      strcpy(rule->state.ldap.attribute_AD, DEFAULT_LDAP_ATTRIBUTE_AD);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (*rule->state.ldap.certfile == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_LDAP_CACERTFILE)
      <= sizeof(rule->state.ldap.certfile));
      strcpy(rule->state.ldap.certfile, DEFAULT_LDAP_CACERTFILE);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (*rule->state.ldap.certpath == NUL) { /* set to default. */
      SASSERTX(sizeof(DEFAULT_LDAP_CERTDBPATH)
      <= sizeof(rule->state.ldap.certpath));
      strcpy(rule->state.ldap.certpath, DEFAULT_LDAP_CERTDBPATH);
   }
   else
      rule->ldapsettingsfromuser = 1;

   if (rule->state.ldap.port == 0) /* set to default */
      rule->state.ldap.port = SOCKD_EXPLICIT_LDAP_PORT;
   else
      rule->ldapsettingsfromuser = 1;

   if (rule->state.ldap.portssl == 0) /* set to default */
      rule->state.ldap.portssl = SOCKD_EXPLICIT_LDAPS_PORT;
   else
      rule->ldapsettingsfromuser = 1;
#endif /* HAVE_LDAP */

   if (*rulebase == NULL) {
      *rulebase = rule;
      (*rulebase)->number = 1;
   }
   else { /* append this rule to the end of our list. */
      struct rule_t *lastrule;

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
#if BAREFOOTD
      if (rule->dst.atype                 == SOCKS_ADDR_IPV4
      &&  rule->dst.addr.ipv4.mask.s_addr != htonl(0xffffffff))
         yyerror("no netmask is necessary for the \"to\" address, "
                 "but if a mask is given, it must be 32, not %d",
                 bitcount(rule->dst.addr.ipv4.mask.s_addr));
#endif /* BAREFOOTD */

      for (i = 0; i < rule->state.methodc; ++i)
         if (!methodisvalid(rule->state.methodv[i], 1))
            yyerror("method %s is not valid for clientrules",
            method2string(rule->state.methodv[i]));
   }

   /* check methods.  Do they make sense with the rest of the rule? */
   for (i = 0; i < rule->state.methodc; ++i)
      switch (rule->state.methodv[i]) {
         case AUTHMETHOD_RFC931:
            /*
             * This is a bit quirky.  If both udpassociate (forward) and
             * udpreply (reverse) is set, assume what the user wants is
             * to do a rfc931 lookup on the forward (control connection),
             * but not on the reverse (where it is impossible).
             * If he has only set udpreply (reverse) for this rule though,
             * assume it's configuration error.
             */
            if (rule->state.command.udpreply
            && !rule->state.command.udpassociate)
               yyerror("method %s can not be used with the %s command",
                       method2string(AUTHMETHOD_RFC931),
                       command2string(SOCKS_UDPREPLY));
            break;

         default:
            break;
      }


   if (rule->user != NULL || rule->group != NULL
#if HAVE_LDAP
   ||  rule->ldapgroup != NULL
   ||  rule->ldapsettingsfromuser /* ldap also requires username. */
#endif /* HAVE_LDAP */
   ) {
      /* check that any methods given in rule provide usernames. */
      for (i = 0; i < rule->state.methodc; ++i) {
         switch (rule->state.methodv[i]) {
            case AUTHMETHOD_GSSAPI:
               if (isclientrule)
                  yyerror("user/group-names are not supported for method \"%s\""
                          " in client-rules.  Move the name(s) to a socks-rule",
                          method2string(rule->state.methodv[i]));
               break;

            default:
               if (!methodcanprovide(rule->state.methodv[i], username))
                  yyerror("method \"%s\" can not provide usernames",
                  method2string(rule->state.methodv[i]));
         }
      }
   }

   if (rule->rdr_from.atype != SOCKS_ADDR_NOTSET) {
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

      if (!addrisbindable(&ruleaddr)) {
         char addr[MAXRULEADDRSTRING];

         yyerror("%s is rule #%lu not bindable",
         ruleaddr2string(&ruleaddr, addr, sizeof(addr)),
         (unsigned long)rule->number);
      }
   }

   if (rule->rdr_to.atype != SOCKS_ADDR_NOTSET) {
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

#if BAREFOOTD
   if (rule->bounce_to.atype                 == SOCKS_ADDR_IPV4
   &&  rule->bounce_to.addr.ipv4.mask.s_addr != htonl(0xffffffff))
      yyerror("no netmask is necessary for the \"bounce to\" address, "
              "but if a mask is given, it must be %d, not %d",
              bitcount(0xffffffff),
              bitcount(rule->bounce_to.addr.ipv4.mask.s_addr));
#endif /* BAREFOOTD */
}

static void
showlog(log)
   const struct log_t *log;
{
   char buf[1024];

   slog(LOG_DEBUG, "log: %s", logs2string(log, buf, sizeof(buf)));
}
