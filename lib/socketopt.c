/*
 * Copyright (c) 2012, 2013
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
"$Id: socketopt.c,v 1.60 2013/10/27 15:24:42 karls Exp $";

static void
setconfsockoption(const int in, const int out, const sa_family_t safamily,
                  const int protocol, const int isclientside,
                  const int whichtime, const socketoption_t *opt);


void
socketoptioncheck(const socketoption_t *option)
{

   if (option->info->level != option->level
   && !(   (option->level == IPPROTO_UDP || option->level == IPPROTO_TCP)
        &&  option->info->level == SOL_SOCKET))
      yywarnx("to our knowledge socket option \"%s\" is not valid at the "
              "protocol level given (%s/%d)",
              option->info->name,
              sockoptlevel2string(option->level),
              option->level);

   if (option->info->mask != 0) {
      SASSERTX(option->info->opttype == int_val
      ||       option->info->opttype == uchar_val);

      if ((~option->info->mask & option->optval.int_val) != 0)
         yywarnx("to our knowledge socket option %s can not have the value %d",
                 option->info->name, option->optval.int_val);
   }
}

int
addedsocketoption(optc, optv, newoption)
   size_t *optc;
   socketoption_t **optv;
   const socketoption_t *newoption;
{
   const char *function = "addedsocketoption()";
   void *newoptv;

   slog(LOG_DEBUG, "%s: adding socket option %s.  Currently have %lu options",
        function, sockopt2string(newoption, NULL, 0), (unsigned long)*optc);

   if (newoption->info != NULL && newoption->info->calltype == invalid) {
      yywarnx("option \"%s\" not user settable, ignoring",
              newoption->info->name);

      return 0;
   }

   if ((newoptv = realloc(*optv, sizeof(**optv) * (*optc + 1))) == NULL) {
      yywarn("could not allocate %lu bytes of memory to expand list of "
             "socket options",
             (unsigned long)(sizeof(**optv) * (*optc + 1)));

      return 0;
   }

   *optv              = newoptv;
   (*optv)[(*optc)++] = *newoption;

   return 1;
}

void
setconfsockoptions(target, in, protocol, isclientside, optc, optv,
                   whichlocals, whichglobals)
   const int target;
   const int in;
   const int protocol;
   const int isclientside;
   const size_t optc;
   const socketoption_t *optv;
   const int whichlocals;
   const int whichglobals;
{
   const char *function = "setconfsockoptions()";
   struct sockaddr addr;
   socklen_t len;
   size_t i;

   slog(LOG_DEBUG,
        "%s: going through options, looking for %s socket options for fd %d "
        "(in: %d) on the %s side",
        function,
        protocol2string(protocol),
        target,
        in,
        isclientside ? "internal" : "external");

   len = sizeof(addr);
   if (getsockname(target, &addr, &len) != 0) {
      slog(LOG_DEBUG, "%s: getsockname(2) on target-fd %d failed: %s",
           function, target, strerror(errno));

      return;
   }

   if (whichglobals) {
      /*
       * Set the globals first so that it is possible for the user to
       * override them locally in a rule/route.
       */

      slog(LOG_DEBUG,
           "%s: going through global array with %lu options, looking for "
           "globals matching %d (%s)",
           function,
           (unsigned long)sockscf.socketoptionc,
           whichglobals,
           socketsettime2string(whichglobals));

      for (i = 0; i < sockscf.socketoptionc; ++i)
         setconfsockoption(target,
                           in,
                           addr.sa_family,
                           protocol,
                           isclientside,
                           whichglobals,
                           &sockscf.socketoptionv[i]);
   }

   if (whichlocals) {
      slog(LOG_DEBUG,
           "%s: going through local array with %lu options, looking for "
           "locals matching %d",
           function, (unsigned long)optc, whichlocals);

      for (i = 0; i < optc; ++i)
         setconfsockoption(target,
                           in,
                           addr.sa_family,
                           protocol,
                           isclientside,
                           whichlocals,
                           &optv[i]);
   }
}

static void
setconfsockoption(target, in, safamily, protocol, isclientside, whichtime, opt)
   const int target;
   const int in;
   const sa_family_t safamily;
   const int protocol;
   const int isclientside;
   const int whichtime;
   const socketoption_t *opt;
{
   const char *function = "setconfsockoption()";
   socketoptvalue_t newvalue;
   socklen_t len;
   int rc;

   slog(LOG_DEBUG,
        "%s: checking protocol %s on the %s-side for whether socket option "
        "%s should be set at %s (%d) on %s target socket",
        function,
        protocol2string(protocol),
        isclientside ? "internal" : "external",
        sockopt2string(opt, NULL, 0),
        socketsettime2string(whichtime),
        whichtime,
        safamily2string(safamily));

   if (opt->info != NULL) {
      if (safamily == AF_INET  && !opt->info->ipv4_on)
         return;

      if (safamily == AF_INET6 && !opt->info->ipv6_on)
         return;

      if (((whichtime & SOCKETOPT_ANYTIME) && opt->info->calltype == anytime)
      ||  ((whichtime & SOCKETOPT_PRE)     && opt->info->calltype == preonly)
      ||  ((whichtime & SOCKETOPT_POST)    && opt->info->calltype == postonly))
         ;
      else
         return;
   }

   if (opt->isinternalside && !isclientside)
      return;

   if (!opt->isinternalside && isclientside)
      return;

/*
 * Does socketlevel "socketlevel" work with any l4 protocol?
 */
#define ANY_L4_PROTOCOL(socketlevel)                                           \
   ((socketlevel) == SOL_SOCKET || (socketlevel) == IPPROTO_IP)

   if (protocol    == SOCKS_TCP
   && !(ANY_L4_PROTOCOL(opt->level) || opt->level == IPPROTO_TCP))
      return;

   if (protocol    == SOCKS_UDP
   && !(ANY_L4_PROTOCOL(opt->level) || opt->level == IPPROTO_UDP))
      return;

   slog(LOG_DEBUG, "%s: setting %s", function, sockopt2string(opt, NULL, 0));

   if (opt->info != NULL) {
      if (opt->info->shift) {
         socketoptvalue_t oldvalue;
         const int mask = opt->info->mask << opt->info->shift;

         SASSERTX(opt->info->opttype == int_val
         ||       opt->info->opttype == uchar_val);

         bzero(&oldvalue, sizeof(oldvalue));

         switch (opt->opttype) {
            case int_val:
               newvalue.int_val = opt->optval.int_val << opt->info->shift;
               oldvalue.int_val &= (~mask);
               newvalue.int_val |= oldvalue.int_val;
               break;

            case uchar_val:
               newvalue.uchar_val= opt->optval.uchar_val << opt->info->shift;
               oldvalue.uchar_val &= (~mask);
               newvalue.uchar_val |= oldvalue.uchar_val;
               break;

            default:
               SERRX(opt->opttype);
         }
      }
      else
         newvalue = opt->optval;
   }
   else
      newvalue = opt->optval;

#if !SOCKS_CLIENT
   if (opt->info != NULL && opt->info->needpriv)
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
#endif /* !SOCKS_CLIENT */

   switch (opt->optname) {
      /*
       * Special cases.
       */

#if HAVE_SOCKS_HOSTID
#ifdef TCP_IPA
      case TCP_IPA: {
         struct sockaddr_storage raddr;
         struct in_addr hostidv[HAVE_MAX_HOSTIDS];
         unsigned char hostidc;
         int getraddr, gethostid;

         switch (newvalue.int_val) {
            case SOCKS_HOSTID_NONE:
               getraddr  = 0;
               gethostid = 0;
               break;

            case SOCKS_HOSTID_SETCLIENT:
               getraddr  = 1;
               gethostid = 0;
               break;

            case SOCKS_HOSTID_PASS:
            case SOCKS_HOSTID_ADDCLIENT:
               getraddr  = 1;
               gethostid = 1;
               break;

            default:
               SERRX(0);
               /* NOTREACHED */
         }

         if (getraddr) {
            len = sizeof(raddr);
            if (getpeername(in, TOSA(&raddr), &len) == -1) {
               slog(LOG_DEBUG,
                    "%s: getpeername(2) on fd %d failed (%s).  Presumably "
                    "the connection has timed out",
                    function, in, strerror(errno));
               return;
            }
         }

         if (gethostid) {
            SASSERTX(getraddr);

            hostidc = getsockethostid(in, ELEMENTS(hostidv), hostidv);
            slog(LOG_DEBUG, "%s: retrieved %u hostids on fd %d from client %s",
                 function,
                 (unsigned)hostidc,
                 in,
                 sockaddr2string(&raddr, NULL, 0));
         }

         switch (newvalue.int_val) {
            case SOCKS_HOSTID_NONE:
               hostidc = 0;
               break;

            case SOCKS_HOSTID_SETCLIENT:
               hostidv[0] = TOIN(&raddr)->sin_addr;
               hostidc    = 1;
               break;

            case SOCKS_HOSTID_PASS:
               SASSERTX(gethostid);
               break; /* nothing to add/remove. */

            case SOCKS_HOSTID_ADDCLIENT:
               SASSERTX(gethostid);
               if ((size_t)(hostidc) + 1 > ELEMENTS(hostidv)) {
                  char ntop[MAXSOCKADDRSTRING];

                  SASSERTX(getraddr);

                  if (inet_ntop(AF_INET,
                                &hostidv[hostidc - 1],
                                ntop,
                                sizeof(ntop)) == NULL) {
                     swarn("%s: inet_ntop(3) failed on %s %x",
                          function,
                          atype2string(SOCKS_ADDR_IPV4),
                          hostidv[hostidc - 1].s_addr);

                     snprintf(ntop, sizeof(ntop), "<unknown>");
                  }

                  slog(LOG_WARNING,
                       "%s: connection from %s has already reached the maximum "
                       "number of hostids (%u); can not add more.  Discarding "
                       "the last hostid (%s) before adding the new one",
                       function,
                       sockaddr2string(&raddr, NULL, 0),
                       (unsigned)hostidc,
                       ntop);

                  hostidc = (unsigned char)ELEMENTS(hostidv) - 1;
               }

               hostidv[hostidc++] = TOIN(&raddr)->sin_addr;
               break;

            default:
               SERRX(newvalue.int_val);
               /* NOTREACHED */
         }

         len = sizeof(*hostidv) * hostidc;
         if ((rc = setsockethostid(target, hostidc, hostidv)) != 0)
            swarn("%s: setsockethostid() on fd %d failed",
                  function, target);
         break;
      }
#endif /* TCP_IPA */
#endif /* HAVE_SOCKS_HOSTID */

      /*
       * The generic cases.
       */

      default:
         len = SOCKETOPTVALUETYPE2SIZE(opt->opttype);
         rc  = setsockopt(target,
                          opt->info == NULL ? opt->level : opt->info->level,
                          opt->optname,
                          &newvalue,
                          len);
   }

   if (rc != 0)
      swarn("%s: failed to set socket option %s of size %lu",
            function, sockopt2string(opt, NULL, 0), (unsigned long)len);
   else
      slog(LOG_DEBUG, "%s: set option %s to %s (len %d)",
           function,
           sockopt2string(opt, NULL, 0),
           sockoptval2string(newvalue, opt->opttype, NULL, 0),
           len);


#if !SOCKS_CLIENT
   if (opt->info != NULL && opt->info->needpriv)
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
#endif /* !SOCKS_CLIENT */
}
