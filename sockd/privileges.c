/*
 * Copyright (c) 2009, 2010, 2011, 2012
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
"$Id: privileges.c,v 1.32 2012/06/01 20:23:06 karls Exp $";

static privilege_t lastprivelege = SOCKD_PRIV_NOTSET;

int
sockd_initprivs(void)
{
   const char *function = "sockd_initprivs()";

#if HAVE_SOLARIS_PRIVS
   priv_set_t *privset;
   const char *extra_privs[] = {
      PRIV_FILE_DAC_READ,    /* password file, and pam? */
      PRIV_FILE_DAC_SEARCH,  /* password file, and pam? */
      PRIV_FILE_DAC_WRITE,   /* writing pidfile.       */
      PRIV_NET_PRIVADDR,     /*
                              * binding ports < 1024 on behalf of the client,
                              * if so configured.
                              */
#if BAREFOOTD
      PRIV_NET_ICMPACCESS,   /* listening for icmp errors from udp packets. */
#endif /* BAREFOOTD */
   };
   size_t i;

   if ((sockscf.privileges.privileged   = priv_allocset()) == NULL
   ||  (sockscf.privileges.unprivileged = priv_allocset()) == NULL)
      serr(EXIT_FAILURE, "%s: priv_allocset()", function);

   if ((privset = priv_str_to_set ("basic", ",", NULL)) == NULL)
      serr(EXIT_FAILURE, "%s: priv_str_to_set failed", function);

   /*
    * First add/remove from the basic set and store it as the unprivileged set.
    * The unprivileged set is also the set used by libwrap.
    */

   /* add ... */

#if 0
   /* ... and remove. */

   /*
    * removing this would mean libwraps exec statement won't work, but
    * probably nobody uses that from sockd anyway.  Could it be needed
    * by pam, though?  Leave it in for now.
    */
   if (priv_delset(privset, PRIV_PROC_EXEC) != 0) {
      swarn("%s: can't remove %s privilege", function, PRIV_PROC_EXEC);
      return -1;
   }
#endif

   priv_copyset(privset, sockscf.privileges.unprivileged);

   /*
    * Then add the extra privileges we need.
    */

   for (i = 0; i < ELEMENTS(extra_privs); ++i)
      if (priv_addset(privset, extra_privs[i]) != 0) {
         swarn("%s: can't add %s privilege", function, extra_privs[i]);
         return -1;
      }
      else
         slog(LOG_DEBUG, "%s: added privilege %s to the privileged set",
         function, extra_privs[i]);

   /* max privileges we may need. */
   priv_copyset(privset, sockscf.privileges.privileged);
   priv_freeset(privset);

   if (setppriv(PRIV_SET, PRIV_PERMITTED, sockscf.privileges.privileged)
   == -1) {
      swarn("%s: can't set PRIV_PERMITTED privileged", function);
      return -1;
   }

   /* this is what we'll be running with normally. */
   if (setppriv(PRIV_SET, PRIV_EFFECTIVE, sockscf.privileges.unprivileged)
   == -1) {
      swarn("%s: can't set PRIV_EFFECTIVE to unprivileged", function);
      return -1;
   }

   /* applied upon exec only.  Only relevant for libwrap, or pam too?  */
   if (setppriv(PRIV_SET, PRIV_INHERITABLE, sockscf.privileges.unprivileged)
   == -1) {
      swarn("%s: can't set PRIV_INHERITABLE to unprivileged", function);
      return -1;
   }

   setreuid(getuid(), getuid());
   setregid(getgid(), getgid());

   slog(LOG_DEBUG, "%s: privileges relinquished successfully", function);
   sockscf.privileges.haveprivs = 1;
#else /* !HAVE_SOLARIS_PRIVS */

   if (socks_seteuid(NULL, sockscf.uid.unprivileged) != 0)
      serr(EXIT_FAILURE, "%s: socks_seteuid to unprivileged uid failed",
           function);

   slog(LOG_DEBUG, "%s: will use uid %u normally",
        function, (unsigned)sockscf.uid.unprivileged);
#endif /* !HAVE_SOLARIS_PRIVS */

   return 0;
}

void
sockd_priv(privilege, op)
   const privilege_t privilege;
   const priv_op_t op;
{
   const char *function = "sockd_priv()";
#if HAVE_SOLARIS_PRIVS
   static priv_set_t *lastprivset;
#else /* !HAVE_SOLARIS_PRIVS */
   static uid_t lasteuid;
   int p;
#endif /* !HAVE_SOLARIS_PRIVS */

#if HAVE_SOLARIS_PRIVS
   if (!sockscf.privileges.haveprivs)
      return;

   if (lastprivset == NULL)
      if ((lastprivset = priv_allocset()) == NULL)
          serr(EXIT_FAILURE, "%s: priv_allocset()", function);
#endif /* HAVE_SOLARIS_PRIVS */

   slog(LOG_DEBUG, "%s: switching privilege %d %s",
        function, privilege, privop2string(op));


   /*
    * these asserts are only valid as long as we never turn more than
    * one privilege on/off at a time.  If that ever changes, we need
    * to remove these asserts, but til then, they are useful.
    */
   if (op == PRIV_ON) {
      SASSERTX(lastprivelege == SOCKD_PRIV_NOTSET);
      lastprivelege = privilege;

#if HAVE_SOLARIS_PRIVS
      switch (privilege) {
         /*
          * needs to be handled special, as it's not a single privilege
          * we turn on/off, but a set we PRIV_SET.
          */
         case SOCKD_PRIV_PRIVILEGED:
         case SOCKD_PRIV_LIBWRAP:
         case SOCKD_PRIV_UNPRIVILEGED:
         case SOCKD_PRIV_PAM:
         case SOCKD_PRIV_BSDAUTH:
            if (getppriv(PRIV_EFFECTIVE, lastprivset) != 0) {
               SWARN(errno);
               swarn("%s: very strange ...  getppriv(PRIV_EFFECTIVE) failed.  "
                     "This might not work out too well ...",
                     function);
            }
            break;

         default:
            break;
      }
#endif /* HAVE_SOLARIS_PRIVS */
   }
   else {
      SASSERTX(op == PRIV_OFF);
      SASSERTX(lastprivelege == privilege);
      lastprivelege = SOCKD_PRIV_NOTSET;
   }

   switch (privilege) {
      /* the full sets. */
      case SOCKD_PRIV_PRIVILEGED:
      case SOCKD_PRIV_LIBWRAP:
      case SOCKD_PRIV_UNPRIVILEGED:
      case SOCKD_PRIV_PAM:
      case SOCKD_PRIV_BSDAUTH: {
#if HAVE_SOLARIS_PRIVS
         priv_set_t *privtoset;

         if (op == PRIV_ON) {
            switch (privilege) {
               case SOCKD_PRIV_PRIVILEGED:
               case SOCKD_PRIV_PAM:
               case SOCKD_PRIV_BSDAUTH:
                  privtoset = sockscf.privileges.privileged;
                  break;

               case SOCKD_PRIV_UNPRIVILEGED:
               case SOCKD_PRIV_LIBWRAP: /* currently the same. */
                  privtoset = sockscf.privileges.unprivileged;
                  break;

               default:
                  SERRX(privilege);
            }
         }
         else
            privtoset = lastprivset;

         if (setppriv(PRIV_SET, PRIV_EFFECTIVE, privtoset) != 0)
            serr(EXIT_FAILURE, "%s: switching privilege level %d %s failed",
            function, (int)privilege, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */
         int haveeuid;
         uid_t neweuid;

         switch (privilege) {
            case SOCKD_PRIV_PRIVILEGED:
            case SOCKD_PRIV_PAM:
            case SOCKD_PRIV_BSDAUTH:
               if (sockscf.uid.privileged_isset) {
                  neweuid  = sockscf.uid.privileged;
                  haveeuid = 1;
               }
               else
                  haveeuid = 0;
               break;

            case SOCKD_PRIV_UNPRIVILEGED:
               if (sockscf.uid.unprivileged_isset) {
                  neweuid  = sockscf.uid.unprivileged;
                  haveeuid = 1;
               }
               else
                  haveeuid = 0;
               break;

            case SOCKD_PRIV_LIBWRAP:
               if (sockscf.uid.libwrap_isset) {
                  neweuid  = sockscf.uid.libwrap;
                  haveeuid = 1;
               }
               else
                  haveeuid = 0;
               break;

            default:
               SERRX(privilege);
         }

         if (!haveeuid)
            break;

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, neweuid);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
            function, op == PRIV_ON ? (unsigned)neweuid : (unsigned)lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;
      }

      case SOCKD_PRIV_FILE_READ:
      case SOCKD_PRIV_GSSAPI:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_SEARCH, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_FILE_DAC_SEARCH %s failed",
            function, privop2string(op));

         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_READ, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_FILE_DAC_READ %s failed",
            function, privop2string(op));
#else /* !HAVE_SOLARIS_PRIVS */
         if (!sockscf.uid.privileged_isset)
            break;

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_FILE_WRITE:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_SEARCH, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_FILE_DAC_SEARCH %s failed",
            function, privop2string(op));

         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_READ, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_FILE_DAC_READ %s failed",
            function, privop2string(op));

         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_WRITE, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_FILE_DAC_WRITE %s failed",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */
         if (!sockscf.uid.privileged_isset)
            break;

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_NET_ADDR:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_NET_PRIVADDR, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_NET_PRIVADDR %s failed",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */
         if (!sockscf.uid.privileged_isset)
            break;

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_NET_ICMPACCESS:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_NET_ICMPACCESS, NULL) != 0)
            serr(EXIT_FAILURE, "%s: switching PRIV_NET_ICMPACCESS %s failed",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */
         if (!sockscf.uid.privileged_isset)
            break;

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_NET_ROUTESOCKET:
#if HAVE_SOLARIS_PRIVS
         /* nothing special required on Solaris apparently. */

#else /* !HAVE_SOLARIS_PRIVS */
         if (!sockscf.uid.privileged_isset)
            break;

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_INITIAL:
#if !HAVE_SOLARIS_PRIVS /* only used with uids. */
         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.state.euid);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: switching to euid %u failed",
                 function, op == PRIV_ON ? sockscf.state.euid : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      default:
         SERRX(privilege);
   }
}
