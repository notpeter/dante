/*
 * Copyright (c) 2009
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
"$Id: privileges.c,v 1.11 2009/10/23 10:37:26 karls Exp $";

static privilege_t lastprivelege;

void
init_privs(void)
{
   const char *function = "init_privs()";

#if HAVE_SOLARIS_PRIVS
   priv_set_t *privset;

   if ((sockscf.privileges.privileged   = priv_allocset()) == NULL
   ||  (sockscf.privileges.unprivileged = priv_allocset()) == NULL)
      serr(EXIT_FAILURE, "%s: priv_allocset()", function);

   if ((privset = priv_str_to_set ("basic", ",", NULL)) == NULL)
      serr(EXIT_FAILURE, "%s: priv_str_to_set failed", function);

   /*
    * First remove what we don't need from the basic set.
    */


#if 0
   /*
    * this means libwraps exec statement won't work, but probably
    * nobody uses that from sockd anyway.  Could it be needed
    * by pam, though?  Leave it in for now.
    */
   if (priv_delset(privset, PRIV_PROC_EXEC) != 0) {
      swarn("%s: can't remove PROC_EXEC privilege", function);
      sockscf.privileges.noprivs = 1;
   }
#endif

   priv_copyset(privset, sockscf.privileges.unprivileged);

   /*
    * Then add the extra privileges we need.
    */

   /* reading passwordfile, and pam? */
   if (priv_addset(privset, PRIV_FILE_DAC_READ) != 0) {
      swarn("%s: can't add FILE_DAC_READ privilege", function);
      sockscf.privileges.noprivs = 1;
   }

   /* passwordfile, and pam? */
   if (priv_addset(privset, PRIV_FILE_DAC_SEARCH) != 0) {
      swarn("%s: can't add FILE_DAC_SEARCH privilege", function);
      sockscf.privileges.noprivs = 1;
   }

   /* writing pidfile. */
   if (priv_addset(privset, PRIV_FILE_DAC_WRITE) != 0) {
      swarn("%s: can't add FILE_DAC_WRITE privilege", function);
      sockscf.privileges.noprivs = 1;
   }

   /* binding ports < 1024 on behalf of the client, if so configured. */
   if (priv_addset(privset, PRIV_NET_PRIVADDR) != 0) {
      swarn("%s: can't add NET_PRIVADDR privilege", function);
      sockscf.privileges.noprivs = 1;
   }

#if BAREFOOTD
   /* listening for icmp errors regarding sent udp packets. */
   if (priv_addset(privset, PRIV_NET_ICMPACCESS) != 0) {
      swarn("%s: can't add NET_RAWACCESS privilege", function);
      sockscf.privileges.noprivs = 1;
   }
#endif

   /* max privileges we may need. */
   priv_copyset(privset, sockscf.privileges.privileged);
   if (setppriv(PRIV_SET, PRIV_PERMITTED, sockscf.privileges.privileged) == -1){
      swarn("%s: can't set permitted privilege set", function);
      sockscf.privileges.noprivs = 1;
   }
   priv_freeset(privset);

   /* this is what we'll be running with normally. */
   if (setppriv(PRIV_SET, PRIV_EFFECTIVE, sockscf.privileges.unprivileged)
   == -1) {
      swarn("%s: can't set PRIV_EFFECTIVE", function);
      sockscf.privileges.noprivs = 1;
   }

   setreuid(getuid(), getuid());
   setregid(getgid(), getgid());

   if (sockscf.privileges.noprivs)
      slog(LOG_DEBUG, "%s: privileges relinquished successfully", function);
   else
      swarnx("%s: disabling privilege switching due to errors", function);

#else /* !HAVE_SOLARIS_PRIVS */

   if (socks_seteuid(NULL, sockscf.uid.unprivileged) != 0)
      serr(EXIT_FAILURE, "%s: socks_seteuid to unprivileged uid failed",
      function);

   slog(LOG_DEBUG, "%s: will use uid %u normally",
   function, (int)sockscf.uid.unprivileged);

#endif /* !HAVE_SOLARIS_PRIVS */

   lastprivelege = SOCKD_PRIV_NOTSET;
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
   if (sockscf.privileges.noprivs)
      return;
#endif /* HAVE_SOLARIS_PRIVS */

   slog(LOG_DEBUG, "%s: switching privilege %d %s",
   function, privilege, privop2string(op));

#if HAVE_SOLARIS_PRIVS
   if (lastprivset == NULL)
      if ((lastprivset = priv_allocset()) == NULL)
          serr(EXIT_FAILURE, "%s: priv_allocset()", function);
#endif /* HAVE_SOLARIS_PRIVS */

   if (op == PRIV_ON) {
      SASSERTX(lastprivelege == SOCKD_PRIV_NOTSET);
      lastprivelege = privilege;
   }
   else {
      SASSERTX(lastprivelege == privilege);
      lastprivelege = SOCKD_PRIV_NOTSET;
   }

   switch (privilege) {
      case SOCKD_PRIV_FILE_READ:
      case SOCKD_PRIV_GSSAPI:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_SEARCH, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_FILE_DAC_SEARCH %s",
            function, privop2string(op));

         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_READ, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_FILE_DAC_READ %s",
            function, privop2string(op));
#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_FILE_WRITE:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_SEARCH, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_FILE_DAC_SEARCH %s",
            function, privop2string(op));

         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_READ, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_FILE_DAC_READ %s",
            function, privop2string(op));

         if (priv_set(op, PRIV_EFFECTIVE, PRIV_FILE_DAC_WRITE, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_FILE_DAC_WRITE %s",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_NET_ADDR:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_NET_PRIVADDR, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_NET_PRIVADDR %s",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_NET_ICMPACCESS:
#if HAVE_SOLARIS_PRIVS
         if (priv_set(op, PRIV_EFFECTIVE, PRIV_NET_ICMPACCESS, NULL) != 0)
            serr(EXIT_FAILURE, "%s: error switching PRIV_NET_ICMPACCESS %s",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_NET_ROUTESOCKET:
#if HAVE_SOLARIS_PRIVS
         /* nothing special required on Solaris apparently. */

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;

      case SOCKD_PRIV_PRIVILEGED:
      case SOCKD_PRIV_PAM: {
#if HAVE_SOLARIS_PRIVS
         priv_set_t *privtoset;

         if (op == PRIV_ON)
            privtoset = sockscf.privileges.privileged;
         else
            privtoset = lastprivset;

         if (setppriv(op, PRIV_EFFECTIVE, privtoset) != 0)
            serr(EXIT_FAILURE, "%s: error switching privileged level %s",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.privileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;
      }

      case SOCKD_PRIV_LIBWRAP: {
#if HAVE_SOLARIS_PRIVS
         priv_set_t *privtoset;

         if (op == PRIV_ON)
            privtoset = sockscf.privileges.privileged;
         else
            privtoset = lastprivset;

         if (setppriv(op, PRIV_EFFECTIVE, privtoset) != 0)
            serr(EXIT_FAILURE, "%s: error switching privileged level %s",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.libwrap);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;
      }

      case SOCKD_PRIV_UNPRIVILEGED: {
#if HAVE_SOLARIS_PRIVS
         priv_set_t *privtoset;

         if (op == PRIV_ON)
            privtoset = sockscf.privileges.unprivileged;
         else
            privtoset = lastprivset;

         if (setppriv(op, PRIV_EFFECTIVE, privtoset) != 0)
            serr(EXIT_FAILURE, "%s: error switching privileged level %s",
            function, privop2string(op));

#else /* !HAVE_SOLARIS_PRIVS */

         if (op == PRIV_ON)
            p = socks_seteuid(&lasteuid, sockscf.uid.unprivileged);
         else
            p = socks_seteuid(NULL, lasteuid);

         if (p != 0)
            serr(EXIT_FAILURE, "%s: error switching to euid %u",
            function, op == PRIV_ON ? sockscf.uid.privileged : lasteuid);
#endif /* !HAVE_SOLARIS_PRIVS */

         break;
      }

      default:
         SERRX(privilege);
   }

#if HAVE_SOLARIS_PRIVS
   if (getppriv(PRIV_EFFECTIVE, lastprivset) != 0)
      serr(EXIT_FAILURE, "%s: unable to get current PRIV_EFFECTIVE set",
      function);
#endif /* HAVE_SOLARIS_PRIV */
}
