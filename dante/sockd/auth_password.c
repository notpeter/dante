/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2009
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
"$Id: auth_password.c,v 1.15 2009/01/02 14:06:07 michaels Exp $";

int
passwordcheck(name, clearpassword, emsg, emsglen)
   const char *name;
   const char *clearpassword;
   char *emsg;
   size_t emsglen;
{
   const char *function = "passwordcheck()"; 
   struct passwd *pw;
   char password[MAXPWLEN];
   uid_t euid;
   int rc;

   socks_seteuid(&euid, sockscf.uid.privileged);

   if ((pw = socks_getpwnam(name)) == NULL) {
      socks_reseteuid(sockscf.uid.privileged, euid);
      snprintfn(emsg, emsglen, "no such system user");
      return -1;
   }

   /* copy it before socks_reseteuid() can overwrite it. */
   strncpy(password, pw->pw_passwd, sizeof(password) - 1);
   password[sizeof(password) - 1] = NUL;

   socks_reseteuid(sockscf.uid.privileged, euid);

   slog(LOG_DEBUG, "%s: clearpassword = %s\n", function, clearpassword);
   if (clearpassword == NULL) /* rfc931. */
      rc = 0;
   else {
      const char *salt = password;

      if (strcmp(crypt(clearpassword, salt), password) == 0)
         rc = 0;
      else {
         snprintfn(emsg, emsglen, "system password authentication failed");
         rc = -1;
      }
   }

   bzero(password, sizeof(password));
   return rc;
}
