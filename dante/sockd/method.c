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

static const char rcsid[] =
"$Id: method.c,v 1.9 2011/05/18 13:48:46 karls Exp $";

int
methodisvalid(method, forclientrules)
   const int method;
   const int forclientrules;
{

   if (forclientrules) {
      switch (method) {
         case AUTHMETHOD_NONE:
         case AUTHMETHOD_GSSAPI: /* XXX hmm. */
         case AUTHMETHOD_RFC931:
         case AUTHMETHOD_PAM:
            return 1;

         default:
            return 0;
      }
   }
   else {
      switch (method) {
         case AUTHMETHOD_NONE:
         case AUTHMETHOD_UNAME:
         case AUTHMETHOD_GSSAPI:
         case AUTHMETHOD_RFC931:
         case AUTHMETHOD_PAM:
         case AUTHMETHOD_BSDAUTH:
            return 1;

         default:
            return 0;
      }
   }
}


int
methodcanprovide(method, what)
   const int method;
   const methodinfo_t what;
{
   const char *function = "methodcanprovide()";

   switch (method) {
      case AUTHMETHOD_NOTSET:
         return 0; /* does not provide anything. */

      case AUTHMETHOD_NONE:
         return 0; /* does not provide anything. */

      case AUTHMETHOD_GSSAPI:
         switch (what) {
            case username:
               return 1;
         }

         return 0;

      case AUTHMETHOD_UNAME:
         switch (what) {
            case username:
               return 1;
         }

         return 0;

      case AUTHMETHOD_RFC931:
         switch (what) {
            case username:
               return 1;
         }

         return 0;

      case AUTHMETHOD_PAM:
         switch (what) {
            case username:
               return 1;
         }

         return 0;

      case AUTHMETHOD_BSDAUTH:
         switch (what) {
            case username:
               return 1;
         }

         return 0;

      default:
         SERRX(method);
   }

   return 0; /* NOTREACHED */
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

#if HAVE_BSDAUTH
      case AUTHMETHOD_BSDAUTH:
         return (const char *)auth->mdata.bsd.name;
#endif /* HAVE_BSDAUTH */

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

   if (info == NULL || infolen == 0) {
      static char buf[MAXAUTHINFOLEN];

      info    = buf;
      infolen = sizeof(buf);
   }

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
      snprintf(info, infolen, "%s%s%s%%%s@",
               method,
               methodinfo == NULL ? "" : "/",
               methodinfo == NULL ? "" : methodinfo,
               name);

   return info;
}
