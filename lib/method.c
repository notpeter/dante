/*
 * Copyright (c) 2010, 2011, 2012, 2013
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
"$Id: method.c,v 1.25 2013/10/27 15:24:42 karls Exp $";

int
methodisvalid(method, ruletype)
   const int method;
   const objecttype_t ruletype;
{

   switch (ruletype) {
      case object_crule:
#if HAVE_SOCKS_HOSTID
      case object_hrule:
#endif /* HAVE_SOCKS_HOSTID */

         switch (method) {
            case AUTHMETHOD_NONE:
            case AUTHMETHOD_RFC931:
            case AUTHMETHOD_PAM_ANY:
            case AUTHMETHOD_PAM_ADDRESS:
               return 1;

            default:
               return 0;
         }

         /* NOTREACHED */

      case object_srule:
         /* all methods are valid for socks-rules. */
         return 1;

      default:
         SERRX(ruletype);
   }

   /* NOTREACHED */
}

#if !SOCKS_CLIENT
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

      case AUTHMETHOD_PAM_ANY:
         return 0; /* may provide something, but can not depend on it. */

      case AUTHMETHOD_BSDAUTH:
      case AUTHMETHOD_GSSAPI:
      case AUTHMETHOD_PAM_ADDRESS:
      case AUTHMETHOD_PAM_USERNAME:
      case AUTHMETHOD_RFC931:
      case AUTHMETHOD_UNAME:
         switch (what) {
            case username:
               return 1;

            default:
               return 0;
         }

         /* NOTREACHED */

      default:
         SERRX(method);
   }

   return 0; /* NOTREACHED */
}

int
methodworkswith(method, what)
   const int method;
   const methodinfo_t what;
{
   const char *function = "methodworkswith()";

   switch (method) {
      case AUTHMETHOD_NOTSET:
         return 0; /* does not work with anything. */

      case AUTHMETHOD_NONE:
         switch (what) {
            case tcpreplies:
            case udpreplies:
            case replies:
               return 1;

            default:
               SERRX(what);
         }
         break;

      case AUTHMETHOD_PAM_ANY:
      case AUTHMETHOD_PAM_ADDRESS:
      case AUTHMETHOD_RFC931:
         switch (what) {
            case replies:
            case udpreplies:
               return 0;

            case tcpreplies:
               return 1;

            default:
               SERRX(what);
         }
         break;

      default:
         switch (what) {
            case udpreplies:
            case tcpreplies:
            case replies:
               return 0;

            default:
               SERRX(what);
         }
         break;
   }

   return 0; /* NOTREACHED */
}


const char *
authname(auth)
   const authmethod_t *auth;
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
      case AUTHMETHOD_PAM_ANY:      /* maybe there is a name, maybe not. */
      case AUTHMETHOD_PAM_ADDRESS:
      case AUTHMETHOD_PAM_USERNAME:
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

char *
build_addrstr_src(hostidv, hostidc, peer, proxy_ext, proxy, local,
                  peerauth, proxyauth, str, strsize)
   const struct in_addr *hostidv;
   const unsigned int hostidc;
   const sockshost_t *peer;
   const sockshost_t *proxy_ext;
   const sockshost_t *proxy;
   const sockshost_t *local;
   const authmethod_t *peerauth;
   const authmethod_t *proxyauth;
   char *str;
   size_t strsize;
{
   const char *function = "build_addrstr_src()";
   size_t strused;
   char peerstr[MAXSOCKSHOSTSTRING], peerauthstr[MAXAUTHINFOLEN],
        proxyauthstr[MAXAUTHINFOLEN], pstr[MAXSOCKSHOSTSTRING],
        pe_str[MAXSOCKSHOSTSTRING + sizeof("[]")], lstr[MAXSOCKSHOSTSTRING];

   strused = 0;
   if (hostidv != NULL && hostidc > 0) {
      size_t i;

      for (i = 0; i < hostidc; ++i) {
         char ntop[MAXSOCKADDRSTRING];

         if (inet_ntop(AF_INET, &hostidv[i], ntop, sizeof(ntop)) == NULL) {
            slog(LOG_DEBUG, "%s: inet_ntop(3) failed on %s %x: %s",
                 function,
                 atype2string(SOCKS_ADDR_IPV4),
                 hostidv[i].s_addr,
                 strerror(errno));

             snprintf(ntop, sizeof(ntop), "<unknown>");
         }

         strused += snprintf(&str[strused], strsize - strused,
                             "%s[%s]",
                             i > 0 ? " " : "",
                             ntop);

      }
      if ((strused + 1) < strsize) {
         str[strused]      = ' ';
         str[strused + 1]  = NUL;
         strused           += 1;
      }
   }

   if ((proxy_ext) == NULL)
      *pe_str = NUL;
   else
      snprintf(pe_str, sizeof(pe_str),
               "[%s] ", sockshost2string(proxy_ext, NULL, 0));

   snprintf(&str[strused], strsize - strused,
            "%s%s "
            "%s"
            "%s%s%s"
            "%s",

            authinfo((peerauth), peerauthstr, sizeof(peerauthstr)),
            (peer) == NULL ?
               "0.0.0.0.0" : sockshost2string((peer), peerstr, sizeof(peerstr)),

            pe_str,

            authinfo((proxyauth), proxyauthstr, sizeof(proxyauthstr)),
            (proxy) == NULL ?
               "" : sockshost2string((proxy), pstr, sizeof(pstr)),
            (proxy) == NULL ? "" : " ",

            (local) == NULL ?
               "0.0.0.0.0" : sockshost2string((local), lstr, sizeof(lstr)));

   return str;
}

char *
build_addrstr_dst(local, proxy, proxy_ext, peer,
                  peerauth, proxyauth, hostidv, hostidc, str, strsize)
   const sockshost_t *local;
   const sockshost_t *proxy;
   const sockshost_t *proxy_ext;
   const sockshost_t *peer;
   const authmethod_t *peerauth;
   const authmethod_t *proxyauth;
   const struct in_addr *hostidv;
   const unsigned int hostidc;
   char *str;
   size_t strsize;
{
   const char *function = "build_addrstr_dst()";
   size_t strused;
   char peerstr[MAXSOCKSHOSTSTRING], peerauthstr[MAXAUTHINFOLEN],
        proxyauthstr[MAXAUTHINFOLEN], pstr[MAXSOCKSHOSTSTRING],
        pe_str[MAXSOCKSHOSTSTRING + sizeof("[]")], lstr[MAXSOCKSHOSTSTRING];

   if ((proxy_ext) == NULL)
      *pe_str = NUL;
   else
      snprintf(pe_str, sizeof(pe_str),
               "[%s] ", sockshost2string(proxy_ext, NULL, 0));

   strused =
   snprintf((str), (strsize),
            "%s "
            "%s%s%s"
            "%s"
            "%s%s",

            local == NULL ?
               "0.0.0.0.0" : sockshost2string(local, lstr, sizeof(lstr)),

            authinfo(proxyauth, proxyauthstr, sizeof(proxyauthstr)),
            proxy == NULL ?
               "" : sockshost2string(proxy, pstr, sizeof(pstr)),
            proxy == NULL ? "" : " ",

            pe_str,

            authinfo(peerauth, peerauthstr, sizeof(peerauthstr)),
            peer == NULL ?
             "0.0.0.0.0" : sockshost2string(peer, peerstr, sizeof(peerstr)));

   if (hostidv != NULL && hostidc > 0) {
      ssize_t i;

      if ((strused + 1) < strsize) {
         str[strused]      = ' ';
         str[strused + 1]  = NUL;
         strused          += 1;
      }

      for (i = hostidc - 1; i >= 0; --i) {
         char ntop[MAXSOCKADDRSTRING];

         if (inet_ntop(AF_INET, &hostidv[i], ntop, sizeof(ntop)) == NULL) {
            slog(LOG_DEBUG, "%s: inet_ntop(3) failed on %s %x: %s",
                 function,
                 atype2string(SOCKS_ADDR_IPV4),
                 hostidv[i].s_addr,
                 strerror(errno));

             snprintf(ntop, sizeof(ntop), "<unknown>");
         }

         strused += snprintf(&str[strused], strsize - strused,
                             "%s[%s]",
                             (i == ((ssize_t)hostidc) - 1) ? "" : " ",
                             ntop);
      }
   }

   return str;
}

const char *
authinfo(auth, info, infolen)
   const authmethod_t *auth;
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

#endif /* !SOCKS_CLIENT  */
