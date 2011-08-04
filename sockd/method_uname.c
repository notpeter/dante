/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009, 2010,
 *               2011
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
"$Id: method_uname.c,v 1.83 2011/06/25 11:58:54 michaels Exp $";

static negotiate_result_t
recv_unamever(int s, struct request_t *request,
      struct negotiate_state_t *state);

static negotiate_result_t
recv_ulen(int s, struct request_t *request, struct negotiate_state_t *state);

static negotiate_result_t
recv_uname(int s, struct request_t *request, struct negotiate_state_t *state);

static negotiate_result_t
recv_plen(int s, struct request_t *request, struct negotiate_state_t *state);

static negotiate_result_t
recv_passwd(int s, struct request_t *request, struct negotiate_state_t *state);

static int
passworddbisunique(void);
/*
 * If it's possible for us to fail username/password authentication
 * on one rule, and succeed at another, returns false.
 * Otherwise returns the unique authmethod that would be used.
 */


negotiate_result_t
method_uname(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;

{

   state->rcurrent = recv_unamever;
   return state->rcurrent(s, request, state);
}

static int
passworddbisunique(void)
{
   const char *function = "passworddbisunique()";
   int rc;

   if (methodisset(AUTHMETHOD_UNAME, sockscf.methodv, sockscf.methodc)) {
#if HAVE_PAM
     if (methodisset(AUTHMETHOD_PAM, sockscf.methodv, sockscf.methodc))
         rc = 0;
      else
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
     if (methodisset(AUTHMETHOD_BSDAUTH, sockscf.methodv, sockscf.methodc))
         rc = 0;
      else
#endif /* HAVE_BSDAUTH */
         rc = AUTHMETHOD_UNAME;
   }

#if HAVE_PAM
   else if (methodisset(AUTHMETHOD_PAM, sockscf.methodv, sockscf.methodc)) {
      if (sockscf.state.pamservicename == NULL)
         rc = 0;    
      else if (methodisset(AUTHMETHOD_UNAME, sockscf.methodv, sockscf.methodc))
         rc = 0;
#if HAVE_BSDAUTH
      else if (methodisset(AUTHMETHOD_BSDAUTH, sockscf.methodv,sockscf.methodc))
         rc = 0;
#endif /* HAVE_BSDAUTH */
      else
         rc = AUTHMETHOD_PAM;
   }
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   else if (methodisset(AUTHMETHOD_BSDAUTH, sockscf.methodv, sockscf.methodc)) {
      if (sockscf.state.bsdauthstylename == NULL)
         rc = 0;
      else if (methodisset(AUTHMETHOD_UNAME, sockscf.methodv, sockscf.methodc))
         rc = 0;
#if HAVE_PAM
      else if (methodisset(AUTHMETHOD_PAM, sockscf.methodv, sockscf.methodc))
         rc = 0;
#endif /* HAVE_PAM */
      else
         rc = AUTHMETHOD_BSDAUTH;
   }
#endif /* HAVE_BSDAUTH */
   else {/* no passworddb-based methods set.  Should not have been called. */
      slog(LOG_DEBUG, "%s: no passwroddb-based methods set.  Why called?", 
           function);

      rc = -1;
   }

   slog(LOG_DEBUG, "%s: returning %d", function, rc);
   return rc;
}


static negotiate_result_t
recv_unamever(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   INIT(sizeof(request->auth->mdata.uname.version));
   CHECK(&request->auth->mdata.uname.version, request->auth, NULL);

   switch (request->auth->mdata.uname.version) {
      case SOCKS_UNAMEVERSION:
         break;

      default:
         slog(LOG_DEBUG, "unknown version on uname packet from client: %d",
         request->auth->mdata.uname.version);
         return NEGOTIATE_ERROR;
   }

   state->rcurrent = recv_ulen;
   return state->rcurrent(s, request, state);
}

static negotiate_result_t
recv_ulen(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   INIT(sizeof(*request->auth->mdata.uname.name));
   CHECK(request->auth->mdata.uname.name, request->auth, NULL);

   /* LINTED conversion from 'int' may lose accuracy */
   OCTETIFY(*request->auth->mdata.uname.name);

   state->rcurrent = recv_uname;
   return state->rcurrent(s, request, state);
}

static negotiate_result_t
recv_uname(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
   const size_t ulen = (size_t)*request->auth->mdata.uname.name;

   INIT(ulen);
   CHECK(request->auth->mdata.uname.name + 1, request->auth, NULL);

   /* convert to string. */
   memmove(request->auth->mdata.uname.name,
           request->auth->mdata.uname.name + 1,
           ulen);
   request->auth->mdata.uname.name[ulen] = NUL;

   state->rcurrent = recv_plen;
   return state->rcurrent(s, request, state);
}

static negotiate_result_t
recv_plen(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{

   INIT(sizeof(*request->auth->mdata.uname.password));
   CHECK(request->auth->mdata.uname.password, request->auth, NULL);

   /* LINTED conversion from 'int' may lose accuracy */
   OCTETIFY(*request->auth->mdata.uname.password);

   state->rcurrent = recv_passwd;
   return state->rcurrent(s, request, state);
}

static negotiate_result_t
recv_passwd(s, request, state)
   int s;
   struct request_t *request;
   struct negotiate_state_t *state;
{
/*   const char *function = "recv_passwd()"; */
   const size_t plen = (size_t)*request->auth->mdata.uname.password;
   unsigned char response[1            /* version. */
                        + 1            /* status.   */
   ];

   INIT(plen);
   CHECK(request->auth->mdata.uname.password + 1, request->auth, NULL);

   /* convert to string. */
   memmove(request->auth->mdata.uname.password,
           request->auth->mdata.uname.password + 1,
           plen);
   request->auth->mdata.uname.password[plen] = NUL;

   /*
    * Very sadly we can't do checking of the username/password here
    * since we don't know what authentication to use yet.  It could
    * be username, but it could also be PAM, or some future method.
    * It depends on what the socks request is.  We therefor would have
    * liked to give the client success status back no matter what
    * the username/password is, and later deny the connection if need be.
    *
    * That however creates problems with clients that, naturally, cache
    * the wrong username/password if they get success.
    * We therefor check if we have a unique passworddb to use, and if so,
    * check the password here so we can return an immediate error to client.
    * This we can do because the passworddb is unique, i.e. there is
    * no chance of the result varying according to the clients request.
    *
    * If the database is not unique, we go with returning a success at
    * this point, and deny it later if need be, even though this might
    * create problems for the clients that cache the result.
   */
   response[UNAME_VERSION] = request->auth->mdata.uname.version;
   switch (passworddbisunique()) {
      case 0:
         /*
          * not unique.  Return ok now, and check correct db later,
          * when we know what rules to use and what "correct" is.
          */
         response[UNAME_STATUS] = (unsigned char)0;
         break;

#if HAVE_PAM
      case AUTHMETHOD_PAM: {
         /*
          * it's a union, make a copy before moving into pam object.
          */
         const struct authmethod_uname_t uname
         = request->auth->mdata.uname;

         request->auth->method = AUTHMETHOD_PAM;

         strcpy((char *)request->auth->mdata.pam.servicename,
         sockscf.state.pamservicename);

         strcpy((char *)request->auth->mdata.pam.name,
         (const char *)uname.name);

         strcpy((char *)request->auth->mdata.pam.password,
         (const char *)uname.password);
         /* FALLTHROUGH */
      }
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
      case AUTHMETHOD_BSDAUTH: {
         /*
          * it's a union, make a copy before moving into bsd object.
          */
         const struct authmethod_uname_t uname
         = request->auth->mdata.uname;

         request->auth->method = AUTHMETHOD_BSDAUTH;
         if (sockscf.state.bsdauthstylename != NULL)
            strcpy((char *)request->auth->mdata.bsd.style,
                   sockscf.state.bsdauthstylename);
         else
            request->auth->mdata.bsd.style[0] = NUL;

         strcpy((char *)request->auth->mdata.bsd.name,
         (const char *)uname.name);

         strcpy((char *)request->auth->mdata.bsd.password,
         (const char *)uname.password);
         /* FALLTHROUGH */
      }
#endif /* HAVE_BSDAUTH */

      case AUTHMETHOD_UNAME: {
         struct sockaddr src, dst;

         sockshost2sockaddr(&state->src, &src);
         dst = src;

         if (accesscheck(s, request->auth, &src, &dst, state->emsg,
         sizeof(state->emsg)))
            response[UNAME_STATUS] = (unsigned char)0; /* OK. */
         else
            response[UNAME_STATUS] = (unsigned char)1; /* Not OK. */

         break;
      }

      default:
         SERRX(passworddbisunique);
   }

   if (socks_sendton(s, response, sizeof(response), 0, 0, NULL, 0,
   request->auth) != sizeof(response))
      return NEGOTIATE_ERROR;

   if (response[UNAME_STATUS] == 0) { /* 0 is success */
      state->rcurrent = recv_sockspacket;
      return state->rcurrent(s, request, state);
   }

   /* else; failed authentication. */
   return NEGOTIATE_ERROR;
}
