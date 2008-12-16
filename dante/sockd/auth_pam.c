/*
 * Copyright (c) 2001, 2002, 2003, 2004
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

/*
 * Based on code originaly from
 * Patrick Bihan-Faou, MindStep Corporation, patrick@mindstep.com.
 */

#include "common.h"

#if HAVE_PAM

static const char rcsid[] =
"$Id: auth_pam.c,v 1.43 2008/12/14 17:14:11 karls Exp $";

__BEGIN_DECLS

static int
_pam_conversation(int msgc, const struct pam_message **msgv,
                  struct pam_response **rspv, void *authdata);

typedef struct
{
   const char *user;
   const char *password;
} _pam_data_t;


__END_DECLS

int
pam_passwordcheck(s, src, dst, auth, emsg, emsgsize)
   int s;
   const struct sockaddr *src, *dst;
   const struct authmethod_pam_t *auth;
   char *emsg;
   size_t emsgsize;
{
   const char *function = "pam_passwordcheck()";
   static pam_handle_t *pamh;
   static int rc;
   struct authmethod_pam_t authdata = *auth;
   struct pam_conv pamconv = { _pam_conversation, &authdata };
   size_t i;
   uid_t euid;

   /*
    * unforunatly we can not set password here, that needs to be set
    * "from a module", i.e. in the converationfunction, at least on 
    * linux.
    */
   struct {
      int         item;
      const char *itemname;
      const void *value;
   } pamval[] = {
      { PAM_CONV,  "PAM_CONV",  &pamconv },
      { PAM_RHOST, "PAM_RHOST", inet_ntoa(TOCIN(src)->sin_addr) },
   };

   slog(LOG_DEBUG, function);

   socks_seteuid(&euid, sockscf.uid.privileged);

#if HAVE_LINUX_BUGS
   if (pamh != NULL) { 
      pam_end(pamh, rc);
      pamh = NULL;
   }  
#endif /* HAVE_LINUX_BUGS */

   if (pamh == NULL) {
      if ((rc = pam_start(*auth->servicename == NUL ?
      DEFAULT_PAMSERVICENAME : auth->servicename, (const char *)auth->name, 
      &pamconv, &pamh)) != PAM_SUCCESS) {
         socks_reseteuid(sockscf.uid.privileged, euid);
         snprintf(emsg, emsgsize, "pam_start(): %s", pam_strerror(pamh, rc));
         pam_end(pamh, rc);
         pamh = NULL;
         return -1;
      }
   }
   else { /*
           * already set up, just make sure servicename is set correctly too,
           * since it can vary on a rule-by-rule basis.
           */
      if ((rc = pam_set_item(pamh, PAM_SERVICE, *auth->servicename == NUL ?
      DEFAULT_PAMSERVICENAME : auth->servicename)) != PAM_SUCCESS) {
         socks_reseteuid(sockscf.uid.privileged, euid);
         snprintf(emsg, emsgsize, "failed to set PAM_SERVICE: %s",
         pam_strerror(pamh, rc));
         pamh = NULL;
         return -1;
      }
   }

   for (i = 0; i < ELEMENTS(pamval); ++i) {
      slog(LOG_DEBUG, "setting item %s to value %s", 
      pamval[i].itemname, pamval[i].value);

      if ((rc = pam_set_item(pamh, pamval[i].item, pamval[i].value))
      != PAM_SUCCESS) {
         socks_reseteuid(sockscf.uid.privileged, euid);
         snprintf(emsg, emsgsize, "pam_set_item(%s): %s",
         pamval[i].itemname, pam_strerror(pamh, rc));
         pam_end(pamh, rc);
         pamh = NULL;
         return -1;
      }
   }

   if ((rc = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
      socks_reseteuid(sockscf.uid.privileged, euid);
      snprintf(emsg, emsgsize, "pam_authenticate(): %s",
      pam_strerror(pamh, rc));
      return -1;
   }

   if ((rc = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
      socks_reseteuid(sockscf.uid.privileged, euid);
      snprintf(emsg, emsgsize, "pam_acct_mgmt(): %s", pam_strerror(pamh, rc));
      return -1;
   }

   socks_reseteuid(sockscf.uid.privileged, euid);
   return 0;
}

static int
_pam_conversation(msgc, msgv, rspv, authdata)
   int msgc;
   const struct pam_message **msgv;
   struct pam_response **rspv;
   void *authdata;
{
   const struct authmethod_pam_t *auth = authdata;
   const char *function = "_pam_conversation()";
   int i;

   if (rspv == NULL || msgv == NULL || auth == NULL || msgc < 1) {
      swarnx("%s: called with invalid input", function);
      return PAM_CONV_ERR;
   }

   if (((*rspv) = malloc(msgc * sizeof(struct pam_response))) == NULL) { 
      swarn("%s: malloc(%d * %d)", function, msgc, sizeof(struct pam_response));
      return PAM_CONV_ERR;
   }

   for (i = 0; i < msgc; ++i) {
      slog(LOG_DEBUG, "%s: msg_style = %d", function, msgv[i]->msg_style);

      (*rspv)[i].resp_retcode = 0;
      switch(msgv[i]->msg_style) {
         case PAM_PROMPT_ECHO_ON:
            (*rspv)[i].resp = strdup((const char *)auth->name);
            break;

         case PAM_PROMPT_ECHO_OFF:
            (*rspv)[i].resp = strdup((const char *)auth->password);
            break;

         default: {
            int j;

            swarnx("%s: unknown msg_style = %d", function, msgv[i]->msg_style);
            for (j = 0; j < i; ++j)
               free((*rspv)[i].resp);         
            free(*rspv);

            return PAM_CONV_ERR;
         }
      }
   }

   return PAM_SUCCESS;
}

#endif /* HAVE_PAM */
