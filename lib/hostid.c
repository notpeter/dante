/*
 * Copyright (c) 2012
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
"$Id: hostid.c,v 1.9 2012/05/21 21:39:17 karls Exp $";

#if SOCKS_HOSTID_TYPE != SOCKS_HOSTID_TYPE_NONE
unsigned char
getsockethostid(s, addrc, addrv)
   const int s;
   const size_t addrc;
   struct in_addr addrv[];
{
#if SOCKS_HOSTID_TYPE == SOCKS_HOSTID_TYPE_TCP_IPA
   const char *function = "getsockethostid()";
   struct tcp_ipa hostid;
   size_t i;
   socklen_t len;

   SASSERTX(sizeof(*addrv) == sizeof(*hostid.ipa_ipaddress));

   len = sizeof(hostid);
   if (getsockopt(s, IPPROTO_TCP, TCP_IPA, &hostid, &len) != 0) {
      slog(LOG_DEBUG, "%s: no hostid retrieved via TCP_IPA on socket %d (%s)",
           function, s, strerror(errno));

      return 0;
   }

   slog(LOG_DEBUG, "%s: hostid of length %lu (max: %lu) retrieved via TCP_IPA "
                   "on socket %d",
                   function, (unsigned long)len, (unsigned long)sizeof(hostid),
                   s);

   for (i = 0; i < len / sizeof(*addrv); ++i) {
      memcpy(&addrv[i], &hostid.ipa_ipaddress[i], sizeof(addrv[i]));

      slog(LOG_DEBUG, "%s: hostid at index #%lu: %s",
           function, (unsigned long)i, inet_ntoa(addrv[i]));
   }

   return i;
#else /* ! (SOCKS_HOSTID_TYPE == SOCKS_HOSTID_TYPE_TCP_IPA) */

   return 0;
#endif
}

int
setsockethostid(s, addrc, addrv)
   const int s;
   const size_t addrc;
   struct in_addr addrv[];
{
#if SOCKS_HOSTID_TYPE == SOCKS_HOSTID_TYPE_TCP_IPA
   const char *function = "setsockethostid()";
   struct tcp_ipa hostid;
   size_t i;
   socklen_t len;

   SASSERTX(sizeof(*addrv) == sizeof(*hostid.ipa_ipaddress));
   for (i = 0; i < addrc; ++i) {
      memcpy(&hostid.ipa_ipaddress[i], &addrv[i], sizeof(addrv[i]));

      slog(LOG_DEBUG, "%s: hostid at index #%lu: %s",
           function, (unsigned long)i, inet_ntoa(addrv[i]));
   }

   len = sizeof(*hostid.ipa_ipaddress) * addrc;
   if (setsockopt(s, IPPROTO_TCP, TCP_IPA, &hostid, len) != 0) {
      swarn("%s: could not set hostid via TCP_IPA on socket %d (%s)",
           function, s, strerror(errno));

      return -1;
   }

   return 0;
#else /* ! (SOCKS_HOSTID_TYPE == SOCKS_HOSTID_TYPE_TCP_IPA) */

   return -1;
#endif
}

#endif /* SOCKS_HOSTID_TYPE != SOCKS_HOSTID_TYPE_NONE */
