/*
 * Copyright (c) 2012, 2013, 2016, 2017
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
"$Id: hostid.c,v 1.18.6.4 2017/01/31 08:17:38 karls Exp $";

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
   ssize_t i, max, last_nonzero;
   socklen_t len;
   unsigned char hostidc;

   len = sizeof(hostid);
   if (getsockopt(s, IPPROTO_TCP, TCP_IPA, &hostid, &len) != 0) {
      slog(LOG_DEBUG, "%s: no hostid retrieved via TCP_IPA on fd %d (%s)",
           function, s, strerror(errno));

      errno = 0;
      return 0;
   }

   slog(LOG_DEBUG,
        "%s: hostids of length %lu (max: %lu) retrieved via TCP_IPA on fd %d",
        function, (unsigned long)len, (unsigned long)sizeof(hostid), s);

   CTASSERT(sizeof(*addrv) == sizeof(*hostid.ipa_ipaddress));

   if (len == 0)
      return 0; /* no hostids. */

   SASSERTX(len >= sizeof(*addrv));

   /*
    * In the current (not original, though marked as "IPA_VERSION 1")
    * version of the API, it's no longer the length of data returned by
    * getsockopt(2) that determines how many hostid values are set.
    * Instead the structure can be considered as an array of fixed length,
    * where indices in the array having a value other than zero are to be
    * considered set, *however*: an indice having the value zero is also
    * considered set if there is a non-zero values in any of the following
    * indices.
    */

#if DEBUG

   max     = MIN(addrc, len / sizeof(*hostid.ipa_ipaddress));
   hostidc = 0;

   if (sockscf.option.debug) {
      char ntop[MAXSOCKADDRSTRING];

      for (i = 0; i < max; ++i) {
         if (inet_ntop(AF_INET, &addrv[i], ntop, sizeof(ntop)) == NULL)
            swarn("%s: inet_ntop(3) failed on %s %x",
                 function, safamily2string(AF_INET), addrv[i].s_addr);
         else
            slog(LOG_DEBUG, "%s: hostid at index #%lu: %s",
                 function, (unsigned long)i, ntop);
      }
   }

#endif /* DEBUG */

   max     = MIN(addrc, len / sizeof(*hostid.ipa_ipaddress));
   hostidc = 0;

   for (i = max - 1; i >= 0; --i) {
      if (hostid.ipa_ipaddress[i] != htonl(0)) {
         hostidc = i + 1;
         break;
      }
   }

   SASSERTX(hostidc >= 0);
   SASSERTX(hostidc <= UCHAR_MAX);

   slog(LOG_DEBUG, "%s: hostids set: %u", function, (unsigned)hostidc);

   memcpy(addrv, hostid.ipa_ipaddress, hostidc * sizeof(*hostid.ipa_ipaddress));

   return (unsigned char)hostidc;

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

   CTASSERT(sizeof(*addrv) <= sizeof(*hostid.ipa_ipaddress));

   if (addrc == 0)
      return 0;

   /*
    * Unset hostid fields must be set to zero.
    */
   bzero(&hostid, sizeof(hostid));

   for (i = 0; i < addrc; ++i) {
      char ntop[MAXSOCKADDRSTRING];

      if (inet_ntop(AF_INET, &addrv[i], ntop, sizeof(ntop)) == NULL)
         swarn("%s: inet_ntop(3) failed on %s %x",
              function, safamily2string(AF_INET), addrv[i].s_addr);
      else
         slog(LOG_DEBUG, "%s: hostid at index #%lu: %s",
              function, (unsigned long)i, ntop);

      memcpy(&hostid.ipa_ipaddress[i], &addrv[i], sizeof(addrv[i]));
   }

   len = sizeof(*hostid.ipa_ipaddress) * addrc;
   if (setsockopt(s, IPPROTO_TCP, TCP_IPA, &hostid, len) != 0) {
      swarn("%s: could not set hostid via TCP_IPA on fd %d (%s)",
           function, s, strerror(errno));

      return -1;
   }

   return 0;

#else /* ! (SOCKS_HOSTID_TYPE == SOCKS_HOSTID_TYPE_TCP_IPA) */

   return -1;

#endif
}

#endif /* SOCKS_HOSTID_TYPE != SOCKS_HOSTID_TYPE_NONE */
