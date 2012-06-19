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

#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

static const char rcsid[] =
"$Id: sockaddr.c,v 1.7 2012/05/22 14:06:38 michaels Exp $";


int
sockaddrareeq(a, b)
   const struct sockaddr *a;
   const struct sockaddr *b;
{

#if HAVE_SOCKADDR_SA_LEN
   if (a->sa_len != b->sa_len)
      return 0;

   return memcmp(a, b, a->sa_len) == 0;

#else

   return memcmp(a, b, sizeof(*a)) == 0;

#endif /* HAVE_SOCKADDR_SA_LEN */
}

void
sockaddrcpy(struct sockaddr *dst, const struct sockaddr *src,
            const size_t dstlen)
{
   const char *function = "sockaddrcpy()";
   const socklen_t salen = sockaddr2salen(src);
   const socklen_t cpylen = MIN(dstlen, salen);

   SASSERTX(salen != 0);

   if (cpylen < salen)
      swarnx("%s: truncating address (af: %d): only %d of %d bytes available",
             function, src->sa_family, dstlen, salen);

   /* ensure all destination bytes are zero */
   bzero(dst, dstlen);

   memcpy(dst, src, cpylen);
}

void
usrsockaddrcpy(struct sockaddr *dst, const struct sockaddr *src,
               const size_t dstlen)
{
   const char *function = "usrsockaddrcpy()";
   /* get length based on address family */
   const socklen_t aflen = sa_family2salen(src->sa_family);
   const socklen_t cpylen = MIN(dstlen, aflen);

   if (cpylen < aflen)
      swarnx("%s: truncating address (af: %d): only %d of %d bytes available",
             function, src->sa_family, dstlen, aflen);

   /* ensure all destination bytes are zero */
   bzero(dst, dstlen);

   memcpy(dst, src, cpylen);

#if HAVE_SOCKADDR_SA_LEN
   /* ensure sa_len is set */
   dst->sa_len = cpylen; /*XXX?*/
#endif /* HAVE_SOCKADDR_SA_LEN */
}

socklen_t
sockaddr2salen(sa)
   const struct sockaddr *sa;
{
   const char *function = "sockaddr2salen()";

#if HAVE_SOCKADDR_SA_LEN
   SASSERTX(sa->sa_len != 0);
   return sa->sa_len;
#else /* !HAVE_SOCKADDR_SA_LEN */

   switch (sa->sa_family) {
      case AF_INET:
         return sizeof(struct sockaddr_in);

      case AF_INET6:
         return sizeof(struct sockaddr_in6);

#ifdef AF_LINK
      case AF_LINK:
         return sizeof(struct sockaddr_dl);
#endif /* AF_LINK */

      default:
         /*
          * no idea, but don't error out as it would make it impossible
          * to call this function without always have a pre-call check.
          */
         slog(LOG_DEBUG, "%s: called with unknown sa_family %d",
                         function, sa->sa_family);

         return sizeof(*sa);
   }
#endif /* !HAVE_SOCKADDR_SA_LEN */

   /* NOTREACHED */
}

sa_len_type
sa_family2salen(family)
   const sa_family_t family;
{
   const char *function = "sa_family2salen()";

   switch (family) {
      case AF_INET:
         return (sa_len_type)sizeof(struct sockaddr_in);

#ifdef AF_INET6
      case AF_INET6:
         return (sa_len_type)sizeof(struct sockaddr_in6);
#endif /* AF_INET6 */

#ifdef AF_LINK
      case AF_LINK:
         return (sa_len_type)sizeof(struct sockaddr_dl);
#endif /* AF_LINK */

#ifdef AF_UNSPEC
      case AF_UNSPEC:
         return (sa_len_type)sizeof(struct sockaddr); /* or? */
#endif /* AF_UNSPEC */

   }

   SWARNX(family);

   return (sa_len_type)sizeof(struct sockaddr);
}
