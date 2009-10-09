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
"$Id: iobuf.c,v 1.44 2009/09/25 20:47:21 michaels Exp $";

static void socks_flushallbuffers(void);

#if !SOCKS_CLIENT
/*
 * Each ioclient can use one iobuffer for src/control, and one for dst.
 */
static iobuffer_t    iobufferv[SOCKD_IOMAX * 2];
static const size_t  iobufferc = ELEMENTS(iobufferv);

#else /* SOCKS_CLIENT; allocate dynamically on a per-need basis. */

static iobuffer_t *iobufferv;
static size_t     iobufferc;
#endif /* SOCKS_CLIENT */

#if SOCKS_CLIENT
void
socks_setbuffer(s, mode)
   const int s;
   const int mode;
{
   iobuffer_t *iobuf;

   if ((iobuf = socks_getbuffer(s)) == NULL)
      return;

   iobuf->info[WRITE_BUF].mode = mode;
}
#endif /* SOCKS_CLIENT */

int
socks_flushbuffer(s, len)
   const int s;
   const ssize_t len;
{
   const char *function = "socks_flushbuffer()";
   ssize_t written, encoded, towrite;
   unsigned char buf[SOCKD_BUFSIZE];

   slog(LOG_DEBUG, "%s: socket %d, len = %ld", function, s, (long)len);

   if (s == -1) {
      socks_flushallbuffers();
      return 0;
   }

   if (socks_bytesinbuffer(s, WRITE_BUF, 0) <= 0
   &&  socks_bytesinbuffer(s, WRITE_BUF, 1) <= 0)
      return 0;

#if SOCKS_CLIENT && HAVE_GSSAPI
   /*
    * In the client-case, we don't want to encode the packet on
    * every buffered write.  E.g. we don't want 100 putc(3)'s to
    * end up creating 100 gssapi-encoded one-byte packets.
    * We therefore postpone encoding til we get a flush call.
    *
    * Note that we only use the buffer in the client if we are doing
    * gssapi i/o, never for ordinary i/o.  For the server, it is used
    * for both ordinary and gssapi-based i/o.
    */

   SASSERTX(len == -1);

   while (socks_bytesinbuffer(s, WRITE_BUF, 1) > 0) {
      /*
       * Already have encoded data ready for write.  Must always
       * write that first, since it came first.
       */
      const struct socksfd_t *socksfd;

      socksfd = socks_getaddr(s, 1);
      SASSERTX(socksfd != NULL);
      SASSERTX(socksfd->state.auth.method == AUTHMETHOD_GSSAPI);

      towrite = socks_getfrombuffer(s, WRITE_BUF, 1, buf, sizeof(buf));

      slog(LOG_DEBUG, "%s: flushing %lu encoded byte%s ...",
      function, (long unsigned)towrite, towrite == 1 ? "" : "s");

      SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 1) == 0);

      if ((written = socks_sendton(s, buf, towrite, towrite, 0, NULL, 0, NULL))
      != towrite) {
         slog(LOG_DEBUG, "%s: socks_sendton() flushed only %ld/%lu: %s",
         function, (long)written, (long unsigned)towrite, strerror(errno));

         if (written > 0) { /* add back what we failed to write. */
            socks_addtobuffer(s, WRITE_BUF, 1, &buf[written],
            towrite - written);

            continue;
         }
         else {
            errno = EAGAIN;
            return -1;
         }
      }
   }

   SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 1) == 0);

   while (socks_bytesinbuffer(s, WRITE_BUF, 0) > 0) {
      /*
       * Unencoded data in buffer, need to encode it first.
       */
      struct socksfd_t socksfd;
      unsigned char token[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
      unsigned short tokenlen;
      size_t token_length;
      ssize_t toencode;

      socksfd = *socks_getaddr(s, 1);
      SASSERTX(socksfd.state.auth.method == AUTHMETHOD_GSSAPI);

      toencode = socks_getfrombuffer(s, WRITE_BUF, 0, buf,
      MIN(sizeof(buf), socksfd.state.auth.mdata.gssapi.state.maxgssdata));

      slog(LOG_DEBUG, "%s: encoding %ld byte%s before flushing ...",
      function, (long)toencode, toencode == 1 ? "" : "s");

      token_length = sizeof(token) - GSSAPI_HLEN;
      if (gssapi_encode(buf, toencode, &socksfd.state.auth.mdata.gssapi.state,
      token + GSSAPI_HLEN, &token_length) != 0) {
         swarnx("%s: gssapi_encode() failed", function);
         return -1;
      }

      token[GSSAPI_VERSION] = SOCKS_GSSAPI_VERSION;
      token[GSSAPI_STATUS]  = SOCKS_GSSAPI_PACKET;

      tokenlen = htons(token_length);
      memcpy(&token[GSSAPI_TOKEN_LENGTH], &tokenlen, sizeof(tokenlen));

      SASSERTX(GSSAPI_HLEN + token_length <= socks_freeinbuffer(s, WRITE_BUF));
      socks_addtobuffer(s, WRITE_BUF, 1, token, GSSAPI_HLEN + token_length);
   }

   if (socks_bytesinbuffer(s, WRITE_BUF, 0) <= 0
   &&  socks_bytesinbuffer(s, WRITE_BUF, 1) <= 0)
      return 0;
#endif /* SOCKS_CLIENT && HAVE_GSSAPI */

   written = 0;
   do {
      /*
       * In case of client, we want to keep trying unless error is permanent.
       * In case of server, we want to keep writing while we can, but return
       * at the first error, permanent or not.
       */
      ssize_t rc;

      if (socks_bytesinbuffer(s, WRITE_BUF, 0) > 0) {
         SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 1) == 0);
         encoded = 0;
      }
      else if (socks_bytesinbuffer(s, WRITE_BUF, 1) > 0) {
         SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 0) == 0);
         encoded = 1;
      }
      else
         SERRX(0);

      towrite = socks_getfrombuffer(s, WRITE_BUF, encoded, buf, len == -1 ?
      sizeof(buf) : (size_t)len);

      rc = sendto(s, buf, towrite, 0, NULL, 0);

      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: flushed %ld/%ld %s byte%s, 0x%x, 0x%x",
         function, (long)rc, (long)towrite, encoded ? "encoded" : "unencoded",
         rc == 1 ? "" : "s",
         buf[rc - 2], buf[rc - 1]);

      if (rc == -1) {
         /* could not flush anything, add all back. */
         socks_addtobuffer(s, WRITE_BUF, encoded, buf, towrite);

#if SOCKS_CLIENT
         if (ERRNOISTMP(errno)) {
            static fd_set *wset;

            if (wset == NULL)
               wset = allocate_maxsize_fdset();

            FD_ZERO(wset);
            FD_SET(s, wset);

            if (select(s + 1, NULL, wset, NULL, NULL) == -1)
               slog(LOG_DEBUG, "%s: select(): %s", function, strerror(errno));

            continue;
         }
         else
            socks_clearbuffer(s, WRITE_BUF);
#endif /* SOCKS_CLIENT */

         return -1;
      }

      written += rc;
      socks_addtobuffer(s, WRITE_BUF, encoded, buf + rc, towrite - rc);

   } while ((len == -1 || written < len)
   && socks_bytesinbuffer(s, WRITE_BUF, encoded) > 0);

   SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 0) == 0);
   SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 1) == 0);

   return written;
}

iobuffer_t *
socks_getbuffer(s)
   const int s;
{
/*   const char *function = "socks_getbuffer()";  */
   size_t i;
#if !SOCKS_CLIENT
   static iobuffer_t *lastbuf;

   /* address of iobufferv; fixed in server, can change in client. */
   if (lastbuf != NULL && lastbuf->allocated && lastbuf->s == s)
      return lastbuf;
#endif /* !SOCKS_CLIENT */

   for (i = 0; i < iobufferc; ++i)
      if (iobufferv[i].allocated && iobufferv[i].s == s)
#if !SOCKS_CLIENT
         return lastbuf = &iobufferv[i];
#else
         return &iobufferv[i];
#endif /* !SOCKS_CLIENT */

   return NULL;
}

void
socks_clearbuffer(s, which)
   const int s;
   const whichbuf_t which;
{
   iobuffer_t *iobuf;

   if ((iobuf = socks_getbuffer(s)) == NULL)
      return;

   iobuf->info[which].len = iobuf->info[which].enclen = 0;
#if SOCKS_CLIENT
   iobuf->info[which].peekedbytes = 0;
#endif /* SOCKS_CLIENT */

   bzero(&iobuf->buf[which], sizeof(iobuf->buf[which]));

}

iobuffer_t *
socks_allocbuffer(s)
   const int s;
{
   const char *function = "socks_allocbuffer()";
   iobuffer_t *freebuffer;
   socklen_t tlen;
   size_t i;

   SASSERTX(socks_getbuffer(s) == NULL);

   /* check if one of the already allocated ones is free. */
   for (i = 0, freebuffer = NULL; i < iobufferc; ++i)
      if (!iobufferv[i].allocated) {
         freebuffer = &iobufferv[i];
         break;
      }

#if SOCKS_CLIENT
   if (freebuffer == NULL) {
      if ((iobufferv = realloc(iobufferv, sizeof(*iobufferv) * ++iobufferc))
      == NULL)
         serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);

      freebuffer = &iobufferv[iobufferc - 1];
      bzero(freebuffer, sizeof(*freebuffer)); 
   }

   freebuffer->info[WRITE_BUF].mode = _IONBF; /* default; no buffering. */
#endif /* SOCKS_CLIENT */

   SASSERTX(freebuffer != NULL);

   freebuffer->s         = s;
   freebuffer->allocated = 1;

   tlen = sizeof(freebuffer->stype);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &freebuffer->stype, &tlen) != 0)
      swarn("%s: getsockopt(SO_TYPE)", function);

   slog(LOG_DEBUG, "%s: socket %d, stype = %d", function, s, freebuffer->stype);

   return freebuffer;
}

void
socks_reallocbuffer(old, new)
   const int old;
   const int new;
{
   const char *function = "socks_reallocbuffer()";
   iobuffer_t *iobuf = socks_getbuffer(old);

   slog(LOG_DEBUG, "%s: old %d, new %d, %s",
   function, old, new, iobuf == NULL ? "no iobuf" : "have iobuf");

   if (iobuf != NULL)
      iobuf->s = new;
}

void
socks_freebuffer(s)
   const int s;
{
   const char *function = "socks_freebuffer()";
   size_t i;

   for (i = 0; i < iobufferc; ++i)
      if (iobufferv[i].allocated && iobufferv[i].s == s) {
         slog(LOG_DEBUG, "%s: freeing buffer %d", function, s); 
         
         if (sockscf.option.debug
         && ( socks_bytesinbuffer(s, READ_BUF, 0)  > 0
           || socks_bytesinbuffer(s, READ_BUF, 1)  > 0
           || socks_bytesinbuffer(s, WRITE_BUF, 0) > 0
           || socks_bytesinbuffer(s, WRITE_BUF, 1) > 0))
            slog(LOG_DEBUG, "%s: freeing buffer with data (%lu/%lu, %lu/%lu)",
            function,
            (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0),
            (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1),
            (unsigned long)socks_bytesinbuffer(s, WRITE_BUF, 0),
            (unsigned long)socks_bytesinbuffer(s, WRITE_BUF, 1));

         bzero(&iobufferv[i], sizeof(iobufferv[i]));
      }
}

size_t
socks_addtobuffer(s, which, encoded, data, datalen)
   const int s;
   const whichbuf_t which;
   const int encoded;
   const void *data;
   const size_t datalen;
{
   const char *function = "socks_addtobuffer()";
   iobuffer_t *iobuf;
   size_t toadd;

   if (datalen == 0)
      return 0;

   iobuf = socks_getbuffer(s);
   SASSERTX(iobuf != NULL);

   toadd = MIN(socks_freeinbuffer(s, which), datalen);

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: s = %lu, add %lu %s byte%s to %s buffer that "
                      "currently has %lu decoded, %lu encoded",
                      function,
                      (long unsigned)s,
                      (unsigned long)datalen,
                      encoded ? "encoded" : "decoded",
                      datalen == 1 ? "" : "s",
                      which == READ_BUF ? "read" : "write",
                      (unsigned long)socks_bytesinbuffer(s, which, 0),
                      (unsigned long)socks_bytesinbuffer(s, which, 1));

      SASSERTX(toadd >= datalen);

      if (encoded) {
         /*
          * appended to the end of encoded data, which is also
          * the end of the buffer.
          */
         memcpy(&iobuf->buf[which][socks_bytesinbuffer(s, which, 0)
         + socks_bytesinbuffer(s, which, 1)], data, toadd);

         iobuf->info[which].enclen += toadd;
      }
      else {
         /*
          * more complex; appended to the end of the unencoded data,
          * which comes before the encoded data.  Meaning we may have
          * to move the encoded data further out in the buffer before
          * we copy in the new data.
          */

         memmove(&iobuf->buf[which][socks_bytesinbuffer(s, which, 0) + toadd],
                 &iobuf->buf[which][socks_bytesinbuffer(s, which, 0)],
                 socks_bytesinbuffer(s, which, 1));

         memcpy(&iobuf->buf[which][socks_bytesinbuffer(s, which, 0)],
                data,
                toadd);

         iobuf->info[which].len += toadd;
      }

   SASSERTX(toadd == datalen);
   return toadd;
}

size_t
socks_bytesinbuffer(s, which, encoded)
   const int s;
   const whichbuf_t which;
   const int encoded;
{
   iobuffer_t *iobuf;

   if ((iobuf = socks_getbuffer(s)) == NULL)
      return 0;

   if (encoded)
      return iobuf->info[which].enclen;
   else
      return iobuf->info[which].len;
}

size_t
socks_freeinbuffer(s, which)
   const int s;
   const whichbuf_t which;
{
   const char *function = "socks_freeinbuffer()";
   iobuffer_t *iobuf;
   size_t rc;

   if ((socks_getbuffer(s)) == NULL)
      return 0;

   rc = sizeof(iobuf->buf[which]) -
   (socks_bytesinbuffer(s, which, 0) + socks_bytesinbuffer(s, which, 1));

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: socket %d, which %d, free: %lu",
      function, s, which, (unsigned long)rc);

   return rc;
}

size_t
socks_getfrombuffer(s, which, encoded, data, datalen)
   const int s;
   const whichbuf_t which;
   const int encoded;
   void *data;
   const size_t datalen;
{
   const char *function = "socks_getfrombuffer()";
   iobuffer_t *iobuf;
   size_t toget;

   if ((iobuf = socks_getbuffer(s)) == NULL)
      return 0;

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: s = %lu, get up to %lu %s byte%s from %s buffer "
                      "that currently has %lu decoded, %lu encoded",
                      function,
                      (long unsigned)s,
                      (unsigned long)datalen,
                      encoded ? "encoded" : "decoded",
                      datalen == 1 ? "" : "s",
                      which == READ_BUF ? "read" : "write",
                      (unsigned long)socks_bytesinbuffer(s, which, 0),
                      (unsigned long)socks_bytesinbuffer(s, which, 1));

   if ((toget = MIN(datalen, socks_bytesinbuffer(s, which, encoded))) == 0)
      return 0;

   if (encoded) {
      SASSERTX(iobuf->info[which].enclen >= toget);

      /* encoded data starts at the end of non-encoded data. */
      memcpy(data, &iobuf->buf[which][iobuf->info[which].len], toget);
      iobuf->info[which].enclen -= toget;

      /* move encoded data remaining in the buffer to the end of unencoded. */
      memmove(&iobuf->buf[which][iobuf->info[which].len],
              &iobuf->buf[which][iobuf->info[which].len + toget],
              iobuf->info[which].enclen);
   }
   else {
      SASSERTX(iobuf->info[which].len >= toget);

      memcpy(data, iobuf->buf[which], toget);
      iobuf->info[which].len -= toget;

      /* move the data remaining to the start of the buffer.  */
      memmove(iobuf->buf[which],
              &iobuf->buf[which][toget],
              iobuf->info[which].len + iobuf->info[which].enclen);
   }

   return toget;
}

static void
socks_flushallbuffers(void)
{
/*   const char *function = "socks_flushallbuffers()";  */
   size_t i;

   for (i = 0; i < iobufferc; ++i)
      if (iobufferv[i].allocated)
         socks_flushbuffer(iobufferv[i].s, -1);
}

#if 0
void
socks_iobuftest(void)
{
   const char *function = "socks_iobuftest()";
   const int s = 64;
   iobuffer_t *iobuf;
   whichbuf_t whichv[] = { READ_BUF, WRITE_BUF };
   size_t i, totbufsize;
   unsigned char encbuf[MAXGSSAPITOKENLEN + GSSAPI_HLEN],
                 decbuf[sizeof(encbuf)], tmpbuf[sizeof(encbuf)];

   slog(LOG_INFO, function);

   SASSERTX((iobuf = socks_allocbuffer(s)) != NULL);
   SASSERTX(iobuf->s == s);
   SASSERTX(iobuf->allocated);

   slog(LOG_INFO, "%s: running simple add and retrieve test ...", function);
   for (i = 0; i < ELEMENTS(whichv); ++i) {
      totbufsize = socks_freeinbuffer(s, whichv[i]);

      slog(LOG_INFO, "%s: free in empty buffer for %s data: %d",
      function, i ? "encoded" : "unencoded", totbufsize);

      memset(decbuf, 0xff, sizeof(decbuf));

      SASSERTX(socks_addtobuffer(s, whichv[i], i, decbuf, sizeof(decbuf))
      == sizeof(decbuf));

      SASSERTX(socks_getfrombuffer(s, whichv[i], i, tmpbuf, sizeof(decbuf))
      == sizeof(decbuf));

      SASSERTX(memcmp(decbuf, tmpbuf, sizeof(tmpbuf)) == 0);

      SASSERTX(socks_freeinbuffer(s, whichv[i]) == totbufsize);
   }

   slog(LOG_INFO, "%s: running mixed full add and retrieve test ...", function);
   for (i = 0; i < ELEMENTS(whichv); ++i) {
      totbufsize = socks_freeinbuffer(s, whichv[i]);

      memset(decbuf, 0xdd, sizeof(decbuf));

      SASSERTX(socks_addtobuffer(s, whichv[i], 0, decbuf, sizeof(decbuf))
      == sizeof(decbuf));

      memset(encbuf, 0xee, sizeof(encbuf));
      SASSERTX(socks_addtobuffer(s, whichv[i], 1, encbuf, sizeof(encbuf))
      == sizeof(decbuf));

      SASSERTX(socks_getfrombuffer(s, whichv[i], 0, tmpbuf, sizeof(decbuf))
      == sizeof(decbuf));
      SASSERTX(memcmp(decbuf, tmpbuf, sizeof(tmpbuf)) == 0);

      SASSERTX(socks_getfrombuffer(s, whichv[i], 1, tmpbuf, sizeof(encbuf))
      == sizeof(encbuf));
      SASSERTX(memcmp(encbuf, tmpbuf, sizeof(tmpbuf)) == 0);

      SASSERTX(socks_freeinbuffer(s, whichv[i]) == totbufsize);
   }

   slog(LOG_INFO, "%s: running partial add and retrieve test ...", function);
   for (i = 0; i < ELEMENTS(whichv); ++i) {
      const size_t firstblock = 1024, secondblock = sizeof(tmpbuf) - firstblock;
      totbufsize = socks_freeinbuffer(s, whichv[i]);

      SASSERTX(sizeof(tmpbuf) > firstblock);

      memset(decbuf, 0xd1, firstblock);
      memset(decbuf + firstblock, 0xdf, secondblock);

      memset(encbuf, 0xe1, firstblock);
      memset(encbuf + firstblock, 0xef, secondblock);

      SASSERTX(socks_addtobuffer(s, whichv[i], 0, decbuf, firstblock)
      == firstblock);

      SASSERTX(socks_addtobuffer(s, whichv[i], 1, encbuf, firstblock)
      == firstblock);

      SASSERTX(socks_addtobuffer(s, whichv[i], 0, decbuf + firstblock,
      secondblock) == secondblock);

      SASSERTX(socks_addtobuffer(s, whichv[i], 1, encbuf + firstblock,
      secondblock) == secondblock);

      SASSERTX(socks_getfrombuffer(s, whichv[i], 0, tmpbuf, firstblock)
      == firstblock);
      SASSERTX(memcmp(decbuf, tmpbuf, firstblock) == 0);

      SASSERTX(socks_getfrombuffer(s, whichv[i], 1, tmpbuf, firstblock)
      == firstblock);
      SASSERTX(memcmp(encbuf, tmpbuf, firstblock) == 0);

      SASSERTX(socks_getfrombuffer(s, whichv[i], 0, tmpbuf + firstblock,
      secondblock) == secondblock);

      SASSERTX(memcmp(decbuf + firstblock, tmpbuf + firstblock, secondblock)
      == 0);

      SASSERTX(socks_getfrombuffer(s, whichv[i], 1, tmpbuf + firstblock,
      secondblock) == secondblock);

      SASSERTX(memcmp(encbuf + firstblock, tmpbuf + firstblock, secondblock)
      == 0);

      SASSERTX(socks_freeinbuffer(s, whichv[i]) == totbufsize);
      SASSERTX(socks_freeinbuffer(s, whichv[i]) == totbufsize);
   }

   socks_freebuffer(s);
   SASSERTX(iobuf->s == 0);
   SASSERTX(!iobuf->allocated);
}
#endif
