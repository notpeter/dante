/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013
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
"$Id: iobuf.c,v 1.116 2013/10/25 12:55:01 karls Exp $";

static int socks_flushallbuffers(void);
/*
 * Flushes all buffers.
 * Returns 0 if all were flushed successfully.
 * Returns -1 if we failed to completely flush at least one buffer.
 */

#if !SOCKS_CLIENT
/*
 * - Each negotiate child client can use one iobuffer for control.
 * - Each request child and io child client can use one iobuffer for
 *   control, src, and st.
 */
static iobuffer_t
   iobufv[MAX((SOCKD_NEGOTIATEMAX * 1  /* control */),
               MAX((SOCKD_IOMAX   * 4  /* control, src, dst1, dst2. */),
                    (SOCKD_REQUESTMAX   * 3  /* control, src, dst */)))];
static const size_t  iobufc = ELEMENTS(iobufv);

#else /* SOCKS_CLIENT; allocate dynamically on per-need basis. */
static iobuffer_t *iobufv;
static size_t     iobufc;
#endif /* SOCKS_CLIENT */

static size_t lastfreei;  /* last buffer freed, for quick allocation.  */

void
socks_setbuffer(iobuf, mode, size)
   iobuffer_t *iobuf;
   const int mode;
   ssize_t size;
{

   iobuf->info[READ_BUF].mode  = _IONBF; /* only one supported for read. */
   iobuf->info[WRITE_BUF].mode = mode;

   if (size == -1)
      size = sizeof(*iobuf->buf);

   SASSERTX(size > 0);
   SASSERTX(size <= (ssize_t)sizeof(*iobuf->buf));

   iobuf->info[READ_BUF].size  = size;
   iobuf->info[WRITE_BUF].size = size;
}

void
socks_setbufferfd(s, mode, size)
   const int s;
   const int mode;
   ssize_t size;
{
   iobuffer_t *iobuf;

   SASSERTX(size <= SOCKD_BUFSIZE);

   if ((iobuf = socks_getbuffer(s)) == NULL)
      return;

   socks_setbuffer(iobuf, mode, size);
}


int
socks_flushbuffer(s, len, sendtoflags)
   const int s;
   const ssize_t len;
   sendto_info_t *sendtoflags;
{
   const char *function = "socks_flushbuffer()";
   size_t towrite;
   ssize_t written;
   unsigned char inputmem[sizeof(iobuffer_t)];
   int encoded;

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: fd %d, len = %ld", function, s, (long)len);

   if (sendtoflags != NULL)
      sendtoflags->tosocket = 0;

   if (s == -1)
      return socks_flushallbuffers();

   if (!socks_bufferhasbytes(s, WRITE_BUF))
      return 0;
   else
      slog(LOG_DEBUG, "%s: buffer for fd %d has bytes (%lu).  Flushing",
           function,
           s,
           (unsigned long)socks_bytesinbuffer(s, WRITE_BUF, 1));

#if SOCKS_CLIENT && HAVE_GSSAPI
   /*
    * In the client-case, we don't want to encode the packet on
    * every buffered write.  E.g. we don't want 100 putc(3)'s to
    * end up creating 100 gssapi-encoded one-byte packets.
    * We therefore postpone encoding til we get a flush call.
    *
    * Note that we only use the iobuffer in the client if we are doing
    * gssapi i/o, never for ordinary i/o.  For the server, it is used
    * for both ordinary and gssapi-based i/o.
    */

   SASSERTX(len == -1);

   while (socks_bytesinbuffer(s, WRITE_BUF, 1) > 0) {
      /*
       * Already have encoded data ready for write.  Must always
       * write that first, since it came first.
       */
      socksfd_t socksfd, *p;

      p = socks_getaddr(s, &socksfd, 1);
      SASSERTX(p != NULL);
      SASSERTX(socksfd.state.auth.method == AUTHMETHOD_GSSAPI);

      towrite = socks_getfrombuffer(s,
                                    0,
                                    WRITE_BUF,
                                    1,
                                    inputmem,
                                    sizeof(inputmem));

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: flushing %lu encoded byte%s ...",
              function, (long unsigned)towrite, towrite == 1 ? "" : "s");

      /*
       * this is important since it verifies that we fetched all
       * the data from the buffer, so that what we add now does
       * not erroneously get appended after something, since when
       * we fetched it was first.
       */

      SASSERTX(socks_bytesinbuffer(s, WRITE_BUF, 1) == 0);

      written = sendto(s, inputmem, towrite, 0, NULL, 0);

      if (written != -1 && sendtoflags != NULL)
         sendtoflags->tosocket += written;

      if (written == -1 || (size_t)written != towrite) {
         if (sockscf.option.debug >= DEBUG_VERBOSE)
            slog(LOG_DEBUG, "%s: sendton() flushed only %ld/%lu: %s",
                 function,
                 (long)written,
                 (long unsigned)towrite,
                 strerror(errno));

         if (written > 0) { /* add back what we failed to write. */
            socks_addtobuffer(s,
                              WRITE_BUF,
                              1,
                              &inputmem[written],
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
      gss_buffer_desc input_token, output_token;
      socksfd_t socksfd, *ptr;
      unsigned char outputmem[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
      unsigned short pshort;
      ssize_t toencode;

      ptr = socks_getaddr(s, &socksfd, 1);
      SASSERTX(ptr != NULL);
      SASSERTX(socksfd.state.auth.method == AUTHMETHOD_GSSAPI);

      toencode
      = socks_getfrombuffer(s,
                            0,
                            WRITE_BUF,
                            0,
                            inputmem,
                            MIN(sizeof(inputmem),
                             socksfd.state.auth.mdata.gssapi.state.maxgssdata));

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: encoding %ld byte%s before flushing ...",
              function, (long)toencode, toencode == 1 ? "" : "s");

      input_token.value  = inputmem;
      input_token.length = toencode;

      output_token.value  = outputmem + GSSAPI_HLEN;
      output_token.length = sizeof(outputmem) - GSSAPI_HLEN;

      if (gssapi_encode(&input_token,
                        &socksfd.state.auth.mdata.gssapi.state,
                        &output_token) != 0) {
         swarnx("%s: gssapi_encode() failed", function);
         return -1;
      }

      ((char *)(output_token.value))[GSSAPI_VERSION] = SOCKS_GSSAPI_VERSION;
      ((char *)(output_token.value))[GSSAPI_STATUS]  = SOCKS_GSSAPI_PACKET;

      pshort = htons(output_token.length);
      memcpy(&((char *)output_token.value)[GSSAPI_TOKEN_LENGTH],
             &pshort,
             sizeof(pshort));

      SASSERTX(GSSAPI_HLEN + output_token.length
      <=       socks_freeinbuffer(s, WRITE_BUF));

      socks_addtobuffer(s,
                        WRITE_BUF,
                        1,
                        output_token.value,
                        output_token.length + GSSAPI_HLEN);
   }

   if (socks_bufferhasbytes(s, WRITE_BUF) == 0)
      return 0;
#endif /* SOCKS_CLIENT && HAVE_GSSAPI */

   written = 0;
   do {
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

      /*
       * In case of client, we want to keep trying unless error is permanent.
       * In case of server, we want to keep writing while we can, but return
       * at the first error, permanent or not.
       */
      towrite = socks_getfrombuffer(s,
                                    0,
                                    WRITE_BUF,
                                    encoded,
                                    inputmem,
                                    len == -1 ? sizeof(inputmem) : (size_t)len);

      rc = sendto(s, inputmem, towrite, 0, NULL, 0);

      if (rc != -1 && sendtoflags != NULL)
         sendtoflags->tosocket += rc;

      slog(LOG_DEBUG, "%s: flushed %ld/%ld %s byte%s (%s)",
           function,
           (long)rc,
           (long)towrite,
           encoded ? "encoded" : "unencoded",
           rc == 1 ? "" : "s",
           strerror(errno));

      if (rc == -1) {
         /* could not flush anything, add all back. */
         socks_addtobuffer(s, WRITE_BUF, encoded, inputmem, towrite);

#if SOCKS_CLIENT
         if (ERRNOISTMP(errno)) {
            fd_set *wset;

            wset = allocate_maxsize_fdset();

            FD_ZERO(wset);
            FD_SET(s, wset);

            if (select(s + 1, NULL, wset, NULL, NULL) == -1)
               slog(LOG_DEBUG, "%s: select(): %s", function, strerror(errno));

            free(wset);
            continue;
         }
         else
            socks_clearbuffer(s, WRITE_BUF);
#endif /* SOCKS_CLIENT */

         return -1;
      }

      written += rc;
      socks_addtobuffer(s,
                        WRITE_BUF,
                        encoded,
                        inputmem + rc,
                        towrite - (size_t)rc);

   } while ((len == -1 || written < len)
   && socks_bytesinbuffer(s, WRITE_BUF, encoded) > 0);

   SASSERTX(socks_bufferhasbytes(s, WRITE_BUF) == 0);

   return written;
}

iobuffer_t *
socks_getbuffer(s)
   const int s;
{
/*   const char *function = "socks_getbuffer()";  */
   static size_t i;

   if (i < iobufc && iobufv[i].s == s && iobufv[i].allocated)
      return &iobufv[i];

   for (i = 0; i < iobufc; ++i)
      if (iobufv[i].s == s && iobufv[i].allocated)
         return &iobufv[i];

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
socks_allocbuffer(s, stype)
   const int s;
   const int stype;
{
   const char *function = "socks_allocbuffer()";

#if SOCKS_CLIENT
   sigset_t oset;
#endif /* SOCKS_CLIENT */
   iobuffer_t *freebuffer;
   size_t i;

   slog(LOG_DEBUG, "%s: fd %d, stype = %d", function, s, stype);

   SASSERTX(socks_getbuffer(s) == NULL);

   /*
    * check if one of the already allocated ones is free.
    */
   if (lastfreei < iobufc && !iobufv[lastfreei].allocated)
      freebuffer = &iobufv[lastfreei];
   else {
      for (i = 0, freebuffer = NULL; i < iobufc; ++i)
         if (!iobufv[i].allocated) {
            freebuffer = &iobufv[i];
            break;
         }
   }

#if SOCKS_CLIENT
   /*
    * for non-blocking connect, we get a SIGIO upon completion.
    * We don't want that to happen during e.g. the below malloc(3) call,
    * as the sigio handler may access the malloc-ed memory, or while
    * we are in the processes of initializing this iobuf.
    */
   socks_sigblock(SIGIO, &oset);

   if (freebuffer == NULL) {
      void *p;

      if ((p = realloc(iobufv, sizeof(*iobufv) * (iobufc + 1))) == NULL) {
         swarn("%s: %s", function, NOMEM);
         socks_sigunblock(&oset);

         return NULL;
      }

      iobufv     = p;
      iobufc     += 1;

      freebuffer = &iobufv[iobufc - 1];
   }
#endif /* SOCKS_CLIENT */

   SASSERTX(freebuffer != NULL);
   socks_initbuffer(s, stype, freebuffer);

#if SOCKS_CLIENT
   socks_sigunblock(&oset);
#endif /* SOCKS_CLIENT */

   return freebuffer;
}

void
socks_initbuffer(fd, stype, iobuf)
   const int fd;
   const int stype;
   iobuffer_t *iobuf;
{

   bzero(iobuf, sizeof(*iobuf));
   iobuf->s         = fd;
   iobuf->stype     = stype;
   iobuf->allocated = 1;

   socks_setbuffer(iobuf, _IONBF, -1); /* default; no buffering. */
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

   slog(LOG_DEBUG, "%s: fd %d", function, s);

   if (lastfreei < iobufc
   && iobufv[lastfreei].s == s && iobufv[lastfreei].allocated)
      ;
   else
      lastfreei = 0;

   for (; lastfreei < iobufc; ++lastfreei) {
      if (!iobufv[lastfreei].allocated
      ||  iobufv[lastfreei].s != s)
         continue;

      if (sockscf.option.debug >= DEBUG_VERBOSE
      && ( socks_bufferhasbytes(s, READ_BUF)
        || socks_bufferhasbytes(s, WRITE_BUF)))
         slog(LOG_DEBUG, "%s: freeing buffer with data (%lu/%lu, %lu/%lu)",
         function,
         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0),
         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1),
         (unsigned long)socks_bytesinbuffer(s, WRITE_BUF, 0),
         (unsigned long)socks_bytesinbuffer(s, WRITE_BUF, 1));

      iobufv[lastfreei].allocated = 0;
      return;
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

   if (iobuf->stype == SOCK_DGRAM) { /* no buffering of udp for now. */
      SASSERTX(socks_bufferhasbytes(s, READ_BUF)  == 0);
      SASSERTX(socks_bufferhasbytes(s, WRITE_BUF) == 0);

      SERRX(0);
   }

   toadd = MIN(socks_freeinbuffer(s, which), datalen);

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG,
           "%s: fd = %d, add %lu %s byte%s to %s buffer which currently has "
           "%lu decoded, %lu encoded.  Last byte to add: 0x%x",
           function,
           s,
           (unsigned long)datalen,
           encoded ? "encoded" : "decoded",
           datalen == 1 ? "" : "s",
           which == READ_BUF ? "read" : "write",
           (unsigned long)socks_bytesinbuffer(s, which, 0),
           (unsigned long)socks_bytesinbuffer(s, which, 1),
           (int)((const unsigned char *)data)[datalen - 1]);

      SASSERTX(toadd >= datalen);

      if (encoded) {
         /*
          * appended to the end of encoded data, which is also
          * the end of the buffer.
          */
         memcpy(&iobuf->buf[which][socks_bytesinbuffer(s, which, 0)
                                 + socks_bytesinbuffer(s, which, 1)],
                data,
                toadd);

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
   const iobuffer_t *iobuf = socks_getbuffer(s);
   size_t rc;

   if (iobuf == NULL)
      return 0;

   if (encoded)
      rc = iobuf->info[which].enclen;
   else
      rc = iobuf->info[which].len;

   SASSERTX(rc <= sizeof(iobuf->buf[which]));
   return rc;
}

int
socks_bufferhasbytes(s, which)
   const int s;
   const whichbuf_t which;
{
   const iobuffer_t *iobuf = socks_getbuffer(s);

   if (iobuf == NULL)
      return 0;

   return iobuf->info[which].enclen || iobuf->info[which].len;
}


size_t
socks_freeinbuffer(s, which)
   const int s;
   const whichbuf_t which;
{
   const char *function = "socks_freeinbuffer()";
   iobuffer_t *iobuf;
   size_t rc;

   if ((iobuf = socks_getbuffer(s)) == NULL)
      return 0;

   rc = iobuf->info[which].size
        - (socks_bytesinbuffer(s, which, 0) + socks_bytesinbuffer(s, which, 1));

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: fd %d, which %d, free: %lu",
           function, s, which, (unsigned long)rc);

   SASSERTX(rc <= sizeof(iobuf->buf[which]));

   return rc;
}

size_t
socks_getfrombuffer(s, flags, which, encoded, data, datalen)
   const int s;
   const size_t flags;
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

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG,
           "%s: fd = %d, get up to %lu %s byte%s from %s buffer which "
           "currently has %lu decoded, %lu encoded.  Flags = %lu",
           function,
           s,
           (unsigned long)datalen,
           encoded ? "encoded" : "decoded",
           datalen == 1 ? "" : "s",
           which == READ_BUF ? "read" : "write",
           (unsigned long)socks_bytesinbuffer(s, which, 0),
           (unsigned long)socks_bytesinbuffer(s, which, 1),
           (unsigned long)flags);

   if ((toget = MIN(datalen, socks_bytesinbuffer(s, which, encoded))) == 0)
      return 0;

   if (encoded) {
      SASSERTX(iobuf->info[which].enclen >= toget);

      /* encoded data starts at the end of non-encoded data. */
      memcpy(data, &iobuf->buf[which][iobuf->info[which].len], toget);

      if (!(flags & MSG_PEEK)) {
         iobuf->info[which].enclen -= toget;

         /*
          * encoded data stays at the end of unencoded data.
          */
         memmove(&iobuf->buf[which][iobuf->info[which].len],
                 &iobuf->buf[which][iobuf->info[which].len + toget],
                 iobuf->info[which].enclen);
      }
   }
   else {
      SASSERTX(iobuf->info[which].len >= toget);

      memcpy(data, iobuf->buf[which], toget);

      if (!(flags & MSG_PEEK)) {
         iobuf->info[which].len -= toget;

         /* move the data remaining to the start of the buffer.  */
         memmove(iobuf->buf[which],
                 &iobuf->buf[which][toget],
                 iobuf->info[which].len + iobuf->info[which].enclen);
      }
   }

   return toget;
}

static int
socks_flushallbuffers(void)
{
/*   const char *function = "socks_flushallbuffers()";  */
   size_t i;
   int rc;

   for (i = 0, rc = 0; i < iobufc; ++i)
      if (iobufv[i].allocated)
         if (socks_flushbuffer(iobufv[i].s, -1, NULL) == -1)
            rc = -1;

   return rc;
}
