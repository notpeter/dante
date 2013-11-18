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

 /*
  * This code was contributed by
  * Markus Moeller (markus_moeller at compuserve.com).
  */


#include "common.h"

static const char rcsid[] =
"$Id: gssapi.c,v 1.171 2013/11/15 05:12:22 michaels Exp $";

#if HAVE_GSSAPI

static ssize_t
gssapi_decode_read_udp(int s, void *buf, size_t len, int flags,
                       struct sockaddr_storage *from, socklen_t *fromlen,
                       recvfrom_info_t *recvflags, gssapi_state_t *gs,
                       unsigned char *token, const size_t tokensize);
/*
 * Reads and decodes a udp packet.  Similar to gssapi_decode_read()
 * and socks_recvfrom(), but takes two additional arguments:
 * token       - tmpbuffer to hold the gssapi token being worked on.
 * tokensize   - size of "token".  Should be big enough to hold the largest
 *               possible GSSAPI token, including the header.
 */

static ssize_t
gssapi_encode_write_udp(int s, const void *msg, size_t len, int flags,
                        const struct sockaddr_storage *to, socklen_t tolen,
                        sendto_info_t *sendtoflags, gssapi_state_t *gs,
                        unsigned char *token, const size_t tokensize);
/*
 * Similar to gssapi_encode_read_udp().
 */

static int
gssapi_headerisok(const unsigned char *headerbuf, const size_t len,
                  unsigned short *tokenlen,
                  char *emsg, size_t emsglen);
/*
 * Checks if the first few bytes of "headerbuf" match a valid socks gssapi
 * header.  If so, "tokenlen" is set to the length of the token.
 *
 * Returns true if it looks valid, false otherwise.
 */

int
gss_err_isset(major_status, minor_status, buf, buflen)
   OM_uint32 major_status;
   OM_uint32 minor_status;
   char *buf;
   size_t buflen;
{
   OM_uint32 maj_stat, min_stat, msg_ctx;
   gss_buffer_desc statstr;
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */
   size_t w;

   if (!GSS_ERROR(major_status))
      return 0;

   if (buf == NULL || buflen <= 0)
      return 0;

   *buf = NUL;

   msg_ctx = 0;
   do {
      /*
       * convert major status code (GSSAPI error) to text.
       * Keep fetching errorstrings as long as gss_display_status()
       * does not fail.
       */

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      maj_stat = gss_display_status(&min_stat,
                                    major_status,
                                    GSS_C_GSS_CODE,
                                    GSS_C_NULL_OID,
                                    &msg_ctx,
                                    &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

      if (!GSS_ERROR(maj_stat)) {
         w = snprintf(buf, buflen,
                      "%.*s.  ", (int)statstr.length, (char *)statstr.value);
         buf    += w;
         buflen -= w;
      }

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      gss_release_buffer(&min_stat, &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);
   } while (buflen > 1 && msg_ctx != 0 && !GSS_ERROR(maj_stat));

   msg_ctx = 0;
   do {
      /*
       * convert minor status code (underlying routine error) to text.
       * Keep fetching errorstrings as long as gss_display_status()
       * does not fail.
       */

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      maj_stat = gss_display_status(&min_stat,
                                    minor_status,
                                    GSS_C_MECH_CODE,
                                    GSS_C_NULL_OID,
                                    &msg_ctx,
                                    &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

      if (!GSS_ERROR(maj_stat)) {
         w = snprintf(buf, buflen,
                      "%.*s.  ", (int)statstr.length, (char *)statstr.value);
         buf    += w;
         buflen -= w;
      }

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      gss_release_buffer(&min_stat, &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);
   } while (buflen > 1 && msg_ctx != 0 && !GSS_ERROR(maj_stat));

   return 1;
}

int
gssapi_encode(input_token, gs, output_token)
   const gss_buffer_t input_token;
   gssapi_state_t *gs;
   gss_buffer_t output_token;
{
   const char *function = "gssapi_encode()";
   gss_buffer_desc encoded_token;
   OM_uint32 minor_status, major_status;
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */
   char emsg[1024];
   int conf_state;

   slog(LOG_DEBUG, "%s, input length %lu, max output length %lu",
        function,
        (long unsigned)input_token->length,
        (long unsigned)output_token->length);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_native();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   major_status = gss_wrap(&minor_status,
                           gs->id,
                           gs->protection == GSSAPI_CONFIDENTIALITY ?
                                 GSS_REQ_CONF : GSS_REQ_INT,
                           GSS_C_QOP_DEFAULT,
                           input_token,
                           &conf_state,
                           &encoded_token);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_normal();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      swarnx("%s: gss_wrap(): %s", function, emsg);
      return -1;
   }

   if (encoded_token.length > input_token->length) {
      if (((encoded_token.length + GSSAPI_HLEN) - input_token->length)
      > gs->gssoverhead) {
        slog(LOG_DEBUG,
             "%s: max expected GSSAPI overhead increased from %lu to %lu",
             function,
             (unsigned long)gs->gssoverhead,
             (unsigned long)((encoded_token.length + GSSAPI_HLEN)
                             - input_token->length));

        gs->gssoverhead = (encoded_token.length + GSSAPI_HLEN)
                          - input_token->length;
      }
   }

   if (encoded_token.length > output_token->length) {
      slog(LOG_DEBUG, "%s: encoded token length (%lu) larger than buffer (%lu)",
           function,
           (long unsigned)encoded_token.length,
           (long unsigned)output_token->length);

      CLEAN_GSS_TOKEN(encoded_token);

      errno = EMSGSIZE; /* caller will have to retry with less data. */
      return -1;
   }

   output_token->length = encoded_token.length;
   memcpy(output_token->value, encoded_token.value, encoded_token.length);

   CLEAN_GSS_TOKEN(encoded_token);

#if 1
   slog(LOG_DEBUG, "%s: gssapi packet encoded.  Decoded/encoded length %lu/%lu",
        function,
        (unsigned long)input_token->length,
        (unsigned long)output_token->length);

#else

   slog(LOG_DEBUG,
        "%s: gssapi packet encoded.  Decoded/encoded length %lu/%lu.  "
        "First + 10 decoded bytes: 0x%x, 0x%x, 0x%x, 0x%x, "
        "first + 10 encoded bytes: 0x%x, 0x%x, 0x%x, 0x%x.  "
        "Last decoded bytes:  0x%x, 0x%x, 0x%x, 0x%x, "
        "last encoded bytes:  0x%x, 0x%x, 0x%x, 0x%x",
        function,
        (unsigned long)input_token->length,
        (unsigned long)output_token->length,
        ((const unsigned char *)input_token->value)[0 + 10],
        ((const unsigned char *)input_token->value)[1 + 10],
        ((const unsigned char *)input_token->value)[2 + 10],
        ((const unsigned char *)input_token->value)[3 + 10],
        ((const unsigned char *)output_token->value)[0 + 10],
        ((const unsigned char *)output_token->value)[1 + 10],
        ((const unsigned char *)output_token->value)[2 + 10],
        ((const unsigned char *)output_token->value)[3 + 10],
        ((const unsigned char *)input_token->value)[input_token->length - 4],
        ((const unsigned char *)input_token->value)[input_token->length - 3],
        ((const unsigned char *)input_token->value)[input_token->length - 2],
        ((const unsigned char *)input_token->value)[input_token->length - 1],
        ((const unsigned char *)output_token->value)[output_token->length - 4],
        ((const unsigned char *)output_token->value)[output_token->length - 3],
        ((const unsigned char *)output_token->value)[output_token->length - 2],
        ((const unsigned char *)output_token->value)[output_token->length - 1]);
#endif

   return 0;
}

int
gssapi_decode(input_token, gs, output_token)
   const gss_buffer_t input_token;
   gssapi_state_t *gs;
   gss_buffer_t output_token;
{
   const char *function = "gssapi_decode()";
   gss_buffer_desc decoded_token;
   OM_uint32  minor_status, major_status;
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */
   char emsg[1024];
   int req_conf_state;

   slog(LOG_DEBUG, "%s, input length %lu, max output length %lu",
        function,
        (long unsigned)input_token->length,
        (long unsigned)output_token->length);

   req_conf_state = (gs->protection == GSSAPI_CONFIDENTIALITY ?
                        GSS_REQ_CONF : GSS_REQ_INT);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_native();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   major_status = gss_unwrap(&minor_status,
                             gs->id,
                             input_token,
                             &decoded_token,
                             &req_conf_state,
                             GSS_C_QOP_DEFAULT);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_normal();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      slog(LOG_INFO,
           "%s: gss_unwrap() failed on token of length %lu.  "
           "First + 10 encoded bytes: 0x%x, 0x%x, 0x%x, 0x%x,  "
           "Last encoded bytes: 0x%x, 0x%x, 0x%x, 0x%x: %s  ",
           function,
           (unsigned long)input_token->length,
           ((const unsigned char *)input_token->value)[0 + 10],
           ((const unsigned char *)input_token->value)[1 + 10],
           ((const unsigned char *)input_token->value)[2 + 10],
           ((const unsigned char *)input_token->value)[3 + 10],
           ((const unsigned char *)input_token->value)[input_token->length - 4],
           ((const unsigned char *)input_token->value)[input_token->length - 3],
           ((const unsigned char *)input_token->value)[input_token->length - 2],
           ((const unsigned char *)input_token->value)[input_token->length - 1],
           emsg);

      if (!GSSERR_IS_OK(major_status))
         SWARNX(0);

      errno = 0; /* make sure caller does not reuse some old leftover value. */
      return -1;
   }

   if (decoded_token.length > output_token->length) {
      swarnx("%s: output buffer too small.  Need %lu bytes, but have only %lu",
             function,
             (unsigned long)decoded_token.length,
             (unsigned long)output_token->length);

      CLEAN_GSS_TOKEN(decoded_token);

      errno = ENOMEM;
      return -1;
   }

   output_token->length = decoded_token.length;
   memcpy(output_token->value, decoded_token.value, decoded_token.length);

   CLEAN_GSS_TOKEN(decoded_token);

#if 1

   slog(LOG_DEBUG, "%s: gssapi packet decoded.  Decoded/encoded length %lu/%lu",
        function,
        (unsigned long)output_token->length,
        (unsigned long)input_token->length);

#else

   slog(LOG_DEBUG,
        "%s: gssapi packet decoded.  Decoded/encoded length %lu/%lu.  "
        "First + 10 decoded bytes: 0x%x, 0x%x, 0x%x, 0x%x, "
        "first + 10 encoded bytes: 0x%x, 0x%x, 0x%x, 0x%x.  "
        "Last decoded bytes:  0x%x, 0x%x, 0x%x, 0x%x, "
        "last encoded bytes:  0x%x, 0x%x, 0x%x, 0x%x",
        function,
        (unsigned long)output_token->length,
        (unsigned long)input_token->length,
        ((const unsigned char *)output_token->value)[0 + 10],
        ((const unsigned char *)output_token->value)[1 + 10],
        ((const unsigned char *)output_token->value)[2 + 10],
        ((const unsigned char *)output_token->value)[3 + 10],
        ((const unsigned char *)input_token->value)[0 + 10],
        ((const unsigned char *)input_token->value)[1 + 10],
        ((const unsigned char *)input_token->value)[2 + 10],
        ((const unsigned char *)input_token->value)[3 + 10],
        ((const unsigned char *)output_token->value)[output_token->length - 4],
        ((const unsigned char *)output_token->value)[output_token->length - 3],
        ((const unsigned char *)output_token->value)[output_token->length - 2],
        ((const unsigned char *)output_token->value)[output_token->length - 1],
        ((const unsigned char *)input_token->value)[input_token->length - 4],
        ((const unsigned char *)input_token->value)[input_token->length - 3],
        ((const unsigned char *)input_token->value)[input_token->length - 2],
        ((const unsigned char *)input_token->value)[input_token->length - 1]);
#endif

   return 0;
}

/*
 * RFC1961: client request / server response
 *
 *   +------+------+------+.......................+
 *   + ver  | mtyp | len  |       token           |
 *   +------+------+------+.......................+
 *   + 0x01 | 0x03 | 0x02 | up to 2^16 - 1 octets |
 *   +------+------+------+.......................+
 *
 */
ssize_t
gssapi_decode_read(s, buf, len, flags, from, fromlen, recvflags, gs)
   int s;
   void *buf;
   size_t len;
   int flags;
   struct sockaddr_storage *from;
   socklen_t *fromlen;
   recvfrom_info_t *recvflags;
   gssapi_state_t *gs;
{
   const char *function = "gssapi_decode_read()";
#if SOCKS_CLIENT
   size_t encodedinbuffer;
#endif /* !SOCKS_CLIENT */

   gss_buffer_desc input_token, output_token;
   iobuffer_t *iobuf;
   unsigned short encodedlen;
   ssize_t nread;
   size_t tokennumber = 1, p, toread, readfrombuf;
   char emsg[512];
   unsigned char outputmem[GSSAPI_HLEN + MAXGSSAPITOKENLEN],
                 inputmem[sizeof(iobuf->buf[0])];

#if SOCKS_CLIENT
   ssize_t rc;

   /*
    * If the socket is blocking, we need to retry the read.
    * The token buffers we allocate for this are too large to simply
    * call ourselves recursively again.
    */
again:
   encodedinbuffer = socks_bytesinbuffer(s, READ_BUF, 1); /* const. */

   SASSERTX(recvflags == NULL);
#endif /* SOCKS_CLIENT */

   slog(LOG_DEBUG, "%s: fd %d, len %lu, flags %d, inbuf %lu/%lu",
        function,
        s,
        (long unsigned)len,
        flags,
        (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0),
        (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1));

   if ((iobuf = socks_getbuffer(s)) == NULL) {
      int stype;

      if (recvflags != NULL)
         stype = recvflags->type;
      else {
         socklen_t tlen = sizeof(stype);

         if (getsockopt(s, SOL_SOCKET, SO_TYPE, &stype, &tlen) != 0) {
            swarn("%s: getsockopt(SO_TYPE)", function);
            return -1;
         }
      }

      if ((iobuf = socks_allocbuffer(s, stype)) == NULL) {
         swarnx("%s: could not allocate iobuffer", function);

         errno = ENOMEM;
         return -1;
      }
   }

   if (iobuf->stype == SOCK_DGRAM)
      return gssapi_decode_read_udp(s,
                                    buf,
                                    len,
                                    flags,
                                    from,
                                    fromlen,
                                    recvflags,
                                    gs,
                                    outputmem,
                                    sizeof(outputmem));

#if SOCKS_CLIENT /* always flush before read. */
   (void)socks_flushbuffer(s, -1, NULL);

   /*
    * When called by the client, we have the added complexity
    * that we can not completely drain the socket, because if the client
    * then select(2)'s on the socket to know when there is more to read,
    * select(2) can block forever, as the data has already been read and
    * buffered by us.
    * What we need to do instead is to only peek at the last byte(s)
    * belonging to the token data as long as we have buffered data which
    * we have not yet returned to the client, and not drain the last byte(s)
    * from socket until we can return all the data in the decoded token to
    * the client.
    * This will make sure the socket remains readable until we have
    * returned all the data belonging to a given token to the caller,
    * which should let all the kernels select(2)/poll(2)/SIGIO/etc.
    * stuff work.
    *
    * We also need to handle a client only peeking at the data correctly.
    * In the case of MSG_PEEK, we can do the same as for a normal read,
    * except we must leave the bytes in the buffer.
    */
#endif /* SOCKS_CLIENT */

   if (socks_bytesinbuffer(s, READ_BUF, 0) > 0) {
      toread = MIN(len, socks_bytesinbuffer(s, READ_BUF, 0));

      if (sockscf.option.debug)
         slog(LOG_DEBUG,
              "%s: bytes in buffer: %lu/%lu.  Returning %lu from there",
              function,
              (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0),
              (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1),
              (unsigned long)toread);

      socks_getfrombuffer(s, flags, READ_BUF, 0, buf, toread);

#if SOCKS_CLIENT
      if (socks_bytesinbuffer(s, READ_BUF, 0) == 0) {
         slog(LOG_DEBUG,
              "%s: all data from token returned to caller.  "
              "Draining socket for last %lu peeked at byte%s",
              function,
              (unsigned long)iobuf->info[READ_BUF].peekedbytes,
              iobuf->info[READ_BUF].peekedbytes == 1 ? "" : "s");

         nread = recv(s, inputmem, iobuf->info[READ_BUF].peekedbytes, 0);

         if (nread != (ssize_t)iobuf->info[READ_BUF].peekedbytes)
            SWARN(nread);

         iobuf->info[READ_BUF].peekedbytes = 0;
         SASSERTX(socks_bufferhasbytes(s, READ_BUF) == 0);

      }
#endif /* SOCKS_CLIENT */

      return toread;
   }

   SASSERTX(socks_bytesinbuffer(s, READ_BUF, 0) == 0);

   /*
    * No decoded data buffered.  Since we were called it should mean there
    * is (encoded) data available for read from socket.  Make sure
    * we read with something that does not step on our toes concerning
    * using our iobuf, like e.g. socks_recvfrom() could do.
    */

   toread = MIN(sizeof(outputmem), socks_freeinbuffer(s, READ_BUF));
   nread = recv(s,
                outputmem,
                toread,
#if !SOCKS_CLIENT
                flags
#else /* SOCKS_CLIENT */
                flags | MSG_PEEK
#endif /* !SOCKS_SERVER */
                );

   if (nread <= 0) {
      slog(LOG_DEBUG, "%s: read from fd %d returned %ld: %s",
           function, s, (long)nread, strerror(errno));

      return nread;
   }

   if (recvflags != NULL)
      recvflags->fromsocket += nread;

   if (sockscf.option.debug)
      slog(LOG_DEBUG,
           "%s: read %ld/%lu from socket.  Previously buffered: %lu/%lu",
           function,
           (long)nread,
           (long unsigned)toread,
           (long unsigned)socks_bytesinbuffer(s, READ_BUF, 0),
           (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

   socks_addtobuffer(s, READ_BUF, 1, outputmem, nread);

   if (socks_bytesinbuffer(s, READ_BUF, 1) < GSSAPI_HLEN) {
      slog(LOG_DEBUG,
           "%s: did not read the whole gssapi header this time.  "
           "%lu read so far, %lu left to read.  ",
           function,
           (unsigned long)(socks_bytesinbuffer(s, READ_BUF, 1)),
           (unsigned long)(  GSSAPI_HLEN
                           - socks_bytesinbuffer(s, READ_BUF, 1)));

#if SOCKS_CLIENT
      slog(LOG_DEBUG, "%s: draining %lu peeked at bytes from socket",
           function, (unsigned long)nread);

      rc = recv(s,
                outputmem,
                nread,
                0);

      if (rc != nread)
         SWARN(rc);

      if (fdisblocking(s)) {
         slog(LOG_DEBUG,
              "%s: fd %d is blocking ... going round again.", function, s);

         goto again;
      }
#endif /* SOCKS_CLIENT */

      errno = EAGAIN;
      return -1;
   }

   /*
    * Have read enough to at least check the whole SOCKS GSSAPI header,
    * so check that first.
    */

   p = socks_getfrombuffer(s, MSG_PEEK, READ_BUF, 1, inputmem, GSSAPI_HLEN);
   SASSERTX(p == GSSAPI_HLEN);

   if (!gssapi_headerisok(inputmem, p, &encodedlen, emsg, sizeof(emsg))) {
      slog(LOG_NOTICE,
           "%s: invalid gssapi header received in data from fd %d (%s): %s",
           function, s, socket2string(s, NULL, 0), emsg);

      /*
       * would be nice to only discard the data belonging to the erroneous
       * token, but how can we know how long it is? Things will probably
       * only go downhill from here so close the session instead,
       * at least in the client tcp case.
       */
      socks_clearbuffer(s, READ_BUF);

#if SOCKS_CLIENT /* drain the bytes we peeked at. */
      if ((rc = recv(s, outputmem, nread, 0)) != nread)
         SWARN(rc);
#endif /* SOCKS_CLIENT */

      /*
       * client should know it can not read again after this, but
       * it would be better if we detected the client trying to.
       * We can however not close the socket on the clients behalf.
       */
      errno = ECONNABORTED;
      return -1;
   }

   if (socks_bytesinbuffer(s, READ_BUF, 1) < (size_t)GSSAPI_HLEN + encodedlen) {
#if SOCKS_CLIENT /* drain the bytes we peeked at. */

      rc = socks_recvfromn(s, outputmem, nread, nread, 0, NULL, NULL, NULL, 0);

      if (rc != nread)
         swarn("%s: could not read %lu peeked byte%s from fd %d.  Read %ld",
               function,
               (unsigned long)nread,
               (unsigned long)nread == 1 ? "" : "s",
               s,
               (long)rc);
#endif /* SOCKS_CLIENT */

      slog(LOG_DEBUG,
           "%s: read %ld this time, %lu left to read to get the whole token",
           function,
           (long)nread,
           (unsigned long)(  GSSAPI_HLEN + encodedlen
                           - socks_bytesinbuffer(s, READ_BUF, 1)));

#if SOCKS_CLIENT
      if (fdisblocking(s)) {
         slog(LOG_DEBUG,
              "%s: fd %d is blocking ... going round again", function, s);

         goto again;
      }
#endif /* SOCKS_CLIENT */

      errno = EAGAIN;
      return -1;
   }

   /*
    * Now we have read all the bytes belonging to at least one token
    * and can start decoding.
    */

#if SOCKS_CLIENT
   /*
    * what we need to save in peekedbytes is the number of bytes we
    * read now that belong to the current token, and no more.
    * That is the size of the encoded token minus the number of bytes
    * we had already read (and thus previously discarded).
    */

   iobuf->info[READ_BUF].peekedbytes =   (GSSAPI_HLEN + encodedlen)
                                       - encodedinbuffer;

   slog(LOG_DEBUG,
        "%s: have read complete token of encoded size %d + %lu.  "
        "Total encoded bytes in buffer %lu",
        function,
        GSSAPI_HLEN,
        (unsigned long)encodedlen,
        (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1));
#endif /* SOCKS_CLIENT */

   readfrombuf = socks_getfrombuffer(s,
                                     0,
                                     READ_BUF,
                                     1,
                                     inputmem,
                                     GSSAPI_HLEN + encodedlen);

   slog(LOG_DEBUG,
        "%s: read all we need to decode token #%lu of length %u.   "
        "Last encoded byte: 0x%x",
        function,
        (unsigned long)tokennumber,
        encodedlen,
        inputmem[readfrombuf - 1]);

   SASSERTX(readfrombuf == (size_t)(GSSAPI_HLEN + encodedlen));

   input_token.value  = inputmem    + GSSAPI_HLEN;
   input_token.length = readfrombuf - GSSAPI_HLEN;

   output_token.value  = outputmem;
   output_token.length = sizeof(outputmem);

   if (gssapi_decode(&input_token, gs, &output_token) != 0) {
      slog(LOG_INFO,
           "%s: gssapi token of length %u failed to decode - discarded: %s",
           function, encodedlen, strerror(errno));

#if SOCKS_CLIENT /* drain the bytes we peeked at. */
      rc = recv(s, outputmem, iobuf->info[READ_BUF].peekedbytes, 0);

      if (rc != (ssize_t)iobuf->info[READ_BUF].peekedbytes)
         SWARN(rc);
      else {
         SASSERTX(rc <= nread);

         /*
          * recvflags is always NULL in the client, but perhaps in future ...
          */
         if (recvflags != NULL) /* only count non-peeked bytes. */
            recvflags->fromsocket -= (nread - rc);
      }
#endif /* SOCKS_CLIENT */

      /*
       * client should know it can not read again after this, but
       * it would be better if we detected the client trying to.
       * We can however not close the socket on the clients behalf.
       */
      errno = ECONNABORTED;
      return -1;
   }

   /*
    * Copy what we have room for to callers buffer, the rest we save
    * in iobuf for later.
    */

   len = MIN(output_token.length, len);
   memcpy(buf, output_token.value, len);

   if (output_token.length > len)
      socks_addtobuffer(s,
                        READ_BUF,
                        0,
                        ((char *)output_token.value) + len,
                        output_token.length - len);


   if (sockscf.option.debug)
      slog(LOG_DEBUG,
           "%s: copied %lu/%lu of this token to caller.  "
           "Have %lu decoded byte%s left in buffer, %lu bytes encoded",
           function,
           (unsigned long)len,
           (unsigned long)output_token.length,
           (long unsigned)socks_bytesinbuffer(s, READ_BUF, 0),
           (long unsigned)socks_bytesinbuffer(s, READ_BUF, 0) == 1 ? "" : "s",
           (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

#if SOCKS_CLIENT
   /*
    * discard any remaining encoded data ... belongs to next token(s).
    * Since we're only peeking in the client case, the data will
    * still be there next time.
    */
   socks_getfrombuffer(s, 0, READ_BUF, 1, inputmem, sizeof(inputmem));

   if (flags & MSG_PEEK) {
      /*
       * Need to add the data we are returning to caller now back to
       * the start of our buffer; it must be there next time too.
       */

      if (len > 0) {
         /*
          * Get whats left in the buffer first, so it is empty and we
          * can add the data back to the start of the buffer.
          */
         nread = socks_getfrombuffer(s,
                                     0,
                                     READ_BUF,
                                     0,
                                     inputmem,
                                     sizeof(inputmem));

         socks_addtobuffer(s, READ_BUF, 0, buf, len);
         socks_addtobuffer(s, READ_BUF, 0, inputmem, nread);
      }
   }
   else if (socks_bytesinbuffer(s, READ_BUF, 0) == 0) {
      slog(LOG_DEBUG,
           "%s: complete token returned to caller, draining socket for last "
           "%lu bytes",
           function,
           (unsigned long)iobuf->info[READ_BUF].peekedbytes);

      rc = recv(s, inputmem, iobuf->info[READ_BUF].peekedbytes, flags);

      if (rc != (ssize_t)iobuf->info[READ_BUF].peekedbytes)
         swarn("%s: expected to read %lu previously peeked at bytes, "
               "but read only %ld",
               function,
               (unsigned long)iobuf->info[READ_BUF].peekedbytes,
               (long)rc);

      socks_clearbuffer(s, READ_BUF);
   }
#else /* !SOCKS_CLIENT */

   /*
    * Make sure we decode what we can.  We should only have encoded data in
    * the buffer if we have not yet read enough encoded data to decode it.
    */

   while (socks_bytesinbuffer(s, READ_BUF, 1) > GSSAPI_HLEN) {
       ++tokennumber;

       slog(LOG_DEBUG,
            "%s: read more than one token, now working on token #%lu",
            function, (long unsigned)tokennumber);

       nread = socks_getfrombuffer(s,
                                   MSG_PEEK,
                                   READ_BUF,
                                   1,
                                   inputmem,
                                   GSSAPI_HLEN);

       SASSERTX(nread == GSSAPI_HLEN);

       if (!gssapi_headerisok(inputmem,
                              nread,
                              &encodedlen,
                              emsg,
                              sizeof(emsg))) {
         /*
          * would be nice to only discard the data belonging to the
          * erroneous token, but how can we know how long it is?
          * Things will probably only go downhill from here, and we should
          * close the session instead, but we already have some correct
          * data from the caller, so at least return that.
          */

         slog(LOG_INFO, "%s: invalid gssapi token received on fd %d (%s): %s",
              function, s, socket2string(s, NULL, 0), emsg);

         socks_clearbuffer(s, READ_BUF);
         break;
      }

      if (socks_bytesinbuffer(s, READ_BUF, 1)
      < (size_t)(encodedlen + GSSAPI_HLEN)) {
         slog(LOG_DEBUG,
              "%s: have only %lu bytes so far, but token is of length %u + %d",
              function,
              (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1),
              encodedlen,
              GSSAPI_HLEN);

         break;
      }

      nread = socks_getfrombuffer(s,
                                  0,
                                  READ_BUF,
                                  1,
                                  inputmem,
                                  GSSAPI_HLEN + encodedlen);

      SASSERTX(nread == GSSAPI_HLEN + encodedlen);

      slog(LOG_DEBUG,
            "%s: read all we need to decode token #%lu of length %u "
            "([%d]: 0x%x, [%d]: 0x%x)",
            function,
            (unsigned long)tokennumber,
            encodedlen,
            GSSAPI_HLEN + encodedlen - 1,
            inputmem[GSSAPI_HLEN + encodedlen - 1],
            GSSAPI_HLEN + encodedlen - 2,
            inputmem[GSSAPI_HLEN + encodedlen - 2]);

      input_token.value  = inputmem  + GSSAPI_HLEN;
      input_token.length = encodedlen;

      output_token.value  = outputmem;
      output_token.length = sizeof(outputmem);

      if (gssapi_decode(&input_token, gs, &output_token) != 0) {
         swarnx("%s: gssapi token of length %lu failed to decode, discarded",
                function, (unsigned long)input_token.length);

         break;
      }

      if (sockscf.option.debug)
         slog(LOG_DEBUG,
              "%s: adding %lu decoded byte%s from new token to buffer.  "
              "Encoded byte%s in buffer: %lu",
              function,
              (unsigned long)output_token.length,
              output_token.length == 1 ? "" : "s",
              (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1) == 1 ?
                  "" : "s",
              (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

      socks_addtobuffer(s, READ_BUF, 0, outputmem, output_token.length);
   }
#endif /* !SOCKS_CLIENT */

   return len;
}

/*
 * RFC1961: client request / server response
 *
 *   +------+------+------+.......................+
 *   + ver  | mtyp | len  |       token           |
 *   +------+------+------+.......................+
 *   + 0x01 | 0x03 | 0x02 | up to 2^16 - 1 octets |
 *   +------+------+------+.......................+
 *
 */

ssize_t
gssapi_encode_write(s, msg, len, flags, to, tolen, sendtoflags, gs)
   int s;
   const void *msg;
   size_t len;
   int flags;
   const struct sockaddr_storage *to;
   socklen_t tolen;
   sendto_info_t *sendtoflags;
   gssapi_state_t *gs;
{
   const char *function = "gssapi_encode_write()";
   gss_buffer_desc input_token, output_token;
   unsigned char outputmem[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
   unsigned short pshort;
   iobuffer_t *iobuf;
   ssize_t towrite, written, p;
   size_t i;

#if 0
   static size_t j;
   size_t lenv[] = { 60000, 60001, 60002, 60003, 60004, 60005, 60006, 60007,
                     60008, 60009, 60010, 60011, 60012, 60013, 60014, 60015 };

   len = MIN(lenv[j % ELEMENTS(lenv)], len);
   ++j;
#endif

   slog(LOG_DEBUG, "%s: fd %d, len %lu, gssoverhead %lu",
        function, s, (unsigned long)len, (unsigned long)gs->gssoverhead);

   if ((iobuf = socks_getbuffer(s)) == NULL) {
      /*
       * Allocate one.
       */
      int stype;
      socklen_t tlen = sizeof(stype);

      /*
       * In server we are only using pre-allocated buffers and we allocate
       * them before this function should ever be called.
       */
      SASSERTX(SOCKS_CLIENT);

      if (getsockopt(s, SOL_SOCKET, SO_TYPE, &stype, &tlen) != 0) {
         swarn("%s: getsockopt(SO_TYPE) on fd %d failed", function, s);
         return -1;
      }

      if ((iobuf = socks_allocbuffer(s, stype)) == NULL) {
         swarn("%s: could not allocate iobuffer for fd %d", function, s);

         errno = ENOMEM;
         return -1;
      }
   }

   if (iobuf->stype == SOCK_DGRAM)
      return gssapi_encode_write_udp(s,
                                     msg,
                                     len,
                                     flags,
                                     to,
                                     tolen,
                                     sendtoflags,
                                     gs,
                                     outputmem,
                                     sizeof(outputmem));

   /*
    * Two modes:
    * Unbuffered:
    *    We try to write upto "len" bytes, and if that fails, we
    *    store the remaining bytes in iobuf, encoded.
    *    This makes us able to return either "len" or -1 to caller, so
    *    that caller understands we have accepted all data.  It is
    *    slightly unfortunate that it does not necessarily mean all
    *    the data has been written to the network-socket, but it's
    *    probably still the best way.
    *
    * Buffered:
    *    We keep saving the data in the buffer, but _not_ encoded.
    *    Upon flush, we encode and write it.
    *    This is only used by the client, to simulate stdio-buffering.
    */

#if SOCKS_CLIENT
   if (iobuf->info[WRITE_BUF].mode != _IONBF) { /* buffered mode. */
      if (flags & MSG_OOB)
         swarnx("%s: oob data is currently not handled for buffered writes",
                function);

      if (socks_freeinbuffer(s, WRITE_BUF) < len) {
         /*
          * after the flush, we should have space in buffer again.
          */
         if (socks_flushbuffer(s, -1, sendtoflags) == -1)
            return -1;
      }

      SASSERTX(socks_freeinbuffer(s, WRITE_BUF) >= len);
      socks_addtobuffer(s, WRITE_BUF, 0, msg, len);

      if (len >= 2) {
         if (((const unsigned char *)msg)[len - 2] == '\r'
         ||  ((const unsigned char *)msg)[len - 2] == '\n')
            /*
             * More correct would be to check if we have \r or \n
             * anywhere in the buffer, and flush up to that point.
             * That is a hassle however, and this is only needed for
             * broken Linux glibc systems, so don't bother.
             */
            (void)socks_flushbuffer(s, -1, sendtoflags);
      }

      return len;
   }
#endif /* SOCKS_CLIENT */

   if ((towrite = socks_bytesinbuffer(s, WRITE_BUF, 1)) > 0) {
      /*
       * have encoded data for write buffered already.  Flush that first.
       */

      /* no permanent buffering for udp. */
      SASSERTX(iobuf->stype == SOCK_STREAM);

      if (socks_flushbuffer(s, -1, sendtoflags) == -1 && !ERRNOISTMP(errno))
         return -1;
   }

   /*
    * Attempt to avoid writing a partial token with no room to buffer the
    * remainder.  Since gs->gssoverhead is not a constant size, we need to
    * handle the possibility of it increasing, by checking again later that
    * we actually have enough room to store the encoded token in our buffer.
    */

   /* save space for SOCKS GSSAPI header too. */
   output_token.length = MIN(sizeof(outputmem) - GSSAPI_HLEN,
                             socks_freeinbuffer(s, WRITE_BUF) - GSSAPI_HLEN);

   /* will put the SOCKS GSSAPI header at the start. */
   output_token.value = outputmem + GSSAPI_HLEN;

   if (gs->maxgssdata != 0) /* 0 if not yet determined. */
      len = MIN(len, gs->maxgssdata);

   p = MIN(len, socks_freeinbuffer(s, WRITE_BUF) - gs->gssoverhead);

   if (p <= 0 || output_token.length < gs->gssoverhead) {
      slog(LOG_DEBUG,
           "%s: not enough room in buffer.  Free space in buffer is only %lu, "
           "while expected gssapi-encapsulation overhead is %lu",
           function,
           (unsigned long)socks_freeinbuffer(s, WRITE_BUF),
           (unsigned long)gs->gssoverhead);

      errno = EAGAIN;
      return -1;
   }

   if (len != (size_t)p)
      slog(LOG_DEBUG, "%s: only have room to attempt a write of %ld/%lu",
           function, (long)p, (unsigned long)len);

   len = p;

   input_token.value  = msg;
   input_token.length = len;

   if (gssapi_encode(&input_token, gs, &output_token) != 0) {
      if (errno == EMSGSIZE) {
         OM_uint32 minor_status, major_status, maxlen;
         char emsg[1024];

         major_status
         = gss_wrap_size_limit(&minor_status,
                               gs->id,
                               gs->protection == GSSAPI_CONFIDENTIALITY ?
                                       GSS_REQ_CONF : GSS_REQ_INT,
                               GSS_C_QOP_DEFAULT,
                               output_token.length,
                               &maxlen);

         if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
            swarnx("%s: gss_wrap_size_limit(): %lu is too big a token for "
                   "GSSAPI-encoding and we are unable to determine what the "
                   "maximum is: %s",
                   function, (long unsigned)len, emsg);

            return -1;
         }

         slog(LOG_DEBUG,
              "%s: data of length %lu too big for GSSAPI-encode.  "
              "Maximum determined to be %lu.  Trying again",
              function, (long unsigned)len, (long unsigned)maxlen);

         /* callers responsibility to cope with a short write. */
         len = maxlen;

         input_token.length = len;

         if (gssapi_encode(&input_token, gs, &output_token) == 0)
            errno = 0;
         else {
            swarnx("%s: strange, gssapi_encode() failed with the shorter "
                   "message of length %lu too",
                   function, (unsigned long)input_token.length);

            errno = ECONNABORTED;
            return -1;
         }
      }
      else
         return -1;
   }

   if (output_token.length + GSSAPI_HLEN > socks_freeinbuffer(s, WRITE_BUF)) {
      slog(LOG_DEBUG,
           "%s: not enough free space in buffer to hold token of length %lu",
           function, (unsigned long)(output_token.length + GSSAPI_HLEN));

      errno = EAGAIN;
      return -1;
   }

   /*
    * Prefix the SOCKS GSSAPI header to the token.
    */

   output_token.value  = outputmem; /* shift back to start. */

   i = 0;
   ((unsigned char *)output_token.value)[i++] = SOCKS_GSSAPI_VERSION;
   ((unsigned char *)output_token.value)[i++] = SOCKS_GSSAPI_PACKET;

   pshort = htons(output_token.length);
   memcpy(&((unsigned char *)output_token.value)[i], &pshort, sizeof(pshort));
   i += sizeof(pshort);

   output_token.length += i;

   SASSERTX(i == GSSAPI_HLEN);

   socks_addtobuffer(s, WRITE_BUF, 1, output_token.value, output_token.length);

   towrite = socks_getfrombuffer(s,
                                 1,
                                 WRITE_BUF,
                                 1,
                                 outputmem,
                                 sizeof(outputmem));

   if (towrite >= GSSAPI_HLEN + 2)
      slog(LOG_DEBUG,
           "%s: attempting to write %lu encoded bytes.  "
           "[0]: 0x%x, [1]: 0x%x, [%d]: 0x%x, [%d]: 0x%x",
           function,
           (unsigned long)towrite,
           outputmem[0],
           outputmem[1],
           (int)towrite - 2,
           outputmem[towrite - 2],
           (int)towrite - 1,
           outputmem[towrite - 1]);
   else
      slog(LOG_DEBUG, "%s: attempting to write %lu encoded bytes",
           function, (unsigned long)towrite);

   if ((written = sendto(s, outputmem, towrite, flags, TOCSA(to), tolen))
   == -1) {
#if SOCKS_CLIENT

      return -1;

#else /* !SOCKS_CLIENT */

      if (ERRNOISTMP(errno))
         written = 0; /* and continue as for any other short write. */
      else
         return -1;
#endif /* !SOCKS_CLIENT */
   }
   else
      if (sendtoflags != NULL)
         sendtoflags->tosocket += written;

   /*
    * Add what we could not write to our buffer.
    */
   socks_addtobuffer(s, WRITE_BUF, 1, outputmem + written, towrite - written);

   if (sockscf.option.debug)
      slog(LOG_DEBUG,
           "%s: wrote %ld/%lu to fd %d, saved remaining %lu byte%s in "
           "buffer that now has %lu bytes free",
           function,
           (long)written,
           (long unsigned)towrite,
           s,
           (long unsigned)(towrite - written),
           (long unsigned)socks_bytesinbuffer(s, WRITE_BUF, 1) == 1 ? "" : "s",
           (long unsigned)socks_freeinbuffer(s,  WRITE_BUF));

   return len;
}

int
gssapi_export_state(id, state)
   gss_ctx_id_t *id;
   gss_buffer_desc *state;
{
   const char *function = "gssapi_export_state()";
   const int errno_s = errno;
   OM_uint32 major_status, minor_status;
   gss_buffer_desc token;
   char emsg[512];
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */

   slog(LOG_DEBUG, "%s", function);

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   major_status = gss_export_sec_context(&minor_status, id, &token);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      swarnx("%s: gss_export_sec_context() failed: %s", function, emsg);
      return -1;
   }

   if (token.length > state->length) {
      swarnx("%s: we depend on the size of the exported gssapi context not "
             "being larger than a predefined value (%lu), but unfortunately "
             "the value here (%lu) larger than that.  Please let us know",
             function,
             (unsigned long)state->length,
             (unsigned long)token.length);

      SWARNX(0);

      return -1;
   }

   SASSERTX(token.length <= state->length);
   memcpy(state->value, token.value, token.length);
   state->length = token.length;

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   gss_release_buffer(&minor_status, &token);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

   slog(LOG_DEBUG,
        "%s: created gssapistate of length %lu (start: 0x%x, 0x%x)",
        function,
        (unsigned long)state->length,
        ((unsigned char *)state->value)[0],
        ((unsigned char *)state->value)[1]);

   errno = errno_s; /* at least some gssapi libraries change errno. :-/ */
   return 0;
}

int
gssapi_import_state(id, state)
   gss_ctx_id_t *id;
   gss_buffer_desc *state;
{
   const char *function = "gssapi_import_state()";
   const int errno_s = errno;
   OM_uint32 major_status, minor_status;
   char emsg[512];
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */

   slog(LOG_DEBUG,
        "%s: importing gssapistate of length %lu " "(start: 0x%x, 0x%x)",
         function,
         (unsigned long)state->length,
         ((unsigned char *)state->value)[0],
         ((unsigned char *)state->value)[1]);

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   major_status = gss_import_sec_context(&minor_status, state, id);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      swarnx("%s: gss_import_sec_context(): %s", function, emsg);
      return -1;
   }

   errno = errno_s; /* at least some gssapi libraries change errno. :-/ */

   return 0;
}

static int
gssapi_headerisok(headerbuf, len, tokenlen, emsg, emsglen)
   const unsigned char *headerbuf;
   const size_t len;
   unsigned short *tokenlen;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "gssapi_headerisok()";

   if (len < GSSAPI_HLEN) {
      snprintf(emsg, emsglen,
               "gssapi packet of length %lu is too short.  Minimum is %lu",
               (unsigned long)len, (unsigned long)GSSAPI_HLEN);
      return 0;
   }

   if (headerbuf[GSSAPI_VERSION] != SOCKS_GSSAPI_VERSION
   ||  headerbuf[GSSAPI_STATUS]  != SOCKS_GSSAPI_PACKET) {
      snprintf(emsg, emsglen,
               "invalid socks gssapi header (0x%x, 0x%x, not 0x%x, 0x%x)",
               (unsigned char)headerbuf[GSSAPI_VERSION],
               (unsigned char)headerbuf[GSSAPI_STATUS],
               SOCKS_GSSAPI_VERSION,
               SOCKS_GSSAPI_PACKET);

      return 0;
   }

   memcpy(tokenlen, &headerbuf[GSSAPI_TOKEN_LENGTH], sizeof(*tokenlen));
   *tokenlen = ntohs(*tokenlen);

   slog(LOG_DEBUG, "%s: SOCKS header for GSSAPI token of length %u is ok",
        function, *tokenlen);

   return 1;
}

#if SOCKS_CLIENT
int
gssapi_isencrypted(s)
   const int s;
{
   socksfd_t socksfd;

   if (!sockscf.state.havegssapisockets)
      return 0;

   /* XXX this takes too long. */
   if (!socks_addrisours(s, &socksfd, 1)) {
      socks_rmaddr(s, 1);
      return 0;
   }

   if (socksfd.state.auth.method != AUTHMETHOD_GSSAPI)
      return 0;

   return socksfd.state.auth.mdata.gssapi.state.wrap;
}

#endif /* SOCKS_CLIENT */

static ssize_t
gssapi_decode_read_udp(s, buf, len, flags, from, fromlen, recvflags, gs,
                       token, tokensize)
   int s;
   void *buf;
   size_t len;
   int flags;
   struct sockaddr_storage *from;
   socklen_t *fromlen;
   recvfrom_info_t *recvflags;
   gssapi_state_t *gs;
   unsigned char *token;
   const size_t tokensize;
{
   const char *function = "gssapi_decode_read_udp()";
   gss_buffer_desc input_token, output_token;
   unsigned short encodedlen;
   ssize_t nread;
   char emsg[512];

   slog(LOG_DEBUG, "%s: fd %d, len %lu, flags %d",
        function, s, (long unsigned)len, flags);

   /*
    * Ok since we don't buffer udp data.  But if that is ever added, we
    * must make sure socks_recvfrom() does not step on our toes as far
    * as using our iobuffer is concerned (e.g. by adding data to the iobuf,
    * saying it is not encrypted since we pass NULL for auth to it).
    */
   if ((nread = socks_recvfrom(s,
                               token,
                               tokensize,
                               flags,
                               from,
                               fromlen,
                               recvflags,
                               NULL)) <= 0) {
      slog(LOG_DEBUG, "%s: read from fd %d returned %ld: %s",
           function, s, (long)nread, strerror(errno));

      return nread;
   }

   slog(LOG_DEBUG, "%s: read %ld/%lu from socket",
        function, (long)nread, (long unsigned)tokensize);

   if (nread < GSSAPI_HLEN) {
      slog(LOG_INFO,
           "%s: packet read on fd %d (%s) is shorter than minimal gssapi "
           "header length (%ld < %lu)",
           function,
           s,
           socket2string(s, NULL, 0),
           (long)nread,
           (unsigned long)GSSAPI_HLEN);

      errno = ENOMSG;
      return -1;
   }

   if (!gssapi_headerisok(token, nread, &encodedlen, emsg, sizeof(emsg))) {
      slog(LOG_INFO, "%s: invalid gssapi header on fd %d (packet from %s): %s",
           function, s, socket2string(s, NULL, 0), emsg);

      errno = ENOMSG;
      return -1;
   }

   if (nread < GSSAPI_HLEN + encodedlen) {
      slog(LOG_INFO,
           "%s: short packet on fd %d (packet from %s).  Should be %lu bytes, "
           "but received only %ld",
           function,
           s,
           socket2string(s, NULL, 0),
           (unsigned long)(GSSAPI_HLEN + encodedlen),
           (long)nread);

      errno = ENOMSG;
      return -1;
   }

   slog(LOG_DEBUG, "%s: read complete token of encoded size %d + %u",
        function, GSSAPI_HLEN, encodedlen);

   input_token.value  = token + GSSAPI_HLEN;
   input_token.length = nread - GSSAPI_HLEN;

   output_token.value  = buf;
   output_token.length = len;

   if (gssapi_decode(&input_token, gs, &output_token) != 0) {
      slog(LOG_INFO, "%s: udp token of length %u failed decode - discarded: %s",
           function,
           encodedlen,
           errno == ENOMEM ? "output buffer too small" : strerror(errno));

      if (errno == ENOMEM) {
#if !SOCKS_CLIENT
         SWARNX(len);
#endif /* !SOCKS_CLIENT */
      }

      errno = ENOMSG;
      return -1;
   }

   return output_token.length;
}

static ssize_t
gssapi_encode_write_udp(s, msg, len, flags, to, tolen, sendtoflags, gs,
                        token, tokensize)
   int s;
   const void *msg;
   size_t len;
   int flags;
   const struct sockaddr_storage *to;
   socklen_t tolen;
   sendto_info_t *sendtoflags;
   gssapi_state_t *gs;
   unsigned char *token;
   const size_t tokensize;
{
   const char *function = "gssapi_encode_write_udp()";
   gss_buffer_desc input_token, output_token;
   unsigned short pshort;
   ssize_t towrite, written;
   size_t i;

   slog(LOG_DEBUG, "%s: fd %d, len %lu, gssoverhead %lu",
        function, s, (unsigned long)len, (unsigned long)gs->gssoverhead);

   /* save space for SOCKS GSSAPI header too. */
   output_token.length = tokensize - GSSAPI_HLEN;

   /* will put the SOCKS GSSAPI header at the start. */
   output_token.value = token + GSSAPI_HLEN;

   input_token.value  = msg;
   input_token.length = len;

   if (gssapi_encode(&input_token, gs, &output_token) != 0)
      return -1;

   /*
    * Prefix the SOCKS GSSAPI header to the token.
    */

   output_token.value  = token; /* shift back to start. */

   i = 0;
   ((unsigned char *)output_token.value)[i++] = SOCKS_GSSAPI_VERSION;
   ((unsigned char *)output_token.value)[i++] = SOCKS_GSSAPI_PACKET;

   pshort = htons(output_token.length);
   memcpy(&((unsigned char *)output_token.value)[i], &pshort, sizeof(pshort));
   i += sizeof(pshort);

   SASSERTX(i == GSSAPI_HLEN);

   output_token.length += i;
   towrite              = output_token.length;


   if (towrite >= GSSAPI_HLEN + 2)
      slog(LOG_DEBUG,
           "%s: attempting to write %lu encoded bytes.  "
           "[0]: 0x%x, [1]: 0x%x, [%d]: 0x%x, [%d]: 0x%x",
           function,
           (unsigned long)towrite,
           token[0],
           token[1],
           (int)towrite - 2,
           token[towrite - 2],
           (int)towrite - 1,
           token[towrite - 1]);
   else
      slog(LOG_DEBUG, "%s: attempting to write %lu encoded bytes",
           function, (unsigned long)towrite);

   written = sendto(s, token, towrite, flags, TOCSA(to), tolen);

   if (sendtoflags != NULL && written > 0)
      sendtoflags->tosocket += written;

   slog(LOG_DEBUG, "%s: wrote %ld/%lu (%lu unencoded) to fd %d",
        function, (long)written, (unsigned long)towrite, (unsigned long)len, s);

   return len;
}

#endif /* HAVE_GSSAPI */
