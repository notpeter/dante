/*
 * Copyright (c) 2009, 2010, 2011, 2012
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
"$Id: gssapi.c,v 1.105 2012/06/01 20:23:05 karls Exp $";

#if HAVE_GSSAPI

static int
gssapi_headerisok(const char *headerbuf);

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
   size_t w, len;

   if (!GSS_ERROR(major_status))
      return 0;

   len     = 0;
   msg_ctx = 0;
   do {
      /*
       * convert major status code (GSSAPI error) to text.
       */

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      maj_stat = gss_display_status(&min_stat, major_status,
                                    GSS_C_GSS_CODE,
                                    GSS_C_NULL_OID,
                                    &msg_ctx, &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

      if (!GSS_ERROR(maj_stat)) {
         w = snprintf(buf, buflen, "%.*s",
                      (int)statstr.length, (char *)statstr.value);
         buf    += w;
         buflen -= w;
      }

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      gss_release_buffer(&min_stat, &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);
   } while (msg_ctx != 0 && !GSS_ERROR(maj_stat));

   if (sizeof(buf) > len + strlen(".  ")) {
      w       = snprintf(buf, buflen, ".  ");
      buf    += w;
      buflen -= w;
   }

   msg_ctx = 0;
   do {
      /*
       * convert minor status code (underlying routine error) to text.
       */

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      maj_stat = gss_display_status(&min_stat, minor_status,
                                    GSS_C_MECH_CODE,
                                    GSS_C_NULL_OID,
                                    &msg_ctx, &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

      if (!GSS_ERROR(maj_stat)) {
         w = snprintf(buf, buflen, "%.*s ",
                      (int)statstr.length, (char *)statstr.value);
         buf    += w;
         buflen -= w;
      }

      SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
      gss_release_buffer(&min_stat, &statstr);
      SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);
   } while (msg_ctx != 0 && !GSS_ERROR(maj_stat));

   return 1;
}

int
gssapi_encode(input, ilen, gs, output, olen)
   const void *input;
   size_t ilen;
   gssapi_state_t *gs;
   size_t *olen;
   void *output;
{
   const char *function = "gssapi_encode()";
   gss_buffer_desc input_token, output_token;
   OM_uint32 minor_status, major_status;
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */
   unsigned char buf[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
   char emsg[1024];
   int conf_state;

   slog(LOG_DEBUG, "%s, ilen %lu, olen %lu",
   function, (long unsigned)ilen, (long unsigned)*olen);

   input_token.length = ilen;
   input_token.value  = buf;
   memcpy(input_token.value, input, ilen);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_native();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   major_status = gss_wrap(&minor_status,
                           gs->id,
                           gs->protection == GSSAPI_CONFIDENTIALITY ?
                           GSS_REQ_CONF : GSS_REQ_INT,
                           GSS_C_QOP_DEFAULT,
                           &input_token,
                           &conf_state,
                           &output_token);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_normal();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      swarnx("%s: gss_wrap(): %s", function, emsg);
      return -1;
   }

   if (output_token.length > *olen) {
      slog(LOG_DEBUG, "%s: encoded token length (%lu) larger than buffer (%lu)",
      function, (long unsigned)output_token.length, (long unsigned)*olen);

      CLEAN_GSS_TOKEN(output_token);

      errno = EMSGSIZE;
      return -1;
   }

   *olen = output_token.length;
   memcpy(output, output_token.value, output_token.length);

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: gssapi packet encoded, dec/enc length %lu/%lu, "
                      "0x%x, 0x%x, 0x%x, 0x%x",
                      function, (long unsigned)ilen, (long unsigned)*olen,
                      ((unsigned char *)output)[0],
                      ((unsigned char *)output)[1],
                      ((unsigned char *)output)[(*olen) - 2],
                      ((unsigned char *)output)[(*olen) - 1]);

   CLEAN_GSS_TOKEN(output_token);

   return 0;
}

int
gssapi_decode(input, ilen, gs, output, olen)
   void *input;
   size_t ilen;
   gssapi_state_t *gs;
   void *output;
   size_t *olen;
{
   const char *function = "gssapi_decode()";
   gss_buffer_desc input_token, output_token;
   OM_uint32  minor_status, major_status;
#if SOCKS_CLIENT
   sigset_t oldset;
#endif /* SOCKS_CLIENT */
   unsigned char buf[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
   char emsg[1024];
   int req_conf_state;

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s:  0x%x, 0x%x, 0x%x, 0x%x",
      function,
      ((unsigned char *)input)[0], ((unsigned char *)input)[1],
      ((unsigned char *)input)[ilen - 2], ((unsigned char *)input)[ilen - 1]);

   if (ilen == 0) {
      *olen = 0;
      return 0;
   }

   input_token.length = ilen;
   input_token.value  = buf;
   SASSERTX(ilen <= sizeof(buf));
   memcpy(input_token.value, input, input_token.length);

   req_conf_state
   = (gs->protection == GSSAPI_CONFIDENTIALITY ? GSS_REQ_CONF : GSS_REQ_INT);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_native();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   major_status = gss_unwrap(&minor_status, gs->id, &input_token,
                             &output_token, &req_conf_state, GSS_C_QOP_DEFAULT);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

#if SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC
   socks_mark_io_as_normal();
#endif /* SOCKS_CLIENT && SOCKSLIBRARY_DYNAMIC */

   if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
      swarnx("%s: gss_unwrap(): %s", function, emsg);
      return -1;
   }

   if (output_token.length > *olen) {
      CLEAN_GSS_TOKEN(output_token);
      errno = ENOMEM;

      return -1;
   }

   *olen = output_token.length;
   memcpy(output, output_token.value, output_token.length);
   CLEAN_GSS_TOKEN(output_token);

   slog(LOG_DEBUG, "%s: gssapi packet decoded, decoded/encoded length %lu/%lu",
   function, (long unsigned)*olen, (long unsigned)ilen);

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
gssapi_decode_read(s, buf, len, flags, from, fromlen, flags_recv, ts_recv, gs)
   int s;
   void *buf;
   size_t len;
   int flags;
   struct sockaddr *from;
   socklen_t *fromlen;
   int *flags_recv;
   struct timeval *ts_recv;
   gssapi_state_t *gs;
{
   const char *function = "gssapi_decode_read()";
#if SOCKS_SERVER
   size_t tokennumber;
#else /* !SOCKS_SERVER */
   size_t encodedinbuffer;
#endif /* !SOCKS_SERVER */
   iobuffer_t *iobuf;
   unsigned short encodedlen;
   ssize_t nread;
   size_t tokenlen, toread;
   char token[GSSAPI_HLEN + MAXGSSAPITOKENLEN], tmpbuf[sizeof(iobuf->buf[0])];

#if SOCKS_CLIENT
   /*
    * If the socket is blocking, we need to retry the read.
    * The token buffers we allocate for this are too large to simply
    * call ourselves recursively again.
    */
again:
   encodedinbuffer = socks_bytesinbuffer(s, READ_BUF, 1); /* const. */
#endif /* SOCKS_CLIENT */

   slog(LOG_DEBUG, "%s: socket %d, len %lu, flags %d, inbuf %lu/%lu",
   function, s, (long unsigned)len, flags,
   (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0),
   (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1));

   if ((iobuf = socks_getbuffer(s)) == NULL) {
      int stype;
      socklen_t tlen = sizeof(stype);

      if (getsockopt(s, SOL_SOCKET, SO_TYPE, &stype, &tlen) != 0) {
         swarn("%s: getsockopt(SO_TYPE)", function);
         return -1;
      }

      if ((iobuf = socks_allocbuffer(s, stype)) == NULL) {
         swarnx("%s: could not allocate iobuffer", function);
         errno = ENOMEM;
         return -1;
      }
   }

#if SOCKS_CLIENT /* always flush before read. */
   socks_flushbuffer(s, -1);

   /*
    * When called by the client, we have the added complexity
    * that we can not completely drain the socket, because if the client
    * then select(2)'s on the socket to know when there is more to read,
    * select(2) can block forever, as the data has already been read and
    * buffered by us.
    *
    * What we need to do instead is to only peek at the last byte(s)
    * belonging to the token data as long as we have buffered data which
    * we have not yet returned to the client, and not drain the last byte(s)
    * from socket until we can return all the data in the decoded token to
    * the client.
    *
    * We also need to handle a client only peeking at the data correctly.
    * In the case of MSG_PEEK, we can do the same as for a normal read,
    * except we must leave the bytes in the buffer.
    *
    * This will make sure the socket remains readable until we have
    * returned all the data belonging to a given token to the caller,
    * which should let all the kernels select(2)/poll(2)/SIGIO/etc.
    * stuff work.
    */
#endif /* SOCKS_CLIENT */

   if (socks_bytesinbuffer(s, READ_BUF, 0) > 0) {
      toread = MIN(len, socks_bytesinbuffer(s, READ_BUF, 0));

      if (sockscf.option.debug)
         slog(LOG_DEBUG, "%s: bytes in buffer: %lu/%lu.  "
                         "Returning %lu from that instead of from socket",
         function,
         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0),
         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1),
         (unsigned long)toread);

      socks_getfrombuffer(s, READ_BUF, 0, buf, toread);

      if (flags & MSG_PEEK) {
         /*
         * client peeking, need to add the data back to the buffer so it
         * is still there next time.
         */

         /*
          * get the rest of the buffer first, so it is empty and we can add
          * to the start ...
          */
         nread = socks_getfrombuffer(s, READ_BUF, 0, tmpbuf, sizeof(tmpbuf));

         /*
          * ... and add it all back to the buffer.
          */
         socks_addtobuffer(s, READ_BUF, 0, buf, toread);
         socks_addtobuffer(s, READ_BUF, 0, tmpbuf, nread);
      }
#if SOCKS_CLIENT
      else if (socks_bytesinbuffer(s, READ_BUF, 0) == 0) {
         slog(LOG_DEBUG, "%s: all data from token returned to caller.  "
                         "Draining socket for last %lu byte%s",
                         function,
                         (unsigned long)iobuf->info[READ_BUF].peekedbytes,
                         iobuf->info[READ_BUF].peekedbytes == 1 ? "" : "s");

         recv(s, tmpbuf, iobuf->info[READ_BUF].peekedbytes, 0);
         iobuf->info[READ_BUF].peekedbytes = 0;

         SASSERTX(socks_bufferhasbytes(s, READ_BUF) == 0);

      }
#endif /* SOCKS_CLIENT */

      return toread;
   }

   /*
    * No decoded data buffered.  Must have encoded data available on socket.
    */

   SASSERTX(socks_bytesinbuffer(s, READ_BUF, 0) == 0);

   toread = MIN(sizeof(token), socks_freeinbuffer(s, READ_BUF));
   if ((nread = socks_recvfrom(s,
                        token,
                        toread,
#if SOCKS_SERVER
                        flags,
#else /* !SOCKS_SERVER */
                        flags | MSG_PEEK,
#endif /* !SOCKS_SERVER */
                        from,
                        fromlen,
                        NULL,
                        flags_recv,
                        ts_recv)) <= 0) {
      slog(LOG_DEBUG, "%s: read from socket returned %ld: %s",
           function, (long)nread, strerror(errno));

      return nread;
   }

   if (sockscf.option.debug)
      slog(LOG_DEBUG, "%s: read %ld from socket, out of a max of %lu.  "
                      "Previously buffered: %lu/%lu",
                      function, (long)nread, (long unsigned)toread,
                      (long unsigned)socks_bytesinbuffer(s, READ_BUF, 0),
                      (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

   socks_addtobuffer(s, READ_BUF, 1, token, nread);

   if (socks_bytesinbuffer(s, READ_BUF, 1) < GSSAPI_HLEN) {
      if (iobuf->stype == SOCK_DGRAM) {
         slog(LOG_DEBUG, "%s: udp packet read is shorter than minimal gssapi "
                         "header length (%lu < %lu)",
         function,
         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1) + nread,
         (unsigned long)GSSAPI_HLEN);

         socks_clearbuffer(s, READ_BUF);
         errno = ENOMSG;
      }
      else {
         slog(LOG_DEBUG, "%s: did not read the whole gssapi header this time. "
                         "%lu read so far, %lu left to read.  ",
         function,
         (unsigned long)(socks_bytesinbuffer(s, READ_BUF, 1)),
         (unsigned long)(GSSAPI_HLEN - socks_bytesinbuffer(s, READ_BUF, 1)));

#if SOCKS_CLIENT
         slog(LOG_DEBUG, "%s: draining %lu bytes from socket",
         function, (unsigned long)nread);

         recv(s, token, nread, 0);

         if (fdisblocking(s)) {
            slog(LOG_DEBUG, "%s: socket %d is blocking ... going round again.",
            function, s);

            goto again;
         }
#endif /* SOCKS_CLIENT */

         errno = EAGAIN;
      }

      return -1;
   }

   /*
    * Have read a whole gssapi header.  First verify the values make sense.
    */

   if (!gssapi_headerisok(iobuf->buf[READ_BUF])) {
      /*
       * would be nice to only discard the data belonging to the
       * erroneous token, but how can we know how long it is?
       * Things will probably only go downhill from here so close
       * the session instead, at least in the client tcp case.
       */
      socks_clearbuffer(s, READ_BUF);

#if SOCKS_CLIENT /* drain the bytes we peeked at. */
      recv(s, token, nread, 0);
#endif /* SOCKS_CLIENT */

      if (iobuf->stype == SOCK_DGRAM)
         errno = ENOMSG;
      else
         /*
          * client should know it can not read again after this, but
          * it would be better if we detected the client trying to.
          * We can however not close the socket on the clients behalf.
          */
         errno = ECONNABORTED;

      return -1;
   }

   memcpy(&encodedlen,
          &iobuf->buf[READ_BUF][GSSAPI_TOKEN_LENGTH],
          sizeof(encodedlen));

   encodedlen = ntohs(encodedlen);

   if (socks_bytesinbuffer(s, READ_BUF, 1) < (size_t)GSSAPI_HLEN + encodedlen) {
#if SOCKS_CLIENT /* drain the bytes we peeked at. */
      recv(s, token, nread, 0);
#endif /* SOCKS_CLIENT */

      if (iobuf->stype == SOCK_DGRAM) {
         slog(LOG_DEBUG, "%s: could not read whole gss-encoded udp packet.  "
                         "Packet size %lu, in buffer only %lu",
         function,  (long unsigned)GSSAPI_HLEN + encodedlen,
         (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

         socks_clearbuffer(s, READ_BUF);
         errno = ENOBUFS;
      }
      else {
         slog(LOG_DEBUG, "%s: read %ld this time, %lu left to read to get "
                         "the whole token",
         function, (long)nread,
         (unsigned long)(GSSAPI_HLEN + encodedlen
                         - socks_bytesinbuffer(s, READ_BUF, 1)));

#if SOCKS_CLIENT
         if (fdisblocking(s)) {
            slog(LOG_DEBUG, "%s: socket %d is blocking ... going round again",
            function, s);

            goto again;
         }
#endif /* SOCKS_CLIENT */

         errno = EAGAIN;
      }

      return -1;
   }

   /*
    *
    * Ok, we have now read all the bytes belonging to at least one token.
    *
    */

#if SOCKS_CLIENT
   /*
    * what we need to save in peekedbytes is the number of bytes we
    * read now that belong to the current token, no more.
    * That is the size of the encoded token minus the number of bytes
    * we had already read (and thus previously discarded).
    */

   iobuf->info[READ_BUF].peekedbytes
   = (GSSAPI_HLEN + encodedlen) - encodedinbuffer;

   slog(LOG_DEBUG, "%s: have read complete token of encoded size %d + %lu, "
                   "total encoded bytes in buffer %lu",
   function, GSSAPI_HLEN, (unsigned long)encodedlen,
   (unsigned long)socks_bytesinbuffer(s, READ_BUF, 1));
#endif /* SOCKS_CLIENT */

   socks_getfrombuffer(s, READ_BUF, 1, tmpbuf, GSSAPI_HLEN); /* checked; ok. */
   socks_getfrombuffer(s, READ_BUF, 1, tmpbuf, encodedlen);  /* to decode.   */

   tokenlen = sizeof(token);
   if (gssapi_decode(tmpbuf, encodedlen, gs, token, &tokenlen) != 0) {
      swarnx("%s: gssapi %s token of length %u failed to decode, discarded",
             iobuf->stype == SOCK_DGRAM ? "datagram" : "stream",
             function, encodedlen);

#if SOCKS_CLIENT /* drain the bytes we peeked at. */
      recv(s, token, nread, iobuf->info[READ_BUF].peekedbytes);
#endif /* SOCKS_CLIENT */

      if (iobuf->stype == SOCK_DGRAM)
         errno = ENOMSG;
      else
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

   memcpy(buf, token, MIN(tokenlen, len));

   if (tokenlen > len) {
      /*
       * have more decoded data, copy into iobuf.
       * If it is not a udp-packet, we could return the remaining to
       * caller at this time also, if there is room in callers buffer.
       * Don't bother differentiating for now.
       */

      if (iobuf->stype == SOCK_DGRAM)
         slog(LOG_DEBUG,
         "%s: decoded packet length %lu > buffer length %lu, truncated",
         function, (long unsigned)tokenlen, (long unsigned)len);
      else
         socks_addtobuffer(s, READ_BUF, 0, token + len, tokenlen - len);
   }

   len = MIN(tokenlen, len);

   if (sockscf.option.debug)
      slog(LOG_DEBUG, "%s: copied %lu to caller.  Have %lu decoded byte%s left "
                       "in buffer, %lu encoded",
      function, (unsigned long)len,
      (long unsigned)socks_bytesinbuffer(s, READ_BUF, 0),
      (long unsigned)socks_bytesinbuffer(s, READ_BUF, 0) == 1 ? "" : "s",
      (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

#if SOCKS_CLIENT
   /*
    * discard any remaining encoded data ... belongs to next token(s).
    * Since we're only peeking in the client case, the data will
    * still be there next time.
    */
   socks_getfrombuffer(s, READ_BUF, 1, tmpbuf, sizeof(tmpbuf));

   if (flags & MSG_PEEK) {
      /*
       * Need to add the data we are returning to caller now back to
       * the start of our buffer; it must be there next time too.
       */

      /*
       * Get whats left in the buffer first, so it is empty and we
       * can add the data back to the start of the buffer.
       */
      nread = socks_getfrombuffer(s, READ_BUF, 0, tmpbuf, sizeof(tmpbuf));

      socks_addtobuffer(s, READ_BUF, 0, buf, len);
      socks_addtobuffer(s, READ_BUF, 0, tmpbuf, nread);
   }
   else if (socks_bytesinbuffer(s, READ_BUF, 0) == 0) {
      slog(LOG_DEBUG, "%s: complete token returned to caller, "
                      "draining socket for last %lu bytes",
                      function,
                      (unsigned long)iobuf->info[READ_BUF].peekedbytes);

      recv(s, tmpbuf, iobuf->info[READ_BUF].peekedbytes, flags);
      socks_clearbuffer(s, READ_BUF);
   }
#else /* !SOCKS_CLIENT */

   /*
    * Make sure we decode what we can.  We should only have
    * encoded data in the buffer if it's because we have not
    * yet read enough encoded data to decode it.
    */

   tokennumber = 1;
   while (socks_bytesinbuffer(s, READ_BUF, 1) > GSSAPI_HLEN) {
       slog(LOG_DEBUG, "%s: read more than one token, now working on "
                        "token #%lu ...",
       function, (long unsigned)++tokennumber);

       nread = socks_getfrombuffer(s, READ_BUF, 1, tmpbuf, sizeof(tmpbuf));
       SASSERTX(socks_bytesinbuffer(s, READ_BUF, 1) == 0);

       if (!gssapi_headerisok(tmpbuf)) {
         /*
          * would be nice to only discard the data belonging to the
          * erroneous token, but how can we know how long it is?
          * Things will probably only go downhill from here, and we should
          * close the session instead, but we already have some correct
          * data from the caller, so at least return that.
          */

         swarnx("%s: data after token failed header check ... "
                "clearing remaining data in buffer", function);

         socks_clearbuffer(s, READ_BUF);
         break;
      }

      memcpy(&encodedlen, &tmpbuf[GSSAPI_TOKEN_LENGTH], sizeof(encodedlen));
      encodedlen = ntohs(encodedlen);

      if (nread < GSSAPI_HLEN + encodedlen) {
         SASSERTX(iobuf->stype != SOCK_DGRAM); /* already got one packet. */

         slog(LOG_DEBUG, "%s: read %ld this time, %lu left to read",
         function, (long)nread,
         (long unsigned)((GSSAPI_HLEN + encodedlen)
         - socks_bytesinbuffer(s, READ_BUF, 1)));

         /* put it back in the buffer. */
         socks_addtobuffer(s, READ_BUF, 1, tmpbuf, nread);

         break;
      }
      else if (nread > GSSAPI_HLEN + encodedlen) {
         /*
          * Need to put back data not belonging to this token, but
          * need to make sure it's at the correct place; first.
          */

         SASSERTX(socks_bytesinbuffer(s, READ_BUF, 1) == 0);

         slog(LOG_DEBUG, "%s: adding %ld extra encoded byte%s back to buffer",
         function, (long)(nread - (GSSAPI_HLEN + encodedlen)),
         (nread - (GSSAPI_HLEN + encodedlen)) == 1 ? "" : "s");

         socks_addtobuffer(s, READ_BUF, 1, tmpbuf + (GSSAPI_HLEN + encodedlen),
         nread - (GSSAPI_HLEN + encodedlen));
      }

      slog(LOG_DEBUG, "%s: read all we need to decode token #%lu",
      function, (long unsigned)tokennumber);

      tokenlen = sizeof(token);
      if (gssapi_decode(tmpbuf + GSSAPI_HLEN, encodedlen, gs, token, &tokenlen)
      != 0) {
         swarnx("%s: gssapi token of length %d failed to decode, discarded",
         function, encodedlen);

         break;
      }

      if (sockscf.option.debug)
         slog(LOG_DEBUG, "%s: adding %lu decoded byte%s from new token to "
                         "buffer.  Encoded byte%s in buffer: %lu",
         function, (unsigned long)tokenlen,
         tokenlen == 1 ? "" : "s",
         (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1) == 1 ? "" : "s",
         (long unsigned)socks_bytesinbuffer(s, READ_BUF, 1));

      socks_addtobuffer(s, READ_BUF, 0, token, tokenlen);
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
gssapi_encode_write(s, msg, len, flags, to, tolen, gs)
   int s;
   const void *msg;
   size_t len;
   int flags;
   const struct sockaddr *to;
   socklen_t tolen;
   gssapi_state_t *gs;
{
   const char *function = "gssapi_encode_write()";
   unsigned short token_length;
   iobuffer_t *iobuf;
   ssize_t towrite, written;
   size_t tokenlen;
   unsigned char token[GSSAPI_HLEN + MAXGSSAPITOKENLEN];

   slog(LOG_DEBUG, "%s: socket %d", function, s);

   if ((iobuf = socks_getbuffer(s)) == NULL) {
      int stype;
      socklen_t tlen = sizeof(stype);

      if (getsockopt(s, SOL_SOCKET, SO_TYPE, &stype, &tlen) != 0) {
         swarn("%s: getsockopt(SO_TYPE)", function);
         return -1;
      }

      if ((iobuf = socks_allocbuffer(s, stype)) == NULL) {
         swarnx("%s: could not allocate iobuffer", function);
         errno = ENOMEM;

         return -1;
      }
   }

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

      if (socks_freeinbuffer(s, WRITE_BUF) < len)
         /*
          * after the flush, we should have space in buffer again.
          */
         if (socks_flushbuffer(s, -1) == -1)
            return -1;

      SASSERTX(socks_freeinbuffer(s, WRITE_BUF) >= len);
      socks_addtobuffer(s, WRITE_BUF, 0, msg, len);

      if (((const char *)msg)[len - 2] == '\r'
      ||  ((const char *)msg)[len - 2] == '\n')
         /*
          * More correct would be to check if we have \r or \n
          * anywhere in the buffer, and flush up to that point.
          * That is a hassle however, and this is only needed for
          * broken Linux glibc systems, so don't bother.
          */
         socks_flushbuffer(s, -1);

      return len;
   }
#endif /* SOCKS_CLIENT */

   if (socks_bytesinbuffer(s, WRITE_BUF, 1) > 0) {
      /*
       * have data for write buffered already.  Write that first, then
       * append the new data after encoding it.
       */

      if (iobuf->stype == SOCK_DGRAM) /* must be an all-or-nothing write. */
         towrite = socks_bytesinbuffer(s, WRITE_BUF, 1);
      else
         towrite = MIN(sizeof(token),
                       MIN(len, socks_bytesinbuffer(s, WRITE_BUF, 1)));

      if (sizeof(token) < (size_t)towrite) {
         swarnx("%s: can't write %lu byte%s, tmpbuffer is only of size %lu",
         function,
         (long unsigned)towrite, towrite == 1 ? "" : "s",
         (long unsigned)sizeof(token));

         errno = ENOBUFS;
         return -1;
      }

      socks_getfrombuffer(s, WRITE_BUF, 1, token, towrite);
      if ((written = sendto(s, token, towrite, flags, to, tolen)) != towrite) {
         slog(LOG_DEBUG, "%s: sendt %ld/%lu: %s",
              function, (long)written, (unsigned long)towrite, strerror(errno));

         if (written == -1)
            return -1;

         /* add to buffer what we could not write. */
         socks_addtobuffer(s, WRITE_BUF, 1, token + written, towrite - written);
      }

      /*
       * Continue and add the new data to the buffer, but wait til next
       * time we are called before writing it.
       */
   }
   else
      written = 0;

   tokenlen = sizeof(token);
   if (gssapi_encode(msg, len, gs, token, &tokenlen) != 0) {
      if (errno == EMSGSIZE) {
         OM_uint32 minor_status, major_status, maxlen;
         char emsg[1024];

         major_status
         = gss_wrap_size_limit(&minor_status,
                               gs->id,
                               gs->protection == GSSAPI_CONFIDENTIALITY ?
                               GSS_REQ_CONF : GSS_REQ_INT,
                               GSS_C_QOP_DEFAULT,
                               sizeof(token),
                               &maxlen);

         if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg))) {
            swarnx("%s: gss_wrap_size_limit(): %lu is too big a message and "
                   "failed to determine what is max.  Should not happen: %s",
                   function, (long unsigned)len, emsg);
            return -1;
         }

         slog(LOG_DEBUG, "%s: data of length %lu too big for gssapi_encode() "
                         "... max determined to be %lu, trying again.",
                         function, (long unsigned)len, (long unsigned)maxlen);

         /* callers responsibility to cope with short write. */
         len = maxlen;

         if (gssapi_encode(msg, len, gs, token, &tokenlen) != 0) {
            swarnx("%s: hmm, gssapi_encode() failed with shorter datalen too",
                   function);
            return -1;
         }
      }
      else
         return -1;
   }

   /*
    * Can't risk writing a partial token with no room to hold the
    * remainder.
    */
   if (GSSAPI_HLEN + tokenlen > socks_freeinbuffer(s, WRITE_BUF)) {
      slog(LOG_DEBUG, "%s: not enough room in buffer to hold %lu more byte%s "
                      "(%lu + %lu encoded)",
      function, (long unsigned)len, len == 1 ? "" : "s",
      (long unsigned)GSSAPI_HLEN, (long unsigned)tokenlen);

      errno = EAGAIN;
      return -1;
   }

   iobuf->buf[WRITE_BUF][iobuf->info[WRITE_BUF].enclen++]
   = SOCKS_GSSAPI_VERSION;

   iobuf->buf[WRITE_BUF][iobuf->info[WRITE_BUF].enclen++]
   = SOCKS_GSSAPI_PACKET;

   token_length = htons(tokenlen);
   memcpy(&iobuf->buf[WRITE_BUF][iobuf->info[WRITE_BUF].enclen], &token_length,
   sizeof(token_length));
   iobuf->info[WRITE_BUF].enclen += sizeof(token_length);

   memcpy(&iobuf->buf[WRITE_BUF][iobuf->info[WRITE_BUF].enclen], token,
   tokenlen);
   iobuf->info[WRITE_BUF].enclen += tokenlen;

   if (written)
      return len;  /* don't try to write anything more for now. */

   towrite = MIN(sizeof(token), MIN(tokenlen + GSSAPI_HLEN,
                                    socks_bytesinbuffer(s, WRITE_BUF, 1)));

   towrite = socks_getfrombuffer(s, WRITE_BUF, 1, token, towrite);
   if ((written = sendto(s, token, towrite, flags, to, tolen)) == -1) {
      slog(LOG_DEBUG, "%s: wrote %lu/%ld (%s)",
           function, (long unsigned)towrite, (long)written, strerror(errno));

      return -1;
   }

   socks_addtobuffer(s, WRITE_BUF, 1, token + written, towrite - written);

   if (sockscf.option.debug)
      slog(LOG_DEBUG, "%s: wrote %ld out of %lu, saved remaining %lu byte%s "
                      "in buffer that now has %lu bytes free",
      function, (long)written, (long unsigned)towrite,
      (long unsigned)socks_bytesinbuffer(s, WRITE_BUF, 1),
      (long unsigned)socks_bytesinbuffer(s, WRITE_BUF, 1) == 1 ? "" : "s",
      (long unsigned)socks_freeinbuffer(s, WRITE_BUF));

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
      swarnx("%s: gss_export_sec_context(): %s", function, emsg);
      return -1;
   }

   SASSERTX(token.length <= state->length);
   memcpy(state->value, token.value, token.length);
   state->length = token.length;

   SOCKS_SIGBLOCK_IF_CLIENT(SIGIO, &oldset);
   gss_release_buffer(&minor_status, &token);
   SOCKS_SIGUNBLOCK_IF_CLIENT(&oldset);

   slog(LOG_DEBUG, "%s: created gssapistate of length %lu (start: 0x%x, 0x%x)",
                   function, (unsigned long)state->length,
                   ((char *)state->value)[0], ((char *)state->value)[1]);

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

   slog(LOG_DEBUG, "%s: importing gssapistate of length %lu "
                   "(start: 0x%x, 0x%x)",
                   function, (unsigned long)state->length,
                   ((char *)state->value)[0], ((char *)state->value)[1]);

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
gssapi_headerisok(headerbuf)
   const char *headerbuf;
{
   const char *function = "gssapi_headerisok()";

   slog(LOG_DEBUG, "%s", function);

   if (headerbuf[GSSAPI_VERSION] != SOCKS_GSSAPI_VERSION
   ||  headerbuf[GSSAPI_STATUS]  != SOCKS_GSSAPI_PACKET) {
      swarnx("%s: invalid socks gssapi header (0x%x, 0x%x, not 0x%x, 0x%x)",
      function,
      (unsigned char)headerbuf[GSSAPI_VERSION],
      (unsigned char)headerbuf[GSSAPI_STATUS],
      SOCKS_GSSAPI_VERSION, SOCKS_GSSAPI_PACKET);

      return 0;
   }

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

#endif /* HAVE_GSSAPI */
