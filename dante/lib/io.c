/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2008,
 *               2009, 2010
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
"$Id: io.c,v 1.143.4.4 2010/09/21 11:24:43 karls Exp $";

#if !SOCKS_CLIENT
static void checkforsignal(void);
/*
 * Check if we have received any signal and calls the handler if so.
 */
#endif /* !SOCKS_CLIENT */

ssize_t
socks_recvfromn(s, buf, len, minread, flags, from, fromlen, auth)
   int s;
   void *buf;
   size_t len;
   size_t minread;
   int flags;
   struct sockaddr *from;
   socklen_t *fromlen;
   struct authmethod_t *auth;
{
   const char *function = "socks_recvfromn()";
   ssize_t p;
   size_t left;

   left = len;
   do {
      if ((p = socks_recvfrom(s, &((char *)buf)[len - left], left, flags,
      from, fromlen, auth)) == -1) {
#if !SOCKS_CLIENT
         if (errno == EINTR)
            continue;
#else /* SOCKS_CLIENT */
         if (sockscf.connectchild != 0 && errno == EINTR)
           /*
            * could be a SICHLD from our child, so not safe to fail on it.
            * XXX this is not good.  If the EINTR was due to something
            * else, it's is wrong to retry and might break things.
            */
            continue;
#endif /* SOCKS_CLIENT */

         if (ERRNOISINPROGRESS(errno) && len - left < minread) {
            static fd_set *rset;

            slog(LOG_DEBUG, "%s: minread ... min is %lu, got %lu, waiting ...",
            function, (unsigned long)minread, (unsigned long)(len - left));

            if (rset == NULL)
               rset = allocate_maxsize_fdset();

            errno = 0;

            FD_ZERO(rset);
            FD_SET(s, rset);
            if (select(s + 1, rset, NULL, NULL, NULL) == -1)
               swarn("%s: select()", function);

            continue;
         }

         break;
      }
      else if (p == 0)
         break;

      left -= (size_t)p;
   } while ((len - left) < minread);

   if (left == len)
      return p;   /* nothing read. */
   return len - left;
}

ssize_t
socks_sendton(s, buf, len, minwrite, flags, to, tolen, auth)
   int s;
   const void *buf;
   size_t len;
   const size_t minwrite;
   int flags;
   const struct sockaddr *to;
   socklen_t tolen;
   struct authmethod_t *auth;
{
   const char *function = "socks_sendton()";
   ssize_t p;
   size_t left = len;

   do {
      if ((p = socks_sendto(s, &((const char *)buf)[len - left], left, flags,
      to, tolen, auth)) == -1) {
#if !SOCKS_CLIENT
         if (errno == EINTR)
            continue;
#endif /* !SOCKS_CLIENT */

         if ((errno == EAGAIN || errno == EWOULDBLOCK) && minwrite > 0) {
            fd_set wset;

            errno = 0;

            FD_ZERO(&wset);
            FD_SET(s, &wset);
            if (selectn(s + 1, NULL, NULL, &wset, NULL, NULL, NULL) == -1) {
               swarn("%s: select()", function);
               return -1;
            }

            continue;
         }

         break;
      }

      left -= (size_t)p;
   } while ((len - left) < minwrite);

   return len - left;
}

ssize_t
socks_recvfrom(s, buf, len, flags, from, fromlen, auth)
   int s;
   void *buf;
   size_t len;
   int flags;
   struct sockaddr *from;
   socklen_t *fromlen;
   struct authmethod_t *auth;
{
   const char *function = "socks_recvfrom()";
   ssize_t r;
#if !SOCKS_CLIENT
   ssize_t readfrombuf, tocaller, tobuf, toread;
   char tmpbuf[MAX(sizeof(struct sockd_io_t), SOCKD_BUFSIZE)];
#endif /* !SOCKS_CLIENT */

   slog(LOG_DEBUG, "%s: socket %d, len %lu", function, s, (unsigned long)len);

   if (auth != NULL)
      switch (auth->method) {
         case AUTHMETHOD_NOTSET:
         case AUTHMETHOD_NONE:
         case AUTHMETHOD_GSSAPI:
         case AUTHMETHOD_UNAME:
         case AUTHMETHOD_NOACCEPT:
         case AUTHMETHOD_RFC931:
         case AUTHMETHOD_PAM:
            break;

         default:
            SERRX(auth->method);
      }

#if HAVE_GSSAPI
   if (auth != NULL
   && auth->method == AUTHMETHOD_GSSAPI && auth->mdata.gssapi.state.encryption)
      return gssapi_decode_read(s, buf, len, flags, from, fromlen,
                                &auth->mdata.gssapi.state);
#endif /* HAVE_GSSAPI */

#if SOCKS_CLIENT

   /*
    * no buffering is provided by us for the client, except if using gssapi,
    * and that is handled in the above function.
    */
   if (from == NULL && flags == 0)
      /* may not be a socket and read(2) will work just as well then. */
      r = read(s, buf, len);
   else
      r = recvfrom(s, buf, len, flags, from, fromlen);

   slog(LOG_DEBUG, "%s: read %ld byte%s, errno = %d",
   function, (long)r, r == 1 ? "" : "s", errno);

   if (r >= 0)
      /*
       * Some systems return bytes read, yet still set errno.  In particular,
       * OpenBSD 4.5's thread implementation does this sometimes.
       * Clearly wrong, but what can we do. :-/
       */
      errno = 0;

   return r;
#else /* SOCKS_SERVER */

   /*
    * Return data from the buffer first, if non-empty, then read data from
    * socket if needed.
    */

   if ((readfrombuf = socks_getfrombuffer(s, READ_BUF, 0, buf, len)) > 0) {
      if (sockscf.option.debug) {
         slog(LOG_DEBUG, "%s: read %lu byte%s from buf, %lu bytes left in buf",
         function,
         (unsigned long)readfrombuf, readfrombuf == 1 ? "" : "s",
         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0));

         if (flags & MSG_PEEK) {
            slog(LOG_DEBUG, "%s: put what was read back; peeking", function);
            socks_addtobuffer(s, READ_BUF, 0, buf, readfrombuf);
         }
      }
   }

   if ((size_t)readfrombuf >= len)
      return readfrombuf;

   if (socks_getbuffer(s) == NULL)
      r = len;
   else
      r = MIN(socks_freeinbuffer(s, READ_BUF), sizeof(tmpbuf));

   if (r <= 0)
      return readfrombuf;

   /*
    * Now read as much as we can into the tmpbuf, and later check what
    * can be copied back to caller this time, and what needs to be stored
    * in iobuf for later.
    */

   toread = r;
   if (from == NULL && flags == 0)
      /* may not be a socket and read(2) will work just as well then. */
      r = read(s, tmpbuf, toread);
   else
      r = recvfrom(s, tmpbuf, toread, flags, from, fromlen);

   slog(LOG_DEBUG, "%s: read %ld byte%s from socket, max read was %ld: %s",
   function, (long)r, r == 1 ? "" : "s", (long)toread, strerror(errno));

   if (r <= 0) {
      if (readfrombuf <= 0)
         return r;

      errno = 0; /* even if read from socket failed, read from buf did not. */
      return readfrombuf;
   }

   tocaller = MIN((size_t)r, len - readfrombuf);
   tobuf    = flags & MSG_PEEK ? 0 : r - tocaller;

   memcpy((char *)buf + readfrombuf, tmpbuf, tocaller);

   if (tobuf > 0)
      socks_addtobuffer(s, READ_BUF, 0, tmpbuf + tocaller, tobuf);

   return readfrombuf + tocaller;
#endif /* SOCKS_SERVER */
}

ssize_t
socks_sendto(s, msg, len, flags, to, tolen, auth)
   int s;
   const void *msg;
   size_t len;
   int flags;
   const struct sockaddr *to;
   socklen_t tolen;
   struct authmethod_t *auth;
{
   const char *function = "socks_sendto()";
#if !SOCKS_CLIENT
   ssize_t towrite, written, p;
   char buf[MAX(sizeof(struct sockd_io_t), SOCKD_BUFSIZE)];
#endif /* !SOCKS_CLIENT */

   slog(LOG_DEBUG, "%s: socket %d, len %lu", function, s, (long unsigned)len);

   if (auth != NULL)
      switch (auth->method) {
         case AUTHMETHOD_NOTSET:
         case AUTHMETHOD_NONE:
         case AUTHMETHOD_GSSAPI:
         case AUTHMETHOD_UNAME:
         case AUTHMETHOD_NOACCEPT:
         case AUTHMETHOD_RFC931:
         case AUTHMETHOD_PAM:
            break;

         default:
            SERRX(auth->method);
      }

#if HAVE_GSSAPI
   if (auth != NULL
   &&  auth->method == AUTHMETHOD_GSSAPI && auth->mdata.gssapi.state.encryption)
      return gssapi_encode_write(s, msg, len, flags, to, tolen,
                                 &auth->mdata.gssapi.state);
#endif

#if SOCKS_CLIENT
   /*
    * no buffering is provided by us for the client, except if using gssapi,
    * and that is handled in the above function.
    */
   if (to == NULL && flags == 0)
      /* may not be a socket; write(2) will work just as well then. */
      return write(s, msg, len);
   return sendto(s, msg, len, flags, to, tolen);

#else /* !SOCKS_CLIENT */

   if ((towrite = socks_getfrombuffer(s, WRITE_BUF, 0, buf, len)) > 0) {
      /*
       * already have data for write buffered.  Write that first, then
       * append the new data, then possibly write the new data, but never
       * write more than "len", even if we could due to data already
       * buffered.
       *
       * Also note that for the data buffered, we have already returned
       * the byte count as written, so don't return it again, only return
       * the count for new bytes added to the buffer.
       */

      slog(LOG_DEBUG, "%s: got %lu byte%s from buffer, %lu bytes in buffer\n",
      function,
      (unsigned long)towrite, towrite == 1 ? "" : "s",
      (unsigned long)socks_bytesinbuffer(s, WRITE_BUF, 0));

      if ((written = send(s, buf, towrite, flags)) < (ssize_t)towrite) {
         /*
          *  need to add at least some back in the buffer.
          */
         const ssize_t addback = written > 0 ? towrite - written : towrite;

         if ((p = socks_addtobuffer(s, WRITE_BUF, 0, buf + (towrite - addback),
         addback)) != addback)
            SERRX(p);
      }

      /* can we write more on this call? */
      if (written == -1) { /* no. */
         if (!ERRNOISTMP(errno))
            return -1;
         /* else; non-fatal error.  Try to buffer the rest. */
         towrite = 0;
      }
      else {
         /*
          * if it's a udp-socket, we can not write "more", we must
          * write the whole packet or nothing.
          */
         socklen_t tlen;
         int type;

         tlen = sizeof(type);
         if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &tlen) != 0) {
            swarn("%s: getsockopt(SO_TYPE)", function);
            return -1;
         }

         if (type == SOCK_DGRAM)
            towrite = 0;
         else
            towrite = len - written;
      }
   }
   else /* nothing buffered. */
      towrite = len;

   if (towrite > 0) { /* try to write (some of?) the data passed us now. */
      if (to == NULL && flags == 0)
         /* may not be a socket; send(2) will work just as well then. */
         written = write(s, msg, towrite);
      else
         written = sendto(s, msg, towrite, flags, to, tolen);

      if (written == -1) {
         if (!ERRNOISTMP(errno))
            return written;

         written = 0;
      }
   }
   else
      written = 0;

   towrite -= written;
   if (towrite > 0) {
      slog(LOG_DEBUG, "%s: %lu byte%s unwritten",
      function, (unsigned long)towrite, towrite == 1 ? "" : "s");

      p = socks_addtobuffer(s, WRITE_BUF, 0, (const char *)msg + written,
      towrite);

      written += p;
   }

   SASSERTX(written == (ssize_t)len);

   return len;
#endif /* !SOCKS_CLIENT */
}

ssize_t
recvmsgn(s, msg, flags)
   int s;
   struct msghdr *msg;
   int flags;
{
   const char *function = "recvmsgn()";
   ssize_t p;
   size_t len, left;

   for (p = len = 0; p < (ssize_t)msg->msg_iovlen; ++p)
      len += msg->msg_iov[p].iov_len;

   while ((p = recvmsg(s, msg, flags)) == -1 && errno == EINTR)
#if SOCKS_CLIENT
      return -1;
#else /* !SOCKS_CLIENT */
      ;
#endif /* !SOCKS_CLIENT */

#if HAVE_SOLARIS_BUGS
   if (p == -1 && (errno == EMFILE || errno == ENFILE)) {
      /*
       * Even if Solaris (2.5.1) fails on recvmsg() it may still have
       * gotten a descriptor or more as ancillary data which it neglects
       * to get rid of, so we have to check for it ourselves and close it,
       * else it just gets lost in the void.
       */
      size_t leaked;
      int d;

      for (leaked = 0;
      CMSG_SPACE(leaked * sizeof(d)) < (size_t)CMSG_TOTLEN(*msg);
      ++leaked) {
         CMSG_GETOBJECT(d, CMSG_CONTROLDATA(*msg), leaked * sizeof(d));
         close(d);
      }
   }
#endif /* HAVE_SOLARIS_BUGS */

   if (p <= 0)
      return p;
   left = len - (size_t)p;

   if (left > 0) {
      size_t i, count, done;

      /*
       * Can't call recvmsg() again since we could be getting ancillary data,
       * read the elements one by one.
       */

      SASSERTX(p >= 0);

      done = (size_t)p;
      i = count = p = 0;
      while (i < (size_t)msg->msg_iovlen && left > 0) {
         const struct iovec *io = &msg->msg_iov[i];

         count += io->iov_len;
         if (count > done) { /* didn't read all of this iovec. */
            if ((p = socks_recvfromn(s,
            &((char *)(io->iov_base))[io->iov_len - (count - done)],
            count - done, count - done, 0, NULL, NULL, NULL))
            != ((ssize_t)(count - done))) {
               /*
                * Failed to read all data, close any descriptors we
                * may have gotten then.
                */
               size_t leaked;
               int d;

               swarn("%s: %ld byte%s left",
               function, (long)left, left == 1 ? "" : "s");

               for (leaked = 0;
               CMSG_SPACE(leaked * sizeof(d)) < (size_t)CMSG_TOTLEN(*msg);
               ++leaked) {
                  CMSG_GETOBJECT(d, CMSG_CONTROLDATA(*msg), leaked * sizeof(d));
                  close(d);
               }

               break;
            }

            left -= p;
            done += p;
         }

         ++i;
      }
   }

   if (left == len)
      return p; /* nothing read. */
   return len - left;
}

ssize_t
sendmsgn(s, msg, flags)
   int s;
   const struct msghdr *msg;
   int flags;
{
   const char *function = "sendmsgn()";
   ssize_t p;
   size_t len, left;

   for (p = len = 0; p < (ssize_t)msg->msg_iovlen; ++p)
      len += msg->msg_iov[p].iov_len;

   while ((p = sendmsg(s, msg, flags)) == -1 && errno == EINTR)
#if SOCKS_CLIENT
      return -1;
#else /* !SOCKS_CLIENT */
      ;
#endif /* !SOCKS_CLIENT */

   if (p <= 0)
      return p;
   left = len - p;

   if (left > 0) {
      size_t i, count, done;

      /*
       * Can't call sendmsg() again since we could be sending ancillary data,
       * send the elements one by one.
       */

      SASSERTX(p >= 0);

      done = p;
      i = count = p = 0;
      while (i < (size_t)msg->msg_iovlen && left > 0) {
         const struct iovec *io = &msg->msg_iov[i];

         count += io->iov_len;
         if (count > done) { /* didn't send all of this iovec. */
            while ((p = socks_sendton(s,
            &((char *)(io->iov_base))[io->iov_len - (count - done)],
            count - done, count - done, 0, NULL, 0, NULL))
            != ((ssize_t)(count - done))) {
               /*
                * yes, we only re-try once.  What errors should we
                * retry again on?
                */
               swarn("%s: failed on re-try", function);
               break;
            }

            left -= p;
            done += p;
         }

         ++i;
      }
   }

   if (left == len)
      return p; /* nothing read. */
   return len - left;
}

int
closen(d)
   int d;
{
   int rc;

#undef close  /* we redefine close() to closen() for convenience. */
   while ((rc = close(d)) == -1 && errno == EINTR)
      ;

   return rc;
}

int
selectn(nfds, rset, bufrset, wset, bufwset, xset, timeout)
   int nfds;
   fd_set *rset, *bufrset;
   fd_set *wset, *bufwset;
   fd_set *xset;
   struct timeval *timeout;
{
   const char *function = "selectn()";
   static fd_set *_rset, *_wset, *_xset;
   struct timeval zerotimeout = { 0, 0 };
   /* const */ struct timeval _timeout = timeout == NULL ? _timeout : *timeout;
   int i, rc, bufset_nfds;
#if !SOCKS_CLIENT
   int goteintr = 0;
#endif /* !SOCKS_CLIENT */

   if (_rset == NULL) {
      _rset = allocate_maxsize_fdset();
      _wset = allocate_maxsize_fdset();
      _xset = allocate_maxsize_fdset();
   }

   if (rset != NULL)
      FD_COPY(_rset, rset);

   if (wset != NULL)
      FD_COPY(_wset, wset);

   if (xset != NULL)
      FD_COPY(_xset, xset);

   bufset_nfds = 0;
   if (bufrset != NULL || bufwset != NULL) {
      /*
       * We need to go through each descriptor and see if it
       * has data buffered ready for reading.  If so, that descriptor
       * needs to also be set on return from the below select(2),
       * and the timeout must be zero (already have at least one
       * descriptor readable).
       */

      if (bufrset != NULL)
         FD_ZERO(bufrset);

      if (bufwset != NULL)
         FD_ZERO(bufwset);

      for (i = 0; i < nfds; ++i) {
         /*
          * should only check for decoded data on read.  If it's not decoded,
          * it means we were unable to read the whole token last time, which
          * means there is no data we can fetch from the buffer until the
          * rest of the token has been read from the socket.
          *
          * If data is buffered for write, that also means the buffer
          * is readable, since we can/must read that data and write
          * it to the socket.
          */
         if (bufrset != NULL
         && ( socks_bytesinbuffer(i, READ_BUF, 0)  > 0
           || socks_bytesinbuffer(i, WRITE_BUF, 0) > 0
           || socks_bytesinbuffer(i, WRITE_BUF, 1) > 0)) {
            if (sockscf.option.debug)
               slog(LOG_DEBUG, "%s: buffer for fd %d is readable: "
               "has %lu + %lu bytes buffered for read, %lu + %lu for write",
               function, i,
               (long unsigned)socks_bytesinbuffer(i, READ_BUF, 0),
               (long unsigned)socks_bytesinbuffer(i, READ_BUF, 1),
               (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 0),
               (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 1));

            FD_SET(i, bufrset);
            bufset_nfds = MAX(bufset_nfds, i + 1);
            timeout     = &zerotimeout;
         }

         if (bufwset != NULL && socks_freeinbuffer(i, WRITE_BUF) > 0) {
            if (sockscf.option.debug)
               slog(LOG_DEBUG, "%s: buffer for fd %d is writable: "
               "has %lu + %lu bytes buffered for read, %lu + %lu for write",
               function, i,
               (long unsigned)socks_bytesinbuffer(i, READ_BUF, 0),
               (long unsigned)socks_bytesinbuffer(i, READ_BUF, 1),
               (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 0),
               (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 1));

            FD_SET(i, bufwset);
            bufset_nfds = MAX(bufset_nfds, i + 1);
            timeout     = &zerotimeout;
         }
      }
   }

#if !SOCKS_CLIENT
   checkforsignal();

   /*
    * There's still a tiny gap here where tings could go wrong
    * if we receive a signal between now and the select(2) call.
    * In that case, the select() will not return EINTR, and we
    * will not know a SIGTERM has been received and we should exit.
    *
    * This should not create problems for children, however, as they
    * should be select()'ing for the mother pipe to know when mother
    * has exited.
    * Likewise, mother will know children has exited because in addition
    * to the sigchld handler, she also has the same pipes to check.
    */
#endif /* !SOCKS_CLIENT */

   while ((rc = select(nfds, rset, wset, xset, timeout)) == -1
   && errno == EINTR) {
#if !SOCKS_CLIENT
      goteintr = 1;
      checkforsignal();
      errno    = 0;
#endif /* !SOCKS_CLIENT */

      if (rset != NULL)
         FD_COPY(rset, _rset);

      if (wset != NULL)
         FD_COPY(wset, _wset);

      if (xset != NULL)
         FD_COPY(xset, _xset);

      if (timeout != NULL)
         *timeout = _timeout;
   }

#if !SOCKS_CLIENT
   checkforsignal();
#endif /* !SOCKS_CLIENT */

   if (rc == -1) {
#if !SOCKS_CLIENT
      if (goteintr && errno == EBADF)
         /*
          * Probably means checkforsignal() was called and the sighandler
          * closed one of the descriptors in our set.  EINTR is the more
          * appropriate error to return in this case.
          */
         errno = EINTR;
#endif /* !SOCKS_CLIENT */

      return rc;
   }

   return MAX(rc, bufset_nfds);
}

#if !SOCKS_CLIENT

static void
checkforsignal()
{
   const char *function = "checkforsignal()";
   struct sigaction oact;
   int i;

   if (sockscf.state.signalc == 0)
      return;

   for (i = 0; i < sockscf.state.signalc; ++i)
      slog(LOG_DEBUG, "%s: signal #%d on the stack is signal %d",
      function, i + 1, (int)sockscf.state.signalv[i]);


   do {
      const int signal = sockd_popsignal();

      slog(LOG_DEBUG, "%s: %d signals on the stack, popped signal %d",
      function, sockscf.state.signalc, signal);

      if (sigaction(signal, NULL, &oact) != 0)
         SERR(0);

      if (oact.sa_handler != SIG_IGN && oact.sa_handler != SIG_DFL)
         oact.sa_handler(-signal);
      else
         /*
          * can happen when a child temporarily changes the
          * signal disposition while starting up.
          */
         slog(LOG_DEBUG, "%s: no handler for signal %d at the moment",
         function, signal);
   } while (sockscf.state.signalc);
}
#endif /* !SOCKS_CLIENT */
