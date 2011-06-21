/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2008,
 *               2009, 2010, 2011
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
"$Id: io.c,v 1.203 2011/06/16 07:22:10 michaels Exp $";

static void
print_selectfds(const char *preamble, const int docheck, const int nfds,
                fd_set *rset, fd_set *bufrset, fd_set *buffwset,
                fd_set *wset, fd_set *xset,
                struct timeval *timeout);

ssize_t
socks_recvfromn(s, buf, len, minread, flags, from, fromlen, auth)
   const int s;
   void *buf;
   const size_t len;
   const size_t minread;
   const int flags;
   struct sockaddr *from;
   socklen_t *fromlen;
   struct authmethod_t *auth;
{
   const char *function = "socks_recvfromn()";
   ssize_t p;
   size_t left;

   left = len;
   do {
#if SOCKS_CLIENT
      /*
       * If this changes between now and the return of socks_recvfrom(), 
       * the change has to be done in the signal handler, and we then
       * assume it's due to us receiving a signal from our connectchild
       * process.
       */
      sockscf.state.signalforus = 0;
#endif /* SOCKS_CLIENT */

      if ((p = socks_recvfrom(s, &((char *)buf)[len - left], left, flags,
      from, fromlen, auth)) == -1) {
#if !SOCKS_CLIENT
         if (errno == EINTR)
            continue;
#else /* SOCKS_CLIENT */
         if (sockscf.state.signalforus && errno == EINTR) {
           /*
            * Can not know for sure, but assume we were interrupted
            * due to a signal from our non-blocking connect child.
            * If so, we should retry the read call.
            */
            slog(LOG_DEBUG,
                 "%s: read was interrupted, but looks like it could be due to"
                 "our own signal (signal #%d), so assume we should retry",
                 function, (int)sockscf.state.signalforus);
            continue;
         }
#endif /* SOCKS_CLIENT */

         if (ERRNOISTMP(errno) && len - left < minread) {
#if SOCKS_CLIENT
            fd_set *rset = NULL;
#else /* SERVER */
            static fd_set *rset;
#endif
            if (rset == NULL)
               rset = allocate_maxsize_fdset();

            errno = 0;
            FD_ZERO(rset);
            FD_SET(s, rset);
            if (select(s + 1, rset, NULL, NULL, NULL) == -1)
               if (errno != EINTR)
                  SERR(errno);

            continue;
         }
         else
            break;
      }
      else if (p == 0)
         break;

      left -= (size_t)p;
   } while (len - left < minread);

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
               if (errno != EINTR)
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
   const socklen_t passed_fromlen = (fromlen == NULL ? 0 : *fromlen);
   ssize_t readfrombuf, tocaller, tobuf, toread;
   char tmpbuf[MAX(sizeof(struct sockd_io_t), SOCKD_BUFSIZE)];
#endif /* !SOCKS_CLIENT */

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: socket %d, len %lu",
      function, s, (unsigned long)len);

   if (auth != NULL)
      switch (auth->method) {
         case AUTHMETHOD_NOTSET:
         case AUTHMETHOD_NONE:
         case AUTHMETHOD_GSSAPI:
         case AUTHMETHOD_UNAME:
         case AUTHMETHOD_NOACCEPT:
         case AUTHMETHOD_RFC931:
         case AUTHMETHOD_PAM:
         case AUTHMETHOD_BSDAUTH:
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

   if (sockscf.option.debug > 1)
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
      if (sockscf.option.debug > 1) {
         slog(LOG_DEBUG, "%s: read %lu byte%s from buf, %lu bytes left in buf",
                         function,
                         (unsigned long)readfrombuf,
                         readfrombuf == 1 ? "" : "s",
                         (unsigned long)socks_bytesinbuffer(s, READ_BUF, 0));
      }

      if (flags & MSG_PEEK) {
         if (sockscf.option.debug > 1)
            slog(LOG_DEBUG, "%s: put what was read back; peeking", function);

         socks_addtobuffer(s, READ_BUF, 0, buf, readfrombuf);
      }
   }

   if ((size_t)readfrombuf >= len)
      return readfrombuf; 

   /*
    * If we have a buffer allocated, assume it's safe to read
    * as much as it can hold, as it make things much more efficient
    * to do subsequent reads from the buffer (i.e., like fread()).
    */
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

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG,
           "%s: read %ld byte%s from socket %d, "
           "max read is %ld, errno = %d (%s)",
           function,
           (long)r,
           r == 1 ? "" : "s",
           s,
           (long)toread,
           errno,
           errnostr(errno));

   if (r != -1 && passed_fromlen >= sizeof(struct sockaddr_in)) {
      /* 
       * Solaris, at least 2.5.1, sometimes fails to return the srcaddress 
       * in recvfrom(2). 
       * More recently it has also been seen at least once on OS X, Kernel 
       * Version 10.5.0, at a point where recvfrom(2) returned 0.
       */
       static int failures, failed_socket;

      if (*fromlen < sizeof(struct sockaddr_in)) {              
         swarnx("%s: kernel/system error: did not get the src address in "
                "recvfrom(2) on socket %d.  Got a fromlen of %ld",       
                function, s, (long)*fromlen);                   
                                                                       
         if (failures++ >= 4) {             
            /*                            
             * don't know if it's the same socket that has failed each
             * time, but this is a kernel error and should never happen 
             * anyway, so go along like this for now.
             */                             
            swarnx("%s: giving up after %d recvfrom(2) failures", 
            function, failures); 

            failed_socket = -1; 
            failures      = 0;
            errno         = 0;

            return -1;
         }
         else {
            failed_socket = s; 
            errno         = EAGAIN;

            return -1;
         } 
      }
      else {
         if (failed_socket == s) 
            failures = 0; /* reset on first success. */ 
      } 
   }

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

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: socket %d, len %lu",
      function, s, (long unsigned)len);

   if (auth != NULL)
      switch (auth->method) {
         case AUTHMETHOD_NOTSET:
         case AUTHMETHOD_NONE:
         case AUTHMETHOD_GSSAPI:
         case AUTHMETHOD_UNAME:
         case AUTHMETHOD_NOACCEPT:
         case AUTHMETHOD_RFC931:
         case AUTHMETHOD_PAM:
         case AUTHMETHOD_BSDAUTH:
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

      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: got %lu byte%s from buffer, %lu bytes in buffer",
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

   if (towrite >= 0) { /* >= 0 because udp packets can be zero. */
      /*
       * try to write some of the data passed us now. 
       */

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
      if (sockscf.option.debug > 1)
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
   ssize_t received;

   if ((received = recvmsg(s, msg, flags)) == -1) {
      if (!ERRNOISTMP(errno))
         swarn("%s: recvmsg() socket %d failed, received %ld bytes",
         function, s, (long)received);

#if HAVE_SOLARIS_BUGS
      if (errno == EMFILE || errno == ENFILE) {
         /*
          * Even if Solaris (2.5.1) fails on recvmsg() it may still have
          * gotten a descriptor or more as ancillary data which it 
          * neglects to get rid of, so we have to check for it ourselves
          * and close it, else it just gets lost in the void.
          */
         size_t leaked;
         int d;

         for (leaked = 0;
              CMSG_SPACE(leaked * sizeof(d)) < (size_t)CMSG_TOTLEN(*msg);
               ++leaked)
         {
              CMSG_GETOBJECT(d, CMSG_CONTROLDATA(*msg), leaked * sizeof(d));
              close(d);
         }
      }
#endif /* HAVE_SOLARIS_BUGS */

      return received;
   }

   return received;

#if 0
   /* 
    * below code should not be used any longer since we only do recvmsg(2)
    * on datagramsockets now.
    */


   if (received <= 0)
      return received;
   left = len - (size_t)received;

   if (left > 0) {
      size_t i, count, done;

      /*
       * Can't call recvmsg() again since we could be getting ancillary data,
       * read the elements one by one.
       */

      SASSERTX(received >= 0);

      done = (size_t)received;
      i = count = received = 0;
      while (i < (size_t)msg->msg_iovlen && left > 0) {
         const struct iovec *io = &msg->msg_iov[i];

         count += io->iov_len;
         if (count > done) { /* didn't read all of this iovec. */
            if ((received = socks_recvfromn(s,
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

            left -= received;
            done += received;
         }

         ++i;
      }
   }

   if (left == len)
      return received; /* nothing read. */
   return len - left;
#endif

}

ssize_t
sendmsgn(s, msg, flags, timeoutseconds)
   int s;
   const struct msghdr *msg;
   int flags;
   const int timeoutseconds;
{
   const char *function = "sendmsgn()";
   static int failedlasttime;
   ssize_t sent;

   if ((sent = sendmsg(s, msg, flags)) == -1) {
      const int doblock = (   ERRNOISTMP(errno)
                           && !failedlasttime
                           && (timeoutseconds != 0));
      ssize_t p, len;

      for (p = len = 0; p < (ssize_t)msg->msg_iovlen; ++p)
         len += msg->msg_iov[p].iov_len;

      swarnx("%s: sendmsg() of %ld bytes on socket %d failed:  %s.  %s",
             function,
             (long)len,
             s, 
             errnostr(errno),
             doblock ?  "Will try blocking on the fd to become writable" : "");

      if (doblock) {
         static fd_set *wset;
         struct timeval timeout;

         failedlasttime = 1;

         if (timeoutseconds != -1) {
            timeout.tv_sec  = timeoutseconds;
            timeout.tv_usec = 0;
         }

         if (wset == NULL)
            wset = allocate_maxsize_fdset();

         FD_ZERO(wset);
         FD_SET(s, wset);
         if (selectn(s + 1,
                     NULL,
                     NULL,
                     NULL,
                     wset,
                     NULL,
                     timeoutseconds == -1 ? NULL : &timeout) == 1) {
            if (timeoutseconds == -1)
               slog(LOG_DEBUG, "%s: blocked on select", function);
            else
               slog(LOG_DEBUG, "%s: blocked on select, time is %ld.%06ld",
                    function, (long)timeout.tv_sec, (long)timeout.tv_usec);

            errno = 0;
            return sendmsgn(s, msg, 0, timeoutseconds);
         }
      }
   }

   failedlasttime = 0;  /* always reset if not select(2)-ing.  */
   return sent;

   /* 
    * below code should not be used any longer since we only do sendmsg(2)
    * on datagramsockets now.
    */

#if 0
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
            while ((p = socks_sendton(
                     s,
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
#endif

}

int
closen(d)
   int d;
{
   int rc;

#undef close  /* we redefine close() to closen() for convenience. */
   while ((rc = close(d)) == -1 && errno == EINTR)
      ; /* LINTED empty */

   return rc;
}

int
selectn(nfds, rset, bufrset, buffwset, wset, xset, timeout)
   int nfds;
   fd_set *rset, *bufrset, *buffwset;
   fd_set *wset;
   fd_set *xset;
   struct timeval *timeout;
{
   const char *function = "selectn()";
   struct timeval zerotimeout = { 0, 0 };
   int i, rc, bufset_nfds;
#if !SOCKS_CLIENT
   int handledsignal;
#endif /* !SOCKS_CLIENT */
   static fd_set *new_bufrset, *new_buffwset;

#if !SOCKS_CLIENT
   if ((handledsignal = sockd_handledsignals()) != 0) {
      /*
       * When mother gets a signal (e.g., SIGHUP or SIGCHLD), it's possible 
       * to add or remove descriptors.  It is thus not safe to continue with
       * the descriptorset we get passed (could get e.g, EBADF); we must 
       * return and let caller regenerate the fd_set's.
       */ 
      errno = EINTR;
      return -1;
   }

   /*
    * There's a gap here where tings could have gone wrong
    * if we receive a signal between now and the select(2) call.
    * In that case, the select(2) below will not return EINTR, and we
    * will not know a SIGTERM has been received and we should exit.
    *
    * This should not create problems for children, however, as they
    * should be select()'ing for the mother pipe to know when mother
    * has exited.
    *
    * Likewise, mother will know children has exited because in addition
    * to the sigchld handler, she also has the same pipes to check.
    * Thus, we need not depend on sockd_handledsignals() to know we
    * should exit.
    */
#endif /* !SOCKS_CLIENT */

   if (new_bufrset == NULL) {
      new_bufrset  = allocate_maxsize_fdset();
      new_buffwset = allocate_maxsize_fdset();
   }

   if (bufrset != NULL)
      FD_ZERO(new_bufrset);

   if (buffwset != NULL)
      FD_ZERO(new_buffwset);

   if (sockscf.option.debug > 1) 
      print_selectfds("pre select:",
                      SOCKS_CLIENT ? 0 : 1,
                      nfds,
                      rset,
                      bufrset,
                      buffwset,
                      wset,
                      xset,
                      timeout);


   bufset_nfds = 0;
   if (bufrset != NULL || buffwset != NULL) {
      /*
       * We need to go through each descriptor and see if it
       * has data buffered ready for reading.  If so, that descriptor
       * needs to also be set on return from the below select(2),
       * and the timeout must be zero (already have at least one
       * descriptor readable).
       */
      for (i = 0; i < nfds; ++i) {
         /*
          * Does the fd has data buffered for reading?
          * Should only check for decoded data on read.  If it's not
          * decoded, it means we were unable to read the whole token 
          * last time, which means there is no data we can fetch from 
          * the buffer until the rest of the token has been read from 
          * the socket.
          */
         if (bufrset != NULL
         &&  FD_ISSET(i, bufrset)
         &&  socks_bytesinbuffer(i, READ_BUF, 0) > 0) {
            if (sockscf.option.debug > 1)
               slog(LOG_DEBUG, "%s: marking fd %d as readable; "
               "%lu + %lu bytes buffered for read, %lu + %lu for write",
               function, i,
               (long unsigned)socks_bytesinbuffer(i, READ_BUF, 0),
               (long unsigned)socks_bytesinbuffer(i, READ_BUF, 1),
               (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 0),
               (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 1));

            FD_SET(i, new_bufrset);
            bufset_nfds = MAX(bufset_nfds, i + 1);
            timeout     = &zerotimeout;
         }

         /*
          * does the fd has data buffered for write?
          */
         if (buffwset != NULL
         &&  FD_ISSET(i, buffwset)
         && socks_bufferhasbytes(i, WRITE_BUF) > 0) {
            if (sockscf.option.debug > 1)
               slog(LOG_DEBUG,
                    "%s: marking fd %d as having data buffered for write; "
                    "%lu + %lu bytes buffered for read, %lu + %lu for write",
                    function, i,
                    (long unsigned)socks_bytesinbuffer(i, READ_BUF, 0),
                    (long unsigned)socks_bytesinbuffer(i, READ_BUF, 1),
                    (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 0),
                    (long unsigned)socks_bytesinbuffer(i, WRITE_BUF, 1));

            FD_SET(i, new_buffwset);
            bufset_nfds = MAX(bufset_nfds, i + 1);
            timeout     = &zerotimeout;
         }
      }
   }


   rc = select(nfds, rset, wset, xset, timeout);

   if (sockscf.option.debug > 1) {
      char pfix[256];

      snprintf(pfix, sizeof(pfix), "post select returned %d (%s):",
               rc, errnostr(errno));

      print_selectfds(pfix,
                      SOCKS_CLIENT ? 0 : 1,
                      nfds,
                      rset,
                      bufrset,
                      buffwset,
                      wset,
                      xset,
                      timeout);
   }

#if !SOCKS_CLIENT
   if (rc == -1 && errno == EINTR) {
      sockd_handledsignals();

      errno = EINTR;
      return -1;
   }
#endif /* !SOCKS_CLIENT */

   if (rc == -1)
      return rc;

   if (bufrset != NULL)
      FD_COPY(bufrset, new_bufrset);

   if (buffwset != NULL)
      FD_COPY(buffwset, new_buffwset);

   return MAX(rc, bufset_nfds);
}

static void
print_selectfds(preamble, docheck, 
                nfds, rset, bufrset, buffwset, wset, xset, timeout)
   const char *preamble;
   const int docheck;
   const int nfds;
   fd_set *rset, *bufrset, *buffwset;
   fd_set *wset;
   fd_set *xset;
   struct timeval *timeout;
{
   const char *function = "print_selectfds()"; 
   const int errno_s = errno;
   char buf[32],
        rsetfd[256], bufrsetfd[1024], buffwsetfd[1024],
        wsetfd[1024], xsetfd[1024];
   size_t rsetfdi, bufrsetfdi, buffwsetfdi, wsetfdi, xsetfdi;
   int i, rc;

   if (timeout != NULL)
      snprintf(buf, sizeof(buf), "%ld:%ld",
              (long)timeout->tv_sec, (long)timeout->tv_usec);
   else
      snprintf(buf, sizeof(buf), "0x0");

   rsetfdi = bufrsetfdi = buffwsetfdi = wsetfdi = xsetfdi = 0;
   *rsetfd = *bufrsetfd = *buffwsetfd = *wsetfd = *xsetfd = NUL;
   for (i = 0; i < nfds; ++i) {
      if (rset != NULL && FD_ISSET(i, rset)) {
         rc = snprintf(&rsetfd[rsetfdi], sizeof(rsetfd) - rsetfdi, 
                      "%d%s, ",
                      i, docheck ? (fdisopen(i) ? "" : "-invalid") : "");
         rsetfdi += rc;
      }

      if (bufrset != NULL && FD_ISSET(i, bufrset)) {
         rc = snprintf(&bufrsetfd[bufrsetfdi],
                       sizeof(bufrsetfd) - bufrsetfdi, 
                       "%d%s, ",
                       i, docheck ? (fdisopen(i) ? "" : "-invalid") : "");
         bufrsetfdi += rc;
      }

      if (buffwset != NULL && FD_ISSET(i, buffwset)) {
         rc = snprintf(&buffwsetfd[buffwsetfdi],
                       sizeof(buffwsetfd) - buffwsetfdi, 
                       "%d%s, ",
                       i, docheck ? (fdisopen(i) ? "" : "-invalid") : "");

         buffwsetfdi += rc;
      }


      if (wset != NULL && FD_ISSET(i, wset)) {
         rc = snprintf(&wsetfd[wsetfdi], sizeof(wsetfd) - wsetfdi, 
                       "%d%s, ",
                       i, docheck ? (fdisopen(i) ? "" : "-invalid") : "");

         wsetfdi += rc;
      }

      if (xset != NULL && FD_ISSET(i, xset)) {
         rc = snprintf(&xsetfd[xsetfdi], sizeof(xsetfd) - xsetfdi, 
                       "%d%s, ",
                       i, docheck ? (fdisopen(i) ? "" : "-invalid") : "");

         xsetfdi += rc;
      }
   }

   slog(LOG_DEBUG, "%s nfds = %d, "
                   "rset = %p (%s), bufrset = %p (%s), buffwset = %p (%s) "
                   "wset = %p (%s), "
                   "xset = %p (%s), timeout = %s",
                   preamble, nfds,
                   rset, rsetfd, bufrset, bufrsetfd, buffwset, buffwsetfd,
                   wset, wsetfd, 
                   xset, xsetfd, buf);

   if (errno != errno_s)
      swarnx("%s: strange ... errno changed from %d to %d",
      function, errno_s, errno);

   errno = errno_s;
}

