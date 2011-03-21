/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010
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
#include "config_parse.h"

static const char rcsid[] =
"$Id: sockd_io.c,v 1.365.2.5.2.2.2.16 2011/03/13 17:13:37 michaels Exp $";

/*
 * IO-child:
 * Accept io objects from mother and do io on them.  We never
 * send back ancillary data, only ordinary data, so no need for
 * locking here even on broken systems (#ifdef HAVE_SENDMSG_DEADLOCK).
 */

/* for delete_io() calls. */
typedef enum { IO_ERRORUNKNOWN, IO_TIMEOUT, IO_ERROR, IO_CLOSE, IO_SHORT,
               IO_SRCBLOCK
} iostatus_t;

static void siginfo(int sig);

static size_t
io_allocated(int *for_tcp, int *for_udp);
/*
 * Returns the number of allocated (active) io's.
 *
 * If "for_tcp" is not NULL, on return it will contain the number of io's
 * allocated for tcp.
 * If "for_udp" is not NULL, on return it will contain the number of io's
 * allocated for udp.
 */

static struct sockd_io_t *
io_getset(const int nfds, const fd_set *set);
/*
 * Goes through our list until it finds an io object where at least one of the
 * descriptors in "set" is set.  "nfds" gives the number of descriptors in
 * "set" to check
 *
 * Returns NULL if none found.
 */

static struct sockd_io_t *
io_finddescriptor(int d);
/*
 * Finds the io object where one of the descriptors matches "fd".
 */

static int
io_fillset(fd_set *set, int antiflags, const struct timeval *timenow);
/*
 * Sets all descriptors from our list, in "set".  If "antiflags"
 * is set, io's with any of the flags in "antiflags" set will be excluded.
 * IO's with state.fin set will also be excluded.
 * "timenow" is the time now.
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors we want to select() on currently.
 */

static void
io_clearset(const struct sockd_io_t *io, fd_set *set);
/*
 * Clears all file descriptors in "io" from "set".
 */

static void
doio(int mother, struct sockd_io_t *io, fd_set *rset, fd_set *wset,
      int flags);
/*
 * Does i/o over the descriptors in "io", in to out and out to in.
 * "mother" is the write connection to mother if we need to send a ack.
 * "io" is the object to do i/o over,
 * "flags" is the flags to set on the actual i/o calls
 * (read()/write(), recvfrom()/sendto()), currently only MSG_OOB.
 * If any of the calls fail the "io" is deleted.
 */

static int
io_rw(struct sockd_io_direction_t *in, struct sockd_io_direction_t *out,
      int *bad, void *buf, size_t bufsize, int flags);
/*
 * Transfers data from "in" to "out" using "buf" as a temporary buffer
 * to store the data, and sets flag "flags" in sendto()/recvfrom().
 * "inauth" is the authentication used for reading from "in",
 * "outauth" is the authentication * used when writing to out.
 * The data transferred uses "buf" as a buffer, which is of size "bufsize".
 * The function never transfers more than the receive low watermark
 * of "out".
 *
 * Returns:
 *      On success: bytes transferred or 0 for eof.
 *      On failure: -1.  "bad" is set to the value of the descriptor that
 *                  failure was first detected on.
 */

static void
delete_io(int mother, struct sockd_io_t *io, int fd, const iostatus_t status);
/*
 * deletes the io object "io".  "fd" is the descriptor on which "status"
 * was returned.  If "fd" is negative, it is ignored.
 * If "mother" is >= 0, the deletion of "io" is ACK'ed to her.
 * "status" can have one of these values and is normally intended to be the
 * result from a io call (read/write/etc).
 *      IO_ERRORUNKNOWN:   unknown error.
 *      IO_TIMEOUT     :   connection timed out.  ("fd" argument is ignored).
 *      IO_ERROR       :   error using "fd".
 *      IO_CLOSE       :   socket was closed.
 *      > 0            :   short read/write
 */

static void
proctitleupdate(void);
/*
 * Updates the title of this process.
 */

static struct timeval *
io_gettimeout(struct timeval *timeout, const struct timeval *timenow);
/*
 * If there is a timeout on the current clients for how long to exist
 * without doing i/o, this function fills in "timeout" with the appropriate
 * timeout.
 * Returns:
 *      If there is a timeout: pointer to filled in "timeout".
 *      If there is no timeout: NULL.
 */

static struct sockd_io_t *
io_gettimedout(const struct timeval *timenow);
/*
 * Scans all clients for one that has timed out according to sockscf
 * settings. "timenow" is the time now.
 * Returns:
 *      If timed out client found: pointer to it.
 *      Else: NULL.
 */

static void
getnewio(struct sockd_mother_t *mother);
/*
 * Receives a io from "mother".  Closes "mother" and sets
 * sockets to -1 if there is an error.
 */

#if BAREFOOTD

#define UDPBLOCK (16)   /*
                         * how many clients to allocate memory for, or by
                         * how many clients to increase allocated memory
                         * when needed.
                         */

#define MAX_ICMPLEN (60 /* MAX IP LEN */ + 8 + 60 + 8)
#define MIN_ICMPLEN (20 /* MIN IP LEN */ + 8)

static void handlerawsocket(const int s);
/*
 * Handles packets coming in on the raw socket "s".  Used
 * to read icmp-errors concerning packets we send to udp clients.
 */

static const struct udpclient *
udpclientofladdr(const struct sockaddr *addr, const size_t udpclientc,
                 const struct udpclient *udpclientv);
/*
 * Returns the udpclient that has the local address "addr", or NULL
 * if no such client exists.
 */

static const struct udpclient *udpclientofraddr(const struct sockaddr *addr,
                                                const size_t udpclientc,
                                            const struct udpclient *udpclientv);
/*
 * Returns the udpclient that has the remote address "addr", or NULL
 * if no such client exists.
 */

static int socketofudpraddr(const struct sockaddr *addr,
                            const size_t udpclientc,
                            const struct udpclient *udpclientv);
/*
 * Returns the udpclient that has the remote address "addr", or NULL
 * if no such client exists.
 */

static struct udpclient *
udpclientofsocket(const int s, const size_t udpclientc,
      struct udpclient *udpclientv);
/*
 * Returns the udpclient belonging to socket "s", or NULL if no
 * such client.
 */

static const struct sockaddr *
srcofudpsocket(const int s, const size_t udpclientc,
       struct udpclient *udpclientv);
/*
 * Returns the srcaddress of the udpclient belonging to socket "s",
 * or NULL if no such client.
 */

static int socketofudpraddr(const struct sockaddr *addr,
                            const size_t udpclientc,
                            const struct udpclient *udpclientv);
/*
 * Returns the socket belonging to the udpclient that has the
 * remote address "addr", or -1 if no such client.
 */

#if 0
static int socketofudpladdr(const struct sockaddr *addr,
                            const size_t udpclientc,
                            const struct udpclient *udpclientv);
/*
 * Returns the socket belonging to the udpclient that has the
 * remote address "addr", or -1 if no such client.
 */
#endif

static struct udpclient *
addudpclient(const struct udpclient *client, size_t *clientc,
             size_t *maxclientc, struct udpclient **clientv);
/*
 * Adds the udpclient "client" to the "clientv" array, which is large
 * enough to contain "maxclientc" clients.
 * "clientc" gives the index of the last slot in "clientv" that is
 * currently in use.
 *
 * Returns a pointer to the added client ("client"), or NULL if there
 * is no more room and clientv can not be expanded.
 */

static int
removeudpclient(const int s, size_t *clientc, struct udpclient *clientv);
/*
 * Removes the udpclient associated with the socket "s" from the
 * "clientv" array, which contains "clientc" elements, and decrements
 * "clientc".
 * Returns 0 on success, -1 on failure.
 */

#endif /* BAREFOOTD */

/* Solaris sometimes fails to return srcaddress in recvfrom(). */
#define UDPFROMLENCHECK(socket, fromlen) \
   do {                                                                       \
      if (fromlen == 0) {                                                     \
         static int failures;                                                 \
                                                                              \
         swarnx("%s: system error: did not get address in recvfrom()",        \
         function);                                                           \
                                                                              \
         if (++failures > 5) {                                                \
            swarnx("%s: running Solaris <= 2.5.1, are we?  "                  \
            "giving up after %d failures", function, failures);               \
            delete_io(mother, io, (socket), IO_ERROR);                        \
            failures = 0;                                                     \
         }                                                                    \
         return;                                                              \
      }                                                                       \
   } while (/*CONSTCOND*/0)

#define BWUPDATE(io, timenow, bwused)                                         \
do {                                                                          \
   if (bwused) {                                                              \
      io->iotime = timenow;                                                   \
                                                                              \
      if (io->rule.bw != NULL)                                                \
         bw_update(io->rule.bw, bwused, &io->iotime);                         \
   }                                                                          \
} while (/*CONSTCOND*/0)

static struct sockd_io_t iov[SOCKD_IOMAX];   /* each child has these io's. */
static size_t ioc = ELEMENTS(iov);
static struct timeval bwoverflow;

void
run_io(mother)
   struct sockd_mother_t *mother;
{
   const char *function = "run_io()";
   struct sigaction sigact;
   int p;
#if BAREFOOTD
   socklen_t optlen;
   int rawsocket;
#endif /* BAREFOOTD */

   bzero(&sigact, sizeof(sigact));
   sigact.sa_flags   = SA_RESTART;
   sigact.sa_handler = siginfo;

#if HAVE_SIGNAL_SIGINFO
   if (sigaction(SIGINFO, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);
#endif /* HAVE_SIGNAL_SIGINFO */

   /* same handler, for systems without SIGINFO. */
   if (sigaction(SIGUSR1, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGUSR1)", function);

#if BAREFOOTD
   /*
    * Set up a raw socket so we can get icmp errors for
    * udp packets sent to clients, and delete them if so.
    */

   sockd_priv(SOCKD_PRIV_NET_ICMPACCESS, PRIV_ON);
   if ((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
      swarn("%s: could not open raw socket", function);
   else
      slog(LOG_DEBUG, "%s: created raw socket, index %d", function, rawsocket);
   sockd_priv(SOCKD_PRIV_NET_ICMPACCESS, PRIV_OFF);

#if HAVE_PRIVILEGES
   /* don't need this privilege any more, permanently loose it. */

   if (!sockscf.privileges.noprivs) {
      priv_delset(sockscf.privileges.privileged, PRIV_NET_ICMPACCESS);
      if (setppriv(PRIV_SET, PRIV_PERMITTED, sockscf.privileges.privileged)
      != 0)
         swarn("%s: setppriv() to relinquish PRIV_NET_ICMPACCESS failed",
         function);
   }
#endif /* HAVE_PRIVILEGES */

   if (rawsocket != -1) {
      optlen = sizeof(p);
      if (getsockopt(rawsocket, SOL_SOCKET, SO_RCVBUF, &p, &optlen) != 0)
         swarn("%s: getsockopt(SO_RCVBUF)", function);
      else {
         if (p < RAW_SOCKETBUFFER) {
            p = RAW_SOCKETBUFFER;
            if (setsockopt(rawsocket, SOL_SOCKET, SO_RCVBUF, &p, sizeof(p))
            != 0)
               swarn("%s: failed setsockopt(SO_RCVBUF, %d) on raw socket",
               function, p);
            else
               slog(LOG_DEBUG, "%s: changed buffer size to %d bytes",
               function, p);
         }
         else
            slog(LOG_DEBUG, "%s: default buffer size is %d bytes, keeping it",
            function, p);
      }
   }

#endif /* BAREFOOTD */

   proctitleupdate();

   /* CONSTCOND */
   while (1) {
      /*
       * The heart and soul of the server.  This is the loop where
       * all i/o is done and involves some tricky stuff.
       *
       * We need to check for write separately to avoid busy-looping.
       * The problem is that if the descriptor is ready for reading but
       * the corresponding descriptor to write out on is not ready, we will
       * be busy-looping; above select will keep returning descriptors set,
       * but we will not be able to write (and thus won't read) them.
       * We therefore only set in wset the descriptors that have the
       * corresponding read descriptor readable, so that when the
       * second select() returns, the io objects we get from wset will
       * be both readable and writable.
       *
       * Another problem is that if while we wait for writability, a new
       * descriptor becomes readable, we thus can't block forever here.
       * We solve this by in the second select() also checking for
       * readability, but now only the descriptors that were not found
       * to be readable in the previous select().
       * This means that a positive return from the second select does not
       * necessarily indicate we have i/o to do, but it does mean we
       * either have it or a new descriptor became readable; in either
       * case, something has happened.
       * Reason we do not check for exceptions in this select is that
       * there is nothing we do about them until the descriptor becomes
       * readable too, thus any new exceptions will be in newrset before
       * we have reason to care about them.
       */
      static fd_set *rset, *wset, *xset, *newrset, *controlset,
                    *tmpset, *bufrset;
      struct sockd_io_t *io;
      struct timeval timeout, timenow;
      sigset_t oldset;
      int rbits, wbits;

      if (rset == NULL) {
         rset       = allocate_maxsize_fdset();
         wset       = allocate_maxsize_fdset();
         xset       = allocate_maxsize_fdset();
         newrset    = allocate_maxsize_fdset();
         controlset = allocate_maxsize_fdset();
         tmpset     = allocate_maxsize_fdset();
         bufrset    = allocate_maxsize_fdset();
      }

      /* look for timed-out clients. */
      gettimeofday(&timenow, NULL);
      while ((io = io_gettimedout(&timenow)) != NULL)
         delete_io(mother->ack, io, -1, IO_TIMEOUT);

      /* starting a new run. */
      timerclear(&bwoverflow);

      io_fillset(xset, MSG_OOB, &timenow);
      rbits = io_fillset(rset, 0, &timenow);

      if (mother->s != -1) {
         FD_SET(mother->s, rset);
         rbits = MAX(rbits, mother->s);

         /* checked so we know if mother goes away.  */
         FD_SET(mother->ack, rset);
         rbits = MAX(rbits, mother->ack);
      }
      else /* no mother.  Do we have any other descriptors to work with? */
         if (rbits == -1) {
            SASSERTX(io_allocated(NULL, NULL) == 0);

            slog(LOG_DEBUG, "%s: no connection to mother and no clients.  "
                            "We should exit",
                             function);

            sockdexit(EXIT_SUCCESS);
         }

#if BAREFOOTD
      if (rawsocket != -1)
         FD_SET(rawsocket, rset);
         rbits = MAX(rbits, rawsocket);
#endif /* BAREFOOTD */

      /*
       * first find descriptors that are readable; we won't write if
       * we can't read.  Also select for exceptions so we can tell
       * the i/o function if there's one pending later.
       */

      switch (selectn(++rbits, rset, bufrset, NULL, NULL, xset,
      io_gettimeout(&timeout, &timenow))) {
         case -1:
            SERR(-1);

         case 0:
            continue; /* restart the loop. */
      }

      /*
       * Add bufrset to rset, so rset contains all sockets we can
       * read from, whether from the socket or from the buffer.
       */
      fdsetop(rbits, '|', rset, bufrset, tmpset);
      FD_COPY(rset, tmpset);

#if BAREFOOTD
      if (rawsocket != -1 && FD_ISSET(rawsocket, rset)) {
         handlerawsocket(rawsocket);
         FD_CLR(rawsocket, rset);
      }
#endif /* BAREFOOTD */

      if (mother->ack != -1 && FD_ISSET(mother->ack, rset)) {
         slog(LOG_DEBUG, "%s: mother closed", function);

         FD_CLR(mother->s, rset);
         FD_CLR(mother->ack, rset);

         mother->s = mother->ack = -1;
      }

      if (mother->s != -1 && FD_ISSET(mother->s, rset)) {
         getnewio(mother);
         continue; /* need to scan rset again, have a new client. */
      }

      /*
       * We now know what descriptors are readable; rset.
       * Next prepare for the second select(2), where we want to
       * know which of the descriptors, paired with the above readable
       * descriptors, we can write to.  In that select(2) we also need to
       * check for read, but only those descriptors that are not already
       * readable, as that constitutes at least a status change which
       * we should loop around for.
       */

      gettimeofday(&timenow, NULL);
      wbits = io_fillset(tmpset, 0, &timenow);
      wbits = fdsetop(wbits + 1, '^', rset, tmpset, newrset);

      if (mother->s != -1) { /* mother status may change too. */
         FD_SET(mother->s, newrset);
         wbits = MAX(wbits, mother->s);

         /* checked so we know if mother goes away.  */
         FD_SET(mother->ack, newrset);
         wbits = MAX(wbits, mother->ack);
      }

      /*
       * descriptors to check for writability: those with the corresponding
       * read-descriptor set, or data already buffered for write.
       * If the descriptor is not readable, don't bother checking for
       * exceptions either.
       */

      FD_ZERO(wset);
      FD_ZERO(controlset);
      for (p = 0; p < rbits; ++p) {
         if (!FD_ISSET(p, rset)) {
            FD_CLR(p, xset);
            continue;
         }

         io = io_finddescriptor(p);
         SASSERTX(io != NULL);

         if (socks_bytesinbuffer(p, WRITE_BUF, 0) > 0
         ||  socks_bytesinbuffer(p, WRITE_BUF, 1) > 0) {
            FD_SET(p, wset);
            wbits = MAX(wbits, p);
         }

#if BAREFOOTD
         /*
          * The tcp case is the same as socks, but in the case of udp,
          * we have a one-to-many scenario, where packets received
          * on "in" can go to many different "out's.", and we don't
          * know which out socket to use until we have read the packet,
          * to see who the sender is.
          *
          * Udp sockets shouldn't block though, so selecting
          * for writability is not really required.  Thus,
          * we just need to make sure at all times that dst.s
          * always contains one of the valid out sockets.  If
          * one is writable, all should be.
          *
          * The reverse, when a packet comes in on one of the many
          * out sockets is slightly more complicated. In this case,
          * we need to select for readability on all the many out
          * sockets.  This is handled in io_fillset(), but we also
          * need to make sure that io->dst.s is set to the (possibly
          * one of many) descriptors in dstv[] that is readable when
          * we call doio().
          */
#endif /* BAREFOOTD */

         if (io->src.s == p) {
            /* read from in requires out to be writable. */
            FD_SET(io->dst.s, wset);
            wbits = MAX(wbits, io->dst.s);
         }
         else if (io->dst.s == p) {
            /* read from out requires in to be writable. */
            FD_SET(io->src.s, wset);
            wbits = MAX(wbits, io->src.s);
         }
         else {
            SASSERTX(io->control.s == p);
            FD_SET(io->control.s, controlset);

            /* also readable without matching writable. */
            FD_SET(io->control.s, newrset);

            wbits = MAX(wbits, io->control.s);
         }
      }

      if (wbits++ == -1)
         continue;

      switch (selectn(wbits, newrset, NULL, wset, NULL, NULL,
      io_gettimeout(&timeout, &timenow))) {
         case -1:
            if (errno != EINTR)
               SERR(-1);
            continue;

         case 0:
            continue;
      }

      if (mother->s != -1 && FD_ISSET(mother->s, rset)) {
         FD_CLR(mother->s, rset);
         getnewio(mother);
      }

      if (mother->ack != -1 && FD_ISSET(mother->ack, rset)) {
         slog(LOG_DEBUG, "%s: mother closed", function);

         FD_CLR(mother->s, rset);
         FD_CLR(mother->ack, rset);

         mother->s = mother->ack = -1;
      }

      FD_COPY(tmpset, controlset);
      fdsetop(wbits, '&', newrset, tmpset, controlset);

      /*
       * newrset: descriptors readable, all new apart from controldescriptors.
       *          Don't do anything with them here, loop around and check for
       *          writability first.
       *
       * controlset: subset of newrset containing control descriptors
       *             that are readable.
       *
       * rset: descriptors readable, from buffer or from socket.
       *
       * xset: subset of rset with exceptions pending.
       *
       * wset: descriptors writable with at least one of:
       *          - a matching descriptor in rset/xset.
       *          - data buffered on the write side.
       *       This is what we can do i/o over.
       */

      /*
       * First check all io's which have an exception pending.
       * Getting an io here does not mean we can do i/o over it
       * however, so need to check for writability also.
       */
      while ((io = io_getset(rbits, xset)) != NULL) {
         slog(LOG_DEBUG, "select(): exception set");

         if (FD_ISSET(io->dst.s, wset)) {
            if (io->state.protocol == SOCKS_UDP)
               socks_sigblock(SIGHUP, &oldset);

            doio(mother->ack, io, xset, wset, MSG_OOB);

            if (io->state.protocol == SOCKS_UDP)
               socks_sigunblock(&oldset);

            io_clearset(io, wset);
         }

         io_clearset(io, xset);

         /* xset is subset of rset so clear rset too. */
         io_clearset(io, rset);

         /* can be likewise. */
         io_clearset(io, controlset);
      }

      /*
       * Get all io's which are writable.  They will have a matching
       * descriptor that is readable.
       */
      while ((io = io_getset(wbits, wset)) != NULL) {
         if (io->state.protocol == SOCKS_UDP)
            socks_sigblock(SIGHUP, &oldset);
         doio(mother->ack, io, rset, wset, 0);

         if (io->state.protocol == SOCKS_UDP)
            socks_sigunblock(&oldset);

#if BAREFOOTD
         if (io->state.command == SOCKS_UDPASSOCIATE
         && FD_SET(io->src.s, rset)) {
            /*
             * More tricky; udp is a "point-to-multipoint" case.
             * If it is the source that is readable, we can not
             * assume that since the destination is writable, we will
             * have a packet pending on source, as with multiple
             * destinations, that, possibly one, packet pending on
             * source has not been read.  We thus need to clear all
             * other destinations too after we have read from source.
             */
            size_t i;

            for (i = 0; i < io->dstc; ++i)
               FD_CLR(io->dstv[i].s, wset);
         }
#endif /* BAREFOOTD */

         io_clearset(io, rset);
         io_clearset(io, wset);
         io_clearset(io, controlset);
      }

      /*
       * Get all io's which have controldescriptors that are readable.
       */
      while ((io = io_getset(rbits, controlset)) != NULL) {
         static fd_set *nullset;

         if (nullset == NULL)
            nullset = allocate_maxsize_fdset();

         FD_ZERO(nullset);

         if (io->state.protocol == SOCKS_UDP)
            socks_sigblock(SIGHUP, &oldset);

         doio(mother->ack, io, controlset, nullset, 0);

         if (io->state.protocol == SOCKS_UDP)
            socks_sigunblock(&oldset);

         io_clearset(io, controlset);
         /* controlset is subset of newrset so clear newrset too. */
         io_clearset(io, newrset);
      }

      /* possible future optimization: if newrset not empty, use it? */
   }
}

static void
delete_io(mother, io, fd, status)
   int mother;
   struct sockd_io_t *io;
   int fd;
   const iostatus_t status;
{
   const char *function = "delete_io()";
   const int errno_s = errno;
   struct rule_t *rulev[2];
   size_t i, src_read, src_written, dst_read, dst_written,
          src_packetsread, src_packetswritten, dst_packetsread,
          dst_packetswritten;
   time_t timenow;
   int command, protocol;
#if HAVE_GSSAPI
   gss_buffer_desc output_token;
   OM_uint32 minor_status;
#endif /* HAVE_GSSAPI */

   SASSERTX(io->allocated);

   session_unuse(io->rule.ss);

   if (io->state.protocol == SOCKS_TCP) /* udp rules are temporary. */
      bw_unuse(io->rule.bw);

   time(&timenow);

   /* log the disconnect if client-rule or socks-rule says so. */
   rulev[0] = &io->rule;
   rulev[1] = &io->crule;
   for (i = 0; i < ELEMENTS(rulev); ++i) {
      const struct rule_t *rule = rulev[i];
      size_t bufused;
      char in[MAX_IOLOGADDR], out[MAX_IOLOGADDR],
           timeinfo[256], logmsg[sizeof(in) + sizeof(out) + 1024];

      if (!rule->log.disconnect)
         continue;

      src_written        = io->src.written.bytes;
      src_packetswritten = io->src.written.packets;

      src_read           = io->src.read.bytes;
      src_packetsread    = io->src.read.packets;

      dst_written        = io->dst.written.bytes;
      dst_packetswritten = io->dst.written.packets;

      dst_read           = io->dst.read.bytes;
      dst_packetsread    = io->dst.read.packets;

      if (rule == &io->crule) { /* client-rule */
         BUILD_ADDRSTR_SRC(&io->control.host,
                           NULL,
                           NULL,
                           &io->control.laddr,
                           &io->clientauth, 
                           NULL,
                           in,
                           sizeof(in));

         *out = NUL; /* client-rule is from client to socks-server, and stop. */

         command  = io->state.clientcommand;
         protocol = io->state.clientprotocol;
      }
      else if (rule == &io->rule) { /* socks rule. */
         /*
          * XXX if support for serverchaining is added to bind, the
          * bindreply might involve a proxy on the src side.
          */
         BUILD_ADDRSTR_SRC(&io->src.host,
                           NULL,
                           NULL,
                           &io->src.laddr,
                           &io->src.auth, 
                           NULL,
                           in,
                           sizeof(in));

         switch (io->state.command) {
            case SOCKS_BINDREPLY:
            case SOCKS_BIND:
            case SOCKS_CONNECT: {
               BUILD_ADDRSTR_DST(&io->dst.laddr,
                                 io->state.proxyprotocol == PROXY_DIRECT
                                    ? NULL : &io->state.proxychain.server,
                                 io->state.proxyprotocol == PROXY_DIRECT
                                    ? NULL : &io->state.proxychain.extaddr,
                                 &io->dst.host,
                                 &io->dst.auth, 
                                 NULL,
                                 out,
                                 sizeof(out));
               break;
            }

            case SOCKS_UDPASSOCIATE: {
#if BAREFOOTD
               struct udpclient *client;
#endif /* BAREFOOTD */
               if (io->dst.state.connected)
                  BUILD_ADDRSTR_DST(&io->dst.laddr,
                                    io->state.proxyprotocol == PROXY_DIRECT
                                        ? NULL : &io->state.proxychain.server,
                                    io->state.proxyprotocol == PROXY_DIRECT
                                        ? NULL : &io->state.proxychain.extaddr,
                                    &io->dst.host,
                                    &io->dst.auth, 
                                    NULL,
                                    out,
                                    sizeof(out));
               else
                  BUILD_ADDRSTR_DST(&io->dst.laddr,
                                    io->state.proxyprotocol == PROXY_DIRECT
                                       ? NULL : &io->state.proxychain.server,
                                    io->state.proxyprotocol == PROXY_DIRECT
                                       ? NULL : &io->state.proxychain.extaddr,
                                    NULL,
                                    &io->dst.auth, 
                                    NULL,
                                    out,
                                    sizeof(out));
#if BAREFOOTD
               client = udpclientofsocket(io->dst.s, io->dstc, io->dstv);
               SASSERTX(client != NULL);

               src_read           = client->src_read.bytes;
               src_packetsread    = client->src_read.packets;

               src_written        = client->src_written.bytes;
               src_packetswritten = client->src_written.packets;

               dst_written        = client->dst_written.bytes;
               dst_packetswritten = client->dst_written.packets;

               dst_read           = client->dst_read.bytes;
               dst_packetsread    = client->dst_read.packets;
#endif /* BAREFOOTD */

               break;
            }

            default:
               SERRX(io->state.command);
         }

         command  = io->state.command;
         protocol = io->state.protocol;
      }
      else
         SERRX(0);

      bufused = snprintfn(logmsg, sizeof(logmsg), "%s(%lu): %s/%s ]: ",
                          rule->verdict == VERDICT_PASS ?
                          VERDICT_PASSs : VERDICT_BLOCKs,
                          (unsigned long)rule->number,
                          protocol2string(protocol),
                          command2string(command));

      if (protocol == SOCKS_TCP) {
         if (*out == NUL) {
            const int isreversed
            = (io->state.command == SOCKS_BINDREPLY ? 1 : 0);

            bufused +=
            snprintfn(&logmsg[bufused], sizeof(logmsg) - bufused,
                      "%lu -> %s -> %lu",
                      (unsigned long)(isreversed ? dst_written : src_written),
                      in,
                      (unsigned long)(isreversed ? src_written : dst_written));
         }
         else
            bufused
            += snprintfn(&logmsg[bufused], sizeof(logmsg) - bufused,
                        "%lu -> %s -> %lu, %lu -> %s -> %lu",
                        (unsigned long)(src_written),
                        in,
                        (unsigned long)(src_read),
                        (unsigned long)(dst_written),
                        out,
                        (unsigned long)(dst_read));
      }
      else {
         SASSERTX(*out != NUL);

         bufused
         += snprintfn(&logmsg[bufused], sizeof(logmsg) - bufused,
                      "%lu/%lu -> %s -> %lu/%lu, %lu/%lu -> %s -> %lu/%lu",
                      (unsigned long)src_written,
                      (unsigned long)src_packetswritten,
                      in,
                      (unsigned long)src_read,
                      (unsigned long)src_packetsread,
                      (unsigned long)dst_written,
                      (unsigned long)dst_packetswritten,
                      out,
                      (unsigned long)dst_read,
                      (unsigned long)dst_packetsread);
      }

      bufused = snprintf(timeinfo, sizeof(timeinfo), "after %.0fs",
                         difftime(timenow, io->state.time.established.tv_sec));

      if (sockscf.option.debug) {
         struct timeval accept2negotiate, neg2establish, established2io;

         timersub(&io->state.time.negotiate, &io->state.time.accepted,
                  &accept2negotiate);

         timersub(&io->state.time.established, &io->state.time.negotiate,
                  &neg2establish);

         timersub(&io->state.time.firstio, &io->state.time.established,
                  &established2io);

         bufused += snprintf(&timeinfo[bufused], sizeof(timeinfo) - bufused,
                             "\n"
                             "accept to negotiate start       : %ld.%ld\n"
                             "negotiate start to finish       : %ld.%ld\n"
                             "session establish to first i/o  : %ld.%ld\n",
                             (long)accept2negotiate.tv_sec,
                             (long)accept2negotiate.tv_usec,
                             (long)neg2establish.tv_sec,
                             (long)neg2establish.tv_usec,
                             (long)established2io.tv_sec, (long)
                             established2io.tv_usec);
      }

      errno = errno_s;
      if (fd < 0) {
         switch (status) {
            case IO_SRCBLOCK:
               slog(LOG_INFO, "%s: delayed source block %s", logmsg, timeinfo);
               break;

            case IO_ERROR:
               swarn("%s: connection error %s", logmsg, timeinfo);
               break;

            case IO_CLOSE:
               slog(LOG_INFO, "%s: connection closed %s", logmsg, timeinfo);
               break;

            case IO_TIMEOUT:
               slog(LOG_INFO, "%s: session i/o timeout %s", logmsg, timeinfo);
               break;

            case IO_SHORT:
               slog(LOG_INFO, "%s: short read/write %s", logmsg, timeinfo);
               break;

            default:
               SERRX(status);
         }
      }
      else if (fd == io->src.s || fd == io->control.s) {
         switch (status) {
            case IO_SRCBLOCK:
               slog(LOG_INFO, "%s: delayed source block %s", logmsg, timeinfo);
               break;

            case IO_ERROR: {
               struct linger linger;

               swarn("%s: error from client %s", logmsg, timeinfo);

               /* send rst to other end. */
               linger.l_onoff  = 1;
               linger.l_linger = 0;
               if (setsockopt(io->dst.s, SOL_SOCKET, SO_LINGER, &linger,
               sizeof(linger)) != 0)
                  swarn("%s: setsockopt(io->dst, SO_LINGER)", function);

               break;
            }

            case IO_CLOSE:
               slog(LOG_INFO, "%s: client closed %s", logmsg, timeinfo);
               break;

            case IO_TIMEOUT:
               slog(LOG_INFO, "%s: session i/o timeout %s", logmsg, timeinfo);
               break;

            case IO_SHORT:
               slog(LOG_INFO, "%s: short read/write from client %s",
               logmsg, timeinfo);
               break;

            default:
               SERRX(status);
         }
      }
      else if (fd == io->dst.s) {
         switch (status) {
            case IO_SRCBLOCK:
               slog(LOG_INFO, "%s: delayed source block %s", logmsg, timeinfo);
               break;

            case IO_ERROR: {
               struct linger linger;

               swarn("%s: error from remote peer %s", logmsg, timeinfo);

               /* send rst to other end. */
               linger.l_onoff    = 1;
               linger.l_linger    = 0;
               if (setsockopt(io->src.s, SOL_SOCKET, SO_LINGER, &linger,
               sizeof(linger)) != 0)
                  swarn("%s: setsockopt(io->dst, SO_LINGER)", function);
               break;
            }

            case IO_CLOSE:
               slog(LOG_INFO, "%s: remote peer closed %s", logmsg, timeinfo);
               break;

            case IO_TIMEOUT:
               slog(LOG_INFO, "%s: session i/o timeout %s", logmsg, timeinfo);
               break;

            case IO_SHORT:
               slog(LOG_INFO, "%s: short read/write from remote peer %s",
               logmsg, timeinfo);
               break;

            default:
               SERRX(status);
         }
      }
      else
         SERRX(fd);


      if (io->state.command == SOCKS_BINDREPLY && rule == &io->rule) {
         /*
          * log the close of the opened bind session also.
          */

         const int original_command = io->state.command;
         io->state.command          = SOCKS_BIND;
         iolog(&io->rule,
               &io->state,
               OPERATION_DISCONNECT,
               /* bindreply order is reversed compared to bind. */
               &io->dst.laddr,
               io->state.extension.bind ? NULL : &io->dst.host,
               &io->dst.auth,
               NULL,
               NULL,
               NULL,
               &io->src.laddr,
               &io->src.host,
               &io->src.auth,
               NULL,
               NULL,
               NULL,
               NULL,
               0);
         io->state.command          = original_command;
      }
   }

#if HAVE_GSSAPI
   if (io->src.auth.method == AUTHMETHOD_GSSAPI) {
      if (gss_delete_sec_context(&minor_status,
      &io->src.auth.mdata.gssapi.state.id, &output_token) != GSS_S_COMPLETE)
         swarnx("%s: gss_delete_sec_context of src failed", function);

      CLEAN_GSS_TOKEN(output_token);
   }

   if (io->dst.auth.method == AUTHMETHOD_GSSAPI) {
      if (gss_delete_sec_context(&minor_status,
      &io->dst.auth.mdata.gssapi.state.id, &output_token) != GSS_S_COMPLETE)
         swarnx("%s: gss_delete_sec_context of dst failed", function);

      CLEAN_GSS_TOKEN(output_token);
   }
#endif /* HAVE_GSSAPI */


#if BAREFOOTD
   if (io->state.command == SOCKS_UDPASSOCIATE) {
      /*
       * The io itself is never freed in the udp-case, as we can
       * always get new clients.
       */
      removeudpclient(io->dst.s, &io->dstc, io->dstv);
      io->dst.s = io->dstv[0].s; /* needs to point at something. */
   }
   else { /* not UDP, must be TCP, free io as usual then. */
#endif /* BAREFOOTD */

   if (io->control.s != -1 && io->control.s != io->src.s)
      socks_freebuffer(io->control.s);

   socks_freebuffer(io->src.s);
   socks_freebuffer(io->dst.s);

   close_iodescriptors(io);

   io->allocated = 0;

   if (mother != -1) {
      const char b = SOCKD_FREESLOT;

      /* ack io slot free. */
      if (socks_sendton(mother, &b, sizeof(b), sizeof(b), 0, NULL, 0, NULL)
      != sizeof(b))
          swarn("%s: socks_sendton(): mother", function);
   }

   proctitleupdate();

#if BAREFOOTD
   }
#endif /* BAREFOOTD */
}

void
close_iodescriptors(io)
   const struct sockd_io_t *io;
{

   close(io->src.s);
   close(io->dst.s);

   switch (io->state.command) {
      case SOCKS_CONNECT:
         break;

      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (!io->state.extension.bind)
            break;
         /* else: */ /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE: {
#if BAREFOOTD
         size_t i;

         for (i = 1; i < io->dstc; ++i)
            close(io->dstv[i].s);
#else /* !BAREFOOTD */
         close(io->control.s);
#endif /* !BAREFOOTD */
         break;
      }
      default:
         SERRX(io->state.command);
   }
}

int
recv_io(s, io)
   int s;
   struct sockd_io_t *io;
{
   const char *function = "recv_io()";
   struct iovec iovecv[2];
   struct msghdr msg;
   ssize_t received;
   size_t i, ioi;
   int wearechild, flags, fdexpect, fdreceived, iovecc, fdv[3];
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);

   ioi = 0;
   if (io == NULL) {   /* child semantics; find a io ourselves. */
      wearechild = 1;

      for (; ioi < ioc; ++ioi)
         if (!iov[ioi].allocated) {
            io = &iov[ioi];
            break;
         }

      if (io == NULL) {
         /*
          * either mother died/closed connection, or there is another error.
          * Both cases should be rare so try to find out what the problem is.
          */
         char buf;

         if (recv(s, &buf, sizeof(buf), MSG_PEEK) > 0)
            SERRX(io_allocated(NULL, NULL));
         return -1;
      }
   }
   else
      wearechild = 0;

   bzero(iovecv, sizeof(iovecv));
   iovecc = 0;

   iovecv[iovecc].iov_base = io;
   iovecv[iovecc].iov_len  = sizeof(*io);
   ++iovecc;

#if HAVE_GSSAPI
   iovecv[iovecc].iov_base = gssapistatemem;
   iovecv[iovecc].iov_len  = sizeof(gssapistatemem);
   ++iovecc;
#endif /* HAVE_GSSAPI */

   bzero(&msg, sizeof(msg));
   msg.msg_iov    = iovecv;
   msg.msg_iovlen = iovecc;
   msg.msg_name   = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

   if ((received = recvmsg(s, &msg, 0)) < (ssize_t)sizeof(*io)) {
      if (received == 0)
         slog(LOG_DEBUG, "%s: recvmsg(): mother closed connection", function);
      else
         swarn("%s: recvmsg(): %ld out of %lu bytes",
         function, (long)received, (long unsigned)sizeof(*io));

      return -1;
   }

   received -= sizeof(*io);

   /* figure out how many descriptors we are supposed to be passed. */
   switch (io->state.command) {
      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (io->state.extension.bind)
            fdexpect = 3;   /* in, out, control. */
         else
            fdexpect = 2;   /* in and out. */
         break;

      case SOCKS_CONNECT:
         fdexpect = 2;   /* in and out */
         break;

      case SOCKS_UDPASSOCIATE:
#if BAREFOOTD
         fdexpect = 2;   /* in and out. */
#else /* SOCKS_SERVER */
         fdexpect = 3;   /* in, out, control. */
#endif /* SOCKS_SERVER */
         break;

      default:
         SERRX(io->state.command);
   }

   /* calculate expected datalen */

#if !HAVE_DEFECT_RECVMSG
   SASSERT((size_t)CMSG_TOTLEN(msg)
   == (size_t)(CMSG_SPACE(sizeof(int) * fdexpect)) ||
   (size_t)CMSG_TOTLEN(msg) == (size_t)(CMSG_LEN(sizeof(int) * fdexpect)));
#endif /* !HAVE_DEFECT_RECVMSG */

   /*
    * Get descriptors sent us.  Should be at least two.
    */

   fdreceived = 0;

   CMSG_GETOBJECT(io->src.s, cmsg, sizeof(io->src.s) * fdreceived++);
   CMSG_GETOBJECT(io->dst.s, cmsg, sizeof(io->dst.s) * fdreceived++);

#if HAVE_GSSAPI
   gssapistate.value  = gssapistatemem;
   gssapistate.length = received;

   if (received > 0)
      slog(LOG_DEBUG, "%s: read gssapistate of size %d", function, received);
#endif /* HAVE_GSSAPI */

   /* any more descriptors to expect? */
   switch (io->state.command) {
      case SOCKS_BIND:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            if (gssapi_import_state(&io->src.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
#endif /* HAVE_GSSAPI */

         if (io->state.extension.bind)
            /* LINTED pointer casts may be troublesome */
            CMSG_GETOBJECT(io->control.s, cmsg,
            sizeof(io->control.s) * fdreceived++);
         else
            io->control.s = -1;
         break;

      case SOCKS_BINDREPLY:
#if HAVE_GSSAPI
         if (io->dst.auth.method == AUTHMETHOD_GSSAPI)
            if (gssapi_import_state(&io->dst.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
#endif /* HAVE_GSSAPI */

         if (io->state.extension.bind)
            /* LINTED pointer casts may be troublesome */
            CMSG_GETOBJECT(io->control.s, cmsg,
            sizeof(io->control.s) * fdreceived++);
         else
            io->control.s = -1;
         break;

      case SOCKS_CONNECT:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            if (gssapi_import_state(&io->src.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
#endif /* HAVE_GSSAPI */

         io->control.s = -1;
         break;

      case SOCKS_UDPASSOCIATE:
#if SOCKS_SERVER
         /* LINTED pointer casts may be troublesome */
         CMSG_GETOBJECT(io->control.s, cmsg,
         sizeof(io->control.s) * fdreceived++);

#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI) {
            if (gssapi_import_state(&io->src.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
         }
#endif /* HAVE_GSSAPI */
#endif /* SOCKS_SERVER */
         break;

      default:
         SERRX(io->state.command);
   }

   if (wearechild) { /* only child does i/o and needs a buffer. */
      /* needs to be set now for correct bandwidth calculation/limiting. */
      gettimeofday(&io->iotime, NULL);

#if BAREFOOTD /* set up things for first socket. */
      if (io->state.command == SOCKS_UDPASSOCIATE) {
         if ((io->dstv = malloc(UDPBLOCK * sizeof(*io->dstv))) == NULL) {
            swarn("%s: failed to allocate memory for udp clients", function);
            close(io->src.s);
            close(io->dst.s);

            return 0; /* strange, but not fatal. */
         }

         io->dstc    = 0;
         io->dstcmax = UDPBLOCK;

         /*
          * dummy-socket.  Need to put in something valid
          * so select() etc. won't error out on bad descriptor.
          */
         bzero(&io->dstv[io->dstc].laddr, sizeof(io->dstv[io->dstc].laddr));
         io->dstv[io->dstc].s               = io->dst.s;
         io->dstv[io->dstc].laddr.sa_family = AF_INET;
         io->dstv[io->dstc].raddr.sa_family = AF_INET;
         io->dstv[io->dstc].iotime          = io->iotime;
         ++io->dstc;
      }

      /* only log once. */
      memset(&io->crule.log, 0, sizeof(io->crule.log));
#endif /* BAREFOOTD */

      if (io->control.s != -1 && io->control.s != io->src.s)
         socks_allocbuffer(io->control.s);

      socks_allocbuffer(io->src.s);
      socks_allocbuffer(io->dst.s);
   }

   slog(LOG_DEBUG, "%s: received %d descriptor(s) for command %d.  "
                   "Control: %d, src: %d, dst: %d.  Allocated to iov #%lu",
                   function, fdreceived, io->state.command,
                   io->control.s, io->src.s, io->dst.s, (unsigned long)ioi);

   /*
    * make sure all our descriptors are non-blocking from now on.
    */
   fdv[0] = io->src.s;
   fdv[1] = io->dst.s;
   fdv[2] = io->control.s;
   for (i = 0; i < ELEMENTS(fdv); ++i) {
      if (fdv[i] == -1)
         continue;

      if ((flags = fcntl(fdv[i], F_GETFL, 0))         == -1
      ||   fcntl(fdv[i], F_SETFL, flags | O_NONBLOCK) == -1)
         swarn("%s: fcntl() failed to set descriptor %d to non-blocking",
         function, fdv[i]);
   }

   io->allocated = 1;
   return 0;
}

static void
io_clearset(io, set)
   const struct sockd_io_t *io;
   fd_set *set;
{

   FD_CLR(io->src.s, set);
   FD_CLR(io->dst.s, set);

   switch (io->state.command) {
      case SOCKS_CONNECT:
         break;

      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (!io->state.extension.bind)
            break;
         /* else: */ /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE:
#if SOCKS_SERVER
         FD_CLR(io->control.s, set);
#endif /* SOCKS_SERVER */
         break;

      default:
         SERRX(io->state.command);
   }
}

static size_t
io_allocated(tcp_alloc, udp_alloc)
   int *tcp_alloc;
   int *udp_alloc;
{
   const char *function = "io_allocated()";
   size_t i;
   int tcp_alloc_mem, udp_alloc_mem;

   if (tcp_alloc == NULL)
      tcp_alloc = &tcp_alloc_mem;

   if (udp_alloc == NULL)
      udp_alloc = &udp_alloc_mem;

   *udp_alloc = *tcp_alloc = 0;
   for (i = 0; i < ioc; ++i)
      if (iov[i].allocated) {
#if BAREFOOTD
         if (iov[i].state.command == SOCKS_UDPASSOCIATE)
            ++(*udp_alloc);
         else
            ++(*tcp_alloc);
#else /* SOCKS_SERVER */
         ++(*tcp_alloc);
#endif /* SOCKS_SERVER */
      }

   slog(LOG_DEBUG, "%s: allocated for tcp: %d, udp: %d",
   function, *tcp_alloc, *udp_alloc);

   return *tcp_alloc + *udp_alloc;
}

static void
doio(mother, io, rset, wset, flags)
   int mother;
   struct sockd_io_t *io;
   fd_set *rset, *wset;
   int flags;
{
   const char *function = "doio()";
   struct timeval timenow;
   char buf[SOCKD_BUFSIZE];
   ssize_t r, w;
   int srchaswritebuf, dsthaswritebuf;

   SASSERTX(io->allocated);

   errno = 0; /* reset on each call. */

   if (FD_ISSET(io->dst.s, rset))
      srchaswritebuf = 0; /* or really, "don't care". */
   else {
      if (socks_bytesinbuffer(io->src.s, WRITE_BUF, 0) > 0
      ||  socks_bytesinbuffer(io->src.s, WRITE_BUF, 1) > 0)
         srchaswritebuf = 1;
      else
         srchaswritebuf = 0;
   }

   if (FD_ISSET(io->src.s, rset))
      dsthaswritebuf = 0; /* or really, "don't care". */
   else {
      if (socks_bytesinbuffer(io->dst.s, WRITE_BUF, 0) > 0
      ||  socks_bytesinbuffer(io->dst.s, WRITE_BUF, 1) > 0)
         dsthaswritebuf = 1;
      else
         dsthaswritebuf = 0;
   }

   SASSERTX(((FD_ISSET(io->src.s, rset) || dsthaswritebuf)
     && FD_ISSET(io->dst.s, wset))
   ||       ((FD_ISSET(io->dst.s, rset) || srchaswritebuf)
     && FD_ISSET(io->src.s, wset))
   ||       (io->control.s != -1 && FD_ISSET(io->control.s, rset)));

   /*
    * we are only called when we have i/o to do.
    * Could probably remove this gettimeofday() call too, but there are
    * platforms without SO_SNDLOWAT which prevents us.
    */
   gettimeofday(&timenow, NULL);
   if (io->state.time.firstio.tv_sec == 0
   && io->state.time.firstio.tv_usec == 0)
      io->state.time.firstio = timenow;

   switch (io->state.protocol) {
      case SOCKS_TCP: {
         size_t bufsize, bwused;
         int bad;

         if (io->rule.bw != NULL) {
            ssize_t left;

            if ((left = bw_left(io->rule.bw)) <= 0) {
               /*
                * update data (new time) so next bw_left() presumably
                * has some left.
                * No harm in calling bw_update() without le 0 check, but
                * maybe this is smarter (avoids extra lock in gt 0 case).
                */
               bw_update(io->rule.bw, 0, &timenow);
               left = bw_left(io->rule.bw);
            }

            if ((bufsize = MIN(sizeof(buf), (size_t)left)) == 0)
               break;
         }
         else
            bufsize = sizeof(buf);

         bwused = 0;

         /* from in to out ... */
         if ((FD_ISSET(io->src.s, rset) || dsthaswritebuf)
         && FD_ISSET(io->dst.s, wset)) {
            bad = -1;
            r = io_rw(&io->src, &io->dst, &bad, buf, bufsize, flags);
            if (bad != -1) {
               delete_io(mother, io, bad, r == 0 ? IO_CLOSE : IO_ERROR);
               return;
            }

            if (r == -1)
               r = 0; /* bad is not set, so temporary error. */

            iolog(&io->rule,
                  &io->state,
                  OPERATION_IO,
                  &io->src.laddr, 
                  &io->src.host,
                  &io->src.auth,
                  NULL,
                  NULL,
                  NULL,
                  &io->dst.laddr,
                  &io->dst.host,
                  &io->dst.auth,
                  io->state.proxyprotocol
                     == PROXY_DIRECT ? NULL : &io->state.proxychain.server,
                  io->state.proxyprotocol == PROXY_DIRECT
                     ? NULL : &io->state.proxychain.extaddr,
                  NULL,
                  buf,
                  r);

            bwused        += r;
            dsthaswritebuf = 0;
         }

         /* ... and out to in. */
#if 0
         /*
          * This doesn't work too good since we can end up doing i/o
          * only in -> out for a long time.  Also since we assume one
          * side is on the lan (where b/w isn't that critical)
          * and the other side is the net, assume some slack on
          * one side is ok.  Same applies to udp case.
          * Another option would be to alternate which direction we
          * do i/o on first each time, but we instead do the simple
          * thing and just don't subtract bufsize.
          */
         bufsize -= bwused;
#endif

         if (bufsize == 0) {
            BWUPDATE(io, timenow, bwused);
            break;
         }

         if ((FD_ISSET(io->dst.s, rset) || srchaswritebuf)
         && FD_ISSET(io->src.s, wset)) {
            bad = -1;
            r = io_rw(&io->dst, &io->src, &bad, buf, bufsize, flags);
            if (bad != -1) {
               delete_io(mother, io, bad, r == 0 ? IO_CLOSE : IO_ERROR);
               return;
            }

            if (r == -1) /* bad is not set, must be temporary error. */
               r = 0;

            iolog(&io->rule,
                  &io->state,
                  OPERATION_IO,
                  &io->dst.laddr,
                  &io->dst.host,
                  &io->dst.auth,
                  io->state.proxyprotocol
                     == PROXY_DIRECT ? NULL : &io->state.proxychain.server,
                  io->state.proxyprotocol == PROXY_DIRECT
                     ? NULL : &io->state.proxychain.extaddr,
                  NULL,
                  &io->src.laddr,
                  &io->src.host,
                  &io->src.auth,
                  NULL,
                  NULL,
                  NULL,
                  buf,
                  (size_t)r);

            bwused += r;
            srchaswritebuf = 0;
         }

         BWUPDATE(io, timenow, bwused);
         break;
      }

      case SOCKS_UDP: {
         session_t *ss = io->rule.ss;
         /*
          * This is the original session object, if any, allocated
          * when we got the request.  For udp, it does not make sense
          * to switch the session-object around depending on the rule
          * used for each packet.  We want it to operate on the
          * control-connection, not on each packet.  We therefor need
          * to save it and restore it after each rulespermit(), as we
          * want it to always refer to the session-object set up
          * for the original control-connection.
          *
          * This in contrast with the bandwidth and the redirect
          * objects, which operate on each packet.
          */
#if BAREFOOTD
         struct udpclient *udpclient;
#endif /* BAREFOOTD */
         struct udpheader_t header;
         socklen_t len;
         int permit;

         /*
          * One side of the udp i/o is always fixed; the socks-client side.
          * The other side can vary for each packet.
          *
          * This makes udp i/o more complicated in the socks case, compared to
          * tcp, as we  may need to check rules on each packet if the
          * destination changes from one packet to the next.
          */

         /*
          * We are less strict about bandwidth in the udp case since we
          * don't want to truncate packets.  Therefore we don't limit
          * the amount of i/o we do in one go for the udp-case; it has to
          * be whole packets.
          *
          * Now that we have a iobuffer, we could in theory check if
          * we have enough bandwidth allocated to send the packet, and
          * if not, wait til later, but don't bother for now.
          */

         /*
          * UDP to relay from client to destination?
          * Note that here io->dst can vary for each packet, unless
          * we're barefootd.
          */
         if ((FD_ISSET(io->src.s, rset) || dsthaswritebuf)
         && FD_ISSET(io->dst.s, wset)) {
            /*
             * io->src is src of packet.
             * io->dst is dst of packet.
             */
            const int lflags = flags & ~MSG_OOB;
            struct sockaddr from;
            size_t bwused;

            len = sizeof(from);
            if ((r = socks_recvfrom(io->src.s, buf, sizeof(buf), lflags,
            &from, &len, &io->src.auth)) == -1) {
               if (ERRNOISTMP(errno) || errno == ECONNREFUSED) {
                  if (errno == ECONNREFUSED)
                     iolog(&io->rule,
                           &io->state,
                           OPERATION_TMPERROR,
                           &io->dst.laddr,
                           &io->dst.host,
                           &io->dst.auth,
                           io->state.proxyprotocol == PROXY_DIRECT ?
                              NULL : &io->state.proxychain.server,
                           io->state.proxyprotocol == PROXY_DIRECT
                              ? NULL : &io->state.proxychain.extaddr,
                           NULL,
                           &io->src.laddr,
                           &io->src.host,
                           &io->src.auth,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           0);
                  else
                     iolog(&io->rule,
                           &io->state,
                           OPERATION_TMPERROR,
                           &io->src.laddr,
                           &io->src.host,
                           &io->src.auth,
                           NULL,
                           NULL,
                           NULL,
                           &io->dst.laddr,
                           &io->dst.host,
                           &io->dst.auth,
                           io->state.proxyprotocol == PROXY_DIRECT
                              ? NULL : &io->state.proxychain.server,
                           io->state.proxyprotocol == PROXY_DIRECT
                              ? NULL : &io->state.proxychain.extaddr,
                           NULL,
                           NULL,
                           0);

                  return;
               }

               /* else: unknown error, assume fatal. */
               delete_io(mother, io, io->src.s, IO_ERROR);
               return;
            }

#if SOCKS_SERVER
            if (!ADDRISBOUND(TOIN(&io->src.raddr))
            ||  !PORTISBOUND(TOIN(&io->src.raddr))) {
               /*
                * Client hasn't sent us it's address yet, so we have
                * to assume this packet is from it.  We then connect
                * the socket for better performance, for receiving errors
                * from sendto() if the clients is not there/goes away,
                * for getpeername() (libwrap in rulespermit()), for ...
                * that's reason enough.
                */
               struct connectionstate_t rstate;
               struct authmethod_t      replyauth;

               UDPFROMLENCHECK(io->src.s, len);

               if (!ADDRISBOUND(TOIN(&io->src.raddr)))
                  TOIN(&io->src.raddr)->sin_addr.s_addr
                  = TOIN(&from)->sin_addr.s_addr;

               if (!PORTISBOUND(TOIN(&io->src.raddr)))
                  TOIN(&io->src.raddr)->sin_port = TOIN(&from)->sin_port;

               if (!sockaddrareeq(&io->src.raddr, &from)) {
                  char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];

                  /* XXX can we change this to iolog()? */
                  slog(LOG_INFO, "%s(0): %s: expected udp packet from %s, but"
                                 "got it from %s",
                  VERDICT_BLOCKs, protocol2string(io->state.protocol),
                  sockaddr2string(&io->src.raddr, src, sizeof(src)),
                  sockaddr2string(&from, dst, sizeof(dst)));

                  break;
               }


               slog(LOG_DEBUG, "%s: first udp packet from previously "
                               "unconnected socks client.  Connecting to"
                               "client at address %s",
               function, sockaddr2string(&io->src.raddr, NULL, 0));

               sockaddr2sockshost(&io->src.raddr, &io->src.host);
               if (connect(io->src.s, &io->src.raddr, sizeof(io->src.raddr))
               != 0) {
                  delete_io(mother, io, io->src.s, IO_ERROR);
                  return;
               }

               rstate           = io->state;
               rstate.command   = SOCKS_UDPREPLY;
               replyauth.method = AUTHMETHOD_NOTSET;

               permit = rulespermit(io->control.s,
                                    &io->control.raddr,
                                    &io->control.laddr,
                                    &io->clientauth,
                                    &io->rule,
                                    &io->src.auth,
                                    &io->state,
                                    &io->src.host,
                                    NULL,
                                    NULL,
                                    0)
               ||       rulespermit(io->control.s,
                                    &io->control.raddr,
                                    &io->control.laddr,
                                    &io->clientauth,
                                    &io->rule,
                                    &replyauth,
                                    &rstate,
                                    NULL,
                                    &io->src.host,
                                    NULL,
                                    0);
               io->rule.ss = ss;

               if (!permit) {
                  /*
                   * can't send anywhere, can't receive from anyone; drop it.
                   */
                  delete_io(mother, io, io->src.s, IO_SRCBLOCK);
                  return;
               }
            }

            io->src.read.bytes += r;
            ++io->src.read.packets;
#endif /* SOCKS_SERVER */

#if BAREFOOTD
            /*
             * no socks header.  Dst must always be bounce_to, but src varies.
             */

            bzero(&header, sizeof(header));
            ruleaddr2sockshost(&io->rule.bounce_to, &header.host, SOCKS_UDP);
            sockaddr2sockshost(&from, &io->src.host);
#else /* SOCKS_SERVER */

            /* got packet, pull out socks UDP header. */
            if (string2udpheader(buf, (size_t)r, &header) == NULL) {
               char badfrom[MAXSOCKADDRSTRING];

               swarnx("%s: bad socks udp packet (length = %u) from %s",
               function, (unsigned)r, sockaddr2string(&io->src.raddr, badfrom,
               sizeof(badfrom)));

               break;
            }

            if (header.frag != 0) {
               char badfrom[MAXSOCKADDRSTRING];

               swarnx("%s: %s: fragmented udp packet from %s.  Not supported",
               function, protocol2string(io->state.protocol),
               sockaddr2string(&io->src.raddr, badfrom, sizeof(badfrom)));

               break;
            }
#endif /* SOCKS_SERVER */

            /*
             * A slight optimization.  If the client will only be
             * sending udp packets to one address, it is much more
             * efficient to connect the socket to that address.
             *
             * However, because we do that, we must be sure to unconnect
             * the socket before sending out on it again if the client wants
             * to send to a new address, and from that point on, leave the
             * socket unconnected.
             */

#if BAREFOOTD
            if ((io->dst.s = socketofudpraddr(&from, io->dstc, io->dstv))
            == -1) {
               struct udpclient udpsrc;

               bzero(&udpsrc, sizeof(udpsrc));
#else /* SOCKS_SERVER */

            if (sockscf.option.udpconnectdst
            && !ADDRISBOUND(TOIN(&io->dst.raddr))) {
#endif /* SOCKS_SERVER */

               /*
                * First packet.  
                */
#if BAREFOOTD
               char tostr[MAXSOCKSHOSTSTRING];
#endif /* BAREFOOTD */

               io->dst.host = header.host;
               sockshost2sockaddr(&io->dst.host, &io->dst.raddr);

#if BAREFOOTD
               /*
                * Create a new socket and use that for sending out
                * packets from this client only.  When reading replies on
                * this socket, we will thus know who it's destined for (from).
                */
               if ((io->dst.s = udpsrc.s = socket(AF_INET, SOCK_DGRAM, 0))
               == -1) {
                  swarn("%s: no more sockets available", function);
                  return;
               }

               setsockoptions(udpsrc.s);
               udpsrc.laddr = io->dst.laddr;
               TOIN(&udpsrc.laddr)->sin_port = htons(0);
               if (sockd_bind(udpsrc.s, &udpsrc.laddr, 0) != 0)
                  swarn("%s: sockd_bind(udpsrc.s)", function);

               len = sizeof(udpsrc.laddr);
               if (getsockname(udpsrc.s, &udpsrc.laddr, &len) != 0)
                  swarn("%s: getsockname(udpsrc.s)", function);
               else
                  slog(LOG_DEBUG, "%s: address bound for udp socket %d: %s",
                  function, udpsrc.s, sockaddr2string(&udpsrc.laddr, NULL, 0));

               udpsrc.raddr  = from;
               udpsrc.iotime = timenow;
               if ((udpclient = addudpclient(&udpsrc, &io->dstc, &io->dstcmax,
               &io->dstv)) == NULL) {
                  swarn("%s: no more udp clients can be accepted (compile-time "
                        "limit).  Client from %s dropped.  "
                        "Increase BAREFOOTD_UDPCLIENTMAX and recompile",
                        function, sockaddr2string(&from, NULL, 0));

                  return;
               }
#endif /* BAREFOOTD */

               permit = rulespermit(io->control.s,
                                    &io->control.raddr,
                                    &io->control.laddr,
                                    &io->clientauth,
                                    &io->rule,
                                    &io->src.auth,
                                    &io->state,
                                    &io->src.host,
                                    &io->dst.host,
                                    NULL,
                                    0);
               io->rule.ss = ss;

               /* connect to redirected-to address, if applicable. */
               if (permit)
                  redirect(io->dst.s, &io->dst.laddr, &io->dst.host,
                  io->state.command, &io->rule.rdr_from, &io->rule.rdr_to);

#if BAREFOOTD
               if (permit && io->rule.ss != NULL) {
                  if (!session_use(io->rule.ss)) {
                     permit           = 0;
                     io->rule.verdict = VERDICT_BLOCK;
                     io->rule.ss      = NULL;

                     snprintf(buf, sizeof(buf), DENY_SESSIONLIMITs);

                     iolog(&io->rule,
                           &io->state,
                           OPERATION_CONNECT,
                           &io->src.laddr,
                           &io->src.host,
                           &io->src.auth,
                           NULL,
                           NULL,
                           NULL,
                           &io->dst.laddr,
                           &io->dst.host,
                           &io->dst.auth,
                           io->state.proxyprotocol == PROXY_DIRECT
                              ? NULL : &io->state.proxychain.server,
                           io->state.proxyprotocol == PROXY_DIRECT
                              ? NULL : &io->state.proxychain.extaddr,
                           NULL,
                           buf,
                           0);

                     removeudpclient(udpclient->s, &io->dstc, iov->dstv);
                     return;
                  }
               }

               if (permit && sockscf.option.udpconnectdst) {
                  slog(LOG_DEBUG, "%s: first udp packet from %s.  "
                                  "Connecting socket to %s",
                  function,
                  sockshost2string(&io->src.host, NULL, 0),
                  sockshost2string(&io->dst.host, tostr, sizeof(tostr)));

                  socks_connecthost(io->dst.s, &io->dst.host);
                  io->dst.state.connected = 1;
               }
#endif /* BAREFOOTD */
            }
            else { /* not first packet from this client. */
#if BAREFOOTD
               udpclient = udpclientofsocket(io->dst.s, io->dstc, io->dstv);
               SASSERTX(udpclient != NULL);
#endif /* BAREFOOTD */

               /*
                * the check against INADDR_ANY guarantees this is not the
                * first packet and thus dst.host, containing the dst of
                * the previous packet, can meaningfully be compared to see
                * if it matches the new destination.  If it does, we can
                * skip the rulespermit() check.
                */
               if ((io->dst.host.atype            != SOCKS_ADDR_IPV4
               ||   io->dst.host.addr.ipv4.s_addr != htonl(INADDR_ANY))
               && sockshostareeq(&header.host, &io->dst.host)) {
                  permit = io->rule.verdict == VERDICT_PASS;

                  slog(LOG_DEBUG, "%s: reusing old verdict, permit = %d",
                  function, permit);
               }
               else {
                  /*
                   * this packet does not have the same destination as the
                   * previous one.
                   * If the socket is connected, we need to unconnect it,
                   * or we can't receive further replies from the previous
                   * destination.  Check that a redirect() does not change
                   * it back to what we used last time though.
                   */

                  permit = rulespermit(io->control.s,
                                       &io->control.raddr,
                                       &io->control.laddr,
                                       &io->clientauth,
                                       &io->rule,
                                       &io->src.auth,
                                       &io->state,
                                       &io->src.host,
                                       &header.host,
                                       NULL,
                                       0);

                  io->rule.ss = ss;

                  if (redirect(io->dst.s, &io->dst.laddr, &header.host,
                  io->state.command, &io->rule.rdr_from, &io->rule.rdr_to)
                  != 0) {
                     swarn("%s: redirect()", function);
                     break;
                  }

                  if (io->dst.state.connected)  {
                     if (!sockshostareeq(&header.host, &io->dst.host)) {
                        /* still not same, must be new host then.  Unconnect. */
                        socks_unconnect(io->dst.s);
                        io->dst.state.connected = 0;
                     }
                  }

                  io->dst.host = header.host;
                  sockshost2sockaddr(&io->dst.host, &io->dst.raddr);
               }
            }

            if (io->rule.bw != NULL)
               bw_use(io->rule.bw);

#if SOCKS_SERVER
            /* set r to bytes sent by client sans socks UDP header. */
            r -= PACKETSIZE_UDP(&header);
#endif /* SOCKS_SERVER */

#if BAREFOOTD
            udpclient->src_read.bytes += r;
            ++udpclient->src_read.packets;
#endif /* BAREFOOTD */

            if (!permit) {
               iolog(&io->rule,
                     &io->state,
                     OPERATION_IO,
                     &io->src.laddr,
                     &io->src.host,
                     &io->src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &io->dst.laddr,
                     &io->dst.host,
                     &io->dst.auth,
                     io->state.proxyprotocol == PROXY_DIRECT
                        ?  NULL : &io->state.proxychain.server,
                     io->state.proxyprotocol == PROXY_DIRECT
                        ? NULL : &io->state.proxychain.extaddr,
                     NULL,
#if BAREFOOTD
                     buf,
#else /* SOCKS_SERVER */
                     &buf[PACKETSIZE_UDP(&header)],
#endif /* SOCKS_SERVER */
                     (size_t)r);

               bw_unuse(io->rule.bw);
               break;
            }

            iolog(&io->rule,
                  &io->state,
                  OPERATION_IO,
                  &io->src.laddr, 
                  &io->src.host,
                  &io->src.auth,
                  NULL,
                  NULL,
                  NULL,
                  &io->dst.laddr,
                  &io->dst.host,
                  &io->dst.auth,
                  io->state.proxyprotocol == PROXY_DIRECT
                     ? NULL : &io->state.proxychain.server,
                  io->state.proxyprotocol == PROXY_DIRECT
                     ? NULL : &io->state.proxychain.extaddr,
                  NULL,
#if BAREFOOTD
                  buf,
#else /* SOCKS_SERVER */
                  &buf[PACKETSIZE_UDP(&header)],
#endif /* SOCKS_SERVER */
                  (size_t)r);

            sockshost2sockaddr(&io->dst.host, &io->dst.raddr);

            if ((w = socks_sendto(io->dst.s,
#if BAREFOOTD
            buf,
#else /* SOCKS_SERVER */
            &buf[PACKETSIZE_UDP(&header)],
#endif /* SOCKS_SERVER */
            (size_t)r, lflags, &io->dst.raddr, sizeof(io->dst.raddr),
            &io->dst.auth)) != r)
               iolog(&io->rule,
                     &io->state,
                     OPERATION_ERROR,
                     &io->src.laddr,
                     &io->src.host,
                     &io->src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &io->dst.laddr,
                     &io->dst.host,
                     &io->dst.auth,
                     io->state.proxyprotocol == PROXY_DIRECT
                        ? NULL : &io->state.proxychain.server,
                     io->state.proxyprotocol == PROXY_DIRECT
                        ? NULL : &io->state.proxychain.extaddr,
                     NULL,
                     NULL,
                     0);

#if SOCKS_SERVER
            io->dst.written.bytes += MAX(0, w);
            if (w >= 0)
               ++io->dst.written.packets;
#else /* BAREFOOTD */
            udpclient->dst_written.bytes += MAX(0, w);
            if (w >= 0)
               ++udpclient->dst_written.packets;
#endif /* BAREFOOTD */

            bwused = MAX(0, w);
            BWUPDATE(io, timenow, bwused);
            bw_unuse(io->rule.bw);

#if BAREFOOTD
            if (bwused) {
               struct udpclient *udpclient;

               udpclient = udpclientofsocket(io->dst.s, io->dstc, io->dstv);
               SASSERTX(udpclient != NULL);
               udpclient->iotime = timenow;
            }
#endif /* BAREFOOTD */

         }

         /*
          * Datagram reply from remote present?
          */

#if 0 /* see comment for tcp case. */
         if (bwused >= io->rule.bw->maxbps)
            break;
#endif

         if ((FD_ISSET(io->dst.s, rset) || srchaswritebuf)
         && FD_ISSET(io->src.s, wset)) {
            /*
             * io->dst is src of packet, and can vary for each packet.
             * io->src is dst of packet (socks client).
             */
            const int lflags = flags & ~MSG_OOB;
            struct connectionstate_t replystate;
            struct sockaddr rfrom;
            struct sockshost_t replyto;
            char *newbuf;
            size_t bwused;
            int redirected;

            if (io->dst.state.connected && io->dst.read.bytes != 0) {
               /*
                * connected and not first reply -> rule must have been
                * matched previously, so reuse it.
                */
               permit              = io->replyrule.verdict == VERDICT_PASS;
               replystate          = io->state;
               replystate.command  = SOCKS_UDPREPLY;
            }
            else {
               /*
                * Is the reply allowed back in?
                *
                * We first peek at it so we can find out what address it's
                * from.  Then we check rules and then we drain the socket
                * buffer.
                * The reason why we need to peek first is that if the rule
                * calls libwrap, libwrap would hang since we'd already read
                * the packet and libwrap also wants to peek.
                */

               len = sizeof(rfrom);
               if ((r = socks_recvfrom(io->dst.s, buf, 1, lflags | MSG_PEEK,
               &rfrom, &len, &io->dst.auth)) == -1) {
                  if (ERRNOISTMP(errno) || errno == ECONNREFUSED) {
                     if (errno == ECONNREFUSED)
                        /*
                         * means the error is actually from our write
                         * to this destination
                         */
                        iolog(&io->rule,
                              &io->state,
                              OPERATION_TMPERROR,
                              &io->src.laddr,
                              &io->src.host,
                              &io->src.auth,
                              NULL,
                              NULL,
                              NULL,
                              &io->dst.laddr,
                              &io->dst.host,
                              &io->dst.auth,
                              io->state.proxyprotocol == PROXY_DIRECT
                                 ? NULL : &io->state.proxychain.server,
                              io->state.proxyprotocol == PROXY_DIRECT
                                 ? NULL : &io->state.proxychain.extaddr,
                              NULL,
                              NULL,
                              0);
                     else
                        iolog(&io->rule,
                              &io->state,
                              OPERATION_TMPERROR,
                              &io->dst.laddr,
                              &io->dst.host,
                              &io->dst.auth,
                              io->state.proxyprotocol == PROXY_DIRECT
                                 ? NULL : &io->state.proxychain.server,
                              io->state.proxyprotocol == PROXY_DIRECT
                                 ? NULL : &io->state.proxychain.extaddr,
                              NULL,
                              &io->src.laddr,
                              &io->src.host,
                              &io->src.auth,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              0);
                  }
                  else /* unknown error, assume fatal. */
                     delete_io(mother, io, io->src.s, IO_ERROR);

                  return;
               }

               UDPFROMLENCHECK(io->dst.s, len);

               sockaddr2sockshost(&rfrom, &io->dst.host);

               replystate          = io->state;
               replystate.command  = SOCKS_UDPREPLY;
               bzero(&io->dst.auth, sizeof(io->dst.auth));
               io->dst.auth.method = AUTHMETHOD_NOTSET;

               permit = rulespermit(io->control.s,
                                    &io->control.raddr,
                                    &io->control.laddr,
                                    &io->clientauth,
                                    &io->replyrule,
                                    &io->dst.auth,
                                    &replystate,
                                    &io->dst.host,
                                    &io->src.host,
                                    NULL,
                                    0);

               io->rule.ss = ss;
            }

#if BAREFOOTD
            udpclient = udpclientofsocket(io->dst.s, io->dstc, io->dstv);
            SASSERTX(udpclient != NULL);
#endif /* BAREFOOTD */

            if (io->replyrule.bw != NULL)
               bw_use(io->replyrule.bw);

            /* read the (possibly peeked at) packet. */
            if ((r = socks_recvfrom(io->dst.s, buf, sizeof(buf), lflags,
            &rfrom, &len, &io->dst.auth)) == -1) {
               bw_unuse(io->rule.bw);
               delete_io(mother, io, io->dst.s, IO_ERROR);
               return;
            }

            bwused = r;

#if SOCKS_SERVER
            io->dst.read.bytes += r;
            ++io->dst.read.packets;
#else /* BAREFOOTD */
            udpclient->dst_read.bytes += r;
            ++udpclient->dst_read.packets;
#endif /* BAREFOOTD */

            iolog(&io->replyrule,
                  &replystate,
                  OPERATION_IO,
                  &io->dst.laddr,
                  &io->dst.host,
                  &io->dst.auth,
                  io->state.proxyprotocol == PROXY_DIRECT
                     ? NULL : &io->state.proxychain.server,
                  io->state.proxyprotocol == PROXY_DIRECT
                     ? NULL : &io->state.proxychain.extaddr,
                  NULL,
                  &io->src.laddr,
                  &io->src.host,
                  &io->src.auth,
                  NULL,
                  NULL,
                  NULL,
                  buf,
                  (size_t)r);

            if (!permit) {
               bw_unuse(io->replyrule.bw);
               break;
            }

            replyto = io->src.host;
            if (redirect(io->src.s, &rfrom, &replyto, replystate.command,
            &io->replyrule.rdr_from, &io->replyrule.rdr_to) != 0) {
               swarn("%s: redirect()", function);
               bw_unuse(io->replyrule.bw);
               break;
            }

            if (!sockshostareeq(&replyto, &io->src.host)) {
               char oldto[MAXSOCKSHOSTSTRING], newto[MAXSOCKSHOSTSTRING];

               slog(LOG_DEBUG, "%s: need to redirect reply, unconnecting socket"
                               " temporarily from %s for redirecting to %s ...",
               function,
               sockshost2string(&io->src.host, oldto, sizeof(oldto)),
               sockshost2string(&replyto, newto, sizeof(newto)));

               if (socks_unconnect(io->src.s) != 0) {
                  swarn("%s: socks_unconnect()", function);
                  bw_unuse(io->replyrule.bw);
                  break;
               }

               redirected = 1;
            }
            else
               redirected = 0;

            /* in case redirect() changed it . */
            sockaddr2sockshost(&rfrom, &replyto);

#if BAREFOOTD
            newbuf = buf;
#else /* SOCKS_SERVER; add socks UDP header.  */
            newbuf
            = udpheader_add(&io->dst.host, buf, (size_t *)&r, sizeof(buf));
            SASSERTX(newbuf == buf);
#endif /* SOCKS_SERVER */

            if ((w = socks_sendto(io->src.s, newbuf, (size_t)r, lflags,
#if BAREFOOTD /* never connected. */
            (struct sockaddr *)&udpclient->raddr, sizeof(udpclient->raddr),
#else /* SOCKS_SERVER: always connected. */
            NULL, 0,
#endif /* SOCKS_SERVER */
            &io->src.auth)) != r)
               iolog(&io->replyrule,
                     &replystate,
                     OPERATION_ERROR,
                     &io->dst.laddr,
                     &io->dst.host,
                     &io->dst.auth,
                     io->state.proxyprotocol == PROXY_DIRECT
                        ? NULL : &io->state.proxychain.server,
                     io->state.proxyprotocol == PROXY_DIRECT
                        ? NULL : &io->state.proxychain.extaddr,
                     NULL,
                     &io->src.laddr,
                     &io->src.host,
                     &io->src.auth,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     0);

            BWUPDATE(io, timenow, bwused);
            bw_unuse(io->replyrule.bw); /* packet-by-packet. */

#if SOCKS_SERVER
            io->src.written.bytes += MAX(0, w);
            if (w >= 0)
               ++io->src.written.packets;
#else /* BAREFOOTD */
            udpclient->src_written.bytes += MAX(0, w);
            if (w >= 0)
               ++udpclient->src_written.packets;
#endif /* BAREFOOTD */

            if (redirected) /* connect back to client. */
               if (connect(io->src.s, &io->src.raddr, sizeof(io->src.raddr))
               != 0) {
                  delete_io(mother, io, io->src.s, IO_ERROR);
                  return;
               }

            if (w == -1) {
               delete_io(mother, io, io->src.s, IO_ERROR);
               return;
            }
         }

         break;
      }

      default:
         SERRX(io->state.protocol);
   }

   /*
    * Only thing we expect from client's control connection is an eof.
    * For commands that do not have a control connection, we set it
    * to -1 when receiving the others.
    */

   if (io->control.s != -1 && FD_ISSET(io->control.s, rset)) {
      if ((r = read(io->control.s, buf, sizeof(buf))) <= 0)
         delete_io(mother, io, io->control.s, r == 0 ? IO_CLOSE : IO_ERROR);
      else {
         char controladdr[MAXSOCKADDRSTRING], visbuf[256];

         slog(LOG_NOTICE, "%s/control: %ld unexpected byte%s: %s",
         sockaddr2string(&io->control.raddr, controladdr,
         sizeof(controladdr)), (long)r, r == 1 ? "" : "s",
         str2vis(buf, r, visbuf, sizeof(visbuf)));
      }
   }
}

static int
io_rw(in, out, bad, buf, bufsize, flag)
   struct sockd_io_direction_t *in;
   struct sockd_io_direction_t *out;
   int *bad;
   void *buf;
   size_t bufsize;
   int flag;
{
   const char *function = "io_rw()";
   const int sv[] = { in->s, out->s };
   ssize_t r, w, p;
   int allflushed;

   slog(LOG_DEBUG, "%s: %d -> %d, bufsize = %lu, flag = %d",
   function, in->s, out->s, (long unsigned)bufsize, flag);

   /*
    * If we have previously tried to write to in our out, but could not
    * write all, we will have data buffered for the socket. In that case
    * we need to flush the buffer before writing anything else.  Since
    * that data has already been logged as written, don't log it again.
    */
   for (p = 0, allflushed = 1; p < (ssize_t)ELEMENTS(sv); ++p)
      if ((w = socks_flushbuffer(sv[p], -1)) == -1) {
         if (!ERRNOISTMP(errno))
            *bad = sv[p];

         allflushed = 0;
      }

   if (!allflushed)
      return -1;

   /*
    * We receive OOB in-line.  If flag has MSG_OOB set, it means we
    * are at the OOB marker.  The next byte we read (and it will be
    * only one) is the OOB byte, and since we receive it in-line,
    * we should turn off the MSG_OOB flag.
    *
    * When we write the data we will keep the MSG_OOB flag, and
    * hopefully that will work even if the write is combined with
    * data read from the buffer (so we send more than one byte), with
    * the last byte, which we will now read, being tagged as the
    * "oob" data.  Possible this will not work 100% correctly on
    * some non-BSD implementations, but go with it for now.
    */
   if (flag & MSG_OOB) {
      if (sockatmark(in->s) != 1)
         flag &= ~MSG_OOB;
      else
         slog(LOG_DEBUG, "%s: have OOB data", function);
   }

   /*
    * read data from in ...
    */


   /*
    * never read more from in than we can write to out, buffer included.
    */
   p = MIN(bufsize, socks_freeinbuffer(out->s, WRITE_BUF));

#if HAVE_GSSAPI
   /*
    * If the data we are writing needs to be gssapi-encapsulated,
    * also make sure we don't read more than we can encapsulate in
    * a gssapi token; we don't want to deal with "segmentation" of
    * gssapi tokens.
    */
   if (out->auth.method == AUTHMETHOD_GSSAPI)
      p = MIN(p, (ssize_t)out->maxgssdata);
#endif /* HAVE_GSSAPI */

   if ((r = socks_recvfrom(in->s, buf, p, flag & ~MSG_OOB, NULL, NULL,
   &in->auth)) <= 0) {
      if (r == 0) {
         /*
          * FIN from "in".  It won't send us any more data, so
          * we shutdown "out" for writing to let it know.
          *
          * When "out" has nothing more to send, it will send us a
          * FIN too, and we will shutdown "in" for writing.
          * At that point, both "in" and "out" have sent a FIN,
          * meaning none of them will send us any more data.
          * Only then can we close the socket.  Since we may clear
          * state.fin however, state.shutdown should be used
          * for testing here.
          *
          */

         slog(LOG_DEBUG, "%s: got EOF on in->s (%d)", function, in->s);
         in->state.fin = 1;

         SASSERTX(socks_bytesinbuffer(out->s, WRITE_BUF, 0)  == 0);

         if (in->state.shutdown_wr) /* have already received FIN from out. */
            *bad = out->s; /* done with this socket, "out" closed first. */

         if (!out->state.shutdown_wr) {
            /*
             * use shutdown() to forward FIN, but continue reading.
             */
            slog(LOG_DEBUG, "%s: shutting down out->s (%d) for writing",
            function, out->s);

            if (shutdown(out->s, SHUT_WR) != 0)
               swarn("%s: shutdown()", function);
            else
               out->state.shutdown_wr = 1;
         }
      }
      else if (!ERRNOISTMP(errno))
         *bad = in->s;

      return r;
   }

   in->read.bytes += r;

   slog(LOG_DEBUG, "%s: read %ld", function, (long)r);

   if (flag & MSG_OOB)
      in->flags |= MSG_OOB;   /* read oob data.            */
   else
      in->flags &= ~MSG_OOB;  /* did not read oob data.   */

   /*
    * ... and send the data read to out.
    */

   if ((w = socks_sendto(out->s, buf, (size_t)r, flag, NULL, 0, &out->auth))
   > 0)
      out->written.bytes += w;

   if (w != r) {
      if (w == -1)
         *bad = out->s;
      else {
         /*
          * should not happen.  Should never read more than we can write.
          */
         swarnx("%s: w = %ld, r = %ld", function, (long)w, (long)r);
         SERRX(w);
      }
   }

   /*
    * we want to select for read again on socket we sent data out on,
    * regardless of whether we have received a FIN from it, to get
    * write errors.
    *
    * Unfortunately, there's no way to make select() not keep
    * returning ready-for-read once the client has sent the FIN,
    * and we do not want to busy-loop around this.  What we would want,
    * is to only select for error on the socket after we receive
    * a FIN.
    * Best we can do is to let io_fillset() skip sockets that
    * have state.fin set, and reset state.fin if we send data on on the
    * socket, hoping to catch any pending errors on second go round.
    * This means some sessions can occupy space for a long time, until
    * tcp keep-alive check kicks in.
    */
   out->state.fin = 0;

   return w;
}

static void
proctitleupdate(void)
{

   setproctitle("iorelayer: %lu/%d",
   (unsigned long)io_allocated(NULL, NULL), SOCKD_IOMAX);
}

static struct sockd_io_t *
io_getset(nfds, set)
   const int nfds;
   const fd_set *set;
{
   struct sockd_io_t *best, *evaluating;
   size_t i;
   int s;

   for (s = 0, best = NULL; s < nfds; ++s) {
      if (!FD_ISSET(s, set))
         continue;

      /*
       * find the io d is part of.
       */

      for (i = 0, evaluating = NULL; i < ioc; ++i) {
         if (!iov[i].allocated)
            continue;

         if (s == iov[i].src.s) {
            evaluating = &iov[i];
            break;
         }
         else if (s == iov[i].dst.s) {
            evaluating = &iov[i];
            break;
         }
         else {
            switch (iov[i].state.command) {
               case SOCKS_BIND:
               case SOCKS_BINDREPLY:
                  if (iov[i].state.extension.bind && s == iov[i].control.s)
                     evaluating = &iov[i];
                  break;

               case SOCKS_UDPASSOCIATE:
                  if (s == iov[i].control.s)
                     evaluating = &iov[i];
#if BAREFOOTD
                  else if (srcofudpsocket(s, iov[i].dstc, iov[i].dstv) != NULL)
                     evaluating = &iov[i];
#endif /* BAREFOOTD */
                  break;

               default:
                  break;
            }

            if (evaluating != NULL)
               break;
         }
      }

      SASSERTX(evaluating != NULL);

      /* select the i/o that has least recently done i/o. */
      if (best == NULL || timercmp(&evaluating->iotime, &best->iotime, <))
         best = evaluating;
   }

   return best;
}

static struct sockd_io_t *
io_finddescriptor(d)
   int d;
{
   size_t i;

   for (i = 0; i < ioc; ++i)
      if (iov[i].allocated) {
         if (d == iov[i].src.s || d == iov[i].dst.s) {

#if BAREFOOTD
            if (d == iov[i].src.s
            && iov[i].state.command == SOCKS_UDPASSOCIATE)
               iov[i].dst.s = iov[i].dstv[0].s; /* dummy socket. */
#endif /* BAREFOOTD */
            return &iov[i];
         }

         switch (iov[i].state.command) {
            case SOCKS_BIND:
            case SOCKS_BINDREPLY:
               if (!iov[i].state.extension.bind)
                  break;
               /* else: */ /* FALLTHROUGH */

            case SOCKS_UDPASSOCIATE:
#if BAREFOOTD
               if (srcofudpsocket(d, iov[i].dstc, iov[i].dstv) != NULL) {
                  iov[i].dst.s = d;
                  return &iov[i];
               }
#else
               if (d == iov[i].control.s)
                  return &iov[i];
#endif /* BAREFOOTD */
               break;

            default:
               break;
         }
      }

   return NULL;
}

static int
io_fillset(set, antiflags, timenow)
   fd_set *set;
   int antiflags;
   const struct timeval *timenow;
{
/*   const char *function = "io_fillset()"; */
   size_t i;
   int max;

   FD_ZERO(set);

   for (i = 0, max = -1; i < ioc; ++i) {
      struct sockd_io_t *io = &iov[i];

      if (io->allocated) {
         if (io->rule.bw != NULL) {
            struct timeval new_bwoverflow;

            if (bw_isoverflow(io->rule.bw, timenow, &new_bwoverflow) != NULL) {
               if (!timerisset(&bwoverflow)
               ||  timercmp(&new_bwoverflow, &bwoverflow, <))
                  bwoverflow = new_bwoverflow;

               /*
                * this also means we won't catch errors on this
                * client for the duration.  Hopefully not a problem.
                */
               continue;
            }
         }

         if (!io->src.state.fin && !(antiflags & io->src.flags)) {
            FD_SET(io->src.s, set);
            max = MAX(max, io->src.s);
         }

         if (!io->dst.state.fin && !(antiflags & io->dst.flags)) {
#if BAREFOOTD
            if (io->state.command == SOCKS_UDPASSOCIATE) {
               size_t i;

               for (i = 0; i < io->dstc; ++i) {
                  FD_SET(io->dstv[i].s, set);
                  max = MAX(max, io->dstv[i].s);
               }
            }
            else {
               FD_SET(io->dst.s, set);
               max = MAX(max, io->dst.s);
            }
#else /* SOCKS_SERVER */
            FD_SET(io->dst.s, set);
            max = MAX(max, io->dst.s);
#endif /* SOCKS_SERVER */
         }

#if SOCKS_SERVER
         switch (io->state.command) {
            case SOCKS_BIND:
            case SOCKS_BINDREPLY:
               if (!io->state.extension.bind)
                  break;
               /* else: */ /* FALLTHROUGH */

            case SOCKS_UDPASSOCIATE:
               if (!(antiflags & io->control.flags)) {
                  FD_SET(io->control.s, set);
                  max = MAX(max, io->control.s);
               }
               break;

            default:
               break;
         }
#endif /* SOCKS_SERVER */
      }
   }

   return max;
}

static struct timeval *
io_gettimeout(timeout, timenow)
   struct timeval *timeout;
   const struct timeval *timenow;
{
   const char *function = "io_gettimeout()";
   size_t i, haveio;

   if (io_allocated(NULL, NULL) == 0)
      return NULL;

   if (sockscf.timeout.tcpio == 0 && sockscf.timeout.udpio == 0
   && !timerisset(&bwoverflow))
      return NULL;

   timeout->tv_sec  = MAX(sockscf.timeout.tcpio, sockscf.timeout.udpio);
   timeout->tv_usec = 0;

   haveio = 0;
   if (timerisset(timeout)) { /* iotimeout set. */
      for (i = 0; i < ioc; ++i) {
         if (timeout->tv_sec <= 0)  {
            timeout->tv_sec = 0;
            break; /* at or past timeout already, don't look further. */
         }

         if (!iov[i].allocated)
            continue;

         if (iov[i].state.protocol == SOCKS_UDP) {
            if (sockscf.timeout.udpio == 0)
               continue;
         }
         else { /* TCP */
            if (sockscf.timeout.tcpio == 0)
               continue;
         }

         if (timenow->tv_sec < iov[i].iotime.tv_sec) {
            slog(LOG_DEBUG, "%s: clock was stepped backwards?", function);
            iov[i].iotime.tv_sec = timenow->tv_sec;
         }

#if BAREFOOTD
         if (iov[i].state.protocol == SOCKS_UDP) {
            size_t ii;

            for (ii = 1; ii < iov[i].dstc; ++ii) {
               struct udpclient *udpclient = &iov[i].dstv[ii];

               timeout->tv_sec
               = MIN(timeout->tv_sec,
                      (ssize_t)sockscf.timeout.udpio
                      - (timenow->tv_sec - udpclient->iotime.tv_sec));

               haveio = 1;
            }

            continue;
         }
         else
#endif /* BAREFOOTD */

         timeout->tv_sec = MIN(timeout->tv_sec,
         (iov[i].state.protocol == SOCKS_TCP ?
         (ssize_t)sockscf.timeout.tcpio : (ssize_t)sockscf.timeout.udpio)
         - (timenow->tv_sec - iov[i].iotime.tv_sec));

         haveio = 1;
      }
   }

   if (timerisset(&bwoverflow)) {
      struct timeval timetobw;

      if (timercmp(timenow, &bwoverflow, >)) /* waited long enough. */
         timerclear(&timetobw);
      else /* still have some to wait. */
         timersub(&bwoverflow, timenow, &timetobw);

      if (!haveio || timercmp(&timetobw, timeout, <)) {
         *timeout = timetobw;
         haveio = 1;
      }
   }

   if (haveio)
      return timeout;
   else
      return NULL;
}

static struct sockd_io_t *
io_gettimedout(timenow)
   const struct timeval *timenow;
{
   const char *function = "io_gettimedout()";
   size_t i;

   if (sockscf.timeout.tcpio == 0 && sockscf.timeout.udpio == 0)
      return NULL;

   for (i = 0; i < ioc; ++i) {
      struct timeval iotimemem, *iotime = &iotimemem;

      if (!iov[i].allocated)
         continue;

      if (iov[i].state.protocol == SOCKS_UDP) {
         if (sockscf.timeout.udpio == 0)
            continue;
      }
      else { /* TCP */
         if (sockscf.timeout.tcpio == 0)
            continue;
      }

#if BAREFOOTD
      if (iov[i].state.command == SOCKS_UDPASSOCIATE) {
         size_t ii;

         if (iov[i].dstc <= 1)
            continue;

         for (ii = 1; ii < iov[i].dstc; ++ii) {
            struct udpclient *udpclient = &iov[i].dstv[ii];

            iotime = &udpclient->iotime;

            if (timenow->tv_sec < iotime->tv_sec) {
               slog(LOG_DEBUG, "%s: clock was stepped backwards?", function);

               *iotime = *timenow;
               continue;
            }

            if ((size_t)(timenow->tv_sec - iotime->tv_sec)
            >= (iov[i].state.protocol == SOCKS_TCP ?
            sockscf.timeout.tcpio : sockscf.timeout.udpio)) {

               iov[i].dst.s     = udpclient->s;
               iov[i].src.laddr = udpclient->laddr;
               iov[i].src.raddr = udpclient->raddr;

               return &iov[i];
            }
         }

         *iotime = *timenow; /* no clients have timed out in this io-object. */
         continue;
      }
      else
         iotime = &iov[i].iotime;
#else /* SOCKS_SERVER */
      iotime = &iov[i].iotime;
#endif /* SOCKS_SERVER */

      if (timenow->tv_sec < iotime->tv_sec) {
         slog(LOG_DEBUG, "%s: clock was stepped backwards?", function);

         *iotime = *timenow;
         continue;
      }

      if ((size_t)(timenow->tv_sec - iotime->tv_sec)
      >= (iov[i].state.protocol == SOCKS_TCP ?
      sockscf.timeout.tcpio : sockscf.timeout.udpio))
         return &iov[i];
   }

   return NULL;
}

static void
getnewio(mother)
   struct sockd_mother_t *mother;
{

   if (recv_io(mother->s, NULL) == 0)
      proctitleupdate();
   else {
      close(mother->s);
      close(mother->ack);
      mother->s = mother->ack = -1;
   }
}

/* ARGSUSED */
static void
siginfo(sig)
   int sig;
{
   const char *function = "siginfo()";
   unsigned long seconds, days, hours, minutes;
   time_t timenow;
   size_t i;

   if (sig > 0) {
      sockd_pushsignal(sig);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, "%s: running due to previously received signal: %d",
   function, sig);

   seconds = difftime(time(&timenow), sockscf.stat.boot);
   seconds2days(&seconds, &days, &hours, &minutes);

   slog(LOG_INFO, "io-child up %lu day%s, %lu:%.2lu:%.2lu",
                  days, days == 1 ? "" : "s", hours, minutes, seconds);

   for (i = 0; i < ioc; ++i) {
      char srcstring[ MAXSOCKADDRSTRING
                    + strlen(" ")
                    + MAXSOCKSHOSTSTRING
                    + MAXAUTHINFOLEN], dststring[sizeof(srcstring)];

      if (!iov[i].allocated)
         continue;

      BUILD_ADDRSTR_SRC(&iov[i].src.host,
                        NULL,
                        NULL,
                        &iov[i].src.laddr,
                        &iov[i].src.auth,
                        NULL,
                        srcstring,
                        sizeof(srcstring));

      BUILD_ADDRSTR_DST(&iov[i].dst.laddr,
                        iov[i].state.proxyprotocol == PROXY_DIRECT
                           ? NULL : &iov[i].state.proxychain.server,
                        iov[i].state.proxyprotocol == PROXY_DIRECT
                           ? NULL : &iov[i].state.proxychain.extaddr,
                        &iov[i].dst.host,
                        &iov[i].dst.auth,
                        NULL,
                        dststring,
                        sizeof(dststring));

      if (iov[i].state.command == SOCKS_UDPASSOCIATE)
         slog(LOG_INFO, "%s: %s <-> %s: idle: %.0fs, "
                        "bytes transferred: %lu <-> %lu, packets: %lu <-> %lu",
              protocol2string(iov[i].state.protocol),
              srcstring, dststring,
              difftime(timenow, (time_t)iov[i].iotime.tv_sec),
              (unsigned long)iov[i].dst.written.bytes,
              (unsigned long)iov[i].src.written.bytes,
              (unsigned long)iov[i].dst.written.packets,
              (unsigned long)iov[i].src.written.packets);
      else
         slog(LOG_INFO,
              "%s: %s <-> %s: idle: %.0fs, bytes transferred: %lu <-> %lu",
              protocol2string(iov[i].state.protocol),
              srcstring, dststring,
              difftime(timenow, (time_t)iov[i].iotime.tv_sec),
              (unsigned long)iov[i].dst.written.bytes,
              (unsigned long)iov[i].src.written.bytes);
   }
}

#if BAREFOOTD

static const struct sockaddr *
srcofudpsocket(s, udpclientc, udpclientv)
   const int s;
   const size_t udpclientc;
   struct udpclient *udpclientv;
{
   struct udpclient *udpclient;

   if ((udpclient = udpclientofsocket(s, udpclientc, udpclientv)) != NULL)
      return &udpclient->raddr;

   return NULL;
}

static int
socketofudpraddr(addr, udpclientc, udpclientv)
   const struct sockaddr *addr;
   const size_t udpclientc;
   const struct udpclient *udpclientv;
{
   const struct udpclient *client;

   if ((client = udpclientofraddr(addr, udpclientc, udpclientv)) != NULL)
      return client->s;

   return -1;
}

#if 0
static int
socketofudpladdr(addr, udpclientc, udpclientv)
   const struct sockaddr *addr;
   const size_t udpclientc;
   const struct udpclient *udpclientv;
{
   const struct udpclient *client;

   if ((client = udpclientofladdr(addr, udpclientc, udpclientv)) != NULL)
      return client->s;

   return -1;
}
#endif

static struct udpclient *
udpclientofsocket(s, udpclientc, udpclientv)
   const int s;
   const size_t udpclientc;
   struct udpclient *udpclientv;
{
   size_t i;

   for (i = 0; i < udpclientc; ++i)
      if (udpclientv[i].s == s)
         return &udpclientv[i];

   return NULL;
}

static const struct udpclient *
udpclientofladdr(addr, udpclientc, udpclientv)
   const struct sockaddr *addr;
   const size_t udpclientc;
   const struct udpclient *udpclientv;
{
   size_t i;

   for (i = 0; i < udpclientc; ++i) {
      if (udpclientv[i].s == -1)
         continue;

      if (sockaddrareeq(addr, &udpclientv[i].laddr))
         return &udpclientv[i];
   }

   return NULL;
}

static const struct udpclient *
udpclientofraddr(addr, udpclientc, udpclientv)
   const struct sockaddr *addr;
   const size_t udpclientc;
   const struct udpclient *udpclientv;
{
   size_t i;

   for (i = 0; i < udpclientc; ++i) {
      if (udpclientv[i].s == -1)
         continue;

      if (sockaddrareeq(addr, &udpclientv[i].raddr))
         return &udpclientv[i];
   }

   return NULL;
}


static struct udpclient *
addudpclient(client, clientc, maxclientc, clientv)
   const struct udpclient *client;
   size_t *clientc;
   size_t *maxclientc;
   struct udpclient **clientv;
{
   const char *function = "addudpclient()";
   char laddr[MAXSOCKADDRSTRING], raddr[MAXSOCKADDRSTRING];

   slog(LOG_DEBUG, "%s: adding udp client for socket %d, clientaddr %s, "
                   "bound addr %s",
                   function, client->s,
                   sockaddr2string(&client->raddr, raddr, sizeof(raddr)),
                   sockaddr2string(&client->laddr, laddr, sizeof(laddr)));

   if (*clientc >= *maxclientc) {
      struct udpclient *p;

      if ((p = realloc(*clientv, (*maxclientc + UDPBLOCK) * sizeof(*p)))
      == NULL) {
         swarn("%s: failed to allocate memory for new udp client", function);
         return NULL;
      }

      *clientv = p;
      *maxclientc += UDPBLOCK;

      slog(LOG_DEBUG, "%s: reallocated memory for udp clients, have memory "
                      "for %lu clients now",
                      function, (unsigned long)*maxclientc);

   }

   (*clientv)[*clientc] = *client;
   return &(*clientv)[(*clientc)++];
}

static int
removeudpclient(s, clientc, clientv)
   const int s;
   size_t *clientc;
   struct udpclient *clientv;
{
   const char *function = "removeudpclient()";
   size_t i;

   for (i = 0; i < *clientc; ++i)
      if (clientv[i].s == s) {
         slog(LOG_DEBUG, "%s: removing client %s on socket %d",
         function, sockaddr2string(&clientv[i].raddr, NULL, 0), s);

         memmove(&clientv[i],
                 &clientv[i + 1],
                 sizeof(*clientv) * (*clientc - (i + 1)));
         --(*clientc);

         return 0;
      }

   SASSERTX(0);
}

static void
handlerawsocket(s)
   const int s;
{
   const char *function = "handlerawsocket()";
   struct icmp *icmp;
   struct ip *ip;
   struct udphdr *udp;
   struct sockaddr addr;
   socklen_t addrlen;
   ssize_t r;
   size_t i;
   char packet[MAX_ICMPLEN], fromstr[16];

   addrlen = sizeof(addr);
   if ((r = recvfrom(s, packet, sizeof(packet), 0, &addr, &addrlen)) == -1) {
      swarn("%s: recvfrom() raw socket failed", function);
      return;
   }

   if (r < MIN_ICMPLEN)    {
      swarn("%s: short read on recvfrom() raw socket: %d/%d",
      function, r, MIN_ICMPLEN);

      return;
   }

   ip   = (struct ip *)packet;
   icmp = (struct icmp *)(packet + (ip->ip_hl << 2));

   if (r < (ip->ip_hl << 2)) {
      swarn("%s: strange ... kernel says ip hl is %d, but packet size is %ld",
      function, ip->ip_hl << 2, (long)r);

      return;
   }

   slog(LOG_DEBUG, "%s: received raw packet from %s, type %d/%d, length %d",
                   function,
                   inet_ntop(AF_INET, &(TOIN(&addr)->sin_addr), fromstr,
                             sizeof(fromstr)),
                   icmp->icmp_type, icmp->icmp_code, r);

   if (icmp->icmp_type != ICMP_UNREACH)
      return;

   /* ip-packet the icmp error is in reply to. */
   ip = (struct ip *)(icmp->icmp_data);

   if (ip->ip_p != IPPROTO_UDP)
      return;

   udp = (struct udphdr *)(icmp->icmp_data + (ip->ip_hl << 2));

   TOIN(&addr)->sin_addr = ip->ip_src;
   TOIN(&addr)->sin_port = udp->uh_sport;

   slog(LOG_DEBUG, "%s: icmp packet is in response to udp packet to %s",
   function, sockaddr2string(&addr, NULL, 0));

   /*
    * Now we need to go through all io-objects with udp clients and
    * see if the address matches a client there.
    */
   for (i = 0; i < ioc; ++i) {
      const struct udpclient *client;

      if (!iov[i].allocated)
         continue;

      if (iov[i].state.protocol != SOCKS_UDP)
         continue;

      if ((client = udpclientofladdr(&addr, iov[i].dstc, iov[i].dstv)) != NULL){
         slog(LOG_DEBUG, "%s: removing client associated with %s from iov #%d",
         function, sockaddr2string(&addr, NULL, 0), i);

         iov[i].dst.s     = client->s;
         iov[i].src.laddr = client->laddr;
         iov[i].src.raddr = client->raddr;

         delete_io(-1 /* nothing to ack */, &iov[i], client->s, IO_CLOSE);
         break;
      }
   }
}

#endif /* BAREFOOTD */
