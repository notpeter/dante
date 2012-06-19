/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2008, 2009,
 *               2010, 2011
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
"$Id: sockd_child.c,v 1.318 2012/06/01 19:59:28 karls Exp $";

#define MOTHER  (0)  /* descriptor mother reads/writes on.   */
#define CHILD   (1)   /* descriptor child reads/writes on.   */

static int
setchildtype(int type, sockd_child_t ***childv, size_t **childc,
             void (**function)(void));
/*
 * Sets "childv", "childc" and "function" to the correct value depending
 * on "type".
 */

static int
findchild(pid_t pid, int childc, const sockd_child_t *childv);
/*
 * Finds the child with pid "pid" in the array "childv".  Searching
 * Elements in "childv" is given by "childc".
 * Returns:
 *      On success: the index of the child in "childv".
 *      On failure: -1.
 */

static sockd_child_t *
addchild(const int type);
/*
 * Adds a new child that can accept objects of type "type" from mother.
 * Returns:
 *    On success: a pointer to the added child.
 *    On failure: NULL.  (resource shortage.)
 */


static sockd_child_t *iochildv;          /* all our iochildren         */
static size_t iochildc;

static sockd_child_t *negchildv;         /* all our negotiatorchildren */
static size_t negchildc;

static sockd_child_t *reqchildv;         /* all our requestchildren    */
static size_t reqchildc;

static sockd_child_t *
addchild(type)
   const int type;
{
   const char *function = "addchild()";
   void (*childfunction)(void);
   sockd_mother_t mother;
   sockd_child_t **childv;
   pid_t pid;
   socklen_t optlen;
   size_t *childc;
   int min, rcvbuf, sndbuf, rcvbuf_set1, rcvbuf_set2, sndbuf_set1, sndbuf_set2,
       p, datapipev[] = { -1, -1 }, ackpipev[] = { -1, -1 };

   /*
    * create datapipe ...
    */
   if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, datapipev) != 0) {
      swarn("%s: socketpair(AF_LOCAL, SOCK_DGRAM)", function);
      return NULL;
   }

   /* ... and ackpipe. */
   if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ackpipev) != 0) {
      swarn("%s: socketpair(AF_LOCAL, SOCK_STREAM)", function);

      closev(datapipev, ELEMENTS(datapipev));
      return NULL;
   }

   if ((p = fcntl(datapipev[0], F_GETFL, 0))              == -1
   ||       fcntl(datapipev[0], F_SETFL, p | O_NONBLOCK)  == -1
   ||       fcntl(datapipev[1], F_SETFL, p | O_NONBLOCK)  == -1
   ||       fcntl(ackpipev[0],  F_SETFL, p | O_NONBLOCK)  == -1
   ||       fcntl(ackpipev[1],  F_SETFL, p | O_NONBLOCK)  == -1) {
      swarn("%s: fcntl() failed to set pipe between mother and "
            "child to non-blocking",
            function);

      closev(datapipev, ELEMENTS(datapipev));
      closev(ackpipev, ELEMENTS(ackpipev));

      return NULL;
   }

   /*
    * Try to set socket buffer and watermarks to a optimal size depending
    * on what kind of data passes over the pipes.  Could fine tune this
    * further by differentiating between snd/rcv-sizes for mother/child,
    * but not bothering with that at the moment.
    */
   switch (setchildtype(type, &childv, &childc, &childfunction)) {
      case CHILD_NEGOTIATE:
         /*
          * A negotiator child receives a sockd_client_t struct,
          * and sends back a sockd_request_t struct.
          */
         rcvbuf = (MAX(sizeof(sockd_client_t), sizeof(sockd_request_t))
                + sizeof(struct msghdr)
                + CMSG_SPACE(sizeof(int)) * FDPASS_MAX);

         rcvbuf += SENDMSG_PADBYTES;

#if HAVE_GSSAPI
         rcvbuf += (MAX_GSS_STATE + sizeof(struct iovec));
#endif /* HAVE_GSSAPI */

         sndbuf = rcvbuf * SOCKD_NEGOTIATEMAX;
         break;

      case CHILD_REQUEST:
         /*
          * A request child receives a sockd_request_t structure,
          * it sends back a sockd_io_t structure.
          */
         rcvbuf = (MAX(sizeof(sockd_request_t), sizeof(sockd_io_t))
                + sizeof(struct msghdr)
                + CMSG_SPACE(sizeof(int)) * FDPASS_MAX);

         rcvbuf += SENDMSG_PADBYTES;

#if HAVE_GSSAPI
         rcvbuf += (MAX_GSS_STATE + sizeof(struct iovec));
#endif /* HAVE_GSSAPI */

         sndbuf = rcvbuf * SOCKD_REQUESTMAX;
         break;

      case CHILD_IO:
         /*
          * A io child receives a sockd_io_t structure,
          * it sends back only an ack-byte.
          * XXX that is not true in COVENANT's case.
          */
         rcvbuf = (sizeof(sockd_io_t)
                +  sizeof(struct msghdr)
                +  CMSG_SPACE(sizeof(int)) * FDPASS_MAX);

         rcvbuf += SENDMSG_PADBYTES;

#if HAVE_GSSAPI
         rcvbuf += (MAX_GSS_STATE + sizeof(struct iovec));
#endif /* HAVE_GSSAPI */

         sndbuf = rcvbuf * SOCKD_IOMAX;
         break;

      default:
         SERRX(type);
   }

   min = rcvbuf;

   if (HAVE_PIPEBUFFER_SEND_BASED)
      ; /* as expected. */
   else if (HAVE_PIPEBUFFER_RECV_BASED) {
      /*
       * reverse of our assumption that how much we can write to the pipe
       * depends on the pipe's sndbuf.
       */
      const size_t tmp    = sndbuf;
                   sndbuf = rcvbuf;
                   rcvbuf = tmp;
   }
   else if (HAVE_PIPEBUFFER_UNKNOWN) { /* wastes a lot of memory. */
      rcvbuf = MAX(sndbuf, rcvbuf);
      sndbuf = MAX(sndbuf, rcvbuf);
   }

   p = rcvbuf;
   do {
      if (setsockopt(datapipev[MOTHER],
                     SOL_SOCKET,
                     SO_RCVBUF,
                     &p,
                     sizeof(p)) != 0
      ||  setsockopt(datapipev[CHILD],
                     SOL_SOCKET,
                     SO_RCVBUF,
                     &p,
                     sizeof(p)) != 0) {
         slog(LOG_DEBUG, "%s: could not set SO_RCVBUF to %d: %s",
              function, p, strerror(errno));

         p -= min;
      }
      else
         break;
   } while (p > min);

   optlen = sizeof(rcvbuf_set1);
   if (getsockopt(datapipev[MOTHER],
                  SOL_SOCKET,
                  SO_RCVBUF,
                  &rcvbuf_set1,
                  &optlen) != 0
   ||  getsockopt(datapipev[CHILD],
                  SOL_SOCKET,
                  SO_RCVBUF,
                  &rcvbuf_set2,
                  &optlen) != 0) {
      swarn("%s: could not get size of SO_RCVBUF", function);

      closev(datapipev, ELEMENTS(datapipev));
      closev(ackpipev, ELEMENTS(ackpipev));

      return NULL;
   }

   p = sndbuf;
   do {
      if (setsockopt(datapipev[MOTHER],
                     SOL_SOCKET,
                     SO_SNDBUF,
                     &p,
                     sizeof(p)) != 0
      ||  setsockopt(datapipev[CHILD],
                     SOL_SOCKET,
                     SO_SNDBUF,
                     &p,
                     sizeof(p)) != 0) {

         slog(LOG_DEBUG, "%s: could not set SO_SNDBUF to %d: %s",
              function, p, strerror(errno));

         p -= min;
      }
      else
         break;
   } while (p > min);

   optlen = sizeof(sndbuf_set1);
   if (getsockopt(datapipev[MOTHER],
                  SOL_SOCKET,
                  SO_SNDBUF,
                  &sndbuf_set1,
                  &optlen) != 0
   ||  getsockopt(datapipev[CHILD],
                  SOL_SOCKET,
                  SO_SNDBUF,
                  &sndbuf_set2,
                  &optlen) != 0) {
      swarn("%s: could not get size of SO_SNDBUF", function);

      closev(datapipev, ELEMENTS(datapipev));
      closev(ackpipev, ELEMENTS(ackpipev));

      return NULL;
   }


   if (rcvbuf_set1 < rcvbuf || rcvbuf_set2 < rcvbuf
   ||  sndbuf_set1 < sndbuf || sndbuf_set2 < sndbuf) {
      const int isfatal = (rcvbuf_set1 < min || rcvbuf_set2 < min
                        || sndbuf_set1 < min || sndbuf_set2 < min);
      char *value;

      switch (type) {
         case CHILD_NEGOTIATE:
             value = "SOCKD_NEGOTIATEMAX";
             break;

         case CHILD_REQUEST:
            value = "SOCKD_REQUESTMAX";
            break;

         case CHILD_IO:
            value = "SOCKD_IOMAX";
            break;

         default:
            SERRX(type);
      }

      slog(isfatal ? LOG_WARNING : LOG_INFO,
           "%s: kernel did not honour requested size for send/receive buffer.  "
           "Requested send size: %d, returned: %d and %d.  "
           "Requested receive size: %d, returned: %d and %d. "
           "This probably means %s's %s was at compile-time set to a value "
           "too large for the current kernel settings.\n"
           "To avoid this warning, you will need to either increase the "
           "kernel's max-size socket buffers somehow, or decrease the %s "
           "value in %s and recompile."
           "%s",
           function,
           sndbuf, sndbuf_set1, sndbuf_set2,
           rcvbuf, rcvbuf_set1, rcvbuf_set2,
           PACKAGE,
           value,
           value,
           PACKAGE,
           isfatal ? "" : "\nWe will continue with the smaller buffersize, "
                          "but performance may be degraded.");

      if (isfatal) {
         closev(datapipev, ELEMENTS(datapipev));
         closev(ackpipev, ELEMENTS(ackpipev));

         return NULL;
      }
   }

   switch ((pid = fork())) {
      case -1:
         swarn("%s: fork()", function);

         closev(datapipev, ELEMENTS(datapipev));
         closev(ackpipev, ELEMENTS(ackpipev));

         return NULL;

      case 0: {
         size_t i, maxfd;
         struct sigaction sigact;

         bzero(&sigact, sizeof(sigact));

         /*
          * signals mother has set up but which we need ignore at this
          * point, lest we accidentally run mothers signal handler if the
          * child does not install it's own signal handler for the
          * particular signal.
          * Later on, the child sets up it's own signal handlers.
          */
         sigact.sa_handler = SIG_IGN;

#if HAVE_SIGNAL_SIGINFO
         if (sigaction(SIGINFO, &sigact, NULL) != 0)
            swarn("%s: sigaction(SIGINFO)", function);
#endif /* HAVE_SIGNAL_SIGINFO */

         if (sigaction(SIGUSR1, &sigact, NULL) != 0)
            swarn("%s: sigaction(SIGUSR1)", function);

#if HAVE_PROFILING && HAVE_MONCONTROL /* XXX is this only needed on Linux? */
         moncontrol(1);
#endif /* HAVE_PROFILING && HAVE_MONCONTROL */

         newprocinit();

         mother.s           = datapipev[CHILD];
         mother.ack         = ackpipev[CHILD];
         sockscf.state.type = type;

#if 0
         slog(LOG_DEBUG, "sleeping...");
         sleep(20);
#endif

#if HAVE_PRIVILEGES
      /* don't need this privilege any more, permanently loose it. */
      if (sockscf.privileges.haveprivs) {
         priv_delset(sockscf.privileges.privileged, PRIV_FILE_DAC_WRITE);
         if (setppriv(PRIV_SET, PRIV_PERMITTED, sockscf.privileges.privileged)
         != 0)
            swarn("%s: setppriv() to relinquish PRIV_FILE_DAC_WRITE failed",
            function);
      }
#endif /* HAVE_PRIVILEGES */

         /*
          * It would be nice to be able to lose all root privileges here
          * but unfortunately we can't;
          *
          * negotiation children:
          *      - could need privileges to check password.
          *
          * request children:
          *      - could need privileges to bind port.
          *      - could need privileges to check password.
          *
          * io children:
          *      - could need privileges to create a raw socket to listen
          *        for icmp errors.
          *      - could need privileges to bind port if using the
          *        redirect() module.
          *
          * Also, all may need privileges to re-open and re-read the sockd.conf.
          * If we have privilege-support, give up what we can though.
          */

         switch (type) {
            case CHILD_NEGOTIATE:
#if HAVE_LIBWRAP
#if SOCKD_NEGOTIATEMAX > 1
               resident = 1;
#endif /* SOCKD_NEGOTIATEMAX > 1 */
#endif /* HAVE_LIBWRAP */

#if HAVE_PRIVILEGES
               /* doesn't need this privilege so permanently loose it. */

               if (sockscf.privileges.haveprivs) {
                  priv_delset(sockscf.privileges.privileged, PRIV_NET_PRIVADDR);
                  if (setppriv(PRIV_SET, PRIV_PERMITTED,
                  sockscf.privileges.privileged) != 0)
                     swarn("%s: setppriv() to relinquish PRIV_NET_PRIVADDR "
                           "failed",
                           function);
               }
#endif /* HAVE_PRIVILEGES */

               break;

            case CHILD_REQUEST:
#if HAVE_LIBWRAP
#if SOCKD_REQUESTMAX > 1
               resident = 1;
#endif /* SOCKD_REQUESTMAX > 1 */
#endif /* HAVE_LIBWRAP */
               break;

            case CHILD_IO:
#if HAVE_LIBWRAP
#if SOCKD_IOMAX > 1
               resident = 1;
#endif /* SOCKD_IOMAX > 1 */
#endif /* HAVE_LIBWRAP */
               break;

            default:
               SERRX(type);
         }

         /* delete everything we got from parent. */
         for (i = 0, maxfd = sockscf.state.maxopenfiles; i < maxfd; ++i) {
            /* exceptions */
            if (i == (size_t)mother.s || i == (size_t)mother.ack)
               continue;

            if (descriptorisreserved((int)i))
               continue;

            close((int)i);
         }

         /*
          * Needs to be called again after closing, since if using syslog we
          * don't know what descriptor that uses, so it will have been closed
          * in the above close(2) loop.
          * This needs to happen as the first thing after the above loop,
          * as newprocinit() will close the old syslog descriptor, if any,
          * before opening a new one.  If we have started to use the
          * descriptor for something else already (e.g. due to dup(2)),
          * newprocinit(), will still close the old descriptor, even
          * though it's no longer a syslog descriptor.
          */
         newprocinit();

         /*
          * This is minor optimization to make things faster for select(2)
          * by avoiding having two increasingly high-numbered descriptors
          * to check for, with most of the other descriptors in the lower-end.
          */

          datapipev[0] = mother.s;
          datapipev[1] = mother.ack;

          if ((mother.s   = dup(mother.s))   == -1
          ||  (mother.ack = dup(mother.ack)) == -1)
            serr(EXIT_FAILURE, "%s: failed to dup(2) pipe to mother", function);

          close(datapipev[0]);
          close(datapipev[1]);

         /*
          * Ok, all set for this process.
          */

         slog(LOG_DEBUG, "I am new %s-child, data-pipe %d, ack-pipe %d",
              childtype2string(type), mother.s, mother.ack);

         sockscf.state.mother = mother;
         time(&sockscf.stat.boot);

         errno = 0;
         childfunction();
         /* NOTREACHED */
      }

      default: {
         sockd_child_t *newchildv;

         if ((newchildv = realloc(*childv, sizeof(**childv) * (*childc + 1)))
         == NULL) {
            swarn("%s: %s", function, NOMEM);
            closev(datapipev, ELEMENTS(datapipev));
            closev(ackpipev, ELEMENTS(ackpipev));

            return NULL;
         }
         *childv = newchildv;

         (*childv)[*childc].type           = type;
         (*childv)[*childc].pid            = pid;
         (*childv)[*childc].s              = datapipev[MOTHER];
         (*childv)[*childc].ack            = ackpipev[MOTHER];
         (*childv)[*childc].sentc          = 0;
#if BAREFOOTD
         (*childv)[*childc].hasudpsession  = 0;
#endif /* BAREFOOTD */

         close(datapipev[CHILD]);
         close(ackpipev[CHILD]);

         slog(LOG_DEBUG,
              "%s: created new %s-child, pid %lu, data-pipe %d, ack-pipe %d.  "
              "Minimum rcvbuf: %d, set: %d and %d.  "
              "Minimum sndbuf: %d, set: %d and %d",
              function,
              childtype2string((*childv)[*childc].type),
              (unsigned long)(*childv)[*childc].pid,
              (*childv)[*childc].s,
              (*childv)[*childc].ack,
              rcvbuf, rcvbuf_set1, rcvbuf_set2,
              sndbuf, sndbuf_set1, sndbuf_set2);

         switch ((*childv)[*childc].type) {
            case CHILD_NEGOTIATE:
               (*childv)[*childc].freec = SOCKD_NEGOTIATEMAX;
               break;

            case CHILD_REQUEST:
               (*childv)[*childc].freec = SOCKD_REQUESTMAX;
               break;

            case CHILD_IO:
               (*childv)[*childc].freec = SOCKD_IOMAX;
               break;

            default:
               SERRX((*childv)[*childc].type);
         }

         return &(*childv)[(*childc)++];
      }
   }
}

size_t
childcheck(type)
   int type;
{
   const char *function = "childcheck()";
   sockd_child_t **childv;
   size_t child, *childc, minfreeslots, maxslotsperproc, maxidle, idle, proxyc;
#if BAREFOOTD
   pid_t havefreeudpslot = 0;
#endif /* BAREFOOTD */
   const int errno_s = errno;

   switch (type) {
      case -CHILD_NEGOTIATE:
      case CHILD_NEGOTIATE:
         childc          = &negchildc;
         childv          = &negchildv;
         maxidle         = sockscf.child.maxidle.negotiate;
         minfreeslots    = SOCKD_FREESLOTS_NEGOTIATE;
         maxslotsperproc = SOCKD_NEGOTIATEMAX;
         break;

      case -CHILD_REQUEST:
      case CHILD_REQUEST:
         childc          = &reqchildc;
         childv          = &reqchildv;
         maxidle         = sockscf.child.maxidle.request;
         minfreeslots    = SOCKD_FREESLOTS_REQUEST;
         maxslotsperproc = SOCKD_REQUESTMAX;
         break;

      case -CHILD_IO:
      case CHILD_IO:
         childc          = &iochildc;
         childv          = &iochildv;
         maxidle         = sockscf.child.maxidle.io;
         minfreeslots    = SOCKD_FREESLOTS_IO;
         maxslotsperproc = SOCKD_IOMAX;
         break;

      default:
         SERRX(type);
   }

   /*
    * get an estimate over how many (new) clients our children are able to
    * accept in total, so we know if we need to create more children,
    * or if we can remove some.
    */
   for (child = idle = proxyc = 0; child < *childc; ++child) {
      SASSERTX((*childv)[child].freec <= maxslotsperproc);

      if (sockscf.child.maxrequests != 0)
         if ((*childv)[child].sentc == sockscf.child.maxrequests) {
            slog(LOG_DEBUG, "%s: not counting child %lu.  Should be removed "
                            "when possible as it has already served %lu "
                            "requests (currently has %lu/%lu slots free).",
                            function,
                            (unsigned long)(*childv)[child].pid,
                            (unsigned long)(*childv)[child].sentc,
                            (unsigned long)(*childv)[child].freec,
                            (unsigned long)maxfreeslots((*childv)[child].type));
            continue;
         }

#if BAREFOOTD
      if (type == CHILD_IO && !(*childv)[child].hasudpsession)
         havefreeudpslot = (*childv)[child].pid;
#endif /* BAREFOOTD */

      proxyc += type < 0 ? maxslotsperproc :
#if BAREFOOTD
                           /*
                            * Don't know what the next client for this
                            * child will be (udp or tcp), so safer to assume
                            * that if it can not handle any more udp clients,
                            * it has no free slots.  Means we will get more
                            * i/o processes than might be required, but
                            * better that than too few.
                            */
                           ((type == CHILD_IO && (*childv)[child].hasudpsession)
                           ? 0 : (*childv)[child].freec);

#else /* !BAREFOOTD */

                           (*childv)[child].freec;

#endif /* !BAREFOOTD */

      if ((*childv)[child].freec == maxslotsperproc) {
#if BAREFOOTD
         if (type == CHILD_IO) {
            if (havefreeudpslot && havefreeudpslot != (*childv)[child].pid)
               /* LINTED */ /* EMPTY */;
            else {
               /*
                * Want to keep this regardless, as we have not seen any
                * other child with a free udp slot so far, so don't
                * include it in the idle count where it could possibly be
                * shut down by maxidle/maxreq code.
                */
               havefreeudpslot = (*childv)[child].pid;
               continue;
            }
         }
#endif /* BAREFOOTD */

         ++idle; /* all slots in this child are idle. */

         if (maxidle != 0 && idle > maxidle) {
            slog(LOG_DEBUG, "%s: already counted %lu idle %s-children, "
                            "removing %s-child with pid %lu",
                            function,
                            (unsigned long)(idle - 1),
                            childtype2string(type < 0 ? -type : type),
                            childtype2string(type < 0 ? -type : type),
                            (unsigned long)(*childv)[child].pid);

            /* will remove this now, no longer part of free slots pool. */
            proxyc -= type < 0 ? maxslotsperproc : (*childv)[child].freec;

            removechild((*childv)[child].pid);
            --idle;
            --child; /* everything was shifted one to the left. */
         }
      }
   }

   if (type >= 0
   && sockscf.child.addchild
   && ((proxyc < minfreeslots)
#if BAREFOOTD
         ||    (type == CHILD_IO && !havefreeudpslot)
#endif /* BAREFOOTD */
      )) {
      int reservedv[MAX(FDPASS_MAX /* max descriptors we receive/pass. */,
                        1          /* need a socket for accept(2).     */)];
      size_t i, freec;

      /*
       * It is better to reserve some descriptors for temporary use
       * than to get errors when receiving from a child and lose clients
       * that way.  Make sure we always have some descriptors available,
       * and don't try to add a child if we don't.
       * If we can add a child after reserving the below number of
       * descriptors, things are ok.  If not, it means we have to few.
       */
      for (i = 0, freec = 0; i < ELEMENTS(reservedv); ++i)
         if ((reservedv[i] = socket(AF_INET, SOCK_STREAM, 0)) != -1)
            ++freec;

      if (freec != ELEMENTS(reservedv)) {
         swarn("%s: not enough free sockets/file descriptors to add a "
               "new child.  Need at least %lu, but have only %lu",
               function,
               (unsigned long)ELEMENTS(reservedv),
               (unsigned long)freec);

         /* don't retry until a child exits. */
         sockscf.child.addchild       = 0;
         sockscf.child.addchild_errno = errno;
      }

      while (sockscf.child.addchild
      &&       ((proxyc < minfreeslots)
#if BAREFOOTD
         ||    (type == CHILD_IO && !havefreeudpslot)
#endif /* BAREFOOTD */
      )) {
         slog(LOG_DEBUG, "%s: current # of free %s-slots is %lu, "
                         "while the configured minimum is %lu. "
                         "Thus need to add a %s-child",
                         function,
                         childtype2string(type),
                         (unsigned long)proxyc,
                         (unsigned long)minfreeslots,
                         childtype2string(type));

         if (addchild(type) != NULL) {
            proxyc += maxslotsperproc;
#if BAREFOOTD
            if (type == CHILD_IO)
              havefreeudpslot = 1;
#endif /* BAREFOOTD */
         }
         else {
            swarn("%s: failed to add a new child to handle new clients",
                 function);

            /* don't retry until a child exits. */
            sockscf.child.addchild       = 0;
            sockscf.child.addchild_errno = errno;
            break;
         }
      }

      closev(reservedv, ELEMENTS(reservedv));
   }

   /* if errno was set, it was also logged.  Don't drag it with us. */
   errno = errno_s;

   return proxyc;
}

int
fillset(set, negc, reqc, ioc)
   fd_set *set;
   int *negc;
   int *reqc;
   int *ioc;
{
/*   const char *function = "fillset()"; */
   size_t i;
   int dbits;

   /*
    * There is no point in setting data descriptor of child type N unless
    * child type N+1 is able to accept the data from child N.  So find
    * out if we have slots of the various types available before setting
    * the descriptor.  The same goes for the ack descriptor; we don't
    * want to think the process has a lot of free slots because we have
    * read the ack, but are unable to read the data.
    */

   *negc = childcheck(CHILD_NEGOTIATE);
   *reqc = childcheck(CHILD_REQUEST);
   *ioc  = childcheck(CHILD_IO);

   FD_ZERO(set);
   dbits = -1;

   for (i = 0; i < sockscf.internalc; ++i) {
#if BAREFOOTD
      if (sockscf.internalv[i].protocol != SOCKS_TCP)
         continue; /* udp handled by io children. */
#endif /* BAREFOOTD */

      /*
       * Before we checked whether we had available negotiate slots
       * before accept(2)'ing a new client, but if we do not have
       * negotiate slots available, it will look like we have hung
       * because we are not accepting any new clients.
       * Also, if we get into the situation where we have no negotiate slots
       * and are unable to fork new negotiate processes, things are probably
       * pretty bad, so it might be better to drop new clients
       * and log a warning about it.
       */

      SASSERTX(sockscf.internalv[i].s >= 0);
      FD_SET(sockscf.internalv[i].s, set);
      dbits = MAX(dbits, sockscf.internalv[i].s);
   }

   /* negotiator children. */
   for (i = 0; i < negchildc; ++i) {
      if (*reqc > 0) {
         SASSERTX(negchildv[i].s >= 0);
         FD_SET(negchildv[i].s, set);
         dbits = MAX(dbits, negchildv[i].s);

         SASSERTX(negchildv[i].ack >= 0);
         FD_SET(negchildv[i].ack, set);
         dbits = MAX(dbits, negchildv[i].ack);
      }
   }

   /* request children. */
   for (i = 0; i < reqchildc; ++i) {
      if (*ioc > 0) {
         SASSERTX(reqchildv[i].s >= 0);
         FD_SET(reqchildv[i].s, set);
         dbits = MAX(dbits, reqchildv[i].s);

         SASSERTX(reqchildv[i].ack >= 0);
         FD_SET(reqchildv[i].ack, set);
         dbits = MAX(dbits, reqchildv[i].ack);
      }
   }

   /*
    * io children are last in chain, unless we are covenant, which may
    * need to send a client object back from  i/o child to a negotiate
    * child.
    */
   for (i = 0; i < iochildc; ++i) {
#if COVENANT
      if (*negc > 0) {
         SASSERTX(iochildv[i].s >= 0);
         FD_SET(iochildv[i].s, set);
         dbits = MAX(dbits, iochildv[i].s);
#endif /* COVENANT */

         SASSERTX(iochildv[i].ack >= 0);
         FD_SET(iochildv[i].ack, set);
         dbits = MAX(dbits, iochildv[i].ack);
#if COVENANT
      }
#endif /* COVENANT */

   }

   return dbits;
}

void
clearset(type, child, set)
   whichpipe_t type;
   const sockd_child_t *child;
   fd_set *set;
{

   switch (type) {
      case ACKPIPE:
         FD_CLR(child->ack, set);
         break;

      case DATAPIPE:
         FD_CLR(child->s, set);
         break;

      default:
         SERRX(type);
   }
}

sockd_child_t *
getset(type, set)
   whichpipe_t type;
   fd_set *set;
{
/*   const char *function = "getset()"; */
   size_t i;

   /* check negotiator children for match. */
   for (i = 0; i < negchildc; ++i)
      switch (type) {
         case DATAPIPE:
#if BAREFOOTD
            if (!sockscf.state.alludpbounced) { /* have some left to fake. */
               static fd_set *zero;

               if (zero == NULL) {
                  zero = allocate_maxsize_fdset();
                  FD_ZERO(zero);
               }

               if (FD_CMP(zero, set) == 0)
                  return &negchildv[i];
            }
#endif /* BAREFOOTD */

            if (FD_ISSET(negchildv[i].s, set))
               return &negchildv[i];
            break;

         case ACKPIPE:
            if (FD_ISSET(negchildv[i].ack, set))
               return &negchildv[i];
            break;
      }

   /* check request children for match. */
   for (i = 0; i < reqchildc; ++i)
      switch (type) {
         case DATAPIPE:
            if (FD_ISSET(reqchildv[i].s, set))
               return &reqchildv[i];
            break;

         case ACKPIPE:
            if (FD_ISSET(reqchildv[i].ack, set))
               return &reqchildv[i];
            break;
      }

   /* check io children for match. */
   for (i = 0; i < iochildc; ++i)
      switch (type) {
         case DATAPIPE:
            if (FD_ISSET(iochildv[i].s, set))
               return &iochildv[i];
            break;

         case ACKPIPE:
            if (FD_ISSET(iochildv[i].ack, set))
               return &iochildv[i];
            break;
      }

   return NULL;
}

void
removechild(pid)
   pid_t pid;
{
   const char *function = "removechild()";
   sockd_child_t **childv;
   size_t *childc;
   int child;

   slog(LOG_DEBUG, "%s: pid %lu", function, (unsigned long)pid);

   if (pid == 0) {
      int childtypev[] = {CHILD_IO, CHILD_NEGOTIATE, CHILD_REQUEST};
      size_t i;

      for (i = 0; i < ELEMENTS(childtypev); ++i) {
         while (1) {
            setchildtype(childtypev[i], &childv, &childc, NULL);
            if (*childc == 0)
               break;

            SASSERTX((*childv)[0].pid != 0);
            removechild((*childv)[0].pid);
         }
      }

      return;
   }

   setchildtype(childtype(pid), &childv, &childc, NULL);
   child = findchild(pid, *childc, *childv);
   SASSERTX(child != -1);

   close((*childv)[child].ack);
   close((*childv)[child].s);

   /* shift all following one down */
   while ((size_t)child < *childc - 1) {
      (*childv)[child] = (*childv)[child + 1];
      ++child;
   }
   --(*childc);

   /*
    * Don't bother with realloc(3) when reducing size.
    */
}

sockd_child_t *
nextchild(type, protocol)
   const int type;
   const int protocol;
{
   const char *function = "nextchild()";
   sockd_child_t **childv;
   size_t i, *childc;
   int mostbusy, triedagain = 0;

tryagain:

   setchildtype(type, &childv, &childc, NULL);

   /*
    * Try to find the child that is most busy, so that we diverge to
    * filling up slots in existing children and removing idle ones.
    */
   mostbusy = -1;
   for (i = 0; i < *childc; ++i) {
      if ((*childv)[i].freec > 0) {
#if BAREFOOTD
         if (protocol == SOCKS_UDP && (*childv)[i].hasudpsession) {
            slog(LOG_DEBUG, "%s: skipping child %lu.  Has %lu free slot%s, "
                            "but also has an udp sessions already",
                            function,
                            (unsigned long)(*childv)[i].pid,
                            (unsigned long)(*childv)[i].freec,
                            (unsigned long)(*childv)[i].freec == 1 ? "" : "s");
            continue;
         }
#endif /* BAREFOOTD */

         if ((*childv)[i].freec <= 0)
            continue;

         /*
          * Child has at least one free slot.
          * We want to find the child with the fewest free slots, to avoid
          * processes with only a few clients that can not be shut down by
          * child.maxidle.  Trying to fit as many clients as possible
          * into each processes allows us to reduce the process count.
          */
         if (mostbusy == -1
         || (*childv)[i].freec < (*childv)[mostbusy].freec)
            mostbusy = i;

         if ((*childv)[mostbusy].freec == 1)
            break; /* no need to look further, got the busiest we can get. */
      }
   }

   if (mostbusy != -1)
      return &(*childv)[mostbusy];

   slog(LOG_DEBUG, "%s: no free %s slots for protocol %s, triedagain = %d",
        function,
        childtype2string(type),
        protocol2string(protocol),
        triedagain);

   if (!triedagain) {
      slog(LOG_DEBUG, "%s: calling childcheck() and trying again", function);
      childcheck(type);

      triedagain = 1;
      childcheck(type);
      goto tryagain;
   }

   return NULL;
}

static int
setchildtype(type, childv, childc, function)
   int type;
   sockd_child_t ***childv;
   size_t **childc;
   void (**function)(void);
{

   switch (type) {
      case CHILD_IO:
         if (childv != NULL)
            *childv = &iochildv;

         if (childc != NULL)
            *childc = &iochildc;

         if (function != NULL)
            *function = &run_io;

         break;

      case CHILD_NEGOTIATE:
         if (childv != NULL)
            *childv = &negchildv;

         if (childc != NULL)
            *childc = &negchildc;

         if (function != NULL)
            *function = &run_negotiate;

         break;

      case CHILD_REQUEST:
         if (childv != NULL)
            *childv = &reqchildv;

         if (childc != NULL)
            *childc = &reqchildc;

         if (function != NULL)
            *function = &run_request;

         break;

      default:
         SASSERTX(type);
   }

   return type;
}

int
childtype(pid)
   pid_t pid;
{

   if (findchild(pid, iochildc, iochildv) != -1)
      return CHILD_IO;

   if (findchild(pid, negchildc, negchildv) != -1)
      return CHILD_NEGOTIATE;

   if (findchild(pid, reqchildc, reqchildv) != -1)
      return CHILD_REQUEST;

   if (pidismother(pid))
      return CHILD_MOTHER;

   return CHILD_NOTOURS;
}

static int
findchild(pid, childc, childv)
   pid_t pid;
   int childc;
   const sockd_child_t *childv;
{
   int i;

   for (i = 0; i < childc; ++i)
      if (childv[i].pid == pid)
         return i;

   return -1;
}

sockd_child_t *
getchild(pid)
   pid_t pid;
{
   int child, type;
   size_t *childc;
   sockd_child_t **childv;

   switch (type = childtype(pid)) {
      case CHILD_IO:
      case CHILD_NEGOTIATE:
      case CHILD_REQUEST:
         break;

      case CHILD_MOTHER:
         return NULL;

      case CHILD_NOTOURS:
         return NULL;

      default:
         SERRX(type);
   }

   setchildtype(type, &childv, &childc, NULL);

   if ((child = findchild(pid, *childc, *childv)) != -1)
      return &(*childv)[child];

   SERRX(pid);
   /* NOTREACHED */
}

int
send_io(s, io)
   int s;
   sockd_io_t *io;
{
   const char *function = "send_io()";
   struct iovec iov[2];
   struct msghdr msg;
   ssize_t w;
   int ioc, fdtosend, length;
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   gss_ctx_id_t gssid = GSS_C_NO_CONTEXT;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);

   bzero(iov, sizeof(iov));
   length = 0;
   ioc    = 0;

   iov[ioc].iov_base  = io;
   iov[ioc].iov_len   = sizeof(*io);
   length            += iov[ioc].iov_len;
   ++ioc;

   fdtosend = 0;
   CMSG_ADDOBJECT(io->src.s, cmsg, sizeof(io->src.s) * fdtosend++);
   CMSG_ADDOBJECT(io->dst.s, cmsg, sizeof(io->dst.s) * fdtosend++);

#if HAVE_GSSAPI
   gssapistate.value  = gssapistatemem;
   gssapistate.length = sizeof(gssapistatemem);
#endif /* HAVE_GSSAPI */

   switch (io->state.command) {
      case SOCKS_BIND:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            gssid = io->src.auth.mdata.gssapi.state.id;
#endif /* HAVE_GSSAPI */

         if (io->state.extension.bind)
            CMSG_ADDOBJECT(io->control.s,
                           cmsg,
                           sizeof(io->control.s) * fdtosend++);
         break;

      case SOCKS_BINDREPLY:
#if HAVE_GSSAPI
         if (io->dst.auth.method == AUTHMETHOD_GSSAPI)
            gssid = io->dst.auth.mdata.gssapi.state.id;
#endif /* HAVE_GSSAPI */

         if (io->state.extension.bind)
            CMSG_ADDOBJECT(io->control.s, cmsg,
            sizeof(io->control.s) * fdtosend++);
         break;

      case SOCKS_UDPASSOCIATE:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            gssid = io->src.auth.mdata.gssapi.state.id;
#endif /* HAVE_GSSAPI */

#if !BAREFOOTD /* no control. */
         CMSG_ADDOBJECT(io->control.s, cmsg,
                       sizeof(io->control.s) * fdtosend++);
#endif /* !BAREFOOTD */
         break;

      case SOCKS_CONNECT:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            gssid = io->src.auth.mdata.gssapi.state.id;
#endif /* HAVE_GSSAPI */
         break;

      default:
         SERRX(io->state.command);
   }

#if HAVE_GSSAPI
   if (gssid != GSS_C_NO_CONTEXT) {
      if (gssapi_export_state(&gssid, &gssapistate) != 0)
         return -1;

      iov[ioc].iov_base = gssapistate.value;
      iov[ioc].iov_len  = gssapistate.length;
      length           += gssapistate.length;
      ++ioc;

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: gssapistate has length %lu",
         function, (long unsigned)gssapistate.length);
   }
#endif /* HAVE_GSSAPI */

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ioc;
   msg.msg_name    = NULL;

   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdtosend);

   if ((w = sendmsgn(s,
                     &msg,
                     0,
                     /*
                      * if not mother, request child.  Since that child only
                      * handles one client at a time, it's safe to block
                      * as long as it takes.  Mother on the other hand should
                      * not block for long.
                      */
                     sockscf.state.type == CHILD_MOTHER ? 0 : -1)) != length) {
      slog(LOG_INFO, "%s: sendmsgn() failed.  Sent %ld/%ld (%s)",
            function, (long)length, (long)w, strerror(errno));

      return -1;
   }

   if (sockscf.option.debug >= DEBUG_VERBOSE) {
      char ctrlbuf[MAXSOCKADDRSTRING * 3], srcbuf[MAXSOCKADDRSTRING * 3],
           dstbuf[MAXSOCKADDRSTRING * 3];

      slog(LOG_DEBUG, "%s: sending %d descriptors for command %d.  "
                      "bw_shmid: %ld, ss_shmid: %ld\n"
                      "Control: %d (%s)\n"
                      "Src    : %d (%s)\n"
                      "Dst    : %d (%s)",
                      function, fdtosend, io->state.command,
                      io->rule.bw_shmid, io->rule.ss_shmid,
                      io->control.s,
                      socket2string(io->control.s, ctrlbuf, sizeof(ctrlbuf)),
                      io->src.s,
                      socket2string(io->src.s, srcbuf, sizeof(srcbuf)),
                      io->dst.s,
                      socket2string(io->dst.s, dstbuf, sizeof(dstbuf)));
   }

   return 0;
}

int
send_client(s, _client, buf, buflen)
   int s;
   const sockd_client_t *_client;
   const char *buf;
   const size_t buflen;
{
   const char *function = "send_client()";
   sockd_client_t client = *_client;
   struct iovec iovec[1];
   struct msghdr msg;
   CMSG_AALLOC(cmsg, sizeof(int));
   ssize_t rc;
   int fdtosend;

   slog(LOG_DEBUG, "%s: buflen = %lu", function, (unsigned long)buflen);

#if COVENANT
   if (buflen > 0) {
      memcpy(client.clientdata, buf, buflen);
      client.clientdatalen = buflen;
   }
#endif /* COVENANT */

   bzero(iovec, sizeof(iovec));
   iovec[0].iov_base = &client;
   iovec[0].iov_len  = sizeof(client);

   fdtosend = 0;
   CMSG_ADDOBJECT(client.s, cmsg, sizeof(client.s) * fdtosend++);

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iovec;
   msg.msg_iovlen  = ELEMENTS(iovec);
   msg.msg_name    = NULL;

   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdtosend);

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: sending socket %d (%s) ...",
      function, client.s, socket2string(client.s, NULL, 0));

   if ((rc = sendmsgn(s,
                      &msg,
                      0,
                      sockscf.state.type == CHILD_MOTHER ? 0 : -1))
                      != sizeof(client))   {
      swarn("%s: sendmsg(): sent %ld/%lu",
            function, (long)rc, (unsigned long)sizeof(client));

      return -1;
   }

   return 0;
}

int
send_req(s, req)
   int s;
   sockd_request_t *req;
{
   const char *function = "send_req()";
   struct iovec iov[2];
   struct msghdr msg;
   ssize_t rc;
   int fdtosend, ioc, length;
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   CMSG_AALLOC(cmsg, sizeof(int));

   ioc    = 0;
   length = 0;

   bzero(iov, sizeof(iov));
   iov[ioc].iov_base = req;
   iov[ioc].iov_len  = sizeof(*req);
   length           += iov[ioc].iov_len;
   ++ioc;

#if HAVE_GSSAPI
   if (req->socksauth.method == AUTHMETHOD_GSSAPI) {
      gssapistate.value   = gssapistatemem;
      gssapistate.length  = sizeof(gssapistatemem);

      if (gssapi_export_state(&req->socksauth.mdata.gssapi.state.id,
      &gssapistate) != 0)
         return 1;

      iov[ioc].iov_base = gssapistate.value;
      iov[ioc].iov_len  = gssapistate.length;
      length += iov[ioc].iov_len;
      ++ioc;

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: gssapistate has length %lu",
         function, (long unsigned)gssapistate.length);
   }
#endif /* HAVE_GSSAPI */

   fdtosend = 0;

   if (req->s == -1)
      SASSERTX(BAREFOOTD && req->req.command == SOCKS_UDPASSOCIATE);
   else
      CMSG_ADDOBJECT(req->s, cmsg, sizeof(req->s) * fdtosend++);

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ELEMENTS(iov);
   msg.msg_name    = NULL;

   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdtosend);

   if (sockscf.option.debug >= DEBUG_VERBOSE && req->s != -1)
      slog(LOG_DEBUG, "%s: sending socket %d (%s) ...",
      function, req->s, socket2string(req->s, NULL, 0));

   if ((rc = sendmsgn(s,
                      &msg,
                      0,
                      sockscf.state.type == CHILD_MOTHER ? 0 : -1)) != length) {
      swarn("%s: sendmsg() sent %ld/%ld", function, (long)rc, (long)length);
      return -1;
   }

   return 0;
}

void
sigchildbroadcast(sig, childtype)
   int sig;
   int childtype;
{
   const char *function = "sigchildbroadcast()";
   int childtypesv[] =  { CHILD_NEGOTIATE, CHILD_REQUEST, CHILD_IO };
   size_t *childc, childtypec;
   sockd_child_t **childv;

   for (childtypec = 0; childtypec < ELEMENTS(childtypesv); ++childtypec)
      if (childtype & childtypesv[childtypec]) {
         size_t i;

         setchildtype(childtypesv[childtypec], &childv, &childc, NULL);
         for (i = 0; i < *childc; ++i) {
            slog(LOG_DEBUG, "%s: sending signal %d to %s-child %lu",
                 function,
                 sig,
                 childtype2string(childtypesv[childtypec]),
                 (unsigned long)(*childv)[i].pid);

            if (kill((*childv)[i].pid, sig) != 0)
               swarn("%s: could not send signal %d to child process %lu",
                     function,
                     sig,
                     (unsigned long)(unsigned long)(*childv)[i].pid);
         }
   }
}

size_t
maxfreeslots(childtype)
   const int childtype;
{

   switch (childtype) {
      case CHILD_NEGOTIATE:
         return SOCKD_NEGOTIATEMAX;

      case CHILD_REQUEST:
         return SOCKD_REQUESTMAX;

      case CHILD_IO:
         return SOCKD_IOMAX;

      default:
         SERRX(childtype);
   }

   return 0; /* NOTREACHED */
}

void
sockd_print_child_ready_message(freefds)
   const size_t freefds;
{
   const char *function = "sockd_print_child_ready_message()";

   slog(LOG_DEBUG,
        "%s: I'm %s-child and ready to serve with %lu free fd%s "
        "and %lu free slot%s",
        function,
        childtype2string(sockscf.state.type),
        (unsigned long)freefds, freefds == 1 ? "" : "s",
        (unsigned long)maxfreeslots(sockscf.state.type),
        maxfreeslots(sockscf.state.type) == 1 ? "" : "s");
}
