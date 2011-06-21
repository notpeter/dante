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
"$Id: sockd_child.c,v 1.276 2011/06/19 14:33:57 michaels Exp $";

#define MOTHER  (0)  /* descriptor mother reads/writes on.   */
#define CHILD   (1)   /* descriptor child reads/writes on.   */

static int
setchildtype(int type, struct sockd_child_t ***childv, size_t **childc,
             void (**function)(void));
/*
 * Sets "childv", "childc" and "function" to the correct value depending
 * on "type".
 */

static int
findchild(pid_t pid, int childc, const struct sockd_child_t *childv);
/*
 * Finds the child with pid "pid" in the array "childv".  Searching
 * Elements in "childv" is given by "childc".
 * Returns:
 *      On success: the index of the child in "childv".
 *      On failure: -1.
 */

static struct sockd_child_t *
addchild(const int type);
/*
 * Adds a new child that can accept objects of type "type" from mother.
 * Returns:
 *    On success: a pointer to the added child.
 *    On failure: NULL.  (resource shortage.)
 */


static struct sockd_child_t *iochildv;          /* all our iochildren         */
static size_t iochildc;

static struct sockd_child_t *negchildv;         /* all our negotiatorchildren */
static size_t negchildc;

static struct sockd_child_t *reqchildv;         /* all our requestchildren    */
static size_t reqchildc;

static struct sockd_child_t *
addchild(type)
   const int type;
{
   const char *function = "addchild()";
   void (*childfunction)(void);
   struct sockd_mother_t mother;
   struct sockd_child_t **childv;
   pid_t pid;
   socklen_t optlen;
   size_t *childc;
   int p, bufval, bufset, bufset2, msg_sep_fuzz,
       datapipev[] = { -1, -1 }, ackpipev[] = { -1, -1 };

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
    * on what kind of data passes over the pipes.
    */
   switch (setchildtype(type, &childv, &childc, &childfunction)) {
      case CHILD_NEGOTIATE:
         /*
          * A negotiator child receives a sockd_client_t struct,
          * and sends back a sockd_request_t struct.
          */
         bufval = (MAX(sizeof(struct sockd_client_t),
                       sizeof(struct sockd_request_t))
                + sizeof(struct msghdr)
                + CMSG_SPACE(sizeof(int)) * FDPASS_MAX)
                * SOCKD_NEGOTIATEMAX;
#if HAVE_GSSAPI
         bufval += (MAX_GSS_STATE + sizeof(struct iovec)) * SOCKD_NEGOTIATEMAX;
#endif /* HAVE_GSSAPI */

         bufval       += SENDMSG_PADBYTES * SOCKD_NEGOTIATEMAX;
         msg_sep_fuzz  = 100 * SOCKD_NEGOTIATEMAX;

#if HAVE_SENDMSG_DEADLOCK
         if ((mother.lock = socks_mklock(SOCKS_LOCKFILE, NULL, 0)) == -1) {
            swarn("%s: socks_mklock()", function);

            closev(datapipev, ELEMENTS(datapipev));
            closev(ackpipev, ELEMENTS(ackpipev));

            return NULL;
         }
#endif /* HAVE_SENDMSG_DEADLOCK */

         break;

      case CHILD_REQUEST:
         /*
          * A request child receives a sockd_request_t structure,
          * it sends back a sockd_io_t structure.
          */
         bufval = (MAX(sizeof(struct sockd_request_t),
                       sizeof(struct sockd_io_t))
                + sizeof(struct msghdr)
                + CMSG_SPACE(sizeof(int)) * FDPASS_MAX)
                * SOCKD_REQUESTMAX;
#if HAVE_GSSAPI
         bufval += (MAX_GSS_STATE + sizeof(struct iovec)) * SOCKD_REQUESTMAX;
#endif /* HAVE_GSSAPI */

         bufval      += SENDMSG_PADBYTES * SOCKD_REQUESTMAX;
         msg_sep_fuzz = 100 * SOCKD_REQUESTMAX;

#if HAVE_SENDMSG_DEADLOCK
         mother.lock = -1;   /* doesn't need lock. */
#endif /* HAVE_SENDMSG_DEADLOCK */
         break;

      case CHILD_IO:
         /*
          * A io child receives a sockd_io_t structure,
          * it sends back only an ack-byte.
          * XXX that is not true in COVENANT's case.
          */

         bufval = (sizeof(struct sockd_io_t)
                +  sizeof(struct msghdr)
                +  CMSG_SPACE(sizeof(int)) * FDPASS_MAX)
                * SOCKD_IOMAX;
#if HAVE_GSSAPI
         bufval += (MAX_GSS_STATE + sizeof(struct iovec)) * SOCKD_IOMAX;
#endif /* HAVE_GSSAPI */

         bufval       += SENDMSG_PADBYTES * SOCKD_IOMAX;
         msg_sep_fuzz  = 100 * SOCKD_REQUESTMAX;

#if HAVE_SENDMSG_DEADLOCK
         mother.lock = -1;   /* doesn't need lock. */
#endif /* HAVE_SENDMSG_DEADLOCK */

         break;

      default:
         SERRX(type);
   }

   bufval += msg_sep_fuzz;

   if (setsockopt(datapipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &bufval,
   sizeof(bufval)) != 0
   ||  setsockopt(datapipev[MOTHER], SOL_SOCKET, SO_SNDBUF, &bufval,
   sizeof(bufval)) != 0
   ||  setsockopt(datapipev[CHILD],  SOL_SOCKET, SO_RCVBUF, &bufval,
   sizeof(bufval)) != 0
   ||  setsockopt(datapipev[CHILD],  SOL_SOCKET, SO_SNDBUF, &bufval,
   sizeof(bufval)) != 0)
      swarn("%s: setsockopt(SO_RCVBUF/SO_SNDBUF)", function);

   optlen = sizeof(bufset);
   if (getsockopt(datapipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &bufset, &optlen)
   != 0
   ||  getsockopt(datapipev[CHILD], SOL_SOCKET, SO_SNDBUF, &bufset2, &optlen)
   != 0){
      swarn("%s: getsockopt(SO_RCVBUF/SO_SNDBUF)", function);

      closev(datapipev, ELEMENTS(datapipev));
      closev(ackpipev, ELEMENTS(ackpipev));

      return NULL;
   }

   if (bufset < bufval || bufset2 < bufval) {
      swarnx("%s: getsockopt(SO_RCVBUF/SO_SNDBUF) did not return "
             "requested value.  Requested: %d and %d, returned: %d and %d.\n"
             "This probably means one of %s's SOCKD_NEGOTIATEMAX or "
             "SOCKD_IOMAX was at compile-time set to a value too large for "
             "your kernel.\n"
             "To avoid this error, you will need to either increase the "
             "kernel max-size socket buffers somehow, or decrease the values "
             "in %s and recompile.",
             function, bufval, bufval, bufset, bufset2, PACKAGE, PACKAGE);

      closev(datapipev, ELEMENTS(datapipev));
      closev(ackpipev, ELEMENTS(ackpipev));

      return NULL;
   }

   if (sockscf.option.debug > 1) {
      slog(LOG_DEBUG, "%s: minimum rcvbuf for mother and sndbuf for %s child: "
                      "%d and %d, set: %d and %d",
      function, childtype2string(type),
      bufval, bufval, bufset, bufset2);
   }

   switch ((pid = fork())) {
      case -1:
         swarn("%s: fork()", function);

         closev(datapipev, ELEMENTS(datapipev));
         closev(ackpipev, ELEMENTS(ackpipev));

#if HAVE_SENDMSG_DEADLOCK
         if (mother.lock != -1)
            close(mother.lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

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
            swarn("%s: sigaction(USR1)", function);

#if HAVE_PROFILING /* XXX is this only needed on linux? */
         moncontrol(1);
#endif /* HAVE_PROFILING */

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
      if (!sockscf.privileges.noprivs) {
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
          *      - could need privileges to listen for icmp errors.
          *      - could need privileges to bind port if using the
          *        redirect() module.
          *
          * Also, all may need privileges to re-read sockd.conf.
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

               if (!sockscf.privileges.noprivs) {
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
            if (i == (size_t)mother.s
#if HAVE_SENDMSG_DEADLOCK
            ||   i == (size_t)mother.lock
#endif /* HAVE_SENDMSG_DEADLOCK */
            ||   i == (size_t)mother.ack)
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

         slog(LOG_DEBUG, "created new %schild, data-pipe %d, ack-pipe %d",
         childtype2string(type), mother.s, mother.ack);

         sockscf.state.mother = mother;
         time(&sockscf.stat.boot);

         errno = 0;
         childfunction();
         /* NOTREACHED */
      }

      default: {
         struct sockd_child_t *newchildv;

         if ((newchildv = realloc(*childv,
         sizeof(**childv) * (*childc + 1))) == NULL) {
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

#if HAVE_SENDMSG_DEADLOCK
         (*childv)[*childc].lock           = mother.lock;
#endif /* HAVE_SENDMSG_DEADLOCK */

         close(datapipev[CHILD]);
         close(ackpipev[CHILD]);

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

int
childcheck(type)
   int type;
{
   const char *function = "childcheck()";
   struct sockd_child_t **childv;
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

      proxyc += type < 0 ? maxslotsperproc : (*childv)[child].freec;

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

         sockscf.child.addchild = 0;   /* don't retry until a child exits. */
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

            sockscf.child.addchild = 0;/* don't retry until a child exits. */
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
   const struct sockd_child_t *child;
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

struct sockd_child_t *
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
   struct sockd_child_t **childv;
   size_t *childc;
   int child;

   slog(LOG_DEBUG, "%s: pid %lu", function, (unsigned long)pid);

   if (pid == 0) {
      int childtypev[] = {CHILD_IO, CHILD_NEGOTIATE, CHILD_REQUEST};
      size_t i;

      for (i = 0; i < ELEMENTS(childtypev); ++i) {
         setchildtype(childtypev[i], &childv, &childc, NULL);

         while (*childc != 0) {
            SASSERTX((*childv)[0].pid != 0);
            removechild((*childv)[0].pid);
            setchildtype(childtypev[i], &childv, &childc, NULL);
         }
      }

      return;
   }

   setchildtype(childtype(pid), &childv, &childc, NULL);
   child = findchild(pid, *childc, *childv);
   SASSERTX(child != -1);

   close((*childv)[child].s);
   close((*childv)[child].ack);
#if HAVE_SENDMSG_DEADLOCK
    close((*childv)[child].lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

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

struct sockd_child_t *
nextchild(type, protocol)
   const int type;
   const int protocol;
{
   const char *function = "nextchild()";
   struct sockd_child_t **childv;
   size_t i, *childc;
   int triedagain = 0;

tryagain:
   setchildtype(type, &childv, &childc, NULL);

   for (i = 0; i < *childc; ++i)
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

         return &(*childv)[i];
      }

   slog(LOG_DEBUG, "%s: no free %s slots for protocol %s, triedagain = %d",
   function, childtype2string(type), protocol2string(protocol), triedagain);

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
   struct sockd_child_t ***childv;
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
   const struct sockd_child_t *childv;
{
   int i;

   for (i = 0; i < childc; ++i)
      if (childv[i].pid == pid)
         return i;

   return -1;
}

struct sockd_child_t *
getchild(pid)
   pid_t pid;
{
   int child, type;
   size_t *childc;
   struct sockd_child_t **childv;

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

   /* NOTREACHED */
   SERRX(pid);
}

int
send_io(s, io)
   int s;
   struct sockd_io_t *io;
{
   const char *function = "send_io()";
   struct iovec iov[2];
   struct msghdr msg;
   int ioc, w, fdtosend, length;
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
            CMSG_ADDOBJECT(io->control.s, cmsg,
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

      if (sockscf.option.debug > 1)
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
                      * as long as it takes.
                      */
                     sockscf.state.type == CHILD_MOTHER ? 1 : -1)) != length) {
      swarn("%s: sendmsgn() of length %ld failed.  Sent %ld",
            function, (long)length, (long)w);

      return -1;
   }

   if (sockscf.option.debug > 1) {
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
   const struct sockd_client_t *_client;
   const char *buf;
   const size_t buflen;
{
   const char *function = "send_client()";
   struct sockd_client_t client = *_client;
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

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: sending socket %d (%s) ...",
      function, client.s, socket2string(client.s, NULL, 0));

   if ((rc = sendmsgn(s, &msg, 0, 1)) != sizeof(client))   {
      swarn("%s: sendmsg(): sent %ld/%lu",
      function, (long)rc, (unsigned long)sizeof(client));

      return -1;
   }

   return 0;
}

int
send_req(s, req)
   int s;
   struct sockd_request_t *req;
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

      if (sockscf.option.debug > 1)
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

   if (sockscf.option.debug > 1 && req->s != -1)
      slog(LOG_DEBUG, "%s: sending socket %d (%s) ...",
      function, req->s, socket2string(req->s, NULL, 0));

   if ((rc = sendmsgn(s,
                      &msg,
                      0,
                      sockscf.state.type == CHILD_MOTHER ? 1 : -1)) != length) {
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
   int childtypesv[] =  { CHILD_NEGOTIATE, CHILD_REQUEST, CHILD_IO };
   size_t *childc, childtypec;
   struct sockd_child_t **childv;

   for (childtypec = 0; childtypec < ELEMENTS(childtypesv); ++childtypec)
      if (childtype & childtypesv[childtypec]) {
         size_t i;

         setchildtype(childtypesv[childtypec], &childv, &childc, NULL);
         for (i = 0; i < *childc; ++i)
            kill((*childv)[i].pid, sig);
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


#if DEBUG
void
printfd(io, prefix)
   const struct sockd_io_t *io;
   const char *prefix;
{
   const char *function = "printfd()";
   struct sockaddr name;
   socklen_t namelen;
   char namestring[MAXSOCKADDRSTRING];

   bzero(&name, sizeof(name));
   namelen = sizeof(name);
   /* LINTED pointer casts may be troublesome */
   if (getsockname(io->src.s, &name, &namelen) != 0)
      swarn("%s: getsockname(io->src)", function);
   else
      slog(LOG_DEBUG, "%s: io->src (%d), name: %s", prefix,
      io->src.s, sockaddr2string(&name, namestring, sizeof(namestring)));

   bzero(&name, sizeof(name));
   namelen = sizeof(name);
   /* LINTED pointer casts may be troublesome */
   if (getsockname(io->dst.s, &name, &namelen) != 0)
      swarn("%s: getsockname(io->dst)", function);
   else
      slog(LOG_DEBUG, "%s: io->dst (%d), name: %s", prefix, io->dst.s,
      sockaddr2string(&name, namestring, sizeof(namestring)));

   switch (io->state.command) {
      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (!io->state.extension.bind)
            break;
         /* else: */ /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE:
         bzero(&name, sizeof(name));
         namelen = sizeof(name);
         /* LINTED pointer casts may be troublesome */
         if (getpeername(io->control.s, &name, &namelen)
         != 0)
            swarn("%s: getpeername(io->control)", function);
         else  {
            if (namelen == 0)
               slog(LOG_DEBUG, "%s: io->control (%d), name: <none>",
               prefix, io->control.s);
            else
               slog(LOG_DEBUG, "%s: io->control (%d), name: %s",
               prefix, io->control.s,
               sockaddr2string(&name, namestring, sizeof(namestring)));
         }
         break;

      case SOCKS_CONNECT:
         break;

      default:
         SERRX(io->state.command);
   }
}
#endif /* DEBUG */
