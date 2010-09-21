/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2004, 2005, 2008, 2009,
 *               2010
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
"$Id: sockd_child.c,v 1.211.2.8.2.2 2010/09/21 11:24:43 karls Exp $";

#define MOTHER  (0)  /* descriptor mother reads/writes on.   */
#define CHILD   (1)   /* descriptor child reads/writes on.   */

static int
setchildtype(int type, struct sockd_child_t ***childv, size_t **childc,
      void (**function)(struct sockd_mother_t *mother));
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
   void (*childfunction)(struct sockd_mother_t *mother);
   struct sockd_mother_t mother;
   struct sockd_child_t **childv;
   pid_t ourpid, pid;
   socklen_t optlen;
   size_t *childc;
   int p, bufval, bufset, bufset2,
       datapipev[] = { -1, -1 }, ackpipev[] = { -1, -1 };
   /*
    * It is better to reserve some descriptors for temporary use
    * than to get errors when receiving from a child, and lose clients
    * that way, so make sure we always have some descriptors available.
    */
   const int reserved = FDPASS_MAX   /* max descriptors we receive/pass.  */
                      + 1            /* need a descriptor for accept().   */
                      + 2;           /* pipe to child.                    */

   /*
    * XXX This is an expensive test which shouldn't be hard to optimize away.
    */
   if ((p = freedescriptors(NULL)) < reserved) {
      swarnx("%s: only have %d free file descriptors left, need at least %d "
             "for a new process", function, p, reserved);
      errno = EMFILE;
      return NULL;
   }

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
          * A negotiator child receives only descriptors, so mothers
          * send buffer can be small, and so can the child's receive buffer.
          * The child sends a sockd_request_t struct back to mother, so
          * mothers recv buffer has to be considerably bigger, as does
          * childs send buffer.
          */
         bufval = (sizeof(struct sockd_request_t)
                + sizeof(struct msghdr)
                + CMSG_SPACE(sizeof(int)) * FDPASS_MAX)
                * SOCKD_NEGOTIATEMAX;
#if HAVE_GSSAPI
         bufval += (MAX_GSS_STATE + sizeof(struct iovec)) * SOCKD_NEGOTIATEMAX;
#endif /* HAVE_GSSAPI */

         bufval += SENDMSG_PADBYTES * SOCKD_NEGOTIATEMAX;

#if HAVE_SENDMSG_DEADLOCK
         if ((mother.lock = socks_mklock(SOCKS_LOCKFILE)) == -1) {
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

         bufval += SENDMSG_PADBYTES * SOCKD_REQUESTMAX;


#if HAVE_SENDMSG_DEADLOCK
         mother.lock = -1;   /* doesn't need lock. */
#endif /* HAVE_SENDMSG_DEADLOCK */

      case CHILD_IO:
         /*
          * A io child receives a sockd_io_t structure,
          * it sends back only an ack-byte.
          */

         bufval = (sizeof(struct sockd_io_t)
                +  sizeof(struct msghdr)
                +  CMSG_SPACE(sizeof(int)) * FDPASS_MAX)
                * SOCKD_IOMAX;
#if HAVE_GSSAPI
         bufval += (MAX_GSS_STATE + sizeof(struct iovec)) * SOCKD_IOMAX;
#endif /* HAVE_GSSAPI */

         bufval += SENDMSG_PADBYTES * SOCKD_REQUESTMAX;

#if HAVE_SENDMSG_DEADLOCK
         mother.lock = -1;   /* doesn't need lock. */
#endif /* HAVE_SENDMSG_DEADLOCK */

         break;

      default:
         SERRX(type);
   }

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
      return NULL;
   }

   if (bufset < bufval || bufset2 < bufval) {
      swarnx("%s: getsockopt(SO_RCVBUF/SO_SNDBUF) did not return "
             "requested value.  Requested: %d and %d, is: %d and %d",
             function, bufval, bufval, bufset, bufset2);
      closev(datapipev, ELEMENTS(datapipev));
      return NULL;
   }

   if (sockscf.option.debug > 1) {
      slog(LOG_DEBUG, "%s: minimum rcvbuf for mother and sndbuf for %s child: "
                      "%d and %d, set: %d and %d",
      function, childtype2string(type),
      bufval, bufval, bufset, bufset2);
   }

   /* so slog() doesn't log wrong pid if we crash here. */
   ourpid            =  sockscf.state.pid;
   sockscf.state.pid = 0;

   switch ((pid = fork())) {
      case -1:
         sockscf.state.pid = ourpid;

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
          * point, lest we accidentally run mothers signalhandler if the
          * child does not install it's own signalhandler for the
          * particular signal.
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

         sockscf.state.type = type;
         slog(LOG_INFO, "created new %schild", childtype2string(type));
#if 0
         slog(LOG_DEBUG, "sleeping...");
         sleep(10);
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

         mother.s   = datapipev[CHILD];
         mother.ack = ackpipev[CHILD];

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
          *
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

         errno = 0;

         time(&sockscf.stat.boot);

         childfunction(&mother);
         /* NOTREACHED */
      }

      default: {
         struct sockd_child_t *newchildv;

         sockscf.state.pid = ourpid;

         if ((newchildv = realloc(*childv,
         sizeof(**childv) * (*childc + 1))) == NULL) {
            slog(LOG_WARNING, "%s: %s", function, NOMEM);
            closev(datapipev, ELEMENTS(datapipev));
            closev(ackpipev, ELEMENTS(ackpipev));
            return NULL;
         }
         *childv = newchildv;

         (*childv)[*childc].type   = type;
         (*childv)[*childc].pid    = pid;
         (*childv)[*childc].s      = datapipev[MOTHER];
         (*childv)[*childc].ack    = ackpipev[MOTHER];
         (*childv)[*childc].sentc  = 0;
#if HAVE_SENDMSG_DEADLOCK
         (*childv)[*childc].lock   = mother.lock;
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
   size_t child, *childc, minfreeslots, maxslotsperproc, idle, proxyc;

   switch (type) {
      case -CHILD_NEGOTIATE:
      case CHILD_NEGOTIATE:
         childc          = &negchildc;
         childv          = &negchildv;
         minfreeslots    = SOCKD_FREESLOTS;
         maxslotsperproc = SOCKD_NEGOTIATEMAX;
         break;

      case -CHILD_REQUEST:
      case CHILD_REQUEST:
         childc          = &reqchildc;
         childv          = &reqchildv;
         minfreeslots    = SOCKD_FREESLOTS;
         maxslotsperproc = SOCKD_REQUESTMAX;
         break;

      case -CHILD_IO:
      case CHILD_IO:
         childc          = &iochildc;
         childv          = &iochildv;
         minfreeslots    = SOCKD_FREESLOTS;
         maxslotsperproc = SOCKD_IOMAX;
         break;

      default:
         SERRX(type);
   }

   /*
    * get a estimate over how many (new) clients our children are able to
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

      proxyc += type < 0 ? maxslotsperproc : (*childv)[child].freec;

      if ((*childv)[child].freec == maxslotsperproc) {
         /* all slots in this child idle. */
         ++idle;

         if (sockscf.child.maxidle > 0 && idle > sockscf.child.maxidle) {
            slog(LOG_DEBUG, "%s: already counted %d idle %s-children, "
                            "removing %s-child with pid %lu",
                            function, idle - 1,
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

   if (type >= 0) {
       if (proxyc < minfreeslots && sockscf.child.addchild) {
         slog(LOG_DEBUG, "%s: current # of free %s-slots is %d, thus less than "
                         "configured minimum of %d.  Trying to add a "
                         "%s-child",
                         function, childtype2string(type),
                         (unsigned long)proxyc, (unsigned long)minfreeslots,
                         childtype2string(type));

         if (addchild(type) != NULL)
            return childcheck(type);
         else
            sockscf.child.addchild = 0;   /* don't retry until a child dies. */
      }
   }

   return proxyc;
}

int
fillset(set)
   fd_set *set;
{
/*   const char *function = "fillset()"; */
   size_t i;
   int negc, reqc, ioc, dbits;

   /*
    * There is no point in setting data descriptor of child type N unless
    * child type N+1 is able to accept the data from child N.  So find
    * out if we have slots of the various types available .
    */

   ioc  = childcheck(CHILD_IO);
   reqc = childcheck(CHILD_REQUEST);
   negc = childcheck(CHILD_NEGOTIATE);

   FD_ZERO(set);
   dbits = -1;

   for (i = 0; i < sockscf.internalc; ++i) {
      SASSERTX(sockscf.internalv[i].s >= 0);
      FD_SET(sockscf.internalv[i].s, set);
      dbits = MAX(dbits, sockscf.internalv[i].s);
   }

   /* negotiator children. */
   for (i = 0; i < negchildc; ++i) {
      if (reqc > 0) {
         SASSERTX(negchildv[i].s >= 0);
         FD_SET(negchildv[i].s, set);
         dbits = MAX(dbits, negchildv[i].s);
      }

      /* we can always accept an ack of course. */
      SASSERTX(negchildv[i].ack >= 0);
      FD_SET(negchildv[i].ack, set);
      dbits = MAX(dbits, negchildv[i].ack);
   }

   /* request children. */
   for (i = 0; i < reqchildc; ++i) {
      if (ioc > 0) {
         SASSERTX(reqchildv[i].s >= 0);
         FD_SET(reqchildv[i].s, set);
         dbits = MAX(dbits, reqchildv[i].s);
      }

      /* we can always accept an ack of course. */
      SASSERTX(reqchildv[i].ack >= 0);
      FD_SET(reqchildv[i].ack, set);
      dbits = MAX(dbits, reqchildv[i].ack);
   }

   /* io children, last in chain. */
   for (i = 0; i < iochildc; ++i) {
      SASSERTX(iochildv[i].s >= 0);
      FD_SET(iochildv[i].s, set);
      dbits = MAX(dbits, iochildv[i].s);

      SASSERTX(iochildv[i].ack >= 0);
      FD_SET(iochildv[i].ack, set);
      dbits = MAX(dbits, iochildv[i].ack);
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
nextchild(type)
   int type;
{
   const char *function = "nextchild()";
   static fd_set *wset;
   struct timeval timeout;
   struct sockd_child_t **childv;
   size_t i, *childc;
   int maxd;

   setchildtype(type, &childv, &childc, NULL);

   if (wset == NULL)
      wset = allocate_maxsize_fdset();

   FD_ZERO(wset);
   for (i = 0, maxd = -1; i < *childc; ++i) {
      if ((*childv)[i].freec > 0) {
         FD_SET((*childv)[i].s, wset);
         maxd = MAX(maxd, (*childv)[i].s);
      }
   }

   if (maxd < 0) {
      slog(LOG_DEBUG, "%s: no free %s slots", function, childtype2string(type));
      return NULL;
   }

   ++maxd;

   timeout.tv_sec  = 0;
   timeout.tv_usec = 0;

   switch (selectn(maxd, NULL, NULL, wset, NULL, NULL, &timeout)) {
      case -1:
         if (errno == EINTR) /* can happen if checkforsignal() closes fd. */
            return nextchild(type);

         SERR(-1);
         /* NOTREACHED */

      case 0:
         slog(LOG_DEBUG, "%s: no child writable", function);
         return NULL;
   }

   return getset(DATAPIPE, wset);
}

static int
setchildtype(type, childv, childc, function)
   int type;
   struct sockd_child_t ***childv;
   size_t **childc;
   void (**function)(struct sockd_mother_t *mother);
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

   SERRX(pid);
   /* NOTREACHED */
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

      default:
         SERRX(type);
   }

   setchildtype(type, &childv, &childc, NULL);

   if ((child = findchild(pid, *childc, *childv)) != -1)
      return &(*childv)[child];
   return NULL;
}

int
send_io(s, io)
   int s;
   struct sockd_io_t *io;
{
   const char *function = "send_io()";
   struct iovec iov[2];
   struct msghdr msg;
   int ioc, w, fdsent, length;
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

   fdsent = 0;
   CMSG_ADDOBJECT(io->src.s, cmsg, sizeof(io->src.s) * fdsent++);
   CMSG_ADDOBJECT(io->dst.s, cmsg, sizeof(io->dst.s) * fdsent++);

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
            sizeof(io->control.s) * fdsent++);
         break;

      case SOCKS_BINDREPLY:
#if HAVE_GSSAPI
         if (io->dst.auth.method == AUTHMETHOD_GSSAPI)
            gssid = io->dst.auth.mdata.gssapi.state.id;
#endif /* HAVE_GSSAPI */

         if (io->state.extension.bind)
            CMSG_ADDOBJECT(io->control.s, cmsg,
            sizeof(io->control.s) * fdsent++);
         break;

      case SOCKS_UDPASSOCIATE:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            gssid = io->src.auth.mdata.gssapi.state.id;
#endif /* HAVE_GSSAPI */

#if !BAREFOOTD /* no control. */
         CMSG_ADDOBJECT(io->control.s, cmsg, sizeof(io->control.s) * fdsent++);
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
      ++ioc;
      length += gssapistate.length;

      slog(LOG_DEBUG, "%s: gssapistate has length %lu",
      function, (long unsigned)gssapistate.length);
   }
#endif /* HAVE_GSSAPI */

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ioc;
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

   if ((w = sendmsgn(s, &msg, 0)) != length)   {
      swarn("%s: sendmsg(): %d of %d", function, w, length);
      return -1;
   }

   slog(LOG_DEBUG, "%s: sent %d descriptors for command %d.  "
                   "Control: %d, src: %d, dst: %d",
                   function, fdsent, io->state.command,
                   io->control.s, io->src.s, io->dst.s);

   return 0;
}

int
send_client(s, client)
   int s;
   const struct sockd_client_t *client;
{
   const char *function = "send_client()";
   struct iovec iovec[1];
   struct msghdr msg;
   CMSG_AALLOC(cmsg, sizeof(int));
   ssize_t rc;
   int fdsent;

   bzero(iovec, sizeof(iovec));
   iovec[0].iov_base = client;
   iovec[0].iov_len  = sizeof(*client);

   fdsent = 0;
   CMSG_ADDOBJECT(client->s, cmsg, sizeof(client->s) * fdsent++);

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iovec;
   msg.msg_iovlen  = ELEMENTS(iovec);
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

   if ((rc = sendmsgn(s, &msg, 0)) != sizeof(*client))   {
      swarn("%s: sendmsg(): sent %ld/%ld",
      function, (long)rc, (long)sizeof(*client));

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
   int fdsent, ioc, length;
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

      slog(LOG_DEBUG, "%s: gssapistate has length %lu",
      function, (long unsigned)gssapistate.length);
   }
#endif /* HAVE_GSSAPI */

   fdsent = 0;

   if (req->s == -1)
      SASSERTX(BAREFOOTD && req->req.command == SOCKS_UDPASSOCIATE);
   else
      CMSG_ADDOBJECT(req->s, cmsg, sizeof(req->s) * fdsent++);

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ELEMENTS(iov);
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

   if (sendmsgn(s, &msg, 0) != length)   {
      swarn("%s: sendmsg()", function);
      return -1;
   }

   return 0;
}

void
sigchildbroadcast(sig, childtype)
   int sig;
   int childtype;
{
   size_t i;

   if (childtype & CHILD_NEGOTIATE)
      for (i = 0; i < negchildc; ++i)
         kill(negchildv[i].pid, sig);

   if (childtype & CHILD_REQUEST)
      for (i = 0; i < reqchildc; ++i)
         kill(reqchildv[i].pid, sig);

   if (childtype & CHILD_IO)
      for (i = 0; i < iochildc; ++i)
         kill(iochildv[i].pid, sig);
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
