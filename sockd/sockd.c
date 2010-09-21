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

static const char rcsid[] =
"$Id: sockd.c,v 1.408.2.8.2.5 2010/09/21 11:24:43 karls Exp $";

int
#if HAVE_SETPROCTITLE
main(int argc, char *argv[]);
#else
main(int argc, char *argv[], char *envp[]);
#endif /* HAVE_SETPROCTITLE */

static void modulesetup(void);

/*
 * signalhandler functions.  Upon reception of signal, "sig" is the real
 * signal value (> 0).  We then set a flag indicating we got a signal,
 * but we don't do anything and return immediately.  Later we are called
 * again, with "sig" having the value -(sig), to indicate we are not
 * executing in the signalhandler and it's safe to do whatever we
 * need to do.
 */
static void sigterm(int sig);
static void siginfo(int sig);
static void sigchld(int sig);
static void sigalrm(int sig);
static void sighup(int sig);

#if DEBUG
static void dotest(void);
/*
 * runs some internal tests if the define is set.  Only used
 * during development.
 */
#endif /* DEBUG */

static void
serverinit(int argc, char *argv[], char *envp[]);
/*
 * Initializes options/sockscf.  "argc" and "argv" should be
 * the arguments passed to main().
 * Exits on failure.
 */

static void
usage(int code);
/*
 * print usage.
 */

static void
showversion(void);
/*
 * show version info and exits.
 */

static void
showlicense(void);
/*
 * shows license and exits.
 */

static void
optioninit(void);
/*
 * sets unset options to a reasonable default.
 */

static void
checkconfig(void);
/*
 * Scans through the config, perhaps fixing some things and warning
 * about strange things, or erroring out on serious mistakes.
 */

#if DIAGNOSTIC && HAVE_MALLOC_OPTIONS
   extern char *malloc_options;
#endif /* DIAGNOSTIC && HAVE_MALLOC_OPTIONS */

#if HAVE_PROGNAME
extern char *__progname;
#else
char *__progname = "sockd";   /* default. */
#endif /* HAVE_PROGNAME */

extern char *optarg;

#define ELECTRICFENCE   0

#if ELECTRICFENCE
   extern int EF_PROTECT_FREE;
   extern int EF_ALLOW_MALLOC_0;
   extern int EF_ALIGNMENT;
   extern int EF_PROTECT_BELOW;
#endif /* ELECTRICFENCE */


int
#if HAVE_SETPROCTITLE
main(argc, argv)
#else
main(argc, argv, envp)
#endif /* HAVE_SETPROCTITLE */
   int   argc;
   char   *argv[];
#if !HAVE_SETPROCTITLE
   char    *envp[];
#endif /* HAVE_SETPROCTITLE */
{
   const char *function = "main()";
   FILE *fp;
   struct sigaction sigact;
   ssize_t p;
   size_t minfd, dforchild;
#if HAVE_SETPROCTITLE
   char *envp[] = { NULL }; /* dummy. */
#endif /* HAVE_SETPROCTITLE */

   const int exitsignalv[] = {
      SIGINT, SIGQUIT, SIGBUS, SIGSEGV, SIGTERM, SIGILL, SIGFPE
#ifdef SIGSYS
      , SIGSYS
#endif /* SIGSYS */
   };
   const size_t exitsignalc = ELEMENTS(exitsignalv);

   const int ignoresignalv[] = {
      SIGPIPE
   };
   const size_t ignoresignalc = ELEMENTS(ignoresignalv);

#if DIAGNOSTIC && HAVE_MALLOC_OPTIONS
   malloc_options = "AFGJP";
#endif /* DIAGNOSTIC && HAVE_MALLOC_OPTIONS */

#if ELECTRICFENCE
   EF_PROTECT_FREE         = 1;
   EF_ALLOW_MALLOC_0       = 1;
   EF_ALIGNMENT            = 0;
   EF_PROTECT_BELOW         = 0;
#endif /* ELECTRICFENCE */

#if DEBUG
   dotest();
#endif /* DEBUG */

   serverinit(argc, argv, envp);
   showconfig(&sockscf);

   /*
    * close any descriptor we don't need, both in case of chroot(2)
    * and needing every descriptor we can get.
    */

   /* syslog takes one */
   dforchild = sockscf.log.type & LOGTYPE_SYSLOG ? -1 : 0;
   for (p = 0, minfd = getmaxofiles(softlimit); (size_t)p < minfd; ++p) {
      size_t i;

      if (descriptorisreserved(p))
         continue;

      ++dforchild; /* descriptor will be usable by child. */

      /* sockets we listen on. */
      for (i = 0; i < sockscf.internalc; ++i) {
         if ((int)p == sockscf.internalv[i].s)
            break;

#if NEED_ACCEPTLOCK
         if (sockscf.option.serverc > 1)
            if ((int)p == sockscf.internalv[i].lock)
               break;
#endif /* NEED_ACCEPTLOCK */
      }
      if (i < sockscf.internalc) /* p is socket we listen on. */
         continue;

      close(p);
   }
   errno = 0;

   /*
    * Check system limits against what we need.
    * Enough descriptors for each child process?  +2 for pipes to mother.
    */

   /* CONSTCOND */
   minfd = MAX(SOCKD_NEGOTIATEMAX,
   MAX(SOCKD_REQUESTMAX, SOCKD_IOMAX * FDPASS_MAX)) + 2;

   if (dforchild < minfd) {
      struct rlimit rlimit;

      swarnx("%s: ... strange, we only have %lu descriptors available for "
             "child processes  ... need at least %lu.  Increasing ...",
             function, (unsigned long)dforchild, (unsigned long)minfd);

      rlimit.rlim_cur = rlimit.rlim_max = MIN(minfd, getmaxofiles(hardlimit));

      if (setrlimit(RLIMIT_OFILE, &rlimit) != 0) {
         const int maxofiles = getmaxofiles(softlimit);

         if (errno != EPERM)
            serr(EXIT_FAILURE, "setrlimit(RLIMIT_OFILE, %d)",
            (int)rlimit.rlim_max);
         else if (maxofiles < SOCKD_NEGOTIATEMAX + 2)
            serr(EXIT_FAILURE,
            "%d descriptors configured for negotiation, %d available",
            SOCKD_NEGOTIATEMAX + 2, maxofiles);
         else if (maxofiles < SOCKD_REQUESTMAX + 2)
            serr(EXIT_FAILURE,
            "%d descriptors configured for request completion, %d available",
            SOCKD_REQUESTMAX + 2, maxofiles);
         else if (maxofiles < SOCKD_IOMAX * FDPASS_MAX + 2)
            serr(EXIT_FAILURE,
            "%d descriptors configured for i/o, %d available",
            SOCKD_IOMAX * FDPASS_MAX + 2, maxofiles);
         else
            SERRX(maxofiles);
      }
   }

   /*
    * need to know max number of open files so we can allocate correctly
    * sized fd_sets.
    */
   sockscf.state.maxopenfiles = getmaxofiles(softlimit);

   /* set up signal handlers. */

   bzero(&sigact, sizeof(sigact));

   (void)sigemptyset(&sigact.sa_mask);
   sigact.sa_flags = SA_RESTART | SA_NOCLDSTOP;

   sigact.sa_handler = siginfo;
#if HAVE_SIGNAL_SIGINFO
   if (sigaction(SIGINFO, &sigact, NULL) != 0) {
      swarn("sigaction(SIGINFO)");
      return EXIT_FAILURE;
   }
#endif /* HAVE_SIGNAL_SIGINFO */

   /* same handler, for systems without SIGINFO. */
   if (sigaction(SIGUSR1, &sigact, NULL) != 0) {
      swarn("sigaction(SIGUSR1)");
      return EXIT_FAILURE;
   }

   sigact.sa_handler = sighup;
   if (sigaction(SIGHUP, &sigact, NULL) != 0) {
      swarn("sigaction(SIGHUP)");
      return EXIT_FAILURE;
   }

   sigact.sa_handler = sigchld;
   if (sigaction(SIGCHLD, &sigact, NULL) != 0) {
      swarn("sigaction(SIGCHLD)");
      return EXIT_FAILURE;
   }

   sigact.sa_handler = sigterm;
   for (p = 0; (size_t)p < exitsignalc; ++p)
      if (sigaction(exitsignalv[p], &sigact, NULL) != 0)
         swarn("sigaction(%d)", exitsignalv[p]);

   sigact.sa_handler = SIG_IGN;
   for (p = 0; (size_t)p < ignoresignalc; ++p)
      if (sigaction(ignoresignalv[p], &sigact, NULL) != 0)
         swarn("sigaction(%d)", ignoresignalv[p]);

   sigact.sa_flags   = 0;   /* want to be interrupted. */
   sigact.sa_handler = sigalrm;
   if (sigaction(SIGALRM, &sigact, NULL) != 0) {
      swarn("sigaction(SIGALRM)");
      return EXIT_FAILURE;
   }

   /*
    * Would have liked to move the daemon() call to after the "running"
    * message below, but we want to know who our children are.
    */
   if (sockscf.option.daemon)
      if (daemon(1, 0) != 0)
         serr(EXIT_FAILURE, "daemon()");

   newprocinit();

#if !HAVE_DISABLED_PIDFILE
   sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_ON);
   if ((fp = fopen(SOCKD_PIDFILE, "w")) == NULL) {
      swarn("open(%s)", SOCKD_PIDFILE);
      errno = 0;
   }
   sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_OFF);

   if (fp != NULL) {
      if (fprintf(fp, "%lu\n", (unsigned long)sockscf.state.pid) == EOF)
         swarn("fprintf(%s)", SOCKD_PIDFILE);
      fclose(fp);
   }
#endif /* !HAVE_DISABLED_PIDFILE */

   time(&sockscf.stat.boot);

   if ((sockscf.state.motherpidv = malloc(
   sizeof(*sockscf.state.motherpidv) * sockscf.option.serverc)) == NULL)
      serrx(EXIT_FAILURE, "%s", NOMEM);
   *sockscf.state.motherpidv = sockscf.state.pid;   /* main server. */

   /* fork of requested number of servers.  Start at one 'cause we are "it".  */
   for (p = 1; (size_t)p < sockscf.option.serverc; ++p) {
      pid_t pid;

      if ((pid = fork()) == -1)
         swarn("fork()");
      else if (pid == 0) {
         newprocinit();
         break;
      }
      else
         sockscf.state.motherpidv[p] = pid;
   }

   if (childcheck(CHILD_NEGOTIATE) <= 0
   ||  childcheck(CHILD_REQUEST)   <= 0
   ||  childcheck(CHILD_IO)        <= 0)
      serr(EXIT_FAILURE, "childcheck() failed");

#if HAVE_PROFILING /* XXX is this only needed on Linux? */
moncontrol(0);
#endif /* HAVE_PROFILING */

#if PRERELEASE
   slog(LOG_INFO, "\n"
   "   ******************************************************************\n"
   "   *** Thank you for testing this %s pre-release.              ***\n"
   "   *** Please note pre-releases are always configured in a way    ***\n"
   "   *** that puts a considerably larger load on the running system ***\n"
   "   *** system than the standard releases.                         ***\n"
   "   *** This is to help simulate high-load situations.             ***\n"
   "   ******************************************************************",
   PACKAGE);
#endif /* PRERELEASE */

   slog(LOG_INFO, "%s/server v%s running", PACKAGE, VERSION);

   /*
    * main loop; accept new connections and handle our children.
    */

   /* CONSTCOND */
   while (1) {
      static fd_set *rset;
      struct sockd_child_t *child;
      int rbits;
#if BAREFOOTD
      struct timeval timeout  = { 0, 0 };
#endif /* BAREFOOTD */

      if (rset == NULL)
         rset = allocate_maxsize_fdset();

      rbits = fillset(rset);

#if BAREFOOTD
      switch ((p = selectn(++rbits, rset, NULL, NULL, NULL, NULL,
      sockscf.state.alludpbounced ? NULL : &timeout)))
#else /* SOCKS_SERVER */
      switch ((p = selectn(++rbits, rset, NULL, NULL, NULL, NULL, NULL)))
#endif /* SOCKS_SERVER */
      {
         case 0:
#if BAREFOOTD
            break;
#else /* SOCKS_SERVER */
            SERR(errno);
            /* NOTREACHED */
#endif /* SOCKS_SERVER */

         case -1:
            if (errno == EINTR)
               continue;

            SERR(errno);
            /* NOTREACHED */
      }

      /*
       * handle our children.
       */

      /* first, get ack of free slots. */
      while ((child = getset(ACKPIPE, rset)) != NULL) {
         char command;
         int childisbad = 0, childhasfinished = 0;

         if ((p = socks_recvfromn(child->ack, &command, sizeof(command),
         sizeof(command), 0, NULL, NULL, NULL)) != sizeof(command)) {
            switch (p) {
               case -1:
                  swarn("socks_recvfromn(child->ack) from %schild %lu failed",
                  childtype2string(child->type), (unsigned long)child->pid);
                  break;

               case 0:
                  swarnx("eof from %schild %lu",
                  childtype2string(child->type), (unsigned long)child->pid);
                  break;

               default:
                  swarnx("unexpected byte count from %schild %lu.  "
                         "Expected %lu, got %lu",
                         childtype2string(child->type),
                         (unsigned long)child->pid,
                         (unsigned long)sizeof(command), (unsigned long)p);
            }

            childisbad = 1;
         }
         else {
            switch(command) {
               case SOCKD_FREESLOT:
                  ++child->freec;

                  slog(LOG_DEBUG, "%s: %s-child %lu has freed a slot, now has "
                                  "%lu slot%s free",
                                  function, childtype2string(child->type),
                                  (unsigned long)child->pid,
                                  child->freec, child->freec == 1 ? "" : "s");

                  if (child->type == CHILD_IO) {
                     /*
                      * don't really receive anything back from i/o childs
                      * except the freeslot ack, as i/o childs are the
                      * last in the chain.  Only reason to care about
                      * freec in the case of io-child is that for
                      * statistics, so we wait for the ack.
                      */
                     ++sockscf.stat.io.received;

                     if (sockscf.child.maxrequests != 0
                     &&  child->freec == maxfreeslots(child->type)
                     &&  child->sentc >= sockscf.child.maxrequests)
                        childhasfinished = 1;
                  }

                  break;

               default:
                  SERRX(command);
            }
         }

         clearset(ACKPIPE, child, rset);

         if (childhasfinished)
            slog(LOG_DEBUG, "closing connection to %s-child %lu as it "
                            "has now handled %lu request%s",
                            childtype2string(child->type),
                            (unsigned long)child->pid,
                            (unsigned long)child->sentc,
                            (unsigned long)child->sentc == 1 ? "" : "s");

         if (childhasfinished || childisbad) {
            removechild(child->pid);

            /*
             * Can no longer be sure we have any free slots to handle
             * new requests.  Finish handling ack of free slots,
             * but after that, restart the loop.
             */
            FD_ZERO(rset);
            break;
         }
      }

      /* next, get new requests. */
      while ((child = getset(DATAPIPE, rset)) != NULL) {
#if DIAGNOSTIC
         int freed = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif /* DIAGNOSTIC */
         int childisbad = 0, childhasfinished = 0;

         switch (child->type) {
            /*
             * in the order a packet travels between children;
             * negotiate -> request -> io.
             */

            case CHILD_NEGOTIATE: {
               struct sockd_request_t req;
               struct sockd_child_t *reqchild;

               if ((reqchild = nextchild(CHILD_REQUEST)) == NULL) {
                  slog(LOG_INFO, "no request child to accept new request");
                  break;
               }

               SASSERTX(reqchild->freec > 0);

               /* receive request from negotiator child... */
               if ((p = recv_req(child->s, &req)) != 0) {
                  childisbad = 1;
                  break;
               }
               ++sockscf.stat.negotiate.received;

               /* and send it to a request child. */
               if ((p = send_req(reqchild->s, &req)) == 0) {
                  --reqchild->freec;
                  ++reqchild->sentc;
                  ++sockscf.stat.request.sendt;
               }
               else {
                  clearset(DATAPIPE, child, rset);
                  childisbad = 1;
                  child = reqchild;
               }

               if (req.s == -1)
                  SASSERTX(BAREFOOTD && req.req.command == SOCKS_UDPASSOCIATE);
               else
                  close(req.s);
               break;
            }

            case CHILD_REQUEST: {
               struct sockd_io_t io;
               struct sockd_child_t *iochild;

               if ((iochild = nextchild(CHILD_IO)) == NULL) {
                  slog(LOG_INFO, "no io child to accept new request");
                  break;
               }

               SASSERTX(iochild->freec > 0);

               /* get io from request child ... */
               if ((p = recv_io(child->s, &io)) != 0) {
                  childisbad = 1;
                  break;
               }
               ++sockscf.stat.request.received;

               /* and send it to a io child. */
               if ((p = send_io(iochild->s, &io)) == 0) {
                  --iochild->freec;
                  ++iochild->sentc;
                  ++sockscf.stat.io.sendt;
               }
               else {
                  clearset(DATAPIPE, child, rset);
                  childisbad = 1;
                  child = iochild;
               }

               close_iodescriptors(&io);
               break;
            }

            case CHILD_IO:
               /*
                * the only thing a iochild should return is a ack each time
                * it finishes with a io, and that is handled in loop at
                * the start.
                */
               break;
         }

#if DIAGNOSTIC
         if (freed != freedescriptors(sockscf.option.debug ?  "end" : NULL))
            swarnx("%s: lost %d file descriptor%s communicating with children",
            function, freed - freedescriptors(NULL),
            (freed - freedescriptors(NULL)) == 1 ? "" : "s");

#endif /* DIAGNOSTIC */
         clearset(DATAPIPE, child, rset);

         if (childisbad) { /* error/eof from child. */
            switch (errno) {
               case EMFILE:
               case ENFILE:
                  break;   /* child is ok, we are not. */

               default:
                  removechild(child->pid);
                  FD_ZERO(rset);
            }
         }
         else if (sockscf.child.maxrequests != 0
         &&       child->freec == maxfreeslots(child->type)
         &&       child->sentc >= sockscf.child.maxrequests) {
            slog(LOG_DEBUG, "closing connection to %s-child %lu as it "
                            "has now handled %lu request%s",
                            childtype2string(child->type),
                            (unsigned long)child->pid,
                            (unsigned long)child->sentc,
                            (unsigned long)child->sentc == 1 ? "" : "s");

            removechild(child->pid);
            FD_ZERO(rset);
         }
      }

      /*
       * handled our children.  Is there a new connection pending now?
       */
      for (p = 0; (size_t)p < sockscf.internalc; ++p) {
         char accepted[MAXSOCKADDRSTRING];
         struct sockd_client_t client;

         if (FD_ISSET(sockscf.internalv[p].s, rset)) {
            const struct listenaddress_t *l = &sockscf.internalv[p];
            struct sockd_child_t *negchild;
            struct sockaddr from;
            socklen_t len;

#if NEED_ACCEPTLOCK
            if (sockscf.option.serverc > 1)
               if (socks_lock(l->lock, F_WRLCK, 0) != 0)
                  continue;
#endif /* NEED_ACCEPTLOCK */

            len = sizeof(from);
            client.s = acceptn(l->s, &from, &len);

#if NEED_ACCEPTLOCK
            if (sockscf.option.serverc > 1)
               socks_unlock(l->lock);
#endif /* NEED_ACCEPTLOCK */


            if (client.s == -1)
               switch (errno) {
#ifdef EPROTO
                  case EPROTO:         /* overloaded SVR4 error */
#endif /* EPROTO */
                  case EWOULDBLOCK:    /* BSD */
                  case ENOBUFS:        /* HPUX */
                  case ECONNABORTED:   /* POSIX */

                  /* rest appears to be Linux stuff according to apache src. */
#ifdef ECONNRESET
                  case ECONNRESET:
#endif /* ECONNRESET */
#ifdef ETIMEDOUT
                  case ETIMEDOUT:
#endif /* ETIMEDOUT */
#ifdef EHOSTUNREACH
                  case EHOSTUNREACH:
#endif /* EHOSTUNREACH */
#ifdef ENETUNREACH
                  case ENETUNREACH:
#endif /* ENETUNREACH */

                     if (sockscf.option.serverc > 1 && errno == EWOULDBLOCK)
                        slog(LOG_DEBUG, "accept(): %s", strerror(errno));
                     else
                        swarn("accept(): %s", strerror(errno));

                     /* connection aborted/failed/was taken by other process. */
                     continue;

                  /*
                   * this should never happen since childcheck(), if
                   * initially successful, should make sure there is
                   * always enough descriptors available before we
                   * try to do accept(2).
                   */
                  case ENFILE:
                  case EMFILE:
                     /* FALLTHROUGH */

                  default:
                     SERR(client.s);
               }

            gettimeofday(&client.accepted, NULL);
            ++sockscf.stat.accepted;

#if HAVE_LINUX_BUGS
            /*
             * yes, Linux manages to lose the descriptor flags, workaround
             * might be insufficient.
             */
            if (fcntl(client.s, F_SETFL, fcntl(l->s, F_GETFL, 0)) != 0)
               swarn("tried to work around Linux bug via fcntl()");
#endif /* HAVE_LINUX_BUGS */

            slog(LOG_DEBUG, "got accept(): %s",
            sockaddr2string(&from, accepted, sizeof(accepted)));

            if ((negchild = nextchild(CHILD_NEGOTIATE)) == NULL) {
               swarnx("new client from %s dropped: no resources "
               "(no free negotiator slots / file descriptors)", accepted);

               close(client.s);
               continue;
            }

            if (send_client(negchild->s, &client) == 0) {
               --negchild->freec;
               ++negchild->sentc;
               ++sockscf.stat.negotiate.sendt;
            }
            else {
               switch (errno) {
                  case EMFILE:
                  case ENFILE:
                     break;   /* child is ok, we are not. */

                  default:
                     removechild(negchild->pid);
                     negchild = NULL;
                     FD_ZERO(rset);
               }
            }

#if HAVE_SENDMSG_DEADLOCK
            if (negchild != NULL)
               socks_unlock(negchild->lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

            close(client.s);
         }
      }
   }
   /* NOTREACHED */
}

static void
usage(code)
   int code;
{

   fprintf(code == 0 ? stdout : stderr,
   "%s v%s.  Copyright (c) 1997 - 2010, Inferno Nettverk A/S, Norway.\n"
   "usage: %s [-DLNVdfhnv]\n"
   "   -D             : run in daemon mode\n"
   "   -L             : shows the license for this program\n"
   "   -N <number>    : fork of <number> servers [1]\n"
   "   -V             : verify configuration and exit\n"
   "   -d             : enable debugging\n"
   "   -f <filename>  : use <filename> as configuration file [%s]\n"
   "   -h             : print this information\n"
   "   -n             : disable TCP keep-alive\n"
   "   -v             : print version info\n",
   PACKAGE, VERSION,
   __progname,
   SOCKD_CONFIGFILE);

   exit(code);
}

static void
showversion(void)
{

   printf("%s: %s v%s\n", __progname, PACKAGE, VERSION);
   exit(EXIT_SUCCESS);
}

static void
showlicense(void)
{

   printf("%s: %s v%s\n%s\n", __progname, PACKAGE, VERSION,
"\
/*\n\
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,\n\
 *               2007, 2008, 2009, 2010\n\
 *      Inferno Nettverk A/S, Norway.  All rights reserved.\n\
 *\n\
 * Redistribution and use in source and binary forms, with or without\n\
 * modification, are permitted provided that the following conditions\n\
 * are met:\n\
 * 1. The above copyright notice, this list of conditions and the following\n\
 *    disclaimer must appear in all copies of the software, derivative works\n\
 *    or modified versions, and any portions thereof, aswell as in all\n\
 *    supporting documentation.\n\
 * 2. All advertising materials mentioning features or use of this software\n\
 *    must display the following acknowledgement:\n\
 *      This product includes software developed by\n\
 *      Inferno Nettverk A/S, Norway.\n\
 * 3. The name of the author may not be used to endorse or promote products\n\
 *    derived from this software without specific prior written permission.\n\
 *\n\
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n\
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n\
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. \n\
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n\
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n\
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n\
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n\
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT \n\
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n\
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n\
 *\n\
 * Inferno Nettverk A/S requests users of this software to return to\n\
 * \n\
 *  Software Distribution Coordinator  or  sdc@inet.no\n\
 *  Inferno Nettverk A/S\n\
 *  Oslo Research Park\n\
 *  Gaustadalléen 21\n\
 *  NO-0349 Oslo\n\
 *  Norway\n\
 * \n\
 * any improvements or extensions that they make and grant Inferno Nettverk A/S\n\
 * the rights to redistribute these changes.\n\
 *\n\
 */");

   exit(EXIT_SUCCESS);
}

/* ARGSUSED */ /* need envp if no HAVE_SETPROCTITLE */
static void
serverinit(argc, argv, envp)
   int argc;
   char *argv[];
   char *envp[];
{
   const char *function = "serverinit()";
   size_t i;
   int ch, verifyonly = 0;

#if !HAVE_PROGNAME
   if (argv[0] != NULL) {
      if ((__progname = strrchr(argv[0], '/')) == NULL)
         __progname = argv[0];
      else
         ++__progname;
   }
#endif /* !HAVE_PROGNAME */

#if !HAVE_SETPROCTITLE
   if (initsetproctitle(argc, argv, envp) == -1)
      serr(EXIT_FAILURE, "%s: malloc", function);
#endif /* !HAVE_SETPROCTITLE*/

   sockscf.child.addchild  = 1;
   sockscf.state.euid      = geteuid();
   sockscf.state.type      = CHILD_MOTHER;
   sockscf.option.serverc  = 1;   /* ourselves. ;-) */
   sockscf.bwlock          = -1;
   sockscf.sessionlock     = -1;

   while ((ch = getopt(argc, argv, "DLN:Vdf:hlnv")) != -1) {
      switch (ch) {
         case 'D':
            sockscf.option.daemon = 1;
            break;

         case 'L':
            showlicense();
            /* NOTREACHED */

         case 'N': {
            char *endptr;

            if ((sockscf.option.serverc = (int)strtol(optarg, &endptr, 10))
            < 1 ||  *endptr != NUL)
               serrx(EXIT_FAILURE, "%s: illegal value for -%c: %s",
               function, ch, optarg);
            break;
         }

         case 'V':
            verifyonly = 1;
            break;

         case 'd':
            ++sockscf.option.debug;
            break;

         case 'f':
#if !HAVE_SETPROCTITLE
            /* let it point outside argv for replacement setproctitle(). */
            if ((sockscf.option.configfile = strdup(optarg)) == NULL)
               serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
#else
            sockscf.option.configfile = optarg;
#endif /* !HAVE_SETPROCTITLE */
            break;

         case 'h':
            usage(0);
            /* NOTREACHED */

         case 'l':
            swarnx("option -%c is deprecated", ch);
            break;

         case 'n':
            sockscf.option.keepalive = 0;
            break;

         case 'v':
            showversion();
            /* NOTREACHED */

         default:
            usage(1);
      }
   }

   argc -= optind;
   argv += optind;

   if (argc > 0)
      serrx(EXIT_FAILURE, "%s: unknown argument %s", function, *argv);

   if (sockscf.option.configfile == NULL)
      sockscf.option.configfile = SOCKD_CONFIGFILE;

   optioninit();
   genericinit();
   newprocinit();
   checkconfig();

   init_privs();

   modulesetup();

   if (verifyonly) {
      showconfig(&sockscf);
      exit(EXIT_SUCCESS);
   }

   for (i = 0; i < sockscf.internalc; ++i) {
      int flags;
      struct listenaddress_t *l = &sockscf.internalv[i];

      if ((l->s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
         serr(EXIT_FAILURE, "%s: socket(SOCK_STREAM)", function);

      setsockoptions(l->s);

      if (sockd_bind(l->s, (struct sockaddr *)&l->addr, 1) != 0) {
         char badbind[MAXSOCKADDRSTRING];

         /* LINTED pointer casts may be troublesome */
         serr(EXIT_FAILURE, "%s: bind of address %s failed",
                            function,
                            sockaddr2string((struct sockaddr *)&l->addr,
                            badbind, sizeof(badbind)));
      }

      if (listen(l->s, SOCKD_MAXCLIENTQUE) == -1)
         serr(EXIT_FAILURE, "%s: listen(%d)", function, SOCKD_MAXCLIENTQUE);

      /*
       * We want to accept(2) on a non-blocking descriptor, and
       * keep it non-blocking while negotiating also.
       */
      if ((flags = fcntl(l->s, F_GETFL, 0)) == -1
      ||  fcntl(l->s, F_SETFL, flags | O_NONBLOCK) == -1)
         serr(EXIT_FAILURE, "%s: fcntl()", function);

#if NEED_ACCEPTLOCK
      if (sockscf.option.serverc > 1)
         if ((l->lock = socks_mklock(SOCKS_LOCKFILE)) == -1)
            serr(EXIT_FAILURE, "%s: socks_mklock()", function);
#endif /* NEED_ACCEPTLOCK */
   }
}

/* ARGSUSED */
static void
sigterm(sig)
   int sig;
{
   const char *function = "sigterm()";

   if (sig > 0) {
      if (SIGNALISOK(sig)) {
         /*
          * A safe signal, but we don't know where we are at this
          * point, and our logging uses some non-signal safe functions,
          * so don't risk exiting and logging now.
          * Instead the code in the normal flow will check for gotten
          * signals and call us if set.
          */

         sockd_pushsignal(sig);
         return;
      }
      else {
         /*
          * A bad signal, something has crashed.  Can't count
          * on it being possible to continue from here, have
          * to exit now.
          */
         sockscf.state.insignal = sig;
         swarn("%s: exiting on signal %d", function, sig);
      }
   }
   else {
      if (sockscf.state.signalc > 0) {
         sockscf.state.insignal = -sig;
         sig = -sig;
         slog(LOG_DEBUG, "%s: exiting due to previously received signal: %d",
         function, sig);

      }
   }

   sockdexit(SIGNALISOK(sig) ? EXIT_SUCCESS : EXIT_FAILURE);
}


/* ARGSUSED */
static void
siginfo(sig)
   int sig;
{
   const char *function = "siginfo()";
   unsigned long seconds, days, hours, minutes;
   size_t clients;

   if (sig > 0) {
      sockd_pushsignal(sig);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, function);

   clients = 0;
   clients += childcheck(-CHILD_NEGOTIATE);
   clients += childcheck(-CHILD_REQUEST);
   clients += childcheck(-CHILD_IO);

   clients -= childcheck(CHILD_NEGOTIATE);
   clients -= childcheck(CHILD_REQUEST);
   clients -= childcheck(CHILD_IO);

   seconds = difftime(time(NULL), sockscf.stat.boot);

   if (seconds >= 3600 * 24) {
      days     = seconds / (3600 * 24);
      seconds -= days * 3600 * 24;
   }
   else
      days = 0;

   if (seconds >= 3600) {
      hours    = seconds / 3600;
      seconds -= hours * 3600;
   }
   else
      hours = 0;

   if (seconds >= 60) {
      minutes  = seconds / 60;
      seconds -= minutes * 60;
   }
   else
      minutes = 0;

   slog(LOG_INFO, "%s v%s up %lu day%s, %lu:%.2lu, a: %lu, h: %lu c: %lu",
   PACKAGE, VERSION, days, days == 1 ? "" : "s", hours, minutes,
   (unsigned long)sockscf.stat.accepted,
   (unsigned long)sockscf.stat.negotiate.sendt,
   (unsigned long)clients);

   slog(LOG_INFO, "negotiators (%d): a: %lu, h: %lu, c: %lu",
   childcheck(-CHILD_NEGOTIATE) / SOCKD_NEGOTIATEMAX,
   (unsigned long)sockscf.stat.negotiate.sendt,
   (unsigned long)sockscf.stat.negotiate.received,
   (unsigned long)childcheck(-CHILD_NEGOTIATE) - childcheck(CHILD_NEGOTIATE));

   slog(LOG_INFO, "requesters (%d): a: %lu, h: %lu, c: %lu",
   childcheck(-CHILD_REQUEST) / SOCKD_REQUESTMAX,
   (unsigned long)sockscf.stat.request.sendt,
   (unsigned long)sockscf.stat.request.received,
   (unsigned long)childcheck(-CHILD_REQUEST) - childcheck(CHILD_REQUEST));

   slog(LOG_INFO, "iorelayers (%d): a: %lu, h: %lu, c: %lu",
   childcheck(-CHILD_IO) / SOCKD_IOMAX,
   (unsigned long)sockscf.stat.io.sendt,
   (unsigned long)sockscf.stat.io.received,
   (unsigned long)childcheck(-CHILD_IO) - childcheck(CHILD_IO));

   if (pidismother(sockscf.state.pid) == 1)   /* main mother */
      sigserverbroadcast(sig);

   sigchildbroadcast(sig, CHILD_NEGOTIATE | CHILD_REQUEST | CHILD_IO);
}


/* ARGSUSED */
static void
sighup(sig)
   int sig;
{
   const char *function = "sighup()";
   int p;

   if (sig > 0) {
      sockd_pushsignal(sig);
      return;
   }

   sig = -sig;

   slog(LOG_INFO, "%s: got SIGHUP, reloading ...", function);

   sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
   resetconfig();
   optioninit();
   genericinit();
   checkconfig();
   sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);

   modulesetup();

   /* LINTED assignment in conditional context */
   if ((p = pidismother(sockscf.state.pid))) {
      if (p == 1) { /* main mother. */
         showconfig(&sockscf);
         sigserverbroadcast(sig);
      }

      sigchildbroadcast(sig, CHILD_NEGOTIATE | CHILD_REQUEST | CHILD_IO);
   }
}

/* ARGSUSED */
static void
sigchld(sig)
   int sig;
{
   const char *function = "sigchld()";
   static int deaths;
   pid_t pid;
   int status;

   if (sig > 0) {
      sockd_pushsignal(sig);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, function);

   while (1) {
      pid = waitpid(WAIT_ANY, &status, WNOHANG);

      if (pid == -1 && errno == EINTR)
         continue;

      if (pid <= 0)
         break;

      slog(LOG_DEBUG, "%s: process %lu exited", function, (unsigned long)pid);

      if (pidismother(pid))
         sockscf.state.motherpidv[pidismother(pid) - 1] = 0;

      /* else;  assume relay child. */
      ++deaths;
   }

   if (sockscf.child.maxidle == 0) {
      /*
       * If maxidle is not set, and many children suddenly die, that
       * probably means something is wrong, so check for it.
       */
      static time_t deathtime;

      if (deathtime == 0)
         time(&deathtime);

      if (difftime(time(NULL), deathtime) > 10) { /* enough time; reset.  */
         deaths = 0;
         time(&deathtime);
      }

      if (deaths >= 10) {
         if (deaths == 10) { /* only log once. */
            slog(LOG_ERR, "%s: %d child deaths in %.0fs.  "
                           "Locking count for a while",
                           function, deaths, difftime(time(NULL), deathtime));

            sockscf.child.addchild = 0;
         }

         time(&deathtime); /* once the ball starts rolling... */
         alarm(10);
      }
      else
         sockscf.child.addchild = 1; /* if we could not before, now we can. */
   }

   sockscf.child.addchild = 1; /* if we could not before, now we can. */
}

/* ARGSUSED */
static void
sigalrm(sig)
   int sig;
{

   sockscf.child.addchild = 1;
}

static void
optioninit(void)
{
   /*
    * initialize misc. options to sensible default.
    */

   sockscf.resolveprotocol       = RESOLVEPROTOCOL_UDP;

   sockscf.option.directfallback = socks_getenv("SOCKS_DIRECTROUTE_FALLBACK",
                                                isfalse) ? 0 : 1;

   sockscf.option.keepalive      = 1;
   sockscf.option.udpconnectdst  = 1;
   sockscf.timeout.negotiate     = SOCKD_NEGOTIATETIMEOUT;
   sockscf.timeout.tcpio         = SOCKD_IOTIMEOUT_TCP;
   sockscf.timeout.udpio         = SOCKD_IOTIMEOUT_UDP;
   sockscf.external.rotation     = ROTATION_NONE;

#if HAVE_PAM
   sockscf.state.pamservicename     = DEFAULT_PAMSERVICENAME;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
   sockscf.state.gssapiservicename  = DEFAULT_GSSAPISERVICENAME;
   sockscf.state.gssapikeytab       = DEFAULT_GSSAPIKEYTAB;
#endif /* HAVE_GSSAPI */

#if BAREFOOTD
   /*
    * Enable all methods that are not socks-dependent.
    */

   sockscf.methodc = 0;
   sockscf.methodv[sockscf.methodc++] = AUTHMETHOD_NONE;
   sockscf.methodv[sockscf.methodc++] = AUTHMETHOD_PAM;
   sockscf.methodv[sockscf.methodc++] = AUTHMETHOD_RFC931;

   sockscf.clientmethodc = 0;
   sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;
   sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_PAM;
   sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_RFC931;
#endif /* BAREFOOTD */

#if DEBUG
   sockscf.child.maxidle         = SOCKD_FREESLOTS * 2;
   sockscf.child.maxrequests     = 2;
#else
   sockscf.child.maxidle         = 0;
   sockscf.child.maxrequests     = 0;
#endif /* DEBUG */
}

static void
checkconfig(void)
{
   const char *function = "checkconfig()";
#if HAVE_PAM
   const char *pamservicename;
#endif /* HAVE_PAM */
#if HAVE_GSSAPI
   const char *gssapiservicename, *gssapikeytab;
#endif /* HAVE_GSSAPI */
   uid_t euid;
   struct rule_t *basev[] = { sockscf.crule, sockscf.srule };
   int isclientrulev[]   = { 1, 0} ;
   int *methodbasev[]    = { sockscf.clientmethodv, sockscf.methodv };
   size_t *methodbasec[] = { &sockscf.clientmethodc, &sockscf.methodc };
   size_t i, basec;

#if !HAVE_DUMPCONF
#if !HAVE_PRIVILEGES
   if (!sockscf.uid.privileged_isset)
      sockscf.uid.privileged = sockscf.state.euid;
   else {
      if (socks_seteuid(&euid, sockscf.uid.privileged) != 0
      ||  socks_seteuid(NULL, euid)                    != 0)
         serr(EXIT_FAILURE, "%s: socks_seteuid() failed", function);
   }

   if (!sockscf.uid.unprivileged_isset)
      sockscf.uid.unprivileged = sockscf.state.euid;
   else { /* check the euid-switching works. */
      if (socks_seteuid(&euid, sockscf.uid.unprivileged) != 0
      ||  socks_seteuid(NULL, euid)                      != 0)
         serr(EXIT_FAILURE, "%s: socks_seteuid() failed", function);
   }

#if HAVE_LIBWRAP
   if (!sockscf.uid.libwrap_isset)
      sockscf.uid.libwrap = sockscf.uid.unprivileged;
   else { /* check the euid-switching works. */
      if (socks_seteuid(&euid, sockscf.uid.libwrap) != 0
      ||  socks_seteuid(NULL, euid)                 != 0)
         serr(EXIT_FAILURE, "%s: socks_seteuid() failed", function);
   }
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_PRIVILEGES */
#endif /* !HAVE_DUMPCONF */

   if (sockscf.internalc == 0)
      serrx(EXIT_FAILURE,
      "%s: no internal address given for server to listen to", function);

   if (sockscf.external.addrc == 0)
      serrx(EXIT_FAILURE,
      "%s: no external address given for server to use for connecting out",
      function);

#if !HAVE_DUMPCONF
   for (i = 0; i < sockscf.external.addrc; ++i)
      if (!addressisbindable(&sockscf.external.addrv[i]))
         serrx(EXIT_FAILURE, "%s: illegal external address given as #%ld: %s",
         function, (long)i,
         ruleaddr2string(&sockscf.external.addrv[i], NULL, 0));
#endif /* !HAVE_DUMPCONF */

#if !HAVE_DUMPCONF && !BAREFOOTD

   if (sockscf.clientmethodc == 0) {
      sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;

      if (methodisset(AUTHMETHOD_GSSAPI, sockscf.methodv, sockscf.methodc))
         sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_GSSAPI;
   }

   if (sockscf.methodc == 0)
      swarnx("%s: no socks methods enabled.  This means all socks-requests "
             "will be blocked after negotiation.  Perhaps this is not "
             "intended?", function);

   if (methodisset(AUTHMETHOD_GSSAPI, sockscf.methodv, sockscf.methodc)
   && !methodisset(AUTHMETHOD_GSSAPI, sockscf.clientmethodv,
   sockscf.clientmethodc))
      serrx(EXIT_FAILURE,
            "%s: authmethod %s is enabled for socks-methods, but not for "
            "client-methods.  Since %s authentication needs to be established "
            "during client-negotiation it thus needs to be set in "
            "clientmethods also",
            function, method2string(AUTHMETHOD_GSSAPI),
            method2string(AUTHMETHOD_GSSAPI));

   /*
    * Other way around should be ok since if the socks-rule method includes
    * "none", it shouldn't matter what auth-method was used during client
    * negotiation; none should be a subset of everything.
    */
#endif /* !HAVE_DUMPCONF && !BAREFOOTD */

#if !HAVE_PRIVILEGES
   if (sockscf.uid.unprivileged == 0)
      swarnx("%s: setting the unprivileged uid to %d is not recommended "
             "for security reasons",
             function, sockscf.uid.unprivileged);

#if HAVE_LIBWRAP
   if (sockscf.uid.libwrap == 0)
      swarnx("%s: setting the libwrap uid to %d is not recommended "
             "for security reasons",
      function, sockscf.uid.libwrap);
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_PRIVILEGES */


   /*
    * Check rules, including if some rule-specific settings vary across
    * rules.  If they don't, we can optimize some things when running.
    */
#if HAVE_PAM
   pamservicename = NULL;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
   gssapiservicename = gssapikeytab = NULL;
#endif /* HAVE_GSSAPI */

   basec = 0;
   while (basec < ELEMENTS(basev)) {
      struct rule_t *rule    = basev[basec];
      const int *methodv     = methodbasev[basec];
      const int methodc      = *methodbasec[basec];
      const int isclientrule = isclientrulev[basec];
      ++basec;

      if (rule == NULL)
         continue;

      for (; rule != NULL; rule = rule->next) {
         const struct command_t udpreplycmd = { .udpreply = 1 };

         for (i = 0; i < rule->state.methodc; ++i) {
            switch (rule->state.methodv[i]) {
#if HAVE_PAM
               case AUTHMETHOD_PAM:
                  if (sockscf.state.pamservicename == NULL)
                     break;

                  if (pamservicename == NULL) /* first pam rule. */
                     pamservicename = rule->state.pamservicename;
                  else if (strcmp(pamservicename, rule->state.pamservicename)
                  != 0) {
                     slog(LOG_DEBUG, "%s: pam.servicename varies, %s ne %s",
                     function, pamservicename, rule->state.pamservicename);

                     sockscf.state.pamservicename = NULL;
                  }

                  break;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
               case AUTHMETHOD_GSSAPI:
                  if (sockscf.state.gssapiservicename != NULL) {
                     if (gssapiservicename == NULL) /* first gssapi rule. */
                        gssapiservicename = rule->state.gssapiservicename;
                     else if (strcmp(gssapiservicename,
                     rule->state.gssapiservicename) != 0) {
                        slog(LOG_DEBUG,
                        "%s: gssapi.servicename varies, %s ne %s",
                         function, gssapiservicename,
                         rule->state.gssapiservicename);

                        sockscf.state.gssapiservicename = NULL;
                     }
                  }

                  if (sockscf.state.gssapikeytab != NULL) {
                     if (gssapikeytab == NULL) /* first gssapi rule. */
                        gssapikeytab = rule->state.gssapikeytab;
                     else if (strcmp(gssapikeytab, rule->state.gssapikeytab)
                     != 0){
                        slog(LOG_DEBUG, "%s: gssapi.keytab varies, %s ne %s",
                        function, gssapikeytab, rule->state.gssapikeytab);

                        sockscf.state.gssapikeytab = NULL;
                     }
                  }
                  break;
#endif /* HAVE_GSSAPI */

               default:
                  break;
            }
         }

         /*
          * If no methods are set in rule, set all from the
          * corresponding global method-line.
          */
          if (rule->state.methodc == 0) {
            int i;

            for (i = 0; i < methodc; ++i) {
               if (isreplycommandonly(&rule->state.command)) {
                  switch (methodv[i]) {
                     case AUTHMETHOD_NONE:
                     case AUTHMETHOD_PAM:
                     case AUTHMETHOD_RFC931:
                        break;

                     default:
                        slog(LOG_DEBUG,
                             "%s: not adding method %s to %s-rule #%lu",
                             function, method2string(methodv[i]),
                             isclientrule ? "client" : "socks",
                             (unsigned long)rule->number);
                        continue;
                  }
               }

               slog(LOG_DEBUG, "%s: adding method %s to %s-rule #%lu",
               function, method2string(methodv[i]),
               isclientrule ? "client" : "socks",
               (unsigned long)rule->number);

               rule->state.methodv[i] = methodv[i];
            }
            rule->state.methodc = i;
         }

         if (rule->state.methodc == 0)
            serrx(EXIT_FAILURE, "%s: %s-rule #%lu allows no methods",
            function, isclientrule ? "client" : "socks",
            (unsigned long)rule->number);

         if (isreplycommandonly(&rule->state.command)) {
            for (i = 0; i < rule->state.methodc; ++i) {
               switch (rule->state.methodv[i]) {
                  case AUTHMETHOD_NONE:
                  case AUTHMETHOD_PAM:
                     break;

                  case AUTHMETHOD_RFC931:
                     if (memcmp(&rule->state.command, &udpreplycmd,
                     sizeof(udpreplycmd)) == 0)
                        serrx(EXIT_FAILURE,
                              "%s-rule #%lu specifies method %s, but this "
                              "method can not be provided by udpreplies",
                              isclientrule ? "client" : "socks",
                              (unsigned long)rule->number,
                              method2string(rule->state.methodv[i]));
                     break;

                  default:
                     serrx(EXIT_FAILURE,
                           "%s-rule #%lu specifies method %s, but this "
                           "method can not be provided by bind/udpreplies",
                           isclientrule ? "client" : "socks",
                           (unsigned long)rule->number,
                           method2string(rule->state.methodv[i]));
               }
            }
         }

         if (rule->user != NULL || rule->group != NULL) {
            if (memcmp(&rule->state.command, &udpreplycmd, sizeof(udpreplycmd))
            == 0)
               serrx(EXIT_FAILURE, "error with %s-rule #%lu: udpreplies can "
                                   "not provide any user/group information",
                                   isclientrule ? "client" : "socks",
                                   (unsigned long)rule->number);

            for (i = 0; i < rule->state.methodc; ++i) {
               switch (rule->state.methodv[i]) {
                  case AUTHMETHOD_GSSAPI:
                  case AUTHMETHOD_UNAME:
                  case AUTHMETHOD_PAM:
                  case AUTHMETHOD_RFC931:
                     break;

                  default:
                     serrx(EXIT_FAILURE,
                           "%s-rule #%lu specifies a user/group-name, "
                           "but no method that can provide it",
                           isclientrule ? "client" : "socks",
                           (unsigned long)rule->number);
               }
            }
         }
      }
   }
}

static void
modulesetup(void)
{
   sigset_t oldset;

   socks_sigblock(SIGHUP, &oldset);
   shmem_setup();
   redirectsetup();

   socks_sigunblock(&oldset);
}


#if DEBUG
static void
dotest(void)
{
#if 0
   socks_iobuftest();
#endif
}
#endif /* DEBUG */
