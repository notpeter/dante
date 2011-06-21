/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011
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
"$Id: sockd.c,v 1.586 2011/06/19 15:27:20 michaels Exp $";


/*
 * signal handler functions.  Upon reception of signal, "sig" is the real
 * signal value (> 0).  We then set a flag indicating we got a signal,
 * but we don't do anything and return immediately.  Later we are called
 * again, with "sig" having the value -(sig), to indicate we are not
 * executing in the signal handler and it's safe to do whatever we
 * need to do.
 */
static void sigterm(int sig, siginfo_t *sip, void *scp);
static void siginfo(int sig, siginfo_t *sip, void *scp);
static void sigchld(int sig, siginfo_t *sip, void *scp);
static void sigalrm(int sig, siginfo_t *sip, void *scp);
static void sighup(int sig, siginfo_t *sip, void *scp);

#if DEBUG
static void dotest(void);
/*
 * runs some internal tests.
 */
#endif

static void
serverinit(int argc, char *argv[]);
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

static char *
getlimitinfo(void);
/*
 * returns a string with some information about current state and limits.
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
checkconfig(void);
/*
 * Scans through the config, perhaps fixing some things and warning
 * about strange things, or errors out on serious mistakes.
 */

#if DIAGNOSTIC && HAVE_MALLOC_OPTIONS
   extern char *malloc_options;
#endif /* DIAGNOSTIC && HAVE_MALLOC_OPTIONS */

#if HAVE_PROGNAME
extern char *__progname;
#elif SOCKS_SERVER
char *__progname = "sockd";   /* default. */
#elif BAREFOOTD
char *__progname = "barefootd";   /* default. */
#elif COVENANT
char *__progname = "covenantd";   /* default. */
#else
#error "who are we?"
#endif /* HAVE_PROGNAME */

extern char *optarg;

#if !HAVE_SETPROCTITLE
char **argv_cpy;
int argc_cpy;
#endif /* !HAVE_SETPROCTITLE */

#define ELECTRICFENCE   0

#if ELECTRICFENCE
   extern int EF_PROTECT_FREE;
   extern int EF_ALLOW_MALLOC_0;
   extern int EF_ALIGNMENT;
   extern int EF_PROTECT_BELOW;
#endif /* ELECTRICFENCE */


int
main(argc, argv)
   int   argc;
   char   *argv[];
{
   const char *function = "main()";
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
#ifdef RLIMIT_NPROC
   struct rlimit maxproc;
#endif /* RLIMIT_NPROC */
   struct sigaction sigact;
   struct rlimit rlimit;
   rlim_t minfd;
   fd_set *rset;
   ssize_t p;
   size_t dforchild;
#if DIAGNOSTIC && HAVE_MALLOC_OPTIONS
   malloc_options = "AFGJP";
#endif /* DIAGNOSTIC && HAVE_MALLOC_OPTIONS */

#if ELECTRICFENCE
   EF_PROTECT_FREE         = 1;
   EF_ALLOW_MALLOC_0       = 1;
   EF_ALIGNMENT            = 0;
   EF_PROTECT_BELOW         = 0;
#endif /* ELECTRICFENCE */

#if !HAVE_SETPROCTITLE
   argc_cpy = argc;
   if ((argv_cpy = malloc(sizeof(*argv_cpy) * (argc + 1))) == NULL)
      serr(EXIT_FAILURE, "%s: %s", function, NOMEM);

   for (p = 0; p < argc; p++)
      if ((argv_cpy[p] = strdup(argv[p])) == NULL)
         serr(EXIT_FAILURE, "%s: %s", function, NOMEM);
   argv_cpy[p] = NULL;

   initsetproctitle(argc, argv);

   serverinit(argc_cpy, argv_cpy);
#else
   serverinit(argc, argv);
#endif /* !HAVE_SETPROCTITLE*/

#if 0
   dotest();
   exit(0);
#endif

   showconfig(&sockscf);

   /*
    * close any descriptor we don't need, both in case of chroot(2)
    * and needing every descriptor we can get.
    */

   /* syslog takes one */
   dforchild = sockscf.log.type & LOGTYPE_SYSLOG ? -1 : 0;
   for (p = 0, minfd = getmaxofiles(softlimit); (rlim_t)p < minfd; ++p) {
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
    * Enough descriptors for each child process? + 2 for the pipes from
    * the child to mother.
    */

   /* CONSTCOND */
   minfd = MAX(SOCKD_NEGOTIATEMAX,
   MAX(SOCKD_REQUESTMAX, SOCKD_IOMAX * FDPASS_MAX)) + 2;

#if BAREFOOTD
   minfd += MIN_UDPCLIENTS;
#endif

   /*
    * need to know max number of open files so we can allocate correctly
    * sized fd_sets.  Also, try to set both it and the max number of
    * processes to the hard limit.
    */
   sockscf.state.maxopenfiles = getmaxofiles(hardlimit);
   slog(LOG_DEBUG, "hard limit for max number of open files is %lu, "
                   "soft limit is %lu",
                   (unsigned long)sockscf.state.maxopenfiles,
                   (unsigned long)getmaxofiles(softlimit));

   if (sockscf.state.maxopenfiles < minfd) {
      swarnx("have only %lu file descriptors available, but need at least %lu "
             "according to the configuration.  Trying to increase it ...",
             (unsigned long)sockscf.state.maxopenfiles, (unsigned long)minfd);

      sockscf.state.maxopenfiles = minfd;
   }

   rlimit.rlim_cur = rlimit.rlim_max = sockscf.state.maxopenfiles;

   if (setrlimit(RLIMIT_OFILE, &rlimit) == 0)
      slog(sockscf.state.maxopenfiles < minfd ? LOG_INFO : LOG_DEBUG,
           "max number of file descriptors is now %lu",
           (unsigned long)sockscf.state.maxopenfiles);
  else
      swarnx("failed to increase the max number of file descriptors.  "
            "setrlimit(RLIMIT_OFILE, {%lu, %lu}) failed (%s).  "
            "Change the kernel's limit, or change the values in %s's "
            "include/config.h, or %s will not run reliably",
            (unsigned long)rlimit.rlim_cur, (unsigned long)rlimit.rlim_max,
            strerror(errno),
            PACKAGE,
            PACKAGE);

#ifdef RLIMIT_NPROC
   if (getrlimit(RLIMIT_NPROC, &maxproc) != 0)
      swarn("getrlimit(RLIMIT_NPROC) failed");
   else {
      maxproc.rlim_cur = maxproc.rlim_max;

      if (setrlimit(RLIMIT_NPROC, &maxproc) != 0)
         swarn("setrlimit(RLIMIT_NPROC, { %lu, %lu }) failed",
         (unsigned long)rlimit.rlim_cur, (unsigned long)rlimit.rlim_max);
   }
#else
   slog(LOG_DEBUG, "no RLIMIT_NPROC defined on this platform, "
                   "max clients calculation will not be done");
#endif /* !RLIMIT_NPROC */

   /*
    * set up signal handlers.
    */

   bzero(&sigact, sizeof(sigact));
   (void)sigemptyset(&sigact.sa_mask);
   sigact.sa_flags = SA_RESTART | SA_NOCLDSTOP | SA_SIGINFO;

   sigact.sa_sigaction = siginfo;
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

   sigact.sa_sigaction = sighup;
   if (sigaction(SIGHUP, &sigact, NULL) != 0) {
      swarn("sigaction(SIGHUP)");
      return EXIT_FAILURE;
   }

   sigact.sa_sigaction = sigchld;
   if (sigaction(SIGCHLD, &sigact, NULL) != 0) {
      swarn("sigaction(SIGCHLD)");
      return EXIT_FAILURE;
   }

   sigact.sa_sigaction = sigterm;
   for (p = 0; (size_t)p < exitsignalc; ++p)
      if (sigaction(exitsignalv[p], &sigact, NULL) != 0)
         swarn("sigaction(%d)", exitsignalv[p]);

   sigact.sa_handler = SIG_IGN;
   for (p = 0; (size_t)p < ignoresignalc; ++p)
      if (sigaction(ignoresignalv[p], &sigact, NULL) != 0)
         swarn("sigaction(%d)", ignoresignalv[p]);

   sigact.sa_flags     = 0;   /* want to be interrupted. */
   sigact.sa_sigaction = sigalrm;
   if (sigaction(SIGALRM, &sigact, NULL) != 0) {
      swarn("sigaction(SIGALRM)");
      return EXIT_FAILURE;
   }

   if (sockscf.option.daemon) {
      if (daemon(1, 0) != 0)
         serr(EXIT_FAILURE, "daemon()");

      close(STDIN_FILENO); /* leave stdout/stderr, but close stdin. */
      *sockscf.state.motherpidv = getpid();   /* we are still main server. */
   }

   newprocinit();

   if (!HAVE_DISABLED_PIDFILE) {
      FILE *fp;

      sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_ON);
      if ((fp = fopen(sockscf.option.pidfile, "w")) == NULL) {
         swarn("open(%s)", sockscf.option.pidfile);
         errno = 0;
      }
      sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_OFF);

      if (fp != NULL) {
         if (fprintf(fp, "%lu\n", (unsigned long)sockscf.state.pid) == EOF)
            swarn("fprintf(%s)", sockscf.option.pidfile);
         fclose(fp);
      }
   }

   time(&sockscf.stat.boot);

   /* fork of requested number of servers.  Start at one 'cause we are "it".  */
   for (p = 1; (size_t)p < sockscf.option.serverc; ++p) {
      pid_t pid;

      if ((pid = fork()) == -1)
         swarn("fork()");
      else if (pid == 0) {
         newprocinit();
         sockscf.option.serverc = p;
         break;
      }
      else
         sockscf.state.motherpidv[p] = pid;
   }

   if (childcheck(CHILD_NEGOTIATE) < SOCKD_FREESLOTS_NEGOTIATE
   ||  childcheck(CHILD_REQUEST)   < SOCKD_FREESLOTS_REQUEST
   ||  childcheck(CHILD_IO)        < SOCKD_FREESLOTS_IO)
      serr(EXIT_FAILURE, "childcheck() failed, not enough slots available "
                         "relative to configured values.  "
                         "Change SOCKD_FREESLOTS_* if desired, or fix the "
                         "problem.");

#if HAVE_PROFILING /* XXX is this only needed on Linux? */
moncontrol(1);
#endif /* HAVE_PROFILING */

#if PRERELEASE
   slog(LOG_INFO, "\n"
   "   ******************************************************************\n"
#if BAREFOOTD
   "   *** Thank you for testing this %s pre-release.          ***\n"
#elif COVENANT
   "   *** Thank you for testing this %s pre-release.           ***\n"
#elif SOCKS_SERVER
   "   *** Thank you for testing this %s pre-release.              ***\n"
#else
#error "hmm, who are we?"
#endif /* SOCKS_SERVER */
   "   *** Please note pre-releases are always configured in a way    ***\n"
   "   *** that puts a considerably larger load on the running system ***\n"
   "   *** system than the standard releases.                         ***\n"
   "   *** This is to help simulate high-load situations and aid in   ***\n"
   "   *** finding bugs before a full release is done.                ***\n"
   "   ******************************************************************",
   PACKAGE);
#endif /* PRERELEASE */

   if (sockscf.option.debug)
      slog(LOG_DEBUG, getlimitinfo());

   rset = allocate_maxsize_fdset();

   slog(LOG_INFO, "%s/server v%s running\n", PACKAGE, VERSION);

   /*
    * main loop; accept new connections and handle our children.
    * CONSTCOND 
    */
   while (1) {
      struct sockd_child_t *child;
      int rbits, havefreeslots, free_negc, free_reqc, free_ioc;
#if BAREFOOTD
      struct timeval zerotimeout  = { 0, 0 };
#endif /* BAREFOOTD */

      errno = 0; /* reset for each iteration. */
      rbits = fillset(rset, &free_negc, &free_reqc, &free_ioc);

      slog(LOG_DEBUG, "calling select().  Free negc: %d reqc: %d; ioc: %d",
      free_negc, free_reqc, free_ioc);

      p = selectn(++rbits,
                  rset,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
#if BAREFOOTD
                  sockscf.state.alludpbounced ? NULL : &zerotimeout
#else /* SOCKS_SERVER */
                  NULL
#endif /* SOCKS_SERVER */
                 );

      switch (p) {
         case 0:
#if BAREFOOTD
            SASSERTX(!sockscf.state.alludpbounced);
            break; /* not all udp sockets yet bounced -> have select timeout. */
#else /* SOCKS_SERVER */
            SERR(p);
            /* NOTREACHED */
#endif /* SOCKS_SERVER */

         case -1:
            SASSERT(errno == EINTR);
            continue;
      }

      slog(LOG_DEBUG, "%s: selectn() returned %ld (%s)",
      function, (long)p, errnostr(errno));

      /*
       * Handle our children.
       *
       * First, get the client objects from the children.  This needs to
       * be done before reading the freeslot ack to avoid a situation where
       * the child acks it has freed many slots, but the data is still
       * pending in the buffer between ourselves and the child.  If that
       * should happen, we might send a new request to the child, and if
       * the child finishes that request and sends us a client object
       * back before we have read the previously finished client objects
       * from that child, the queue between us and the child may already
       * be full.
       *
       * Also, don't get too many requests here.  If we do, we could end up
       * needlessly forking a lot of new processes, while at the same time
       * having a lot of unread SOCKD_FREESLOT messages which we won't get
       * to read before we've finished reading the new requests.
       */
      havefreeslots = 1;
      while (havefreeslots && (child = getset(DATAPIPE, rset)) != NULL) {
#if DIAGNOSTIC
         int freed = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif /* DIAGNOSTIC */

         clearset(DATAPIPE, child, rset);
         errno = 0;

         switch (child->type) {
            /*
             * in the order a packet travels between children;
             * negotiate -> request -> io
             * (and in Covenants case, -> io -> negotiate again, sometimes).
             */

            case CHILD_NEGOTIATE: {
               struct sockd_request_t req;
               struct sockd_child_t *reqchild;

               if ((reqchild = nextchild(CHILD_REQUEST, SOCKS_TCP)) == NULL) {
                  slog(LOG_DEBUG, "no request slot available for new client");
                  havefreeslots = 0;
                  break;
               }

               SASSERTX(reqchild->freec > 0);

               slog(LOG_DEBUG, "trying to receive request from negotiator-"
                               "child %lu",
                               (unsigned long)child->pid);

               if ((p = recv_req(child->s, &req)) != 0) {
                  slog(LOG_DEBUG, "recv_req() failed with %ld: %s",
                       (long)p, errnostr(errno));

                  break;
               }
               ++sockscf.stat.negotiate.received;

               slog(LOG_DEBUG, "sending %s-client from client-rule #%lu "
                               "to reqchild %lu",
                               protocol2string(req.state.protocol),
                               (unsigned long)req.rule.number,
                               (unsigned long)reqchild->pid);

               if (send_req(reqchild->s, &req) == 0) {
                  --free_reqc;
                  --reqchild->freec;
                  ++reqchild->sentc;
                  ++sockscf.stat.request.sendt;
               }
               else {
#if HAVE_NEGOTIATE_PHASE
                  struct response_t response;

                  slog(LOG_DEBUG, "send_req() failed: %s", errnostr(errno));

                  create_response(NULL,
                                  &req.clientauth,
                                  req.req.version,
                                  errno2reply(errno, req.req.version),
                                  &response);

                  if (send_response(req.s, &response) != 0) {
                     slog(LOG_DEBUG,
                          "%s: send_response(%d) to %s failed: %s",
                          function,
                          req.s,
                          sockaddr2string(&req.from, NULL, 0),
                          errnostr(errno));
                  }
#endif /* HAVE_NEGOTIATE_PHASE */
               }

               close(req.s);
               break;
            }

            case CHILD_REQUEST: {
               struct sockd_io_t io;
               struct sockd_child_t *iochild_tcp, *iochild_udp, *iochild;

               /*
                * don't know which protocol the request we receive is for
                * until we receive it, so make sure we have space for
                * either possibility
                */

               if ((iochild_tcp = nextchild(CHILD_IO, SOCKS_TCP)) == NULL) {
                  slog(LOG_DEBUG, "no tcp io slot available for new client");
                  havefreeslots = 0;
                  break;
               }

#if BAREFOOTD
               /* A child should only handle one udp session at a time. */
               if ((iochild_udp = nextchild(CHILD_IO, SOCKS_UDP)) == NULL) {
                  slog(LOG_DEBUG, "no udp io slot available for new client");
                  havefreeslots = 0;
                  break;
               }

               SASSERTX(iochild_udp->hasudpsession == 0);
#else /* !BAREFOOTD */
               /* any child with a free slot can handle a udp session. */
               iochild_udp = iochild_tcp;
#endif /* !BAREFOOTD */

               slog(LOG_DEBUG, "trying to receive request from request-"
                               "child %lu",
                               (unsigned long)child->pid);

               if ((p = recv_io(child->s, &io)) != 0) {
                  slog(LOG_DEBUG, "recv_io() failed with %ld: %s",
                       (long)p, errnostr(errno));

                  break;
               }
               ++sockscf.stat.request.received;

               switch (io.state.protocol) {
                  case SOCKS_TCP:
                     iochild = iochild_tcp;
                     break;

                  case SOCKS_UDP:
                     iochild = iochild_udp;
                     break;

                  default:
                     SERRX(io.state.protocol);
               }

               SASSERTX(iochild->freec > 0);

               slog(LOG_DEBUG, "sending %s-client to iochild %lu",
                               protocol2string(io.state.protocol),
                               (unsigned long)iochild->pid);

               /* and send it to a io child. */
               if (send_io(iochild->s, &io) == 0) {
                  --free_ioc;
                  --iochild->freec;
                  ++iochild->sentc;
                  ++sockscf.stat.io.sendt;
#if BAREFOOTD
                  if (io.state.protocol == SOCKS_UDP) {
                     SASSERTX(iochild->hasudpsession == 0);
                     ++iochild->hasudpsession;

                     slog(LOG_DEBUG, "sent udp session for local address %s "
                                     "to io-child %lu",
                                     sockaddr2string(&io.src.laddr, NULL, 0),
                                     (unsigned long)iochild->pid);
                  }
#endif /* BAREFOOTD */
               }
               else {
#if HAVE_NEGOTIATE_PHASE
                  struct response_t response;

                  slog(LOG_DEBUG, "send_io() failed: %s", errnostr(errno));

                  create_response(NULL,
                                  &io.src.auth,
                                  io.state.version,
                                  errno2reply(errno, io.state.version),
                                  &response);

                  if (send_response(io.control.s, &response) != 0) {
                     slog(LOG_DEBUG,
                          "%s: send_response(%d) to %s failed: %s",
                          function,
                          io.control.s,
                          sockshost2string(&io.src.host, NULL, 0),
                          errnostr(errno));
                  }
#endif /* HAVE_NEGOTIATE_PHASE */
               }

               close_iodescriptors(&io);
               break;
            }

            case CHILD_IO: {
#if COVENANT
               struct sockd_client_t client;
               struct sockd_child_t *negchild;

               if ((negchild = nextchild(CHILD_NEGOTIATE, SOCKS_TCP)) == NULL) {
                  slog(LOG_DEBUG,
                       "no negotiate child available to accept old client");
                  break;
               }

               SASSERTX(negchild->freec > 0);

               slog(LOG_DEBUG, "trying to receive request from io-child %lu",
                               (unsigned long)child->pid);

               if ((p = recv_resentclient(child->s, &client)) != 0) {
                  slog(LOG_DEBUG, "recv_resentclient() failed with %ld: %s",
                       (long)p, errnostr(errno));

                  break;
               }

               ++sockscf.stat.io.received;

               slog(LOG_DEBUG, "sending client to negchild %lu",
               (unsigned long)negchild->pid);


#if HAVE_SENDMSG_DEADLOCK
               if (socks_lock(negchild->lock, 1, 0) != 0)
                  continue;
#endif /* HAVE_SENDMSG_DEADLOCK */

               p = send_client(negchild->s, &client, NULL, 0);

#if HAVE_SENDMSG_DEADLOCK
               if (negchild != NULL)
                  socks_unlock(negchild->lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

               if (p == 0) {
                  --negchild->freec;
                  ++negchild->sentc;
                  ++sockscf.stat.negotiate.sendt;
               }
               else {
#if HAVE_NEGOTIATE_PHASE
                  struct response_t response;

                  slog(LOG_DEBUG, "send_client() failed: %s", errnostr(errno));

                  /* XXX missing stuff here. */
                  create_response(NULL,
                                  &client.auth,
                                  client.request.version,
                                  errno2reply(errno, client.request.version),
                                  &response);

                  if (send_response(client.s, &response) != 0) {
                     slog(LOG_DEBUG,
                          "%s: send_response(%d) to %s failed: %s",
                          function,
                          client.s,
                          sockshost2string(&client.request.host, NULL, 0),
                          errnostr(errno));
                  }
#endif /* HAVE_NEGOTIATE_PHASE */
               }

               close(client.s);
#endif /* COVENANT */

               break;
            }

            default:
               SERRX(child->type);
         }

#if DIAGNOSTIC
         if (freed != freedescriptors(sockscf.option.debug ?  "end" : NULL))
            swarnx("%s: lost %d file descriptor%s communicating with "
                   "children",
                   function, freed - freedescriptors(NULL),
                   (freed - freedescriptors(NULL)) == 1 ? "" : "s");
#endif /* DIAGNOSTIC */

         /* XXX same code as later down; merge. */
         if (sockscf.child.maxrequests != 0
         &&  child->freec              == maxfreeslots(child->type)
         &&  child->sentc              >= sockscf.child.maxrequests) {
            slog(LOG_DEBUG, "closing connection to %s-child %lu as it "
                            "has now handled %lu request%s",
                            childtype2string(child->type),
                            (unsigned long)child->pid,
                            (unsigned long)child->sentc,
                            (unsigned long)child->sentc == 1 ? "" : "s");
            havefreeslots = 0;
         }
         else if (free_negc == 0
         ||       free_reqc == 0
         ||       free_ioc  == 0) {
            /*
             * Could have created more in the meantime, but better
             * safe than sorry.
             */
            if (sockscf.option.debug > 1)
               slog(LOG_DEBUG, "free negc = %d, reqc = %d, ioc = %d",
                               free_negc, free_reqc, free_ioc);

            havefreeslots = 0;
         }
      }

      /*
       * next, get ack of free slots.
       */
      while ((child = getset(ACKPIPE, rset)) != NULL) {
         char command;
         int childisbad = 0, childhasfinished = 0;

         errno = 0;

         p = socks_recvfromn(child->ack,
                             &command,
                             sizeof(command),
                             sizeof(command),
                             0,
                             NULL,
                             NULL,
                             NULL);
         clearset(ACKPIPE, child, rset);

         if (p != sizeof(command)) {
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
               case SOCKD_FREESLOT_TCP:
               case SOCKD_FREESLOT_UDP:
                  ++child->freec;

                  SASSERTX(child->freec <= maxfreeslots(child->type));

                  slog(LOG_DEBUG, "%s: %s-child %lu has freed a %s slot, "
                                  "now has %lu slot%s free",
                                  function,
                                  childtype2string(child->type),
                                  (unsigned long)child->pid,
                                  command == SOCKD_FREESLOT_TCP ?
                                  "tcp" : "udp",
                                  (unsigned long)child->freec,
                                  child->freec == 1 ? "" : "s");

                  if (child->type == CHILD_IO) {
                     /*
                      * don't normally receive anything back from i/o childs
                      * except the freeslot ack, as i/o childs are the
                      * last in the chain.
                      */
                     ++sockscf.stat.io.received;
#if BAREFOOTD
                     if (command == SOCKD_FREESLOT_UDP) {
                        --child->hasudpsession;
                        SASSERTX(child->hasudpsession == 0);
                     }
#endif /* BAREFOOTD */

                     if (sockscf.child.maxrequests != 0
                     &&  child->freec              == maxfreeslots(child->type)
                     &&  child->sentc              >= sockscf.child.maxrequests)
                        childhasfinished = 1;
                  }
                  break;

               default:
                  SERRX(command);
           }
         }

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
            * new clients accept(2)-ed, so restart the loop.
            */
           continue;
         }
      }

      /*
       * handled our children.  Is there a new connection pending now?
       */
      for (p = 0; (size_t)p < sockscf.internalc; ++p) {
         char accepted[MAXSOCKADDRSTRING];
         struct sockd_client_t client;

#if BAREFOOTD
         if (sockscf.internalv[p].protocol != SOCKS_TCP)
            continue; /* udp handled by io children. */
#endif /* BAREFOOTD */

         /* clear client to silence valgrind */
         bzero(&client, sizeof(client));

         if (FD_ISSET(sockscf.internalv[p].s, rset)) {
            struct sockd_child_t *negchild;
            struct sockaddr from;
            socklen_t len;

#if NEED_ACCEPTLOCK
            if (sockscf.option.serverc > 1)
               if (socks_lock(sockscf.internalv[p].lock, 1, 0) != 0)
                  continue;
#endif /* NEED_ACCEPTLOCK */

            /* XXX put this in a while loop, up to SOCKD_FREESLOTS? */
            len = sizeof(from);
            client.s = acceptn(sockscf.internalv[p].s, &from, &len);

#if NEED_ACCEPTLOCK
            if (sockscf.option.serverc > 1)
               socks_unlock(sockscf.internalv[p].lock);
#endif /* NEED_ACCEPTLOCK */

            if (client.s  == -1) {
               switch (errno) {
#ifdef EPROTO
                  case EPROTO:         /* overloaded SVR4 error */
#endif /* EPROTO */
                  case EWOULDBLOCK:    /* BSD   */
                  case ENOBUFS:        /* HPUX  */
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
                     else if (errno == ECONNABORTED)
                        slog(LOG_NOTICE, "accept(2) failed: %s",
                        errnostr(errno));
                     else
                        swarn("accept(2) failed");

                     /*
                      * assume connection was aborted/failed/was taken by
                      * another (if serverc > 1) process.
                      */
                     continue;

                  case ENFILE:
                  case EMFILE:
                     swarn("could not accept new client");
                     continue;

                  default:
                     SERR(client.s);
               }
            }

            gettimeofday(&client.accepted, NULL);
            ++sockscf.stat.accepted;

#if HAVE_LINUX_BUGS
            /*
             * yes, Linux manages to lose the descriptor flags. :-(
             * Workaround might be insufficient.
             */
            if (fcntl(client.s, F_SETFL,
                      fcntl(sockscf.internalv[p].s, F_GETFL, 0)) != 0)
               swarn("tried to work around Linux bug via fcntl()");
#endif /* HAVE_LINUX_BUGS */

            slog(LOG_DEBUG, "got accept(): %s",
            sockaddr2string(&from, accepted, sizeof(accepted)));

            if ((negchild = nextchild(CHILD_NEGOTIATE, SOCKS_TCP)) == NULL) {
               swarnx("new client from %s dropped: no resources "
               "(no free negotiator slots / file descriptors)", accepted);

               close(client.s);
               continue;
            }

            slog(LOG_DEBUG, "sending %s-client to negchild %lu",
                            protocol2string(SOCKS_TCP),
                            (unsigned long)negchild->pid);

#if HAVE_SENDMSG_DEADLOCK
            socks_lock(negchild->lock, 1, 1);
#endif /* HAVE_SENDMSG_DEADLOCK */

            p = send_client(negchild->s, &client, NULL, 0);

#if HAVE_SENDMSG_DEADLOCK
               socks_unlock(negchild->lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

            if (p == 0) {
               --free_negc;
               --negchild->freec;
               ++negchild->sentc;
               ++sockscf.stat.negotiate.sendt;
            }
            else
               slog(LOG_DEBUG, "send_client() failed: %s", errnostr(errno));

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
   "   -d <number>    : set degree of debugging\n"
   "   -f <filename>  : use <filename> as configuration file [%s]\n"
   "   -h             : print this information\n"
   "   -n             : disable TCP keep-alive\n"
   "   -p <filename>  : write pid to <filename> [%s]\n"
   "   -v             : print version info\n",
   PACKAGE, VERSION,
   __progname,
   SOCKD_CONFIGFILE,
   SOCKD_PIDFILE);

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
 *               2007, 2008, 2009\n\
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

static void
serverinit(argc, argv)
   int argc;
   char *argv[];
{
   const char *function = "serverinit()";
   int ch, verifyonly = 0;

#if !HAVE_PROGNAME
   if (argv[0] != NULL) {
      if ((__progname = strrchr(argv[0], '/')) == NULL)
         __progname = argv[0];
      else
         ++__progname;
   }
#endif /* !HAVE_PROGNAME */

   sockscf.child.addchild = 1;
   sockscf.state.euid     = geteuid();
   sockscf.state.type     = CHILD_MOTHER;
   sockscf.option.serverc = 1;   /* ourselves. ;-) */

   sockscf.shmemfd        = -1;
   sockscf.hostfd         = -1;
   sockscf.loglock        = -1;

   sockscf.option.hosts_access = 0;
   sockscf.option.debugrunopt = -1;

   while ((ch = getopt(argc, argv, "DLN:Vd:f:hlnp:v")) != -1) {
      switch (ch) {
         case 'D':
            sockscf.option.daemon = 1;
            break;

         case 'L':
            showlicense();
            /* NOTREACHED */

         case 'N': {
            char *endptr;

            if ((sockscf.option.serverc = (int)strtol(optarg, &endptr, 10)) < 1
            ||  *endptr != NUL)
               serrx(EXIT_FAILURE, "%s: illegal value for -%c: %s",
               function, ch, optarg);

            break;
         }

         case 'V':
            verifyonly = 1;
            break;

         case 'd':
            sockscf.option.debugrunopt = atoi(optarg);
            sockscf.option.debug       = sockscf.option.debugrunopt;
            break;

         case 'f':
            sockscf.option.configfile = optarg;
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

         case 'p':
            sockscf.option.pidfile = optarg;
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

   if ((sockscf.state.motherpidv = malloc(sizeof(*sockscf.state.motherpidv)
   * sockscf.option.serverc)) == NULL)
      serrx(EXIT_FAILURE, "%s", NOMEM);

   /* we are the main server. */
   *sockscf.state.motherpidv = sockscf.state.pid = getpid();

   if (argc > 0)
      serrx(EXIT_FAILURE, "%s: unknown argument %s", function, *argv);

   if (sockscf.option.configfile == NULL)
      sockscf.option.configfile = SOCKD_CONFIGFILE;

   if (sockscf.option.pidfile == NULL)
      sockscf.option.pidfile = SOCKD_PIDFILE;

   /*
    * needs to be before config file read, as config file may access
    * hostcache.
    */
   hostcachesetup();

#if HAVE_LDAP
   ldapcachesetup();
#endif /* HAVE_LDAP */

   optioninit();
   genericinit();
   newprocinit();

   checkconfig();

   if (verifyonly) {
      showconfig(&sockscf);
      exit(EXIT_SUCCESS);
   }

   init_privs();
   shmem_setup();

   if (bindinternal(SOCKS_TCP) != 0)
      serr(EXIT_FAILURE, "%s: failed to bind internal addresses()", function);

   sockscf.state.inited = 1;
}

/* ARGSUSED */
static void
sigterm(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
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

         sockd_pushsignal(sig, sip);
         return;
      }
      else {
         /*
          * A bad signal, something has crashed.  Can't count
          * on it being possible to continue from here, have
          * to exit now.
          */

         sockscf.state.insignal = sig;
         swarnx("%s: terminating on unexpected signal %d", function, sig);

         /*
          * Reinstall default signal handler for this signal and raise it again,
          * assuming we will terminate and get a coredump if that is default
          * behavior.
          */

         if (signal(sig, SIG_DFL) == SIG_ERR)
            serr(EXIT_FAILURE,
                 "%s: failed to reinstall original signal handler for signal %d",
                 function, sig);

         raise(sig);
         return; /* need to exit this signal handler so the default can run. */
      }
   }
   else
      sig = -sig;

   slog(LOG_INFO, "%s: exiting on signal %d", function, sig);
   sockdexit(EXIT_SUCCESS);
}


/* ARGSUSED */
static void
siginfo(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "siginfo()";
   const int errno_s = errno;
   unsigned long seconds, days, hours, minutes, free_negc, free_reqc, free_ioc;

   size_t clients;

   if (sig > 0) {
      sockd_pushsignal(sig, sip);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, "%s", function);

   clients = 0;
   clients += childcheck(-CHILD_NEGOTIATE);
   clients += childcheck(-CHILD_REQUEST);
   clients += childcheck(-CHILD_IO);

   clients -= (free_negc = childcheck(CHILD_NEGOTIATE));
   clients -= (free_reqc = childcheck(CHILD_REQUEST));
   clients -= (free_ioc  = childcheck(CHILD_IO));

   seconds = ROUNDFLOAT(difftime(time(NULL), sockscf.stat.boot));
   seconds2days(&seconds, &days, &hours, &minutes);

   slog(LOG_INFO,
        "%s v%s up %lu day%s, %lu:%.2lu\n"
        "mother                     : a: %-10lu h: %-10lu c: %-10lu\n"
        "negotiate processes (%-5d): a: %-10lu h: %-10lu c: %-8lu f: %-8lu\n"
        "request processes   (%-5d): a: %-10lu h: %-10lu c: %-8lu f: %-8lu\n"
        "i/o processes       (%-5d): a: %-10lu h: %-10lu c: %-8lu f: %-8lu\n"
        "%s",

        PACKAGE, VERSION, days, days == 1 ? "" : "s", hours, minutes,
        (unsigned long)sockscf.stat.accepted,
        (unsigned long)sockscf.stat.negotiate.sendt,
        (unsigned long)clients,

        childcheck(-CHILD_NEGOTIATE) / SOCKD_NEGOTIATEMAX,
        (unsigned long)sockscf.stat.negotiate.sendt,
        (unsigned long)sockscf.stat.negotiate.received,
        (unsigned long)childcheck(-CHILD_NEGOTIATE) - free_negc,
        free_negc,

        childcheck(-CHILD_REQUEST) / SOCKD_REQUESTMAX,
        (unsigned long)sockscf.stat.request.sendt,
        (unsigned long)sockscf.stat.request.received,
        (unsigned long)childcheck(-CHILD_REQUEST) - free_reqc,
        free_reqc,

        childcheck(-CHILD_IO) / SOCKD_IOMAX,
        (unsigned long)sockscf.stat.io.sendt,
        (unsigned long)sockscf.stat.io.received,
        (unsigned long)childcheck(-CHILD_IO) - free_ioc,
        free_ioc,

        getlimitinfo());

   if (pidismother(sockscf.state.pid) == 1)   /* main mother */
      sigserverbroadcast(sig);

   sigchildbroadcast(sig, CHILD_NEGOTIATE | CHILD_REQUEST | CHILD_IO);
   errno = errno_s;
}


/* ARGSUSED */
static void
sighup(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "sighup()";
   const int errno_s = errno;
   struct listenaddress_t *oldinternalv;
   struct rule_t *rule;
   size_t oldinternalc, i;

   if (sig > 0) {
      sockd_pushsignal(sig, sip);
      return;
   }

   sig = -sig;

#if 0 /* Doesn't work as many systems don't bother to fill in si_pid. :-/. */
   if (!pidismother(sockscf.state.pid) == 1 /* we are not mother. */
   &&  !pidismother(sip->si_pid)) /* and the signal is not from mother. */ {
      swarnx("%s: received SIGHUP from process id %lu, but only expecting it "
             "from mother, so ignoring the signal",
             function, (unsigned long)sip->si_pid);

      return;
   }
#endif

   if (pidismother(sockscf.state.pid) != 1) {
      /*
       * we are not main mother.  Can we assume the signal is from mother?
       * If not, ignore it.
       */
      static int lastsighupid;

      if (lastsighupid == sockscf.shmeminfo->sighupid) {
         /*
          * mothers sighupid has not changed, meaning she has not gotten any
          * sighup.
          */
         swarnx("%s: received SIGHUP, but it does not seem to have been sent "
                "by mother.   Ignoring it.",
                function);

          return;
      }

      lastsighupid = sockscf.shmeminfo->sighupid;
   }

   slog(LOG_INFO, "%s: got SIGHUP, reloading ...", function);

   /*
    * Copy the current addresses on the internal interfaces so that after
    * we have read in the new configuration, we can compare the old list
    * against the new to know which addresses/sockets are longer in use,
    * and stop listening on them.
    *
    * We can not simply clear them before reading in the new config
    * and then start listening on them (again) after we in read the new
    * config, as that would mean we could lose clients in the time-gap
    * between unbinding and rebinding the addresses.
    *
    * This is mainly for barefootd, where adding/removing bounce-to
    * addresses is probably not uncommon.  In the case of barefootd,
    * we additionally have udp addresses we listen on constantly that
    * we need to handle in a similar way.
    *
    * We also have a slight problem with udp rules, as we need to
    * know if the rule existed before the reload.  If it did,
    * we will fail when we try to bind on the internal side,
    * and also waste time trying to set up bouncing for the same
    * udp addresses several times.  More importantly, we will not 
    * know whether the error is expected, or if we should tell the
    * user he is trying to use an address already in use by
    * somebody else.
    * The same problem occurs if we have multiple rules with the
    * same "to:" address, which can make sense provided "from:"
    * differs.  We then have multiple acls for the same "to:" address,
    * but of course only one "to:" address/socket.
    *
    * Our solution for this is to also save the unique udp addresses we
    * need to listen to, and compare against them upon config reload.
    * If one of the udp address is the same as before, we consider the
    * session to be "bounced" already, and if one of the addresses
    * present on the old list is not present on the new list, we know
    * we have an old session/socket to terminate.
    */

    oldinternalc      = sockscf.internalc;
    if ((oldinternalv = malloc(sizeof(*oldinternalv) * oldinternalc))
    == NULL) {
      swarn("%s: failed to allocate memory for saving state before "
            "configuration reload",
            function);

      return;
   }

   for (i = 0; i < oldinternalc; ++i)
      oldinternalv[i] = sockscf.internalv[i];

   genericinit();
   checkconfig();

   /* delay this as long as possible. */
   if (pidismother(sockscf.state.pid) == 1)
      ++sockscf.shmeminfo->sighupid;

   shmem_setup();

   for (i = 0; i < oldinternalc; ++i) {
      ssize_t p;

      p = addrindex_on_listenlist(sockscf.internalc,
                                  sockscf.internalv,
                                  &oldinternalv[i].addr,
                                  oldinternalv[i].protocol);

      if (p >= 0) {
         /*
          * this socket/session should continue to exist.
          */
         sockscf.internalv[p].s = oldinternalv[i].s;
         continue;
      }

#if BAREFOOTD
      /*
       * this socket should be removed.
       */

      if (oldinternalv[i].protocol == SOCKS_TCP) {
         if (pidismother(sockscf.state.pid) == 1) {  /* main mother. */
            SASSERTX(sockscf.option.serverc == 1);

            close(oldinternalv[i].s);
#if NEED_ACCEPTLOCK
         close(oldinternalv[i].lock);
#endif /* NEED_ACCEPTLOCK */
         }

         continue;
      }

      /* else; udp. */

      if (pidismother(sockscf.state.pid) == 1) { /* main mother. */
         slog(LOG_DEBUG, "%s: child should remove udp session for %s",
                         function,
                         sockaddr2string(&oldinternalv[i].addr, NULL, 0));
      }
      else {
         switch (sockscf.state.type) {
            case CHILD_IO:
               io_remove_session(&oldinternalv[i].addr,
                                 oldinternalv[i].protocol);
               break;

         }
      }
#endif /* BAREFOOTD */
   }

   if (pidismother(sockscf.state.pid) == 1) { /* main mother. */
#if BAREFOOTD
      if (!sockscf.state.alludpbounced) {
         /*
          * Go through all rules and see if the current udp addresses
          * to bind matches any of the old ones, to see which new addresses
          * we need to bounce.  Those already bounced we can mostly ignore,
          * except we need to mark them as bounced already.
          */

         /*
          * Assume there are no new addresses to bounce initially.
          */
         sockscf.state.alludpbounced = 1;

         for (rule = sockscf.crule; rule != NULL; rule = rule->next) {
            struct sockshost_t hosttobind;
            struct sockaddr addrtobind;

            if (!rule->state.protocol.udp)
               continue;

            switch (rule->dst.atype) {
               case SOCKS_ADDR_IPV4:
                  ruleaddr2sockshost(&rule->dst, &hosttobind, SOCKS_UDP);
                  sockshost2sockaddr(&hosttobind, &addrtobind);

                  if (addrindex_on_listenlist(oldinternalc, oldinternalv,
                  &addrtobind, SOCKS_UDP) != -1) {
                     slog(LOG_DEBUG, "%s: marking address %s in rule %lu "
                                     "as bounced; previously bounced",
                                     function,
                                     sockaddr2string(&addrtobind, NULL, 0),
                                     (unsigned long)rule->number);
                     rule->bounced = 1;
                  }
                  break;

               case SOCKS_ADDR_DOMAIN: {
                  size_t i;

                  i = 0;
                  while (hostname2sockaddr(rule->dst.addr.domain, i++,
                  &addrtobind) != NULL) {
                     if (addrindex_on_listenlist(oldinternalc, oldinternalv,
                     &addrtobind, SOCKS_UDP) != -1) {
                        slog(LOG_DEBUG, "%s: marking address %s in rule %lu "
                                        "as bounced; previously bounced",
                                        function,
                                        sockaddr2string(&addrtobind, NULL, 0),
                                        (unsigned long)rule->number);
                        rule->bounced = 1;
                        break;
                     }
                  }
                  break;
               }

               case SOCKS_ADDR_IFNAME: {
                  size_t i;

                  i = 0;
                  while (ifname2sockaddr(rule->dst.addr.ifname, i++,
                  &addrtobind, NULL) != NULL) {
                     if (addrindex_on_listenlist(oldinternalc, oldinternalv,
                     &addrtobind, SOCKS_UDP) != -1) {
                        slog(LOG_DEBUG, "%s: marking address %s in rule %lu "
                                        "as bounced; previously bounced",
                                        function,
                                        sockaddr2string(&addrtobind, NULL, 0),
                                        (unsigned long)rule->number);
                        rule->bounced = 1;
                        break;
                     }
                  }
                  break;
               }

               default:
                  SERRX(rule->dst.atype);
            }

            if (!rule->bounced)
               sockscf.state.alludpbounced = 0;
         }
      }

      /* may have added addresses in new config, rebind if necessary. */
      if (bindinternal(SOCKS_TCP) != 0)
         serr(EXIT_FAILURE, "%s: failed to bind internal addresses()",
         function);

#endif /* BAREFOOTD */

      showconfig(&sockscf);
      sigserverbroadcast(sig);
   }

   free(oldinternalv);

   if (pidismother(sockscf.state.pid)) /* a mother. */
      sigchildbroadcast(sig, CHILD_NEGOTIATE | CHILD_REQUEST | CHILD_IO);
   else {
      switch (sockscf.state.type) {
         case CHILD_IO:
            io_handlesighup();
            break;
      }
   }

   slog(LOG_INFO, "%s: finished SIGHUP reloading ...", function);

   time(&sockscf.stat.configload);
   errno = errno_s;
}

/* ARGSUSED */
static void
sigchld(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "sigchld()";
   static int deaths;
   pid_t pid;
   int status;

   if (sig > 0) {
      sockd_pushsignal(sig, sip);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, "%s", function);

   while (1) {
      pid = waitpid(WAIT_ANY, &status, WNOHANG);

      if (pid == -1 && errno == EINTR)
         continue;

      if (pid <= 0)
         break;

      slog(LOG_DEBUG, "%s: process %lu exited", function, (unsigned long)pid);

      if (pidismother(pid))
         sockscf.state.motherpidv[pidismother(pid) - 1] = 0;

      /*
       * else;  assume relay child.
       * The reason we have to check if the child is known is that we also
       * call removechild() if the child appears to have become "bad",
       * or signals us that it has exited via eof.  I.e., by the time we
       * get here, the child could already have been removed.
       */

      if (getchild(pid) != CHILD_NOTOURS)
         removechild(pid);

      ++deaths;
   }

   if (sockscf.child.maxidle.negotiate == 0
   &&  sockscf.child.maxidle.request   == 0
   &&  sockscf.child.maxidle.io        == 0) {
      /*
       * If maxidle is not set, and many children suddenly die, that
       * probably means something is wrong, so check for that.
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
sigalrm(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{

   sockscf.child.addchild = 1;
}


static void
checkconfig(void)
{
   const char *function = "checkconfig()";
#if HAVE_PAM
   char *pamservicename = NULL;
#endif /* HAVE_PAM */
#if HAVE_BSDAUTH
   char *bsdauthstylename = NULL;
#endif /* HAVE_BSDAUTH */
#if HAVE_GSSAPI
   char *gssapiservicename = NULL, *gssapikeytab = NULL;
#endif /* HAVE_GSSAPI */
/* XXX same for LDAP */
   uid_t euid;
   struct rule_t *basev[] = { sockscf.crule,         sockscf.srule     };
   int isclientrulev[]   =  { 1,                     0                 };
   int *methodbasev[]    =  { sockscf.clientmethodv, sockscf.methodv   };
   size_t *methodbasec[] =  { &sockscf.clientmethodc, &sockscf.methodc };
   size_t i, basec;

#if !HAVE_DUMPCONF
#if !HAVE_PRIVILEGES
   if (!sockscf.uid.privileged_isset) {
      sockscf.uid.privileged       = sockscf.state.euid;
      sockscf.uid.privileged_isset = 1;
   }
   else {
      if (socks_seteuid(&euid, sockscf.uid.privileged) != 0
      ||  socks_seteuid(NULL, euid)                    != 0)
         serr(EXIT_FAILURE, "%s: socks_seteuid() failed", function);
   }

   if (!sockscf.uid.unprivileged_isset) {
      sockscf.uid.unprivileged       = sockscf.state.euid;
      sockscf.uid.unprivileged_isset = 1;
   }
   else { /* check the euid-switching works. */
      if (socks_seteuid(&euid, sockscf.uid.unprivileged) != 0
      ||  socks_seteuid(NULL, euid)                      != 0)
         serr(EXIT_FAILURE, "%s: socks_seteuid() failed", function);
   }

#if HAVE_LIBWRAP
   if (!sockscf.uid.libwrap_isset) {
      sockscf.uid.libwrap       = sockscf.uid.unprivileged;
      sockscf.uid.libwrap_isset = 1;
   }
   else { /* check the euid-switching works. */
      if (socks_seteuid(&euid, sockscf.uid.libwrap) != 0
      ||  socks_seteuid(NULL, euid)                 != 0)
         serr(EXIT_FAILURE, "%s: socks_seteuid() failed", function);
   }
#endif /* HAVE_LIBWRAP */
#endif /* !HAVE_PRIVILEGES */
#endif /* !HAVE_DUMPCONF */

#if !HAVE_DUMPCONF && SOCKS_SERVER

   if (sockscf.clientmethodc == 0) {
      sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_NONE;

      if (methodisset(AUTHMETHOD_GSSAPI, sockscf.methodv, sockscf.methodc))
         sockscf.clientmethodv[sockscf.clientmethodc++] = AUTHMETHOD_GSSAPI;
   }

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
#endif /* !HAVE_DUMPCONF && SOCKS_SERVER */

   if (sockscf.methodc == 0)
      swarnx("%s: no authentication methods enabled.  This means all requests "
             "will be blocked after negotiation.  Perhaps this is not "
             "intended?", function);


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
         const struct command_t udpreplyonly = { .udpreply = 1 };

         for (i = 0; i < rule->state.methodc; ++i) {
            switch (rule->state.methodv[i]) {
#if HAVE_PAM
               case AUTHMETHOD_PAM:
                  if (sockscf.state.pamservicename == NULL)
                     break; /* already found to vary. */

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

#if HAVE_BSDAUTH
               case AUTHMETHOD_BSDAUTH:
                  if (sockscf.state.bsdauthstylename == NULL)
                     break; /* already found to vary. */

                  if (bsdauthstylename == NULL) /* first bsdauth rule. */
                     bsdauthstylename = rule->state.bsdauthstylename;
                  else if (strcmp(bsdauthstylename,
                  rule->state.bsdauthstylename) != 0) {
                     slog(LOG_DEBUG, "%s: bsdauth.stylename varies, %s ne %s",
                     function, bsdauthstylename, rule->state.bsdauthstylename);

                     sockscf.state.bsdauthstylename = NULL;
                  }

                  break;
#endif /* HAVE_BSDAUTH */

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
                  /* else; already found to vary. */

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
                  /* else; already found to vary. */

                  break;
#endif /* HAVE_GSSAPI */

               default:
                  break;
            }
         }

         if (rule->state.methodc == 0) {
            if (isreplycommandonly(&rule->state.command)
            &&  !sockscf.srchost.checkreplyauth)
               /* don't require user to specify a method for reply-only rules */
               ;
            else
               serrx(EXIT_FAILURE,
                     "%s: %s-rule #%lu allows no authentication methods",
                     function,
                     isclientrule ? "client" : "socks",
                     (unsigned long)rule->number);
         }

         if (isreplycommandonly(&rule->state.command)) {
            for (i = 0; i < rule->state.methodc; ++i) {
               switch (rule->state.methodv[i]) {
                  case AUTHMETHOD_NONE:
                  case AUTHMETHOD_PAM:
                     break;

                  case AUTHMETHOD_RFC931:
                     if (memcmp(&rule->state.command, &udpreplyonly,
                     sizeof(udpreplyonly)) == 0) /* udp only. */
                        serrx(EXIT_FAILURE,
                              "%s: %s-rule #%lu specifies method %s, but this "
                              "method can not be provided by udpreplies",
                              function,
                              isclientrule ? "client" : "socks",
                              (unsigned long)rule->number,
                              method2string(rule->state.methodv[i]));
                     break;

                  default:
                     serrx(EXIT_FAILURE,
                           "%s: %s-rule #%lu specifies method %s, but this "
                           "method can not be provided by replies",
                           function,
                           isclientrule ? "client" : "socks",
                           (unsigned long)rule->number,
                           method2string(rule->state.methodv[i]));
               }
            }
         }

         if (rule->user != NULL || rule->group != NULL) {
            if (memcmp(&rule->state.command, &udpreplyonly,
            sizeof(udpreplyonly)) == 0)
               serrx(EXIT_FAILURE, "%s-rule #%lu: udpreplies can "
                                   "not provide any user/group information",
                                   isclientrule ? "client" : "socks",
                                   (unsigned long)rule->number);

            for (i = 0; i < rule->state.methodc; ++i) {
               if (methodcanprovide(rule->state.methodv[i], username))
                  break;

            if (i >= rule->state.methodc)
               serrx(EXIT_FAILURE,
                     "%s-rule #%lu specifies a user/group-name, "
                     "but no method that can provide it",
                     isclientrule ? "client" : "socks",
                     (unsigned long)rule->number);
            }
         }
#if BAREFOOTD
         if (isclientrule && rule->state.protocol.tcp)
            /*
             * Add all "to:" addresses to the list of internal interfaces;
             * barefootd doesn't use a separate "internal:" keyword for it.
             */
             addinternal(&rule->dst, SOCKS_TCP);
         else if (!isclientrule && rule->state.protocol.udp)
            sockscf.state.alludpbounced = 0;
#endif /* BAREFOOTD */
      }
   }

#if HAVE_PAM
   if (sockscf.state.pamservicename != NULL
   &&  pamservicename               != NULL)
      /*
       * pamservicename does not vary, but is not necessarily the
       * the same as sockscf.state.pamservicename (default).
       * If it is not, set sockscf.state.pamservicename to
       * what the user used in one or more of the rules, since
       * it is the same in all rules, i.e. making it that value
       * we use to make passworddbisunique() work as expected.
       *
       * Likewise for bsdauth, gssapi, etc.
      */

      if (strcmp(pamservicename, sockscf.state.pamservicename) != 0)
         sockscf.state.pamservicename = pamservicename;
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   if (sockscf.state.bsdauthstylename != NULL
   &&  bsdauthstylename               != NULL)
      if (strcmp(bsdauthstylename, sockscf.state.bsdauthstylename) != 0)
         sockscf.state.bsdauthstylename = bsdauthstylename;
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
   if (sockscf.state.gssapiservicename != NULL
   &&  gssapiservicename               != NULL)
      if (strcmp(gssapiservicename, sockscf.state.gssapiservicename) != 0)
         sockscf.state.gssapiservicename = gssapiservicename;

   if (sockscf.state.gssapikeytab != NULL
   &&  gssapikeytab               != NULL)
      if (strcmp(gssapikeytab, sockscf.state.gssapikeytab) != 0)
         sockscf.state.gssapikeytab = gssapikeytab;
#endif /* HAVE_GSSAPI */

   /*
    * Go through all rules again and set default values for
    * authentication-methods, if none set.
    */
   basec = 0;
   while (basec < ELEMENTS(basev)) {
#if HAVE_PAM || HAVE_BSDAUTH || HAVE_GSSAPI
      const int *methodv     = methodbasev[basec];
      const int methodc      = *methodbasec[basec];
#endif /* HAVE_PAM || HAVE_BSDAUTH || HAVE_GSSAPI */
      struct rule_t *rule    = basev[basec];

      ++basec;

      if (rule == NULL)
         continue;

      for (; rule != NULL; rule = rule->next) {
#if HAVE_PAM
         if (methodisset(AUTHMETHOD_PAM, methodv, methodc))
            if (*rule->state.pamservicename == NUL) { /* set to default. */
               SASSERTX(strlen(sockscf.state.pamservicename)
               < sizeof(rule->state.pamservicename));

               strcpy(rule->state.pamservicename, sockscf.state.pamservicename);
            }
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
         if (methodisset(AUTHMETHOD_BSDAUTH, methodv, methodc))
            if (*rule->state.bsdauthstylename == NUL) { /* set to default. */
               if (sockscf.state.bsdauthstylename != NULL) {
                   SASSERTX(strlen(sockscf.state.bsdauthstylename)
                   < sizeof(rule->state.bsdauthstylename));

                   strcpy(rule->state.bsdauthstylename,
                   sockscf.state.bsdauthstylename);
               } else
                   rule->state.bsdauthstylename[0] = NUL;
            }
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
         if (methodisset(AUTHMETHOD_GSSAPI, methodv, methodc)) {
            if (*rule->state.gssapiservicename == NUL) { /* set to default. */
               SASSERTX(strlen(sockscf.state.gssapiservicename)
               < sizeof(rule->state.gssapiservicename));

               strcpy(rule->state.gssapiservicename,
                      sockscf.state.gssapiservicename);
            }

            if (*rule->state.gssapikeytab == NUL) { /* set to default. */
               SASSERTX(strlen(sockscf.state.gssapikeytab)
               < sizeof(rule->state.gssapikeytab));
               strcpy(rule->state.gssapikeytab, sockscf.state.gssapikeytab);
            }

            /*
             * can't do memcmp since we don't want to include
             * gssapiencryption.nec in the compare.
             */
            if (rule->state.gssapiencryption.clear           == 0
            &&  rule->state.gssapiencryption.integrity       == 0
            &&  rule->state.gssapiencryption.confidentiality == 0
            &&  rule->state.gssapiencryption.permessage      == 0) {
               rule->state.gssapiencryption.clear          = 1;
               rule->state.gssapiencryption.integrity      = 1;
               rule->state.gssapiencryption.confidentiality= 1;
               rule->state.gssapiencryption.permessage     = 0;
            }
         }
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
         if (*rule->state.ldap.keytab == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_GSSAPIKEYTAB)
            <= sizeof(rule->state.ldap.keytab));
            strcpy(rule->state.ldap.keytab, DEFAULT_GSSAPIKEYTAB);
         }

         if (*rule->state.ldap.filter == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_LDAP_FILTER)
            <= sizeof(rule->state.ldap.filter));
            strcpy(rule->state.ldap.filter, DEFAULT_LDAP_FILTER);
         }

         if (*rule->state.ldap.filter_AD == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_LDAP_FILTER_AD)
            <= sizeof(rule->state.ldap.filter_AD));
            strcpy(rule->state.ldap.filter_AD, DEFAULT_LDAP_FILTER_AD);
         }

         if (*rule->state.ldap.attribute == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_LDAP_ATTRIBUTE)
            <= sizeof(rule->state.ldap.attribute));
            strcpy(rule->state.ldap.attribute, DEFAULT_LDAP_ATTRIBUTE);
         }

         if (*rule->state.ldap.attribute_AD == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_LDAP_ATTRIBUTE_AD)
            <= sizeof(rule->state.ldap.attribute_AD));
            strcpy(rule->state.ldap.attribute_AD, DEFAULT_LDAP_ATTRIBUTE_AD);
         }

         if (*rule->state.ldap.certfile == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_LDAP_CACERTFILE)
            <= sizeof(rule->state.ldap.certfile));
            strcpy(rule->state.ldap.certfile, DEFAULT_LDAP_CACERTFILE);
         }

         if (*rule->state.ldap.certpath == NUL) { /* set to default. */
            SASSERTX(sizeof(DEFAULT_LDAP_CERTDBPATH)
            <= sizeof(rule->state.ldap.certpath));
            strcpy(rule->state.ldap.certpath, DEFAULT_LDAP_CERTDBPATH);
         }

         if (rule->state.ldap.port == 0) /* set to default */
            rule->state.ldap.port = SOCKD_EXPLICIT_LDAP_PORT;

         if (rule->state.ldap.portssl == 0) /* set to default */
            rule->state.ldap.portssl = SOCKD_EXPLICIT_LDAPS_PORT;
#endif /* HAVE_LDAP */
      }
   }

   if (sockscf.internalc == 0
#if BAREFOOTD
   && sockscf.state.alludpbounced
#endif /* BAREFOOTD */
   )
      serrx(EXIT_FAILURE,
            "%s: no internal address given for server to listen for "
            "clients on",
            function);


   if (sockscf.external.addrc == 0)
      serrx(EXIT_FAILURE,
            "%s: no external address given for server to use forwarding "
            "data on behalf of clients",
            function);

   if (sockscf.external.rotation == ROTATION_SAMESAME
   &&  sockscf.external.addrc    == 1)
      swarnx("%s: rotation for external addresses is set to same-same, but "
             "the number of external addresses is only one, so this does "
             "not make sense",
             function);

   if (sockscf.routeoptions.maxfail == 0 && sockscf.routeoptions.badexpire != 0)
      swarnx("%s: it does not make sense to set \"route.badexpire\" "
             "when \"route.maxfail\" is set to zero",
             function);

#if COVENANT
   if (*sockscf.realmname == NUL)
      strcpy(sockscf.realmname, DEFAULT_REALMNAME);
#endif /* COVENANT */

#if !HAVE_DUMPCONF
   if (pidismother(sockscf.state.pid) == 1) {   /* main mother */
      for (i = 0; i < sockscf.external.addrc; ++i)
         if (!addrisbindable(&sockscf.external.addrv[i]))
            serrx(EXIT_FAILURE, "%s: can not bind external address #%ld: %s",
                  function,
                  (long)i,
                  ruleaddr2string(&sockscf.external.addrv[i], NULL, 0));
   }
#endif /* !HAVE_DUMPCONF */

}

static char *
getlimitinfo(void)
{
#ifndef RLIMIT_NPROC
   return "";
#else /* have RLIMIT_NPROC */
   static char buf[2048];
   const int fds_per_proc = 2 /* two pipes */ + HAVE_SENDMSG_DEADLOCK;
   const char *limiter;
   struct rlimit maxfd, maxproc;
   char maxprocstr[64], maxfdstr[64];
   unsigned long negc_proc, negc_fd, reqc_proc, reqc_fd, ioc_proc, ioc_fd,
                 negc_limit, reqc_limit, ioc_limit,
                 proc_in_use, proc_free, fds_in_use, fds_free;

   if (getrlimit(RLIMIT_NOFILE, &maxfd) != 0) {
      swarn("getrlimit(RLIMIT_NOFILE) failed");
      return "";
   }

   if (getrlimit(RLIMIT_NPROC, &maxproc) != 0) {
      swarn("getrlimit(RLIMIT_NPROC) failed");
      return "";
   }

   if (maxfd.rlim_cur == RLIM_INFINITY
   &&  maxproc.rlim_cur == RLIM_INFINITY)
      return "no applicable environment resource limits configured";

   if (maxproc.rlim_cur == RLIM_INFINITY)
      snprintf(maxprocstr, sizeof(maxprocstr), "no limit");
   else
      snprintf(maxprocstr, sizeof(maxprocstr), "%lu",
               (unsigned long)maxproc.rlim_cur);

   if (maxfd.rlim_cur == RLIM_INFINITY)
      snprintf(maxfdstr, sizeof(maxfdstr), "no limit");
   else
      snprintf(maxfdstr, sizeof(maxfdstr), "%lu",
               (unsigned long)maxfd.rlim_cur);

   fds_free    = freedescriptors(NULL) - FDPASS_MAX;
   fds_in_use  = (unsigned long)maxfd.rlim_cur - fds_free;

   proc_free   = maxproc.rlim_cur
               - sockscf.option.serverc
               - childcheck(-CHILD_NEGOTIATE) / SOCKD_NEGOTIATEMAX
               - childcheck(-CHILD_REQUEST)   / SOCKD_REQUESTMAX
               - childcheck(-CHILD_IO)        / SOCKD_IOMAX;
   proc_in_use = maxproc.rlim_cur - proc_free;

   negc_proc = proc_free * SOCKD_NEGOTIATEMAX;
   reqc_proc = proc_free * SOCKD_REQUESTMAX;
   ioc_proc  = proc_free * SOCKD_IOMAX;

   negc_fd   = (fds_free / fds_per_proc) * SOCKD_NEGOTIATEMAX;
   reqc_fd   = (fds_free / fds_per_proc) * SOCKD_REQUESTMAX;
   ioc_fd    = (fds_free / fds_per_proc) * SOCKD_IOMAX;

   if (negc_proc < negc_fd
   ||  reqc_proc < reqc_fd
   ||  ioc_proc  < ioc_fd) {
      limiter = "processes";

      negc_limit = negc_proc;
      reqc_limit = reqc_proc;
      ioc_limit  = ioc_proc;
   }
   else {
      limiter = "open files";

      negc_limit = negc_fd;
      reqc_limit = reqc_fd;
      ioc_limit  = ioc_fd;
   }

   negc_limit += childcheck(-CHILD_NEGOTIATE);
   reqc_limit += childcheck(-CHILD_REQUEST);
   ioc_limit  += childcheck(-CHILD_IO);

   snprintf(buf, sizeof(buf),
            "current resource limits:\n"
            "   processes: %s, file descriptors: %s\n"
            "number of %s limits max clients per phase to the following:\n"
            "   negotiate phase: %lu, request phase: %lu, io phase: %lu\n"
            "note that resources are shared; actual limits will depend on "
            "phase composition",
             maxprocstr, maxfdstr,
             limiter,
             negc_limit, reqc_limit, ioc_limit);

   return buf;
#endif /* have RLIMIT_NPROC */
}


#if DEBUG
static void
dotest(void)
{
   const char *function = "dotest()";
   struct sockd_child_t *child;
   struct sockd_client_t client;
   struct sockd_request_t request;
   struct sockd_io_t io;
   int i;

   slog(LOG_INFO, "%s: starting send_client() test ...", function);

   if ((child = nextchild(CHILD_NEGOTIATE, SOCKS_TCP)) == NULL)
      serr(EXIT_FAILURE, "%s: nextchild(CHILD_NEGOTIATE) failed", function);

   if (kill(child->pid, SIGSTOP) != 0)
      serr(EXIT_FAILURE, "%s: kill(SIGSTOP) of child %ld failed",
      function, (long)child->pid);

   bzero(&client, sizeof(client));
   if ((client.s = socket(SOCK_STREAM, AF_INET, 0)) == -1)
      serr(EXIT_FAILURE, "%s: failed to create a SOCK_STREAM socket", function);

   i = 0;
   while (send_client(child->s, &client, NULL, 0) == 0)
      ++i;

   if (kill(child->pid, SIGTERM) != 0)
      serr(EXIT_FAILURE, "%s: kill(SIGTERM) of child %ld failed",
      function, (long)child->pid);

   if (i >= SOCKD_NEGOTIATEMAX)
      slog(LOG_INFO, "%s: send_client() test completed ok, sent %d requests",
      function, i);
   else
      swarn("%s: send_client() test failed after %d requests", function, i);


   slog(LOG_INFO, "%s: starting send_req() test ...", function);

   if ((child = nextchild(CHILD_REQUEST, SOCKS_TCP)) == NULL)
      serr(EXIT_FAILURE, "%s: nextchild(CHILD_REQUEST) failed", function);

   if (kill(child->pid, SIGSTOP) != 0)
      serr(EXIT_FAILURE, "%s: kill(SIGSTOP) of child %ld failed",
      function, (long)child->pid);

   bzero(&request, sizeof(request));
   if ((request.s = socket(SOCK_STREAM, AF_INET, 0)) == -1)
      serr(EXIT_FAILURE, "%s: failed to create a SOCK_STREAM socket", function);

   i = 0;
   while (send_req(child->s, &request) == 0)
      ++i;

   if (kill(child->pid, SIGTERM) != 0)
      serr(EXIT_FAILURE, "%s: kill(SIGTERM) of child %ld failed",
      function, (long)child->pid);

   if (i >= SOCKD_REQUESTMAX)
      slog(LOG_INFO, "%s: send_req() test completed ok, sent %d requests",
      function, i);
   else
      swarn("%s: send_req() test failed after %d requests", function, i);

   slog(LOG_INFO, "%s: starting send_io() test ...", function);

   if ((child = nextchild(CHILD_IO, SOCKS_TCP)) == NULL)
      serr(EXIT_FAILURE, "%s: nextchild(CHILD_IO) failed", function);

   if (kill(child->pid, SIGSTOP) != 0)
      serr(EXIT_FAILURE, "%s: kill(SIGSTOP) of child %ld failed",
      function, (long)child->pid);

   bzero(&io, sizeof(io));
   io.state.command = SOCKS_UDPASSOCIATE;
   if ((io.control.s = socket(SOCK_STREAM, AF_INET, 0)) == -1
   ||  (io.src.s     = socket(SOCK_STREAM, AF_INET, 0)) == -1
   ||  (io.dst.s     = socket(SOCK_DGRAM, AF_INET, 0)) == -1)
      serr(EXIT_FAILURE, "%s: failed to create a SOCK_STREAM socket", function);

   i = 0;
   while (send_io(child->s, &io) == 0)
      ++i;

   if (kill(child->pid, SIGTERM) != 0)
      serr(EXIT_FAILURE, "%s: kill(SIGTERM) of child %ld failed",
      function, (long)child->pid);

   if (i >= SOCKD_IOMAX)
      slog(LOG_INFO, "%s: send_io() test completed ok, sent %d requests",
      function, i);
   else
      swarn("%s: send_io() test failed after %d requests", function, i);

#if 0
   socks_iobuftest();
#endif
}

#endif /* DEBUG */
