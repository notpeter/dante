/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005
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
"$Id: sockd.c,v 1.311 2006/01/20 13:06:39 michaels Exp $";

	/*
	 * signal handlers
    */

__BEGIN_DECLS

static void
modulesetup __P((void));

static void
siginfo __P((int sig));

static void
sigchld __P((int sig));

static void
sigalrm __P((int sig));

static void
sighup __P((int sig));


static void
sigserverbroadcast __P((int sig));
/*
 * Broadcasts "sig" to all other servers.
 *
 */

static void
serverinit __P((int argc, char *argv[], char *envp[]));
/*
 * Initialises options/sockscf.  "argc" and "argv" should be
 * the arguments passed to main().
 * Exits on failure.
 */

static void
usage __P((int code));
/*
 * print usage.
 */

static void
showversion __P((void));
/*
 * show versioninfo and exits.
 */


static void
showlicense __P((void));
/*
 * shows license and exits.
 */

static void
optioninit __P((void));
/*
 * sets unset options to a reasonable default.
*/

#if DIAGNOSTIC && HAVE_MALLOC_OPTIONS
	extern char *malloc_options;
#endif  /* DIAGNOSTIC && HAVE_MALLOC_OPTIONS */

#if HAVE_PROGNAME
extern char *__progname;
#else
char *__progname = "sockd";	/* default. */
#endif  /* HAVE_PROGNAME */

extern char *optarg;

#define ELECTRICFENCE	0

#if ELECTRICFENCE
	extern int EF_PROTECT_FREE;
	extern int EF_ALLOW_MALLOC_0;
	extern int EF_ALIGNMENT;
	extern int EF_PROTECT_BELOW;
#endif /* ELECTRICFENCE */

__END_DECLS

int
#if HAVE_SETPROCTITLE
main(argc, argv)
#else
main(argc, argv, envp)
#endif /* HAVE_SETPROCTITLE */
	int	argc;
	char	*argv[];
#if !HAVE_SETPROCTITLE
	char    *envp[];
#endif  /* HAVE_SETPROCTITLE */
{
	struct sigaction sigact;
	int p, maxfd, dforchild;
	FILE *fp;
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
	malloc_options = "AJ";
#endif  /* DIAGNOSTIC && HAVE_MALLOC_OPTIONS */

#if ELECTRICFENCE
	EF_PROTECT_FREE         = 1;
	EF_ALLOW_MALLOC_0       = 1;
	EF_ALIGNMENT            = 0;
	EF_PROTECT_BELOW			= 0;
#endif /* ELECTRICFENCE */

	serverinit(argc, argv, envp);
	showconfig(&sockscf);
	socks_seteuid(NULL, sockscf.uid.unprivileged);

	/*
	 * for chroot and needing every descriptor we can get.
	 */

	/* syslog takes one */
	dforchild = sockscf.log.type & LOGTYPE_SYSLOG ? -1 : 0;
	for (p = 0, maxfd = getdtablesize(); p < maxfd; ++p) {
		int i;

		if (descriptorisreserved(p))
			continue;

		++dforchild; /* descriptor will be usable by child. */

		/* sockets we listen on. */
		for (i = 0; i < sockscf.internalc; ++i) {
			if (p == sockscf.internalv[i].s)
				break;

#if NEED_ACCEPTLOCK
			if (sockscf.option.serverc > 1)
				if (p == sockscf.internalv[i].lock)
					break;
#endif
		}
		if (i < sockscf.internalc) /* p is socket we listen on. */
			continue;

		close(p);
	}
	errno = 0;

	/*
	 * Check system limits against what we need.
	 * Enough descriptors for each childprocess?  +2 for mother connections.
	 */

	/* CONSTCOND */
	maxfd = MAX(SOCKD_NEGOTIATEMAX,
	MAX(SOCKD_REQUESTMAX, SOCKD_IOMAX * FDPASS_MAX)) + 2;

	if (dforchild < maxfd) {
		struct rlimit rlimit;

		rlimit.rlim_cur = rlimit.rlim_max = MIN(maxfd, FD_SETSIZE);

		if (setrlimit(RLIMIT_OFILE, &rlimit) != 0) {
			if (errno != EPERM)
				serr(EXIT_FAILURE, "setrlimit(RLIMIT_OFILE, %d)",
				(int)rlimit.rlim_max);
			else if (getdtablesize() < SOCKD_NEGOTIATEMAX + 2)
				serr(EXIT_FAILURE,
				"%d descriptors configured for negotiation, %d available",
				SOCKD_NEGOTIATEMAX + 2, getdtablesize());
			else if (getdtablesize() < SOCKD_REQUESTMAX + 2)
				serr(EXIT_FAILURE,
				"%d descriptors configured for requestcompletion, %d available",
				SOCKD_REQUESTMAX + 2, getdtablesize());
			else if (getdtablesize() < SOCKD_IOMAX * FDPASS_MAX + 2)
				serr(EXIT_FAILURE,
				"%d descriptors configured for i/o, %d available",
				SOCKD_IOMAX * FDPASS_MAX + 2, getdtablesize());
			else
				SERRX(getdtablesize());
		}
	}

	/* set up signalhandlers. */

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags	= SA_RESTART | SA_NOCLDSTOP;

	sigact.sa_handler = siginfo;
#if HAVE_SIGNAL_SIGINFO
	if (sigaction(SIGINFO, &sigact, NULL) != 0) {
		swarn("sigaction(SIGINFO)");
		return EXIT_FAILURE;
	}
#endif  /* HAVE_SIGNAL_SIGINFO */

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

	sigact.sa_handler = sockdexit;
	for (p = 0; (size_t)p < exitsignalc; ++p)
		if (sigaction(exitsignalv[p], &sigact, NULL) != 0)
			swarn("sigaction(%d)", exitsignalv[p]);

	sigact.sa_handler = SIG_IGN;
	for (p = 0; (size_t)p < ignoresignalc; ++p)
		if (sigaction(ignoresignalv[p], &sigact, NULL) != 0)
			swarn("sigaction(%d)", ignoresignalv[p]);

	sigact.sa_flags	= 0;	/* want to be interrupted. */
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
	socks_seteuid(NULL, sockscf.uid.privileged);
	if ((fp = fopen(SOCKD_PIDFILE, "w")) == NULL) {
		swarn("open(%s)", SOCKD_PIDFILE);
		errno = 0;
	}
	socks_seteuid(NULL, sockscf.uid.unprivileged);

	if (fp != NULL) {
		if (fprintf(fp, "%lu\n", (unsigned long)sockscf.state.pid) == EOF)
			swarn("fprintf(%s)", SOCKD_PIDFILE);
		fclose(fp);
	}
#endif /* !HAVE_DISABLED_PIDFILE */

	time(&sockscf.stat.boot);

	if ((sockscf.state.motherpidv = (pid_t *)malloc(
	sizeof(*sockscf.state.motherpidv) * sockscf.option.serverc)) == NULL)
		serrx(EXIT_FAILURE, "%s", NOMEM);
	*sockscf.state.motherpidv = sockscf.state.pid;	/* main server. */

	/* fork of requested number of servers.  Start at one 'cause we are "it".  */
	for (p = 1; p < sockscf.option.serverc; ++p) {
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

	if (childcheck(CHILD_NEGOTIATE)	<= 0
	||  childcheck(CHILD_REQUEST)		<= 0
	||	 childcheck(CHILD_IO)			<= 0)
		serr(EXIT_FAILURE, "childcheck() failed");

	slog(LOG_INFO, "%s/server v%s running", PACKAGE, VERSION);

	/*
	 * main loop; accept new connections and handle our children.
	 */

	/* CONSTCOND */
	while (1) {
		int client;
		struct sockd_child_t *child;
		fd_set rset;
		int rbits;

		rbits = fillset(&rset);

		++rbits;
		switch ((p = select(rbits, &rset, NULL, NULL, NULL))) {
			case 0:
				SERR(p);
				/* NOTREACHED */

			case -1:
				if (errno == EINTR)
					continue;
				SERR(p);
				/* NOTREACHED */
		}

		/*
		 * handle our children.
		 */

		/* first, get ack of free slots. */
		while ((child = getset(SOCKD_FREESLOT, &rset)) != NULL) {
			char command;
			int childisbad = 0;

			if ((p = readn(child->ack, &command, sizeof(command), NULL))
			!= sizeof(command)) {
				if (p == 0)
					swarnx("eof from %schild %lu",
					childtype2string(child->type), (unsigned long)child->pid);
				else
					swarn("readn(child->ack) from %schild %lu failed",
					childtype2string(child->type), (unsigned long)child->pid);

				childisbad = 1;
			}
			else {
				SASSERTX(command == SOCKD_FREESLOT);
				++child->freec;
			}

			clearset(SOCKD_FREESLOT, child, &rset);

			if (childisbad)
				removechild(child->pid);
		}

		/* next, get new requests. */
		while ((child = getset(SOCKD_NEWREQUEST, &rset)) != NULL) {
			int childisbad = 0;

#if DIAGNOSTIC
			int freed = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif

			switch (child->type) {
				/*
				 * in the order a packet travels between children;
				 * negotiate -> request -> io.
				 */

				case CHILD_NEGOTIATE: {
					int flags;
					struct sockd_request_t req;
					struct sockd_child_t *reqchild;

					if ((reqchild = nextchild(CHILD_REQUEST)) == NULL)
						break;	/* no child to accept a new request. */

					SASSERTX(reqchild->freec > 0);

					/* receive request from negotiator child... */
					if ((p = recv_req(child->s, &req)) != 0) {
						childisbad = 1;
						break;
					}
					++sockscf.stat.negotiate.received;

					/* set descriptor to blocking for request... */
					if ((flags = fcntl(req.s, F_GETFL, 0)) == -1
					||  fcntl(req.s, F_SETFL, flags & ~O_NONBLOCK) == -1)
						swarn("fcntl()");

					/* and send it to a request child. */
					if ((p = send_req(reqchild->s, &req)) == 0) {
						--reqchild->freec;
						++sockscf.stat.request.sendt;
					}
					else {
						clearset(SOCKD_NEWREQUEST, child, &rset);
						childisbad = 1;
						child = reqchild;
					}

					close(req.s);
					break;
				}

				case CHILD_REQUEST: {
					struct sockd_io_t io;
					struct sockd_child_t *iochild;

					if ((iochild = nextchild(CHILD_IO)) == NULL)
						break;	/* no child to accept new io. */

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
						++sockscf.stat.io.sendt;
					}
					else {
						clearset(SOCKD_NEWREQUEST, child, &rset);
						childisbad = 1;
						child = iochild;
					}

					close_iodescriptors(&io);
					break;
				}

				case CHILD_IO:
					/*
					 * the only thing a iochild should return is a ack each time
					 * it finishes with a io, that is handled in loop above.
					 */
					break;
			}

#if DIAGNOSTIC
			SASSERTX(freed == freedescriptors(sockscf.option.debug ?
			"end" : NULL));
#endif
			clearset(SOCKD_NEWREQUEST, child, &rset);

			if (childisbad) /* error/eof from child. */
				switch (errno) {
					case EMFILE:
					case ENFILE:
						break;	/* child is ok, we are not. */

					default:
						removechild(child->pid);
				}
		}

		/* handled our children.  Is there a new connection pending? */
		for (p = 0; p < sockscf.internalc; ++p) {
			char accepted[MAXSOCKADDRSTRING];

			if (FD_ISSET(sockscf.internalv[p].s, &rset)) {
				const struct listenaddress_t *l = &sockscf.internalv[p];
				struct sockd_child_t *negchild;
				struct sockaddr from;
				socklen_t len;

				if ((negchild = nextchild(CHILD_NEGOTIATE)) == NULL)
					break;  /* no free negotiator children, don't accept(). */

#if NEED_ACCEPTLOCK
				if (sockscf.option.serverc > 1)
					if (socks_lock(l->lock, F_WRLCK, 0) != 0)
						continue;
#endif

#if HAVE_SENDMSG_DEADLOCK
				if (socks_lock(negchild->lock, F_WRLCK, 0) != 0) {
#if NEED_ACCEPTLOCK
					if (sockscf.option.serverc > 1)
						socks_unlock(l->lock);
#endif /* NEED_ACCEPTLOCK */
					continue;
				}
#endif /* HAVE_SENDMSG_DEADLOCK */

				len = sizeof(from);
				if ((client = acceptn(l->s, &from, &len)) == -1)
					switch (errno) {
#ifdef EPROTO
						case EPROTO:			/* overloaded SVR4 error */
#endif
						case EWOULDBLOCK:		/* BSD */
						case ECONNABORTED:	/* POSIX */

						/* rest appears to be Linux stuff according to apache src. */
#ifdef ECONNRESET
						case ECONNRESET:
#endif
#ifdef ETIMEDOUT
						case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
						case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
						case ENETUNREACH:
#endif

#if NEED_ACCEPTLOCK
							if (sockscf.option.serverc > 1)
								socks_unlock(l->lock);
#endif /* NEED_ACCEPTLOCK */

#if HAVE_SENDMSG_DEADLOCK
							socks_unlock(negchild->lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

							slog(LOG_DEBUG, "accept(): %s", strerror(errno));
							continue; /* connection aborted/failed. */

						case ENFILE:
							continue;

						/*
						 * this should never happen since childcheck(), if
						 * initially successful, should make sure there is
						 *	always enough descriptors available.
						 */
						case EMFILE:
							/* FALLTHROUGH */

						default:
							SERR(client);
					}

#if HAVE_LINUX_BUGS
				/*
				 * yes, Linux manages to lose the descriptor flags, workaround
				 *	might be insufficient.
				 */
				if (fcntl(client, F_SETFL, fcntl(l->s, F_GETFL, 0)) != 0)
					swarn("tried to work around Linux bug via fcntl()");
#endif /* HAVE_LINUX_BUGS */

				++sockscf.stat.accepted;

#if NEED_ACCEPTLOCK
				if (sockscf.option.serverc > 1)
					socks_unlock(l->lock);
#endif

				slog(LOG_DEBUG, "got accept(): %s",
				sockaddr2string(&from, accepted, sizeof(accepted)));

				if (send_client(negchild->s, client) == 0) {
					--negchild->freec;
					++sockscf.stat.negotiate.sendt;
				}
				else
					switch (errno) {
						case EMFILE:
						case ENFILE:
							break;	/* child is ok, we are not. */

						default:
							removechild(negchild->pid);
					}

#if HAVE_SENDMSG_DEADLOCK
				socks_unlock(negchild->lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

				close(client);
			}
		}
	}

	/* NOTREACHED */
}

static void
sigserverbroadcast(sig)
	int sig;
{
	int i;

	for (i = 1; i < sockscf.option.serverc; ++i)
		if (sockscf.state.motherpidv[i] != 0)
			kill(sockscf.state.motherpidv[i], sig);
}


static void
usage(code)
	int code;
{

	fprintf(code == 0 ? stdout : stderr,
	"%s: usage: %s [-DLNVdfhnv]\n"
	"   -D             : run in daemon mode\n"
	"   -L             : shows the license for this program\n"
   "   -N <number>    : fork of <number> servers [1]\n"
	"   -V             : verify configuration and exit\n"
	"   -d             : enable debugging\n"
	"   -f <filename>  : use <filename> as configuration file [%s]\n"
	"   -h             : print this information\n"
   "   -n             : disable TCP keep-alive\n"
	"   -v             : print version info\n",
	__progname, __progname, SOCKD_CONFIGFILE);

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
 * Copyright (c) 1997, 1998, 1999, 2000, 2001\n\
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
	uid_t euid;
	int ch, i;
	int verifyonly = 0;
	struct rlimit rlimit;

#if !HAVE_PROGNAME
	if (argv[0] != NULL)
		if ((__progname = strrchr(argv[0], '/')) == NULL)
			__progname = argv[0];
		else
			++__progname;
#endif  /* !HAVE_PROGNAME */

#if !HAVE_SETPROCTITLE
	if (initsetproctitle(argc, argv, envp) == -1)
		serr(EXIT_FAILURE, "%s: malloc", function);
#endif  /* !HAVE_SETPROCTITLE*/

	sockscf.child.addchild	= 1;
	sockscf.state.euid		= geteuid();
	sockscf.state.type		= CHILD_MOTHER;
	sockscf.option.serverc	= 1;	/* ourselves. ;-) */
	sockscf.bwlock				= -1;
	sockscf.sessionlock		= -1;

	while ((ch = getopt(argc, argv, "DLN:Vdf:hlnvw:")) != -1) {
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

			case 'w':
				sockscf.option.sleep = atoi(optarg);
				break;

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

		ch = 1;
		if (setsockopt(l->s, SOL_SOCKET, SO_REUSEADDR, &ch, sizeof(ch))
		!= 0)
			swarn("%s: setsockopt(SO_REUSEADDR)", function);

		socks_seteuid(&euid, sockscf.uid.privileged);
		/* LINTED pointer casts may be troublesome */
		if (bind(l->s, (struct sockaddr *)&l->addr, sizeof(l->addr)) != 0) {
			char badbind[MAXSOCKADDRSTRING];

			/* LINTED pointer casts may be troublesome */
			serr(EXIT_FAILURE, "%s: bind(%s)",
			function, sockaddr2string((struct sockaddr *)&l->addr, badbind,
			sizeof(badbind)));
		}
		socks_reseteuid(sockscf.uid.privileged, euid);

		if (listen(l->s, SOCKD_MAXCLIENTQUE) == -1)
			serr(EXIT_FAILURE, "%s: listen(%d)", function, SOCKD_MAXCLIENTQUE);

		if ((flags = fcntl(l->s, F_GETFL, 0)) == -1
		||  fcntl(l->s, F_SETFL, flags | O_NONBLOCK) == -1)
			serr(EXIT_FAILURE, "%s: fcntl()", function);

#if NEED_ACCEPTLOCK
		if (sockscf.option.serverc > 1)
			if ((l->lock = socks_mklock(SOCKS_LOCKFILE)) == -1)
				serr(EXIT_FAILURE, "%s: socks_mklock()", function);
#endif
	}

	/* avoid potentioal overflow of fd_set. */
	if (getrlimit(RLIMIT_OFILE, &rlimit) != 0)
			serr(EXIT_FAILURE, "getrlimit(RLIMIT_OFILE)");
	if (rlimit.rlim_cur > FD_SETSIZE) {
		rlimit.rlim_cur = rlimit.rlim_max = FD_SETSIZE;

		if (setrlimit(RLIMIT_OFILE, &rlimit) != 0)
			serr(EXIT_FAILURE, "setrlimit(RLIMIT_OFILE, %d)",
			(int)rlimit.rlim_cur);
		slog(LOG_DEBUG, "%s: reduced max descriptors to %d",
		function, (int)rlimit.rlim_cur);
	}
}

/* ARGSUSED */
static void
siginfo(sig)
	int sig;
{
	unsigned long seconds, days, hours, minutes;
	size_t clients;

	clients = 0;
	clients += childcheck(-CHILD_NEGOTIATE);
	clients += childcheck(-CHILD_REQUEST);
	clients += childcheck(-CHILD_IO);

	clients -= childcheck(CHILD_NEGOTIATE);
	clients -= childcheck(CHILD_REQUEST);
	clients -= childcheck(CHILD_IO);

	seconds = difftime(time(NULL), sockscf.stat.boot);

	if (seconds >= 3600 * 24) {
		days		= seconds / (3600 * 24);
		seconds -= days * 3600 * 24;
	}
	else
		days = 0;

	if (seconds >= 3600) {
		hours		= seconds / 3600;
		seconds -= hours * 3600;
	}
	else
		hours = 0;

	if (seconds >= 60) {
		minutes	= seconds / 60;
		seconds -= minutes * 60;
	}
	else
		minutes = 0;

	slog(LOG_INFO, "%s v%s up %lu day%s, %lu:%.2lu, a: %lu, c: %lu",
	PACKAGE, VERSION, days, days == 1 ? "" : "s", hours, minutes,
	(unsigned long)sockscf.stat.accepted, (unsigned long)clients);

	slog(LOG_INFO, "negotiators (%d): a: %lu, h: %lu, c: %lu",
	childcheck(-CHILD_NEGOTIATE) / SOCKD_NEGOTIATEMAX,
	(unsigned long)sockscf.stat.negotiate.sendt,
	(unsigned long)sockscf.stat.negotiate.received,
	(unsigned long)childcheck(-CHILD_NEGOTIATE) - childcheck(CHILD_NEGOTIATE));

	slog(LOG_INFO, "requests (%d): a: %lu, h: %lu, c: %lu",
	childcheck(-CHILD_REQUEST) / SOCKD_REQUESTMAX,
	(unsigned long)sockscf.stat.request.sendt,
	(unsigned long)sockscf.stat.request.received,
	(unsigned long)childcheck(-CHILD_REQUEST) - childcheck(CHILD_REQUEST));

	slog(LOG_INFO, "iorelayers (%d): a: %lu, h: %lu, c: %lu",
	childcheck(-CHILD_IO) / SOCKD_IOMAX,
	(unsigned long)sockscf.stat.io.sendt,
	(unsigned long)sockscf.stat.io.sendt,
	(unsigned long)childcheck(-CHILD_IO) - childcheck(CHILD_IO));

	if (pidismother(sockscf.state.pid) == 1)	/* main mother */
		sigserverbroadcast(sig);

	sigchildbroadcast(sig, CHILD_NEGOTIATE | CHILD_REQUEST | CHILD_IO);
}


/* ARGSUSED */
static void
sighup(sig)
	int sig;
{
	const char *function = "sighup()";
	uid_t euid;
	int p;

	slog(LOG_INFO, function);

	resetconfig();
	optioninit();
	socks_seteuid(&euid, sockscf.state.euid);
	genericinit();
	socks_reseteuid(sockscf.state.euid, euid);
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
	static time_t deathtime;
	static int deaths;
	int status;
	pid_t pid;


	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		int i;

		/*
		 * No child should normally die, but try to cope with it happening.
		 */

		/* LINTED assignment in conditional context */
		if ((i = pidismother(pid)))
			sockscf.state.motherpidv[i - 1] = 0;
		else
			; /* assume relay child. */

		++deaths;
	}

	/*
	 * If we get a lot of childdeaths in a short time, assume something
	 * is wrong.
	 */

	if (deathtime == 0)
		time(&deathtime);

	if (difftime(time(NULL), deathtime) > 60) { /* enough time passed; reset.	*/
		deaths = 0;
		time(&deathtime);
	}

	if (deaths >= 10) {
		if (deaths == 10) { /* log once. */
			slog(LOG_ERR, "%s: %d childdeaths in %.0fs; locking count for a while",
			function, deaths, difftime(time(NULL), deathtime));
			sockscf.child.addchild = 0;
		}
		time(&deathtime); /* once the ball starts rolling... */
		alarm(60);
	}
	else
		sockscf.child.addchild = 1; /* can try to add a new one. */
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

	sockscf.resolveprotocol			= RESOLVEPROTOCOL_UDP;
	sockscf.option.keepalive		= 1;
	sockscf.timeout.negotiate		= SOCKD_NEGOTIATETIMEOUT;
	sockscf.timeout.io				= SOCKD_IOTIMEOUT;
	sockscf.external.rotation		= ROTATION_NONE;
#if HAVE_PAM
	sockscf.state.pamservicename 	= DEFAULT_PAMSERVICENAME;
#endif
	
#if DEBUG
	sockscf.child.maxidle 		= 0; /* XXX SOCKD_FREESLOTS;*/
#else
	sockscf.child.maxidle 		= 0;
#endif
}

static void
modulesetup(void)
{
	shmem_lockall();

	shmem_setup();
	redirectsetup();

	shmem_unlockall();
}
