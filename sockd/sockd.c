/*
 * Copyright (c) 1997, 1998
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
 *  Gaustadaléen 21
 *  N-0371 Oslo
 *  Norway
 * 
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

static const char rcsid[] =
"$Id: sockd.c,v 1.199 1999/02/26 19:26:48 michaels Exp $";

#include "common.h"

	/*
	 * signal handlers
   */

__BEGIN_DECLS

static void
siginfo __P((int sig));

static void
sigchld __P((int sig));

static void
sighup __P((int sig));

static void
sigserverbroadcast __P((int sig));
/*
 * Broadcasts "sig" to all other servers. 
 *
*/

static void
initoptions __P((int argc, char *argv[]));
/*
 * Initialises options/config.  "argc" and "argv" should be
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

__END_DECLS


#ifdef HAVE_PROGNAME
extern char *__progname;
#else
char *__progname = "sockd";
#endif  /* HAVE_PROGNAME */

extern char *optarg;

const int configtype =  CONFIGTYPE_SERVER;

struct config_t config;

int exitsignalv[] = {
	SIGINT, SIGQUIT, SIGBUS, SIGSEGV, SIGTERM
};
const int exitsignalc = ELEMENTS(exitsignalv);

int ignoresignalv[] = {
	SIGPIPE
};
const int ignoresignalc = ELEMENTS(ignoresignalv);


int
#ifdef HAVE_SETPROCTITLE
main(argc, argv)
#else
main(argc, argv, envp)
#endif /* HAVE_SETPROCTITLE */
	int	argc;
	char	*argv[];
#ifndef HAVE_SETPROCTITLE
	char    *envp[];
#endif  /* HAVE_SETPROCTITLE */
{
	struct sigaction sigact;
	int p, maxfd, dforchild;
	FILE *fp;

#if defined(DEBUG) && defined(HAVE_MALLOC_OPTIONS)
	extern char *malloc_options;
	malloc_options = "AJ";
#endif  /* DEBUG && HAVE_MALLOC_OPTIONS */

#ifndef HAVE_PROGNAME
	if (argv[0] != NULL)
		if ((__progname = strrchr(argv[0], '/')) == NULL) 
			__progname = argv[0];
		else
			++__progname;
#endif  /* !HAVE_PROGNAME */


	/*
	 * initialize misc options to sensible default.
 	*/

	config.option.serverc		= 1;	/* ourselves. ;-) */
	config.option.keepalive		= 1;

	config.srchost.unknown		= 1;

	config.timeout.negotiate	= DEFAULT_NEGOTIATETIMEOUT;
	config.timeout.io				= DEFAULT_IOTIMEOUT;	

	config.state.addchild		= 1;

#ifndef HAVE_SETPROCTITLE
#if 0 /* XXX */
	if (initsetproctitle(argc, argv, envp) == -1) 
		serr(EXIT_FAILURE, "malloc");
#endif
#endif  /* !HAVE_SETPROCTITLE*/

	initoptions(argc, argv);

	if (geteuid() != config.uid.unprivileged)
		seteuid(config.uid.unprivileged); 

	showconfig(&config);

	if (config.option.daemon)
		if (daemon(0, 0) != 0)
			serr(EXIT_FAILURE, "daemon()");

	/* we need every descriptor we can get. */
	for (dforchild = p = 0, maxfd = getdtablesize(); p < maxfd; ++p) {
		int i;

		/* don't close config/log files. */
		if (p == fileno(config.option.configfp)
		|| socks_logmatch(p, &config.log))
			continue;

		++dforchild; /* descriptor will be usable by child. */

		/* sockets we listen on. */
		for (i = 0; i < config.internalc; ++i) {
			if (p == config.internalv[i].s)
				break;

#ifdef NEED_ACCEPTLOCK
			if (config.option.serverc > 1)
				if (p == config.internalv[i].lock)
					break;
#endif
		}

		if (i < config.internalc)
			continue;

		close(p);
	}

	/*
	 * Check system limits against what we need.
	 * Enough descriptors for each childprocess?  +2 for mother connections.
	*/

	/* CONSTCOND */
	maxfd = MAX(SOCKD_NEGOTIATEMAX,
	MAX(SOCKD_REQUESTMAX, SOCKD_IOMAX * FDPASS_MAX)) + 2;

	if (dforchild < maxfd) {
		struct rlimit rlimit;

		rlimit.rlim_cur = maxfd;
		rlimit.rlim_max = maxfd;

		if (setrlimit(RLIMIT_OFILE, &rlimit) != 0)
			if (errno != EPERM)
				serr(EXIT_FAILURE, "setrlimit(RLIMIT_OFILE, %d)", rlimit.rlim_max);
			/* else; tell user what is too big. */

		if (getdtablesize() < SOCKD_NEGOTIATEMAX + 2)
			serrx(EXIT_FAILURE,
			"%d descriptors configured for negotiation, %d available",
			SOCKD_NEGOTIATEMAX + 2, getdtablesize());

		if (getdtablesize() < SOCKD_REQUESTMAX + 2)
			serrx(EXIT_FAILURE,
			"%d descriptors configured for requestcompletion, %d available",
			SOCKD_REQUESTMAX + 2, getdtablesize());

		if (getdtablesize() < SOCKD_IOMAX * FDPASS_MAX + 2)
			serrx(EXIT_FAILURE,
			"%d descriptors configured for i/o, %d available",
			SOCKD_IOMAX * FDPASS_MAX + 2, getdtablesize());
	}

	/* set up signalhandlers. */

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags	= SA_RESTART | SA_NOCLDSTOP;
	sigact.sa_handler = siginfo;

#ifdef HAVE_SIGNAL_SIGINFO
	if (sigaction(SIGINFO, &sigact, NULL) != 0) {
		swarn("sigaction(SIGINFO)");
		return EXIT_FAILURE;
	}
#endif  /* HAVE_SIGNAL_SIGINFO */

	/* same handler, for systems without SIGINFO. */
	sigact.sa_handler = siginfo;
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
	for (p = 0; p < exitsignalc; ++p)
		if (sigaction(exitsignalv[p], &sigact, NULL) != 0)
			swarn("sigaction(%d)", exitsignalv[p]);

	sigact.sa_handler = SIG_IGN;
	for (p = 0; p < ignoresignalc; ++p)
		if (sigaction(ignoresignalv[p], &sigact, NULL) != 0)
			swarn("sigaction(%d)", ignoresignalv[p]);

	/* may need privileges for writing out our pid. */
	seteuid(config.uid.privileged);
	
	if ((fp = fopen(SOCKD_PIDFILE, "w")) == NULL)
		swarn("open(%s)", SOCKD_PIDFILE);
	else {
		if (fprintf(fp, "%ld\n", (long)getpid()) == EOF)
			swarn("fprintf(%s)", SOCKD_PIDFILE);
		fclose(fp);
	}

	/* can't throw it all away, a child may need some. */
	seteuid(config.uid.unprivileged);

	if (time(&config.stat.boot) == (time_t)-1)
		SERR(-1);

	/* fork of requested number of servers.  Start at one, 'cause we are it.  */
	for (p = 1; p < config.option.serverc; ++p) {
		pid_t pid;

		if ((pid = fork()) == -1)
			swarn("fork()");
		else if (pid == 0) {
			config.state.pid = getpid();
			break;
		}
		else
			config.state.pidv[p] = pid;
	}

	if (childcheck(CHILD_NEGOTIATE) 	<= 0
	||  childcheck(CHILD_REQUEST)		<= 0
	||	 childcheck(CHILD_IO)			<= 0)
		serr(EXIT_FAILURE, "childcheck() failed");

  	slog(LOG_INFO, "%s/sockd v%s running", PACKAGE, VERSION);


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
			case -1:
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

			if ((p = readn(child->ack, &command, sizeof(command)))
			!= sizeof(command)) {
				if (p == 0)
					swarnx("readn(child->ack): child closed connection");
				else
					swarn("readn(child->ack)");
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

#ifdef DIAGNOSTIC
			int freed = freedescriptors(config.option.debug ? "start" : NULL);
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

					/* receive request from negotiator child ... */
					if ((p = recv_req(child->s, &req)) != 0) {
						childisbad = 1;
						break;
					}
					++config.stat.negotiate.received;

					/* set descriptor to blocking for request. */
					if ((flags = fcntl(req.s, F_GETFL, 0)) == -1
					||  fcntl(req.s, F_SETFL, flags & NONBLOCKING) == -1)
						swarn("%s: fcntl()");

					/* and send it to a request child. */
					if ((p = send_req(reqchild->s, &req)) == 0) {
						--reqchild->freec;
						++config.stat.request.sendt;
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
					++config.stat.request.received;

					/* and send it to a io child. */
					if ((p = send_io(iochild->s, &io)) == 0) {
						--iochild->freec;
						++config.stat.io.sendt;
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
					 * the only thing a iochild should return is a ack byte each
					 * time it finishes with a io, that is handled in loop
					 * above.
					*/
					break;
			}

#ifdef DIAGNOSTIC
			SASSERTX(freed == freedescriptors(config.option.debug ? "end" : NULL));
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

		/* handled our children, is there a new connection pending? */
		for (p = 0; p < config.internalc; ++p) {
			char accepted[MAXSOCKADDRSTRING];

			if (FD_ISSET(config.internalv[p].s, &rset)) {
				const struct listenaddress_t *l = &config.internalv[p];
				struct sockd_child_t *negchild;
				struct sockaddr from;
				socklen_t len;

				if ((negchild = nextchild(CHILD_NEGOTIATE)) == NULL)
					break;  /* no free negotiator children, don't accept(). */
				
#ifdef NEED_ACCEPTLOCK
				if (config.option.serverc > 1)
					if (socks_lock(l->lock, F_WRLCK, 0) != 0)
						continue;
#endif

#ifdef HAVE_SENDMSG_DEADLOCK
				if (socks_lock(negchild->lock, F_WRLCK, 0) != 0) {
#ifdef NEED_ACCEPTLOCK
					if (config.option.serverc > 1)
						socks_unlock(l->lock, -1);
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

						/* rest appears to be linux stuff according to apache src. */
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

#ifdef NEED_ACCEPTLOCK
							if (config.option.serverc > 1)
								socks_unlock(l->lock, -1);
#endif /* NEED_ACCEPTLOCK */

#ifdef HAVE_SENDMSG_DEADLOCK
							socks_unlock(negchild->lock, -1);
#endif /* HAVE_SENDMSG_DEADLOCK */

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

#ifdef HAVE_LINUX_BUGS
				/*
				 * yes, linux manages to lose the descriptor flags, workaround
				 *	might be insufficient.
				*/
				if (fcntl(client, F_SETFL, fcntl(l->s, F_GETFL, 0)) != 0)
					swarn("tried to work around linux bug via fcntl()");
#endif /* HAVE_LINUX_BUGS */

				++config.stat.accepted;

#ifdef NEED_ACCEPTLOCK
				if (config.option.serverc > 1)
					if ((len = socks_unlock(l->lock, -1)) != 0)
						SERR(len);
#endif

				slog(LOG_DEBUG, "got accept(): %s",
				sockaddr2string(&from, accepted, sizeof(accepted)));

				if (send_client(negchild->s, client) == 0) {
					--negchild->freec;
					++config.stat.negotiate.sendt;
				}
				else 
					switch (errno) {
						case EMFILE:
						case ENFILE:
							break;	/* child is ok, we are not. */

						default:
							removechild(negchild->pid);
					}

#ifdef HAVE_SENDMSG_DEADLOCK
				socks_unlock(negchild->lock, -1);
#endif /* HAVE_SENDMSG_DEADLOCK */

				close(client);
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
	"%s: usage: %s [-DLNdfhlnv]\n"
	"\t -D             : run in daemon mode\n"
	"\t -L             : shows the license for this program\n"
   "\t -N <number>    : fork of <number> servers (default: 1)\n"
	"\t -d             : enable debugging\n"
	"\t -f <filename>  : use <filename> as configuration file\n"
	"\t -h             : print this information\n"
	"\t -l             : linebuffer output\n"
   "\t -n             : disable TCP keep-alive\n"
	"\t -v             : print version info\n",
	__progname, __progname);

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
 * Copyright (c) 1997, 1998\n\
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
 *  Gaustadaléen 21\n\
 *  N-0371 Oslo\n\
 *  Norway\n\
 * \n\
 * any improvements or extensions that they make and grant Inferno Nettverk A/S\n\
 * the rights to redistribute these changes.\n\
 *\n\
 */");

	exit(EXIT_SUCCESS);
}

static void
initoptions(argc, argv)
	int argc;
	char *argv[];
{
	const char *function = "initoptions()";
	uid_t euid;
	int ch, i;
	
	if (config.state.pid == 0)
		config.state.pid = getpid();

	while ((ch = getopt(argc, argv, "DLN:df:hlnvw:")) != -1) {
		switch (ch) {
			case 'D':
				config.option.daemon = 1;
				break;

			case 'L':
				showlicense();
				/* NOTREACHED */	

			case 'N':
				if ((config.option.serverc = atoi(optarg)) < 1)
					serrx(1, "%s: illegal value for -n: %d",
					function, config.option.serverc);
				break;
				
			case 'd':
				++config.option.debug;
				break;
				
			case 'f':
				config.option.configfile = optarg;
				break;

			case 'h':
				usage(0);	
				/* NOTREACHED */
				
			case 'l':
				config.option.lbuf = 1;
				break;

			case 'n':
				config.option.keepalive = 0;
				break;

			case 'v':
				showversion();
				/* NOTREACHED */	

			case 'w':
				config.option.sleep = atoi(optarg);
				break;
					
			default:
				usage(1);
		}
	}

	if ((config.state.pidv = (pid_t *)malloc(sizeof(config.state.pidv)
	* config.option.serverc)) == NULL)
		serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
	*config.state.pidv = getpid();	/* main server. */

	if (config.option.configfile == NULL)
		config.option.configfile = SOCKD_CONFIGFILE;

	if (config.option.configfp == NULL) {
		if ((config.option.configfp = fopen(config.option.configfile, "r"))
		== NULL)
			serr(EXIT_FAILURE, "%s: %s", function, config.option.configfile);
	}

	if (readconfig(config.option.configfp) != 0)
		serr(EXIT_FAILURE, "%s: %s", function, config.option.configfile);

	/* 
	 * Check arguments and settings, do they make sense?
	*/

	if (*config.domain == NUL)
		swarnx("%s: local domainname not set", function);
		
	euid = geteuid();	/* for reset back to original before function return. */ 
	if (euid != config.uid.privileged)
		seteuid(config.uid.privileged);

	if (config.internalc == 0) {
		struct servent	*service;

		if ((config.internalv = (struct listenaddress_t *)
		realloc(config.internalv, sizeof(*config.internalv) * ++config.internalc))
		== NULL)
			serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);

		(*config.internalv).addr.sin_addr.s_addr = htonl(INADDR_ANY);

		if ((service = getservbyname("socks", "tcp")) == NULL)
			(*config.internalv).addr.sin_port = htons(SOCKD_PORT);
		else
			(*config.internalv).addr.sin_port = (in_port_t)service->s_port;
	}

	for (i = 0; i < config.internalc; ++i) {
		int flags;
		struct listenaddress_t *l = &config.internalv[i];

		if ((l->s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			serr(EXIT_FAILURE, "%s: socket(SOCK_STREAM)", function);

		setsockoptions(l->s);

		ch = 1;
		if (setsockopt(l->s, SOL_SOCKET, SO_REUSEADDR, &ch, sizeof(ch)) != 0)
			swarn("%s: setsockopt(SO_REUSEADDR)", function);

		/* LINTED pointer casts may be troublesome */
		if (sockd_bind(l->s, (struct sockaddr *)&l->addr, 0) != 0) {
			char badbind[MAXSOCKADDRSTRING];

			/* LINTED pointer casts may be troublesome */
			serr(EXIT_FAILURE, "%s: bind(%s)",
			function, sockaddr2string((struct sockaddr *)&l->addr, badbind,
			sizeof(badbind)));
		}

		if (listen(l->s, SOCKD_MAXCLIENTQUE) == -1)
			serr(EXIT_FAILURE, "%s: listen(%d)", function, SOCKD_MAXCLIENTQUE);

		if ((flags = fcntl(l->s, F_GETFL, 0)) == -1
		||  fcntl(l->s, F_SETFL, flags | NONBLOCKING) == -1)
			serr(EXIT_FAILURE, "%s: fcntl()", function);
		

#ifdef NEED_ACCEPTLOCK
		if (config.option.serverc > 1)
			if ((l->lock = socks_mklock(SOCKS_LOCKFILE)) == -1)
				serr(EXIT_FAILURE, "%s: socks_mklock()", function);
#endif
	}

	if (euid != geteuid())
		seteuid(euid); /* reset back. */

	if (config.option.lbuf)
		for (i = 0; i < config.log.fpc; ++i)
			if (setvbuf(config.log.fpv[i], NULL, _IONBF, 0) != 0)
				swarnx("%s: setvbuf()", function);

	config.state.init = 1;
}



/* ARGSUSED */
static void
siginfo(sig)
	int sig;
{
	unsigned long seconds, days, hours, minutes;
	size_t clients = 0;

	clients += childcheck(-CHILD_NEGOTIATE);
	clients += childcheck(-CHILD_REQUEST);
	clients += childcheck(-CHILD_IO);

	clients -= childcheck(CHILD_NEGOTIATE);
	clients -= childcheck(CHILD_REQUEST);
	clients -= childcheck(CHILD_IO);

	seconds = (unsigned long)difftime(time(NULL), config.stat.boot);
	
	if (seconds >= 3600 * 24) {
		days = seconds / (3600 * 24);
		seconds -= days * 3600 * 24;
	}
	else
		days = 0;

	if (seconds >= 3600) {
		hours = seconds / 3600;
		seconds -= hours * 3600;
	}
	else
		hours = 0;

	if (seconds >= 60) {
		minutes = seconds / 60;
		seconds -= minutes * 60;
	}
	else
		minutes = 0;

	slog(LOG_INFO, "%s v%s up %lu day%s, %lu:%.2lu, a: %lu, c: %lu",
	PACKAGE, VERSION, days, days == 1 ? "" : "s", hours, minutes,
	(unsigned long)config.stat.accepted, (unsigned long)clients);

	slog(LOG_INFO, "negotiators:    a: %lu, h: %lu, c: %ld",
	config.stat.negotiate.sendt, config.stat.negotiate.received,
	(unsigned long)childcheck(-CHILD_NEGOTIATE) - childcheck(CHILD_NEGOTIATE));

	slog(LOG_INFO, "requests   :    a: %lu, h: %lu, c: %lu",
	config.stat.request.sendt, config.stat.request.received,
	(unsigned long)childcheck(-CHILD_REQUEST) - childcheck(CHILD_REQUEST));

	slog(LOG_INFO, "iorelayers :    a: %lu, h: %lu, c: %lu",
	config.stat.io.sendt, config.stat.io.sendt,
	(unsigned long)childcheck(-CHILD_IO) - childcheck(CHILD_IO));

	if (*config.state.pidv == config.state.pid)	/* main server */
		sigserverbroadcast(sig);
}


/* ARGSUSED */
static void
sighup(sig)
	int sig;
{
	const char *function = "sighup()";

	slog(LOG_INFO, "received SIGHUP, rereading config file");

	if (fseek(config.option.configfp, (long)0, SEEK_SET) == -1)
		swarn("%s: fseek(%s)", function, config.option.configfile);

	clearconfig(); 

	if (readconfig(config.option.configfp) != 0)
		serr(EXIT_FAILURE, "%s: %s", function, config.option.configfile);

	if (config.state.pid == getpid()) {	/* a server. */
		sigchildbroadcast(sig, CHILD_NEGOTIATE | CHILD_REQUEST | CHILD_IO);

		if (*config.state.pidv == config.state.pid)	/* main server */
			sigserverbroadcast(sig);
	}
}

/* ARGSUSED */
static void
sigchld(sig)
	int sig;
{
	int status;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		int i;

		for (i = 1; i < config.option.serverc; ++i)
			if (config.state.pidv[i] == pid)
				config.state.pidv[i] = 0;	/* a server died. */

		if (i == config.option.serverc)
			/* assume a relay child died, we can try to add a new one later. */
			config.state.addchild = 1;
	}
}


static void
sigserverbroadcast(sig)
	int sig;
{
	int i;

	SASSERT(*config.state.pidv == config.state.pid);

	for (i = 1; i < config.option.serverc; ++i)
		if (config.state.pidv[i] != 0)
			kill(config.state.pidv[i], sig);
}
