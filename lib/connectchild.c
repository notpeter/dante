/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2008, 2009
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
"$Id: connectchild.c,v 1.238 2009/10/09 07:47:17 michaels Exp $";

#define MOTHER  (0)   /* descriptor mother reads/writes on.  */
#define CHILD   (1)   /* descriptor child reads/writes on.   */

/*
 * Max number of unhandled packets in pipe between mother and child.
 */
#define MAXPACKETSQUEUED   (10)

static void sigio(int sig, siginfo_t *sip, void *scp);
static void run_connectchild(const int mother_data, const int mother_ack);

static struct sigaction       originalsig;
static volatile sig_atomic_t  reqoutstanding; 

struct route_t *
socks_nbconnectroute(s, control, packet, src, dst)
   int s;
   int control;
   struct socks_t *packet;
   const struct sockshost_t *src, *dst;
{
   const char *function = "socks_nbconnectroute()";
   struct sigaction currentsig, newsig;
   struct iovec iov[1];
   struct sockaddr_in local;
   struct msghdr msg;
   struct route_t *route;
   struct socksfd_t socksfd;
   struct childpacket_t childreq;
   socklen_t len;
   ssize_t p, fdsent;
   CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);
   int flags, isourhandler;

   slog(LOG_DEBUG, "%s: socket %d", function, s);

   if ((route = socks_getroute(&packet->req, src, dst)) == NULL)
      return NULL;

   if (route->gw.state.proxyprotocol.direct)
      return route; /* nothing more to do. */

   if (sigaction(SIGIO, NULL, &currentsig) != 0) {
      swarn("%s: sigaction(SIGIO)", function);
      return NULL;
   }

   if (currentsig.sa_flags & SA_SIGINFO) { /* sa_sigaction. */
      isourhandler = (currentsig.sa_sigaction == sigio); 

      if (!isourhandler) {
         if (currentsig.sa_sigaction == NULL) { /* OpenBSD threads weirdness. */
            slog(LOG_DEBUG, "%s: hmm, that's strange ... sa_flags set to 0x%x, "
                            "but sa_sigaction is NULL",
                            function, currentsig.sa_flags);
         }
         else
            slog(LOG_DEBUG, "%s: a SIGIO sa_sigaction is already installed, "
                            "but not ours ... wonder how this will work out",
                            function);
      }
   }
   else { /* sa_handler. */
      isourhandler = 0; /* we install with SA_SIGINFO. */

      if (currentsig.sa_handler != SIG_IGN
      &&  currentsig.sa_handler != SIG_DFL)
         slog(LOG_DEBUG, "%s: a handler is installed, but it's not ours ...",
         function);
      else
         slog(LOG_DEBUG, "%s: no SIGIO handler previously installed",
         function);
   }

   if (!isourhandler) {
      newsig               = currentsig; /* keep same as much as possible. */
      newsig.sa_sigaction  = sigio;
      newsig.sa_flags     |= SA_SIGINFO;

      slog(LOG_DEBUG, "%s: our signal handler is not installed, installing ...",
      function);

      originalsig = currentsig;

      if (sigaction(SIGIO, &newsig, NULL) != 0) {
         swarn("%s: sigaction(SIGIO)", function);
         return NULL;
      }
   }
   else
      slog(LOG_DEBUG, "%s: our signal handler already installed", function);

   if (sockscf.connectchild == 0) {
      /*
       * Create child process that will do our connections.
       */
      int datapipev[2], ackpipev[2];
      int valtoset, valchild, valmother;
      socklen_t optlen;

      /* Should have been SOCK_SEQPACKET, but that's not portable. :-( */
      if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, datapipev) != 0) {
         swarn("%s: socketpair(AF_LOCAL, SOCK_DGRAM)", function);
         return NULL;
      }
      else
         slog(LOG_DEBUG, "%s: socketpair(SOCK_DGRAM) returned %d, %d",
         function, datapipev[0], datapipev[1]);

      if (socketpair(AF_LOCAL, SOCK_STREAM, 0, ackpipev) != 0) {
         swarn("%s: socketpair(AF_LOCAL, SOCK_DGRAM)", function);
         return NULL;
      }
      else
         slog(LOG_DEBUG, "%s: socketpair(SOCK_STREAM) returned %d, %d",
         function, ackpipev[0], ackpipev[1]);

      if ((flags = fcntl(datapipev[0], F_GETFL, 0))                  == -1
      ||           fcntl(datapipev[0], F_SETFL, flags | O_NONBLOCK)  == -1
      ||           fcntl(datapipev[1], F_SETFL, flags | O_NONBLOCK)  == -1
      ||           fcntl(ackpipev[0],  F_SETFL, flags | O_NONBLOCK)  == -1
      ||           fcntl(ackpipev[1],  F_SETFL, flags | O_NONBLOCK)  == -1)
         swarn("%s: fcntl() failed to set pipe between mother and "
               "connect-child to non-blocking", function);

      valtoset = (sizeof(struct childpacket_t)
                  + sizeof(struct msghdr)
                  + CMSG_SPACE(sizeof(int) * FDPASS_MAX)
                  + SENDMSG_PADBYTES);
#if HAVE_GSSAPI
      valtoset += MAX_GSS_STATE + sizeof(struct iovec);
#endif /* HAVE_GSSAPI */

      /*
       * XXX
       * This is still not safe, since we can of course receive more than
       * MAXPACKETSQUEUED from mother.
       * Best way around this, lacking SOCK_SEQPACKET, is probably to make
       * the child support handling multiple simultaneous requests (connects)
       * so it can empty the queue faster than mother can fill it.
       */
      valtoset *= MAXPACKETSQUEUED;

      optlen   = sizeof(valtoset);
      if (setsockopt(datapipev[MOTHER], SOL_SOCKET, SO_SNDBUF, &valtoset,
      optlen) != 0
      || setsockopt(datapipev[CHILD],   SOL_SOCKET, SO_SNDBUF, &valtoset,
      optlen) != 0
      ||  setsockopt(datapipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &valtoset,
      optlen) != 0
      ||  setsockopt(datapipev[CHILD],  SOL_SOCKET, SO_RCVBUF, &valtoset,
      optlen) != 0) {
         swarn("%s: setsockopt(SO_SNDBUF/RCVBUF, %u)",
         function, (unsigned)valtoset);

         return NULL;
      }

      optlen = sizeof(valmother);
      if (getsockopt(datapipev[MOTHER], SOL_SOCKET, SO_SNDBUF, &valmother,
      &optlen) == -1
      || getsockopt(datapipev[CHILD],   SOL_SOCKET, SO_SNDBUF, &valchild,
      &optlen) == -1) {
         swarn("%s: getsockopt(SO_SNDBUF)", function);
         return NULL;
      }

      if (valmother < valtoset || valchild < valtoset) {
         swarnx("%s: could not set SNDBUF to %u and %u, is %u and %u",
         function, (unsigned)valtoset, (unsigned)valtoset,
         (unsigned)valmother, (unsigned)valchild);

         return NULL;
      }
      else
         slog(LOG_DEBUG, "%s: SNDBUF set to %u and %u, minimum was %u",
         function, (unsigned)valmother, (unsigned)valchild, (unsigned)valtoset);

      optlen = sizeof(valmother);
      if (getsockopt(datapipev[MOTHER], SOL_SOCKET, SO_RCVBUF, &valmother,
      &optlen) == -1
      ||  getsockopt(datapipev[CHILD],  SOL_SOCKET, SO_RCVBUF, &valchild,
      &optlen) == -1) {
         swarn("%s: getsockopt(SO_RCVBUF)", function);
         return NULL;
      }

      if (valmother < valtoset || valchild < valtoset) {
         swarnx("%s: could not set RCVBUF to %u and %u, is %u and %u",
         function, (unsigned)valtoset, (unsigned)valtoset,
         (unsigned)valmother, (unsigned)valmother);

         return NULL;
      }
      else
         slog(LOG_DEBUG, "%s: RCVBUF set to %u and %u",
         function, valmother, valchild);

      switch (sockscf.connectchild = fork()) {
         case -1:
            swarn("%s: fork()", function);
            return NULL;

         case 0: {
            struct sigaction sigact;
            struct itimerval timerval;
            size_t max, i;

            slog(LOG_DEBUG, "%s: connectchild forked", function);

            /* close unknown descriptors. */
            for (i = 0, max = getmaxofiles(softlimit); i < max; ++i)
               if (socks_logmatch((unsigned int)i, &sockscf.log)
               || i == (size_t)datapipev[CHILD]
               || i == (size_t)ackpipev[CHILD])
                  continue;
               else if (isatty(i))
                  continue;
               else
                  close(i);

            newprocinit();

            /*
             * in case of using msproxy stuff, don't want mothers stuff,
             * disable alarm timers.
             */

            bzero(&sigact, sizeof(sigact));
            sigact.sa_handler = SIG_DFL;
            if (sigaction(SIGALRM, &sigact, NULL) != 0)
               swarn("%s: sigaction()", function);

            timerval.it_value.tv_sec  = 0;
            timerval.it_value.tv_usec = 0;
            timerval.it_interval = timerval.it_value;

            if (setitimer(ITIMER_REAL, &timerval, NULL) != 0)
               swarn("%s: setitimer()", function);

            run_connectchild(datapipev[CHILD], ackpipev[CHILD]);
            /* NOTREACHED */
         }

         default:
            sockscf.child_data = datapipev[MOTHER];
            sockscf.child_ack  = ackpipev[MOTHER];

            close(datapipev[CHILD]);
            close(ackpipev[CHILD]);

            if (fcntl(sockscf.child_data, F_SETOWN, getpid()) == -1)
               serr(EXIT_FAILURE, "%s: fcntl(F_SETOWN)", function);

            if ((flags = fcntl(sockscf.child_data, F_GETFL, 0))    == -1
            ||  fcntl(sockscf.child_data, F_SETFL, flags | FASYNC) == -1)
               serr(EXIT_FAILURE, "%s: fcntl(F_SETFL, FASYNC)", function);
      }
   }

   switch (packet->req.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
      case PROXY_UPNP:
      case PROXY_HTTP_V1_0: {
         /*
          * Controlsocket is what later becomes datasocket.
          * We don't want to allow the client to read/write/select etc.
          * on the socket yet, since we need to read/write on it
          * ourselves to setup the connection to the socks server.
          *
          * We therefore create a new unconnected socket and assign
          * it the same descriptor number as the number the client uses.
          * This way, the clients select(2)/poll(2) will not mark the 
          * descriptor as ready for anything while we are working on it.
          *
          * When the connection has been set up, by the child, we duplicate
          * back the socket we were passed here and close the temporarily
          * created socket.
          */
         int tmp;
         struct sockaddr_in addr;

         SASSERTX(control == s);
         if ((control = socketoptdup(s)) == -1)
            return NULL;

#if HAVE_GSSAPI
         if (socks_allocbuffer(s) == NULL) {
            swarn("%s: socks_allocbuffer() failed", function);
            close(control);

            return NULL;
         }
#endif /* HAVE_GSSAPI */

         /*
          * The below bind(2) and listen(2) is necessary for
          * Linux not to mark the socket as readable/writable.
          * Under other unix systems, just a socket() is
          * enough.  Judging from the Open Unix spec., Linux
          * is the one that is correct though.
          */

         bzero(&addr, sizeof(addr));
         addr.sin_family      = AF_INET;
         addr.sin_addr.s_addr = htonl(INADDR_ANY);
         addr.sin_port        = htons(0);

         /* LINTED pointer casts may be troublesome */
         if (bind(control, (struct sockaddr *)&addr, sizeof(addr)) != 0
         ||  listen(control, 1) != 0) {
            close(control);
            return NULL;
         }

         if ((tmp = dup(s)) == -1) { /* dup2() will to close it. */
            close(control);
            return NULL;
         }

         if (dup2(control, s) == -1) { /* give the client a dummy socket. */
            close(control);
            return NULL;
         }
         close(control);

         control = tmp; /* and use the clients original socket to connect. */

         slog(LOG_DEBUG, "%s: socket to use for non-blocking connect: %d",
         function, control);

         /*
          * Now the status is:
          * s       - new (temporary) socket using original index of "s".
          * control -  original "s" socket, but using new descriptor index.
          */

         /* if used for something else before, free now. */
         socks_rmaddr(control, 1);
         break;
      }

      case PROXY_MSPROXY_V2:
         /*
          * Controlsocket is separate from datasocket.
          * Identical to our fixed sockssetup.
          */
         break;

      default:
         SERRX(packet->req.version);
   }

   bzero(&socksfd, sizeof(socksfd));
   if ((socksfd.route = socks_connectroute(control, packet, src, dst)) == NULL)
      return NULL;

   if (route->gw.state.proxyprotocol.direct)
      return route;

   /*
    * datasocket probably unbound.  If so we need to bind it so
    * we can get a (hopefully) unique local address for it.
    */

   len = sizeof(local);
   /* LINTED pointer casts may be troublesome */
   if (getsockname(s, (struct sockaddr *)&local, &len) != 0)
      return NULL;

   if (!PORTISBOUND(&local)) {
      bzero(&local, sizeof(local));

      /* bind same IP as control, any fixed address would do though. */

      len = sizeof(local);
      /* LINTED pointer casts may be troublesome */
      if (getsockname(control, (struct sockaddr *)&local, &len) != 0) {
         int new_control;

         socks_blacklist(socksfd.route);

         if ((new_control = socketoptdup(control)) == -1)
            return NULL;

         switch (packet->req.version) {
            case PROXY_SOCKS_V4:
            case PROXY_SOCKS_V5:
            case PROXY_HTTP_V1_0:
            case PROXY_UPNP:
               close(control); /* created in this function. */
               control = s;
               break;

            case PROXY_MSPROXY_V2:
            swarn("%s: connect failed", function);
               break;

            default:
               SERRX(packet->req.version);
         }

         if (dup2(new_control, control) != -1) {
            close(new_control);
            /* try again, hopefully there's a backup route. */
            return socks_nbconnectroute(s, control, packet, src, dst);
         }
         close(new_control);
         return NULL;
      }

      SASSERTX(PORTISBOUND(&local));
      local.sin_port = htons(0);

      /* LINTED pointer casts may be troublesome */
      if (bind(s, (struct sockaddr *)&local, sizeof(local)) != 0)
         return NULL;
   }

   len = sizeof(socksfd.local);
   if (getsockname(s, &socksfd.local, &len) != 0)
      SERR(s);

   /* this has to be done here or there would be a race against the signal. */
   socksfd.control             = control;
   socksfd.state.command       = packet->req.command;
   socksfd.state.version       = packet->req.version;
   socksfd.state.protocol.tcp  = 1;
   socksfd.state.inprogress    = 1;
   sockshost2sockaddr(&packet->req.host, &socksfd.forus.connected);

   socks_addaddr(s, &socksfd, 1);

   /*
    * send the request to our connectprocess and let it do the rest.
    * When it's done, we get a signal and dup "s" over "socksfd.control"
    * in the handler.
    */

   fdsent = 0;
   /* LINTED pointer casts may be troublesome */
   CMSG_ADDOBJECT(control, cmsg, sizeof(control) * fdsent++);

   switch (packet->req.version) {
      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
      case PROXY_HTTP_V1_0:
      case PROXY_UPNP:
         break;

      case PROXY_MSPROXY_V2:
         /* LINTED pointer casts may be troublesome */
         CMSG_ADDOBJECT(s, cmsg, sizeof(s) * fdsent++);
         break;

      default:
         SERRX(packet->req.version);
   }

   bzero(&childreq, sizeof(childreq)); /* silence valgrind warning */
   childreq.s       = s;
   childreq.src     = *src;
   childreq.dst     = *dst;
   childreq.packet  = *packet;

   iov[0].iov_base  = &childreq;
   iov[0].iov_len   = sizeof(childreq);
   len              = sizeof(childreq);

   bzero(&msg, sizeof(msg));
   msg.msg_iov      = iov;
   msg.msg_iovlen   = ELEMENTS(iov);
   msg.msg_name     = NULL;
   msg.msg_namelen  = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsent);

   slog(LOG_DEBUG, "%s: sending request of size %lu + %lu to connectchild, "
                   "%d requests previously outstanding", 
                   function, (unsigned long)len,
                   (unsigned long)CMSG_TOTLEN(msg), (int)reqoutstanding);

#if 0
   if (1) {
      static int sleept;

      if (!sleept) {
         sleep(20);
         sleept = 1;
      }
   }
#endif

   /*
    * must be before we send request to child, or child could finish
    * and signal us first.
    */
   errno = EINPROGRESS;

   if ((p = sendmsgn(sockscf.child_data, &msg, 0)) != (ssize_t)len) {
      swarn("%s: sendmsg(): %ld of %ld", function, (long)p, (long)len);
      return NULL;
   }

   ++reqoutstanding;
   return socksfd.route;
}

/*
 * XXX should have more code so we could handle multiple requests at
 * a time.
 */
static void
run_connectchild(mother_data, mother_ack)
   const int mother_data;
   const int mother_ack;
{
   const char *function = "run_connectchild()";
   fd_set *rset, *wset;
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   char string[MAXSOCKADDRSTRING];
   ssize_t p;
   int rbits;

   slog(LOG_DEBUG, "%s: data %d, ack %d", function, mother_data, mother_ack);

#if 0
   sleep(20);
#endif

   setproctitle("connectchild");

#if HAVE_GSSAPI
   gssapistate.value  = gssapistatemem;
   gssapistate.length = sizeof(gssapistatemem);
#endif /* HAVE_GSSAPI */

   rset = allocate_maxsize_fdset();
   wset = allocate_maxsize_fdset();

   /* CONSTCOND */
   while (1) {
      int flags;

      FD_ZERO(rset);
      FD_SET(mother_data, rset);
      FD_SET(mother_ack, rset);
      rbits = MAX(mother_data, mother_ack);

      ++rbits;
      switch (selectn(rbits, rset, NULL, NULL, NULL, NULL, NULL)) {
         case -1:
            SERR(-1);
            /* NOTREACHED */
      }

      if (FD_ISSET(mother_ack, rset)) {
         char buf[1];

         switch ((p = read(mother_ack, buf, sizeof(buf)))) {
            case -1:
               slog(LOG_DEBUG, "%s: read(): mother closed: %s",
               function, strerror(errno));
               _exit(EXIT_SUCCESS);
               /* NOTREACHED */

            case 0:
               slog(LOG_DEBUG, "%s: read(): mother closed", function);
               _exit(EXIT_SUCCESS);
               /* NOTREACHED */

            default:
               SERRX(p);
         }
      }

      if (FD_ISSET(mother_data, rset)) {
         /*
          * Mother sending us a connected (or in the process of being
          * connected) socket and necessary info to negotiate with
          * proxyserver.
          */
         struct childpacket_t req;
         struct iovec iov[2];
         socklen_t len;
         size_t tosend;
         struct sockaddr local, remote;
         struct msghdr msg;
         struct stat sb;
         int data, control, ioc, getpeernamefailed;

         CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);

         ioc = 0;
         bzero(iov, sizeof(iov));
         iov[ioc].iov_base = &req;
         iov[ioc].iov_len  = sizeof(req);
         len               = iov[ioc].iov_len;
         ++ioc;

         bzero(&msg, sizeof(msg));
         msg.msg_iov      = iov;
         msg.msg_iovlen   = ioc;
         msg.msg_name     = NULL;
         msg.msg_namelen  = 0;

         /* LINTED pointer casts may be troublesome */
         CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));
         if ((p = recvmsg(mother_data, &msg, 0)) != (ssize_t)len) {
            switch (p) {
               case -1:
                  serr(EXIT_FAILURE, "%s: recvmsg()", function);
                  /* NOTREACHED */

               case 0:
                  slog(LOG_DEBUG, "%s: recvmsg(): mother closed", function);
                  _exit(EXIT_SUCCESS);
                  /* NOTREACHED */

               default:
                  swarn("%s: recvmsg(): got %ld of %ld",
                  function, (long)p, (long)len);
            }

            continue;
         }

         slog(LOG_DEBUG, "%s: received request of size %ld + %lu from mother",
         function, (long)p, (unsigned long)CMSG_TOTLEN(msg));

         if (msg.msg_flags & MSG_TRUNC) {
            swarnx("%s: msg from mother was truncated ... request discarded",
            function);

            if (CMSG_TOTLEN(msg) > 0) 
               swarnx("%s: XXX should close received descriptors", function);

            continue; 
         }

         if (msg.msg_flags & MSG_CTRUNC) {
            swarnx("%s: cmsg from mother was truncated ... request discarded",
            function);

            continue; 
         }

         /* how many descriptors are we supposed to receive? */
         switch (req.packet.req.version) {
            case PROXY_MSPROXY_V2:
               len = 2;   /* control + socket for dataflow. */
               break;

            case PROXY_SOCKS_V4:
            case PROXY_SOCKS_V5:
            case PROXY_HTTP_V1_0:
            case PROXY_UPNP:
               len = 1; /* only controlsocket (which is also datasocket). */
               break;

            default:
               SERRX(req.packet.req.version);
         }


#if !HAVE_DEFECT_RECVMSG
         SASSERTX((size_t)CMSG_TOTLEN(msg)
         == (size_t)(CMSG_SPACE(sizeof(int) * len)));
#endif /* !HAVE_DEFECT_RECVMSG */

         len = 0;
         /* LINTED pointer casts may be troublesome */
         CMSG_GETOBJECT(control, cmsg, sizeof(control) * len++);

         switch (req.packet.req.version) {
            case PROXY_MSPROXY_V2:
               /* LINTED pointer casts may be troublesome */
               CMSG_GETOBJECT(data, cmsg, sizeof(data) * len++);
               break;

            case PROXY_SOCKS_V4:
            case PROXY_SOCKS_V5:
            case PROXY_HTTP_V1_0:
            case PROXY_UPNP:
               data = control;   /* datachannel is controlchannel. */
               break;

            default:
               SERRX(req.packet.req.version);
         }

         slog(LOG_DEBUG, "%s: controlsocket %d, datasocket %d",
         function, control, data);

         /*
          * default, in case we don't even get a valid response.
          */
         req.packet.res.reply
         = sockscode(req.packet.req.version, SOCKS_FAILURE);
         req.packet.res.version = req.packet.req.version;

         if (req.packet.req.version == PROXY_SOCKS_V4)
            req.packet.res.version = PROXY_SOCKS_V4REPLY_VERSION;
         else
            req.packet.res.version = req.packet.req.version;

         req.packet.req.auth         = &req.packet.state.auth;
         req.packet.req.auth->method = AUTHMETHOD_NOTSET;

         len = sizeof(local);
         if (getsockname(control, &local, &len) == 0)
            slog(LOG_DEBUG, "%s: control local: %s",
            function, sockaddr2string(&local, string, sizeof(string)));
         else
            swarn("%s: getsockname(%d)", function, control);

         len = sizeof(remote);
         if (getpeername(control, &remote, &len) == 0) {
            slog(LOG_DEBUG, "%s: control remote: %s",
            function, sockaddr2string(&remote, string, sizeof(string)));
         
            /*
             * On Solaris 5.11, it seems to be possible for a socket,
             * used for a non-blocking connect, to fail to become 
             * writable if the connect fails.  On our test-machine,
             * this seems to happen about 1 in 2000 times.  Don't know why
             * it happens, but is probably a kernel bug.
             *
             * Hopefully it's enough of a workaround to not do select(2) if
             * the getpeername(2) call failed.
             * getpeername(1, 0x080333E0, 0x0803340C, SOV_DEFAULT)
             *            Err#134 ENOTCONN
             * fcntl(1, F_SETFL, FWRITE)                       = 0
             * pollsys(0x08033220, 1, 0x00000000, 0x00000000) (sleeping...)
             *         fd=1  ev=POLLOUT rev=0
             * <never returns>
             */

            /*
             * we're not interested the extra hassle of negotiating over
             * a non-blocking socket, so set it to blocking while we
             * use it.
             */
            if ((flags = fcntl(control, F_GETFL, 0))                  == -1
            ||           fcntl(control, F_SETFL, flags & ~O_NONBLOCK) == -1)
               swarn("%s: fcntl(control)", function);

            slog(LOG_DEBUG, "%s: waiting for connect response ...", function);

            FD_ZERO(wset);
            FD_SET(control, wset);
            switch (selectn(control + 1, NULL, NULL, wset, NULL, NULL, NULL)) {
               case -1:
                  SERR(-1);
                  /* NOTREACHED */

               case 0:
                  SERRX(0);
                  /* NOTREACHED */
            }
         }
         else
            flags = -1;

         /*
          * sigh, for some reason, atleast some versions of Linux
          * return 0 for a read(control, NULL, 0), even if the connect(2)
          * failed, and the error does not become apparent til later,
          * on e.g. the first write(2).  Unfortunately, that write(2) also
          * resets SO_ERROR, which means that applications checking SO_ERROR
          * to see if the connect failed won't work, and while 
          * recv(control, buf, 1, MSG_PEEK) works on linux, it too resets
          * SO_ERROR.
          *
          * Getpeername(2) seems to work correctly on linux also, but
          * that doesn't tell us why the connect failed.  Would be nice
          * to have a way that worked on linux also, but alas. :-/
          */

         len = sizeof(local);
         if (getsockname(control, &local, &len) != 0) {
            slog(LOG_DEBUG, "%s: getsockname(control) failed: %s",
            function, strerror(errno));

            /*
             * this is pretty bad, but it could happen unfortunately.
             */
            bzero(&local, sizeof(local));
            local.sa_family               = AF_INET;
            TOIN(&local)->sin_addr.s_addr = htonl(INADDR_ANY);
            TOIN(&local)->sin_port        = htons(0);
         }
         sockaddr2sockshost(&local, &req.src);

         errno = 0;
         len = sizeof(remote);
         if (getpeername(control, &remote, &len) != 0) {
            getpeernamefailed = 1;
            slog(LOG_DEBUG, "%s: getpeername(control) failed: %s",
            function, strerror(errno));
         }
         else
            getpeernamefailed = 0;

         req.packet.state.err = errno;

         slog(LOG_DEBUG, "%s: checking result ... connect %s",
         function, req.packet.state.err == 0 ? "succeeded" : "failed");

         if (req.packet.state.err == 0) { /* connected ok. */
            if (socks_negotiate(data, control, &req.packet, NULL) != 0) {
               slog(LOG_DEBUG, "%s: socks_negotiate() failed", function);
               req.packet.state.err = errno;
            }
            else {
               slog(LOG_DEBUG, "%s: socks_negotiate() succeeded", function);
               req.packet.state.err = 0;
            }
         }

         /* back to original. */
         if (flags != -1)
            if (fcntl(control, F_SETFL, flags) == -1)
               swarn("%s: fcntl(control)", function);

         ioc = 0;
         bzero(iov, sizeof(iov));

         iov[ioc].iov_base  = &req;
         iov[ioc].iov_len   = sizeof(req);
         tosend             = iov[ioc].iov_len;
         ++ioc;

#if HAVE_GSSAPI
         if (req.packet.state.err == 0
         &&  req.packet.state.auth.method == AUTHMETHOD_GSSAPI) {
            gssapi_export_state(&req.packet.state.auth.mdata.gssapi.state.id,
            &gssapistate);

            iov[ioc].iov_base  = gssapistate.value;
            iov[ioc].iov_len   = gssapistate.length;
            tosend            += iov[ioc].iov_len;
            ++ioc;

            slog(LOG_DEBUG, "%s: exporting gssapistate of size %lu",
            function, (long unsigned)gssapistate.length);
         }
#endif /* HAVE_GSSAPI */

         bzero(&msg, sizeof(msg));
         msg.msg_iov      = iov;
         msg.msg_iovlen   = ioc;
         msg.msg_name     = NULL;
         msg.msg_namelen  = 0;

         /*
          * Need to do getpeername again, and send zero for the
          * remote addr if we no longer have a peer, as things
          * may have changed during negotiation, and mother
          * needs to know whether there is a peer or not.
          */
         len = sizeof(remote);
         if (getpeernamefailed
         || getpeername(control, &remote, &len) != 0) {
            if (!getpeernamefailed)
               slog(LOG_DEBUG, "%s: getpeername(control) failed: %s",
               function, strerror(errno));

            bzero(&remote, sizeof(remote));
            remote.sa_family               = AF_INET;
            TOIN(&remote)->sin_addr.s_addr = htonl(INADDR_ANY);
            TOIN(&remote)->sin_port        = htons(0);
         }
         sockaddr2sockshost(&remote, &req.dst);

         if (fstat(control, &sb) == 0) {
            if (sb.st_ino == 0) {
               /* assume 0 means the kernel does not support socket inodes. */
               req.device = (dev_t)-1;
               req.inode  = (ino_t)-1;
            }
            else {
               req.device = sb.st_dev;
               req.inode  = sb.st_ino;
            }
         }
         else {
            swarn("%s: fstat() failed", function);
            req.inode = (ino_t)-1;
         }

         slog(LOG_DEBUG, "%s: sending response, size %ld, socket %d, "
                         "inode %lu, to mother",
                         function, (long)tosend, req.s,
                         (unsigned long)req.inode);

         if ((p = sendmsgn(mother_data, &msg, 0)) != (ssize_t)tosend)
            serr(EXIT_FAILURE, "%s: sendmsg() to mother failed: %ld out of %ld",
            function, (long)p, (long)len);

         close(control);
         if (data != control)
            close(data);
      }
   }
}

static void
sigio(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "sigio()";
   const int errno_s = errno;
   struct socksfd_t socksfd;
   struct childpacket_t childres;
   struct sockaddr localmem, *local = &localmem;
   struct sockaddr remotemem, *remote = &remotemem;
   struct msghdr msg;
   struct iovec iov[2];
   socklen_t len;
   ssize_t p;
   char string[MAX(MAXSOCKADDRSTRING, MAXSOCKSHOSTSTRING)];
   int s, gotapacket, ioc;
#if HAVE_GSSAPI
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */

#ifdef HAVE_LINUX_BUGS
   /*
    * Don't know how, but on linux, it seems possible for this to
    * happen:
    *
    * #29 <signal handler called>
    * ...
    * #21 0x0000003de487cb1b in _L_lock_9857 () at hooks.c:126
    * #20 __lll_lock_wait_private ()
    *  at ../nptl/sysdeps/unix/sysv/linux/x86_64/lowlevellock.S:97
    * #19 <signal handler called>
    */
   if (sockscf.state.insignal) {
      slog(LOG_DEBUG, "%s: this shouldn't happen ..."
                      "in signal %d, and got signal %d",
                      function, sockscf.state.insignal, sig);

      return;
   }
#else
   SASSERTX(!sockscf.state.insignal);
#endif /* HAVE_LINUX_BUGS */

   sockscf.state.insignal = sig;

   slog(LOG_DEBUG, "%s: got signal, requests outstanding: %d",
   function, (int)reqoutstanding);

   if (originalsig.sa_flags & SA_SIGINFO
   &&  originalsig.sa_sigaction != NULL) {
      slog(LOG_DEBUG, "%s: calling original sa_sigaction()", function);
      originalsig.sa_sigaction(sig, sip, scp);
   }
   else {
      if (originalsig.sa_handler != SIG_IGN
      &&  originalsig.sa_handler != SIG_DFL) {
         slog(LOG_DEBUG, "%s: calling original sa_handler()", function);
         originalsig.sa_handler(sig);
      }
   }

   if (sockscf.connectchild == 0) {
      sockscf.state.insignal = 0;
      return;
   }

   bzero(iov, sizeof(iov));
   ioc = 0;

   iov[ioc].iov_base = &childres;
   iov[ioc].iov_len  = sizeof(childres);
   ++ioc;

#if HAVE_GSSAPI
   iov[ioc].iov_base = gssapistatemem;
   iov[ioc].iov_len  = sizeof(gssapistatemem);
   ++ioc;
#endif /* HAVE_GSSAPI */

   bzero(&msg, sizeof(msg));
   msg.msg_iov      = iov;
   msg.msg_iovlen   = ioc;
   msg.msg_name     = NULL;
   msg.msg_namelen  = 0;

   slog(LOG_DEBUG, "%s: trying to receive msg from child ...", function);

   gotapacket = 0;
   while ((p = recvmsg(sockscf.child_data, &msg, MSG_DONTWAIT))
   >= (ssize_t)sizeof(childres)) {
      gotapacket = 1;
      --reqoutstanding;

      slog(LOG_DEBUG, "%s: received msg of size %ld from child, "
                      "%d requests now outstanding",
                      function, (long)p, (int)reqoutstanding);

      p -= sizeof(childres);

      childres.packet.req.auth = childres.packet.res.auth
      = &childres.packet.state.auth;

      slog(LOG_DEBUG, "%s: auth method child negotiated is %d",
      function, childres.packet.res.auth->method);

      sockshost2sockaddr(&childres.src, local);
      sockshost2sockaddr(&childres.dst, remote);

      slog(LOG_DEBUG, "%s: local = %s",
      function, sockaddr2string(local, string, sizeof(string)));

      slog(LOG_DEBUG, "%s: remote = %s",
      function, sockaddr2string(remote, string, sizeof(string)));

      if (!ADDRISBOUND(TOIN(local)) && !PORTISBOUND(TOIN(local)))
         swarnx("%s: running Solaris, are we?  It lookks like the socket used "
                "for the non-blocking connect no longer has a local name.  "
                "It's quite possible the client will hang now",
                function);

      if (!ADDRISBOUND(TOIN(remote)) && !PORTISBOUND(TOIN(remote))) {
         slog(LOG_DEBUG, "%s: remote address not bound, setup must have failed",
         function);
         remote = NULL;
      }

      if ((s = socks_addrcontrol(local, remote, childres.s, childres.device,
      childres.inode, 1)) == -1) {
         slog(LOG_DEBUG, "%s: socks_addrcontrol() failed, assuming socket %d/"
                         "inode %lu has been recycled for other things",
                         function, childres.s, (unsigned long)childres.inode);

         break;
      }

      slog(LOG_DEBUG, "%s: packet belongs to socket %d", function, s);

      if (socks_getaddr(s, 1) == NULL) {
         swarnx("%s: could not getaddr %d", function, s);
         break;
      }
      socksfd = *socks_getaddr(s, 1);

      switch (socksfd.state.version) {
         case PROXY_MSPROXY_V2:
            break; /* nothing to do, control separate from data. */

         case PROXY_SOCKS_V4:
         case PROXY_SOCKS_V5:
         case PROXY_HTTP_V1_0:
         case PROXY_UPNP:
            if (socksfd.control == s) {
               slog(LOG_DEBUG, "%s: duping %d over %d not needed",
               function, socksfd.control, s);

               break;
            }

            slog(LOG_DEBUG, "%s: duping %d over %d",
            function, socksfd.control, s);

            if (dup2(socksfd.control, s) == -1) {
               swarn("%s: dup2(%d, %d)", function, socksfd.control, s);
               SASSERT(errno != EBADF);

               socksfd.state.err = errno;
               socks_addaddr(s, &socksfd, 1);
               break;
            }

            close(socksfd.control);
            socksfd.control = s;
            socks_addaddr(s, &socksfd, 1);
            break;

         default:
            SERRX(socksfd.state.version);
      }

      /*
       * it's possible endpoint changed/got fixed.  Update in case.
       */

      len = sizeof(socksfd.local);
      if (getsockname(s, &socksfd.local, &len) != 0) {
         slog(LOG_INFO, "%s: getsockname() failed (%s), assuming client has "
                          "closed the socket and removing socksfd",
                          function, strerror(errno));
         socks_rmaddr(s, 1);
         continue;
      }
      else
         slog(LOG_DEBUG, "%s: socksfd.local: %s",
         function, sockaddr2string(&socksfd.local, string, sizeof(string)));

      len = sizeof(socksfd.server);
      if (getpeername(s, &socksfd.server, &len) != 0)
         swarn("%s: getpeername(s)", function);

      socksfd.state.inprogress = 0;

      socks_addaddr(s, &socksfd, 1);

      if (!serverreplyisok(childres.packet.res.version,
      childres.packet.res.reply, socksfd.route)) {
         slog(LOG_DEBUG, "%s: connectchild failed to set up connection, "
                         "error mapped to %d",
                         function, errno);

         socksfd.state.err = errno;
         socks_addaddr(s, &socksfd, 1);

         /*
          * XXX If it's a server error it would be nice to retry, could
          * be there's a backup route.
          */

#if DIAGNOSTIC
         SASSERTX(socks_addrisours(s, 1));
#endif /* DIAGNOSTIC */

         break;
      }

      slog(LOG_DEBUG, "server reply is ok, server will use as src: %s",
      sockshost2string(&childres.packet.res.host, string, sizeof(string)));

      socksfd.state.auth         = *childres.packet.res.auth;
      socksfd.state.msproxy      = childres.packet.state.msproxy;
      sockshost2sockaddr(&childres.packet.res.host, &socksfd.remote);

#if HAVE_GSSAPI
      if (socksfd.state.auth.method == AUTHMETHOD_GSSAPI) {
         iobuffer_t *iobuf;

         SASSERTX(p > 0);

         /* 
          * can't import gssapi state here; we're in a signal handler and 
          * that is not safe.  Will be imported upon first call to
          * socks_getaddr() later, so save it in iobuf for now, as 
          * nobody should be using that before call to socks_getaddr().
          *
          * Would be cleaner to have the memory in socksfd, but it's a
          * big buffer, and only needed once, so do it like this for now.
          */
         slog(LOG_DEBUG, "%s: read gssapistate of size %ld, will store it in "
                         "iobuffer for socket %d",
                         function, (long)p, s);

         SASSERTX((iobuf = socks_getbuffer(s)) != NULL);
         SASSERTX(iobuf->info[0].len == 0 && iobuf->info[0].enclen == 0);
         SASSERTX(iobuf->info[1].len == 0 && iobuf->info[1].enclen == 0);
         SASSERTX(sizeof(iobuf->buf) >= sizeof(gssapistatemem));

         socksfd.state.gssimportneeded    = 1;
         socksfd.state.gssapistate.value  = iobuf->buf;
         socksfd.state.gssapistate.length = p;
         memcpy(socksfd.state.gssapistate.value, gssapistatemem, p);
      }
#endif /* HAVE_GSSAPI */

      socks_addaddr(s, &socksfd, 1);

      /* needed for standard socks bind. */
      sockscf.state.lastconnect = socksfd.forus.connected;

#if 0
      {
      static int init;

      if (!init) {
         slog(LOG_DEBUG, "%s: XXX sleeping", function);
         init = 1;
         sleep(20);
      }
      }
#endif
   }

   if ((sip->si_pid == sockscf.connectchild || sip->si_pid == 0)
   && !gotapacket)
      swarn("%s: received %ld bytes from child, expected a minimum of %lu",
      function, (long)p, (unsigned long)sizeof(childres));

   errno = errno_s;
   sockscf.state.insignal = 0;
}
