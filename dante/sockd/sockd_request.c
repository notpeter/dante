/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011, 2012
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
"$Id: sockd_request.c,v 1.574 2012/06/01 20:23:06 karls Exp $";

/*
 * XXX Should fix things so this process too can support multiple clients.
 * Will also fix the terrible fact that we just sit around and wait if the
 * command is bind, wasting the whole process on practically nothing.
 */


/* start of siginfo struct for requestchild.  Just the basics for now. */
static struct {
   struct sockaddr_storage   client;     /* clients address.                          */
   time_t            starttime;  /* time client was received.                 */
} reqv[1];
static const size_t reqc = ELEMENTS(reqv);



static void siginfo(int sig, siginfo_t *sip, void *scp);

static void
convertresponse(const response_t *oldres, response_t *newres,
                const int newversion);
/*
 * Converts a response on form "oldres", using oldres->version,
 * to a new response on form "newversion".
 */

static int
dorequest(const sockd_mother_t *mother, sockd_request_t *request);
/*
 * When a complete request has been read, this function can be
 * called.  It will perform the request "request->req" and send the
 * result to "mother".
 * Returns:
 *    If request was successfully completed: 0.
 *    If request was blocked or there was an error: -1.
 */

static void
flushio(int mother, sockd_io_t *io);
/*
 * "flushes" a complete io object and free's any state/resources held by it.
 * Also iolog()s that the session was accepted.
 * "mother" is connection to mother for sending the io.
 * "io" is the io object to send to mother.
 */

static void
proctitleupdate(const struct sockaddr *from);
/*
 * Updates the title of this process.
 */

static int
serverchain(int s, const request_t *req, response_t *res,
            sockd_io_direction_t *src, sockd_io_direction_t *dst,
            int *proxyprotocol, proxychaininfo_t *proxychain);
/*
 * Checks if we should create a serverchain on socket "s" for the request
 * "req".  If a serverchain was created, the proxyprotocol used in that
 * chain is set in "proxyprotocol", and further information is provided
 * in "proxychain".  Otherwise, proxyprotocol is set to PROXY_DIRECT.

 * Returns:
 *       0: Serverchain established successfully.
 *      -1: No serverchain established.  If errno set, it indicates the reason.
 *          If errno is not set, no route exists to handle this connection,
 *          and it should be direct.
 */


#if SOCKS_SERVER
static sockd_io_t *
io_add(sockd_io_t *iolist, const sockd_io_t *newio);
/*
 * Adds _a copy_ of the object "newio" to the list "iolist".
 * Returns a pointer to the (new) iolist.
 */

static sockd_io_t *
io_remove(sockd_io_t *iolist, sockd_io_t *rmio);
/*
 * Removes the object "rmio" from the list "iolist".
 * Returns a pointer to the (new) iolist.
 */

static sockd_io_t *
io_find(sockd_io_t *iolist, const struct sockaddr *addr);
/*
 * Scans "iolist" for a object that contains "addr" as a local address.
 * If "addr" is NULL, returns "iolist".
 * Returns:
 *      On success: pointer to the matching io object.
 *      On failure: NULL.
 */
#endif /* SOCKS_SERVER */


void
run_request()
{
   const char *function = "run_request()";
   sockd_request_t req;
   struct sigaction sigact;
   fd_set *rset;

   bzero(&sigact, sizeof(sigact));
   sigact.sa_flags     = SA_RESTART | SA_SIGINFO;
   sigact.sa_sigaction = siginfo;

#if HAVE_SIGNAL_SIGINFO
   if (sigaction(SIGINFO, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);
#endif /* HAVE_SIGNAL_SIGINFO */

   /* same handler, for systems without SIGINFO. */
   if (sigaction(SIGUSR1, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);

   rset  = allocate_maxsize_fdset();
   req.s = -1;

   sockd_print_child_ready_message((size_t)freedescriptors(NULL));

   while (1) {
      /*
       * Get request from mother, perform it, get next request.
       */
#if DIAGNOSTIC
      const int freec = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif /* DIAGNOSTIC */
      int fdbits;
      char command;

      errno = 0; /* reset for each iteration. */

      proctitleupdate(NULL);
      SET_SOCKADDR(TOSA(&reqv[0].client), AF_UNSPEC);

      FD_ZERO(rset);
      FD_SET(sockscf.state.mother.s, rset);
      fdbits = sockscf.state.mother.s;

      /* checked so we know if mother goes away.  */
      FD_SET(sockscf.state.mother.ack, rset);
      fdbits = MAX(fdbits, sockscf.state.mother.ack);

      ++fdbits;
      switch (selectn(fdbits, rset, NULL, NULL, NULL, NULL, NULL)) {
         case -1:
            if (errno == EINTR)
               continue;

            SERR(-1);
            /* NOTREACHED */

         case 0:
            SERRX(0);
      }

      if (FD_ISSET(sockscf.state.mother.ack, rset)) {
         slog(LOG_DEBUG,
              "%s: mother closed it's connection to us.  We should exit.",
              function);

         sockdexit(EXIT_FAILURE);
      }

      if (FD_ISSET(sockscf.state.mother.s, rset)) {
         if (recv_req(sockscf.state.mother.s, &req) == -1) {
            slog(LOG_DEBUG, "%s: recv_req() from mother failed: %s",
            function, strerror(errno));

             continue;
          }
      }

#if !BAREFOOTD /* doesn't need buffer in the request process. */
      socks_allocbuffer(req.s, SOCK_STREAM);
#endif /* BAREFOOTD */

      if (dorequest(&sockscf.state.mother, &req) == -1) {
         /*
          * log the client-rule and hostid-rule close also if appropriate,
          * as this will not be logged on the normal session-close in the i/o
          * process because the session was not successfully established.
          */
         iologaddr_t src;

         slog(LOG_DEBUG, "%s: dorequest() failed", function);

         init_iologaddr(&src,
                        SOCKADDR_OBJECT,
                        &req.to,
                        SOCKADDR_OBJECT,
                        &req.from,
                        &req.clientauth,
                        GET_HOSTIDV(&req.state),
                        GET_HOSTIDC(&req.state));

#if HAVE_SOCKS_HOSTID
         if (req.hostidrule_isset) {
            req.state.command = SOCKS_HOSTID;
            iolog(&req.hostidrule,
                  &req.state,
                  OPERATION_DISCONNECT,
                  &src,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  0);
         }
#endif /* HAVE_SOCKS_HOSTID */

         req.state.command = SOCKS_ACCEPT;
         iolog(&req.rule,
               &req.state,
               OPERATION_DISCONNECT,
               &src,
               NULL,
               NULL,
               NULL,
               NULL,
               0);

         switch (req.state.protocol) {
            case SOCKS_TCP:
               command = SOCKD_FREESLOT_TCP;
               break;

            case SOCKS_UDP:
               command = SOCKD_FREESLOT_UDP;
               break;

            default:
               SERRX(req.state.protocol);
         }

         if (socks_sendton(sockscf.state.mother.ack,
                           &command,
                           sizeof(command),
                           sizeof(command),
                           0,
                           NULL,
                           0,
                           NULL) != sizeof(command))
            serr(EXIT_FAILURE, "%s: sending ack to mother failed", function);
      }

#if !BAREFOOTD /* Barefoot doesn't need buffer in the request process. */
      socks_freebuffer(req.s);
#endif /* BAREFOOTD */

#if DIAGNOSTIC
      if (freec != freedescriptors(sockscf.option.debug ?  "end" : NULL))
         swarnx("%s: lost %d file descriptor%s",
                function, freec - freedescriptors(NULL),
                (freec - freedescriptors(NULL)) == 1 ? "" : "s");
#endif /* DIAGNOSTIC */
   }
}

int
recv_req(s, req)
   int s;
   sockd_request_t *req;
{
   const char *function = "recv_req()";
#if HAVE_GSSAPI
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   struct iovec iov[2];
   struct msghdr msg;
   struct timeval tnow;
   int ioc, fdexpect, fdreceived, r;
   CMSG_AALLOC(cmsg, sizeof(int));

#if BAREFOOTD
   if (!sockscf.state.alludpbounced && pidismother(sockscf.state.pid) == 1) {
      /*
       * We're the main mother.  Go through all client-rules
       * that have a bounce-to address that requires us to
       * listen to udp addresses, and fake a request for it,
       * without going through the negotiate child (there is
       * nothing to negotiate).
       */
      rule_t *rule;
      int foundtobounce = 0;

      bzero(req, sizeof(*req));

      for (rule = sockscf.srule; rule != NULL; rule = rule->next) {
         /*
          * We autogenerate the second-level socks-rule acl for udp
          * client-rules.
          */
         sockshost_t host;
         struct sockaddr_storage addr;

         if (!rule->state.protocol.udp || rule->crule->bounced)
            continue;

         sockshost2sockaddr(ruleaddr2sockshost(&rule->crule->dst, &host,
                            SOCKS_UDP),
                            TOSA(&addr));

         if (!ADDRISBOUND(TOIN(&addr)))
            serrx(EXIT_FAILURE, "%s: can not resolve %s",
            function, sockshost2string(&host, NULL, 0));

         if (++foundtobounce > 1) {
            slog(LOG_DEBUG, "%s: more addresses to bounce, next one is "
                            "rule #%lu",
                            function, (unsigned long)rule->number);
            break;
         }

         req->to = addr;

         slog(LOG_DEBUG, "%s: creating new udp session for dst %s in rule #%lu",
                         function,
                         sockaddr2string(TOSA(&req->to), NULL, 0),
                         (unsigned long)rule->number);

         sockshost2sockaddr(ruleaddr2sockshost(&rule->src, &host, SOCKS_UDP),
         TOSA(&req->from));

         req->rule                      = *rule->crule;

         req->clientauth.method         = AUTHMETHOD_NONE;
         req->socksauth.method          = AUTHMETHOD_NONE;
         req->s                         = -1;

         req->state.command             = SOCKS_ACCEPT;
         req->state.clientprotocol      = SOCKS_UDP;
         req->state.protocol            = SOCKS_UDP;

         req->req.version               = PROXY_SOCKS_V5;
         req->req.command               = SOCKS_UDPASSOCIATE;
         req->req.flag                  = 0;
         req->req.host.atype            = SOCKS_ADDR_IPV4;
         req->req.host.addr.ipv4.s_addr = htonl(INADDR_ANY);
         req->req.host.port             = htons(0);
         req->req.auth                  = &req->socksauth;
         req->req.protocol              = SOCKS_UDP;

         /*
          * no negotiation going on here; what we want is what we get.
          */
         req->state.command = req->req.command;
         req->state.version = req->req.version;

         gettimeofday(&req->state.time.accepted, NULL);
         req->state.time.negotiatestart = req->state.time.accepted;
         req->state.time.negotiateend   = req->state.time.accepted;
         req->state.time.established    = req->state.time.accepted;

         rule->crule->bounced = 1;

         /* don't break out yet; check if this was the last rule to bounce. */
      }

      if (foundtobounce <= 1) {
         slog(LOG_DEBUG, "%s: no more addresses to bounce", function);
         sockscf.state.alludpbounced = 1;
      }

      SASSERTX(req->s == -1);
      return 0;
   }
#endif /* BAREFOOTD */

   ioc = 0;
   bzero(iov, sizeof(iov));
   iov[ioc].iov_base = req;
   iov[ioc].iov_len  = sizeof(*req);
   ++ioc;

#if HAVE_GSSAPI
   iov[ioc].iov_base = gssapistatemem;
   iov[ioc].iov_len  = sizeof(gssapistatemem);
   ++ioc;
#endif /* HAVE_GSSAPI */

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ioc;
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

   if ((r = recvmsgn(s, &msg, 0)) < (ssize_t)sizeof(*req)) {
      switch (r) {
         case -1:
            slog(LOG_DEBUG, "%s: recvmsg() failed: %s",
            function, strerror(errno));
            break;

         case 0:
            slog(LOG_DEBUG, "%s: recvmsg(): other side closed connection",
            function);
            break;

         default:
            swarnx("%s: recvmsg(): unexpected short read: %d/%lu",
            function, r, (unsigned long)sizeof(*req));
      }

      return -1;
   }

   if (socks_msghaserrors(function, &msg))
      return -1;

   gettimeofday(&tnow, NULL);
   sockd_isoverloaded("client object received from negotiate process",
                      &req->state.time.negotiateend,
                      &tnow,
                      &tnow);

   SASSERTX(req->rule.bw == NULL);
   SASSERTX(req->rule.ss == NULL);

#if BAREFOOTD
   if (req->req.command == SOCKS_UDPASSOCIATE)
      fdexpect = 0; /* no client yet. */
   else
      fdexpect = 1; /* client. */
#else /* SOCKS_SERVER */
   fdexpect = 1; /* client. */
#endif /* SOCKS_SERVER */

   if (!CMSG_RCPTLEN_ISOK(msg, sizeof(int) * fdexpect)) {
      swarnx("%s: received control message has the invalid len of %d",
              function, (int)CMSG_TOTLEN(msg));

      return -1;
   }

   SHMEM_CLEAR(&req->rule, 0);
#if COVENANT
   SHMEM_CLEAR(&req->srule, 0);
#endif

   fdreceived = 0;
   if (fdexpect > 0) {
      SASSERTX(cmsg->cmsg_level == SOL_SOCKET);
      SASSERTX(cmsg->cmsg_type  == SCM_RIGHTS);

      SASSERTX(fdexpect == 1);
      CMSG_GETOBJECT(req->s, cmsg, sizeof(req->s) * fdreceived++);

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: received socket %d (%s) ...",
         function, req->s, socket2string(req->s, NULL, 0));
   }

   req->req.auth = &req->socksauth; /* pointer fixup */

#if HAVE_GSSAPI
   if (req->req.auth->method == AUTHMETHOD_GSSAPI) {
      gss_buffer_desc gssapistate;

      r -= sizeof(*req);
      SASSERTX(r > 0);

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: read gssapistate of size %d", function, r);

      gssapistate.value  = gssapistatemem;
      gssapistate.length = r;

      if (gssapi_import_state(&req->req.auth->mdata.gssapi.state.id,
      &gssapistate) != 0)
         return -1;
   }
#endif /* HAVE_GSSAPI */

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: received %d descriptors for request with method %d, "
                      "req->s = %d",
                      function, fdreceived, req->req.auth->method, s);

   return 0;
}

static int
dorequest(mother, request)
   const sockd_mother_t *mother;
   sockd_request_t *request;
{
   const char *function = "dorequest()";
   struct sockaddr_storage bound;
   sockd_io_t io;
   response_t response;
   iologaddr_t src, dst;
#if SOCKS_SERVER
   sockshost_t expectedbindreply, bindreplydst;
#endif /* SOCKS_SERVER */
#if HAVE_SOCKS_RULES
   int permit;
#endif /* HAVE_SOCKS_RULES */
   char strhost[MAXSOCKSHOSTSTRING], msg[256] = { NUL };
   int p, out, rc;

   if (sockscf.option.debug)
      slog(LOG_DEBUG,
           "request received, %s -> %s, authmethod: %s, %s, "
           "bw_shmid: %ld (%p), ss_shmid: %ld (%p)",
           sockaddr2string(TOSA(&request->from), strhost, sizeof(strhost)),
           sockaddr2string(TOSA(&request->to), NULL, 0),
           method2string(request->req.auth->method),
           socks_packet2string(&request->req, 1),
           request->rule.bw_shmid, request->rule.bw,
           request->rule.ss_shmid, request->rule.ss);

   proctitleupdate(TOSA(&request->from));
   time(&reqv[0].starttime);
   reqv[0].client = request->from;

   bzero(&response, sizeof(response));
   response.host   = request->req.host;
   response.auth   = request->req.auth;

   bzero(&io, sizeof(io));

#if BAREFOOTD
   io.control.s    = -1;
#endif /* BAREFOOTD */
   io.reqflags     = request->req.flags;
   io.state        = request->state;

   io.crule        = request->rule;
#if HAVE_SOCKS_HOSTID
   io.hostidrule       = request->hostidrule;
   io.hostidrule_isset = request->hostidrule_isset;
#endif /* HAVE_SOCKS_HOSTID */

   io.clientauth   = request->clientauth;

   /*
    * Assign crule to rule for now, so we can call iolog() before
    * rulespermit() on errors.
    */
   io.rule = io.crule;

   /*
    * But not shmem stuff, that needs to be handled specially; inherited
    * in TWO_LEVEL_ACL case, or remain in the client-rule otherwise.
    */
   SHMEM_CLEAR(&io.rule, 1);

#if !HAVE_SOCKS_RULES
   /*
    * Will not do a socks-rule lookup, except in the udp case, but even that
    * is not done til we get to the i/o phase.  Need to have something
    * to use until then though, to avoid a plethora of #ifdef's.
    */
   io.rule.crule = &io.crule;
#endif /* !HAVE_SOCKS_RULES */

#if HAVE_NEGOTIATE_PHASE
   SASSERTX(sizeof(io.clientdata) == sizeof(request->clientdata));
   io.clientdatalen = request->clientdatalen;
   memcpy(io.clientdata, request->clientdata, io.clientdatalen);
#endif /* HAVE_NEGOTIATE_PHASE */

#if SOCKS_SERVER
   io.rule.verdict = VERDICT_BLOCK;
   io.rule.number  = 0;
   if (io.crule.log.error)
      /* if we log before rulespermit() it's due to an error. */
      io.rule.log.connect = 1;
#endif /* SOCKS_SERVER */

   sockaddr2sockshost(TOSA(&request->from), &io.control.host);
   io.control.s       = request->s;
   io.control.laddr   = request->to;
   io.control.raddr   = request->from;
   io.control.auth    = *request->req.auth;

   io.dst.auth.method = AUTHMETHOD_NOTSET; /* at least so far. */

   init_iologaddr(&src,
                  SOCKADDR_OBJECT,
                  &io.control.laddr,
                  SOCKSHOST_OBJECT,
                  &io.control.host,
                  &io.control.auth,
                  GET_HOSTIDV(&io.state),
                  GET_HOSTIDC(&io.state));

   /*
    * examine client request.
    */

   /* supported version? */
   switch (request->req.version) {
#if SOCKS_SERVER || BAREFOOTD
      case PROXY_SOCKS_V4:
         response.version = PROXY_SOCKS_V4REPLY_VERSION;

         /* supported address format for this version? */
         switch (request->req.host.atype) {
            case SOCKS_ADDR_IPV4:
               break;

            default:
               snprintf(msg, sizeof(msg), "unrecognized v%d atype: %d",
                        request->req.version, request->req.host.atype);

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     0);

               send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           TOSA(&io.control.raddr),
                           sockscf.shmemfd,
                           SHMEM_ALL);
               return -1;
         }

         /* recognized command for this version? */
         switch (request->req.command) {
            case SOCKS_BIND:
            case SOCKS_CONNECT:
               io.state.protocol = SOCKS_TCP;
               break;

            default:
               snprintf(msg, sizeof(msg), "unrecognized v%d command: %d",
                        request->req.version, request->req.command);

               io.state.command = SOCKS_UNKNOWN;
               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     0);

               send_failure(request->s, &response, SOCKS_CMD_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           TOSA(&io.control.raddr),
                           sockscf.shmemfd,
                           SHMEM_ALL);

               return -1;
         }
         break; /* PROXY_SOCKS_V4 */

      case PROXY_SOCKS_V5:
         response.version = request->req.version;

         /* supported address format for this version? */
         switch (request->req.host.atype) {
            case SOCKS_ADDR_IPV4:
            case SOCKS_ADDR_DOMAIN:
               break;

            default:
               snprintf(msg, sizeof(msg), "unrecognized v%d atype: %d",
                        request->req.version, request->req.host.atype);

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

               send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           TOSA(&io.control.raddr),
                           sockscf.shmemfd,
                           SHMEM_ALL);

               return -1;
         }

         /* recognized command for this version? */
         switch (request->req.command) {
            case SOCKS_BIND:
            case SOCKS_CONNECT:
               io.state.protocol = SOCKS_TCP;
               break;

            case SOCKS_UDPASSOCIATE:
               io.state.protocol = SOCKS_UDP;
               break;

            default:
               snprintf(msg, sizeof(msg), "unrecognized v%d command: %d",
                        request->req.version, request->req.command);

               io.state.command = SOCKS_UNKNOWN;
               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     0);

               send_failure(request->s, &response, SOCKS_CMD_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           TOSA(&io.control.raddr),
                           sockscf.shmemfd,
                           SHMEM_ALL);

               return -1;
         }

         break; /* PROXY_SOCKS_V5 */
#endif /* SOCKS_SERVER || BAREFOOTD */

#if COVENANT
      case PROXY_HTTP_10:
      case PROXY_HTTP_11:
         SASSERTX(request->req.command == SOCKS_CONNECT);
         SASSERTX (request->req.host.atype == SOCKS_ADDR_IPV4
         ||        request->req.host.atype == SOCKS_ADDR_DOMAIN);

         response.version  = request->req.version;
         io.state.protocol = SOCKS_TCP;
         break;
#endif /* COVENANT */


      default:
         SERRX(request->req.version);
   }

   /*
    * Any command-specific things to check?
    */
   switch (request->req.command) {
      case SOCKS_CONNECT:
#if HAVE_LINUX_BUGS
         if (ntohs(request->req.host.port) == 0) {
            /*
             * What was observed was that the connect(2) would return
             * EINPROGRESS as expected.  Later select(2) would however
             * indicate the socket was writable, but getpeername(2)
             * would fail on the socket, while getsockopt(2) for SO_ERROR
             * would indicate there was no error.
             * Strangely enough, this does not happen every time, just
             * sometimes, and has only been reproduced on some very busy
             * servers running Linux 2.6.18.
             */
            snprintf(msg, sizeof(msg),
                     "connecting to port 0 leads to strange behaviour on "
                     "Linux sometimes, so blocked");

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  NULL,
                  NULL,
                  NULL,
                  msg,
                  0);

               send_failure(request->s, &response, SOCKS_INVALID_ADDRESS);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           TOSA(&io.control.raddr),
                           sockscf.shmemfd,
                           SHMEM_ALL);

               return -1;
            }
#endif /* HAVE_LINUX_BUGS */

            break;
   }

   /*
    * packet looks ok, fill in remaining bits and check rules.
    */

   switch (request->req.command) {
#if SOCKS_SERVER
      case SOCKS_BIND:
         /*
          * Bind is a bit cumbersome.
          * We first need to check if the bind request is allowed, and then
          * we transform io.dst to something completely different to check
          * if the bindreply is allowed.
          */

         io.src = io.control;

         io.dst.host = request->req.host;
         if (io.dst.host.atype            == SOCKS_ADDR_IPV4
         &&  io.dst.host.addr.ipv4.s_addr == htonl(BINDEXTENSION_IPADDR))
            io.state.extension.bind = 1;
         else
            io.state.extension.bind = 0;

         break;
#endif /* SOCKS_SERVER */

      case SOCKS_CONNECT:
         io.src      = io.control;
         io.dst.host = request->req.host;
         break;

      case SOCKS_UDPASSOCIATE:
         /*
          * some things will change, but some things, auth included, will
          * stay the same.
          */

         io.src                               = io.control;

         SET_SOCKADDR(TOSA(&io.src.laddr), AF_INET);
         TOIN(&io.src.laddr)->sin_addr.s_addr = htonl(INADDR_ANY);
         TOIN(&io.src.laddr)->sin_port        = htons(0);

         io.src.host                          = request->req.host;
         sockshost2sockaddr(&io.src.host, TOSA(&io.src.raddr));

         /*
          * for UDP_ASSOCIATE we are getting clients UDP address,
          * not destination in request. Destination address will be
          * checked in the i/o loop for each destination for each packet.
          * For now set it to INADDR_ANY.
          */
         io.dst.host.atype            = SOCKS_ADDR_IPV4;
         io.dst.host.addr.ipv4.s_addr = htonl(INADDR_ANY);
         io.dst.host.port             = htons(0);

         break;

      default:
         SERRX(request->req.command);
   }

   /* create outgoing socket. */
   switch (io.state.protocol) {
      case SOCKS_TCP:
         out = socket(AF_INET, SOCK_STREAM, 0);
         break;

      case SOCKS_UDP:
         out = socket(AF_INET, SOCK_DGRAM, 0);
         break;

      default:
         SERRX(io.state.protocol);
   }

   /*
    * Update now that we have parsed the request and know what is what.
    */
   init_iologaddr(&src,
                  SOCKADDR_OBJECT,
                  &io.src.laddr,
                  SOCKSHOST_OBJECT,
                  &io.src.host,
                  &io.src.auth,
                  GET_HOSTIDV(&io.state),
                  GET_HOSTIDC(&io.state));

   /* also know parts of dst now. */
   init_iologaddr(&dst,
                  NOOBJECT,
                  NULL,
                  SOCKSHOST_OBJECT,
                  &io.dst.host,
                  NULL,
                  NULL,
                  0);

   if (out == -1) {
      snprintf(msg, sizeof(msg), "could not create socket: %s",
               strerror(errno));

      iolog(&io.rule,
            &io.state,
            OPERATION_ERROR,
            &src,
            &dst,
            NULL,
            NULL,
            msg,
            0);

      send_failure(request->s, &response, SOCKS_FAILURE);
      close(request->s);

      SHMEM_UNUSE(&io.crule, TOSA(&io.control.raddr), sockscf.shmemfd, SHMEM_ALL);
      return -1;
   }

   bzero(&bound, sizeof(bound));

   /*
    * Find address to bind on clients behalf.
    * First, the IP address ...
   */
   switch (request->req.command) {
      case SOCKS_BIND:
      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE: { /* dst is 0.0.0.0. */
         struct sockaddr_storage dstaddr;

         sockshost2sockaddr(&io.dst.host, TOSA(&dstaddr));
         TOIN(&bound)->sin_addr = getoutaddr(TOIN(&request->to)->sin_addr,
                                             TOIN(&dstaddr)->sin_addr);
         break;
      }

      default:
         SERRX(request->req.command);
   }

   /* ... and then the port. */
   switch (request->req.command) {
#if SOCKS_SERVER
      case SOCKS_BIND:
         /*
          * Figure out what address to expect the bind reply from at the
          * same time, as well as what the destination for the bind reply is.
          *
          * Unfortunately, this is a mishmash of different interpretations.
          *
          * The socks v4 standard is pretty strict about the meaning,
          * while the v5 is much less clear.
          * Unfortunately, the meaning given in these standard provides
          * limited usability, so people "interpret" the standards more
          * loose to get more practical functionality out of them.
          *
          * - If the client provided an ip address when requesting the
          *   bind, we should only return remote connections matching
          *   that ip address.  The port number we should ignore.
          *
          * - If the client did not provide an ip address (set it to 0),
          *   we should probably try to match neither ip nor port.
          *
          * The standard is not very clear on this point, but the above
          * interpretation seems most practical.
          */

         bindreplydst = io.control.host;

         if (io.state.extension.bind) {
            io.dst.host.addr.ipv4  = TOCIN(&request->from)->sin_addr;
            bindreplydst           = io.dst.host;
            bindreplydst.port      = io.dst.host.port;

            TOIN(&bound)->sin_port = TOCIN(&request->from)->sin_port;

            bzero(&expectedbindreply, sizeof(expectedbindreply));
            expectedbindreply.atype = SOCKS_ADDR_IPV4;
         }
         else {
            if (io.dst.host.addr.ipv4.s_addr == htonl(0)) {
               bzero(&expectedbindreply, sizeof(expectedbindreply));
               expectedbindreply.atype = SOCKS_ADDR_IPV4;
            }
            else
               expectedbindreply = io.dst.host;

            expectedbindreply.port = htons(0);

            slog(LOG_DEBUG, "%s: expecting bindreply from %s",
            function, sockshost2string(&expectedbindreply, NULL, 0));

            switch (request->req.version) {
               case PROXY_SOCKS_V4:
                  /*
                   * If the address is 0, assume port is port client
                   * wants to bind.  If not, best we can try for is to
                   * use same port as client used for connecting to us.
                   */
                  if (io.dst.host.addr.ipv4.s_addr == htonl(0))
                     TOIN(&bound)->sin_port = io.dst.host.port;
                  else
                     TOIN(&bound)->sin_port =TOCIN(&request->from)->sin_port;

                  break;

               case PROXY_SOCKS_V5:
                  /*
                   * similar to above, but here one popular interpretation
                   * is that the port gives the desired port, rather than
                   * the port the client previously connected to.
                   */
                  TOIN(&bound)->sin_port = io.dst.host.port;
                  break;

               default:
                  SERRX(request->req.version);
            }
         }
         break;
#endif /* SOCKS_SERVER */

      case SOCKS_CONNECT:
#if 0
         /*
          * Set SO_REUSEADDR to limit the chances that we run out of
          * available TCP ports to use.
          * We however need to handle the case of us trying to connect
          * from the same port (due to the client connecting from the
          * same port) to the same destination multiple times, which
          * we don't do yet.  Thus disabled.
          */
         p = 1;
         if (setsockopt(out, SOL_SOCKET, SO_REUSEADDR, &p, sizeof(p)) != 0)
            swarn("%s: setsockopt(SO_REUSEADDR)", function);
#endif

         TOIN(&bound)->sin_port = TOCIN(&request->from)->sin_port;
         break;

      case SOCKS_UDPASSOCIATE:
         TOIN(&bound)->sin_port = request->req.host.port;
         break;

      default:
         SERRX(request->req.command);
   }

   if (PORTISRESERVED(TOIN(&bound)->sin_port) && !sockscf.compat.sameport) {
      slog(LOG_DEBUG, "%s: would normally try to bind port %d, but"
                      "\"compatibility: sameport\" is not set, so binding any",
                      function, ntohs(TOIN(&bound)->sin_port));

      TOIN(&bound)->sin_port = htons(0);
   }

   if (io.state.extension.bind && request->req.command == SOCKS_BIND) {
      p = 1;
      if (setsockopt(out, SOL_SOCKET, SO_REUSEADDR, &p, sizeof(p)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);
   }

   /* need to bind address so rulespermit() has an address to compare against.*/
   SET_SOCKADDR(TOSA(&bound), AF_INET);
   if ((p = sockd_bind(out, TOSA(&bound), 0)) != 0) {
      /* no such luck.  Bind any port and let client decide if ok. */

      /* LINTED pointer casts may be troublesome */
      TOIN(&bound)->sin_port = htons(0);

      if ((p = sockd_bind(out, TOSA(&bound), 0)) == 0)
         slog(LOG_DEBUG, "%s: bound different port than desired (bound %s)\n",
         function, sockaddr2string(TOSA(&bound), NULL, 0));
      else
         swarn("%s: this is certainly strange ... failed to bind "
               "port 0 (%s) also",
               function, sockaddr2string(TOSA(&bound), NULL, 0));
   }

   if (p != 0) {
      snprintf(msg, sizeof(msg), "failed to bind address on external side: %s",
               strerror(errno));

      iolog(&io.rule,
            &io.state,
            OPERATION_ERROR,
            &src,
            &dst,
            NULL,
            NULL,
            msg,
            0);

      send_failure(request->s, &response, errno2reply(errno, response.version));

      close(request->s);
      close(out);
      SHMEM_UNUSE(&io.crule, TOSA(&io.control.raddr), sockscf.shmemfd, SHMEM_ALL);
      return -1;
   }


#if BAREFOOTD
   if (io.state.protocol == SOCKS_UDP) {
      /*
       * dst.s is just a dummy socket used for select(2).  The real
       * socket will be created in the i/o process when we actually
       * get a real client, one for each client.
       */
      bzero(&bound, sizeof(bound));
      SET_SOCKADDR(TOSA(&bound), AF_INET);
   }
   else
#endif /* BAREFOOTD */
      slog(LOG_DEBUG, "%s: bound address on external side is %s",
           function, sockaddr2string(TOSA(&bound), NULL, 0));

   io.dst.laddr = bound;
   io.dst.s     = out;

#if HAVE_SOCKS_RULES
   /*
    * rules permit?
    */
   switch (request->req.command) {
#if SOCKS_SERVER
      case SOCKS_BIND: {
         sockshost_t boundhost;

         sockaddr2sockshost(TOSA(&bound), &boundhost);

         permit = rulespermit(request->s,
                              TOSA(&request->from),
                              TOSA(&request->to),
                              &io.clientauth,
                              &io.src.auth,
                              &io.rule,
                              &io.state,
                              &io.src.host,
                              &boundhost,
                              msg,
                              sizeof(msg));

         /*
          * XXX we should check whether it's possible receive any bindreply
          * also.  No need to stick around if no replies will be allowed.
          */
         break;
      }
#endif /* SOCKS_SERVER */

      case SOCKS_CONNECT:
         /*
          * XXX if the request is bind, we should check whether it's possible
          * receive any bindreply also.  No need to stick around if no
          * replies will be allowed.
          */
         permit = rulespermit(request->s,
                              TOSA(&request->from),
                              TOSA(&request->to),
                              &io.clientauth,
                              &io.src.auth,
                              &io.rule,
                              &io.state,
                              &io.src.host,
                              &io.dst.host,
                              msg,
                              sizeof(msg));
         break;

      case SOCKS_UDPASSOCIATE: {
         sockshost_t *src;

         /*
          * Client is allowed to send a "incomplete" address, but if it has
          * not done that, the address it sent is the fixed source address.
          * Destination address can vary for each packet, so NULL here.
          */
         if (io.src.host.atype             == SOCKS_ADDR_IPV4
         &&  (io.src.host.addr.ipv4.s_addr == htonl(0)
           || io.src.host.port             == htons(0)))
            /*
             * If ip or port is not set, we won't know what rule to use if
             * we have multiple, so check against any for now.
             * XXX or?  At least we should close the session once we know
             * the address if it turns out no forwarding is allowed.
             */
            src = NULL;
         else
            src = &io.src.host;

         permit = rulespermit(request->s,
                              TOSA(&request->from),
                              TOSA(&request->to),
                              &io.clientauth,
                              &io.src.auth,
                              &io.rule,
                              &io.state,
                              src,
                              NULL,
                              msg,
                              sizeof(msg));
         break;
      }

      default:
         SERRX(request->req.command);
   }

   if (io.state.protocol == SOCKS_TCP) {
      setconfsockoptions(io.control.s,
                         -1,
                         io.state.protocol,
                         1,
                         io.rule.socketoptionc,
                         io.rule.socketoptionv,
                         SOCKETOPT_ANYTIME | SOCKETOPT_POST,
                         0 /* should be set already. */);
   }

   /*
    * Check session-limit here so we can know before iolog().  No point
    * in logging that rulespermit() passed if the session-limit denies.
    *
    * XXX in udp's case, if src was NULL, we should wait til the first
    * packet before we set the limits.
    */
   if (permit && io.rule.ss_shmid != 0) { /* don't bother if rules deny. */
      sockd_shmat(&io.rule, SHMEM_SS);

      if (io.rule.ss_shmid != 0) {
         if (!session_use(io.rule.ss, sockscf.shmemfd)) {
            permit          = 0;
            io.rule.verdict = VERDICT_BLOCK;

            snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
         }

         sockd_shmdt(&io.rule, SHMEM_SS);
      }
   }

   sockaddr2sockshost(TOSA(&io.dst.laddr), &dst.local);
   dst.local_isset = 1;

   if (!permit) {
      iolog(&io.rule,
            &io.state,
            permit ? OPERATION_CONNECT : OPERATION_BLOCK,
            &src,
            &dst,
            NULL,
            NULL,
            msg,
            0);

      SHMEM_UNUSE(&io.crule,
                  TOSA(&io.control.raddr),
                  sockscf.shmemfd,
                  SHMEM_ALL);

      send_failure(request->s, &response, SOCKS_NOTALLOWED);
      close(request->s);
      close(out);

      return -1;
   }

   /*
    * Some stuff can be inherited from lower level rules by the socks-rule.
    */

   /*
    * Bandwidth.  If it's set in the lower level rule, let the socks-rule
    * inherit it.
    */

   if (io.crule.bw_shmid == 0
#if HAVE_SOCKS_HOSTID
   &&  (!io.hostidrule_isset || io.hostidrule.bw_shmid == 0)
#endif /* HAVE_SOCKS_HOSTID */
   ) {
      if (io.rule.bw_shmid != 0)
         sockd_shmat(&io.rule, SHMEM_BW);

      if (io.rule.bw_shmid != 0) {
         bw_use(io.rule.bw, sockscf.shmemfd);
         sockd_shmdt(&io.rule, SHMEM_BW);
      }
   }
   else {
      /*
       * lower level rule is not used anymore after the matching socks-rule
       * has been determined, except for possible logging related to
       * disconnect, so copy over what we need from client-rule to the
       * socks-rule and then use the socks-rule for everything from now on.
       */
      ruletype_t inheritedruletype;
      rule_t *inheritedrule;

#if HAVE_SOCKS_HOSTID
      if (io.hostidrule_isset && io.hostidrule.bw_shmid != 0) {
         inheritedruletype = hostidrule;
         inheritedrule     = &io.hostidrule;
      }
      else
#endif /* HAVE_SOCKS_HOSTID */
      if (io.crule.bw_shmid != 0) {
         inheritedruletype = clientrule;
         inheritedrule     = &io.crule;
      }

      if (io.rule.bw_shmid == 0) {
         slog(LOG_DEBUG, "%s: socks-rule #%lu inherits bandwidth-limit "
                         "from %s #%lu",
                         function,
                         (unsigned long)io.rule.number,
                         ruletype2string(inheritedruletype),
                         (unsigned long)inheritedrule->number);

         switch (inheritedruletype) {
            case clientrule:
               io.rule.bw_shmid = io.crule.bw_shmid;
               break;

#if HAVE_SOCKS_HOSTID
            case hostidrule:
               io.rule.bw_shmid = io.hostidrule.bw_shmid;
               break;
#endif /* HAVE_SOCKS_HOSTID */

            default:
               SERRX(inheritedruletype);
         }
      }
      else {
         if (io.crule.bw_shmid != 0)
            sockd_shmat(&io.crule, SHMEM_BW);

#if HAVE_SOCKS_HOSTID
         if (io.hostidrule_isset && io.hostidrule.bw_shmid != 0)
            sockd_shmat(&io.hostidrule, SHMEM_BW);
#endif /* HAVE_SOCKS_HOSTID */

         sockd_shmat(&io.rule, SHMEM_BW);

         if (memcmp(io.crule.bw, io.rule.bw, sizeof(*io.crule.bw)) != 0)
            slog(LOG_DEBUG, "%s: client-rule #%lu limits bandwidth to %lu B/s, "
                            "but limit is overridden by socks-rule #%lu which "
                            "limits bandwidth to %lu B/s ",
                            function,
                            (unsigned long)io.crule.number,
                            (unsigned long)io.crule.bw->object.bw.maxbps,
                            (unsigned long)io.rule.number,
                            (unsigned long)io.rule.bw->object.bw.maxbps);

         bw_unuse(io.crule.bw, sockscf.shmemfd);
         sockd_shmdt(&io.crule, SHMEM_BW);

#if HAVE_SOCKS_HOSTID
         if (memcmp(io.hostidrule.bw, io.rule.bw, sizeof(*io.hostidrule.bw))
         != 0)
            slog(LOG_DEBUG, "%s: hostid-rule #%lu limits bandwidth to %lu B/s, "
                            "but limit is overridden by socks-rule #%lu which "
                            "limits bandwidth to %lu B/s ",
                            function,
                            (unsigned long)io.hostidrule.number,
                            (unsigned long)io.hostidrule.bw->object.bw.maxbps,
                            (unsigned long)io.rule.number,
                            (unsigned long)io.rule.bw->object.bw.maxbps);

         bw_unuse(io.hostidrule.bw, sockscf.shmemfd);
         sockd_shmdt(&io.hostidrule, SHMEM_BW);
#endif /* HAVE_SOCKS_HOSTID */

         bw_use(io.rule.bw, sockscf.shmemfd);
         sockd_shmdt(&io.rule, SHMEM_BW);
      }
   }

   /*
    * Session.  Client-rule limits sessions client-rules apply to (i.e.,
    * negotiate) and should have been unused already by the negotiate-child,
    * while socks-rule limits session socks-rules apply to, so no inheritance
    * here.
    */
   SASSERTX(io.crule.ss_shmid == 0);
#if HAVE_SOCKS_HOSTID
   SASSERTX(io.hostidrule.ss_shmid == 0);
#endif /* HAVE_SOCKS_HOSTID */

   /*
    * Redirection.
    */
   switch (request->req.command) {
      /* only meaningful to inherit for these commands. */
      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE: {
         ruletype_t inheritedruletype;
         rule_t *inheritedrule;

#if HAVE_SOCKS_HOSTID
         if (io.hostidrule_isset
         && io.hostidrule.rdr_from.atype != SOCKS_ADDR_NOTSET) {
            inheritedruletype = hostidrule;
            inheritedrule     = &io.hostidrule;
         }
         else
#endif /* HAVE_SOCKS_HOSTID */
         if (io.crule.rdr_from.atype != SOCKS_ADDR_NOTSET) {
            inheritedruletype = clientrule;
            inheritedrule     = &io.crule;
         }
         else {
            /* don't inherit. */
            inheritedruletype = socksrule;
            inheritedrule     = &io.rule;
         }

         if (inheritedruletype != socksrule
         &&  io.rule.rdr_from.atype == SOCKS_ADDR_NOTSET) {
               slog(LOG_DEBUG, "%s: socks-rule #%lu inherits redirection "
                               "from %s from %s #%lu",
                               function,
                               (unsigned long)io.rule.number,
                               ruleaddr2string(&inheritedrule->rdr_from,
                                               NULL,
                                               0),
                               ruletype2string(inheritedruletype),
                               (unsigned long)inheritedrule->number);

               switch (inheritedruletype) {
                  case clientrule:
                     io.rule.rdr_from = io.crule.rdr_from;
                     break;

#if HAVE_SOCKS_HOSTID
                  case hostidrule:
                     io.rule.rdr_from = io.hostidrule.rdr_from;
                     break;
#endif /* HAVE_SOCKS_HOSTID */

                  default:
                     SERRX(inheritedruletype);
               }
            }
            else {
               if (inheritedruletype != socksrule)
                  slog(LOG_DEBUG, "%s: %s #%lu specifies redirection, but is "
                                  "overridden by socks-rule #%lu",
                                  function,
                                  ruletype2string(inheritedruletype),
                                  (unsigned long)inheritedrule->number,
                                  (unsigned long)io.rule.number);
            }
         }
   }

#else /* !HAVE_SOCKS_RULES */

   /*
    * copy over auth from lower level.
    */
    io.src.auth = io.control.auth = io.clientauth;
#endif /* !HAVE_SOCKS_RULES */

   /*
    * whatever should be inherited has been inherited now so can clear the
    * lower levels rule. 
    */
   SHMEM_CLEAR(&io.crule, 1);
#if HAVE_SOCKS_HOSTID
   SHMEM_CLEAR(&io.hostidrule, 1);
#endif /* HAVE_SOCKS_HOSTID */


   if (redirect(out,
                TOSA(&bound),
                &io.dst.host,
                request->req.command,
                &io.rule.rdr_from,
                &io.rule.rdr_to) != 0) {
      SHMEM_UNUSE(&io.rule,
                   TOSA(&io.control.raddr),
                   sockscf.shmemfd,
                   SHMEM_ALL);

      if (io.rule.log.error) {
         snprintf(msg, sizeof(msg), "redirect() failed: %s", strerror(errno));
         iolog(&io.rule,
                &io.state,
                OPERATION_ERROR,
                &src,
                &dst,
                NULL,
                NULL,
                msg,
                0);
      }

      send_failure(request->s, &response, errno2reply(errno, response.version));
      close(request->s);
      close(out);

      return -1;
   }

   io.dst.laddr = bound; /* in case redirect changed it. */

   setsockoptions(out,
                  io.state.protocol == SOCKS_TCP ? SOCK_STREAM : SOCK_DGRAM,
                  0);

   setconfsockoptions(out,
                      io.control.s,
                      io.state.protocol,
                      0,
                      io.rule.socketoptionc,
                      io.rule.socketoptionv,
                      SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                      SOCKETOPT_PRE | SOCKETOPT_ANYTIME);

   if (serverchain(out,
                   &request->req,
                   &response,
                   &io.src,
                   &io.dst,
                   &io.state.proxyprotocol,
                   &io.state.proxychain) == 0) {
      socklen_t sinlen;
      int failed = 0;

      SASSERTX(io.state.proxyprotocol != PROXY_DIRECT);

      io.dst.state.connected = 1;

      sinlen = sizeof(io.dst.raddr);
      if (getpeername(io.dst.s, TOSA(&io.dst.raddr), &sinlen) != 0) {
         if (io.rule.log.error) {
            snprintf(msg, sizeof(msg), "getpeername(io.dst.s) failed: %s",
                     strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);
         }

         send_failure(request->s, &response, SOCKS_FAILURE);
         close(request->s);
         failed = 1;
      }

      if (!failed)
         if (send_response(request->s, &response) != 0) {
            snprintf(msg, sizeof(msg), "could not send response to client: %s",
                     strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);

            failed = 1;
         }

      if (!failed) {
         setconfsockoptions(out,
                            request->s,
                            io.state.protocol,
                            0,
                            io.rule.socketoptionc,
                            io.rule.socketoptionv,
                            SOCKETOPT_POST,
                            SOCKETOPT_POST);

         io.reqinfo.command = (io.state.protocol == SOCKS_TCP ?
                                    SOCKD_FREESLOT_TCP : SOCKD_FREESLOT_UDP);
         flushio(mother->s, &io);
      }

      close(out);

      if (failed) {
         SHMEM_UNUSE(&io.rule,
                     TOSA(&io.control.raddr),
                     sockscf.shmemfd,
                     SHMEM_ALL);
         return -1;
      }

      return 0;
   }
   else { /* no chain.  Error, or no route? */
      if (errno != 0) { /* error. */
         SHMEM_UNUSE(&io.rule,
                     TOSA(&io.control.raddr),
                     sockscf.shmemfd,
                     SHMEM_ALL);

         snprintf(msg, sizeof(msg), "serverchain failed (%s)", strerror(errno));
         iolog(&io.rule,
               &io.state,
               OPERATION_ERROR,
               &src,
               &dst,
               NULL,
               NULL,
               msg,
               0);

         send_failure(request->s,
                      &response,
                      errno2reply(errno,
                      response.version));

         close(request->s);
         close(out);

         return -1;
      }

      SASSERTX(io.state.proxyprotocol == PROXY_DIRECT);
   }

   /*
    * Set up missing bits of io and send it to mother.
    */

   socks_set_responsevalue(&response,
                           sockscode(response.version, SOCKS_SUCCESS));
   rc = 0;

   switch (io.state.command) {
#if SOCKS_SERVER
      case SOCKS_BIND: {
         sockd_io_t *iolist;
         sockd_io_t bindio;         /* send this to iochild.  */
         socklen_t len;
         enum socketindex { client, childpipe, ourpipe, reply, remote };
         /* array of sockets, indexed by above enums.  -1 if not open. */
         int sv[(int)(remote) + 1] = { -1, -1, -1, -1, -1 }, flags, emfile;

         /*
          * - io.dst gives the address bound on behalf of the client (io.src).
          * - expectedbindreply give the address to expect the bindreply from.
          * - bindreplydst give the address to send the bindreply to.
          */

         SASSERTX(sv[ELEMENTS(sv) - 1] == -1);
         sv[client] = request->s;

         if (io.state.extension.bind)
            dst.peer_isset = 0;
         else {
            dst.peer_isset = 1;
            dst.peer       = io.dst.host;
         }

         if (listen(out, SOCKD_MAXCLIENTQUE) != 0) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "listen(out) failed: %s",
                        strerror(errno));

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     &dst,
                     NULL,
                     NULL,
                     msg,
                     0);
            }

            send_failure(sv[client], &response, SOCKS_FAILURE);
            closev(sv, ELEMENTS(sv));
            close(out);

            rc = -1;
            break;
         }

         /* for accept(). */
         if ((flags = fcntl(out, F_GETFL, 0))          == -1
         ||   fcntl(out, F_SETFL, flags | O_NONBLOCK) == -1) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "fcntl() failed: %s",
                        strerror(errno));

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     &dst,
                     NULL,
                     NULL,
                     msg,
                     0);
            }

            send_failure(sv[client], &response, SOCKS_FAILURE);
            close(out);
            closev(sv, ELEMENTS(sv));

            rc = -1;
            break;
         }

         sockaddr2sockshost(TOSA(&io.dst.laddr), &response.host);

         if (io.state.extension.bind) {
            int pipev[2];

            /*
             * The problem is that both we and the process which receives
             * the io packet needs to know when the client closes it's
             * connection, but _we_ need to receive a query from the
             * client on the connection as well, and the io process would
             * get confused about that.  We try to hack around that
             * by making a "dummy" descriptor that the io process can
             * check as all other control connections and which we
             * can close when the client closes the real control connection,
             * so the io process can detect it.
             * Not very nice, no.
             */

            if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pipev) != 0) {
               snprintf(msg, sizeof(msg), "socketpair() failed: %s",
                        strerror(errno));

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     &dst,
                     NULL,
                     NULL,
                     msg,
                     0);

               send_failure(sv[client], &response, SOCKS_FAILURE);
               close(out);
               closev(sv, ELEMENTS(sv));

               rc = -1;
               break;
            }

            sv[childpipe] = pipev[0];
            sv[ourpipe]   = pipev[1];
         }

         /* let client know what address we bound to on it's behalf. */
         if (send_response(sv[client], &response) != 0) {
            snprintf(msg, sizeof(msg), "sending response to client failed: %s",
                     strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);

            close(out);
            closev(sv, ELEMENTS(sv));

            rc = -1;
            break;
         }

         iolog(&io.rule,
               &io.state,
               OPERATION_CONNECT,
               &src,
               &dst,
               NULL,
               NULL,
               NULL,
               0);

         emfile = 0;
         iolist = NULL;

         bindio               = io; /* quick init of most stuff. */
         bindio.state.command = SOCKS_BINDREPLY;

         bindio.dst.host = bindreplydst;
         if (bindio.state.extension.bind) {
            sockshost2sockaddr(&bindio.dst.host, TOSA(&bindio.dst.raddr));

            /* won't create socket for this til we connect to the client. */
            bzero(&bindio.dst.laddr, sizeof(bindio.dst.laddr));
            SET_SOCKADDR(TOSA(&bindio.dst.laddr), AF_INET);
            TOIN(&bindio.dst.laddr)->sin_addr.s_addr = htonl(INADDR_ANY);
            TOIN(&bindio.dst.laddr)->sin_port        = htons(0);
         }
         else
            bindio.dst.laddr = io.src.laddr;

         bindio.dst.auth = io.src.auth;

         bindio.src.auth.method  = AUTHMETHOD_NOTSET;
         bindio.src.laddr        = bound;
         sockaddr2sockshost(TOSA(&bindio.src.laddr), &bindio.src.host);

         /* don't know what peer will be til we accept(2) it. */
         bzero(&bindio.src.raddr, sizeof(bindio.src.raddr));
         SET_SOCKADDR(TOSA(&bindio.src.raddr), AF_INET);
         TOIN(&bindio.src.raddr)->sin_addr.s_addr = htonl(INADDR_ANY);
         TOIN(&bindio.src.raddr)->sin_port        = htons(0);

         bindio.cmd.bind.host = io.dst.host;
         bindio.cmd.bind.rule = io.rule;

         /*
          * if we are using the bind extension, keep accepting connections
          * until client closes the control-connection.  If not, break
          * after the first.
          */
         while (1) {
            static fd_set *rset;
            ruleaddr_t ruleaddr;
            struct sockaddr_storage remoteaddr; /* remote address accepted.   */
            struct sockaddr_storage replyaddr;  /* addr of bindreply socket.  */
            int replyredirect, fdbits = -1;

            if (rset == NULL)
               rset = allocate_maxsize_fdset();

            FD_ZERO(rset);

            /* some sockets change, most remain the same. */
            sv[reply]  = -1;
            sv[remote] = -1;

            FD_SET(sv[client], rset);
            fdbits = MAX(fdbits, sv[client]);

            FD_SET(mother->s, rset);
            fdbits = MAX(fdbits, mother->s);

            FD_SET(mother->ack, rset);
            fdbits = MAX(fdbits, mother->ack);

            if (!emfile) {
               FD_SET(out, rset);
               fdbits = MAX(fdbits, out);
            }

            ++fdbits;
            if ((p = selectn(fdbits, rset, NULL, NULL, NULL, NULL, NULL)) <= 0){
               if (p == -1 && errno == EINTR)
                  continue;

               SERR(p);
            }

            if (FD_ISSET(mother->ack, rset)) {
               slog(LOG_DEBUG, "%s: socket to mother is readable ... since we "
                               "can only handle one client at a time, this "
                               "should only happen if mother closes the "
                               "connection.  Nobody to send the client too "
                               "then, so return",
                               function);

               return -1;
            }

            if (FD_ISSET(sv[client], rset)) {
               /*
                * nothing is normally expected on control connection so
                * assume it's a bind extension query or eof.
                */
               request_t query;
               response_t queryresponse;
               negotiate_state_t state;
               struct sockaddr_storage queryaddr;
               negotiate_result_t res;

               bzero(&state, sizeof(state));
               bzero(&query, sizeof(query));
               bzero(&queryresponse, sizeof(queryresponse));

               query.auth         = request->req.auth;
               queryresponse.auth = query.auth;

               /* XXX use switch (). */
               if ((res = recv_sockspacket(sv[client], &query, &state))
               == NEGOTIATE_CONTINUE) {
                  slog(LOG_DEBUG, "%s: did not receive full request",
                       function);

                  continue;
               }

               if (res == NEGOTIATE_ERROR) {
                  snprintf(msg, sizeof(msg),
                           "receiving request from client failed: %s",
                           strerror(errno));

                  iolog(&io.rule,
                        &io.state,
                        OPERATION_ERROR,
                        &src,
                        &dst,
                        NULL,
                        NULL,
                        msg,
                        0);

                  p = -1; /* session ended. */
               }
               else {
                  sockd_io_t *fio;

                  SASSERTX(res == NEGOTIATE_FINISHED);

                  slog(LOG_DEBUG, "received bind resolve request: %s",
                  socks_packet2string(&query, 1));

                  switch (query.version) {
                     case PROXY_SOCKS_V4:
                        queryresponse.version = PROXY_SOCKS_V4REPLY_VERSION;
                        break;

                     case PROXY_SOCKS_V5:
                        queryresponse.version = query.version;
                        break;

                     default:
                        SERRX(query.version);
                  }

                  sockshost2sockaddr(&query.host, TOSA(&queryaddr));
                  if ((fio = io_find(iolist, TOSA(&queryaddr))) == NULL) {
                     queryresponse.host.atype            = SOCKS_ADDR_IPV4;
                     queryresponse.host.addr.ipv4.s_addr = htonl(0);
                     queryresponse.host.port             = htons(0);
                  }
                  else {
                     SASSERTX(fio->state.command == SOCKS_BINDREPLY);
                     SASSERTX(sockaddrareeq(TOSA(&fio->dst.laddr),
                                            TOSA(&queryaddr)));

                     sockaddr2sockshost(TOSA(&fio->src.raddr),
                     &queryresponse.host);
                  }

                  if ((p = send_response(sv[client], &queryresponse)) == 0) {
                     if (fio != NULL) {
                        fio->dst.state.connected = 1;

                        fio->reqinfo.command = SOCKD_NOP;
                        flushio(mother->s, fio);

                        emfile = MAX(0, emfile - 3); /* flushio() closes 3 */
                        iolist = io_remove(iolist, fio);
                     }
                     /* else; nothing to flush yet. */
                  }
                  else {
                     snprintf(msg, sizeof(msg),
                              "sending response to client failed: %s",
                              strerror(errno));

                     iolog(&io.rule,
                           &io.state,
                           OPERATION_ERROR,
                           &src,
                           &dst,
                           NULL,
                           NULL,
                           msg,
                           0);

                     p = -1; /* session ended. */
                  }
               }

               if (p == -1) {
                  rc = -1;
                  break;
               }
            }

            if (!FD_ISSET(out, rset))
               continue;

            len = sizeof(remoteaddr);
            if ((sv[remote] = acceptn(out, TOSA(&remoteaddr), &len)) == -1) {
               if (io.rule.log.error)
                  swarn("%s: accept()", function);

               switch (errno) {
#ifdef EPROTO
                  case EPROTO:         /* overloaded SVR4 error */
#endif /* EPROTO */
                  case EWOULDBLOCK:    /* BSD */
                  case ECONNABORTED:   /* POSIX */

                  /* rest appears to be Linux stuff according to Apache src. */
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
                     continue;

                  case EMFILE:
                  case ENFILE:
                     ++emfile;
                     continue;
               }

               rc = -1;
               break; /* errno is not ok, end. */
            }

            slog(LOG_DEBUG, "%s: got a bindreply from %s",
            function, sockaddr2string(TOSA(&remoteaddr), NULL, 0));

            sockaddr2sockshost(TOSA(&remoteaddr), &bindio.src.host);

            /*
             * Accepted a connection.  Does remote address match requested?
             */

            if (io.state.extension.bind
            || expectedbindreply.addr.ipv4.s_addr == htonl(0)
            || addrmatch(sockshost2ruleaddr(&expectedbindreply, &ruleaddr),
                         &bindio.src.host, SOCKS_TCP, 1))
               permit = rulespermit(sv[remote],
                                    TOSA(&remoteaddr),
                                    TOSA(&bound),
                                    &bindio.clientauth,
                                    &bindio.src.auth,
                                    &bindio.rule,
                                    &bindio.state,
                                    &bindio.src.host,
                                    &bindio.dst.host,
                                    msg,
                                    sizeof(msg));
            else {
               bindio.rule.number  = 0;
               bindio.rule.verdict = VERDICT_BLOCK;

               snprintf(msg, sizeof(msg),
                       "expected bindreply from %s, but got it from %s, "
                       "rejecting",
                        sockshost2string(&expectedbindreply,
                                         strhost,
                                         sizeof(strhost)),
                        sockshost2string(&bindio.src.host, NULL, 0));

               permit = 0;
            }

            /*
             * a bindreply reverses src/dst, but save the auth acquired for
             * the bind request src, or we will lose it in the above
             * rulespermit().
             */

            if (permit && bindio.rule.ss_shmid != 0)
               sockd_shmat(&bindio.rule, SHMEM_SS);

            if (permit && bindio.rule.ss_shmid != 0) {
               if (!session_use(bindio.rule.ss, sockscf.shmemfd)) {
                  permit              = 0;
                  bindio.rule.verdict = VERDICT_BLOCK;

                  snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
               }
               sockd_shmdt(&bindio.rule, SHMEM_SS);
            }

            if (!permit) {
               iolog(&bindio.rule,
                     &bindio.state,
                     OPERATION_BLOCK,
                     &dst,
                     &src,
                     NULL,
                     NULL,
                     msg,
                     0);

               if (!bindio.state.extension.bind) {
                  /*
                   * can only accept one client, and that one failed,
                   * so assume it's better to end it rather than possibly
                   * wait forever for another client.
                   */
                  response.host = bindio.src.host;
                  send_failure(sv[client], &response, SOCKS_NOTALLOWED);

                  /*
                   * log the close of the opened bind session also.
                   */
                  errno = 0; /* in case send_failure() sets it. */
                  iolog(&io.rule,
                        &io.state,
                        OPERATION_DISCONNECT,
                        &src,
                        &dst,
                        NULL,
                        NULL,
                        NULL,
                        0);

                  rc = -1;
                  break;
               }
               else {
                  close(sv[remote]);
                  continue; /* wait for next client, but will there be one? */
               }
            }

            if (bindio.rule.bw_shmid != 0)
               sockd_shmat(&bindio.rule, SHMEM_BW);

            if (bindio.rule.bw_shmid != 0) {
               bw_use(bindio.rule.bw, sockscf.shmemfd);
               sockd_shmdt(&bindio.rule, SHMEM_BW);
            }

            if (redirect(sv[reply],
                         TOSA(&remoteaddr),
                         &bindreplydst,
                         SOCKS_BINDREPLY,
                         &bindio.rule.rdr_from,
                         &bindio.rule.rdr_to) != 0) {
               if (io.rule.log.error)
                  swarn("%s: redirect(sv[reply])", function);

               close(sv[remote]);
               close(sv[reply]);

               SHMEM_UNUSE(&bindio.rule,
                           TOSA(&bindio.control.raddr),
                           sockscf.shmemfd,
                           SHMEM_ALL);
               continue;
            }
            else {
               bindio.dst.host = bindreplydst;
               sockshost2sockaddr(&bindio.dst.host, TOSA(&bindio.dst.raddr));
            }


            /*
             * Someone connected to socket we listen to on behalf of client.
             * If we are using the bind extension, or are redirecting
             * the reply, connect to address client is listening on.
             * Otherwise, send the data on the connection we already have.
             */

            if (!sockshostareeq(&bindreplydst, &io.control.host)
            && !bindio.state.extension.bind)
               replyredirect = 1;
            else
               replyredirect = 0;

            if (bindio.state.extension.bind || replyredirect) {
               /*
                * need to create a new socket to use for connecting
                * to the destination address; not sending the data over
                * the control-socket.
                */
               char emsg[256];

               if ((sv[reply] = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                  if (io.rule.log.error)
                     swarn("%s: socket(SOCK_STREAM)", function);

                  switch (errno) {
                     case EMFILE:
                     case ENFILE:
                        ++emfile;
                        /* FALLTHROUGH */

                     case ENOBUFS:
                        close(sv[remote]);
                        SHMEM_UNUSE(&bindio.rule,
                                    TOSA(&bindio.control.raddr),
                                    sockscf.shmemfd,
                                    SHMEM_ALL);
                        continue;
                  }

                  rc = -1;
                  break; /* errno is not ok. */
               }

               setsockoptions(sv[reply], SOCK_STREAM, 1);
               setconfsockoptions(sv[client],
                                  sv[reply],
                                  bindio.state.protocol,
                                  1,
                                  bindio.rule.socketoptionc,
                                  bindio.rule.socketoptionv,
                                  SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                                  SOCKETOPT_PRE | SOCKETOPT_ANYTIME);

               replyaddr                  = io.control.laddr;
               TOIN(&replyaddr)->sin_port = htons(0);

               if (sockd_bind(sv[reply], TOSA(&replyaddr), 0) != 0) {
                  if (bindio.rule.log.error)
                     swarn("%s: sockd_bind(%s)", function,

                  sockaddr2string(TOSA(&replyaddr), strhost, sizeof(strhost)));

                  rc = -1;
                  break;
               }

               bindio.dst.laddr = replyaddr;

               slog(LOG_DEBUG, "%s: connecting to %s",
                    function,
                    sockshost2string(&bindreplydst, strhost, sizeof(strhost)));

               if (socks_connecthost(sv[reply],
                                     &bindreplydst,
                                     NULL,
                                     bindio.rule.timeout.connect ?
                                     (long)bindio.rule.timeout.connect : -1,
                                     emsg,
                                     sizeof(emsg))
                                     != 0) {
                  snprintf(msg, sizeof(msg), "connect() to %s failed: %s",
                           sockshost2string(&bindreplydst, NULL, 0), emsg);

                  iolog(&bindio.rule,
                        &bindio.state,
                        OPERATION_ERROR,
                        &dst,
                        &src,
                        NULL,
                        NULL,
                        msg,
                        0);

                  /* log the close of the opened bind session also. */
                  iolog(&io.rule,
                        &io.state,
                        OPERATION_DISCONNECT,
                        &src,
                        &dst,
                        NULL,
                        NULL,
                        NULL,
                        0);


                  rc = -1;
                  break;
               }

               setconfsockoptions(sv[client],
                                  sv[reply],
                                  bindio.state.protocol,
                                  1,
                                  bindio.rule.socketoptionc,
                                  bindio.rule.socketoptionv,
                                  SOCKETOPT_POST,
                                  SOCKETOPT_POST);

               if (replyredirect) {
                  close(sv[client]);
                  sv[client] = sv[reply];
                  sv[reply]  = -1;
               }
            }

            if (bindio.state.extension.bind) {
               /*
                * flushio() will close all descriptors set in io packet,
                * so dup what we need to keep going.
                */

               if ((bindio.control.s = dup(sv[childpipe])) == -1) {
                  switch (errno) {
                     case EMFILE:
                     case ENFILE:
                        if (bindio.rule.log.error)
                           swarn("%s: dup()", function);

                        ++emfile;
                        close(sv[remote]);
                        continue;

                     default:
                        SERR(bindio.control.s);
                  }
               }
            }
            else
               bindio.control.s = sv[client];

            /* back to blocking. */
            if (fcntl(sv[remote], F_SETFL, flags) == -1) {
               if (bindio.rule.log.error)
                  swarn("%s: fcntl()", function);

               rc = -1;
               break;
            }

            if (bindio.state.extension.bind || replyredirect) {
               if (bindio.state.extension.bind)
                  bindio.dst.s = sv[reply];
               else /* replyredirect */
                  bindio.dst.s = sv[client];
            }
            else
               bindio.dst = io.src;

            bindio.src.s     = sv[remote];
            bindio.src.laddr = bound;

            if (bindio.state.extension.bind)
               /* add to list, client will query. */
               iolist = io_add(iolist, &bindio);
            else {
               response.host = bindio.src.host;

               if (send_response(sv[client], &response) != 0) {
                  close_iodescriptors(&io);
                  rc = -1;
               }
               else {
                  bindio.dst.state.connected = 1;
                  bindio.reqinfo.command = (bindio.state.protocol == SOCKS_TCP ?
                                       SOCKD_FREESLOT_TCP : SOCKD_FREESLOT_UDP);
                  flushio(mother->s, &bindio);
               }

               /* flushio() closes these, not closev(). */
               sv[client] = sv[remote] = -1;

               /* only one connection to relay and that is sent to iochild. */
               break;
            }
         }

         close(out); /* not accepting any more connections on this socket. */

         if (bindio.state.extension.bind) {
            sockd_io_t *rmio;

            /* delete any connections we have queued. */
            while ((rmio = io_find(iolist, NULL)) != NULL) {
               close_iodescriptors(rmio);
               iolist = io_remove(iolist, rmio);
            }
         }

         closev(sv, ELEMENTS(sv));
         break;
      }
#endif /* SOCKS_SERVER */

      case SOCKS_CONNECT: {
         char emsg[256];

         if ((p = socks_connecthost(out,
                                    &io.dst.host,
                                    TOSA(&io.dst.raddr),
                                    0, /* wait for completion in i/o child. */
                                    emsg,
                                    sizeof(emsg))) == -1
         && errno == EINPROGRESS)
            /*
             * don't wait for the result, push the io object on and and hope
             * the best.  This allows the connect(2) time to overlap with the
             * sending of the io-object to the io-process.
             */
            p = 0;

         if (p != 0) {
            snprintf(msg, sizeof(msg), "connect() failed: %s", emsg);
            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);

            send_failure(request->s,
                         &response, errno2reply(errno,
                         response.version));

            close(request->s);
            close(out);

            rc = -1;
            break;
         }

         SASSERTX(io.state.proxyprotocol == PROXY_DIRECT);
         io.src = io.control;
         io.reqinfo.command = (io.state.protocol == SOCKS_TCP ?
                                    SOCKD_FREESLOT_TCP : SOCKD_FREESLOT_UDP);

         flushio(mother->s, &io);
         break;
      }

#if SOCKS_SERVER || BAREFOOTD
      case SOCKS_UDPASSOCIATE: {
         struct sockaddr_storage client;
         socklen_t boundlen;
         int clientfd, rc;
#if !BAREFOOTD
         int triesleft;
#endif /* !BAREFOOTD */

#if BAREFOOTD
         dst.local_isset = 0; /* will be set when we add a client. */
#endif /* BAREFOOTD */

         /* socket we will receive datagrams from client on */
         if ((clientfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            snprintf(msg, sizeof(msg), "could not create socket(): %s",
                     strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(out);

            rc = -1;
            break;
         }

         setsockoptions(clientfd, SOCK_DGRAM, 1);
         setconfsockoptions(clientfd,
                            io.control.s,
                            io.state.protocol,
                            1,
                            io.rule.socketoptionc,
                            io.rule.socketoptionv,
                            SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                            SOCKETOPT_PRE | SOCKETOPT_ANYTIME);

         sockshost2sockaddr(&request->req.host, TOSA(&client));
         io.src.s     = clientfd;
         io.src.laddr = request->to;
         io.src.raddr = client;

#if BAREFOOTD
       rc = sockd_bind(clientfd, TOSA(&io.src.laddr), 1);
#else /* SOCKS_SERVER */

         /*
          * bind client-side address for receiving UDP packets, so we can tell
          * the client where to send it's packets.
          * XXX add check for privileges on startup if range is privileged
          */
         if (io.rule.udprange.op == range)
            triesleft = MIN(10,
            ntohs(io.rule.udprange.end) - ntohs(io.rule.udprange.start) + 1);
         else
            triesleft = 1;

         do {
            if (io.rule.udprange.op == range) {
               /*
                * First try to select a random port in range.
                */

               TOIN(&io.src.laddr)->sin_port
               = htons(ntohs(io.rule.udprange.start)
               + (random() % (  ntohs(io.rule.udprange.end)
                              - ntohs(io.rule.udprange.start) + 1)));

               slog(LOG_DEBUG,
                    "%s: random port selected for udp in range %u - %u: %u",
                    function,
                    ntohs(io.rule.udprange.start), ntohs(io.rule.udprange.end),
                    ntohs(TOIN(&io.src.laddr)->sin_port));
            }
            else
               TOIN(&io.src.laddr)->sin_port = htons(0);

            rc = sockd_bind(clientfd, TOSA(&io.src.laddr), 0);
         } while (rc == -1 && (errno == EADDRINUSE || ERRNOISACCES(errno))
         && io.rule.udprange.op == range && --triesleft > 0);
#endif /* SOCKS_SERVER */

         if (rc != 0 && io.rule.udprange.op != none) {
            /*
             * Sigh.  No luck.  Will need to try every port in range.
             */

            slog(LOG_DEBUG, "%s: failed to bind udp port in range %u - %u by "
                            "random selection.  Doing a sequential search ...",
                            function,
                            ntohs(io.rule.udprange.start),
                            ntohs(io.rule.udprange.end));

            rc = sockd_bindinrange(clientfd, TOSA(&io.src.laddr),
            io.rule.udprange.start, io.rule.udprange.end, io.rule.udprange.op);
         }

         if (rc != 0) {
            snprintf(msg, sizeof(msg), "bind(%s) failed: %s",
                     sockaddr2string(TOSA(&io.src.laddr),
                     strhost,
                     sizeof(strhost)),
                     strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(clientfd);
            close(out);

            rc = -1;
            break;
         }

         if (ADDRISBOUND(TOIN(&io.src.raddr))
         &&  PORTISBOUND(TOIN(&io.src.raddr))) {
            slog(LOG_DEBUG, "%s: connecting to udp client at address %s",
            function, sockaddr2string(TOSA(&io.src.raddr), NULL, 0));

            /* faster and better. */
            if (connect(io.src.s,
                        TOSA(&io.src.raddr),
                        sockaddr2salen(TOSA(&io.src.raddr))) != 0) {
               snprintf(msg, sizeof(msg),
                        "udp client said it's address is %s, but connect(2) "
                        "to that address failed: %s",
                        sockaddr2string(TOSA(&io.src.raddr), NULL, 0),
                        strerror(errno));

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &src,
                     &dst,
                     NULL,
                     NULL,
                     msg,
                     0);

               send_failure(request->s, &response, SOCKS_FAILURE);
               close(request->s);
               close(clientfd);
               close(out);

               rc = -1;
               break;
            }

            io.src.state.connected = 1;
         }

         boundlen = sizeof(io.src.laddr);
         if (getsockname(clientfd, TOSA(&io.src.laddr), &boundlen) != 0) {
            snprintf(msg, sizeof(msg), "getsockname() failed: %s",
            strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  msg,
                  0);

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(clientfd);
            close(out);

            rc = -1;
            break;
         }

         slog(LOG_DEBUG, "%s: address bound on client side for udp: %s",
              function, sockaddr2string(TOSA(&io.src.laddr), NULL, 0));

         /* remote out can change each time, set to INADDR_ANY for now. */
         bzero(&io.dst.raddr, sizeof(io.dst.raddr));
         SET_SOCKADDR(TOSA(&io.dst.raddr), AF_INET);
         TOIN(&io.dst.raddr)->sin_addr.s_addr = htonl(INADDR_ANY);
         TOIN(&io.dst.raddr)->sin_port        = htons(0);

         if (request->req.flag & SOCKS_USECLIENTPORT
         &&  sockscf.compat.draft_5_05)
            /* LINTED pointer casts may be troublesome */
            if (TOIN(&client)->sin_port == TOIN(&io.dst.laddr)->sin_port)
               response.flag |= SOCKS_USECLIENTPORT;

         sockaddr2sockshost(TOSA(&io.src.laddr), &response.host);

         if (send_response(request->s, &response) == 0) {
            io.reqinfo.command = (io.state.protocol == SOCKS_TCP ?
                                       SOCKD_FREESLOT_TCP : SOCKD_FREESLOT_UDP);
            flushio(mother->s, &io);
         }
         else {
            close_iodescriptors(&io);
            rc = -1;
         }

         break;
      }
#endif /* SOCKS_SERVER || BAREFOOTD */

      default:
         SERRX(io.state.command);
   }

#if DIAGNOSTIC
   SASSERT(close(out) == -1 && errno == EBADF);
#endif /* DIAGNOSTIC */

   return rc;
}

static void
flushio(mother, io)
   int mother;
   sockd_io_t *io;
{
   const char *function = "flushio()";
   int sentio, dolog;

#if HAVE_GSSAPI
   if (io->control.auth.method == AUTHMETHOD_GSSAPI) {
      OM_uint32 minor_status, major_status, maxlen;
      char emsg[1024];

      major_status
      = gss_wrap_size_limit(&minor_status,
                            io->control.auth.mdata.gssapi.state.id,
                            io->control.auth.mdata.gssapi.state.protection
                            == GSSAPI_CONFIDENTIALITY ?
                              GSS_REQ_CONF : GSS_REQ_INT,
                            GSS_C_QOP_DEFAULT,
                            (OM_uint32)(MAXGSSAPITOKENLEN - GSSAPI_HLEN),
                            &maxlen);

      if (gss_err_isset(major_status, minor_status, emsg, sizeof(emsg)))
         serrx(EXIT_FAILURE, "%s: gss_wrap_size_limit() failed: %s",
         function, emsg);

      if (maxlen == 0)
         serrx(EXIT_FAILURE, "%s: for a token of length %d, "
                             "gss_wrap_size_limit() returned %d.  "
                             "The kerberos library might not fully support "
                             "the configured encoding type",
                             function, MAXGSSAPITOKENLEN - GSSAPI_HLEN,
                             maxlen);

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: gss_wrap_size_limit() for socket %d is %lu",
              function, io->control.s, (unsigned long)maxlen);

      if (io->control.auth.method == AUTHMETHOD_GSSAPI)
         io->control.auth.mdata.gssapi.state.maxgssdata = maxlen;

      if (io->src.auth.method == AUTHMETHOD_GSSAPI)
         io->src.auth.mdata.gssapi.state.maxgssdata = maxlen;

      if (io->dst.auth.method == AUTHMETHOD_GSSAPI)
         io->dst.auth.mdata.gssapi.state.maxgssdata = maxlen;
   }
#endif /* HAVE_GSSAPI */

   if (io->state.command == SOCKS_CONNECT) {
      /*
       * Need to save all the socketoptions that we can not set now but
       * with which we must wait until the connection has been fully
       * established.  The i/o child will have to set them if the connect(2)
       * completes successfully.
       */
      size_t i;

      for (i = 0; i < io->rule.socketoptionc; ++i) {
         if (!io->rule.socketoptionv[i].isinternalside
         &&   (io->rule.socketoptionv[i].info == NULL
           ||  io->rule.socketoptionv[i].info->calltype == postonly)) {
            if (io->rule.socketoptionc >= ELEMENTS(io->extsocketoptionv)) {
               swarnx("%s: one or more socket options from socks-rule #%lu "
                      "could not be set on socket %d because the hardcoded for "
                      "limit options that can be set on the external side is "
                      "%lu",
                      function,
                      (unsigned long)io->rule.number,
                      io->dst.s,
                      (unsigned long)ELEMENTS(io->extsocketoptionv));

               break;
            }

            io->extsocketoptionv[io->extsocketoptionc++]
            = io->rule.socketoptionv[i];
         }
      }
   }

   gettimeofday(&io->state.time.established, NULL);

   SASSERTX(io->crule.bw == NULL);
   SASSERTX(io->crule.ss == NULL);
   SASSERTX(io->rule.bw == NULL);
   SASSERTX(io->rule.ss == NULL);

   sentio = (send_io(mother, io) == 0);

   if (!sentio)
      dolog = 1; /* things failed.  Log it. */
   else if (io->state.command       == SOCKS_CONNECT
   &&       io->state.proxyprotocol == PROXY_DIRECT) {
      SASSERTX(!io->dst.state.connected);
      dolog = 0; /* don't know status yet.  I/O child will have to log it. */
   }
#if !HAVE_SOCKS_RULES
   else if (io->state.command == SOCKS_UDPASSOCIATE)
      dolog = 0; /* only log once we get a client. */
#endif /* !HAVE_SOCKS_RULES */
   else
      dolog = 1;

   if (dolog) {
      iologaddr_t src, dst, proxy;

      init_iologaddr(&src,
                     SOCKADDR_OBJECT,
                     &io->src.laddr,
                     SOCKSHOST_OBJECT,
                     &io->src.host,
                     &io->src.auth,
                     GET_HOSTIDV(&io->state),
                     GET_HOSTIDC(&io->state));

      init_iologaddr(&dst,
                     SOCKADDR_OBJECT,
                     &io->dst.laddr,
                     SOCKSHOST_OBJECT,
                     &io->dst.host,
                     io->state.proxyprotocol == PROXY_DIRECT ?
                        &io->dst.auth : NULL,
                     NULL,
                     0);

      if (io->state.proxyprotocol != PROXY_DIRECT)
         init_iologaddr(&proxy,
                        SOCKADDR_OBJECT,
                        &io->dst.raddr,
                        SOCKSHOST_OBJECT,
                        &io->state.proxychain.extaddr,
                        &io->dst.auth,
                        NULL,
                        0);

      iolog(&io->rule,
            &io->state,
            sentio ? OPERATION_CONNECT : OPERATION_ERROR,
            &src,
            &dst,
            NULL,
            io->state.proxyprotocol == PROXY_DIRECT ? NULL : &proxy,
            NULL,
            0);
   }

   if (!sentio) {
#if HAVE_NEGOTIATE_PHASE
      response_t response;

      create_response(NULL,
                      &io->src.auth,
                      io->state.version,
                      errno2reply(errno, io->state.version),
                      &response);

      if (send_response(io->control.s, &response) != 0) {
         slog(LOG_DEBUG, "%s: send_response(%d) to %s failed: %s",
                         function,
                         io->control.s,
                         sockshost2string(&io->src.host, NULL, 0),
                         strerror(errno));
      }
#endif /* HAVE_NEGOTIATE_PHASE */
      slog(LOG_DEBUG,
           "%s: sending io to mother on socket %d failed: %s",
           function, mother, strerror(errno));
   }

   close_iodescriptors(io);
}

static void
proctitleupdate(from)
   const struct sockaddr *from;
{
   setproctitle("requestcompleter: %s", from == NULL ?  "0/1" : "1/1");
}

static int
serverchain(s, req, res, src, dst, proxyprotocol, proxychain)
   int s;
   const request_t *req;
   response_t *res;
   sockd_io_direction_t *src, *dst;
   int *proxyprotocol;
   proxychaininfo_t *proxychain;
{
   const char *function = "serverchain()";
   route_t *route;
   socks_t packet;
   int flags;

   *proxyprotocol = PROXY_DIRECT;

   if (sockscf.route == NULL) {
      errno = 0;
      return -1;
   }


   packet.req         = *req;
   packet.req.version = PROXY_DIRECT;

   bzero(&packet.state.auth, sizeof(packet.state.auth));
   packet.req.auth         = &packet.state.auth;
   packet.req.auth->method = AUTHMETHOD_NOTSET;

   if (socks_requestpolish(&packet.req, &src->host, &dst->host) == NULL) {
      if (packet.req.command    == SOCKS_CONNECT
      &&  packet.req.host.atype == SOCKS_ADDR_DOMAIN) {
         /*
          * Possibly there is a route supporting an ipaddress destination,
          * even if there was no route supporting a hostname destination
          * (e.g., only socks v4 route).  Therefor try resolving the
          * destination locally before giving up on finding a route.
          *
          * We will need to resolve the destination sooner or later
          * anyway, so if it's not already in our hostcache, there should
          * not be a big penalty incurred by adding it now before doing
          * a route lookup again.
          */
         sockshost_t resolvedhost;
         struct sockaddr_storage saddr;

         slog(LOG_DEBUG, "%s: no hostname-route for destination %s found.  "
                         "Trying to resolve and do route lookup again",
                         function, sockshost2string(&packet.req.host, NULL, 0));

         sockshost2sockaddr(&packet.req.host, TOSA(&saddr));

         if (!ADDRISBOUND(TOIN(&saddr)))
            return -1;

         sockaddr2sockshost(TOSA(&saddr), &resolvedhost);
         packet.req.host = resolvedhost;
         if (socks_requestpolish(&packet.req, &src->host, &dst->host)
         == NULL)
            return -1;
      }
      else
         return -1;
   }

   if (packet.req.version == PROXY_DIRECT) {
      slog(LOG_DEBUG, "%s: using direct system calls for socket %d",
      function, s);

      errno = 0;
      return -1;
   }

   errno = 0;
   if ((route = socks_connectroute(s, &packet, &src->host, &dst->host)) == NULL)
      return -1;

   /*
    * we're not interested the extra hassle of negotiating over
    * a non-blocking socket, so set it to blocking while we
    * use it.
    */
   if ((flags = fcntl(s, F_GETFL, 0))                  == -1
   ||           fcntl(s, F_SETFL, flags & ~O_NONBLOCK) == -1)
      swarn("%s: failed to set the socket to blocking via fcntl(2)", function);

   if (socks_negotiate(s, s, &packet, route) != 0) {
      slog(LOG_DEBUG, "%s: socks_negotiate() failed: %s",
           function, strerror(errno));

      return -1;
   }


   /* back to original. */
   if (flags != -1)
      if (fcntl(s, F_SETFL, flags) == -1)
         swarn("%s: failed to reset the flags via fcntl(2)", function);

   convertresponse(&packet.res, res, req->version);

   /* when we reply, we have to use our clients auth ... */
   res->auth = &src->auth;

   /* ... but when we talk to remote, we have to use remotes auth. */
   dst->auth = *packet.res.auth;

   *proxyprotocol     = (int)packet.req.version; /* req.  Res differs in v4. */

   switch (packet.req.command) {
      case SOCKS_CONNECT:
         proxychain->extaddr = packet.res.host;
         break;

      default:
         bzero(&proxychain->extaddr, sizeof(proxychain->extaddr));
         proxychain->extaddr.atype = SOCKS_ADDR_IPV4;
   }

   slog(LOG_DEBUG, "%s: extaddr is %s",
        function, sockshost2string(&proxychain->extaddr, NULL, 0));

   return 0;
}

static void
convertresponse(oldres, newres, newversion)
   const response_t *oldres;
   response_t *newres;
   const int newversion;
{
   const char *function = "convertresponse()";
   int genericreply;

   if ((newversion == PROXY_SOCKS_V4
      && oldres->version == PROXY_SOCKS_V4REPLY_VERSION)
   || (oldres->version == newversion)) {
      *newres = *oldres;
      return;
   }

   /*
    * first convert the genericreply code from whatever old version to the
    * corresponding socks v5 genericreply code.  Then convert from the
    * v5 replycode to whatever new version.
    */
   switch (oldres->version) {
      case PROXY_HTTP_10:
      case PROXY_HTTP_11:
         switch (oldres->reply.http) {
            case HTTP_SUCCESS:
               genericreply = SOCKS_SUCCESS;
               break;

            case HTTP_NOTALLOWED:
            case HTTP_FORBIDDEN:
            case HTTP_PROXYAUTHREQUIRED:
               genericreply = SOCKS_NOTALLOWED;
               break;

            case HTTP_HOSTUNREACH:
               genericreply = SOCKS_HOSTUNREACH;
               break;

            default:
               genericreply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_UPNP:
         switch (oldres->reply.upnp) {
            case UPNP_SUCCESS:
               genericreply = SOCKS_SUCCESS;
               break;

            default:
               genericreply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_SOCKS_V4REPLY_VERSION:
         switch (oldres->reply.socks) {
            case SOCKSV4_SUCCESS:
               genericreply = SOCKS_SUCCESS;
               break;

            case SOCKSV4_NO_IDENTD:
            case SOCKSV4_BAD_ID:
               genericreply = SOCKS_NOTALLOWED;
               break;

            default:
               genericreply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_SOCKS_V5: /* default; what we use as the generic replycode. */
         genericreply = oldres->reply.socks;
         break;

      default:
         swarnx("%s: unknown proxy protocol: %d", function, oldres->version);
         genericreply = SOCKS_FAILURE;
   }


   if (newversion == PROXY_SOCKS_V4) {
      if (oldres->host.atype != SOCKS_ADDR_IPV4) {
         /*
          * v4 only supports ipaddr, so if the address is not an IP address,
          * we need to resolve it before responding.
          */
         struct sockaddr_storage addr;

         sockshost2sockaddr(&oldres->host, TOSA(&addr));
         if (ADDRISBOUND(TOIN(&addr)))
            sockaddr2sockshost(TOSA(&addr), &newres->host);
         else {
            swarnx("%s: can not resolve %s",
                   function, sockshost2string(&oldres->host, NULL, 0));

            genericreply = SOCKS_FAILURE;
         }
      }

      newres->flag    = 0; /* no flagbits in v4. */
      newres->version = PROXY_SOCKS_V4REPLY_VERSION;
   }
   else {
      newres->host    = oldres->host;
      newres->version = newversion;
   }

   newres->auth = oldres->auth;
   socks_set_responsevalue(newres, sockscode(newversion, genericreply));

   slog(LOG_DEBUG, "%s: converted from version %d to version %d.  "
                   "Old response value was %d, new is %d",
                   function,
                   oldres->version,
                   newversion,
                   socks_get_responsevalue(oldres),
                   socks_get_responsevalue(newres));
}

/* ARGSUSED */
static void
siginfo(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "siginfo()";
   const int debug_s = sockscf.option.debug;
   unsigned long seconds, days, hours, minutes;
   time_t timenow;
   size_t i;

   if (sig > 0) {
      sockd_pushsignal(sig, sip);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, "%s: running due to previously received signal: %d",
        function, sig);

   seconds = ROUNDFLOAT(difftime(time(&timenow), sockscf.stat.boot));
   seconds2days(&seconds, &days, &hours, &minutes);

   sockscf.option.debug = 1;

   slog(LOG_DEBUG, "request-child up %lu day%s, %lu:%.2lu:%.2lu",
                   days, days == 1 ? "" : "s", hours, minutes, seconds);

   for (i = 0; i < reqc; ++i) {
      if (TOSA(&reqv[i].client)->sa_family == AF_UNSPEC)
         continue;

      slog(LOG_DEBUG, "%s: request in progress for %.0fs",
           sockaddr2string(TOSA(&reqv[i].client), NULL, 0),
           difftime(timenow, reqv[i].starttime));
   }

   sockscf.option.debug = debug_s;
}

#if HAVE_NEGOTIATE_PHASE
response_t *
create_response(host, auth, version, responsecode, response)
   const sockshost_t *host;
   authmethod_t *auth;
   const int version;
   const int responsecode;
   response_t *response;
{

   bzero(response, sizeof(*response));
   response->auth = auth;

   switch (version) {
#if SOCKS_SERVER
      case PROXY_SOCKS_V4:
         response->version = PROXY_SOCKS_V4REPLY_VERSION;
         break;

      case PROXY_SOCKS_V5:
#elif COVENANT /* !SOCKS_SERVER */
      case PROXY_HTTP_10:
      case PROXY_HTTP_11:
#endif /* COVENANT */
         response->version = version;
         break;

      default:
         SERRX(version);
   }

   if (host != NULL)
      response->host = *host;
   else
      response->host.atype = SOCKS_ADDR_IPV4;
      /* rest can be 0. */

   socks_set_responsevalue(response,
                           sockscode(version, responsecode));

   return response;
}
#endif /* HAVE_NEGOTIATE_PHASE */

#if SOCKS_SERVER
static sockd_io_t *
io_add(iolist, newio)
   sockd_io_t *iolist;
   const sockd_io_t *newio;
{
   const char *function = "io_add()";
   sockd_io_t *io, *previo;

   SASSERTX(newio->next == NULL);

   previo = io = iolist;
   while (io != NULL) {
      previo = io;
      io = io->next;
   }

   if ((io = malloc(sizeof(*newio))) == NULL)
      swarnx("%s: %s", function, NOMEM);
   else {
      *io = *newio;

      if (previo == NULL)
         previo = io;
      else
         previo->next = io;
   }

   return iolist == NULL ? previo : iolist;
}

static sockd_io_t *
io_remove(iolist, rmio)
   sockd_io_t *iolist;
   sockd_io_t *rmio;
{
   sockd_io_t *io, *previo;

   SASSERTX(iolist != NULL);

   if (iolist == rmio) {
      iolist = rmio->next;
      free(rmio);
      return iolist;
   }

   previo = iolist;
   io = iolist->next;
   while (io != NULL) {
      if (io == rmio) {
         previo->next = rmio->next;
         free(rmio);
         break;
      }

      previo = io;
      io = io->next;
   }

   return iolist;
}

static sockd_io_t *
io_find(iolist, addr)
   sockd_io_t *iolist;
   const struct sockaddr *addr;
{
   sockd_io_t *io;

   if (addr == NULL)
      return iolist;

   io = iolist;
   while (io != NULL)
      if (sockaddrareeq(TOSA(&io->src.laddr), addr)
      ||  sockaddrareeq(TOSA(&io->dst.laddr), addr)
      ||  sockaddrareeq(TOSA(&io->control.laddr), addr))
         return io;
      else
         io = io->next;

   return NULL;
}
#endif /* SOCKS_SERVER */
