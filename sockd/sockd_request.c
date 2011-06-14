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
#include "config_parse.h"

static const char rcsid[] =
"$Id: sockd_request.c,v 1.467 2011/06/09 09:47:03 michaels Exp $";

/*
 * Since it only handles one client at a time there is no possibility
 * for the mother to send a new client before we have got rid of the
 * old one and thus no need for locking even on broken systems.
 * (#ifdef HAVE_SENDMSG_DEADLOCK)
 * XXX Should fix things so this process too can support multiple clients.
 * Will also fix the terrible fact that we just sit around and wait if the
 * command is bind, wasting the whole process on practically nothing.
 */

static void siginfo(int sig, siginfo_t *sip, void *scp);

static void
convertresponse(const struct response_t *oldres, struct response_t *newres,
             const int newversion);
/*
 * Converts a response on form "oldres", using oldres->version,
 * to a new response on form "newversion".
 */

static int
dorequest(int mother, struct sockd_request_t *request);
/*
 * When a complete request has been read, this function can be
 * called.  It will perform the request "request->req" and send the
 * result to "mother".
 * Returns:
 *    If request was successfully completed: 0.
 *    If request was blocked or there was an error: -1.
 */

static void
flushio(int mother, struct sockd_io_t *io);
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
serverchain(int s, const struct request_t *req, struct response_t *res,
      struct sockd_io_direction_t *src, struct sockd_io_direction_t *dst,
      int *proxyprotocol, proxychaininfo_t *proxychain);
/*
 * Checks if we should create a serverchain on socket "s" for the request
 * "req".  If a serverchain was created, the proxyprotocol used in that
 * chain is set in "proxyprotocol", and the futher information is provded
 * in "proxychain".  Otherwise, proxyprotocol is set to PROXY_DIRECT.

 * Returns:
 *       0: Serverchain established successfully.
 *      -1: No serverchain established.  If errno set, it indicates the reason.
 *          If errno is not set, no route exists to handle this connection,
 *          and it should be direct.
 */


#if SOCKS_SERVER
static struct sockd_io_t *
io_add(struct sockd_io_t *iolist, const struct sockd_io_t *newio);
/*
 * Adds _a copy_ of the object "newio" to the list "iolist".
 * Returns a pointer to the (new) iolist.
 */

static struct sockd_io_t *
io_remove(struct sockd_io_t *iolist, struct sockd_io_t *rmio);
/*
 * Removes the object "rmio" from the list "iolist".
 * Returns a pointer to the (new) iolist.
 */

static struct sockd_io_t *
io_find(struct sockd_io_t *iolist, const struct sockaddr *addr);
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
   struct sockd_request_t req;
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

   proctitleupdate(NULL);

   rset  = allocate_maxsize_fdset();
   req.s = -1;

   /* CONSTCOND */
   while (1) {
      /*
       * Get request from mother, perform it, get next request.
       */
      int fdbits;
      char command;
#if DIAGNOSTIC
   const int freec = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif /* DIAGNOSTIC */

      errno = 0; /* reset for each iteration. */

      proctitleupdate(NULL);

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
            function, errnostr(errno));

             continue;
          }
      }

#if !BAREFOOTD /* doesn't need buffer in the request process. */
      socks_allocbuffer(req.s, SOCK_STREAM);
#endif /* BAREFOOTD */

      if (dorequest(sockscf.state.mother.s, &req) == -1) {
         /*
          * log the client-rule close also, if appropriate, as this
          * will not be logged on the normal session-close in the i/o 
          * process because the session was not successfully established.
          */
         struct sockshost_t from;

         slog(LOG_DEBUG, "%s: dorequest() failed", function);

         req.state.command = req.state.clientcommand = SOCKS_ACCEPT;
         iolog(&req.rule,
               &req.state,
               OPERATION_DISCONNECT,
               &req.to,
               sockaddr2sockshost(&req.from, &from),
               &req.clientauth,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               0);
      }

#if !BAREFOOTD /* doesn't need buffer in the request process. */
      socks_freebuffer(req.s);
#endif /* BAREFOOTD */

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

      if (socks_sendton(sockscf.state.mother.ack, &command, sizeof(command),
      sizeof(command), 0, NULL, 0, NULL) != sizeof(command))
         serr(EXIT_FAILURE, "%s: sending ack to mother failed", function);

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
   struct sockd_request_t *req;
{
   const char *function = "recv_req()";
#if HAVE_GSSAPI
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   struct iovec iov[2];
   struct msghdr msg;
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
      struct rule_t *rule;
      int foundtobounce = 0;

      bzero(req, sizeof(*req));

      for (rule = sockscf.srule; rule != NULL; rule = rule->next) {
         /*
          * We autogenerate the second-level socks-rule acl for udp
          * client-rules.
          */
         struct sockshost_t host;
         struct sockaddr addr;

         if (!rule->state.protocol.udp || rule->crule->bounced)
            continue;

         sockshost2sockaddr(ruleaddr2sockshost(&rule->crule->dst, &host,
                            SOCKS_UDP),
                            &addr);

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
                         sockaddr2string(&req->to, NULL, 0),
                         (unsigned long)rule->number);

         sockshost2sockaddr(ruleaddr2sockshost(&rule->src, &host, SOCKS_UDP),
         &req->from);

         req->rule                      = *rule->crule;

         req->clientauth.method         = AUTHMETHOD_NONE;
         req->socksauth.method          = AUTHMETHOD_NONE;
         req->s                         = -1;

         req->state.clientcommand       = SOCKS_ACCEPT;
         req->state.clientprotocol      = SOCKS_UDP;
         req->state.protocol            = SOCKS_UDP;

         req->req.version               = PROXY_SOCKS_V5;
         req->req.command               = SOCKS_UDPASSOCIATE;
         req->req.flag                  = 0;
         req->req.host.atype            = (unsigned char)SOCKS_ADDR_IPV4;
         req->req.host.addr.ipv4.s_addr = htonl(INADDR_ANY);
         req->req.host.port             = htons(0);
         req->req.auth                  = &req->socksauth;
         req->req.protocol              = SOCKS_UDP;

         /*
          * no negotiation going on here; what we want is what we get.
          */
         req->state.command = req->req.command;
         req->state.version = req->req.version;

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
            function, errnostr(errno));
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

#if BAREFOOTD
   if (req->req.command == SOCKS_UDPASSOCIATE)
      fdexpect = 0; /* no client yet. */
   else
      fdexpect = 1; /* client. */
#else /* SOCKS_SERVER */
   fdexpect = 1; /* client. */
#endif /* SOCKS_SERVER */

   CMSG_VERIFY_RCPTLEN(msg, sizeof(int) * fdexpect);

   SHMEM_CLEAR(&req->rule, 0);
#if COVENANT
   SHMEM_CLEAR(&req->srule, 0);
#endif

   fdreceived = 0;
   if (fdexpect > 0) {
      SASSERTX(fdexpect == 1);
      CMSG_GETOBJECT(req->s, cmsg, sizeof(req->s) * fdreceived++);

      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: received socket %d (%s) ...",
         function, req->s, socket2string(req->s, NULL, 0));
   }

   req->req.auth = &req->socksauth; /* pointer fixup */

#if HAVE_GSSAPI
   if (req->req.auth->method == AUTHMETHOD_GSSAPI) {
      gss_buffer_desc gssapistate;

      r -= sizeof(*req);
      SASSERTX(r > 0);

      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: read gssapistate of size %d", function, r);

      gssapistate.value  = gssapistatemem;
      gssapistate.length = r;

      if (gssapi_import_state(&req->req.auth->mdata.gssapi.state.id,
      &gssapistate) != 0)
         return -1;
   }
#endif /* HAVE_GSSAPI */

   if (sockscf.option.debug > 1)
      slog(LOG_DEBUG, "%s: received %d descriptors for request with method %d, "
                      "req->s = %d",
                      function, fdreceived, req->req.auth->method, s);

   return 0;
}

static int
dorequest(mother, request)
   int mother;
   struct sockd_request_t *request;
{
   const char *function = "dorequest()";
   static struct sockd_io_t ioinit;
   struct sockaddr bound;
   struct sockd_io_t io;
   struct response_t response;
#if SOCKS_SERVER
   struct sockshost_t expectedbindreply, bindreplydst;
#endif /* SOCKS_SERVER */
   char strhost[MAXSOCKSHOSTSTRING], msg[256] = { NUL };
   int p, permit, out, rc;

   if (sockscf.option.debug)
      slog(LOG_DEBUG,
           "request received, %s -> %s, authmethod: %s, %s, "
           "bw_shmid: %ld (%p), ss_shmid: %ld (%p)",
           sockaddr2string(&request->from, strhost, sizeof(strhost)),
           sockaddr2string(&request->to, NULL, 0),
           method2string(request->req.auth->method),
           socks_packet2string(&request->req, 1),
           request->rule.bw_shmid, request->rule.bw,
           request->rule.ss_shmid, request->rule.ss);

   proctitleupdate(&request->from);

   bzero(&response, sizeof(response));
   response.host   = request->req.host;
   response.auth   = request->req.auth;

   io              = ioinit;
   io.reqflags     = request->req.flags;
   io.state        = request->state;
   io.crule        = request->rule;

   io.clientauth   = request->clientauth;

   /*
    * Assign crule to rule for now, so we can call iolog() before
    * rulespermit() on errors.
    * Also, in the case of barefootd, since the only rule we have is
    * the client-rule, it remains like this.
    */
   io.rule       = io.crule;
#if BAREFOOTD
   io.rule.crule = &io.crule;
#endif /* BAREFOOTD */

   /*
    * But not shmem stuff; will inherit from client-rule later if appropriate.
    */
   SHMEM_CLEAR(&io.rule, 1);

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

   sockaddr2sockshost(&request->from, &io.control.host);
   io.control.s       = request->s;
   io.control.laddr   = request->to;
   io.control.raddr   = request->from;
   io.control.auth    = *request->req.auth;

   io.dst.auth.method = AUTHMETHOD_NOTSET; /* at least so far. */

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
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d atype: %d",
               sockaddr2string(&request->from, strhost, sizeof(strhost)),
               request->req.version, request->req.host.atype);

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &io.control.laddr,
                     &io.control.host,
                     &io.control.auth,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

               send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           &(TOIN(&io.control.raddr)->sin_addr),
                           sockscf.shmemfd);

               return -1;
         }

         /* recognized command for this version? */
         switch (request->req.command) {
            case SOCKS_BIND:
            case SOCKS_CONNECT:
               io.state.protocol = SOCKS_TCP;
               break;

            default:
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d command: %d",
                      sockaddr2string(&request->from, strhost, sizeof(strhost)),
                      request->req.version,
                      request->req.command);

               io.state.command = SOCKS_UNKNOWN;
               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &io.control.laddr,
                     &io.control.host,
                     &io.control.auth,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

               send_failure(request->s, &response, SOCKS_CMD_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           &(TOIN(&io.control.raddr)->sin_addr),
                           sockscf.shmemfd);

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
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d atype: %d",
                      sockaddr2string(&request->from, strhost, sizeof(strhost)),
                      request->req.version,
                      request->req.host.atype);

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &io.control.laddr,
                     &io.control.host,
                     &io.control.auth,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

               send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           &(TOIN(&io.control.raddr)->sin_addr),
                           sockscf.shmemfd);

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
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d command: %d",
                      sockaddr2string(&request->from, strhost, sizeof(strhost)),
                      request->req.version,
                      request->req.command);

               io.state.command = SOCKS_UNKNOWN;
               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &io.control.laddr,
                     &io.control.host,
                     &io.control.auth,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

               send_failure(request->s, &response, SOCKS_CMD_UNSUPP);

               close(request->s);
               SHMEM_UNUSE(&io.crule,
                           &(TOIN(&io.control.raddr)->sin_addr),
                           sockscf.shmemfd);

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
    * packet looks ok, fill in remaining bits and check rules.
    */

   switch (request->req.command) {
#if SOCKS_SERVER
      case SOCKS_BIND:
         /*
          * bind is a bit funky.  We first need to check if the bind request
          * is allowed, and then we transform io.dst to something completely
          * different to check if the bindreply is allowed.
          * For the bind request, the ip address given is the host the client
          * previously issued a connect to, more or less.  What we
          * want to check first is whether the rules permit the client
          * to bind some port, if it's a socks v4 request, or the port, if
          * it's a socks v5 request.
          *
          * Thus the src is the client address, the dst should be the address
          * bound for the client.
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

         TOIN(&io.src.laddr)->sin_family      = AF_INET;
         TOIN(&io.src.laddr)->sin_addr.s_addr = htonl(INADDR_ANY);
         TOIN(&io.src.laddr)->sin_port        = htons(0);

         io.src.host                          = request->req.host;
         sockshost2sockaddr(&io.src.host, &io.src.raddr);

#if BAREFOOTD /* fixed destination. */
         ruleaddr2sockshost(&io.crule.bounce_to, &io.dst.host, SOCKS_UDP);
#else /* SOCKS_SERVER */
         /*
          * for UDP_ASSOCIATE we are getting clients UDP address,
          * not destination in request. Destination address will be
          * checked in the i/o loop for each destination for each packet.
          * For now just set it to INADDR_ANY.
          */

         io.dst.host.atype            = SOCKS_ADDR_IPV4;
         io.dst.host.addr.ipv4.s_addr = htonl(INADDR_ANY);
         io.dst.host.port             = htons(0);
#endif /* SOCKS_SERVER */
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

   if (out == -1) {
      iolog(&io.rule,
            &io.state,
            OPERATION_ERROR,
            &io.src.laddr,
            &io.src.host,
            &io.src.auth,
            NULL,
            NULL,
            NULL,
            NULL,
            &io.dst.host,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            0);

      send_failure(request->s, &response, SOCKS_FAILURE);
      close(request->s);

      SHMEM_UNUSE(&io.crule,
                  &(TOIN(&io.control.raddr)->sin_addr),
                  sockscf.shmemfd);

      return -1;
   }

   setsockoptions(out,
                  io.state.protocol == SOCKS_TCP ? SOCK_STREAM : SOCK_DGRAM,
                  0);

   bzero(&bound, sizeof(bound));

   /*
    * Find address to bind on clients behalf.
    * First, the IP address ...
   */
   switch (request->req.command) {
      case SOCKS_BIND:
      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE: /* dst is 0.0.0.0. */
         TOIN(&bound)->sin_addr = getoutaddr(TOIN(&request->to)->sin_addr,
                                             io.dst.host.addr.ipv4);
         break;

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
          * Unfortunately, this is a mixmash of different interpretations.
          *
          * The socks v5 standard is pretty strict about the meaning,
          * and the v4 standard even more so.
          * Unfortunately, the meaning given in these standard provides
          * only limited usability, so people "interpret" the standards
          * more loose to get a more practical functionality out of them.
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
            io.dst.host.addr.ipv4 = TOCIN(&request->from)->sin_addr;
            bindreplydst      = io.dst.host;
            bindreplydst.port = io.dst.host.port;
         }

         if (io.state.extension.bind) {
            /* LINTED pointer casts may be troublesome */
            TOIN(&bound)->sin_port = TOCIN(&request->from)->sin_port;
            expectedbindreply.addr.ipv4.s_addr = htonl(INADDR_ANY);
         }
         else {
            if (io.dst.host.addr.ipv4.s_addr == htonl(0))
               expectedbindreply.addr.ipv4.s_addr = htonl(0);
            else
               expectedbindreply = io.dst.host;

            expectedbindreply.port = htons(0);

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
   TOIN(&bound)->sin_family = AF_INET;
   if ((p = sockd_bind(out, &bound, 0)) != 0) {
      /* no such luck.  Bind any port and let client decide if ok. */

      /* LINTED pointer casts may be troublesome */
      TOIN(&bound)->sin_port = htons(0);

      if ((p = sockd_bind(out, &bound, 0)) == 0)
         slog(LOG_DEBUG, "%s: bound different port than desired (bound %s)\n",
         function, sockaddr2string(&bound, NULL, 0));
      else
         swarn("%s: this is certainly strange ... failed to bind "
               "port 0 (%s) also",
               function, sockaddr2string(&bound, NULL, 0));
   }

   if (p != 0) {
      iolog(&io.rule,
            &io.state,
            OPERATION_ERROR,
            &io.src.laddr,
            &io.src.host,
            &io.src.auth,
            NULL,
            NULL,
            NULL,
            NULL,
            &io.dst.host,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            0);

      send_failure(request->s, &response, errno2reply(errno, response.version));

      close(request->s);
      close(out);
      SHMEM_UNUSE(&io.crule,
                  &(TOIN(&io.control.raddr)->sin_addr),
                  sockscf.shmemfd);

      return -1;
   }

   io.dst.laddr = bound;
   io.dst.s     = out;

   if (BAREFOOTD && io.state.protocol == SOCKS_UDP)
      /*
       * dst.s is just a dummy socket used for select(2), the real
       * socket will be created in the i/o process when we actually
       * get a real client.
       */
      ;
   else
      slog(LOG_DEBUG, "%s: bound address on external side is %s",
           function, sockaddr2string(&bound, NULL, 0));

   /*
    * rules permit?
    */
   switch (request->req.command) {
      case SOCKS_BIND:
      case SOCKS_CONNECT:
#if HAVE_TWO_LEVEL_ACL
         permit = rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &io.clientauth,
                              &io.src.auth,
                              &io.rule,
                              &io.state,
                              &io.src.host,
                              &io.dst.host,
                              msg,
                              sizeof(msg));
#else /* !HAVE_TWO_LEVEL_ACL */
         permit = 1;
#endif /* !HAVE_TWO_LEVEL_ACL */
         break;

      case SOCKS_UDPASSOCIATE: {
#if HAVE_TWO_LEVEL_ACL
         struct sockshost_t *src;
         struct connectionstate_t replystate;
         struct authmethod_t replyauth;

         /*
          * Client is allowed to send a "incomplete" address, but if it has
          * not done that, the address it sent is the fixed source address.
          * Destination address can vary for each packet, so NULL
          * for now.
          */
         if (io.src.host.atype             == SOCKS_ADDR_IPV4
         && ( io.src.host.addr.ipv4.s_addr == htonl(0)
           || io.src.host.port             == htons(0)))
            src = NULL;
         else
            src = &io.src.host;

         /*
          * make a temp to check for i/o both ways.
          */
         replystate         = io.state;
         replystate.command = SOCKS_UDPREPLY;

         bzero(&replyauth, sizeof(replyauth));
         replyauth.method   = AUTHMETHOD_NOTSET;

         /*
          * if we can do i/o in only one direction that is enough, though
          * it could also be a configuration error.
          */
         permit = rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &io.clientauth,
                              &io.control.auth,
                              &io.rule,
                              &io.state,
                              src,
                              NULL,
                              msg,
                              sizeof(msg))
         ||       rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &io.clientauth,
                              &replyauth,
                              &io.rule,
                              &replystate,
                              NULL,
                              src,
                              msg,
                              sizeof(msg));
#else /* !HAVE_TWO_LEVEL_ACL */
         permit = 1;
#endif /* !HAVE_TWO_LEVEL_ACL */

         break;
      }

      default:
         SERRX(request->req.command);
   }

#if !HAVE_TWO_LEVEL_ACL
   /*
    * copy over auth from first level.
    */
    io.src.auth = io.control.auth = io.clientauth;
#endif /* !HAVE_TWO_LEVEL_ACL */


   /*
    * Check session-limit here so we can know before iolog().  No point
    * in logging that rulespermit() passed if the session-limit denies.
    */
   if (permit && io.rule.ss_shmid != 0) { /* don't bother if rules deny. */
      sockd_shmat(&io.rule, SHMEM_SS);
      if (!session_use(io.rule.ss, sockscf.shmemfd)) {
         permit          = 0;
         io.rule.verdict = VERDICT_BLOCK;

         snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
      }
      sockd_shmdt(&io.rule, SHMEM_SS);
   }

   if (!permit) {
      iolog(&io.rule,
            &io.state,
            OPERATION_CONNECT,
            &io.src.laddr,
            &io.src.host,
            &io.src.auth,
            NULL,
            NULL,
            NULL,
            &io.dst.laddr,
            &io.dst.host,
            NULL,
            NULL,
            NULL,
            NULL,
            msg,
            strlen(msg));

      SHMEM_UNUSE(&io.crule,
                  &(TOIN(&io.control.raddr)->sin_addr),
                  sockscf.shmemfd);

      send_failure(request->s, &response, SOCKS_NOTALLOWED);
      close(request->s);
      close(out);

      return -1;
   }

   /*
    * Some stuff can be inherited from client-rule by socks-rule.
    */

   /*
    * Bandwidth.  If it's set in the client-rule, let the socks-rule
    * inherit it.
    */
   if (io.crule.bw_shmid == 0) {
      if (io.rule.bw_shmid != 0) {
         sockd_shmat(&io.rule, SHMEM_BW);
         bw_use(io.rule.bw, sockscf.shmemfd);
         sockd_shmdt(&io.rule, SHMEM_BW);
      }
   }
   else {
      /*
       * client-rule is not used anymore after the matching socks-rule
       * has been determined, except for possible logging related to
       * disconnect, so copy over what we need from client-rule to
       * the socks-rule and then use the socks-rule from now on.
       */
      if (io.rule.bw_shmid == 0) {
         slog(LOG_DEBUG, "%s: socks-rule #%lu inherits bandwidth-limit "
                         "from client-rule #%lu",
                         function,
                         (unsigned long)io.crule.number,
                         (unsigned long)io.rule.number);

         io.rule.bw_shmid  = io.crule.bw_shmid;
         io.crule.bw_shmid = 0;
      }
      else {
         sockd_shmat(&io.crule, SHMEM_BW);
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
         bw_use(io.rule.bw, sockscf.shmemfd);

         sockd_shmdt(&io.crule, SHMEM_BW);
         sockd_shmdt(&io.rule, SHMEM_BW);
      }
   }

   /*
    * Session.  Client-rule limits sessions client-rules apply to (i.e.,
    * negotiate), while socks-rule limits session socks-rules apply to.
    */

#if !SOCKS_SERVER
   /*
    * Normally not inheritable, but for barefoot/covenant, it can only be
    * set in what corresponds to a client-rule, so it has to be inheritable,
    * and the client-rule reference has to be NULL-ed after it's inherited.
    */
   if (io.crule.ss_shmid != 0) {
      slog(LOG_DEBUG, "%s: socks-rule #%lu inherits session-limit %ld (%p)"
                      "from client-rule #%lu",
                      function,
                      (unsigned long)io.rule.number,
                      io.crule.ss_shmid, io.crule.ss,
                      (unsigned long)io.crule.number);

      io.rule.ss_shmid  = io.crule.ss_shmid;
      io.crule.ss_shmid = 0;
   }
#else /* SOCKS_SERVER */
   if (io.crule.ss_shmid != 0 && io.rule.ss_shmid == 0)
      slog(LOG_DEBUG, "%s: client has a session-limit in client-rule "
                      "#%lu, but that does not affect socks-rule #%lu, "
                      "because session-limits are not inherited",
                      function,
                      (unsigned long)io.crule.number,
                      (unsigned long)io.rule.number);
#endif /* SOCKS_SERVER */

   /*
    * Redirection.
    */
   switch (request->req.command) {
      /* only meaningful to inherit for these. */
      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE:
         if (io.crule.rdr_from.atype != SOCKS_ADDR_NOTSET) {
            if (io.rule.rdr_from.atype == SOCKS_ADDR_NOTSET) {
               slog(LOG_DEBUG, "%s: socks-rule #%lu inherits redirection "
                               "from %s from client-rule #%lu",
                               function,
                               (unsigned long)io.crule.number,
                               ruleaddr2string(&io.crule.rdr_from, NULL, 0),
                               (unsigned long)io.rule.number);

               io.rule.rdr_from = io.crule.rdr_from;
            }
            else {
               slog(LOG_DEBUG, "%s: client-rule #%lu has redirection from "
                               "%s, but overridden by socks-rule #%lu",
                               function,
                               (unsigned long)io.crule.number,
                               ruleaddr2string(&io.crule.rdr_from, NULL, 0),
                               (unsigned long)io.rule.number);
            }
         }
   }

   if (redirect(out,
                &bound,
                &io.dst.host,
                request->req.command,
                &io.rule.rdr_from,
                &io.rule.rdr_to) != 0) {
      SHMEM_UNUSE(&io.rule,
                  &(TOIN(&io.control.raddr)->sin_addr),
                  sockscf.shmemfd);

      if (io.rule.log.error) {
         snprintf(msg, sizeof(msg), "redirect() failed: %s", errnostr(errno));
         iolog(&io.rule,
                &io.state,
                OPERATION_ERROR,
                &io.src.laddr,
                &io.src.host,
                &io.src.auth,
                NULL,
                NULL,
                NULL,
                NULL,
                &io.dst.host,
                NULL,
                NULL,
                NULL,
                NULL,
                msg,
                strlen(msg));
      }

      send_failure(request->s, &response, errno2reply(errno, response.version));
      close(request->s);
      close(out);

      return -1;
   }

   io.dst.laddr = bound; /* in case redirect changed it. */

   if (serverchain(out,
                   &request->req,
                   &response,
                   &io.src,
                   &io.dst,
                   &io.state.proxyprotocol,
                   &io.state.proxychain) == 0) {
      int failed = 0;

      switch (io.state.command) {
         case SOCKS_CONNECT: {
            socklen_t sinlen;

            sinlen = sizeof(io.dst.raddr);
            if (getpeername(io.dst.s, &io.dst.raddr, &sinlen) != 0) {
               if (io.rule.log.error) {
                  snprintf(msg, sizeof(msg), "getpeername(io.dst.s) failed: %s",
                  strerror(errno));

                  iolog(&io.rule,
                        &io.state,
                        OPERATION_ERROR,
                        &io.src.laddr,
                        &io.src.host,
                        &io.src.auth,
                        NULL,
                        NULL,
                        NULL,
                        &io.dst.laddr,
                        &io.dst.host,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        msg,
                        strlen(msg));
               }

               send_failure(request->s, &response, SOCKS_FAILURE);
               close(request->s);
               failed = 1;

               break;
            }

            flushio(mother, &io);
            break;
         }

         default:
            SERRX(request->req.command);
      }

      close(out);

      if (failed) {
         SHMEM_UNUSE(&io.rule,
                     &(TOIN(&io.control.raddr)->sin_addr),
                     sockscf.shmemfd);
         return -1;
      }

      return 0;
   }
   else { /* no chain.  Error, or no route? */
      if (errno != 0) { /* error. */
         SHMEM_UNUSE(&io.rule,
                     &(TOIN(&io.control.raddr)->sin_addr),
                     sockscf.shmemfd);

         snprintf(msg, sizeof(msg), "serverchain failed: %s", strerror(errno));
         iolog(&io.rule,
               &io.state,
               OPERATION_ERROR,
               &io.src.laddr,
               &io.src.host,
               &io.src.auth,
               NULL,
               NULL,
               NULL,
               &io.dst.laddr,
               &io.dst.host,
               NULL,
               NULL,
               NULL,
               NULL,
               msg,
               strlen(msg));

         send_failure(request->s,
                      &response,
                      errno2reply(errno,
                      response.version));

         close(request->s);
         close(out);

         return -1;
      }

      /* else; not an error, no route.  Go direct. */
      io.state.proxyprotocol = PROXY_DIRECT;

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
         struct sockd_io_t *iolist;
         struct sockd_io_t bindio;         /* send this to iochild.  */
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

         if (listen(out, SOCKD_MAXCLIENTQUE) != 0) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "listen(out) failed: %s",
               strerror(errno));

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &io.src.laddr,
                     &io.src.host,
                     &io.src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &io.dst.laddr,
                     io.state.extension.bind ? NULL : &io.dst.host,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));
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
                     &io.src.laddr,
                     &io.src.host,
                     &io.src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &io.dst.laddr,
                     io.state.extension.bind ? NULL : &io.dst.host,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));
            }

            send_failure(sv[client], &response, SOCKS_FAILURE);
            close(out);
            closev(sv, ELEMENTS(sv));

            rc = -1;
            break;
         }

         sockaddr2sockshost(&io.dst.laddr, &response.host);

         if (io.state.extension.bind) {
            int pipev[2];

            /*
             * The problem is that both we and the process which receives
             * the io packet needs to know when the client closes it's
             * connection, but _we_ need to receive a query from the
             * client on the connection aswell, and the io process would
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
                     &io.src.laddr,
                     &io.src.host,
                     &io.src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &io.dst.laddr,
                     io.state.extension.bind ? NULL : &io.dst.host,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

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
            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &io.src.laddr, 
                  &io.src.host,
                  &io.src.auth,
                  NULL,
                  NULL,
                  NULL,
                  &io.dst.laddr,
                  io.state.extension.bind ? NULL : &io.dst.host,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  0);

            close(out);
            closev(sv, ELEMENTS(sv));

            rc = -1;
            break;
         }

         iolog(&io.rule,
               &io.state,
               OPERATION_CONNECT,
               &io.src.laddr,
               &io.src.host,
               &io.src.auth,
               NULL,
               NULL,
               NULL,
               &io.dst.laddr,
               io.state.extension.bind ? NULL : &io.dst.host,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               0);

         emfile = 0;
         iolist = NULL;

         bindio                   = io; /* quick init of most stuff. */
         bindio.state.command     = SOCKS_BINDREPLY;

         bindio.dst.host = bindreplydst;
         if (bindio.state.extension.bind) {
            sockshost2sockaddr(&bindio.dst.host, &bindio.dst.raddr);

            /* won't create socket for this til we connect to the client. */
            bzero(&bindio.dst.laddr, sizeof(bindio.dst.laddr));
            TOIN(&bindio.dst.laddr)->sin_family      = AF_INET;
            TOIN(&bindio.dst.laddr)->sin_addr.s_addr = htonl(INADDR_ANY);
            TOIN(&bindio.dst.laddr)->sin_port        = htons(0);
         }
         else
            bindio.dst.laddr           = io.src.laddr;

         bindio.dst.auth = io.src.auth;

         bindio.src.auth.method  = AUTHMETHOD_NOTSET;
         bindio.src.laddr        = bound;
         sockaddr2sockshost(&bindio.src.laddr, &bindio.src.host);

         /* don't know what peer will be til we accept(2) it. */
         bzero(&bindio.src.raddr, sizeof(bindio.src.raddr));
         TOIN(&bindio.src.raddr)->sin_family      = AF_INET;
         TOIN(&bindio.src.raddr)->sin_addr.s_addr = htonl(INADDR_ANY);
         TOIN(&bindio.src.raddr)->sin_port        = htons(0);

         /*
          * if we are using the bind extension, keep accepting connections
          * until client closes the control-connection.  If not, break
          * after the first.
          */
         while (1) {
            static fd_set *rset;
            struct ruleaddr_t ruleaddr;
            struct sockaddr remoteaddr;      /* remote address we accepted.   */
            struct sockaddr replyaddr;       /* address of bindreply socket.  */
            int replyredirect, fdbits = -1;

            if (rset == NULL)
               rset = allocate_maxsize_fdset();

            FD_ZERO(rset);

            /* some sockets change, most remain the same. */
            sv[reply]  = -1;
            sv[remote] = -1;

            FD_SET(sv[client], rset);
            fdbits = MAX(fdbits, sv[client]);

            FD_SET(mother, rset);
            fdbits = MAX(fdbits, mother);

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

            if (FD_ISSET(sockscf.state.mother.ack, rset)) {
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
               struct request_t query;
               struct response_t queryresponse;
               struct negotiate_state_t state;
               struct sockaddr queryaddr;

               bzero(&state, sizeof(state));
               bzero(&query, sizeof(query));
               bzero(&queryresponse, sizeof(queryresponse));

               query.auth         = request->req.auth;
               queryresponse.auth = query.auth;

               switch (p = recv_sockspacket(sv[client], &query, &state)) {
                  case -1:
                     iolog(&io.rule,
                           &io.state,
                           OPERATION_ERROR,
                           &io.src.laddr,
                           &io.src.host,
                           &io.src.auth,
                           NULL,
                           NULL,
                           NULL,
                           &io.dst.laddr,
                           io.state.extension.bind ? NULL : &io.dst.host,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           0);

                     p = -1; /* session ended. */
                     break;

                  case 0: {
                     char *msg = "client closed before bindreply was received";

                     iolog(&io.rule,
                           &io.state,
                           OPERATION_DISCONNECT,
                           &io.src.laddr,
                           &io.src.host,
                           &io.src.auth,
                           NULL,
                           NULL,
                           NULL,
                           &io.dst.laddr,
                           io.state.extension.bind ? NULL : &io.dst.host,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           msg,
                           strlen(msg));

                     p = -1; /* session ended. */
                     break;
                  }

                  default: {
                     struct sockd_io_t *fio;

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

                     sockshost2sockaddr(&query.host, &queryaddr);
                     if ((fio = io_find(iolist, &queryaddr)) == NULL) {
                        queryresponse.host.atype            = SOCKS_ADDR_IPV4;
                        queryresponse.host.addr.ipv4.s_addr = htonl(0);
                        queryresponse.host.port             = htons(0);
                     }
                     else {
                        SASSERTX(fio->state.command == SOCKS_BINDREPLY);
                        SASSERTX(sockaddrareeq(&fio->dst.laddr, &queryaddr));

                        sockaddr2sockshost(&fio->src.raddr,
                        &queryresponse.host);
                     }

                     if ((p = send_response(sv[client], &queryresponse)) == 0) {
                        if (fio != NULL) {
                           fio->dst.state.connected = 1;

                           flushio(mother, fio);

                           emfile = MAX(0, emfile - 3); /* flushio() closes 3 */
                           iolist = io_remove(iolist, fio);
                        }
                        /* else; nothing to flush yet. */
                     }
                     else {
                        iolog(&io.rule,
                              &io.state,
                              OPERATION_ERROR,
                              &io.src.laddr,
                              &io.src.host,
                              &io.src.auth,
                              NULL,
                              NULL,
                              NULL,
                              &io.dst.laddr,
                              io.state.extension.bind ? NULL : &io.dst.host,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              0);

                        p = -1;
                     }
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
            if ((sv[remote] = acceptn(out, &remoteaddr, &len)) == -1) {
               if (io.rule.log.error)
                  swarn("%s: accept()", function);

               switch (errno) {
#ifdef EPROTO
                  case EPROTO:         /* overloaded SVR4 error */
#endif /* EPROTO */
                  case EWOULDBLOCK:    /* BSD */
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
            function, sockaddr2string(&remoteaddr, NULL, 0));

            sockaddr2sockshost(&remoteaddr, &bindio.src.host);

            /*
             * Accepted a connection.  Does remote address match requested?
             */

            if (io.state.extension.bind
            || expectedbindreply.addr.ipv4.s_addr == htonl(0)
            || addrmatch(sockshost2ruleaddr(&expectedbindreply, &ruleaddr),
                         &bindio.src.host, SOCKS_TCP, 1))
               permit = rulespermit(sv[remote],
                                    &remoteaddr,
                                    &bound,
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

            if (permit && bindio.rule.ss_shmid != 0) {
               sockd_shmat(&bindio.rule, SHMEM_SS);
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
                     OPERATION_CONNECT,
                     &bindio.src.laddr,
                     &bindio.src.host,
                     &bindio.src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &bindio.dst.laddr,
                     &bindio.dst.host,
                     &bindio.dst.auth,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

               if (!bindio.state.extension.bind) {
                  /*
                   * can only accept one client, and that one failed,
                   * so assume it's better to end it rather than possibly
                   * wait forever for another client.
                   */
                  response.host = bindio.src.host;
                  send_failure(sv[client], &response, SOCKS_NOTALLOWED);

                  /* log the close of the opened bind session also. */
                  iolog(&io.rule,
                        &io.state,
                        OPERATION_DISCONNECT,
                        &io.src.laddr,
                        &io.src.host,
                        &io.src.auth,
                        NULL,
                        NULL,
                        NULL,
                        &io.dst.laddr,
                        io.state.extension.bind ? NULL : &io.dst.host,
                        NULL,
                        NULL,
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

            if (bindio.rule.bw_shmid != 0) {
               sockd_shmat(&bindio.rule, SHMEM_BW);
               bw_use(bindio.rule.bw, sockscf.shmemfd);
               sockd_shmdt(&bindio.rule, SHMEM_BW);
            }

            if (redirect(sv[reply], &remoteaddr, &bindreplydst, SOCKS_BINDREPLY,            &bindio.rule.rdr_from, &bindio.rule.rdr_to) != 0) {
               if (io.rule.log.error)
                  swarn("%s: redirect(sv[reply])", function);

               close(sv[remote]);
               close(sv[reply]);

               SHMEM_UNUSE(&bindio.rule,
                           &(TOIN(&bindio.control.raddr)->sin_addr),
                           sockscf.shmemfd);
               continue;
            }
            else {
               bindio.dst.host = bindreplydst;
               sockshost2sockaddr(&bindio.dst.host, &bindio.dst.raddr);
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
                                    &(TOIN(&bindio.control.raddr)->sin_addr),
                                    sockscf.shmemfd);
                        continue;
                  }

                  rc = -1;
                  break; /* errno is not ok. */
               }
               setsockoptions(sv[reply], SOCK_STREAM, 1);

               replyaddr                  = io.control.laddr;
               TOIN(&replyaddr)->sin_port = htons(0);

               if (bind(sv[reply], &replyaddr, sizeof(replyaddr)) != 0) {
                  if (bindio.rule.log.error)
                     swarn("%s: bind(%s)", function,

                  sockaddr2string(&replyaddr, strhost, sizeof(strhost)));

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
                        &bindio.src.laddr,
                        &bindio.src.host,
                        &bindio.src.auth,
                        NULL,
                        NULL,
                        NULL,
                        &bindio.dst.laddr,
                        &bindio.dst.host,
                        &bindio.dst.auth,
                        NULL,
                        NULL,
                        NULL,
                        msg,
                        strlen(msg));

                  /* log the close of the opened bind session also. */
                  iolog(&io.rule,
                        &io.state,
                        OPERATION_DISCONNECT,
                        &io.src.laddr,
                        &io.src.host,
                        &io.src.auth,
                        NULL,
                        NULL,
                        NULL,
                        &io.dst.laddr,
                        io.state.extension.bind ? NULL : &io.dst.host,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        0);


                  rc = -1;
                  break;
               }

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

               if (send_response(sv[client], &response) != 0)
                  close_iodescriptors(&io);
               else {
                  bindio.dst.state.connected = 1;
                  flushio(mother, &bindio);
               }

               /* flushio() closes these, not closev(). */
               sv[client] = sv[remote] = -1;

               /* only one connection to relay and that is sent to iochild. */
               break;
            }
         }

         close(out); /* not accepting any more connections on this socket. */

         if (bindio.state.extension.bind) {
            struct sockd_io_t *rmio;

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
                                    &io.dst.raddr,
                                    0,
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
            snprintf(msg, sizeof(msg), "connect() to %s failed: %s",
            sockshost2string(&io.dst.host, NULL, 0), emsg);

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &io.src.laddr,
                  &io.src.host,
                  &io.src.auth,
                  NULL,
                  NULL,
                  NULL,
                  &io.dst.laddr,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  msg,
                  strlen(msg));

            send_failure(request->s,
                         &response, errno2reply(errno,
                         response.version));

            close(request->s);
            close(out);

            rc = -1;
            break;
         }

         io.src = io.control;

         flushio(mother, &io);
         break;
      }

#if SOCKS_SERVER || BAREFOOTD
      case SOCKS_UDPASSOCIATE: {
         struct sockaddr client;
         socklen_t boundlen;
         int clientfd, rc;
#if !BAREFOOTD
         int triesleft;
#endif /* !BAREFOOTD */

         /* socket we will receive datagrams from client on */
         if ((clientfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            snprintf(msg, sizeof(msg), "socket() failed: %s", strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &io.src.laddr,
                  &io.src.host,
                  &io.src.auth,
                  NULL,
                  NULL,
                  NULL,
#if BAREFOOTD
                  NULL,
#else /* SOCKS_SERVER */
                  &io.dst.laddr,
#endif /* SOCKS_SERVER */
                  &io.dst.host,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  msg,
                  strlen(msg));

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(out);

            rc = -1;
            break;
         }
         setsockoptions(clientfd, SOCK_DGRAM, 1);

         sockshost2sockaddr(&request->req.host, &client);
         io.src.s     = clientfd;
         io.src.laddr = request->to;
         io.src.raddr = client;

#if BAREFOOTD
       rc = sockd_bind(clientfd, &io.src.laddr, 1);
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

            rc = sockd_bind(clientfd, &io.src.laddr, 0);
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

            rc = sockd_bindinrange(clientfd, &io.src.laddr,
            io.rule.udprange.start, io.rule.udprange.end, io.rule.udprange.op);
         }

         if (rc != 0) {
            snprintf(msg, sizeof(msg), "bind(%s) failed: %s",
            sockaddr2string(&io.src.laddr, strhost, sizeof(strhost)),
            strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &io.src.laddr,
                  &io.src.host,
                  &io.src.auth,
                  NULL,
                  NULL,
                  NULL,
#if BAREFOOTD
                  NULL,
#else /* SOCKS_SERVER */
                  &io.dst.laddr,
#endif /* SOCKS_SERVER */
                  &io.dst.host,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  msg,
                  strlen(msg));

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
            function, sockaddr2string(&io.src.raddr, NULL, 0));

            /* faster and better. */
            if (connect(io.src.s, &io.src.raddr, sizeof(io.src.raddr)) != 0) {
               snprintf(msg, sizeof(msg),
                        "udp client said it's address is %s, but connect(2) "
                        "to that address failed: %s",
                        sockaddr2string(&io.src.raddr, NULL, 0),
                        errnostr(errno));

               iolog(&io.rule,
                     &io.state,
                     OPERATION_ERROR,
                     &io.src.laddr,
                     &io.src.host,
                     &io.src.auth,
                     NULL,
                     NULL,
                     NULL,
                     &io.dst.laddr,
                     &io.dst.host,
                     NULL,
                     NULL,
                     NULL,
                     NULL,
                     msg,
                     strlen(msg));

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
         if (getsockname(clientfd, &io.src.laddr, &boundlen) != 0) {
            snprintf(msg, sizeof(msg), "getsockname() failed: %s",
            strerror(errno));

            iolog(&io.rule,
                  &io.state,
                  OPERATION_ERROR,
                  &io.src.laddr,
                  &io.src.host,
                  &io.src.auth,
                  NULL,
                  NULL,
                  NULL,
#if BAREFOOTD
                  NULL,
#else /* SOCKS_SERVER */
                  &io.dst.laddr,
#endif /* SOCKS_SERVER */
                  &io.dst.host,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  msg,
                  strlen(msg));

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(clientfd);
            close(out);

            rc = -1;
            break;
         }

         slog(LOG_DEBUG, "%s: address bound on client side for udp: %s",
         function, sockaddr2string(&io.src.laddr, NULL, 0));

         /* remote out can change each time, set to INADDR_ANY for now. */
         bzero(&io.dst.raddr, sizeof(io.dst.raddr));
         TOIN(&io.dst.raddr)->sin_family      = AF_INET;
         TOIN(&io.dst.raddr)->sin_addr.s_addr = htonl(INADDR_ANY);
         TOIN(&io.dst.raddr)->sin_port        = htons(0);

         if (request->req.flag & SOCKS_USECLIENTPORT
         &&  sockscf.compat.draft_5_05)
            /* LINTED pointer casts may be troublesome */
            if (TOIN(&client)->sin_port == TOIN(&io.dst.laddr)->sin_port)
               response.flag |= SOCKS_USECLIENTPORT;

         sockaddr2sockshost(&io.src.laddr, &response.host);

         if (send_response(request->s, &response) == 0)
            flushio(mother, &io);
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
   struct sockd_io_t *io;
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

      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: gss_wrap_size_limit() for socket %d is %lu",
         function, io->control.s, (unsigned long)maxlen);

      if (io->control.auth.method == AUTHMETHOD_GSSAPI)
         io->control.maxgssdata = maxlen;

      if (io->src.auth.method == AUTHMETHOD_GSSAPI)
         io->src.maxgssdata = maxlen;

      if (io->dst.auth.method == AUTHMETHOD_GSSAPI)
         io->dst.maxgssdata = maxlen;
   }
#endif /* HAVE_GSSAPI */

   gettimeofday(&io->state.time.established, NULL);

   sentio = (send_io(mother, io) == 0);

   if (!sentio)
      dolog = 1; /* things failed.  Log it. */
   else if (io->state.command == SOCKS_CONNECT) {
      SASSERTX(!io->dst.state.connected);
      dolog = 0; /* don't know status yet.  I/O child will have to log it. */
   }
   else
      dolog = 1;

   if (dolog)
      iolog(&io->rule,
            &io->state,
            sentio ? OPERATION_CONNECT : OPERATION_ERROR,
            &io->src.laddr,
            &io->src.host,
            &io->src.auth,
            NULL,
            NULL,
            NULL,
            (BAREFOOTD && io->state.protocol == SOCKS_UDP) ?
            NULL : &io->dst.laddr,
            &io->dst.host,
            &io->dst.auth,
            io->state.proxyprotocol == PROXY_DIRECT ?
               NULL : &io->state.proxychain.server,
            io->state.proxyprotocol == PROXY_DIRECT ?
               NULL : &io->state.proxychain.extaddr,
            NULL,
            NULL,
            0);

  if (!sentio) {
#if HAVE_NEGOTIATE_PHASE
      struct response_t response;

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
                         errnostr(errno));
      }
#endif /* HAVE_NEGOTIATE_PHASE */
      slog(LOG_DEBUG,
           "%s: sending io to mother on socket %d failed: %s",
           function, mother, errnostr(errno));
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
   const struct request_t *req;
   struct response_t *res;
   struct sockd_io_direction_t *src, *dst;
   int *proxyprotocol;
   proxychaininfo_t *proxychain;
{
   const char *function = "serverchain()";
   struct route_t *route;
   struct socks_t packet;
   int flags;

   if (sockscf.route == NULL) {
      errno = 0;
      return -1;
   }

   packet.req         = *req;
   packet.req.version = PROXY_DIRECT;

   bzero(&packet.state.auth, sizeof(packet.state.auth));
   packet.req.auth         = &packet.state.auth;
   packet.req.auth->method = AUTHMETHOD_NOTSET;

   if (socks_requestpolish(&packet.req, &src->host, &dst->host) == NULL)
      return -1;

   if (packet.req.version == PROXY_DIRECT) {
      slog(LOG_DEBUG, "%s: using direct system calls for socket %d",
      function, s);

      errno = 0;
      return -1;
   }

   errno = 0;
   if ((route = socks_connectroute(s, &packet, &src->host, &dst->host)) == NULL)
      return -1;

   /* check again in case of sighup adding a route. */
   if (route->gw.state.proxyprotocol.direct) {
      errno = 0;
      return -1;
   }

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

   *proxyprotocol     = (int)packet.version;
   proxychain->server = route->gw.addr;

   switch (packet.req.command) {
      case SOCKS_CONNECT:
         proxychain->extaddr = packet.res.host;
         break;

      default:
         bzero(&proxychain->extaddr, sizeof(proxychain->extaddr));
         proxychain->extaddr.atype = (unsigned char)SOCKS_ADDR_IPV4;
   }

   slog(LOG_DEBUG, "%s: extaddr is %s",
   function, sockshost2string(&proxychain->extaddr, NULL, 0));

   return 0;
}

static void
convertresponse(oldres, newres, newversion)
   const struct response_t *oldres;
   struct response_t *newres;
   const int newversion;
{
   const char *function = "convertresponse()";
   int reply;

   if (oldres->version == newversion) {
      *newres = *oldres;
      return;
   }

   slog(LOG_DEBUG, "%s: converting from version %d to version %d",
   function, oldres->version, newversion);

   switch (oldres->version) {
      case PROXY_HTTP_10:
      case PROXY_HTTP_11:
         switch (oldres->reply.http) {
            case HTTP_SUCCESS:
               reply = SOCKS_SUCCESS;
               break;

            default:
               reply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_UPNP:
         switch (oldres->reply.upnp) {
            case UPNP_SUCCESS:
               reply = SOCKS_SUCCESS;
               break;

            default:
               reply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_SOCKS_V4REPLY_VERSION:
         switch (oldres->reply.socks) {
            case SOCKSV4_SUCCESS:
               reply = SOCKS_SUCCESS;
               break;

            default:
               reply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_SOCKS_V5: /* base format. */
         reply = oldres->reply.socks;
         break;

      default:
         swarnx("%s: unknown proxy protocol: %d", function, oldres->version);
         reply   = SOCKS_FAILURE;
   }

   if (newversion == PROXY_SOCKS_V4) {
      if (oldres->host.atype != (unsigned char)SOCKS_ADDR_IPV4) {
         /* v4 only supports ipaddr. */
         struct sockaddr addr;

         sockshost2sockaddr(&oldres->host, &addr);

         if (ADDRISBOUND(TOIN(&addr)))
            sockaddr2sockshost(&addr, &newres->host);
         else {
            swarnx("%s: can not resolve %s",
            function, sockshost2string(&oldres->host, NULL, 0));

            reply = SOCKS_FAILURE;
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
   socks_set_responsevalue(newres, reply);
}


/* ARGSUSED */
static void
siginfo(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "siginfo()";
   unsigned long seconds, days, hours, minutes;
   time_t timenow;

   if (sig > 0) {
      sockd_pushsignal(sig, sip);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, "%s: running due to previously received signal: %d",
   function, sig);

   seconds = ROUNDFLOAT(difftime(time(&timenow), sockscf.stat.boot));
   seconds2days(&seconds, &days, &hours, &minutes);

   /* XXX no clientinfo. */
   slog(LOG_INFO, "request-child up %lu day%s, %lu:%.2lu:%.2lu",
                  days, days == 1 ? "" : "s", hours, minutes, seconds);
}

#if HAVE_NEGOTIATE_PHASE
struct response_t *
create_response(host, auth, version, responsecode, response)
   const struct sockshost_t *host;
   struct authmethod_t *auth;
   const int version;
   const int responsecode;
   struct response_t *response;
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
static struct sockd_io_t *
io_add(iolist, newio)
   struct sockd_io_t *iolist;
   const struct sockd_io_t *newio;
{
   const char *function = "io_add()";
   struct sockd_io_t *io, *previo;

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

static struct sockd_io_t *
io_remove(iolist, rmio)
   struct sockd_io_t *iolist;
   struct sockd_io_t *rmio;
{
   struct sockd_io_t *io, *previo;

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

static struct sockd_io_t *
io_find(iolist, addr)
   struct sockd_io_t *iolist;
   const struct sockaddr *addr;
{
   struct sockd_io_t *io;

   if (addr == NULL)
      return iolist;

   io = iolist;
   while (io != NULL)
      if (sockaddrareeq(&io->src.laddr, addr)
      ||  sockaddrareeq(&io->dst.laddr, addr)
      ||  sockaddrareeq(&io->control.laddr, addr))
         return io;
      else
         io = io->next;

   return NULL;
}
#endif /* SOCKS_SERVER */
