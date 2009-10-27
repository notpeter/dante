/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009
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
"$Id: sockd_request.c,v 1.294 2009/10/27 12:11:08 karls Exp $";

/*
 * Since it only handles one client at a time there is no possibility
 * for the mother to send a new client before we have got rid of the
 * old one and thus no need for locking even on broken systems.
 * (#ifdef HAVE_SENDMSG_DEADLOCK)
 * XXX Should fix things so this process too can support multiple clients.
 * Will also fix the terrible fact that we just sit around and wait if the
 * command is bind, wasting the whole process on practically nothing.
 */

static void
send_failure(int s, struct response_t *response, int failure);
/*
 * Sends a failure message to the client at "s".  "response" is the packet
 * we send, "failure" is the reason for failure and "auth" is the agreed on
 * authentication.
 */

static void
convertresponse(const struct response_t *oldres, struct response_t *newres,
             const int newversion);
/*
 * Converts a response on form "oldres", using oldres->version,
 * to a new response on form "newversion".
 */

static void
dorequest(int mother, struct sockd_request_t *request);
/*
 * When a complete request has been read, this function can be
 * called.  It will perform the request "request->req" and send the
 * result to "mother".
 */

static void
flushio(int mother, int clientcontrol, const struct response_t *response,
   struct sockd_io_t *io);
/*
 * "flushes" a complete io object and free's any state/resources held by it.
 * "mother" is connection to mother for sending the io.
 * "clientcontrol" is the client connection.
 * "response" is the response to be sent the client.
 * "io" is the io object sent mother.
 */

static void
proctitleupdate(const struct sockaddr *from);
/*
 * Updates the title of this process.
 */

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

static int
serverchain(int s, const struct request_t *req, struct response_t *res,
      struct sockd_io_direction_t *src, struct sockd_io_direction_t *dst);
/*
 * Checks if we should create a serverchain on socket "s" for the request
 * "req".
 * Returns:
 *       0: Serverchain established successfully.
 *      -1: No serverchain established.  If errno set, it indicates the reason.
 *          If errno is not set, no route exists to handle this connection,
 *          and it should be direct.
 */


#define SHMEM_UNUSE(rule)     \
do {                          \
   bw_unuse((rule)->bw);      \
   session_unuse((rule)->ss); \
} while (/*CONSTCOND*/0)


void
run_request(mother)
   struct sockd_mother_t *mother;
{
   const char *function = "run_request()";
   struct sockd_request_t req;

   proctitleupdate(NULL);

   req.s = -1;

   /* CONSTCOND */
   while (1) {
      /*
       * Get request from mother, perform it, get next request.
       */
      static fd_set *rset;
      const char command = SOCKD_FREESLOT;
      int fdbits;
#if DIAGNOSTIC
   const int freec = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif /* DIAGNOSTIC */

      proctitleupdate(NULL);

      if (rset == NULL)
         rset = allocate_maxsize_fdset();
      FD_ZERO(rset);

      FD_SET(mother->s, rset);
      fdbits = mother->s;

      /* checked so we know if mother goes away.  */
      FD_SET(mother->ack, rset);
      fdbits = MAX(fdbits, mother->ack);

      ++fdbits;
      switch (selectn(fdbits, rset, NULL, NULL, NULL, NULL, NULL)) {
         case -1:
            if (errno != EINTR)
               SERR(-1);
            continue;

         case 0:
            SERRX(0);
      }

      if (FD_ISSET(mother->ack, rset)) {
         slog(LOG_DEBUG, "%s: mother exited, we should too", function);
         sockdexit(EXIT_SUCCESS);
      }

      if (FD_ISSET(mother->s, rset))
         if (recv_req(mother->s, &req) == -1)
            sockdexit(EXIT_FAILURE);


      if (req.s == -1)
         SASSERTX(BAREFOOTD && req.req.command == SOCKS_UDPASSOCIATE);
      else
         socks_allocbuffer(req.s);

      dorequest(mother->s, &req);

      if (req.s != -1)
         socks_freebuffer(req.s);

      if (socks_sendton(mother->ack, &command, sizeof(command),
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
       * listen to udp addresses, and fake a request for it
       */
      struct rule_t *rule;
      sigset_t newmask, oldmask;

      /*
       * need to block sighup, as it can cause the bounce-to addresses
       * to change.
       */
      (void)sigemptyset(&newmask);
      (void)sigaddset(&newmask, SIGHUP);
      if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) != 0)
         swarn("%s: sigprocmask(SIG_BLOCK) set", function);

      for (rule = sockscf.srule; rule != NULL; rule = rule->next) {
         struct sockshost_t host;

         if (!rule->state.protocol.udp
         ||  rule->bounced)
            continue;

         slog(LOG_DEBUG, "need to add listen for socks-rule #%d", rule->number);

         bzero(req, sizeof(*req));

         sockshost2sockaddr(ruleaddr2sockshost(&rule->src, &host, SOCKS_UDP),
         &req->from);

         sockshost2sockaddr(ruleaddr2sockshost(&rule->crule->dst, &host,
         SOCKS_UDP), &req->to);

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
         req->req.host.atype            = SOCKS_ADDR_IPV4;
         req->req.host.addr.ipv4.s_addr = htonl(INADDR_ANY);
         req->req.host.port             = htons(0);
         req->req.auth                  = &req->socksauth;
         req->req.protocol              = SOCKS_UDP;

         /*
          * no negotiation going on here, what we want is what we get.
          */
         req->state.command = req->req.command;
         req->state.version = req->req.version;

         rule->bounced = 1;
         break;
      }

      if (sigprocmask(SIG_BLOCK, &oldmask, NULL) != 0)
         swarn("%s: sigprocmask() reset", function);

      if (rule == NULL) /* no more rules found.  Should not have been called. */
         sockscf.state.alludpbounced = 1;
      else { /* check if this was the last one before returning. */
         for (rule = rule->next; rule != NULL; rule = rule->next)
            if (rule->state.protocol.udp && !rule->bounced) {
               slog(LOG_DEBUG, "%s: more addresses to bounce, next one "
                               "rule #%d", function, rule->number);

               break;
            }

         if (rule == NULL) {
            slog(LOG_DEBUG, "%s: no more addresses to bounce", function);
            sockscf.state.alludpbounced = 1;
         }

         return 0;
      }
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

   if ((r = recvmsg(s, &msg, 0)) < (ssize_t)sizeof(*req)) {
      switch (r) {
         case -1:
            swarn("%s: recvmsg() failed", function);
            break;

         case 0:
            slog(LOG_DEBUG, "%s: recvmsg(): other side closed connection",
            function);
            break;

         default:
            swarnx("%s: recvmsg(): unexpected short read: %d/%ld",
            function, r, (long)sizeof(*req));
      }

      return -1;
   }

   r -= sizeof(*req);

#if BAREFOOTD
   if (req->req.command == SOCKS_UDPASSOCIATE)
      fdexpect = 0; /* no client yet. */
   else
      fdexpect = 1; /* client. */
#else /* SOCKS_SERVER */
   fdexpect = 1; /* client. */
#endif /* SOCKS_SERVER */

#if !HAVE_DEFECT_RECVMSG
   SASSERT((size_t)CMSG_TOTLEN(msg)
   == (size_t)(CMSG_SPACE(sizeof(int) * fdexpect)));
#endif /* !HAVE_DEFECT_RECVMSG */

   fdreceived = 0;

   if (fdexpect > 0) {
      SASSERTX(fdexpect == 1);
      CMSG_GETOBJECT(req->s, cmsg, sizeof(req->s) * fdreceived++);
   }

   req->req.auth = &req->socksauth; /* pointer fixup */

#if HAVE_GSSAPI
   if (req->req.auth->method == AUTHMETHOD_GSSAPI) {
      gss_buffer_desc gssapistate;

      SASSERTX(r > 0);

      slog(LOG_DEBUG, "%s: read gssapistate of size %d", function, r);

      gssapistate.value  = gssapistatemem;
      gssapistate.length = r;

      if (gssapi_import_state(&req->req.auth->mdata.gssapi.state.id,
      &gssapistate) != 0)
         return -1;
   }
#endif /* HAVE_GSSAPI */

   slog(LOG_DEBUG, "%s: received %d descriptors for request with method %d, "
                   "req->s = %d",
                   function, fdreceived, req->req.auth->method, s);

   return 0;
}

static void
dorequest(mother, request)
   int mother;
   struct sockd_request_t *request;
{
   const char *function = "dorequest()";
   static struct sockd_io_t ioinit;
   struct sockaddr bound;
   struct sockd_io_t io;
   struct response_t response;
   struct sockshost_t expectedbindreply, bindreplydst;
   sigset_t oldset;
   char strhost[MAXSOCKSHOSTSTRING], msg[256];
   int p, permit, out, failurecode = SOCKS_NOTALLOWED;

   slog(LOG_DEBUG, "request received from %s using authentication %s: %s",
   sockaddr2string(&request->from, strhost, sizeof(strhost)),
   method2string(request->req.auth->method),
   socks_packet2string(&request->req, SOCKS_REQUEST));

   proctitleupdate(&request->from);

   bzero(&response, sizeof(response));
   response.host   = request->req.host;
   response.auth   = request->req.auth;

   io              = ioinit;
   io.state        = request->state;
   io.crule        = request->rule;

   /* so we can call iolog() before rulespermit() on errors. */
   io.rule         = io.crule;
   io.rule.verdict = VERDICT_BLOCK;
   io.rule.number  = 0;
   if (io.crule.log.error)
      /* if we log before rulespermit() it's due to an error. */
      io.rule.log.connect = 1;

   sockaddr2sockshost(&request->to,   &io.dst.host);
   sockaddr2sockshost(&request->from, &io.src.host);
   io.control.s       = request->s;
   io.control.laddr   = request->to;
   io.control.raddr   = request->from;
   io.control.host    = io.src.host;
   io.control.auth    = io.src.auth = *request->req.auth;
   io.dst.auth.method = AUTHMETHOD_NOTSET; /* at least so far. */

   /*
    * examine client request.
    */

   /* supported version? */
   switch (request->req.version) {
      case PROXY_SOCKS_V4:
         response.version = PROXY_SOCKS_V4REPLY_VERSION;

         /* recognized command for this version? */
         switch (request->req.command) {
            case SOCKS_BIND:
            case SOCKS_CONNECT:
               io.state.protocol = SOCKS_TCP;
               break;

            default:
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d command: %d",
               sockaddr2string(&request->from, strhost, sizeof(strhost)),
               request->req.version, request->req.command);

               io.state.command = SOCKS_UNKNOWN;
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

               send_failure(request->s, &response, SOCKS_CMD_UNSUPP);
               close(request->s);
               return;
         }

         /* supported address format for this version? */
         switch (request->req.host.atype) {
            case SOCKS_ADDR_IPV4:
               break;

            default:
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d atype: %d",
               sockaddr2string(&request->from, strhost, sizeof(strhost)),
               request->req.version, request->req.host.atype);

               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

               send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);
               close(request->s);
               return;
         }
         break; /* PROXY_SOCKS_V4 */

      case PROXY_SOCKS_V5:
         response.version = request->req.version;

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
               request->req.version, request->req.command);

               io.state.command = SOCKS_UNKNOWN;
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

               send_failure(request->s, &response, SOCKS_CMD_UNSUPP);
               close(request->s);
               return;
         }

         /* supported address format for this version? */
         switch (request->req.host.atype) {
            case SOCKS_ADDR_IPV4:
            case SOCKS_ADDR_DOMAIN:
               break;

            default:
               snprintf(msg, sizeof(msg), "%s: unrecognized v%d atype: %d",
               sockaddr2string(&request->from, strhost, sizeof(strhost)),
               request->req.version, request->req.host.atype);

               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

               send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);
               close(request->s);
               return;
         }
         break; /* PROXY_SOCKS_V5 */

      default:
         SERRX(request->req.version);
   }

   /*
    * packet looks ok, fill in remaining bits and check rules.
    */

   switch (request->req.command) {
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

         io.dst.host = request->req.host;

         if (io.dst.host.atype            == SOCKS_ADDR_IPV4
         &&  io.dst.host.addr.ipv4.s_addr == htonl(BINDEXTENSION_IPADDR))
            io.state.extension.bind = 1;
         else
            io.state.extension.bind = 0;

         io.src.host = io.control.host;
         break;

      case SOCKS_CONNECT:
         io.src.host = io.control.host;
         io.dst.host = request->req.host;
         break;

      case SOCKS_UDPASSOCIATE:
         io.src.host                  = request->req.host;

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

   bzero(&bound, sizeof(bound));

   /*
    * Find address to bind on clients behalf.
    * First, the IP address ...
   */
   switch (request->req.command) {
      case SOCKS_BIND:
      case SOCKS_CONNECT:
      case SOCKS_UDPASSOCIATE: /* dst is 0.0.0.0. */
         TOIN(&bound)->sin_addr = getifa(io.dst.host.addr.ipv4);
         break;

      default:
         SERRX(request->req.command);
   }

   /* ... and then the port. */
   switch (request->req.command) {
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
               expectedbindreply = request->req.host;

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

      case SOCKS_CONNECT:
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
                      "\"compatibility: sameport\" is not set, so using 0",
                      function, ntohs(TOIN(&bound)->sin_port));

      TOIN(&bound)->sin_port = htons(0);
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
      iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
      &io.src.auth, &io.dst.host, &io.dst.auth, strerror(errno), 0);

      send_failure(request->s, &response, SOCKS_FAILURE);
      close(request->s);
      return;
   }
   setsockoptions(out);

   /* bind it. */ /* LINTED possible pointer alignment problem */
   TOIN(&bound)->sin_family = AF_INET;
   if (sockscf.compat.reuseaddr) {/* XXX and not rebinding in redirect(). */
      p = 1;
      if (setsockopt(out, SOL_SOCKET, SO_REUSEADDR, &p, sizeof(p)) != 0)
         swarn("%s: setsockopt(SO_REUSEADDR)", function);
   }

   /* need to bind address so rulespermit() has an address to compare against.*/
   if ((p = sockd_bind(out, &bound, 0)) != 0) {
      /* no such luck.  Bind any port and let client decide if ok. */

      /* LINTED pointer casts may be troublesome */
      TOIN(&bound)->sin_port = htons(0);

      if ((p = sockd_bind(out, &bound, 0)) == 0) {
         socklen_t len;

         len = sizeof(bound);
         p = getsockname(out, &bound, &len);

         slog(LOG_DEBUG, "%s: bound different port than desired, bound %s\n",
         function, sockaddr2string(&bound, NULL, 0));
      }
   }

   if (p != 0) {
      iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
      &io.src.auth, &io.dst.host, &io.dst.auth, strerror(errno), 0);

      send_failure(request->s, &response, errno2reply(errno, response.version));
      close(request->s);
      close(out);
      return;
   }

   /*
    * lock before rulescheck, in case we're gonna use rule.{ss,bw,etc}.
    */
   socks_sigblock(SIGHUP, &oldset);

   /* rules permit? */
   switch (request->req.command) {
      case SOCKS_BIND:
         /*
          * now that we know what address/port we bound, fill in dst
          * correctly.  For the other commands, things are already
          * set up correctly.
          */
         sockaddr2sockshost(&bound, &io.dst.host);

         permit = rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &request->clientauth,
                              &io.rule,
                              &io.src.auth,
                              &io.state,
                              &io.src.host,
                              &io.dst.host,
                              msg,
                              sizeof(msg));
         break;

      case SOCKS_CONNECT:
         permit = rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &request->clientauth,
                              &io.rule,
                              &io.src.auth,
                              &io.state,
                              &io.src.host,
                              &io.dst.host,
                              msg,
                              sizeof(msg));
         break;

      case SOCKS_UDPASSOCIATE: {
#if BAREFOOTD
         permit  = 1;
         io.rule = io.crule;
         *msg    = NUL;

#else /* SOCKS_SERVER */
         struct sockshost_t *src;
         struct connectionstate_t replystate;
         struct authmethod_t replyauth;

         /*
          * Client is allowed to send a "incomplete" address, but
          * if not, that's the source address.
          * Destination address can vary for each packet, so NULL
          * for now.
          */
         if (io.src.host.atype             == SOCKS_ADDR_IPV4
         && ( io.src.host.addr.ipv4.s_addr == htonl(0)
           || io.src.host.port             == htons(0)))
            src = NULL;
         else
            src = &io.src.host;

         /* make a temp to check for i/o both ways. */
         replystate         = io.state;
         replystate.command = SOCKS_UDPREPLY;

         bzero(&replyauth, sizeof(replyauth));
         replyauth.method   = AUTHMETHOD_NOTSET;

         /*
          * if we can do i/o in one direction that is enough, though
          * it could also be a configuration error.
          */
         permit = rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &request->clientauth,
                              &io.rule,
                              &io.control.auth,
                              &io.state,
                              src,
                              NULL,
                              msg,
                              sizeof(msg))
         ||       rulespermit(request->s,
                              &request->from,
                              &request->to,
                              &request->clientauth,
                              &io.rule,
                              &replyauth,
                              &replystate,
                              NULL,
                              src,
                              msg,
                              sizeof(msg));
#endif /* SOCKS_SERVER */

         break;
      }

      default:
         SERRX(request->req.command);
   }

   if (permit && io.rule.ss != NULL) { /* don't bother if rules deny anyway. */
      if (!session_use(io.rule.ss)) {
         permit          = 0;
         io.rule.verdict = VERDICT_BLOCK;
         failurecode     = SOCKS_NOTALLOWED;
         io.rule.ss      = NULL;

         snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
      }
   }

   iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host, &io.src.auth,
   &io.dst.host, &io.dst.auth, msg, 0);

   if (!permit) {
      send_failure(request->s, &response, failurecode);
      close(request->s);
      close(out);

      socks_sigunblock(&oldset);
      return;
   }

   switch (request->req.command) {
      case SOCKS_UDPASSOCIATE:
         break; /* does a rulecheck for each packet, not now. */

      default:
         if (io.crule.bw != NULL) {
            /*
             * client-rule is not used anymore after the matching socks-rule
             * has been determined, so copy over what we need from
             * client-rule to socks-rule and then use socks-rule.
             */
            if (io.rule.bw == NULL) {
               slog(LOG_DEBUG, "%s: socks rule #%lu inherits bandwidth "
                               "limitation from client rule #%lu",
                               function,
                               (unsigned long)io.crule.number,
                               (unsigned long)io.rule.number);
               io.rule.bw = io.crule.bw;
            }
            else
               slog(LOG_DEBUG, "%s: client rule #%lu limits bandwidth, "
                               "but overridden by socks rule #%lu",
                               function,
                               (unsigned long)io.crule.number,
                               (unsigned long)io.rule.number);
         }

         if (io.rule.bw != NULL)
            bw_use(io.rule.bw);
   }

   socks_sigunblock(&oldset);

   if (redirect(out, &bound, &io.dst.host, request->req.command,
   &io.rule.rdr_from, &io.rule.rdr_to) != 0) {
      if (io.rule.log.error) {
         snprintf(msg, sizeof(msg), "redirect(): %s", strerror(errno));
         iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
         &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
      }

      send_failure(request->s, &response, errno2reply(errno, response.version));
      close(request->s);
      close(out);
      SHMEM_UNUSE(&io.rule);
      return;
   }

   if (serverchain(out, &request->req, &response, &io.src, &io.dst) == 0) {
      switch (io.state.command) {
         case SOCKS_CONNECT: {
            socklen_t sinlen;

            io.src   = io.control;
            io.dst.s = out;

            sinlen   = sizeof(io.dst.raddr);
            if (getpeername(io.dst.s, &io.dst.raddr, &sinlen) != 0) {
               if (io.rule.log.error) {
                  snprintf(msg, sizeof(msg), "getpeername(io.dst.s): %s",
                  strerror(errno));
                  iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
                  &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
               }

               send_failure(request->s, &response, SOCKS_FAILURE);
               close(request->s);
               break;
            }

            sinlen = sizeof(io.dst.laddr);
            if (getsockname(io.dst.s, &io.dst.laddr, &sinlen) != 0) {
               if (io.rule.log.error) {
                  snprintf(msg, sizeof(msg), "getsockname(io.dst.s): %s",
                  strerror(errno));
                  iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
                  &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
               }

               send_failure(request->s, &response, SOCKS_FAILURE);
               close(request->s);
               break;
            }

            flushio(mother, request->s, &response, &io);
            break;
         }

         default:
            SERRX(request->req.command);
      }

      close(out);
      return;
   }
   else /* no chain.  Error, or no route? */
      if (errno != 0) { /* error. */
         snprintf(msg, sizeof(msg), "serverchain failed: %s", strerror(errno));
         iolog(&io.rule, &io.state, OPERATION_ABORT, &io.src.host,
         &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

         send_failure(request->s, &response, errno2reply(errno,
         response.version));
         close(request->s);
         close(out);
         SHMEM_UNUSE(&io.rule);
         return;
      }
      /*
       * else; no route, so go direct.
       */

   /*
    * Set up missing bits of io and send it to mother.
    */

   switch (io.state.command) {
      case SOCKS_BIND: {
         struct sockd_io_t *iolist;
         struct sockd_io_t bindio;         /* send this to iochild.  */
         struct sockaddr boundaddr;        /* address we listen on.  */
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
               snprintf(msg, sizeof(msg), "listen(out): %s", strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(sv[client], &response, SOCKS_FAILURE);
            closev(sv, ELEMENTS(sv));
            close(out);
            break;
         }

         /* for accept(). */
         if ((flags = fcntl(out, F_GETFL, 0))          == -1
         ||   fcntl(out, F_SETFL, flags | O_NONBLOCK) == -1) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "fcntl(): %s", strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(sv[client], &response, SOCKS_FAILURE);
            close(out);
            closev(sv, ELEMENTS(sv));
            break;
         }

         len = sizeof(boundaddr);
         if (getsockname(out, &boundaddr, &len) != 0) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "getsockname(out): %s",
               strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(sv[client], &response, SOCKS_FAILURE);
            close(out);
            closev(sv, ELEMENTS(sv));
            break;
         }

         response.host  = io.dst.host;
         response.reply = (char)sockscode(response.version, SOCKS_SUCCESS);

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
               if (io.rule.log.error) {
                  snprintf(msg, sizeof(msg), "socketpair(): %s",
                  strerror(errno));
                  iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
                  &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
               }

               send_failure(sv[client], &response, SOCKS_FAILURE);
               close(out);
               closev(sv, ELEMENTS(sv));
               break;
            }

            sv[childpipe] = pipev[0];
            sv[ourpipe]   = pipev[1];
         }

         /* let client know what address we bound to on it's behalf. */
         if (send_response(sv[client], &response) != 0) {
            iolog(&io.rule, &io.state, OPERATION_ABORT, &io.control.host,
            &io.control.auth, &io.dst.host, &io.dst.auth, NULL, 0);
            close(out);
            closev(sv, ELEMENTS(sv));
            break;
         }

         emfile = 0;
         iolist = NULL;

         bindio                   = io; /* quick init of most stuff. */
         bindio.state.command     = SOCKS_BINDREPLY;
         bindio.dst.host          = bindreplydst;
         bindio.src.auth.method   = AUTHMETHOD_NOTSET;

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
            int replyredirect;
            int fdbits = -1;

            if (rset == NULL)
               rset = allocate_maxsize_fdset();
            FD_ZERO(rset);

            /* some sockets change, most remain the same. */
            sv[reply]  = -1;
            sv[remote] = -1;

            FD_SET(sv[client], rset);
            fdbits = MAX(fdbits, sv[client]);

            if (!emfile) {
               FD_SET(out, rset);
               fdbits = MAX(fdbits, out);
            }

            ++fdbits;
            if ((p = selectn(fdbits, rset, NULL, NULL, NULL, NULL, NULL)) <= 0)
               SERR(p);

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
                     iolog(&io.rule, &io.state, OPERATION_ABORT,
                     &io.control.host, &io.control.auth, &io.dst.host,
                     &io.dst.auth, NULL, 0);

                     break;

                  case 0: {
                     char *emsg = "client closed";

                     iolog(&io.rule, &io.state, OPERATION_ABORT,
                     &io.control.host, &io.control.auth,
                     &io.dst.host, &io.dst.auth, emsg, 0);
                     p = -1; /* session ended. */
                     break;
                  }

                  default: {
                     struct sockd_io_t *fio;

                     slog(LOG_DEBUG, "received request: %s",
                     socks_packet2string(&query, SOCKS_REQUEST));

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

                     if (fio != NULL) {
                        flushio(mother, sv[client], &queryresponse, fio);
                        emfile = MAX(0, emfile - 3); /* flushio() closes 3. */
                        iolist = io_remove(iolist, fio);
                        p = 0;
                     }
                     else
                        if ((p = send_response(sv[client], &queryresponse))
                        != 0)
                           iolog(&io.rule, &io.state, OPERATION_ABORT,
                           &io.control.host, &io.control.auth,
                           &io.dst.host, &io.dst.auth, NULL, 0);
                  }
               }

               if (p != 0)
                  break;
            }

            if (!FD_ISSET(out, rset))
               continue;

            len = sizeof(remoteaddr);
            if ((sv[remote] = acceptn(out, &remoteaddr, &len)) == -1) {
               if (io.rule.log.error)
                  swarn("%s: accept(out)", function);

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

               break; /* errno is not ok, end. */
            }

            slog(LOG_DEBUG, "%s: got a bindreply from %s",
            function, sockaddr2string(&remoteaddr, NULL, 0));

            sockaddr2sockshost(&remoteaddr, &bindio.src.host);

            /*
             * Accepted a connection.  Does remote address match requested?
             */

            socks_sigblock(SIGHUP, &oldset);

            if (io.state.extension.bind
            || expectedbindreply.addr.ipv4.s_addr == htonl(0)
            || addrmatch(sockshost2ruleaddr(&expectedbindreply, &ruleaddr),
                         &bindio.src.host, SOCKS_TCP, 1)) {
               permit = rulespermit(sv[remote],
                                    &remoteaddr,
                                    &boundaddr,
                                    &request->clientauth,
                                    &bindio.rule,
                                    &bindio.src.auth,
                                    &bindio.state,
                                    &bindio.src.host,
                                    &bindio.dst.host,
                                    msg,
                                    sizeof(msg));
            }
            else {
               bindio.rule.number  = 0;
               bindio.rule.verdict = VERDICT_BLOCK;

               snprintfn(msg, sizeof(msg),
               "expected bindreply from %s, but got it from %s, rejecting",
               sockshost2string(&expectedbindreply, strhost, sizeof(strhost)),
               sockshost2string(&bindio.src.host, NULL, 0));

               permit = 0;
            }

            if (permit && bindio.rule.ss != NULL) {
               if (!session_use(bindio.rule.ss)) {
                  permit              = 0;
                  bindio.rule.verdict = VERDICT_BLOCK;
                  failurecode         = SOCKS_NOTALLOWED;
                  bindio.rule.ss      = NULL;

                  snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
               }
            }

            iolog(&bindio.rule, &bindio.state, OPERATION_CONNECT,
            &bindio.src.host, &bindio.src.auth, &bindio.dst.host,
            &bindio.dst.auth, msg, 0);

            if (!permit) {
               socks_sigunblock(&oldset);

               if (!bindio.state.extension.bind) {
                  /*
                   * can only accept one client, and that one failed,
                   * so assume it's better to end it rather than possibly
                   * wait forever for another client.
                   */
                  response.host = bindio.src.host;
                  send_failure(sv[client], &response, SOCKS_NOTALLOWED);

                  break;
               }
               else {
                  close(sv[remote]);
                  continue; /* wait for next client, but will there be one? */
               }
            }

            if (bindio.rule.bw != NULL)
               bw_use(bindio.rule.bw);

            socks_sigunblock(&oldset);

            if (redirect(sv[reply], &remoteaddr, &bindreplydst, SOCKS_BINDREPLY,            &bindio.rule.rdr_from, &bindio.rule.rdr_to) != 0) {
               if (io.rule.log.error)
                  swarn("%s: redirect(sv[reply])", function);

               close(sv[remote]);
               close(sv[reply]);
               SHMEM_UNUSE(&bindio.rule);
               continue;
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
                        SHMEM_UNUSE(&bindio.rule);
                        continue;
                  }
                  break; /* errno is not ok. */
               }
               setsockoptions(sv[reply]);

               replyaddr                  = boundaddr;
               /* LINTED pointer casts may be troublesome */
               TOIN(&replyaddr)->sin_port = htons(0);

               if (bind(sv[reply], &replyaddr, sizeof(replyaddr)) != 0) {
                  if (bindio.rule.log.error)
                     swarn("%s: bind(%s)", function,
                  sockaddr2string(&replyaddr, strhost, sizeof(strhost)));
                  break;
               }

               len = sizeof(replyaddr);
               /* LINTED pointer casts may be troublesome */
               if (getsockname(sv[reply], &replyaddr, &len) != 0) {
                  if (bindio.rule.log.error)
                     swarn("%s: getsockname(sv[reply])", function);

                  if (errno == ENOBUFS) {
                     close(sv[remote]);
                     close(sv[reply]);
                     SHMEM_UNUSE(&bindio.rule);
                     continue;
                  }

                  break;
               }

               slog(LOG_DEBUG, "%s: connecting to %s",
               function,
               sockshost2string(&bindreplydst, strhost, sizeof(strhost)));

               if (socks_connecthost(sv[reply], &bindreplydst) != 0) {
                  iolog(&bindio.rule, &bindio.state, OPERATION_ABORT,
                  &bindio.src.host, &bindio.src.auth,
                  &bindreplydst, &bindio.dst.auth, NULL, 0);
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
               break;
            }

            if (bindio.state.extension.bind || replyredirect) {
               if (bindio.state.extension.bind)
                  bindio.dst.s = sv[reply];
               else /* replyredirect */
                  bindio.dst.s = sv[client];
               bindio.dst.laddr = replyaddr;
            }
            else {
               bindio.dst       = bindio.control;
               bindio.dst.raddr = request->from;
            }
            sockshost2sockaddr(&bindio.dst.host, &bindio.dst.raddr);

            bindio.src.s     = sv[remote];
            bindio.src.laddr = boundaddr;
            bindio.src.raddr = remoteaddr;

            if (bindio.state.extension.bind)
               /* add to list, client will query. */
               iolist = io_add(iolist, &bindio);
            else {
               response.host = bindio.src.host;

               flushio(mother, sv[client], &response, &bindio);
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

      case SOCKS_CONNECT: {
         socklen_t sinlen;

         if (socks_connecthost(out, &io.dst.host) != 0) {
            iolog(&io.rule, &io.state, OPERATION_ABORT, &io.src.host,
            &io.src.auth, &io.dst.host, &io.dst.auth, NULL, 0);

            send_failure(request->s, &response, errno2reply(errno,
            response.version));

            close(request->s);
            close(out);
            break;
         }

         io.src   = io.control;

         io.dst.s = out;
         sinlen   = sizeof(io.dst.raddr);
         if (getpeername(io.dst.s, &io.dst.raddr, &sinlen) != 0) {
            recvfrom(io.dst.s, NULL, 0, 0, NULL, NULL);
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "getpeername(io.dst.s): %s",
               strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(out);
            break;
         }

         sinlen = sizeof(io.dst.laddr);
         if (getsockname(io.dst.s, &io.dst.laddr, &sinlen) != 0) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "getsockname(io.dst.s): %s",
               strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(out);
            break;
         }

         sockaddr2sockshost(&io.dst.laddr, &response.host);
         response.reply = sockscode(response.version, SOCKS_SUCCESS);

         flushio(mother, request->s, &response, &io);
         break;
      }

      case SOCKS_UDPASSOCIATE: {
         struct sockaddr client;
         socklen_t boundlen;
         int clientfd, rc;
#if !BAREFOOTD
         int triesleft;
#endif /* !BAREFOOTD */

         /* socket we will receive datagrams from client on */
         if ((clientfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "socket(): %s", strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(out);
            break;
         }
         setsockoptions(clientfd);

         sockshost2sockaddr(&request->req.host, &client);

         io.src.s                      = clientfd;
         io.src.raddr                  = client;
         io.src.laddr                  = request->to;

#if BAREFOOTD
       rc = sockd_bind(clientfd, &io.src.laddr, 1);
#else /* SOCKS_SERVER */

         /*
          * bind client-side address for receiving UDP packets, so we can tell
          * client where to send it's packets.
          */
         if (io.rule.udprange.op == range) {
            triesleft = MIN(10,
            ntohs(io.rule.udprange.end) - ntohs(io.rule.udprange.start) + 1);

            srandom(sockscf.state.pid);
         }
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
            /* XXX add check for privileges on startup if range is privileged*/
         } while (rc == -1 && (errno == EADDRINUSE || ERRNOISACCES(errno))
         && io.rule.udprange.op == range && --triesleft > 0);
#endif /* SOCKS_SERVER */

         if (rc != 0 && io.rule.udprange.op) {
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
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "bind(%s): %s",
               sockaddr2string(&io.src.laddr, strhost, sizeof(strhost)),
               strerror(errno));

               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(clientfd);
            close(out);
            break;
         }

         if (ADDRISBOUND(TOIN(&io.src.raddr))) {
            slog(LOG_DEBUG, "%s: connecting to udp client at address %s",
            function, sockaddr2string(&io.src.raddr, NULL, 0));

            /* faster and better. */
            connect(io.src.s, &io.src.raddr, sizeof(io.src.raddr));
         }

         boundlen = sizeof(io.src.laddr);
         if (getsockname(clientfd, &io.src.laddr, &boundlen) != 0) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "getsockname(): %s", strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(clientfd);
            close(out);
            break;
         }

         slog(LOG_DEBUG, "%s: address bound on client side for udp: %s",
         function, sockaddr2string(&io.src.laddr, NULL, 0));

         io.dst.s = out;
         boundlen = sizeof(io.dst.laddr);
         if (getsockname(out, &io.dst.laddr, &boundlen) != 0) {
            if (io.rule.log.error) {
               snprintf(msg, sizeof(msg), "getsockname(): %s", strerror(errno));
               iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
               &io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
            }

            send_failure(request->s, &response, SOCKS_FAILURE);
            close(request->s);
            close(clientfd);
            close(out);
            break;
         }

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
         response.reply = (char)sockscode(response.version, SOCKS_SUCCESS);

         flushio(mother, request->s, &response, &io);
         break;
      }

      default:
         SERRX(io.state.command);
   }

#if DIAGNOSTIC
   SASSERT(close(out) == -1 && errno == EBADF);
#endif /* DIAGNOSTIC */
}

static void
flushio(mother, clientcontrol, response, io)
   int mother;
   int clientcontrol;
   const struct response_t *response;
   struct sockd_io_t *io;
{
   const char *function = "flushio()";
   socklen_t len;
#if HAVE_SO_SNDLOWAT
   int value;
#endif /* HAVE_SO_SNDLOWAT */
   int sndlowat;
   float skew;

   switch (io->state.command) {
      case SOCKS_UDPASSOCIATE:
         sndlowat = SOCKD_BUFSIZE;
         skew     = 1.0; /* no skew. */
         break;

      default:
         sndlowat = SOCKD_BUFSIZE;
         skew     = LOWATSKEW;
   }

   /* set socket options for relay process. */

#if HAVE_SO_SNDLOWAT
   len = sizeof(value);
   if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDBUF, &value, &len) != 0)
      swarn("%s: getsockopt(io->src.s, SO_SNDBUF)", function);
   sndlowat = MIN(sndlowat, value * skew);

   if (setsockopt(io->src.s, SOL_SOCKET, SO_SNDLOWAT, &sndlowat,
   sizeof(sndlowat)) != 0)
      swarn("%s: setsockopt(in, SO_SNDLOWAT)", function);

   len = sizeof(io->src.sndlowat);
   if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDLOWAT, &io->src.sndlowat, &len)
   != 0)
      swarn("%s: getsockopt(io-.src.s, SO_SNDLOWAT)", function);

   len = sizeof(value);
   if (getsockopt(io->dst.s, SOL_SOCKET, SO_SNDBUF, &value, &len) != 0)
      swarn("%s: getsockopt(io->dst.s, SO_SNDBUF)", function);
   sndlowat = MIN(sndlowat, value * skew);

   if (setsockopt(io->dst.s, SOL_SOCKET, SO_SNDLOWAT, &sndlowat,
   sizeof(sndlowat)) != 0)
      swarn("%s: setsockopt(io->dst.s, SO_SNDLOWAT", function);

   len = sizeof(io->dst.sndlowat);
   if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDLOWAT, &io->dst.sndlowat, &len)
   != 0)
      swarn("%s: getsockopt(io->src.s, SO_SNDLOWAT)", function);
#else
   switch (io->state.command) {
      case SOCKS_UDPASSOCIATE:
         len = sizeof(sndlowat);
         if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDBUF, &sndlowat, &len)
         != 0) {
            swarn("%s: getsockopt(io->src.s, SO_SNDBUF)", function);
            io->src.sndlowat = SOCKD_BUFSIZE;
         }
         else if (sndlowat == 0)
            io->src.sndlowat = SOCKD_BUFSIZE;
         else
            io->src.sndlowat = sndlowat;

         len = sizeof(sndlowat);
         if (getsockopt(io->dst.s, SOL_SOCKET, SO_SNDBUF, &sndlowat, &len)
         != 0) {
            swarn("%s: getsockopt(io->dst.s, SO_SNDBUF)", function);
            io->dst.sndlowat = SOCKD_BUFSIZE;
         }
         else if (sndlowat == 0)
            io->dst.sndlowat = SOCKD_BUFSIZE;
         else
            io->dst.sndlowat = sndlowat;
         break;

      default:
         /* TCP; use minimum guess. */
         io->src.sndlowat = SO_SNDLOWAT_SIZE;
         io->dst.sndlowat = SO_SNDLOWAT_SIZE;
   }
#endif /* HAVE_SO_SNDLOWAT. */

   SASSERTX(io->src.sndlowat > 0
   && (size_t)io->dst.sndlowat >= sizeof(struct udpheader_t));

   if (send_response(clientcontrol, response) == 0) {
#if HAVE_GSSAPI
      if (response->auth->method == AUTHMETHOD_GSSAPI) {
         OM_uint32 minor_status, major_status, maxlen;
         char emsg[1024];

         major_status
         = gss_wrap_size_limit(&minor_status,
                               response->auth->mdata.gssapi.state.id,
                               response->auth->mdata.gssapi.state.protection
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
                                "That can't be right ...",
                                function, MAXGSSAPITOKENLEN - GSSAPI_HLEN,
                                maxlen);

         if (sockscf.option.debug > 1)
            slog(LOG_DEBUG, "%s: gss_wrap_size_limit() for socket %d is %lu",
            function, clientcontrol, (unsigned long)maxlen);

         if (io->control.auth.method == AUTHMETHOD_GSSAPI)
            io->control.maxgssdata = maxlen;

         if (io->src.auth.method == AUTHMETHOD_GSSAPI)
            io->src.maxgssdata = maxlen;

         if (io->dst.auth.method == AUTHMETHOD_GSSAPI)
            io->dst.maxgssdata = maxlen;
      }
#endif /* HAVE_GSSAPI */

      gettimeofday(&io->state.time.established, NULL);
      if (send_io(mother, io) != 0)
         serr(EXIT_FAILURE, "%s: sending io to mother failed", function);
   }

   close_iodescriptors(io);
}

static void
proctitleupdate(from)
   const struct sockaddr *from;
{
   setproctitle("requestcompleter: %s", from == NULL ?  "0/1" : "1/1");
}

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

   /* XXX should actually check that the io is still "active". */

   return NULL;
}

static int
serverchain(s, req, res, src, dst)
   int s;
   const struct request_t *req;
   struct response_t *res;
   struct sockd_io_direction_t *src, *dst;
{
   const char *function = "serverchain()";
   struct route_t *route;
   struct socks_t packet;

   if (sockscf.route == NULL) {
      errno = 0;
      return -1;
   }

   packet.req = *req;
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

   /* in case of sighup adding a route. */
   if (route->gw.state.proxyprotocol.direct) {
      errno = 0;
      return -1;
   }

   if (socks_negotiate(s, s, &packet, route) != 0) {
      slog(LOG_DEBUG, "%s: socks_negotiate() failed: %s",
      function, strerror(errno));

      return -1;
   }

   convertresponse(&packet.res, res, req->version);

   /* when we reply, we have to use our clients auth ... */
   res->auth = &src->auth;

   /* ... but when we talk to remote, we have to use remotes auth. */
   dst->auth = *packet.res.auth;

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

   slog(LOG_DEBUG, "%s: converting from version %d to version %d",
   function, oldres->version, newversion);

   if (oldres->version == newversion) {
      *newres = *oldres;
      return;
   }

   switch (oldres->version) {
      case PROXY_HTTP_V1_0:
         switch (oldres->reply) {
            case HTTP_SUCCESS:
               reply = SOCKS_SUCCESS;
               break;

            default:
               reply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_UPNP:
         switch (oldres->reply) {
            case UPNP_SUCCESS:
               reply = SOCKS_SUCCESS;
               break;

            default:
               reply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_SOCKS_V4REPLY_VERSION:
         switch (oldres->reply) {
            case SOCKSV4_SUCCESS:
               reply = SOCKS_SUCCESS;
               break;

            default:
               reply = SOCKS_FAILURE;
               break;
         }
         break;

      case PROXY_SOCKS_V5: /* base format. */
         reply = oldres->reply;
         break;

      default:
         swarnx("%s: unknown proxy protocol: %d", function, oldres->version);
         reply   = SOCKS_FAILURE;
   }

   if (newversion == PROXY_SOCKS_V4) {
      if (oldres->host.atype != SOCKS_ADDR_IPV4) {
         /* v4 only supports ipaddr. */
         struct sockaddr addr;

         sockshost2sockaddr(&oldres->host, &addr);
         sockaddr2sockshost(&addr, &newres->host);
      }

      newres->flag    = 0; /* no flagbits in v4. */
      newres->version = PROXY_SOCKS_V4REPLY_VERSION;
   }
   else {
      newres->host    = oldres->host;
      newres->version = newversion;
   }

   newres->auth  = oldres->auth;
   newres->reply = sockscode(newres->version, reply);
}

static void
send_failure(s, response, failure)
   int s;
   struct response_t *response;
   int failure;
{
#if BAREFOOTD
   /* NOP */
#endif /* !BAREFOOTD */

#if HAVE_GSSAPI
   const char *function = "send_failure()";
   gss_buffer_desc output_token;
   OM_uint32 minor_status;
#endif /* HAVE_GSSAPI */

   response->reply = (unsigned char)sockscode(response->version, failure);
   send_response(s, response);

#if HAVE_GSSAPI
   if (response->auth->method == AUTHMETHOD_GSSAPI) {
      if (gss_delete_sec_context(&minor_status,
         &response->auth->mdata.gssapi.state.id, &output_token)
         != GSS_S_COMPLETE)
            swarn("%s: gss_delete_sec_context failed", function);

      CLEAN_GSS_TOKEN(output_token);
   }
#endif /* HAVE_GSSAPI */
}
