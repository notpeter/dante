/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2005, 2006, 2008,
 *               2009, 2010, 2011, 2012
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
"$Id: sockd_negotiate.c,v 1.326 2012/06/01 20:23:06 karls Exp $";

static sockd_negotiate_t negv[SOCKD_NEGOTIATEMAX];
static const size_t negc = ELEMENTS(negv);

static void siginfo(int sig, siginfo_t *sip, void *scp);

static int
send_negotiate(sockd_negotiate_t *neg);
/*
 * Sends "neg" to "mother".
 * Returns:
 *      On success: 0
 *      On error: -1.  If error was in relation to sending to mother,
 *                     errno will be set.
 */

static int
recv_negotiate(void);
/*
 * Tries to receive a client from mother.
 * Returns: the number of new clients received on success, or -1 on error.
 *
 * Note that a return of 0 does not indicate an error, but does mean
 * no new clients were added, most likely because none of the clients
 * received passed the ACL-checks.
 */

static void
delete_negotiate(sockd_negotiate_t *neg, const int doackfreeslot);
/*
 * Frees any state occupied by "neg", including closing any descriptors.
 * If "doackfreeslot" is set, ack to mother that we have freed a slot.
 */

static int
neg_fillset(fd_set *set, const int skipcompleted, const int skipinprogress);
/*
 * Sets all client descriptors in our list in the set "set".
 *
 * If "skipcompleted" is set, skip those descriptors that belong to
 * clients that have completed negotiation.
 *
 * If "skipinprogress" is set, skip those descriptors that belong to
 * clients that have not yet completed negotiation.
 *
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors open currently.
 */

static void
neg_clearset(sockd_negotiate_t *neg, fd_set *set);
/*
 * Clears all file descriptors in "neg" from "set".
 */

static sockd_negotiate_t *
neg_getset(fd_set *set);
/*
 * Goes through our list until it finds a negotiate object where at least
 * one of the descriptors is set, or where the negotiation has completed,
 * which always implies the descriptor is "set".
 *
 * Returns:
 *      On success: pointer to the found object.
 *      On failure: NULL.
 */

static size_t
completed(const size_t howmany);
/*
 * Returns the number of objects completed and ready to be sent currently.
 * The function stops counting when a count of "howmany" is reached.
 */

static size_t
allocated(void);
/*
 * Returns the number of objects currently allocated for use.
 */

static void
proctitleupdate(void);
/*
 * Updates the title of this process.
 */

static struct timeval *
neg_gettimeout(struct timeval *timeout);
/*
 * Fills in "timeout" with time til the first clients connection
 * expires.
 * Returns:
 *      If there is a timeout: pointer to filled in "timeout".
 *      If there is no timeout: NULL.
 */

#if HAVE_NEGOTIATE_PHASE
static sockd_negotiate_t *
neg_gettimedout(void);
/*
 * Scans all clients for one that has timed out according to sockscf
 * settings.
 * Returns:
 *      If timed out client found: pointer to it.
 *      Else: NULL.
 */
#endif /* HAVE_NEGOTIATE_PHASE */

static void
neg_clearset(sockd_negotiate_t *neg, fd_set *set);
/*
 * Clears all file descriptors in "neg" from "set".
 */

static sockd_negotiate_t *
neg_getset(fd_set *set);
/*
 * Goes through our list until it finds a negotiate object where at least
 * one of the descriptors is set, or where the negotiation has completed,
 * which always implies the descriptor is "set".
 *
 * Returns:
 *      On success: pointer to the found object.
 *      On failure: NULL.
 */

static size_t
completed(const size_t howmany);
/*
 * Returns the number of objects completed and ready to be sent currently.
 * The function stops counting when a count of "howmany" is reached.
 */

static size_t
allocated(void);
/*
 * Returns the number of objects currently allocated for use.
 */

static void
proctitleupdate(void);
/*
 * Updates the title of this process.
 */

static struct timeval *
neg_gettimeout(struct timeval *timeout);
/*
 * Fills in "timeout" with time til the first clients connection
 * expires.
 * Returns:
 *      If there is a timeout: pointer to filled in "timeout".
 *      If there is no timeout: NULL.
 */

#if HAVE_NEGOTIATE_PHASE
static sockd_negotiate_t *
neg_gettimedout(void);
/*
 * Scans all clients for one that has timed out according to sockscf
 * settings.
 * Returns:
 *      If timed out client found: pointer to it.
 *      Else: NULL.
 */
#endif /* HAVE_NEGOTIATE_PHASE */

void
run_negotiate()
{
   const char *function = "run_negotiate()";
   struct sigaction sigact;
   fd_set *rset, *rsetbuf, *tmpset, *wsetmem;
   int sendfailed;

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


   rset        = allocate_maxsize_fdset();
   rsetbuf     = allocate_maxsize_fdset();
   tmpset      = allocate_maxsize_fdset();
   wsetmem     = allocate_maxsize_fdset();

   proctitleupdate();

   sockd_print_child_ready_message((size_t)freedescriptors(NULL));

   sendfailed  = 0;
   while (1 /* CONSTCOND */) {
      negotiate_result_t negstatus;
      fd_set *wset;
      int fdbits;
      sockd_negotiate_t *neg;
      struct timeval *timeout, timeoutmem;

      errno = 0; /* reset for each iteration. */


#if HAVE_NEGOTIATE_PHASE
      while ((neg = neg_gettimedout()) != NULL) {
         iologaddr_t src;

         init_iologaddr(&src,
                        SOCKSHOST_OBJECT,
                        &neg->negstate.dst,
                        SOCKSHOST_OBJECT,
                        &neg->negstate.src,
                        &neg->clientauth,
                        GET_HOSTIDV(&neg->state),
                        GET_HOSTIDC(&neg->state));

         iolog(&neg->rule,
               &neg->state,
               OPERATION_ERROR,
               &src,
               NULL,
               NULL,
               NULL,
               "negotiation timed out",
               0);

         delete_negotiate(neg, 1);
      }

      fdbits = neg_fillset(rset,
                           sendfailed, /*
                                        * If we've previously failed sending
                                        * the completed clients back to mother,
                                        * don't bother select(2)ing o them
                                        * for readability; can't send them
                                        * until we know mother is writable.
                                        */
                           0);         /*
                                        * clients where negotiation is not
                                        * yet completed we want to continue
                                        * negotiating with.
                                        */
#else /* !HAVE_NEGOTIATE_PHASE */

      /*
       * don't bother checking here.  All, if any, should be completed.
       * Meaning, completed(1) will be true and no timeout will be set
       * on select(2), unless sending to mother failed.
       */
      fdbits = -1;
      FD_ZERO(rset);

#endif /* HAVE_NEGOTIATE_PHASE */

      FD_COPY(rsetbuf, rset);

      if (completed(1) && !sendfailed) {
         timeout         = &timeoutmem;
         timeout->tv_sec = timeout->tv_usec = 0;
      }
      else
         timeout = neg_gettimeout(&timeoutmem);

      FD_SET(sockscf.state.mother.s, rset);
      fdbits = MAX(fdbits, sockscf.state.mother.s);

      if (sendfailed) {
         /*
          * Previously failed sending a request to mother.
          * Pull in select this time to check; normally we don't
          * bother and just assume mother will be able to accept it.
          */
         FD_ZERO(wsetmem);
         FD_SET(sockscf.state.mother.s, wsetmem);
         wset = wsetmem;

         fdbits     = MAX(fdbits, sockscf.state.mother.s);
         sendfailed = 0;
      }
      else
         wset = NULL;

      /* also check ack-pipe so we know if mother goes away.  */
      FD_SET(sockscf.state.mother.ack, rset);
      fdbits = MAX(fdbits, sockscf.state.mother.ack);

      SASSERTX(fdbits >= 0);

      ++fdbits;
      switch (selectn(fdbits, rset, rsetbuf, NULL, wset, NULL, timeout)) {
         case -1:
            if (errno == EINTR)
               continue;

            SERR(-1);
            /* NOTREACHED */

         case 0:
            if (completed(1))
               break;
            else
               continue;
      }

#if !HAVE_NEGOTIATE_PHASE
      /*
       * since we have no negotiate phase, any fd's should be "readable", or
       * in practice, "completed", so just add them to what is reported
       * as readable by selectn() (could only be mother).
       */
      fdbits = MAX(fdbits, neg_fillset(tmpset, 0, 1));

      fdsetop(fdbits, '|', rset, tmpset, rset);
#else /* HAVE_NEGOTIATE_PHASE */

      fdsetop(fdbits, '|', rset, rsetbuf, rset);

      /*
       * Those descriptors that have completed negotiation we want to
       * consider readable/ready, so we know to call recv_clientrequest()
       * on them.
       */
      fdbits = MAX(fdbits, neg_fillset(tmpset, 0, 1));
      fdsetop(fdbits, '|', rset, tmpset, rset);
#endif /* HAVE_NEGOTIATE_PHASE */

      if (FD_ISSET(sockscf.state.mother.ack, rset)) {
         slog(LOG_DEBUG,
              "%s: mother closed it's connection to us.  We should exit",
              function);

         sockdexit(EXIT_SUCCESS);
      }

      if (FD_ISSET(sockscf.state.mother.s, rset)) {
         if (recv_negotiate() == -1) {
            slog(LOG_DEBUG, "%s: not expecting recv_negotiate() to fail (%s) "
                            "unless mother is exiting ... restarting loop to "
                            "find out more before continuing",
                            function, strerror(errno));
            continue;
         }

         FD_CLR(sockscf.state.mother.s, rset);
      }

      while ((neg = neg_getset(rset)) != NULL) {
         neg_clearset(neg, rset);

         errno     = 0; /* reset before each client. */
         negstatus = recv_clientrequest(neg->s, &neg->req, &neg->negstate);

         slog(LOG_DEBUG,
              "%s: recv_clientrequest() from client %s returned %d, "
              "errno is %d (%s)",
              function,
              sockshost2string(&neg->negstate.src, NULL, 0),
              negstatus,
              errno,
              errno == 0 ? "no error"
              : ERRNOISTMP(errno) ? "temp error" : "fatal error");

         if (negstatus == NEGOTIATE_CONTINUE)
            continue;
         else if (negstatus == NEGOTIATE_FINISHED) {
#if HAVE_SOCKS_RULES
            /*
             * Barefoot uses the ss-limits in the client-rule for all phases,
             * while Dante has separate limits for client and
             * socks-phases, so Dante can unuse the session now, making
             * it possible to accept new ones.  Safer and easier do it
             * here, since negotiation has indeed finished.
             */
            if (neg->rule.ss_shmid != 0)
               sockd_shmat(&neg->rule, SHMEM_SS);

            if (neg->rule.ss_shmid != 0) {
               session_unuse(neg->rule.ss, sockscf.shmemfd);
               sockd_shmdt(&neg->rule, SHMEM_SS);
               neg->rule.ss_shmid = 0;
               neg->rule.ss_fd    = -1;
            }
#endif /* HAVE_SOCKS_RULES */

            if (!timerisset(&neg->state.time.negotiateend))
               gettimeofday(&neg->state.time.negotiateend, NULL);

#if COVENANT
            if (neg->negstate.havedonerulespermit)
               slog(LOG_DEBUG, "%s: must have failed to send client %s to "
                               "mother before ... trying again",
                               function,
                               sockshost2string(&neg->negstate.src, NULL, 0));
            else {
               /*
                * Need to do rulespermit() of second-level acl in this
                * process as well, as if it fails due to missing proxy
                * authentication we need to inform the client and restart
                * negotiation (i.e., wait for the client to repeat the
                * request, but this time with proxy authentication).
                */
               struct sockaddr_storage src, dst;
               char srchost[MAXSOCKSHOSTSTRING], dsthost[MAXSOCKSHOSTSTRING];
               int permit;

               sockshost2sockaddr(&neg->negstate.src, &src);
               sockshost2sockaddr(&neg->negstate.dst, &dst);

               neg->state.command = neg->req.command;
               neg->state.version = neg->req.version;

               slog(LOG_DEBUG,
                    "%s: doing second-level acl check on %s -> %s",
                    function,
                    sockaddr2string(&src, srchost, sizeof(srchost)),
                    sockshost2string(&neg->req.host, dsthost, sizeof(dsthost)));
               permit = rulespermit(neg->s,
                                    &src,
                                    &dst,
                                    &neg->clientauth,
                                    &neg->socksauth,
                                    &neg->srule,
                                    &neg->state,
                                    &neg->negstate.src,
                                    &neg->req.host,
                                    neg->negstate.emsg,
                                    sizeof(neg->negstate.emsg));

               if (permit)
                  neg->negstate.havedonerulespermit = 1;
               else {
                  iologaddr_t src;
                  response_t response;

                  if (neg->srule.whyblock.missingproxyauth) {
                     if (!neg->negstate.haverequestedproxyauth) {
                        slog(LOG_DEBUG, "%s: telling client at %s to provide "
                                        "proxy authentication before "
                                        "restarting negotiation",
                                        function,
                                        sockaddr2string(&src, NULL, 0));

                        bzero(&response, sizeof(response));
                        response.version    = neg->state.version;
                        response.host       = neg->req.host;
                        response.reply.http = response.version == PROXY_HTTP_10?
                        HTTP_NOTALLOWED : HTTP_PROXYAUTHREQUIRED;

                        send_response(neg->s, &response);

                        neg->negstate.complete               = 0;
                        neg->negstate.haverequestedproxyauth = 1;
                        bzero(neg->negstate.mem, sizeof(neg->negstate.mem));

                        continue;
                     }

                     slog(LOG_DEBUG, "%s: already told client at %s to provide "
                                     "proxy authentication, but again it sent "
                                     "us a request without authentication",
                                     function,  sockaddr2string(&src, NULL, 0));
                  }

                  /*
                   * only log on deny.  Pass will be logged as usual later.
                   */

                  init_iologaddr(&src,
                                 SOCKSHOST_OBJECT,
                                 &neg->negstate.dst,
                                 SOCKSHOST_OBJECT,
                                 &neg->negstate.src,
                                 &neg->clientauth,
                                 GET_HOSTIDV(&neg->state),
                                 GET_HOSTIDC(&neg->state));

                  iolog(&neg->srule,
                        &neg->state,
                        OPERATION_CONNECT,
                        &src,
                        NULL,
                        NULL,
                        NULL,
                        neg->negstate.emsg,
                        0);

                  bzero(&response, sizeof(response));
                  response.version    = neg->state.version;
                  response.host       = neg->req.host;
                  response.reply.http = HTTP_FORBIDDEN;

                  send_response(neg->s, &response);
                  delete_negotiate(neg, 1);

                  continue;
               }
            }
#endif /* COVENANT */

            if (wset != NULL && !FD_ISSET(sockscf.state.mother.s, wset)) {
               sendfailed = 1;
               continue; /* don't bother trying to send to mother now. */
            }

            errno = 0;
            if (send_negotiate(neg) == 0) {
               delete_negotiate(neg, 0);
               sendfailed = 0;
            }
            else if (ERRNOISTMP(errno))
               sendfailed = 1; /* we will retry sending this object later. */
            else {
               if (errno != 0)
                  slog(LOG_INFO,
                       "%s: could not send client %s to mother: %s",
                       function,
                       sockshost2string(&neg->negstate.src, NULL, 0),
                       strerror(errno));

               delete_negotiate(neg, 1);

               /*
                * assume what failed was not related to the send to mother,
                * but some (network) error related to the connection between
                * us and the client.  If the error is between us and mother,
                * it will be picked up on the control-pipe.
                */
               sendfailed = 0;
            }
         }
         else if (negstatus == NEGOTIATE_ERROR) {
            const char *error;
            iologaddr_t src;
            char reason[256];
#if HAVE_GSSAPI
            gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
            OM_uint32 minor_status;
#endif /* HAVE_GSSAPI */

            if (ERRNOISTMP(errno))
               continue;

            if (*neg->negstate.emsg == NUL) {
               if (errno == 0) {
                  if (neg->negstate.reqread == 0)
                     error = "eof from client";
                  else
                     error = "client protocol error";
               }
               else
                  error = strerror(errno);
            }
            else
               error = neg->negstate.emsg;

            snprintf(reason, sizeof(reason),
                    "error after having read %lu bytes: %s",
                    (unsigned long)neg->negstate.reqread, error);

            init_iologaddr(&src,
                           SOCKSHOST_OBJECT,
                           &neg->negstate.dst,
                           SOCKSHOST_OBJECT,
                           &neg->negstate.src,
                           &neg->clientauth,
                           GET_HOSTIDV(&neg->state),
                           GET_HOSTIDC(&neg->state));

            iolog(&neg->rule,
                  &neg->state,
                  OPERATION_ERROR,
                  &src,
                  NULL,
                  NULL,
                  NULL,
                  reason,
                  0);

#if HAVE_GSSAPI
            if (neg->socksauth.method == AUTHMETHOD_GSSAPI
            && neg->socksauth.mdata.gssapi.state.id != GSS_C_NO_CONTEXT)
               if (gss_delete_sec_context(&minor_status,
                  &neg->socksauth.mdata.gssapi.state.id, &output_token)
                  != GSS_S_COMPLETE)
                     swarn("%s: gss_delete_sec_context failed", function);
#endif /* HAVE_GSSAPI */

            delete_negotiate(neg, 1);
         }
      }
   }
}

static int
send_negotiate(neg)
   sockd_negotiate_t *neg;
{
   const char *function = "send_negotiate()";
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   struct iovec iov[2];
   sockd_request_t req;
   struct msghdr msg;
   ssize_t w;
   size_t length, ioc, fdsendt;
   CMSG_AALLOC(cmsg, sizeof(int));

   /*
    * copy needed fields from negotiate.
    */
   bzero(&req, sizeof(req)); /* silence valgrind warning */
   sockshost2sockaddr(&neg->negstate.src, TOSA(&req.from));
   sockshost2sockaddr(&neg->negstate.dst, TOSA(&req.to));
   req.req             = neg->req;

   req.reqinfo.command = (neg->state.protocol == SOCKS_TCP ?
                              SOCKD_FREESLOT_TCP : SOCKD_FREESLOT_UDP);

#if HAVE_NEGOTIATE_PHASE
   /*
    * save initial requestdata from client, if any.
    */

#if COVENANT

   if (neg->req.flags.httpconnect)
      length = 0;
   else {
      /* XXX should probably strip out any authorization headers if present. */
      length = neg->negstate.reqread;
      memcpy(req.clientdata, neg->negstate.mem, length);
   }

#else /* SOCKS_SERVER */
   if ((length = socks_bytesinbuffer(neg->s, READ_BUF, 0)) != 0) {
      slog(length > sizeof(req.clientdata) ? LOG_INFO : LOG_DEBUG,
           "%s: socks client at %s sent us %lu bytes of payload before we told "
           "it it can do that.  Not permitted by the SOCKS standard.  %s",
           function,
           socket2string(neg->s, NULL, 0),
           (unsigned long)length,
           length > sizeof(req.clientdata) ?
                 "Too much unexpected data for us to handle"
               : "Trying to handle it however");

      if (length > sizeof(req.clientdata))
        return -1;

      socks_getfrombuffer(neg->s, READ_BUF, 0, req.clientdata, length);
   }
#endif /* SOCKS_SERVER */

    req.clientdatalen = length;

    if (req.clientdatalen > 0)
       slog(LOG_DEBUG,
            "%s: saving client data of length %lu for later forwarding",
            function, (unsigned long)req.clientdatalen);
#endif /* HAVE_NEGOTIATE_PHASE */

   req.rule             = neg->rule;

#if HAVE_SOCKS_HOSTID
   req.hostidrule       = neg->hostidrule;
   req.hostidrule_isset = neg->hostidrule_isset;
#endif /* HAVE_SOCKS_HOSTID */

#if COVENANT
   req.srule         = neg->srule;
#endif /* COVENANT */

   req.clientauth    = neg->clientauth;
   req.socksauth     = neg->socksauth;

   req.state         = neg->state;
   req.state.command = req.req.command;
   req.state.version = req.req.version;

   bzero(iov, sizeof(iov));
   ioc               = 0;
   length            = 0;
   iov[ioc].iov_base = &req;
   iov[ioc].iov_len  = sizeof(req);
   length           += iov[ioc].iov_len;
   ++ioc;

#if HAVE_GSSAPI
   if (req.socksauth.method == AUTHMETHOD_GSSAPI) {
      gssapistate.value   = gssapistatemem;
      gssapistate.length  = sizeof(gssapistatemem);

      if (gssapi_export_state(&req.socksauth.mdata.gssapi.state.id,
      &gssapistate) != 0)
         return -1;

      iov[ioc].iov_base = gssapistate.value;
      iov[ioc].iov_len  = gssapistate.length;
      length           += iov[ioc].iov_len;
      ++ioc;

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: gssapistate has length %lu",
         function, (long unsigned)gssapistate.length);
   }
#endif /* HAVE_GSSAPI */

   fdsendt = 0;

#if BAREFOOTD
   if (req.state.command != SOCKS_UDPASSOCIATE)
      /* udp has no control/client socket until set up in request-child. */
      CMSG_ADDOBJECT(neg->s, cmsg, sizeof(neg->s) * fdsendt++);

#else /* !BAREFOOTD */

   CMSG_ADDOBJECT(neg->s, cmsg, sizeof(neg->s) * fdsendt++);

#endif /* !BAREFOOTD */

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ioc;
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsendt);

   if (sockscf.option.debug >= DEBUG_VERBOSE) {
      slog(LOG_DEBUG, "%s: sending request to mother, "
                      "bw_shmid = %ld, ss_shmid = %ld",
                      function,
                      req.rule.bw_shmid, req.rule.ss_shmid);

      if (neg->s != -1)
         slog(LOG_DEBUG, "%s: sending socket %d (%s) ...",
              function, neg->s, socket2string(neg->s, NULL, 0));
   }

   if ((w = sendmsgn(sockscf.state.mother.s, &msg, 0, 100)) != (ssize_t)length)
      slog(LOG_INFO, "%s: sendmsg() failed: sent %ld/%lu: %s",
                     function, (long)w, (unsigned long)length, strerror(errno));
   else {
      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: sent %ld descriptors for command %d.  "
                         "clientauth %s, socksauth %s, neg->s %d",
                         function, (unsigned long)fdsendt, req.state.command,
                         method2string(req.clientauth.method),
                         method2string(req.socksauth.method),
                         neg->s);
   }

   return (size_t)w == length ? 0 : -1;
}

static int
recv_negotiate(void)
{
   const char *function = "recv_negotiate()";
   sockd_client_t client;
   sockd_negotiate_t *neg;
   struct iovec iov[1];
   struct msghdr msg;
   ssize_t r;
   size_t i, newc, failedc;
   CMSG_AALLOC(cmsg, sizeof(int));
   char ruleinfo[256];
   int permit, fdreceived;

   bzero(iov, sizeof(iov));
   iov[0].iov_base = &client;
   iov[0].iov_len  = sizeof(client);

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ELEMENTS(iov);
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

   newc = failedc = 0;
   while (1) { /* until it blocks. */
      const size_t fdexpect = 1;
      iologaddr_t src, dst;

      if ((r = recvmsgn(sockscf.state.mother.s, &msg, 0)) != sizeof(client)) {
         switch (r) {
            case -1:
            case 0:
               slog(LOG_DEBUG,
                    "%s: recvmsg() from mother returned %ld after having "
                    "received %lu new clients and %lu failed/blocked clients.  "
                    "errno = %d (%s)",
                    function, (long)r,
                    (unsigned long)newc, (unsigned long)failedc,
                    errno, strerror(errno));
               break;

            default:
               swarnx("%s: recvmsg(): unexpected short read from mother after "
                      "having received %lu new clients.  Got %ld/%lu bytes",
                      function,
                      (unsigned long)newc,
                      (long)r,
                      (unsigned long)sizeof(client));
         }

         if (newc > 0 || ERRNOISTMP(errno)) {
            errno = 0;
            return newc;
         }
         else
            return -1;
      }

      if (socks_msghaserrors(function, &msg)) {
         ++failedc;
         continue;
      }

      /*
       * Got packet of expected size, now find a free slot for it.
       */
      for (i = 0, neg = NULL; i < negc; ++i)
         if (!negv[i].allocated) {
            /* don't allocate it yet, so siginfo() doesn't print before ready */
            neg = &negv[i];
            break;
         }

      if (neg == NULL)
         SERRX(allocated());

      if (!CMSG_RCPTLEN_ISOK(msg, sizeof(int) * fdexpect)) {
         swarnx("%s: received control message has the invalid len of %d",
                 function, (int)CMSG_TOTLEN(msg));

         ++failedc;
         continue;
      }

      SASSERTX(cmsg->cmsg_level == SOL_SOCKET);
      SASSERTX(cmsg->cmsg_type  == SCM_RIGHTS);

      fdreceived = 0;
      CMSG_GETOBJECT(neg->s, cmsg, sizeof(neg->s) * fdreceived++);

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: received socket %d (%s) ...",
              function, neg->s, socket2string(neg->s, NULL, 0));

      neg->state.time.accepted = client.accepted;
      gettimeofday(&neg->state.time.negotiatestart, NULL);

      sockd_isoverloaded("client object received from mother",
                         &neg->state.time.accepted,
                         &neg->state.time.negotiatestart,
                         &neg->state.time.negotiatestart);

      /*
       * init state correctly for checking a connection to us.
       */

      sockaddr2sockshost(TOSA(&client.from), &neg->negstate.src);
      sockaddr2sockshost(TOSA(&client.to), &neg->negstate.dst);

      neg->state.command       = SOCKS_ACCEPT;
      neg->state.protocol      = neg->state.clientprotocol = SOCKS_TCP;

      neg->req.auth            = &neg->socksauth;   /* pointer fixup    */
      neg->clientauth.method   = AUTHMETHOD_NOTSET; /* nothing so far   */

      permit = rulespermit(neg->s,
                           TOSA(&client.from),
                           TOSA(&client.to),
#if BAREFOOTD
                           &neg->negstate.dst,
#endif /* BAREFOOTD */
                           NULL,
                           &neg->clientauth,
                           &neg->rule,
                           &neg->state,
                           &neg->negstate.src,
                           &neg->negstate.dst,
                           ruleinfo,
                           sizeof(ruleinfo));

      setconfsockoptions(neg->s,
                         -1,
                         SOCKS_TCP,
                         1,
                         neg->rule.socketoptionc,
                         neg->rule.socketoptionv,
                         SOCKETOPT_ANYTIME | SOCKETOPT_POST,
                         SOCKETOPT_ANYTIME | SOCKETOPT_POST);

      /*
       * Might need to use some values from clientauth when negotiating,
       * i.e. gssapi or pam-values.  Also, in some cases (gssapi), the
       * authmethod to be used for socks negotiation needs to be
       * set at the client acl pass, so start by copying the current
       * clientauth into what will become the socksauth proper.
       */
      neg->socksauth = neg->clientauth;

      /* but don't actually set the authmethod.  rulespermit() will do that. */
      neg->socksauth.method = AUTHMETHOD_NOTSET;

      if (neg->socksauth.method != AUTHMETHOD_GSSAPI)
         neg->socksauth.method = AUTHMETHOD_NOTSET; /* default. */

      if (permit)  {
         sockd_shmat(&neg->rule, SHMEM_ALL);

         if (neg->rule.ss_shmid != 0) {
            if (!session_use(neg->rule.ss, sockscf.shmemfd)) {
               permit            = 0;
               neg->rule.verdict = VERDICT_BLOCK;
               snprintf(ruleinfo, sizeof(ruleinfo), DENY_SESSIONLIMITs);
            }
         }

         if (permit) {
            if (neg->rule.bw_shmid != 0)
               bw_use(neg->rule.bw, sockscf.shmemfd);
         }

         sockd_shmdt(&neg->rule, SHMEM_ALL);
      }


#if !HAVE_SOCKS_RULES
      /*
       * don't have separate client-rules and socks-rules as far as the user
       * is concerned so only log socks-rule normally, unless it's a block.
       * If it's a block, this is the only logging that will be done, so
       * do it now.
       */

      if (!permit) /* really SOCKS_ACCEPT, but user does not know about that. */
         neg->state.command = SOCKS_CONNECT;

      if (sockscf.option.debug || !permit) {
#endif /* !HAVE_SOCKS_RULES */

      init_iologaddr(&src,
                     SOCKADDR_OBJECT,
                     &client.to,
                     SOCKSHOST_OBJECT,
                     &neg->negstate.src,
                     &neg->clientauth,
                     GET_HOSTIDV(&neg->state),
                     GET_HOSTIDC(&neg->state));

      init_iologaddr(&dst,
                     NOOBJECT,
                     NULL,
                     SOCKSHOST_OBJECT,
#if BAREFOOTD
                     ruleaddr2sockshost(&neg->rule.extra.bounceto,
                                        NULL,
                                        SOCKS_TCP),
#else /* !BAREFOOTD */
                     NULL,
#endif /* !BAREFOOTD */
                     NULL,
                     NULL,
                     0);

      iolog(&neg->rule,
            &neg->state,

#if HAVE_SOCKS_RULES
            permit ? OPERATION_ACCEPT  : OPERATION_BLOCK,
#else /* !HAVE_SOCKS_RULES */
            permit ? OPERATION_CONNECT : OPERATION_BLOCK,
#endif /* !HAVE_SOCKS_RULES */

            &src,

#if BAREFOOTD
            &dst,
#else /* !HAVE_SOCKS_RULES */
            NULL,
#endif /* !HAVE_SOCKS_RULES */

            NULL,
            NULL,
            ruleinfo,
            0);

#if !HAVE_SOCKS_RULES
      }
#endif /* !HAVE_SOCKS_RULES */

      if (!permit) {
         ++failedc;
         delete_negotiate(neg, 1);

         continue;
      }

#if HAVE_NEGOTIATE_PHASE
    socks_allocbuffer(neg->s, SOCK_STREAM);

    /*
     * We don't want this buffer to be bigger than MAXREQLEN, as that is
     * the amount of memory we have allocated to hold possible client data.
     *
     * Normally there is no client data in Dante's case, but some clients
     * may piggy-back the payload together with the socks request, without
     * waiting for our response.  That is not legal to do, but some clients
     * do it anyway, so we better support it.
     * We therefor need to make sure we never read more of the payload than
     * we can send on to the i/o process, which will eventually need to
     * forward it to the destination.
     */
    socks_setbuffer(neg->s, _IONBF, MAXREQLEN);
#endif /* HAVE_NEGOTIATE_PHASE */

#if HAVE_PAM
      /* copy over pam-values from matched rule. */
      strcpy(neg->socksauth.mdata.pam.servicename,
             neg->rule.state.pamservicename);
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
      /* copy over bsdauth-values from matched rule. */
      strcpy(neg->socksauth.mdata.bsd.style, neg->rule.state.bsdauthstylename);
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
      /* copy over gssapi-values from matched rule. */
      strcpy(neg->socksauth.mdata.gssapi.servicename,
      neg->rule.state.gssapiservicename);

      strcpy(neg->socksauth.mdata.gssapi.keytab, neg->rule.state.gssapikeytab);

      neg->socksauth.mdata.gssapi.encryption = neg->rule.state.gssapiencryption;
#endif /* HAVE_GSSAPI */

#if HAVE_SOCKS_HOSTID
      if (sockscf.hostidrule != NULL) {
         /*
          * Unlike the client- and socks-rules, we assume that if no
          * hostid-rules are configured, we should simply skip/pass
          * that step.  The reason for this is that hostid may not be
          * available or in use on the network, or the user may not
          * want to care about it.  So unless the user explicitly enables
          * hostid-usage by providing at least one hostid-rule, the most
          * sensible default is to not require that we have a matching
          * hostid-rule.
          */

         slog(LOG_DEBUG, "%s: checking for access through hostid rules",
              function);

         neg->state.command = SOCKS_HOSTID;
         permit = rulespermit(neg->s,
                              TOSA(&client.from),
                              TOSA(&client.to),
#if BAREFOOTD
                              &neg->negstate.dst,
#endif /* BAREFOOTD */
                              &neg->clientauth,
                              &neg->clientauth,
                              &neg->hostidrule,
                              &neg->state,
                              &neg->negstate.src,
                              &neg->negstate.dst,
                              ruleinfo,
                              sizeof(ruleinfo));

         /*
          * if no hostids, no rules will have been checked, so only log
          * if rules have been checked.
          */
         if (!permit || (permit && neg->state.hostidc > 0)) {
            neg->hostidrule_isset = 1;

            setconfsockoptions(neg->s,
                               -1,
                               SOCKS_TCP,
                               1,
                               neg->hostidrule.socketoptionc,
                               neg->hostidrule.socketoptionv,
                               SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                               0 /* should already be set. */);

            memcpy(src.hostidv,
                   neg->state.hostidv,
                   sizeof(*neg->state.hostidv) * neg->state.hostidc);
            src.hostidc = neg->state.hostidc;

            iolog(&neg->hostidrule,
                  &neg->state,
                  permit ? OPERATION_HOSTID  : OPERATION_BLOCK,
                  &src,
#if BAREFOOTD
                  &dst,
#else /* !HAVE_SOCKS_RULES */
                  NULL,
#endif /* !HAVE_SOCKS_RULES */

                  NULL,
                  NULL,
                  ruleinfo,
                  0);

            if (!permit) { /* log the clientrule close too. */
               neg->state.command
               = HAVE_SOCKS_RULES ? SOCKS_ACCEPT : SOCKS_CONNECT;

               iolog(&neg->rule,
                     &neg->state,
                     OPERATION_DISCONNECT,
                     &src,

#if BAREFOOTD
                     &dst,
#else /* !HAVE_SOCKS_RULES */
                     NULL,
#endif /* !HAVE_SOCKS_RULES */

                     NULL,
                     NULL,
                     ruleinfo,
                     0);
            }
         }

         if (!permit) {
            ++failedc;
            delete_negotiate(neg, 1);

            continue;
         }
      }
#endif /* HAVE_SOCKS_HOSTID */

#if BAREFOOTD
      neg->req.version       = PROXY_SOCKS_V5;
      neg->req.command       = SOCKS_CONNECT;
      neg->req.flag          = 0;
      ruleaddr2sockshost(&neg->rule.extra.bounceto, &neg->req.host, SOCKS_TCP);
      neg->req.protocol      = SOCKS_TCP;

      neg->negstate.complete = 1; /* nothing to do in barefoot's case. */
#elif COVENANT /* !BAREFOOTD */
      if (client.clientdatalen > 0) {
         slog(LOG_DEBUG, "%s: received client already has %lu bytes read "
                         "from it.  Must be a client that is changing "
                         "it's http server target to %s, so request should "
                         "already be parsed",
                         function, (unsigned long)client.clientdatalen,
                         sockshost2string(&client.request.host, NULL, 0));

         SASSERTX(client.clientdatalen <= sizeof(neg->negstate.mem));
         memcpy(neg->negstate.mem, client.clientdata, client.clientdatalen);
         neg->negstate.reqread  = client.clientdatalen;
         neg->negstate.complete = 1;
         neg->req               = client.request;
         *neg->req.auth         = client.auth; /* pointer fixup. */

      }
#endif /* COVENANT */

      neg->allocated = 1;
      ++newc;
   }

   /* NOTREACHED */
}

static void
delete_negotiate(neg, doackfreeslot)
   sockd_negotiate_t *neg;
   const int doackfreeslot;
{
   const char *function = "delete_negotiate()";

   slog(LOG_DEBUG, "%s: doackfreeslot: %d", function, doackfreeslot);

   if (doackfreeslot) {
      const unsigned char command = (neg->state.protocol == SOCKS_TCP ?
                                       SOCKD_FREESLOT_TCP : SOCKD_FREESLOT_UDP);

      if (socks_sendton(sockscf.state.mother.ack,
                        &command,
                        sizeof(command),
                        sizeof(command),
                        0,
                        NULL,
                        0,
                        NULL) != sizeof(command))
         swarn("%s: socks_sendton()", function);
   }

#if SOCKS_SERVER
   socks_freebuffer(neg->s);
#endif /* SOCKS_SERVER */

   close(neg->s);

   bzero(neg, sizeof(*neg));
   proctitleupdate();
}

static int
neg_fillset(set, skipcompleted, skipinprogress)
   fd_set *set;
   const int skipcompleted;
   const int skipinprogress;
{
   size_t i;
   int max;

   FD_ZERO(set);
   for (i = 0, max = -1; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;

#if !HAVE_NEGOTIATE_PHASE
      SASSERTX(negv[i].negstate.complete);
#endif /* HAVE_NEGOTIATE_PHASE */

      if (skipcompleted && negv[i].negstate.complete)
         continue;

      if (skipinprogress && !negv[i].negstate.complete)
         continue;

      FD_SET(negv[i].s, set);
      max = MAX(max, negv[i].s);
   }

   return max;
}

static void
neg_clearset(neg, set)
   sockd_negotiate_t *neg;
   fd_set *set;
{

   FD_CLR(neg->s, set);
}

static sockd_negotiate_t *
neg_getset(set)
   fd_set *set;
{
   size_t i;

   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;

      if (FD_ISSET(negv[i].s, set))
         return &negv[i];
   }

   return NULL;
}

static size_t
allocated(void)
{
   size_t i, alloc;

   for (i = 0, alloc = 0; i < negc; ++i)
      if (negv[i].allocated)
         ++alloc;

   return alloc;
}

static size_t
completed(count)
   const size_t count;
{
   size_t i, completec;

   for (i = 0, completec = 0; i < negc; ++i)
      if (negv[i].allocated && negv[i].negstate.complete)
         if (++completec >= count)
            return completec;

   return completec;
}

static void
proctitleupdate(void)
{

   setproctitle("negotiator: %lu/%d",
   (unsigned long)allocated(), SOCKD_NEGOTIATEMAX);
}

static struct timeval *
neg_gettimeout(timeout)
   struct timeval *timeout;
{
#if HAVE_NEGOTIATE_PHASE
   time_t timenow;
   size_t i;


   if (allocated() == completed(negc))
      /*
       * all objects allocated have completed.  We can only be waiting
       * for mother, and there is no timeout on that.
       */
      return NULL;

   timeout->tv_sec  = -1;
   timeout->tv_usec = 0;

   /* find how long it is till the first session should time out. */
   time(&timenow);
   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;

      if (timeout->tv_sec != -1)
         timeout->tv_sec = MAX(0, MIN(timeout->tv_sec,
                                      difftime(negv[i].rule.timeout.negotiate,
                                               difftime(timenow,
                                   negv[i].state.time.negotiatestart.tv_sec))));
      else
         timeout->tv_sec
         = MAX(0, difftime(negv[i].rule.timeout.negotiate,
                           difftime(timenow,
                                    negv[i].state.time.negotiatestart.tv_sec)));
   }


   if (timeout->tv_sec == -1)
      return NULL;

   return timeout;
#else /* !HAVE_NEGOTIATE_PHASE */
   timeout = NULL;
#endif /* !HAVE_NEGOTIATE_PHASE */

   return timeout;
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
   slog(LOG_DEBUG, "negotiate-child up %lu day%s, %lu:%.2lu:%.2lu",
                   days, days == 1 ? "" : "s", hours, minutes, seconds);

   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;
      else {
         char srcstring[MAX_IOLOGADDR];

         build_addrstr_src(GET_HOSTIDV(&negv[i].state),
                           GET_HOSTIDC(&negv[i].state),
                           &negv[i].negstate.src,
                           NULL,
                           NULL,
                           &negv[i].negstate.dst,
                           &negv[i].clientauth,
                           NULL,
                           srcstring,
                           sizeof(srcstring));

         slog(LOG_DEBUG, "%s: negotiating for %.0fs",
              srcstring,
              difftime(timenow, negv[i].state.time.negotiatestart.tv_sec));
      }
   }

   sockscf.option.debug = debug_s;
}

#if HAVE_NEGOTIATE_PHASE
static sockd_negotiate_t *
neg_gettimedout(void)
{
   size_t i;
   time_t timenow;

   time(&timenow);
   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;

      if (negv[i].rule.timeout.negotiate != 0)
         if (difftime(timenow, negv[i].state.time.negotiatestart.tv_sec)
         >= negv[i].rule.timeout.negotiate)
            return &negv[i];
   }

   return NULL;
}
#endif /* HAVE_NEGOTIATE_PHASE */
