/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2005, 2006, 2008,
 *               2009, 2010, 2011
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
"$Id: sockd_negotiate.c,v 1.268 2011/06/16 13:26:35 michaels Exp $";

static struct sockd_negotiate_t negv[SOCKD_NEGOTIATEMAX];
static const size_t negc = ELEMENTS(negv);

static void siginfo(int sig, siginfo_t *sip, void *scp);

static int
send_negotiate(const struct sockd_negotiate_t *neg);
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
 * Returns:
 *      If a new negotiate object was received successfully: 0.
 *      Otherwise: -1.
 */

static void
delete_negotiate(struct sockd_negotiate_t *neg);
/*
 * Frees any state occupied by "neg", including closing any
 * descriptors and sending a ack that we have deleted a "negotiate"
 * object to "mother".
 */

static int
neg_fillset(fd_set *set, const int skipcompleted, const int skipinprogress);
/*
 * Sets all client descriptors in our list in the set "set".
 *
 * If "skipcompleted" is set, skip those descriptors that belong to
 * clients that have completed negotation.
 *
 * If "skipinprogress" is set, skip those descriptors that belong to
 * clients that have not yet completed negotation.
 *
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors open currently.
 */

static void
neg_clearset(struct sockd_negotiate_t *neg, fd_set *set);
/*
 * Clears all file descriptors in "neg" from "set".
 */

static struct sockd_negotiate_t *
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
static struct sockd_negotiate_t *
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
neg_clearset(struct sockd_negotiate_t *neg, fd_set *set);
/*
 * Clears all file descriptors in "neg" from "set".
 */

static struct sockd_negotiate_t *
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
static struct sockd_negotiate_t *
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

   proctitleupdate();

   rset        = allocate_maxsize_fdset();
   rsetbuf     = allocate_maxsize_fdset();
   tmpset      = allocate_maxsize_fdset();
   wsetmem     = allocate_maxsize_fdset();
   sendfailed  = 0;

   while (1 /* CONSTCOND */) {
      negotiate_result_t negstatus;
      fd_set *wset;
      int fdbits;
      struct sockd_negotiate_t *neg;
      struct timeval *timeout, timeoutmem;

      errno = 0; /* reset for each iteration. */


#if HAVE_NEGOTIATE_PHASE
      while ((neg = neg_gettimedout()) != NULL) {
         struct sockaddr sa;

         iolog(&neg->rule,
               &neg->state,
               OPERATION_TIMEOUT,
               sockshost2sockaddr(&neg->negstate.dst, &sa),
               &neg->negstate.src,
               &neg->clientauth,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               "negotiation timed out",
               0);

         delete_negotiate(neg);
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
         if (recv_negotiate() != 0)
            continue;

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
               struct sockaddr src, dst;
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
                  struct sockaddr sa;
                  struct response_t response;

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

                  /* only log on deny.  Pass will be logged as usual later. */
                  iolog(&neg->srule,
                        &neg->state,
                        OPERATION_CONNECT,
                        sockshost2sockaddr(&neg->negstate.dst, &sa),
                        &neg->negstate.src,
                        &neg->socksauth,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
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
                  delete_negotiate(neg);

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
               delete_negotiate(neg);
               sendfailed = 0;
            }
            else if (ERRNOISTMP(errno))
               sendfailed = 1; /* we will retry sending this object later. */
            else {
               if (errno != 0)
                  swarn("%s: could not send client to mother", function);

               delete_negotiate(neg);

               /* assume what failed was not related to the send. */
               sendfailed = 0;
            }
         }
         else if (negstatus == NEGOTIATE_ERROR) {
            const char *error;
            char reason[256];
            struct sockaddr sa;
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

            iolog(&neg->rule,
                  &neg->state,
                  OPERATION_ERROR,
                  sockshost2sockaddr(&neg->negstate.dst, &sa),
                  &neg->negstate.src,
                  &neg->clientauth,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  reason,
                  strlen(reason));

#if HAVE_GSSAPI
            if (neg->socksauth.method == AUTHMETHOD_GSSAPI
            && neg->socksauth.mdata.gssapi.state.id != GSS_C_NO_CONTEXT)
               if (gss_delete_sec_context(&minor_status,
                  &neg->socksauth.mdata.gssapi.state.id, &output_token)
                  != GSS_S_COMPLETE)
                     swarn("%s: gss_delete_sec_context failed", function);
#endif /* HAVE_GSSAPI */

            delete_negotiate(neg);
         }
      }
   }
}

static int
send_negotiate(neg)
   const struct sockd_negotiate_t *neg;
{
   const char *function = "send_negotiate()";
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif /* HAVE_GSSAPI */
   struct iovec iov[2];
   struct sockd_request_t req;
   struct msghdr msg;
   ssize_t w;
   size_t length, ioc, fdsendt;
   CMSG_AALLOC(cmsg, sizeof(int));

#if HAVE_SENDMSG_DEADLOCK
   socks_lock(sockscf.state.mother.lock, 1, 1);
#endif /* HAVE_SENDMSG_DEADLOCK */


   /*
    * copy needed fields from negotiate.
    */
   bzero(&req, sizeof(req)); /* silence valgrind warning */
   sockshost2sockaddr(&neg->negstate.src, (struct sockaddr *)&req.from);
   sockshost2sockaddr(&neg->negstate.dst, (struct sockaddr *)&req.to);
   req.req           = neg->req;

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
           "%s: socks client at %s sent us %lu bytes of payload data "
           "before we have told it that it can do that.  Not permitted by "
           "the SOCKS standard and not expected.  %s",
           function,
           socket2string(neg->s, NULL, 0),
           (unsigned long)length,
           length > sizeof(req.clientdata) ?
           "Too much unexpected data" : "Trying to handle it");

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

   req.rule          = neg->rule;
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

      if (sockscf.option.debug > 1)
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

   if (sockscf.option.debug > 1) {
      slog(LOG_DEBUG, "%s: sending request to mother, "
                      "bw_shmid = %ld, ss_shmid = %ld",
                      function,
                      req.rule.bw_shmid, req.rule.ss_shmid);

      if (neg->s != -1)
         slog(LOG_DEBUG, "%s: sending socket %d (%s) ...",
         function, neg->s, socket2string(neg->s, NULL, 0));
   }

   if ((w = sendmsgn(sockscf.state.mother.s, &msg, 0, 1)) != (ssize_t)length)
      swarn("%s: sendmsg(): %ld of %lu",
      function, (long)w, (unsigned long)length);
   else {
      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: sent %ld descriptors for command %d.  "
                         "clientauth %s, socksauth %s, neg->s %d",
                         function, (unsigned long)fdsendt, req.state.command,
                         method2string(req.clientauth.method),
                         method2string(req.socksauth.method),
                         neg->s);
   }
#if HAVE_SENDMSG_DEADLOCK
   socks_unlock(sockscf.state.mother.lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

   return (size_t)w == length ? 0 : -1;
}

static int
recv_negotiate(void)
{
   const char *function = "recv_negotiate()";
   struct sockd_client_t client;
   struct sockd_negotiate_t *neg;
   struct iovec iov[1];
   struct msghdr msg;
#if BAREFOOTD
    struct sockshost_t host;
#endif /* BAREFOOTD */
   struct sockaddr src, dst;
   socklen_t len;
   ssize_t r;
   size_t i;
   CMSG_AALLOC(cmsg, sizeof(int));
   char ruleinfo[256];
   int permit, fdreceived, packetc;

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

   packetc = 0;
   while (1) { /* until it would block. */
      const size_t fdexpect = 1;

      if ((r = recvmsgn(sockscf.state.mother.s, &msg, 0)) != sizeof(client)) {
         switch (r) {
            case -1:
            case 0:
               slog(LOG_DEBUG,
                    "%s: recvmsg() from mother returned %ld "
                    "after having received %d packets, errno = %d (%s)",
                    function, (long)r,
                    packetc, errno, errnostr(errno));
               break;

            default:
               swarnx("%s: recvmsg(): unexpected short read from mother "
                      "after %d packets.  Got %ld/%lu bytes",
                      function,
                      packetc, (long)r, (unsigned long)sizeof(client));
         }

         return -1;
      }

      if (socks_msghaserrors(function, &msg))
         continue;

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

      CMSG_VERIFY_RCPTLEN(msg, sizeof(int) * fdexpect);

      fdreceived = 0;
      CMSG_GETOBJECT(neg->s, cmsg, sizeof(neg->s) * fdreceived++);

      if (sockscf.option.debug > 1)
         slog(LOG_DEBUG, "%s: received socket %d (%s) ...",
         function, neg->s, socket2string(neg->s, NULL, 0));

      /*
       * get local and remote address.
       */

      len = sizeof(src);
      if (getpeername(neg->s, &src, &len) != 0) {
         slog(LOG_DEBUG, "%s: getpeername(): %s", function, strerror(errno));

         delete_negotiate(neg);
         return -1;
      }
      sockaddr2sockshost(&src, &neg->negstate.src);

      len = sizeof(dst);
      if (getsockname(neg->s, &dst, &len) != 0) {
         slog(LOG_DEBUG, "%s: getsockname(): %s", function, strerror(errno));

         delete_negotiate(neg);
         return -1;
      }
      sockaddr2sockshost(&dst, &neg->negstate.dst);

      /* init state correctly for checking a connection to us. */
      neg->state.clientcommand = neg->state.command        = SOCKS_ACCEPT;
      neg->state.protocol      = neg->state.clientprotocol = SOCKS_TCP;

      neg->req.auth                  = &neg->socksauth;   /* pointer fixup    */
      neg->clientauth.method         = AUTHMETHOD_NOTSET; /* nothing so far   */

      permit = rulespermit(neg->s,
                           &src,
                           &dst,
                           NULL,
                           &neg->clientauth,
                           &neg->rule,
                           &neg->state,
                           &neg->negstate.src,
                           &neg->negstate.dst,
                           ruleinfo,
                           sizeof(ruleinfo));

      /*
       * Might need to use some values from clientauth when negotiating,
       * i.e. gssapi or pam-values.  Also, in some cases (gssapi), the
       * authmethod to be used for socks negotiation needs to be
       * set at the client acl pass, so start by copying the current
       * clientauth into what will become the socksauth proper.
       */
      neg->socksauth        = neg->clientauth;

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


#if !HAVE_TWO_LEVEL_ACL
      /*
       * don't have separate client-rules and socks-rules, so only log
       * socks-rule normally, unless it's a block, in which case this is
       * the only logging that will be done.
       */

      if (!permit) /* really SOCKS_ACCEPT, but user does not know about that. */
         neg->state.command = SOCKS_CONNECT;

      if (sockscf.option.debug || !permit)
#endif /* !HAVE_TWO_LEVEL_ACL */
      iolog(&neg->rule,
            &neg->state,
#if HAVE_TWO_LEVEL_ACL
            OPERATION_ACCEPT,
#else /* !HAVE_TWO_LEVEL_ACL */
            OPERATION_CONNECT,
#endif /* !HVE_TWO_LEVEL_ACL */

            &dst,
            &neg->negstate.src,
            &neg->clientauth,
            NULL,
            NULL,
            NULL,
            NULL,

#if BAREFOOTD
            ruleaddr2sockshost(&neg->rule.bounce_to, &host, SOCKS_TCP),
#else /* !BAREFOOTD */
            NULL,
#endif /* !BAREFOOTD */

            NULL,
            NULL,
            NULL,
            NULL,
            ruleinfo,
            0);

      if (!permit) {
         delete_negotiate(neg);
         return -1;
      }

#if SOCKS_SERVER
   /* only socks-server wants iobuffer in this process.  Barefoot
    * has no negotiate-phase, and while Covenant does, it must be
    * careful not to read past the first eof; i.e., we do not
    * want to fill the iobuffer with "unread" data, as we only have
    * space allocated to the first eof, which we must pass on to
    * other processes, but we are not passing on the iobuf, so it
    * must be empty.
    */
    socks_allocbuffer(neg->s, SOCK_STREAM);
#endif /* SOCKS_SERVER */

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

#if BAREFOOTD
      neg->req.version       = PROXY_SOCKS_V5;
      neg->req.command       = SOCKS_CONNECT;
      neg->req.flag          = 0;
      ruleaddr2sockshost(&neg->rule.bounce_to, &neg->req.host, SOCKS_TCP);
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

      gettimeofday(&neg->state.time.negotiate, NULL);
      neg->state.time.accepted = client.accepted;
      neg->allocated           = 1;

      ++packetc;
   }

   /* NOTREACHED */
}

static void
delete_negotiate(neg)
   struct sockd_negotiate_t *neg;
{
   const char *function = "delete_negotiate()";
   const char command = SOCKD_FREESLOT_TCP;

#if !BAREFOOTD
   /*
    * barefootd needs to let socks-rule inherit ss, dante never lets ss
    * be inherited, so dante needs to unuse it now.
    */
   if (neg->rule.ss_shmid != 0) {
      sockd_shmat(&neg->rule, SHMEM_SS);
      session_unuse(neg->rule.ss, sockscf.shmemfd);
      sockd_shmdt(&neg->rule, SHMEM_SS);
   }
#endif /* !BAREFOOTD */

#if SOCKS_SERVER
   socks_freebuffer(neg->s);
#endif /* SOCKS_SERVER */

   if (socks_sendton(sockscf.state.mother.ack,
                     &command,
                     sizeof(command),
                     sizeof(command),
                     0,
                     NULL,
                     0,
                     NULL) != sizeof(command))
      swarn("%s: socks_sendton()", function);

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
   struct sockd_negotiate_t *neg;
   fd_set *set;
{

   FD_CLR(neg->s, set);
}

static struct sockd_negotiate_t *
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
                  difftime(timenow, negv[i].state.time.negotiate.tv_sec))));
      else
         timeout->tv_sec
         = MAX(0, difftime(negv[i].rule.timeout.negotiate,
                           difftime(timenow,
                                    negv[i].state.time.negotiate.tv_sec)));
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

   slog(LOG_INFO, "negotiate-child up %lu day%s, %lu:%.2lu:%.2lu",
                  days, days == 1 ? "" : "s", hours, minutes, seconds);

   for (i = 0; i < negc; ++i)
      if (!negv[i].allocated)
         continue;
      else {
         struct sockaddr sa;
         char srcstring[MAX_IOLOGADDR];

         BUILD_ADDRSTR_SRC(&negv[i].negstate.src,
                           NULL,
                           NULL,
                           sockshost2sockaddr(&negv[i].negstate.dst, &sa),
                           &negv[i].clientauth,
                           NULL,
                           srcstring,
                           sizeof(srcstring));

         slog(LOG_INFO,
              "%s: negotiating for %.0fs",
              srcstring,
              difftime(timenow, negv[i].state.time.negotiate.tv_sec));
      }
}

#if HAVE_NEGOTIATE_PHASE
static struct sockd_negotiate_t *
neg_gettimedout(void)
{
   size_t i;
   time_t timenow;

   time(&timenow);
   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;

      if (negv[i].rule.timeout.negotiate != 0)
         if (difftime(timenow, negv[i].state.time.negotiate.tv_sec)
         >= negv[i].rule.timeout.negotiate)
            return &negv[i];
   }

   return NULL;
}
#endif /* HAVE_NEGOTIATE_PHASE */
