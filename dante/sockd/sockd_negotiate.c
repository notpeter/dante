/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2005, 2006, 2008,
 *               2009
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
"$Id: sockd_negotiate.c,v 1.148 2009/10/02 13:22:27 michaels Exp $";

static void siginfo(int sig);

static int
send_negotiate(const struct sockd_mother_t *mother,
      const struct sockd_negotiate_t *neg);
/*
 * Sends "neg" to "mother".  Also notifies "mother" that we have freed
 * a slot.
 *
 * Returns:
 *      On success: 0
 *      On failure: -1
 *      If some other, possibly non-fatal, problem prevented success: > 0
 */

static int
recv_negotiate(const struct sockd_mother_t *mother);
/*
 * Tries to receive a client from mother "mother".
 * Returns:
 *      On success: 0
 *      If an error occured on the connection with "mother": -1
 *      If some other, non-fatal, problem prevented success: > 0
 */

static void
delete_negotiate(const struct sockd_mother_t *mother,
      struct sockd_negotiate_t *neg);
/*
 * Frees any state occupied by "neg", including closing any
 * descriptors and sending a ack that we have deleted a "negotiate"
 * object to "mother".
 */

static int
neg_fillset(fd_set *set);
/*
 * Sets all descriptors in our list in the set "set".
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors open currently.
 */

static void
neg_clearset(struct sockd_negotiate_t *neg, fd_set *set);
/*
 * Clears all filedescriptors in "neg" from "set".
 */

static struct sockd_negotiate_t *
neg_getset(fd_set *set);
/*
 * Goes through our list until it finds a negotiate object where atleast
 * one of the descriptors is set.
 * Returns:
 *      On success: pointer to the found object.
 *      On failure: NULL.
 */

static int
completed(void);
/*
 * Returns the number of objects completed and ready to be sent currently.
 */

static int
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

static struct sockd_negotiate_t *
neg_gettimedout(void);
/*
 * Scans all clients for one that has timed out according to sockscf
 * settings.
 * Returns:
 *      If timed out client found: pointer to it.
 *      Else: NULL.
 */

static struct sockd_negotiate_t negv[SOCKD_NEGOTIATEMAX];
static int negc = ELEMENTS(negv);

void
run_negotiate(mother)
   struct sockd_mother_t *mother;
{
   const char *function = "run_negotiate()";
   struct sigaction sigact;

   bzero(&sigact, sizeof(sigact));
   sigact.sa_flags   = SA_RESTART;
   sigact.sa_handler = siginfo;

#if HAVE_SIGNAL_SIGINFO
   if (sigaction(SIGINFO, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);
#endif /* HAVE_SIGNAL_SIGINFO */

   /* same handler, for systems without SIGINFO. */
   if (sigaction(SIGUSR1, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);

   proctitleupdate();

   /* CONSTCOND */
   while (1) {
      static fd_set *rset, *rsetbuf, *tmpset, *wsetmem;
      fd_set *wset;
      int fdbits, p;
      struct sockd_negotiate_t *neg;
      struct timeval timeout;

      if (rset == NULL) {
         rset    = allocate_maxsize_fdset();
         rsetbuf = allocate_maxsize_fdset();
         tmpset  = allocate_maxsize_fdset();
         wsetmem = allocate_maxsize_fdset();
      }

      while ((neg = neg_gettimedout()) != NULL) {
         const char *reason = "negotiation timed out";

         iolog(&neg->rule, &neg->state, OPERATION_ABORT, &neg->negstate.src,
         &neg->auth, &neg->negstate.dst, NULL, reason, 0);
         delete_negotiate(mother, neg);
      }

      fdbits = neg_fillset(rset);
      FD_SET(mother->s, rset);
      fdbits = MAX(fdbits, mother->s);

      /* checked so we know if mother goes away.  */
      FD_SET(mother->ack, rset);
      fdbits = MAX(fdbits, mother->ack);

      /* if we have a completed request check whether we can send to mother. */
      if (completed() > 0) {
         FD_ZERO(wsetmem);
         FD_SET(mother->s, wsetmem);
         wset = wsetmem;
      }
      else
         wset = NULL;

      ++fdbits;
      switch (selectn(fdbits, rset, rsetbuf, wset, NULL, NULL,
      neg_gettimeout(&timeout))) {
         case -1:
            if (errno != EINTR)
               SERR(-1);
            continue;

         case 0:
            continue;
      }

      fdsetop(fdbits, '|', rset, rsetbuf, tmpset);
      FD_COPY(rset, tmpset);

      if (FD_ISSET(mother->ack, rset)) {
         slog(LOG_DEBUG, "%s: mother exited, we should too", function);
         sockdexit(EXIT_SUCCESS);
      }

      if (FD_ISSET(mother->s, rset)) {
         if (recv_negotiate(mother) == -1)
            sockdexit(EXIT_FAILURE);
         FD_CLR(mother->s, rset);
      }


      while ((neg = neg_getset(rset)) != NULL) {
         neg_clearset(neg, rset);

         errno = 0;

         if ((p = recv_request(neg->s, &neg->req, &neg->negstate)) <= 0) {
#if HAVE_GSSAPI
            gss_buffer_desc output_token;
            OM_uint32 minor_status;
#endif /* HAVE_GSSAP */
            const char *reason = NULL;   /* init or gcc complains. */

            switch (p) {
               case 0:
                  reason = "eof from client";
                  break;

               case -1:
                  switch (errno) {
                     case 0:
                        reason = *neg->negstate.emsg == NUL ?
                        "socks protocol error" : neg->negstate.emsg;
                        break;

                     case EINTR:
                     case EAGAIN:
#if EAGAIN != EWOULDBLOCK
                     case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
                        continue; /* ok, retry. */

                     default:
                        reason = *neg->negstate.emsg == NUL ?
                        strerror(errno) : neg->negstate.emsg;
                  }
            }

            iolog(&neg->rule, &neg->state, OPERATION_ABORT, &neg->negstate.src,
            &neg->auth, &neg->negstate.dst, NULL, reason, 0);

            delete_negotiate(mother, neg);

#if HAVE_GSSAPI
            neg->auth.mdata.gssapi.state.id = GSS_C_NO_CONTEXT;
            if (neg->auth.method == AUTHMETHOD_GSSAPI)
               if (gss_delete_sec_context(&minor_status,
                  &neg->auth.mdata.gssapi.state.id, &output_token)
                  != GSS_S_COMPLETE)
                     swarn("%s: gss_delete_sec_context failed", function);
#endif /* HAVE_GSSAPI */
         }
         else if (wset != NULL && FD_ISSET(mother->s, wset)) {
            /* read a complete request, send to mother. */
            switch (send_negotiate(mother, neg)) {
               case -1:
                  sockdexit(EXIT_FAILURE);
                  /* NOTREACHED */

               case 0:
                  delete_negotiate(mother, neg); /* sent to mother ok. */
                  break;
            }
         }
      }
   }
}

static int
send_negotiate(mother, neg)
   const struct sockd_mother_t *mother;
   const struct sockd_negotiate_t *neg;
{
   const char *function = "send_negotiate()";
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAXGSSAPITOKENLEN];
#endif
   struct iovec iov[2];
   struct sockd_request_t req;
   struct msghdr msg;
   int fdsendt, w, ioc, length;
   CMSG_AALLOC(cmsg, sizeof(int));

#if HAVE_SENDMSG_DEADLOCK
   if (socks_lock(mother->lock, F_WRLCK, 0) != 0)
      return 1;
#endif /* HAVE_SENDMSG_DEADLOCK */

   /* copy needed fields from negotiate */
   bzero(&req, sizeof(req)); /* silence valgrind warning */
   sockshost2sockaddr(&neg->negstate.src, (struct sockaddr *)&req.from);
   sockshost2sockaddr(&neg->negstate.dst, (struct sockaddr *)&req.to);
   req.req           = neg->req;
   req.rule          = neg->rule;
   req.auth          = neg->auth;
   req.state         = neg->state;
   req.state.command = req.req.command;
   req.state.version = req.req.version;

   length = 0;

   bzero(iov, sizeof(iov));
   ioc = 0;
   iov[ioc].iov_base = &req;
   iov[ioc].iov_len  = sizeof(req);
   length += iov[ioc].iov_len;
   ++ioc;

#if HAVE_GSSAPI
   if (req.auth.method == AUTHMETHOD_GSSAPI) {
      gssapistate.value   = gssapistatemem;
      gssapistate.length  = sizeof(gssapistatemem);

      if (gssapi_export_state(&req.auth.mdata.gssapi.state.id, &gssapistate)
      != 0)
         return 1;

      iov[ioc].iov_base = gssapistate.value;
      iov[ioc].iov_len  = gssapistate.length;
      length += iov[ioc].iov_len;
      ++ioc;

      slog(LOG_DEBUG, "%s: gssapistate has length %lu",
      function, (long unsigned)gssapistate.length);
   }
#endif /* HAVE_GSSAPI */

   fdsendt = 0;

#if BAREFOOTD
   if (req.state.command == SOCKS_UDPASSOCIATE)
      ; /* no control/client socket until set up in request-child. */
   else
      CMSG_ADDOBJECT(neg->s, cmsg, sizeof(neg->s) * fdsendt++);
#else /* SOCKS_SERVER */
   CMSG_ADDOBJECT(neg->s, cmsg, sizeof(neg->s) * fdsendt++);
#endif /* SOCKS_SERVER */

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ioc;
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_SEND(msg, cmsg, sizeof(int) * fdsendt);

   slog(LOG_DEBUG, "%s: sending request to mother", function);
   if ((w = sendmsgn(mother->s, &msg, 0)) != length)
      switch (errno) {
         case EAGAIN:
         case ENOBUFS:
            w = 1;   /* temporal error. */
            break;

         default:
            swarn("%s: sendmsg(): %d of %lu",
            function, w, (unsigned long)length);
      }

#if HAVE_SENDMSG_DEADLOCK
   socks_unlock(mother->lock);
#endif /* HAVE_SENDMSG_DEADLOCK */

   slog(LOG_DEBUG, "%s: sent %d descriptors for command %d.  neg->s = %d",
   function, fdsendt, req.state.command, neg->s);

   return w == length ? 0 : w;
}

static int
recv_negotiate(mother)
   const struct sockd_mother_t *mother;
{
   const char *function = "recv_negotiate()";
   struct sockd_client_t client;
   struct sockd_negotiate_t *neg;
   struct iovec iov[1];
   struct msghdr msg;
   char ruleinfo[256];
   int permit, i, r, fdexpect, fdreceived;
   struct sockaddr src, dst;
   socklen_t len;
   CMSG_AALLOC(cmsg, sizeof(int));

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

   if ((r = recvmsg(mother->s, &msg, 0)) != sizeof(client)) {
      switch (r) {
         case -1:
            swarn("%s: recvmsg() from mother", function);
            break;

         case 0:
            slog(LOG_DEBUG, "%s: recvmsg(): mother closed connection",
            function);
            break;

         default:
            swarnx("%s: recvmsg(): unexpected %d/%lu bytes from mother",
            function, r, (unsigned long)sizeof(client));
      }

      return -1;
   }

   fdexpect = 1;   /* constant */

   /* find a free slot. */
   for (i = 0, neg = NULL; i < negc; ++i)
      if (!negv[i].allocated) {
         /* don't allocate it yet, so siginfo() doesn't print before ready. */
         neg = &negv[i];
         break;
      }

   if (neg == NULL)
      SERRX(allocated());

#if !HAVE_DEFECT_RECVMSG
   SASSERT((size_t)CMSG_TOTLEN(msg)
   == (size_t)(CMSG_SPACE(sizeof(int) * fdexpect)));
#endif /* !HAVE_DEFECT_RECVMSG */

   fdreceived = 0;
   CMSG_GETOBJECT(neg->s, cmsg, sizeof(neg->s) * fdreceived++);

   /*
    * get local and remote address.
    */

   len = sizeof(src);
   if (getpeername(neg->s, &src, &len) != 0) {
      slog(LOG_DEBUG, "%s: getpeername(): %s", function, strerror(errno));
      delete_negotiate(mother, neg);
      return 1;
   }
   sockaddr2sockshost(&src, &neg->negstate.src);

   len = sizeof(dst);
   if (getsockname(neg->s, &dst, &len) != 0) {
      slog(LOG_DEBUG, "%s: getsockname(): %s", function, strerror(errno));
      delete_negotiate(mother, neg);
      return 1;
   }
   sockaddr2sockshost(&dst, &neg->negstate.dst);

   /* init state correctly for checking a connection to us. */
   neg->state.command  = neg->state.clientcommand  = SOCKS_ACCEPT;
   neg->state.protocol = neg->state.clientprotocol = SOCKS_TCP;

   neg->auth.method    = AUTHMETHOD_NOTSET; /* nothing so far. */
   neg->req.auth       = &neg->auth;        /* pointer fixup */

   if (sockscf.sessionlock != -1)
      socks_lock(sockscf.sessionlock, F_WRLCK, -1);

   permit = rulespermit(neg->s, &src, &dst, &neg->rule, &neg->auth, &neg->state,
   &neg->negstate.src, &neg->negstate.dst, ruleinfo, sizeof(ruleinfo));

   if (permit && neg->rule.ss != NULL) { /* only bother if rules permit. */
      if (!session_use(neg->rule.ss)) {
         permit            = 0;
         neg->rule.verdict = VERDICT_BLOCK;
         neg->rule.ss      = NULL; /* don't want delete_io to unuse() it. */

         snprintf(ruleinfo, sizeof(ruleinfo), DENY_SESSIONLIMITs);
      }
   }

   if (sockscf.sessionlock != -1)
      socks_unlock(sockscf.sessionlock);

   iolog(&neg->rule, &neg->state, OPERATION_ACCEPT, &neg->negstate.src,
   &neg->auth, &neg->negstate.dst, NULL, ruleinfo, 0);

   if (!permit) {
      delete_negotiate(mother, neg);
      return 0;
   }

   /*
    * If a iobuf was allocated for this socket before, free and allocate new.
    */
   socks_freebuffer(neg->s);
   socks_allocbuffer(neg->s);

#if HAVE_PAM
   /* copy over pam-values from matched rule. */
   strcpy(neg->auth.mdata.pam.servicename, neg->rule.state.pamservicename);
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
   /* copy over gssapi-values from matched rule. */
   strcpy(neg->auth.mdata.gssapi.servicename,
   neg->rule.state.gssapiservicename);

   strcpy(neg->auth.mdata.gssapi.keytab, neg->rule.state.gssapikeytab);

   neg->auth.mdata.gssapi.encryption = neg->rule.state.gssapiencryption;
#endif /* HAVE_GSSAPI */

   neg->state.time.accepted = client.accepted;
   gettimeofday(&neg->state.time.negotiate, NULL);
   neg->allocated = 1;
   proctitleupdate();

#if BAREFOOTD
   neg->req.version       = PROXY_SOCKS_V5;
   neg->req.command       = SOCKS_CONNECT;
   neg->req.flag          = 0;
   ruleaddr2sockshost(&neg->rule.bounce_to, &neg->req.host, SOCKS_TCP);
   neg->req.protocol      = SOCKS_TCP;
   neg->negstate.complete = 1;
#endif /* BAERFOOTD */

   return 0;
}

static void
delete_negotiate(mother, neg)
   const struct sockd_mother_t *mother;
   struct sockd_negotiate_t *neg;
{
   const char *function = "delete_negotiate()";
   static const struct sockd_negotiate_t neginit;
   const char command = SOCKD_FREESLOT;

   if (neg->rule.ss != NULL)
      session_unuse(neg->rule.ss);

   close(neg->s);

   *neg = neginit;

   /* ack we have freed a slot. */
   if (socks_sendton(mother->ack, &command, sizeof(command), sizeof(command),
   0, NULL, 0, NULL) != sizeof(command))
      swarn("%s: socks_sendton()", function);

   proctitleupdate();
}

static int
neg_fillset(set)
   fd_set *set;
{
   int i, max;

   FD_ZERO(set);
   for (i = 0, max = -1; i < negc; ++i)
      if (negv[i].allocated) {
         negv[i].ignore = 0;
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
   neg->ignore = 1;
}

static struct sockd_negotiate_t *
neg_getset(set)
   fd_set *set;
{
   int i;

   for (i = 0; i < negc; ++i)
      if (negv[i].allocated) {
         if (negv[i].ignore)
            continue;

         if (negv[i].negstate.complete)
            return &negv[i];

         if (FD_ISSET(negv[i].s, set))
            return &negv[i];

      }

   return NULL;
}

static int
allocated(void)
{
   int i, alloc;

   for (i = 0, alloc = 0; i < negc; ++i)
      if (negv[i].allocated)
         ++alloc;

   return alloc;
}

static int
completed(void)
{
   int i, completec;

   for (i = 0, completec = 0; i < negc; ++i)
      if (negv[i].allocated && negv[i].negstate.complete)
         ++completec;

   return completec;
}

static void
proctitleupdate(void)
{

   setproctitle("negotiator: %d/%d", allocated(), SOCKD_NEGOTIATEMAX);
}

static struct timeval *
neg_gettimeout(timeout)
   struct timeval *timeout;
{
   time_t timenow;
   int i;


   if (sockscf.timeout.negotiate == 0 || (allocated() == completed()))
      return NULL;

   timeout->tv_sec  = sockscf.timeout.negotiate;
   timeout->tv_usec = 0;

   /* if we have clients negotiating, check if we need to shrink timeout. */
   time(&timenow);
   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;
      else
         timeout->tv_sec = MAX(0, MIN(timeout->tv_sec,
         difftime(sockscf.timeout.negotiate,
         difftime(timenow, negv[i].state.time.negotiate.tv_sec))));
   }

   return timeout;
}

static struct sockd_negotiate_t *
neg_gettimedout(void)
{
   int i;
   time_t timenow;

   if (sockscf.timeout.negotiate == 0)
      return NULL;

   time(&timenow);
   for (i = 0; i < negc; ++i) {
      if (!negv[i].allocated)
         continue;
      if (negv[i].ignore)
         continue;
      else
         if (difftime(timenow, negv[i].state.time.negotiate.tv_sec)
         >= sockscf.timeout.negotiate)
            return &negv[i];
   }

   return NULL;
}

/* ARGSUSED */
void
siginfo(sig)
   int sig;
{
   const char *function = "siginfo()";
   time_t timenow;
   int i;

   if (sig > 0) {
      sockd_pushsignal(sig);
      return;
   }

   sig = -sig; 

   slog(LOG_DEBUG, "%s: running due to previously received signal: %d",
   function, sig);

   time(&timenow);
   for (i = 0; i < negc; ++i)
      if (!negv[i].allocated)
         continue;
      else {
         char srcstring[MAXSOCKSHOSTSTRING];

         slog(LOG_INFO, "%s: negotiating for %.0fs",
         sockshost2string(&negv[i].negstate.src, srcstring, sizeof(srcstring)),
         difftime(timenow, negv[i].state.time.negotiate.tv_sec));
      }
}
