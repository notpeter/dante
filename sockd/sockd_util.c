/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 2008,
 *               2009, 2010
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

static const char rcsid[] =
"$Id: sockd_util.c,v 1.143.2.2 2010/05/24 16:39:13 karls Exp $";

#include "common.h"


int
selectmethod(methodv, methodc, offeredv, offeredc)
   const int *methodv;
   size_t methodc;
   const unsigned char *offeredv;
   size_t offeredc;
{
   size_t i, methodokc;
   const unsigned char *methodokv;

   for (i = 0; i < methodc; ++i) {
      if (methodv[i] > AUTHMETHOD_NOACCEPT) {
         /*
          * non-socks method.  Can select any of the standard
          * methods then, but might pay some attention to what
          * is preferred.  For rfc931, choose the simplest.
          * For pam, make a guess.
          */
         const unsigned char rfc931methodv[] = { AUTHMETHOD_NONE,
                                                 AUTHMETHOD_UNAME,
#if HAVE_GSSAPI
                                                 AUTHMETHOD_GSSAPI
#endif /* HAVE_GSSAPI */
                                               };

         const unsigned char pammethodv[] = {    AUTHMETHOD_UNAME,
#if HAVE_GSSAPI
                                                 AUTHMETHOD_GSSAPI,
#endif /* HAVE_GSSAPI */
                                                 AUTHMETHOD_NONE   };
         int intmethodv[MAXMETHOD];
         size_t ii;

         /* find the correct array to use for selecting the method. */
         switch (methodv[i]) {
            case AUTHMETHOD_RFC931:
               methodokc = ELEMENTS(rfc931methodv);
               methodokv = rfc931methodv;
               break;

            case AUTHMETHOD_PAM:
               methodokc = ELEMENTS(pammethodv);
               methodokv = pammethodv;
               break;

            default:
               SERRX(methodv[i]);
         }

         CM2IM(offeredc, offeredv, intmethodv);
         for (ii = 0; ii < methodokc; ++ii)
            if (methodisset(methodokv[ii], intmethodv, offeredc))
               return methodokv[ii];

         continue;
      }

      if (memchr(offeredv, (unsigned char)methodv[i], offeredc) != NULL)
         return methodv[i];
   }

   return AUTHMETHOD_NOACCEPT;
}

void
setsockoptions(s)
   int s;
{
   const char *function = "setsockoptions()";
   socklen_t len;
   int type, val, bufsize;


   len = sizeof(type);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len) != 0) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return;
   }

   switch (type) {
      case SOCK_STREAM:
         bufsize = SOCKS_SOCKET_BUFSIZETCP;

         val = 1;
         if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != 0)
            swarn("%s: setsockopt(TCP_NODELAY)", function);

         val = 1;
         if (setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &val, sizeof(val)) != 0)
            swarn("%s: setsockopt(SO_OOBINLINE)", function);

         if (sockscf.option.keepalive) {
            val = 1;
            if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) != 0)
               swarn("%s: setsockopt(SO_KEEPALIVE)", function);
         }
         break;

      case SOCK_DGRAM:
         bufsize = SOCKS_SOCKET_BUFSIZEUDP;

         val = 1;
         if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val)) != 0)
            if (errno != ENOPROTOOPT)
               swarn("%s: setsockopt(SO_BROADCAST)", function);

         break;

      default:
         SERRX(type);
   }

   val = bufsize;
   if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)) != 0
   ||  setsockopt(s, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) != 0)
      swarn("%s: setsockopt(SO_SNDBUF/SO_RCVBUF)", function);

#if HAVE_LIBWRAP
   if ((val = fcntl(s, F_GETFD, 0))       == -1
   || fcntl(s, F_SETFD, val | FD_CLOEXEC) == -1)
      swarn("%s: fcntl(F_GETFD/F_SETFD)", function);
#endif /* HAVE_LIBWRAP */
}


void
sockdexit(code)
   const int code;
{
   const char *function = "sockdexit()";
   static int exiting;
   struct sigaction sigact;
   size_t i;
   int ismainmother;

   /*
    * Since this function can also be called on an assert-failure,
    * try to guard against repeated calls.
    */
   if (exiting)
      return;
   exiting = 1;

   /*
    * we are terminating, don't want to receive SIGTERM or SIGCHLD
    * while terminating.
    */
   bzero(&sigact, sizeof(sigact));
   sigact.sa_handler = SIG_IGN;
   if (sigaction(SIGTERM, &sigact, NULL) != 0
   ||  sigaction(SIGCHLD, &sigact, NULL) != 0)
      swarn("%s: sigaction()", function);

   slog(LOG_DEBUG, "%s: insignal = %d", function, (int)sockscf.state.insignal);

   if ((ismainmother = pidismother(sockscf.state.pid)) == 1) {
      if (sockscf.state.insignal)
         slog(LOG_ALERT, "%s: terminating on signal %d",
         function, sockscf.state.insignal);
      else
         slog(LOG_ALERT, "%s: terminating", function);

#if !HAVE_DISABLED_PIDFILE
      if (sockscf.state.init)
         sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_ON);

      if (truncate(SOCKD_PIDFILE, 0) != 0)
         swarn("%s: truncate(%s)", function, SOCKD_PIDFILE);

      if (sockscf.state.init)
         sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_OFF);
#endif /* !HAVE_DISABLED_PIDFILE */

   }

#if HAVE_PROFILING
   if (chdir(SOCKS_PROFILEDIR) != 0)
      swarn("%s: chdir(%s)", function, SOCKS_PROFILEDIR);
   else {
      char dir[80];

      snprintfn(dir, sizeof(dir), "%s.%d",
      childtype2string(sockscf.state.type), (int)getpid());

      if (mkdir(dir, S_IRWXU) != 0)
         swarn("%s: mkdir(%s)", function, dir);
      else
         if (chdir(dir) != 0)
            swarn("%s: chdir(%s)", function, dir);
   }
#endif /* HAVE_PROFILING */

   if (pidismother(sockscf.state.pid))
      removechild(0);

   if (ismainmother)
      sigserverbroadcast(SIGTERM); /* let others terminate too. */

   if (!sockscf.state.insignal || SIGNALISOK(sockscf.state.insignal))
      for (i = 0;  i < sockscf.log.fpc; ++i) {
         fclose(sockscf.log.fpv[i]);
         close(sockscf.log.fplockv[i]);
      }


   if (ismainmother)
      exit(code);
   else {
#if HAVE_PROFILING
      exit(code);
#else
      fflush(NULL);
      _exit(code);
#endif /* HAVE_PROFILING */
   }
}

int
socks_seteuid(old, new)
   uid_t *old;
   uid_t new;
{
   const char *function = "socks_seteuid()";
   uid_t oldmem;
   struct passwd *pw;
#if HAVE_LINUX_BUGS
   int errno_s;
#endif /* HAVE_LINUX_BUGS */

   if (old == NULL)
      old = &oldmem;
   *old = geteuid();

   slog(LOG_DEBUG, "%s: old: %lu, new: %lu",
   function, (unsigned long)*old, (unsigned long)new);

   if (*old == new)
      return 0;

   if (*old != sockscf.state.euid)
      /* need to revert back to original (presumably 0) euid before changing. */
      if (seteuid(sockscf.state.euid) != 0) {
         swarn("%s: failed revering to original euid %u",
         function, (int)sockscf.state.euid);

         SERR(sockscf.state.euid);
      }

#if HAVE_LINUX_BUGS
   errno_s = errno;
#endif /* HAVE_LINUX_BUGS */
   if ((pw = getpwuid(new)) == NULL) {
      swarn("%s: getpwuid(%d)", function, new);
      return -1;
   }
#if HAVE_LINUX_BUGS
   errno = errno_s;
#endif /* HAVE_LINUX_BUGS */

   /* groupid ... */
   if (setegid(pw->pw_gid) != 0) {
      swarn("%s: setegid(%d)", function, pw->pw_gid);
      return -1;
   }

   /* ... and uid. */
   if (seteuid(new) != 0) {
      swarn("%s: seteuid(%d)", function, new);
      return -1;
   }

   return 0;
}


int
pidismother(pid)
   pid_t pid;
{
   size_t i;

   if (sockscf.state.motherpidv == NULL)
      return 1; /* so early we haven't forked yet. */

   for (i = 0; i < sockscf.option.serverc; ++i)
      if (sockscf.state.motherpidv[i] == pid)
         return i + 1;

   return 0;
}

int
descriptorisreserved(d)
   int d;
{

   if (d == sockscf.bwlock
   ||  d == sockscf.sessionlock)
      return 1;

   /* don't close sockscf/log files. */
   if (socks_logmatch((size_t)d, &sockscf.log))
      return 1;

   return 0;
}

void
sigserverbroadcast(sig)
   int sig;
{
   size_t i;

   if (sockscf.state.motherpidv == NULL)
      return; /* so early we haven't forked yet. */

   for (i = 1; i < sockscf.option.serverc; ++i)
      if (sockscf.state.motherpidv[i] != 0)
         kill(sockscf.state.motherpidv[i], sig);
}


unsigned char *
socks_getmacaddr(ifname, addr)
   const char *ifname;
   unsigned char *addr;
{
   const char *function = "socks_getmacaddr()";
#ifdef SIOCGIFHWADDR
   struct ifreq ifr;
   int s;

   slog(LOG_DEBUG, "%s: ifname %s", function, ifname);

   if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      swarn("%s: socket()", function);
      return NULL;
   }

   strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
   ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = NUL;

   if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) {
      swarn("%s: ioctl(SIOCGIFHWADDR)", function);

      close(s);
      return NULL;
   }

   memcpy(addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

   slog(LOG_DEBUG, "%s: mac address of interface %s is "
                   "%02x:%02x:%02x:%02x:%02x:%02x",
                   function, ifname,
                   addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

   return addr;

#else /* !SIOCGIFHWADDR */
   swarnx("%s: getting the mac address not supported on this platform",
   function);

   return NULL;
#endif /* !SIOCGIFHWADDR */
}

void
sockd_pushsignal(sig)
   const int sig;
{
   const char *function = "sockd_pushsignal()";
   sigset_t all, oldmask;
   size_t i, alreadythere;

   (void)sigfillset(&all);
   if (sigprocmask(SIG_SETMASK, &all, &oldmask) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK)", function);

   /* if already there, don't add. */
   for (i = alreadythere = 0; i < (size_t)sockscf.state.signalc; ++i)
      if (sockscf.state.signalv[i] == sig) {
         alreadythere = 1;
         break;
      }

   if (!alreadythere) {
      if (i < ELEMENTS(sockscf.state.signalv))
         sockscf.state.signalv[sockscf.state.signalc++] = sig;
      else
         SERRX(sig);
   }

   if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK, &oldmask, NULL)", function);
}

int
sockd_popsignal(void)
{
   const char *function = "sockd_popsignal()";
   sigset_t all, oldmask;
   int sig;

   (void)sigfillset(&all);
   if (sigprocmask(SIG_SETMASK, &all, &oldmask) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK)", function);

   SASSERTX(sockscf.state.signalc > 0);

   sig = sockscf.state.signalv[0];
   memmove(sockscf.state.signalv, &sockscf.state.signalv[1],
   sizeof(*sockscf.state.signalv) * (--sockscf.state.signalc));

   if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK, &oldmask, NULL)", function);

   return sig;
}
