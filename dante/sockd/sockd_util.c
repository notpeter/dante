/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 2008,
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

static const char rcsid[] =
"$Id: sockd_util.c,v 1.187 2011/05/09 09:53:06 michaels Exp $";

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
          * non-socks method.  Can select any of the standard methods 
          * that can provide the necessary information.
          */
         const unsigned char rfc931methodv[] = { AUTHMETHOD_NONE,
                                                 AUTHMETHOD_UNAME,
#if HAVE_GSSAPI
                                                 AUTHMETHOD_GSSAPI
#endif /* HAVE_GSSAPI */
                                               };

         const unsigned char pammethodv[] = {    AUTHMETHOD_UNAME,
                                                 AUTHMETHOD_NONE,
#if HAVE_GSSAPI
                                                 AUTHMETHOD_GSSAPI,
#endif /* HAVE_GSSAPI */
                                            };

         const unsigned char bsdmethodv[] = {    AUTHMETHOD_UNAME,
#if HAVE_GSSAPI
                                                 AUTHMETHOD_GSSAPI,
#endif /* HAVE_GSSAPI */
                                            };
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

            case AUTHMETHOD_BSDAUTH:
               methodokc = ELEMENTS(bsdmethodv);
               methodokv = bsdmethodv;
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
sockdexit(code)
   const int code;
{
   const char *function = "sockdexit()";
   static int exiting;
   struct rule_t *rulev[] = { sockscf.crule,
#if HAVE_TWO_LEVEL_ACL
                              sockscf.srule 
#endif /* HAVE_TWO_LEVEL_ACL */
   };
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
      if (sockscf.state.inited)
         sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_ON);

      if (sockscf.option.pidfile              != NULL
      &&  truncate(sockscf.option.pidfile, 0) != 0)
         swarn("%s: truncate(%s)", function, sockscf.option.pidfile);

      if (sockscf.state.inited)
         sockd_priv(SOCKD_PRIV_FILE_WRITE, PRIV_OFF);
#endif /* !HAVE_DISABLED_PIDFILE */

   }

#if HAVE_PROFILING
   if (chdir(SOCKS_PROFILEDIR) != 0) {
      if (pidismother(sockscf.state.pid))
         slog(LOG_ERR,
              "%s: profiling is enabled, but could not chdir(2) to it (%s).  "
              "If you wish profiling output to be saved, create a directory "
              "named \"%s\" in the same as directory as you start %s",
              function, strerror(errno), SOCKS_PROFILEDIR, PACKAGE);
   }
   else {
      char dir[80];

      snprintf(dir, sizeof(dir), "%s.%d",
      childtype2string(sockscf.state.type), (int)getpid());

      if (mkdir(dir, S_IRWXU) != 0)
         swarn("%s: mkdir(%s)", function, dir);
      else
         if (chdir(dir) != 0)
            swarn("%s: chdir(%s)", function, dir);
   }
#endif /* HAVE_PROFILING */

   /*
    * For some reason, Valgrind complains that the pointer to "name" is
    * lost:
    *
    * #  13 bytes in 1 blocks are definitely lost in loss record 3 of 9
    * #     at 0x4A0763E: malloc (vg_replace_malloc.c:207)
    * #     by 0x3FC387F681: strdup (in /lib64/libc-2.10.2.so)
    * #     by 0x43CE90: addlinkedname (rule.c:257)
    * #     by 0x403E3E: socks_yyparse (config_parse.y:470)
    * #     by 0x405B55: parseconfig (config_parse.y:2016)
    * #     by 0x41DE29: genericinit (config.c:80)
    * #     by 0x40AA22: serverinit (sockd.c:1157)
    * #     by 0x408EF8: main (sockd.c:193)
    *
    * Don't understand why valgrind complains, as it's not lost afaik, 
    * and adding this code to make the (on unix unnecessary) free(3) call
    * seems to prove that. 
    */
   for (i = 0; i < ELEMENTS(rulev); ++i) {
      struct rule_t *rule;

      for (rule = rulev[i]; rule != NULL; rule = rule->next) {
         struct linkedname_t *link;

         for (link = rule->user; link != NULL; link = link->next)
            free(link->name);

         for (link = rule->group; link != NULL; link = link->next)
            free(link->name);
      }
   }

   if (pidismother(sockscf.state.pid))
      removechild(0);

   if (ismainmother) {
      sigserverbroadcast(SIGTERM); /* let others terminate too. */
      resetconfig(1); /* mainly for removing old shared memory stuff. */
      exit(code);
   }

   /* 
    * Else; we are child.
    */

#if HAVE_PROFILING
   exit(code);
#else
   fflush(NULL);
   _exit(code);
#endif /* HAVE_PROFILING */
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

   if (d == sockscf.hostfd
   ||  d == sockscf.shmemfd
   ||  d == sockscf.loglock
#if HAVE_LDAP

   ||  d == sockscf.ldapfd
#endif /* HAVE_LDAP */
   ||  d == sockscf.configfd 
   /* due to external libraries/software trying to log to stdout/stderr. :-( */
   ||  d == STDOUT_FILENO
   ||  d == STDERR_FILENO)
      return 1;

   /* don't close log files. */
   if (socks_logmatch((size_t)d, &sockscf.log)
   ||  socks_logmatch((size_t)d, &sockscf.errlog))
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



void
sockd_pushsignal(sig, siginfo)
   const int sig;
   const siginfo_t *siginfo;
{
   const char *function = "sockd_pushsignal()";
   sigset_t all, oldmask;
   size_t i, alreadythere;

   SASSERTX(sig > 0);

   (void)sigfillset(&all);
   if (sigprocmask(SIG_SETMASK, &all, &oldmask) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK)", function);

   /* if already there, don't add. */
   for (i = alreadythere = 0; i < (size_t)sockscf.state.signalc; ++i)
      if (sockscf.state.signalv[i].signal == sig) {
         alreadythere = 1;
         break;
      }

   if (!alreadythere) {
      if (i < ELEMENTS(sockscf.state.signalv)) {
         sockscf.state.signalv[sockscf.state.signalc].signal    = sig;
         sockscf.state.signalv[sockscf.state.signalc].siginfo = *siginfo;
         ++sockscf.state.signalc;
      }
      else
         SERRX(sig);
   }

   if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK, &oldmask, NULL)", function);
}

int
sockd_popsignal(siginfo_t *siginfo)
{
   const char *function = "sockd_popsignal()";
   sigset_t all, oldmask;
   int sig;

   (void)sigfillset(&all);
   if (sigprocmask(SIG_SETMASK, &all, &oldmask) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK)", function);

   SASSERTX(sockscf.state.signalc > 0);

   sig      = sockscf.state.signalv[0].signal;
   *siginfo = sockscf.state.signalv[0].siginfo;

   memmove(sockscf.state.signalv, &sockscf.state.signalv[1],
   sizeof(*sockscf.state.signalv) * (--sockscf.state.signalc));

   if (sigprocmask(SIG_SETMASK, &oldmask, NULL) != 0)
      swarn("%s: sigprocmask(SIG_SETMASK, &oldmask, NULL)", function);

   return sig;
}

int
sockd_handledsignals()
{
   const char *function = "sockd_handledsignals()";
   struct sigaction oact;
   int i, rc = 0;

   if (sockscf.state.signalc == 0)
      return 0;

   if (sockscf.option.debug > 1)
      for (i = 0, rc = 0; i < sockscf.state.signalc; ++i)
         slog(LOG_DEBUG, "%s: signal #%d on the stack is signal %d",
         function, i + 1, (int)sockscf.state.signalv[i].signal);

   while (sockscf.state.signalc) {
      siginfo_t siginfo;
      const int signal = sockd_popsignal(&siginfo);

      slog(LOG_DEBUG, "%s: %d signals on the stack, popped signal %d",
      function, sockscf.state.signalc, signal);

      if (sigaction(signal, NULL, &oact) != 0)
         SERR(0);

      if (oact.sa_handler != SIG_IGN && oact.sa_handler != SIG_DFL) {
         oact.sa_sigaction(-signal, &siginfo, NULL);
         rc = 1;
      }
      else
         /*
          * can happen when a child temporarily changes the
          * signal disposition while starting up.
          */
         slog(LOG_DEBUG, "%s: no handler for signal %d at the moment",
         function, signal);
   }

   return rc;
}

