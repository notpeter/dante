/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009
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
"$Id: log.c,v 1.113.6.7 2011/03/08 15:06:32 michaels Exp $";

#include "common.h"
#include "config_parse.h"


#if HAVE_EXECINFO_H && DEBUG
#include <execinfo.h>
#endif /* HAVE_EXECINFO_H && DEBUG */

#if DEBUG
#undef SOCKS_IGNORE_SIGNALSAFETY
#define SOCKS_IGNORE_SIGNALSAFETY 1
#endif /* DEBUG */

static const struct {
   const char *name;
   const int value;
} syslogfacilityv[] = {
#ifdef LOG_AUTH
   { "auth",   LOG_AUTH          },
#endif /* LOG_AUTH */
#ifdef LOG_AUTHPRIV
   { "authpriv",   LOG_AUTHPRIV  },
#endif /* LOG_AUTHPRIV */
#ifdef LOG_DAEMON
   { "daemon",   LOG_DAEMON      },
#endif /* LOG_DAEMON */
#ifdef LOG_USER
   { "user",   LOG_USER          },
#endif /* LOG_USER */
#ifdef LOG_LOCAL0
   { "local0",   LOG_LOCAL0      },
#endif /* LOG_LOCAL0 */
#ifdef LOG_LOCAL1
   { "local1",   LOG_LOCAL1      },
#endif /* LOG_LOCAL1 */
#ifdef LOG_LOCAL2
   { "local2",   LOG_LOCAL2      },
#endif /* LOG_LOCAL2 */
#ifdef LOG_LOCAL3
   { "local3",   LOG_LOCAL3      },
#endif /* LOG_LOCAL3 */
#ifdef LOG_LOCAL4
   { "local4",   LOG_LOCAL4      },
#endif /* LOG_LOCAL4 */
#ifdef LOG_LOCAL5
   { "local5",   LOG_LOCAL5      },
#endif /* LOG_LOCAL5 */
#ifdef LOG_LOCAL6
   { "local6",   LOG_LOCAL6      },
#endif /* LOG_LOCAL6 */
#ifdef LOG_LOCAL7
   { "local7",   LOG_LOCAL7      }
#endif /* LOG_LOCAL7 */
};



static char *
logformat(int priority, char *buf, size_t buflen, const char *message,
      va_list ap)
      __attribute__((__bounded__(__string__, 2, 3)))
      __attribute__((format(printf, 4, 0)));
/*
 * formats "message" as appropriate.  The formatted message is stored
 * in the buffer "buf", which is of size "buflen".
 * If no newline is present at the end of the string, one is added.
 * Returns:
 *      On success: pointer to "buf".
 *      On failure: NULL.
 */


void
newprocinit(void)
{

#if !SOCKS_CLIENT
   /*
    * not using this for client, since if e.g. the client forks, we'd
    * end up printing the wrong pid.
    */
   sockscf.state.pid = getpid();

   /* don't want to override original clients stuff. */
   if (sockscf.log.type & LOGTYPE_SYSLOG) {
      closelog();

      /*
       * LOG_NDELAY so we don't end up in a situation where we
       * have no free descriptors and haven't yet syslog-ed anything.
       */
      openlog(__progname, LOG_NDELAY | LOG_PID, sockscf.log.facility);
   }
#endif /* !SOCKS_CLIENT */
}

void
socks_addlogfile(logfile)
   const char *logfile;
{
   const char *syslogname = "syslog";

   if (strncmp(logfile, syslogname, strlen(syslogname)) == 0
   && ( logfile[strlen(syslogname)] == NUL
     || logfile[strlen(syslogname)] == '/')) {
      const char *sl;

      sockscf.log.type |= LOGTYPE_SYSLOG;

      if (*(sl = &(logfile[strlen(syslogname)])) == '/') { /* facility. */
         size_t i;

         for (i = 0, ++sl; i < ELEMENTS(syslogfacilityv); ++i)
            if (strcmp(sl, syslogfacilityv[i].name) == 0)
               break;

         if (i == ELEMENTS(syslogfacilityv))
            serr(EXIT_FAILURE, "unknown syslog facility \"%s\"", sl);

         sockscf.log.facility = syslogfacilityv[i].value;
         sockscf.log.facilityname = syslogfacilityv[i].name;
      }
      else {
         sockscf.log.facility = LOG_DAEMON; /* default. */
         sockscf.log.facilityname = "daemon";
      }
   }
   else { /* filename. */
      if (!sockscf.state.init) {
         int flag;

         sockscf.log.type |= LOGTYPE_FILE;

         if ((sockscf.log.fpv = realloc(sockscf.log.fpv,
         sizeof(*sockscf.log.fpv) * (sockscf.log.fpc + 1))) == NULL
         || (sockscf.log.fplockv = realloc(sockscf.log.fplockv,
         sizeof(*sockscf.log.fplockv) * (sockscf.log.fpc + 1))) == NULL
         || (sockscf.log.filenov = realloc(sockscf.log.filenov,
         sizeof(*sockscf.log.filenov) * (sockscf.log.fpc + 1))) == NULL
         || (sockscf.log.fnamev = realloc(sockscf.log.fnamev,
         sizeof(*sockscf.log.fnamev) * (sockscf.log.fpc + 1)))
         == NULL)
            serrx(EXIT_FAILURE, NOMEM);

         if ((sockscf.log.fplockv[sockscf.log.fpc]
         = socks_mklock(SOCKS_LOCKFILE)) == -1)
            serr(EXIT_FAILURE, "socks_mklock()");

         if (strcmp(logfile, "stdout") == 0)
            sockscf.log.fpv[sockscf.log.fpc] = stdout;
         else if (strcmp(logfile, "stderr") == 0)
            sockscf.log.fpv[sockscf.log.fpc] = stderr;
         else {
            if ((sockscf.log.fpv[sockscf.log.fpc] = fopen(logfile, "a"))
            == NULL)
               serr(EXIT_FAILURE, "fopen(%s)", logfile);

            if (setvbuf(sockscf.log.fpv[sockscf.log.fpc], NULL, _IOLBF, 0)
            != 0)
               serr(EXIT_FAILURE, "setvbuf(_IOLBF)");
         }

         if ((flag = fcntl(fileno(sockscf.log.fpv[sockscf.log.fpc]),
         F_GETFD, 0)) == -1
         ||  fcntl(fileno(sockscf.log.fpv[sockscf.log.fpc]), F_SETFD,
         flag | FD_CLOEXEC) == -1)
            serr(EXIT_FAILURE, "fcntl(F_GETFD/F_SETFD)");

         if ((sockscf.log.fnamev[sockscf.log.fpc] = strdup(logfile)) == NULL)
            serr(EXIT_FAILURE, NOMEM);

         /*
          * Now that fileno(3) is no longer just a simple macro (due to
          * 1003.1-2001?), but something that can require locking, which I
          * don't think we need, just do a lookup here instead and save the
          * value.  Avoids a possible (?) deadlock in vslog, where we do
          * fileno(3) both for SYSCALL_START and SYSCALL_END(), and in
          * between lock the logfile itself.
          */
         sockscf.log.filenov[sockscf.log.fpc]
         = fileno(sockscf.log.fpv[sockscf.log.fpc]);

         ++sockscf.log.fpc;
      }
      else {
         /*
          * Can't change filenames we log to after startup, so
          * try to check and warn about that.
          */
         size_t i;

         for (i = 0; i < sockscf.log.fpc; ++i)
            if (strcmp(sockscf.log.fnamev[i], logfile) == 0) {
               /* same name; reopen. */
               FILE *fp;

               if (strcmp(sockscf.log.fnamev[i], "stdout") == 0
               ||  strcmp(sockscf.log.fnamev[i], "stderr") == 0)
                  break; /* don't try to reopen these. */

               if ((fp = fopen(sockscf.log.fnamev[i], "a")) == NULL)
                  serr(EXIT_FAILURE,
                       "can't reopen %s, continuing to use existing file",
                       logfile);
               else {
                  fclose(sockscf.log.fpv[i]);
                  sockscf.log.fpv[i] = fp;

                  if (setvbuf(sockscf.log.fpv[i], NULL, _IOLBF, 0) != 0)
                     serr(EXIT_FAILURE, "setvbuf(_IOLBF)");
               }
               break;
            }

         if (i == sockscf.log.fpc) /* no match found. */
            swarnx("can't change logoutput after startup, "
                   "continuing to use original logfiles");
      }
   }
}

void
slog(int priority, const char *message, ...)
{
   va_list ap, apcopy;

   /*
    * not all systems may have va_copy().  Idea from a news post by
    * Chris Torek.
    */
   va_start(ap, message);
   va_start(apcopy, message);

   vslog(priority, message, ap, apcopy);

   va_end(apcopy);
   va_end(ap);
}

void
vslog(priority, message, ap, apsyslog)
   int priority;
   const char *message;
   va_list ap;
   va_list apsyslog;
{
   const int errno_s = errno;
#if SOCKS_CLIENT /* can have a small buffer. */
   char buf[1024];
#else /* !SOCKS_CLIENT */
   /*
    * This needs to be at least as larg as SOCKD_BUFSIZE, as in
    * the worst (best?) case, that's how much we will read/write
    * from the socket, and user wants to log it all ...
    */
   char buf[SOCKD_BUFSIZE + 2048 /* 2048: "context" */];
#endif /* !SOCKS_CLIENT */
   int logged = 0;


#if !SOCKS_IGNORE_SIGNALSAFETY
   if (sockscf.state.insignal 
   /* && priority > LOG_ERR */) /* > pri means < serious */
      /*
       * Note that this can be the case even if insignal is not set.
       * This can happen in the client if the application has
       * installed a signalhandler, and that signalhandler ends
       * up making calls that involve us.
       */
      return;
#endif /* !SOCKS_IGNORE_SIGNALSAFETY */

   *buf = NUL;
   if (sockscf.log.type & LOGTYPE_SYSLOG)
      if ((sockscf.state.init && priority != LOG_DEBUG)
      || (priority == LOG_DEBUG && sockscf.option.debug)) {
         vsyslog(priority, message, apsyslog);
         logged = 1;
      }

   if (sockscf.log.type & LOGTYPE_FILE) {
      size_t i;

      if (logformat(priority, buf, sizeof(buf), message, ap) == NULL)
         return;

      for (i = 0; i < sockscf.log.fpc; ++i) {
#if SOCKSLIBRARY_DYNAMIC
         SYSCALL_START(sockscf.log.filenov[i]);
#endif /* SOCKSLIBRARY_DYNAMIC */

         socks_lock(sockscf.log.fplockv[i], F_WRLCK, -1);
         fprintf(sockscf.log.fpv[i], "%s", buf);
         socks_unlock(sockscf.log.fplockv[i]);
         logged = 1;

#if SOCKSLIBRARY_DYNAMIC
         SYSCALL_END(sockscf.log.filenov[i]);
#endif /* SOCKSLIBRARY_DYNAMIC */
      }
   }

   if (!logged && !sockscf.state.init) { /* may not have set-up logfiles yet. */
#if !SOCKS_CLIENT /* log to stdout for now. */
      if (*buf == NUL)
         if (logformat(priority, buf, sizeof(buf), message, ap) == NULL)
            return;

      fprintf(stdout, "%s", buf);
      return;
#else /* SOCKS_CLIENT */ /* no idea where stdout points to in client case. */
#endif /* SOCKS_SERVER */
   }

   errno = errno_s;
}

static char *
logformat(priority, buf, buflen, message, ap)
   int priority;
   char *buf;
   size_t buflen;
   const char *message;
   va_list ap;
{
   struct timeval timenow;
   time_t secondsnow;
   size_t bufused;
   pid_t pid;

#if SOCKS_CLIENT /* can't trust saved state. */
   pid = getpid();
#else /* !SOCKS_CLIENT */
   if (sockscf.state.pid == 0)
      pid = getpid();
   else
      pid = sockscf.state.pid;
#endif /* !SOCKS_CLIENT */

   switch (priority) {
      case LOG_DEBUG:
#if DEBUG || DIAGNOSTIC || SOCKS_CLIENT
         if (sockscf.state.init && !sockscf.option.debug)
            return NULL;
#else  /* !(DEBUG || DIAGNOSTIC || SOCKS_CLIENT) */
         if (!sockscf.option.debug)
            return NULL;
#endif /* DEBUG || DIAGNOSTIC || SOCKS_CLIENT */
         break;
   }

   gettimeofday(&timenow, NULL);

   if (!sockscf.state.insignal) { /* very prone to hanging on some systems. */
      secondsnow = (time_t)timenow.tv_sec;
      bufused = strftime(buf, buflen, "%h %e %T ", localtime(&secondsnow));
   }
   else
      bufused = snprintfn(buf, buflen, "<in signalhandler - no localtime> ");

   bufused += snprintfn(&buf[bufused], buflen - bufused, "(%ld.%ld) %s[%lu]: ",
   (long)timenow.tv_sec, timenow.tv_usec, __progname, (unsigned long)pid);

   vsnprintf(&buf[bufused], buflen - bufused, message, ap);
   bufused = strlen(buf);

   if (buf[bufused - 1] != '\n') { /* add ending newline. */
      bufused = MIN(bufused, buflen - 2); /* silently truncate. */
      buf[bufused++] = '\n';
      buf[bufused++] = NUL;
   }

   return buf;
}

#if !SOCKS_CLIENT
#define DO_BUILD(srcdst_str, dst_too)                                          \
do {                                                                           \
   char srcstr[MAX_IOLOGADDR];                                                 \
                                                                               \
   BUILD_ADDRSTR_SRC(src_peer,                                                 \
                     src_proxy_ext,                                            \
                     src_proxy,                                                \
                     src_local,                                                \
                     src_auth,                                                 \
                     src_proxyauth,                                            \
                     (dst_too) ? (srcstr) : (srcdst_str),                      \
                     (dst_too) ? sizeof(srcstr) : sizeof(srcdst_str));         \
                                                                               \
   if ((dst_too)) {                                                            \
      char dststr[MAX_IOLOGADDR];                                              \
                                                                               \
      BUILD_ADDRSTR_DST(dst_local,                                             \
                        dst_proxy,                                             \
                        dst_proxy_ext,                                         \
                        dst_peer,                                              \
                        dst_auth,                                              \
                        dst_proxyauth,                                         \
                        dststr,                                                \
                        sizeof(dststr));                                       \
                                                                               \
      snprintf((srcdst_str), sizeof((srcdst_str)), "%s -> %s", srcstr, dststr);\
   }                                                                           \
} while (/* CONSTCOND */ 0)

void
iolog(rule, state, operation,
      src_local, src_peer, src_auth, src_proxy, src_proxy_ext, src_proxyauth,
      dst_local, dst_peer, dst_auth, dst_proxy, dst_proxy_ext, dst_proxyauth,
      data, count)
   struct rule_t *rule;
   const struct connectionstate_t *state;
   const operation_t operation;
   const struct sockaddr *src_local;
   const struct sockshost_t *src_peer;
   const struct authmethod_t *src_auth;
   const gwaddr_t *src_proxy;
   const struct sockshost_t *src_proxy_ext;
   const struct authmethod_t *src_proxyauth;
   const struct sockaddr *dst_local;
   const struct sockshost_t *dst_peer;
   const struct authmethod_t *dst_auth;
   const gwaddr_t *dst_proxy;
   const struct sockshost_t *dst_proxy_ext;
   const struct authmethod_t *dst_proxyauth;
   const char *data;
   size_t count;
{
   char srcdst_str[MAX_IOLOGADDR + strlen(" -> ") + MAX_IOLOGADDR],
        rulecommand[256], 
        ruleinfo[SOCKD_BUFSIZE * 4 + 1 + sizeof(srcdst_str)
                 + 1024 /* misc stuff, if any. */];
   int logdstinfo;

   if (state->command == SOCKS_ACCEPT)
      logdstinfo = 0; /* no dst (yet); connect is from client to us. */
   else
      logdstinfo = 1;

   switch (operation) {
      case OPERATION_ACCEPT:
      case OPERATION_CONNECT:
         if (!rule->log.connect)
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "[: %s%s%s",
                     srcdst_str,
                     (data == NULL || *data == NUL) ? "" : ": ",
                     (data == NULL || *data == NUL) ? "" : data);
         }
         break;

      case OPERATION_DISCONNECT:
         if (!rule->log.disconnect)
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo), "]: %s", srcdst_str);
         }
         break;


      case OPERATION_TIMEOUT:
         if (!(rule->log.disconnect || rule->log.error))
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo), "]: %s: %s", srcdst_str, data);
         }
         break;

      case OPERATION_TMPERROR:
         if (!rule->log.error)
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo), "-: %s: %s",
                     srcdst_str, 
                     (data == NULL || *data == NUL) ? ERRNOSTR(errno) : data);
         }
         break;

      case OPERATION_ERROR:
         if (!rule->log.error)
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "]: %s: %s",
                     srcdst_str,
                    (data == NULL || *data == NUL) ? ERRNOSTR(errno) : data);
         }
         break;

      case OPERATION_BLOCK:
         if (!rule->log.disconnect)
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "]: %s%s%s",
                     srcdst_str,
                     (data == NULL || *data == NUL) ? "" : ": ",
                     (data == NULL || *data == NUL) ? "" : data);
         }
         break;

      case OPERATION_IO:
         if (!(rule->log.data || rule->log.iooperation))
            return;

         if (rule->log.data && count != 0) {
            char visdata[SOCKD_BUFSIZE * 4 + 1];

            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "-: %s (%lu): %s",
                     srcdst_str, (unsigned long)count,
                     str2vis(data, count, visdata, sizeof(visdata)));
         }
         else if (rule->log.iooperation || rule->log.data) {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "-: %s (%lu)",
                     srcdst_str, (unsigned long)count);
         }
         break;

      default:
         SERRX(operation);
   }

   snprintf(rulecommand, sizeof(rulecommand), "%s(%lu): %s/%s",
            verdict2string(operation == OPERATION_BLOCK ?
                           VERDICT_BLOCK : rule->verdict),
#if BAREFOOTD
            /* always use the number from the user-created rule. */
            (state->protocol == SOCKS_UDP && rule->crule != NULL) ?
            (unsigned long)rule->crule->number : (unsigned long)rule->number,
#else /* !BAREFOOTD */
            (unsigned long)rule->number,
#endif /* !BAREFOOTD */
            protocol2string(state->protocol),
            command2string(state->command));

   slog(LOG_INFO, "%s %s", rulecommand, ruleinfo);
}
#endif /* !SOCKS_CLIENT */


#if DEBUG && 0 /* XXX should be && <glibc> */
void
slogstack(void)
{
   const char *function = "slogstack()";
   void *array[20];
   size_t i, size;
   char **strings;

   size    = backtrace(array, 20);
   strings = backtrace_symbols(array, size);

   for (i = 1; i < size; i++)
      slog(LOG_DEBUG, "%s: stackframe %d: %s\n", function, i, strings[i]);

   free(strings);
}
#endif
