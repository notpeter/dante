/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009, 2010,
 *               2011
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
"$Id: log.c,v 1.188 2011/06/18 19:13:34 michaels Exp $";

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


static size_t
logformat(int priority, char *buf, const size_t buflen, const char *message,
      va_list ap)
      __attribute__((__bounded__(__string__, 2, 3)))
      __attribute__((format(printf, 4, 0)));
/*
 * formats "message" as appropriate.  The formatted message is stored
 * in the buffer "buf", which is of size "buflen".
 * If no newline is present at the end of the string, one is added.
 *
 * Returns the number of writes written to buf, terminating NUL included.
 */

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
                     (dst_too) ? srcstr : srcdst_str,                          \
                     (dst_too) ? sizeof(srcstr) : sizeof(srcdst_str));         \
                                                                               \
   if (dst_too) {                                                              \
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
      snprintf(srcdst_str, sizeof(srcdst_str), "%s -> %s", srcstr, dststr);    \
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
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "]: %s%s%s",
                     srcdst_str,
                     (data == NULL || *data == NUL) ? "" : ": ",
                     (data == NULL || *data == NUL) ? "" : data);
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

      case OPERATION_ERROR:
         if (!rule->log.error)
            return;
         else {
            DO_BUILD(srcdst_str, logdstinfo);
            snprintf(ruleinfo, sizeof(ruleinfo),
                     "]: %s: %s",
                     srcdst_str,
                    (data == NULL || *data == NUL) ? errnostr(errno) : data);
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

void
newprocinit(void)
{
#if !SOCKS_CLIENT
   const char *function = "newprocinit()";

   /*
    * not using this for client, since if e.g. the client forks, we'd
    * end up printing the wrong pid.
    */
   sockscf.state.pid = getpid();

   /* CONSTCOND */
   if ((sockscf.log.type    & LOGTYPE_SYSLOG)
   ||  (sockscf.errlog.type & LOGTYPE_SYSLOG)
   ||  HAVE_LIBWRAP /* libwrap may also log to syslog. */) {
      closelog();

      /*
       * LOG_NDELAY so we don't end up in a situation where we
       * have no free descriptors and haven't yet syslog-ed anything.
       */
      openlog(__progname,
              LOG_NDELAY | LOG_PID
#ifdef LOG_NOWAIT
              | LOG_NOWAIT
#endif /* LOG_NOWAIT */
              , 0);
   }

   /*
    * Don't inherit mothers signal-queue.
    */
   sockscf.state.signalc = 0;

   srandom(sockscf.state.pid);
#endif /* !SOCKS_CLIENT */
}

int
socks_addlogfile(logcf, logfile)
   struct logtype_t *logcf;
   const char *logfile;
{
   const char *function = "socks_addlogfile()";
   const char *syslogname = "syslog";

   if (strncmp(logfile, syslogname, strlen(syslogname)) == 0
   && ( logfile[strlen(syslogname)] == NUL
     || logfile[strlen(syslogname)] == '/')) {
      const char *sl;

      logcf->type |= LOGTYPE_SYSLOG;

      if (*(sl = &(logfile[strlen(syslogname)])) == '/') { /* facility. */
         size_t i;

         for (i = 0, ++sl; i < ELEMENTS(syslogfacilityv); ++i)
            if (strcmp(sl, syslogfacilityv[i].name) == 0)
               break;

         if (i == ELEMENTS(syslogfacilityv)) {
            swarnx("unknown syslog facility \"%s\"", sl);
            return -1;
         }

         logcf->facility = syslogfacilityv[i].value;
         logcf->facilityname = syslogfacilityv[i].name;
      }
      else {
         logcf->facility = LOG_DAEMON; /* default. */
         logcf->facilityname = "daemon";
      }
   }
   else { /* filename. */
      int flag;

      logcf->type |= LOGTYPE_FILE;

      if ((logcf->filenov = realloc(logcf->filenov,
      sizeof(*logcf->filenov) * (logcf->filenoc + 1))) == NULL
      || (logcf->fnamev = realloc(logcf->fnamev,
      sizeof(*logcf->fnamev) * (logcf->filenoc + 1))) == NULL) {
         swarn("failed to allocate memory for logfile names");
         return -1;
      }

      if (strcmp(logfile, "stdout") == 0)
         logcf->filenov[logcf->filenoc] = fileno(stdout);
      else if (strcmp(logfile, "stderr") == 0)
         logcf->filenov[logcf->filenoc] = fileno(stderr);
      else {
         logcf->filenov[logcf->filenoc]
         = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

         if (logcf->filenov[logcf->filenoc] == -1) {
            swarn("open(%s) failed", logfile);
            return -1;
         }
      }

      if ((flag = fcntl(logcf->filenov[logcf->filenoc], F_GETFD, 0)) == -1
      ||  fcntl(logcf->filenov[logcf->filenoc], F_SETFD, flag | FD_CLOEXEC)
      == -1) {
         swarn("fcntl(F_GETFD/F_SETFD) failed");
         return -1;
      }

      if ((logcf->fnamev[logcf->filenoc] = strdup(logfile)) == NULL) {
         swarn("failed to allocate memory for logfile name");
         return -1;
      }

      ++logcf->filenoc;
   }

   return 0;
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
   size_t loglen;
   int needlock;
#if SOCKS_CLIENT /* can have a small buffer. */
   char logstr[1024];
#else /* !SOCKS_CLIENT */
   /*
    * This needs to be at least as large as SOCKD_BUFSIZE, as in
    * the worst (best?) case, that's how much we will read/write
    * from the socket, and user wants to log it all ...
    */
   char logstr[SOCKD_BUFSIZE + 2048 /* 2048: "context" */];
#endif /* !SOCKS_CLIENT */
   int logged = 0;

#if !SOCKS_IGNORE_SIGNALSAFETY
   if (sockscf.state.insignal
   /* && priority > LOG_WARNING */) /* > pri means < serious */
      /*
       * Note that this can be the case even if insignal is not set.
       * This can happen in the client if the application has
       * installed a signalhandler, and that signalhandler ends
       * up making calls that involve us.
       */
      return;
#endif /* !SOCKS_IGNORE_SIGNALSAFETY */

   if (priority == LOG_DEBUG && !sockscf.option.debug)
      return;

   /*
    * Do syslog logging first ...
    */
   if ((sockscf.errlog.type & LOGTYPE_SYSLOG)
   ||  (sockscf.log.type    & LOGTYPE_SYSLOG)) {
      int p;

      if ((p = vsnprintf(logstr, sizeof(logstr), message, apsyslog)) < 0 
      ||  p >= (int)sizeof(logstr))
         return;

      if (priority <= LOG_WARNING) /* lower pri value means more serious */
         if (sockscf.errlog.type & LOGTYPE_SYSLOG) {
            syslog(priority | sockscf.errlog.facility,
                   "%s: %s",
                   loglevel2string(priority), logstr);

            logged = 1;
         }

      if (sockscf.log.type & LOGTYPE_SYSLOG) {
         syslog(priority | sockscf.log.facility,
                "%s: %s",
                loglevel2string(priority), logstr);

         logged = 1;
      }
   }

   /*
    * ... and then logging to file.
    */

   needlock = 0;
   if ((priority <= LOG_WARNING && (sockscf.errlog.type & LOGTYPE_FILE))
   || ((sockscf.log.type & LOGTYPE_FILE))) {
      loglen = logformat(priority, logstr, sizeof(logstr), message, ap);

      if (loglen != 0 && sockscf.loglock != -1) {
         needlock = 1;
         socks_lock(sockscf.loglock, 1, 1);
      }
   }
   else
      loglen = 0;

   /* error-related logging first ...  */
   if (priority <= LOG_WARNING) { /* lower pri value means more serious */
      if (loglen != 0 && (sockscf.errlog.type & LOGTYPE_FILE)) {
         size_t i;

         for (i = 0; i < sockscf.errlog.filenoc; ++i) {
            write(sockscf.errlog.filenov[i], logstr, loglen - 1);
            logged = 1;
         }
      }
   }

   /* ... and then normal logging. */
   if (loglen != 0 && (sockscf.log.type & LOGTYPE_FILE)) {
      size_t i;

      for (i = 0; i < sockscf.log.filenoc; ++i) {
         write(sockscf.log.filenov[i], logstr, loglen - 1);
         logged = 1;
      }
   }

   if (needlock)
      socks_unlock(sockscf.loglock);

   /*
    * If we need to log something serious, but have not inited
    * logfiles yet, try to log to stderr if that seems likly to
    * work.
    */

   if (!logged
   &&  !sockscf.state.inited
   &&  priority != LOG_DEBUG
#if !SOCKS_CLIENT
   && !sockscf.option.daemon
#endif /* !SOCKS_CLIENT */
   ) {
      /* may not have set-up logfiles yet. */
#if !SOCKS_CLIENT /*
                   * log to stderr for now.
                   * no idea where stdout points to in client case.
                   */

      if (loglen == 0)
         loglen = logformat(priority, logstr, sizeof(logstr), message, ap);

      if (loglen != 0)
         write(fileno(stderr), logstr, loglen - 1);
#endif /* SOCKS_SERVER */
   }

   errno = errno_s;
}

static size_t
logformat(priority, buf, buflen, message, ap)
   int priority;
   char *buf;
   const size_t buflen;
   const char *message;
   va_list ap;
{
   struct timeval timenow;
   time_t secondsnow;
   ssize_t p;
   size_t bufused;
   pid_t pid;

   if (buflen <= 0)
      return 0;

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
         if (!sockscf.option.debug)
            return 0;
   }

   gettimeofday(&timenow, NULL);
   bufused = 0;

   if (!sockscf.state.insignal) { /* very prone to hanging on some systems. */
      secondsnow = (time_t)timenow.tv_sec;
      bufused += strftime(&buf[bufused], buflen - bufused,
                          "%h %e %T ",
                          localtime(&secondsnow));
   }
   else
      bufused += snprintf(&buf[bufused], buflen - bufused,
                          "<in signalhandler> ");

   if (bufused >= buflen) {
      buf[buflen - 1] = NUL;
      return buflen;
   }

   bufused += snprintf(&buf[bufused], buflen - bufused,
                       "(%ld.%ld) %s[%lu]: ",
                       (long)timenow.tv_sec,
                       (long)timenow.tv_usec,
                       __progname,
                       (unsigned long)pid);

   if (bufused >= buflen) {
      buf[buflen - 1] = NUL;
      return buflen;
   }

   bufused += snprintf(&buf[bufused], buflen - bufused,
                       "%s: ",
                       loglevel2string(priority));

   if (bufused >= buflen) {
      buf[buflen - 1] = NUL;
      return buflen;
   }

   if ((p = vsnprintf(&buf[bufused], buflen - bufused, message, ap)) < 0
   ||  (size_t)p >= buflen - bufused)
      return 0;

   bufused += p;

   if (bufused >= buflen) {
      buf[buflen - 1] = NUL;
      return buflen;
   }

   SASSERTX(buf[bufused] == NUL);

   /* make sure there always is an ending newline. */
   if (buf[bufused - 1] != '\n') {
      if ((bufused - 1) + strlen("\n") + 1 /* NUL */ >= buflen)
         --bufused; /* silently truncate. */

      buf[bufused++] = '\n';
      buf[bufused++] = NUL;
   }
   else
      ++bufused; /* count NUL also. */

   return bufused;
}

#if DEBUG && HAVE_BACKTRACE
void
slogstack(void)
{
   const char *function = "slogstack()";
   void *array[20];
   size_t i, size;
   char **strings;

   size    = backtrace(array, (int)ELEMENTS(array));
   strings = backtrace_symbols(array, size);

   if (strings == NULL)  {
      swarn("%s: strings = NULL", function);
      return;
   }

   for (i = 1; i < size; i++)
      slog(LOG_DEBUG, "%s: stackframe #%lu: %s\n",
      function, (unsigned long)i, strings[i]);

   free(strings);
}
#endif /* DEBUG && HAVE_BACKTRACE */
