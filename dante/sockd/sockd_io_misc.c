/*
 * Copyright (c) 2013
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

static const char rcsid[] =
"$Id: sockd_io_misc.c,v 1.30 2013/10/27 15:17:07 karls Exp $";

void
io_updatemonitor(io)
   sockd_io_t *io;
{
   const char *function = "io_updatemonitor()";
   const monitor_t *newmatch;
   clientinfo_t cinfo;
   rule_t *oldrule = IORULE(io);
   size_t disconnect_needed;
   int is_same;

   SASSERTX(sockscf.state.type == PROC_IO);

   slog(LOG_DEBUG,
        "%s: control-fd %d, src-fd %d, dst-fd %d, protocol %s, command %s, "
        "mstats_shmid %lu, at address %p",
        function,
        io->control.s,
        io->src.s,
        io->dst.s,
        protocol2string(io->state.protocol),
        command2string(io->state.command),
        oldrule->mstats_shmid,
        oldrule->mstats);

   if (oldrule->mstats_shmid != 0)
      SASSERTX(oldrule->mstats != NULL); /* i/o process; always attached. */

   /*
    * XXX could probably optimize this function away be checking if a sighup
    * has occurred since the monitor settings were applied to this i/o object.
    */

#define DISCONNECT_NEEDED(_io, _dodisconnect)                                  \
do {                                                                           \
   *(_dodisconnect) = 0;                                                       \
                                                                               \
   if (!CONTROLIO((_io))->state.alarmdisconnectdone)                           \
      *(_dodisconnect) |= ALARM_INTERNAL;                                      \
                                                                               \
   if ((_io)->state.protocol == SOCKS_TCP) {                                   \
      if (!EXTERNALIO((_io))->state.alarmdisconnectdone)                       \
         *(_dodisconnect) |= ALARM_EXTERNAL;                                   \
   }                                                                           \
   /* else: other side is udp, only control-connection is tcp. */              \
} while (/* CONSTCOND */ 0)

   DISCONNECT_NEEDED(io, &disconnect_needed);

   if (io->state.protocol == SOCKS_UDP) {
#if HAVE_CONTROL_CONNECTION
      const connectionstate_t oldstate = io->state;

      /*
       * For the fixed (not per-packet) monitormatch we always base ourselves
       * on the control-connection, which is a TCP connection.
       */
      io->state.protocol = SOCKS_TCP;
      io->state.command  = SOCKS_ACCEPT; /* XXX what about SOCKS_HOSTID? */

      newmatch = monitormatch(&io->control.host,
                              sockaddr2sockshost(&io->control.laddr, NULL),
                              &io->src.auth,
                              &io->state);
      io->state = oldstate;
#else /* !HAVE_CONTROL_CONNECTION, and thus no TCP. */

      /*
       * we do a monitormatch() on the udp-endpoints also, but that
       * is done on a per-packet basis and that match is not saved any
       * longer than what it takes to attach, update the data-counters,
       * and detach.
       */
      newmatch = NULL;

#endif /* !HAVE_CONTROL_CONNECTION */
   }
   else
      newmatch = monitormatch(&io->src.host,
                              &io->dst.host,
                              &io->src.auth,
                              &io->state);

   if (newmatch == NULL) {
      if (oldrule->mstats_shmid == 0)
         is_same = 1;
      else
         is_same = 0;
   }
   else
      is_same = (oldrule->mstats_shmid == newmatch->mstats_shmid);

   slog(LOG_DEBUG,
        "%s: previously matched mstats_shmid %lu, now matching monitor "
        "#%lu with mstats_shmid %lu (%s)",
        function,
        (unsigned long)oldrule->mstats_shmid,
        newmatch == NULL ? 0 : (unsigned long)newmatch->number,
        newmatch == NULL ? 0 : (unsigned long)newmatch->mstats_shmid,
        is_same ? "same as now" : "different from before");

   if (oldrule->mstats_shmid == 0
   &&  (newmatch == NULL || newmatch->mstats_shmid == 0))
      return;

   cinfo.from = CONTROLIO(io)->raddr;
   HOSTIDCOPY(&io->state, &cinfo);

   if (newmatch == NULL) {
      if (oldrule->mstats_shmid != 0) {
         /*
          * Remove monitorstate belonging to old rule.
          */

         if (oldrule->alarmsconfigured & ALARM_DISCONNECT) {
            io_add_alarmdisconnects(io, function);

            /*
             * disconnecting because alarm no longer configured, so
             * don't confuse ourselves later by having this set to true.
             */
            CONTROLIO(io)->state.alarmdisconnectdone  = 0;
            EXTERNALIO(io)->state.alarmdisconnectdone = 0;
         }

         monitor_unuse(oldrule->mstats, &cinfo, sockscf.shmemfd);
      }
   }
   else {
      /*
       * Create monitorstate belonging to new rule.
       */
      monitor_t oldmonitor, newmonitor;
      rule_t newrule;

      SASSERTX(newmatch->mstats       == NULL);
      SASSERTX(newmatch->mstats_shmid != 0);

      if (is_same) {
         SASSERTX(oldrule->mstats_shmid == newmatch->mstats_shmid);
         SASSERTX(oldrule->mstats       != NULL);

         return;
      }

      /*
       * Else; matched monitor changed.  Can happen if a SIGHUP occurred.
       */

      /*
       * i/o process stays attached to monitor objects.
       */
      COPY_MONITORFIELDS(newmatch, &newrule);
      (void)sockd_shmat(&newrule, SHMEM_MONITOR);

      COPY_MONITORFIELDS(oldrule,  &oldmonitor);
      COPY_MONITORFIELDS(&newrule, &newmonitor);

      monitor_move(&oldmonitor,
                   &newmonitor,
                   disconnect_needed,
                   &cinfo,
                   sockscf.shmemfd);

      COPY_MONITORFIELDS(&newmonitor, oldrule);
   }

   if (newmatch == NULL)
      SHMEM_CLEAR(IORULE(io), SHMEM_MONITOR, 1);
}

void
io_add_alarmdisconnects(io, reason)
   sockd_io_t *io;
   const char *reason;
{
   const char *function = "io_add_alarmdisconnect()";
   clientinfo_t cinfo;
   rule_t *rule = IORULE(io);
   size_t sidestodisconnect;

   if (rule->mstats_shmid == 0
   || !(rule->alarmsconfigured & ALARM_DISCONNECT))
      return;

   DISCONNECT_NEEDED(io, &sidestodisconnect);

   if (sidestodisconnect == 0)
      return;

   /*
    * at least one disconnect to do.
    */

   cinfo.from = CONTROLIO(io)->raddr;
   HOSTIDCOPY(&io->state, &cinfo);

   alarm_add_disconnect(1,
                        rule,
                        sidestodisconnect,
                        &cinfo,
                        reason,
                        sockscf.shmemfd);

   if (sidestodisconnect & ALARM_INTERNAL)
      CONTROLIO(io)->state.alarmdisconnectdone  = 1;

   if (sidestodisconnect & ALARM_EXTERNAL)
      EXTERNALIO(io)->state.alarmdisconnectdone = 1;
}
