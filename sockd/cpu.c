/*
 * Copyright (c) 2012
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
"$Id: cpu.c,v 1.12 2012/05/21 21:39:17 karls Exp $";

void
sockd_setcpusettings(cpu)
   const cpusetting_t *cpu;
{
#if HAVE_SCHED_SETSCHEDULER || HAVE_SCHED_SETAFFINITY
   const char *function = "sockd_setcpusettings()";
   int rc;

#if HAVE_SCHED_SETSCHEDULER
   if (cpu->scheduling_isset
    &&  (sockscf.state.cpu.policy != cpu->policy
      || sockscf.state.cpu.param.sched_priority  != cpu->param.sched_priority)){
      slog(LOG_DEBUG, "%s: setting cpu scheduling policy/priority to %s/%d",
           function, numeric2cpupolicy(cpu->policy), cpu->param.sched_priority);

      SASSERTX(sockscf.state.cpu.scheduling_isset);

      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
      rc = sched_setscheduler(0, cpu->policy, &cpu->param);
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);

      if (rc == 0) {
         sockscf.state.cpu.policy = cpu->policy;
         sockscf.state.cpu.param  = cpu->param;
      }
      else
         swarn("%s: failed to set cpu scheduling policy/priority to %s/%d",
               function,
               numeric2cpupolicy(cpu->policy),
               cpu->param.sched_priority);
   }
#endif /* HAVE_SCHED_SETSCHEDULER */

#if HAVE_SCHED_SETAFFINITY
   if (cpu->affinity_isset && !cpu_equal(&sockscf.state.cpu.mask, &cpu->mask)) {
      SASSERTX(sockscf.state.cpu.affinity_isset);

      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
      rc = cpu_setaffinity(0, sizeof(cpu->mask), &cpu->mask);
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);

      if (rc == 0)
         sockscf.state.cpu.mask = cpu->mask;
      else {
         size_t i;
         size_t errcpus_used  = 0;
         const size_t setsize = cpu_get_setsize();
         const long cpus      = sysconf(_SC_NPROCESSORS_ONLN);
         char errcpus[2048]   = { NUL };

         if (cpus == -1)
            serr(EXIT_FAILURE, "sysconf(_SC_NPROCESSORS_ONLN) failed");

         for (i = 0; i < setsize; ++i)
            if (cpu_isset(i, &cpu->mask) && i + 1 > (size_t)cpus)
               errcpus_used += snprintf(&errcpus[errcpus_used],
                                        sizeof(errcpus) - errcpus_used,
                                        "%ld ",
                                        (long)i);

         if (*errcpus != NUL)
            serr(EXIT_FAILURE, "%s: failed to set cpu affinity.  Probably "
                               "because the configured cpu mask contains the "
                               "following cpus which do not appear to be "
                               "present on this system (which has a total of "
                               "%ld cpus): %s",
                               function, cpus, errcpus);

         serr(EXIT_FAILURE, "%s: failed to set cpu affinity using mask %s",
                             function, cpuset2string(&cpu->mask, NULL, 0));
      }
   }
#endif /* HAVE_SCHED_SETAFFINITY */
#endif /* HAVE_SCHED_SETSCHEDULER || HAVE_SCHED_SETAFFINITY */

#if HAVE_PROCESSOR_BIND
#endif /* HAVE_PROCESSOR_BIND */

}
