/* NOTICE: sockopt.c. Generated from sockopt.c.tpl by configure */
/*
 * Copyright (c) 2011, 2012
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

#include "qos.h"

static const char rcsid[] =
"$Id: sockopt_tpl.c,v 1.8 2012/04/14 01:00:39 karls Exp $";

struct option {
   int level;
   int optname;
   char *optstr;
};
static const struct option option[];
static const sockopt_t sockopts[];
static const sockoptvalsym_t sockoptvalsyms[];


int
socketoptdup(s)
   int s;
{
   const char *function = "socketoptdup()";
   unsigned int i;
   int flags, new_s, errno_s;
   socklen_t len;
   socketoptvalue_t val;

   errno_s = errno;

   len = sizeof(val);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) == -1) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return -1;
   }

   if ((new_s = socket(AF_INET, val.int_val, 0)) == -1) {
      swarn("%s: socket(AF_INET, %d)", function, val.int_val);
      return -1;
   }

   for (i = 0; i < HAVE_DUPSOCKOPT_MAX; ++i) {
      len = sizeof(val);
      if (getsockopt(s, option[i].level, option[i].optname, &val, &len) == -1) {
         if (errno != ENOPROTOOPT)
            slog(LOG_DEBUG, "%s: getsockopt(%d, %d) failed: %s",
            function, option[i].level, option[i].optname, strerror(errno));

         continue;
      }

      if (setsockopt(new_s, option[i].level, option[i].optname, &val, len) == -1)
         if (errno != ENOPROTOOPT)
            slog(LOG_DEBUG, "%s: setsockopt(%d, %d) failed: %s",
            function, option[i].level, option[i].optname, strerror(errno));
   }

   if ((flags = fcntl(s, F_GETFL, 0))          == -1
   ||           fcntl(new_s, F_SETFL, flags)   == -1)
      swarn("%s: fcntl(F_GETFL/F_SETFL)", function);

   errno = errno_s;
   return new_s;
}

#if DEBUG
void
printsocketopts(s)
   const int s;
{
   const char *function = "printsocketopts()";
   unsigned int i;
   int flags, errno_s;
   socklen_t len;
   socketoptvalue_t val;

   errno_s = errno;

   len = sizeof(val);
   if (getsockopt(s, SOL_SOCKET, SO_TYPE, &val, &len) == -1) {
      swarn("%s: getsockopt(SO_TYPE)", function);
      return;
   }

   for (i = 0; i < HAVE_DUPSOCKOPT_MAX; ++i) {
      len = sizeof(val);
      if (getsockopt(s, option[i].level, option[i].optname, &val, &len) == -1) {
         if (errno != ENOPROTOOPT)
            swarn("%s: getsockopt(%s) failed", function, option[i].optstr);
         continue;
      }

      slog(LOG_DEBUG, "%s: value of socket option \"%s\" is %d\n",
      function, option[i].optstr, val.int_val);
   }

   if ((flags = fcntl(s, F_GETFL, 0)) == -1)
      swarn("%s: fcntl(F_GETFL)", function);
   else
      slog(LOG_DEBUG, "%s: value of file status flags is %d\n",
      function, flags);

   if ((flags = fcntl(s, F_GETFD, 0)) == -1)
      swarn("fcntl(F_GETFD)");
   else
      slog(LOG_DEBUG, "%s: value of file descriptor flags is %d\n",
      function, flags);

   errno = errno_s;
}

#endif /* DEBUG */

void
sockopts_dump(void)
{
   const char *function = "sockops_dump()";
   int i;

   slog(LOG_DEBUG, "%s: showing generated socket option keywords:", function);
   slog(LOG_DEBUG, "%s: socket option names (%d entries):", function,
        HAVE_SOCKOPTVAL_MAX);
   for (i = 0; i < HAVE_SOCKOPTVAL_MAX; i++)
      slog(LOG_DEBUG, "%s: %2d: %s (%d/%d)", function, i, sockopts[i].name,
           sockopts[i].level, sockopts[i].value);

   slog(LOG_DEBUG, "%s: socket option value names (%d entries):", function,
        HAVE_SOCKOPTVALSYM_MAX);
   for (i = 0; i < HAVE_SOCKOPTVALSYM_MAX; i++) {
      const sockopt_t *opt;

      SASSERTX(sockoptvalsyms[i].optid < HAVE_SOCKOPTVAL_MAX);
      opt = &sockopts[sockoptvalsyms[i].optid];
      if (opt == NULL)
         serrx(EXIT_FAILURE, "socket option data invalid");
      slog(LOG_DEBUG, "%s: %2d: %s - %s - %s", function, i, opt->name,
           sockoptvalsyms[i].name,
           sockoptval2string(sockoptvalsyms[i].symval, opt->argtype, NULL, 0));
   }
}

const sockopt_t *
optname2sockopt(char *name)
{
   int i;

   for (i = 0; i < HAVE_SOCKOPTVAL_MAX; i++) {
      if (strcmp(name, sockopts[i].name) == 0)
         return &sockopts[i];
   }

   return NULL;
}

const sockopt_t *
optval2sockopt(int level, int value)
{
   int i;

   for (i = 0; i < HAVE_SOCKOPTVAL_MAX; i++) {
      if (level == sockopts[i].level && value == sockopts[i].value)
         return &sockopts[i];
   }

   return NULL;
}

const sockopt_t *
optid2sockopt(size_t optid)
{
   SASSERTX(optid < HAVE_SOCKOPTVAL_MAX);
   return &sockopts[optid];
}

const sockoptvalsym_t *
optval2valsym(size_t optid, char *name)
{
   int i;

   for (i = 0; i < HAVE_SOCKOPTVALSYM_MAX; i++) {
      if (optid == sockoptvalsyms[i].optid &&
          strcmp(name, sockoptvalsyms[i].name) == 0)
         return &sockoptvalsyms[i];
   }

   return NULL;
}

static const struct option option[] = {
   { SOL_SOCKET, SO_BROADCAST, "SO_BROADCAST" },
   { SOL_SOCKET, SO_DEBUG, "SO_DEBUG" },
   { SOL_SOCKET, SO_DONTROUTE, "SO_DONTROUTE" },
   { SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE" },
   { SOL_SOCKET, SO_LINGER, "SO_LINGER" },
   { SOL_SOCKET, SO_OOBINLINE, "SO_OOBINLINE" },
   { SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF" },
   { SOL_SOCKET, SO_RCVLOWAT, "SO_RCVLOWAT" },
   { SOL_SOCKET, SO_RCVTIMEO, "SO_RCVTIMEO" },
   { SOL_SOCKET, SO_SNDBUF, "SO_SNDBUF" },
   { SOL_SOCKET, SO_SNDLOWAT, "SO_SNDLOWAT" },
   { SOL_SOCKET, SO_SNDTIMEO, "SO_SNDTIMEO" },
   { SOL_SOCKET, SO_TIMESTAMP, "SO_TIMESTAMP" },
   { SOL_SOCKET, SO_USELOOPBACK, "SO_USELOOPBACK" },
   { IPPROTO_TCP, TCP_MAXSEG, "TCP_MAXSEG" },
   { IPPROTO_TCP, TCP_NODELAY, "TCP_NODELAY" },
   { IPPROTO_IP, IP_TOS, "IP_TOS" },
   { IPPROTO_IP, IP_TTL, "IP_TTL" },
   { SOL_SOCKET, SO_REUSEADDR, "SO_REUSEADDR" },
   { SOL_SOCKET, SO_REUSEPORT, "SO_REUSEPORT" },
   { IPPROTO_IP, IP_HDRINCL, "IP_HDRINCL" },
   { IPPROTO_IP, IP_MULTICAST_IF, "IP_MULTICAST_IF" },
   { IPPROTO_IP, IP_MULTICAST_LOOP, "IP_MULTICAST_LOOP" },
   { IPPROTO_IP, IP_MULTICAST_TTL, "IP_MULTICAST_TTL" },
   { IPPROTO_IP, IP_OPTIONS, "IP_OPTIONS" },
   { IPPROTO_IP, IP_RECVDSTADDR, "IP_RECVDSTADDR" },
   { IPPROTO_IP, IP_RECVIF, "IP_RECVIF" },
};

static const sockopt_t sockopts[] = {
   { 0, int_val, SO_BINDANY, SOCKS_SO_BINDANY_LVL, preonly, 0, 0, 0, 1, SOCKS_SO_BINDANY_NAME },
   { 1, int_val, SO_BROADCAST, SOCKS_SO_BROADCAST_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_BROADCAST_NAME },
   { 2, int_val, SO_DEBUG, SOCKS_SO_DEBUG_LVL, anytime, 0, 0, 0, 0, SOCKS_SO_DEBUG_NAME },
   { 3, int_val, SO_DONTROUTE, SOCKS_SO_DONTROUTE_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_DONTROUTE_NAME },
   { 4, int_val, SO_JUMBO, SOCKS_SO_JUMBO_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_JUMBO_NAME },
   { 5, int_val, SO_KEEPALIVE, SOCKS_SO_KEEPALIVE_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_KEEPALIVE_NAME },
   { 6, linger_val, SO_LINGER, SOCKS_SO_LINGER_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_LINGER_NAME },
   { 7, int_val, SO_OOBINLINE, SOCKS_SO_OOBINLINE_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_OOBINLINE_NAME },
   { 8, int_val, SO_RCVBUF, SOCKS_SO_RCVBUF_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_RCVBUF_NAME },
   { 9, int_val, SO_RCVLOWAT, SOCKS_SO_RCVLOWAT_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_RCVLOWAT_NAME },
   { 10, timeval_val, SO_RCVTIMEO, SOCKS_SO_RCVTIMEO_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_RCVTIMEO_NAME },
   { 11, int_val, SO_SNDBUF, SOCKS_SO_SNDBUF_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_SNDBUF_NAME },
   { 12, int_val, SO_SNDLOWAT, SOCKS_SO_SNDLOWAT_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_SNDLOWAT_NAME },
   { 13, timeval_val, SO_SNDTIMEO, SOCKS_SO_SNDTIMEO_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_SNDTIMEO_NAME },
   { 14, int_val, SO_TIMESTAMP, SOCKS_SO_TIMESTAMP_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_TIMESTAMP_NAME },
   { 15, int_val, SO_USELOOPBACK, SOCKS_SO_USELOOPBACK_LVL, preonly, 0, 0, 0, 0, SOCKS_SO_USELOOPBACK_NAME },
   { 16, int_val, TCP_MAXSEG, SOCKS_TCP_MAXSEG_LVL, preonly, 0, 0, 0, 0, SOCKS_TCP_MAXSEG_NAME },
   { 17, int_val, TCP_MD5SIG, SOCKS_TCP_MD5SIG_LVL, preonly, 0, 0, 0, 0, SOCKS_TCP_MD5SIG_NAME },
   { 18, int_val, TCP_NODELAY, SOCKS_TCP_NODELAY_LVL, preonly, 0, 0, 0, 0, SOCKS_TCP_NODELAY_NAME },
   { 19, int_val, TCP_SACK_ENABLE, SOCKS_TCP_SACK_ENABLE_LVL, preonly, 0, 0, 0, 0, SOCKS_TCP_SACK_ENABLE_NAME },
   { 20, int_val, IP_AUTH_LEVEL, SOCKS_IP_AUTH_LEVEL_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_AUTH_LEVEL_NAME },
   { 21, int_val, IP_ESP_NETWORK_LEVEL, SOCKS_IP_ESP_NETWORK_LEVEL_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_ESP_NETWORK_LEVEL_NAME },
   { 22, int_val, IP_ESP_TRANS_LEVEL, SOCKS_IP_ESP_TRANS_LEVEL_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_ESP_TRANS_LEVEL_NAME },
   { 23, int_val, IP_IPCOMP_LEVEL, SOCKS_IP_IPCOMP_LEVEL_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_IPCOMP_LEVEL_NAME },
   { 24, int_val, IP_MINTTL, SOCKS_IP_MINTTL_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_MINTTL_NAME },
   { 25, int_val, IP_PORTRANGE, SOCKS_IP_PORTRANGE_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_PORTRANGE_NAME },
   { 26, int_val, IP_TOS, SOCKS_IP_TOS_LVL, anytime, 0, 0, 0, 0, SOCKS_IP_TOS_NAME },
   { 27, int_val, IP_TOS, SOCKS_IP_TOS_LVL, anytime, 2, 0x3F, 0, 0, SOCKS_IP_TOS_DSCP_NAME },
   { 28, int_val, IP_TOS, SOCKS_IP_TOS_LVL, anytime, 5, 0x7, 0, 0, SOCKS_IP_TOS_PREC_NAME },
   { 29, int_val, IP_TOS, SOCKS_IP_TOS_LVL, anytime, 1, 0xf, 0, 0, SOCKS_IP_TOS_TOS_NAME },
   { 30, int_val, IP_TTL, SOCKS_IP_TTL_LVL, preonly, 0, 0, 0, 0, SOCKS_IP_TTL_NAME },
   { 31, int_val, SO_REUSEADDR, SOCKS_SO_REUSEADDR_LVL, invalid, 0, 0, 0, 0, SOCKS_SO_REUSEADDR_NAME },
   { 32, int_val, SO_REUSEPORT, SOCKS_SO_REUSEPORT_LVL, invalid, 0, 0, 0, 0, SOCKS_SO_REUSEPORT_NAME },
   { 33, int_val, IP_HDRINCL, SOCKS_IP_HDRINCL_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_HDRINCL_NAME },
   { 34, int_val, IP_MULTICAST_IF, SOCKS_IP_MULTICAST_IF_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_MULTICAST_IF_NAME },
   { 35, int_val, IP_MULTICAST_LOOP, SOCKS_IP_MULTICAST_LOOP_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_MULTICAST_LOOP_NAME },
   { 36, int_val, IP_MULTICAST_TTL, SOCKS_IP_MULTICAST_TTL_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_MULTICAST_TTL_NAME },
   { 37, int_val, IP_OPTIONS, SOCKS_IP_OPTIONS_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_OPTIONS_NAME },
   { 38, int_val, IP_RECVDSTADDR, SOCKS_IP_RECVDSTADDR_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_RECVDSTADDR_NAME },
   { 39, int_val, IP_RECVIF, SOCKS_IP_RECVIF_LVL, invalid, 0, 0, 0, 0, SOCKS_IP_RECVIF_NAME },
};

static const sockoptvalsym_t sockoptvalsyms[] = {
   { 25, { .int_val = IP_PORTRANGE_DEFAULT }, SOCKS_IP_PORTRANGE_DEFAULT_SYMNAME },
   { 25, { .int_val = IP_PORTRANGE_HIGH }, SOCKS_IP_PORTRANGE_HIGH_SYMNAME },
   { 25, { .int_val = IP_PORTRANGE_LOW }, SOCKS_IP_PORTRANGE_LOW_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF11 }, SOCKS_IP_TOS_DSCP_AF11_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF12 }, SOCKS_IP_TOS_DSCP_AF12_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF13 }, SOCKS_IP_TOS_DSCP_AF13_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF21 }, SOCKS_IP_TOS_DSCP_AF21_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF22 }, SOCKS_IP_TOS_DSCP_AF22_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF23 }, SOCKS_IP_TOS_DSCP_AF23_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF31 }, SOCKS_IP_TOS_DSCP_AF31_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF32 }, SOCKS_IP_TOS_DSCP_AF32_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF33 }, SOCKS_IP_TOS_DSCP_AF33_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF41 }, SOCKS_IP_TOS_DSCP_AF41_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF42 }, SOCKS_IP_TOS_DSCP_AF42_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_AF43 }, SOCKS_IP_TOS_DSCP_AF43_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS0 }, SOCKS_IP_TOS_DSCP_CS0_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS1 }, SOCKS_IP_TOS_DSCP_CS1_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS2 }, SOCKS_IP_TOS_DSCP_CS2_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS3 }, SOCKS_IP_TOS_DSCP_CS3_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS4 }, SOCKS_IP_TOS_DSCP_CS4_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS5 }, SOCKS_IP_TOS_DSCP_CS5_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS6 }, SOCKS_IP_TOS_DSCP_CS6_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_CS7 }, SOCKS_IP_TOS_DSCP_CS7_SYMNAME },
   { 27, { .int_val = SOCKS_IP_TOS_DSCP_EF }, SOCKS_IP_TOS_DSCP_EF_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_NETCONTROL }, SOCKS_IP_TOS_PREC_NETCONTROL_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_INTERNETCONTROL }, SOCKS_IP_TOS_PREC_INTERNETCONTROL_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_CRITIC_ECP }, SOCKS_IP_TOS_PREC_CRITIC_ECP_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_FLASHOVERRIDE }, SOCKS_IP_TOS_PREC_FLASHOVERRIDE_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_FLASH }, SOCKS_IP_TOS_PREC_FLASH_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_IMMEDIATE }, SOCKS_IP_TOS_PREC_IMMEDIATE_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_PRIORITY }, SOCKS_IP_TOS_PREC_PRIORITY_SYMNAME },
   { 28, { .int_val = SOCKS_IP_TOS_PREC_ROUTINE }, SOCKS_IP_TOS_PREC_ROUTINE_SYMNAME },
   { 29, { .int_val = SOCKS_IP_TOS_TOS_LOWDELAY }, SOCKS_IP_TOS_TOS_LOWDELAY_SYMNAME },
   { 29, { .int_val = SOCKS_IP_TOS_TOS_THROUGHPUT }, SOCKS_IP_TOS_TOS_THROUGHPUT_SYMNAME },
   { 29, { .int_val = SOCKS_IP_TOS_TOS_RELIABILITY }, SOCKS_IP_TOS_TOS_RELIABILITY_SYMNAME },
};
