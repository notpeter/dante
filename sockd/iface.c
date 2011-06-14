/*
 * Copyright (c) 2010, 2011
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
"$Id: iface.c,v 1.11 2011/06/13 08:35:14 michaels Exp $";

#include "common.h"

#if !HAVE_SIOCGIFHWADDR
/*
 * Retrieve ifconfig(8) output for the interface "ifname".
 * The output is stored in "output", which is of size "outputlen".
 * Returns 0 on success, -1 on error.
 */
static int
get_ifconfig_output(const char *ifname, char *output, size_t outputlen);

/*
 * Parses the ifconfig output present in the string "output" for
 * the macaddress.  If found, the macaddress is stored in "addr", 
 * which must be at least ETHER_ADDR_LEN.
 * Returns 0 if the output was parsed ok, -1 on error.
 */
static int
parse_ifconfig_output(const char *input, unsigned char *addr);

#endif /* !HAVE_SIOCGIFHWADDR */

unsigned char *
socks_getmacaddr(ifname, addr)
   const char *ifname;
   unsigned char *addr;
{
   const char *function = "socks_getmacaddr()";

#if HAVE_SIOCGIFHWADDR
   struct ifreq ifr;
   int s;

   slog(LOG_DEBUG, "%s: HAVE_SIOCGIFHWADDR.  Ifname %s", function, ifname);

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

#else /* !HAVE_SIOCGIFHWADDR */
   char output[1024];

   slog(LOG_DEBUG, "%s: don't have HAVE_SIOCGIFHWADDR, so using ifconfig.  "
                   "Ifname %s",
                   function, ifname);

   if (get_ifconfig_output(ifname, output, sizeof(output)) != 0) {
      slog(LOG_DEBUG,
           "%s: could not retrieve ifconfig(8) output for interface %s",
           function, ifname);

      return NULL;
   }

   if (parse_ifconfig_output(output, addr) != 0) {
      slog(LOG_DEBUG, "%s: parsing ifconfig output for interface %s failed",
      function, ifname);

#if HAVE_SOLARIS_PRIVS
      if (sockscf.privileges.noprivs)
         swarnx("%s: parsing ifconfig output for interface %s failed.  "
                "Retrieving the hardware address requires the elevated "
                "privileges on Solaris.  Please make sure %s is started "
                "by root",
                function, ifname, PACKAGE);
#endif /* HAVE_SOLARIS_PRIVS */

      return NULL;
   }
#endif /* !SIOCGIFHWADDR */

   slog(LOG_DEBUG, "%s: mac address of interface %s is "
                   "%02x:%02x:%02x:%02x:%02x:%02x",
                   function, ifname,
                   addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

   return addr;
}

#if !HAVE_SIOCGIFHWADDR
static int
get_ifconfig_output(ifname, output, outputlen)
   const char *ifname;
   char *output;
   size_t outputlen;
{
   const char *function = "get_ifconfig_output()";
   FILE *fp;
   size_t i, rc;
   const char *ifconfig_paths[] = { "ifconfig",
                                    "/sbin/ifconfig",
                                    "/usr/sbin/ifconfig"
   };

   for (i = 0; i < ELEMENTS(ifconfig_paths); ++i) {
      char cmd[256];

      snprintf(cmd, sizeof(cmd), "%s %s 2>/dev/null",
      ifconfig_paths[i], ifname);

      slog(LOG_DEBUG, "%s: trying %s ... \n", function, cmd);

      /* at least on Solaris we need to be privileged to read the hw addr.  */
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
      fp = popen(cmd, "r");
      sockd_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);

      if (fp == NULL) {
         slog(LOG_DEBUG, "%s: popen(%s) failed: %s\n",
         function, cmd, strerror(errno));

         continue;
      }

      rc = fread(output, 1, outputlen - 1, fp);
      output[rc] = NUL;
      pclose(fp);

      if (rc == 0) {
         slog(LOG_DEBUG, "%s: popen(%s) failed: %s\n",
         function, cmd, strerror(errno));

         continue;
      }
      else
         break;
   }

   if (fp == NULL)
      return -1;

   return 0;
}

static int
parse_ifconfig_output(input, addr)
   const char *input;
   unsigned char *addr;
{
   const char *function = "parse_ifconfig_output()";
   regex_t preg;
   regmatch_t pmatch;
   size_t i, nextbyte;

   if (regcomp(&preg,
              "[[:space:]|^]"
              "[0-9a-fA-F]{1,2}:"
              "[0-9a-fA-F]{1,2}:"
              "[0-9a-fA-F]{1,2}:"
              "[0-9a-fA-F]{1,2}:"
              "[0-9a-fA-F]{1,2}:"
              "[0-9a-fA-F]{1,2}"
              "[[:space:]|$]",
              REG_EXTENDED) != 0)
      return -1;

   if (regexec(&preg, input, 1, &pmatch, 0) != 0)
      return -1;

   nextbyte = pmatch.rm_so;
   while (isspace(input[nextbyte]))
      ++nextbyte;

   for (i = 0; i < 6; ++i) {
      char *endptr;

      errno    = 0;
      addr[i]  = (unsigned char)strtol(&input[nextbyte], &endptr, 16);
      nextbyte += (endptr - &input[nextbyte]) + strlen(":");

      /* last byte will not have a ':' after it. */
      if (i != 5  && *endptr != ':') {
         swarnx("%s: missing ':' separator in string: %s\n", function, input);
         return -1;
      }

      if (errno == ERANGE) {
         swarn("%s: out of range in string: %s\n", function, input);
         return -1;
      }
   }

   return 0;
}

#endif /* !HAVE_SIOCGIFHWADDR */
