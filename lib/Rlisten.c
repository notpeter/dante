/*
 * Copyright (c) 2008
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
"$Id: Rlisten.c,v 1.17 2008/07/25 08:48:55 michaels Exp $";

int
Rlisten(s, backlog)
   int s;
   int backlog;
{
   const char *function = "Rlisten()";
   const struct socksfd_t *socksfd;

   clientinit();

   slog(LOG_DEBUG, "%s, s = %d", function, s);

   if (!socks_addrisok((unsigned int)s, 0))
      return listen(s, backlog);

   socksfd = socks_getaddr((unsigned int)s, 0);
   if (socksfd->state.command != SOCKS_BIND) {
      swarnx("%s: doing listen on socket, but commandstate is %d",
      function, socksfd->state.command);
      socks_rmaddr(s, 0);

      return listen(s, backlog);
   }

   /*
    * find out if it's bound using the bind extension or not.
    * If it's using the bind extension, we do a standard listen(2), if
    * not, we need to drop the listen(2), as doing listen(2) on a socket
    * we have previously done connect(2) on (for connect to the socks 
    * server) does not necessarily work so well on all (any?) systems.
    */
   if (socksfd->state.acceptpending)
      return listen(s, backlog);
   return 0;
}
