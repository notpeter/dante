/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003
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
"$Id: address.c,v 1.102 2008/12/11 14:11:01 karls Exp $";

__BEGIN_DECLS

#define SOCKS_ADDRLOCKFILE "./socksaddrlockXXXXXXXXXX"

/* fake "ip address", for clients without DNS access. */
static char **ipv;
static in_addr_t ipc;

static struct socksfd_t socksfdinit;
static int *dv;
static unsigned int dc;
static struct socksfd_t *socksfdv;
static unsigned int socksfdc;
static int mutex = -1; /* lock for socksfdv. */

static void
socks_sigblock __P((void));
/*
 * Blocks signals that can change socksfdv.
 */

static void
socks_sigunblock __P((void));
/*
 * Unblocks signals that can change socksfdv.
 */


static int
socks_addfd __P((unsigned int d));
/*
 * adds the filedescriptor "fd" to an internal table.
 * If it is already in the table the  request is ignored.
 * Returns:
 *    On success: 0
 *    On failure: -1
 */

static int
socks_isfd __P((unsigned int fd));
/*
 * returns 1 if "fd" is a filedescriptor in our internal table, 0 if not.
 */

static void
socks_rmfd __P((unsigned int fd));
/*
 * removes the filedescriptor "fd" from our internal table.
 */


static void
mutexinit __P((void));
/* 
 * Initializes mutex stuff for *addr() functions.
 */

static struct socksfd_t *
socksfddup __P((const struct socksfd_t *old, struct socksfd_t *new));
/*
 * Duplicates "old", in "new".
 * Returns:
 *    On success: "new".
 *    On failure: NULL (resource shortage).
 */
 
__END_DECLS

const struct socksfd_t *
socks_addaddr(clientfd, socksfd, havelock)
   const unsigned int clientfd;
   const int havelock;
   const struct socksfd_t *socksfd;
{
   const char *function = "socks_addaddr()";

#if 0 /* DEBUG */
   if (socksfd->state.command != -1 && !socksfd->state.system)
      slog(LOG_DEBUG, "%s: %d", function, clientfd);
#endif

   SASSERTX(socksfd->state.command      == -1
   ||    socksfd->state.command            == SOCKS_BIND
   ||    socksfd->state.command            == SOCKS_CONNECT
   ||    socksfd->state.command            == SOCKS_UDPASSOCIATE);

   if (!havelock)
      socks_addrlock(F_WRLCK);

   if (socks_addfd(clientfd) != 0)
      serrx(EXIT_FAILURE, "%s: error adding descriptor %d", function, clientfd);

   if (socksfdc < dc) { /* init/reallocate */
      if (socksfdinit.control == 0) {   /* not initialized */
         socksfdinit.control = -1;
         /* other members have ok default value. */
      }

      if ((socksfdv = realloc(socksfdv, sizeof(*socksfdv) * dc)) == NULL)
         serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);

      /* init new objects */
      while (socksfdc < dc)
         socksfdv[socksfdc++] = socksfdinit;
   }

   socksfdv[clientfd]           = *socksfd;
   socksfdv[clientfd].allocated = 1;

   if (!havelock)
      socks_addrunlock();

   return &socksfdv[clientfd];
}


const struct socksfd_t *
socks_getaddr(d, havelock)
   const unsigned int d;
   const int havelock;
{
   const struct socksfd_t *sfd;

   if (!havelock)
      socks_addrlock(F_RDLCK);

   if (socks_isaddr(d, 1))
      sfd = &socksfdv[d];
   else
      sfd = NULL;
   
   if (!havelock)
      socks_addrunlock();

   return sfd;
}

void
socks_rmaddr(d, havelock)
   const unsigned int d;
   const int havelock;
{
/*   const char *function = "socks_rmaddr()";   */

   if (!havelock)
      socks_addrlock(F_WRLCK);

   if (!socks_isaddr(d, 1)) {
      if (!havelock) /* we must have locked, so unlock before returning. */
         socks_addrunlock(); 

      return; /* not a socket of ours. */
   }

   socks_rmfd(d);

   switch (socksfdv[d].state.version) {
      case PROXY_MSPROXY_V2:
         if (socksfdv[d].control != -1)
            close(socksfdv[d].control);
         break;

      case PROXY_SOCKS_V4:
      case PROXY_SOCKS_V5:
         if (!socksfdv[d].state.issyscall)
            switch (socksfdv[d].state.command) {
               case SOCKS_BIND:
                  if (socksfdv[d].control == -1
                  ||  socksfdv[d].control == (int)d)
                     break;

                  /*
                   * If we are using the bind extension it's possible
                   * that this controlconnection is shared with other
                   * (accept()'ed) addresses, if so we must leave it
                   * open for the other connections.
                  */
                  if (socks_addrcontrol(&socksfdv[d].local,
                  &socksfdv[d].remote, 1)
                  == -1)
                     break;

                  close(socksfdv[d].control);
                  break;

               case SOCKS_CONNECT:
                  break; /* no separate controlconnection. */

               case SOCKS_UDPASSOCIATE:
                  if (socksfdv[d].control != -1)
                     close(socksfdv[d].control);
                  break;

               default:
                  SERRX(socksfdv[d].state.command);
            }
   }

   socksfdv[d] = socksfdinit;

   if (!havelock)
      socks_addrunlock();
}

int
socks_isaddr(d, havelock)
   const unsigned int d;
   const int havelock;
{
   int rc;

   if (d >= socksfdc)
      return 0;

   if (!havelock)
      socks_addrlock(F_WRLCK);

   rc = socksfdv[d].allocated;

   if (!havelock)
      socks_addrunlock();
   
   return rc;
}

int
socks_addrisok(s, havelock)
   const unsigned int s;
   const int havelock;
{
   const char *function = "socks_addrisok()";
   const int errno_s = errno;
   int matched;

   if (!havelock)
      socks_addrlock(F_RDLCK);

   matched = 0;
   do {
      const struct socksfd_t *socksfd;
      struct sockaddr local;
      socklen_t locallen;

      locallen = sizeof(local);
      if (getsockname((int)s, &local, &locallen) != 0)
         break;

      socksfd = socks_getaddr(s, 1);

      if (socksfd != NULL) {
         if (TOCIN(&socksfd->local)->sin_addr.s_addr == htonl(0)) {
            /*
             * if address was not bound before, it might have become
             * later, after client did a send(2) or similar.
             */
            struct socksfd_t nsocksfd;
            
            nsocksfd = *socksfd;
            TOIN(&nsocksfd.local)->sin_addr = TOIN(&local)->sin_addr;
            socksfd = socks_addaddr(s, &nsocksfd, 1);
         }   
            
         if (!sockaddrareeq(&local, &socksfd->local))
            break;

         /* check remote endpoint too? */

         matched = 1;
      }
      else { /* unknown descriptor.  Try to check whether it's a dup. */
         int duped;

         if ((duped = socks_addrmatch(&local, NULL, NULL, 1)) != -1) {
            struct socksfd_t nsocksfd;

            socksfd = socksfddup(socks_getaddr((unsigned int)duped, 1),
            &nsocksfd);

            if (socksfd == NULL) {
               swarn("%s: socksfddup()", function);
               break;
            }

            socks_addaddr(s, socksfd, 1);
            matched = 1;
         }
         break;
      }
   /* CONSTCOND */
   } while (0);

   if (!havelock)
      socks_addrunlock();

   errno = errno_s;
   return matched;
}

int
socks_addrcontrol(local, remote, havelock)
   const struct sockaddr *local;
   const struct sockaddr *remote;
   const int havelock;
{
   unsigned int i;

   if (!havelock)
      socks_addrlock(F_RDLCK);

   for (i = 0; i < socksfdc; ++i) {
      struct sockaddr localcontrol, remotecontrol;

      if (!socks_isaddr((unsigned int)i, 1))
         continue;

      if (local != NULL) {
         socklen_t len = sizeof(localcontrol);
         if (getsockname(socksfdv[i].control, &localcontrol, &len) != 0)
            continue;

         if (!sockaddrareeq(local, &localcontrol))
            continue;
      }

      if (remote != NULL) {
         socklen_t len = sizeof(remotecontrol);
         if (getpeername(socksfdv[i].control, &remotecontrol, &len) != 0)
            continue;

         if (!sockaddrareeq(remote, &remotecontrol))
            continue;
      }

      break;
   }

   if (!havelock)
      socks_addrunlock();

   if (i < socksfdc)
      return i;
   return -1;
}

int
socks_addrmatch(local, remote, state, havelock)
   const struct sockaddr *local;
   const struct sockaddr *remote;
   const struct socksstate_t *state;
   const int havelock;
{
   unsigned int i;

   if (!havelock)
      socks_addrlock(F_RDLCK);

   for (i = 0; i < socksfdc; ++i) {
      if (!socks_isaddr(i, 1))
         continue;

      /*
       * only compare fields that have a valid value in request to compare
       * against.
       */

      if (local != NULL)
         if (!sockaddrareeq(local, &socksfdv[i].local))
            continue;

      if (remote != NULL)
         if (!sockaddrareeq(remote, &socksfdv[i].remote))
            continue;

      if (state != NULL) {
         if (state->version != -1)
            if (state->version != socksfdv[i].state.version)
               continue;

         if (state->command != -1)
            if (state->command != socksfdv[i].state.command)
               continue;

         if (state->inprogress != -1)
            if (state->inprogress != socksfdv[i].state.inprogress)
               continue;

         if (state->acceptpending != -1)
            if (state->acceptpending != socksfdv[i].state.acceptpending)
               continue;
      }

      break;
   }

   if (!havelock)
      socks_addrunlock();

   if (i < socksfdc)
      return i;
   return -1;
}


static int
socks_addfd(d)
   unsigned int d;
{
   const char *function = "socks_addfd()";

   if (d + 1 < d) /* integer overflow. */
      return -1;

   if (d >= dc) { /* init/reallocate */
      int *newfdv;
      unsigned int newfdc;

      newfdc = MAX(d + 1, (unsigned int)getdtablesize());
      if ((newfdv = realloc(dv, sizeof(*dv) * newfdc)) == NULL)
         serrx(EXIT_FAILURE, "%s: %s", function, NOMEM);
      dv = newfdv;

      /* init all to -1, a illegal value for a descriptor. */
      while (dc < newfdc)
         dv[dc++] = -1;
   }

   dv[d] = d;

   return 0;
}

static int
socks_isfd(d)
   unsigned int d;
{
   if (d >= dc || dv[d] == -1)
      return 0;
   return 1;
}

static void
socks_rmfd(d)
   unsigned int d;
{
   if (socks_isfd(d))
      dv[d] = -1;
}

static struct socksfd_t *
socksfddup(old, new)
   const struct socksfd_t *old;
   struct socksfd_t *new;
{

   *new = *old;   /* init most stuff. */

   switch (old->state.command) {
      case SOCKS_BIND:
      case SOCKS_UDPASSOCIATE:
         if ((new->control = socketoptdup(old->control)) == -1)
            return NULL;
         break;

      case SOCKS_CONNECT:
         /* only descriptor for connect is the one client has. */
         break;

      default:
         break;
   }

   return new;
}

static void
socks_sigblock(void)
{
   const char *function = "socks_sigblock()";
   sigset_t newmask;

   /*
    * block signals that might change socksfd.
    */

   (void)sigemptyset(&newmask);
   (void)sigaddset(&newmask, SIGIO);
   (void)sigaddset(&newmask, SIGCHLD);
   if (sigprocmask(SIG_BLOCK, &newmask, NULL) != 0)
      swarn("%s: sigprocmask()", function);
}

static void
socks_sigunblock(void)
{
   const char *function = "socks_sigunblock()";
   sigset_t newmask;

   /*
    * unblock signals that we blocked.
    */

   (void)sigemptyset(&newmask);
   (void)sigaddset(&newmask, SIGIO);
   (void)sigaddset(&newmask, SIGCHLD);
   if (sigprocmask(SIG_UNBLOCK, &newmask, NULL) != 0)
      swarn("%s: sigprocmask()", function);
}

void
socks_addrlock(locktype)
   const int locktype;
{

   socks_sigblock();

   mutexinit();
   if (mutex != -1)
      socks_lock(mutex, locktype, -1);
};

void
socks_addrunlock(void)
{
   if (mutex != -1)
      socks_unlock(mutex);
   socks_sigunblock();
};


in_addr_t
socks_addfakeip(host)
   const char *host;
{
   const char *function = "socks_addfakeip()";
   char **tmpmem;
   struct in_addr addr;

   socks_addrlock(F_WRLCK);

   if (socks_getfakeip(host, &addr) == 1) {
      socks_addrunlock();
      return addr.s_addr;
   }

#if FAKEIP_END < FAKEIP_START
error "\"FAKEIP_END\" can't be smaller than \"FAKEIP_START\""
#endif

   if (ipc >= FAKEIP_END - FAKEIP_START) {
      swarnx("%s: fakeip range (%d - %d) exhausted",
      function, FAKEIP_START, FAKEIP_END);

      socks_addrunlock();
      return INADDR_NONE;
   }

   if ((tmpmem = realloc(ipv, sizeof(*ipv) * (ipc + 1))) == NULL
   || (tmpmem[ipc] = malloc(sizeof(*tmpmem) * (strlen(host) + 1)))
   == NULL) {
      if (tmpmem != NULL)
         free(tmpmem);

      swarnx("%s: %s", function, NOMEM);

      socks_addrunlock();
      return INADDR_NONE;
   }
   ipv = tmpmem;

   strcpy(ipv[ipc], host);

   socks_addrunlock();
   return htonl(ipc++ + FAKEIP_START);
}

const char *
socks_getfakehost(addr)
   in_addr_t addr;
{
   const char *host;

   socks_addrlock(F_RDLCK);

   if (ntohl(addr) - FAKEIP_START < ipc)
      host = ipv[ntohl(addr) - FAKEIP_START];
   else
      host = NULL;

   socks_addrunlock();
   return host;
}

int
socks_getfakeip(host, addr)
   const char *host;
   struct in_addr *addr;
{
   unsigned int i;

   socks_addrlock(F_RDLCK);

   for (i = 0; i < ipc; ++i)
      if (strcasecmp(host, ipv[i]) == 0) {
         addr->s_addr = htonl(i + FAKEIP_START);
         break;
      }

   socks_addrunlock();

   if (i < ipc)
      return i;
   return 0;
}

struct sockshost_t *
fakesockaddr2sockshost(addr, host)
   const struct sockaddr *addr;
   struct sockshost_t *host;
{
   const char *function = "fakesockaddr2sockshost()";
   char string[MAXSOCKADDRSTRING];

#if SOCKS_CLIENT /* may be called before normal init, log to right place. */
   clientinit();
#endif /* SOCKS_CLIENT */

   /* LINTED pointer casts may be troublesome */
   slog(LOG_DEBUG, "%s: %s -> %s",
   function, sockaddr2string(addr, string, sizeof(string)),
   socks_getfakehost(TOCIN(addr)->sin_addr.s_addr) == NULL ?
   string : socks_getfakehost(TOCIN(addr)->sin_addr.s_addr));

   /* LINTED pointer casts may be troublesome */
   if (socks_getfakehost(TOCIN(addr)->sin_addr.s_addr) != NULL) {
      /* LINTED pointer casts may be troublesome */
      const char *ipname = socks_getfakehost(TOCIN(addr)->sin_addr.s_addr);

      SASSERTX(ipname != NULL);

      host->atype = SOCKS_ADDR_DOMAIN;
      SASSERTX(strlen(ipname) < sizeof(host->addr.domain));
      strcpy(host->addr.domain, ipname);
      /* LINTED pointer casts may be troublesome */
      host->port   = TOCIN(addr)->sin_port;
   }
   else
      sockaddr2sockshost(addr, host);

   return host;
}

struct sockaddr *
fakesockshost2sockaddr(host, addr)
   const struct sockshost_t *host;
   struct sockaddr *addr;
{
   const char *function = "fakesockshost2sockaddr()";
   char string[MAXSOCKSHOSTSTRING];
   uint8_t sa_length;

#if SOCKS_CLIENT /* may be called before normal init, log to right place. */
   clientinit();
#endif /* SOCKS_CLIENT */

   slog(LOG_DEBUG, "%s: %s",
   function, sockshost2string(host, string, sizeof(string)));

   bzero(addr, sizeof(*addr));

   switch (host->atype) {
      case SOCKS_ADDR_DOMAIN:
         addr->sa_family = AF_INET;
         sa_length = sizeof(struct sockaddr_in);

         /* LINTED pointer casts may be troublesome */
         if (socks_getfakeip(host->addr.domain, &TOIN(addr)->sin_addr))
            break;
         /* else; */ /* FALLTHROUGH */

      default:
         return sockshost2sockaddr(host, addr);
   }

#if HAVE_SOCKADDR_SA_LEN
   addr->sa_len = sa_length;
#endif /* HAVE_SOCKADDR_SA_LEN */

   /* LINTED pointer casts may be troublesome */
   TOIN(addr)->sin_port = host->port;

   return addr;
}


static void
mutexinit(void)
{
#ifdef HAVE_VOLATILE_SIG_ATOMIC_T
   static sig_atomic_t initing;
#else
   static volatile sig_atomic_t initing;
#endif
   const char *function = "mutexinit()";

   if (initing)
      return; /* already initing, avoid recursion. */

   if (mutex == -1 || !fdisopen(mutex)) {
      initing = 1;

      if ((mutex = socks_mklock(SOCKS_ADDRLOCKFILE)) == -1) 
         swarn("%s: could not create address mutex", function);

      initing = 0; 
   }
}

