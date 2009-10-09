/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2008, 2009
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

#include "interposition.h"

#define __USE_GNU /* XXX for RTLD_NEXT on Linux */
#include <dlfcn.h>

static const char rcsid[] =
"$Id: address.c,v 1.163 2009/10/09 07:28:46 michaels Exp $";

/* fake "ip address", for clients without DNS access. */
static char **ipv;
static in_addr_t ipc;

static struct socksfd_t socksfdinit;
static int *dv;
static size_t dc;
static struct socksfd_t *socksfdv;
static size_t socksfdc;

#if HAVE_PTHREAD_H
static pthread_mutex_t addrmutex;

static int socks_pthread_mutex_init(pthread_mutex_t *mutex,
                                    const pthread_mutexattr_t *attr);
static int socks_pthread_mutexattr_init(pthread_mutexattr_t *attr);
static int socks_pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
static int socks_pthread_mutex_lock(pthread_mutex_t *mutex);
static int socks_pthread_mutex_unlock(pthread_mutex_t *mutex);

typedef int (*PT_INIT_FUNC_T)(pthread_mutex_t *mutex,
                                     const pthread_mutexattr_t *attr);
static PT_INIT_FUNC_T pt_init;

typedef int (*PT_ATTRINIT_FUNC_T)(pthread_mutexattr_t *attr);
static PT_ATTRINIT_FUNC_T pt_attrinit;

typedef int (*PT_SETTYPE_FUNC_T)(pthread_mutexattr_t *attr, int type);
static PT_SETTYPE_FUNC_T pt_settype;

typedef int (*PT_LOCK_FUNC_T)(pthread_mutex_t *mutex);
static PT_LOCK_FUNC_T pt_lock;

typedef int (*PT_UNLOCK_FUNC_T)(pthread_mutex_t *mutex);
static PT_LOCK_FUNC_T pt_unlock;

typedef pthread_t (*PT_SELF_FUNC_T)(void);
static PT_SELF_FUNC_T pt_self;
#endif /* HAVE_PTHREAD_H */

static void
socks_sigblock(sigset_t *oldset);
/*
 * Blocks signals that can change socksfdv.
 */

static void
socks_sigunblock(const sigset_t *oldset);
/*
 * Unblocks signals that can change socksfdv.
 */

static int
socks_addfd(const int d);
/*
 * adds the file descriptor "fd" to an internal table.
 * If it is already in the table the  request is ignored.
 * Returns:
 *    On success: 0
 *    On failure: -1
 */

static int
socks_isfd(const int fd);
/*
 * returns 1 if "fd" is a file descriptor in our internal table, 0 if not.
 */

static void
socks_rmfd(const int fd);
/*
 * removes the file descriptor "fd" from our internal table.
 */

struct socksfd_t *
socks_addaddr(clientfd, socksfd, takelock)
   const int clientfd;
   const struct socksfd_t *socksfd;
   const int takelock;
{
   const char *function = "socks_addaddr()";
   addrlockopaque_t opaque;

#if 0 /* DEBUG */
   if (socksfd->state.command != -1 && !socksfd->state.system)
      slog(LOG_DEBUG, "%s: %d", function, clientfd);
#endif

   SASSERTX(socksfd->state.command == -1
   ||       socksfd->state.command == SOCKS_BIND
   ||       socksfd->state.command == SOCKS_CONNECT
   ||       socksfd->state.command == SOCKS_UDPASSOCIATE);

   if (takelock)
      socks_addrlock(F_WRLCK, &opaque);

   if (socks_addfd(clientfd) != 0)
      serrx(EXIT_FAILURE, "%s: error adding descriptor %d", function, clientfd);

   if (socksfdc < dc) { /* init/reallocate */
      if (socksfdinit.control == 0) { /* not initialized */
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

   if (takelock)
      socks_addrunlock(&opaque);

#ifdef THREAD_DEBUG
   if (sockscf.log.fpv != NULL) {
      char buf[80];

      snprintf(buf, sizeof(buf),
      "%s: allocating fd %d for command %d\n",
      function, clientfd, socksfdv[clientfd].state.command);

      syssys_write(fileno(sockscf.log.fpv[0]), buf, strlen(buf) + 1);
   }
#endif

   if (socksfd->state.auth.method == AUTHMETHOD_GSSAPI)
      sockscf.state.havegssapisockets = 1;

   return &socksfdv[clientfd];
}

struct socksfd_t *
socks_getaddr(d, takelock)
   const int d;
   const int takelock;
{
   const char *function = "socks_getaddr()";
   addrlockopaque_t opaque;
   struct socksfd_t *sfd;

   if (takelock)
      socks_addrlock(F_RDLCK, &opaque);

   if (socks_isaddr(d, 0)) {
      sfd = &socksfdv[d];

#if HAVE_GSSAPI
      if (sfd->state.gssimportneeded && !sockscf.state.insignal) { 
         iobuffer_t *iobuf;

         iobuf = socks_getbuffer(d);
         SASSERTX(iobuf != NULL);

         /* iobuf->buf can change due to realloc(3), so make sure to update. */
         sfd->state.gssapistate.value = iobuf->buf;

         slog(LOG_DEBUG, "%s: importing gssapistate for socket %d",
         function, d);

         if (gssapi_import_state(&sfd->state.auth.mdata.gssapi.state.id,
         &sfd->state.gssapistate) != 0)
            swarnx("%s: failed to import gssapi context of length %lu",
            function, (unsigned long)sfd->state.gssapistate.length);

         sfd->state.gssimportneeded = 0;
      }
#endif
   }
   else
      sfd = NULL;

   if (takelock)
      socks_addrunlock(&opaque);


   return sfd;
}

void
socks_rmaddr(d, takelock)
   const int d;
   const int takelock;
{
/*   const char *function = "socks_rmaddr()";    */
   addrlockopaque_t opaque;

   if (d < 0 || (size_t)d >= socksfdc)
      return; /* not a socket of ours. */

   if (takelock)
      socks_addrlock(F_WRLCK, &opaque);

   socks_rmfd(d);
   if (!socksfdv[d].state.issyscall) /* syscall adds/removes all the time. */
      socks_freebuffer(d);

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
                  ||  socksfdv[d].control == d)
                     break;

                  /*
                   * If we are using the bind extension it's possible
                   * that this controlconnection is shared with other
                   * (accept()'ed) addresses, if so we must leave it
                   * open for the other connections.
                  */
                  if (socks_addrcontrol(&socksfdv[d].local,
                  &socksfdv[d].remote, -1, -1, -1, 0)
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
         break;

      case PROXY_UPNP:
         upnpcleanup(d);
         break;
   }

#ifdef THREAD_DEBUG
   if (sockscf.log.fpv != NULL) {
      char buf[80];

      snprintf(buf, sizeof(buf),
      "%s: deallocating fd %d, was allocated for command %d\n",
      function, d, socksfdv[d].state.command);

      syssys_write(fileno(sockscf.log.fpv[0]), buf, strlen(buf) + 1);
   }
#endif /* THREAD_DEBUG */

   socksfdv[d] = socksfdinit;

   if (takelock)
      socks_addrunlock(&opaque);
}

int
socks_isaddr(d, takelock)
   const int d;
   const int takelock;
{

   if (d < 0 || (size_t)d >= socksfdc)
      return 0;

   return socksfdv[d].allocated;
}

int
socks_addrisours(s, takelock)
   const int s;
   const int takelock;
{
   const char *function = "socks_addrisours()";
   const int errno_s = errno;
   addrlockopaque_t opaque;
   int matched;

   errno = 0;

   if (takelock)
      socks_addrlock(F_RDLCK, &opaque);

   matched = 0;
   do {
      const struct socksfd_t *socksfd;
      struct sockaddr local, remote;
      socklen_t locallen, remotelen;

      locallen = sizeof(local);
      if (getsockname(s, &local, &locallen) != 0)
         break;

      /* only network-sockets can be proxied. */
      if (local.sa_family != AF_INET
#ifdef AF_INET6
      &&  local.sa_family != AF_INET6)
#endif /* AF_INET6 */
         break;

      if ((socksfd = socks_getaddr(s, 0)) != NULL) {
         if (TOCIN(&socksfd->local)->sin_addr.s_addr == htonl(0)) {
            /*
             * if address was not bound before, it might have become
             * later, after client did a send(2) or similar.
             * It's also possible accept(2) was called, so check
             * for that first.
             */
            struct socksfd_t nsocksfd;
            int duped;

            remotelen = sizeof(remote);
            if (getpeername(s, &remote, &remotelen) == 0
            && (duped = socks_addrmatch(&local, &remote, NULL, 0)) != -1) {
               if ((socksfd = socks_addrdup(socks_getaddr(duped, 0), &nsocksfd))
               == NULL) {
                  swarn("%s: socks_addrdup()", function);

                  if (errno == EBADF)
                     socks_rmaddr(duped, 0);
                  break;
               }

               socks_addaddr(s, &nsocksfd, 0);
               matched = 1;

               if (!fdisopen(duped))
                  socks_rmaddr(duped, 0);
            }
            else {
               nsocksfd = *socksfd;
               TOIN(&nsocksfd.local)->sin_addr = TOIN(&local)->sin_addr;
               socksfd = socks_addaddr(s, &nsocksfd, 0);
            }
         }

         if (!sockaddrareeq(&local, &socksfd->local))
            break;

         /* check remote endpoint too? */

         matched = 1;
      }
      else { /* unknown descriptor.  Try to check whether it's a dup. */
         int duped;

         if ((duped = socks_addrmatch(&local, NULL, NULL, 0)) != -1) {
            struct socksfd_t nsocksfd;

            socksfd = socks_addrdup(socks_getaddr(duped, 0), &nsocksfd);

            if (socksfd == NULL) {
               swarn("%s: socks_addrdup()", function);

               if (errno == EBADF)
                  socks_rmaddr(duped, 0);
               break;
            }

            socks_addaddr(s, &nsocksfd, 0);

            if (!fdisopen(duped))
               socks_rmaddr(duped, 0);

            matched = 1;
         }
         break;
      }
   /* CONSTCOND */
   } while (0);

   if (takelock)
      socks_addrunlock(&opaque);

   errno = errno_s;
   return matched;
}

int
socks_addrcontrol(local, remote, s, device, inode, takelock)
   const struct sockaddr *local;
   const struct sockaddr *remote;
   const int s;
   const dev_t device;
   const ino_t inode;
   const int takelock;
{
   const char *function = "socks_addrcontrol()"; 
   addrlockopaque_t opaque;
   size_t i;
#if DIAGNOSTIC
   int matched = -1;
#endif /* DIAGNOSTIC */

   if (takelock)
      socks_addrlock(F_RDLCK, &opaque);

   for (i = 0; i < socksfdc; ++i) {
      struct sockaddr addr;

      if (!socks_isaddr(i, 0))
         continue;

      if (device != (dev_t)-1 && inode != (ino_t)-1)  {
         struct stat sb;

         if (fstat(socksfdv[i].control, &sb) != 0)
            slog(LOG_DEBUG, "%s: fstat(%d) failed: %s",
            function, socksfdv[i].control, strerror(errno));
         else {
            if (sb.st_dev != device || sb.st_ino != inode)
               continue;
            else {
               slog(LOG_DEBUG, "%s: fd %d matched to addressindex %d via "
                               "device/inode %lu/%lu",
                               function, socksfdv[i].control, i,
                               (unsigned long)device, (unsigned long)inode);

#if HAVE_UNIQUE_SOCKET_INODES
#if !DIAGNOSTIC
               break;
#else /* DIAGNOSTIC */
               if (matched == -1) {
                  matched = i; 
                  continue;
               }
               else
                  SASSERTX(i);
#endif /* DIAGNOSTIC */
#else /* !HAVE_UNIQUE_SOCKET_INODES */ 
               slog(LOG_DEBUG, "%s: this system however does not have unique "
                               "inodes for sockets as far as we know, so need "
                               "to do address match also", 
                               function);
#endif /* !HAVE_UNIQUE_SOCKET_INODES */
            }
         }
      }

      if (local != NULL) {
         socklen_t len = sizeof(addr);
         if (getsockname(socksfdv[i].control, &addr, &len) != 0)
            continue;

         if (!sockaddrareeq(local, &addr))
            continue;
      }

      /*
       * If remote is NULL, it means the socket we are looking for
       * is not connected, either because the connect(2) failed,
       * or because it's a datagram socket.
       * If remote is not NULL, the socket we are looking for is
       * connected.
       */
      if (remote == NULL) {
         socklen_t len = 0;
         if (getpeername(socksfdv[i].control, NULL, &len) != -1)
            continue; 
      }
      else {
         socklen_t len = sizeof(addr);
         if (getpeername(socksfdv[i].control, &addr, &len) == -1)
            continue;

         if (!sockaddrareeq(remote, &addr))
            continue;
      }

#if DIAGNOSTIC
      if (matched == -1) {
         matched = i; 
         continue;
      }
      else
         SASSERTX(i);
#else /* !DIAGNOSTIC */
      break;
#endif /* !DIAGNOSTIC */
   }

   if (takelock)
      socks_addrunlock(&opaque);

#if DIAGNOSTIC
   i = matched;
#endif /* DIAGNOSTIC */

   if (i < socksfdc)
      return (int)i;

   return -1;
}

int
socks_addrmatch(local, remote, state, takelock)
   const struct sockaddr *local;
   const struct sockaddr *remote;
   const struct socksstate_t *state;
   const int takelock;
{
   addrlockopaque_t opaque;
   int i;

   if (takelock)
      socks_addrlock(F_RDLCK, &opaque);

   for (i = 0; i < (int)socksfdc; ++i) {
      if (!socks_isaddr(i, 0))
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

   if (takelock)
      socks_addrunlock(&opaque);

   if (i < (int)socksfdc)
      return i;

   return -1;
}

struct socksfd_t *
socks_addrdup(old, new)
   const struct socksfd_t *old;
   struct socksfd_t *new;
{
/*   const char *function = "socks_addrdup()"; */

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

void
socks_addrlock(locktype, opaque)
   const int locktype;
   addrlockopaque_t *opaque;
{

   socks_sigblock((sigset_t *)opaque);

#if HAVE_PTHREAD_H
   /*
    * With the OpenBSD thread implementation, and presumably FreeBSD 
    * also, if a thread is interrupted, calling pthread_mutex_lock()
    * seems to clear the interrupt flag, so that e.g. select(2) will
    * restart rather than returning EINTR.  We don't wont that to
    * happen since we depend on select(2)/etc. being interrupted by
    * the process used to handle non-blocking connects.
    * We therefor instead take the risk of not taking the thread-lock
    * in that case.
    */
   if (!sockscf.state.insignal)
      /* XXX set based on locktype. */
      socks_pthread_mutex_lock(&addrmutex);
#endif /* HAVE_PTHREAD_H */
}

void
socks_addrunlock(opaque)
   const addrlockopaque_t *opaque;
{

#if HAVE_PTHREAD_H
   if (!sockscf.state.insignal)
      socks_pthread_mutex_unlock(&addrmutex);
#endif /* HAVE_PTHREAD_H */

   socks_sigunblock((const sigset_t *)opaque);
}

in_addr_t
socks_addfakeip(host)
   const char *host;
{
   const char *function = "socks_addfakeip()";
   addrlockopaque_t opaque;
   struct in_addr addr;
   char **tmpmem;

   socks_addrlock(F_WRLCK, &opaque);

   if (socks_getfakeip(host, &addr)) {
      socks_addrunlock(&opaque);
      return addr.s_addr;
   }

#if FAKEIP_END < FAKEIP_START
error "\"FAKEIP_END\" can't be smaller than \"FAKEIP_START\""
#endif

   if (ipc >= FAKEIP_END - FAKEIP_START) {
      swarnx("%s: fakeip range (%d - %d) exhausted",
      function, FAKEIP_START, FAKEIP_END);

      socks_addrunlock(&opaque);
      return INADDR_NONE;
   }

   if ((tmpmem = realloc(ipv, sizeof(*ipv) * (ipc + 1))) == NULL
   || (tmpmem[ipc] = malloc(sizeof(*tmpmem) * (strlen(host) + 1)))
   == NULL) {
      if (tmpmem != NULL)
         free(tmpmem);

      swarnx("%s: %s", function, NOMEM);

      socks_addrunlock(&opaque);
      return INADDR_NONE;
   }
   ipv = tmpmem;

   strcpy(ipv[ipc], host);

   socks_addrunlock(&opaque);
   return htonl(ipc++ + FAKEIP_START);
}

const char *
socks_getfakehost(addr)
   in_addr_t addr;
{
   addrlockopaque_t opaque;
   const char *host;

   socks_addrlock(F_RDLCK, &opaque);

   if (ntohl(addr) - FAKEIP_START < ipc)
      host = ipv[ntohl(addr) - FAKEIP_START];
   else
      host = NULL;

   socks_addrunlock(&opaque);
   return host;
}

int
socks_getfakeip(host, addr)
   const char *host;
   struct in_addr *addr;
{
   addrlockopaque_t opaque;
   unsigned int i;

   socks_addrlock(F_RDLCK, &opaque);

   for (i = 0; i < ipc; ++i)
      if (strcasecmp(host, ipv[i]) == 0) {
         addr->s_addr = htonl(i + FAKEIP_START);
         break;
      }

   socks_addrunlock(&opaque);

   if (i < ipc)
      return 1;
   return 0;
}

struct sockshost_t *
fakesockaddr2sockshost(addr, host)
   const struct sockaddr *addr;
   struct sockshost_t *host;
{
   const char *function = "fakesockaddr2sockshost()";
   char string[MAXSOCKADDRSTRING];

   clientinit(); /* may be called before normal init, log to right place. */

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

   clientinit(); /* may be called before normal init, log to right place. */

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

static int
socks_addfd(d)
   const int d;
{
   const char *function = "socks_addfd()";

   if (d + 1 < d) /* integer overflow. */
      return -1;

   if ((unsigned int)d >= dc) { /* init/reallocate */
      int *newfdv;
      unsigned int newfdc;

      newfdc = MIN((d + 1) * 4, d + 64);
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
   const int d;
{
   if (d < 0 || (unsigned int)d >= dc || dv[d] == -1)
      return 0;
   return 1;
}

static void
socks_rmfd(d)
   const int d;
{
   if (socks_isfd(d))
      dv[d] = -1;
}

static void
socks_sigblock(oldset)
   sigset_t *oldset;
{
   const char *function = "socks_sigblock()";
   sigset_t newmask;

   (void)sigemptyset(&newmask);
   (void)sigaddset(&newmask, SIGIO);
   if (sigprocmask(SIG_BLOCK, &newmask, oldset) != 0)
      swarn("%s: sigprocmask()", function);
}

static void
socks_sigunblock(oldset)
   const sigset_t *oldset;
{
   const char *function = "socks_sigunblock()";

   if (sigprocmask(SIG_SETMASK, oldset, NULL) != 0)
      swarn("%s: sigprocmask()", function);
}

void
addrlockinit(void)
{
   const char *function = "addrlockinit()";
   static int inited;
#if HAVE_PTHREAD_H
   pthread_mutexattr_t attr;
   void *lpt;
#endif /* HAVE_PTHREAD_H */

   if (inited)
      return;

#if HAVE_PTHREAD_H
   if (socks_getenv("SOCKS_DISABLE_THREADLOCK", istrue) != NULL) {
      slog(LOG_DEBUG, "pthread locking off, manually disabled in environment");
      inited = 1;

      return;
   }

#if HAVE_RTLD_NEXT
   /*
    * XXX following test will always perceive the application as being
    * threaded if lib(d)socks depend on libpthread, which might be the
    * case if e.g., some gssapi libs require this library.
    */
   if (dlsym(RTLD_NEXT, SYMBOL_PT_ATTRINIT) != NULL) {
      /* appears to be threaded application, obtain function pointers */
      lpt = RTLD_NEXT;
      slog(LOG_DEBUG, "pthread locking desired, threaded application (rtld)");
   } else {
      slog(LOG_DEBUG, "pthread locking off, non-threaded application (rtld)");
      lpt = NULL;
   }
#else
   /* load libthreads */
   if ((lpt = dlopen(LIBRARY_PTHREAD, RTLD_LAZY)) == NULL) {
      swarn("%s: compile time configuration error?  "
      "Failed to open \"%s\": %s", function, LIBRARY_PTHREAD, dlerror());
   }
#endif /* HAVE_RTLD_NEXT */

   if (lpt != NULL) {
         /*
          * resolve pthread symbols.
          */

      if ((pt_init = (PT_INIT_FUNC_T)dlsym(lpt, SYMBOL_PT_INIT)) == NULL)
         swarn("%s: compile time configuration error?  "
         "Failed to find \"%s\" in \"%s\": %s",
         function, SYMBOL_PT_INIT, LIBRARY_PTHREAD, dlerror());

      if ((pt_attrinit = (PT_ATTRINIT_FUNC_T)dlsym(lpt, SYMBOL_PT_ATTRINIT))
      == NULL)
         swarn("%s: compile time configuration error?  "
         "Failed to find \"%s\" in \"%s\": %s",
         function, SYMBOL_PT_ATTRINIT, LIBRARY_PTHREAD, dlerror());

      if ((pt_settype = (PT_SETTYPE_FUNC_T)dlsym(lpt, SYMBOL_PT_SETTYPE))
      == NULL)
         swarn("%s: compile time configuration error?  "
         "Failed to find \"%s\" in \"%s\": %s",
         function, SYMBOL_PT_SETTYPE, LIBRARY_PTHREAD, dlerror());

      if ((pt_lock = (PT_LOCK_FUNC_T)dlsym(lpt, SYMBOL_PT_LOCK)) == NULL)
         swarn("%s: compile time configuration error?  "
         "Failed to find \"%s\" in \"%s\": %s",
         function, SYMBOL_PT_LOCK, LIBRARY_PTHREAD, dlerror());

      if ((pt_unlock = (PT_UNLOCK_FUNC_T)dlsym(lpt, SYMBOL_PT_UNLOCK)) == NULL)
         swarn("%s: compile time configuration error?  "
         "Failed to find \"%s\" in \"%s\": %s",
         function, SYMBOL_PT_UNLOCK, LIBRARY_PTHREAD, dlerror());

      if ((pt_self = (PT_SELF_FUNC_T)dlsym(lpt, SYMBOL_PT_SELF)) == NULL)
         swarn("%s: compile time configuration error?  "
         "Failed to find \"%s\" in \"%s\": %s",
         function, SYMBOL_PT_SELF, LIBRARY_PTHREAD, dlerror());
   }

   if (pt_init == NULL || pt_attrinit == NULL || pt_settype == NULL
   ||  pt_lock == NULL || pt_unlock   == NULL || pt_self    == NULL) {
      pt_init     = NULL;
      pt_attrinit = NULL;
      pt_settype  = NULL;
      pt_lock     = NULL;
      pt_unlock   = NULL;
      pt_self     = NULL;
   }

   if (pt_init == NULL)
      slog(LOG_DEBUG, "pthread locking disabled");
   else
      slog(LOG_DEBUG, "pthread locking enabled");

   if (socks_pthread_mutexattr_init(&attr) != 0)
      serr(EXIT_FAILURE, "mutexattr_init()");

   if (socks_pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0)
      swarn("mutex_settype(PTHREAD_MUTEX_ERRORCHECK) failed");

   if (socks_pthread_mutex_init(&addrmutex, &attr) != 0)
      serr(EXIT_FAILURE, "mutex_init()");
#endif /* HAVE_PTHREAD_H */

   inited = 1;
}

struct socks_id_t *
socks_whoami(id)
   struct socks_id_t *id;
{

#if HAVE_PTHREAD_H
   if (pt_self != NULL) {
      id->whichid   = thread;
      id->id.thread = pt_self();

      return id;
   }
#endif /* HAVE_PTHREAD_H */

   id->whichid = pid;

   if (sockscf.state.pid == 0) /* not yet inited. */
      id->id.pid = getpid();
   else
      id->id.pid = sockscf.state.pid;

   return id;
}

#if HAVE_PTHREAD_H
/* pthread lock wrapper functions */
static int
socks_pthread_mutex_init(mutex, attr)
   pthread_mutex_t *mutex;
   const pthread_mutexattr_t *attr;
{
   if (pt_init != NULL)
      return pt_init(mutex, attr);
   else
      return 0;
}

static int
socks_pthread_mutexattr_init(attr)
   pthread_mutexattr_t *attr;
{
   if (pt_attrinit != NULL)
      return pt_attrinit(attr);
   else
      return 0;
}

static int
socks_pthread_mutexattr_settype(attr, type)
   pthread_mutexattr_t *attr;
   int type;
{
   if (pt_settype != NULL)
      return pt_settype(attr, type);
   else
      return 0;
}

static int
socks_pthread_mutex_lock(mutex)
   pthread_mutex_t *mutex;
{
   if (pt_lock != NULL)
      return pt_lock(mutex);
   else
      return 0;
}

static int
socks_pthread_mutex_unlock(mutex)
   pthread_mutex_t *mutex;
{
   if (pt_unlock != NULL)
      return pt_unlock(mutex);
   else
      return 0;
}
#endif /* HAVE_PTHREAD_H */
