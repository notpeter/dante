/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2008, 2009, 2010, 2011
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

#include "upnp.h"

#ifndef __USE_GNU
#define __USE_GNU /* XXX for RTLD_NEXT on Linux */
#endif /* !__USE_GNU */
#include <dlfcn.h>

static const char rcsid[] =
"$Id: address.c,v 1.208 2011/07/22 08:45:02 karls Exp $";

/*
 * During init, we need to let all system calls resolve to the native
 * version.  I.e., socks_shouldcallasnative() need to always return
 * true as long as we are initing. Use this object for holding that
 * knowledge.
 */
#ifdef HAVE_VOLATILE_SIG_ATOMIC_T
sig_atomic_t doing_addrinit;
#else
volatile sig_atomic_t doing_addrinit;
#endif /* HAVE_VOLATILE_SIG_ATOMIC_T */


/*
 * "fake" ip addresses for clients that want/need to use that.
 * Note that this is process-specific, so it will not work with
 * programs that fork of "dns-helper".  Shared memory might have worked,
 * but even that would have depended on us being able to set up the
 * shared memory early enough, so just say we don't support that.
 */
static char **ipv;
static in_addr_t ipc;

#define FDV_INITSIZE    64 /* on init allocate memory for first 64 fd indexes */
static struct socksfd_t socksfdinit;
static int *dv;
static size_t dc;
static struct socksfd_t *socksfdv;
static size_t socksfdc;

#if HAVE_PTHREAD_H

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

static pthread_mutex_t addrmutex;
#endif /* HAVE_PTHREAD_H */

static int
fdisdup(const int fd1, const int fd2);
/*
 * Tries to determine if file descriptor fd1 is a dup of fd2.
 * Returns true if yes, false if not.
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
   addrlockopaque_t lock;

   clientinit();

#if 0 /* DEBUG */
   if (socksfd->state.command != -1 && !socksfd->state.system)
      slog(LOG_DEBUG, "%s: %d", function, clientfd);
#endif

   SASSERTX(socksfd->state.command == -1
   ||       socksfd->state.command == SOCKS_BIND
   ||       socksfd->state.command == SOCKS_CONNECT
   ||       socksfd->state.command == SOCKS_UDPASSOCIATE);

   if (takelock)
      socks_addrlock(F_WRLCK, &lock);

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
#if HAVE_GSSAPI
   socksfdv[clientfd].state.gssapistate.value
   = socksfdv[clientfd].state.gssapistatemem;
#endif
   socksfdv[clientfd].allocated = 1;

   if (takelock)
      socks_addrunlock(&lock);

#ifdef THREAD_DEBUG
   if (sockscf.log.fpv != NULL) {
      char buf[80];

      snprintf(buf, sizeof(buf),
      "%s: allocating fd %d for command %d\n",
      function, clientfd, socksfdv[clientfd].state.command);

      syssys_write(fileno(sockscf.log.fpv[0]), buf, strlen(buf) + 1);
   }
#endif /* THREAD_DEBUG */

   if (socksfd->state.auth.method == AUTHMETHOD_GSSAPI)
      sockscf.state.havegssapisockets = 1;

   return &socksfdv[clientfd];
}

struct socksfd_t *
socks_getaddr(d, socksfd, takelock)
   const int d;
   struct socksfd_t *socksfd;
   const int takelock;
{
#if HAVE_GSSAPI
   const char *function = "socks_getaddr()";
#endif /* HAVE_GSSAPI */
   struct socksfd_t *sfd;
   addrlockopaque_t lock;

   if (socksfd == NULL) {
      static struct socksfd_t ifnullsocksfd;

      socksfd = &ifnullsocksfd;
   }

   if (takelock)
      socks_addrlock(F_RDLCK, &lock);

   if (socks_isaddr(d, 0)) {
      sfd = &socksfdv[d];

#if HAVE_GSSAPI
      if (sfd->state.gssimportneeded && !sockscf.state.insignal) {
         slog(LOG_DEBUG, "%s: importing gssapistate for socket %d",
         function, d);

         if (gssapi_import_state(&sfd->state.auth.mdata.gssapi.state.id,
         &sfd->state.gssapistate) != 0) {
            swarnx("%s: failed to import gssapi context of length %lu "
                   "for socket %d",
                   function, (unsigned long)sfd->state.gssapistate.length, d);

            socks_rmaddr(d, 0);
            sfd = NULL;
         }
         else
            sfd->state.gssimportneeded = 0;
      }
#endif /* HAVE_GSSAPI */
   }
   else
      sfd = NULL;

   if (takelock)
      socks_addrunlock(&lock);

   if (sfd == NULL)
      return NULL;

   *socksfd = *sfd;
   return socksfd;
}

void
socks_rmaddr(d, takelock)
   const int d;
   const int takelock;
{
   const char *function = "socks_rmaddr()";
   addrlockopaque_t lock;

   if (d < 0 || (size_t)d >= socksfdc)
      return; /* not a socket of ours. */

   if (takelock)
      socks_addrlock(F_WRLCK, &lock);

   socks_rmfd(d);
   if (socksfdv[d].state.issyscall) /* syscall adds/removes all the time. */
      slog(LOG_DEBUG, "%s: not freeing buffer for fd %d, issyscall",
      function, d);
   else
      socks_freebuffer(d);

   switch (socksfdv[d].state.version) {
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
                   * that this control connection is shared with other
                   * (accept()'ed) addresses, if so we must leave it
                   * open for the other connections.
                  */
                  if (socks_addrcontrol(&socksfdv[d].local,
                  &socksfdv[d].remote, -1, -1, 0)
                  == -1)
                     break;

                  close(socksfdv[d].control);
                  break;

               case SOCKS_CONNECT:
                  break; /* no separate control connection. */

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
      socks_addrunlock(&lock);
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
socks_addrisours(s, socksfdmatch, takelock)
   const int s;
   struct socksfd_t *socksfdmatch;
   const int takelock;
{
   const char *function = "socks_addrisours()";
   const int errno_s = errno;
   addrlockopaque_t lock;
   int matched;

   errno = 0;

   if (takelock)
      socks_addrlock(F_RDLCK, &lock);

   matched = 0;
   do {
      struct sockaddr local, remote;
      struct socksfd_t socksfd;
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

      if (socks_getaddr(s, &socksfd, 0) != NULL) {
         if (TOCIN(&socksfd.local)->sin_addr.s_addr == htonl(0)) {
            /*
             * if address was not bound before, it might have become
             * later, after client did a send(2) or similar.
             * It's also possible accept(2) was called, so check
             * for that first.
             */
            struct socksfd_t nsocksfd, *socksfdptr;
            int duped;

            remotelen = sizeof(remote);
            if (getpeername(s, &remote, &remotelen) == 0
            && (duped = socks_addrmatch(&local, &remote, NULL, 0)) != -1) {
               if ((socksfdptr = socks_addrdup(socks_getaddr(duped, NULL, 0),
                                            &nsocksfd))
               == NULL) {
                  swarn("%s: socks_addrdup()", function);

                  if (errno == EBADF)
                     socks_rmaddr(duped, 0);
                  break;
               }

               socksfd = *socksfdptr;
               socks_addaddr(s, &nsocksfd, 0);
               matched = 1;

               if (!fdisopen(duped))
                  socks_rmaddr(duped, 0);
            }
            else {
               nsocksfd = socksfd;
               TOIN(&nsocksfd.local)->sin_addr = TOIN(&local)->sin_addr;
               socksfd = *socks_addaddr(s, &nsocksfd, 0);
            }
         }

         if (!sockaddrareeq(&local, &socksfd.local))
            break;

         /* check remote endpoint too? */

         matched = 1;
      }
      else { /* unknown descriptor.  Try to check whether it's a dup. */
         int duped;

         if ((duped = socks_addrmatch(&local, NULL, NULL, 0)) != -1) {
            struct socksfd_t nsocksfd;

            if (socks_addrdup(socks_getaddr(duped, NULL, 0), &nsocksfd)
            == NULL) {
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
   } while (/* CONSTCOND */ 0);

   if (matched && socksfdmatch != NULL)
      socks_getaddr(s, socksfdmatch, 0);

   if (takelock)
      socks_addrunlock(&lock);

   errno = errno_s;
   return matched;
}

int
socks_addrcontrol(local, remote, s, childsocket, takelock)
   const struct sockaddr *local;
   const struct sockaddr *remote;
   const int s;
   const int childsocket;
   const int takelock;
{
   const char *function = "socks_addrcontrol()";
   addrlockopaque_t lock;
   size_t i;
   char a[MAXSOCKADDRSTRING], b[MAXSOCKADDRSTRING];
#if DIAGNOSTIC
   int matched = -1;
#endif /* DIAGNOSTIC */

   if (takelock)
      socks_addrlock(F_RDLCK, &lock);

   if (socks_isaddr(s, 0)) {
      /*
       * First check the index corresponding to what the descriptor should
       * be, if nothing tricky (dup(2) or similar) happened between the time
       * we sent the descriptor to the connect-process, and now.
       * If it doesn't match, we will have to go through all of the indexes.
       */
      if (fdisdup(childsocket, socksfdv[s].control))
#if !DIAGNOSTIC
         return s;
#else /* DIAGNOSTIC */
         slog(LOG_DEBUG, "%s: descriptor %d is a dup of %d, but going through "
                         "the whole array anyway for diagnostic reasons",
                         function, childsocket, socksfdv[s].control);
#endif /* DIAGNOSTIC */
   }

   for (i = 0; i < socksfdc; ++i) {
      struct sockaddr addr;
      socklen_t len;

      if (!socks_isaddr(i, 0))
         continue;

      if (socksfdv[i].state.command == -1)
         continue;

      if (childsocket != -1) {
         if (fdisdup(childsocket, socksfdv[i].control)) {
#if !DIAGNOSTIC
            break;
#else /* DIAGNOSTIC; go through the rest.  Should be no more matches though. */
         if (matched == -1)
            matched = i;
         else
            SASSERTX(i);
#endif /* DIAGNOSTIC */
         }

         continue;
      }

      slog(LOG_DEBUG, "%s: no descriptor to check against, "
                      "need to check addresses (%s and %s)",
                      function,
                      local == NULL
                        ? "N/A" : sockaddr2string(local, a, sizeof(a)),
                      remote == NULL
                        ? "N/A" : sockaddr2string(remote, b, sizeof(b)));


      if (local == NULL) {
         len = 0;
         if (getsockname(socksfdv[i].control, &addr, &len) == 0)
            continue; /* can't be this one, our socket has no local name.  */
      }
      else  {
         len = sizeof(addr);
         if (getsockname(socksfdv[i].control, &addr, &len) != 0)
            continue;

         if (!sockaddrareeq(local, &addr))
            continue;
      }

      if (remote == NULL) {
         len = 0;
         if (getpeername(socksfdv[i].control, (struct sockaddr *)&len, &len)
         == 0)
            continue;  /* can't be this one, our socket has no peer. */
      }
      else {
         len = sizeof(addr);
         if (getpeername(socksfdv[i].control, &addr, &len) == -1)
            continue;

         if (!sockaddrareeq(remote, &addr))
            continue;
      }

      if (local == NULL && remote == NULL) {
         int type_s, type_childsocket;

         slog(LOG_DEBUG, "%s: hmm, this is pretty bad, no addressinfo "
                         "and nothing else to use to match descriptors",
                         function);

         if (fdisopen(s) != fdisopen(childsocket))
            continue;

         len = sizeof(type_s);
         if (getsockopt(s, SOL_SOCKET, SO_TYPE, &type_s, &len) != 0) {
            slog(LOG_DEBUG, "%s: getsockopt(SO_TYPE) on socket %d failed: %s",
            function, s, strerror(errno));
            continue;
         }

         len = sizeof(type_s);
         if (getsockopt(childsocket, SOL_SOCKET, SO_TYPE, &type_childsocket,
         &len) != 0) {
            slog(LOG_DEBUG, "%s: getsockopt(SO_TYPE) on socket %d failed: %s",
            function, childsocket, strerror(errno));
            continue;
         }

         if (type_s == type_childsocket) {
            slog(LOG_DEBUG, "%s: no addressinfo to match socket by, but found "
                            "another socket (addrindex %lu) of the same "
                            "type (%d) without any addressinfo either.  "
                            "Lets hope that's good enough",
                            function, (unsigned long)i, type_s);

#if DIAGNOSTIC
            matched = i;
#endif /* DIAGNOSTIC */
            break; /* no diagnostic of interest in this case. */
         }
         else
            continue;
      }

#if !DIAGNOSTIC
      break;
#else /* DIAGNOSTIC */
      if (matched == -1)
         matched = i;
      else
         SASSERTX(i);
#endif /* DIAGNOSTIC */
   }

   if (takelock)
      socks_addrunlock(&lock);

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
   addrlockopaque_t lock;
   int i;

   if (takelock)
      socks_addrlock(F_RDLCK, &lock);

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
      socks_addrunlock(&lock);

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
socks_addrlock(locktype, lock)
   const int locktype;
   addrlockopaque_t *lock;
{

   socks_sigblock(-1, (sigset_t *)lock);

#if HAVE_PTHREAD_H
   /*
    * With the OpenBSD thread implementation, if a thread is interrupted, 
    * calling pthread_mutex_lock() seems to clear the interrupt flag, so
    * that e.g. select(2) will restart rather than returning EINTR. 
    * We don't wont that to happen since we depend on select(2)/etc.
    * being interrupted by the process used to handle non-blocking connects.
    * We instead take the risk of not taking the thread-lock in this case.
    */
   if (!sockscf.state.insignal)
      /* XXX set based on locktype. */
      socks_pthread_mutex_lock(&addrmutex);
#endif /* HAVE_PTHREAD_H */
}

void
socks_addrunlock(lock)
   const addrlockopaque_t *lock;
{

#if HAVE_PTHREAD_H
   if (!sockscf.state.insignal)
      socks_pthread_mutex_unlock(&addrmutex);
#endif /* HAVE_PTHREAD_H */

   socks_sigunblock((const sigset_t *)lock);
}

in_addr_t
socks_addfakeip(host)
   const char *host;
{
   const char *function = "socks_addfakeip()";
   addrlockopaque_t lock;
   struct in_addr addr;
   char **tmpmem;
   int ipc_added;

   socks_addrlock(F_WRLCK, &lock);

   if (socks_getfakeip(host, &addr)) {
      socks_addrunlock(&lock);
      return addr.s_addr;
   }

#if FAKEIP_END < FAKEIP_START
error "\"FAKEIP_END\" can't be smaller than \"FAKEIP_START\""
#endif

   if (ipc >= FAKEIP_END - FAKEIP_START) {
      swarnx("%s: fakeip range (%d - %d) exhausted",
      function, FAKEIP_START, FAKEIP_END);

      socks_addrunlock(&lock);
      return INADDR_NONE;
   }

   if ((tmpmem = realloc(ipv, sizeof(*ipv) * (ipc + 1))) == NULL
   || (tmpmem[ipc] = malloc(sizeof(*tmpmem) * (strlen(host) + 1))) == NULL) {
      swarnx("%s: %s", function, NOMEM);

      if (tmpmem != NULL)
         free(tmpmem);

      socks_addrunlock(&lock);
      return INADDR_NONE;
   }
   ipv = tmpmem;

   ipc_added = ipc;
   strcpy(ipv[ipc++], host);

   socks_addrunlock(&lock);

   return htonl(ipc_added + FAKEIP_START);
}

const char *
socks_getfakehost(addr)
   in_addr_t addr;
{
   const char *function = "socks_getfakehost()";
   addrlockopaque_t lock;
   const char *host;

   if (ntohl(addr) - FAKEIP_START < ipc) {
      socks_addrlock(F_RDLCK, &lock);
      host = ipv[ntohl(addr) - FAKEIP_START];
      socks_addrunlock(&lock);
   }
   else {
      if (ntohl(addr) >= FAKEIP_START &&  ntohl(addr) <= FAKEIP_END)
         swarnx("%s: looks like ip address %s might be a \"fake\" ip address, "
                "but we have no knowledge of that address in this process.  "
                "Possibly this client is forking of a \"dns-helper\"-style "
                "program for dns stuff.  We unfortunately do not support "
                "using fake ip addresses in that case.",
                function, inet_ntoa(*(struct in_addr *)&addr));

      host = NULL;
   }

   return host;
}

int
socks_getfakeip(host, addr)
   const char *host;
   struct in_addr *addr;
{
   addrlockopaque_t lock;
   unsigned int i;

   socks_addrlock(F_RDLCK, &lock);

   for (i = 0; i < ipc; ++i)
      if (strcasecmp(host, ipv[i]) == 0) {
         addr->s_addr = htonl(i + FAKEIP_START);
         break;
      }

   socks_addrunlock(&lock);

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
        socks_getfakehost(TOCIN(addr)->sin_addr.s_addr)
        == NULL ? string : socks_getfakehost(TOCIN(addr)->sin_addr.s_addr));

   /* LINTED pointer casts may be troublesome */
   if (socks_getfakehost(TOCIN(addr)->sin_addr.s_addr) != NULL) {
      /* LINTED pointer casts may be troublesome */
      const char *ipname = socks_getfakehost(TOCIN(addr)->sin_addr.s_addr);

      SASSERTX(ipname != NULL);

      host->atype = (unsigned char)SOCKS_ADDR_DOMAIN;
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

   clientinit();

   if (d + 1 < d) /* integer overflow. */
      return -1;

   if ((unsigned int)d >= dc) { /* init/reallocate */
      int *newfdv;
      unsigned int newfdc;

      newfdc = (d + 1) * 2; /* add some extra at the same time. */
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

static int
fdisdup(fd1, fd2)
   const int fd1;
   const int fd2;
{
   const char *function = "fdisdup()";
#if HAVE_UNIQUE_SOCKET_INODES
   struct stat sb1, sb2;
#endif /* HAVE_UNIQUE_SOCKET_INODES */
   socklen_t len1, len2;
   int isdup, rc1, rc2, errno1, errno2, flags1, flags2,  newflags1, newflags2,
       testflag = SO_REUSEADDR, setflag;

   slog(LOG_DEBUG, "%s: %d, %d", function, fd1, fd2);

   if (fd1 == fd2)
      return 1;

#if HAVE_UNIQUE_SOCKET_INODES
   rc1    = fstat(fd1, &sb1);
   errno1 = errno;

   rc2    = fstat(fd2, &sb2);
   errno2 = errno;

   if (rc1 != rc2 || errno1 != errno2) {
      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: failed due to fstat() on line %d",
         function, __LINE__);

      return 0;
   }

   if (rc1 == -1) {
      SASSERTX(rc2 == -1 && errno1 == errno2);

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: failed due to rc1 on line %d",
         function, __LINE__);

      return 1; /* assume any failed socket is as good as any other. */
   }

   if (sb1.st_ino == 0)
      slog(LOG_DEBUG, "%s: socket inode is 0.  Assuming kernel does "
                      "not support the inode field for (this) socket",
                      function);
   else if (sb1.st_dev != sb2.st_dev
   ||       sb1.st_ino != sb2.st_ino) {
      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: failed due to inode-compare on line %d "
                         "(sb1.st_dev = %d, sb2.st_dev = %d, "
                         "sb1.st_ino = %d, sb2.st_ino = %d)",
                         function, __LINE__,
                         (int)sb1.st_dev, (int)sb2.st_dev,
                         (int)sb1.st_ino, (int)sb2.st_ino);

      return 0;
   }
#endif /* HAVE_UNIQUE_SOCKET_INODES */

   len1   = sizeof(flags1);
   rc1    = getsockopt(fd1, SOL_SOCKET, testflag, &flags1, &len1);
   errno1 = errno;

   len2   = sizeof(flags2);
   rc2    = getsockopt(fd1, SOL_SOCKET, testflag, &flags2, &len2);
   errno2 = errno;

   if (rc1 != rc2 || errno1 != errno2 || flags1 != flags2) {
      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: failed due to flags/errno/len-compare on line %d",
         function, __LINE__);

      return 0;
   }

   /*
    * Test is to set a flag on fd1, and see if the same flag then gets set on
    * fd2.  Note that this flag must be a flag we can set on a socket that
    * failed during connect(2), or where the remote end has closed it's side
    * of the pipe, and that will be shared between descriptors that are
    * dup(2)'s of each other.
    *
    * File status flags are shared, but descriptor flags (e.g., FD_CLOEXEC),
    * are of course not.  Also note that not all platforms let all F_SETFL
    * commands change the same flags, and not all platforms let us set
    * the flag on a "failed" socket (a socket where the connect(2) failed).
    * We however assume that if the socket failed, and we are getting the
    * same errno from the socket we are checking against, it is either the
    * socket, or any failed socket is as good as any other failed socket.
    *
    * XXX this does not work on OpenBSD if one of the descriptors were passed
    * us by another process (e.g., passed us by the connect child).
    * Need to sendbug this.
    *
    * The reason we do not do this test first is that if there are multiple
    * processes/threads using the same fd, we want to minimize the chance
    * of us changing the descriptor under their feet while they are using it.
    */

   slog(LOG_DEBUG, "%s: all looks equal so far, doing final test, flags = %d",
   function, flags1);

   SASSERTX(flags1 == flags2);

   if (rc1 == -1 && errno1 == ENOTSOCK) {
      SWARNX(fd1); /* should not happen as we are only interested in sockets. */
      return 0;
   }

   if (flags1)
      /*
       * remove testflag from fd1 and see if it gets removed from fd2 too.
       */
      setflag = 0;
   else
      /*
       * add testflag to fd1 and see if it gets added to fd2 too.
       */
      setflag = 1;

   SASSERTX(setflag != flags1);

   rc1    = setsockopt(fd1, SOL_SOCKET, testflag, &setflag, sizeof(setflag));
   len1   = sizeof(newflags1);
   rc1    = getsockopt(fd1, SOL_SOCKET, testflag, &newflags1, &len1);
   errno1 = errno;

   len2   = sizeof(newflags2);
   rc2    = getsockopt(fd2, SOL_SOCKET, testflag, &newflags2, &len2);
   errno2 = errno;

   if (newflags1 == newflags2) {
      slog(LOG_DEBUG, "%s: newflags1 = newflags2 -> %d is a dup of %d",
      function, fd1, fd2);

      isdup = 1;
   }
   else if (rc1 == -1 && rc2 == rc1
   &&       errno1 == errno2) {
      slog(LOG_DEBUG, "%s: flagcheck failed, but rc (%d) and errno (%d) is "
                      "the same, so assuming %d is a dup of %d, or that "
                      "any failed socket is as good as any other failed "
                      "socket.  Not many other choices",
                      function, rc1, errno1, fd1, fd2);
      isdup = 1;
   }
   else
      isdup = 0;

   slog(LOG_DEBUG, "%s: final test indicates fd %d %s of fd %d",
   function, fd1, isdup ? "is a dup" : "is not a dup", fd2);

   /* restore flags back to original. */
   SASSERTX(flags1 == flags2);
   rc1 = setsockopt(fd1, SOL_SOCKET, testflag, &flags1, sizeof(flags1));
   rc2 = setsockopt(fd2, SOL_SOCKET, testflag, &flags2, sizeof(flags2));

   return isdup;
}


void
socks_addrinit(void)
{
   const char *function = "socks_addrinit()";
#if HAVE_PTHREAD_H
   pthread_mutexattr_t attr;
   void *lpt;
#endif /* HAVE_PTHREAD_H */

#ifdef HAVE_VOLATILE_SIG_ATOMIC_T
   static sig_atomic_t inited;
#else
   static volatile sig_atomic_t inited;
#endif /* HAVE_VOLATILE_SIG_ATOMIC_T */

   if (inited)
      return;

   if (doing_addrinit)
      /*
       * XXX should really be sched_yield() or similar if initing, unless
       * the thread initing is ours.  If the thread initing is ours,
       * we can just return, to handle recursive problems during init.
       */
      return;

   doing_addrinit = 1; /*
                        * XXX should be pthread_self() or similar, but how can
                        * we call that before we have finished initing? :-/
                        */

   SASSERTX(socksfdv == NULL && dv == NULL);

   if ((socksfdv = malloc(sizeof(*socksfdv) * FDV_INITSIZE)) == NULL)
      serr(EXIT_FAILURE,
           "%s: failed to alloc %lu bytes for socksify socksfd memory",
           function, (unsigned long)(sizeof(*socksfdv) * 64));

   if ((dv = malloc(sizeof(*dv) * FDV_INITSIZE)) == NULL)
      serr(EXIT_FAILURE,
           "%s: failed to alloc %lu bytes for socksify dv memory",
           function, (unsigned long)(sizeof(*dv) * 64));

   /* init new objects */
   while (socksfdc < FDV_INITSIZE)
      socksfdv[socksfdc++] = socksfdinit;

   /* init all to -1, a illegal value for a descriptor. */
   while (dc < FDV_INITSIZE)
      dv[dc++] = -1;


#if HAVE_PTHREAD_H
   if (socks_getenv("SOCKS_DISABLE_THREADLOCK", istrue) != NULL)
      slog(LOG_DEBUG, "pthread locking off, manually disabled in environment");
   else {
#if HAVE_RTLD_NEXT
      /*
       * XXX following test will always perceive the application as being
       * threaded if lib(d)socks depends on libpthread, which might be the
       * case if e.g., some gssapi libs require this library.
       */
      if (dlsym(RTLD_NEXT, SYMBOL_PT_ATTRINIT) != NULL) {
         /*
          * appears to be a threaded application, obtain function pointers.
          */

         lpt = RTLD_NEXT;
         slog(LOG_DEBUG,
              "pthread locking desired, threaded application (rtld)");
      }
      else {
         slog(LOG_DEBUG,
              "pthread locking off, non-threaded application (rtld)");
         lpt = NULL;
      }

#else
      /* load libpthread */
      if ((lpt = dlopen(LIBRARY_PTHREAD, RTLD_LAZY)) == NULL) {
         swarn("%s: compile time configuration error?  "
         "Failed to open \"%s\": %s", function, LIBRARY_PTHREAD, dlerror());
      }
#endif /* !HAVE_RTLD_NEXT */

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

         if ((pt_unlock = (PT_UNLOCK_FUNC_T)dlsym(lpt, SYMBOL_PT_UNLOCK))
         == NULL)
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
      else {
         slog(LOG_DEBUG, "pthread locking enabled");

         if (socks_pthread_mutexattr_init(&attr) != 0)
            serr(EXIT_FAILURE, "%s: mutexattr_init() failed", function);

         if (socks_pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)
         != 0)
            swarn("%s: mutex_settype(PTHREAD_MUTEX_ERRORCHECK) failed",
            function);

         if (socks_pthread_mutex_init(&addrmutex, &attr) != 0) {
            swarn("%s: mutex_init() failed", function);

            if (socks_pthread_mutex_init(&addrmutex, NULL) != 0)
               serr(EXIT_FAILURE, "%s: mutex_init() failed", function);
         }
      }
#endif /* HAVE_PTHREAD_H */
   }

   inited         = 1;
   doing_addrinit = 0;
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
   id->id.pid = getpid();

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
