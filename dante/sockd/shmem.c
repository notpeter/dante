/*
 * Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2010, 2011,
 *               2012
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
"$Id: shmem.c,v 1.86 2012/06/01 20:23:06 karls Exp $";

/*
 * Mother needs to create and fill in the correct contents initially.
 * Afterwards she can detach from the memory it, and not touch it again
 * until exit or sighup, at which point she may need to save those segments
 * that are still use (if SIGHUP), or delete those that are no longer in use.
 */
#define HANDLE_SHMCR(ismother, rule, memfield, idfield, fdfield, key)          \
do {                                                                           \
   if ((ismother)) {                                                           \
      shmem_object_t *mem;                                                     \
      const char *fname = sockd_getshmemname((key));                           \
      int rc;                                                                  \
                                                                               \
      if (((rule)->fdfield                                                     \
      = open(fname, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)) == -1)      \
         serr(EXIT_FAILURE, "%s: failed to create %s", function, fname);       \
                                                                               \
      slog(LOG_DEBUG, "%s: will use filename %s for key %ld when creating "    \
                      "shmem segment for " #memfield " in rule %lu",           \
                       function, fname, (key), (unsigned long)(rule)->number); \
                                                                               \
      if ((mem = sockd_mmap(sizeof(*(rule)->memfield), (rule)->fdfield, 1))    \
      == NULL)                                                                 \
         serr(EXIT_FAILURE, "%s: sockd_mmap of size %lu failed",               \
         function, (unsigned long)sizeof(*(rule)->memfield));                  \
                                                                               \
      /* replace the ordinary memory with shared memory. */                    \
      *mem = *(rule)->memfield;                                                \
      free((rule)->memfield);                                                  \
      (rule)->memfield = mem;                                                  \
                                                                               \
      rc = close((rule)->fdfield);                                             \
      SASSERTX(rc == 0);                                                       \
   }                                                                           \
   else                                                                        \
      (rule)->memfield = NULL;                                                 \
                                                                               \
   (rule)->idfield  = (key);                                                   \
                                                                               \
   slog(LOG_DEBUG, "%s: %s " #idfield " %ld for rule #%lu, using key %ld",     \
                    function,                                                  \
                    (ismother) ? "allocated" : "got",                          \
                    (rule)->idfield, (unsigned long)(rule)->number, (key));    \
} while (/* CONSTCOND */ 0)

#define HANDLE_SHMAT(rule, memfield, idfield, fdfield)                         \
do {                                                                           \
   const char *fname = sockd_getshmemname((rule)->idfield);                    \
   int rc;                                                                     \
                                                                               \
   SASSERTX((rule)->memfield == NULL);                                         \
                                                                               \
   if (((rule)->fdfield = open(fname, O_RDWR)) == -1) {                        \
      swarn("%s: failed to open %s for attaching to " #idfield " %ld",         \
      function, fname, (rule)->idfield);                                       \
                                                                               \
      (rule)->memfield = NULL;                                                 \
      (rule)->idfield  = 0;                                                    \
      break;                                                                   \
   }                                                                           \
                                                                               \
   if (((rule)->memfield                                                       \
   = sockd_mmap(sizeof(*(rule)->memfield), (rule)->fdfield, 0)) == NULL) {     \
      swarn("%s: failed to mmap " #idfield " shmem segment %ld from file %s",  \
      function, (rule)->idfield, fname);                                       \
                                                                               \
      close((rule)->fdfield);                                                  \
      (rule)->memfield = NULL;                                                 \
      (rule)->idfield  = 0;                                                    \
      break;                                                                   \
   }                                                                           \
                                                                               \
   slog(LOG_DEBUG, "%s: attached to " #idfield " %ld at %p, "                  \
                   "%lu clients, filename %s",                                 \
                   function,                                                   \
                   (rule)->idfield,                                            \
                   (rule)->memfield,                                           \
                   (unsigned long)(rule)->memfield->mstate.clients, fname);    \
                                                                               \
   rc = close((rule)->fdfield);                                                \
   SASSERTX(rc == 0);                                                          \
} while (/* CONSTCOND */ 0)

#define HANDLE_SHMDT(rule, memfield, idfield, fdfield)                         \
do {                                                                           \
   SASSERTX((rule)->idfield != 0);                                             \
   SASSERTX((rule)->memfield != NULL);                                         \
                                                                               \
   slog(LOG_DEBUG,                                                             \
        "%s: detaching from " #idfield " %ld at %p with %lu clients",          \
        function,                                                              \
        (rule)->idfield,                                                       \
        (rule)->memfield,                                                      \
        (unsigned long)(rule)->memfield->mstate.clients);                      \
                                                                               \
   if (munmap((rule)->memfield, sizeof(*rule->memfield)) != 0)                 \
      swarn("%s: detach from " #idfield " shmem segment %ld (%p) failed",      \
      function, (rule)->idfield, rule->memfield);                              \
                                                                               \
   (rule)->memfield = NULL;                                                    \
   (rule)->fdfield  = -1;                                                      \
} while (/* CONSTCOND */ 0)

void
sockd_shmdt(rule, objects)
   rule_t *rule;
   const int objects;
{
   const char *function = "sockd_shmdt()";

   if ((objects & SHMEM_BW) && rule->bw_shmid)
      HANDLE_SHMDT(rule, bw, bw_shmid, bw_fd);

   if ((objects & SHMEM_SS) && rule->ss_shmid)
      HANDLE_SHMDT(rule, ss, ss_shmid, ss_fd);
}

void
sockd_shmat(rule, objects)
   rule_t *rule;
   const int objects;
{
   const char *function = "sockd_shmat()";

   if (objects & SHMEM_BW) {
      if (rule->bw_shmid)
         HANDLE_SHMAT(rule, bw, bw_shmid, bw_fd);
#if DEBUG
      else
         slog(LOG_DEBUG,
              "%s: no bw_shmid we need to (re)attach to for rule #%lu",
              function, (unsigned long)rule->number);
#endif /* DEBUG */
   }

   if (objects & SHMEM_SS) {
      if (rule->ss_shmid)
         HANDLE_SHMAT(rule, ss, ss_shmid, ss_fd);
#if DEBUG
      else
         slog(LOG_DEBUG,
              "%s: no ss_shmid we need to (re)attach to for rule #%lu",
               function, (unsigned long)rule->number);
#endif /* DEBUG */
   }
}

char *
sockd_getshmemname(id)
   const long id;
{
/*   const char *function = "sockd_getshmemname()"; */
   static char name[PATH_MAX];

   SASSERTX(*sockscf.shmem_fnamebase != NUL);

   snprintf(name, sizeof(name), "%s.%ld", sockscf.shmem_fnamebase, id);
   return name;
}

void *
sockd_mmap(size, fd, docreate)
   size_t size;
   const int fd;
   const int docreate;
{
   const char *function = "sockd_mmap()";
   void *mem;

   if (size == 0)
      return NULL;

   if (docreate) {
      if (lseek(fd, size - 1, SEEK_SET) == -1) {
         swarn("%s: lseek()", function);
         return NULL;
      }

      if (write(fd, "", sizeof("")) != sizeof("")) {
         swarn("%s: write()", function);
         return NULL;
      }
   }

   slog(LOG_DEBUG, "%s: mmap(2)'ing %lu bytes in fd %d",
        function, (unsigned long)size, fd);

   if ((mem = mmap(NULL,
                   size,
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED,
                   fd,
                   0)) == MAP_FAILED) {
      swarn("%s: mmap() of %lu bytes failed", function, (unsigned long)size);
      return NULL;
   }

   return mem;
}

void
shmem_unuse(object, lock)
   shmem_object_t *object;
   int lock;
{
   const char *function = "shmem_unuse()";

   if (object == NULL)
      return;

   if (lock != -1)
      socks_lock(lock, 1, 1);

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: lock = %d, clients = %lu, object = %p",
                      function,
                      lock,
                      (unsigned long)object->mstate.clients,
                      object);

   SASSERTX(object->mstate.clients > 0);
   --object->mstate.clients;

   if (lock != -1)
      socks_unlock(lock);
}

void
shmem_use(object, lock)
   shmem_object_t *object;
   int lock;
{
   const char *function = "shmem_use()";

   if (object == NULL)
      return;

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: lock = %d, new # of clients = %lu, "
                      "rule = %lu, object = %p",
                      function,
                      lock,
                      (unsigned long)object->mstate.clients + 1,
                      (unsigned long)object->mstate.rulenumber,
                      object);

   if (lock != -1)
      socks_lock(lock, 1, 1);

   SASSERTX(object->mstate.clients >= 0);
   ++object->mstate.clients;

   if (lock != -1)
      socks_unlock(lock);
}

void
shmem_setup(void)
{
   const char *function = "shmem_setup()";
   static long lastkey;

   if (sockscf.shmemfd == -1) { /* first time we set things up. */
      char *p;

      SASSERTX(pidismother(sockscf.state.pid) == 1);

      /* as good as starting point as any. */
      lastkey = 1;

      if (sizeof(sockscf.shmem_fnamebase) < sizeof(SOCKD_SHMEMFILE))
         serrx(EXIT_FAILURE,
               "%s: SOCKD_SHMEMFILE (%s) is %lu bytes too long, max is %lu",
               function,
               SOCKD_SHMEMFILE,
               (unsigned long)( sizeof(sockscf.shmem_fnamebase)
                               - sizeof(SOCKD_SHMEMFILE)),
               (unsigned long)sizeof(SOCKD_SHMEMFILE));

      strcpy(sockscf.shmem_fnamebase, SOCKD_SHMEMFILE);

      /*
       * First check that this works ok.  If e.g., user has changed some
       * config-files and made strings too long, it might fail.
       */
      if ((sockscf.shmemfd = socks_mklock(sockscf.shmem_fnamebase,
                                          sockscf.shmem_fnamebase,
                                          sizeof(sockscf.shmem_fnamebase)))
      == -1)
         serr(EXIT_FAILURE, "%s: socks_mklock(%s)",
              function, sockscf.shmem_fnamebase);

      if ((p = sockd_getshmemname(lastkey)) == NULL)
         serrx(EXIT_FAILURE, "%s: failed to generate shmem filename based on "
                             "\"%s\" and id %ld",
                             function, sockscf.shmem_fnamebase, lastkey);

      if (strlen(p) >= sizeof(sockscf.shmem_fnamebase))
         serrx(EXIT_FAILURE, "%s: shmem filename is %ld bytes too long."
                             "Reduce the length of SOCKD_SHMEMFILE",
                             function,
                             (unsigned long)(strlen(p) + 1)
                                             - sizeof(sockscf.shmem_fnamebase));

      if ((sockscf.shmeminfo
      = sockd_mmap(sizeof(*sockscf.shmeminfo), sockscf.shmemfd, 1)) == NULL)
         serr(EXIT_FAILURE, "%s: failed to mmap shmeminfo", function);

      /* can unlink this file; all children will inherit the fd. */
      if (unlink(sockscf.shmem_fnamebase) != 0)
         serr(EXIT_FAILURE, "%s: failed to unlink %s",
         function, sockscf.shmem_fnamebase);

   }

   socks_lock(sockscf.shmemfd, 1, 1);

   if (pidismother(sockscf.state.pid) == 1)
      /*
       * only mother updates the key value in shmem.  The children
       * only read it.
       */
      sockscf.shmeminfo->firstkey = lastkey + 1;

   lastkey = mem2shmem(sockscf.shmeminfo->firstkey);

   socks_unlock(sockscf.shmemfd);
}

unsigned long
mem2shmem(firstkey)
   const unsigned long firstkey;
{
   const char *function = "mem2shmem()";
   rule_t *rule;
   rule_t *rulev[]    = { sockscf.crule,
#if HAVE_SOCKS_RULES
                          sockscf.srule
#endif /* HAVE_SOCKS_RULES */
                               };
   int ismother;
   unsigned long nextkey;
   size_t i;

   /*
    * Only main mother allocates the memory.  Children just
    * get the shmid and attach to the memory as needed later on.
    * Mother makes sure all they keys are in consecutive order starting
    * from the passed "firstkey" argument, so children just need to
    * increment it to get the shmid of the next object.
    */
   ismother = (pidismother(sockscf.state.pid) == 1);

   nextkey = firstkey;
   for (i = 0; i < ELEMENTS(rulev); ++i) {
      rule = rulev[i];

      while (rule != NULL) {
         if (rule->bw != NULL) {
            HANDLE_SHMCR(ismother, rule, bw, bw_shmid, bw_fd, nextkey);
            ++nextkey;
         }

         if (rule->ss != NULL) {
            HANDLE_SHMCR(ismother, rule, ss, ss_shmid, ss_fd, nextkey);
            ++nextkey;
         }


         if (ismother) {
            /*
             * Ok, created and values are set.  Now we can detach.
             */

            /* mother also needs to save these for e.g. sighup handling. */
            const int bw_shmid = rule->bw_shmid;
            const int ss_shmid = rule->ss_shmid;

            sockd_shmdt(rule, SHMEM_ALL);

            rule->bw_shmid = bw_shmid;
            rule->ss_shmid = ss_shmid;
         }

         rule = rule->next;
      }
   }

   slog(LOG_DEBUG, "%s: ok, allocated %lu shared memory id%s, first key is %ld",
                   function,
                   nextkey - firstkey,
                   nextkey - firstkey == 1 ? "" : "s",
                   firstkey);

   return nextkey;
}
