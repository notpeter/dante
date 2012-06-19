/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2008, 2009, 2010, 2011, 2012
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
"$Id: hostcache.c,v 1.83 2012/06/01 20:23:05 karls Exp $";

#define HOSTENT_MAX_ALIASES (2)   /* max h_aliases or h_addr_list */

#if !SOCKS_CLIENT

typedef struct {
   unsigned       allocated:1;      /* entry allocated?                       */
   unsigned       notfound:1;       /* looked up address/name was not found.  */
   time_t         written;          /* time this entry was created.           */

   char           name[MAXHOSTNAMELEN]; /*
                                         * name used to fetch this entry, or
                                         * hostent->h_name if an address was
                                         * used.
                                         */

   struct in_addr ipv4;                  /*
                                          * addr used to fetch this entry, or
                                          * hostent->h_addr if a name was
                                          * used.
                                          */

   struct hostent hostent;

   /*
    * memory for hostent pointers.  The contents of hostent is set to
    * point to the corresponding area here, rather than allocating
    * it on the stack.
    */
   char _h_name[MAXHOSTNAMELEN];
   char *_h_aliases[HOSTENT_MAX_ALIASES + 1];    /* +1; NULL-terminated. */
   char *_h_addr_list[HOSTENT_MAX_ALIASES + 1];  /* +1; NULL-terminated. */

   char _h_aliasesmem[HOSTENT_MAX_ALIASES][MAXHOSTNAMELEN];
   char _h_addr_listmem[HOSTENT_MAX_ALIASES][MAX(sizeof(struct in_addr),
                                                 sizeof(struct in6_addr))];
} hostentry_t;

/*
 * hostname/ipaddress cache.  Shared among all processes.
 */
static hostentry_t *hostcache;

static int dnsfd = -1; /*
                        * Try to reserve one fd for dns-resolving.
                        * If the libresolv-call fails, and the errno
                        * indicates it is because there are to many
                        * files open, close this fd and try again.
                        * It is of course not certain libresolv-call
                        * will return with errno indicating this, but
                        * hopefully it will.
                        *
                        * Only works for the main process, as the children
                        * won't know about this descriptor and will close it.
                        * Main process may need to use it when parsing the
                        * config file however.
                        */


#undef gethostbyaddr
#undef gethostbyname

#if SOCKSLIBRARY_DYNAMIC

#define gethostbyaddr(addr, len, type)   sys_gethostbyaddr(addr, len, type)
#define gethostbyname(name)              sys_gethostbyname(name)

#endif /* SOCKSLIBRARY_DYNAMIC */


static hostentry_t *
hostentcopy(hostentry_t *to, const struct hostent *from,
            const size_t maxaliases);
/*
 * Copies the values in "from" into to, which must have enough memory
 * previously allocated.
 * "maxaliases" gives the maximum number of entries from->h_aliases and
 * from->h_addr_list to copy.
 * The only reason this function may fail is if "from" is too big, i.e.
 * has names that are too long or similar.
 *
 * Note that this function does not set to->ipv4 or to->h_name.
 * This must be done by caller.  XXX why?
 *
 * Returns "to" on success, NULL on failure.
*/

static int
hosthash(const char *name, size_t size);
/*
 * Calculates a hash value for "name" and returns it's value.
 * Size of hash table is given by "size".
*/

static int
addrhash(in_addr_t addr, size_t size);
/*
 * Calculates a hash value for "addr" and returns it's value.
 * Size of hash table is given by "size".
*/

#endif /* !SOCKS_CLIENT */

static int
hostentistoobig(const struct hostent *hostent, const size_t maxaliases);
/*
 * "maxaliases" gives the maximum number of hostent->h_aliases and
 * h_addr_list entries we can handle.
 *
 * If "hostent" is bigger than the max we can handle, return true.
 * If not, return false.
 */

static char **
listrealloc(char ***old, char ***new, int length);
/*
 * Reallocates "old" and copies in the contents of "new".
 * The last element of both "old" and "new" must be NULL.
 * If "length" is less than 0, each element is assumed to
 * be NUL terminated, otherwise "length" gives the total length
 * of every string.
 *
 * Returns:
 *      On success: "**old", with the contents of "new".
 *      On failure: NULL.
*/


struct hostent *
hostentdup(hostent, duped, maxaliases)
   struct hostent *hostent;
   struct hostent *duped;
   ssize_t maxaliases;
{
   static struct hostent dupedinit;

   if (duped == NULL) {
      if ((duped = malloc(sizeof(*duped))) == NULL)
         return NULL;

      *duped = dupedinit;

      if ((duped->h_name = strdup(hostent->h_name)) == NULL) {
         hostentfree(duped);
         return NULL;
      }

      if (listrealloc(&duped->h_aliases, &hostent->h_aliases, -1) == NULL) {
         hostentfree(duped);
         return NULL;
      }

      if (listrealloc(&duped->h_addr_list,
                      &hostent->h_addr_list,
                      hostent->h_length) == NULL) {
         hostentfree(duped);
         return NULL;
      }
   }
   else {
      ssize_t i;

      SASSERTX(maxaliases >= 0);

      if (hostentistoobig(hostent, maxaliases))
         return NULL;

      strcpy(duped->h_name, hostent->h_name);

      for (i = 0; i < maxaliases && hostent->h_aliases[i] != NULL; ++i)
         strcpy(duped->h_aliases[i], hostent->h_aliases[i]);
      duped->h_aliases[MIN(i, maxaliases - 1)] = NULL;

      for (i = 0; i < maxaliases && hostent->h_addr_list[i] != NULL; ++i)
         memcpy(duped->h_addr_list[i],
                hostent->h_addr_list[i],
                hostent->h_length);
      duped->h_addr_list[MIN(i, maxaliases - 1)] = NULL;
   }

   duped->h_addrtype = hostent->h_addrtype;
   duped->h_length   = hostent->h_length;

   return duped;
}

void
hostentfree(hostent)
   struct hostent *hostent;
{
   char **p;

   if (hostent == NULL)
      return;

   free(hostent->h_name);
   hostent->h_name = NULL;

   if (hostent->h_aliases != NULL)
      for (p = hostent->h_aliases; *p != NULL; ++p)
         free(*p);
   free(hostent->h_aliases);
   hostent->h_aliases = NULL;

   if (hostent->h_addr_list != NULL)
      for (p = hostent->h_addr_list; *p != NULL; ++p)
         free(*p);

   free(hostent->h_addr_list);
   hostent->h_addr_list = NULL;
   free(hostent);
}

static char **
listrealloc(old, new, length)
   char ***old;
   char ***new;
   int length;
{
   int i, oldi, newi;

   /* entries we can reallocate, starting at 0. */
   oldi = 0;
   if (*old != NULL)
      while ((*old)[oldi] != NULL)
         ++oldi;

   newi = 0;
   while ((*new)[newi] != NULL)
      ++newi;

   for (i = newi; i < oldi; ++i)
      free((*old)[i]);

   if ((*old = realloc(*old, sizeof(**new) * (newi + 1))) == NULL)
      return NULL;

   for (newi = 0; (*new)[newi] != NULL; ++newi, --oldi) {
      if (((*old)[newi] = realloc(oldi > 0 ? (*old)[newi] : NULL,
                                  length < 0 ?
                                      ((size_t)strlen((*new)[newi]) + 1)
                                    : (size_t)length))== NULL)
         return NULL;

      if (length < 0)
         strcpy((*old)[newi], (*new)[newi]);
      else
         memcpy((*old)[newi], (*new)[newi], (size_t)length);
   }

   (*old)[newi] = NULL;

   return *old;
}

static int
hostentistoobig(hostent, maxaliases)
   const struct hostent *hostent;
   const size_t maxaliases;
{
   const char *function = "hostentistoobig()";
   size_t i;

   if ((size_t)hostent->h_length
   > MAX(sizeof(struct in_addr), sizeof(struct in6_addr))) {
      swarnx("%s: h_length of %s is %d bytes long, max expected is %lu",
             function, hostent->h_name, hostent->h_length,
             (unsigned long)MAX(sizeof(struct in_addr),
                                sizeof(struct in6_addr)));

      return 1;
   }

   if (strlen(hostent->h_name) >= MAXHOSTNAMELEN) {
      swarnx("%s: name %s is %lu bytes long, max expected is %d",
             function, hostent->h_name, (unsigned long)strlen(hostent->h_name),
             MAXHOSTNAMELEN - 1);

      return 1;
   }

   for (i = 0; i < maxaliases && hostent->h_aliases[i] != NULL; ++i) {
      if (strlen(hostent->h_aliases[i]) >= MAXHOSTNAMELEN) {
         swarnx("%s: name %s is %lu bytes long, max expected is %d",
                function, hostent->h_aliases[i],
                (unsigned long)strlen(hostent->h_aliases[i]),
                MAXHOSTNAMELEN - 1);

         return 1;
      }
   }

   return 0;
}


#if !SOCKS_CLIENT

void
hostcachesetup(void)
{
   const char *function = "hostcachesetup()";

   if ((sockscf.hostfd = socks_mklock(SOCKD_SHMEMFILE, NULL, 0)) == -1)
      serr(EXIT_FAILURE, "%s: socks_mklock(%s)", function, SOCKD_SHMEMFILE);

   if ((hostcache = sockd_mmap(sizeof(*hostcache) * SOCKD_HOSTCACHE,
                               sockscf.hostfd,
                               1)) == NULL)
      serr(EXIT_FAILURE, "%s: failed to create hostcache", function);


   if (dnsfd == -1)
      dnsfd = socket(AF_LOCAL, SOCK_DGRAM, 0);
}


struct hostent *
cgethostbyname(name)
   const char *name;
{
   const char *function = "cgethostbyname()";
   static hostentry_t hostentrymem;
   static size_t i;
   static unsigned long hit, miss;
   static int count;
   const time_t timenow = time(NULL);
   hostentry_t *freehost;
   struct hostent *hostent;
   int hashi;

   if (count++ % SOCKD_CACHESTAT == 0)
      slog(LOG_DEBUG, "%s, name: %s: hit: %lu, miss: %lu",
           function, name, hit, miss);

   if (strlen(name) >= sizeof(freehost->name)) {
      swarnx("%s: hostname \"%s\" is too long.  Max length is %lu",
              function, name, (unsigned long)sizeof(freehost->name) - 1);

      return NULL;
   }

   socks_lock(sockscf.hostfd, 0, 1);

   if (i < SOCKD_HOSTCACHE
   &&  hostcache[i].allocated
   &&  difftime(timenow, hostcache[i].written) < SOCKD_CACHETIMEOUT
   &&  strcasecmp(hostcache[i].name, name) == 0) {
      ++hit;

      if (hostcache[i].notfound) {
         socks_unlock(sockscf.hostfd);
         return NULL;
      }

      hostentcopy(&hostentrymem, &hostcache[i].hostent, HOSTENT_MAX_ALIASES);

      socks_unlock(sockscf.hostfd);
      return &hostentrymem.hostent;
   }

   hashi = hosthash(name, SOCKD_HOSTCACHE);
   for (i = hashi, freehost = NULL; i < SOCKD_HOSTCACHE; ++i) {
      if (!hostcache[i].allocated) {
         if (freehost == NULL)
            freehost = &hostcache[i];

         continue;
      }

      if (strcasecmp(hostcache[i].name, name) == 0) {
         if (difftime(timenow, hostcache[i].written) >= SOCKD_CACHETIMEOUT) {
            freehost = &hostcache[i];
            ++miss;

            break;
         }

         ++hit;

         if (hostcache[i].notfound) {
            socks_unlock(sockscf.hostfd);
            return NULL;
         }

         /*
          * Need to copy since another process could overwrite the entry
          * the hostcache.
          */
         hostentcopy(&hostentrymem, &hostcache[i].hostent, HOSTENT_MAX_ALIASES);

         socks_unlock(sockscf.hostfd);
         return &hostentrymem.hostent;
      }
   }

   if (i >= SOCKD_HOSTCACHE)
      ++miss;

   socks_unlock(sockscf.hostfd);

   if ((hostent = gethostbyname(name)) == NULL)
      if (ERRNOISNOFILE(errno) && dnsfd != -1) {
         close(dnsfd);
         hostent = gethostbyname(name);
         dnsfd   = socket(AF_LOCAL, SOCK_DGRAM, 0);
      }

   socks_lock(sockscf.hostfd, 1, 1);

   if (freehost == NULL) {
      for (i = hashi, freehost = &hostcache[i]; i < SOCKD_HOSTCACHE; ++i) {
         if (difftime(timenow, hostcache[i].written) >= SOCKD_CACHETIMEOUT) {
            freehost = &hostcache[i];
            break;
         }

         if (difftime(hostcache[i].written, freehost->written) < 0)
            freehost = &hostcache[i]; /* not expired, but oldest so far. */
      }
   }

   SASSERTX(freehost != NULL);

   if (hostent == NULL) {
      static struct hostent hostentmem;
      static char *addrlist[1];

      hostent              = &hostentmem;
      hostent->h_name      = (char *)name;
      hostent->h_aliases   = addrlist;
      hostent->h_addr_list = addrlist;
      hostent->h_length    = sizeof(struct in_addr);

      freehost->notfound   = 1;
   }
   else
      freehost->notfound = 0;

   if (hostentcopy(freehost, hostent, HOSTENT_MAX_ALIASES) == NULL) {
      swarnx("%s: hostentcopy() failed for hostname %s", function, name);

      socks_unlock(sockscf.hostfd);
      return NULL;
   }

   strcpy(freehost->name, name);
   hostent->h_name = freehost->name;

   if (!freehost->notfound)
      memcpy(&freehost->ipv4, hostent->h_addr, hostent->h_length);

   freehost->written   = timenow;
   freehost->allocated = 1;

   socks_unlock(sockscf.hostfd);

   if (freehost->notfound)
      return NULL;

   return hostent; /*
                    * since it may contain more than HOSTENT_MAX_ALIASES.
                    * If user later retrieves our cached version, he will
                    * only get up to HOSTENT_MAX_ALIASES though.
                    */
}

struct hostent *
cgethostbyaddr(_addr, len, type)
   const void *_addr;
   socklen_t len;
   int type;
{
   const char *function = "cgethostbyaddr()";
   static struct hostent *hostent;
   static hostentry_t hostentrymem;
   static unsigned long hit, miss;
   static size_t i;
   static int count;
   const time_t timenow = time(NULL);
   hostentry_t *freehost;
   char addr[sizeof(struct in_addr)];
   int hashi;

   if (count++ % SOCKD_CACHESTAT == 0)
      slog(LOG_DEBUG, "%s: addr: %s, hit: %lu, miss: %lu",
           function, inet_ntoa(*((const struct in_addr *)_addr)), hit, miss);


   SASSERTX(type == AF_INET);
   SASSERTX(len <= sizeof(addr));
   memcpy(addr, _addr, len); /* _addr is const */

   socks_lock(sockscf.hostfd, 0, 1);

   if (i < SOCKD_HOSTCACHE
   &&  hostcache[i].allocated
   &&  hostcache[i].ipv4.s_addr == ((const struct in_addr *)addr)->s_addr
   &&  difftime(timenow, hostcache[i].written) < SOCKD_CACHETIMEOUT) {
      ++hit;

      if (hostcache[i].notfound) {
         socks_unlock(sockscf.hostfd);
         return NULL;
      }

      hostentcopy(&hostentrymem, &hostcache[i].hostent, HOSTENT_MAX_ALIASES);

      socks_unlock(sockscf.hostfd);
      return &hostentrymem.hostent;
   }

   hashi = addrhash(((const struct in_addr *)addr)->s_addr, SOCKD_HOSTCACHE);
   for (i = hashi, freehost = NULL; i < SOCKD_HOSTCACHE; ++i) {
      if (!hostcache[i].allocated) {
         if (freehost == NULL)
            freehost = &hostcache[i];

         continue;
      }

      if (hostcache[i].ipv4.s_addr == ((const struct in_addr *)addr)->s_addr) {
         if (difftime(timenow, hostcache[i].written) >= SOCKD_CACHETIMEOUT) {
            freehost = &hostcache[i];
            ++miss;

            break;
         }

         ++hit;

         if (hostcache[i].notfound) {
            socks_unlock(sockscf.hostfd);
            return NULL;
         }

         /*
          * Need to copy since another process could overwrite the entry
          * the hostcache.
          */
         hostentcopy(&hostentrymem, &hostcache[i].hostent, HOSTENT_MAX_ALIASES);

         socks_unlock(sockscf.hostfd);
         return &hostentrymem.hostent;
      }
   }

   if (i >= SOCKD_HOSTCACHE)
      ++miss;

   socks_unlock(sockscf.hostfd);
   if ((hostent = gethostbyaddr(addr, len, type)) == NULL)
      if (ERRNOISNOFILE(errno) && dnsfd != -1) {
         close(dnsfd);
         hostent = gethostbyaddr(addr, len, type);
         dnsfd   = socket(AF_LOCAL, SOCK_DGRAM, 0);
      }

   socks_lock(sockscf.hostfd, 1, -1);

   if (freehost == NULL) {
      for (i = hashi, freehost = &hostcache[i]; i < SOCKD_HOSTCACHE; ++i) {
         if (difftime(timenow, hostcache[i].written) >= SOCKD_CACHETIMEOUT) {
            freehost = &hostcache[i];
            break;
         }

         if (difftime(hostcache[i].written, freehost->written) < 0)
            freehost = &hostcache[i]; /* not expired, but oldest so far. */
      }
   }

   if (hostent == NULL) {
      static struct hostent hostentmem;
      static char *addrlist[1];

      hostent              = &hostentmem;
      hostent->h_aliases   = addrlist;
      hostent->h_addr_list = addrlist;
      hostent->h_name      = "";
      hostent->h_length    = sizeof(struct in_addr);

      freehost->notfound   = 1;
   }
   else
      freehost->notfound = 0;

   if (hostentcopy(freehost, hostent, HOSTENT_MAX_ALIASES) == NULL) {
      char straddr[MAXSOCKADDRSTRING];

      inet_ntop(type, addr, straddr, len);
      swarnx("%s: hostentcopy() failed for address %s", function, straddr);

      socks_unlock(sockscf.hostfd);
      return NULL;
   }

   memcpy(&freehost->ipv4, addr, len);

   if (!freehost->notfound) {
      SASSERTX(strlen(hostent->h_name) < sizeof(freehost->name));
      strcpy(freehost->name, hostent->h_name);
   }

   freehost->written   = timenow;
   freehost->allocated = 1;

   socks_unlock(sockscf.hostfd);

   if (freehost->notfound)
      return NULL;

   return hostent; /* since it may contain more than HOSTENT_MAX_ALIASES. */
}

static int
hosthash(name, size)
   const char *name;
   size_t size;
{
   char *end;
   unsigned int value;

   /* don't bother scanning past second dot. */
   if ((end = strchr(name, '.')) != NULL)
      end = strchr(end + 1, '.');
   if (end == NULL) /* <= one dots in name. */
      end = strchr(name, NUL);

   SASSERTX(name <= end);
   value = 0;
   while (name != end) {
      value = (value << 5) + *name;   /* MAW - DS&A: Horner's rule. */
      ++name;
   }

   return value % size;
}

static int
addrhash(addr, size)
   in_addr_t addr;
   size_t size;
{

   return addr % size;
}

static hostentry_t *
hostentcopy(to, from, maxaliases)
   hostentry_t *to;
   const struct hostent *from;
   const size_t maxaliases;
{
   const char *function = "hostentcopy()";
   size_t i;

   if (hostentistoobig(from, HOSTENT_MAX_ALIASES))
      return NULL;

   to->hostent.h_addrtype = from->h_addrtype;
   to->hostent.h_length   = from->h_length;

   to->hostent.h_name     = to->_h_name;
   strcpy(to->hostent.h_name, from->h_name);

   for (i = 0; i < maxaliases && from->h_aliases[i] != NULL; ++i) {
      to->_h_aliases[i] = to->_h_aliasesmem[i];
      strcpy(to->_h_aliases[i], from->h_aliases[i]);
   }
   to->_h_aliases[MIN(i, maxaliases - 1)] = NULL;
   to->hostent.h_aliases                  = to->_h_aliases;

   for (i = 0; i < maxaliases && from->h_addr_list[i] != NULL; ++i) {
      to->_h_addr_list[i] = to->_h_addr_listmem[i];
      memcpy(to->_h_addr_list[i], from->h_addr_list[i], from->h_length);
   }
   to->_h_addr_list[MIN(i, maxaliases - 1)] = NULL;
   to->hostent.h_addr_list                  = to->_h_addr_list;

   return to;
}

#endif /* !SOCKS_CLIENT */
