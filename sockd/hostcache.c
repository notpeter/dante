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
"$Id: hostcache.c,v 1.24 2003/07/01 13:21:29 michaels Exp $";

__BEGIN_DECLS

#if SOCKS_SERVER

#undef gethostbyaddr
#undef gethostbyname

#if SOCKSLIBRARY_DYNAMIC

#define gethostbyaddr(addr, len, type)	sys_gethostbyaddr(addr, len, type)
#define gethostbyname(name)				sys_gethostbyname(name)

#endif /* SOCKSLIBRARY_DYNAMIC */

static struct hostent *
hostentupdate __P((struct hostent *old, const struct hostent *new));
/*
 * Updates "old" with the contents of "new", freeing any
 * resources currently used by "old".
 * Returns:
 *		On success: "old", updated.
 *		On failure: NULL.
*/

static int
hosthash __P((const char *name, size_t size));
/*
 * Calculates a hashvalue for "name" and returns it's value.
 * Size of hashtable is given by "size".
*/

static int
addrhash __P((in_addr_t addr, size_t size));
/*
 * Calculates a hashvalue for "addr" and returns it's value.
 * Size of hashtable is given by "size".
*/

#endif /* SOCKS_SERVER */

static char **
listrealloc __P((char ***old, const char ***new, int length));
/*
 * Reallocates "old" and copies in the contents of "new".
 * The last element of both "old" and "new" must be NULL.
 * If "length" is less than 0, each element is assumed to
 * be NUL terminated, otherwise "length" gives the total length
 * of every string.
 * Returns:
 *		On success: "**old", with the contents of "new".
 *		On failure: NULL.
*/

__END_DECLS

struct hostent *
hostentdup(hostent)
	const struct hostent *hostent;
{
	static struct hostent dupedinit;
	struct hostent *duped;

	if ((duped = (struct hostent *)malloc(sizeof(*duped))) == NULL)
		return NULL;

	*duped = dupedinit;

	if ((duped->h_name = strdup(hostent->h_name)) == NULL) {
		hostentfree(duped);
		return NULL;
	}

	if (listrealloc(&duped->h_aliases, (const char ***)&hostent->h_aliases, -1)
	== NULL) {
		hostentfree(duped);
		return NULL;
	}

	duped->h_addrtype = hostent->h_addrtype;
	duped->h_length	= hostent->h_length;

	if (listrealloc(&duped->h_addr_list, (const char ***)&hostent->h_addr_list,
	hostent->h_length) == NULL) {
		hostentfree(duped);
		return NULL;
	}

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
	const char ***new;
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

	if ((*old = (char **)realloc(*old, sizeof(**new) * (newi + 1))) == NULL)
		return NULL;

	for (newi = 0; (*new)[newi] != NULL; ++newi, --oldi) {
		if (((*old)[newi] = (char *)realloc(oldi > 0 ? (*old)[newi] : NULL,
		length < 0 ? (strlen((*new)[newi]) + 1) : length)) == NULL)
			return NULL;

		if (length < 0)
			strcpy((*old)[newi], (*new)[newi]);
		else
			memcpy((*old)[newi], (*new)[newi], (size_t)length);
	}
	(*old)[newi] = NULL;

	return *old;
}

#if SOCKS_SERVER

struct hostent *
cgethostbyname(name)
	const char *name;
{
	const char *function = "cgethostbyname()";
	static struct {
		unsigned				allocated:1;
		char					host[MAXHOSTNAMELEN];
		time_t				written;
		struct hostent		hostent;
	} table[SOCKD_HOSTCACHE], *freehost;
	static unsigned int hit, miss, count;
	const time_t timenow = time(NULL);
	const int hashi = hosthash(name, ELEMENTS(table));
	size_t i;
	struct hostent *hostent;

#if SOCKD_CACHESTAT
	if (++count % SOCKD_CACHESTAT == 0)
		slog(LOG_INFO, "%s: hit: %d, miss: %d", function, hit, miss);
#endif /* SOCKD_CACHESTAT */

	for (i = hashi, freehost = NULL; i < ELEMENTS(table); ++i) {
		if (!table[i].allocated) {
			if (freehost == NULL)
				freehost = &table[i];
			continue;
		}

		if (strcasecmp(table[i].host, name) == 0) {
			if (difftime(timenow, table[i].written) >= SOCKD_CACHETIMEOUT) {
				freehost = &table[i];
				break;
			}
			++hit;
			return &table[i].hostent;
		}
	}
	++miss;

	if ((hostent = gethostbyname(name)) == NULL)
		return NULL;

	if (freehost == NULL)
		for (i = hashi, freehost = &table[i]; i < ELEMENTS(table); ++i) {
			if (difftime(timenow, table[i].written) >= SOCKD_CACHETIMEOUT) {
				freehost = &table[i];
				break;
			}

			if (freehost->written < table[i].written) {
				freehost = &table[i]; /* oldest. */
				break;
			}
		}

	if (hostentupdate(&freehost->hostent, hostent) == NULL) {
		freehost->allocated = 0;
		slog(LOG_WARNING, "%s: %s", NOMEM, function);
		return NULL;
	}

	SASSERTX(strlen(name) < sizeof(freehost->host));
	strcpy(freehost->host, name);
	time(&freehost->written);
	freehost->allocated = 1;

	return &freehost->hostent;
}

struct hostent *
cgethostbyaddr(addr, len, type)
	const char *addr;
	int len;
	int type;
{
	const char *function = "cgethostbyaddr()";
	static struct {
		unsigned			allocated:1;
		in_addr_t			addr;
		time_t				written;
		struct hostent		hostent;
	} table[SOCKD_ADDRESSCACHE], *freehost;
	static unsigned long int hit, miss, count;
	const time_t timenow = time(NULL);
	/* LINTED pointer casts may be troublesome */
	const int hashi
	= addrhash(((const struct in_addr *)addr)->s_addr, ELEMENTS(table));
	size_t i;
	struct hostent *hostent;

#if SOCKD_CACHESTAT
	if (++count % SOCKD_CACHESTAT == 0)
		slog(LOG_INFO, "%s: hit: %d, miss: %d", function, hit, miss);
#endif /* SOCKD_CACHESTAT */

	for (i = hashi, freehost = NULL; i < ELEMENTS(table); ++i) {
		if (!table[i].allocated) {
			if (freehost == NULL)
				freehost = &table[i];
			continue;
		}

		/* LINTED pointer casts may be troublesome */
		if (table[i].addr == ((const struct in_addr *)addr)->s_addr) {
			if (difftime(timenow, table[i].written) >= SOCKD_CACHETIMEOUT) {
				freehost = &table[i];
				break;
			}
			++hit;
			return &table[i].hostent;
		}
	}
	++miss;

	if ((hostent = gethostbyaddr(addr, len, type)) == NULL)
		return NULL;

	if (freehost == NULL)
		for (i = hashi, freehost = &table[i]; i < ELEMENTS(table); ++i) {
			if (difftime(timenow, table[i].written) >= SOCKD_CACHETIMEOUT) {
				freehost = &table[i];
				break;
			}

			if (freehost->written < table[i].written) {
				freehost = &table[i]; /* oldest. */
				break;
			}
		}

	if (hostentupdate(&freehost->hostent, hostent) == NULL) {
		freehost->allocated = 0;
		slog(LOG_WARNING, "%s: %s", NOMEM, function);
		return NULL;
	}

	/* LINTED pointer casts may be troublesome */
	freehost->addr = ((const struct in_addr *)addr)->s_addr;
	time(&freehost->written);
	freehost->allocated = 1;

	return &freehost->hostent;
}

static int
hosthash(name, size)
	const char *name;
	size_t size;
{
	char *end;
	unsigned int value;

	/* end at second dot. */
	if ((end = strchr(name, '.')) != NULL)
		end = strchr(end, '.');
	if (end == NULL)
		end = strchr(name, NUL);

	SASSERTX(name <= end);
	value = 0;
	while (name != end)
		value = (value << 5) + *name++;	/* MAW - DS&A: Horner's rule. */

	return value % size;
}

static int
addrhash(addr, size)
	in_addr_t addr;
	size_t size;
{

	return addr % size;
}

static struct hostent *
hostentupdate(old, new)
	struct hostent *old;
	const struct hostent *new;
{

	if ((old->h_name = (char *)realloc(old->h_name, strlen(new->h_name) + 1))
	== NULL)
		return NULL;
	strcpy(old->h_name, new->h_name);

	if (listrealloc(&old->h_aliases, (const char ***)&new->h_aliases, -1)
	== NULL)
		return NULL;

	old->h_addrtype	= new->h_addrtype;
	old->h_length		= new->h_length;

	if (listrealloc(&old->h_addr_list, (const char ***)&new->h_addr_list,
	new->h_length) == NULL)
		return NULL;

	return old;
}

#endif /* SOCKS_SERVER */
