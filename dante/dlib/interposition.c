/*
 * Copyright (c) 1997, 1998
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
 *  Gaustadaléen 21
 *  N-0371 Oslo
 *  Norway
 * 
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

static const char rcsid[] =
"$Id: interposition.c,v 1.23 1998/11/13 21:17:07 michaels Exp $";

#define WE_DONT_WANT_NO_SOCKADDR_ARG_UNION

#include "common.h"

#ifdef SOCKSLIBRARY_DYNAMIC

#include "interposition.h"

#undef accept
#undef bind
#undef bindresvport
#undef connect
#undef gethostbyname
#undef gethostbyname2
#undef getpeername
#undef getsockname
#undef recvfrom
#undef rresvport
#undef sendto

#ifdef NEED_DYNA_RTLD
#define DL_LAZY RTLD_LAZY
#endif  /* NEED_DYNA_RTLD */

static struct libsymbol_t libsymbolv[] = {
	{	SYMBOL_ACCEPT, 					LIBRARY_ACCEPT },
	{	SYMBOL_BIND, 	 					LIBRARY_BIND },
	{	SYMBOL_BINDRESVPORT,	 			LIBRARY_BINDRESVPORT },
	{	SYMBOL_CONNECT, 	 				LIBRARY_CONNECT },
	{	SYMBOL_GETHOSTBYNAME,			LIBRARY_GETHOSTBYNAME },
	{	SYMBOL_GETHOSTBYNAME2,	 		LIBRARY_GETHOSTBYNAME2 },
	{	SYMBOL_GETPEERNAME,	 			LIBRARY_GETPEERNAME },
	{	SYMBOL_GETSOCKNAME,	 			LIBRARY_GETSOCKNAME },
	{	SYMBOL_RECVFROM,	 				LIBRARY_RECVFROM },
	{	SYMBOL_RRESVPORT,	 				LIBRARY_RRESVPORT },
	{	SYMBOL_SENDTO,	 					LIBRARY_SENDTO },
};

__BEGIN_DECLS

static struct libsymbol_t *
libsymbol(const char *symbol);
/*
 * Finds the libsymbol_t that "symbol" is defined in.
*/


static void *
symbolfunction(const char *symbol);
/*
 * Returns the address binding of the symbol "symbol" and updates
 * libsymbol_t structure "symbol" is defined in if necessary.
 * Returns NULL on failure.
*/

__END_DECLS

static struct libsymbol_t *
libsymbol(symbol)
	const char *symbol;
{
	const char *function = "libsymbol()";
	int i;

	for (i = 0; i < ELEMENTS(libsymbolv); ++i)
		if (strcmp(libsymbolv[i].symbol, symbol) == 0)
			return &libsymbolv[i];

	serrx(1, "%s: can't find symbol %s", function, symbol);

	return NULL;

	/* NOTREACHED */
}


static void *
symbolfunction(symbol)
	const char *symbol;
{
	const char *function = "symbolfunction()";
	struct libsymbol_t *lib;

	lib = libsymbol(symbol);

	SASSERTX(lib != NULL);
	SASSERTX(lib->library != NULL);
	SASSERTX(strcmp(lib->symbol, symbol) == 0);

	if (lib->handle == NULL)
		/* LINTED argument has incompatible pointer type, arg #2 */
		if ((lib->handle = dlopen(lib->library, DL_LAZY)) == NULL) {
			swarnx("%s: %s: %s", function, lib->library, dlerror());
			return NULL;
		}

	if (lib->function == NULL)
		/* LINTED argument has incompatible pointer type, arg #2 */
		if ((lib->function = dlsym(lib->handle, symbol)) == NULL) {
			swarnx("%s: %s: %s", function, symbol, dlerror());
			return NULL;
		}

#if 0
	slog(LOG_DEBUG, "found symbol %s in library %s",
	lib->symbol, lib->library);
#endif

	return lib->function;
}



	/* the real system calls/functions. */

int 
sys_accept(s, addr, addrlen)
	int s;
	__SOCKADDR_ARG addr;
	socklen_t *addrlen;
{
	int (*function)(int s, __SOCKADDR_ARG addr, socklen_t *addrlen);

	if ((function = symbolfunction(SYMBOL_ACCEPT)) == NULL)
		return -1;

	return function(s, addr, addrlen);
}

int
sys_bind(s, name, namelen)
	int s;
#ifdef HAVE_FAULTY_BINDPROTO
	struct sockaddr *name;
#else
	__CONST_SOCKADDR_ARG name;
#endif  /* HAVE_FAULTY_BINDPROTO */
	socklen_t namelen;
{
	int (*function)(int s, __CONST_SOCKADDR_ARG name, socklen_t namelen);

	if ((function = symbolfunction(SYMBOL_BIND)) == NULL)
		return -1;

	return function(s, name, namelen);
}

int
sys_bindresvport(sd, sin)
	int sd;
	struct sockaddr_in *sin;
{
	int (*function)(int sd, struct sockaddr_in *sin);

	if ((function = symbolfunction(SYMBOL_BINDRESVPORT)) == NULL)
		return -1;

	return function(sd, sin);
}


int
sys_connect(s, name, namelen)
	int s;
#ifdef HAVE_FAULTY_CONNECTPROTO
	struct sockaddr *name;
#else
	__CONST_SOCKADDR_ARG name;
#endif  /* HAVE_FAULTY_CONNECTPROTO */
	socklen_t namelen;
{
	int (*function)(int s, __CONST_SOCKADDR_ARG name, socklen_t namelen);

	if ((function = symbolfunction(SYMBOL_CONNECT)) == NULL)
		return -1;

	return function(s, name, namelen);
}

struct hostent *
sys_gethostbyname(name)
	const char *name;
{
	struct hostent *(*function)(const char *name);

	if ((function = symbolfunction(SYMBOL_GETHOSTBYNAME)) == NULL)
		return NULL;

	return function(name);
}

struct hostent *
sys_gethostbyname2(name, af)
	const char *name;
	int af;
{
	struct hostent *(*function)(const char *name, int af);

	if ((function = symbolfunction(SYMBOL_GETHOSTBYNAME2)) == NULL)
		return NULL;

	return function(name, af);
}

int
sys_getpeername(s, name, namelen)
	int s;
	__SOCKADDR_ARG name;
	socklen_t *namelen;
{
	int (*function)(int s, const __SOCKADDR_ARG name, socklen_t *namelen);

	if ((function = symbolfunction(SYMBOL_GETPEERNAME)) == NULL)
		return -1;

	return function(s, name, namelen);

}

int
sys_getsockname(s, name, namelen)
	int s;
	__SOCKADDR_ARG name;
	socklen_t *namelen;
{
	int (*function)(int s, const __SOCKADDR_ARG name, socklen_t *namelen);

	if ((function = symbolfunction(SYMBOL_GETSOCKNAME)) == NULL)
		return -1;

	return function(s, name, namelen);
}

int
sys_recvfrom(s, buf, len, flags, from, fromlen)
	int s;
#ifdef HAVE_RECVFROM_CHAR
	char *buf;
	int len;
#else
	void *buf;
	size_t len;
#endif  /* HAVE_RECVFROM_CHAR */
	int flags;
	__SOCKADDR_ARG from;
	socklen_t *fromlen;
{
	int (*function)(int s, void *buf, size_t len, int flags,
					    __SOCKADDR_ARG from, socklen_t *fromlen);

	if ((function = symbolfunction(SYMBOL_RECVFROM)) == NULL)
		return -1;

	return function(s, buf, len, flags, from, fromlen);
}

int 
sys_rresvport(port)
	int *port;
{
	int (*function)(int *port);

	if ((function = symbolfunction(SYMBOL_RRESVPORT)) == NULL)
		return -1;

	return function(port);
}

int
sys_sendto(s, msg, len, flags, to, tolen)
	int s;
#ifdef HAVE_SENDTO_ALT
	const char *msg;
	int len;
#else
	const void *msg;
	size_t len;
#endif  /* HAVE_SENDTO_ALT */
	int flags;
	__CONST_SOCKADDR_ARG to;
	socklen_t tolen;
{
	int (*function)(int s, const void *msg, size_t len, int flags,
					    __CONST_SOCKADDR_ARG to, socklen_t tolen);

	if ((function = symbolfunction(SYMBOL_SENDTO)) == NULL)
		return -1;

	return function(s, msg, len, flags, to, tolen);
}


	/* the interpositioned functions. */

int 
accept(s, addr, addrlen)
	int s;
	__SOCKADDR_ARG addr;
	socklen_t *addrlen;
{
	return Raccept(s, addr, addrlen);
}

int
bind(s, name, namelen)
	int s;
#ifdef HAVE_FAULTY_BINDPROTO
	struct sockaddr *name;
#else
	__CONST_SOCKADDR_ARG name;
#endif  /* HAVE_FAULTY_BINDPROTO */
	socklen_t namelen;
{
	return Rbind(s, name, namelen);
}

int
bindresvport(sd, sin)
	int sd;
	struct sockaddr_in *sin;
{
	return Rbindresvport(sd, sin);
}

int
connect(s, name, namelen)
	int s;
#ifdef HAVE_FAULTY_CONNECTPROTO
	struct sockaddr *name;
#else
	__CONST_SOCKADDR_ARG name;
#endif  /* HAVE_FAULTY_CONNECTPROTO */
	socklen_t namelen;
{
	return Rconnect(s, name, namelen);
}

struct hostent *
gethostbyname(name)
	const char *name;
{
	return Rgethostbyname(name);
}

struct hostent *
gethostbyname2(name, af)
	const char *name;
	int af;
{
	return Rgethostbyname2(name, af);
}

int
getpeername(s, name, namelen)
	int s;
	__SOCKADDR_ARG name;
	socklen_t *namelen;
{
	return Rgetpeername(s, name, namelen);
}

int
getsockname(s, name, namelen)
	int s;
	__SOCKADDR_ARG name;
	socklen_t *namelen;
{
	return Rgetsockname(s, name, namelen);
}

int
recvfrom(s, buf, len, flags, from, fromlen)
	int s;
#ifdef HAVE_RECVFROM_CHAR
	char *buf;
	int len; /* XXX include in HAVE_RECVFROM_CHAR */
#else
	void *buf;
	size_t len;
#endif  /* HAVE_RECVFROM_CHAR */
	int flags;
	__SOCKADDR_ARG from;
	socklen_t *fromlen;
{
	return Rrecvfrom(s, buf, len, flags, from, fromlen);
}
	
int
rresvport(port)
	int *port;
{
	return Rrresvport(port);
}

int 
sendto(s, msg, len, flags, to, tolen)
	int s;
#ifdef HAVE_SENDTO_ALT
	const char *msg;
	int len;
#else
	const void *msg;
	size_t len;
#endif  /* HAVE_SENDTO_ALT */
	int flags;
	__CONST_SOCKADDR_ARG to;
	socklen_t tolen;
{
	return Rsendto(s, msg, len, flags, to, tolen);
}

#endif /* SOCKSLIBRARY_DYNAMIC */
