/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004
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
 *  Gaustadallllléen 21
 *  NO-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

#include "common.h"

#if SOCKSLIBRARY_DYNAMIC


static const char rcsid[] =
"$Id: interposition.c,v 1.79 2005/01/24 10:24:19 karls Exp $";

#undef accept
#undef bind
#undef bindresvport
#undef connect
#undef gethostbyaddr
#undef gethostbyname
#undef gethostbyname2
#undef getaddrinfo
#undef getipnodebyname
#undef freehostent
#undef getpeername
#undef getsockname
#undef read
#undef readv
#undef recv
#undef recvfrom
#undef recvmsg
#undef rresvport
#undef send
#undef sendmsg
#undef sendto
#undef write
#undef writev

#if NEED_DYNA_RTLD
#define DL_LAZY RTLD_LAZY
#endif  /* NEED_DYNA_RTLD */

static struct libsymbol_t libsymbolv[] = {
#if SOCKS_CLIENT
	{	SYMBOL_ACCEPT,						LIBRARY_ACCEPT,			NULL,	NULL },
	{	SYMBOL_BIND,						LIBRARY_BIND,				NULL,	NULL },
	{	SYMBOL_BINDRESVPORT,				LIBRARY_BINDRESVPORT,	NULL,	NULL },
	{	SYMBOL_CONNECT,					LIBRARY_CONNECT,			NULL,	NULL },
	{	SYMBOL_GETPEERNAME,				LIBRARY_GETPEERNAME,		NULL,	NULL },
	{	SYMBOL_GETSOCKNAME,				LIBRARY_GETSOCKNAME,		NULL,	NULL },
	{	SYMBOL_READ,						LIBRARY_READ,				NULL,	NULL },
	{	SYMBOL_READV,						LIBRARY_READV,				NULL,	NULL },
	{	SYMBOL_RECV,						LIBRARY_RECV,				NULL,	NULL },
	{	SYMBOL_RECVMSG,					LIBRARY_RECVMSG,			NULL,	NULL },
	{	SYMBOL_RECVFROM,					LIBRARY_RECVFROM,			NULL,	NULL },
	{	SYMBOL_RRESVPORT,					LIBRARY_RRESVPORT,		NULL,	NULL },
	{	SYMBOL_SEND,						LIBRARY_SEND,				NULL,	NULL },
	{	SYMBOL_SENDMSG,					LIBRARY_SENDMSG,			NULL,	NULL },
	{	SYMBOL_SENDTO,						LIBRARY_SENDTO,			NULL,	NULL },
	{	SYMBOL_WRITE,						LIBRARY_WRITE,				NULL,	NULL },
	{	SYMBOL_WRITEV,						LIBRARY_WRITEV,			NULL,	NULL },
#if HAVE_GETHOSTBYNAME2
	{	SYMBOL_GETHOSTBYNAME2,			LIBRARY_GETHOSTBYNAME2,	NULL,	NULL },
#endif /* HAVE_GETHOSTBYNAME2 */
#if HAVE_GETADDRINFO
	{	SYMBOL_GETADDRINFO,				LIBRARY_GETADDRINFO,	NULL,	NULL },
#endif /* HAVE_GETADDRINFO */
#if HAVE_GETIPNODEBYNAME
	{	SYMBOL_GETIPNODEBYNAME,			LIBRARY_GETIPNODEBYNAME,	NULL,	NULL },
 	{	SYMBOL_FREEHOSTENT,			LIBRARY_FREEHOSTENT,	NULL,	NULL },
#endif /* HAVE_GETIPNODEBYNAME */
#endif /* SOCKS_CLIENT */
	{	SYMBOL_GETHOSTBYNAME,			LIBRARY_GETHOSTBYNAME,	NULL,	NULL },

#if SOCKS_SERVER
	{	SYMBOL_GETHOSTBYADDR,			LIBRARY_GETHOSTBYADDR,	NULL,	NULL },
#endif

#if SOCKS_CLIENT
#if HAVE_EXTRA_OSF_SYMBOLS
	{	SYMBOL_EACCEPT,					LIBRARY_EACCEPT,			NULL,	NULL },
	{	SYMBOL_EGETPEERNAME,				LIBRARY_EGETPEERNAME,	NULL,	NULL },
	{  SYMBOL_EGETSOCKNAME,				LIBRARY_EGETSOCKNAME,	NULL,	NULL },
	{	SYMBOL_EREADV,						LIBRARY_EREADV,			NULL,	NULL },
	{	SYMBOL_ERECVFROM,					LIBRARY_ERECVFROM,		NULL,	NULL },
	{	SYMBOL_ERECVMSG,					LIBRARY_ERECVMSG,			NULL,	NULL },
	{  SYMBOL_ESENDMSG,					LIBRARY_ESENDMSG,			NULL,	NULL },
	{	SYMBOL_EWRITEV,					LIBRARY_EWRITEV,			NULL,	NULL },

	{	SYMBOL_NACCEPT,					LIBRARY_EACCEPT,			NULL,	NULL },
	{	SYMBOL_NGETPEERNAME,				LIBRARY_NGETPEERNAME,	NULL,	NULL },
	{	SYMBOL_NGETSOCKNAME,				LIBRARY_NGETSOCKNAME,	NULL,	NULL },
	{  SYMBOL_NRECVFROM,					LIBRARY_NRECVFROM,		NULL,	NULL },
	{  SYMBOL_NRECVMSG,					LIBRARY_NRECVMSG,			NULL,	NULL },
	{	SYMBOL_NSENDMSG,					LIBRARY_NSENDMSG,			NULL,	NULL },
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */
#endif /* SOCKS_CLIENT */
};

__BEGIN_DECLS

static struct libsymbol_t *
libsymbol __P((const char *symbol));
/*
 * Finds the libsymbol_t that "symbol" is defined in.
 */

__END_DECLS

void
symbolcheck(void)
{
	size_t i;

	for (i = 0; i < ELEMENTS(libsymbolv); ++i)
		symbolfunction(libsymbolv[i].symbol);
}


void *
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
		if ((lib->handle = dlopen(lib->library, DL_LAZY)) == NULL)
			serrx(EXIT_FAILURE, "%s: compiletime configuration error?  "
			"Failed to open \"%s\": %s",
			function, lib->library, dlerror());

	if (lib->function == NULL)
		if ((lib->function = dlsym(lib->handle, symbol)) == NULL)
			serrx(EXIT_FAILURE, "%s: compiletime configuration error?  "
			"Failed to find \"%s\" in \"%s\": %s",
			function, symbol, lib->library, dlerror());

#if 0
	if (strcmp(symbol, SYMBOL_WRITE) != 0)
		slog(LOG_DEBUG, "found symbol %s in library %s",
		lib->symbol, lib->library);
#endif

	return lib->function;
}

static struct libsymbol_t *
libsymbol(symbol)
	const char *symbol;
{
/*	const char *function = "libsymbol()"; */
	size_t i;

	for (i = 0; i < ELEMENTS(libsymbolv); ++i)
		if (strcmp(libsymbolv[i].symbol, symbol) == 0)
			return &libsymbolv[i];

	/* CONSTCOND */
	SASSERTX(0);	/* should never happen. */

	/* NOTREACHED */
	return NULL; /* please compiler. */
}



	/* the real system calls. */

#if SOCKS_CLIENT

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_ACCEPT_0
sys_accept(s, addr, addrlen)
	HAVE_PROT_ACCEPT_1 s;
	HAVE_PROT_ACCEPT_2 addr;
	HAVE_PROT_ACCEPT_3 addrlen;
{
	int rc;
	typedef HAVE_PROT_ACCEPT_0 (*ACCEPT_FUNC_T)(HAVE_PROT_ACCEPT_1,
															  HAVE_PROT_ACCEPT_2,
															  HAVE_PROT_ACCEPT_3);
	ACCEPT_FUNC_T function;

	SYSCALL_START(s);
	function = (ACCEPT_FUNC_T)symbolfunction(SYMBOL_ACCEPT);
	rc = function(s, addr, addrlen);
	SYSCALL_END(s);
	return rc;
}
#endif  /* !HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_BIND_0
sys_bind(s, name, namelen)
	HAVE_PROT_BIND_1 s;
	HAVE_PROT_BIND_2 name;
	HAVE_PROT_BIND_3 namelen;
{
	int rc;
	typedef HAVE_PROT_BIND_0 (*BIND_FUNC_T)(HAVE_PROT_BIND_1,
														 HAVE_PROT_BIND_2,
														 HAVE_PROT_BIND_3);
	BIND_FUNC_T function;

	SYSCALL_START(s);
	function = (BIND_FUNC_T)symbolfunction(SYMBOL_BIND);
	rc = function(s, name, namelen);
	SYSCALL_END(s);
	return rc;
}
#endif /* !HAVE_EXTRA_OSF_SYMBOLS */

int
sys_bindresvport(sd, sin)
	int sd;
	struct sockaddr_in *sin;
{
	int rc;
	typedef int (*BINDRESVPORT_FUNC_T)(int, struct sockaddr_in *);
	BINDRESVPORT_FUNC_T function;

	SYSCALL_START(sd);
	function = (BINDRESVPORT_FUNC_T)symbolfunction(SYMBOL_BINDRESVPORT);
	rc = function(sd, sin);
	SYSCALL_END(sd);
	return rc;
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_CONNECT_0
sys_connect(s, name, namelen)
	HAVE_PROT_CONNECT_1 s;
	HAVE_PROT_CONNECT_2 name;
	HAVE_PROT_CONNECT_3 namelen;
{
	int rc;
	typedef HAVE_PROT_CONNECT_0 (*CONNECT_FUNC_T)(HAVE_PROT_CONNECT_1,
																 HAVE_PROT_CONNECT_2,
																 HAVE_PROT_CONNECT_3);
	CONNECT_FUNC_T function;

	SYSCALL_START(s);
	function = (CONNECT_FUNC_T)symbolfunction(SYMBOL_CONNECT);
	rc = function(s, name, namelen);
	SYSCALL_END(s);
	return rc;
}
#endif /* !HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_GETPEERNAME_0
sys_getpeername(s, name, namelen)
	HAVE_PROT_GETPEERNAME_1 s;
	HAVE_PROT_GETPEERNAME_2 name;
	HAVE_PROT_GETPEERNAME_3 namelen;
{
	int rc;
	typedef HAVE_PROT_GETPEERNAME_0
		 (*GETPEERNAME_FUNC_T)(HAVE_PROT_GETPEERNAME_1,
									  HAVE_PROT_GETPEERNAME_2,
									  HAVE_PROT_GETPEERNAME_3);
	GETPEERNAME_FUNC_T function;

	SYSCALL_START(s);
	function = (GETPEERNAME_FUNC_T)symbolfunction(SYMBOL_GETPEERNAME);
	rc = function(s, name, namelen);
	SYSCALL_END(s);
	return rc;
}
#endif /* ! HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_GETSOCKNAME_0
sys_getsockname(s, name, namelen)
	HAVE_PROT_GETSOCKNAME_1 s;
	HAVE_PROT_GETSOCKNAME_2 name;
	HAVE_PROT_GETSOCKNAME_3 namelen;
{
	int rc;
	typedef HAVE_PROT_GETSOCKNAME_0
		 (*GETSOCKNAME_FUNC_T)(HAVE_PROT_GETSOCKNAME_1,
									  HAVE_PROT_GETSOCKNAME_2,
									  HAVE_PROT_GETSOCKNAME_3);
	GETSOCKNAME_FUNC_T function;

	SYSCALL_START(s);
	function = (GETSOCKNAME_FUNC_T)symbolfunction(SYMBOL_GETSOCKNAME);
	rc = function(s, name, namelen);
	SYSCALL_END(s);
	return rc;
}
#endif /* !HAVE_EXTRA_OSF_SYMBOLS */

HAVE_PROT_READ_0
sys_read(d, buf, nbytes)
	HAVE_PROT_READ_1 d;
	HAVE_PROT_READ_2 buf;
	HAVE_PROT_READ_3 nbytes;
{
	ssize_t rc;
	typedef HAVE_PROT_READ_0 (*READ_FUNC_T)(HAVE_PROT_READ_1,
														 HAVE_PROT_READ_2,
														 HAVE_PROT_READ_3);
	READ_FUNC_T function;

	SYSCALL_START(d);
	function = (READ_FUNC_T)symbolfunction(SYMBOL_READ);
	rc = function(d, buf, nbytes);
	SYSCALL_END(d);
	return rc;
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_READV_0
sys_readv(d, iov, iovcnt)
	HAVE_PROT_READV_1 d;
	HAVE_PROT_READV_2 iov;
	HAVE_PROT_READV_3 iovcnt;
{
	ssize_t rc;
	typedef HAVE_PROT_READV_0 (*READV_FUNC_T)(HAVE_PROT_READV_1,
															HAVE_PROT_READV_2,
															HAVE_PROT_READV_3);
	READV_FUNC_T function;

	SYSCALL_START(d);
	function = (READV_FUNC_T)symbolfunction(SYMBOL_READV);
	rc = function(d, iov, iovcnt);
	SYSCALL_END(d);
	return rc;
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

HAVE_PROT_RECV_0
sys_recv(s, buf, len, flags)
	HAVE_PROT_RECV_1 s;
	HAVE_PROT_RECV_2 buf;
	HAVE_PROT_RECV_3 len;
	HAVE_PROT_RECV_4 flags;
{
	ssize_t rc;
	typedef HAVE_PROT_RECV_0 (*RECV_FUNC_T)(HAVE_PROT_RECV_1,
														 HAVE_PROT_RECV_2,
														 HAVE_PROT_RECV_3,
														 HAVE_PROT_RECV_4);
	RECV_FUNC_T function;

	SYSCALL_START(s);
	function = (RECV_FUNC_T)symbolfunction(SYMBOL_RECV);
	rc = function(s, buf, len, flags);
	SYSCALL_END(s);
	return rc;
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_RECVFROM_0
sys_recvfrom(s, buf, len, flags, from, fromlen)
	HAVE_PROT_RECVFROM_1 s;
	HAVE_PROT_RECVFROM_2 buf;
	HAVE_PROT_RECVFROM_3 len;
	HAVE_PROT_RECVFROM_4 flags;
	HAVE_PROT_RECVFROM_5 from;
	HAVE_PROT_RECVFROM_6 fromlen;
{
	int rc;
	typedef HAVE_PROT_RECVFROM_0 (*RECVFROM_FUNC_T)(HAVE_PROT_RECVFROM_1,
																	HAVE_PROT_RECVFROM_2,
																	HAVE_PROT_RECVFROM_3,
																	HAVE_PROT_RECVFROM_4,
																	HAVE_PROT_RECVFROM_5,
																	HAVE_PROT_RECVFROM_6);
	RECVFROM_FUNC_T function;

	SYSCALL_START(s);
	function = (RECVFROM_FUNC_T)symbolfunction(SYMBOL_RECVFROM);
	rc = function(s, buf, len, flags, from, fromlen);
	SYSCALL_END(s);
	return rc;
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_RECVMSG_0
sys_recvmsg(s, msg, flags)
	HAVE_PROT_RECVMSG_1 s;
	HAVE_PROT_RECVMSG_2 msg;
	HAVE_PROT_RECVMSG_3 flags;
{
	ssize_t rc;
	typedef HAVE_PROT_RECVMSG_0 (*RECVMSG_FUNC_T)(HAVE_PROT_RECVMSG_1,
																 HAVE_PROT_RECVMSG_2,
																 HAVE_PROT_RECVMSG_3);
	RECVMSG_FUNC_T function;

	SYSCALL_START(s);
	function = (RECVMSG_FUNC_T)symbolfunction(SYMBOL_RECVMSG);
	rc = function(s, msg, flags);
	SYSCALL_END(s);
	return rc;
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

int
sys_rresvport(port)
	int *port;
{
	typedef int (*RRESVPORT_FUNC_T)(int *);
	RRESVPORT_FUNC_T function;

	function = (RRESVPORT_FUNC_T)symbolfunction(SYMBOL_RRESVPORT);
	return function(port);
}

HAVE_PROT_SEND_0
sys_send(s, msg, len, flags)
	HAVE_PROT_SEND_1 s;
	HAVE_PROT_SEND_2 msg;
	HAVE_PROT_SEND_3 len;
	HAVE_PROT_SEND_4 flags;
{
	ssize_t rc;
	typedef HAVE_PROT_SEND_0 (*SEND_FUNC_T)(HAVE_PROT_SEND_1,
														 HAVE_PROT_SEND_2,
														 HAVE_PROT_SEND_3,
														 HAVE_PROT_SEND_4);
	SEND_FUNC_T function;

	SYSCALL_START(s);
	function = (SEND_FUNC_T)symbolfunction(SYMBOL_SEND);
	rc = function(s, msg, len, flags);
	SYSCALL_END(s);
	return rc;
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_SENDMSG_0
sys_sendmsg(s, msg, flags)
	HAVE_PROT_SENDMSG_1 s;
	HAVE_PROT_SENDMSG_2 msg;
	HAVE_PROT_SENDMSG_3 flags;
{
	ssize_t rc;
	typedef HAVE_PROT_SENDMSG_0 (*SENDMSG_FUNC_T)(HAVE_PROT_SENDMSG_1,
																 HAVE_PROT_SENDMSG_2,
																 HAVE_PROT_SENDMSG_3);
	SENDMSG_FUNC_T function;

	SYSCALL_START(s);
	function = (SENDMSG_FUNC_T)symbolfunction(SYMBOL_SENDMSG);
	rc = function(s, msg, flags);
	SYSCALL_END(s);
	return rc;
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_SENDTO_0
sys_sendto(s, msg, len, flags, to, tolen)
	HAVE_PROT_SENDTO_1 s;
	HAVE_PROT_SENDTO_2 msg;
	HAVE_PROT_SENDTO_3 len;
	HAVE_PROT_SENDTO_4 flags;
	HAVE_PROT_SENDTO_5 to;
	HAVE_PROT_SENDTO_6 tolen;
{
	ssize_t rc;
	typedef HAVE_PROT_SENDTO_0 (*SENDTO_FUNC_T)(HAVE_PROT_SENDTO_1,
															  HAVE_PROT_SENDTO_2,
															  HAVE_PROT_SENDTO_3,
															  HAVE_PROT_SENDTO_4,
															  HAVE_PROT_SENDTO_5,
															  HAVE_PROT_SENDTO_6);
	SENDTO_FUNC_T function;

	SYSCALL_START(s);
	function = (SENDTO_FUNC_T)symbolfunction(SYMBOL_SENDTO);
	rc = function(s, msg, len, flags, to, tolen);
	SYSCALL_END(s);
	return rc;
}
#endif /* !HAVE_EXTRA_OSF_SYMBOLS */

HAVE_PROT_WRITE_0
sys_write(d, buf, nbytes)
	HAVE_PROT_WRITE_1 d;
	HAVE_PROT_WRITE_2 buf;
	HAVE_PROT_WRITE_3 nbytes;
{
	ssize_t rc;
	typedef HAVE_PROT_WRITE_0 (*WRITE_FUNC_T)(HAVE_PROT_WRITE_1,
															HAVE_PROT_WRITE_2,
															HAVE_PROT_WRITE_3);
	WRITE_FUNC_T function;

	SYSCALL_START(d);
	function = (WRITE_FUNC_T)symbolfunction(SYMBOL_WRITE);
	rc = function(d, buf, nbytes);
	SYSCALL_END(d);
	return rc;
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_WRITEV_0
sys_writev(d, iov, iovcnt)
	HAVE_PROT_WRITEV_1 d;
	HAVE_PROT_WRITEV_2 iov;
	HAVE_PROT_WRITEV_3 iovcnt;
{
	ssize_t rc;
	typedef HAVE_PROT_WRITEV_0 (*WRITEV_FUNC_T)(HAVE_PROT_WRITEV_1,
															  HAVE_PROT_WRITEV_2,
															  HAVE_PROT_WRITEV_3);
	WRITEV_FUNC_T function;

	SYSCALL_START(d);
	function = (WRITEV_FUNC_T)symbolfunction(SYMBOL_WRITEV);
	rc = function(d, iov, iovcnt);
	SYSCALL_END(d);
	return rc;
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */


	/*
	 * the interpositioned functions.
	 */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_ACCEPT_0
accept(s, addr, addrlen)
	HAVE_PROT_ACCEPT_1 s;
	HAVE_PROT_ACCEPT_2 addr;
	HAVE_PROT_ACCEPT_3 addrlen;
{
	if (ISSYSCALL(s))
		return sys_accept(s, addr, addrlen);
	return Raccept(s, addr, (socklen_t *)addrlen);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_BIND_0
bind(s, name, namelen)
	HAVE_PROT_BIND_1 s;
	HAVE_PROT_BIND_2 name;
	HAVE_PROT_BIND_3 namelen;
{
	if (ISSYSCALL(s))
		return sys_bind(s, name, namelen);
	return Rbind(s, name, namelen);
}
#endif /* !HAVE_EXTRA_OSF_SYMBOLS */

int
bindresvport(sd, sin)
	int sd;
	struct sockaddr_in *sin;
{
	if (ISSYSCALL(sd))
		return sys_bindresvport(sd, sin);
	return Rbindresvport(sd, sin);
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_CONNECT_0
connect(s, name, namelen)
	HAVE_PROT_CONNECT_1 s;
	HAVE_PROT_CONNECT_2 name;
	HAVE_PROT_CONNECT_3 namelen;
{
	if (ISSYSCALL(s))
		return sys_connect(s, name, namelen);
	return Rconnect(s, name, namelen);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */


#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_GETPEERNAME_0
getpeername(s, name, namelen)
	HAVE_PROT_GETPEERNAME_1 s;
	HAVE_PROT_GETPEERNAME_2 name;
	HAVE_PROT_GETPEERNAME_3 namelen;
{
	if (ISSYSCALL(s))
		return sys_getpeername(s, name, namelen);
	return Rgetpeername(s, name, namelen);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_GETSOCKNAME_0
getsockname(s, name, namelen)
	HAVE_PROT_GETSOCKNAME_1 s;
	HAVE_PROT_GETSOCKNAME_2 name;
	HAVE_PROT_GETSOCKNAME_3 namelen;
{
	if (ISSYSCALL(s))
		return sys_getsockname(s, name, namelen);
	return Rgetsockname(s, name, namelen);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

HAVE_PROT_READ_0
read(d, buf, nbytes)
	HAVE_PROT_READ_1 d;
	HAVE_PROT_READ_2 buf;
	HAVE_PROT_READ_3 nbytes;
{
	if (ISSYSCALL(d))
		return sys_read(d, buf, nbytes);
	return Rread(d, buf, nbytes);
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_READV_0
readv(d, iov, iovcnt)
	HAVE_PROT_READV_1 d;
	HAVE_PROT_READV_2 iov;
	HAVE_PROT_READV_3 iovcnt;
{
	if (ISSYSCALL(d))
		return sys_readv(d, iov, iovcnt);
	return Rreadv(d, iov, iovcnt);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

HAVE_PROT_RECV_0
recv(s, msg, len, flags)
	HAVE_PROT_RECV_1 s;
	HAVE_PROT_RECV_2 msg;
	HAVE_PROT_RECV_3 len;
	HAVE_PROT_RECV_4 flags;
{
	if (ISSYSCALL(s))
		return sys_recv(s, msg, len, flags);
	return Rrecv(s, msg, len, flags);
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_RECVFROM_0
recvfrom(s, buf, len, flags, from, fromlen)
	HAVE_PROT_RECVFROM_1 s;
	HAVE_PROT_RECVFROM_2 buf;
	HAVE_PROT_RECVFROM_3 len;
	HAVE_PROT_RECVFROM_4 flags;
	HAVE_PROT_RECVFROM_5 from;
	HAVE_PROT_RECVFROM_6 fromlen;
{
	if (ISSYSCALL(s))
		return sys_recvfrom(s, buf, len, flags, from, fromlen);
	return Rrecvfrom(s, buf, len, flags, from, fromlen);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_RECVMSG_0
recvmsg(s, msg, flags)
	HAVE_PROT_RECVMSG_1 s;
	HAVE_PROT_RECVMSG_2 msg;
	HAVE_PROT_RECVMSG_3 flags;
{
	if (ISSYSCALL(s))
		return sys_recvmsg(s, msg, flags);
	return Rrecvmsg(s, msg, flags);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

int
rresvport(port)
	int *port;
{
	return Rrresvport(port);
}

HAVE_PROT_WRITE_0
write(d, buf, nbytes)
	HAVE_PROT_WRITE_1 d;
	HAVE_PROT_WRITE_2 buf;
	HAVE_PROT_WRITE_3 nbytes;
{
	if (ISSYSCALL(d))
		return sys_write(d, buf, nbytes);
	return Rwrite(d, buf, nbytes);
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_WRITEV_0
writev(d, iov, iovcnt)
	HAVE_PROT_WRITEV_1 d;
	HAVE_PROT_WRITEV_2 iov;
	HAVE_PROT_WRITEV_3 iovcnt;
{
	if (ISSYSCALL(d))
		return sys_writev(d, iov, iovcnt);
	return Rwritev(d, iov, iovcnt);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

HAVE_PROT_SEND_0
send(s, msg, len, flags)
	HAVE_PROT_SEND_1 s;
	HAVE_PROT_SEND_2 msg;
	HAVE_PROT_SEND_3 len;
	HAVE_PROT_SEND_4 flags;
{
	if (ISSYSCALL(s))
		return sys_send(s, msg, len, flags);
	return Rsend(s, msg, len, flags);
}

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_SENDMSG_0
sendmsg(s, msg, flags)
	HAVE_PROT_SENDMSG_1 s;
	HAVE_PROT_SENDMSG_2 msg;
	HAVE_PROT_SENDMSG_3 flags;
{
	if (ISSYSCALL(s))
		return sys_sendmsg(s, msg, flags);
	return Rsendmsg(s, msg, flags);
}
#endif /* HAVE_EXTRA_OSF_SYMBOLS */

#if !HAVE_EXTRA_OSF_SYMBOLS
HAVE_PROT_SENDTO_0
sendto(s, msg, len, flags, to, tolen)
	HAVE_PROT_SENDTO_1 s;
	HAVE_PROT_SENDTO_2 msg;
	HAVE_PROT_SENDTO_3 len;
	HAVE_PROT_SENDTO_4 flags;
	HAVE_PROT_SENDTO_5 to;
	HAVE_PROT_SENDTO_6 tolen;
{
	if (ISSYSCALL(s))
		return sys_sendto(s, msg, len, flags, to, tolen);
	return Rsendto(s, msg, len, flags, to, tolen);
}
#endif /* !HAVE_EXTRA_OSF_SYMBOLS */

#endif /* SOCKS_CLIENT */

#if SOCKS_SERVER

struct hostent *
sys_gethostbyaddr(addr, len, af)
	const char *addr;
	int len;
	int af;
{
	typedef struct hostent *(*GETHOSTBYADDR_FUNC_T)(const char *, int, int);
	GETHOSTBYADDR_FUNC_T function;

	function = (GETHOSTBYADDR_FUNC_T)symbolfunction(SYMBOL_GETHOSTBYADDR);
	return function(addr, len, af);
}

HAVE_PROT_GETHOSTBYADDR_0
gethostbyaddr(addr, len, af)
	HAVE_PROT_GETHOSTBYADDR_1 addr;
	HAVE_PROT_GETHOSTBYADDR_2 len;
	HAVE_PROT_GETHOSTBYADDR_3 af;
{

	return cgethostbyaddr(addr, len, af);
}

#endif /* SOCKS_SERVER */

struct hostent *
sys_gethostbyname(name)
	const char *name;
{
	typedef struct hostent *(*GETHOSTBYNAME_FUNC_T)(const char *);
	GETHOSTBYNAME_FUNC_T function;

	function = (GETHOSTBYNAME_FUNC_T)symbolfunction(SYMBOL_GETHOSTBYNAME);
	return function(name);
}

struct hostent *
gethostbyname(name)
	const char *name;
{
#if SOCKS_SERVER
	return cgethostbyname(name);
#else
	return Rgethostbyname(name);
#endif
}

#if SOCKS_CLIENT

struct hostent *
sys_gethostbyname2(name, af)
	const char *name;
	int af;
{
	typedef struct hostent *(*GETHOSTBYNAME2_FUNC_T)(const char *, int);
	GETHOSTBYNAME2_FUNC_T function;

	function = (GETHOSTBYNAME2_FUNC_T)symbolfunction(SYMBOL_GETHOSTBYNAME2);
	return function(name, af);
}


struct hostent *
gethostbyname2(name, af)
	const char *name;
	int af;
{
	return Rgethostbyname2(name, af);
}

#if HAVE_GETADDRINFO

int
sys_getaddrinfo(nodename, servname, hints, res)
	const char *nodename;
	const char *servname;
	const struct addrinfo *hints;
	struct addrinfo **res;
{
	typedef int (*GETADDRINFO_FUNC_T)(const char *, const char *, 
					  const struct addrinfo *,
					  struct addrinfo **);
	GETADDRINFO_FUNC_T function;

	function = (GETADDRINFO_FUNC_T)symbolfunction(SYMBOL_GETADDRINFO);
	return function(nodename, servname, hints, res);
}

int
getaddrinfo(nodename, servname, hints, res)
	const char *nodename;
	const char *servname;
	const struct addrinfo *hints;
	struct addrinfo **res;
{
	return Rgetaddrinfo(nodename, servname, hints, res);
}

#endif /* HAVE_GETADDRINFO */

#if HAVE_GETIPNODEBYNAME

struct hostent *
sys_getipnodebyname(name, af, flags, error_num)
	const char *name;
	int af;
	int flags;
	int *error_num;
{
	typedef struct hostent *(*GETIPNODEBYNAME_FUNC_T)(const char *, int, int, int *);
	GETIPNODEBYNAME_FUNC_T function;

	function = (GETIPNODEBYNAME_FUNC_T)symbolfunction(SYMBOL_GETIPNODEBYNAME);
	return function(name, af, flags, error_num);
}

struct hostent *
getipnodebyname(name, af, flags, error_num)
	const char *name;
	int af;
	int flags;
	int *error_num;
{
	return Rgetipnodebyname(name, af, flags, error_num);
}

void
sys_freehostent(ptr)
        struct hostent *ptr;
{
        typedef struct hostent *(*FREEHOSTENT_FUNC_T)(struct hostent *);

	FREEHOSTENT_FUNC_T function;

	function = (FREEHOSTENT_FUNC_T)symbolfunction(SYMBOL_FREEHOSTENT);
	function(ptr);
}

void 
freehostent(ptr)
        struct hostent *ptr;
{
        Rfreehostent(ptr);
}

#endif /* HAVE_GETIPNODEBYNAME */

#endif /* SOCKS_CLIENT */

#endif /* SOCKSLIBRARY_DYNAMIC */
