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

/* $Id: interposition.h,v 1.9 1998/12/09 17:14:53 michaels Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#ifndef LIBRARY_PATH
#define LIBRARY_PATH ""
#endif

/* XXX */
#ifndef LIBRARY_LIBC
#define LIBRARY_LIBC								__CONCAT(LIBRARY_PATH, "libc.so")
#endif

#ifndef SYMBOL_ACCEPT
#define SYMBOL_ACCEPT							"_accept"
#endif
#ifndef LIBRARY_ACCEPT
#define LIBRARY_ACCEPT							LIBRARY_LIBC
#endif

#ifndef SYMBOL_BIND
#define SYMBOL_BIND								"_bind"
#endif
#ifndef LIBRARY_BIND
#define LIBRARY_BIND								LIBRARY_LIBC
#endif

#ifndef SYMBOL_CONNECT
#define SYMBOL_CONNECT							"_connect"
#endif
#ifndef LIBRARY_CONNECT
#define LIBRARY_CONNECT							LIBRARY_LIBC
#endif

#ifndef SYMBOL_BINDRESVPORT
#define SYMBOL_BINDRESVPORT					"_bindresvport"
#endif
#ifndef LIBRARY_BINDRESVPORT
#define LIBRARY_BINDRESVPORT					LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETHOSTBYNAME
#define SYMBOL_GETHOSTBYNAME					"_gethostbyname"
#endif
#ifndef LIBRARY_GETHOSTBYNAME
#define LIBRARY_GETHOSTBYNAME					LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETHOSTBYNAME2
#define SYMBOL_GETHOSTBYNAME2					"_gethostbyname2"
#endif
#ifndef LIBRARY_GETHOSTBYNAME2
#define LIBRARY_GETHOSTBYNAME2				LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETPEERNAME
#define SYMBOL_GETPEERNAME						"_getpeername"
#endif
#ifndef LIBRARY_GETPEERNAME
#define LIBRARY_GETPEERNAME					LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETSOCKNAME
#define SYMBOL_GETSOCKNAME						"_getsockname"
#endif
#ifndef LIBRARY_GETSOCKNAME
#define LIBRARY_GETSOCKNAME					LIBRARY_LIBC
#endif

#ifndef SYMBOL_READ
#define SYMBOL_READ								"_read"
#endif
#ifndef LIBRARY_READ
#define LIBRARY_READ								LIBRARY_LIBC
#endif

#ifndef SYMBOL_READV
#define SYMBOL_READV								"_readv"
#endif
#ifndef LIBRARY_READV
#define LIBRARY_READV							LIBRARY_LIBC
#endif

#ifndef SYMBOL_RECV
#define SYMBOL_RECV								"_recv"
#endif
#ifndef LIBRARY_RECV
#define LIBRARY_RECV								LIBRARY_LIBC
#endif

#ifndef SYMBOL_RECVMSG
#define SYMBOL_RECVMSG							"_recvmsg"
#endif
#ifndef LIBRARY_RECVMSG
#define LIBRARY_RECVMSG							LIBRARY_LIBC
#endif

#ifndef SYMBOL_RECVFROM
#define SYMBOL_RECVFROM							"_recvfrom"
#endif
#ifndef LIBRARY_RECVFROM
#define LIBRARY_RECVFROM						LIBRARY_LIBC
#endif

#ifndef SYMBOL_RRESVPORT
#define SYMBOL_RRESVPORT						"_rresvport"
#endif
#ifndef LIBRARY_RRESVPORT
#define LIBRARY_RRESVPORT						LIBRARY_LIBC
#endif

#ifndef SYMBOL_SEND
#define SYMBOL_SEND								"_send"
#endif
#ifndef LIBRARY_SEND
#define LIBRARY_SEND								LIBRARY_LIBC
#endif

#ifndef SYMBOL_SENDMSG
#define SYMBOL_SENDMSG							"_sendmsg"
#endif
#ifndef LIBRARY_SENDMSG
#define LIBRARY_SENDMSG							LIBRARY_LIBC
#endif

#ifndef SYMBOL_SENDTO
#define SYMBOL_SENDTO							"_sendto"
#endif
#ifndef LIBRARY_SENDTO
#define LIBRARY_SENDTO							LIBRARY_LIBC
#endif

#ifndef SYMBOL_WRITE
#define SYMBOL_WRITE								"_write"
#endif
#ifndef LIBRARY_WRITE
#define LIBRARY_WRITE							LIBRARY_LIBC
#endif

#ifndef SYMBOL_WRITEV
#define SYMBOL_WRITEV							"_writev"
#endif
#ifndef LIBRARY_WRITEV
#define LIBRARY_WRITEV							LIBRARY_LIBC
#endif


struct libsymbol_t {
	char *symbol;			/* the symbol.						*/
	char *library;			/* library symbol is in.		*/
	void *handle;			/* our handle to the library.	*/
	void *function;		/* the bound symbol.				*/
};


#define SYSCALL_START(s) \
int socksfd_added = 0;	 														\
do {																					\
	struct socksfd_t *socksfd = socks_getaddr((unsigned int)s);		\
	struct socksfd_t socksfdmem;												\
																						\
	if (socksfd == NULL) {														\
		bzero(&socksfdmem, sizeof(socksfdmem));							\
		socksfdmem.state.command  = -1;										\
		socksfd = socks_addaddr((unsigned int)s, &socksfdmem);		\
		socksfd_added = 1;														\
	}																					\
																						\
	SASSERTX(socksfd->state.system >= 0);									\
	++socksfd->state.system;													\
} while (lintnoloop_socks_h)


#define SYSCALL_END(s) \
do {																					\
	struct socksfd_t *socksfd = socks_getaddr((unsigned int)s);		\
																						\
	SASSERTX(socksfd != NULL);													\
																						\
	if (socksfd_added)															\
		socks_rmaddr((unsigned int)s);										\
	else																				\
		--socksfd->state.system;												\
	SASSERTX(socksfd->state.system >= 0);									\
} while (lintnoloop_socks_h)

#define ISSYSCALL(s)	\
	(socks_getaddr((unsigned int)(s)) != NULL 					\
	&& socks_getaddr((unsigned int)(s))->state.system > 0)

