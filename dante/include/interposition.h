/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2009
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

/* $Id: interposition.h,v 1.45 2009/01/02 14:06:01 michaels Exp $ */

#ifndef LIBRARY_PATH
#define LIBRARY_PATH ""
#endif

#if HAVE_NO_SYMBOL_UNDERSCORE
#define SYMBOL_ACCEPT "accept"
#define SYMBOL_BIND "bind"
#define SYMBOL_BINDRESVPORT "bindresvport"
#define SYMBOL_CONNECT "connect"
#define SYMBOL_GETHOSTBYADDR "gethostbyaddr"
#define SYMBOL_GETHOSTBYNAME "gethostbyname"
#define SYMBOL_GETHOSTBYNAME2 "gethostbyname2"
#define SYMBOL_GETADDRINFO "getaddrinfo"
#define SYMBOL_GETIPNODEBYNAME "getipnodebyname"
#define SYMBOL_FREEHOSTENT "freehostent"
#define SYMBOL_GETPEERNAME "getpeername"
#define SYMBOL_GETSOCKNAME "getsockname"
#define SYMBOL_LISTEN "listen"
#define SYMBOL_READ "read"
#define SYMBOL_READV "readv"
#define SYMBOL_RECV "recv"
#define SYMBOL_RECVFROM "recvfrom"
#define SYMBOL_RECVMSG "recvmsg"
#define SYMBOL_RRESVPORT "rresvport"
#define SYMBOL_SEND "send"
#define SYMBOL_SENDMSG "sendmsg"
#define SYMBOL_SENDTO "sendto"
#define SYMBOL_WRITE "write"
#define SYMBOL_WRITEV "writev"
#endif /* HAVE_NO_SYMBOL_UNDERSCORE */

/* XXX */
#ifndef LIBRARY_LIBC
#define LIBRARY_LIBC                        __CONCAT(LIBRARY_PATH, "libc.so")
#endif

#ifndef SYMBOL_ACCEPT
#define SYMBOL_ACCEPT                     "_accept"
#endif
#ifndef LIBRARY_ACCEPT
#define LIBRARY_ACCEPT                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_BIND
#define SYMBOL_BIND                        "_bind"
#endif
#ifndef LIBRARY_BIND
#define LIBRARY_BIND                        LIBRARY_LIBC
#endif

#ifndef SYMBOL_BINDRESVPORT
#define SYMBOL_BINDRESVPORT               "_bindresvport"
#endif
#ifndef LIBRARY_BINDRESVPORT
#define LIBRARY_BINDRESVPORT               LIBRARY_LIBC
#endif

#ifndef SYMBOL_CONNECT
#define SYMBOL_CONNECT                     "_connect"
#endif
#ifndef LIBRARY_CONNECT
#define LIBRARY_CONNECT                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETHOSTBYADDR
#define SYMBOL_GETHOSTBYADDR               "_gethostbyaddr"
#endif
#ifndef LIBRARY_GETHOSTBYADDR
#define LIBRARY_GETHOSTBYADDR               LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETHOSTBYNAME
#define SYMBOL_GETHOSTBYNAME               "_gethostbyname"
#endif
#ifndef LIBRARY_GETHOSTBYNAME
#define LIBRARY_GETHOSTBYNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETHOSTBYNAME2
#define SYMBOL_GETHOSTBYNAME2               "_gethostbyname2"
#endif
#ifndef LIBRARY_GETHOSTBYNAME2
#define LIBRARY_GETHOSTBYNAME2            LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETADDRINFO
#define SYMBOL_GETADDRINFO                  "_getaddrinfo"
#endif
#ifndef LIBRARY_GETADDRINFO
#define LIBRARY_GETADDRINFO               LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETIPNODEBYNAME
#define SYMBOL_GETIPNODEBYNAME            "_getipnodebyname"
#endif
#ifndef LIBRARY_GETIPNODEBYNAME
#define LIBRARY_GETIPNODEBYNAME            LIBRARY_LIBC
#endif

#ifndef SYMBOL_FREEHOSTENT
#define SYMBOL_FREEHOSTENT            "_freehostent"
#endif
#ifndef LIBRARY_FREEHOSTENT
#define LIBRARY_FREEHOSTENT            LIBRARY_LIBC
#endif
 
#ifndef SYMBOL_GETPEERNAME
#define SYMBOL_GETPEERNAME                  "_getpeername"
#endif
#ifndef LIBRARY_GETPEERNAME
#define LIBRARY_GETPEERNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_GETSOCKNAME
#define SYMBOL_GETSOCKNAME                  "_getsockname"
#endif
#ifndef LIBRARY_GETSOCKNAME
#define LIBRARY_GETSOCKNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_LISTEN
#define SYMBOL_LISTEN                  "_listen"
#endif
#ifndef LIBRARY_LISTEN
#define LIBRARY_LISTEN               LIBRARY_LIBC
#endif

#ifndef SYMBOL_READ
#define SYMBOL_READ                        "_read"
#endif
#ifndef LIBRARY_READ
#define LIBRARY_READ                        LIBRARY_LIBC
#endif

#ifndef SYMBOL_READV
#define SYMBOL_READV                        "_readv"
#endif
#ifndef LIBRARY_READV
#define LIBRARY_READV                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_RECV
#define SYMBOL_RECV                        "_recv"
#endif
#ifndef LIBRARY_RECV
#define LIBRARY_RECV                        LIBRARY_LIBC
#endif

#ifndef SYMBOL_RECVFROM
#define SYMBOL_RECVFROM                     "_recvfrom"
#endif
#ifndef LIBRARY_RECVFROM
#define LIBRARY_RECVFROM                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_RECVMSG
#define SYMBOL_RECVMSG                     "_recvmsg"
#endif
#ifndef LIBRARY_RECVMSG
#define LIBRARY_RECVMSG                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_RRESVPORT
#define SYMBOL_RRESVPORT                  "_rresvport"
#endif
#ifndef LIBRARY_RRESVPORT
#define LIBRARY_RRESVPORT                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_SEND
#define SYMBOL_SEND                        "_send"
#endif
#ifndef LIBRARY_SEND
#define LIBRARY_SEND                        LIBRARY_LIBC
#endif

#ifndef SYMBOL_SENDMSG
#define SYMBOL_SENDMSG                     "_sendmsg"
#endif
#ifndef LIBRARY_SENDMSG
#define LIBRARY_SENDMSG                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_SENDTO
#define SYMBOL_SENDTO                     "_sendto"
#endif
#ifndef LIBRARY_SENDTO
#define LIBRARY_SENDTO                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_WRITE
#define SYMBOL_WRITE                        "_write"
#endif
#ifndef LIBRARY_WRITE
#define LIBRARY_WRITE                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_WRITEV
#define SYMBOL_WRITEV                     "_writev"
#endif
#ifndef LIBRARY_WRITEV
#define LIBRARY_WRITEV                     LIBRARY_LIBC
#endif

/* only used on OSF */
#if HAVE_EXTRA_OSF_SYMBOLS

#ifndef SYMBOL_EACCEPT
#define SYMBOL_EACCEPT                     "_Eaccept"
#endif
#ifndef LIBRARY_EACCEPT
#define LIBRARY_EACCEPT                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_EGETPEERNAME
#define SYMBOL_EGETPEERNAME               "_Egetpeername"
#endif
#ifndef LIBRARY_EGETPEERNAME
#define LIBRARY_EGETPEERNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_EGETSOCKNAME
#define SYMBOL_EGETSOCKNAME               "_Egetsockname"
#endif
#ifndef LIBRARY_EGETSOCKNAME
#define LIBRARY_EGETSOCKNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_EREADV
#define SYMBOL_EREADV                     "_Ereadv"
#endif
#ifndef LIBRARY_EREADV
#define LIBRARY_EREADV                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_ERECVFROM
#define SYMBOL_ERECVFROM                  "_Erecvfrom"
#endif
#ifndef LIBRARY_ERECVFROM
#define LIBRARY_ERECVFROM                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_ERECVMSG
#define SYMBOL_ERECVMSG                     "_Erecvmsg"
#endif
#ifndef LIBRARY_ERECVMSG
#define LIBRARY_ERECVMSG                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_ESENDMSG
#define SYMBOL_ESENDMSG                     "_Esendmsg"
#endif
#ifndef LIBRARY_ESENDMSG
#define LIBRARY_ESENDMSG                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_EWRITEV
#define SYMBOL_EWRITEV                     "_Ewritev"
#endif
#ifndef LIBRARY_EWRITEV
#define LIBRARY_EWRITEV                     LIBRARY_LIBC
#endif

/* more OSF functions */

#ifndef SYMBOL_NACCEPT
#define SYMBOL_NACCEPT                     "naccept"
#endif
#ifndef LIBRARY_NACCEPT
#define LIBRARY_NACCEPT                     LIBRARY_LIBC
#endif

#ifndef SYMBOL_NGETPEERNAME
#define SYMBOL_NGETPEERNAME               "ngetpeername"
#endif
#ifndef LIBRARY_NGETPEERNAME
#define LIBRARY_NGETPEERNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_NGETSOCKNAME
#define SYMBOL_NGETSOCKNAME               "ngetsockname"
#endif
#ifndef LIBRARY_NGETSOCKNAME
#define LIBRARY_NGETSOCKNAME               LIBRARY_LIBC
#endif

#ifndef SYMBOL_NRECVFROM
#define SYMBOL_NRECVFROM                  "nrecvfrom"
#endif
#ifndef LIBRARY_NRECVFROM
#define LIBRARY_NRECVFROM                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_NRECVMSG
#define SYMBOL_NRECVMSG                     "nrecvmsg"
#endif
#ifndef LIBRARY_NRECVMSG
#define LIBRARY_NRECVMSG                  LIBRARY_LIBC
#endif

#ifndef SYMBOL_NSENDMSG
#define SYMBOL_NSENDMSG                     "nsendmsg"
#endif
#ifndef LIBRARY_NSENDMSG
#define LIBRARY_NSENDMSG                  LIBRARY_LIBC
#endif

#endif  /* HAVE_EXTRA_OSF_SYMBOLS */


#ifdef lint
extern const int lintnoloop_interposition_h;
#else
#define lintnoloop_interposition_h 0
#endif


struct libsymbol_t {
   char *symbol;         /* name of the symbol.         */
   char *library;         /* library symbol is in.      */
   void *handle;         /* handle to the library.      */
   void *function;      /* the bound symbol.            */
};

#if SOCKS_CLIENT

#define SYSCALL_START(s)                                             \
do {                                                                 \
   const struct socksfd_t *p;                                        \
   struct socksfd_t socksfd;                                         \
                                                                     \
   socks_addrlock(F_WRLCK);                                          \
                                                                     \
   if ((p = socks_getaddr((unsigned int)s, 1)) == NULL) {            \
      bzero(&socksfd, sizeof(socksfd));                              \
      socksfd.state.command   = -1;                                  \
      socksfd.state.issyscall = 1;                                   \
      p = socks_addaddr((unsigned int)s, &socksfd, 1);               \
   }                                                                 \
                                                                     \
   socksfd = *p;                                                     \
   ++socksfd.state.syscalldepth;                                     \
   socks_addaddr((unsigned int)s, &socksfd, 1);                      \
                                                                     \
   socks_addrunlock();                                               \
} while (lintnoloop_interposition_h)

#define SYSCALL_END(s)                                               \
do {                                                                 \
   const struct socksfd_t *p;                                        \
   struct socksfd_t socksfd;                                         \
                                                                     \
   socks_addrlock(F_WRLCK);                                          \
                                                                     \
   p = socks_getaddr((unsigned int)s, 1);                            \
   SASSERTX(p != NULL);                                              \
   socksfd = *p;                                                     \
   SASSERTX(socksfd.state.syscalldepth > 0);                         \
                                                                     \
   if (--socksfd.state.syscalldepth <= 0) { /* all finished. */      \
      if (socksfd.state.issyscall) /* started out as a syscall. */   \
         socks_rmaddr((unsigned int)s, 1);                           \
   }                                                                 \
                                                                     \
   socks_addrunlock();                                               \
} while (lintnoloop_interposition_h)

#define ISSYSCALL(s)   \
   (socks_getaddr((unsigned int)(s), 0) != NULL              \
 && socks_getaddr((unsigned int)(s), 0)->state.issyscall)

#endif /* SOCKS_CLIENT */

__BEGIN_DECLS

void *
symbolfunction __P((const char *symbol));
/*
 * Returns the address binding of the symbol "symbol" and updates
 * libsymbol_t structure "symbol" is defined in if necessary.
 * Exits on failure.
 */

void
symbolcheck __P((void));
/*
 * Checks that all defined symbols are loadable (and loads them).
 * Note that this might open filedescriptors (and keep them open).
 */

__END_DECLS
