/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2004, 2008, 2009
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

/* $Id: symbols.h,v 1.2.4.2 2010/08/01 15:11:59 karls Exp $ */

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
#define SYMBOL_GETSOCKOPT "getsockopt"
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
#if HAVE_GSSAPI && HAVE_LINUX_GLIBC_WORKAROUND
#define SYMBOL_GETC "getc"
#define SYMBOL_FGETC "fgetc"
#define SYMBOL_GETS "gets"
#define SYMBOL_FGETS "fgets"
#define SYMBOL_PUTC "putc"
#define SYMBOL_FPUTC "fputc"
#define SYMBOL_PUTS "puts"
#define SYMBOL_FPUTS "fputs"
#define SYMBOL_FFLUSH "fflush"
#define SYMBOL_FCLOSE "fclose"
#define SYMBOL_PRINTF "printf"
#define SYMBOL_VPRINTF "vprintf"
#define SYMBOL_FPRINTF "fprintf"
#define SYMBOL_VFPRINTF "vfprintf"
#define SYMBOL_FWRITE "fwrite"
#define SYMBOL_FREAD "fread"
#if HAVE___FPRINTF_CHK
#define SYMBOL___FPRINTF_CHK "__fprintf_chk"
#endif /* HAVE___FPRINTF_CHK */
#if HAVE___VFPRINTF_CHK
#define SYMBOL___VFPRINTF_CHK "__vfprintf_chk"
#endif /* HAVE___VFPRINTF_CHK */
#if HAVE__IO_GETC
#define SYMBOL__IO_GETC "_IO_getc"
#endif /* HAVE__IO_GETC */
#if HAVE__IO_PUTC
#define SYMBOL__IO_PUTC "_IO_putc"
#endif /* HAVE__IO_PUTC */
#endif /* HAVE_GSSAPI && HAVE_LINUX_GLIBC_WORKAROUND */
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

#ifndef SYMBOL_GETSOCKOPT
#define SYMBOL_GETSOCKOPT                   "_getsockopt"
#endif /* !SYMBOL_GETSOCKOPT */
#ifndef LIBRARY_GETSOCKOPT
#define LIBRARY_GETSOCKOPT                  LIBRARY_LIBC
#endif /* !LIBRARY_GETSOCKOPT */

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

#if HAVE_GSSAPI && HAVE_LINUX_GLIBC_WORKAROUND
#ifndef SYMBOL_GETC
#define SYMBOL_GETC                        "_getc"
#endif /* !SYMBOL_GETC */
#ifndef LIBRARY_GETC
#define LIBRARY_GETC                       LIBRARY_LIBC
#endif /* !LIBRARY_GETC */

#ifndef SYMBOL_FGETC
#define SYMBOL_FGETC                       "_fgetc"
#endif /* !SYMBOL_FGETC */
#ifndef LIBRARY_FGETC
#define LIBRARY_FGETC                      LIBRARY_LIBC
#endif /* !LIBRARY_FGETC */

#ifndef SYMBOL_GETS
#define SYMBOL_GETS                        "_gets"
#endif /* !SYMBOL_GETS */
#ifndef LIBRARY_GETS
#define LIBRARY_GETS                       LIBRARY_LIBC
#endif /* !LIBRARY_GETS */

#ifndef SYMBOL_FGETS
#define SYMBOL_FGETS                       "_fgets"
#endif /* !SYMBOL_FGETS */
#ifndef LIBRARY_FGETS
#define LIBRARY_FGETS                      LIBRARY_LIBC
#endif /* !LIBRARY_FGETS */

#ifndef SYMBOL_PUTC
#define SYMBOL_PUTC                        "_putc"
#endif /* !SYMBOL_PUTC */
#ifndef LIBRARY_PUTC
#define LIBRARY_PUTC                       LIBRARY_LIBC
#endif /* !LIBRARY_PUTC */

#ifndef SYMBOL_FPUTC
#define SYMBOL_FPUTC                       "_fputc"
#endif /* !SYMBOL_FPUTC */
#ifndef LIBRARY_FPUTC
#define LIBRARY_FPUTC                      LIBRARY_LIBC
#endif /* !LIBRARY_FPUTC */

#ifndef SYMBOL_PUTS
#define SYMBOL_PUTS                        "_puts"
#endif /* !SYMBOL_PUTS */
#ifndef LIBRARY_PUTS
#define LIBRARY_PUTS                       LIBRARY_LIBC
#endif /* !LIBRARY_PUTS */

#ifndef SYMBOL_FPUTS
#define SYMBOL_FPUTS                       "_fputs"
#endif /* !SYMBOL_FPUTS */
#ifndef LIBRARY_FPUTS
#define LIBRARY_FPUTS                      LIBRARY_LIBC
#endif /* !LIBRARY_FPUTS */

#ifndef SYMBOL_FFLUSH
#define SYMBOL_FFLUSH                      "_fflush"
#endif /* !SYMBOL_FFLUSH */
#ifndef LIBRARY_FFLUSH
#define LIBRARY_FFLUSH                     LIBRARY_LIBC
#endif /* !LIBRARY_FFLUSH */

#ifndef SYMBOL_FCLOSE
#define SYMBOL_FCLOSE                      "_fclose"
#endif /* !SYMBOL_FCLOSE */
#ifndef LIBRARY_FCLOSE
#define LIBRARY_FCLOSE                     LIBRARY_LIBC
#endif /* !LIBRARY_FCLOSE */

#ifndef SYMBOL_PRINTF
#define SYMBOL_PRINTF                      "_printf"
#endif /* !SYMBOL_PRINTF */
#ifndef LIBRARY_PRINTF
#define LIBRARY_PRINTF                     LIBRARY_LIBC
#endif /* !LIBRARY_PRINTF */

#ifndef SYMBOL_VPRINTF
#define SYMBOL_VPRINTF                     "_vprintf"
#endif /* !SYMBOL_VPRINTF */
#ifndef LIBRARY_VPRINTF
#define LIBRARY_VPRINTF                    LIBRARY_LIBC
#endif /* !LIBRARY_VPRINTF */

#ifndef SYMBOL_FPRINTF
#define SYMBOL_FPRINTF                     "_fprintf"
#endif /* SYMBOL_FPRINTF */
#ifndef LIBRARY_FPRINTF
#define LIBRARY_FPRINTF                    LIBRARY_LIBC
#endif /* !LIBRARY_FPRINTF */

#ifndef SYMBOL_VFPRINTF
#define SYMBOL_VFPRINTF                    "_vfprintf"
#endif /* !SYMBOL_VFPRINTF */
#ifndef LIBRARY_VFPRINTF
#define LIBRARY_VFPRINTF                   LIBRARY_LIBC
#endif /* !LIBRARY_VFPRINTF */

#ifndef SYMBOL_FWRITE
#define SYMBOL_FWRITE                      "_fwrite"
#endif /* !SYMBOL_FWRITE */
#ifndef LIBRARY_FWRITE
#define LIBRARY_FWRITE                     LIBRARY_LIBC
#endif /* !LIBRARY_FWRITE */

#ifndef SYMBOL_FREAD
#define SYMBOL_FREAD                      "_fread"
#endif /* !SYMBOL_FREAD */
#ifndef LIBRARY_FREAD
#define LIBRARY_FREAD                     LIBRARY_LIBC
#endif /* !LIBRARY_FREAD */

#if HAVE___FPRINTF_CHK
#ifndef SYMBOL___FPRINTF_CHK
#define SYMBOL___FPRINTF_CHK               "__fprintf_chk"
#endif /* !SYMBOL___FPRINTF_CHK */
#ifndef LIBRARY___FPRINTF_CHK
#define LIBRARY___FPRINTF_CHK              LIBRARY_LIBC
#endif /* !LIBRARY___FPRINTF_CHK */
#endif /* HAVE___FPRINTF_CHK */

#if HAVE___VFPRINTF_CHK
#ifndef SYMBOL___VFPRINTF_CHK
#define SYMBOL___VFPRINTF_CHK              "__vfprintf_chk"
#endif /* !SYMBOL___VFPRINTF_CHK */
#ifndef LIBRARY___VFPRINTF_CHK
#define LIBRARY___VFPRINTF_CHK             LIBRARY_LIBC
#endif /* !LIBRARY___VFPRINTF_CHK */
#endif /* HAVE___VFPRINTF_CHK */

#if HAVE__IO_GETC
#ifndef SYMBOL__IO_GETC
#define SYMBOL__IO_GETC                    "__IO_getc"
#endif /* !SYMBOL__IO_GETC */
#ifndef LIBRARY__IO_GETC
#define LIBRARY__IO_GETC                   LIBRARY_LIBC
#endif /* !LIBRARY__IO_GETC */
#endif /* HAVE__IO_GETC */

#if HAVE__IO_PUTC
#ifndef SYMBOL__IO_PUTC
#define SYMBOL__IO_PUTC                    "__IO_putc"
#endif /* !SYMBOL__IO_PUTC */
#ifndef LIBRARY__IO_PUTC
#define LIBRARY__IO_PUTC                   LIBRARY_LIBC
#endif /* !LIBRARY__IO_PUTC */
#endif /* HAVE__IO_PUTC */
#endif /* HAVE_GSSAPI && HAVE_LINUX_GLIBC_WORKAROUND */

#ifdef __sun
#define SYMBOL_XNET_BIND "__xnet_bind"
#define SYMBOL_XNET_CONNECT "__xnet_connect"
#define SYMBOL_XNET_LISTEN "__xnet_listen"
#define SYMBOL_XNET_RECVMSG "__xnet_recvmsg"
#define SYMBOL_XNET_SENDMSG "__xnet_sendmsg"
#define SYMBOL_XNET_SENDTO "__xnet_sendto"
#endif /* __sun */

/* pthread functions */
#if HAVE_PTHREAD_H
#if HAVE_NO_SYMBOL_UNDERSCORE
#define SYMBOL_PT_INIT      "pthread_mutex_init"
#define SYMBOL_PT_ATTRINIT  "pthread_mutexattr_init"
#define SYMBOL_PT_SETTYPE   "pthread_mutexattr_settype"
#define SYMBOL_PT_LOCK      "pthread_mutex_lock"
#define SYMBOL_PT_UNLOCK    "pthread_mutex_unlock"
#define SYMBOL_PT_SELF      "pthread_self"
#else
#define SYMBOL_PT_INIT      "_pthread_mutex_init"
#define SYMBOL_PT_ATTRINIT  "_pthread_mutexattr_init"
#define SYMBOL_PT_SETTYPE   "_pthread_mutexattr_settype"
#define SYMBOL_PT_LOCK      "_pthread_mutex_lock"
#define SYMBOL_PT_UNLOCK    "_pthread_mutex_unlock"
#define SYMBOL_PT_SELF      "_pthread_self"
#endif /* HAVE_NO_SYMBOL_UNDERSCORE */
#ifndef LIBRARY_PTHREAD
#define LIBRARY_PTHREAD                  LIBRARY_LIBC
#endif
#endif /* HAVE_PTHREAD_H */
