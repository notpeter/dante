/* PACKAGE */
#undef PACKAGE

/* VERSION */
#undef VERSION

/* LOG_PERROR logopt to openlog not supported everywhere */
#undef HAVE_OPENLOG_LOG_PERROR

/* AC_CHECK_TYPE */
#undef in_port_t
#undef in_addr_t
#undef ssize_t
#undef socklen_t
#undef int16_t
#undef int32_t

/* send/recvmsg cmsg types */
#undef HAVE_CMSGHDR

/* solaris 2.5 name */
#undef HAVE_OPTHDR

/* recvmsg MSG_WAITALL flag */
#undef HAVE_MSG_WAITALL

/* sysV <sys/ioctl.h> doesn't include <sys/sockio.h> */
#undef NEED_SYS_SOCKIO_H

/* used for debugging */
#undef HAVE_MALLOC_OPTIONS

/* programname */
#undef HAVE_PROGNAME

/* char* in getsockopt() ? */
#undef NEED_GETSOCKOPT_CAST

/* dynamic loading */
#undef SOCKSLIBRARY_DYNAMIC

/* BSD4.3 (sunos), namechanges, missing defines */
#undef NEED_SA_RESTART
#undef NEED_AF_LOCAL
#undef NEED_EXIT_FAILURE

/*XXX function missing from lib, but not headers */
#undef HAVE_INET_ATON

/* defined on systems which doesn't support more than one process
   doing accept on the same descriptor.  BSD systems and solaris 2.6 is
   supposed to support this (Stevens) */
#undef NEED_ACCEPTLOCK

/* not defined through the normal mechanism */
#undef HAVE_DLFCN_H
#undef HAVE_SYS_SOCKIO_H

/* define by other name */
#undef NEED_DYNA_RTLD

/* XXX needed for proper behaviour for now */
#undef HAVE_SO_SNDLOWAT

/* SIGINFO signal */
#undef HAVE_SIGNAL_SIGINFO

/* XXX special test for gethostbyname2 */
#undef HAVE_GETHOSTBYNAME2

/* function location */
#undef LIBRARY_PATH
#undef LIBRARY_ACCEPT
#undef LIBRARY_BIND
#undef LIBRARY_BINDRESVPORT
#undef LIBRARY_CONNECT
#undef LIBRARY_GETHOSTBYNAME
#undef LIBRARY_GETHOSTBYNAME2
#undef LIBRARY_GETPEERNAME
#undef LIBRARY_GETSOCKNAME
#undef LIBRARY_LIBC
#undef LIBRARY_LIBNSL
#undef LIBRARY_LIBRESOLV
#undef LIBRARY_LIBSOCKET
#undef LIBRARY_LISTEN
#undef LIBRARY_RECVFROM
#undef LIBRARY_RRESVPORT
#undef LIBRARY_SENDTO
#undef LIBRARY_RECVMSG
#undef LIBRARY_SENDMSG

/* symbol names */
#undef SYMBOL_GETHOSTBYNAME
#undef SYMBOL_GETHOSTBYNAME2
#undef SYMBOL_GETSOCKNAME
#undef SYMBOL_CONNECT
#undef SYMBOL_GETPEERNAME
#undef SYMBOL_RECVFROM
#undef SYMBOL_ACCEPT
#undef SYMBOL_BIND
#undef SYMBOL_BINDRESVPORT
#undef SYMBOL_SENDTO
#undef SYMBOL_LISTEN
#undef SYMBOL_RRESVPORT
#undef SYMBOL_READV
#undef SYMBOL_RECVMSG
#undef SYMBOL_SENDMSG
#undef SYMBOL_WRITEV
#undef SYMBOL_SEND
#undef SYMBOL_RECV
#undef SYMBOL_WRITE
#undef SYMBOL_READ


/* workaround for solaris bug */
#undef HAVE_SENDMSG_DEADLOCK

/* no support for NULL pointer to realloc? */
#undef HAVE_NOMALLOC_REALLOC

/* linux (2.0.x?) doesn't seem to set some recvmsg related values in some cases */
#undef HAVE_DEFECT_RECVMSG

/* XXX used to enable alternative code to avoid broken solaris libsocket */
#undef HAVE_SOLARIS_2_5_1
#undef HAVE_SOLARIS_BUGS

/* problems on linux */
#undef HAVE_LINUX_BUGS

/* sun4 vsprintf doesn't seem to return length */
#undef HAVE_BROKEN_VSPRINTF

/* system name */
#undef HAVE_HOST_TYPE

/* diagnostic */
#undef DIAGNOSTIC

/* solaris/sysv include fun */
#undef NEED_UCBINCLUDE_SYS_IOCTL

/* convenience struct for getsockopt(IP_OPTIONS) */
#undef HAVE_STRUCT_IPOPTS

/* used by setproctitle */
#undef SPT_PADCHAR

/* try to detect 64bit irix gcc/native cc problem */
#undef HAVE_BROKEN_INET_NTOA

/* dec/alpha */
#undef HAVE_DEC_PROTO
#undef HAVE_EXTRA_OSF_SYMBOLS

/* missing sig_atomic_t */
#undef HAVE_SIG_ATOMIC_T

/* when proper resolver functions are missing (sun4) */
#undef HAVE_NO_RESOLVESTUFF
#undef SOCKS_DOMAINNAME

/* not all platforms allow free(NULL) */
#undef HAVE_NONULL_FREE

/* interposition.c prototypes */
#undef HAVE_PROT_CONNECT_0
#undef HAVE_PROT_CONNECT_1
#undef HAVE_PROT_CONNECT_2
#undef HAVE_PROT_CONNECT_3

#undef HAVE_PROT_ACCEPT_0
#undef HAVE_PROT_ACCEPT_1
#undef HAVE_PROT_ACCEPT_2
#undef HAVE_PROT_ACCEPT_3

#undef HAVE_PROT_BIND_0
#undef HAVE_PROT_BIND_1
#undef HAVE_PROT_BIND_2
#undef HAVE_PROT_BIND_3

#undef HAVE_PROT_GETPEERNAME_0
#undef HAVE_PROT_GETPEERNAME_1
#undef HAVE_PROT_GETPEERNAME_2
#undef HAVE_PROT_GETPEERNAME_3

#undef HAVE_PROT_GETSOCKNAME_0
#undef HAVE_PROT_GETSOCKNAME_1
#undef HAVE_PROT_GETSOCKNAME_2
#undef HAVE_PROT_GETSOCKNAME_3

#undef HAVE_PROT_RECVFROM_0
#undef HAVE_PROT_RECVFROM_1
#undef HAVE_PROT_RECVFROM_2
#undef HAVE_PROT_RECVFROM_3
#undef HAVE_PROT_RECVFROM_4
#undef HAVE_PROT_RECVFROM_5
#undef HAVE_PROT_RECVFROM_6

#undef HAVE_PROT_SEND_0
#undef HAVE_PROT_SEND_1
#undef HAVE_PROT_SEND_2
#undef HAVE_PROT_SEND_3
#undef HAVE_PROT_SEND_4

#undef HAVE_PROT_RECV_0
#undef HAVE_PROT_RECV_1
#undef HAVE_PROT_RECV_2
#undef HAVE_PROT_RECV_3
#undef HAVE_PROT_RECV_4

#undef HAVE_PROT_SENDTO_0
#undef HAVE_PROT_SENDTO_1
#undef HAVE_PROT_SENDTO_2
#undef HAVE_PROT_SENDTO_3
#undef HAVE_PROT_SENDTO_4
#undef HAVE_PROT_SENDTO_5
#undef HAVE_PROT_SENDTO_6

#undef HAVE_PROT_READV_0
#undef HAVE_PROT_READV_1
#undef HAVE_PROT_READV_2
#undef HAVE_PROT_READV_3

#undef HAVE_PROT_WRITEV_0
#undef HAVE_PROT_WRITEV_1
#undef HAVE_PROT_WRITEV_2
#undef HAVE_PROT_WRITEV_3

#undef HAVE_PROT_RECVMSG_0
#undef HAVE_PROT_RECVMSG_1
#undef HAVE_PROT_RECVMSG_2
#undef HAVE_PROT_RECVMSG_3

#undef HAVE_PROT_SENDMSG_0
#undef HAVE_PROT_SENDMSG_1
#undef HAVE_PROT_SENDMSG_2
#undef HAVE_PROT_SENDMSG_3

#undef HAVE_PROT_WRITE_0
#undef HAVE_PROT_WRITE_1
#undef HAVE_PROT_WRITE_2
#undef HAVE_PROT_WRITE_3

#undef HAVE_PROT_READ_0
#undef HAVE_PROT_READ_1
#undef HAVE_PROT_READ_2
#undef HAVE_PROT_READ_3

/* XXX autoheader snafu */
/*#undef HAVE_PROT__*/

/* XXX run include/redefgen.sh manually to regenerate redefac.h after
   changes have been made to this file */

@BOTTOM@
/* change all #undef's to #define foo 0 */
#include "redefac.h"
