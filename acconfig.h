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
#undef int32_t
#undef int16_t
#undef int8_t
#undef uint32_t
#undef uint16_t
#undef uint8_t

/* send/recvmsg cmsg types */
#undef HAVE_CMSGHDR

/* CMSG_LEN/SPACE */
#undef HAVE_CMSG_LEN
#undef HAVE_CMSG_SPACE

/* Solaris 2.5 name */
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

/* defined on systems which doesn't support more than one process
   doing accept on the same descriptor.  BSD systems and Solaris 2.6 is
   supposed to support this (Stevens) */
#undef NEED_ACCEPTLOCK

/* not defined through the normal mechanism */
#undef HAVE_DLFCN_H
#undef HAVE_SYS_SOCKIO_H

/* define by other name */
#undef NEED_DYNA_RTLD

/* needed for better performance */
#undef HAVE_SO_SNDLOWAT

/* SIGINFO signal */
#undef HAVE_SIGNAL_SIGINFO

/* XXX special test for gethostbyname2 */
#undef HAVE_GETHOSTBYNAME2

/* libwrap test needs special care */
#undef HAVE_LIBWRAP

/* IPv6 support */
#undef HAVE_IPV6_SUPPORT

/* function location */
#undef LIBRARY_ACCEPT
#undef LIBRARY_BIND
#undef LIBRARY_BINDRESVPORT
#undef LIBRARY_CONNECT
#undef LIBRARY_GETHOSTBYADDR
#undef LIBRARY_GETHOSTBYNAME
#undef LIBRARY_GETHOSTBYNAME2
#undef LIBRARY_FREEHOSTENT
#undef LIBRARY_GETADDRINFO
#undef LIBRARY_GETIPNODEBYNAME
#undef LIBRARY_FREEHOSTENT
#undef LIBRARY_GETPEERNAME
#undef LIBRARY_GETSOCKNAME
#undef LIBRARY_LIBC
#undef LIBRARY_LIBNSL
#undef LIBRARY_LIBRESOLV
#undef LIBRARY_LIBSOCKET
#undef LIBRARY_LIBRPCSOC
#undef LIBRARY_LISTEN
#undef LIBRARY_PATH
#undef LIBRARY_READ
#undef LIBRARY_READV
#undef LIBRARY_RECV
#undef LIBRARY_RECVFROM
#undef LIBRARY_RECVMSG
#undef LIBRARY_RECVMSG
#undef LIBRARY_RRESVPORT
#undef LIBRARY_SEND
#undef LIBRARY_SENDMSG
#undef LIBRARY_SENDTO
#undef LIBRARY_WRITE
#undef LIBRARY_WRITEV

/* symbol names */
#undef SYMBOL_ACCEPT
#undef SYMBOL_BIND
#undef SYMBOL_BINDRESVPORT
#undef SYMBOL_CONNECT
#undef SYMBOL_GETHOSTBYADDR
#undef SYMBOL_GETHOSTBYNAME
#undef SYMBOL_GETHOSTBYNAME2
#undef SYMBOL_FREEHOSTENT
#undef SYMBOL_GETPEERNAME
#undef SYMBOL_GETSOCKNAME
#undef SYMBOL_READ
#undef SYMBOL_READV
#undef SYMBOL_RECV
#undef SYMBOL_RECVFROM
#undef SYMBOL_RECVMSG
#undef SYMBOL_RRESVPORT
#undef SYMBOL_SEND
#undef SYMBOL_SENDMSG
#undef SYMBOL_SENDTO
#undef SYMBOL_WRITE
#undef SYMBOL_WRITEV


/* workaround for Solaris bug */
#undef HAVE_SENDMSG_DEADLOCK

/* no support for NULL pointer to realloc? */
#undef HAVE_NOMALLOC_REALLOC

/* Linux (2.0.x?) doesn't seem to set some recvmsg related values in some cases */
#undef HAVE_DEFECT_RECVMSG

/* XXX used to enable alternative code to avoid broken Solaris libsocket */
#undef HAVE_SOLARIS_2_5_1
#undef HAVE_SOLARIS_BUGS

/* problems on Linux */
#undef HAVE_LINUX_BUGS
#undef HAVE_LINUX_ECCENTRICITIES

/* sun4 vsprintf doesn't seem to return length */
#undef HAVE_BROKEN_VSPRINTF

/* system name */
#undef HAVE_HOST_TYPE

/* diagnostic */
#undef DIAGNOSTIC

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

/* allow default file locations to be overridden */
#undef HAVE_ALT_SOCKS_CONFIGFILE
#undef HAVE_ALT_SOCKD_CONFIGFILE
#undef HAVE_ALT_SOCKD_PIDFILE
#undef HAVE_SOCKD_PIDFILE
#undef HAVE_SOCKD_CONFIGFILE
#undef HAVE_SOCKS_CONFIGFILE

#undef HAVE_DISABLED_PIDFILE

/* some netdb.h files doesn't appear to declare h_errno */
#undef HAVE_H_ERRNO

/* probably all elf based systems (no underscore for library symbols) */
#undef HAVE_NO_SYMBOL_UNDERSCORE

#undef HAVE_PROFILING

/* Solaris 2.5.1 needs it. Otherwise FIOASYNC will not be defined
   -(Pavel Roskin <pavel_roskin@geocities.com>) */
#undef BSD_COMP

/* IPv6 types */
#undef HAVE_SOCKADDR_STORAGE
#undef HAVE_IN6_ADDR

/* AIX has volatile sig_atomic_t */
#undef HAVE_VOLATILE_SIG_ATOMIC_T

/* System V getpwnam 'improvement' workaround */
#undef HAVE_WORKING_GETPWNAM

#undef HAVE_SOCKADDR_SA_LEN

/* PAM (Pluggable Authentication Module) found? */
#undef HAVE_PAM
/* more Solaris bugs */
#undef HAVE_SOLARIS_PAM_BUG

/* support for retrieval of route data? */
#undef HAVE_ROUTE_SOURCE

/* architecture dependent code */
#undef HAVE_ROUTEINFO_BSD
#undef HAVE_ROUTEINFO_LINUX

/* module defines */
#undef HAVE_MODULE_REDIRECT
#undef HAVE_MODULE_BANDWIDTH

/* more AIX bandaid */
#undef HAVE_SYSTEM_XMSG_MAGIC

/* for gui */
#undef HAVE_DUMPCONF

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

#undef HAVE_PROT_GETHOSTBYADDR_0
#undef HAVE_PROT_GETHOSTBYADDR_1
#undef HAVE_PROT_GETHOSTBYADDR_2
#undef HAVE_PROT_GETHOSTBYADDR_3
