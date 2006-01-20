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

/* $Id: common.h,v 1.329 2006/01/15 15:33:38 karls Exp $ */

#ifndef _COMMON_H_
#define _COMMON_H_
#endif

#ifndef SOCKS_SERVER
#define SOCKS_SERVER 0
#endif /* !defined SOCKS_SERVER */

#ifndef SOCKS_CLIENT
#define SOCKS_CLIENT 0
#endif /* !defined SOCKS_CLIENT */

#ifndef SOCKSLIBRARY_DYNAMIC
#define SOCKSLIBRARY_DYNAMIC 0
#endif /* !defined SOCKSLIBRARY_DYNAMIC */

/* XXX ifdef, not if, defined on command line */
#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#ifndef __GNUC__
#define __attribute__(a)
#endif

#if HAVE_LINUX_ECCENTRICITIES
/*
 * XXX This is a hack. Avoid transparent sockaddr union used in Linux
 *  to avoid the use of the union in the code. Mainly used in
 *  interposition.c (also for CMSG_)
 */

#ifdef __GNUC__
#undef __GNUC__
#define __GNUC__ 0
#endif /* __GNUC__ */

#endif /* HAVE_LINUX_ECCENTRICITIES */

#include <sys/types.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif  /* HAVE_SYS_FILE_H */
#include <sys/resource.h>
#include <sys/ioctl.h>
#if HAVE_SYS_IPC_H
#include <sys/ipc.h>
#endif /* HAVE_SYS_IPC_H */
#if HAVE_SYS_SEM_H
#include <sys/sem.h>
#endif /* HAVE_SYS_SEM_H */
#include <sys/socket.h>
#include <net/if.h>
#if NEED_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* NEED_SYS_SOCKIO_H */
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/stat.h>
#ifdef SOCKS_DLIB_OSF
#undef __DECC
#endif /* SOCKS_DLIB_OSF */
#include <sys/uio.h>
#ifdef SOCKS_DLIB_OSF
#define __DECC
#endif /* SOCKS_DLIB_OSF */
#include <sys/wait.h>
#include <netinet/in.h>
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif  /* HAVE_NETINET_IP_H */
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif  /* HAVE_NETINET_IP_VAR_H */
#include <arpa/inet.h>
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif /* HAVE_ARPA_NAMESER_H */
#include <sys/mman.h>

#include <assert.h>
#if HAVE_CRYPT_H
#include <crypt.h>
#endif  /* HAVE_CRYPT_H */
#include <ctype.h>
#if SOCKSLIBRARY_DYNAMIC
#include <dlfcn.h>
#endif  /* SOCKSLIBRARY_DYNAMIC */
#include <errno.h>
#include <fcntl.h>
#if HAVE_LIMITS_H
#include <limits.h>
#endif  /* HAVE_LIMITS_H */
#include <netdb.h>
#include <pwd.h>
#include <setjmp.h>
#include <signal.h>
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif  /* STDC_HEADERS */
#include <stdio.h>
#include <stdlib.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif  /* HAVE_STRINGS_H */
#if STDC_HEADERS
#include <string.h>
#endif  /* STDC_HEADERS */
#include <syslog.h>
#if HAVE_LIBWRAP && HAVE_TCPD_H
#include <tcpd.h>
#endif  /* HAVE_LIBWRAP && HAVE_TCPD_H */
#if TIME_WITH_SYS_TIME || (!TIME_WITH_SYS_TIME && !HAVE_SYS_TIME_H)
#include <time.h>
#endif
#if HAVE_UNISTD_H
#ifdef HAVE_DEC_PROTO
#undef  _XOPEN_SOURCE_EXTENDED
#endif  /* HAVE_DEC_PROTO */
#include <unistd.h>
#ifdef HAVE_DEC_PROTO
#define _XOPEN_SOURCE_EXTENDED 1
#endif /* HAVE_DEC_PROTO */
#endif  /* HAVE_UNISTD_H */
#if HAVE_RESOLV_H
#include <resolv.h>
#endif /* HAVE_RESOLV_H */
#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif /* HAVE_IFADDRS_H */
#if HAVE_PAM
#include <security/pam_appl.h>
#endif /* HAVE_PAM */

#include "yacconfig.h"

#if HAVE_LINUX_BUGS
#if (defined __bswap_16) && (!defined __bswap_32)
#undef ntohl
#undef ntohs
#undef htonl
#undef htons
#endif
#endif /* HAVE_LINUX_BUGS */

#ifdef lint
extern const int lintnoloop_common_h;
#else
#define lintnoloop_common_h 0
#endif

#include "config.h"

#define SOCKS_TRYHARDER	0	/* XXX BUGS */ /* XXX should be configure option. */

#ifndef RLIMIT_OFILE
#define RLIMIT_OFILE RLIMIT_NOFILE
#endif /* !RLIMIT_OFILE */


#if NEED_GETSOCKOPT_CAST
#define getsockopt(a,b,c,d,e) getsockopt((a),(b),(c),(char *)(d),(e))
#define setsockopt(a,b,c,d,e) setsockopt((a),(b),(c),(char *)(d),(e))
#endif  /* NEED_GETSOCKOPT_CAST */

#if !HAVE_BZERO
#define bzero(b, len) memset(b, 0, len)
#endif  /* !HAVE_BZERO */

#if !HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
#endif  /* !HAVE_SIG_ATOMIC_T */

#ifdef DIAGNOSTIC
#undef DIAGNOSTIC
#define DIAGNOSTIC 1
#else
#define DIAGNOSTIC 0
#endif

#ifdef DEBUG
#undef DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#if DEBUG
#if !DIAGNOSTIC
#undef DIAGNOSTIC
#define DIAGNOSTIC 1
#endif  /* !DIAGNOSTIC */

/*
 * Solaris 2.5.1 and it's stream stuff is broken and puts the processes
 * into never-never land forever on half the sendmsg() calls if they
 * involve ancillary data.  (it seems to deadlock the processes.)
 */

#ifndef HAVE_SENDMSG_DEADLOCK
#define HAVE_SENDMSG_DEADLOCK 1
#endif

#ifndef HAVE_ACCEPTLOCK
#define HAVE_ACCEPTLOCK 1
#endif

#endif  /* DEBUG */


/* __P and __BEGIN_DECLS definitions taken from libtool manual */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

#undef __P
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
# define __P(protos) protos
#else
# define __P(protos) ()
#endif

#if SIZEOF_CHAR == 1
 typedef unsigned char ubits_8;
 typedef          char sbits_8;
#else
error "no known 8 bits wide datatype"
#endif

#if SIZEOF_SHORT == 2
 typedef unsigned short ubits_16;
 typedef          short sbits_16;
#else
# if SIZEOF_INT == 2
  typedef unsigned int ubits_16;
  typedef          int sbits_16;
# else
error "no known 16 bits wide datatype"
# endif
#endif


#if SIZEOF_INT == 4
 typedef unsigned int ubits_32;
 typedef          int sbits_32;
#else
# if SIZEOF_SHORT == 4
   typedef unsigned short ubits_32;
   typedef          short sbits_32;
# else
#  if SIZEOF_LONG == 4
    typedef unsigned long ubits_32;
    typedef          long sbits_32;
#  else
error "no known 32 bits wide datatype"
#  endif /* SIZEOF_LONG == 4 */
# endif /* SIZEOF_SHORT == 4 */
#endif /* SIZEOF_INT == 4 */

#if !HAVE_INT8_T
#define int8_t sbits_8
#endif /* HAVE_INT8_T */

#if !HAVE_INT16_T
#define int16_t sbits_16
#endif /* HAVE_INT16_T */

#if !HAVE_INT32_T
#define int32_t sbits_32
#endif /* HAVE_INT32_T */

#if !HAVE_UINT8_T
#define uint8_t ubits_8
#endif /* HAVE_UINT8_T */

#if !HAVE_UINT16_T
#define uint16_t ubits_16
#endif /* HAVE_UINT16_T */

#if !HAVE_UINT32_T
#define uint32_t ubits_32
#endif /* HAVE_UINT32_T */

#if !HAVE_IN_PORT_T
#define in_port_t ubits_16
#endif /* HAVE_IN_PORT_T */

#if !HAVE_IN_ADDR_T
#define in_addr_t ubits_32
#endif /* HAVE_IN_ADDR_T */

#ifndef INADDR_NONE
# define INADDR_NONE (ubits_32) 0xffffffff
#endif  /* !INADDR_NONE */

#ifndef MAX
# define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif /* !MAX */

#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif /* !MIN */

#if NEED_EXIT_FAILURE
/* XXX assumes EXIT_SUCCESS is undefined too */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#endif /* NEED_EXIT_FAILURE */

#if NEED_SA_RESTART
#define SA_RESTART SV_INTERRUPT
#endif  /* NEED_SA_RESTART */

#if NEED_AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif  /* NEED_AF_LOCAL */

#if HAVE_NOMALLOC_REALLOC
#define realloc(p,s) (((p) == NULL) ? (malloc(s)) : (realloc((p),(s))))
#endif  /* HAVE_NOMALLOC_REALLOC */

#if HAVE_NONULL_FREE
#define free(p)	(((p) == NULL) ? ((void)(p)) : (free(p)))
#endif

/* __CONCAT macro from anoncvs */
#ifndef __CONCAT
#if defined(__STDC__) || defined(__cplusplus)
#define __CONCAT(x,y)    x ## y
#else
#define __CONCAT(x,y)    x/**/y
#endif
#endif

#ifndef __CONCAT3
#if defined(__STDC__) || defined(__cplusplus)
#define __CONCAT3(x,y,z)        x ## y ## z
#else
#define __CONCAT3(x,y,z)        x/**/y/**/z
#endif
#endif


#if !HAVE_STRUCT_IPOPTS
#define	MAX_IPOPTLEN	40
struct ipoption {
	struct	in_addr ipopt_dst;
	sbits_8	ipopt_list[MAX_IPOPTLEN];
};
#endif  /* !HAVE_STRUCT_IPOPTS */

#if !HAVE_IN6_ADDR
/* from OpenBSD netinet6/in6.h */
struct in6_addr {
	union {
		u_int8_t   __u6_addr8[16];
		u_int16_t  __u6_addr16[8];
		u_int32_t  __u6_addr32[4];
	} __u6_addr;/* 128-bit IP6 address */
};
#define s6_addr   __u6_addr.__u6_addr8
#endif /* !HAVE_IN6_ADDR */

#if !HAVE_TIMER_MACROS
/* timeval macros, taken from OpenBSD sys/time.h */
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)

#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)
#endif /* !HAVE_TIMER_MACROS */

#if 0
#if !HAVE_SOCKADDR_STORAGE
/*
 * sockaddr_storage (see rfc2553).
 * struct taken from OpenBSD <sys/socket.h>
 */
struct sockaddr_storage {
	u_int8_t    ss_len;		/* total length */
	sa_family_t ss_family;		/* address family */
	u_char	    __ss_pad1[6];	/* align to quad */
	u_int64_t   __ss_pad2;		/* force alignment for stupid compilers */
	u_char      __ss_pad3[240];	/* pad to a total of 256 bytes */
};
#endif /* !HAVE_SOCKADDR_STORAGE */
#endif


#if !HAVE_GETIFADDRS
/* Taken from OpenBSD <ifaddrs.h> */
struct ifaddrs {
	struct ifaddrs  *ifa_next;
	char		*ifa_name;
	unsigned int	 ifa_flags;
	struct sockaddr	*ifa_addr;
	struct sockaddr	*ifa_netmask;
/*XXX*/
#undef ifa_dstaddr
	struct sockaddr	*ifa_dstaddr;
	void		*ifa_data;
};

/*
 * This may have been defined in <net/if.h>.  Note that if <net/if.h> is
 * to be included it must be included before this header file.
 */
#ifndef	ifa_broadaddr
#define	ifa_broadaddr	ifa_dstaddr	/* broadcast address interface */
#endif

#endif /* !HAVE_GETIFADDRS */

/*
 * BSDI 4.1 doesn't have freeifaddrs(), but uses free()
 *  Problem reported by "Zand, Nooshin" <nooshin.zand@intel.com>
 */
#if HAVE_GETIFADDRS && !HAVE_FREEIFADDRS
#define freeifaddrs free
#endif /* HAVE_GETIFADDRS && !HAVE_FREEIFADDRS */

#define TOIN(addr) ((struct sockaddr_in *)(addr))
#define TOCIN(addr) ((const struct sockaddr_in *)(addr))

/* global variables needed by everyone. */
extern struct config_t sockscf;
extern char *__progname;

#if !HAVE_H_ERRNO
extern int h_errno;
#endif  /* !HAVE_H_ERRNO */

	/*
	 * defines
	 */


#define IP_MAXPORT 65535	/* max value for ip port number. */

/*
 * redefine system limits to match that of socks protocol.
 * No need for these to be bigger than protocol allows, but they
 * _must_ be atleast as big as protocol allows.
 */

#ifdef	MAXHOSTNAMELEN
#undef	MAXHOSTNAMELEN
#endif
#define	MAXHOSTNAMELEN		(255 + 1)		/* socks5: 255, +1 for len. */

#ifdef	MAXNAMELEN
#undef	MAXNAMELEN
#endif
#define	MAXNAMELEN			(255 + 1)		/* socks5: 255, +1 for len. */

#ifdef	MAXPWLEN
#undef	MAXPWLEN
#endif
#define	MAXPWLEN				(255 + 1)		/* socks5: 255, +1 for len. */


#define	MAXIFNAMELEN		255

/*									"255." "255." "255." "255" "." "65535" + NUL */
#define	MAXSOCKADDRSTRING	 (4   +   4   + 4   +  3  + 1 +    5   + 1)

/*														   "." + "65535" + NUL */
#define	MAXSOCKSHOSTSTRING (MAXHOSTNAMELEN + 1  +    5)

#define	MAXRULEADDRSTRING	 (MAXSOCKSHOSTSTRING * 2)


#define MAXAUTHINFOLEN		(((sizeof("(") - 1) + MAXMETHODSTRING) \
									+ (sizeof(")") - 1) + (sizeof("@") - 1) + MAXNAMELEN)

#ifndef NUL
#define NUL '\0'
#endif

/*
 * We don't care whether it's called O_NONBLOCK, FNDELAY or whatever.
 * We just want to know whether the flags set give blocking or nonblocking
 * semantics.
 */
#ifndef FNDELAY
#define NONBLOCKING	(O_NONBLOCK | O_NDELAY)
#else
#define NONBLOCKING	(O_NONBLOCK | FNDELAY | O_NDELAY)
#endif

#define CONFIGTYPE_SERVER		1
#define CONFIGTYPE_CLIENT		2

#define PROTOCOL_TCPs			"tcp"
#define PROTOCOL_UDPs			"udp"
#define PROTOCOL_UNKNOWNs		"unknown"

#define RESOLVEPROTOCOL_UDP	0
#define RESOLVEPROTOCOL_TCP	1
#define RESOLVEPROTOCOL_FAKE	2

#define LOGTYPE_SYSLOG			0x1
#define LOGTYPE_FILE				0x2

#define NOMEM						"<memory exhausted>"


	/*
	 * macros
	 */


#ifndef _NO_FUNCTION_REDIFINE
#define close(n)	closen(n)

/* XXX needed on AIX apparently */
#ifdef recvmsg
#define recvmsg_system recvmsg
#undef recvmsg
#endif /* recvmsg */

#if HAVE_SYSTEM_XMSG_MAGIC
#undef recvmsg_system
#define recvmsg_system nrecvmsg
#endif /* HAVE_SYSTEM_XMSG_MAGIC */

#define recvmsg(s, msg, flags)	recvmsgn(s, msg, flags)

#ifdef sendmsg
#define sendmsg_system sendmsg
#undef sendmsg
#endif /* sendmsg */

#if HAVE_SYSTEM_XMSG_MAGIC
#undef sendmsg_system
#define sendmsg_system nsendmsg
#endif /* HAVE_SYSTEM_XMSG_MAGIC */

#define sendmsg(s, msg, flags)	sendmsgn(s, msg, flags)

#endif /* _NO_FUNCTION_REDIFINE */


#define PORTISRESERVED(port)	\
	(ntohs((port)) != 0 && ntohs((port)) < IPPORT_RESERVED)

#define ADDRISBOUND(addr) \
	((((struct sockaddr_in *)(&addr))->sin_addr.s_addr != htonl(INADDR_ANY)) \
	|| (((struct sockaddr_in *)(&addr))->sin_port != htons(0)))

#define ELEMENTS(array) (sizeof(array) / sizeof(array[0]))

#define OCTETIFY(a) ((a) &= 0xff)
/*
 * Note that it's the argument that will be truncated, not just the
 * return value.
 */


/*
 * macros to manipulate ancillary data depending on if we're on sysv or BSD.
 */

/*
 * Modern CMSG alignment macros. Use them if the platform has them,
 * if not we get the default behaviour.
 */

#if HAVE_CMSGHDR

#if !HAVE_CMSG_LEN
#define CMSG_LEN(len) (sizeof(struct cmsghdr) + (len))
#endif /* !HAVE_CMSG_LEN */

#if !HAVE_CMSG_SPACE
#define CMSG_SPACE(len) (sizeof(struct cmsghdr) + (len))
#endif /* !HAVE_CMSG_SPACE */

#else /* HAVE_CMSGHDR */

#if !HAVE_CMSG_LEN
#define CMSG_LEN(len) (len)
#endif /* !HAVE_CMSG_LEN */

#if !HAVE_CMSG_SPACE
#define CMSG_SPACE(len) (len)
#endif /* !HAVE_CMSG_SPACE */

#endif /* HAVE_CMSGHDR */

/*
 * allocate memory for a controlmessage of size "size".  "name" is the
 * name of the allocated memory.
 */
#if HAVE_CMSGHDR
#define CMSG_AALLOC(name, size) \
	union { \
		char cmsgmem[CMSG_SPACE(size)]; \
		struct cmsghdr align; \
	} __CONCAT3(_, name, mem); \
	struct cmsghdr *name = &__CONCAT3(_, name, mem).align
#else /* !HAVE_CMSGHDR */
#define CMSG_AALLOC(name, size) \
	char name[(size)]
#endif /* !HAVE_CMSGHDR */

/*
 * Returns the size of the previously allocated controlmessage named
 * "name"
 */
#if HAVE_CMSGHDR
#define CMSG_MEMSIZE(name) (sizeof(__CONCAT3(_, name, mem)))
#else /* !HAVE_CMSGHDR */
#define CMSG_MEMSIZE(name) (sizeof((name)))
#endif

/*
 * Returns the controldata member of "msg".
 */
#if HAVE_CMSGHDR
/* cast is necessary on AIX, due to buggy headers there?. */
#define CMSG_CONTROLDATA(msg)	((struct cmsghdr *)((msg).msg_control))
#else /* !HAVE_CMSGHDR */
#define CMSG_CONTROLDATA(msg)	((msg).msg_accrights)
#endif

/*
 * add "object" to "data".  "object" is the object to add to "data" at
 * offset "offset".
 */
#if HAVE_CMSGHDR
#define CMSG_ADDOBJECT(object, data, offset) \
	do \
		memcpy(CMSG_DATA(data) + (offset), &(object), sizeof(object)); \
	while (lintnoloop_common_h)
#else /* !HAVE_CMSGHDR */
#define CMSG_ADDOBJECT(object, data, offset) \
	do \
		memcpy(data + (offset), &(object), sizeof((object))); \
	while (lintnoloop_common_h)
#endif /* !HAVE_CMSGHDR */


/*
 * get a object from controldata "data".
 * "object" is the object to fill with data gotten from "data" at offset
 * "offset".
 */
#if HAVE_CMSGHDR
#define CMSG_GETOBJECT(object, data, offset) \
	do \
		memcpy(&(object), CMSG_DATA((data)) + (offset), sizeof((object))); \
	while (lintnoloop_common_h)
#else /* !HAVE_CMSGHDR */
#define CMSG_GETOBJECT(object, data, offset) \
	do \
		memcpy(&(object), ((data) + (offset)), sizeof((object))); \
	while (lintnoloop_common_h)
#endif /* !HAVE_CMSGHDR */



/*
 * Sets up "object" for sending a controlmessage of size "size".
 * "controlmem" is the memory the controlmessage is stored in.
 */
#if HAVE_CMSGHDR
#define CMSG_SETHDR_SEND(object, controlmem, size) \
	do { \
		controlmem->cmsg_level		= SOL_SOCKET; \
		controlmem->cmsg_type		= SCM_RIGHTS; \
		controlmem->cmsg_len			= CMSG_LEN(size); \
		\
		object.msg_control		= (caddr_t)controlmem; \
		object.msg_controllen	= controlmem->cmsg_len; \
	} while (lintnoloop_common_h)
#else /* !HAVE_CMSGHDR */
#define CMSG_SETHDR_SEND(object, controlmem, size) \
	do { \
		object.msg_accrights		= (caddr_t)controlmem; \
		object.msg_accrightslen	= (size); \
	} while (lintnoloop_common_h)
#endif /* !HAVE_CMSGHDR */

/*
 * Sets up "object" for receiving a controlmessage of size "size".
 * "controlmem" is the memory set aside for the controlmessage.
 */
#if HAVE_CMSGHDR
#define CMSG_SETHDR_RECV(object, controlmem, size) \
	do { \
		object.msg_control		= (caddr_t)controlmem; \
		object.msg_controllen	= (size); \
	} while (lintnoloop_common_h)
#else /* !HAVE_CMSGHDR */
#define CMSG_SETHDR_RECV(object, controlmem, size) \
	do { \
		object.msg_accrights		= (caddr_t)controlmem; \
		object.msg_accrightslen	= (size); \
	} while (lintnoloop_common_h)
#endif /* !HAVE_CMSGHDR */


/* returns length of controldata actually sent. */
#if HAVE_CMSGHDR
#define CMSG_GETLEN(msg)	((msg).msg_controllen - CMSG_LEN(0))
#else
#define CMSG_GETLEN(msg)	((msg).msg_accrightslen)
#endif

#if HAVE_CMSGHDR
#define CMSG_TOTLEN(msg)	((msg).msg_controllen)
#else
#define CMSG_TOTLEN(msg)	((msg).msg_accrightslen)
#endif


#define INTERNAL_ERROR \
"an internal error was detected at %s:%d\nvalue = %ld, version = %s"

#define SASSERT(expression)	\
do {									\
	if (!(expression))			\
		SERR(expression);			\
} while (lintnoloop_common_h)


#define SASSERTX(expression)	\
do {									\
	if (!(expression))			\
		SERRX(expression);		\
} while (lintnoloop_common_h)


/*
 * wrappers around err()/errx()/warn()/warnx() for more consistent error
 * messages.
 * "failure" is the value that was wrong and which caused the internal error.
 */


#define SERR(failure)				\
do {										\
	SWARN(failure);					\
	abort();								\
} while (lintnoloop_common_h)

#define SERRX(failure)				\
do {										\
	SWARNX(failure);					\
	abort();								\
} while (lintnoloop_common_h)


#define SWARN(failure)		\
	swarn(INTERNAL_ERROR,	\
	__FILE__, __LINE__,	(long int)(failure), rcsid)

#define SWARNX(failure)		\
	swarnx(INTERNAL_ERROR,	\
	__FILE__, __LINE__,	(long int)(failure), rcsid)



#define ERR(failure)									\
do {														\
	warn(INTERNAL_ERROR, __FILE__, __LINE__,	\
	(long int)(failure), rcsid);					\
	abort();												\
} while (p)

#define ERRX(failure)								\
do {														\
	warnx(INTERNAL_ERROR, __FILE__, __LINE__, \
	(long int)(failure), rcsid);					\
	abort();												\
} while (lintnoloop_common_h)


#define WARN(failure) \
	warn(INTERNAL_ERROR, __FILE__, __LINE__, (long int)(failure), rcsid)

#define WARNX(failure) \
	warnx(INTERNAL_ERROR, __FILE__, __LINE__, (long int)(failure), rcsid)

#define ERRORMSG(failure) \
	error_msg(LOG_HIGH, INTERNAL_ERROR, __FILE__, __LINE__, (long int)(failure),\
	rcsid)


/* the size of a UDP header "packet" (no padding) */
#define PACKETSIZE_UDP(packet) (												\
	sizeof((packet)->flag) + sizeof((packet)->frag)						\
	+ sizeof((packet)->host.atype) + sizeof((packet)->host.port)	\
	+ (ADDRESSIZE_V5(packet)))


/*
 * returns the length of the current address field in socks packet "packet".
 * "packet" can be one of pointer to response_t, request_t or udpheader_t.
 */
#define ADDRESSIZE(packet) ( \
	  ((packet)->version == SOCKS_V4 ? \
	  (ADDRESSIZE_V4(packet)) : (ADDRESSIZE_V5(packet))))

/*
 *	version specifics
 */
#define ADDRESSIZE_V5(packet) (																\
  (packet)->host.atype == SOCKS_ADDR_IPV4 ?												\
  sizeof((packet)->host.addr.ipv4) :(packet)->host.atype == SOCKS_ADDR_IPV6 ?	\
  sizeof((packet)->host.addr.ipv6) : (strlen((packet)->host.addr.domain) + 1))

#define ADDRESSIZE_V4(packet) ( \
	(packet)->atype == SOCKS_ADDR_IPV4 ? \
	sizeof((packet)->addr.ipv4) : (strlen((packet)->addr.host) + 1))


/*
 * This is for Rgethostbyname() support for clients without access to
 * DNS.
 * FAKEIP_START is the first address in the range of "fake" IP addresses,
 * FAKEIP_END is the last.
 * There can thus be FAKEIP_END - FAKEIP_START number of fake IP addresses
 * supported per program.
 *
 * INADDR_NONE and INADDR_ANY may not be part of the range.
 */
#define FAKEIP_START 0x00000001
#define FAKEIP_END	0x000000ff

#define SOCKS_V4					4
#define SOCKS_V4s					"socks_v4"
#define SOCKS_V4REPLY_VERSION 0
#define SOCKS_V5					5
#define SOCKS_V5s					"socks_v5"
#define MSPROXY_V2				2
#define MSPROXY_V2s				"msproxy_v2"
#define HTTP_V1_0					1
#define HTTP_V1_0s				"http_v1.0"

/* subnegotiation. */
#define SOCKS_UNAMEVERSION		1

/* authentication METHOD values. */
#define AUTHMETHOD_NOTSET		-1
#define AUTHMETHOD_NOTSETs		"notset"
#define AUTHMETHOD_NONE			0
#define AUTHMETHOD_NONEs		"none"
#define AUTHMETHOD_GSSAPI		1
#define AUTHMETHOD_GSSAPIs		"gssapi"
#define AUTHMETHOD_UNAME		2
#define AUTHMETHOD_UNAMEs		"username"

/* X'03' to X'7F' IANA ASSIGNED						*/

/* X'80' to X'FE' RESERVED FOR PRIVATE METHODS	*/

#define AUTHMETHOD_NOACCEPT	255
#define AUTHMETHOD_NOACCEPTs	"no acceptable method"

/* not standard methods, must be > AUTHMETHOD_NOACCEPT. */
#define AUTHMETHOD_RFC931		(AUTHMETHOD_NOACCEPT + 1)
#define AUTHMETHOD_RFC931s		"rfc931"

#define AUTHMETHOD_PAM			(AUTHMETHOD_RFC931 + 1)
#define AUTHMETHOD_PAMs			"pam"

#define AUTHMETHOD_MAX			(AUTHMETHOD_PAM + 1)

#define MAXMETHODSTRING			MAX(sizeof(AUTHMETHOD_NONEs),		\
										MAX(sizeof(AUTHMETHOD_GSSAPIs),	\
										MAX(sizeof(AUTHMETHOD_UNAMEs),	\
										MAX(sizeof(AUTHMETHOD_RFC931s),	\
										sizeof(AUTHMETHOD_PAMs)))))

/* number of supported methods. */
#define MAXMETHOD					1 /* NONE		*/	\
									 + 1 /* UNAME		*/	\
									 + 1 /* RFC931		*/	\
									 + 1 /* RFC931		*/

/*
 *  Response commands/codes
 */
#define SOCKS_CONNECT				1
#define SOCKS_CONNECTs				"connect"
#define SOCKS_BIND					2
#define SOCKS_BINDs					"bind"
#define SOCKS_UDPASSOCIATE       3
#define SOCKS_UDPASSOCIATEs		"udpassociate"

/* pseudo commands */

#define SOCKS_COMMANDEND			0xff

#define SOCKS_BINDREPLY				(SOCKS_COMMANDEND + 1)
#define SOCKS_BINDREPLYs			"bindreply"

#define SOCKS_UDPREPLY				(SOCKS_BINDREPLY + 1)
#define SOCKS_UDPREPLYs				"udpreply"

/* misc. stuff */
#define SOCKS_ACCEPT					(SOCKS_UDPREPLY + 1)
#define SOCKS_ACCEPTs				"accept"

#define SOCKS_DISCONNECT			(SOCKS_ACCEPT + 1)
#define SOCKS_DISCONNECTs			"disconnect"

#define SOCKS_UNKNOWN				(SOCKS_DISCONNECT + 1)
#define SOCKS_UNKNOWNs				"unknown"


/* address types */
#define SOCKS_ADDR_IPV4			0x01
/* not a socks constant but put here for convenience. */
#define SOCKS_ADDR_IFNAME		0x02
#define SOCKS_ADDR_DOMAIN		0x03
#define SOCKS_ADDR_IPV6       0x04


/* reply field values */
#define SOCKS_SUCCESS			0x00
#define SOCKS_FAILURE			0x01
#define SOCKS_NOTALLOWED		0x02
#define SOCKS_NETUNREACH		0x03
#define SOCKS_HOSTUNREACH		0x04
#define SOCKS_CONNREFUSED		0x05
#define SOCKS_TTLEXPIRED		0x06
#define SOCKS_CMD_UNSUPP		0x07
#define SOCKS_ADDR_UNSUPP		0x08
#define SOCKS_INVALID_ADDRESS 0x09

/* version 4 codes. */
#define SOCKSV4_SUCCESS			90
#define SOCKSV4_FAIL				91
#define SOCKSV4_NO_IDENTD		92
#define SOCKSV4_BAD_ID			93

/* http stuff. */
#define HTTP_SUCCESS				200


#define MSPROXY_PINGINTERVAL	(6 * 60)

#define MSPROXY_SUCCESS			0
#define MSPROXY_FAILURE			1
#define MSPROXY_NOTALLOWED		2

#define MSPROXY_MINLENGTH		172			/* minimum length of packet.				*/
#define MSPROXY_VERSION			0x00010200	/* perhaps?									*/

/* errors */
#define MSPROXY_ADDRINUSE				0x0701
#define MSPROXY_BIND_AUTHFAILED		0x0804	/* auth failed for connect.	*/
#define MSPROXY_CONNECT_AUTHFAILED	0x081e	/* auth failed for bind.		*/
#define MSPROXY_CONNREFUSED			0x4		/* low 12 bits seem to vary.	*/

/*
 * Server seems to ignore low-order bits of a 0x47?? command, so take them
 * for our own use.
 */
#define MSPROXY_HELLO				0x0500	/* packet 1 from client.				*/
#define MSPROXY_HELLO_ACK			0x1000	/* packet 1 from server.				*/

#define MSPROXY_USERINFO			0x1000	/* packet 2 from client.				*/
#define MSPROXY_USERINFO_ACK		0x0400	/* packet 2 from server.				*/

#define MSPROXY_SOMETHING			0x4700	/* packet 3 from client.				*/
#define MSPROXY_SOMETHING_1_ACK	0x4714	/* packet 3 from server.				*/

#define MSPROXY_SOMETHING_2		0x4701	/* packet 4 from client.				*/
#define MSPROXY_SOMETHING_2_ACK	0x4715	/* packet 4 from server, high 8 bits
															seem to vary.							*/
#define MSPROXY_SOMETHING_2_ACK2	0x4716	/* could be this too... dunno.		*/

#define MSPROXY_RESOLVE				0x070d	/* resolve request from client.		*/
#define MSPROXY_RESOLVE_ACK		0x070f	/* resolved info from server.			*/

#define MSPROXY_BIND					0x0704	/* bind request.							*/
#define MSPROXY_BIND_ACK			0x0706	/* bind request accepted.				*/

#define MSPROXY_BIND2				0x0707	/* dunno.									*/
#define MSPROXY_BIND2_ACK			0x0708	/* dunno.									*/

#define MSPROXY_BIND2				0x0707	/* dunno.									*/
#define MSPROXY_BIND2_ACK			0x0708	/* dunno.									*/

#define MSPROXY_LISTEN				0x0406	/* listen() performed(?)				*/

#define MSPROXY_BINDINFO			0x0709	/* info about client server accepted*/

#define MSPROXY_BINDINFO_ACK		0x070a	/* we got the info(?)					*/

#define MSPROXY_CONNECT				0x071e	/* connect request.						*/
#define MSPROXY_CONNECT_ACK		0x0703	/* connect request accepted.			*/

#define MSPROXY_UDPASSOCIATE		0x0705	/* UDP associate request.				*/
#define MSPROXY_UDPASSOCIATE_ACK	0x0706	/* UDP associate request accepted.	*/

#define MSPROXY_CONNECTED			0x042c	/* client connected to server?		*/

#define MSPROXY_SESSIONEND			0x251e	/* maybe...									*/


/* flag _bits_ */
#define SOCKS_INTERFACEREQUEST	0x01
#define SOCKS_USECLIENTPORT		0x04

/* subcommands */
#define SOCKS_INTERFACEDATA		0x01


#define SOCKS_TCP			1
#define SOCKS_UDP			2

#define SOCKS_RECV		0
#define SOCKS_SEND		1

/* offsets into authentication packet */
#define AUTH_VERSION		0	/* version of method packet.								*/

/* request */
#define AUTH_NMETHODS	1	/* number of methods to offer.							*/
#define AUTH_METHODS		2	/* start of methods to offer.								*/

/* reply */
#define AUTH_VERSION		0	/* offset for version in reply.							*/
#define AUTH_METHOD		1	/* offset for selected method in reply.				*/

/* offsets into username/password negotiation packet */
#define UNAME_VERSION	0
#define UNAME_STATUS		1

/* XXX no IPv6 support currently. */
#define SOCKS_IPV6_ALEN 16

enum operator_t { none = 0, eq, neq, ge, le, gt, lt, range };


struct logtype_t {
	int				type;			/* type of logging (where to).						*/
	FILE				**fpv;		/* if logging is to file, this is the open file.*/
	char				**fnamev;	/* if logging is to file, name of file.			*/
	size_t			fpc;			/* number of files.										*/
	int				*fplockv;	/* locking of logfiles.									*/
	int				facility;	/* if logging to syslog, this is the facility.	*/
	const char		*facilityname;	/* if logging to syslog, name of facility.	*/ };



/* extensions supported by us. */
struct extension_t {
	unsigned bind:1;		/* use bind extension? */
	unsigned :0;
};



/* the address part of a socks packet */
union socksaddr_t {
	struct in_addr ipv4;
	char				ipv6[SOCKS_IPV6_ALEN];
	char				domain[MAXHOSTNAMELEN]; /* _always_ stored as C string.		*/
};

/* the hostspecific part of misc. things */
struct sockshost_t {
	unsigned char			atype;
	union socksaddr_t		addr;
	in_port_t				port;
};



struct msproxy_request_t {
	char						username[MAXNAMELEN];
	char						unknown[MAXNAMELEN];
	char						executable[MAXNAMELEN];
	char						clienthost[MAXHOSTNAMELEN];

	int32_t					clientid;			/* 1-4										*/
	int32_t					magic25;				/* 5-8										*/
	int32_t					serverid;			/* 9-12										*/
	unsigned char			serverack;			/* 13: ack of last server packet		*/
	char						pad10[3];			/* 14-16										*/
	unsigned char			sequence;			/* 17: sequence # of this packet.	*/
	char						pad11[7];			/* 18-24										*/
	char						RWSP[4];				/* 25-28: 0x52,0x57,0x53,0x50			*/
	char						pad15[8];			/* 29-36										*/
	int16_t					command;				/* 37-38										*/

	/* packet specifics start at 39. */
	union {
		struct {
			char				pad1[18];			/* 39-56										*/
			int16_t			magic3;				/* 57-58										*/
			char           pad3[114];			/* 59-172									*/
			int16_t			magic5;				/* 173-174: 0x4b, 0x00					*/
			char				pad5[2];				/* 175-176									*/
			int16_t			magic10;				/* 177-178: 0x14, 0x00					*/
			char				pad6[2];				/* 179-180									*/
			int16_t			magic15;				/* 181-182: 0x04, 0x00					*/
			char				pad10[6];			/* 183-188									*/
			int16_t			magic20;				/* 189-190: 0x57, 0x04					*/
			int16_t			magic25;				/* 191-192: 0x00, 0x04					*/
			int16_t			magic30;				/* 193-194: 0x01, 0x00					*/
			char				pad20[2];			/* 195-196: 0x4a, 0x02					*/
			int16_t			magic35;				/* 197-198: 0x4a, 0x02					*/
			char				pad30[10];			/* 199-208									*/
			int16_t			magic40;				/* 209-210: 0x30, 0x00					*/
			char				pad40[2];			/* 211-212									*/
			int16_t			magic45;				/* 213-214: 0x44, 0x00					*/
			char				pad45[2];			/* 215-216									*/
			int16_t			magic50;				/* 217-218: 0x39, 0x00					*/
			char				pad50[2];			/* 219-220									*/
		} _1;

		struct {
			char				pad1[18];			/* 39-56										*/
			int16_t			magic3;				/* 57-58										*/
			char           pad3[114];			/* 59-172									*/
			int16_t			magic5;				/* 173-174: 0x00, 0x4b					*/
			char				pad5[2];				/* 175-176									*/
			int16_t			magic10;				/* 177-178: 0x14, 0x00					*/
			char				pad10[2];			/* 179-180									*/
			int16_t			magic15;				/* 181-182: 0x04, 0x00					*/
			char				pad15[6];			/* 183-188									*/
			int16_t			magic20;				/* 189-190: 0x57, 0x04					*/
			int16_t			magic25;				/* 191-192: 0x00, 0x04					*/
			int16_t			magic30;				/* 193-194: 0x01, 0x00					*/
			char				pad20[2];			/* 195-196									*/
			int16_t			magic35;				/* 197-198: 0x04, 0x00					*/
			char				pad25[10];			/* 199-208									*/
			int16_t			magic50;				/* 209-210: 0x30, 0x00					*/
			char				pad50[2];			/* 211-212									*/
			int16_t			magic55;				/* 213-214: 0x44, 0x00					*/
			char				pad55[2];			/* 215-216									*/
			int16_t			magic60;				/* 217-218: 0x39, 0x00					*/
		} _2;

		struct {
			char				pad1[4];				/* 39-42										*/
			int16_t			magic2;				/* 43-44										*/
			char				pad10[12];			/* 45-56										*/
			in_addr_t		bindaddr;			/* 57-60: address to bind.				*/
			in_port_t		bindport;			/* 61-62: port to bind.					*/
			char           pad15[2];			/* 63-64										*/
			int16_t			magic3;				/* 65-66										*/
			in_port_t		boundport;			/* 67-68										*/
			char           pad20[104];			/* 69-172									*/
			char				NTLMSSP[sizeof("NTLMSSP")];	/* 173-180: "NTLMSSP"	*/
			int16_t			magic5;				/* 181-182: 0x01, 0x00					*/
			char				pad25[2];			/* 183-184									*/
			int16_t			magic10;				/* 185-186: 0x96, 0x82					*/
			int16_t			magic15;				/* 187-188: 0x08, 0x00					*/
			int16_t			magic20;				/* 189-190: 0x28, 0x00					*/
			char				pad30[2];			/* 191-192									*/
			int16_t			magic25;				/* 193-194: 0x96, 0x82					*/
			int16_t			magic30;				/* 195-196: 0x01, 0x00					*/
			char				pad40[12];			/* 197-208									*/
			int16_t			magic50;				/* 209-210: 0x30, 0x00					*/
			char				pad50[6];			/* 211-216									*/
			int16_t			magic55;				/* 217-218: 0x30, 0x00					*/
			char				pad55[2];			/* 219-220									*/
		} _3;

		struct {
			char				pad1[4];				/* 39-42										*/
			int16_t			magic1;				/* 43-44										*/
			int32_t			magic2;				/* 45-48										*/
			char				pad2[8];				/* 49-56										*/
			int16_t			magic3;				/* 57-58										*/
			char				pad3[6];				/* 59-64										*/
			int16_t			magic4;				/* 65-66										*/
			in_port_t		boundport;			/* 67-68										*/
			char           pad4[104];			/* 69-172									*/
			char				NTLMSSP[sizeof("NTLMSSP")];	/* 173-180: "NTLMSSP"	*/
			int16_t			magic5;				/* 181-182: 0x03, 0x00					*/
			char				pad5[2];				/* 183-184									*/
			int16_t			magic10;				/* 185-186: 0x18, 0x00					*/
			int16_t			magic15;				/* 187-188: 0x18, 0x00					*/
			int16_t			magic20;				/* 189-190: 0x49, 0x00					*/
			char				pad10[6];			/* 191-196									*/
			int16_t			magic30;				/* 197-198: 0x61, 0x00					*/
			char				pad15[2];			/* 199-200									*/
			int16_t			magic35;				/* 201-202: 0x08, 0x00					*/
			int16_t			magic40;				/* 203-204: 0x08, 0x00					*/
			int16_t			magic45;				/* 205-206: 0x34, 0x00					*/
			char				pad20[2];			/* 207-208									*/
			int16_t			magic50;				/* 209-210: 0x07, 0x00					*/
			int16_t			magic55;				/* 211-212: 0x07, 0x00					*/
			int16_t			magic60;				/* 213-214: 0x3c, 0x00					*/
			char				pad25[2];			/* 215-216									*/
			int16_t			magic65;				/* 217-218: 0x06, 0x00					*/
			int16_t			magic70;				/* 219-220: 0x06, 0x00					*/
			int16_t			magic75;				/* 221-222: 0x43, 0x00					*/
		} _4;

		struct {
			unsigned char	hostlength;			/* length of host, including NUL.	*/
			char				pad1[17];			/* 39-56										*/
			char				*host;				/* 57-...									*/
		} resolve;

		struct {
			int16_t			magic1;				/* 39-40										*/
			char				pad1[4];				/* 41-45										*/
			int32_t			magic3;				/* 45-48										*/
			char				pad5[8];				/* 48-56										*/
			int16_t			magic6;				/* 57-58: 0x0200							*/
			in_port_t		destport;			/* 59-60										*/
			in_addr_t		destaddr;			/* 61-64										*/
			char				pad10[4];			/* 65-68										*/
			int16_t			magic10;				/* 69-70										*/
			char				pad15[2];			/* 71-72										*/
			in_port_t		srcport;				/* 73-74: port client connects from	*/
			char				pad20[82];			/* 75-156									*/
		} _5;

		struct {
			int16_t			magic1;				/* 39-40										*/
			char				pad5[2];				/* 41-42										*/
			int16_t			magic5;				/* 43-44										*/
			int32_t			magic10;				/* 45-48										*/
			char				pad10[2];			/* 49-50										*/
			int16_t			magic15;				/* 51-52										*/
			int32_t			magic16;				/* 53-56										*/
			int16_t			magic20;				/* 57-58										*/
			in_port_t		clientport;			/* 59-60: forwarded port.				*/
			in_addr_t		clientaddr;			/* 61-64: forwarded address.			*/
			int32_t			magic30;				/* 65-68										*/
			int32_t			magic35;				/* 69-72										*/
			in_port_t		serverport;			/* 73-74: port server will connect
														 *	       to us from.
														*/
			in_port_t		srcport;				/* 75-76: connect request; port used
														 *			 on client behalf.
														*/
			in_port_t		boundport;			/* 77-78: bind request; port used
														 *		 on client behalf.
														*/
			in_addr_t		boundaddr;			/* 79-82: addr used on client behalf*/
			char				pad30[90];			/* 83-172									*/
		} _6;

	} packet;
};

struct msproxy_response_t {
	int32_t					packetid;			/* 1-4										*/
	int32_t					magic5;				/* 5-8										*/
	int32_t              serverid;			/* 9-12										*/
	char						clientack;			/* 13: ack of last client packet.	*/
	char						pad5[3];				/* 14-16										*/
	unsigned char			sequence;			/* 17: sequence # of this packet.	*/
	char						pad10[7];			/* 18-24										*/
	char						RWSP[4];				/* 25-28: 0x52,0x57,0x53,0x50			*/
	char						pad15[8];			/* 29-36										*/
	int16_t					command;				/* 37-38										*/

	union {
		struct {
			char				pad5[18];			/* 39-56										*/
			int16_t			magic20;				/* 57-58: 0x02, 0x00						*/
			char				pad10[6];			/* 59-64										*/
			int16_t			magic30;				/* 65-66: 0x74, 0x01						*/
			char				pad15[2];			/* 67-68										*/
			int16_t			magic35;				/* 69-70: 0x0c, 0x00						*/
			char				pad20[6];			/* 71-76										*/
			int16_t			magic50;				/* 77-78: 0x04, 0x00						*/
			char				pad30[6];			/* 79-84										*/
			int16_t			magic60;				/* 85-86: 0x65, 0x05						*/
			char				pad35[2];			/* 87-88										*/
			int16_t			magic65;				/* 89-90: 0x02, 0x00						*/
			char				pad40[8];			/* 91-98										*/
			in_port_t		udpport;				/* 99-100									*/
			in_addr_t		udpaddr;				/* 101-104									*/
		} _1;

		struct {
			char				pad5[18];			/* 39-56										*/
			int16_t			magic5;				/* 57-58: 0x01, 0x00						*/
		} _2;

		struct {
			char				pad1[6];				/* 39-44										*/
			int32_t			magic10;				/* 45-48										*/
			char				pad3[10];			/* 49-58										*/
			in_port_t		boundport;			/* 59-60: port server bound for us.	*/
			in_addr_t		boundaddr;			/* 61-64: addr server bound for us.	*/
			char				pad10[4];			/* 65-68										*/
			int16_t			magic15;				/* 69-70										*/
			char				pad15[102];			/* 70-172									*/
			char				NTLMSSP[sizeof("NTLMSSP")];	/* 173-180: "NTLMSSP"	*/
			int16_t			magic50;				/* 181-182: 0x02, 0x00					*/
			char				pad50[2];			/* 183-184									*/
			int16_t			magic55;				/* 185-186: 0x08, 0x00					*/
			int16_t			magic60;				/* 187-188: 0x08, 0x00					*/
			int16_t			magic65;				/* 189-190: 0x28, 0x00					*/
			char				pad60[2];			/* 191-192									*/
			int16_t			magic70;				/* 193-194: 0x96, 0x82					*/
			int16_t			magic75;				/* 195-196: 0x01, 0x00					*/
			char				pad70[16];			/* 197-212									*/
			char				ntdomain[257];		/* 213-EOP									*/
		} _3;

		struct {
			char				pad5[134];			/* 39-172									*/
		} _4;

		struct {
			unsigned char	addroffset;			/* 39: weird, probably wrong.			*/
			char				pad5[13];			/* 40-52										*/
			in_addr_t		hostaddr;			/* ?-?+4										*/
		} resolve;

		struct {
			int16_t			magic1;				/* 39-40										*/
			char				pad5[18];			/* 41-58										*/
			in_port_t		clientport;			/* 59-60: forwarded port.				*/
			in_addr_t		clientaddr;			/* 61-64: forwarded address.			*/
			int32_t			magic10;				/* 65-68										*/
			int32_t			magic15;				/* 69-72										*/
			in_port_t		serverport;			/* 73-74: port server will connect
														 *	       to us from.
														*/
			in_port_t		srcport;				/* 75-76: connect request; port used
														 *			 on client behalf.
														*/
			in_port_t		boundport;			/* 77-78: bind request; port used
														 *			 on client behalf.
														*/
			in_addr_t		boundaddr;			/* 79-82: addr used on client behalf*/
			char				pad10[90];			/* 83-172									*/
		} _5;
	} packet;
};

struct request_t {
	unsigned char			version;
	unsigned char			command;
	unsigned char			flag;
	struct sockshost_t	host;
	struct authmethod_t	*auth;	/* pointer to level above. */
};


struct response_t {
	unsigned char			version;
	unsigned char			reply;
	unsigned char			flag;
	struct sockshost_t	host;
	struct authmethod_t	*auth;	/* pointer to level above. */
};

/* encapsulation for UDP packets. */
struct udpheader_t {
	unsigned char			flag[2];
	unsigned char			frag;
	struct sockshost_t	host;
};


/* method username */
struct authmethod_uname_t {
	unsigned char	version;
	unsigned char	name[MAXNAMELEN];
	unsigned char	password[MAXPWLEN];
};

/* method rfc931 */
struct authmethod_rfc931_t {
	unsigned char	name[MAXNAMELEN];
};

/* method pam. */
struct authmethod_pam_t {
	char				servicename[MAXNAMELEN];	/* servicename to use with pam.	*/
	unsigned char	name[MAXNAMELEN];
	unsigned char	password[MAXPWLEN];
};

/* this must be big enough to hold a complete method request. */
struct authmethod_t {
	int						method;					/* method in use.						*/
	int						methodv[MAXMETHOD];	/* methods somewhere matched.		*/
	size_t					methodc;					/* number of methods matched.		*/
	int						badmethodv[MAXMETHOD];/* methods not matched.			*/
	size_t					badmethodc;				/* number of methods not matched.*/

	union {
		struct authmethod_uname_t	uname;
		struct authmethod_rfc931_t	rfc931;
		struct authmethod_pam_t		pam;
	} mdata;
};


struct protocol_t {
	unsigned tcp:1;
	unsigned udp:1;
	unsigned :0;
};


struct command_t {
	unsigned bind:1;
	unsigned connect:1;
	unsigned udpassociate:1;

	/* not real commands as per standard, but they have their use. */
	unsigned bindreply:1;		/* reply to bind command.	*/
	unsigned udpreply:1;			/* reply to UDP packet.		*/
	unsigned :0;
};


struct proxyprotocol_t {
	unsigned socks_v4:1;
	unsigned socks_v5:1;
	unsigned msproxy_v2:1;
	unsigned http_v1_0:1;
	unsigned :0;
};



struct msproxy_state_t {
	struct sockaddr_in		controladdr;	/* UDP address of proxyserver.		*/
	int32_t						magic25;
	int32_t						bindid;
	int32_t						clientid;
	int32_t						serverid;
	unsigned char				seq_recv;		/* seq number of last packet recv.	*/
	unsigned char				seq_sent;		/* seq number of last packet sent.	*/
};


/* values in parentheses designate "don't care" values.	*/
struct socksstate_t {
	int							acceptpending;	/* a accept pending?		(-1)			*/
	struct authmethod_t		auth;				/* authentication in use.				*/
	int							command;			/* command (-1)							*/
	int							err;				/* if request failed, errno.			*/
	int							inprogress;		/* operation in progress? (-1)		*/
#ifdef SOCKS_TRYHARDER
	int							lock;				/* some calls require a lock.			*/
#endif
	struct msproxy_state_t	msproxy;			/* if msproxy, msproxy state.			*/
	struct protocol_t			protocol;		/* protocol in use.						*/
	unsigned						udpconnect:1;	/* connected UDP socket?				*/
	int							system;			/* don't check, use system call.		*/
	int							version;			/* version (-1)							*/
};


struct ruleaddress_t {
	char						atype;
	union {
		char					domain[MAXHOSTNAMELEN];
		char					ifname[MAXIFNAMELEN];
		struct {
			struct in_addr	ip;
			struct in_addr	mask;
		} ipv4;

	} addr;

	struct {
		in_port_t			tcp;			/* TCP portstart or field to operator on.	*/
		in_port_t			udp;			/* UDP portstart or field to operator on.	*/
	} port;
	in_port_t				portend;		/* only used if operator is range.			*/
	enum operator_t		operator;	/* operator to compare ports via.			*/
};

struct serverstate_t {
	struct command_t			command;
	struct extension_t		extension;
	struct protocol_t			protocol;
	int							methodv[MAXMETHOD];		/* methods to offer.			*/
	size_t						methodc;						/* number of methods set.	*/
	struct proxyprotocol_t	proxyprotocol;
};


struct gateway_t {
	struct sockshost_t			host;
	struct serverstate_t			state;
};


struct socks_t {
	unsigned char				version;
									/*
									 *	Negotiated version.  Each request and
									 *	response will also contain a version number, that
									 *	is the version number given for that particular
									 *	packet and should be checked to make sure it is
									 *  the same as the negotiated version.
									*/
	struct request_t				req;
	struct response_t				res;
	struct authmethod_t			auth;
	struct gateway_t				gw;
	struct socksstate_t			state;
};

enum portcmp { e_lt, e_gt, e_eq, e_neq, e_le, e_ge, e_nil };



/*
 * for use in generic functions that take either reply or request
 * packets, include a field indicating what it is.
 */
#define SOCKS_REQUEST	0x1
#define SOCKS_RESPONSE	0x2

struct socksfd_t {
	unsigned					allocated:1;/* allocated?										*/
	int						control;		/* control connection to server.				*/
	struct socksstate_t	state;		/* state of this connection.					*/
	unsigned					:0;
	struct sockaddr		local;		/* local address of data connection.		*/
	unsigned					:0;
	struct sockaddr		server;		/* remote address of data connection.		*/
	unsigned					:0;
	struct sockaddr		remote;		/* address server is using on our behalf.	*/
	unsigned					:0;
	struct sockaddr		reply;		/* address to expect reply from.				*/
	unsigned					:0;

	union {
		struct sockaddr		accepted;	/* address server accepted for us.		*/
		struct sockaddr		connected;	/* address server connected to for us.	*/
	} forus;

	struct route_t		*route;
};



struct route_t {
	int							number;		/* routenumber.								*/

	struct {
		unsigned bad:1;		/* route is bad?												*/
		time_t	badtime;		/* if route is bad, time it was marked as such.		*/
		unsigned direct:1;	/* direct connection, no proxy.							*/
		unsigned :0;
	} state;


	struct ruleaddress_t		src;
	struct ruleaddress_t		dst;
	struct gateway_t			gw;

	struct route_t				*next;		/* next route in list.						*/
};



__BEGIN_DECLS

/*
 * versions of BSD's error functions that log via slog() instead.
 */

#ifdef STDC_HEADERS
void serr(int eval, const char *fmt, ...)
#else
void serr()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 2, 3)));

#ifdef STDC_HEADERS
void serrx(int eval, const char *fmt, ...)
#else
void serrx()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 2, 3)));

#ifdef STDC_HEADERS
void swarn(const char *fmt, ...)
#else
void swarn()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 1, 2)));

#ifdef STDC_HEADERS
void swarnx(const char *fmt, ...)
#else
void swarnx()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 1, 2)));

void
genericinit __P((void));
/*
 * Generic init, called after clientinit()/serverinit().
 */

void
newprocinit __P((void));
/*
 * After a new process is started/forked, this function should
 * be called.  It will initialize various things, open needed
 * descriptors, etc. and can be called as many times as wanted.
 */


struct udpheader_t *
sockaddr2udpheader __P((const struct sockaddr *to, struct udpheader_t *header));
/*
 * Writes a udpheader representation of "to" to "header".
 * Returns a pointer to "header".
 */

char *
udpheader_add __P((const struct sockshost_t *host, char *msg, size_t *len,
						 size_t msgsize));
/*
 * Prefixes the udpheader_t version of "host" to a copy of "msg",
 * which is of length "len".
 * "msgsize" gives the size of the memory pointed to by "msg".
 * If "msgsize" is large enough the function will prepend the udpheader
 * to "msg" directly (moving the old contents to the right) rather than
 * allocating new memory.
 * Upon return "len" gives the length of the new "msg".
 *
 *	Returns:
 *		On success: "msg" with the udpheader prepended.
 *		On failure: NULL (out of memory).
 */

int
socks_socketisbound __P((int s));
/*
 * Returns:
 *		If "s" is bound: 1
 *		If "s" is not bound: 0
 *		If "s" is not socket or error occurred determining if bound: -1
 */

int
fdisopen __P((int fd));
/*
 * returns 1 if the filedescriptor "fd" currently references a open object.
 * returns 0 otherwise.
 */

void
closev __P((int *array, int count));
/*
 * Goes through "array", which contains "count" elements.
 * Each element that does not have a negative value is closed.
 */

int
socks_logmatch __P((unsigned int d, const struct logtype_t *log));
/*
 * Returns true if "d" is a descriptor matching any descriptor in "log".
 * Returns false otherwise.
 */


struct sockaddr *
sockshost2sockaddr __P((const struct sockshost_t *shost,
								struct sockaddr *addr));
/*
 * Converts the sockshost_t "shost" to a sockaddr struct and stores it
 * in "addr".
 * Returns: "addr".
 */

struct sockaddr *
fakesockshost2sockaddr __P((const struct sockshost_t *host,
									 struct sockaddr *addr));
/*
 * Like sockshost2sockaddr(), but checks whether the address in
 * "host" is fake when converting.
 */

struct sockshost_t *
sockaddr2sockshost __P((const struct sockaddr *addr, struct sockshost_t *host));
/*
 * Converts the sockaddr struct "shost" to a sockshost_t struct and stores it
 * in "host".
 * Returns: "host".
 */

struct sockshost_t *
ruleaddress2sockshost __P((const struct ruleaddress_t *address,
									struct sockshost_t *host, int protocol));
/*
 * Converts the ruleaddress_t "address" to a sockshost_t struct and stores it
 * in "host".
 * Returns: "host".
 */

struct ruleaddress_t *
sockshost2ruleaddress __P((const struct sockshost_t *host,
									struct ruleaddress_t *addr));
/*
 * Converts the sockshost_t "host" to a ruleaddress_t struct and stores it
 * in "addr".
 * Returns: "addr".
 */

struct ruleaddress_t *
sockaddr2ruleaddress __P((const struct sockaddr *addr,
								  struct ruleaddress_t *ruleaddr));
/*
 * Converts the struct sockaddr "addr" to a ruleaddress_t struct and stores
 * it in "ruleaddr".
 * Returns: "addr".
 */

struct sockaddr *
hostname2sockaddr __P((const char *name, int index, struct sockaddr *addr));
/*
 * Retrieves the address with index "index" for the hostname named "name".
 * Returns:
 *		On success: "addr", filled in with the address found.
 *		On failure: NULL (no address found).
 */

struct sockaddr *
ifname2sockaddr __P((const char *ifname, int index, struct sockaddr *addr));
/*
 * Retrieves the address with index "index" on the interface named "ifname".
 * Returns:
 *		On success: "addr", filled in with the address found.
 *		On failure: NULL (no address found).
 */

int
sockatmark __P((int s));
/*
 * If "s" is at oob mark, return 1, otherwise 0.
 * Returns -1 if a error occurred.
 */

ssize_t
recvmsgn __P((int s, struct msghdr *msg, int flags));
/*
 * Like recvmsg(), but tries to read until all has been read.
 */

ssize_t
sendmsgn __P((int s, const struct msghdr *msg, int flags));
/*
 * Like sendmsg(), but tries to send until all has been sent.
 */

ssize_t
readn __P((int, void *, size_t, struct authmethod_t *auth));
/*
 * Like read() but retries and takes an additional "auth" argument
 * to be used if not NULL.
 */

ssize_t
writen __P((int, const void *, size_t, struct authmethod_t *auth));
/*
 * like write() but retries and takes an additional "auth" argument
 * to be used if not NULL.
 */

ssize_t
socks_recvfrom __P((int, void *, size_t, int, struct sockaddr *, socklen_t *,
						  struct authmethod_t *auth));
/*
 * Like recvfrom(), but with an additional auth argument to be used
 * if not NULL.
 */

ssize_t
socks_sendto __P((int, const void *, size_t, int, const struct sockaddr *,
						socklen_t, struct authmethod_t *auth));
/*
 * Like sendto(), but with an additional auth argument to be used
 * if not NULL.
 */

int
closen __P((int));
/*
 * Wrapper around close().  Retries on EINTR.
 */

int
selectn __P((int, fd_set *, fd_set *, fd_set *, struct timeval *));
/*
 * Wrapper around select().  Retries on EINTR.
 */

int
acceptn __P((int, struct sockaddr *, socklen_t *));
/*
 * Wrapper around accept().  Retries on EINTR.
 */

#ifdef STDC_HEADERS
int
snprintfn(char *str, size_t size, const char *format, ...);
#else
int
snprintfn();
#endif
/*
 * Wrapper around snprintf() for consistent behaviour, same as system
 * snprintf() but the following are also enforced:
 *		returns 0 instead of -1 (rawterminates *str).
 *		never returns a value greater than size - 1.
 */

const char *
strcheck __P((const char *string));
/*
 * Checks "string".  If it is NULL, returns a string indicating memory
 * exhausted, if not, returns the same string it was passed.
 */


unsigned char *
sockshost2mem __P((const struct sockshost_t *host, unsigned char *mem,
						 int version));
/*
 * Writes "host" out to "mem".  The caller must make sure "mem"
 * is big enough to hold the contents of "host".
 * "version" gives the socks version "host" is to be written out in.
 * Returns a pointer to one element past the last byte written to "mem".
 */

const unsigned char *
mem2sockshost __P((struct sockshost_t *host, const unsigned char *mem,
						 size_t len, int version));
/*
 * Writes "mem", which is assumed to be a sockshost string
 * of version "version" in network order, out to "host".
 * Returns:
 *		On success: pointer to one element past last byte used of mem
 *						and fills in "host" appropriately.
 *		On failure: NULL ("mem" is not a valid sockshost.)
 */

#ifdef STDC_HEADERS
void slog(int priority, const char *fmt, ...)
#else
void slog()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 2, 3)));
/*
 * Logs message "fmt" at priority "priority" to previously configured
 * outputdevice.
 * Checks settings and ignores message if it's of to low a priority.
 */

#ifdef STDC_HEADERS
void vslog(int priority, const char *fmt, va_list ap);
#else
void vslog();
#endif  /* STDC_HEADERS */
/*
 * Same as slog() but assumes varargs/stdargs have already processed
 * the arguments.
 */

int
readconfig __P((const char *filename));
/*
 * Parses the config stored in in the filename "filename".
 * Returns:
 *		On success: 0.
 *		On failure: -1.
 */

#ifdef STDC_HEADERS
void
yywarn (const char *fmt, ...)
#else
void
yywarn()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 1, 2)));
/*
 * Report a error related to (configfile) parsing.
 */

#ifdef STDC_HEADERS
void
yyerror (const char *fmt, ...)
#else
void
yyerror()
#endif  /* STDC_HEADERS */
__attribute__ ((format (__printf__, 1, 2)));
/*
 * Report a error related to (configfile) parsing and exit.
 */

int
addressmatch __P((const struct ruleaddress_t *rule,
						const struct sockshost_t *address, int protocol,
						int ipalias));
/*
 * Tries to match "address" against "rule".  "address" is resolved
 * if necessary.  "address" supports the wildcard INADDR_ANY and port of 0.
 * "protocol" is the protocol to compare under.
 * If "ipalias" is true, the function will try to match any IP alias
 * "address"'s might have if appropriate, this can be useful to match
 * multihomed hosts where the client requests e.g a bind connection.
 * Returns true if "rule" matched "address".
 */

struct hostent *
hostentdup __P((const struct hostent *hostent));
/*
 * Duplicates "hostent".
 * Returns:
 *		On success: a pointer to the duplicated hostent.
 *		On failure: NULL.
 */

void
hostentfree __P((struct hostent *hostent));
/*
 * Free's all resourced used by "hostent", including "hostent"
 * itself.  If "hostent" is NULL, nothing is done.
 */



int
socks_connect __P((int s, const struct sockshost_t *host));
/*
 * Tries to connect to "host".  If "host"'s address is not a IP address,
 * the function also tries to connect to any alias for "host"'s
 * name.  The connection is done using the open descriptor "s".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

struct route_t *
socks_connectroute __P((int s, struct socks_t *packet,
								const struct sockshost_t *src,
								const struct sockshost_t *dst));
/*
 * Finds a route from "src" to "dst" and connects to it "s".
 * If src or dst is NULL, that argument is ignored.
 *
 * The route used may take into account the contents of "packet->req",
 * which is assumed to be the packet that will be sent to a socksserver,
 * so it is recommended that it's contents be as conservative as possible.
 *
 * When it has successfully connected to a gateway it will set
 * the packet->method members to point to the methods the gateway
 * should be offered.
 *
 * Returns:
 *		On success: the route that was used.
 *		On failure: NULL.  See errno for reason.  0 means no route exists.
 */


struct request_t *
socks_requestpolish __P((struct request_t *req, const struct sockshost_t *src,
							   const struct sockshost_t *dst));
/*
 * Tries to "polish" the request "req" so that a later socks_getroute()
 * will succeed.
 * Returns:
 *		On success: "req".
 *		On failure: NULL.
 */

void
showstate __P((const struct serverstate_t *state));
/*
 * Shows "state".
 */

void
showmethod __P((size_t methodc, const int *methodv));
/*
 * Shows "methodv".
 */

struct route_t *
addroute __P((const struct route_t *route));
/*
 * Appends a copy of "route" to our list of routes.
 * Returns a pointer to the added route.
 */

void
showroute __P((const struct route_t *route));
/*
 * prints the route "route".
 */


struct route_t *
socks_getroute __P((const struct request_t *req, const struct sockshost_t *src,
						  const struct sockshost_t *dst));
/*
 * Tries to find a  route to be used for a connection going from
 * "src" to "dst".
 * If src or dst is NULL, that argument is ignored.
 *
 * The route used may take into account the contents of "req", which is
 * assumed to be the packet that will be sent to a socksserver, so it is
 * recommended that it's contents be as conservative as possible.
 *
 * Returns:
 *		On success: pointer to route that should be used.
 *		On failure: NULL (no socks route found).
 */


unsigned char
sockscode __P((int version, int code));
/*
 * Maps the socks replycode "code", which is in non-version specific format,
 * to the equivalent replycode in version "version".
 */

unsigned char
errno2reply __P((int errnum, int version));
/*
 * Returns the socks version "version" reply code for a error of type "errno".
 */

char *
str2vis __P((const char *string, size_t len));
/*
 * Visually encodes exactly "len" chars of "string".
 * Returns:
 *		On success: the visually encoded string, to be free()'ed by caller.
 *		On failure: NULL.  (out of memory).
 */

in_addr_t
socks_addfakeip __P((const char *name));
/*
 * Adds "name" to a internal table indexed by (fake)IP addresses.
 * Returns:
 *		On success: "name"'s index.
 *		On failure:	INADDR_NONE
 */

const char *
socks_getfakehost __P((in_addr_t addr));
/*
 * If "addr" is a "fake" (non-resolved) addr, it returns the name
 * corresponding to it.
 * Else, NULL is returned.
 */

int
socks_getfakeip __P((const char *host, struct in_addr *addr));
/*
 * If "host" has a fake address entry, the address is written into
 * "addr".
 * Returns:
 *		If a fake address exits: 1
 *		Else: 0
 */

struct sockshost_t *
fakesockaddr2sockshost __P((const struct sockaddr *addr,
									 struct sockshost_t *host));
/*
 * Identical to sockaddr2sockshost, but checks whether
 * the address in "addr" is a "fake" one when converting.
 */

int
sockaddrareeq __P((const struct sockaddr *a, const struct sockaddr *b));
/*
 * Compares the address "a" against "b".
 * Returns:
 *		If "a" and "b" are equal: true
 *		else: false
 */

int
sockshostareeq __P((const struct sockshost_t *a, const struct sockshost_t *b));
/*
 * Compares the address "a" against "b".
 * Returns:
 *		If "a" and "b" are equal: true
 *		else: false
 */

int
fdsetop __P((int nfds, int op, const fd_set *a, const fd_set *b,
				 fd_set *result));
/*
 * Performs operation on descriptor sets.
 * "nfds" is the number of descriptors to perform "op" on in the sets
 * "a" and "b".
 * "op" is the operation to be performed on the descriptor sets and
 * can take on the value of standard C bitwise operators.
 * The result of the operation is stored in "result".
 *
 * Returns the number of the highest descriptor set in "result".
 * NOTES:
 *		Operators supported is: AND ('&') and XOR ('^')
 */

int
methodisset __P((int method, const int *methodv, size_t methodc));
/*
 * Returns true if the method "method" is set in "methodv", false otherwise.
 * "methodc" is the length of "methodv".
 */

int
socketoptdup __P((int s));
/*
 * Duplicates the settings of "s" and returns a new socket with the
 * same settings.
 * Returns:
 *		On success: the descriptor for the new socket
 *		On failure: -1
 */

int
socks_mklock __P((const char *template));
/*
 * Creates a filedescriptor that can be used with socks_lock() and
 * socks_unlock().
 * Returns:
 *		On success: filedescriptor
 *		On failure: -1
 */

int
socks_lock __P((int fd, int type, int timeout));
/*
 * Looks the filedescriptor "fd".
 * "type" is the type of lock; F_RDLCK or F_WRLCK.
 * "timeout" is how long to wait for lock, supported values:
 *		-1: forever.
 *		0 : don't wait.
 * Returns:
 *		On success: 0
 *		On error  : -1
 */

void
socks_unlock __P((int d));
/*
 * Unlocks the filedescriptor "d", previously locked by this process.
 */

int
bitcount __P((unsigned long number));
/*
 * Returns the number of bits set in "number".
 */

#if SOCKSLIBRARY_DYNAMIC
struct hostent *sys_gethostbyaddr __P((const char *addr, int len, int af));
struct hostent *sys_gethostbyname __P((const char *));
struct hostent *sys_gethostbyname2 __P((const char *, int));
#if HAVE_GETADDRINFO
int sys_getaddrinfo __P((const char *nodename, const char *servname,
			 				const struct addrinfo *hints, struct addrinfo **res));
#endif /* HAVE_GETADDRINFO */
#if HAVE_GETIPNODEBYNAME
struct hostent *sys_getipnodebyname __P((const char *name, int af, int flags,
					 int *error_num));
#endif /* HAVE_GETIPNODEBYNAME */
#endif /* SOCKSLIBRARY_DYNAMIC */

#if defined(DEBUG) || HAVE_SOLARIS_BUGS

int
freedescriptors __P((const char *message));
/*
 * Returns the number on unallocated descriptors.
 */

#endif /* DEBUG) || HAVE_SOLARIS_BUGS */


#ifdef DEBUG

int
fd_isset __P((int fd, fd_set *fdset));
/* function version of FD_ISSET() */

#endif /* DEBUG */

/* replacements */

#if !HAVE_DAEMON
int daemon __P((int, int));
#endif  /* !HAVE_DAEMON */

#if !HAVE_GETDTABLESIZE
/* return upper limit on per-process open file descriptors */
int getdtablesize __P((void));
#endif  /* !HAVE_GETDTABLESIZE */

#if !HAVE_VSNPRINTF
# ifdef STDC_HEADERS
int snprintf __P((char *, size_t, char const *, ...));
# else
int snprintf ();
# endif /* STDC_HEADERS */
int vsnprintf __P((char *, size_t, const char *, va_list));
#endif /* !HAVE_VSNPRINTF */

#if !HAVE_SETPROCTITLE
#ifdef STDC_HEADERS
void setproctitle __P((const char *fmt, ...))
__attribute__ ((format (__printf__, 1, 2)));
int initsetproctitle __P((int, char **, char **));
#else
void setproctitle()
__attribute__ ((format (__printf__, 1, 2)));
int initsetproctitle __P((int, char **, char **));
#endif  /* STDC_HEADERS */
#endif  /* !HAVE_SETPROCTITLE */

#if !HAVE_SOCKATMARK
int sockatmark __P((int));
#endif  /* !HAVE_SOCKATMARK */

#if !HAVE_INET_ATON
int inet_aton __P((register const char *cp, struct in_addr *addr));
#endif  /* ! HAVE_ATON */

#if !HAVE_GETDTABLESIZE
int getdtablesize __P((void));
#endif  /* ! HAVE_GETDTABLESIZE */

#if !HAVE_STRERROR
char *__strerror __P((int, char *));
char *strerror __P((int));
const char *hstrerror __P((int));
#endif  /* !HAVE_STRERROR */

#if !HAVE_MEMMOVE
void * memmove __P((void *, const void *, register size_t));
#endif  /* !HAVE_MEMMOVE */

#if !HAVE_INET_PTON
int inet_pton __P((int af, const char *src, void *dst));
#endif

#if !HAVE_ISSETUGID
int issetugid __P((void));
#endif  /* !HAVE_ISSETUGID */

#if !HAVE_VSYSLOG
void vsyslog __P((int, const char *, va_list));
#endif  /* !HAVE_VSYSLOG */

#if !HAVE_GETIFADDRS
int getifaddrs __P((struct ifaddrs **));
void freeifaddrs __P((struct ifaddrs *));
#endif /* !HAVE_GETIFADDRS */

struct passwd *
socks_getpwnam __P((const char *login));
/*
 * Like getpwnam() but works around sysv bug, tries to get the shadow
 * password too.
 */

int
msproxy_negotiate __P((int s, int control, struct socks_t *packet));
/*
 * Negotiates with the msproxy server connected to "control".
 * "s" gives the socket to be used for dataflow.
 * "packet" contains the request and on return from the function
 * contains the response.
 * Returns:
 *		On success: 0 (server replied to our request).
 *		On failure: -1
 */


int
send_msprequest __P((int s, struct msproxy_state_t *state,
						  struct msproxy_request_t *packet));
/*
 * Sends a msproxy request to "s".
 * "state" is the current state of the connection to "s",
 * "packet" is the request to send.
 */

int
recv_mspresponse __P((int s, struct msproxy_state_t *state,
						  struct msproxy_response_t *packet));
/*
 * Receives a msproxy response from "s".
 * "state" is the current state of the connection to "s",
 * "packet" is the memory the response is read into.
 */

int
msproxy_sigio __P((int s));
/*
 * Must be called on sockets where we expect the connection to be forwarded
 * by the msproxy server.
 * "s" is the socket and must have been added with socks_addaddr() beforehand.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

int
msproxy_init __P((void));
/*
 * inits things for using a msproxyserver.
 *		On success: 0
 *		On failure: -1
 */

int
httpproxy_negotiate __P((int control, struct socks_t *packet));
/*
 * Negotiates a method to be used when talking with the server connected
 * to "s".  "packet" is the packet that will later be sent to server.
 * packet->res.reply will be set depending on the result of negotiation.
 * Returns:
 *		On success: 0 (server accepted our request).
 *		On failure: -1.
 */


int
socks_negotiate __P((int s, int control, struct socks_t *packet,
							struct route_t *route));
/*
 * "s" is the socket data will flow over.
 * "control" is the control connection to the socks server.
 * "packet" is a socks packet containing the request.
 *	"route" is the connected route.
 * Negotiates method and fills the response to the request into packet->res.
 * Returns:
 *		On success: 0 (server replied to our request).
 *		On failure: -1.
 */

int
serverreplyisok __P((int version, int reply, struct route_t *route));
/*
 * "replycode" is the reply code returned by a socksserver of version
 * "version".
 * "route" is the route that was used for the socksserver.  If
 * the errorcode indicates a serverfailure, it might be "badrouted".
 * Returns true if the reply indicates request succeeded, false otherwise
 * and sets errno accordingly.
 */


struct route_t *
socks_nbconnectroute __P((int s, int control, struct socks_t *packet,
								  const struct sockshost_t *src,
								  const struct sockshost_t *dst));
/*
 * The non-blocking version of socks_connectroute(), only used by client.
 * Takes one additional argument, "s", which is the socket to connect
 * and not necessarily the same as "control" (msproxy case).
 */

void
socks_badroute __P((struct route_t *route));
/*
 * Marks route "route" as bad.
 */

int
negotiate_method __P((int s, struct socks_t *packet));
/*
 * Negotiates a method to be used when talking with the server connected
 * to "s".  "packet" is the packet that will later be sent to server,
 * only the "auth" element in it will be set but other elements are needed
 * too.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */


int
clientmethod_uname __P((int s, const struct sockshost_t *host, int version,
								unsigned char *name, unsigned char *password));
/*
 * Enters username/password negotiation with the socksserver connected to
 * the socket "s".
 * "host" gives the name of the server.
 * "version" gives the socksversion established to use.
 * "name", if not NULL, gives the name to use for authenticating.
 * "password", if not NULL, gives the name to use for authenticating.
 * Returns:
 *		On success: 0
 *		On failure: whatever the remote socksserver returned as status.
 */



void
checkmodule __P((const char *name));
/*
 * Checks that the system has the module "name" and permission to use it.
 * Aborts with a errormessage if not.
 */

int socks_yyparse __P((void));
int socks_yylex __P((void));


__END_DECLS

#if SOCKSLIBRARY_DYNAMIC
#include "interposition.h"
#endif /* SOCKSLIBRARY_DYNAMIC */

/* XXX */
#if defined(SOCKS_CLIENT) || defined(SOCKS_SERVER)
#if SOCKS_CLIENT
#include "socks.h"
#endif
#if SOCKS_SERVER
#include "sockd.h"
#endif  /* SOCKS_CLIENT */
#endif  /* SOCKS_CLIENT || SOCKS_SERVER */

#include "tostring.h"
