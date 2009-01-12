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
#include <grp.h>

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
#define free(p)   (((p) == NULL) ? ((void)(p)) : (free(p)))
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
#define   MAX_IPOPTLEN   40
struct ipoption {
   struct   in_addr ipopt_dst;
   sbits_8   ipopt_list[MAX_IPOPTLEN];
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
   u_int8_t    ss_len;      /* total length */
   sa_family_t ss_family;      /* address family */
   u_char       __ss_pad1[6];   /* align to quad */
   u_int64_t   __ss_pad2;      /* force alignment for stupid compilers */
   u_char      __ss_pad3[240];   /* pad to a total of 256 bytes */
};
#endif /* !HAVE_SOCKADDR_STORAGE */
#endif


#if !HAVE_GETIFADDRS
/*
 * Copyright (c) 2000 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id: osdep.h,v 1.3 2009/01/11 21:21:01 karls Exp $ */

#ifndef __ifaddrs_h__
#define __ifaddrs_h__

#if 0
#ifndef ROKEN_LIB_FUNCTION
#ifdef _WIN32
#define ROKEN_LIB_FUNCTION _stdcall
#else
#define ROKEN_LIB_FUNCTION
#endif
#endif
#endif
#define ROKEN_LIB_FUNCTION

/*
 * the interface is defined in terms of the fields below, and this is
 * sometimes #define'd, so there seems to be no simple way of solving
 * this and this seemed the best. */

#undef ifa_dstaddr

struct ifaddrs {
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned int ifa_flags;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    struct sockaddr *ifa_dstaddr;
    void *ifa_data;
};

#ifndef ifa_broadaddr
#define ifa_broadaddr ifa_dstaddr
#endif

int ROKEN_LIB_FUNCTION
rk_getifaddrs(struct ifaddrs**);

void ROKEN_LIB_FUNCTION
rk_freeifaddrs(struct ifaddrs*);

#define getifaddrs(a) rk_getifaddrs(a)
#define freeifaddrs(a) rk_freeifaddrs(a)

#endif /* __ifaddrs_h__ */
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
