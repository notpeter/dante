/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011
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

/* $Id: common.h,v 1.591 2011/06/19 14:33:16 michaels Exp $ */

#ifndef _COMMON_H_
#define _COMMON_H_

/* ifdef, not if, defined on command line */
#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif /* HAVE_CONFIG_H */

#ifndef NO_OSDEP
#include "osdep.h"
#endif /* !NO_OSDEP */

#include "yacconfig.h"

#include "config.h"

/* global variables needed by everyone. */
extern struct config_t sockscf;
extern char *__progname;

   /*
    * defines
    */
#if HAVE_SOLARIS_BUGS
#define HAVE_UNIQUE_SOCKET_INODES   (0)
#else /* !HAVE_SOLARIS_BUGS */
#define HAVE_UNIQUE_SOCKET_INODES   (1)
#endif /* HAVE_SOLARIS_BUGS */

#define SOCKS_IGNORE_SIGNALSAFETY   (0)

#if DEBUG

#if !DIAGNOSTIC
#undef DIAGNOSTIC
#define DIAGNOSTIC 1
#endif /* !DIAGNOSTIC */

/*
 * Solaris 2.5.1 and it's stream stuff is broken and puts the processes
 * into never-never land forever on half the sendmsg() calls if they
 * involve ancillary data.  (it seems to deadlock the processes.)
 */
/* always enable if DEBUG */
#undef HAVE_SENDMSG_DEADLOCK
#define HAVE_SENDMSG_DEADLOCK 1

#undef HAVE_ACCEPTLOCK
#define HAVE_ACCEPTLOCK 1

#endif /* DEBUG */

#define TOIN(addr) ((struct sockaddr_in *)(addr))
#define TOCIN(addr) ((const struct sockaddr_in *)(addr))

#define IP_MAXPORT (65535)   /* max value for ip port number. */

/*
 * redefine system limits to match that of socks protocol.
 * No need for these to be bigger than protocol allows, but they
 * _must_ be at least as big as protocol allows.
 */

#ifdef   MAXHOSTNAMELEN
#undef   MAXHOSTNAMELEN
#endif /* MAXHOSTNAMELEN */
#define  MAXHOSTNAMELEN    (255 + 1)      /* socks5: 255, +1 for len. */

#ifdef   MAXURLLEN
#undef   MAXURLLEN
#endif /* MAXURLLEN */
#define  MAXURLLEN         (255 + 1)      /* whatever. */

#ifdef   MAXNAMELEN
#undef   MAXNAMELEN
#endif /* MAXNAMELEN */
#define  MAXNAMELEN        (255 + 1)      /* socks5: 255, +1 for len. */

#ifdef   MAXPWLEN
#undef   MAXPWLEN
#endif /* MAXPWLEN */
#define  MAXPWLEN          (255 + 1)      /* socks5: 255, +1 for len. */

#if HAVE_GSSAPI
#ifdef MAXGSSAPITOKENLEN
#undef MAXGSSAPITOKENLEN
#endif /* MAXGSSAPITOKENLEN */
#define MAXGSSAPITOKENLEN (1024 * 64 - 1) /* socks5: up to 2^16 - 1 */

#define GSSAPI_HLEN       (4) /* GSSAPI headerlen. */

/*
 * XXX should be max-size of exported state, but we don't know what it is.
 * Is there any way to find out?
 */
#define MAX_GSS_STATE     (2000)

#endif /* HAVE_GSSAPI */


#define  MAXIFNAMELEN      (255)

/*                           "255." "255." "255." "255" "." "65535" + NUL */
#define   MAXSOCKADDRSTRING    (4   +   4   + 4   +  3  + 1 +    5   + 1)

/*                                             "." + "65535" + NUL */
#define   MAXSOCKSHOSTSTRING (MAXHOSTNAMELEN + 1  +    5)

#define   MAXRULEADDRSTRING  (MAXSOCKSHOSTSTRING * 2 + 32 /* atype, etc. */)
#define   MAXGWSTRING        (MAXSOCKSHOSTSTRING)


#define MAXSUBDOMAINS      (10) /* a.b.c.d.e.f ... */


#define MAXAUTHINFOLEN      (((sizeof("(") - 1) + MAXMETHODSTRING) \
                           + (sizeof(")") - 1) + (sizeof("@") - 1) + MAXNAMELEN)

#ifndef NUL
#define NUL '\0'
#endif /* !NUL */

#define CONFIGTYPE_SERVER      1
#define CONFIGTYPE_CLIENT      2

#define PROTOCOL_TCPs         "tcp"
#define PROTOCOL_UDPs         "udp"
#define PROTOCOL_UNKNOWNs      "unknown"

#define RESOLVEPROTOCOL_UDP   0
#define RESOLVEPROTOCOL_TCP   1
#define RESOLVEPROTOCOL_FAKE  2

#define LOGTYPE_SYSLOG        0x1
#define LOGTYPE_FILE          0x2

#define NOMEM                 "<memory exhausted>"


   /*
    * macros
    */

#ifndef ROUNDDOWN
#define ROUNDDOWN(x, size)  (((x) / (size) ) * (size))
#endif

#ifndef ROUNDUP
#define ROUNDUP(x, size)    ((((x) + (size) - 1) / (size)) * (size))
#endif

#define ROUNDFLOAT(x) ((x) >= 0 ? (long)((x) + 0.5) : (long)((x) - 0.5))


/*
 * If client, it might need to call malloc(3) to expand socksfdv
 * from the signal handler upon SIGIO, but if we are in a gssapi-function
 * that also is calling malloc(3) ...
 */
#if SOCKS_CLIENT

#define SOCKS_SIGBLOCK_IF_CLIENT(sig, oldset) \
do { socks_sigblock(sig, oldset); } while (/* CONSTCOND */ 0)

#define SOCKS_SIGUNBLOCK_IF_CLIENT(oldset) \
do { socks_sigunblock(oldset); } while (/* CONSTCOND */ 0)

#define SIGSET_ALLOCATE(name) sigset_t name

#else /* !SOCKS_CLIENT */
#define SIGSET_ALLOCATE(name)
#define SOCKS_SIGBLOCK_IF_CLIENT(sig, oldset)
#define SOCKS_SIGUNBLOCK_IF_CLIENT(oldset)
#endif /* !SOCKS_CLIENT */



#define close(n)   closen(n)
#undef snprintf
#define snprintf   snprintfn

/*
 * If "str", of size "strused", contains characters present in
 * "strip", strips them off from "str".
 */
#define STRIPTRAILING(str, strused, strip)   \
do {                                         \
   ssize_t i;                                \
                                             \
   for (i = strused - 1; i > 0; --i)         \
      if (strchr(strip, str[i]))             \
         str[i] = NUL;                       \
      else                                   \
         break;                              \
} while (/* CONSTCOND */ 0)

/* char method array to integer method array. */
#define CM2IM(methodc, charmethodv, intmethodv)      \
   do {                                              \
      int cm2im = (methodc);                         \
      while (--cm2im >= 0)                           \
         (intmethodv)[cm2im] = (charmethodv)[cm2im]; \
   } while (/* CONSTCOND */ 0)


/*
 * for dynamically-sized fd_sets.
 */

#ifndef howmany
#define howmany(x, y) (((x) + ((y) - 1)) / (y))
#endif /* !howmany */

#define SOCKD_FD_SIZE() \
((size_t)(howmany((sockscf.state.maxopenfiles + 1), NFDBITS) * sizeof(fd_mask)))

#ifdef FD_ZERO
#undef FD_ZERO
#endif /* FD_ZERO */

#define FD_ZERO(p)                      \
do {                                    \
   memset((p), 0, SOCKD_FD_SIZE());     \
} while (/* CONSTCOND */ 0)

#ifdef FD_CMP
#undef FD_CMP
#endif /* FD_CMP */

#define FD_CMP(a, b) (memcmp((a), (b), SOCKD_FD_SIZE()))

#ifdef FD_COPY
#undef FD_COPY
#endif /* FD_COPY */

#define FD_COPY(dst, src)                 \
do {                                      \
   memcpy((dst), (src), SOCKD_FD_SIZE()); \
} while (/* CONSTCOND */ 0)


#define ERRNOISNOFILE(errno) \
   ((errno) == EMFILE || (errno) == ENFILE)

#define ERRNOISTMP(errno)      \
   (  (errno) == EAGAIN        \
   || (errno) == EWOULDBLOCK   \
   || (errno) == EINTR         \
   || (errno) == ENOBUFS       \
   || (errno) == ENOMEM)

#define ERRNOISACCES(errno) ((errno) == EPERM || (errno) == EACCES)

#define PORTISRESERVED(port)   \
   (ntohs((port)) != 0 && ntohs((port)) < IPPORT_RESERVED)

#define ADDRISBOUND(addr) \
   (((addr))->sin_addr.s_addr != htonl(INADDR_ANY))

#define PORTISBOUND(addr) \
   (((addr))->sin_port != htons(0))

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
 * if not we get the default behavior.
 */

#define SENDMSG_PADBYTES   (sizeof(long) * 32) /* just a guess. */

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
 * allocate memory for a control message of size "size".  "name" is the
 * name of the allocated memory.
 */
#if HAVE_CMSGHDR /* union cleared to appease valgrind */
#define CMSG_AALLOC(name, size)           \
   union {                                \
      char   cmsgmem[CMSG_SPACE(size)];   \
      struct cmsghdr align;               \
   } __CONCAT3(_, name, mem) = { { 0 } }; \
   struct cmsghdr *name = &__CONCAT3(_, name, mem).align;
#else /* !HAVE_CMSGHDR */
#define CMSG_AALLOC(name, size) \
   char name[(size)];
#endif /* !HAVE_CMSGHDR */

/*
 * Returns the size of the previously allocated control message named
 * "name"
 */
#if HAVE_CMSGHDR
#define CMSG_MEMSIZE(name) (sizeof(__CONCAT3(_, name, mem)))
#else /* !HAVE_CMSGHDR */
#define CMSG_MEMSIZE(name) (sizeof((name)))
#endif /* HAVE_CMSGHDR */

/*
 * Verifies length of received control message.
 *
 * Final padding might not be present in received message,
 * expected length can be either value of CMSG_SPACE() or CMSG_LEN().
 */
#define CMSG_VERIFY_RCPTLEN(msg, datalen) \
    SASSERT((datalen) == 0 ? ((size_t)(CMSG_TOTLEN(msg) == 0))                 \
    :   ((size_t)CMSG_TOTLEN((msg)) == (size_t)(CMSG_SPACE((datalen)))         \
      || (size_t)CMSG_TOTLEN((msg)) == (size_t)(CMSG_LEN((datalen)))))

/*
 * Returns the control data member of "msg".
 */
#if HAVE_CMSGHDR
/*
 * cast is necessary on AIX, due to buggy headers there?
 * needs additional testing on AIX, disable for now.
 */
/* #define CMSG_CONTROLDATA(msg)   ((struct cmsghdr *)((msg).msg_control)) */
#define CMSG_CONTROLDATA(msg)   ((msg).msg_control)
#else /* !HAVE_CMSGHDR */
#define CMSG_CONTROLDATA(msg)   ((msg).msg_accrights)
#endif /* HAVE_CMSGHDR */

/*
 * add "object" to "data".  "object" is the object to add to "data" at
 * offset "offset".
 */
#if HAVE_CMSGHDR
#define CMSG_ADDOBJECT(object, data, offset)                         \
   do                                                                \
      memcpy(CMSG_DATA(data) + (offset), &(object), sizeof(object)); \
   while (/* CONSTCOND */ 0)
#else /* !HAVE_CMSGHDR */
#define CMSG_ADDOBJECT(object, data, offset)                         \
   do                                                                \
      memcpy(data + (offset), &(object), sizeof((object)));          \
   while (/* CONSTCOND */ 0)
#endif /* !HAVE_CMSGHDR */

/*
 * get a object from control data "data".
 * "object" is the object to fill with data gotten from "data" at offset
 * "offset".
 */
#if HAVE_CMSGHDR
#define CMSG_GETOBJECT(object, data, offset)                               \
   do                                                                      \
      memcpy(&(object), CMSG_DATA((data)) + (offset), sizeof((object)));   \
   while (/* CONSTCOND */ 0)
#else /* !HAVE_CMSGHDR */
#define CMSG_GETOBJECT(object, data, offset)                               \
   do                                                                      \
      memcpy(&(object), ((data) + (offset)), sizeof((object)));            \
   while (/* CONSTCOND */ 0)
#endif /* !HAVE_CMSGHDR */

/*
 * Sets up "object" for sending a control message of size "size".
 * "controlmem" is the memory the control message is stored in.
 *
 * CMSG_SPACE() rather than CMSG_LEN() apparently correct value
 * for msg_controllen.
 */
#if HAVE_CMSGHDR
#define CMSG_SETHDR_SEND(object, controlmem, size)                             \
do {                                                                           \
   if (size == 0) {                                                            \
      object.msg_control      = NULL;                                          \
      object.msg_controllen   = 0;                                             \
   }                                                                           \
   else {                                                                      \
      bzero(controlmem, sizeof(*controlmem));                                  \
                                                                               \
      controlmem->cmsg_level  = SOL_SOCKET;                                    \
      controlmem->cmsg_type   = SCM_RIGHTS;                                    \
      controlmem->cmsg_len    = CMSG_LEN(size);                                \
                                                                               \
      object.msg_control      = (caddr_t)controlmem;                           \
      object.msg_controllen   = (size) == 0 ? 0 : CMSG_SPACE((size));          \
  }                                                                            \
} while (/* CONSTCOND */ 0)
#else /* !HAVE_CMSGHDR */
#define CMSG_SETHDR_SEND(object, controlmem, size)                             \
do {                                                                           \
  object.msg_accrights      = (caddr_t)controlmem;                             \
  object.msg_accrightslen   = (size);                                          \
} while (/* CONSTCOND */ 0)
#endif /* !HAVE_CMSGHDR */

/*
 * Sets up "object" for receiving a control message of size "size".
 * "controlmem" is the memory set aside for the control message.
 */
#if HAVE_CMSGHDR
#define CMSG_SETHDR_RECV(object, controlmem, size)             \
   do {                                                        \
      object.msg_control      = (caddr_t)controlmem;           \
      object.msg_controllen   = (size);                        \
   } while (/* CONSTCOND */ 0)
#else /* !HAVE_CMSGHDR */
#define CMSG_SETHDR_RECV(object, controlmem, size)             \
   do {                                                        \
      object.msg_accrights      = (caddr_t)controlmem;         \
      object.msg_accrightslen   = (size);                      \
   } while (/* CONSTCOND */ 0)
#endif /* !HAVE_CMSGHDR */

/* returns length of control data actually sent. */
#if HAVE_CMSGHDR
#define CMSG_GETLEN(msg)   ((msg).msg_controllen - CMSG_LEN(0))
#else
#define CMSG_GETLEN(msg)   ((msg).msg_accrightslen)
#endif /* HAVE_CMSGHDR */

#if HAVE_CMSGHDR
#define CMSG_TOTLEN(msg)   ((msg).msg_controllen)
#else
#define CMSG_TOTLEN(msg)   ((msg).msg_accrightslen)
#endif /* HAVE_CMSGHDR */




/*
 * Error macros.
 */

#if BAREFOOTD

#define INTERNAL_ERROR \
"an internal error was detected at %s:%d\nvalue = %ld, version = %s\n" \
"Please report this to barefoot-bugs@inet.no"

#elif COVENANT /* !BAREFOOTD */

#define INTERNAL_ERROR \
"an internal error was detected at %s:%d\nvalue = %ld, version = %s\n" \
"Please report this to covenant-bugs@inet.no"

#elif SOCKS_SERVER || SOCKS_CLIENT /* !COVENANT */

#define INTERNAL_ERROR \
"an internal error was detected at %s:%d\nvalue = %ld, version = %s\n" \
"Please report this to dante-bugs@inet.no"

#else /* !SOCKS_SERVER || SOCKS_CLIENT */
#error "who are we?"
#endif

#if DIAGNOSTIC

#define SASSERT(expression)      \
do {                             \
   if (!(expression))            \
      SERR(expression);          \
} while (/* CONSTCOND */ 0)

#define SASSERTX(expression)     \
do {                             \
   if (!(expression))            \
      SERRX(expression);         \
} while (/* CONSTCOND */ 0)

#else /* !DIAGNOSTIC */

#define SASSERT(expression)      \
do {                             \
   if (!(expression))            \
      SWARN(expression);         \
} while (/* CONSTCOND */ 0)

#define SASSERTX(expression)     \
do {                             \
   if (!(expression))            \
      SWARNX(expression);        \
} while (/* CONSTCOND */ 0)


#endif /* !DIAGNOSTIC */

#if 0
/* so we can attach to the process while it's alive ... */
#define abort() do { sleep(60); } while (1)
#endif

/*
 * wrappers around warn()/warnx() for more consistent error messages.
 * "failure" is the value that was wrong and which caused the internal error.
 */
#define SERR(failure)               \
do {                                \
   SWARN(failure);                  \
   abort();                         \
} while (/* CONSTCOND */ 0)

#define SERRX(failure)              \
do {                                \
   SWARNX(failure);                 \
   abort();                         \
} while (/* CONSTCOND */ 0)

#define SWARN(failure)                                \
   swarn(INTERNAL_ERROR,                              \
   __FILE__, __LINE__,   (long int)(failure), rcsid)

#define SWARNX(failure)                               \
   swarnx(INTERNAL_ERROR,                             \
   __FILE__, __LINE__,   (long int)(failure), rcsid)

#define WARN(failure) \
   warn(INTERNAL_ERROR, __FILE__, __LINE__, (long int)(failure), rcsid)

#define WARNX(failure) \
   warnx(INTERNAL_ERROR, __FILE__, __LINE__, (long int)(failure), rcsid)

#define ERRORMSG(failure) \
   error_msg(LOG_HIGH, INTERNAL_ERROR, __FILE__, __LINE__, \
   (long int)(failure), rcsid)


/* the size of a UDP header "packet" (no padding) */
#define PACKETSIZE_UDP(packet) (                                     \
   sizeof((packet)->flag) + sizeof((packet)->frag)                   \
   + sizeof((packet)->host.atype) + sizeof((packet)->host.port)      \
   + (ADDRESSIZE_V5(packet)))


/*
 * returns the length of the current address field in socks packet "packet".
 * "packet" can be one of pointer to response_t, request_t or udpheader_t.
 */
#define ADDRESSIZE(packet) (                                         \
     ((packet)->version == SOCKS_V4 ?                                \
     (ADDRESSIZE_V4(packet)) : (ADDRESSIZE_V5(packet))))

/*
 *   version specifics
 */
#define ADDRESSIZE_V5(packet) (                                                \
  (packet)->host.atype == (unsigned char)SOCKS_ADDR_IPV4 ?                     \
  sizeof((packet)->host.addr.ipv4) :(packet)->host.atype == SOCKS_ADDR_IPV6 ?  \
  sizeof((packet)->host.addr.ipv6) : (strlen((packet)->host.addr.domain) + 1))

#define ADDRESSIZE_V4(packet) (                                                \
   (packet)->atype == (unsigned char)SOCKS_ADDR_IPV4 ?                         \
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
#define FAKEIP_END   0x000000ff

#define PROXY_UPNP                  3
#define PROXY_UPNPs                 "UPNP"
#define PROXY_SOCKS_V4               4
#define PROXY_SOCKS_V4s              "socks_v4"
#define PROXY_SOCKS_V4REPLY_VERSION  0
#define PROXY_SOCKS_V5               5
#define PROXY_SOCKS_V5s              "socks_v5"
#define PROXY_DIRECT                 6
#define PROXY_DIRECTs               "direct"
#define PROXY_HTTP_10               7
#define PROXY_HTTP_10s              "HTTP/1.0"
#define PROXY_HTTP_11               8
#define PROXY_HTTP_11s              "HTTP/1.1"

/* sub negotiation. */
#define SOCKS_UNAMEVERSION              1
#define SOCKS_GSSAPI_VERSION            1
#define SOCKS_GSSAPI_AUTHENTICATION     1
#define SOCKS_GSSAPI_ENCRYPTION         2
#define SOCKS_GSSAPI_PACKET             3
#define SOCKS_GSSAPI_CLEAR              0
#define SOCKS_GSSAPI_INTEGRITY          1
#define SOCKS_GSSAPI_CONFIDENTIALITY    2
#define SOCKS_GSSAPI_PERMESSAGE         3

/* authentication METHOD values. */
#define AUTHMETHOD_NOTSET      -1
#define AUTHMETHOD_NOTSETs      "notset"
#define AUTHMETHOD_NONE         0
#define AUTHMETHOD_NONEs        "none"
#define AUTHMETHOD_GSSAPI       1
#define AUTHMETHOD_GSSAPIs      "gssapi"
#define AUTHMETHOD_UNAME        2
#define AUTHMETHOD_UNAMEs      "username"

/* X'03' to X'7F' IANA ASSIGNED                  */

/* X'80' to X'FE' RESERVED FOR PRIVATE METHODS   */

#define AUTHMETHOD_NOACCEPT   255
#define AUTHMETHOD_NOACCEPTs   "no acceptable method"

/* not standard methods, must be > AUTHMETHOD_NOACCEPT. */
#define AUTHMETHOD_RFC931      (AUTHMETHOD_NOACCEPT + 1)
#define AUTHMETHOD_RFC931s     "rfc931"

#define AUTHMETHOD_PAM         (AUTHMETHOD_RFC931 + 1)
#define AUTHMETHOD_PAMs        "pam"

#define AUTHMETHOD_BSDAUTH     (AUTHMETHOD_PAM + 1)
#define AUTHMETHOD_BSDAUTHs    "bsdauth"

#define AUTHMETHOD_MAX         (AUTHMETHOD_BSDAUTH + 1)

#define MAXMETHODSTRING       MAX(sizeof(AUTHMETHOD_NONEs),     \
                              MAX(sizeof(AUTHMETHOD_GSSAPIs),   \
                              MAX(sizeof(AUTHMETHOD_UNAMEs),    \
                              MAX(sizeof(AUTHMETHOD_RFC931s),   \
                              MAX(sizeof(AUTHMETHOD_PAMs),      \
                              sizeof(AUTHMETHOD_BSDAUTHs))))))

/* number of supported methods. */
#define MAXMETHOD             1 /* NONE      */   \
                            + 1 /* GSSAPI    */   \
                            + 1 /* UNAME     */   \
                            + 1 /* RFC931    */   \
                            + 1 /* PAM       */   \
                            + 1 /* BSDAUTH   */

/*
 *  Response commands/codes
 */
#define SOCKS_CONNECT            1
#define SOCKS_CONNECTs           "connect"
#define SOCKS_BIND               2
#define SOCKS_BINDs              "bind"
#define SOCKS_UDPASSOCIATE       3
#define SOCKS_UDPASSOCIATEs      "udpassociate"

/* pseudo commands */

#define SOCKS_COMMANDEND         0xff

#define SOCKS_BINDREPLY          (SOCKS_COMMANDEND + 1)
#define SOCKS_BINDREPLYs         "bindreply"

#define SOCKS_UDPREPLY           (SOCKS_BINDREPLY + 1)
#define SOCKS_UDPREPLYs          "udpreply"

/* misc. stuff */
#define SOCKS_ACCEPT             (SOCKS_UDPREPLY + 1)
#define SOCKS_ACCEPTs            "accept"

#define SOCKS_DISCONNECT         (SOCKS_ACCEPT + 1)
#define SOCKS_DISCONNECTs        "disconnect"

#define SOCKS_BOUNCETO            (SOCKS_DISCONNECT + 1)
#define SOCKS_BOUNCETOs           "bounce-to"

#define SOCKS_UNKNOWN            (SOCKS_BOUNCETO + 1)
#define SOCKS_UNKNOWNs           "unknown"


/* reply field values */
#define SOCKS_SUCCESS         0x00
#define SOCKS_FAILURE         0x01
#define SOCKS_NOTALLOWED      0x02
#define SOCKS_NETUNREACH      0x03
#define SOCKS_HOSTUNREACH     0x04
#define SOCKS_CONNREFUSED     0x05
#define SOCKS_TTLEXPIRED      0x06
#define SOCKS_CMD_UNSUPP      0x07
#define SOCKS_ADDR_UNSUPP     0x08
#define SOCKS_INVALID_ADDRESS 0x09

/* version 4 codes. */
#define SOCKSV4_SUCCESS        90
#define SOCKSV4_FAIL           91
#define SOCKSV4_NO_IDENTD      92
#define SOCKSV4_BAD_ID         93

/* http stuff. */
#define HTTP_SUCCESS           200
#define HTTP_NOTALLOWED        401
#define HTTP_FORBIDDEN         403
#define HTTP_PROXYAUTHREQUIRED 407
#define HTTP_HOSTUNREACH       504
#define HTTP_FAILURE           501

/* upnp stuff. */
#define UPNP_DISCOVERYTIME_MS          (1000)
#define DEFAULT_SSDP_BROADCAST_ADDR    "239.255.255.250"
#define DEFAULT_SSDP_PORT              (1900)

/* return codes from UPNP_GetValidIGD(). */
#define UPNP_NO_IGD           (0)
#define UPNP_CONNECTED_IGD    (1)
#define UPNP_DISCONNECTED_IGD (2)
#define UPNP_UNKNOWN_DEVICE   (3)

#define UPNP_SUCCESS          (1)
#define UPNP_FAILURE          (2)

/* flag _bits_ */
#define SOCKS_INTERFACEREQUEST   0x01
#define SOCKS_USECLIENTPORT      0x04

/* subcommands */
#define SOCKS_INTERFACEDATA      0x01


/* environment variables. */
#define ENV_SOCKS4_SERVER     "SOCKS4_SERVER"
#define ENV_SOCKS5_SERVER     "SOCKS5_SERVER"
#define ENV_SOCKS_SERVER      "SOCKS_SERVER"
#define ENV_HTTP_PROXY        "HTTP_PROXY"

#define SOCKS_TCP         1
#define SOCKS_UDP         2

#define SOCKS_RECV      0
#define SOCKS_SEND      1

/* offsets into authentication packet */
#define AUTH_VERSION      0 /* version of method packet.                      */

/* request */
#define AUTH_NMETHODS   1   /* number of methods to offer.                    */
#define AUTH_METHODS    2   /* offset of first method to offer.               */

/* reply */
#define AUTH_METHOD      1  /* offset for selected method in reply.           */

/* offsets into username/password negotiation packet */
#define UNAME_VERSION   0
#define UNAME_STATUS    1

/* offsets into gssapi negotiation packet */
#define GSSAPI_VERSION          0
#define GSSAPI_STATUS           1
#define GSSAPI_TOKEN_LENGTH     2
#define GSSAPI_TOKEN            4


#define GSSAPI_CLEAR            0
#define GSSAPI_INTEGRITY        1
#define GSSAPI_CONFIDENTIALITY  2

#define GSSAPI_ENCRYPT          1

#define GSS_REQ_INT             0
#define GSS_REQ_CONF            1

#define BINDEXTENSION_IPADDR 0xffffffff

/* XXX no IPv6 support currently. */
#define SOCKS_IPV6_ALEN 16

enum operator_t { none = 0, eq, neq, ge, le, gt, lt, range };
typedef enum { dontcare, istrue, isfalse } value_t;
typedef enum { username } methodinfo_t;
typedef enum { softlimit, hardlimit } limittype_t;


typedef enum { SOCKS_ADDR_NOTSET   = 0,
               SOCKS_ADDR_IPV4     = 1,
               SOCKS_ADDR_IFNAME   = 2,
               SOCKS_ADDR_DOMAIN   = 3,
               SOCKS_ADDR_IPV6     = 4,
               SOCKS_ADDR_URL      = 5
} atype_t;

typedef struct {
   /*
    * if we mark a route/proxy server as bad, how many seconds to wait
    * until we expire the badmarking so it will be tried again for new
    * connections.  A value of zero means never.
    */
   size_t badexpire;

   /*
    * how many times a route can fail before being marked as bad.
    * A value of zero means it will never be marked as bad.
    */
   size_t maxfail;
} routeoptions_t;

struct logtype_t {
   int            type;      /* type of logging (where to).                   */

   char           **fnamev;  /* name of file, if logging to file.             */
   int            *filenov;  /* if logging is to file, the file descriptor.   */
   size_t         filenoc;   /* number of files.                              */

   int            facility;  /* if logging to syslog, this is the facility.   */
   const char      *facilityname; /* if logging to syslog, name of facility   */
};



/* extensions supported by us. */
struct extension_t {
   unsigned char bind;      /* use bind extension? */
};

struct timeout_t {
   unsigned long  connect;   /* how long to wait before giving up connect(2). */
#if !SOCKS_CLIENT
   unsigned long  negotiate; /* how long negotiation can last.                */
   unsigned long  tcpio;     /* how long session can last without i/o.        */
   unsigned long  udpio;     /* how long session can last without i/o.        */

   unsigned long  tcp_fin_wait; /* how long to wait after one end closes.     */
#endif /* !SOCKS_CLIENT */
};




/* the address part of a socks packet */
union socksaddr_t {
   struct in_addr ipv4;
   char           ipv6[SOCKS_IPV6_ALEN];
   char           domain[MAXHOSTNAMELEN]; /* _always_ stored as C string.    */
};

/* the host specific part of misc. things */
struct sockshost_t {
   unsigned char        atype;
   union socksaddr_t    addr;
   in_port_t            port;
};

typedef struct {
   unsigned char httpconnect;
} requestflags_t;

struct request_t {
   unsigned char         version;
   unsigned char         command;
   unsigned char         flag;
   struct sockshost_t    host;
   struct authmethod_t   *auth;   /* pointer to level above. */
   int                   protocol;

   requestflags_t       flags;
};


struct response_t {
   unsigned char         version;

   union {
      unsigned char         socks;
      unsigned char         upnp;
      unsigned short        http;
   } reply;

   unsigned char         flag;
   struct sockshost_t    host;
   struct authmethod_t   *auth;   /* pointer to level above. */
};

/* encapsulation for UDP packets. */
struct udpheader_t {
   unsigned char       flag[2];
   unsigned char       frag;
   struct sockshost_t  host;
};


/* method username */
struct authmethod_uname_t {
   unsigned char   version;
   unsigned char   name[MAXNAMELEN];
   unsigned char   password[MAXPWLEN];
};

#if HAVE_GSSAPI
struct gssapi_enc_t {
       unsigned char nec;
       unsigned char clear;
       unsigned char integrity;
       unsigned char confidentiality;
       unsigned char permessage;
};

#ifndef BUFSIZ
#define BUFSIZ 1024
#endif /* !BUFSIZ */
struct gssapi_buf_t {
    int            read;
    int            rpos;
    int            wpos;
    int            isbuffered;
    unsigned char  rbuffer[GSSAPI_HLEN + MAXGSSAPITOKENLEN];
    unsigned char  wbuffer[BUFSIZ];
};

struct gssapi_state_t {
   int                 encryption;  /* encrypted?                             */
   gss_ctx_id_t        id;          /* gssapi context id.                     */
   OM_uint32           maxgssdata;  /* max length of gss data pre-encoding.   */
   int                 protection;  /* selected protection mechanism.         */
};

/* method gssapi */
struct authmethod_gssapi_t {
       char                  servicename[MAXNAMELEN];
       char                  keytab[MAXNAMELEN];
       unsigned char         name[MAXNAMELEN];
       struct gssapi_enc_t   encryption;  /* encryption details */
       struct gssapi_state_t state;       /* gssapi state details */
};

#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
struct ldap_t {
       struct linkedname_t *ldapurl;               /* name of ldap urls.      */
       struct linkedname_t *ldapbasedn;            /* name of ldap basedns.   */
       char                attribute[MAXNAMELEN];
       char                attribute_AD[MAXNAMELEN];
       char                certfile[MAXURLLEN];
       char                certpath[MAXURLLEN];
       int                 debug;
       int                 mdepth;
       char                domain[MAXNAMELEN];
       char                filter[MAXNAMELEN];
       char                filter_AD[MAXNAMELEN];
       char                keytab[MAXNAMELEN];
       int                 port;
       int                 portssl;

       unsigned char       auto_off;
       unsigned char       ssl;
       unsigned char       certcheck;
       unsigned char       keeprealm;
};
#endif /* HAVE_LDAP */

/* method rfc931 */
struct authmethod_rfc931_t {
   unsigned char   name[MAXNAMELEN];
};

/* method pam. */
struct authmethod_pam_t {
   char            servicename[MAXNAMELEN];   /* servicename to use with pam. */
   unsigned char   name[MAXNAMELEN];
   unsigned char   password[MAXPWLEN];
};

/* method bsdauth. */
struct authmethod_bsd_t {
   char            style[MAXNAMELEN];   /* style to use. */
   unsigned char   name[MAXNAMELEN];
   unsigned char   password[MAXPWLEN];
};

/* this must be big enough to hold a complete method request. */
struct authmethod_t {
   int                  method;                /* method in use.              */
   int                  methodv[MAXMETHOD];    /* methods somewhere matched.  */
   size_t               methodc;               /* number of methods matched.  */
   int                  badmethodv[MAXMETHOD]; /* methods not matched.        */
   size_t               badmethodc;          /* number of methods not matched.*/

   union {
      struct authmethod_uname_t   uname;

#if HAVE_GSSAPI
      struct authmethod_gssapi_t  gssapi;
#endif /* HAVE_GSSAPI */
#if HAVE_LIBWRAP
      struct authmethod_rfc931_t  rfc931;
#endif /* HAVE_LIBWRAP */
#if HAVE_PAM
      struct authmethod_pam_t     pam;
#endif /* HAVE_PAM */
#if HAVE_BSDAUTH
      struct authmethod_bsd_t     bsd;
#endif /* HAVE_BSDAUTH */
   } mdata;
};


struct protocol_t {
   unsigned char tcp;
   unsigned char udp;
};


struct command_t {
   unsigned char bind;
   unsigned char connect;
   unsigned char udpassociate;

   /* not real commands as per standard, but they have their use. */
   unsigned char bindreply;      /* reply to bind command.   */
   unsigned char udpreply;       /* reply to UDP packet.     */
};


struct proxyprotocol_t {
   unsigned char direct;
   unsigned char socks_v4;
   unsigned char socks_v5;
   unsigned char http;
   unsigned char upnp;
};

/* values in parentheses designate "don't care" values when searching.  */
struct socksstate_t {
   int                     acceptpending; /* a accept pending?      (-1)      */
   struct authmethod_t     auth;          /* authentication in use.           */
   int                     command;       /* command (-1)                     */
   int                     err;           /* if request failed, errno.        */
#if HAVE_GSSAPI
   int                     gssimportneeded;
   gss_buffer_desc         gssapistate;   /* if gssimportneeded, data for it. */
   unsigned char           gssapistatemem[MAX_GSS_STATE];
#endif /* HAVE_GSSAPI */
   int                     inprogress;    /* operation in progress? (-1)      */
   unsigned char           issyscall;     /* started out as a real system call*/
   struct protocol_t       protocol;      /* protocol in use.                 */
   unsigned char           udpconnect;    /* connected UDP socket?            */
   int                     syscalldepth;
   int                     version;       /* version (-1)                     */
};

struct ruleaddr_t {
   atype_t               atype;
   union {
      char               domain[MAXHOSTNAMELEN];
      char               ifname[MAXIFNAMELEN];
      struct {
         struct in_addr   ip;
         struct in_addr   mask;
      } ipv4;

   } addr;

   struct {
      in_port_t         tcp;      /* TCP portstart or field to operator on.   */
      in_port_t         udp;      /* UDP portstart or field to operator on.   */
   } port;
   in_port_t            portend;   /* only used if operator is range.         */
   enum operator_t      operator;  /* operator to compare ports via.          */
};

typedef struct {
   atype_t               atype;
   union {
      char               domain[MAXHOSTNAMELEN];
      char               urlname[MAXURLLEN];
      char               ifname[MAXIFNAMELEN];
      struct in_addr     ipv4;
   } addr;
   in_port_t            port;
} gwaddr_t;

#define MINIUPNPC_URL_MAXSIZE (128) /* XXX */
typedef union {
   struct {
      char    controlurl[MINIUPNPC_URL_MAXSIZE];
      char    servicetype[MINIUPNPC_URL_MAXSIZE];
   } upnp;
} proxystate_t;


struct serverstate_t {
   struct command_t        command;
   struct extension_t      extension;
   struct protocol_t       protocol;
   int                     methodv[MAXMETHOD];      /* methods to offer.      */
   size_t                  methodc;                 /* number of methods set. */
   struct proxyprotocol_t  proxyprotocol;

#if HAVE_PAM
   char                    pamservicename[MAXNAMELEN];
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   char                    bsdauthstylename[MAXNAMELEN];
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
   char                    gssapiservicename[MAXNAMELEN];
   char                    gssapikeytab[MAXNAMELEN];
   struct gssapi_enc_t     gssapiencryption;       /* encryption status.      */
#endif /* HAVE_GSSAPI */
#if HAVE_LDAP
   struct ldap_t           ldap;
#endif

#if HAVE_LIBMINIUPNP
   proxystate_t            data;
#endif /* HAVE_LIBMINIUPNP */
};

struct gateway_t {
   gwaddr_t               addr;
   struct serverstate_t   state;
};


struct socks_t {
   unsigned char           version;
                           /*
                            * Negotiated version.  Each request and
                            * response will also contain a version number, that
                            * is the version number given for that particular
                            * packet and should be checked to make sure it is
                            * the same as the negotiated version.
                            */
   struct request_t         req;
   struct response_t        res;
   struct gateway_t         gw;
   struct socksstate_t      state;
};

enum portcmp { e_lt, e_gt, e_eq, e_neq, e_le, e_ge, e_nil };



/*
 * for use in generic functions that take either reply or request
 * packets, include a field indicating what it is.
 */
#define SOCKS_REQUEST   0x1
#define SOCKS_RESPONSE  0x2

/*
 * This object is either used for straightforward buffering, or
 * in the case the data is gssapi-encapsulated, to handle gssapi-data.
 * In the case of simple, non-gssapi, buffering,
 * no further explanation is given; the len field simply holds
 * the number of bytes currently buffered.
 *
 * Next we describe how it is used in the case of gssapi.
 *
 * In the case of gssapi, the buffer is divided into two parts,
 * the first part holding not-encoded data, and the latter part
 * holding encoded data.
 *
 * The operation when reading is as follows:
 *    1) Read into buf as much data as is needed to be able to
 *       decode the data (in the case of gssapi, the whole token).
 *       While doing this, we keep incrementing "enclen", to indicate
 *       how much encoded data has been stored in the buffer.  "len"
 *       is not touch during this.
 *
 *    2) When 1) has completed, we replace the data in buf with
 *       the decoded version of data in "buf", reset "enclen", and
 *       set "len" to indicate how much decoded data is stored in the
 *       buffer.
 *
 *    3) On subsequent read operations on the socket corresponding to
 *       the data (s), return data from buf instead of reading it from
 *       the socket.
 *
 *    4) When all data in buf has been returned, clear the iobuffer.
 *
 * The operation when writing is more complicated, because
 * we can get multiple write requests that we fail to send down
 * to the socket buffer, which in sum may be bigger than the
 * the iobuffer set aside to hold buffered unwritten data.
 *
 * The only way to prevent that situation from occurring is to
 * put a cap on how much we read, and never read more data than
 * we can store in our write-buffer, encoded.
 * We can use gss_wrap_size_limit() in combination with the amount
 * of data free in the buffer to find out the max amount of data to
 * read, and read no more than that in the tcp case.
 *
 * The operation for writing thus becomes:
 * 1) Encode the data received and write it to the socket.
 *
 * 2) If we fail to write all the data, and it is a tcp socket,
 *    store the remaining data in the iobuffer, setting encodedlen
 *    to the size of data remaining, and used to zero.
 *    If it's a udp socket, there is not much to do, so return the
 *    error.
 *
 * 3) On subsequent write operations on the socket, try to write the
 *    data we had previously buffered.  Then continue with 1).
 *
 $ 4) When all data has been written, clear the iobuffer.
 *
 */

typedef enum { READ_BUF, WRITE_BUF } whichbuf_t;

typedef struct {
   unsigned char allocated;
   int           s;

#if HAVE_GSSAPI
#  if (SOCKD_BUFSIZE) < (2 * (MAXGSSAPITOKENLEN + GSSAPI_HLEN))
 #     error "SOCKD_BUFSIZE too small."
#  endif
#endif /* HAVE_GSSAPI */

   char         buf[2][SOCKD_BUFSIZE];
   size_t       bufsize[2];

   struct {
#if SOCKS_CLIENT
      int      mode;       /* buffering mode.  Default is no buffering.       */
      size_t   peekedbytes;/* # of bytes we last peeked at.                   */
#endif /* SOCKS_CLIENT */

      size_t   len;        /* length of decoded/plain text data in buffer     */
      size_t   enclen;     /* length of encoded data in buffer.               */
   } info[2];

   int      stype;         /* socket type; tcp or udp                         */
} iobuffer_t;


struct socksfd_t {
   unsigned char        allocated;  /* allocated?                             */
   int                  control;    /* control connection to server.          */
   struct socksstate_t  state;      /* state of this connection.              */
   struct sockaddr      local;      /* local address of data connection.      */
   struct sockaddr      server;     /* remote address of data connection.     */
   struct sockaddr      remote;     /* address server is using on our behalf. */
   struct sockaddr      reply;      /* address to expect reply from.          */

   union {
      struct sockshost_t   accepted;   /* address server accepted for us.     */
      struct sockshost_t   connected;  /* address server connected to for us. */
   } forus;

   struct route_t      *route;
};



struct route_t {
   int                     number;      /* route number.                       */

   struct {
      unsigned char autoadded;/* autoadded route?                             */
      size_t        failed;   /* route is bad?  How many times it has failed. */
      time_t        badtime;  /* if route is bad, time last marked as such.   */
   } state;

   struct ruleaddr_t src;
   struct ruleaddr_t dst;
   struct gateway_t  gw;

   struct route_t            *next;      /* next route in list.               */
};

/*
 * versions of BSD's error functions that log via slog() instead.
 */

void serr(int eval, const char *fmt, ...)
      __attribute__((format(printf, 2, 3)));

void serrx(int eval, const char *fmt, ...)
      __attribute__((format(printf, 2, 3)));

void swarn(const char *fmt, ...)
      __attribute__((format(printf, 1, 2)));

void swarnx(const char *fmt, ...)
      __attribute__((format(printf, 1, 2)));

void
genericinit(void);
/*
 * Generic init, called after clientinit()/serverinit().
 */

void
optioninit(void);
/*
 * sets options to a reasonable default.
 */


int
socks_initupnp(const gwaddr_t *gw, proxystate_t *data);
/*
 * Inits upnp for interface corresponding to address "gw".
 * If successful, the necessary information to later use the found
 * upnp router is saved in "data", which should normally be part of a
 * route object.
 *
 * Returns:
 *    On success: 0.
 *    On failure: -1 (no appropriate upnp devices found, or some other error.)
 */

void
newprocinit(void);
/*
 * After a new process is started/forked, this function should
 * be called.  It will initialize various things, open needed
 * descriptors, etc. and can be called as many times as wanted.
 */

struct udpheader_t *
sockaddr2udpheader(const struct sockaddr *to, struct udpheader_t *header);
/*
 * Writes a udpheader representation of "to" to "header".
 * Returns a pointer to "header".
 */

void *
udpheader_add(const struct sockshost_t *host, void *msg, size_t *len,
              const size_t msgsize);
/*
 * Prefixes the udpheader_t version of "host" to a copy of "msg",
 * which is of length "len".
 * "msgsize" gives the size of the memory pointed to by "msg".
 *
 * If "msgsize" is large enough the function will prepend the socks
 * udpheader to "msg", moving the old contents to the right.
 * If not, NULL will be returned with errno set to EMSGSIZE.  This
 * should only happen if the payload + the socks udpheader is larger
 * than the maxsize of a UDP (IP) packet.
 *
 * Returns:
 *   On success: "msg" with the udpheader prepended.  The length of the new
       message is stored in "len".
 *   On failure: NULL (message to large).
 */

int
fdisopen(const int fd);
/*
 * returns true if the file descriptor "fd" currently references a open fd,
 * false otherwise.
 */

int
fdisblocking(const int fd);
/*
 * returns true if the file descriptor "fd" is blocking, false otherwise.
 */


void
closev(int *array, int count);
/*
 * Goes through "array", which contains "count" elements.
 * Each element that does not have a negative value is closed.
 */

int
socks_logmatch(unsigned int d, const struct logtype_t *log);
/*
 * Returns true if "d" is a descriptor matching any descriptor in "log".
 * Returns false otherwise.
 */

struct sockaddr *
sockshost2sockaddr(const struct sockshost_t *shost, struct sockaddr *addr);
/*
 * Converts the sockshost_t "shost" to a sockaddr struct and stores it
 * in "addr".
 * Returns: "addr".
 */

struct sockaddr *
fakesockshost2sockaddr(const struct sockshost_t *host, struct sockaddr *addr);
/*
 * Like sockshost2sockaddr(), but checks whether the address in
 * "host" is fake when converting.
 */

struct sockaddr *
urlstring2sockaddr(const char *string, struct sockaddr *saddr,
                   char *emsg, const size_t emsglen);
/*
 * Converts the address given in "string", on URL:// format, to
 * a sockaddr address stored in "saddr".
 *
 * Returns "saddr" on success.
 * Returns NULL on failure with the reason written to "emsg", which must
 * be of at least "emsglen" size.
 */

struct sockshost_t *
sockaddr2sockshost(const struct sockaddr *addr, struct sockshost_t *host);
/*
 * Converts the sockaddr struct "shost" to a sockshost_t struct and stores it
 * in "host".
 * Returns: "host".
 */

struct sockshost_t *
ruleaddr2sockshost(const struct ruleaddr_t *address, struct sockshost_t *host,
      int protocol);
/*
 * Converts the ruleaddr_t "address" to a sockshost_t struct and stores it
 * in "host".
 * Returns: "host".
 */

gwaddr_t *
ruleaddr2gwaddr(const struct ruleaddr_t *address, gwaddr_t *gw);
/*
 * Converts the ruleaddr_t "address" to a gwaddr_t and stores it
 * in "hw".
 * Returns: gw;
 */

struct sockaddr *
ruleaddr2sockaddr(const struct ruleaddr_t *address, struct sockaddr *sa,
                  const int protocol);
/*
 * Converts the ruleaddr_t "address" to a sockshost_t struct and stores it
 * in "host".
 * Returns: "host".
 */


struct sockshost_t *
gwaddr2sockshost(const gwaddr_t *gw, struct sockshost_t *host);
/*
 * Converts the gwaddr_t "address" to a sockshost_t and stores it
 * in "host".
 * Returns: host;
 */

struct ruleaddr_t *
sockshost2ruleaddr(const struct sockshost_t *host, struct ruleaddr_t *addr);
/*
 * Converts the sockshost_t "host" to a ruleaddr_t struct and stores it
 * in "addr".
 * Returns: "addr".
 */

struct ruleaddr_t *
sockaddr2ruleaddr(const struct sockaddr *addr, struct ruleaddr_t *ruleaddr);
/*
 * Converts the struct sockaddr "addr" to a ruleaddr_t struct and stores
 * it in "ruleaddr".
 * Returns: "addr".
 */

struct sockaddr *
hostname2sockaddr(const char *name, size_t index, struct sockaddr *addr);
/*
 * Retrieves the address with index "index" for the hostname named "name".
 * Returns:
 *      On success: "addr", filled in with the address found.
 *      On failure: NULL (no address found).
 */

struct sockaddr *
ifname2sockaddr(const char *ifname, size_t index, struct sockaddr *addr,
                struct sockaddr *netmask);
/*
 * Retrieves the address with index "index" on the interface named "ifname".
 * If "netmask" is not NULL, the netmask on the interface is stored here.
 *
 * Returns:
 *      On success: "addr", and possibly "netmask", filled in with the address
 *                found.
 *      On failure: NULL (no address found).
 */

const char *
sockaddr2ifname(struct sockaddr *addr, char *ifname, size_t iflen);
/*
 * Retrieves the name of the interface the address "addr" belongs to.
 * The name is written to "ifname", which must be of len "iflen".
 * If "ifname" or "iflen" is NULL, the name is written to a local
 * buffer instead.
 *
 * Returns a pointer to the memory containing the interface name, or
 * NULL if no matching interface is found.
 *
 */

int
sockatmark(int s);
/*
 * If "s" is at oob mark, return 1, otherwise 0.
 * Returns -1 if a error occurred.
 */

ssize_t
recvmsgn(int s, struct msghdr *msg, int flags);
/*
 * Like recvmsg(), but handles some os-specific bugs.
 */

ssize_t
sendmsgn(int s, const struct msghdr *msg, int flags, const int timeout);
/*
 * Like sendmsg(), but retries on temporary errors, including blocking
 * with select(2) for up to "timeout" seconds.  If "timeout" is -1,
 * block forever.
 */

ssize_t
readn(int, void *, size_t, const size_t minread, struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Like read() but with two additional arguments:
 * minread - the minimum amount of bytes to read before returning, or error.
 * auth    - authentication info for the file descriptor.  May be NULL.
 */

ssize_t
writen(int, const void *, size_t, const size_t minwrite,
      struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * like write() but if with two additional arguments:
 * minwrite - the minimum amount of bytes to write before returning, or error.
 * auth     - authentication info for the file descriptor.  May be NULL.
 */

ssize_t
socks_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *,
      struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Like recvfrom(), but with an additional auth argument to be used
 * if not NULL.
 */

ssize_t
socks_recvfromn(const int s, void *buf, const size_t len, const size_t minread,
                const int flags, struct sockaddr *from, socklen_t *fromlen,
                struct authmethod_t *auth)
                __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Like socks_recvfromn(), but retries until minread has been read, or failure.
 */

ssize_t
socks_sendto(int, const void *, size_t, int, const struct sockaddr *,
      socklen_t, struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Like sendto(), but with an additional auth argument to be used
 * if not NULL.
 */

ssize_t
socks_sendton(int s, const void *buf, size_t len, const size_t minwrite,
      int flags, const struct sockaddr *to, socklen_t tolen,
      struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Like socks_sendto(), but retries until "minwrite" is written, or failure.
 */

int
closen(int);
/*
 * Wrapper around close().  Retries on EINTR.
 */

int
selectn(int nfds, fd_set *rset, fd_set *bufrset, fd_set *buffwset,
         fd_set *wset, fd_set *xset, struct timeval *);
/*
 * Wrapper around select() that takes two additional arguments:
 * bufrset  - if not NULL, set to contain descriptors with data buffered
 *            for reading.
 * buffwset - if not NULL, set to contain descriptors with data buffered
 *            for writing (buffered-for-writing).
 *
 * In addition, if it's called by the server, it checks whether we
 * have a signal queued internally, and if so calls the appropriate
 * signal handler.
 */

int
acceptn(int, struct sockaddr *, socklen_t *);
/*
 * Wrapper around accept().  Retries on EINTR.
 */

int
socks_socketisforlan(const int s);
/*
 * If we can determine that the socket "s" is for lan use only, i.e. should
 * not be proxied, returns true.  Otherwise, returns false.
 */

const char *errnostr(const int err);
/* returns a printable representation of the errno "errno". */


size_t
snprintfn(char *str, size_t size, const char *format, ...)
      __attribute__((format(printf, 3, 4)))
      __attribute__((__nonnull__(3)))
      __attribute__((__bounded__(__string__, 1, 2)));
/*
 * Wrapper around snprintf() for consistent behavior.  Same as stdio
 * snprintf() but the following are also enforced:
 *      returns 0 instead of -1 (rawterminates *str) on error.
 *      never returns a value greater than size - 1.
 */

void
socks_sigblock(const int sig, sigset_t *oldset);
/*
 * If "sig" is -1, blocks all signals.  If not, adds only "sig" to
 * the list of currently blocked signals.
 *
 * The old signalmask is returned in "oldset".
 */

void
socks_sigunblock(const sigset_t *oldset);
/*
 * Restores the current signalmask to "oldset".
 */


const char *
strcheck(const char *string);
/*
 * Checks "string".  If it is NULL, returns a string indicating memory
 * exhausted, if not, returns the same string it was passed.
 */

unsigned char *
sockshost2mem(const struct sockshost_t *host, unsigned char *mem, int version);
/*
 * Writes "host" out to "mem".  The caller must make sure "mem"
 * is big enough to hold the contents of "host".
 * "version" gives the socks version "host" is to be written out in.
 * Returns a pointer to one element past the last byte written to "mem".
 */

const unsigned char *
mem2sockshost(struct sockshost_t *host, const unsigned char *mem, size_t len,
      int version)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Writes "mem", which is assumed to be a sockshost string
 * of version "version" in network order, out to "host".
 * Returns:
 *      On success: pointer to one element past last byte used of mem
 *                  and fills in "host" appropriately.
 *      On failure: NULL ("mem" is not a valid sockshost.)
 */

/*
 * Functions to fetch or set the value of the response, depending on what
 * version the response belongs to.
 */
unsigned int socks_get_responsevalue(const struct response_t *response);
void socks_set_responsevalue(struct response_t *response, unsigned int value);


int
socks_addlogfile(struct logtype_t *logcf, const char *logfile);
/*
 * Adds the file "logfile" to the list of files we log to, stored in "logcf".
 * Returns 0 on sucess, -1 on error.
 */

void slog(int priority, const char *fmt, ...)
      __attribute__((format(printf, 2, 3)));
/*
 * Logs message "fmt" at priority "priority" to previously configured
 * outputdevice.
 * Checks settings and ignores message if it's of to low a priority.
 */

void vslog(int priority, const char *fmt, va_list ap, va_list apcopy)
      __attribute__((format(printf, 2, 0)));
/*
 * Same as slog() but assumes varargs/stdargs have already processed
 * the arguments.
 */

int
parseconfig(const char *filename);
/*
 * Parses the config stored in in the filename "filename", as well
 * as environment-variables related.
 *
 * Returns:
 *      On success: 0.
 *      On failure: -1.
 */

void
yywarn(const char *fmt, ...)
   __attribute__((format(printf, 1, 2)));
/*
 * Report a error related to (configfile) parsing.
 */

void
yyerror(const char *fmt, ...)
   __attribute__((format(printf, 1, 2)));
/*
 * Report a error related to (configfile) parsing and exit.
 */

int
addrmatch(const struct ruleaddr_t *rule, const struct sockshost_t *address,
          int protocol, int ipalias);
/*
 * Tries to match "address" against "rule".  "address" is resolved
 * if necessary.  "rule" supports the wildcard INADDR_ANY and port of 0.
 * "protocol" is the protocol to compare under.
 * If "ipalias" is true, the function will try to match any IP alias
 * "address"'s might have if appropriate.  This can be useful to match
 * multihomed hosts where the client requests e.g a bind connection.
 *
 * Returns true if "rule" matched "address".
 */

struct hostent *
hostentdup(struct hostent *hostent, struct hostent *duped,
           const ssize_t maxaliases);
/*
 * Duplicates "hostent".  If "duped" is NULL, memory is allocated
 * dynamically to duplicate "hostent".  This memory must later
 * be freed with hostentfree().
 * If "duped" is not NULL, the duplicated "hostent" is stored there,
 * otherwise a new struct hostent is allocated that must be freed by caller.
 * "maxaliases" gives the maximum number of aliases or addresses to
 * duplicate, and may be -1 for unbounded duplication in the case
 * when "hostent" is NULL.
 *
 * Returns:
 *      On success: a pointer to the duplicated hostent.
 *      On failure: NULL.
 */

void
hostentfree(struct hostent *hostent);
/*
 * Free's all resourced used by "hostent", including "hostent"
 * itself.  If "hostent" is NULL, nothing is done.
 */

int
socks_connecthost(int s, const struct sockshost_t *host,
                  struct sockaddr *addr, const long timeout,
                  char *emsg, const size_t emsglen);
/*
 * Tries to connect to "host".  If "host"'s address is not a IP address,
 * the function also tries to connect to any alias for "host"'s
 * name.  The connection is done using the open descriptor "s".
 * If "addr" is not NULL, it is filled in with the address connected to if
 * successful.  If "host" is a an ip address, it will be identical to that
 * ip address, but if "host" is a hostname, they will of course differ.
 *
 * If "timeout" is not negative, it gives the timeout for how long to wait
 * for the connect to complete.  A value of zero means no wait will be
 * done, and the the function may return with errno set to EINPROGRESS.
 * A negative value for timeout means wait the kernel/system default.
 *
 * If the function fails, the reason is writtent to emsg, which must be
 * at least "emsglen" long.
 *
 * Returns:
 *      On success: 0
 *      On failure: -1.  Reason for error is written to emsg.
 */

struct route_t *
socks_connectroute(int s, struct socks_t *packet,
      const struct sockshost_t *src,
      const struct sockshost_t *dst);
/*
 * Finds a route from "src" to "dst" and connects to it "s".
 * If src or dst is NULL, that argument is ignored.
 *
 * The route used may take into account the contents of "packet->req",
 * which is assumed to be the packet that will be sent to a socks server,
 * so it is recommended that it's contents be as conservative as possible.
 *
 * When it has successfully connected to a gateway it will set
 * the packet->method members to point to the methods the gateway
 * should be offered.
 *
 * Returns:
 *      On success: the route that was used.
 *      On failure: NULL.  See errno for reason.  If the reason for
 *                  failure is that no route was found, errno will not
 *                  be set.
 */

struct request_t *
socks_requestpolish(struct request_t *req, const struct sockshost_t *src,
      const struct sockshost_t *dst);
/*
 * Tries to "polish" the request "req" so that a later socks_getroute()
 * will succeed.
 * Returns:
 *      On success: "req".
 *      On failure: NULL.
 */

void
showstate(const struct serverstate_t *state, const int isclientrule);
/*
 * Shows "state".  "isclientrule" indicates whether it's state for
 * a clientrule or not.
 */

void
showmethod(size_t methodc, const int *methodv);
/*
 * Shows "methodv".
 */

void
showtimeout(const struct timeout_t *timeout);
/*
 * shows timeouts set in "timeout".
 */


struct route_t *
socks_addroute(const struct route_t *route, const int last);
/*
 * Appends a copy of "route" to our list of routes.
 * If "last" is true, the route is added to the end of our list.
 * If not, it's added to the start, and existing rule numbers are updated
 * correspondingly.
 *
 * Returns a pointer to the added route.
 */

struct route_t *
socks_autoadd_directroute(const struct sockaddr_in *saddr,
      const struct sockaddr_in *netmask);
/*
 * Adds a direct route to "saddr", netmask "netmask".
 * Intended to be used for routes that are added automatically,
 * and not via socks.conf.
 */

void
socks_showroute(const struct route_t *route);
/*
 * prints the route "route".
 */

struct route_t *
socks_getroute(const struct request_t *req, const struct sockshost_t *src,
      const struct sockshost_t *dst);
/*
 * Tries to find a  route to be used for a connection going from
 * "src" to "dst".
 * If src or dst is NULL, that argument is ignored.
 *
 * The route used may take into account the contents of "req", which is
 * assumed to be the packet that will be sent to a socks server, so it is
 * recommended that it's contents be as conservative as possible.
 *
 * Returns:
 *      On success: pointer to route that should be used.
 *      On failure: NULL (no route found).
 */

unsigned int
sockscode(const int version, const int code);
/*
 * Maps the socks replycode "code", which is in non-version specific format,
 * to the equivalent replycode in version "version".
 */

unsigned int
errno2reply(int errnum, int version);
/*
 * Returns the proxy version "version" reply code for a error of type "errno".
 */

char *
str2vis(const char *string, size_t len, char *visstring, size_t vislen)
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Visually encodes exactly "len" chars of "string" and stores the
 * result in "visstring", which is of length "vislen".  "vislen" should
 * be at least "len" * 4 + 1.
 *
 * Returns: the visually encoded string, "visstring".
 */

in_addr_t
socks_addfakeip(const char *name);
/*
 * Adds "name" to a internal table indexed by (fake)IP addresses.
 * Returns:
 *      On success: "name"'s index.
 *      On failure:   INADDR_NONE
 */

const char *
socks_getfakehost(in_addr_t addr);
/*
 * If "addr" is a "fake" (non-resolved) addr, it returns the name
 * corresponding to it.
 * Else, NULL is returned.
 */

int
socks_getfakeip(const char *host, struct in_addr *addr);
/*
 * If "host" has a fake address entry, the address is written into
 * "addr".
 * Returns:
 *      If a fake address exits: true
 *      Else: false
 */

struct sockshost_t *
fakesockaddr2sockshost(const struct sockaddr *addr, struct sockshost_t *host);
/*
 * Identical to sockaddr2sockshost, but checks whether
 * the address in "addr" is a "fake" one when converting.
 */

int
sockaddrareeq(const struct sockaddr *a, const struct sockaddr *b);
/*
 * Compares the address "a" against "b".
 * Returns:
 *      If "a" and "b" are equal: true
 *      else: false
 */

int
sockshostareeq(const struct sockshost_t *a, const struct sockshost_t *b);
/*
 * Compares the address "a" against "b".
 * Returns:
 *      If "a" and "b" are equal: true
 *      else: false
 */

int
fdsetop(int highestfd, int op, const fd_set *a, const fd_set *b,
        fd_set *result);
/*
 * Performs operation on descriptor sets.
 * "highestfd" is the descriptors with the highest index to perform operation
 * "op" on in the sets "a" and "b".
 *
 * The result of the operation is stored in "result".
 *
 * Returns the number of the highest descriptor set in "result".
 * NOTES:
 *      - operators supported is: AND ('&'), XOR ('^'), and OR ('|').
 */

int
methodisset(int method, const int *methodv, size_t methodc);
/*
 * Returns true if the method "method" is set in "methodv", false otherwise.
 * "methodc" is the length of "methodv".
 */

int
socketoptdup(int s);
/*
 * Duplicates the settings of "s" and returns a new socket with the
 * same settings.
 * Returns:
 *      On success: the descriptor for the new socket
 *      On failure: -1
 */

int
socks_mklock(const char *template, char *newname, const size_t newnamelen);
/*
 * Creates a file that can be used with socks_lock() and
 * socks_unlock().  Returns the file descriptor of the created file.
 * If "newname" or "newnamelen" is zero, the created file is unlinked.
 * Otherwise the file is not unlinked and the name of the created file is
 * is saved to newname.
 *
 * Returns:
 *      On success: file descriptor
 *      On failure: -1
 */

int
socks_lock(const int fd, const int exclusive, const int wait);
/*
 * Looks the file descriptor "fd".
 * If "exclusive" is true, the lock is exclusive.  If not, it is shared.
 * If "wait" is true, wait for the lock.  If not, return if the lock
 * can not be taken.
 * Upgrade/downgrade to/from exclusive is permitted.
 *
 * Returns:
 *      On success: 0
 *      On error  : -1
 */

void
socks_unlock(int d);
/*
 * Unlocks the file descriptor "d", previously locked by this process.
 */

int
bitcount(unsigned long number);
/*
 * Returns the number of bits set in "number".
 */

#if SOCKSLIBRARY_DYNAMIC
struct hostent *sys_gethostbyaddr(const char *addr, socklen_t len, int af);
struct hostent *sys_gethostbyname(const char *);
struct hostent *sys_gethostbyname2(const char *, int);
#if HAVE_GETADDRINFO
int sys_getaddrinfo(const char *nodename, const char *servname,
      const struct addrinfo *hints, struct addrinfo **res);
#endif /* HAVE_GETADDRINFO */
#if HAVE_GETIPNODEBYNAME
struct hostent *sys_getipnodebyname(const char *name, int af, int flags,
      int *error_num);
#endif /* HAVE_GETIPNODEBYNAME */

#if HAVE___FPRINTF_CHK
HAVE_PROT_FPRINTF_0 __fprintf_chk(HAVE_PROT_FPRINTF_1 stream, int dummy,
              HAVE_PROT_FPRINTF_2 format, ...);
#endif /* HAVE___FPRINTF_CHK */

#if HAVE___VFPRINTF_CHK
HAVE_PROT_VFPRINTF_0 __vfprintf_chk(HAVE_PROT_VFPRINTF_1 stream,
      int dummy, HAVE_PROT_VFPRINTF_2 format, HAVE_PROT_VFPRINTF_3 ap);
#endif /* HAVE___VFPRINTF_CHK */
#endif /* SOCKSLIBRARY_DYNAMIC */

#if defined(DEBUG) || HAVE_SOLARIS_BUGS

void
slogstack(void);
/*
 * Prints the current stack.
 */

int
freedescriptors(const char *message);
/*
 * Returns the number on unallocated descriptors.
 */

void
printsocketopts(const int s);
/*
 * prints socketoptions and other flags set on the socket "s".
 */

#endif /* DEBUG || HAVE_SOLARIS_BUGS */

#ifdef DEBUG

int
fd_isset(int fd, fd_set *fdset);
/* function version of FD_ISSET() */

#endif /* DEBUG */

struct passwd *
socks_getpwnam(const char *login);
/*
 * Like getpwnam() but works around sysv bug and tries to get the shadow
 * password too.
 */

int
httpproxy_negotiate(int control, struct socks_t *packet);
/*
 * Negotiates a session to be used with the server connected to "control".
 * "packet" is the packet with information about what we want the
 * server to do for us.
 * packet->res.reply will be set according to the result of negotiation.
 * Returns:
 *      On success: 0 (server accepted our request).
 *      On failure: -1.
 */

int
upnp_negotiate(const int s, struct socks_t *packet,
      const proxystate_t *state);
/*
 * Negotiates a session to be used with the upnp server.
 * If the request is for a i/o operation, socket is the socket to be used
 * for performing the i/o.
 *
 * "packet" is the packet with information about what we want the
 * server to do for us.
 *
 * "state" is the previously established upnp state to be used with
 * the upnp device.
 *
 * packet->res.reply will be set according to the result of negotiation.
 *
 * Returns:
 *      On success: 0 (server accepted our request).
 *      On failure: -1.
 */

int
socks_negotiate(int s, int control, struct socks_t *packet,
      struct route_t *route);
/*
 * "s" is the socket data will flow over.
 * "control" is the control connection to the socks server.
 * "packet" is a socks packet containing the request.
 *   "route" is the connected route.
 * Negotiates method and fills the response to the request into packet->res.
 * Returns:
 *      On success: 0 (server replied to our request).
 *      On failure: -1.
 */

int
serverreplyisok(int version, unsigned int reply, struct route_t *route);
/*
 * "replycode" is the reply code returned by a socks server of version
 * "version".
 * "route" is the route that was used for the socks server.
 * If the error code indicates a server failure, the route might be
 * "blacklisted".
 *
 * Returns true if the reply indicates request succeeded, false otherwise
 * and sets errno accordingly.
 */

struct route_t *
socks_nbconnectroute(int s, int control, struct socks_t *packet,
      const struct sockshost_t *src, const struct sockshost_t *dst);
/*
 * The non-blocking version of socks_connectroute(), only used by client.
 * Takes one additional argument, "s", which is the socket to connect
 * and not necessarily the same as "control" (msproxy case).
 */

void
socks_blacklist(struct route_t *route);
/*
 * Marks route "route" as bad.
 */

void
socks_clearblacklist(struct route_t *route);
/*
 * Clears bad marks on route.
 */

int
negotiate_method(int s, struct socks_t *packet, struct route_t *route);
/*
 * Negotiates a method to be used when talking with the server connected
 * to "s".
 * "packet" is the packet that will later be sent to server, and only
 * the "auth" element in it will be set but other elements are needed
 * for reading too.
 * "route" is the route selected for connecting to the socks-server.
 *
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
clientmethod_uname(int s, const struct sockshost_t *host, int version,
       unsigned char *name, unsigned char *password);
/*
 * Enters username/password negotiation with the socks server connected to
 * the socket "s".
 * "host" gives the name of the server.
 * "version" gives the socks version established to use.
 * "name", if not NULL, gives the name to use for authenticating.
 * "password", if not NULL, gives the name to use for authenticating.
 * Returns:
 *      On success: 0
 *      On failure: whatever the remote socks server returned as status.
 */

#if HAVE_GSSAPI
int
clientmethod_gssapi(int s, int protocol, const struct gateway_t *gw,
       int version, struct authmethod_t *auth);
/*
 * Enters gssapi negotiation with the socks server connected to
 * the socket "s".
 * "gw" gives the name of the gateway.
 * "version" gives the socks version established to use.
 * "*auth", authentication structure
 * Returns:
 *              On success: 0
 *              On failure: whatever the remote socks server returned as status.
 */

int
gssapi_encode(const void *input, size_t ilen, struct gssapi_state_t *gs,
       void *output, size_t *olen);
/*
 * gssapi encode the data in "input", storing the encoded message
 * in "output", which is of size "olen".  On return, "olen" contains
 * the length of the encoded message.
 * gs structure contains details about gssapi context.
 *
 * Returns:
 *    On success: 0
 *    On failure: -1
 */

int
gssapi_decode(void *input, size_t ilen, struct gssapi_state_t *gs,
       void *output, size_t *olen)
       __attribute__((__bounded__(__buffer__, 1, 2)));
/*
 * gssapi decode the data in "input", storing the decoded message
 * in "output", which is of size "olen".  On return, "olen" contains
 * the length of the decoded message.
 * gs structure contains details about gssapi context.
 *
 * Returns:
 *    On success: 0
 *    On failure: -1
 */

#endif /* HAVE_GSSAPI */

void
checkmodule(const char *name);
/*
 * Checks that the system has the module "name" and permission to use it.
 * Aborts with an error message if not.
 */

int socks_yyparse(void);
int socks_yylex(void);

int
socks_sendrequest(int s, const struct request_t *request);
/*
 * Sends the request "request" to the socks server connected to "s".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
socks_recvresponse(int s, struct response_t *response, int version);
/*
 * Receives a socks response from the "s".  "response" is filled in with
 * the data received.
 * "version" is the protocol version negotiated.
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

iobuffer_t *
socks_allocbuffer(const int s, const int type);
/*
 * Returns the iobuffer allocated to file descriptor "s", or
 * a new free one if none is allocated.
 * "type" gives the type of socket "s" is, SOCK_STREAM or SOCK_DGRAM.
 *
 * It is an error if a new buffer is allocated to "s" before the old
 * one has been freed.
 */

iobuffer_t *
socks_getbuffer(const int s);
/*
 * Returns the iobuffer allocated to file descriptor "s".
 */

void
socks_freebuffer(const int s);
/*
 * Marks the iobuffer allocated to file descriptor "s" as free.
 * It is not an error if no iobuffer is currently allocate dto "s".
 */

void
socks_reallocbuffer(const int old, const int new);
/*
 * Reallocs the buffer assigned to "old", if any, to instead be assigned
 * to "new".
 */

void
socks_clearbuffer(const int s, const whichbuf_t type);
/*
 * Clears the iobuffer belonging to "s".
 * "type" gives the buffer-type that should be cleared, READ_BUF or WRITE_BUF.
 */

int socks_flushbuffer(const int s, const ssize_t len);
/*
 * Tries to flush the data buffered for file descriptor "s".
 * If "len" is -1, tries to flush all data, otherwise only flushed
 * up to "len" bytes.
 *
 * Return the number of bytes flushed on success, or -1 if we could
 * not flush all data.
 */

void socks_setbuffer(const int s, const int mode);
/*
 * Sets a flag in the iobuf belonging to "s", indicating data should
 * not be be written before a flush is done, the buffer becomes full,
 * or "another good reason" is given, according to "mode".
 * "mode" can take the same values as the corresponding argument
 * to setvbuf(3).
 */

size_t socks_addtobuffer(const int s, const whichbuf_t which,
                         const int encoded, const void *data,
                         const size_t datalen)
       __attribute__((__bounded__(__buffer__, 4, 5)));
/*
 * Adds "data", of length "datalen" to the buffer belonging to "s".
 * "which" must have one of the values WRITE_BUF or READ_BUF, to
 * indicate what part of the buffer to add the data to;
 * READ_BUF : data that has been read from the socket.
 * WRITE_BUF: data that should be written to the socket.
 *
 * Returns the number of bytes added.
 */

size_t
socks_getfrombuffer(const int s, const whichbuf_t which,
                    const int encoded, void *data, size_t datalen)
      __attribute__((__bounded__(__buffer__, 4, 5)));

/*
 * Copies up to "datalen" bytes from the iobuf belonging to "s".
 * "which" must have one of the values WRITE_BUF or READ_BUF, to
 * indicate what part of the buffer to copy the data from.
 *
 * Returns the number of bytes copied.
 */

size_t
socks_bytesinbuffer(const int s, const whichbuf_t which, const int encoded);
/*
 * Returns the number of bytes currently in the iobuf belonging to "s".
 */

int
socks_bufferhasbytes(const int s, const whichbuf_t which);
/*
 * Returns true if any of the buffers (encoded or decoded) belonging
 * to "s" has data in it.
 * Intended to be faster than calling socks_bytesinbuffer() twice,
 * once for each buffer (encoded/decoded).
 */


size_t
socks_freeinbuffer(const int s, const whichbuf_t which);
/*
 * Returns the number of bytes free in the iobuf belonging to "s".
 */

fd_set *
allocate_maxsize_fdset(void);
/*
 * Allocate a fd_set big enough to hold the highest file descriptor
 * we could possibly use.
 * Returns a pointer to the allocated fd_set, or exits on failure.
 */

rlim_t
getmaxofiles(limittype_t type);
/*
 * Return max number of open files for process.
 * If type is softlimit, the current limit is returned.
 * If type is hardlimit, the absolute maximum value is returned.
 */

char *
socks_getusername(const struct sockshost_t *host, char *buf, size_t buflen)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Tries to determine the username of the current user, to be used
 * when negotiating with the server "host".
 * The NUL-terminated username is written to "buf", which is of size
 * "buflen".
 * Returns:
 *      On success: pointer to "buf" with the username.
 *      On failure: NULL.
 */

char *
socks_getpassword(const struct sockshost_t *host, const char *user,
      char *buf, size_t buflen);
/*
 * Tries to determine the password of user "user", to be used
 * when negotiating with the server "host".
 * The NUL-terminated password is written to "buf", which is of length
 * "buflen"
 * Returns:
 *      On success: pointer to "buf" with the password.
 *      On failure: NULL.
 */

char *
socks_getenv(const char *name, value_t value);
/*
 * Depending on how the program was ./configured and on what
 * platform it runs, getenv(3) may or may not be disabled for
 * some names, for security reasons.
 *
 * This wrapper will return NULL if getenv(3) is disabled,
 * otherwise it will return the result of getenv(3).
 *
 * In addition, if "value" is not "dontcare", the function will
 * also compare the value returned by getenv(3), if any, to
 * see it it matches the value described by "value".  If they don't
 * match, the function will return NULL.
 */

int
socks_msghaserrors(const char *prefix, const struct msghdr *msg);
/*
 * Checks if "msg", as received via recvmsg(2), was truncated or
 * had other detectable errors, and reports it if so.
 * If reporting, "prefix" should contain information about where
 * the message was received.
 *
 * Returns true if "msg" has errors, "false" if not.
 */

void seconds2days(unsigned long *seconds, unsigned long *days,
                  unsigned long *hours, unsigned long *minutes);
/*
 * Converts "seconds" to the corresponding number of days, hours, minutes,
 * and seconds.
 * Upon return, the days, hours, minutes, and seconds are stored in the
 * passed arguments.
 */

void
showconfig(const struct config_t *config);
/*
 * prints out config "config".
 */

#if COVENANT
char *socks_decode_base64(char *in, char *out, size_t outlen);

#endif /* COVENANT */

#if SOCKSLIBRARY_DYNAMIC
#include "interposition.h"
#endif /* SOCKSLIBRARY_DYNAMIC */

#if SOCKS_CLIENT
#include "socks.h"
#else /* SOCKS_SERVER */
#include "sockd.h"
#endif /* SOCKS_SERVER */

#include "tostring.h"

#if HAVE_GSSAPI
#include "socks_gssapi.h"
#endif /* HAVE_GSSAPI */

#endif /* !_COMMON_H_ */
