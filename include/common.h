/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009
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

/* $Id: common.h,v 1.479 2009/10/09 08:05:13 michaels Exp $ */

#ifndef _COMMON_H_
#define _COMMON_H_
#endif /* !_COMMON_H_ */

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
 * _must_ be atleast as big as protocol allows.
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

/* should be max-size of exported state, but we don't know what it is. */
#define MAX_GSS_STATE     (2000)

#endif /* HAVE_GSSAPI */


#define  MAXIFNAMELEN      (255)

/*                           "255." "255." "255." "255" "." "65535" + NUL */
#define   MAXSOCKADDRSTRING    (4   +   4   + 4   +  3  + 1 +    5   + 1)

/*                                             "." + "65535" + NUL */
#define   MAXSOCKSHOSTSTRING (MAXHOSTNAMELEN + 1  +    5)

#define   MAXRULEADDRSTRING    (MAXSOCKSHOSTSTRING * 2)
#define   MAXGWSTRING        (MAXSOCKSHOSTSTRING)


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

#define close(n)   closen(n)

#define STRIPTRAILING(str, strused)          \
do {                                         \
   ssize_t i;                                \
                                             \
   for (i = strused - 1; i > 0; --i)         \
      if (str[i] == ',' || isspace(str[i]))  \
         str[i] = NUL;                       \
      else                                   \
         break;                              \
} while (/* CONSTCOND */ 0)

/* char methodarray to integer methodarray. */
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

#define SOCKD_FD_SIZE()   \
   (size_t)(howmany(sockscf.state.maxopenfiles + 1, NFDBITS) * sizeof(fd_mask))

#ifdef FD_ZERO
#undef FD_ZERO
#endif /* FD_ZERO */

#define FD_ZERO(p)                     \
do {                                   \
   memset((p), 0, SOCKD_FD_SIZE());    \
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

#define ERRNOISTMP(errno) \
   (  (errno) == EAGAIN  || (errno) == EWOULDBLOCK || (errno) == EINTR \
   || (errno) == ENOBUFS)

#define ERRNOISINPROGRESS(errno) \
   ((errno) == EWOULDBLOCK || (errno) == EINPROGRESS || (errno) == EAGAIN)

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
 * if not we get the default behaviour.
 */

#define SENDMSG_PADBYTES   (sizeof(long) * 8) /* just a guess. */

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
#define CMSG_AALLOC(name, size)           \
   union {                                \
      char cmsgmem[CMSG_SPACE(size)];     \
      struct cmsghdr align;               \
   } __CONCAT3(_, name, mem);             \
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
#endif /* HAVE_CMSGHDR */

/*
 * Returns the controldata member of "msg".
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
 * get a object from controldata "data".
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
 * Sets up "object" for sending a controlmessage of size "size".
 * "controlmem" is the memory the controlmessage is stored in.
 */
#if HAVE_CMSGHDR
#define CMSG_SETHDR_SEND(object, controlmem, size)             \
   do {                                                        \
      controlmem->cmsg_level  = SOL_SOCKET;                    \
      controlmem->cmsg_type   = SCM_RIGHTS;                    \
      controlmem->cmsg_len    = CMSG_LEN(size);                \
                                                               \
      object.msg_control      = (caddr_t)controlmem;           \
      object.msg_controllen   = controlmem->cmsg_len;          \
   } while (/* CONSTCOND */ 0)
#else /* !HAVE_CMSGHDR */
#define CMSG_SETHDR_SEND(object, controlmem, size)             \
   do {                                                        \
      object.msg_accrights      = (caddr_t)controlmem;         \
      object.msg_accrightslen   = (size);                      \
   } while (/* CONSTCOND */ 0)
#endif /* !HAVE_CMSGHDR */

/*
 * Sets up "object" for receiving a controlmessage of size "size".
 * "controlmem" is the memory set aside for the controlmessage.
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


/* returns length of controldata actually sent. */
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


#define INTERNAL_ERROR \
"an internal error was detected at %s:%d\nvalue = %ld, version = %s"

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
   error_msg(LOG_HIGH, INTERNAL_ERROR, __FILE__, __LINE__, (long int)(failure),\
   rcsid)


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
  (packet)->host.atype == SOCKS_ADDR_IPV4 ?                                    \
  sizeof((packet)->host.addr.ipv4) :(packet)->host.atype == SOCKS_ADDR_IPV6 ?  \
  sizeof((packet)->host.addr.ipv6) : (strlen((packet)->host.addr.domain) + 1))

#define ADDRESSIZE_V4(packet) (                                      \
   (packet)->atype == SOCKS_ADDR_IPV4 ?                              \
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

#define PROXY_HTTP_V1_0             1
#define PROXY_HTTP_V1_0s            "http_v1.0"
#define PROXY_MSPROXY_V2            2
#define PROXY_MSPROXY_V2s           "msproxy_v2"
#define PROXY_UPNP                  3
#define PROXY_UPNPs                 "UPNP"
#define PROXY_SOCKS_V4               4
#define PROXY_SOCKS_V4s              "socks_v4"
#define PROXY_SOCKS_V4REPLY_VERSION  0
#define PROXY_SOCKS_V5               5
#define PROXY_SOCKS_V5s              "socks_v5"
#define PROXY_DIRECT                 6
#define PROXY_DIRECTs               "direct"

/* subnegotiation. */
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

#define AUTHMETHOD_MAX         (AUTHMETHOD_PAM + 1)

#define MAXMETHODSTRING       MAX(sizeof(AUTHMETHOD_NONEs),     \
                              MAX(sizeof(AUTHMETHOD_GSSAPIs),   \
                              MAX(sizeof(AUTHMETHOD_UNAMEs),    \
                              MAX(sizeof(AUTHMETHOD_RFC931s),   \
                              sizeof(AUTHMETHOD_PAMs)))))

/* number of supported methods. */
#define MAXMETHOD             1 /* NONE      */   \
                            + 1 /* UNAME     */   \
                            + 1 /* GSSAPI    */   \
                            + 1 /* RFC931    */   \
                            + 1 /* RFC931    */

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

#define SOCKS_UNKNOWN            (SOCKS_DISCONNECT + 1)
#define SOCKS_UNKNOWNs           "unknown"


/* address types XXX should be enum. */
#define SOCKS_ADDR_IPV4        0x01
#define SOCKS_ADDR_IFNAME      0x02 /* not a socks constant, for convenience. */
#define SOCKS_ADDR_DOMAIN      0x03
#define SOCKS_ADDR_IPV6        0x04
#define SOCKS_ADDR_URL         0x05 /* not a socks constant, for convenience. */


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
#define HTTP_FAILURE           0   /* whatever, anything but 200. */

/* upnp stuff. */
#define UPNP_DISCOVERYTIME_MS          (1000)
#define DEFAULT_SSDP_BROADCAST_ADDR    "239.255.255.250"
#define DEFAULT_SSDP_PORT              (1900)

/* returncodes from UPNP_GetValidIGD(). */
#define UPNP_NO_IGD           (0)
#define UPNP_CONNECTED_IGD    (1)
#define UPNP_DISCONNECTED_IGD (2)
#define UPNP_UNKNOWN_DEVICE   (3)

#define UPNP_SUCCESS          (1)
#define UPNP_FAILURE          (2)


/* msproxy stuff. */

#define MSPROXY_PINGINTERVAL   (6 * 60)

#define MSPROXY_SUCCESS         0
#define MSPROXY_FAILURE         1
#define MSPROXY_NOTALLOWED      2

#define MSPROXY_MINLENGTH       172   /* minimum length of packet.            */
#define MSPROXY_VERSION         0x00010200   /* perhaps?                      */

/* errors */
#define MSPROXY_ADDRINUSE           0x0701
#define MSPROXY_BIND_AUTHFAILED     0x0804   /* auth failed for connect.   */
#define MSPROXY_CONNECT_AUTHFAILED  0x081e   /* auth failed for bind.      */
#define MSPROXY_CONNREFUSED         0x4      /* low 12 bits seem to vary.   */

/*
 * Server seems to ignore low-order bits of a 0x47?? command, so take them
 * for our own use.
 */
#define MSPROXY_HELLO            0x0500   /* packet 1 from client.            */
#define MSPROXY_HELLO_ACK        0x1000   /* packet 1 from server.            */

#define MSPROXY_USERINFO         0x1000   /* packet 2 from client.            */
#define MSPROXY_USERINFO_ACK     0x0400   /* packet 2 from server.            */

#define MSPROXY_SOMETHING        0x4700   /* packet 3 from client.            */
#define MSPROXY_SOMETHING_1_ACK  0x4714   /* packet 3 from server.            */

#define MSPROXY_SOMETHING_2      0x4701   /* packet 4 from client.            */
#define MSPROXY_SOMETHING_2_ACK  0x4715   /*
                                           * packet 4 from server, high 8 
                                           * bits seem to vary.               */
#define MSPROXY_SOMETHING_2_ACK2 0x4716   /* could be this too... dunno.      */

#define MSPROXY_RESOLVE          0x070d   /* resolve request from client.     */
#define MSPROXY_RESOLVE_ACK      0x070f   /* resolved info from server.         */

#define MSPROXY_BIND             0x0704   /* bind request.                    */
#define MSPROXY_BIND_ACK         0x0706   /* bind request accepted.           */

#define MSPROXY_BIND2            0x0707   /* dunno.                           */
#define MSPROXY_BIND2_ACK        0x0708   /* dunno.                           */

#define MSPROXY_BIND2            0x0707   /* dunno.                           */
#define MSPROXY_BIND2_ACK        0x0708   /* dunno.                           */

#define MSPROXY_LISTEN           0x0406   /* listen() performed(?)            */

#define MSPROXY_BINDINFO         0x0709   /* info about client server accepted*/

#define MSPROXY_BINDINFO_ACK     0x070a   /* we got the info(?)               */

#define MSPROXY_CONNECT          0x071e   /* connect request.                 */
#define MSPROXY_CONNECT_ACK      0x0703   /* connect request accepted.        */

#define MSPROXY_UDPASSOCIATE      0x0705   /* UDP associate request.          */
#define MSPROXY_UDPASSOCIATE_ACK  0x0706   /* UDP associate request accepted. */

#define MSPROXY_CONNECTED         0x042c   /* client connected to server?     */

#define MSPROXY_SESSIONEND        0x251e   /* maybe...                        */


/* flag _bits_ */
#define SOCKS_INTERFACEREQUEST   0x01
#define SOCKS_USECLIENTPORT      0x04

/* subcommands */
#define SOCKS_INTERFACEDATA      0x01


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

struct logtype_t {
   int            type;      /* type of logging (where to).                   */
   FILE            **fpv;    /* if logging is to file, this is the open file. */
   char            **fnamev; /* ... name of file.                             */
   int            *filenov;  /* ... filedescriptor of file (fileno).          */
   size_t         fpc;       /* number of files.                              */
   int            *fplockv;  /* locking of logfiles.                          */
   int            facility;  /* if logging to syslog, this is the facility.   */
   const char      *facilityname;   /* if logging to syslog, name of facility.   */ };



/* extensions supported by us. */
struct extension_t {
   unsigned bind:1;      /* use bind extension? */
   unsigned :0;
};



/* the address part of a socks packet */
union socksaddr_t {
   struct in_addr ipv4;
   char            ipv6[SOCKS_IPV6_ALEN];
   char            domain[MAXHOSTNAMELEN]; /* _always_ stored as C string.      */
};

/* the hostspecific part of misc. things */
struct sockshost_t {
   unsigned char        atype;
   union socksaddr_t    addr;
   in_port_t            port;
};



struct msproxy_request_t {
   char                  username[MAXNAMELEN];
   char                  unknown[MAXNAMELEN];
   char                  executable[MAXNAMELEN];
   char                  clienthost[MAXHOSTNAMELEN];

   int32_t               clientid;        /* 1-4                              */
   int32_t               magic25;         /* 5-8                              */
   int32_t               serverid;        /* 9-12                             */
   unsigned char         serverack;       /* 13: ack of last server packet    */
   char                  pad10[3];        /* 14-16                            */
   unsigned char         sequence;        /* 17: sequence # of this packet.   */
   char                  pad11[7];        /* 18-24                            */
   char                  RWSP[4];         /* 25-28: 0x52,0x57,0x53,0x50       */
   char                  pad15[8];        /* 29-36                            */
   int16_t               command;         /* 37-38                            */

   /* packet specifics start at 39. */
   union {
      struct {
         char            pad1[18];      /* 39-56                              */
         int16_t         magic3;        /* 57-58                              */
         char           pad3[114];      /* 59-172                             */
         int16_t         magic5;        /* 173-174: 0x4b, 0x00                */
         char            pad5[2];       /* 175-176                            */
         int16_t         magic10;       /* 177-178: 0x14, 0x00                */
         char            pad6[2];       /* 179-180                            */
         int16_t         magic15;       /* 181-182: 0x04, 0x00                */
         char            pad10[6];      /* 183-188                            */
         int16_t         magic20;       /* 189-190: 0x57, 0x04                */
         int16_t         magic25;       /* 191-192: 0x00, 0x04                */
         int16_t         magic30;       /* 193-194: 0x01, 0x00                */
         char            pad20[2];      /* 195-196: 0x4a, 0x02                */
         int16_t         magic35;       /* 197-198: 0x4a, 0x02                */
         char            pad30[10];     /* 199-208                            */
         int16_t         magic40;       /* 209-210: 0x30, 0x00                */
         char            pad40[2];      /* 211-212                            */
         int16_t         magic45;       /* 213-214: 0x44, 0x00                */
         char            pad45[2];      /* 215-216                            */
         int16_t         magic50;       /* 217-218: 0x39, 0x00                */
         char            pad50[2];      /* 219-220                            */
      } _1;

      struct {
         char            pad1[18];      /* 39-56                              */
         int16_t         magic3;        /* 57-58                              */
         char           pad3[114];      /* 59-172                             */
         int16_t         magic5;        /* 173-174: 0x00, 0x4b                */
         char            pad5[2];       /* 175-176                            */
         int16_t         magic10;       /* 177-178: 0x14, 0x00                */
         char            pad10[2];      /* 179-180                            */
         int16_t         magic15;       /* 181-182: 0x04, 0x00                */
         char            pad15[6];      /* 183-188                            */
         int16_t         magic20;       /* 189-190: 0x57, 0x04                */
         int16_t         magic25;       /* 191-192: 0x00, 0x04                */
         int16_t         magic30;       /* 193-194: 0x01, 0x00                */
         char            pad20[2];      /* 195-196                            */
         int16_t         magic35;       /* 197-198: 0x04, 0x00                */
         char            pad25[10];     /* 199-208                            */
         int16_t         magic50;       /* 209-210: 0x30, 0x00                */
         char            pad50[2];      /* 211-212                            */
         int16_t         magic55;       /* 213-214: 0x44, 0x00                */
         char            pad55[2];      /* 215-216                            */
         int16_t         magic60;       /* 217-218: 0x39, 0x00                */
      } _2;

      struct {
         char         pad1[4];          /* 39-42                              */
         int16_t      magic2;           /* 43-44                              */
         char         pad10[12];        /* 45-56                              */
         in_addr_t    bindaddr;         /* 57-60: address to bind.            */
         in_port_t    bindport;         /* 61-62: port to bind.               */
         char         pad15[2];         /* 63-64                              */
         int16_t      magic3;           /* 65-66                              */
         in_port_t    boundport;        /* 67-68                              */
         char         pad20[104];       /* 69-172                             */
         char         NTLMSSP[sizeof("NTLMSSP")];   /* 173-180: "NTLMSSP"     */
         int16_t      magic5;           /* 181-182: 0x01, 0x00                */
         char         pad25[2];         /* 183-184                            */
         int16_t      magic10;          /* 185-186: 0x96, 0x82                */
         int16_t      magic15;          /* 187-188: 0x08, 0x00                */
         int16_t      magic20;          /* 189-190: 0x28, 0x00                */
         char         pad30[2];         /* 191-192                            */
         int16_t      magic25;          /* 193-194: 0x96, 0x82                */
         int16_t      magic30;          /* 195-196: 0x01, 0x00                */
         char         pad40[12];        /* 197-208                            */
         int16_t      magic50;          /* 209-210: 0x30, 0x00                */
         char         pad50[6];         /* 211-216                            */
         int16_t      magic55;            /* 217-218: 0x30, 0x00              */
         char         pad55[2];         /* 219-220                            */
      } _3;

      struct {
         char            pad1[4];       /* 39-42                              */
         int16_t         magic1;        /* 43-44                              */
         int32_t         magic2;        /* 45-48                              */
         char            pad2[8];       /* 49-56                              */
         int16_t         magic3;        /* 57-58                              */
         char            pad3[6];       /* 59-64                              */
         int16_t         magic4;        /* 65-66                              */
         in_port_t      boundport;      /* 67-68                              */
         char           pad4[104];      /* 69-172                             */
         char            NTLMSSP[sizeof("NTLMSSP")];   /* 173-180: "NTLMSSP"  */
         int16_t         magic5;        /* 181-182: 0x03, 0x00                */
         char            pad5[2];       /* 183-184                            */
         int16_t         magic10;       /* 185-186: 0x18, 0x00                */
         int16_t         magic15;       /* 187-188: 0x18, 0x00                */
         int16_t         magic20;       /* 189-190: 0x49, 0x00                */
         char            pad10[6];      /* 191-196                            */
         int16_t         magic30;       /* 197-198: 0x61, 0x00                */
         char            pad15[2];      /* 199-200                            */
         int16_t         magic35;       /* 201-202: 0x08, 0x00                */
         int16_t         magic40;       /* 203-204: 0x08, 0x00                */
         int16_t         magic45;       /* 205-206: 0x34, 0x00                */
         char            pad20[2];      /* 207-208                            */
         int16_t         magic50;       /* 209-210: 0x07, 0x00                */
         int16_t         magic55;       /* 211-212: 0x07, 0x00                */
         int16_t         magic60;       /* 213-214: 0x3c, 0x00                */
         char            pad25[2];      /* 215-216                            */
         int16_t         magic65;       /* 217-218: 0x06, 0x00                */
         int16_t         magic70;       /* 219-220: 0x06, 0x00                */
         int16_t         magic75;       /* 221-222: 0x43, 0x00                */
      } _4;

      struct {
         unsigned char   hostlength;    /* length of host, including NUL.     */
         char            pad1[17];      /* 39-56                              */
         char            *host;         /* 57-...                             */
      } resolve;

      struct {
         int16_t         magic1;        /* 39-40                              */
         char            pad1[4];       /* 41-45                              */
         int32_t         magic3;        /* 45-48                              */
         char            pad5[8];       /* 48-56                              */
         int16_t         magic6;        /* 57-58: 0x0200                      */
         in_port_t      destport;       /* 59-60                              */
         in_addr_t      destaddr;       /* 61-64                              */
         char            pad10[4];      /* 65-68                              */
         int16_t         magic10;       /* 69-70                              */
         char            pad15[2];      /* 71-72                              */
         in_port_t      srcport;        /* 73-74: port client connects from   */
         char            pad20[82];     /* 75-156                             */
      } _5;

      struct {
         int16_t         magic1;        /* 39-40                              */
         char            pad5[2];       /* 41-42                              */
         int16_t         magic5;        /* 43-44                              */
         int32_t         magic10;       /* 45-48                              */
         char            pad10[2];      /* 49-50                              */
         int16_t         magic15;       /* 51-52                              */
         int32_t         magic16;       /* 53-56                              */
         int16_t         magic20;       /* 57-58                              */
         in_port_t      clientport;     /* 59-60: forwarded port.             */
         in_addr_t      clientaddr;     /* 61-64: forwarded address.          */
         int32_t         magic30;       /* 65-68                              */
         int32_t         magic35;       /* 69-72                              */
         in_port_t      serverport;     /* 73-74: port server will connect
                                          *          to us from.
                                          */
         in_port_t      srcport;        /* 75-76: connect request; port used
                                         *          on client behalf.
                                         */
         in_port_t      boundport;      /* 77-78: bind request; port used
                                          *       on client behalf.
                                          */
         in_addr_t      boundaddr;      /* 79-82: addr used on client behalf  */
         char            pad30[90];     /* 83-172                             */
      } _6;

   } packet;
};

struct msproxy_response_t {
   int32_t               packetid;         /* 1-4                              */
   int32_t               magic5;            /* 5-8                              */
   int32_t              serverid;         /* 9-12                              */
   char                  clientack;         /* 13: ack of last client packet.   */
   char                  pad5[3];            /* 14-16                              */
   unsigned char         sequence;         /* 17: sequence # of this packet.   */
   char                  pad10[7];         /* 18-24                              */
   char                  RWSP[4];            /* 25-28: 0x52,0x57,0x53,0x50         */
   char                  pad15[8];         /* 29-36                              */
   int16_t               command;            /* 37-38                              */

   union {
      struct {
         char            pad5[18];         /* 39-56                              */
         int16_t         magic20;            /* 57-58: 0x02, 0x00                  */
         char            pad10[6];         /* 59-64                              */
         int16_t         magic30;            /* 65-66: 0x74, 0x01                  */
         char            pad15[2];         /* 67-68                              */
         int16_t         magic35;            /* 69-70: 0x0c, 0x00                  */
         char            pad20[6];         /* 71-76                              */
         int16_t         magic50;            /* 77-78: 0x04, 0x00                  */
         char            pad30[6];         /* 79-84                              */
         int16_t         magic60;            /* 85-86: 0x65, 0x05                  */
         char            pad35[2];         /* 87-88                              */
         int16_t         magic65;            /* 89-90: 0x02, 0x00                  */
         char            pad40[8];         /* 91-98                              */
         in_port_t      udpport;            /* 99-100                           */
         in_addr_t      udpaddr;            /* 101-104                           */
      } _1;

      struct {
         char            pad5[18];         /* 39-56                              */
         int16_t         magic5;            /* 57-58: 0x01, 0x00                  */
      } _2;

      struct {
         char            pad1[6];            /* 39-44                              */
         int32_t         magic10;            /* 45-48                              */
         char            pad3[10];         /* 49-58                              */
         in_port_t      boundport;         /* 59-60: port server bound for us.   */
         in_addr_t      boundaddr;         /* 61-64: addr server bound for us.   */
         char            pad10[4];         /* 65-68                              */
         int16_t         magic15;            /* 69-70                              */
         char            pad15[102];         /* 70-172                           */
         char            NTLMSSP[sizeof("NTLMSSP")];   /* 173-180: "NTLMSSP"   */
         int16_t         magic50;            /* 181-182: 0x02, 0x00               */
         char            pad50[2];         /* 183-184                           */
         int16_t         magic55;            /* 185-186: 0x08, 0x00               */
         int16_t         magic60;            /* 187-188: 0x08, 0x00               */
         int16_t         magic65;            /* 189-190: 0x28, 0x00               */
         char            pad60[2];         /* 191-192                           */
         int16_t         magic70;            /* 193-194: 0x96, 0x82               */
         int16_t         magic75;            /* 195-196: 0x01, 0x00               */
         char            pad70[16];         /* 197-212                           */
         char            ntdomain[257];      /* 213-EOP                           */
      } _3;

      struct {
         char            pad5[134];         /* 39-172                           */
      } _4;

      struct {
         unsigned char   addroffset;         /* 39: weird, probably wrong.         */
         char            pad5[13];         /* 40-52                              */
         in_addr_t      hostaddr;         /* ?-?+4                              */
      } resolve;

      struct {
         int16_t         magic1;            /* 39-40                              */
         char            pad5[18];         /* 41-58                              */
         in_port_t      clientport;         /* 59-60: forwarded port.            */
         in_addr_t      clientaddr;         /* 61-64: forwarded address.         */
         int32_t         magic10;            /* 65-68                              */
         int32_t         magic15;            /* 69-72                              */
         in_port_t      serverport;         /* 73-74: port server will connect
                                           *          to us from.
                                          */
         in_port_t      srcport;            /* 75-76: connect request; port used
                                           *          on client behalf.
                                          */
         in_port_t      boundport;         /* 77-78: bind request; port used
                                           *          on client behalf.
                                          */
         in_addr_t      boundaddr;         /* 79-82: addr used on client behalf*/
         char            pad10[90];         /* 83-172                           */
      } _5;
   } packet;
};
struct request_t {
   unsigned char         version;
   unsigned char         command;
   unsigned char         flag;
   struct sockshost_t    host;
   struct authmethod_t   *auth;   /* pointer to level above. */
   int                   protocol;
};


struct response_t {
   unsigned char         version;
   unsigned char         reply;
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
       unsigned nec:1;
       unsigned clear:1;
       unsigned integrity:1;
       unsigned confidentiality:1;
       unsigned permessage:1;
       unsigned :0;
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
   } mdata;
};


struct protocol_t {
   unsigned tcp:1;
   unsigned udp:1;
   unsigned :0;
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
   unsigned direct:1;
   unsigned socks_v4:1;
   unsigned socks_v5:1;
   unsigned msproxy_v2:1;
   unsigned http_v1_0:1;
   unsigned upnp:1;
   unsigned :0;
};



struct msproxy_state_t {
   struct sockaddr_in      controladdr;   /* UDP address of proxyserver.      */
   int32_t                  magic25;
   int32_t                  bindid;
   int32_t                  clientid;
   int32_t                  serverid;
   unsigned char            seq_recv;    /* seq number of last packet recv.   */
   unsigned char            seq_sent;    /* seq number of last packet sent.   */
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
#endif
   int                     inprogress;    /* operation in progress? (-1)      */
   unsigned                issyscall:1;   /* started out as a real systemcall */
   struct msproxy_state_t  msproxy;       /* if msproxy, msproxy state.       */
   struct protocol_t       protocol;      /* protocol in use.                 */
   unsigned char           udpconnect;    /* connected UDP socket?            */
   int                     syscalldepth;
   int                     version;       /* version (-1)                     */
};

struct ruleaddr_t {
   unsigned char         atype;
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
   unsigned char         atype;
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

#if HAVE_GSSAPI
   char                    gssapiservicename[MAXNAMELEN];
   char                    gssapikeytab[MAXNAMELEN];
   struct gssapi_enc_t     gssapiencryption;       /* encryption status.      */
#endif /* HAVE_GSSAPI */

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
 * no futher explenation is given; the len field simply holds
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
 * The operation when writting is more complicated, because
 * we can get multiple write requests that we fail to send down
 * to the socket buffer, which in sum may be bigger than the
 * the iobuffer set asside to hold buffered unwritten data.
 *
 * The only way to prevent that situation from occuring is to
 * put a cap on how much we read, and never read more data than
 * we can store in our write-buffer, encoded.
 * We can use gss_wrap_size_limit() in combination with the amount
 * of data free in the buffer to find out the max amount of data to
 * read, and read no more than that in the tcp case.
 *
 * The operation for writting thus becomes:
 * 1) Encode the data received and write it to the socket.
 *
 * 2) If we fail to write all the data, and it is a tcp socket,
 *    store the remaing data in the iobuffer, setting encodedlen
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
   unsigned    allocated:1;
   int         s;

#if HAVE_GSSAPI
#  if (SOCKD_BUFSIZE) < (2 * (MAXGSSAPITOKENLEN + GSSAPI_HLEN))
 #     error "SOCKD_BUFSIZE too small."
#  endif
#endif /* HAVE_GSSAPI */

   char         buf[2][SOCKD_BUFSIZE];

   struct {
#if SOCKS_CLIENT
      int      mode;       /* buffering mode.  Default is no buffering.       */
      size_t   peekedbytes;/* # of bytes we last peeked at.                   */
#endif /* SOCKS_CLIENT */

      size_t   len;        /* length of decoded/plaintext data in buffer.     */
      size_t   enclen;     /* length of encoded data in buffer.               */
   } info[2];

   int      stype;         /* sockettype; tcp or udp                          */
} iobuffer_t;


struct socksfd_t {
   unsigned             allocated:1;/* allocated?                             */
   int                  control;    /* control connection to server.          */
   struct socksstate_t  state;      /* state of this connection.              */
   struct sockaddr      local;      /* local address of data connection.      */
   struct sockaddr      server;     /* remote address of data connection.     */
   struct sockaddr      remote;     /* address server is using on our behalf. */
   struct sockaddr      reply;      /* address to expect reply from.          */

   union {
      struct sockaddr      accepted;   /* address server accepted for us.     */
      struct sockaddr      connected;  /* address server connected to for us. */
   } forus;

   struct route_t      *route;
};



struct route_t {
   int                     number;      /* routenumber.                       */

   struct {
      unsigned    autoadded:1;/* autoadded route?                             */
      size_t      failed;     /* route is bad?  How many times it has failed. */
      time_t      badtime;    /* if route is bad, time last marked as such.   */
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

int
socks_initupnp(const gwaddr_t *gw, proxystate_t *data);
/*
 * Inits upnp for interface corresponding to address "gw".
 * If successfull, the necessary information to later use the found
 * upnp router is saved in "data", which should normaly be part of a
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
udpheader_add(const struct sockshost_t *host, const void *msg, size_t *len,
      const size_t msgsize);
/*
 * Prefixes the udpheader_t version of "host" to a copy of "msg",
 * which is of length "len".
 * "msgsize" gives the size of the memory pointed to by "msg".
 * If "msgsize" is large enough the function will prepend the udpheader
 * to "msg" directly (moving the old contents to the right) rather than
 * allocating new memory.  XXX fix this, can't be both const and not const.
 * Upon return "len" gives the length of the new "msg".
 *
 *   Returns:
 *      On success: "msg" with the udpheader prepended, or a new message
 *                  that the caller needs to free.
 *      On failure: NULL (out of memory).
 */

int
fdisopen(const int fd);
/*
 * returns true if the filedescriptor "fd" currently references a open fd,
 * false otherwise.
 */

int
fdisblocking(const int fd);
/*
 * returns true if the filedescriptor "fd" is blocking, false otherwise.
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
urlstring2sockaddr(const char *string, struct sockaddr *saddr);
/*
 * Converts the address givein in "string", on URL:// format, to
 * a sockaddr address.
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
hostname2sockaddr(const char *name, int index, struct sockaddr *addr);
/*
 * Retrieves the address with index "index" for the hostname named "name".
 * Returns:
 *      On success: "addr", filled in with the address found.
 *      On failure: NULL (no address found).
 */

struct sockaddr *
ifname2sockaddr(const char *ifname, int index, struct sockaddr *addr,
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
 * Returns a pointer to the memory containing the interfacename, or
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
 * Like recvmsg(), but tries to read until all has been read.
 */

ssize_t
sendmsgn(int s, const struct msghdr *msg, int flags);
/*
 * Like sendmsg(), but tries to send until all has been sent.
 */

ssize_t
readn(int, void *, size_t, const size_t minread, struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * Like read() but with two additional arguments:
 * minread - the minimum amount of bytes to read before returning, or error.
 * auth    - authentication info for the filedescriptor.  May be NULL.
 */

ssize_t
writen(int, const void *, size_t, const size_t minwrite,
      struct authmethod_t *auth)
      __attribute__((__bounded__(__buffer__, 2, 3)));
/*
 * like write() but if with two additional arguments:
 * minwrite - the minimum amount of bytes to write before returning, or error.
 * auth     - authentication info for the filedescriptor.  May be NULL.
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
socks_recvfromn(int s, void *buf, size_t len, size_t minread, int flags,
      struct sockaddr *from, socklen_t *fromlen,
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
selectn(int, fd_set *rset, fd_set *bufrset, fd_set *wset, fd_set *bufwset,
      fd_set *xset, struct timeval *);
/*
 * Wrapper around select() that _mostly_ retries on EINTR, and also takes
 * two * additional arguments:
 * bufrset - if not NULL, descriptors with data buffered for reading.
 * bufwset - if not NULL, descriptors with free space in the write buffer.
 *
 * In addition, if it's called by the server, it checks whether we
 * have a signal queed internally, and if so calls the appopriate
 * signalhandler.
 * Note that if this happens, it's possible the function will set errno
 * to EINTR and return.  This can happen if the signalhandler closed one
 * of the descriptors in the sets, so that select(2) can no longer be called
 * without returing EBADF.
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

size_t
snprintfn(char *str, size_t size, const char *format, ...)
      __attribute__((format(printf, 3, 4)))
      __attribute__((__nonnull__(3)))
      __attribute__((__bounded__(__string__, 1, 2)));
/*
 * Wrapper around snprintf() for consistent behaviour.  Same as stdio
 * snprintf() but the following are also enforced:
 *      returns 0 instead of -1 (rawterminates *str).
 *      never returns a value greater than size - 1.
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

void
socks_addlogfile(const char *logfile);
/*
 * Adds the file "logfile" to the list of files we log to.
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
 * as environment-varibles related.
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
 * "address"'s might have if appropriate, this can be useful to match
 * multihomed hosts where the client requests e.g a bind connection.
 * Returns true if "rule" matched "address".
 */

struct hostent *
hostentdup(struct hostent *hostent);
/*
 * Duplicates "hostent".
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
socks_connecthost(int s, const struct sockshost_t *host);
/*
 * Tries to connect to "host".  If "host"'s address is not a IP address,
 * the function also tries to connect to any alias for "host"'s
 * name.  The connection is done using the open descriptor "s".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
socks_unconnect(const int s);
/*
 * "unconnects" a socket.  Must only be used with udp sockets.
 * Returns:
 *      On success: 0
 *      On failure: -1
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
 * which is assumed to be the packet that will be sent to a socksserver,
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
showstate(const struct serverstate_t *state);
/*
 * Shows "state".
 */

void
showmethod(size_t methodc, const int *methodv);
/*
 * Shows "methodv".
 */

struct route_t *
socks_addroute(const struct route_t *route, const int last);
/*
 * Appends a copy of "route" to our list of routes.
 * If "last" is true, the route is added to the end of our list.
 * If not, it's added to the start, and existing rulenumbers are updated
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
 * assumed to be the packet that will be sent to a socksserver, so it is
 * recommended that it's contents be as conservative as possible.
 *
 * Returns:
 *      On success: pointer to route that should be used.
 *      On failure: NULL (no route found).
 */

unsigned char
sockscode(int version, int code);
/*
 * Maps the socks replycode "code", which is in non-version specific format,
 * to the equivalent replycode in version "version".
 */

unsigned char
errno2reply(int errnum, int version);
/*
 * Returns the socks version "version" reply code for a error of type "errno".
 */

char *
str2vis(const char *string, size_t len, char *visstring, size_t vislen)
      __attribute__((__bounded__(__string__, 3, 4)));
/*
 * Visually encodes exactly "len" chars of "string" and stores the
 * result in "visstring", which is of length "vislen".  "vislen" should
 * be at least "len" * 4 + 1.
 * If "visstring" is NULL, memory of the appropriate size is allocated,
 * and must later be freed by caller.
 *
 * Returns:
 *      On success: the visually encoded string.
 *      On failure: NULL.  (out of memory.)
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
fdsetop(int nfds, int op, const fd_set *a, const fd_set *b, fd_set *result);
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
 *      Operators supported is: AND ('&'), XOR ('^'), and OR ('|').
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
socks_mklock(const char *template);
/*
 * Creates a filedescriptor that can be used with socks_lock() and
 * socks_unlock().
 * Returns:
 *      On success: filedescriptor
 *      On failure: -1
 */

int
socks_lock(int fd, int type, int timeout);
/*
 * Looks the filedescriptor "fd".
 * "type" is the type of lock; F_RDLCK or F_WRLCK.
 * "timeout" is how long to wait for lock, supported values:
 *      -1: forever.
 *      0 : don't wait.
 * Returns:
 *      On success: 0
 *      On error  : -1
 */

void
socks_unlock(int d);
/*
 * Unlocks the filedescriptor "d", previously locked by this process.
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
msproxy_negotiate(int s, int control, struct socks_t *packet);
/*
 * Negotiates with the msproxy server connected to "control".
 * "s" gives the socket to be used for dataflow.
 * "packet" contains the request and on return from the function
 * contains the response.
 * Returns:
 *      On success: 0 (server replied to our request).
 *      On failure: -1
 */

int
send_msprequest(int s, struct msproxy_state_t *state,
      struct msproxy_request_t *packet);
/*
 * Sends a msproxy request to "s".
 * "state" is the current state of the connection to "s",
 * "packet" is the request to send.
 */

int
recv_mspresponse(int s, struct msproxy_state_t *state,
      struct msproxy_response_t *packet);
/*
 * Receives a msproxy response from "s".
 * "state" is the current state of the connection to "s",
 * "packet" is the memory the response is read into.
 */

int
msproxy_sigio(int s);
/*
 * Must be called on sockets where we expect the connection to be forwarded
 * by the msproxy server.
 * "s" is the socket and must have been added with socks_addaddr() beforehand.
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
msproxy_init(void);
/*
 * inits things for using a msproxyserver.
 *      On success: 0
 *      On failure: -1
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
serverreplyisok(int version, int reply, struct route_t *route);
/*
 * "replycode" is the reply code returned by a socksserver of version
 * "version".
 * "route" is the route that was used for the socksserver.
 * If the errorcode indicates a serverfailure, the route might be
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
 * Clears bad markson route.
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
 * Enters username/password negotiation with the socksserver connected to
 * the socket "s".
 * "host" gives the name of the server.
 * "version" gives the socksversion established to use.
 * "name", if not NULL, gives the name to use for authenticating.
 * "password", if not NULL, gives the name to use for authenticating.
 * Returns:
 *      On success: 0
 *      On failure: whatever the remote socksserver returned as status.
 */

#if HAVE_GSSAPI
int
clientmethod_gssapi(int s, int protocol, const struct gateway_t *gw,
       int version, struct authmethod_t *auth);
/*
 * Enters gssapi negotiation with the socksserver connected to
 * the socket "s".
 * "gw" gives the name of the gateway.
 * "version" gives the socksversion established to use.
 * "*auth", authentication structure
 * Returns:
 *              On success: 0
 *              On failure: whatever the remote socksserver returned as status.
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
 * Aborts with an errormessage if not.
 */

int socks_yyparse(void);
int socks_yylex(void);

int
socks_sendrequest(int s, const struct request_t *request);
/*
 * Sends the request "request" to the socksserver connected to "s".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
socks_recvresponse(int s, struct response_t *response, int version);
/*
 * Receives a socks response from the "s".  "response" is filled in with
 * the data received.
 * "version" is the protocolversion negotiated.
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

iobuffer_t *
socks_allocbuffer(const int s);
/*
 * Returns the iobuffer allocated to filedescriptor "s", or
 * a new free one if none is allocated.
 */

iobuffer_t *
socks_getbuffer(const int s);
/*
 * Returns the iobuffer allocated to filedescriptor "s".
 */

void
socks_freebuffer(const int s);
/*
 * Marks the iobuffer allocated to filedescriptor "s" as free.
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
 * Tries to flush the data buffered for filedescriptor "s".
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
 * indicate what part of the buffer to add the data to.
 * and also implies the data belongs to a udp-packet.
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

size_t
socks_freeinbuffer(const int s, const whichbuf_t which);
/*
 * Returns the number of bytes free in the iobuf belonging to "s".
 */

fd_set *
allocate_maxsize_fdset(void);
/*
 * Allocate a fd_set big enough to hold the highest filedescriptor
 * we could possibly use.
 * Returns a pointer to the allocated fd_set, or exits on failure.
 */

typedef enum { softlimit, hardlimit } limittype_t;
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

#if SOCKSLIBRARY_DYNAMIC
#include "interposition.h"
#endif /* SOCKSLIBRARY_DYNAMIC */

#if SOCKS_CLIENT
#include "socks.h"
#endif /* SOCKS_CLIENT */
#if SOCKS_SERVER || BAREFOOTD
#include "sockd.h"
#endif /* SOCKS_SERVER || BAREFOOTD */

#include "tostring.h"

#if HAVE_GSSAPI
#include "socks_gssapi.h"
#endif /* HAVE_GSSAPI */
