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

/* $Id: common.h,v 1.126 1998/11/13 21:17:14 michaels Exp $ */

#ifndef _COMMON_H_
#define _COMMON_H_
#endif

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */



#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif  /* HAVE_SYS_FILE_H */
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
/* XXX This is a hack. Avoid transparent sockaddr union used in linux
   to avoid the use of the union in the code. Mainly used in
   interposition.c*/
#ifdef WE_DONT_WANT_NO_SOCKADDR_ARG_UNION
#ifdef __GNUC__
#define __HAD_GNUC __GNUC__
#undef __GNUC__
#endif  /* __GNUC__ */
#endif  /* WE_DONT_WANT_NO_SOCKADDR_ARG_UNION */
#include <sys/socket.h>
#ifdef __HAD_GNUC
#define __GNUC__ __HAD_GNUC
#endif  /* __HAD_GNUC */
#ifdef NEED_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* NEED_SYS_SOCKIO_H */
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif  /* HAVE_CRYPT_H */
#include <ctype.h>
#ifdef SOCKSLIBRARY_DYNAMIC
#include <dlfcn.h>
#endif  /* SOCKSLIBRARY_DYNAMIC */
#ifdef HAVE_VWARNX
#include <err.h>
#endif  /* HAVE_VWARNX */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include <string.h>
#include <syslog.h>
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif  /* HAVE_LIBWRAP */
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif  /* HAVE_UNISTD_H */

#ifdef lint
extern const int lintnoloop_common_h;
#else
#define lintnoloop_common_h 0
#endif

/*XXX?*/
#ifndef _CONFIG_H_
#include "config.h"
#endif

#ifndef RLIMIT_OFILE
#define RLIMIT_OFILE RLIMIT_NOFILE
#endif /* !RLIMIT_OFILE */


#ifdef NEED_GETSOCKOPT_CAST
#define getsockopt(a,b,c,d,e) getsockopt((a),(b),(c),(char *)(d),(e))
#define setsockopt(a,b,c,d,e) setsockopt((a),(b),(c),(char *)(d),(e))
#endif  /* NEED_GETSOCKOPT_CAST */

#ifndef HAVE_BZERO
#define bzero(b, len) memset(b, 0, len)
#endif  /* !HAVE_BZERO */

#ifdef DEBUG

/*
 * solaris 2.5.1 and it's stream stuff is broken and puts the processes
 * into never-never land forever on half the sendmsg() calls if they
 * involve ancillary data.
*/

#ifndef HAVE_SENDMSG_DEADLOCK
#define HAVE_SENDMSG_DEADLOCK
#endif

#ifndef HAVE_ACCEPTLOCK
#define HAVE_ACCEPTLOCK
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
# error "no known 8 bits wide datatype"
#endif

#if SIZEOF_SHORT == 2
 typedef unsigned short ubits_16;
 typedef          short sbits_16;
#else
# if SIZEOF_INT == 2
  typedef unsigned int ubits_16;
  typedef          int sbits_16;
# else
#  error "no known 16 bits wide datatype"
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
#   error "no known 32 bits wide datatype"
#  endif /* SIZEOF_LONG == 4 */
# endif /* SIZEOF_SHORT == 4 */
#endif /* SIZEOF_INT == 4 */

#ifndef INADDR_NONE
# define INADDR_NONE (ubits_32) 0xffffffff
#endif  /* !INADDR_NONE */

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif  /* HAVE_LIMITS_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif  /* HAVE_STRINGS_H */

#ifndef MAX
# define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif /* !MAX */

#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif /* !MIN */

#ifdef NEED_EXIT_FAILURE
/* XXX assumes EXIT_SUCCESS is undefined too */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#endif /* NEED_EXIT_FAILURE */

#ifdef NEED_SA_RESTART
#define SA_RESTART SV_INTERRUPT
#endif  /* NEED_SA_RESTART */

#ifdef NEED_AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif  /* NEED_AF_LOCAL */

#define SOCKS_TRYHARDER

#ifndef HAVE_LINUX_SOCKADDR_TYPE
#define __SOCKADDR_ARG struct sockaddr *
#define __CONST_SOCKADDR_ARG const struct sockaddr *
#define socklen_t int
#endif  /* ! HAVE_LINUX_SOCKADDR_TYPE */

#ifdef HAVE_NOMALLOC_REALLOC
#define realloc(p,s) (((p) == NULL) ? (malloc(s)) : (realloc((p),(s))))
#endif  /* HAVE_NOMALLOC_REALLOC */

/* __CONCAT macro from anoncvs */
#ifndef __CONCAT
#if defined(__STDC__) || defined(__cplusplus)
#define __CONCAT(x,y)    x ## y
#else
#define __CONCAT(x,y)    x/**/y
#endif
#endif


/* global variables needed by everyone. */
extern struct config_t config;

	/*
	 * defines
	*/


/*
 * redefine system limits to match that of socks protocol. 
 * No need for these to be bigger than protocol allows, but they
 * _must_ be atleast as big as protocol allows.
*/

/* used only if no usable system call is found (getdtablesize/sysconf)*/
#define SOCKS_FD_MAX 250

#ifdef 	MAXHOSTNAMELEN
#undef 	MAXHOSTNAMELEN
#endif
#define	MAXHOSTNAMELEN		(255 + 1)		/* socks5: 255, +1 for len. */

#ifdef	MAXNAMELEN
#undef 	MAXNAMELEN
#endif
#define 	MAXNAMELEN			(255 + 1)		/* socks5: 255, +1 for len. */

#ifdef	MAXPWLEN
#undef 	MAXPWLEN
#endif
#define 	MAXPWLEN				(255 + 1)		/* socks5: 255, +1 for len. */


#ifndef NUL
#define NUL '\0'
#endif

#define CONFIGTYPE_SERVER	1
#define CONFIGTYPE_CLIENT	2

#define PROTOCOL_TCPs		"tcp"
#define PROTOCOL_UDPs		"udp"
#define PROTOCOL_UNKNOWNs	"unknown"


/*#define DEFAULT_SOCKSVERSION		SOCKS_V5 */

#define LOGTYPE_SYSLOG				0x1
#define LOGTYPE_FILE					0x2

#define NOMEM "<memory exhausted>"


	/*
	 * macros
	*/


#define close(n)	closen(n)

#define select(nfds, readfds, writefds, exceptfds, timeout) \
		 selectn(nfds, readfds, writefds, exceptfds, timeout)

#define PORTRESERVED(port)	(ntohs((port)) == 0 ? \
	0 : ntohs((port)) < IPPORT_RESERVED ? 1 : 0)

#define ELEMENTS(array) (sizeof(array) / sizeof(array[0]))

#if UCHAR_MAX > 0xff
#define OCTETIFY(a) ((a) = ((a) & 0xff))
#else
#define OCTETIFY(a)	((a) = (a))
#endif
/*
 * Note that it's the argument that will be truncated, not just the
 * returnvalue.
*/


#define INTERNAL_ERROR \
"an internal error was detected at %s:%d\nvalue = %ld, version = %s"

#define SASSERT(expression) 	\
do {									\
	if (!(expression))			\
		SERR(expression);			\
} while (lintnoloop_common_h)


#define SASSERTX(expression) 	\
do {									\
	if (!(expression))			\
		SERRX(expression);		\
} while (lintnoloop_common_h)


/*
 * wrappers around err()/errx()/warn()/warnx() for more consistent error
 * messages.
 * "failure" is the value that was wrong and which caused the internal error.
*/


#define SERR(failure) 				\
do {										\
	SWARN(failure);					\
	abort();								\
} while (lintnoloop_common_h)

#define SERRX(failure) 				\
do {										\
	SWARNX(failure);					\
	abort();								\
} while (lintnoloop_common_h)



#define SWARN(failure) 		\
	swarn(INTERNAL_ERROR,	\
	__FILE__, __LINE__, 	(long int)(failure), rcsid)

#define SWARNX(failure) 	\
	swarnx(INTERNAL_ERROR,	\
	__FILE__, __LINE__, 	(long int)(failure), rcsid)



#define ERR(failure) 								\
do {														\
	warn(INTERNAL_ERROR, __FILE__, __LINE__, 	\
	(long int)(failure), rcsid);					\
	abort();												\
} while (p)

#define ERRX(failure) 								\
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


/* the size of a udp header "packet" (no padding) */
#define PACKETSIZE_UDP(packet) ( 											\
	sizeof((packet)->flag) + sizeof((packet)->frag) 					\
	+ sizeof((packet)->host.atype) + sizeof((packet)->host.port) 	\
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
#define ADDRESSIZE_V5(packet) ( 																\
  (packet)->host.atype == SOCKS_ADDR_IPV4 ? 												\
  sizeof((packet)->host.addr.ipv4) :(packet)->host.atype == SOCKS_ADDR_IPV6 ?	\
  sizeof((packet)->host.addr.ipv6) : (strlen((packet)->host.addr.domain) + 1))

#define ADDRESSIZE_V4(packet) ( \
	(packet)->atype == SOCKS_ADDR_IPV4 ? \
	sizeof((packet)->addr.ipv4) : (strlen((packet)->addr.host) + 1))


/*
 * This is for Rgethostbyname() support.  FAKEIP_START is the first
 * address in the range of "fake" ip addresses, FAKEIP_END is the last.
 * There can thus be FAKEIP_END - FAKEIP_START number of fake ip addresses' 
 * supported per program.  INADDR_ANY must not be within the range.
*/
#define FAKEIP_START 1	
#define FAKEIP_END	255


#define SOCKS_V4 	4
#define SOCKS_V5 	5

#define SOCKS_V4REPLY_VERSION 0

/* connection authentication METHOD values from rfc19228 */
#define AUTHMETHOD_NONE   	0x00
#define AUTHMETHOD_NONEs  	"none"
#define AUTHMETHOD_GSSAPI 	0x01
#define AUTHMETHOD_GSSAPIs "GSS-API"
#define AUTHMETHOD_UNAME  	0x02
#define AUTHMETHOD_UNAMEs  "username/password"


/* X'03' to X'7F' IANA ASSIGNED 						*/

/* X'80' to X'FE' RESERVED FOR PRIVATE METHODS	*/

#define AUTHMETHOD_NOACCEPT 0xff
#define AUTHMETHOD_NOACCEPTs "no acceptable method"

#define METHODS_MAX	255

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

#define SOCKS_PURECONNECT			(SOCKS_BINDREPLY + 1)
#define SOCKS_PURECONNECTs			"connect"

/* misc stuff */
#define SOCKS_ACCEPT					(SOCKS_PURECONNECT + 1)
#define SOCKS_ACCEPTs				"accept"

#define SOCKS_DISCONNECT			(SOCKS_ACCEPT + 1)
#define SOCKS_DISCONNECTs			"disconnect"


/* address types */ 
#define SOCKS_ADDR_IPV4     	0x01
#define SOCKS_ADDR_DOMAIN	 	0x03
#define SOCKS_ADDR_IPV6       0x04

/* reply field values */
#define SOCKS_SUCCESS    		0x00
#define SOCKS_FAILURE    		0x01
#define SOCKS_NOTALLOWED 		0x02
#define SOCKS_NETUNREACH 		0x03
#define SOCKS_HOSTUNREACH 		0x04
#define SOCKS_CONNREFUSED 		0x05
#define SOCKS_TTLEXPIRED  		0x06
#define SOCKS_CMD_UNSUPP  		0x07
#define SOCKS_ADDR_UNSUPP 		0x08
#define SOCKS_INVALID_ADDRESS 0x09

/* version 4 codes. */
#define SOCKSV4_SUCCESS			90
#define SOCKSV4_FAIL				91
#define SOCKSV4_NO_IDENTD		92
#define SOCKSV4_BAD_ID			93



/* flag _bits_ */
#define SOCKS_INTERFACEREQUEST 	0x01
#define SOCKS_USECLIENTPORT		0x04

/* subcommands */
#define SOCKS_INTERFACEDATA		0x01


#define SOCKS_TCP			1
#define SOCKS_UDP			2

#define SOCKS_RECV		0
#define SOCKS_SEND		1

#if 0
/* where is this from? (michaels) */
#if defined(__alpha__)
typedef unsigned int u_int32;
#else
typedef unsigned long u_int32;
#endif
#endif

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

/* XXX no ivp6 support currently. */
#define SOCKS_IPV6_ALEN 16

#if !defined(SOCKSLIBRARY_DYNAMIC)
#define sys_accept(s, addr, addrlen)		accept(s, addr, addrlen)
#define sys_bind(s, name, namelen)			bind(s, name, namelen)
#define sys_connect(s, name, namelen)		connect(s, name, namelen)
#define sys_bindresvport(sd, sin)			bindresvport(sd, sin)
#define sys_gethostbyname(name)				gethostbyname(name)
#define sys_gethostbyname2(name, af)		gethostbyname2(name, af)
#define sys_getpeername(s, name, namelen)	getpeername(s, name, namelen)
#define sys_getsockname(s, name, namelen)	getsockname(s, name, namelen)
#define sys_recvfrom(s, buf, len, flags, from, fromlen) \
		  recvfrom(s, buf, len, flags, from, fromlen)
#define sys_rresvport(port)					rresvport(port)
#define sys_sendto(s, msg, len, flags, to, tolen) \
		  sendto(s, msg, len, flags, to, tolen)
#endif

enum operator_t { none, eq, neq, ge, le, gt, lt, range };

struct compat_t {
	unsigned int	reuseaddr:1;		/* set SO_REUSEADDR?								*/
	unsigned int	sameport:1;			/* always try to use same port as client?	*/
	unsigned int	:0;
};


struct logtype_t {
	int				type;			/* type of logging (where to). 						*/
	FILE				**fpv;		/* if logging is to file, this is the open file.	*/
	int 				fpc;
	int				*fplockv;	/* locking of logfiles.									*/
};



/* extensions supported by us. */
struct extension_t {
	unsigned int 		bind:1;		/* use bind extension?							*/
	unsigned int			 :0;
};



/* the address part of a socks packet */
union socksaddr_t {
	struct in_addr ipv4;
	char 				ipv6[SOCKS_IPV6_ALEN];
  	char				domain[MAXHOSTNAMELEN]; /* _always_ stored as C string. */
}; 

/* the hostspecific part of misc. things */
struct sockshost_t {
	unsigned char 			atype;
	union socksaddr_t 	addr;
	in_port_t 				port;
};


struct request_t {
	unsigned char 			version; 
	unsigned char 			command;
	unsigned char 			flag; 
	struct sockshost_t	host;
	struct authmethod_t	*auth;	/* pointer to level above. */
};


struct response_t {
	unsigned char 			version; 
	unsigned char 			reply;
	unsigned char 			flag; 
	struct sockshost_t	host;
	struct authmethod_t	*auth;	/* pointer to level above. */
};

/* encapsulation for udp packets. */
struct udpheader_t {
	unsigned char 			flag[2];
	unsigned char 			frag;
	struct sockshost_t	host;
};


/* interface request packet. */
struct interfacerequest_t {
	unsigned char 			rsv;
	unsigned char 			sub;
	unsigned char 			flag;
	struct sockshost_t	host;
};


/* username */
struct uname_t {
	unsigned char	version;
	char				name[MAXNAMELEN];
	char				password[MAXPWLEN];
};


/* this must be big enough to hold a complete method request. */
struct authmethod_t {
	unsigned char 			method;
	union {
		struct uname_t		uname;
	} mdata;
};


struct method_t {
	unsigned int	none:1;
	unsigned int	uname:1;
	unsigned int	:0;
};


struct protocol_t {
	unsigned int	tcp:1;
	unsigned int	udp:1;
	unsigned int	:0;
};


struct command_t {
	unsigned int	bind:1;
	unsigned int	connect:1;
	unsigned int	udpassociate:1;

	/* not real commands as per standard, but they can have their use. */
	unsigned int	bindreply:1;		/* allow a reply to bind command.	*/
	unsigned int	:0;
};


struct version_t {
	unsigned int			v4:1;
	unsigned int			v5:1;
	unsigned int			:0;
};


struct serverstate_t {
	struct command_t			command;
	struct extension_t		extension;
	struct protocol_t			protocol;
	char							methodv[METHODS_MAX];	/* methods to offer.			*/
	unsigned	char				methodc;						/* number of methods set.	*/
	struct version_t			version;
};


struct gateway_t {
	struct sockshost_t			host;
	struct serverstate_t			state;
};


struct ruleaddress_t {
	char						atype;
	union {

		char					domain[MAXHOSTNAMELEN];
		
		struct {
			struct in_addr	ip;
			struct in_addr	mask;
		} ipv4;

	} addr;

	struct {
		in_port_t 			tcp;			/* tcp portstart or field to operator on.	*/
		in_port_t 			udp;			/* udp portstart or field to operator on.	*/
	} port;
	in_port_t 				portend;		/* only used if operator is range.			*/
	enum operator_t		operator;	/* operator to compare ports via.			*/
};

struct route_t {
	int							number;		/* routenumber.								*/

	struct {
		unsigned int			bad:1;		/* route is bad?								*/
		unsigned int			direct:1;	/* direct connection, no proxy.			*/
	} state;


	struct ruleaddress_t		src;
	struct ruleaddress_t		dst;
	struct gateway_t			gw;

	struct route_t				*next;		/* next route in list.						*/
};




struct socks_t {
	unsigned char 				version;
							/*
							 *	Negotiated version.  Each request and
							 *	response will also contain a version number, that is
							 *	the version number given for that particular packet
							 *	and should be checked to make sure it is the same as
							 * the negotiated version.
							 */

  	struct request_t 				req;
  	struct response_t 			res;
	struct authmethod_t			*auth;
	char 								*methodv;	/* pointer into gateway structure.	*/
	unsigned	char					*methodc;	/* pointer into gateway structure.	*/
};



enum portcmp { e_lt, e_gt, e_eq, e_neq, e_le, e_ge, e_nil };
typedef enum portcmp Portcmp;



/*
 * for use in generic functions that take either reply or request
 * packets, include a field indicating what it is.
*/
#define SOCKS_REQUEST 	0x1
#define SOCKS_RESPONSE	0x2



/* values in parentheses designate "don't care" values.	*/
struct socksstate_t {
	unsigned int			udpconnect:1;	/* connected udp socket?					*/
	unsigned int			system:1;		/* don't check, use system call.			*/
#ifdef SOCKS_TRYHARDER
	int						lock;				/* some calls require a lock.				*/
#endif
	int 						version;			/* version connection made under	(-1)	*/
	int						command;			/* command connection created with (-1)*/
	struct protocol_t		protocol;
	struct authmethod_t	auth;				/* authentication in use.					*/
	int 						inprogress;		/* connection in progress? (-1)		  	*/
	int						acceptpending;	/* a accept pending?		(-1)			*/
	pid_t						childpid;		/* pid of child if created	(0)		   */
};

struct socksfd_t {
	unsigned int			allocated:1;/* allocated?										*/
	int 						s;				/* tcp (control) connection to server.		*/
	struct socksstate_t 	state;		/* state of this connection.		 			*/
	struct sockaddr 		local;		/* our local address.							*/
	struct sockaddr 		server;		/* address of server we connected to.		*/
	struct sockaddr 		remote;		/* address server is using on our behalf.	*/
	struct sockaddr		reply;		/* address to expect reply from.				*/

	/* XXX union this. */
	struct sockaddr		accepted;	/* address server accepted for us.	 		*/
	struct sockaddr		connected;	/* address server connected to for us.		*/

	struct route_t 		*route;
};

__BEGIN_DECLS

/*
 * versions of BSD's error functions that log via slog() instead.
*/

#ifdef STDC_HEADERS
void serr(int eval, const char *fmt, ...);
#else
void serr();
#endif  /* STDC_HEADERS */

#ifdef STDC_HEADERS
void serrx(int eval, const char *fmt, ...);
#else
void serrx();
#endif  /* STDC_HEADERS */

#ifdef STDC_HEADERS
void swarn(const char *fmt, ...);
#else
void swarn();
#endif  /* STDC_HEADERS */

#ifdef STDC_HEADERS
void swarnx(const char *fmt, ...);
#else
void swarnx();
#endif  /* STDC_HEADERS */


struct udpheader_t *
sockaddr2udpheader __P((const struct sockaddr *to));
/*
 * Returns a udpheader representation of the "to" address.
 * Returns NULL on failure.
*/

char *
udpheader_add __P((const struct sockaddr *to, const char *msg, size_t *len));
/*
 * Prefixes the udpheader_t version of "to" to "msg", which is of 
 * length "len".
 * Upon return "len" gives the length of the returned "msg".
 *	Returns:
 *		On success: the new string.
 *		On failure: NULL.
*/

struct udpheader_t *
string2udpheader __P((const char *data, size_t len));
/*
 * Converts "data" to udpheader_t representation. 
 * "len" is length of "data". 
 * "data" is assumed to be in network order.
 * Returns:
 * 	On success: pointer to a udpheader_t in static memory.
 *		On failure: NULL ("data" is not a complete udppacket).
*/


const char *
socks_packet2string __P((const void *packet, int type));
/*
 * debug function; dumps socks packet content
 * "packet" is a socks packet, "type" indicates it's type.
 * Returns:
 * 	On success: 0
 *		On failure: -1
 */




int
fdisopen __P((int fd));
/*
 * returns 1 if the filedescriptor "fd" currently references a open object.
 * returns 0 otherwise.
*/

int
socks_logmatch(int d, const struct logtype_t *log);
/*
 * Returns true if "d" is a descriptor matching any descriptor in "log".
 * Returns false otherwise.
*/

char *
sockaddr2string __P((const struct sockaddr *address));
/*
 * Returns the ip address and port in "address" on string form.
 * "address" is assumed to be on network form and it will be
 * converted to host form before converted to string form.
 * The string is allocated statically and a subsequent call to the same
 * function will overwrite the old contents.
*/


struct sockaddr *
sockshost2sockaddr __P((const struct sockshost_t *shost));
/*
 * Returns a pointer to a statically allocated sockaddr structure containing
 * the address in "shost".
*/

struct sockshost_t *
sockaddr2sockshost __P((const struct sockaddr *addr));
/*
 * Returns pointer to statically allocated sockshost structure containing
 * the address "addr".
*/

struct sockshost_t *
ruleaddress2sockshost __P((const struct ruleaddress_t *address, int protocol));
/*
 * Returns a sockshost representation of "address", using protocol
 * "protocol".
 * Static memory.
*/

struct ruleaddress_t *
sockshost2ruleaddress __P((const struct sockshost_t *host));
/*
 * Returns a ruleaddress_t representation of "host".
 * Static memory.
*/

struct ruleaddress_t *
sockaddr2ruleaddress(const struct sockaddr *addr);
/*
 * Returns a ruleaddress_t representation of "addr" stored in static memory.
*/

int 
sockatmark __P((int s));
/* 
 * If "s" is at oob mark, return 1, otherwise 0.
 * Returns -1 if a error occurred.
*/

ssize_t
recvmsgn __P((int s, struct msghdr *msg, int flags, size_t len));
/*
 * Like recvmsg(), but tries to read until "len" has been read.
 * BUGS:
 *   Assumes msg->msg_iov[n] are laid out next to each others.
*/

ssize_t
readn __P((int, void *, size_t));
/*
 * Like read() but retries. 
*/

ssize_t
writen __P((int, const void *, size_t));
/*
 * like write() but retries.
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
acceptn __P((int, struct sockaddr *, int *));
/*
 * Wrapper around accept().  Retries on EINTR.
*/


char *
sockshost2string __P((const struct sockshost_t *host));
/*
 * Converts the address in "host" to a string.
 * Returns a pointer to statically allocated memory containing the
 * address.  The memory will be overwritten on the next call to this
 * function.
*/

struct sockaddr *
sockspacket2sockaddr __P((const struct sockshost_t *packet));
/*
 * converts the sockspacket "packet" to a sockaddr structure.
 * Returns a pointer to static memory holding the converted sockaddr
 * structure, valid until the next time this function is called.
*/

const char *
strcheck __P((const char *string));
/* 
 * Checks "string".  If it is NULL, returns a string indicating memory
 * exhausted, if not, returns the same string it was passed.
*/

const char *
command2string __P((int command));
/*
 * Returns a printable representation of the socks command "command". 
*/

const char *
method2string __P((int method));
/*
 * Returns a printable representation of the authmethod "method".
*/



char *
sockshost2mem __P((const struct sockshost_t *host, char *mem, int version));
/*
 * Writes "host" out to "mem".  The caller must make sure "mem"
 * is big enough to hold the contents of "host".
 * "version" gives the socks version "host" is to be written out in.
 * Returns a pointer to one element past the last byte written to "mem".
*/

const char *
mem2sockshost __P((struct sockshost_t *host, const char *mem, size_t len,
						 int version));
/*
 * Writes "mem", which is assumed to be a sockshost string 
 * of version "version" in network order, out to "host".
 * Returns:
 *		On success: pointer to one element past last byte used of mem
 *						and fills in "host" appropriately.
 *		On failure: NULL ("mem" is not a valid sockshost.)
*/
#ifdef STDC_HEADERS
void slog(int priority, const char *message, ...);
#else
void slog();
#endif  /* STDC_HEADERS */
/*
 * Logs message "message" at priority "priority" to previously configured
 * outputdevice.
 * Checks settings and ignores message if it's of to low a priority.
*/

void vslog __P((int priority, const char *message, va_list ap));
/*
 * Same as slog() but assumes varargs/stdargs have already processed 
 * the arguments.
*/

int
readconfig __P((FILE *fp));
/*
 * Parses the config in the open file "fp" from current offset.
 * Returns:
 *		On success: 0.
 *		On failure: -1.  If failure is in config, function exits.
*/


int
addressmatch __P((const struct ruleaddress_t *rule, 
			 			const struct sockshost_t *address, int protocol, int
			 			ipalias));
/*
 * Tries to match "address" against "rule".  "address" is resolved
 * if necessary.  "address" supports the wildcard INADDR_ANY and port of 0.
 * "protocol" is the protocol to compare under.
 * If "ipalias" is true, the function will try to match any ip alias
 * "address"'s might have if appropriate, this can be useful to match
 * multihomed hosts where the client requests e.g a bind connection.
 * Returns true if "rule" matched "address". 

*/


int
socks_connect __P((int s, const struct sockshost_t *host));
/*
 * Tries to connect to "host".  If "host"'s address is not a ip address,
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
 * If any of the arguments is NULL, that argument is ignored.
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
 *		On failure: NULL.  If errno is 0, the reason for failure was
 *   					that no route was found.
*/



void
showstate __P((const struct serverstate_t *state));
/*
 * Shows "state".
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
 * If any of the arguments is NULL, that argument is ignored.
 *
 * The route used may take into account the contents of "req", which is
 * assumed to be the packet that will be sent to a socksserver, so it is
 * recommended that it's contents be as conservative as possible.
 *
 * Returns:
 *		On success: pointer to a serverentry
 *		On failure: NULL
*/

const char *
ruleaddress2string __P((const struct ruleaddress_t *rule));
/*
 * Returns "rule" as a printable static string.
*/


int
sockscode __P((int version, int code));
/*
 * Maps the socks replycode "code", which is in non-version specific format,
 * to the equivalent replycode in version "version".
*/

int
errno2reply __P((int errnum, int version));
/*
 * Returns the socks version "version" reply code for a error of type "errno".
*/

enum operator_t
string2operator __P((const char *operator));
/*
 * Returns the enum for the string representation of a operator.
*/

const char *
operator2string __P((enum operator_t operator));
/*
 * Returns the string representation of the operator.
*/

char *
str2vis(const char *string, size_t len);
/* 
 * Visually encodes exactly "len" chars of "string".
 * Returns:
 *		On success: the visually encoded string, to be free()'ed by caller.
 * 	On failure: NULL.  (out of memory).
*/

in_addr_t
socks_addfakeip __P((const char *name));
/*
 * Adds "name" to a internal table indexed by (fake)ip addresses.
 * Returns:
 *		On success: "name"'s index.
 *		On failure:	INADDR_NONE
*/

const char *
socks_getfakeip __P((in_addr_t ip));
/*
 * If "ip" is a "fake" (non-resolved) ip, it returns the name
 * corresponding to it.
 * Else, NULL is returned.
*/


int
sockaddrcmp __P((const struct sockaddr *a, const struct sockaddr *b));
/*
 * Compares the address in "a" against "b", returning 0 if they are
 * identical, something else otherwise.
*/

fd_set *
fdsetop(int nfds, const fd_set *a, const fd_set *b, int op);
/*
 * Performs operation on descriptor sets.
 * "nfds" is the number of descriptors to perform "op" on in the sets
 * "a" and "b".
 * "op" is the operation to be performed on the descriptor sets and
 * can take on the value of standard C bitwise operators. 
 * Returns a pointer to the set that is the result of doing "a" "op" "b".
 * The memory used is static.
 * BUGS:
 * 	Only operator currently supported is XOR ('^').
*/

int
methodisset(int method, const char *methodv, size_t methodc);
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
 *		On success: the descriptor for the new socket
 *		On failure: -1
*/

int 
socks_mklock(const char *template);
/*
 * Creates a filedescriptor that can be used with socks_lock() and
 * socks_unlock().
 * Returns:
 *		On success: filedescriptor
 *		On failure: -1
*/

int
socks_lock(int fd, int type, int timeout);
/*
 * Looks the filedescriptor "fd".
 * "type" is the type of lock; F_RDLCK or F_WRLCK.
 * "timeout" is how long to wait for lock, a negative value means forever.
 * Returns:
 *		On success: 0
 *		On error  : -1
*/

int 
socks_unlock(int fd, int timeout);
/*
 * Unlocks the filedescriptor "fd".
 * "timeout" is how long to wait for successful unlock.
 * Returns:
 *		On success: 0
 *		On error  : -1
*/ 


#if defined(DEBUG) || defined(HAVE_SOLARIS_BUGS)

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

#ifndef HAVE_VWARNX
void vwarnx __P((const char *, va_list ap));
#endif  /* !HAVE_VWARNX */

#ifndef HAVE_DAEMON
int daemon __P((int, int));
#endif  /* !HAVE_DAEMON */

#ifndef HAVE_GETDTABLESIZE
/* return upper limit on per-process open file descriptors */
int getdtablesize __P((void));
#endif  /* !HAVE_GETDTABLESIZE */

#ifndef HAVE_SNPRINTF
# ifdef STDC_HEADERS
int snprintf __P((char *, size_t, char const *, ...));
# else
int snprintf ();
# endif /* STDC_HEADERS */
int vsnprintf __P((char *, size_t, const char *, char *));
#endif /* !HAVE_SNPRINTF */

#ifndef HAVE_SETPROCTITLE
#ifdef STDC_HEADERS
void setproctitle(const char *fmt, ...);
#else
void setproctitle();
#endif  /* STDC_HEADERS */
#endif  /* !HAVE_SETPROCTITLE */

#ifndef HAVE_SOCKATMARK
int sockatmark __P((int));
#endif  /* !HAVE_SOCKATMARK */

#ifndef HAVE_ATON
int inet_aton __P((register const char *cp, struct in_addr *addr));
#endif  /* ! HAVE_ATON */

#ifndef HAVE_GETDTABLESIZE
int getdtablesize __P((void));
#endif  /* ! HAVE_GETDTABLESIZE */

#ifdef HAVE_FEEBLE_DESCRIPTOR_PASSING
int sockd_write_fd __P((int fd,	int sendfd));
int sockd_read_fd __P((int fd));
#endif  /* HAVE_FEEBLE_DESCRIPTOR_PASSING */

#ifndef HAVE_STRERROR
char *__strerror __P((int, char *));
char *strerror __P((int));
const char *hstrerror __P((int));
#endif  /* !HAVE_STRERROR */

#ifndef HAVE_MEMMOVE
void * memmove __P((void *, const void *, register size_t));
#endif  /* !HAVE_MEMMOVE */

#ifndef HAVE_INET_PTON
int inet_pton __P((int af, const char *src, void *dst));
#endif

__END_DECLS

/* XXX */
#ifdef SOCKS_CLIENT
#include "socks.h"
#else
#include "sockd.h"
#endif  /* SOCKS_CLIENT */
