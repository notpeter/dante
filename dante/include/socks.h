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

/* $Id: socks.h,v 1.171 2005/10/11 10:53:19 michaels Exp $ */

#ifndef _SOCKS_H_
#define _SOCKS_H_
#endif  /* ! _SOCKS_H_ */

#ifdef lint
extern const int lintnoloop_socks_h;
#else
#define lintnoloop_socks_h 0
#endif

#ifndef HAVE_OSF_OLDSTYLE
#define HAVE_OSF_OLDSTYLE 0
#endif  /* !HAVE_OSF_OLDSTYLE */

#if SOCKSLIBRARY_DYNAMIC

#ifdef accept
#undef accept
#endif  /* accept */
#if HAVE_EXTRA_OSF_SYMBOLS
#define accept(s, addr, addrlen)			sys_Eaccept(s, addr, addrlen)
#else
#define accept(s, addr, addrlen)			sys_accept(s, addr, addrlen)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#ifdef bind
#undef bind
#endif  /* bind */
#define bind(s, name, namelen)			sys_bind(s, name, namelen)

#ifdef bindresvport
#undef bindresvport
#endif  /* bindresvport */
#define bindresvport(sd, sin)				sys_bindresvport(sd, sin)

#ifdef connect
#undef connect
#endif  /* connect */
#define connect(s, name, namelen)		sys_connect(s, name, namelen)

#ifdef gethostbyname
#undef gethostbyname
#endif  /* gethostbyname */
#if HAVE_GETHOSTBYNAME2
/*
 * a little tricky ... we need it to be at the bottom of the stack,
 * like a syscall.
*/
#define gethostbyname(name)				sys_gethostbyname2(name, AF_INET)
#else
#define gethostbyname(name)				sys_gethostbyname(name)
#endif

#ifdef gethostbyname2
#undef gethostbyname2
#endif  /* gethostbyname2 */
#define gethostbyname2(name, af)			sys_gethostbyname2(name, af)

#ifdef getaddrinfo
#undef getaddrinfo
#endif /* getaddrinfo */
#define getaddrinfo(nodename, servname, hints, res)	\
			sys_getaddrinfo(nodename, servname, hints, res)

#ifdef getipnodebyname
#undef getipnodebyname
#endif /* getipnodebyname */
#define getipnodebyname(name, af, flags, error_num)	\
			sys_getipnodebyname(name, af, flags, error_num)

#ifdef freehostent
#undef freehostent
#endif  /* freehostent */
#define freehostent(ptr)				sys_freehostent(ptr)

#ifdef getpeername
#undef getpeername
#endif  /* getpeername */
#if HAVE_EXTRA_OSF_SYMBOLS
#define getpeername(s, name, namelen)	sys_Egetpeername(s, name, namelen)
#else
#define getpeername(s, name, namelen)	sys_getpeername(s, name, namelen)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#ifdef getsockname
#undef getsockname
#endif  /* getsockname */
#if HAVE_EXTRA_OSF_SYMBOLS
#define getsockname(s, name, namelen)	sys_Egetsockname(s, name, namelen)
#else
#define getsockname(s, name, namelen)	sys_getsockname(s, name, namelen)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#ifdef read
#undef read
#endif  /* read */
#define read(d, buf, nbytes)				sys_read(d, buf, nbytes)

#ifdef readv
#undef readv
#endif  /* readv */
#if HAVE_EXTRA_OSF_SYMBOLS
#define readv(d, iov, iovcnt)				sys_Ereadv(d, iov, iovcnt)
#else
#define readv(d, iov, iovcnt)				sys_readv(d, iov, iovcnt)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#ifdef recv
#undef recv
#endif  /* recv */
#define recv(s, msg, len, flags)			sys_recv(s, msg, len, flags)

#ifdef recvfrom
#undef recvfrom
#endif  /* recvfrom */
#if HAVE_EXTRA_OSF_SYMBOLS
#define recvfrom(s, buf, len, flags, from, fromlen)	\
		  sys_Erecvfrom(s, buf, len, flags, from, fromlen)
#else
#define recvfrom(s, buf, len, flags, from, fromlen)	\
		  sys_recvfrom(s, buf, len, flags, from, fromlen)

#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#ifdef rresvport
#undef rresvport
#endif  /* rresvport */
#define rresvport(port)						sys_rresvport(port)

#ifdef sendto
#undef sendto
#endif  /* sendto */
#define sendto(s, msg, len, flags, to, tolen)	\
		  sys_sendto(s, msg, len, flags, to, tolen)

#ifdef write
#undef write
#endif  /* write */
#define write(d, buf, nbytes)				sys_write(d, buf, nbytes)

#ifdef writev
#undef writev
#endif  /* writev */
#if HAVE_EXTRA_OSF_SYMBOLS
#define writev(d, iov, iovcnt)			sys_Ewritev(d, iov, iovcnt)
#else
#define writev(d, iov, iovcnt)			sys_writev(d, iov, iovcnt)
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#ifdef send
#undef send
#endif  /* send */
#define send(s, msg, len, flags)			sys_send(s, msg, len, flags)

#endif /* SOCKSLIBRARY_DYNAMIC */

struct configstate_t {
	unsigned				init:1;
	unsigned				:0;
	struct sockaddr	lastconnect;		/* address we last connected to.		*/
	pid_t					pid;
	unsigned				:0;
};

struct option_t {
	int					debug;
	char					*configfile;	/* name of current configfile.				*/
	unsigned				:0;
};



struct config_t {
	pid_t								connectchild;				/* connect process.		*/
	int								connect_s;					/* socket to child.		*/
	char								domain[MAXHOSTNAMELEN]; /* localdomain.			*/
	struct logtype_t				log;							/* where to log.			*/
	struct option_t				option;						/* misc. options.			*/
	struct configstate_t			state;
	int								resolveprotocol;			/* resolveprotocol.		*/
	struct route_t					*route;						/* linked list of routes*/
};

struct childpacket_t {
	int						s;				/* filedescriptor number.						*/
   struct sockshost_t   src;			/* local address of control-connection. 	*/
   struct sockshost_t   dst;			/* remote address of control-connection. 	*/
   struct socks_t       packet;		/* socks packet exchanged with server.		*/
};


__BEGIN_DECLS

/*
 * libsocks function declarations
 */

void
clientinit __P((void));
/*
 * initialises clientstate, reads configfile, etc.
 */


#if !HAVE_OSF_OLDSTYLE
int Raccept __P((int, struct sockaddr *, socklen_t *));
int Rconnect __P((int, const struct sockaddr *, socklen_t));
int Rgetsockname __P((int, struct sockaddr *, socklen_t *));
int Rgetpeername __P((int, struct sockaddr *, socklen_t *));
ssize_t Rsendto __P((int s, const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen));
ssize_t Rrecvfrom __P((int s, void *buf, size_t len, int flags, struct sockaddr * from, socklen_t *fromlen));
ssize_t Rsendmsg __P((int s, const struct msghdr *msg, int flags));
ssize_t Rrecvmsg __P((int s, struct msghdr *msg, int flags));
int Rbind __P((int, const struct sockaddr *, socklen_t));
#endif  /* !HAVE_OSF_OLDSTYLE */

int Rbindresvport __P((int, struct sockaddr_in *));
int Rrresvport __P((int *));
struct hostent *Rgethostbyname __P((const char *));
struct hostent *Rgethostbyname2 __P((const char *, int af));
#if HAVE_GETADDRINFO
int Rgetaddrinfo __P((const char *nodename, const char *servname,
		      		const struct addrinfo *hints, struct addrinfo **res));
#endif /* HAVE_GETADDRINFO */
#if HAVE_GETIPNODEBYNAME
struct hostent *Rgetipnodebyname __P((const char *, int, int, int *));
void Rfreehostent __P((struct hostent *));
#endif /* HAVE_GETIPNODEBYNAME */
ssize_t Rwrite __P((int d, const void *buf, size_t nbytes));
ssize_t Rwritev __P((int d, const struct iovec *iov, int iovcnt));
ssize_t Rsend __P((int s, const void *msg, size_t len, int flags));
ssize_t Rread __P((int d, void *buf, size_t nbytes));
ssize_t Rreadv __P((int d, const struct iovec *iov, int iovcnt));
ssize_t Rrecv __P((int s, void *msg, size_t len, int flags));

int SOCKSinit __P((char *));
int Rlisten __P((int, int));
int Rselect __P((int, fd_set *, fd_set *, fd_set *, struct timeval *));
/*
 * unused functions needed to compile programs with support for other
 * socks implementations.
 */


int
udpsetup __P((int s, const struct sockaddr *to, int type));
/*
 * sets up udp relaying between address of "s" and "to" by connecting
 * to socksserver.
 * If relaying is already set up the function returns with success.
 * Type is the type of connection setup, SOCKS_SEND or SOCKS_RECV.
 * At the moment only SOCKS_SEND is supported.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */



int
socks_sendrequest __P((int s, const struct request_t *request));
/*
 * Sends the request "request" to the socksserver connected to "s".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

int
socks_recvresponse __P((int s, struct response_t *response, int version));
/*
 * Receives a socks response from the "s".  "response" is filled in with
 * the data received.
 * "version" is the protocolversion negotiated.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */


	/*
	 *  Misc. functions to help keep track of our connection(s) to the server.
	 */

struct socksfd_t *
socks_addaddr __P((unsigned int clientfd, struct socksfd_t *socksaddress));
/*
 * "clientfd" is associated with the structure "socksfd".
 * The function duplicates all arguments in it's own form and does
 * not access the memory referenced by them afterwards.
 *
 * The function checks the state of all filedescriptors on each call and
 * removes those that are no longer open.
 *
 * Returns:
 *		On success: pointer to the added socksfd_t structure.
 *		On failure: exits.  (memory exhausted and process grew descriptor size.)
 *
 */

struct socksfd_t *
socks_getaddr __P((unsigned int fd));
/*
 * Returns:
 *		On success:  the socketaddress associated with filedescriptor "fd".
 *		On failure:	 NULL.  (no socketaddress associated with "fd").
 */


void
socks_rmaddr __P((unsigned int s));
/*
 * removes the association for the socket "s", also closes the server
 * connection.  If "s" is not registered the request is ignored.
 */

struct socksfd_t *
socksfddup __P((const struct socksfd_t *old, struct socksfd_t *new));
/*
 * Duplicates "old", in "new".
 * Returns:
 *		On success: "new".
 *		On failure: NULL (resource shortage).
 */


int
socks_addrcontrol __P((const struct sockaddr *local,
							  const struct sockaddr *remote));
/*
 * Goes through all addresses registered and tries to find one where
 * the control socket has a local address of "local" and peer address
 * of "remote".  If either of "local" or "remote" is NULL, that
 * endpoint is not checked against.
 *	Returns:
 *		On success: the descriptor the socksfd struct was registered with.
 *		On failure: -1
 */

int
socks_addrmatch __P((const struct sockaddr *local,
							const struct sockaddr *remote,
							const struct socksstate_t *state));
/*
 * Goes through all addresses registered and tries to find one where
 * all arguments match.
 * Arguments that are NULL or have "illegal" values are ignored.
 * Returns:
 *		On success: the descriptor the socksfd with matching arguments was
 *                registered with (>= 0).
 *		On failure: -1.
 */


int
socks_isaddr __P((unsigned int fd));
/*
 * Returns true if there is a address registered for the socket "fd", false
 * otherwise.
 */


int
socks_addrisok __P((unsigned int s));
/*
 * Compares the current address of "s" to the registered address.
 * If there is a mismatch, the function will try to correct it if possible.
 * Returns:
 *		If current address found to match registered: true.
 *		Else: false.
 */

int
socks_addfd __P((unsigned int fd));
/*
 * adds the filedescriptor "fd" to an internal table.
 * If it is already in the table the  request is ignored.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

int
socks_isfd __P((unsigned int fd));
/*
 * returns 1 if "fd" is a filedescriptor in our internal table, 0 if not.
 */

void
socks_rmfd __P((unsigned int fd));
/*
 * removes the filedescriptor "fd" from our internal table.
 */


int
fdisopen __P((int fd));
/*
 * returns 1 if the filedescriptor "fd" currently references a open object.
 * returns 0 otherwise.
 */


char *
socks_getusername __P((const struct sockshost_t *host, char *buf,
							  size_t buflen));
/*
 * Tries to determine the username of the current user, to be used
 * when negotiating with the server "host".
 * The NUL-terminated username is written to "buf", which is of size
 * "buflen".
 * Returns:
 *		On success: pointer to "buf" with the username.
 *		On failure: NULL.
 */

char *
socks_getpassword __P((const struct sockshost_t *host, const char *user,
							  char *buf, size_t buflen));
/*
 * Tries to determine the password of user "user", to be used
 * when negotiating with the server "host".
 * The NUL-terminated password is written to "buf", which is of length
 * "buflen"
 * Returns:
 *		On success: pointer to "buf" with the password.
 *		On failure: NULL.
 */

#if DIAGNOSTIC
void
cc_socksfdv(int sig);
/*
 * consistencycheck on socksfdv.
 */
#endif


#if SOCKSLIBRARY_DYNAMIC

int sys_rresvport __P((int *));
int sys_bindresvport __P((int, struct sockaddr_in *));
void sys_freehostent __P((struct hostent *));

HAVE_PROT_READ_0 sys_read
__P((HAVE_PROT_READ_1, HAVE_PROT_READ_2, HAVE_PROT_READ_3));
HAVE_PROT_READV_0 sys_readv
__P((HAVE_PROT_READV_1, HAVE_PROT_READV_2, HAVE_PROT_READV_3));
HAVE_PROT_RECV_0 sys_recv
__P((HAVE_PROT_RECV_1, HAVE_PROT_RECV_2, HAVE_PROT_RECV_3, HAVE_PROT_RECV_4));
HAVE_PROT_RECVMSG_0 sys_recvmsg
__P((HAVE_PROT_RECVMSG_1, HAVE_PROT_RECVMSG_2, HAVE_PROT_RECVMSG_3));
HAVE_PROT_SEND_0 sys_send
__P((HAVE_PROT_SEND_1 , HAVE_PROT_SEND_2, HAVE_PROT_SEND_3, HAVE_PROT_SEND_4));
HAVE_PROT_WRITE_0 sys_write
__P((HAVE_PROT_WRITE_1, HAVE_PROT_WRITE_2, HAVE_PROT_WRITE_3));

#if HAVE_OSF_OLDSTYLE
int sys_accept __P((int, struct sockaddr *, int *));
#else
HAVE_PROT_ACCEPT_0 sys_accept
__P((HAVE_PROT_ACCEPT_1, HAVE_PROT_ACCEPT_2, HAVE_PROT_ACCEPT_3));
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#if HAVE_OSF_OLDSTYLE
int sys_bind __P((int, const struct sockaddr *, int));
#else
HAVE_PROT_BIND_0 sys_bind
__P((HAVE_PROT_BIND_1, HAVE_PROT_BIND_2, HAVE_PROT_BIND_3));
#endif /* !HAVE_OSF_OLDSTYLE */

#if HAVE_OSF_OLDSTYLE
int sys_connect __P((int, const struct sockaddr *, int));
#else
HAVE_PROT_CONNECT_0 sys_connect
__P((HAVE_PROT_CONNECT_1, HAVE_PROT_CONNECT_2, HAVE_PROT_CONNECT_3));
#endif  /* HAVE_OSF_OLDSTYLE */

#if HAVE_OSF_OLDSTYLE
int sys_getpeername __P((int, struct sockaddr *, int *));
#else
HAVE_PROT_GETPEERNAME_0 sys_getpeername
__P((HAVE_PROT_GETPEERNAME_1, HAVE_PROT_GETPEERNAME_2, HAVE_PROT_GETPEERNAME_3));
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#if HAVE_OSF_OLDSTYLE
int sys_getsockname __P((int, struct sockaddr *, int *));
#else
HAVE_PROT_GETSOCKNAME_0 sys_getsockname
__P((HAVE_PROT_GETSOCKNAME_1, HAVE_PROT_GETSOCKNAME_2, HAVE_PROT_GETSOCKNAME_3));
#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#if HAVE_OSF_OLDSTYLE
int sys_recvfrom __P((int, void*, int, int, struct sockaddr *, int *));
#else
HAVE_PROT_RECVFROM_0 sys_recvfrom
__P((HAVE_PROT_RECVFROM_1, HAVE_PROT_RECVFROM_2, HAVE_PROT_RECVFROM_3, HAVE_PROT_RECVFROM_4, HAVE_PROT_RECVFROM_5, HAVE_PROT_RECVFROM_6));
#endif

#if HAVE_OSF_OLDSTYLE
ssize_t sys_writev __P((int, const struct iovec *, int));
#else
HAVE_PROT_WRITEV_0 sys_writev
__P((HAVE_PROT_WRITEV_1, HAVE_PROT_WRITEV_2, HAVE_PROT_WRITEV_3));
#endif

#if HAVE_OSF_OLDSTYLE
ssize_t sys_sendmsg __P((int, struct msghdr *, int));
#else
HAVE_PROT_SENDMSG_0 sys_sendmsg
__P((HAVE_PROT_SENDMSG_1, HAVE_PROT_SENDMSG_2, HAVE_PROT_SENDMSG_3));
#endif

#if HAVE_OSF_OLDSTYLE
int sys_sendto __P((int, const void *, int, int, const struct sockaddr *, socklen_t));
#else
HAVE_PROT_SENDTO_0 sys_sendto
__P((HAVE_PROT_SENDTO_1, HAVE_PROT_SENDTO_2, HAVE_PROT_SENDTO_3, HAVE_PROT_SENDTO_4, HAVE_PROT_SENDTO_5, HAVE_PROT_SENDTO_6));
#endif /* !HAVE_OSF_OLDSTYLE */

#if HAVE_EXTRA_OSF_SYMBOLS
int sys_Eaccept __P((int, struct sockaddr *, socklen_t *));
int sys_Egetpeername __P((int, struct sockaddr *, socklen_t *));
int sys_Egetsockname __P((int, struct sockaddr *, socklen_t *));
ssize_t sys_Ereadv __P((int, const struct iovec *, int));
int sys_Erecvfrom __P((int, void *, size_t, int, struct sockaddr *, size_t *));
ssize_t sys_Erecvmsg __P((int, struct msghdr *, int));
ssize_t sys_Esendmsg __P((int, const struct msghdr *, int));
ssize_t sys_Ewritev __P((int, const struct iovec *, int));

int sys_naccept __P((int, struct sockaddr *, socklen_t *));
int sys_ngetpeername __P((int, struct sockaddr *, socklen_t *));
int sys_ngetsockname __P((int, struct sockaddr *, socklen_t *));
int sys_nrecvfrom __P((int, void *, size_t, int, struct sockaddr *, size_t *));
ssize_t sys_nrecvmsg __P((int, struct msghdr *, int));
ssize_t sys_nsendmsg __P((int, const struct msghdr *, int));

#endif  /* HAVE_EXTRA_OSF_SYMBOLS */

#endif /* SOCKSLIBRARY_DYNAMIC */

__END_DECLS
