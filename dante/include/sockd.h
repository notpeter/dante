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

/* $Id: sockd.h,v 1.215 2005/11/08 15:57:48 michaels Exp $ */

#ifndef _SOCKD_H_
#define _SOCKD_H_
#endif

#ifdef lint
extern const int lintnoloop_sockd_h;
#else
#define lintnoloop_sockd_h 0
#endif

/* use caching versions directly, avoid overhead. */
#undef gethostbyname
#define gethostbyname(name)				cgethostbyname(name)
#undef gethostbyaddr
#define gethostbyaddr(addr, len, type)	cgethostbyaddr(addr, len, type)


#define INIT(length)									\
	const size_t start	= state->start;		\
	const size_t end		= start + (length);	\
	errno = 0

#define MEMLEFT()		(sizeof(state->mem) - state->reqread)

#define LEFT()	((end) - state->reqread)
/*
 * Returns the number of bytes left to read.
 */

#define READ(s, length, auth)	\
	(readn((s), &state->mem[state->reqread], (length), auth))
/*
 * "s" is the descriptor to read from.
 * "length" is how much to read.
 * Returns the number of bytes read, -1 on error.
 */



#define OBJECTFILL(object)	memcpy((object), &state->mem[start], end - start)
/*
 * Fills "object" with data.
 */

#define CHECK(object, auth, nextfunction)							\
do {																			\
	int p;																	\
																				\
	if (LEFT()) {															\
																				\
		SASSERT(LEFT() > 0);												\
																				\
		if (LEFT() > MEMLEFT())											\
			SERRX(MEMLEFT());												\
																				\
		errno = 0;															\
		if ((p = READ(s, LEFT(), auth)) <= 0)						\
			return p;														\
		state->reqread += p;												\
																				\
		if (LEFT()) { /* read something, but not all. */		\
			errno = EWOULDBLOCK;											\
			return -1;														\
		}																		\
																				\
		state->start = end;												\
		OBJECTFILL((object));											\
		state->rcurrent = nextfunction;								\
																				\
		if (state->rcurrent != NULL)									\
			return state->rcurrent(s, request, state);			\
	}																			\
} while (lintnoloop_sockd_h)
/*
 * Checks whether "object" has been filled with all data requested and
 * if so calls "function", if function is not NULL.
 * If "object" has not been filled it returns the number of bytes
 * that was added to object on this call, or error.
*/

#define SOCKD_NEWREQUEST	1	/* sending a new request	*/
#define SOCKD_FREESLOT		2	/* free'd a slot.				*/


/* a requestchild can currently only handle a maximum of one client. */
#define SOCKD_REQUESTMAX	1


/* IO stuff. */
#define IO_SRCBLOCK			-4
#define IO_ERRORUNKNOWN		-3
#define IO_TIMEOUT			-2
#define IO_ERROR				-1
#define IO_CLOSE				0

/* types of children. */
#define CHILD_MOTHER			1
#define CHILD_IO				2
#define CHILD_NEGOTIATE		3
#define CHILD_REQUEST		4

#define FDPASS_MAX			3	/* max number of descriptors we send/receive. */


	/*
	 * config stuff
	 */

#define VERDICT_BLOCKs		"block"
#define VERDICT_PASSs		"pass"

/* how to rotate addresses. */
#define ROTATION_NONE		0
#define ROTATION_ROUTE		1

#define LOG_CONNECTs			"connect"
#define LOG_DISCONNECTs		"disconnect"
#define LOG_DATAs				"data"
#define LOG_ERRORs			"error"
#define LOG_IOOPERATIONs	"iooperation"


#define OPERATION_ACCEPT		1
#define OPERATION_CONNECT		(OPERATION_ACCEPT + 1)
#define OPERATION_IO				(OPERATION_CONNECT + 1)
#define OPERATION_ABORT			(OPERATION_IO + 1)
#define OPERATION_ERROR			(OPERATION_ABORT + 1)

#define DENY_SESSIONLIMITs		"session-limit reached"


struct compat_t {
	unsigned reuseaddr:1;				/* set SO_REUSEADDR?								*/
	unsigned sameport:1;					/* always try to use same port as client?	*/
	unsigned :0;
};


struct log_t {
	unsigned connect:1;
	unsigned disconnect:1;
	unsigned data:1;
	unsigned error:1;
	unsigned iooperation:1;
	unsigned :0;
};


struct timeout_t {
	time_t			negotiate;	/* how long negotiation can last.					*/
	time_t			io;			/* how long connection lasts without i/o.			*/
};


struct linkedname_t {
	char						*name;
	struct linkedname_t	*next;	/* next name in list.								*/
};

typedef struct {
	int					clients;				/* clients using this object.			*/
	unsigned 			expired:1;			/* the rule has expired.				*/
	unsigned 			isclientrule:1;	/* is used by clientrule.				*/
	int					number;				/* rule number using this.				*/
} shmem_header_t;

typedef struct {
	struct timeval			time;					/* time of last i/o operation.		*/
	long						bytes;				/* amount of bytes done at time.		*/
	long						maxbps;				/* maximal b/s allowed.					*/
} bw_t;

typedef struct {
	int						maxsessions;		/* max number of sessions allowed.	*/
} session_t;
	
typedef struct {
	shmem_header_t			mstate;
	union {
		bw_t					bw;
		session_t			session;
	} object;
} shmem_object_t;


	

/* linked list over current rules. */
struct rule_t {
	struct ruleaddress_t		src;				/* src.										*/
	struct ruleaddress_t		dst;				/* dst.										*/
	struct log_t				log;				/* type of logging to do.				*/
	int							number;			/* rulenumber.								*/
	unsigned long				linenumber;		/* linenumber; info/debugging only.	*/
	struct serverstate_t		state;
	struct linkedname_t		*user;			/* name of users allowed.				*/
	int							verdict;			/* verdict for this rule.				*/

#if HAVE_LIBWRAP
	char							libwrap[LIBWRAPBUF];	/* libwrapline.					*/
#endif  /* HAVE_LIBWRAP */

#if HAVE_PAM
	char							pamservicename[MAXNAMELEN];/* name for pamservice.	*/
#endif /* HAVE_PAM */

	struct ruleaddress_t		rdr_from;
	struct ruleaddress_t		rdr_to;

	bw_t							*bw;				/* pointer since will be shared.		*/
	session_t					*ss;				/* pointer since will be shared.		*/

	struct rule_t				*next;			/* next rule in list.					*/
};

struct srchost_t {
	unsigned nomismatch:1;	/* deny mismatch between claim and fact?				*/
	unsigned nounknown:1;	/* deny no fact?												*/
	unsigned :0;
};

struct option_t {
	char					*configfile;	/* name of configfile.							*/
	unsigned				daemon:1;		/* run as a daemon?								*/
	int					debug;			/* debug level.									*/
	unsigned				keepalive:1;	/* set SO_KEEPALIVE?								*/
	int					sleep;			/* sleep at misc. places. (debugging)		*/
	int					serverc;			/* number of servers.							*/
};


struct userid_t {
	uid_t				privileged;
	unsigned			privileged_isset:1;
	uid_t				unprivileged;
	unsigned			unprivileged_isset:1;
	uid_t				libwrap;
	unsigned			libwrap_isset:1;
};

struct configstate_t {
	unsigned						init:1;

#if HAVE_PAM
	/*
	 * allows us to optimize a few things a little based on configuration.
	 * If it is not NULL, it means we are using a fixed pam servicename,
	 * otherwise, the servicename varies, and we have to set it on a
	 * rule-by-rule basis
	 */

	const char 					*pamservicename;		/* have rules with pamdata.	*/
#endif 

	uid_t							euid;						/* original euid.					*/
	pid_t							*motherpidv;			/* pid of mothers.				*/
	pid_t							pid;						/* pid of current process.		*/
	int							type;						/* process type we are.			*/
};

struct listenaddress_t {
	struct sockaddr		addr;							/* bound address.					*/
	int						s;								/* bound socket.					*/
#if NEED_ACCEPTLOCK
	int						lock;							/* lock on structure.			*/
#endif
};

struct externaladdress_t {
	struct ruleaddress_t			*addrv;				/*	address'.						*/
	int								addrc;
	int								rotation;			/* how to rotate, if at all.	*/
};

struct statistic_t {
	time_t						boot;						/* time of serverstart.			*/

	size_t						accepted;				/* connections accepted.		*/

	struct {
		size_t					sendt;					/* clients sent to children.	*/
		size_t					received;				/* clients received back.		*/
	} negotiate;

	struct {
		size_t					sendt;					/* clients sent to children.	*/
		size_t					received;				/* clients received back.		*/
	} request;

	struct {
		size_t					sendt;					/* clients sent to children.	*/
	} io;
};

struct childstate_t {
#ifdef HAVE_VOLATILE_SIG_ATOMIC_T
	sig_atomic_t				addchild;				/* okay to do a addchild()?	*/
#else
	volatile sig_atomic_t   addchild;            /* okay to do a addchild()?   */
#endif
	
	int							maxidle;					/* how many can be idle.		*/
};


/* Make sure to keep in sync with resetconfig(). */
struct config_t {
	struct listenaddress_t		*internalv;				/* internal address'.		*/
	int								internalc;

	struct externaladdress_t	external;				/*	external address'.		*/

	struct rule_t					*crule;					/* clientrules, list.		*/
	struct rule_t					*srule;					/* socksrules, list.			*/
	struct route_t					*route;					/* not in use yet.			*/

	shmem_object_t					*bwv;						/* bwmem for rules.			*/
	size_t							bwc;
	/*
	 * should have one for each rule instead, but sadly some systems seem to
	 * have trouble with sysv-style shared memory/semaphores so we use
	 * the older/better supported filelock, and a global to at that.
	 */
	int								bwlock;					/* lock for modifying bw.	*/

	shmem_object_t					*sessionv;				/* sessionmem for rules.	*/
	size_t							sessionc;
	int								sessionlock;			/* lock for sessionv.		*/

	struct compat_t				compat;					/* compatibility options.  */
	struct extension_t			extension;				/* extensions set.			*/
	struct logtype_t				log;						/* where to log.				*/
	struct option_t				option;					/* commandline options.		*/
	int								resolveprotocol;		/* resolve protocol.			*/
	struct srchost_t				srchost;					/* relevant to srchost.		*/
	struct statistic_t			stat;						/* some statistics.			*/
	struct configstate_t			state;
	struct timeout_t				timeout;					/* timeout values.			*/
	struct userid_t				uid;						/* userids.						*/
	struct childstate_t			child;					/* childstate.					*/

	int								clientmethodv[MAXMETHOD]; /* clientmethods.		*/
	size_t							clientmethodc;				  /* methods in list.	*/

	int								methodv[MAXMETHOD];  /* methods by priority.		*/
	size_t							methodc;					/* methods in list.			*/
};


struct connectionstate_t {
	struct authmethod_t	auth;					/* XXX should probably not be here. */
	int						command;
	struct extension_t	extension;			/* extensions set.						*/
	int						protocol;
	struct {
		time_t				accept;				/* time of connection accept.			*/
		time_t				negotiate_start;	/* time negotiation started.			*/
	} time;
	int						version;

};

struct sockd_io_direction_t {
	int								s;				/* socket connection.					*/
	struct sockaddr				laddr;		/* local address of s.					*/
	struct sockaddr				raddr;		/* address of remote peer for s.		*/

	/*
	 * Varies according to context.
	 * src:		as laddr but on sockshost_t form.
	 * dst:		name as given by client.
	 * control: as laddr
	*/
	struct sockshost_t			host;

	struct authmethod_t			auth;			/* authentication used.					*/

	size_t							sndlowat;	/* low-water mark for send.			*/

		/* byte count */
	size_t							read;			/* bytes read.								*/
	size_t							written;		/* bytes written.							*/

	int								flags;		/* misc. flags								*/
	struct {
		unsigned 					fin:1;			/* received FIN on this socket.	*/
		unsigned 					shutdown_wr:1;	/* shutdown for writing. 			*/
	} state;
};


struct sockd_io_t {
	unsigned								allocated:1;/* object allocated?					*/

	struct connectionstate_t		state;

	struct sockd_io_direction_t	control;		/* clients controlconnection.		*/
	struct sockd_io_direction_t	src;			/* client we receive data from.	*/
	struct sockd_io_direction_t	dst;			/* remote peer.						*/

	struct rule_t						crule;		/* client rule matched.				*/
	struct rule_t						rule;			/* matched rule for i/o.			*/
	struct route_t						route;		/* route to next proxy, if used. */
	struct timeval						time;			/* time of last i/o operation.	*/
	struct sockd_io_t					*next;		/* for some special cases.			*/
};


struct negotiate_state_t {
	unsigned					complete:1;							/* completed?				*/
	unsigned char			mem[ 1								/* VER						*/
									+ 1								/* NMETHODS					*/
									+ AUTHMETHOD_MAX				/* METHODS					*/
									+ sizeof(struct request_t)
									];
	int						reqread;								/* read so far.			*/
	size_t					start;								/* start of current req */
	char						emsg[256];							/* errormessage, if any.*/
	int						(*rcurrent)(int s,
											   struct request_t *request,
												struct negotiate_state_t *state);
	struct sockshost_t	src;									/* client's address. 	*/
	struct sockshost_t	dst;									/* our address. 			*/

};

struct sockd_negotiate_t {
	unsigned							allocated:1;
	unsigned							ignore:1;		/* ignore for now?					*/
	struct request_t				req;
	struct negotiate_state_t	negstate;
	struct rule_t					rule;				/* rule matched for accept().		*/
	int								s;					/* client connection.				*/
	struct connectionstate_t	state;			/* state of connection.				*/
};


struct sockd_request_t {
	struct sockaddr				from;			/* client's control address.			*/
	struct sockaddr				to;			/* address client was accepted on.	*/
	struct request_t				req;			/* request to perform.					*/
	struct rule_t					rule;			/* rule matched for accept().			*/
	int								s;				/* clients control connection.		*/
	struct connectionstate_t	state;		/* state of connection.					*/
};

struct sockd_mother_t {
	int						s;					/* connection to child for ancillary.	*/
#if HAVE_SENDMSG_DEADLOCK
	int						lock;				/* lock on request connection.			*/
#endif /* HAVE_SENDMSG_DEADLOCK */
	int						ack;				/* connection for ack's.					*/
};

struct sockd_child_t {
	int						type;				/* child type.									*/
	pid_t						pid;				/* childs pid.									*/
	int						freec;			/* free slots on last count.				*/
	int						s;					/* connection to mother for ancillary.	*/
#if HAVE_SENDMSG_DEADLOCK
	int						lock;				/* lock on request connection.			*/
#endif /* HAVE_SENDMSG_DEADLOCK */
	int						ack;				/* connection for ack's.					*/
};




/* functions */
__BEGIN_DECLS


int
sockd_bind __P((int s, struct sockaddr *addr, size_t retries));
/*
 * Binds the address "addr" to the socket "s".  The bind call will
 * be tried "retries" + 1 times if the error is EADDRINUSE, or until
 * successful, whatever comes first.
 * If the portnumber is privileged, it will set and reset the euid
 * as appropriate.
 *
 * If successful, "addr" is filled in with the bound address.
 * Returns:
 *		On success: 0.
 *		On failure:	-1
 */


int
socks_permit __P((int client, struct socks_t *dst, int permit));
/*
 * "client" is the connection to the client from which the request in
 * "dst" was made.  "permit" is the result of a rulecheck.
 * The function sends a correct reply to the connection on "client" if
 * "permit" indicates the connection is not to be allowed.
 * Returns:
 *		If connection allowed: true.
 *		If connection disallowed: false.
 */


int
sockdio __P((struct sockd_io_t *io));
/*
 * Tries to send the io object "io" to a child.
 * If no child is able to accept the io a new one is created and
 * the attempt is retried.
 *
 * Returns
 *    On success: 0
 *    On failure: -1, io was not accepted by any child.
 */

int
pidismother __P((pid_t pid));
/*
 * If "pid" refers to a mother, the number of "pid" in
 * state.motherpidv is returned.  Numbers are counted from 1.
 * IF "pid" is no mother, 0 is returned.
 */

int
descriptorisreserved __P((int d));
/*
 * If "d" is a descriptor reserved for use globally, the function
 * returns true.
 * Otherwise, false.
*/
int
childcheck __P((int type));
/*
 * Calculates the number of free slots every child of type "type" has,
 * combined. 
 * If "type" is negated, the function instead returns
 * the total number of slots (free or not) in every child of that type.
 * Also adjusts the number of children of type "type" if needed, according
 * to configure variables.
 *
 * If childcheck() is successful it also means there is at the minimum
 * one free descriptor available.
 */

int
childtype __P((pid_t pid));
/*
 * Returns the type of child the child with pid "pid" is.
 */

int
removechild __P((pid_t childpid));
/*
 * Removes the child "child" with pid "childpid" and updates internal lists.
 * Returns:
 *		On success: 0
 *		On failure: -1 (no current proxychild has pid "childpid".)
 */

struct rule_t *
addclientrule __P((const struct rule_t *rule));
/*
 * Appends a copy of "rule" to our list of client rules.
 * Returns a pointer to the added rule (not "rule").
 */

struct rule_t *
addsocksrule __P((const struct rule_t *rule));
/*
 * Appends a copy of "rule" to our list of socks rules.
 * Returns a pointer to the added rule (not "rule").
 */

void
addinternal __P((const struct ruleaddress_t *addr));
/*
 * Adds "addr" to the list of external addresses.
*/

void
addexternal __P((const struct ruleaddress_t *addr));
/*
 * Adds "addr" to the list of internal addresses (to listen on).
*/

int
addressisbindable __P((const struct ruleaddress_t *addr));
/*
 * Checks whether "addr" is bindable.
 * Returns:
 *		On success: true.
 *		On failure: false.
 */


struct linkedname_t *
adduser __P((struct linkedname_t **ruleuser, const char *name));
/*
 * Adds a user with the name "name" to the list hanging of "ruleuser".
 * Returns:
 *		On success: a pointer ruleuser.
 *		On failure: NULL.
 */
void
showrule __P((const struct rule_t *rule));
/*
 * prints the rule "rule".
 */


void
showclient __P((const struct rule_t *rule));
/*
 * prints the clientrule "rule".
 */


void
showconfig __P((const struct config_t *config));
/*
 * prints out config "config".
 */


const char *
authinfo __P((const struct authmethod_t *auth, char *info, size_t infolen));
/*
 * Fills in "info" with a printable representation of the "auth".
 * Returns a pointer to "info".
*/


int
rulespermit __P((int s,
						const struct sockaddr *peer, const struct sockaddr *local,
					  struct rule_t *rule, struct connectionstate_t *state,
					  const struct sockshost_t *src, const struct sockshost_t *dst,
					  char *msg, size_t msgsize));
/*
 * Checks whether the rules permit data from "src" to "dst".
 * "s" is the socket the connection is on, from the address "peer", accepted
 * on the address "local".
 * "state" is the current state of the connection and may be updated.
 * "msg" is filled in with any message/information provided when checking
 * access, "msgsize" is the size of "msg".
 *
 * Wildcard fields are supported for the following fields;
 *		ipv4:			INADDR_ANY
 *		port:			none [enum]
 *
 * "rule" is filled in with the contents of the matching rule.
 * Returns:
 *		True if a connection should be allowed.
 *		False otherwise.
 */




int
sockd_connect __P((int s, const struct sockshost_t *dst));
/*
 * Tries to connect socket "s" to the host given in "dst".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

void
resetconfig __P((void));
/*
 * resets the current config back to default, freeing memory aswell.
 */


int
send_response __P((int s, const struct response_t *response));
/*
 * Sends "response" to "s".
 *		On success: 0
 *		On failure: -1
 */



int
send_req __P((int s, const struct sockd_request_t *req));
/*
 * Sends "req" to "s".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

int
send_client __P((int s, int client));
/*
 * Sends the client "client" to "s".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */



/*
 * Returns a value indicating whether relaying from "src" to "dst" should
 * be permitted.
 */

int
selectmethod __P((const int *methodv, size_t methodc,
					   const unsigned char *offeredv, size_t offeredc));
/*
 * Selects the best method based on available methods and given
 * priority.
 * "methodv" is a list over available methods, methodc in length.
 * "offerdv" is a list over offered methods, offeredc in length.
 * The function returns the value of the method that should be selected,
 * AUTMETHOD_NOACCEPT if none is acceptable.
 */

int
method_uname __P((int s, struct request_t *request,
						struct negotiate_state_t *state));
/*
 * Enters username/password subnegotiation.  If successful,
 * "request->auth.mdata.uname" is filled in with values read from client.
 * If unsuccessful, the contents of "uname" is indeterminate.
 * After negotiation has finished and the response to client has been sent
 * the function returns.
 * Returns:
 *		On success: 0 (user/password accepted)
 *		On failure: -1  (user/password not accepted, communication failure,
 *							  or something else.)
 */



void
iolog __P((struct rule_t *rule, const struct connectionstate_t *state,
		int operation,
		const struct sockshost_t *src, const struct authmethod_t *srcauth,
		const struct sockshost_t *dst, const struct authmethod_t *dstauth,
		const char *data, size_t count));
/*
 * Called after each each complete io operation
 * (read then write, or read then block).
 * Does misc. logging based on the logoptions set in "log".
 * "rule" is the rule that matched the iooperation, not "const" due to
 * possible libwrap interaction.
 * "state" is the state of the connection.
 * "operation" is the operation that was performed.
 * "src" is where data was read from.
 * "dst" is where data was written to.
 * "data" and "count" are interpreted depending on "operation".
 *
 * If "operation" is
 *    OPERATION_ACCEPT
 *		OPERATION_CONNECT
 *			"count" is ignored.
 *			If "data" is not NULL or NUL, it is a string giving additional
 * 		information about the operation.
 *
 *		OPERATION_ABORT
 *		OPERATION_ERROR
 *			"count" is ignored.
 *			If "data" is not NULL or NUL, it is a string giving the reason for 
 *			abort or error.
 *			If "data" is NULL or NUL, the reason is the errormessage affiliated
 *			with the current errno.
 *
 *		OPERATION_IO
 *			"data" is the data that was read and written.
 *			"count" is the number of bytes that was read/written.
 */


void
close_iodescriptors __P((const struct sockd_io_t *io));
/*
 * A subset of delete_io().  Will just close all descriptors in
 * "io".
 */

int
sockdnegotiate __P((int s));
/*
 * Sends the connection "s" to a negotiator child.
 * Returns:
 *		On success: 0
 *		On failure: -1
 */


void
run_io __P((struct sockd_mother_t *mother));
/*
 * Sets a io child running.  "mother" is the childs mother.
 *
 * A child starts running with zero clients and waits
 * indefinitely for mother to send atleast one.
 */

void
run_negotiate __P((struct sockd_mother_t *mother));
/*
 * Sets a negotiator child running.  "mother" is the childs mother.
 * A child starts running with zero clients and waits
 * indefinitely for mother to send atleast one.
 */


void
run_request __P((struct sockd_mother_t *mother));
/*
 * Sets a request child running.  "mother" is the childs mother.
 * "mread" is read connection to mother, "mwrite" is write connection.
 * A child starts running with zero clients and waits
 * indefinitely for mother to send atleast one.
 */

int
send_io __P((int s, const struct sockd_io_t *io));
/*
 * Tries to add send the io "io" to "s".
 * Returns
 *    On success: 0
 *    On failure: -1
 */

int
recv_io __P((int mother, struct sockd_io_t *io));
/*
 * Attempts to read a new io object from "mother".
 * If a io is received it is either copied into "io", or it's copied
 * to a internal list depending on if "io" is NULL or not;  thus mother
 * vs child semantics.  If semantics are those of a child, the request
 * field of "io" is sent to the controlconnection in "io".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */

int
recv_req __P((int s, struct sockd_request_t *req));
/*
 * Receives a request from "s" and writes it to "req".
 * Returns:
 *		On success: 0
 *		On failure: -1
 */


int
recv_request __P((int s, struct request_t *request,
						struct negotiate_state_t *state));
/*
 * Reads a socks request from the socket "s", which can be set to
 * non-blocking.
 * "request" will be filled in as reading progresses but it should
 * be considered of indeterminate contents untill the whole request
 * has been read.
 * Returns:
 *    On success: > 0
 *    On failure: <= 0.  If errno does not indicate the request should be
 *                       be retried, the connection "s" should be dropped.
 */

int
recv_sockspacket __P((int s, struct request_t *request,
							 struct negotiate_state_t *state));
/*
 * When methodnegotiation has finished (if appropriate) this function
 * is called to receive the actual packet.
 * Returns:
 *    On success: > 0
 *    On failure: <= 0.  If errno does not indicate the request should be
 *                       be retried, the connection "s" should be dropped.
 */

struct sockd_child_t *
addchild __P((int type));
/*
 * Adds a new child that can accept objects of type "type" from mother.
 * Returns:
 *    On success: a pointer to the added child.
 *    On failure: NULL.  (resource shortage.)
 */

struct sockd_child_t *
getchild __P((pid_t pid));
/*
 * Attempts to find a child with pid "pid".
 * Returns:
 *		On success: a pointer to the found child.
 *		On failure: NULL.
 */


void
sigchildbroadcast __P((int sig, int childtype));
/*
 * Sends signal "sig" to all children of type "childtype".
 */

int
fillset __P((fd_set *set));
/*
 * Sets every child's descriptor in "set", aswell as sockets we listen on.
 * Returns the number of the highest descriptor set, or -1 if none was set.
 */

void
clearset __P((int type, const struct sockd_child_t *child, fd_set *set));
/*
 * Clears every descriptor of type "type" in "child" from "set".
 * The values valid for "type" is SOCKD_NEWREQUEST or SOCKD_FREESLOT.
 */

struct sockd_child_t *
getset __P((int type, fd_set *set));
/*
 * If there is a child with a descriptor set in "set", a pointer to
 * the child is returned.  "type" gives the type of descriptor that must
 * be set, either SOCKD_NEWREQUEST or SOCKD_FREESLOT.
 * The children returned are returned in prioritised order.
 * If no child is found, NULL is returned.
 */

struct sockd_child_t *
nextchild __P((int type));
/*
 * Returns:
 *		On success: pointer to a child of correct type with atleast one free slot.
 *		On failure: NULL.
 */

void
setsockoptions(int s);
/*
 * Sets options _all_ serversockets should have set.
 */

void
sockdexit __P((int sig));
/*
 * Called both by signal and manually.
 * If "sig" is less than 0, assume it's manually and exit with absolute
 * value of "sig".
 * Otherwise report exit due to signal "sig".
 */

struct hostent *
cgethostbyname __P((const char *name));
/*
 * Identical to gethostbyname() but caches info.
 */

struct hostent *
cgethostbyaddr __P((const char *addr, int len, int type));
/*
 * Identical to gethostbyaddr() but caches info.
 */

void
socks_seteuid __P((uid_t *old, uid_t new));
/*
 * Sets euid to "new".  If "old" is not NULL, current euid is saved in it.
 * Exits on failure.
 */

void
socks_reseteuid __P((uid_t current, uid_t new));
/*
 * "Resets" euid back from "current" to "new".
 * If the operation fails, it's flagged as an internal error.
 */

int
usermatch __P((const struct authmethod_t *auth, 
               const struct linkedname_t *userlist));
/*
 * Checks whether the username in "auth" matches a name in the
 * list "userlist".
 * Returns:
 * 	If match: true.
 *		Else: false.
 */

int
accesscheck __P((int s, struct authmethod_t *auth,
					  const struct sockaddr *src, const struct sockaddr *dst,
					  char *emsg, size_t emsgsize));
/*
 * Checks whether access matches according to supplied arguments.
 * "auth" is the authentication to be matched against,
 * "s" is the socket the client is connected to,
 * "src" is address client connected from, "dst" is address client
 * connected to.
 * "emsg" is a buffer that information can be written into, "emsgsize"
 * is the size of that buffer.
 *
 * Returns:
 *		If access is ok: true.
 *		Otherwise: false.  Writes the reason into "emsg".
 */


int
passwordcheck __P((const char *name, const char *cleartextpassword,
						 char *emsg, size_t emsglen));
/*
 * Checks whether "name" is in the passwordfile.
 * If "cleartextpassword" is not NULL, also checks if "name"'s
 * password is "cleartextpassword".
 *
 * Returns:
 *		If "name" and "cleartextpassword" is matched: 0
 *		Otherwise: -1.  "emsg" is filled in with the errormessage.
 */

int
pam_passwordcheck __P((int s,
							  const struct sockaddr *src, const struct sockaddr *dst,
							  const struct authmethod_pam_t *auth, char *emsg,
							  size_t emsglen));
/*
 * Checks whether pam grants access to the client connected to the socket "s".
 * "src" is the clients sourceaddress, "dst" is address we accepted the
 * clients connection on.
 *
 * Returns:
 *		If "name" and "cleartextpassword" is matched: 0
 *		Otherwise: -1.  "emsg" is filled in with the errormessage.
 */

void
redirectsetup __P((void));
/*
 * sets up things for using the redirect module.
 * Must be called at start and after sighup by main mother.
 */

int
redirect __P((int s, struct sockaddr *addr, struct sockshost_t *host,
				  int command, const struct ruleaddress_t *from,
				  const struct ruleaddress_t *to));
/*
 * "s" is the socket to use for performing "command".
 * The meaning of "addr" and "host" varies depending on what "command" is:
 *		SOCKS_BIND:
 *			"addr" is local address of "s", to accept connection on.
 *			"host" is ignored.
 *
 *		SOCKS_BINDREPLY:
 *			"addr" is the address to say connection is from.
 *			"host" is the address to send reply to.
 *
 *		SOCKS_CONNECT:
 *			"addr" is local address of "s".
 *			"host" is host to connect to.
 *
 *		case SOCKS_UDPASSOCIATE:
 *			"addr" is local address of "s", to send udp packet from.
 *			"host" is address to send packet to.
 *
 *		case SOCKS_UDPREPLY:
 *			"addr" is the address to say reply is from.
 *			"host" is the address to send reply to.
 *
 * "host", "addr", and the address of "s" will be changed if needed.
 * Returns:
 *		On success: 0.
 *		On failure: -1.
 */

void
shmem_setup __P((void));
/*
 * sets up shmem structures, must be called at start and after sighup by
 * main mother, but only main mother.
 */

shmem_object_t *
shmem_alloc __P((int isclientrule, int number, shmem_object_t *poolv,
							  size_t poolc, int lock));
/*
 * Returns a pointer to an object allocated to rule number "number", 
 * from the pool "poolv".  If a object has already been allocated,
 * return the previosuly allocated object.
 * "lock" is used for locking, if it is -1, no locking is enforced.
 */

void
shmem_unuse __P((shmem_object_t *object, int lock));
/* 
 * Says we are no longer using "object".
 * "lock" is used for locking, if it is -1, no locking is enforced.
 */

void
shmem_use __P((shmem_object_t *object, int lock));
/* 
 * Marks "object" as in use.
 * "lock" is used for locking, if it is -1, no locking is enforced.
 */

void *
shmem_resize __P((size_t size, void *oldmem, size_t oldsize, int fd));
/*
 * Allocates shared memory of size "size", using "fd" for storage.
 * If "oldmem" is not NULL, it is a pointer to previously allocated
 * memory of size "oldsize".  The new memory will start at the same
 * address as "oldmem" if so.
 *
 * Returns a pointer to the memory allocated.
 */

void
shmem_lockall __P((void));
/*
 * Locks all locks related to shared mem use.  Should be used
 * before calling functions that would get into trouble if 
 * e.g. a SIGHUP changed rule memory.  E.g. calling rulespermit(),
 * then before using a shmem object (e.g. bw_use(()), a SIGHUP
 * is received, which changes the shmem object.
 */

void
shmem_unlockall __P((void));
/*
 * Unlocks all locks related to shared mem use. 
 */

int
bw_use __P((bw_t *bw));
/*
 * Marks "bw" as in use.
 */

void
bw_unuse __P((bw_t *bw));
/*
 * Says we are no longer using "bw".
 * If "bw" is NULL, nothing is done.
 */

bw_t *
bw_alloc __P((int isclientrule, int number));
/*
 * Allocates a bw object to rule number "number". 
 * "ruleclient" says whether it's a client-rule or not.
 * Returns a pointer to the allocated bw object.
*/

ssize_t
bw_left __P((const bw_t *bw));
/*
 * Returns how many bytes we should read if the client is restricted
 * by "bw".
 */

void
bw_update __P((bw_t *bw, size_t bwused, const struct timeval *bwusedtime));
/*
 * Updates "bw".  "bwused" is the bandwidth used (in bytes) at time
 * "bwusedtime".
 */

struct timeval *
bw_isoverflow __P((bw_t *bw, const struct timeval *timenow,
						struct timeval *overflow));
/*
 * Checks whether "bw" would overflow if we transfered more data through it.
 * "timenow" is the time now,
 * Returns:
 *		If "bw" would overflow: til what time we have to wait until we can
 *		again transfer data through it.  The memory used for those values is
 *		"overflow".
 *
 *		If "bw" would not overflow: NULL.  "overflow" is not touched.
 */

int
session_use __P((session_t *ss));
/*
 * If limits allow "ss" to be marked as in use, return true, else false.
 */

void
session_unuse __P((session_t *ss));
/*
 * Says we are no longer using "ss".
 */

session_t *
session_alloc __P((int isclientrule, int number));
/*
 * Allocates a session object to rule number "number". 
 * "ruleclient" says whether it's a client-rule or not.
 * Returns a pointer to the allocated session object.
*/

ssize_t
session_left __P((session_t *ss));
/*
 * Returns how many sessions are left if the client is restricted
 * by "ss".   
 *
 * Returns the number of sessions left for use.  If "use" is set,
 * this is the number left after "ss" has been set to use, which
 * will be negative if the session-limit was reached, and "ss"
 * was thus not set to use.
 */


#ifdef DEBUG
void
printfd __P((const struct sockd_io_t *io, const char *prefix));
/*
 * prints the contents of "io".  "prefix" is the string prepended
 * to the printing. (typically "received" or "sent".)
 */
#endif

struct in_addr
getifa __P((struct in_addr addr));
/*
 * Returns the address the system would chose to use for connecting
 * to the IP address "addr".
 * Returns INADDR_NONE on error.
 */
__END_DECLS
