/*
 * Copyright (c) 1997, 1998, 1999
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
 *  N-0349 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

/* $Id: sockd.h,v 1.134 1999/09/02 10:45:11 michaels Exp $ */

#ifndef _SOCKD_H_
#define _SOCKD_H_
#endif

/* use caching version in server. */
#define gethostbyname(name)				cgethostbyname(name)
#define gethostbyaddr(addr, len, type)	cgethostbyaddr(addr, len, type)

#ifdef lint
extern const int lintnoloop_sockd_h;
#else
#define lintnoloop_sockd_h 0
#endif


#define INIT(length)									\
	const size_t start	= state->start;		\
	const size_t end		= start + (length);	\
	errno = 0

#define MEMLEFT()		(sizeof(state->mem) - state->reqread)

#define LEFT()	((end) - state->reqread)
/*
 * Returns the number of bytes left to read.
 */

#define READ(s, length)	(readn((s), &state->mem[state->reqread], (length)))
/*
 * "s" is the descriptor to read from.
 * "length" is how much to read.
 * Returns the number of bytes read, -1 on error.
 */



#define OBJECTFILL(object)	memcpy((object), &state->mem[start], end - start)
/*
 * Fills "object" with data.
 */

#define CHECK(object, nextfunction)									\
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
		if ((p = READ(s, LEFT())) <= 0)								\
			return p;														\
		state->reqread += p;												\
																				\
		if (LEFT())															\
			return p;														\
																				\
		state->start = end;												\
		OBJECTFILL((object));											\
		state->rcurrent = nextfunction;								\
																				\
		if (state->rcurrent != NULL)									\
			return state->rcurrent(s, request, state);			\
	}																			\
} while (lintnoloop_sockd_h)



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


#define LOG_CONNECTs			"connect"
#define LOG_DISCONNECTs		"disconnect"
#define LOG_DATAs				"data"
#define LOG_ERRORs			"error"
#define LOG_IOOPERATIONs	"iooperation"


#define OPERATION_ACCEPT		1
#define OPERATION_CONNECT		(OPERATION_ACCEPT + 1)
#define OPERATION_IO				(OPERATION_CONNECT + 1)
#define OPERATION_DISCONNECT	(OPERATION_IO + 1)
#define OPERATION_ABORT			(OPERATION_DISCONNECT + 1)
#define OPERATION_ERROR			(OPERATION_ABORT + 1)



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

/* linked list over current rules. */
struct rule_t {
	struct ruleaddress_t		dst;				/* dst.										*/
	struct log_t				log;				/* type of logging to do.				*/
	int							number;			/* rulenumber, info/debugging only.	*/
	struct ruleaddress_t		src;				/* src.										*/
	struct serverstate_t		state;
	struct linkedname_t		*user;			/* name of users allowed.				*/
	int							verdict;			/* verdict for this rule.				*/

#if HAVE_LIBWRAP
	char							libwrap[LIBWRAPBUF];	/* libwrapline.					*/
#endif  /* HAVE_LIBWRAP */

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
	unsigned				lbuf:1;			/* line buffered output?						*/
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
	volatile sig_atomic_t	addchild;				/* okay to do a addchild()?	*/
	uid_t							euid;						/* original euid.					*/
	pid_t							*motherpidv;			/* pid of mothers.				*/
	pid_t							pid;						/* pid of current process.		*/
	int							type;						/* process type we are.			*/
};

struct listenaddress_t {
	struct sockaddr_in	addr;							/* bound address.					*/
	int						s;								/* bound socket.					*/
#if NEED_ACCEPTLOCK
	int						lock;							/* lock on structure.			*/
#endif
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


/* Make sure to keep in sync with clearconfig(). */
struct config_t {
	struct listenaddress_t		*internalv;				/* internal address'.		*/
	int								internalc;

	struct sockaddr_in			*externalv;				/*	external address'.		*/
	int								externalc;

	struct rule_t					*crule;					/* clientrules, list.		*/
	struct rule_t					*srule;					/* socksrules, list.			*/
	struct route_t					*route;					/* not in use yet.			*/

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

	int								methodv[AUTHMETHOD_MAX];/* methods by priority.	*/
	int								methodc;					/* methods in list.			*/

};


struct connectionstate_t {
	struct authmethod_t	auth;
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
	struct sockaddr_in			laddr;		/* local address of s.					*/
	struct sockaddr_in			raddr;		/* address of remote peer for s.		*/
	struct connectionstate_t	state;

	size_t							sndlowat;	/* low-water mark for send.			*/

		/* byte count */
	size_t							read;			/* bytes read.								*/
	size_t							written;		/* bytes written.							*/

	int								flags;		/* misc. flags								*/
};


struct sockd_io_t {
	unsigned								allocated:1;/* object allocated?					*/

	struct connectionstate_t		state;

	struct sockd_io_direction_t	in;			/* client we receive data from.	*/
	struct sockd_io_direction_t	out;			/* remote peer.						*/
	struct sockd_io_direction_t	control;		/* control connection to client.	*/

	struct rule_t						acceptrule;	/* rule matched for accept().		*/
	struct rule_t						rule;			/* matched rule for i/o.			*/

	struct sockshost_t				src;			/* our client.							*/
	struct sockshost_t				dst;			/* it's desired peer.				*/

	time_t								time;			/* time of last i/o operation.	*/
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
	int						(*rcurrent)(int s,
											   struct request_t *request,
												struct negotiate_state_t *state);
};

struct sockd_negotiate_t {
	unsigned							allocated:1;
	unsigned							ignore:1;		/* ignore for now?					*/
	struct request_t				req;
	struct negotiate_state_t	negstate;
	struct rule_t					rule;				/* rule matched for accept().		*/
	int								s;					/* client connection.				*/
	struct sockshost_t			src;				/* client address.					*/
	struct sockshost_t			dst;				/* our address.						*/
	struct connectionstate_t	state;			/* state of connection.				*/
};


struct sockd_request_t {
	struct sockaddr_in			from;			/* client's control address.			*/
	struct request_t				req;			/* request to perform.					*/
	struct rule_t					rule;			/* rule matched for accept().			*/
	int								s;				/* clients control connection.		*/
	struct connectionstate_t	state;		/* state of connection.					*/
	struct sockaddr_in			to;			/* address client was accepted on.	*/
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
sockd_bind __P((int s, const struct sockaddr *addr, size_t retries));
/*
 * Binds the address "addr" to the socket "s".  The bind call will
 * be be tried "retries" + 1 times if the error is EADDRINUSE, or until
 * successful, whatever comes first.
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
childcheck __P((int type));
/*
 * Calculates the number of free slots every child of type "type" has
 * combined.  If "type" is negated, the function instead returns
 * the total number of slots in every child.
 * If childcheck() is successful it also means there is at the minimum
 * one descriptor available.
 * Returns the total number of new objects children can accept.
 */

int
childtype __P((pid_t pid));
/*
 * Returns the type of child the child with pid "pid" is.
 */

const char *
childtype2string __P((int type));
/*
 * returns the string representation of "type".
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



int
rulespermit __P((int s, struct rule_t *rule,
					  struct connectionstate_t *state,
					  const struct sockshost_t *src, const struct sockshost_t *dst));
/*
 * Checks whether the rules permit data from "src" to "dst".
 * "s" is the socket the connection is on.  "state" is the current
 * state of the connection and may be updated.
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


void
send_failure __P((int s, const struct response_t *response, int failure));
/*
 * Sends a failure message to the client at "s".  "response" is the packet
 * we send, "failure" is the reason for failure and "auth" is the agreed on
 * authentication.
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
selectmethod __P((const unsigned char *methodv, size_t methodc));
/*
 * Selects the best method based on available methods and given
 * priority.  "methodv" is a list over available methods, methodc
 * in length.
 * The function returns the value of the method that should be selected,
 * AUTMETHOD_NOACCEPT if none is acceptable.
 */

int
method_uname __P((int s, struct request_t *request,
						struct negotiate_state_t *state));
/*
 * Enters username/password subnegotiation.  If successful,
 * "uname" is filled in with values read from client, if unsuccessful,
 * the contents of "uname" is indeterminate.  After negotiation has
 * finished and response to client is sent the function returns.
 * Returns:
 *		On success: 0 (user/password accepted)
 *		On failure: -1  (user/password not accepted, communication failure,
 *							  or something else.)
 */



void
iolog __P((struct rule_t *rule, const struct connectionstate_t *state,
		int operation,
		const struct sockshost_t *src, const struct sockshost_t *dst,
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
 *    OPERATION_DISCONNECT
 *			"data" and "count" is ignored.
 *
 * 	OPERATION_ABORT
 * 	OPERATION_ERROR
 *			"count" is ignored.
 *			If "data" is not NULL, it is a string giving the reason for abort
 * 		or error.
 *			If "data" is NULL, the reason is the errormessage affiliated
 *			with the current errno.
 *			
 *		OPERATION_IO
 * 		"data" is the data that was read and written.
 * 		"count" is the number of bytes that was read/written.
 */


int
serverchild __P((int s, const struct sockaddr_in *local,
					  const struct sockaddr_in *remote));
/*
 * Forked off by the server after a connection has come in on "s" but
 * before any data has been read.  "local" is the address "remote"
 * connected to.
 * Returns:
 *		On success: 0
 *		On failure : -1
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
passwordmatch __P((const char *name, const char *cleartextpassword));
/*
 * Checks whether "name" is in the passwordfile and if "name"'s
 * cleartext password is "cleartextpassword".
 * Returns:
 *		If "name" and "cleartextpassword" matches: 1
 *		else: 0
 */


#ifdef DEBUG
void
printfd __P((const struct sockd_io_t *io, const char *prefix));
/*
 * prints the contents of "io".  "prefix" is the string prepended
 * to the printing. (typically "received" or "sent".)
 */
#endif

__END_DECLS
