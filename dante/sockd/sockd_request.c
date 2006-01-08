/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004
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

#include "common.h"
#include "config_parse.h"

static const char rcsid[] =
"$Id: sockd_request.c,v 1.176 2006/01/07 18:54:07 michaels Exp $";

/*
 * Since it only handles one client at a time there is no possibility
 * for the mother to send a new client before we have got rid of the
 * old one and thus no need for locking even on broken systems.
 * (#ifdef HAVE_SENDMSG_DEADLOCK)
 * XXX I have started to work on fixing this, so this process too
 * can support multiple clients, perhaps for a later release I will
 * have time to complete it.  Will also fix the terrible fact
 * that we just sit around and wait if the command is bind, wasting
 * the whole process on practically nothing.
 */

__BEGIN_DECLS

static void
dorequest __P((int mother, const struct sockd_request_t *request));
/*
 * When a complete request has been read, this function can be
 * called.  It will perform the request "request->req" and send the
 * result to "mother".
 */

static int
flushio __P((int mother, int clientcontrol, const struct response_t *response,
				 struct sockd_io_t *io));
/*
 * "flushes" a complete io object and free's any state/resources held by it.
 * "mother" is connection to mother for sending the io.
 * "clientcontrol" is the client connection.
 * "response" is the response to be sent the client.
 * "io" is the io object sent mother.
 * Returns: 0, unless fatal error.
 */

static void
proctitleupdate __P((const struct sockaddr *from));
/*
 * Updates the title of this process.
 */

static struct sockd_io_t *
io_add __P((struct sockd_io_t *iolist, const struct sockd_io_t *newio));
/*
 * Adds _a copy_ of the object "newio" to the list "iolist".
 * Returns a pointer to the (new) iolist.
 */

static struct sockd_io_t *
io_remove __P((struct sockd_io_t *iolist, struct sockd_io_t *rmio));
/*
 * Removes the object "rmio" from the list "iolist".
 * Returns a pointer to the (new) iolist.
 */

static struct sockd_io_t *
io_find __P((struct sockd_io_t *iolist, const struct sockaddr *addr));
/*
 * Scans "iolist" for a object that contains "addr" as a local address.
 * If "addr" is NULL, returns "iolist".
 * Returns:
 *		On success: pointer to the matching io object.
 *		On failure: NULL.
 */

static int
serverchain __P((int s, const struct request_t *req, struct response_t *res,
							struct sockd_io_direction_t *src,
							struct sockd_io_direction_t *dst));
/*
 * Checks if we should create a serverchain on socket "s" for the request
 * "req".
 * Returns:
 *		0 : serverchain established successfully.
 * 	-1: No serverchain established.  If errno set, it indicates the reason.
 *        If errno is not set, no route exists to handle this connection,
 *        and it should be direct.
 */ 

static void
send_failure __P((int s, const struct response_t *response, int failure));
/*
 * Sends a failure message to the client at "s".  "response" is the packet
 * we send, "failure" is the reason for failure and "auth" is the agreed on
 * authentication.
 */


#define SHMEM_UNUSE(rule) \
do { \
	bw_unuse((rule)->bw); \
	session_unuse((rule)->ss); \
} while (lintnoloop_sockd_h)

__END_DECLS


void
run_request(mother)
	struct sockd_mother_t *mother;
{
	const char *function = "run_request()";
	struct sockd_request_t req;
#if DIAGNOSTIC
	const int freec = freedescriptors(sockscf.option.debug ? "start" : NULL);
#endif /* DIAGNOSTIC */

	proctitleupdate(NULL);

	/* CONSTCOND */
	while (1) {
		/*
		 * Get request from mother, perform it, get next request.
		 */
		const char command = SOCKD_FREESLOT;

		proctitleupdate(NULL);

		if (recv_req(mother->s, &req) == -1)
			sockdexit(-EXIT_FAILURE);

		dorequest(mother->s, &req);

		if (writen(mother->ack, &command, sizeof(command), NULL)
		!= sizeof(command))
			serr(EXIT_FAILURE, "%s: sending ack to mother failed", function);

#if DIAGNOSTIC
		SASSERTX(freec == freedescriptors(sockscf.option.debug ?  "end" : NULL));
#endif /* DIAGNOSTIC */
	}
}


int
recv_req(s, req)
	int s;
	struct sockd_request_t *req;
{
	const char *function = "recv_req()";
	int fdexpect, fdreceived, r;
	struct iovec iovec[1];
	struct msghdr msg;
	CMSG_AALLOC(cmsg, sizeof(int));

	iovec[0].iov_base		= req;
	iovec[0].iov_len		= sizeof(*req);

	msg.msg_iov				= iovec;
	msg.msg_iovlen			= ELEMENTS(iovec);
	msg.msg_name			= NULL;
	msg.msg_namelen		= 0;

	/* LINTED pointer casts may be troublesome */
	CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

	if ((r = recvmsgn(s, &msg, 0)) != sizeof(*req)) {
		switch (r) {
			case -1:
				swarn("%s: recvmsg() from mother", function);
				break;

			case 0:
				slog(LOG_DEBUG, "%s: recvmsg(): mother closed connection",
				function);
				break;

			default:
				swarnx("%s: recvmsg(): unexpected %d/%d bytes from mother",
				function, r, sizeof(*req));
		}

		return -1;
	}
	fdexpect = 1;

#if !HAVE_DEFECT_RECVMSG
	SASSERT(CMSG_TOTLEN(msg) == CMSG_SPACE(sizeof(int) * fdexpect));
#endif

	fdreceived = 0;
	/* LINTED pointer casts may be troublesome */
	CMSG_GETOBJECT(req->s, cmsg, sizeof(req->s) * fdreceived++);

	/* pointer fixup */
	req->req.auth = &req->state.auth;

	return 0;
}

static void
dorequest(mother, request)
	int mother;
	const struct sockd_request_t *request;
{
	const char *function = "dorequest()";
	static const struct sockd_io_t ioinit;
	struct sockaddr bound;
	struct sockd_io_t io;
	struct response_t response;
	char a[MAXSOCKSHOSTSTRING];
	char msg[256];
	int failed, p, permit, out, failurecode = SOCKS_NOTALLOWED;

	slog(LOG_DEBUG, "received request: %s",
	socks_packet2string(&request->req, SOCKS_REQUEST));

	proctitleupdate(&request->from);

	bzero(&response, sizeof(response));
	response.host	= request->req.host;
	response.auth	= request->req.auth;

	io							= ioinit;
	io.state					= request->state;
	io.state.extension	= sockscf.extension;
	io.crule					= request->rule;

	/* so we can call iolog() before rulespermit() on errors. */
	io.rule					= io.crule;
	io.rule.verdict 		= VERDICT_BLOCK;
	io.rule.number			= 0;
	sockaddr2sockshost(&request->from, &io.src.host);
	sockaddr2sockshost(&request->to, &io.dst.host);
	if (io.crule.log.error)
		/* if we log before rulespermit() it's due to an error. */
		io.rule.log.connect = 1;

	/*
	 * examine client request.
	 */

	/* supported version? */
	switch (request->req.version) {
		case SOCKS_V4:
			response.version = SOCKS_V4REPLY_VERSION;

			/* recognized command for this version? */
			switch (request->req.command) {
				case SOCKS_BIND:
				case SOCKS_CONNECT:
					io.state.protocol = SOCKS_TCP;
					break;

				default:
					snprintf(msg, sizeof(msg), "%s: unrecognized v%d command: %d",
					sockaddr2string(&request->from, a, sizeof(a)),
					request->req.version, request->req.command);

					io.state.command		= SOCKS_UNKNOWN;
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

					send_failure(request->s, &response, SOCKS_CMD_UNSUPP);
					close(request->s);
					return;
			}

			/* supported address format for this version? */
			switch (request->req.host.atype) {
				case SOCKS_ADDR_IPV4:
					break;

				default:
					snprintf(msg, sizeof(msg), "%s: unrecognized v%d atype: %d",
					sockaddr2string(&request->from, a, sizeof(a)),
					request->req.version, request->req.host.atype);

					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

					send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);
					close(request->s);
					return;
			}
			break; /* SOCKS_V4 */

		case SOCKS_V5:
			response.version = request->req.version;

			/* recognized command for this version? */
			switch (request->req.command) {
				case SOCKS_BIND:
				case SOCKS_CONNECT:
					io.state.protocol = SOCKS_TCP;
					break;

				case SOCKS_UDPASSOCIATE:
					io.state.protocol = SOCKS_UDP;
					break;

				default:
					snprintf(msg, sizeof(msg), "%s: unrecognized v%d command: %d",
					sockaddr2string(&request->from, a, sizeof(a)),
					request->req.version, request->req.command);

					io.state.command		= SOCKS_UNKNOWN;
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

					send_failure(request->s, &response, SOCKS_CMD_UNSUPP);
					close(request->s);
					return;
			}

			/* supported address format for this version? */
			switch (request->req.host.atype) {
				case SOCKS_ADDR_IPV4:
				case SOCKS_ADDR_DOMAIN:
					break;

				default:
					snprintf(msg, sizeof(msg), "%s: unrecognized v%d atype: %d",
					sockaddr2string(&request->from, a, sizeof(a)),
					request->req.version, request->req.host.atype);

					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

					send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);
					close(request->s);
					return;
			}
			break; /* SOCKS_V5 */

		default:
			SERRX(request->req.version);
	}


	/*
	 * packet looks ok, fill in remaining bits and check rules.
	 */

	/* LINTED pointer casts may be troublesome */
	sockaddr2sockshost(&request->from, &io.control.host);

	io.control.s		= request->s;
	io.control.laddr	= request->to;
	io.control.raddr	= request->from;

	switch (request->req.command) {
		case SOCKS_BIND:
			/*
			 * bind is a bit funky.  We first check if the bind request
			 * is allowed, and then we transform io.dst to something
			 * completly different to check if the bindreply is alloswed.
			 */

			io.src.host = io.control.host;
			io.dst.host = request->req.host;

			if (io.dst.host.atype					!= SOCKS_ADDR_IPV4
			||  io.dst.host.addr.ipv4.s_addr		!= htonl(0)
			||  io.dst.host.port						== htons(0))
				io.state.extension.bind = 0;	/* not requesting bind extension. */
			break;

		case SOCKS_CONNECT:
			io.src.host = io.control.host;
			io.dst.host = request->req.host;
			break;

		case SOCKS_UDPASSOCIATE:
			/*
			 * for UDP_ASSOCIATE we are getting clients UDP address,
			 * not destination in request.
			 * Destination address will be checked in the i/o loop for
			 * each destination, for now just set it to INADDR_ANY.
			 */

			io.src.host							= request->req.host;

			io.dst.host.atype					= SOCKS_ADDR_IPV4;
			io.dst.host.addr.ipv4.s_addr	= htonl(INADDR_ANY);
			io.dst.host.port					= htons(0);
			break;

		default:
			SERRX(request->req.command);
	}

	bzero(&bound, sizeof(bound));

	/*
	 * Find address to bind on clients behalf.
	 * First get the IP address.
	*/
	switch (request->req.command) {
		case SOCKS_BIND: /* either 0.0.0.0 or previous connectionaddress, ok. */
		case SOCKS_CONNECT:
		case SOCKS_UDPASSOCIATE: { /* dst is 0.0.0.0. */
			struct sockaddr dst;

			sockshost2sockaddr(&io.dst.host, &dst);

			/* LINTED possible pointer alignment problem */
			if ((request->req.command == SOCKS_CONNECT 
			  &&  (TOIN(&dst)->sin_addr.s_addr == htonl(INADDR_ANY)))
			|| ((TOIN(&bound)->sin_addr = getifa(TOIN(&dst)->sin_addr)).s_addr
			== htonl(INADDR_NONE))) {
				snprintf(msg, sizeof(msg), "invalid address: %s",
				sockaddr2string(&dst, a, sizeof(a)));

				iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
				&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);

				send_failure(request->s, &response, SOCKS_ADDR_UNSUPP);
				close(request->s);
				return;
			}
			break;
		}

		default:
			SERRX(request->req.command);
	}

	/* ... and now the port. */
	switch (request->req.command) {
		case SOCKS_BIND:
			/* find out what port to bind;  v4/v5 semantics?  bind extension? */
			switch (request->req.version) {
				case SOCKS_V4:
					if (io.state.extension.bind)
						/* LINTED pointer casts may be troublesome */
						TOIN(&bound)->sin_port = io.dst.host.port;
					else
						/* best we can try for is to use same port as source. */
						/* LINTED pointer casts may be troublesome */
						TOIN(&bound)->sin_port = TOCIN(&request->from)->sin_port;
					break;

				case SOCKS_V5:
					/* LINTED pointer casts may be troublesome */
					TOIN(&bound)->sin_port = io.dst.host.port;
					break;

				default:
					SERRX(request->req.version);
			}
			break;

		case SOCKS_CONNECT:
			/* LINTED pointer casts may be troublesome */
			TOIN(&bound)->sin_port = TOCIN(&request->from)->sin_port;
			break;

		case SOCKS_UDPASSOCIATE:
			/* LINTED pointer casts may be troublesome */
			TOIN(&bound)->sin_port	= request->req.host.port;
			break;

		default:
			SERRX(request->req.command);
	}

	/* create outgoing socket. */
	switch (io.state.protocol) {
		case SOCKS_TCP:
			out = socket(AF_INET, SOCK_STREAM, 0);
			break;

		case SOCKS_UDP:
			out = socket(AF_INET, SOCK_DGRAM, 0);
			break;

		default:
			SERRX(io.state.protocol);
	}

	if (out == -1) {
		iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
		&io.src.auth, &io.dst.host, &io.dst.auth, strerror(errno), 0);

		send_failure(request->s, &response, SOCKS_FAILURE);
		close(request->s);
		return;
	}
	setsockoptions(out);

	/* bind it. */ /* LINTED possible pointer alignment problem */
	TOIN(&bound)->sin_family = AF_INET;
	if (sockscf.compat.reuseaddr) {/* XXX and not rebinding in redirect(). */
		p = 1;
		if (setsockopt(out, SOL_SOCKET, SO_REUSEADDR, &p, sizeof(p)) != 0)
			swarn("%s: setsockopt(SO_REUSEADDR)", function);
	}

	/* need to bind address so rulespermit() has an address to compare against.*/
	if ((p = sockd_bind(out, &bound, 1)) != 0) {
		/* no such luck, bind any port and let client decide if ok. */
		/* LINTED pointer casts may be troublesome */
		TOIN(&bound)->sin_port = htons(0);
		p = bind(out, &bound, sizeof(bound));
	}

	if (p != 0) {
		iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
		&io.src.auth, &io.dst.host, &io.dst.auth, strerror(errno), 0);

		send_failure(request->s, &response, errno2reply(errno, response.version));
		close(request->s);
		close(out);
		return;
	}

	/* rules permit? */
	shmem_lockall();
	switch (request->req.command) {
		case SOCKS_BIND:
			permit = rulespermit(request->s, &request->from, &request->to,
			&io.rule, &io.state, &io.src.host, &io.dst.host, msg, sizeof(msg));
			break;

		case SOCKS_CONNECT:
			permit = rulespermit(request->s, &request->from, &request->to,
			&io.rule, &io.state, &io.src.host, &io.dst.host, msg, sizeof(msg));
			break;

		case SOCKS_UDPASSOCIATE: {
			struct sockshost_t *src;
			struct connectionstate_t replystate;

			/*
			 * Client is allowed to send a "incomplete" address.
			 */
			if (io.src.host.atype == SOCKS_ADDR_IPV4
			&& (io.src.host.addr.ipv4.s_addr == htonl(0)
			  || io.src.host.port == htons(0)))
				src = NULL;
			else
				src = &io.src.host;

			/* make a temp to check for i/o both ways. */
			replystate				= io.state;
			replystate.command	= SOCKS_UDPREPLY;

			/* one direction is atleast in theory good enough. */
			permit = rulespermit(request->s, &request->from, &request->to,
			&io.rule, &io.state, src, NULL, msg, sizeof(msg))
			|| rulespermit(request->s, &request->from, &request->to,
			&io.rule, &replystate, NULL, src, msg, sizeof(msg));
			break;
		}

		default:
			SERRX(request->req.command);
	}

	if (permit && io.rule.ss != NULL) /* don't bother if rules deny anyway. */
		if (!session_use(io.rule.ss)) {
			permit = 0;
			io.rule.verdict = VERDICT_BLOCK;
			snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
			failurecode = SOCKS_FAILURE;
			io.rule.ss = NULL;
		}


	io.src.auth = io.control.auth = io.state.auth;
	iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host, &io.src.auth,
	&io.dst.host, &io.dst.auth, msg, 0);

	if (!permit) {
		shmem_unlockall();
		send_failure(request->s, &response, failurecode);
		close(request->s);
		close(out);
		return;
	}

	switch (request->req.command) {
		case SOCKS_UDPASSOCIATE:
			break; /* does a rulecheck for each packet. */

		default:
			if (io.rule.bw != NULL)
				bw_use(io.rule.bw);
	}

	shmem_unlockall();

	if (redirect(out, &bound, &io.dst.host, request->req.command,
	&io.rule.rdr_from, &io.rule.rdr_to) != 0) {
		if (io.rule.log.error) {
			snprintf(msg, sizeof(msg), "redirect(): %s", strerror(errno));
			iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
			&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
		}

		send_failure(request->s, &response, errno2reply(errno, response.version));
		close(request->s);
		close(out);
		SHMEM_UNUSE(&io.rule);
		return;
	}

	if (serverchain(out, &request->req, &response, &io.src, &io.dst) == 0) {
		switch (io.state.command) {
			case SOCKS_BIND:
				SERRX(request->req.command);
				/* NOTREACHED */

			case SOCKS_CONNECT: {
				socklen_t sinlen;

				io.src	= io.control;

				io.dst.s	= out;
				sinlen	= sizeof(io.dst.raddr);
				if (getpeername(io.dst.s, &io.dst.raddr, &sinlen) != 0) {
					if (io.rule.log.error) {
						snprintf(msg, sizeof(msg), "getpeername(io.dst.s): %s",
						strerror(errno));
						iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
						&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
					}

					send_failure(request->s, &response, SOCKS_FAILURE);
					close(request->s);
					break;
				}

				sinlen = sizeof(io.dst.laddr);
				if (getsockname(io.dst.s, &io.dst.laddr, &sinlen) != 0) {
					if (io.rule.log.error) {
						snprintf(msg, sizeof(msg), "getsockname(io.dst.s): %s",
						strerror(errno));
						iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
						&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
					}

					send_failure(request->s, &response, SOCKS_FAILURE);
					close(request->s);
					break;
				}

				flushio(mother, request->s, &response, &io);
				break;
			}

			case SOCKS_UDPASSOCIATE:
			default:
				SERRX(request->req.command);
		}

		close(out);
		SHMEM_UNUSE(&io.rule);
		return;
	}
	else /* no chain.  Error, or no route? */
		if (errno != 0) { /* error. */
			if (io.rule.log.error) {
				snprintf(msg, sizeof(msg), "serverchain failed: %s",
				strerror(errno));

				iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
				&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
			}

			send_failure(request->s, &response, errno2reply(errno,
			response.version));
			close(request->s);
			close(out);
			SHMEM_UNUSE(&io.rule);
			return;
		}
		/* else; no route, so go direct. */

	/*
	 * Set up missing bits of io and send it to mother.
	 */

	failed = 1; /* default.  Set to 0 on success. */
	io.dst.auth.method = AUTHMETHOD_NONE; /* no remote auth so far. */

	switch (io.state.command) {
		case SOCKS_BIND: {
			struct sockd_io_t *iolist;
			struct sockd_io_t bindio;			/* send this to proxyrelayer.			*/
			struct sockaddr boundaddr;			/* address we listen on.				*/
			socklen_t len;
			int flags, emfile;
			enum socketindex { client, childpipe, ourpipe, reply, remote };
			/* array of sockets, indexed by above enums, -1 if not open. */
			int sv[(int)(remote) + 1] = { -1, -1, -1, -1, -1 };

			SASSERTX(sv[ELEMENTS(sv) - 1] == -1);
			sv[client] = request->s;

			if (listen(out, SOCKD_MAXCLIENTQUE) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "listen(out): %s", strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(sv[client], &response, SOCKS_FAILURE);
				closev(sv, ELEMENTS(sv));
				break;
			}

			/* for accept(). */
			if ((flags = fcntl(out, F_GETFL, 0)) == -1
			|| fcntl(out, F_SETFL, flags | O_NONBLOCK) == -1) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "fcntl(): %s", strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(sv[client], &response, SOCKS_FAILURE);
				closev(sv, ELEMENTS(sv));
				break;
			}

			len = sizeof(boundaddr);
			if (getsockname(out, &boundaddr, &len) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "getsockname(out): %s",
					strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(sv[client], &response, SOCKS_FAILURE);
				closev(sv, ELEMENTS(sv));
				break;
			}

			sockaddr2sockshost(&boundaddr, &response.host);
			response.reply	= (char)sockscode(response.version, SOCKS_SUCCESS);

			if (io.state.extension.bind) {
				int pipev[2];

				/*
				 * The problem is that both we and the process which receives
				 * the io packet needs to know when the client closes it's
				 * connection, but _we_ need to receive a query from the
				 * client on the connection aswell, and the io process would
				 * get confused about that.  We try to hack around that
				 * by making a "dummy" descriptor that the io process can
				 * check as all other controlconnections and which we
				 * can close when the client closes the real controlconnection,
				 * so the io process can detect it.  Not very nice, no.
				 */

				if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pipev) != 0) {
					if (io.rule.log.error) {
						snprintf(msg, sizeof(msg), "socketpair(): %s",
						strerror(errno));
						iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
						&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
					}

					send_failure(sv[client], &response, SOCKS_FAILURE);
					closev(sv, ELEMENTS(sv));
					break;
				}

				sv[childpipe]	= pipev[0];
				sv[ourpipe]		= pipev[1];
			}

			/* let client know what address we bound to on it's behalf. */
			if (send_response(sv[client], &response) != 0) {
				iolog(&io.rule, &io.state, OPERATION_ABORT, &io.src.host,
				&io.src.auth, &response.host, &io.dst.auth, NULL, 0);
				closev(sv, ELEMENTS(sv));
				break;
			}

			/*
			 * convert io.dst to the dst for bindreply.  src will be 
			 * the remote address we accept(2) the bindreply from.
			 */
			if (io.state.extension.bind) {
				/* LINTED possible pointer alignment problem */
				io.dst.host.addr.ipv4 	= TOCIN(&request->from)->sin_addr;
				io.dst.auth					= io.src.auth;
			}
			else {
				struct sockd_io_direction_t tmp;

				 /* bindreply reverses src/dst. */	
				tmp 		= io.dst;
				io.dst	= io.src;
				io.src	= tmp;
			}

			emfile = 0;
			iolist = NULL;

			/* CONSTCOND */
			/* keep accepting connections until 
			 * a) we get a remote address that matches what client asked for.
			 * b) til client closes if we are using bind extension.
			 */
			while (1) {
				struct ruleaddress_t ruleaddr;
				struct sockaddr remoteaddr;		/* remote address we accepted.	*/
				struct sockshost_t dsthost;		/* host to send reply to.			*/
				struct sockaddr replyaddr;			/* address of bindreply socket.	*/
				int replyredirect;
				int fdbits = -1;
				fd_set rset;

				/* some sockets change, most remain the same. */
				sv[reply]	= -1;
				sv[remote]	= -1;

				FD_ZERO(&rset);
				FD_SET(sv[client], &rset);
				fdbits = MAX(fdbits, sv[client]);

				if (!emfile) {
					FD_SET(out, &rset);
					fdbits = MAX(fdbits, out);
				}

				++fdbits;
				if ((p = selectn(fdbits, &rset, NULL, NULL, NULL)) <= 0)
					SERR(p);

				if (FD_ISSET(sv[client], &rset)) {
					/*
					 * nothing is normally expected on controlconnection so
					 * assume it's a bind extension query or eof.
					 */
					struct request_t query;
					struct response_t queryresponse;
					struct negotiate_state_t state;
					struct sockaddr queryaddr;

					bzero(&state, sizeof(state));
					bzero(&query, sizeof(query));
					bzero(&queryresponse, sizeof(queryresponse));

					query.auth = request->req.auth;
					switch (p = recv_sockspacket(sv[client], &query, &state)) {
						case -1:
							iolog(&io.rule, &io.state, OPERATION_ABORT,
							&io.control.host, &io.control.auth,
							&response.host, &io.dst.auth, NULL, 0);
							break;

						case 0: {
							char *emsg = "client closed";

							iolog(&io.rule, &io.state, OPERATION_ABORT,
							&io.control.host, &io.control.auth,
							&response.host, &io.dst.auth, emsg, 0);
							p = -1; /* session ended. */
							break;
						}

						default: {
							struct sockd_io_t *fio;

							slog(LOG_DEBUG, "received request: %s",
							socks_packet2string(&query, SOCKS_REQUEST));

							switch (query.version) {
								case SOCKS_V4:
									queryresponse.version = SOCKS_V4REPLY_VERSION;
									break;

								case SOCKS_V5:
									queryresponse.version = query.version;
									break;

								default:
									SERRX(query.version);
							}

							sockshost2sockaddr(&query.host, &queryaddr);
							if ((fio = io_find(iolist, &queryaddr)) == NULL) {
								queryresponse.host.atype				= SOCKS_ADDR_IPV4;
								queryresponse.host.addr.ipv4.s_addr = htonl(0);
								queryresponse.host.port					= htons(0);
							}
							else {
								SASSERTX(fio->state.command = SOCKS_BINDREPLY);
								SASSERTX(sockaddrareeq(&fio->dst.laddr, &queryaddr));

								sockaddr2sockshost(&fio->src.raddr,
								&queryresponse.host);
							}

							if (fio != NULL) {
								flushio(mother, sv[client], &queryresponse, fio);
								emfile = MAX(0, emfile - 3); /* flushio() closes 3. */
								iolist = io_remove(iolist, fio);
								p = 0;
							}
							else
								if ((p = send_response(sv[client], &queryresponse))
								!= 0)
									iolog(&io.rule, &io.state, OPERATION_ABORT,
									&io.control.host, &io.control.auth,
									&response.host, &io.dst.auth, NULL, 0);
						}
					}

					if (p != 0)
						break;
				}

				if (!FD_ISSET(out, &rset))
					continue;

				len = sizeof(remoteaddr);
				if ((sv[remote] = acceptn(out, &remoteaddr, &len)) == -1) {
					if (io.rule.log.error)
						swarn("%s: accept(out)", function);

					switch (errno) {
#ifdef EPROTO
						case EPROTO:			/* overloaded SVR4 error */
#endif
						case EWOULDBLOCK:		/* BSD */
						case ECONNABORTED:	/* POSIX */

						/* rest appears to be Linux stuff according to apache src. */
#ifdef ECONNRESET
						case ECONNRESET:
#endif
#ifdef ETIMEDOUT
						case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
						case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
						case ENETUNREACH:
#endif
							continue;

						case EMFILE:
						case ENFILE:
							++emfile;
							continue;
					}
					break; /* errno is not ok. */
				}

				bindio							= io; /* quick init of most stuff. */
				bindio.state.command			= SOCKS_BINDREPLY;
				/* no auth at the moment. */
				bindio.state.auth.method	= AUTHMETHOD_NONE;

				sockaddr2sockshost(&remoteaddr, &bindio.src.host);

				/* accepted connection.  Does remote address match requested? */
				if (io.state.extension.bind
				|| addressmatch(sockshost2ruleaddress(&io.src.host, &ruleaddr),
				&bindio.src.host, SOCKS_TCP, 1)) {
					permit = rulespermit(sv[remote], &request->from, &request->to,
					&bindio.rule, &bindio.state, &bindio.src.host, &bindio.dst.host,
					msg, sizeof(msg));
					bindio.src.auth = bindio.state.auth;
				}
				else {
					bindio.rule.number 	= 0;
					bindio.rule.verdict = VERDICT_BLOCK;

					snprintfn(msg, sizeof(msg), "expected reply from %s",
					sockshost2string(&io.src.host, a, sizeof(a)));
					permit = 0;
				}

				if (permit && bindio.rule.ss != NULL)
					if (!session_use(bindio.rule.ss)) {
						permit = 0;
						bindio.rule.verdict = VERDICT_BLOCK;
						snprintf(msg, sizeof(msg), DENY_SESSIONLIMITs);
						failurecode = SOCKS_FAILURE;
						bindio.rule.ss = NULL;
					}

				iolog(&bindio.rule, &bindio.state, OPERATION_CONNECT,
				&bindio.src.host, &bindio.src.auth, &bindio.dst.host,
				&bindio.dst.auth, msg, 0);

				if (!permit) {
					close(sv[remote]);
					continue; /* wait for next connect, but will there be one? */
				}

				if (bindio.rule.bw != NULL)
					bw_use(bindio.rule.bw);

				dsthost = io.dst.host;
				if (redirect(sv[reply], &remoteaddr, &dsthost, SOCKS_BINDREPLY,
				&bindio.rule.rdr_from, &bindio.rule.rdr_to) != 0) {
					if (io.rule.log.error)
						swarn("%s: redirect(sv[reply])", function);
					close(sv[remote]);
					close(sv[reply]);
					SHMEM_UNUSE(&bindio.rule);
					continue;
				}

				/*
				 * Someone connected to socket we listen to on behalf of client.
				 * If we are using the bind extension, or are redirecting
				 * the reply, connect to address client is listening on.
				 * Otherwise, send the data on the connection we already have.
				 */

				if (sockshostareeq(&dsthost, &io.dst.host))
					replyredirect = 0;
				else
					replyredirect = 1;

				if (bindio.state.extension.bind || replyredirect) {
					if ((sv[reply] = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
						if (io.rule.log.error)
							swarn("%s: socket(SOCK_STREAM)", function);

						switch (errno) {
							case EMFILE:
							case ENFILE:
								++emfile;
								/* FALLTHROUGH */

							case ENOBUFS:
								close(sv[remote]);
								SHMEM_UNUSE(&bindio.rule);
								continue;
						}
						break; /* errno is not ok. */
					}
					setsockoptions(sv[reply]);

					replyaddr						= boundaddr;
					/* LINTED pointer casts may be troublesome */
					TOIN(&replyaddr)->sin_port	= htons(0);

					if (bind(sv[reply], &replyaddr, sizeof(replyaddr)) != 0) {
						if (bindio.rule.log.error)
							swarn("%s: bind(%s)", function,
						sockaddr2string(&replyaddr, a, sizeof(a)));
						break;
					}

					len = sizeof(replyaddr);
					/* LINTED pointer casts may be troublesome */
					if (getsockname(sv[reply], &replyaddr, &len) != 0) {
						if (bindio.rule.log.error)
							swarn("%s: getsockname(sv[reply])", function);
						if (errno == ENOBUFS) {
							close(sv[remote]);
							close(sv[reply]);
							SHMEM_UNUSE(&bindio.rule);
							continue;
						}
						break;
					}

					slog(LOG_DEBUG, "%s: connecting to %s",
					function, sockshost2string(&dsthost, a, sizeof(a)));

					if (socks_connect(sv[reply], &dsthost) != 0) {
						iolog(&bindio.rule, &bindio.state, OPERATION_ABORT,
						&bindio.src.host, &bindio.src.auth,
						&dsthost, &bindio.dst.auth, NULL, 0);
						break;
					}

					if (replyredirect) {
						close(sv[client]);
						sv[client] = sv[reply];
						sv[reply] = -1;
					}
				}

				if (bindio.state.extension.bind) {
					/*
					 * flushio() will close all descriptors set in io packet,
					 * so dup what we need to keep going.
					 */

					if ((bindio.control.s = dup(sv[childpipe])) == -1) {
						switch (errno) {
							case EMFILE:
							case ENFILE:
								if (bindio.rule.log.error)
									swarn("%s: dup()", function);
								++emfile;
								close(sv[remote]);
								continue;

							default:
								SERR(bindio.control.s);
						}
					}
				}
				else
					bindio.control.s = sv[client];

				/* back to blocking. */
				if (fcntl(sv[remote], F_SETFL, flags) == -1) {
					if (bindio.rule.log.error)
						swarn("%s: fcntl()", function);
					break;
				}

				if (bindio.state.extension.bind || replyredirect) {
					if (bindio.state.extension.bind)
						bindio.dst.s = sv[reply];
					else /* replyredirect */
						bindio.dst.s = sv[client];
					bindio.dst.laddr = replyaddr;
				}
				else {
					bindio.dst			= bindio.control;
					bindio.dst.laddr	= request->from;
				}
				sockshost2sockaddr(&bindio.dst.host, &bindio.dst.raddr);

				bindio.src.s		= sv[remote];
				bindio.src.laddr	= boundaddr;
				bindio.src.raddr	= remoteaddr;

				if (bindio.state.extension.bind)
					/* add to list, client will query. */
					iolist = io_add(iolist, &bindio);
				else {
					response.host = bindio.dst.host;

					failed = flushio(mother, sv[client], &response, &bindio);
					/* flushio() closes these, not closev(). */
					sv[client] = sv[remote] = -1;

					break;	/* only one connection to relay and that is done. */
				}
			}

			close(out); /* not accepting any more connections on this socket. */

			if (bindio.state.extension.bind) {
				struct sockd_io_t *rmio;

				/* delete any connections we have queued. */
				while ((rmio = io_find(iolist, NULL)) != NULL) {
					close_iodescriptors(rmio);
					iolist = io_remove(iolist, rmio);
				}
			}

			closev(sv, ELEMENTS(sv));
			break;
		}

		case SOCKS_CONNECT: {
			socklen_t sinlen;

			if (socks_connect(out, &io.dst.host) != 0) {
				iolog(&io.rule, &io.state, OPERATION_ABORT, &io.src.host,
				&io.src.auth, &io.dst.host, &io.dst.auth, NULL, 0);

				send_failure(request->s, &response, errno2reply(errno,
				response.version));

				close(request->s);
				break;
			}

			io.src	= io.control;

			io.dst.s	= out;
			sinlen	= sizeof(io.dst.raddr);
			if (getpeername(io.dst.s, &io.dst.raddr, &sinlen) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "getpeername(io.dst.s): %s",
					strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(request->s, &response, SOCKS_FAILURE);
				close(request->s);
				break;
			}

			sinlen = sizeof(io.dst.laddr);
			if (getsockname(io.dst.s, &io.dst.laddr, &sinlen) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "getsockname(io.dst.s): %s",
					strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(request->s, &response, SOCKS_FAILURE);
				close(request->s);
				break;
			}

			sockaddr2sockshost(&io.dst.laddr, &response.host);
			response.reply	= sockscode(response.version, SOCKS_SUCCESS);

			failed = flushio(mother, request->s, &response, &io);
			break;
		}

		case SOCKS_UDPASSOCIATE: {
			struct sockaddr client;
			socklen_t boundlen;
			int clientfd;

			/* socket we receive datagram's from client on */
			if ((clientfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "socket(): %s", strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(request->s, &response, SOCKS_FAILURE);
				close(request->s);
				break;
			}
			setsockoptions(clientfd);

			sockshost2sockaddr(&request->req.host, &client);

			io.src.s									= clientfd;
			io.src.raddr							= client;
			io.src.laddr							= request->to;
			/* LINTED pointer casts may be troublesome */
			TOIN(&io.src.laddr)->sin_port		= htons(0);

			/*
			 * bind address for receiving UDP packets so we can tell client
			 * where to send it's packets.
			 */
			if (bind(clientfd, &io.src.laddr, sizeof(io.src.laddr)) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "bind(%s): %s",
					sockaddr2string(&io.src.laddr, a, sizeof(a)), strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(request->s, &response, SOCKS_FAILURE);
				close(request->s);
				close(clientfd);
				break;
			}

			boundlen = sizeof(io.src.laddr);
			if (getsockname(clientfd, &io.src.laddr, &boundlen) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "getsockname(): %s", strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(request->s, &response, SOCKS_FAILURE);
				close(request->s);
				close(clientfd);
				break;
			}

			io.dst.s					= out;
			boundlen = sizeof(io.dst.laddr);
			if (getsockname(out, &io.dst.laddr, &boundlen) != 0) {
				if (io.rule.log.error) {
					snprintf(msg, sizeof(msg), "getsockname(): %s", strerror(errno));
					iolog(&io.rule, &io.state, OPERATION_CONNECT, &io.src.host,
					&io.src.auth, &io.dst.host, &io.dst.auth, msg, 0);
				}

				send_failure(request->s, &response, SOCKS_FAILURE);
				close(request->s);
				close(clientfd);
				break;
			}
			/* remote out can change each time, set to INADDR_ANY for now. */
			bzero(&io.dst.raddr, sizeof(io.dst.raddr));
			/* LINTED pointer casts may be troublesome */
			TOIN(&io.dst.raddr)->sin_family			= AF_INET;
			/* LINTED pointer casts may be troublesome */
			TOIN(&io.dst.raddr)->sin_addr.s_addr	= htonl(INADDR_ANY);
			/* LINTED pointer casts may be troublesome */
			TOIN(&io.dst.raddr)->sin_port				= htons(0);

			if (request->req.flag & SOCKS_USECLIENTPORT)
				/* LINTED pointer casts may be troublesome */
				if (TOIN(&client)->sin_port == TOIN(&io.dst.laddr)->sin_port)
					response.flag |= SOCKS_USECLIENTPORT;

			sockaddr2sockshost(&io.src.laddr, &response.host);
			response.reply	= (char)sockscode(response.version, SOCKS_SUCCESS);

			failed = flushio(mother, request->s, &response, &io);
			break;
		}

		default:
			SERRX(request->req.command);
	}

	if (failed) {
		SHMEM_UNUSE(&io.rule);
		close(out);
	}
#if DIAGNOSTIC
	else
		SASSERT(close(out) == -1 && errno == EBADF);
#endif
}


static int
flushio(mother, clientcontrol, response, io)
	int mother;
	int clientcontrol;
	const struct response_t *response;
	struct sockd_io_t *io;
{
	const char *function = "flushio()";
	socklen_t len;
	int sndlowat, value;
	float skew;

	switch (io->state.command) {
		case SOCKS_UDPASSOCIATE:
			sndlowat = SOCKD_BUFSIZEUDP;
			skew		= 1.0; /* no skew. */
			break;

		default:
			sndlowat = SOCKD_BUFSIZETCP;
			skew		= LOWATSKEW;
	}

	/* set socket options for relay process. */

#if SOCKD_IOMAX == 1
	/* only one client per process; doesn't matter much whether we block. */
	io->src.sndlowat	= sndlowat;
	io->dst.sndlowat	= sndlowat;

#elif	HAVE_SO_SNDLOWAT

	len = sizeof(value);
	if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDBUF, &value, &len) != 0)
		swarn("%s: getsockopt(io->src.s, SO_SNDBUF)", function);
	sndlowat = MIN(sndlowat, value * skew);

	if (setsockopt(io->src.s, SOL_SOCKET, SO_SNDLOWAT, &sndlowat,
	sizeof(sndlowat)) != 0)
		swarn("%s: setsockopt(in, SO_SNDLOWAT)", function);

	len = sizeof(io->src.sndlowat);
	if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDLOWAT, &io->src.sndlowat, &len)
	!= 0)
		swarn("%s: getsockopt(io-.src.s, SO_SNDLOWAT)", function);

	len = sizeof(value);
	if (getsockopt(io->dst.s, SOL_SOCKET, SO_SNDBUF, &value, &len) != 0)
		swarn("%s: getsockopt(io->dst.s, SO_SNDBUF)", function);
	sndlowat = MIN(sndlowat, value * skew);

	if (setsockopt(io->dst.s, SOL_SOCKET, SO_SNDLOWAT, &sndlowat,
	sizeof(sndlowat)) != 0)
		swarn("%s: setsockopt(io->dst.s, SO_SNDLOWAT", function);

	len = sizeof(io->dst.sndlowat);
	if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDLOWAT, &io->dst.sndlowat, &len)
	!= 0)
		swarn("%s: getsockopt(io->src.s, SO_SNDLOWAT)", function);

#else	/* SOCKD_IOMAX > 1 && !HAVE_SO_SNDLOWAT. */
	switch (io->state.command) {
		case SOCKS_UDPASSOCIATE:
			len = sizeof(sndlowat);
			if (getsockopt(io->src.s, SOL_SOCKET, SO_SNDBUF, &sndlowat, &len)
			!= 0) {
				swarn("%s: getsockopt(io->src.s, SO_SNDBUF)", function);
				io->src.sndlowat = SOCKD_BUFSIZEUDP;
			}
			else if (sndlowat == 0)
				io->src.sndlowat = SOCKD_BUFSIZEUDP;
			else
				io->src.sndlowat = sndlowat;

			len = sizeof(sndlowat);
			if (getsockopt(io->dst.s, SOL_SOCKET, SO_SNDBUF, &sndlowat, &len)
			!= 0) {
				swarn("%s: getsockopt(io->dst.s, SO_SNDBUF)", function);
				io->dst.sndlowat = SOCKD_BUFSIZEUDP;
			}
			else if (sndlowat == 0)
				io->dst.sndlowat = SOCKD_BUFSIZEUDP;
			else
				io->dst.sndlowat = sndlowat;

			break;

		default:
			/* TCP; use minimum guess. */
			io->src.sndlowat	= SO_SNDLOWAT_SIZE;
			io->dst.sndlowat	= SO_SNDLOWAT_SIZE;
	}
#endif  /* SOCKD_IOMAX > 1 && !HAVE_SO_SNDLOWAT */

	SASSERTX(io->src.sndlowat > 0
	&& io->dst.sndlowat >= sizeof(struct udpheader_t));

	if (send_response(clientcontrol, response) == 0)
		if (send_io(mother, io) != 0)
			serr(EXIT_FAILURE, "%s: sending io to mother failed", function);

	close_iodescriptors(io);
	return 0;
}


static void
proctitleupdate(from)
	const struct sockaddr *from;
{
	setproctitle("requestcompleter: %s", from == NULL ?  "0/1" : "1/1");
}

static struct sockd_io_t *
io_add(iolist, newio)
	struct sockd_io_t *iolist;
	const struct sockd_io_t *newio;
{
	const char *function = "io_add()";
	struct sockd_io_t *io, *previo;

	SASSERTX(newio->next == NULL);

	previo = io = iolist;
	while (io != NULL) {
		previo = io;
		io = io->next;
	}

	if ((io = (struct sockd_io_t *)malloc(sizeof(*newio))) == NULL)
		swarnx("%s: %s", function, NOMEM);
	else {
		*io = *newio;

		if (previo == NULL)
			previo = io;
		else
			previo->next = io;
	}

	return iolist == NULL ? previo : iolist;
}

static struct sockd_io_t *
io_remove(iolist, rmio)
	struct sockd_io_t *iolist;
	struct sockd_io_t *rmio;
{
	struct sockd_io_t *io, *previo;

	SASSERTX(iolist != NULL);

	if (iolist == rmio) {
		iolist = rmio->next;
		free(rmio);
		return iolist;
	}

	previo = iolist;
	io = iolist->next;
	while (io != NULL) {
		if (io == rmio) {
			previo->next = rmio->next;
			free(rmio);
			break;
		}

		previo = io;
		io = io->next;
	}

	return iolist;
}

static struct sockd_io_t *
io_find(iolist, addr)
	struct sockd_io_t *iolist;
	const struct sockaddr *addr;
{
	struct sockd_io_t *io;

	if (addr == NULL)
		return iolist;

	io = iolist;
	while (io != NULL)
		if (sockaddrareeq(&io->src.laddr, addr)
		||  sockaddrareeq(&io->dst.laddr, addr)
		||  sockaddrareeq(&io->control.laddr, addr))
			return io;
		else
			io = io->next;

	/* XXX should actually check that the io is still "active". */

	return NULL;
}

static int
serverchain(s, req, res, src, dst)
	int s;
	const struct request_t *req;
	struct response_t *res;
	struct sockd_io_direction_t *src, *dst;
{
	struct route_t *route;
	struct socks_t packet;
	
	packet.req 	= *req;
	packet.auth	= src->auth;

	/*
	 * If it's a non-standard method, convert to the closest standard method
	 * and offer that to the remote server.  Keep the original method
	 * though, since that's what the client authenticated to us via.
	 */
	switch (packet.auth.method) {
		case AUTHMETHOD_NONE:
		case AUTHMETHOD_UNAME:
			break;

		case AUTHMETHOD_PAM: { /* same as uname, just copy name/password. */
			/* it's a union, make a copy first. */
			const struct authmethod_pam_t pam
			= packet.auth.mdata.pam;

			strcpy((char *)packet.auth.mdata.uname.name,
			(const char *)pam.name);
			strcpy((char *)packet.auth.mdata.uname.password,
			(const char *)pam.password);

			packet.auth.method = AUTHMETHOD_UNAME;
			break;
		}

		case AUTHMETHOD_RFC931: /* has to beceome AUTHMETHOD_NONE. */
			packet.auth.method = AUTHMETHOD_NONE;
			break;

		default:
			SERRX(packet.auth.method);
	}

	errno = 0;
	if ((route = socks_connectroute(s, &packet, &src->host, &dst->host)) == NULL)
		return -1;

	if (socks_negotiate(s, s, &packet, route) != 0)
		return -1;

	*res = packet.res;

	/* when we reply, we have to use our clients auth ... */
	res->auth = &src->auth;

	/* ... but when we talk to remote, we have to use remotes auth. */
	dst->auth = packet.auth;

	return 0;
}

static void
send_failure(s, response, failure)
	int s;
	const struct response_t *response;
	int failure;
{
	struct response_t newresponse;	/* keep const. */

	newresponse = *response;
	newresponse.reply = (char)sockscode(newresponse.version, failure);
	send_response(s, &newresponse);
}

