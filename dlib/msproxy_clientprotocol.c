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

/*
 * This code is terrible so hopefully it will match the protocol.
 */

#include "common.h"

static const char rcsid[] =
"$Id: msproxy_clientprotocol.c,v 1.30 2003/07/01 13:21:30 michaels Exp $";

static char executable[] = "TELNET.EXE";
static struct sigaction oldsigio;

__BEGIN_DECLS

static int
msproxy_connect __P((int s, int control, struct socks_t *packet));

static int
msproxy_bind __P((int s, int control, struct socks_t *packet));

static char *
mem2response __P((struct msproxy_response_t *res, char *mem, size_t len));

static char *
request2mem __P((const struct msproxy_request_t *req, char *mem));

static void
msproxy_sessionsend __P((void));
/*
 * Terminates all msproxy sessions.
 */

static void
msproxy_sessionend __P((int s, struct msproxy_state_t *msproxy));
/*
 * ends the session negotiated with "s" and having state "msproxy".
 */

static void
msproxy_keepalive __P((int signal));
/*
 * Sends a keepalive packet on behalf of all established sessions.
 */

static void
sigio __P((int sig));

__END_DECLS

int
msproxy_init(void)
{
	const char *function = "msproxy_init()";
	struct itimerval timerval;
	struct sigaction sigact, oldsigact;

	if (atexit(msproxy_sessionsend) != 0) {
		swarn("%s: atexit()", function);
		return -1;
	}

	if (sigaction(SIGALRM, NULL, &oldsigact) != 0) {
		swarn("%s: sigaction(SIGALRM)", function);
		return -1;
	}

	/* XXX */
	if (oldsigact.sa_handler != SIG_DFL
	&&  oldsigact.sa_handler != SIG_IGN) {
		swarnx("%s: could not install signalhandler for SIGALRM, already set",
		function);
		return 0;	/* will probably timeout, don't consider it fatal for now. */
	}

	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags	= SA_RESTART;
	sigact.sa_handler	= msproxy_keepalive;
	if (sigaction(SIGALRM, &sigact, NULL) != 0) {
		swarn("%s: sigaction(SIGALRM)", function);
		return -1;
	}

	timerval.it_value.tv_sec	= MSPROXY_PINGINTERVAL;
	timerval.it_value.tv_usec	= 0;
	timerval.it_interval = timerval.it_value;

	if (setitimer(ITIMER_REAL, &timerval, NULL) != 0) {
		swarn("%s: setitimer()", function);
		return -1;
	}

	srand((unsigned int)time(NULL) * getpid());

	return 0;
}

int
msproxy_negotiate(s, control, packet)
	int s;
	int control;
	struct socks_t *packet;
{
	const char *function = "msproxy_negotiate()";
	char string[MAXSOCKADDRSTRING];
	struct msproxy_request_t req;
	struct msproxy_response_t res;
	int p;

	slog(LOG_DEBUG, "%s: packet #1", function);

	bzero(&req, sizeof(req));
	req.clientid	= htonl(0x0a000000);
	req.command		= htons(MSPROXY_HELLO);

	/* in case we don't get something more sensible. */
	packet->res.version	= packet->req.version;
	packet->res.reply		= MSPROXY_FAILURE;

	switch (packet->req.command) {
		case SOCKS_BIND:
#if 1
			req.packet._1.magic5		= htons(0x4800);
			req.packet._1.magic10	= htons(0x1400);
			req.packet._1.magic15	= htons(0x0400);
			req.packet._1.magic20	= htons(0x5704);
			req.packet._1.magic25	= htons(0x0004);
			req.packet._1.magic30	= htons(0x0100);
			req.packet._1.magic35	= htons(0x4a02);
			req.packet._1.magic40	= htons(0x3000);
			req.packet._1.magic45	= htons(0x4100);
			req.packet._1.magic50	= htons(0x3900);
#endif
			break;

		case SOCKS_CONNECT:
#if 0
			req.packet._1.magic5		= htons(0x4b00);
			req.packet._1.magic10	= htons(0x1400);
			req.packet._1.magic15	= htons(0x0400);
			req.packet._1.magic20	= htons(0x5704);
			req.packet._1.magic25	= htons(0x0004);
			req.packet._1.magic30	= htons(0x0100);
			req.packet._1.magic35	= htons(0x4a02);
			req.packet._1.magic40	= htons(0x3000);
			req.packet._1.magic45	= htons(0x4400);
			req.packet._1.magic50	= htons(0x3900);
#endif
			break;

		case SOCKS_UDPASSOCIATE:
			SERRX(packet->req.command);
			/* NOTREACHED */

		default:
			SERRX(packet->req.command);
	}

	if (socks_getusername(&packet->gw.host, req.username, sizeof(req.username))
	== NULL)
		return -1;

	*req.unknown = NUL;

	strncpy(req.executable, executable, sizeof(req.executable) - 1);
	req.executable[sizeof(req.executable) - 1] = NUL;

	*req.clienthost = NUL;

#if 0
	strncpy(req.clienthost, "foo", sizeof(req.clienthost) - 1);
	req.clienthost[sizeof(req.clienthost) - 1] = NUL;
#endif

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (strcmp(res.RWSP, "RWSP") != 0)
		serrx(EXIT_FAILURE, "expected \"RWSP\", got \"%s\"",
		str2vis(res.RWSP, sizeof(res.RWSP)));

	if (ntohs(res.command) >> 8 != 0x10)
		serrx(EXIT_FAILURE, "expected res.command = 10??, is %x",
		ntohs(res.command));

	packet->state.msproxy.controladdr.sin_family			= AF_INET;
	packet->state.msproxy.controladdr.sin_port			= res.packet._1.udpport;
	packet->state.msproxy.controladdr.sin_addr.s_addr	= res.packet._1.udpaddr;

	packet->state.msproxy.clientid	= htonl(rand());
	packet->state.msproxy.serverid	= res.serverid;

	slog(LOG_DEBUG, "%s: clientid: 0x%x, serverid: 0x%0x",
	function, packet->state.msproxy.clientid, packet->state.msproxy.serverid);

	/* LINTED pointer casts may be troublesome */
	slog(LOG_DEBUG, "%s: msproxy controladdress: %s",
	function,
	sockaddr2string((struct sockaddr *)&packet->state.msproxy.controladdr,
	string, sizeof(string)));


	slog(LOG_DEBUG, "%s: packet #2", function);

	/* almost identical. */
	req.clientid	= packet->state.msproxy.clientid;
	req.serverid	= packet->state.msproxy.serverid;

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (res.serverid != packet->state.msproxy.serverid)
		serrx(EXIT_FAILURE, "expected serverid = 0x%x, is 0x%x",
		packet->state.msproxy.serverid, res.serverid);

	if (res.sequence != 0x01)
		serrx(EXIT_FAILURE, "expected res.sequence = 0x%x, is 0x%x",
		0x01, res.sequence);

	if (ntohs(res.command) != MSPROXY_USERINFO_ACK)
		serrx(EXIT_FAILURE, "expected res.command = 0x%x, is 0x%x",
		MSPROXY_USERINFO_ACK, ntohs(res.command));

	switch (packet->req.command) {
		case SOCKS_BIND:
			p = msproxy_bind(s, control, packet);
			break;

		case SOCKS_CONNECT:
			p = msproxy_connect(s, control, packet);
			break;

		case SOCKS_UDPASSOCIATE:
		default:
			SERRX(packet->req.command);
	}

	return p;
}

static int
msproxy_connect(s, control, packet)
	int s;
	int control;
	struct socks_t *packet;
{
	const char *function = "msproxy_connect()";
	char string[MAXSOCKSHOSTSTRING];
	struct msproxy_request_t req;
	struct msproxy_response_t res;
	struct sockaddr_in addr;
	socklen_t len;

	slog(LOG_DEBUG, function);

#if 0

	bzero(&req, sizeof(req));
	req.clientid		= packet->state.msproxy.clientid;
	req.serverid		= packet->state.msproxy.serverid;
	req.command			= htons(MSPROXY_SOMETHING);
	memcpy(req.packet._3.NTLMSSP, "NTLMSSP", sizeof("NTLMSSP"));
	req.packet._3.bindaddr	= htonl(0x02000000);
	req.packet._3.magic5		= htons(0x0100);
	req.packet._3.magic10	= htons(0x9682);
#if 0
	req.packet._3.magic50	= htons(0x3000);
	req.packet._3.magic55	= htons(0x3000);
#endif

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (res.serverid != packet->state.msproxy.serverid)
		serrx(EXIT_FAILURE, "expected serverid = 0x%x, is 0x%x",
		packet->state.msproxy.serverid, res.serverid);

	if (ntohs(res.command) != MSPROXY_SOMETHING_1_ACK)
		serrx(EXIT_FAILURE, "expected res.command = 0x%x, is 0x%x",
		MSPROXY_SOMETHING_1_ACK, ntohs(res.command));

	slog(LOG_DEBUG, "%s: ntdomain: \"%s\"", function, res.packet._3.ntdomain);


	slog(LOG_DEBUG, "%s: packet #4", function);

	bzero(&req, sizeof(req));
	req.clientid		= packet->state.msproxy.clientid;
	req.serverid		= packet->state.msproxy.serverid;
	req.command			= htons(MSPROXY_SOMETHING_2);
#if 0
	memcpy(req.packet._4.NTLMSSP, "NTLMSSP", sizeof("NTLMSSP"));
	req.packet._4.magic3			= htons(0x0200);
	req.packet._4.magic5			= htons(0x0300);
	req.packet._4.magic10		= htons(0x1800);
	req.packet._4.magic15		= htons(0x1800);
	req.packet._4.magic20		= htons(0x4900);
	req.packet._4.magic30		= htons(0x6100);
	req.packet._4.magic35		= htons(0x0800);
	req.packet._4.magic40		= htons(0x0800);
	req.packet._4.magic45		= htons(0x3400);
	req.packet._4.magic50		= htons(0x0700);
	req.packet._4.magic55		= htons(0x0700);
	req.packet._4.magic60		= htons(0x3c00);
	req.packet._4.magic65		= htons(0x0600);
	req.packet._4.magic70		= htons(0x0600);
	req.packet._4.magic75		= htons(0x4300);
#endif

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (res.serverid != packet->state.msproxy.serverid)
		serrx(EXIT_FAILURE, "expected res.serverid = 0x%x, is 0x%x",
		packet->state.msproxy.serverid, res.serverid);

	if (res.clientack != 0x01)
		serrx(EXIT_FAILURE, "expected res.clientack = 0x%x, is 0x%x",
		0x01, res.clientack);

	if (ntohs(res.command) >> 8 != 0x47)
		serrx(EXIT_FAILURE, "expected res.command = 47??, is 0x%x",
		ntohs(res.command));
#endif

	switch (packet->req.host.atype) {
		case SOCKS_ADDR_IPV4:
			/* LINTED pointer casts may be troublesome */
			sockshost2sockaddr(&packet->req.host, (struct sockaddr *)&addr);
			break;

		case SOCKS_ADDR_DOMAIN:
			slog(LOG_DEBUG, "%s: resolve packet", function);

			bzero(&req, sizeof(req));
			req.clientid	= packet->state.msproxy.clientid;
			req.serverid	= packet->state.msproxy.serverid;

			req.command	= htons(MSPROXY_RESOLVE);
			req.packet.resolve.hostlength
			= (unsigned char)(strlen(packet->req.host.addr.domain) + 1);
			memcpy(&req.packet.resolve.host, packet->req.host.addr.domain,
			(size_t)req.packet.resolve.hostlength);

			if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
				return -1;

			if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
				return -1;

			if (ntohs(res.command) != MSPROXY_RESOLVE_ACK)
				serrx(EXIT_FAILURE, "expected res.command = 0x%x, is 0x%x",
				MSPROXY_RESOLVE_ACK, ntohs(res.command));

			addr.sin_addr.s_addr = res.packet.resolve.hostaddr;
			slog(LOG_DEBUG, "%s: IP address of %s: %s",
			function, packet->req.host.addr.domain, inet_ntoa(addr.sin_addr));

			break;

		default:
			SERRX(packet->req.host.atype);
	}


	slog(LOG_DEBUG, "%s: packet #5", function);

	bzero(&req, sizeof(req));
	req.clientid	= packet->state.msproxy.clientid;
	req.serverid	= packet->state.msproxy.serverid;
	req.command		= htons(MSPROXY_CONNECT);
	req.packet._5.magic6		= htons(0x0200);
	req.packet._5.destport	= packet->req.host.port;
	req.packet._5.destaddr	= addr.sin_addr.s_addr;

	/*
	 * need to tell server what port we will connect from, so if socket
	 * is not bound, bind it.
	 */

	len = sizeof(addr);
	/* LINTED pointer casts may be troublesome */
	if (getsockname(s, (struct sockaddr *)&addr, &len) != 0)
		return -1;

	if (!ADDRISBOUND(addr)) {
		/*
		 * Don't have any specific preference for what address to bind and
		 * proxyserver only expects to be told port.
		 */

		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		/* LINTED pointer casts may be troublesome */
		if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			return -1;

		len = sizeof(addr);
		/* LINTED pointer casts may be troublesome */
		if (getsockname(s, (struct sockaddr *)&addr, &len) != 0)
			return -1;
	}
	req.packet._5.srcport = addr.sin_port;

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (ntohs(res.command) != MSPROXY_CONNECT_ACK) {
		swarnx("expected res.command = 0x%x, is 0x%x",
		MSPROXY_CONNECT_ACK, ntohs(res.command));
		packet->res.reply = MSPROXY_NOTALLOWED;
		return -1;
	}

	packet->res.host.atype					= SOCKS_ADDR_IPV4;
	packet->res.host.port					= res.packet._5.clientport;
	packet->res.host.addr.ipv4.s_addr	= res.packet._5.clientaddr;

	if (socks_connect(s, &packet->res.host) != 0) {
		swarn("%s: failed to connect to %s",
		function, sockshost2string(&packet->res.host, string, sizeof(string)));
		return -1;
	}
	else
		slog(LOG_DEBUG, "%s: connected to %s",
		function, sockshost2string(&packet->res.host, string, sizeof(string)));

	packet->res.host.atype					= SOCKS_ADDR_IPV4;
	packet->res.host.port					= res.packet._5.clientport;
	packet->res.host.addr.ipv4.s_addr	= res.packet._5.clientaddr;

	/* LINTED pointer casts may be troublesome */
	slog(LOG_DEBUG, "%s: server will use as source address: %s",
	function, sockshost2string(&packet->res.host, string, sizeof(string)));


	slog(LOG_DEBUG, "%s: packet #6", function);

	bzero(&req, sizeof(req));
	req.clientid	= packet->state.msproxy.clientid;
	req.serverid	= packet->state.msproxy.serverid;
	req.command		= htons(MSPROXY_CONNECTED);

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;


	/* make response look sensible. */
	packet->res.version						= packet->req.version;
	packet->res.reply							= MSPROXY_SUCCESS;
	packet->res.flag							= 0;
	packet->res.auth							= NULL;

	return 0;
}

static int
msproxy_bind(s, control, packet)
	int s;
	int control;
	struct socks_t *packet;
{
	const char *function = "msproxy_bind()";
	char string[MAXSOCKSHOSTSTRING];
	struct msproxy_request_t req;
	struct msproxy_response_t res;
	struct sockaddr_in addr;
	socklen_t len;

	slog(LOG_DEBUG, function);

	bzero(&req, sizeof(req));
	req.clientid		= packet->state.msproxy.clientid;
	req.serverid		= packet->state.msproxy.serverid;
	req.command			= htons(MSPROXY_BIND);
	req.packet._3.magic2		= htons(0x0100);
	req.packet._3.bindaddr	= packet->req.host.addr.ipv4.s_addr;
	req.packet._3.bindport	= packet->req.host.port;
	req.packet._3.magic3		= htons(0x0200);
	len = sizeof(addr);
	/* LINTED pointer casts may be troublesome */
	if (getsockname(s, (struct sockaddr *)&addr, &len) != 0)
		return -1;
	req.packet._3.boundport	= addr.sin_port;

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (res.serverid != packet->state.msproxy.serverid)
		serrx(EXIT_FAILURE, "expected serverid = 0x%x, is 0x%x",
		packet->state.msproxy.serverid, res.serverid);

	if (ntohs(res.command) != MSPROXY_BIND_ACK) {
		swarnx("expected res.command = 0x%x, is 0x%x",
		MSPROXY_BIND_ACK, ntohs(res.command));
		packet->res.reply = MSPROXY_NOTALLOWED;
		return -1;
	}

	packet->state.msproxy.bindid = res.packet._3.magic10;
	packet->res.host.atype					= SOCKS_ADDR_IPV4;
	packet->res.host.port					= res.packet._3.boundport;
	packet->res.host.addr.ipv4.s_addr	= res.packet._3.boundaddr;

	slog(LOG_DEBUG, "%s: server bound for us: %s",
	function, sockshost2string(&packet->res.host, string, sizeof(string)));

	slog(LOG_DEBUG, "%s: packet #4", function);

	bzero(&req, sizeof(req));
	req.clientid	= packet->state.msproxy.clientid;
	req.serverid	= packet->state.msproxy.serverid;
	req.command		= htons(MSPROXY_BIND2);
	req.packet._4.magic1		= htons(0x0100);
	req.packet._4.magic2		= packet->state.msproxy.bindid;
	req.packet._4.magic3		= htons(0x0500);
	memcpy(req.packet._4.pad3 + 2, &addr.sin_port, sizeof(addr.sin_port));
	req.packet._4.magic4		= htons(0x0200);
	req.packet._4.boundport	= addr.sin_port;

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	if (recv_mspresponse(control, &packet->state.msproxy, &res) == -1)
		return -1;

	if (res.serverid != packet->state.msproxy.serverid)
		serrx(EXIT_FAILURE, "expected res.serverid = 0x%x, is 0x%x",
		packet->state.msproxy.serverid, res.serverid);

	if (res.clientack != 0x01)
		serrx(EXIT_FAILURE, "expected res.clientack = 0x%x, is 0x%x",
		0x01, res.clientack);

	if (ntohs(res.command) != MSPROXY_BIND2_ACK) {
		swarnx("expected res.command = %x, is 0x%x",
		MSPROXY_BIND2_ACK, ntohs(res.command));
		return -1;
	}


	slog(LOG_DEBUG, "%s: packet #5", function);

	bzero(&req, sizeof(req));
	req.clientid	= packet->state.msproxy.clientid;
	req.serverid	= packet->state.msproxy.serverid;
	req.command		= htons(MSPROXY_LISTEN);
	req.packet._5.magic6		= htons(0x0200);
	req.packet._5.destport	= packet->res.host.port;
	req.packet._5.destaddr	= packet->res.host.addr.ipv4.s_addr;

	if (send_msprequest(control, &packet->state.msproxy, &req) == -1)
		return -1;

	/*
	 * When the server accepts the client, it will send us a new
	 * controlpacket.  That will be caught in sigio().
	 */

	slog(LOG_DEBUG, "%s: waiting for forwarded connection...", function);

	/* make response look sensible. */
	packet->res.version						= packet->req.version;
	packet->res.reply							= MSPROXY_SUCCESS;
	packet->res.flag							= 0;
	packet->res.auth							= NULL;

	return 0;
}

int
msproxy_sigio(s)
	int s;
{
	const char *function = "msproxy_sigio()";
	static int init;
	const int errno_s = errno;
	struct socksfd_t *socksfd;
	int p;

	/*
	 * The msproxy protocol sends a udp packet which we must ack
	 * before it will connect to us.  We set up the controlsocket
	 * for signaldriven i/o so we can ack it asynchronously.
	 *
	 */

	SASSERTX(socks_addrisok((unsigned int)s));
	socksfd = socks_getaddr((unsigned int)s);
	SASSERTX(socksfd->state.version == MSPROXY_V2);

	if (!init) { /* could be smarter about this... */
		struct sigaction sigact;

		sigemptyset(&sigact.sa_mask);
		sigact.sa_flags	= SA_RESTART;
		sigact.sa_handler	= sigio;
		if (sigaction(SIGIO, &sigact, &oldsigio) != 0)
			return -1;

		init = 1;
	}

	if (fcntl(socksfd->control, F_SETOWN, getpid()) == -1)
		return -1;

	p = 1;
	if (ioctl(socksfd->control, FIOASYNC, &p) == -1)
		return -1;

	slog(LOG_DEBUG, "%s: set up sigio for %d", function, socksfd->control);

	errno = errno_s;
	return 0;
}

/* ARGSUSED */
static void
sigio(sig)
	int sig;
{
	const char *function = "sigio()";
	const int errno_s = errno;
	char string[MAXSOCKSHOSTSTRING];
	int i, max, dset;
	struct socksfd_t *socksfd;
	fd_set rset;
	struct timeval timeout;
	int dbits;

	slog(LOG_DEBUG, function);

	/*
	 * Find the socket we were signalled for.
	 */

	dbits = -1;
	FD_ZERO(&rset);

	for (i = 0, max = getdtablesize(); i < max; ++i) {
		if ((socksfd = socks_getaddr((unsigned int)i)) == NULL)
			continue;

		if (socksfd->state.command != SOCKS_BIND
		||  socksfd->state.version != MSPROXY_V2
		|| !socksfd->state.inprogress)
			continue;

		if (!socks_addrisok((unsigned int)i))
			continue;

		SASSERTX(fdisopen(socksfd->control));

		FD_SET(socksfd->control, &rset);
		dbits = MAX(dbits, socksfd->control);
	}

	if (dbits == -1) {
		if (oldsigio.sa_handler != NULL)
			oldsigio.sa_handler(sig);
		return; /* old signal handler. */
	}

	dset = 0;
	do {
		fd_set newrset;
		timeout.tv_sec		= 0;
		timeout.tv_usec	= 0;

		newrset = rset;
		switch (selectn(dbits + 1, &newrset, NULL, NULL, &timeout)) {
			case -1:
				SERR(-1);
				/* NOTREACHED */

			case 0:
				dset = 0;
				slog(LOG_DEBUG, "%s: no descriptors readable", function);
				if (oldsigio.sa_handler != NULL)
					oldsigio.sa_handler(sig);
				break;

			default: {
				dset = 1;
				for (i = 0, max = getdtablesize(); i < max; ++i) {
					if ((socksfd = socks_getaddr((unsigned int)i)) == NULL)
						continue;

					if (FD_ISSET(socksfd->control, &newrset)) {
						struct sockshost_t host;
						struct msproxy_request_t req;
						struct msproxy_response_t res;
						int p;

						SASSERTX(socksfd->state.command == SOCKS_BIND
						&&			socksfd->state.version == MSPROXY_V2
						&&			socksfd->state.inprogress);

						slog(LOG_DEBUG, "%s: attempting to receive bind info...",
						function);

						FD_CLR(socksfd->control, &newrset);

						if (recv_mspresponse(socksfd->control,
						&socksfd->state.msproxy, &res) == -1)
							continue;

						if (ntohs(res.command) != MSPROXY_BINDINFO) {
							swarnx("%s: expected res.command = %x, is 0x%x",
							function, MSPROXY_BINDINFO, ntohs(res.command));
							continue;
						}

						/* no need for more signals on this socket. */
						p = 0;
						if (ioctl(socksfd->control, FIOASYNC, &p) == -1) {
							swarn("%s: ioctl(socksfd->control)", function);
							continue;
						}

						slog(LOG_DEBUG, "%s: turned off sigio for %d",
						function, socksfd->control);

						/*
						 * if we asked server to bind INADDR_ANY, we don't know
						 * what address it bound until now.
						 */
						host.atype					= SOCKS_ADDR_IPV4;
						host.port					= res.packet._5.boundport;
						host.addr.ipv4.s_addr	= res.packet._5.boundaddr;
						sockshost2sockaddr(&host, &socksfd->remote);

						slog(LOG_DEBUG, "%s: server bound address %s",
						function, sockshost2string(&host, string, sizeof(string)));

						host.atype					= SOCKS_ADDR_IPV4;
						host.port					= res.packet._5.clientport;
						host.addr.ipv4.s_addr	= res.packet._5.clientaddr;
						sockshost2sockaddr(&host, &socksfd->forus.accepted);

						slog(LOG_DEBUG, "%s: server accepted: %s",
						function, sockshost2string(&host, string, sizeof(string)));

						slog(LOG_DEBUG, "%s: server will connect to us from port %d",
						function, ntohs(res.packet._5.serverport));

						/* LINTED pointer casts may be troublesome */
						TOIN(&socksfd->reply)->sin_port = res.packet._5.serverport;

						slog(LOG_DEBUG, "%s: packet #6", function);

						bzero(&req, sizeof(req));
						req.clientid	= socksfd->state.msproxy.clientid;
						req.serverid	= socksfd->state.msproxy.serverid;
						req.command		= htons(MSPROXY_BINDINFO_ACK);
						req.packet._6.magic1			= res.packet._5.magic1;
						req.packet._6.magic5			= htons(0x0100);
						req.packet._6.magic10		= socksfd->state.msproxy.bindid;
						req.packet._6.magic15		= htons(0x0100);
						req.packet._6.magic16		= socksfd->state.msproxy.bindid;
						req.packet._6.magic20		= htons(0x0200);
						req.packet._6.clientport	= res.packet._5.clientport;
						req.packet._6.clientaddr	= res.packet._5.clientaddr;
						req.packet._6.magic30		= res.packet._5.magic10;
						req.packet._6.magic35		= res.packet._5.magic15;
						req.packet._6.serverport	= res.packet._5.serverport;
						req.packet._6.srcport		= res.packet._5.srcport;
						req.packet._6.boundport		= res.packet._5.boundport;
						req.packet._6.boundaddr		= res.packet._5.boundaddr;

						if (send_msprequest(socksfd->control, &socksfd->state.msproxy,
						&req) == -1)
							continue;

						if (recv_mspresponse(socksfd->control,
						&socksfd->state.msproxy, &res) == -1)
							continue;

						/* all done.  Can accept(). */
						socksfd->state.inprogress = 0;
					}
				}
			}
		}
	} while (dset != 0);

	errno = errno_s;
}


int
recv_mspresponse(s, state, response)
	int s;
	struct msproxy_state_t *state;
	struct msproxy_response_t *response;
{
	const char *function = "recv_mspresponse()";
	/* CONSTCOND */
	char responsemem[MAX(sizeof(*response), 1024)];
	ssize_t r;

	/* CONSTCOND */
	while (1) {
		if ((r = read(s, responsemem, sizeof(responsemem))) < MSPROXY_MINLENGTH) {
			swarn("%s: expected to read atleast %d, read %d",
			function, MSPROXY_MINLENGTH, r);
			return -1;
		}

		if (mem2response(response, responsemem, (size_t)r) == NULL) {
			swarnx("%s: bad response from server", function);
			return -1;
		}

		if (state->seq_recv > 0) {
			if (response->sequence == state->seq_recv + 1)
				break; /* all ok. */
			else if (response->sequence < state->seq_recv) {
				/*
				 * sequence number less that last, sometimes this happens too,
				 * don't know why.
				 */
				slog(LOG_DEBUG, "%s: sequence (%d) < seq_recv (%d)",
				function, response->sequence, state->seq_recv);
				break;
			}
			else if (response->sequence == state->seq_recv) {
				slog(LOG_DEBUG, "%s: seq_recv: %d, dup response, seqnumber: 0x%x",
				function, state->seq_recv, response->sequence);

				if (response->clientack == state->seq_sent) {
					slog(LOG_DEBUG,
					"%s: ack matches last sent though, hoping it's a new one...",
					function);
					break;
				}
			}
			else if (response->sequence > state->seq_recv) {
				slog(LOG_DEBUG, "%s: sequence (%d) > seq_recv (%d)",
				function, response->sequence, state->seq_recv);
				break;
			}
		}
		else
			break; /* not started incrementing yet. */
	}

	state->seq_recv = response->sequence;

	return r;
}


int
send_msprequest(s, state, request)
	int s;
	struct msproxy_state_t *state;
	struct msproxy_request_t *request;
{
	const char *function = "send_msprequest()";
	ssize_t w;
	char requestmem[sizeof(struct msproxy_request_t)], *p;

	request->magic25 = htonl(MSPROXY_VERSION);
	request->serverack = state->seq_recv;
	/* don't start incrementing sequence until we are acking packet #2. */
	request->sequence
	= (unsigned char)(request->serverack >= 2 ? state->seq_sent + 1 : 0);

	memcpy(request->RWSP, "RWSP", sizeof(request->RWSP));

	p = request2mem(request, requestmem);

	/* all requests must be atleast MSPROXY_MINLENGTH it seems. */
	if (p - requestmem < MSPROXY_MINLENGTH) {
		bzero(p, (size_t)(MSPROXY_MINLENGTH - (p - requestmem)));
		p = requestmem + MSPROXY_MINLENGTH;
	}

	if ((w = write(s, requestmem, (size_t)(p - requestmem)))
	!= (ssize_t)(p - requestmem)) {
		swarn("%s: write()", function);
		return -1;
	}
	state->seq_sent = request->sequence;

	return w;
}

static char *
mem2response(res, mem, len)
	struct msproxy_response_t *res;
	char *mem;
	size_t len;
{
	const char *function = "mem2response()";

	if (len < sizeof(res->packetid))
		return NULL;
	memcpy(&res->packetid, mem, sizeof(res->packetid));
	mem += sizeof(res->packetid);
	len -= sizeof(res->packetid);

	if (len < sizeof(res->magic5))
		return NULL;
	memcpy(&res->magic5, mem, sizeof(res->magic5));
	mem += sizeof(res->magic5);
	len -= sizeof(res->magic5);

	if (len < sizeof(res->serverid))
		return NULL;
	memcpy(&res->serverid, mem, sizeof(res->serverid));
	mem += sizeof(res->serverid);
	len -= sizeof(res->serverid);

	if (len < sizeof(res->clientack))
		return NULL;
	memcpy(&res->clientack, mem, sizeof(res->clientack));
	mem += sizeof(res->clientack);
	len -= sizeof(res->clientack);

	if (len < sizeof(res->pad5))
		return NULL;
	memcpy(res->pad5, mem, sizeof(res->pad5));
	mem += sizeof(res->pad5);
	len -= sizeof(res->pad5);

	if (len < sizeof(res->sequence))
		return NULL;
	memcpy(&res->sequence, mem, sizeof(res->sequence));
	mem += sizeof(res->sequence);
	len -= sizeof(res->sequence);

	if (len < sizeof(res->pad10))
		return NULL;
	memcpy(res->pad10, mem, sizeof(res->pad10));
	mem += sizeof(res->pad10);
	len -= sizeof(res->pad10);

	if (len < sizeof(res->RWSP))
		return NULL;
	memcpy(res->RWSP, mem, sizeof(res->RWSP));
	mem += sizeof(res->RWSP);
	len -= sizeof(res->RWSP);

	if (len < sizeof(res->pad15))
		return NULL;
	memcpy(res->pad15, mem, sizeof(res->pad15));
	mem += sizeof(res->pad15);
	len -= sizeof(res->pad15);

	if (len < sizeof(res->command))
		return NULL;
	memcpy(&res->command, mem, sizeof(res->command));
	mem += sizeof(res->command);
	len -= sizeof(res->command);

	switch (ntohs(res->command)) {
		case MSPROXY_HELLO_ACK:
			if (len < sizeof(res->packet._1.pad5))
				return NULL;
			memcpy(res->packet._1.pad5, mem, sizeof(res->packet._1.pad5));
			mem += sizeof(res->packet._1.pad5);
			len -= sizeof(res->packet._1.pad5);

			if (len < sizeof(res->packet._1.magic20))
				return NULL;
			memcpy(&res->packet._1.magic20, mem, sizeof(res->packet._1.magic20));
			mem += sizeof(res->packet._1.magic20);
			len -= sizeof(res->packet._1.magic20);

			if (len < sizeof(res->packet._1.pad10))
				return NULL;
			memcpy(&res->packet._1.pad10, mem, sizeof(res->packet._1.pad10));
			mem += sizeof(res->packet._1.pad10);
			len -= sizeof(res->packet._1.pad10);

			if (len < sizeof(res->packet._1.magic30))
				return NULL;
			memcpy(&res->packet._1.magic30, mem, sizeof(res->packet._1.magic30));
			mem += sizeof(res->packet._1.magic30);
			len -= sizeof(res->packet._1.magic30);

			if (len < sizeof(res->packet._1.pad15))
				return NULL;
			memcpy(res->packet._1.pad15, mem, sizeof(res->packet._1.pad15));
			mem += sizeof(res->packet._1.pad15);
			len -= sizeof(res->packet._1.pad15);

			if (len < sizeof(res->packet._1.magic35))
				return NULL;
			memcpy(&res->packet._1.magic35, mem, sizeof(res->packet._1.magic35));
			mem += sizeof(res->packet._1.magic35);
			len -= sizeof(res->packet._1.magic35);

			if (len < sizeof(res->packet._1.pad20))
				return NULL;
			memcpy(res->packet._1.pad20, mem, sizeof(res->packet._1.pad20));
			mem += sizeof(res->packet._1.pad20);
			len -= sizeof(res->packet._1.pad20);

			if (len < sizeof(res->packet._1.magic50))
				return NULL;
			memcpy(&res->packet._1.magic50, mem, sizeof(res->packet._1.magic50));
			mem += sizeof(res->packet._1.magic50);
			len -= sizeof(res->packet._1.magic50);

			if (len < sizeof(res->packet._1.pad30))
				return NULL;
			memcpy(res->packet._1.pad30, mem, sizeof(res->packet._1.pad30));
			mem += sizeof(res->packet._1.pad30);
			len -= sizeof(res->packet._1.pad30);

			if (len < sizeof(res->packet._1.magic60))
				return NULL;
			memcpy(&res->packet._1.magic60, mem, sizeof(res->packet._1.magic60));
			mem += sizeof(res->packet._1.magic60);
			len -= sizeof(res->packet._1.magic60);

			if (len < sizeof(res->packet._1.pad35))
				return NULL;
			memcpy(res->packet._1.pad35, mem, sizeof(res->packet._1.pad35));
			mem += sizeof(res->packet._1.pad35);
			len -= sizeof(res->packet._1.pad35);

			if (len < sizeof(res->packet._1.magic65))
				return NULL;
			memcpy(&res->packet._1.magic65, mem, sizeof(res->packet._1.magic65));
			mem += sizeof(res->packet._1.magic65);
			len -= sizeof(res->packet._1.magic65);

			if (len < sizeof(res->packet._1.pad40))
				return NULL;
			memcpy(res->packet._1.pad40, mem, sizeof(res->packet._1.pad40));
			mem += sizeof(res->packet._1.pad40);
			len -= sizeof(res->packet._1.pad40);

			if (len < sizeof(res->packet._1.udpport))
				return NULL;
			memcpy(&res->packet._1.udpport, mem, sizeof(res->packet._1.udpport));
			mem += sizeof(res->packet._1.udpport);
			len -= sizeof(res->packet._1.udpport);

			if (len < sizeof(res->packet._1.udpaddr))
				return NULL;
			memcpy(&res->packet._1.udpaddr, mem, sizeof(res->packet._1.udpaddr));
			mem += sizeof(res->packet._1.udpaddr);
			len -= sizeof(res->packet._1.udpaddr);

			break;

		case MSPROXY_USERINFO_ACK:
			if (len < sizeof(res->packet._2.pad5))
				return NULL;
			memcpy(res->packet._2.pad5, mem, sizeof(res->packet._2.pad5));
			mem += sizeof(res->packet._2.pad5);
			len -= sizeof(res->packet._2.pad5);

			if (len < sizeof(res->packet._2.magic5))
				return NULL;
			memcpy(&res->packet._2.magic5, mem, sizeof(res->packet._2.magic5));
			mem += sizeof(res->packet._2.magic5);
			len -= sizeof(res->packet._2.magic5);

			break;

		case MSPROXY_BIND_ACK:
		case MSPROXY_SOMETHING_1_ACK:
			if (len < sizeof(res->packet._3.pad1))
				return NULL;
			memcpy(res->packet._3.pad1, mem, sizeof(res->packet._3.pad1));
			mem += sizeof(res->packet._3.pad1);
			len -= sizeof(res->packet._3.pad1);

			if (len < sizeof(res->packet._3.magic10))
				return NULL;
			memcpy(&res->packet._3.magic10, mem, sizeof(res->packet._3.magic10));
			mem += sizeof(res->packet._3.magic10);
			len -= sizeof(res->packet._3.magic10);

			if (len < sizeof(res->packet._3.pad3))
				return NULL;
			memcpy(res->packet._3.pad3, mem, sizeof(res->packet._3.pad3));
			mem += sizeof(res->packet._3.pad3);
			len -= sizeof(res->packet._3.pad3);

			if (len < sizeof(res->packet._3.boundport))
				return NULL;
			memcpy(&res->packet._3.boundport, mem,
			sizeof(res->packet._3.boundport));
			mem += sizeof(res->packet._3.boundport);
			len -= sizeof(res->packet._3.boundport);

			if (len < sizeof(res->packet._3.boundaddr))
				return NULL;
			memcpy(&res->packet._3.boundaddr, mem,
			sizeof(res->packet._3.boundaddr));
			mem += sizeof(res->packet._3.boundaddr);
			len -= sizeof(res->packet._3.boundaddr);

			if (len < sizeof(res->packet._3.pad10))
				return NULL;
			memcpy(res->packet._3.pad10, mem, sizeof(res->packet._3.pad10));
			mem += sizeof(res->packet._3.pad10);
			len -= sizeof(res->packet._3.pad10);

			if (len < sizeof(res->packet._3.magic15))
				return NULL;
			memcpy(&res->packet._3.magic15, mem, sizeof(res->packet._3.magic15));
			mem += sizeof(res->packet._3.magic15);
			len -= sizeof(res->packet._3.magic15);

			if (len < sizeof(res->packet._3.pad15))
				return NULL;
			memcpy(res->packet._3.pad15, mem, sizeof(res->packet._3.pad15));
			mem += sizeof(res->packet._3.pad15);
			len -= sizeof(res->packet._3.pad15);

			if (len < sizeof(res->packet._3.NTLMSSP))
				return NULL;
			memcpy(res->packet._3.NTLMSSP, mem, sizeof(res->packet._3.NTLMSSP));
			mem += sizeof(res->packet._3.NTLMSSP);
			len -= sizeof(res->packet._3.NTLMSSP);

			if (len < sizeof(res->packet._3.magic50))
				return NULL;
			memcpy(&res->packet._3.magic50, mem, sizeof(res->packet._3.magic50));
			mem += sizeof(res->packet._3.magic50);
			len -= sizeof(res->packet._3.magic50);

			if (len < sizeof(res->packet._3.pad50))
				return NULL;
			memcpy(res->packet._3.pad50, mem, sizeof(res->packet._3.pad50));
			mem += sizeof(res->packet._3.pad50);
			len -= sizeof(res->packet._3.pad50);

			if (len < sizeof(res->packet._3.magic55))
				return NULL;
			memcpy(&res->packet._3.magic55, mem, sizeof(res->packet._3.magic55));
			mem += sizeof(res->packet._3.magic55);
			len -= sizeof(res->packet._3.magic55);

			if (len < sizeof(res->packet._3.magic60))
				return NULL;
			memcpy(&res->packet._3.magic60, mem, sizeof(res->packet._3.magic60));
			mem += sizeof(res->packet._3.magic60);
			len -= sizeof(res->packet._3.magic60);

			if (len < sizeof(res->packet._3.magic65))
				return NULL;
			memcpy(&res->packet._3.magic65, mem, sizeof(res->packet._3.magic65));
			mem += sizeof(res->packet._3.magic65);
			len -= sizeof(res->packet._3.magic65);

			if (len < sizeof(res->packet._3.pad60))
				return NULL;
			memcpy(res->packet._3.pad60, mem, sizeof(res->packet._3.pad60));
			mem += sizeof(res->packet._3.pad60);
			len -= sizeof(res->packet._3.pad60);

			if (len < sizeof(res->packet._3.magic70))
				return NULL;
			memcpy(&res->packet._3.magic70, mem, sizeof(res->packet._3.magic70));
			mem += sizeof(res->packet._3.magic70);
			len -= sizeof(res->packet._3.magic70);

			if (len < sizeof(res->packet._3.magic75))
				return NULL;
			memcpy(&res->packet._3.magic75, mem, sizeof(res->packet._3.magic75));
			mem += sizeof(res->packet._3.magic75);
			len -= sizeof(res->packet._3.magic75);

			if (len < sizeof(res->packet._3.pad70))
				return NULL;
			memcpy(res->packet._3.pad70, mem, sizeof(res->packet._3.pad70));
			mem += sizeof(res->packet._3.pad70);
			len -= sizeof(res->packet._3.pad70);

			if (len > sizeof(res->packet._3.ntdomain))
				swarnx("hmm, ntdomain length is %d, our max is %d?",
				len, sizeof(res->packet._3.ntdomain) - 1);
			memcpy(res->packet._3.ntdomain, mem,
			MIN(len, sizeof(res->packet._3.ntdomain) - 1));
			res->packet._3.ntdomain[len] = NUL;
			mem += len;
			len -= len;

			break;

		case MSPROXY_SOMETHING_2_ACK:
		case MSPROXY_SOMETHING_2_ACK2:
		case MSPROXY_BIND2_ACK:
			if (len < sizeof(res->packet._4.pad5))
				return NULL;
			memcpy(res->packet._4.pad5, mem, sizeof(res->packet._4.pad5));
			mem += sizeof(res->packet._4.pad5);
			len -= sizeof(res->packet._4.pad5);
			break;

		case MSPROXY_RESOLVE_ACK: {
			if (len < sizeof(res->packet.resolve.addroffset))
				return NULL;
			memcpy(&res->packet.resolve.addroffset, mem,
			sizeof(res->packet.resolve.addroffset));
			mem += sizeof(res->packet.resolve.addroffset);
			len -= sizeof(res->packet.resolve.addroffset);

			if (len < sizeof(res->packet.resolve.pad5))
				return NULL;
			memcpy(res->packet.resolve.pad5, mem,
			sizeof(res->packet.resolve.pad5));
			mem += sizeof(res->packet.resolve.pad5);
			len -= sizeof(res->packet.resolve.pad5);

			mem += res->packet.resolve.addroffset;

			if (len < sizeof(res->packet.resolve.hostaddr))
				return NULL;
			memcpy(&res->packet.resolve.hostaddr, mem,
			sizeof(res->packet.resolve.hostaddr));
			mem += sizeof(res->packet.resolve.hostaddr);
			len -= sizeof(res->packet.resolve.hostaddr);

			break;
		}

		case MSPROXY_CONNECT_ACK:
		case MSPROXY_BINDINFO:
			if (len < sizeof(res->packet._5.magic1))
				return NULL;
			memcpy(&res->packet._5.magic1, mem, sizeof(res->packet._5.magic1));
			mem += sizeof(res->packet._5.magic1);
			len -= sizeof(res->packet._5.magic1);

			if (len < sizeof(res->packet._5.pad5))
				return NULL;
			memcpy(res->packet._5.pad5, mem, sizeof(res->packet._5.pad5));
			mem += sizeof(res->packet._5.pad5);
			len -= sizeof(res->packet._5.pad5);

			if (len < sizeof(res->packet._5.clientport))
				return NULL;
			memcpy(&res->packet._5.clientport, mem,
			sizeof(res->packet._5.clientport));
			mem += sizeof(res->packet._5.clientport);
			len -= sizeof(res->packet._5.clientport);

			if (len < sizeof(res->packet._5.clientaddr))
				return NULL;
			memcpy(&res->packet._5.clientaddr, mem,
			sizeof(res->packet._5.clientaddr));
			mem += sizeof(res->packet._5.clientaddr);
			len -= sizeof(res->packet._5.clientaddr);

			if (len < sizeof(res->packet._5.magic10))
				return NULL;
			memcpy(&res->packet._5.magic10, mem, sizeof(res->packet._5.magic10));
			mem += sizeof(res->packet._5.magic10);
			len -= sizeof(res->packet._5.magic10);

			if (len < sizeof(res->packet._5.magic15))
				return NULL;
			memcpy(&res->packet._5.magic15, mem, sizeof(res->packet._5.magic15));
			mem += sizeof(res->packet._5.magic15);
			len -= sizeof(res->packet._5.magic15);

			if (len < sizeof(res->packet._5.serverport))
				return NULL;
			memcpy(&res->packet._5.serverport, mem,
			sizeof(res->packet._5.serverport));
			mem += sizeof(res->packet._5.serverport);
			len -= sizeof(res->packet._5.serverport);

			if (len < sizeof(res->packet._5.srcport))
				return NULL;
			memcpy(&res->packet._5.srcport, mem, sizeof(res->packet._5.srcport));
			mem += sizeof(res->packet._5.srcport);
			len -= sizeof(res->packet._5.srcport);

			if (len < sizeof(res->packet._5.boundport))
				return NULL;
			memcpy(&res->packet._5.boundport, mem,
			sizeof(res->packet._5.boundport));
			mem += sizeof(res->packet._5.boundport);
			len -= sizeof(res->packet._5.boundport);

			if (len < sizeof(res->packet._5.boundaddr))
				return NULL;
			memcpy(&res->packet._5.boundaddr, mem,
			sizeof(res->packet._5.boundaddr));
			mem += sizeof(res->packet._5.boundaddr);
			len -= sizeof(res->packet._5.boundaddr);

			if (len < sizeof(res->packet._5.pad10))
				return NULL;
			memcpy(res->packet._5.pad10, mem, sizeof(res->packet._5.pad10));
			mem += sizeof(res->packet._5.pad10);
			len -= sizeof(res->packet._5.pad10);

			break;

		case MSPROXY_CONNECT_AUTHFAILED:
		case MSPROXY_BIND_AUTHFAILED:
			break;

		default:
			if (ntohs(res->command) >> 8 == MSPROXY_CONNREFUSED
			||  ntohs(res->command) >> 12 == MSPROXY_CONNREFUSED)
				;
			else
				slog(LOG_DEBUG, "%s: unknown command in msproxy reply: 0x%x",
				function, ntohs(res->command));
	}

	return mem;
}

static char *
request2mem(req, mem)
	const struct msproxy_request_t *req;
	char *mem;
{

	memcpy(mem, &req->clientid, sizeof(req->clientid));
	mem += sizeof(req->clientid);

	memcpy(mem, &req->magic25, sizeof(req->magic25));
	mem += sizeof(req->magic25);

	memcpy(mem, &req->serverid, sizeof(req->serverid));
	mem += sizeof(req->serverid);

	memcpy(mem, &req->serverack, sizeof(req->serverack));
	mem += sizeof(req->serverack);

	memcpy(mem, &req->pad10, sizeof(req->pad10));
	mem += sizeof(req->pad10);

	memcpy(mem, &req->sequence, sizeof(req->sequence));
	mem += sizeof(req->sequence);

	memcpy(mem, &req->pad11, sizeof(req->pad11));
	mem += sizeof(req->pad11);

	memcpy(mem, &req->RWSP, sizeof(req->RWSP));
	mem += sizeof(req->RWSP);

	memcpy(mem, &req->pad15, sizeof(req->pad15));
	mem += sizeof(req->pad15);

	memcpy(mem, &req->command, sizeof(req->command));
	mem += sizeof(req->command);

	switch (ntohs(req->command)) {
		case MSPROXY_HELLO:
			memcpy(mem, &req->packet._1.pad1, sizeof(req->packet._1.pad1));
			mem += sizeof(req->packet._1.pad1);

			memcpy(mem, &req->packet._1.magic3, sizeof(req->packet._1.magic3));
			mem += sizeof(req->packet._1.magic3);

			memcpy(mem, &req->packet._1.pad3, sizeof(req->packet._1.pad3));
			mem += sizeof(req->packet._1.pad3);

			memcpy(mem, &req->packet._1.magic5, sizeof(req->packet._1.magic5));
			mem += sizeof(req->packet._1.magic5);

			memcpy(mem, &req->packet._1.pad5, sizeof(req->packet._1.pad5));
			mem += sizeof(req->packet._1.pad5);

			memcpy(mem, &req->packet._1.magic10, sizeof(req->packet._1.magic10));
			mem += sizeof(req->packet._1.magic10);

			memcpy(mem, &req->packet._1.pad6, sizeof(req->packet._1.pad6));
			mem += sizeof(req->packet._1.pad6);

			memcpy(mem, &req->packet._1.magic15, sizeof(req->packet._1.magic15));
			mem += sizeof(req->packet._1.magic15);

			memcpy(mem, &req->packet._1.pad10, sizeof(req->packet._1.pad10));
			mem += sizeof(req->packet._1.pad10);

			memcpy(mem, &req->packet._1.magic20, sizeof(req->packet._1.magic20));
			mem += sizeof(req->packet._1.magic20);

			memcpy(mem, &req->packet._1.magic25, sizeof(req->packet._1.magic25));
			mem += sizeof(req->packet._1.magic25);

			memcpy(mem, &req->packet._1.magic30, sizeof(req->packet._1.magic30));
			mem += sizeof(req->packet._1.magic30);

			memcpy(mem, &req->packet._1.pad20, sizeof(req->packet._1.pad20));
			mem += sizeof(req->packet._1.pad20);

			memcpy(mem, &req->packet._1.magic35, sizeof(req->packet._1.magic35));
			mem += sizeof(req->packet._1.magic35);

			memcpy(mem, &req->packet._1.pad30, sizeof(req->packet._1.pad30));
			mem += sizeof(req->packet._1.pad30);

			memcpy(mem, &req->packet._1.magic40, sizeof(req->packet._1.magic40));
			mem += sizeof(req->packet._1.magic40);

			memcpy(mem, &req->packet._1.pad40, sizeof(req->packet._1.pad40));
			mem += sizeof(req->packet._1.pad40);

			memcpy(mem, &req->packet._1.magic45, sizeof(req->packet._1.magic45));
			mem += sizeof(req->packet._1.magic45);

			memcpy(mem, &req->packet._1.pad45, sizeof(req->packet._1.pad45));
			mem += sizeof(req->packet._1.pad45);

			memcpy(mem, &req->packet._1.magic50, sizeof(req->packet._1.magic50));
			mem += sizeof(req->packet._1.magic50);

			memcpy(mem, &req->packet._1.pad50, sizeof(req->packet._1.pad50));
			mem += sizeof(req->packet._1.pad50);

			strcpy(mem, req->username);
			mem += strlen(req->username) + 1;

			strcpy(mem, req->unknown);
			mem += strlen(req->unknown) + 1;

			strcpy(mem, req->executable);
			mem += strlen(req->executable) + 1;

			strcpy(mem, req->clienthost);
			mem += strlen(req->clienthost) + 1;

			break;

		case MSPROXY_USERINFO:
			memcpy(mem, &req->packet._2.pad1, sizeof(req->packet._2.pad1));
			mem += sizeof(req->packet._2.pad1);

			memcpy(mem, &req->packet._2.magic3, sizeof(req->packet._2.magic3));
			mem += sizeof(req->packet._2.magic3);

			memcpy(mem, &req->packet._2.pad3, sizeof(req->packet._2.pad3));
			mem += sizeof(req->packet._2.pad3);

			memcpy(mem, &req->packet._2.magic5, sizeof(req->packet._2.magic5));
			mem += sizeof(req->packet._2.magic5);

			memcpy(mem, &req->packet._2.pad5, sizeof(req->packet._2.pad5));
			mem += sizeof(req->packet._2.pad5);

			memcpy(mem, &req->packet._2.magic10, sizeof(req->packet._2.magic10));
			mem += sizeof(req->packet._2.magic10);

			memcpy(mem, &req->packet._2.pad10, sizeof(req->packet._2.pad10));
			mem += sizeof(req->packet._2.pad10);

			memcpy(mem, &req->packet._2.magic15, sizeof(req->packet._2.magic15));
			mem += sizeof(req->packet._2.magic15);

			memcpy(mem, &req->packet._2.pad15, sizeof(req->packet._2.pad15));
			mem += sizeof(req->packet._2.pad15);

			memcpy(mem, &req->packet._2.magic20, sizeof(req->packet._2.magic20));
			mem += sizeof(req->packet._2.magic20);

			memcpy(mem, &req->packet._2.magic25, sizeof(req->packet._2.magic25));
			mem += sizeof(req->packet._2.magic25);

			memcpy(mem, &req->packet._2.magic30, sizeof(req->packet._2.magic30));
			mem += sizeof(req->packet._2.magic30);

			memcpy(mem, &req->packet._2.pad20, sizeof(req->packet._2.pad20));
			mem += sizeof(req->packet._2.pad20);

			memcpy(mem, &req->packet._2.magic35, sizeof(req->packet._2.magic35));
			mem += sizeof(req->packet._2.magic35);

			memcpy(mem, &req->packet._2.pad25, sizeof(req->packet._2.pad25));
			mem += sizeof(req->packet._2.pad25);

			memcpy(mem, &req->packet._2.magic35, sizeof(req->packet._2.magic35));
			mem += sizeof(req->packet._2.magic35);

			memcpy(mem, &req->packet._2.pad25, sizeof(req->packet._2.pad25));
			mem += sizeof(req->packet._2.pad25);

			memcpy(mem, &req->packet._2.magic50, sizeof(req->packet._2.magic50));
			mem += sizeof(req->packet._2.magic50);

			memcpy(mem, &req->packet._2.pad50, sizeof(req->packet._2.pad50));
			mem += sizeof(req->packet._2.pad50);

			memcpy(mem, &req->packet._2.magic55, sizeof(req->packet._2.magic55));
			mem += sizeof(req->packet._2.magic55);

			memcpy(mem, &req->packet._2.pad55, sizeof(req->packet._2.pad55));
			mem += sizeof(req->packet._2.pad55);

			memcpy(mem, &req->packet._2.magic60, sizeof(req->packet._2.magic60));
			mem += sizeof(req->packet._2.magic60);

			strcpy(mem, req->username);
			mem += strlen(req->username) + 1;

			strcpy(mem, req->unknown);
			mem += strlen(req->unknown) + 1;

			strcpy(mem, req->executable);
			mem += strlen(req->executable) + 1;

			strcpy(mem, req->clienthost);
			mem += strlen(req->clienthost) + 1;

			break;

		case MSPROXY_BIND:
		case MSPROXY_SOMETHING:
			memcpy(mem, &req->packet._3.pad1, sizeof(req->packet._3.pad1));
			mem += sizeof(req->packet._3.pad1);

			memcpy(mem, &req->packet._3.magic2, sizeof(req->packet._3.magic2));
			mem += sizeof(req->packet._3.magic2);

			memcpy(mem, &req->packet._3.pad10, sizeof(req->packet._3.pad10));
			mem += sizeof(req->packet._3.pad10);

			memcpy(mem, &req->packet._3.bindaddr, sizeof(req->packet._3.bindaddr));
			mem += sizeof(req->packet._3.bindaddr);

			memcpy(mem, &req->packet._3.bindport, sizeof(req->packet._3.bindport));
			mem += sizeof(req->packet._3.bindport);

			memcpy(mem, &req->packet._3.pad15, sizeof(req->packet._3.pad15));
			mem += sizeof(req->packet._3.pad15);

			memcpy(mem, &req->packet._3.magic3, sizeof(req->packet._3.magic3));
			mem += sizeof(req->packet._3.magic3);

			memcpy(mem, &req->packet._3.boundport,
			sizeof(req->packet._3.boundport));
			mem += sizeof(req->packet._3.boundport);

			memcpy(mem, &req->packet._3.pad20, sizeof(req->packet._3.pad20));
			mem += sizeof(req->packet._3.pad20);

			memcpy(mem, &req->packet._3.NTLMSSP, sizeof(req->packet._3.NTLMSSP));
			mem += sizeof(req->packet._3.NTLMSSP);

			memcpy(mem, &req->packet._3.magic5, sizeof(req->packet._3.magic5));
			mem += sizeof(req->packet._3.magic5);

			memcpy(mem, &req->packet._3.pad25, sizeof(req->packet._3.pad25));
			mem += sizeof(req->packet._3.pad25);

			memcpy(mem, &req->packet._3.magic10, sizeof(req->packet._3.magic10));
			mem += sizeof(req->packet._3.magic10);

			memcpy(mem, &req->packet._3.magic15, sizeof(req->packet._3.magic15));
			mem += sizeof(req->packet._3.magic15);

			memcpy(mem, &req->packet._3.magic20, sizeof(req->packet._3.magic20));
			mem += sizeof(req->packet._3.magic20);

			memcpy(mem, &req->packet._3.pad30, sizeof(req->packet._3.pad30));
			mem += sizeof(req->packet._3.pad30);

			memcpy(mem, &req->packet._3.magic25, sizeof(req->packet._3.magic25));
			mem += sizeof(req->packet._3.magic25);

			memcpy(mem, &req->packet._3.magic30, sizeof(req->packet._3.magic30));
			mem += sizeof(req->packet._3.magic30);

			memcpy(mem, &req->packet._3.pad40, sizeof(req->packet._3.pad40));
			mem += sizeof(req->packet._3.pad40);

			memcpy(mem, &req->packet._3.magic50, sizeof(req->packet._3.magic50));
			mem += sizeof(req->packet._3.magic50);

			memcpy(mem, &req->packet._3.pad50, sizeof(req->packet._3.pad50));
			mem += sizeof(req->packet._3.pad50);

			memcpy(mem, &req->packet._3.magic55, sizeof(req->packet._3.magic55));
			mem += sizeof(req->packet._3.magic55);

			memcpy(mem, &req->packet._3.pad55, sizeof(req->packet._3.pad55));
			mem += sizeof(req->packet._3.pad55);

			break;

		case MSPROXY_BIND2:
		case MSPROXY_SOMETHING_2:
			memcpy(mem, &req->packet._4.pad1, sizeof(req->packet._4.pad1));
			mem += sizeof(req->packet._4.pad1);

			memcpy(mem, &req->packet._4.magic1, sizeof(req->packet._4.magic1));
			mem += sizeof(req->packet._4.magic1);

			memcpy(mem, &req->packet._4.magic2, sizeof(req->packet._4.magic2));
			mem += sizeof(req->packet._4.magic2);

			memcpy(mem, &req->packet._4.pad2, sizeof(req->packet._4.pad2));
			mem += sizeof(req->packet._4.pad2);

			memcpy(mem, &req->packet._4.magic3, sizeof(req->packet._4.magic3));
			mem += sizeof(req->packet._4.magic3);

			memcpy(mem, &req->packet._4.pad3, sizeof(req->packet._4.pad3));
			mem += sizeof(req->packet._4.pad3);

			memcpy(mem, &req->packet._4.magic4, sizeof(req->packet._4.magic4));
			mem += sizeof(req->packet._4.magic4);

			memcpy(mem, &req->packet._4.boundport,
			sizeof(req->packet._4.boundport));
			mem += sizeof(req->packet._4.boundport);

			memcpy(mem, &req->packet._4.pad4, sizeof(req->packet._4.pad4));
			mem += sizeof(req->packet._4.pad4);

			memcpy(mem, &req->packet._4.NTLMSSP, sizeof(req->packet._4.NTLMSSP));
			mem += sizeof(req->packet._4.NTLMSSP);

			memcpy(mem, &req->packet._4.magic5, sizeof(req->packet._4.magic5));
			mem += sizeof(req->packet._4.magic5);

			memcpy(mem, &req->packet._4.pad5, sizeof(req->packet._4.pad5));
			mem += sizeof(req->packet._4.pad5);

			memcpy(mem, &req->packet._4.magic10, sizeof(req->packet._4.magic10));
			mem += sizeof(req->packet._4.magic10);

			memcpy(mem, &req->packet._4.magic10, sizeof(req->packet._4.magic10));
			mem += sizeof(req->packet._4.magic10);

			memcpy(mem, &req->packet._4.magic20, sizeof(req->packet._4.magic20));
			mem += sizeof(req->packet._4.magic20);

			memcpy(mem, &req->packet._4.pad10, sizeof(req->packet._4.pad10));
			mem += sizeof(req->packet._4.pad10);

			memcpy(mem, &req->packet._4.magic30, sizeof(req->packet._4.magic30));
			mem += sizeof(req->packet._4.magic30);

			memcpy(mem, &req->packet._4.pad15, sizeof(req->packet._4.pad15));
			mem += sizeof(req->packet._4.pad15);

			memcpy(mem, &req->packet._4.magic35, sizeof(req->packet._4.magic35));
			mem += sizeof(req->packet._4.magic35);

			memcpy(mem, &req->packet._4.magic40, sizeof(req->packet._4.magic40));
			mem += sizeof(req->packet._4.magic40);

			memcpy(mem, &req->packet._4.magic45, sizeof(req->packet._4.magic45));
			mem += sizeof(req->packet._4.magic45);

			memcpy(mem, &req->packet._4.pad20, sizeof(req->packet._4.pad20));
			mem += sizeof(req->packet._4.pad20);

			memcpy(mem, &req->packet._4.magic50, sizeof(req->packet._4.magic50));
			mem += sizeof(req->packet._4.magic50);

			memcpy(mem, &req->packet._4.magic55, sizeof(req->packet._4.magic55));
			mem += sizeof(req->packet._4.magic55);

			memcpy(mem, &req->packet._4.magic60, sizeof(req->packet._4.magic60));
			mem += sizeof(req->packet._4.magic60);

			memcpy(mem, &req->packet._4.pad25, sizeof(req->packet._4.pad25));
			mem += sizeof(req->packet._4.pad25);

			memcpy(mem, &req->packet._4.magic65, sizeof(req->packet._4.magic65));
			mem += sizeof(req->packet._4.magic65);

			memcpy(mem, &req->packet._4.magic70, sizeof(req->packet._4.magic70));
			mem += sizeof(req->packet._4.magic70);

			memcpy(mem, &req->packet._4.magic75, sizeof(req->packet._4.magic75));
			mem += sizeof(req->packet._4.magic75);

			break;

		case MSPROXY_RESOLVE:
			memcpy(mem, &req->packet.resolve.hostlength,
			sizeof(req->packet.resolve.hostlength));
			mem += sizeof(req->packet.resolve.hostlength);

			memcpy(mem, &req->packet.resolve.pad1,
			sizeof(req->packet.resolve.pad1));
			mem += sizeof(req->packet.resolve.pad1);

			memcpy(mem, &req->packet.resolve.host,
			(size_t)req->packet.resolve.hostlength);
			mem += req->packet.resolve.hostlength;

			break;

		case MSPROXY_LISTEN:
		case MSPROXY_CONNECT:
			memcpy(mem, &req->packet._5.magic1, sizeof(req->packet._5.magic1));
			mem += sizeof(req->packet._5.magic1);

			memcpy(mem, &req->packet._5.pad1, sizeof(req->packet._5.pad1));
			mem += sizeof(req->packet._5.pad1);

			memcpy(mem, &req->packet._5.magic3, sizeof(req->packet._5.magic3));
			mem += sizeof(req->packet._5.magic3);

			memcpy(mem, &req->packet._5.pad5, sizeof(req->packet._5.pad5));
			mem += sizeof(req->packet._5.pad5);

			memcpy(mem, &req->packet._5.magic6, sizeof(req->packet._5.magic6));
			mem += sizeof(req->packet._5.magic6);

			memcpy(mem, &req->packet._5.destport, sizeof(req->packet._5.destport));
			mem += sizeof(req->packet._5.destport);

			memcpy(mem, &req->packet._5.destaddr, sizeof(req->packet._5.destaddr));
			mem += sizeof(req->packet._5.destaddr);

			memcpy(mem, &req->packet._5.pad10, sizeof(req->packet._5.pad10));
			mem += sizeof(req->packet._5.pad10);

			memcpy(mem, &req->packet._5.magic10, sizeof(req->packet._5.magic10));
			mem += sizeof(req->packet._5.magic10);

			memcpy(mem, &req->packet._5.pad15, sizeof(req->packet._5.pad15));
			mem += sizeof(req->packet._5.pad15);

			memcpy(mem, &req->packet._5.srcport, sizeof(req->packet._5.srcport));
			mem += sizeof(req->packet._5.srcport);

			memcpy(mem, &req->packet._5.pad20, sizeof(req->packet._5.pad20));
			mem += sizeof(req->packet._5.pad20);
			strcpy(mem, req->executable);

			break;

		case MSPROXY_BINDINFO_ACK:
		case MSPROXY_CONNECTED:
			memcpy(mem, &req->packet._6.magic1, sizeof(req->packet._6.magic1));
			mem += sizeof(req->packet._6.magic1);

			memcpy(mem, req->packet._6.pad5, sizeof(req->packet._6.pad5));
			mem += sizeof(req->packet._6.pad5);

			memcpy(mem, &req->packet._6.magic5, sizeof(req->packet._6.magic5));
			mem += sizeof(req->packet._6.magic5);

			memcpy(mem, &req->packet._6.magic10, sizeof(req->packet._6.magic10));
			mem += sizeof(req->packet._6.magic10);

			memcpy(mem, req->packet._6.pad10, sizeof(req->packet._6.pad10));
			mem += sizeof(req->packet._6.pad10);

			memcpy(mem, &req->packet._6.magic15, sizeof(req->packet._6.magic15));
			mem += sizeof(req->packet._6.magic15);

			memcpy(mem, &req->packet._6.magic16, sizeof(req->packet._6.magic16));
			mem += sizeof(req->packet._6.magic16);

			memcpy(mem, &req->packet._6.magic20, sizeof(req->packet._6.magic20));
			mem += sizeof(req->packet._6.magic20);

			memcpy(mem, &req->packet._6.clientport,
			sizeof(req->packet._6.clientport));
			mem += sizeof(req->packet._6.clientport);

			memcpy(mem, &req->packet._6.clientaddr,
			sizeof(req->packet._6.clientaddr));
			mem += sizeof(req->packet._6.clientaddr);

			memcpy(mem, &req->packet._6.magic30, sizeof(req->packet._6.magic30));
			mem += sizeof(req->packet._6.magic30);

			memcpy(mem, &req->packet._6.magic35, sizeof(req->packet._6.magic35));
			mem += sizeof(req->packet._6.magic35);

			memcpy(mem, &req->packet._6.serverport,
			sizeof(req->packet._6.serverport));
			mem += sizeof(req->packet._6.serverport);

			memcpy(mem, &req->packet._6.srcport, sizeof(req->packet._6.srcport));
			mem += sizeof(req->packet._6.srcport);

			memcpy(mem, &req->packet._6.boundport,
			sizeof(req->packet._6.boundport));
			mem += sizeof(req->packet._6.boundport);

			memcpy(mem, &req->packet._6.boundaddr,
			sizeof(req->packet._6.boundaddr));
			mem += sizeof(req->packet._6.boundaddr);

			memcpy(mem, req->packet._6.pad30, sizeof(req->packet._6.pad30));
			mem += sizeof(req->packet._6.pad30);

			break;

		case MSPROXY_SESSIONEND:
			break;

		default:
			SERRX(req->command);
	}

	return mem;
}

void
msproxy_sessionsend(void)
{
	const char *function = "msproxy_sessionsend()";
	int i, max;
	struct socksfd_t *socksfd;

	slog(LOG_DEBUG, function);

	for (i = 0, max = getdtablesize(); i < max; ++i) {
		if ((socksfd = socks_getaddr((unsigned int)i)) == NULL)
			continue;

		if (socksfd->state.version != MSPROXY_V2)
			continue;

		msproxy_sessionend(socksfd->control, &socksfd->state.msproxy);
	}
}

static void
msproxy_sessionend(s, msproxy)
	int s;
	struct msproxy_state_t *msproxy;
{
	const char *function = "msproxy_sessionend()";
	struct msproxy_request_t req;

	slog(LOG_DEBUG, function);

	bzero(&req, sizeof(req));
	*req.username		= NUL;
	*req.unknown		= NUL;
	*req.executable	= NUL;
	*req.clienthost	= NUL;
	req.clientid	= msproxy->clientid;
	req.serverid	= msproxy->serverid;
	req.command		= htons(MSPROXY_SESSIONEND);

	send_msprequest(s, msproxy, &req);
}

/* ARGSUSED */
static void
msproxy_keepalive(sig)
	int sig;
{
	const char *function = "msproxy_keepalive()";
	struct msproxy_request_t req;
	struct msproxy_response_t res;
	struct socksfd_t *socksfd;
	int i, max;

	slog(LOG_DEBUG, function);

	for (i = 0, max = getdtablesize(); i < max; ++i) {
		if ((socksfd = socks_getaddr((unsigned int)i)) == NULL)
			continue;

		if (socksfd->state.version != MSPROXY_V2
		||  socksfd->state.inprogress)
			continue;

		slog(LOG_DEBUG, "%s: sending keepalive packet", function);

		bzero(&req, sizeof(req));
		req.clientid	= socksfd->state.msproxy.clientid;
		req.serverid	= socksfd->state.msproxy.serverid;
		req.command		= htons(MSPROXY_HELLO);

		if (send_msprequest(socksfd->control, &socksfd->state.msproxy, &req)
		== -1)
			return;

		if (recv_mspresponse(socksfd->control, &socksfd->state.msproxy, &res)
		== -1)
			return;
	}
}
