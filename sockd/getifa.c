/*
 * $Id: getifa.c,v 1.20 2001/11/11 13:38:33 michaels Exp $
 *
 * Copyright (c) 2001
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
 * This code originated from From Tom Chan <tchan@austin.rr.com>.
 */

#include "common.h"

static const char rcsid[] =
"$Id: getifa.c,v 1.20 2001/11/11 13:38:33 michaels Exp $";


/*===========================================================================
 * Given a destination address, getifa() returns the local source address
 * that will be selected by the OS to connect to that destination address.
 *==========================================================================*/
#include	<net/route.h>           /* RTA_xxx constants */
#ifdef linux
#include	<asm/types.h>
#include	<linux/netlink.h>
#include	<linux/rtnetlink.h>
#endif /* linux */

__BEGIN_DECLS

static struct in_addr
getdefaultexternal __P((void));
/*
 * Returns the default ipaddress to use for external connections.
 */

static int
isonexternal __P((const struct sockaddr *addr));

__END_DECLS

#ifdef linux
typedef unsigned char uchar_t;

struct in_addr
getifa(destaddr)
	struct in_addr destaddr;
{
	const char *function = "getifa()";
	struct {
		struct nlmsghdr nh;
		struct rtmsg   rt;
		char           attrbuf[512];
	} req;
	struct rtattr *rta;
	char buf[BUFSIZ];
	struct nlmsghdr *rhdr;
	struct rtmsg *rrt;
	struct rtattr *rrta;
	struct sockaddr *raddr;
	int attrlen;
	int rtnetlink_sk;
	uid_t euid;
	struct in_addr inaddr_none;

	if (socksconfig.external.addrc <= 1
	||  socksconfig.external.rotation == ROTATION_NONE)
		return getdefaultexternal();

	inaddr_none.s_addr = htonl(INADDR_NONE);

	/*===================================================================
	 * Get a NETLINK_ROUTE socket.
	 *==================================================================*/
	socks_seteuid(&euid, socksconfig.uid.privileged);
	rtnetlink_sk = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	socks_reseteuid(socksconfig.uid.privileged, euid);

	if (rtnetlink_sk == -1) {
		swarn("%s: socket(NETLINK_ROUTE)", function);
		return inaddr_none;
	}
 
	/*===================================================================
	 * Build the necessary data structures to get routing info.
	 * The structures are:
	 *   nlmsghdr - message header for netlink requests
	 *		It specifies RTM_GETROUTE for get routing table info
	 *   rtmsg - for routing table requests
	 *   rtattr - Specifies RTA_DST indicating that the payload contains a
	 *		destination address
	 * the payload - the destination address
	 *==================================================================*/
	bzero(&req, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.nh.nlmsg_type = RTM_GETROUTE;

	req.rt.rtm_family = AF_INET;
	req.rt.rtm_dst_len = 0;
	req.rt.rtm_src_len = 0;
	req.rt.rtm_tos = 0;
	req.rt.rtm_table = RT_TABLE_UNSPEC;
	req.rt.rtm_protocol = RTPROT_UNSPEC;
	req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rt.rtm_type = RTN_UNICAST;
	req.rt.rtm_flags = 0;

	rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = RTA_DST;
	rta->rta_len = RTA_LENGTH(sizeof(destaddr));

	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + rta->rta_len;

	/*===================================================================
	 * Send the request and get the response.
	 *==================================================================*/
	memcpy(RTA_DATA(rta), &destaddr, sizeof(destaddr));
	if (send(rtnetlink_sk, &req, req.nh.nlmsg_len, 0)
	!= (ssize_t)req.nh.nlmsg_len) {
		swarn("%s: send() to netlink failed", function);
		return inaddr_none;
	}

	if (recv(rtnetlink_sk, &buf, sizeof(buf), 0) == -1) {
		swarn("%s: recv() from netlink failed", function);
		return inaddr_none;
	}

	/*====================================================================
	 * Walk the response structures to find the one that contains
	 * RTA_PREFSRC in order to get the local source address to bind to.
	 *===================================================================*/
	rhdr = (struct nlmsghdr *)buf;
	rrt = (struct rtmsg *)NLMSG_DATA(rhdr);
	attrlen = sizeof(buf) - sizeof(struct nlmsghdr) - sizeof(struct rtmsg);

	for (rrta = (struct rtattr *)((char *)rrt + sizeof(struct rtmsg));
			RTA_OK(rrta, attrlen);
			rrta = (struct rtattr *)RTA_NEXT(rrta, attrlen)) {
		if (rrta->rta_type == RTA_PREFSRC) {
			TOIN(raddr)->sin_addr = *(struct in_addr *)RTA_DATA(rrta);

			if (!isonexternal(raddr)) {
				char a[MAXSOCKADDRSTRING];

				swarn("%s: address %s selected, but not set on external",
				function, sockaddr2string(raddr, a, sizeof(a)));

				return getdefaultexternal();
			}

			return TOIN(raddr)->sin_addr;
		}
	}

	slog(LOG_DEBUG, "%s: can't find a gateway for %s, using defaultexternal",
	function, inet_ntoa(destaddr));
	return getdefaultexternal();
}

#else /* ifdef linux	*/

__BEGIN_DECLS

static void
get_rtaddrs __P((int addrs, struct sockaddr *sa, struct sockaddr **rti_info));

__END_DECLS

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#define	BUFLEN	(sizeof(struct rt_msghdr) + 512)
				/* 8 * sizeof(struct sockaddr_in6) = 192 */

#ifndef RTAX_MAX
#define RTAX_MAX 8
#endif

#define SEQ	9999
/*
 * Round up 'a' to next multiple of 'size'
 */
#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

/*
 * Step to next socket address structure;
 * if sa_len is 0, assume it is sizeof(u_long).
 */
#if defined(__sun) || defined(linux)
#define NEXT_SA(ap)	ap = (struct sockaddr *) \
	((caddr_t) ap + sizeof(struct sockaddr))
#else
#define NEXT_SA(ap)	ap = (struct sockaddr *) \
	((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (u_long)) : sizeof(u_long)))
#endif


static void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int		i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			NEXT_SA(sa);
		} else
			rti_info[i] = NULL;
	}
}

#if HAVE_RTAX_GATEWAY
struct in_addr
getifa(destaddr)
	struct in_addr destaddr;
{
	const char *function = "getifa()";
	int					sockfd;
	char				buf[BUFLEN];
	pid_t				pid;
	struct rt_msghdr *rtm;
	struct sockaddr *sa, *rti_info[RTAX_MAX];
	uid_t euid;
	struct in_addr inaddr_none;

	inaddr_none.s_addr = htonl(INADDR_NONE);

	if (socksconfig.external.addrc <= 1
	||  socksconfig.external.rotation == ROTATION_NONE)
		return getdefaultexternal();

	/*===================================================================
	 * Get a socket.
	 *==================================================================*/
	socks_seteuid(&euid, socksconfig.uid.privileged);
	sockfd = socket(AF_ROUTE, SOCK_RAW, 0);	/* need superuser privileges */
	socks_reseteuid(socksconfig.uid.privileged, euid);

	if (sockfd == -1) {
		swarn("%s: socket(AF_ROUTE)", function);
		return inaddr_none;
	}


	/*===================================================================
	 * Build the necessary data structures to get routing info.
	 * The structures are:
	 *   rt_msghdr - Specifies RTM_GET for getting routing table info
	 *   sockaddr - contains the destination address 
	 *==================================================================*/
	bzero(buf, sizeof(buf));
	rtm = (struct rt_msghdr *) buf;
	rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = pid = getpid();
	rtm->rtm_seq = SEQ;

	sa 						= (struct sockaddr *) (rtm + 1);
	/* LINTED pointer casts may be troublesome */
	TOIN(sa)->sin_family	= AF_INET;
	/* LINTED pointer casts may be troublesome */
	TOIN(sa)->sin_addr 	= destaddr;
	/* LINTED pointer casts may be troublesome */
	TOIN(sa)->sin_port	= htons(0);

	/*===================================================================
	 * Send the request and get the response.
	 *==================================================================*/
	if (write(sockfd, rtm, (size_t)rtm->rtm_msglen) != rtm->rtm_msglen) {
		swarn("%s: write() to AF_ROUTE failed", function);
		close(sockfd);
		return inaddr_none;
	}

	do {
		if (read(sockfd, rtm, sizeof(buf)) == -1) {
			swarn("%s: read from AF_ROUTE failed", function);
			close(sockfd);
			return inaddr_none;
		}
	} while (rtm->rtm_type != RTM_GET || rtm->rtm_seq != SEQ
	|| rtm->rtm_pid != pid);

	close(sockfd);

	/*====================================================================
	 * Go straight to the RTA_DST entry for our info.
	 *===================================================================*/
	rtm = (struct rt_msghdr *) buf;
	sa = (struct sockaddr *) (rtm + 1);
	get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

	if (!(rtm->rtm_addrs & RTA_GATEWAY)
	|| (sa = rti_info[RTAX_GATEWAY]) == NULL
	||  TOIN(&sa)->sin_family != AF_INET) {
		slog(LOG_DEBUG, "%s: can't find a gateway for %s, using defaultexternal",
		function, inet_ntoa(destaddr));
		return getdefaultexternal();
	}

	if (!isonexternal(sa)) {
		char a[MAXSOCKADDRSTRING];

		swarnx("%s: address %s selected, but not set on external",
		function, sockaddr2string(sa, a, sizeof(a)));

		return getdefaultexternal();
	}

	/* LINTED pointer casts may be troublesome */
	return TOIN(&sa)->sin_addr;
}
#else /* HAVE_RTAX_GATEWAY */
struct in_addr
getifa(destaddr)
	struct in_addr destaddr;
{
	return getdefaultexternal();
}
#endif /* RTAX_GATEWAY */
#endif /* !linux */

static struct in_addr
getdefaultexternal(void)
{
	const char *function = "getdefaultexternal()";
	struct sockaddr bound;

	/* find address to bind on clients behalf. */
	switch ((*socksconfig.external.addrv).atype) {
		case SOCKS_ADDR_IFNAME:
			if (ifname2sockaddr((*socksconfig.external.addrv).addr.ifname, 0,
			&bound) == NULL) {
				swarnx("%s: can't find external interface/address: %s",
				function, (*socksconfig.external.addrv).addr.ifname);

				/* LINTED pointer casts may be troublesome */
				TOIN(&bound)->sin_addr.s_addr = htonl(INADDR_NONE);
			}
			break;
	
		case SOCKS_ADDR_IPV4: {
			struct sockshost_t host;

			sockshost2sockaddr(ruleaddress2sockshost(&*socksconfig.external.addrv,
			&host, SOCKS_TCP), &bound);
			break;
		}

		default:
			SERRX((*socksconfig.external.addrv).atype);
	}

	/* LINTED pointer casts may be troublesome */
	return TOIN(&bound)->sin_addr;
}

static int
isonexternal(addr)
	const struct sockaddr *addr;
{
	const char *function = "isonexternal()";
	int i;

	for (i = 0; i < socksconfig.external.addrc; ++i) {
		struct sockaddr check;
		int match = 0;

		switch ((*socksconfig.external.addrv).atype) {
			case SOCKS_ADDR_IFNAME: {
				int ifi;

				ifi = 0;
				while (ifname2sockaddr(socksconfig.external.addrv[i].addr.ifname,
				ifi++, &check) != NULL)
					/* LINTED pointer casts may be troublesome */
					if (TOIN(&check)->sin_addr.s_addr 
					== TOCIN(addr)->sin_addr.s_addr) {
						match = 1;
						break;
					}
				}
				break;
		
			case SOCKS_ADDR_IPV4:
				/* LINTED pointer casts may be troublesome */
				if (socksconfig.external.addrv[i].addr.ipv4.ip.s_addr
				== TOCIN(addr)->sin_addr.s_addr)
					match = 1;
				break;

			default:
				SERRX((*socksconfig.external.addrv).atype);
		}

		if (match)
			break;
	}

	if (i == socksconfig.external.addrc) {
		char a[MAXSOCKADDRSTRING];

		swarnx("%s: %s selected for connection but not on external list",
		function, sockaddr2string(addr, a, sizeof(a)));
		return 0;
	}

	return 1;
}

