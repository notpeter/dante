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

#include "common.h"

static const char rcsid[] =
"$Id: udp_util.c,v 1.40 1999/12/14 11:45:39 michaels Exp $";

struct udpheader_t *
sockaddr2udpheader(to, header)
	const struct sockaddr *to;
	struct udpheader_t *header;
{

	SASSERTX(to->sa_family == AF_INET);

	bzero(header, sizeof(*header));

	fakesockaddr2sockshost(to, &header->host);

	return header;
}

char *
udpheader_add(host, msg, len, msgsize)
	const struct sockshost_t *host;
	char *msg;
	size_t *len;
	size_t msgsize;
{
/*	const char *function = "udpheader_add()"; */
	struct udpheader_t header;
	char *newmsg, *offset;

	bzero(&header, sizeof(header));
	header.host = *host;

	if (msgsize >= sizeof(*newmsg) * (*len + PACKETSIZE_UDP(&header)))
		newmsg = msg;
	else
		if ((newmsg = (char *)malloc(sizeof(*newmsg)
		* (*len + PACKETSIZE_UDP(&header)))) == NULL)
			return NULL;

	/* offset old contents by size of header we are about to prefix. */
	memmove(newmsg + PACKETSIZE_UDP(&header), msg, *len);

	offset = newmsg;

	memcpy(offset, &header.flag, sizeof(header.flag));
	offset += sizeof(header.flag);

	memcpy(offset, &header.frag, sizeof(header.frag));
	offset += sizeof(header.frag);

	offset = sockshost2mem(&header.host, offset, SOCKS_V5);

	offset += *len; /* len bytes copied above. */

	*len = offset - newmsg;

	return newmsg;
}

struct udpheader_t *
string2udpheader(data, len, header)
	const char *data;
	size_t len;
	struct udpheader_t *header;
{

	bzero(header, sizeof(*header));

	if (len < sizeof(header->flag))
		return NULL;
	memcpy(&header->flag, data, sizeof(header->flag));
	data += sizeof(header->flag);
	len -= sizeof(header->flag);

	if (len < sizeof(header->frag))
		return NULL;
	memcpy(&header->frag, data, sizeof(header->frag));
	data += sizeof(header->frag);
	len -= sizeof(header->frag);

	if ((data = mem2sockshost(&header->host, data, len, SOCKS_V5)) == NULL)
		return NULL;

	return header;
}
