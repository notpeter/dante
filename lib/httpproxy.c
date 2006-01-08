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

#include "common.h"

static const char rcsid[] =
"$Id: httpproxy.c,v 1.16 2005/12/31 13:59:47 michaels Exp $";

int
httpproxy_negotiate(s, packet)
	int s;
	struct socks_t *packet;
{
	const char *function = "httpproxy_negotiate()";
	char buf[MAXHOSTNAMELEN + 512]; /* +512 for httpbabble. */
	char host[MAXSOCKSHOSTSTRING];
	int checked, eof;
	ssize_t len, rc;
	struct sockaddr addr;
	socklen_t addrlen;

	slog(LOG_DEBUG, function);

	sockshost2string(&packet->req.host, host, sizeof(host));

	/*
	 * replace the dot that sockshost2string uses to separate port from host
	 * with http's ':'.
	*/
	*strrchr(host, '.') = ':';

	len = snprintfn(buf, sizeof(buf),
	"CONNECT %s HTTP/1.0\r\n"
	"User-agent: %s/client v%s\r\n"
	"\r\n",
	host, PACKAGE, VERSION);

	slog(LOG_DEBUG, "%s: sending: %s", function, buf);
	if ((rc = writen(s, buf, (size_t)len, NULL)) != len) {
		swarn("%s: wrote %d/%d bytes", function, rc, len);
		return -1;
	}


	eof = checked = 0;
	/*
	 * read til eof so there's no junk left in buffer for client, then return
	 * reply.
	 */
	do {
		char *eol;
		const char *terminator = "\r\n";

		/*
		 * -1 so we can NUL-terminate, and - length of terminator so we can
		 * read the missing bits if neccessary.
		 */
		switch(len = read(s, buf, sizeof(buf) - 1 - (strlen(terminator) + 1))) {
			case -1:
				swarn("%s: read()", function);
				return -1;

			case 0:
				eof = 1;
				break;
		}

		/*
		 * if last char we read is start of terminator,
		 * read some more to make sure the terminator does not get split
		 * accross buffers.
		 */
		if (buf[len - 1] == *terminator)
			switch(rc = read(s, &buf[len], strlen(terminator) - 1)) {
				case -1:
					swarn("%s: read()", function);
					return -1;

				case 0:
					eof = 1;
					break;

				default:
					len += rc;
			}

		buf[len] = NUL;

		while ((eol = strstr(buf, terminator)) != NULL) { /* new line. */
			*eol = NUL;
			slog(LOG_DEBUG, "%s: read: %s", function, buf);

			if (!checked) {
				int error = 0;

				switch (packet->req.version) {
					case HTTP_V1_0: {
						const char *offset = "HTTP/1.0 ";

						if (strncmp(buf, offset, strlen(offset)) != 0) {
							error = 1;
							break;
						}

						if (!isdigit(buf[strlen(offset)])) {
							error = 1;
							break;
						}

						packet->res.version = packet->req.version;

						/*
						 * XXX we've assumed that a reply is the size of a socks
						 * reply, http replies can however be bigger. :-/
						*/

						/*
						 * http replycode is > 8 bits, socks is 8 bits.
						 * Just make sure we don't end up truncating to
						 * HTTP_SUCCESS.
						 */
						rc = atoi(&buf[strlen(offset)]);
						if (rc != HTTP_SUCCESS && (unsigned char)rc == HTTP_SUCCESS)
							rc = 0;
						packet->res.reply = (unsigned char)rc;

						/*
						 * we don't know what address the server will use on
						 * our behalf, set it to what we use, better than nothing.
						*/
						addrlen = sizeof(addr);
						if (getsockname(s, &addr, &addrlen) != 0)
							SWARN(s);
						sockaddr2sockshost(&addr, &packet->res.host);

						checked = 1;
						break;
					}

					default:
						SERRX(packet->req.version);
				}

				if (error) {
					swarnx("%s: unknown response: \"%s\"", function, buf);
					errno = ECONNREFUSED;
					return -1;
				}
			}

			/* shift out the line we just parsed. */
			len -= (eol + strlen(terminator)) - buf;
			SASSERTX(len >= 0);
			SASSERTX((size_t)len < sizeof(buf));
			memmove(buf, eol + strlen(terminator), (size_t)len);
			buf[len] = NUL;

			if (strcmp(buf, terminator) == 0)
				eof = 1;	/* empty line, end of response. */
		}

		if (*buf != NUL)
			slog(LOG_DEBUG, "%s: read: %s", function, buf);
	} while (!eof);

	if (checked)
		return packet->res.reply == HTTP_SUCCESS ? 0 : -1;

	slog(LOG_DEBUG, "%s: didn't get statuscode from proxy", function);
	return -1;	/* proxyserver doing something strange/unknown. */
}
