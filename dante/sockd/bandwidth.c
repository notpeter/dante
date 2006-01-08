/*
 * Copyright (c) 2001, 2002, 2003
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

#include <math.h> /* XXX */

static const char rcsid[] =
"$Id: bandwidth.c,v 1.12 2005/11/02 12:11:28 michaels Exp $";

const char module_bandwidth_version[] =
"$Id: bandwidth.c,v 1.12 2005/11/02 12:11:28 michaels Exp $";


int
bw_use(bw)
	bw_t *bw;
{
	return 1;
}

bw_t *
bw_alloc(client, number)
	int client;
	int number;
{
	return NULL;
}

void
bw_unuse(bw)
	bw_t *bw;
{

}

ssize_t
bw_left(bw)
	const bw_t *bw;
{

	return MAX(SOCKD_BUFSIZETCP, SOCKD_BUFSIZEUDP);
}

void
bw_update(bw, bwused, bwusedtime)
	bw_t *bw;
	size_t bwused;
	const struct timeval *bwusedtime;
{

}

struct timeval *
bw_isoverflow(bw, timenow, overflow)
	bw_t *bw;
	const struct timeval *timenow;
	struct timeval *overflow;
{

	return NULL;
}
