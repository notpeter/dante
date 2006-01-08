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

/* $Id: config.h,v 1.52 2005/12/25 13:58:10 michaels Exp $ */

#ifndef _CONFIG_H_
#define _CONFIG_H_
#endif

/*
 * Everything in this file is put here so you can change it to suit
 * your particular installation. You should not need to change
 * any other files.
 *
 * Several of the variables can have a big impact on performance,
 * latency and throughput.  Tuning the server to the optimum for
 * your particular environment might be difficult but hopefully
 * the defaults as set in this file will provide a adequate
 * compromise.  Should you wish for more optimum tuning, you
 * might want to look at the SUPPORT file coming with Dante.
 */


	/*
	 * client/server stuff.
	 */

/*
 * default client/server lockfile (put in $TMPDIR, or /tmp).
 * Put this on a fast, low-latency fs, under /tmp is usually good.
 */
#define SOCKS_LOCKFILE				"./sockslockXXXXXXXXXX"

/* if profiling is enabled, directory to store profile files in. */
#define SOCKS_PROFILEDIR			"./.prof"


	/*
	 * client stuff.
	 */

/* default client config file. */
#if !HAVE_SOCKS_CONFIGFILE
#define SOCKS_CONFIGFILE			"/etc/socks.conf"
#else
#define SOCKS_CONFIGFILE			HAVE_ALT_SOCKS_CONFIGFILE
#endif /* !HAVE_SOCKS_CONFIGFILE */

/*
 * if we mark a route/socksserver as bad, how many seconds to wait
 * until we expire the badmarking so it will be tried again for new
 * connections.
 * A value of zero means never.
 */
#if SOCKS_CLIENT
#define BADROUTE_EXPIRE				(60 * 0)
#else /* SOCKS_SERVER */
#define BADROUTE_EXPIRE				(60 * 5)
#endif


	/*
	 * server stuff.
	 */

/*
 * If we are compiling with libwrap support, this sets the maximum
 * linelength for a libwrap line.  Should be the same or less as the
 * one libwrap uses internally, but we don't have access to that size.
 */
#if HAVE_LIBWRAP
#define LIBWRAPBUF			80
#endif  /* HAVE_LIBWRAP */

/*
 * Name to give as servicename when starting pam for rules that don't
 * set it.
 */
#define DEFAULT_PAMSERVICENAME	"sockd"

/*
 * used only if no usable system call is found (getdtablesize()/sysconf()).
 * If you are missing the system calls, but know what the value should
 * be for max open files per process on your system, you should set
 * this define to the correct value.
 */
#define SOCKS_FD_MAX					64

/*
 * The file the server will write it's process id to.
 * Note that this file should be in a restricted directory.
 */
#if !HAVE_SOCKD_PIDFILE
#define SOCKD_PIDFILE				"/var/run/sockd.pid"
#else
#define SOCKD_PIDFILE				HAVE_ALT_SOCKD_PIDFILE
#endif /* !HAVE_SOCKD_PIDFILE */

/* default port for server to listen on. */
#define SOCKD_PORT					1080

/* default server configfile */
#if !HAVE_SOCKD_CONFIGFILE
#define SOCKD_CONFIGFILE			"/etc/sockd.conf"
#else
#define SOCKD_CONFIGFILE			HAVE_ALT_SOCKD_CONFIGFILE
#endif /* !HAVE_SOCKD_CONFIGFILE */

/* max number of clients pending to server (argument to listen()).
 * The Apache people say:
 *   It defaults to 511 instead of 512 because some systems store it
 *   as an 8-bit datatype; 512 truncated to 8-bits is 0, while 511 is
 *   255 when truncated.
 */
#define SOCKD_MAXCLIENTQUE			511


/*
 * We try to cache resolved hostnames and addresses.  The following
 * values affect this.
 */

/* cacheentries we should allocate for caching hostnames. */
#define SOCKD_HOSTCACHE				512

/* cacheentries we should allocate for caching addresses. */
#define SOCKD_ADDRESSCACHE			512

/* seconds a cacheentry is to be considered valid, don't set below 1. */
#define SOCKD_CACHETIMEOUT			3600

/* print some statistics for every SOCKD_CACHESTAT lookup.  0 to disable. */
#define SOCKD_CACHESTAT				0

/*
 * number of seconds a client can negotiate with server.
 * Can be changed in configfile.
 */
#define SOCKD_NEGOTIATETIMEOUT	120

/*
 * number of seconds a client can be connected after negotiation is completed
 * without sending/receiving any data.  Can be changed in configfile.
 */
#define SOCKD_IOTIMEOUT				86400

/*
 * Number of slots to try and keep available for new clients at any given time.
 * The server tries to be a little more intelligent about this, but not much.
 */
#define SOCKD_FREESLOTS				4

/*
 * Dante supports one process handling N clients, where the max value for
 * 'N' is limited by your system.  There will be a degradation in
 * performance as N increases, the biggest hop being from one to two,
 * but significantly less resources/processes might be used on the machine
 * the Dante server is running on.
 *
 * There are two defines that govern this; SOCKD_NEGOTIATEMAX and SOCKD_IOMAX.
 * Note that these are per process basis, Dante will automatically create as
 * many processes as it thinks it needs as it goes along.
 */

/*
 * max number of clients each negotiate process will handle.
 * You can probably set this to a big number.
 * Each client will occupy one descriptor.
 */
#if DEBUG
#define SOCKD_NEGOTIATEMAX			2
#else
#define SOCKD_NEGOTIATEMAX			24
#endif /* DEBUG */

/*
 * max number of clients each i/o process will handle.
 * Each client will occupy up to three descriptors.
 * While shortage of slots in the other processes will create a
 * delay for the client, shortage of i/o slots will prevent the client
 * from doing any i/o untill a i/o slot has become available.  It is
 * therefore important that enough i/o slots are available at all times.
 */
#if DEBUG
#define SOCKD_IOMAX					2
#else
#define SOCKD_IOMAX					8
#endif /* DEBUG */

/* server buffersize for network i/o using TCP. */
#define SOCKD_BUFSIZETCP			(1024 * 16)

/* server buffersize for network i/o using UDP. */
#define SOCKD_BUFSIZEUDP			(1024 * 16)

/*
 * skew watermarks by this factor compared to "optimal".
 * Setting it to one minimises cputime used by the server at a
 * possibly big cost in performance.  Never set it to more than one.
 * I'd be interested in hearing peoples result with this.
 */
#define LOWATSKEW						(0.75)

/*
 * For systems that do not have the "low watermarks" socket option.
 * It is important not to set it to too high a value as that will
 * probably degrade performance for clients even more, causing starvation.
 * Basicly; low value  -> better interactive performance,
 *				high value -> better throughput.
 */
#if !HAVE_SO_SNDLOWAT
#define SO_SNDLOWAT_SIZE			(1024 * 4)
#endif
