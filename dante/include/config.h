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
 *  N-0371 Oslo
 *  Norway
 *
 * any improvements or extensions that they make and grant Inferno Nettverk A/S
 * the rights to redistribute these changes.
 *
 */

/* $Id */

#ifndef _CONFIG_H_
#define _CONFIG_H_
#endif

/*
 * Everything in this file is put here so you can change it to suit
 * your particular installation. You should not need to change
 * any other files.
*/

	/*
	 * client/server stuff.
	*/

/* default server/client lockfile */
#define SOCKS_LOCKFILE				".sockslockXXXXXXXXXX"


	/*
	 * client stuff.
	*/

/* default client config file. */
#define SOCKS_CONFIGFILE			"/etc/socks.conf"


	/*
	 * server stuff.
	*/

/* 
 * If we are compiling with libwrap support, this sets the maximum
 * linelength for a libwrap line.  Should be the same or less as the
 * one libwrap uses internally, but we don't have access to that size.
*/
#if HAVE_LIBWRAP
#define LIBWRAPBUF			256
#endif  /* HAVE_LIBWRAP */

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
#define SOCKD_PIDFILE				"/var/run/sockd.pid"

/* default port for server to listen on. */
#define SOCKD_PORT					1080

/* default server configfile */
#define SOCKD_CONFIGFILE			"/etc/sockd.conf"

/* default server buffersize for network i/o using TCP. */
#define SOCKD_BUFSIZETCP			(1024 * 16)

/* default server buffersize for network i/o using UDP. */
#define SOCKD_BUFSIZEUDP			(1024 * 256)

/* max number of clients pending to server (argument to listen()). */
#define SOCKD_MAXCLIENTQUE			5


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


#define SOCKD_FREESLOTS				4
/*
 * Number of slots to try and keep available for new clients at any given time.
 * The server tries to be a little more intelligent about this, but not much.
*/

/*
 * Dante supports one process handling N clients, where the max value for 'N'
 * is limited by your system.  There will probably be a minor degradation
 * in performance for the clients with a big N, but less resources/processes
 * will be used on the machine the Dante server is running on.
 * There are two defines that govern this; SOCKD_NEGOTIATEMAX and SOCKD_IOMAX. 
 * Note that this are per process basis, Dante will automatically create as
 * many process as it thinks it needs as it goes along.
*/

/*
 * max number of clients each negotiate process will handle.
 * You can probably set this to a big number.
 * Each client will occupy one descriptor.
*/
#define SOCKD_NEGOTIATEMAX			24


/*
 * max number of clients each i/o process will handle.
 * Each client will occupy up to three descriptors.
 * While shortage of slots in the other processes will create a
 * delay for the client, shortage of i/o slots will prevent the client
 * from doing any i/o untill a i/o slot has become available.  It is
 * therefore important that enough i/o slots are available at all times.
*/
#define SOCKD_IOMAX					8


/*
 * For systems that do not have the "low watermarks" socket option.
 * The more accurate you can set this, the better performance.
 * It is important not to set it to too high a value as that will
 * degrade performance for clients even more, causing starvation.
*/
#if !HAVE_SO_SNDLOWAT
#define SO_SNDLOWAT_SIZE			1024
#endif
