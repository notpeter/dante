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

/* variables you can change to suit your needs. */


	/*
	 * client stuff.
	*/

/* default client config file. */
#define SOCKS_CONFIGFILE		"/etc/socks.conf"


	/*
	 * server stuff.
	*/

/*
 * used only if no usable system call is found (getdtablesize()/sysconf()). 
 * If you are missing the system calls, but know what the value should
 * be for max open files per process on your system, you should set
 * this define to the correct value.
*/
#define SOCKS_FD_MAX 		64

/*
 * The file the server will write it's process id to.
 * Note that this file should be in a restricted directory.
*/
#define SOCKD_PIDFILE		"/var/run/sockd.pid"

/* default port for server to listen on. */
#define SOCKD_PORT			1080

/* default server configfile */
#define SOCKD_CONFIGFILE		"/etc/sockd.conf"

/* default server buffersize for network i/o using TCP. */
#define SOCKD_BUFSIZETCP	(1024 * 16)

/* default server buffersize for network i/o using UDP. */
#define SOCKD_BUFSIZEUDP	(1024 * 256)

/* max number of clients pending to server (listen()). */
#define SOCKD_MAXCLIENTQUE	5

/* default server/client lockfile */
#define SOCKS_LOCKFILE		".sockslockXXXXXXXXXX"


/* number of seconds a client can negotiate with server. */
#define DEFAULT_NEGOTIATETIMEOUT	120 

/*
 * number of seconds a client can be connected after negotiation is completed
 * without sending/receiving any data.
*/
#define DEFAULT_IOTIMEOUT			7200 


#define SOCKD_FREESLOTS		4
/* 
 * Number of slots to try and keep available for new clients at any given time.
 * The server tries to be a little more intelligent about this, but not much.
*/

/*
 * Dante supports one process handling N clients, where the max value for 'N'
 * is limited by your system.  There will probably be a minor degradation
 * in performance for the clients with a big N, but less resources/processes
 * will be used on the machine the Dante server is running on. 
 * There are two defines that govern this; SOCKD_NEGOTIATEMAX and 
 * SOCKD_IOMAX.  Tailor to your preference.
*/

/*
 * max number of clients each negotiate process will handle.
 * You can probably set this to a big number.
 * Each client will occupy one descriptor.
*/
#define SOCKD_NEGOTIATEMAX 4


/*
 * max number of clients each i/o process will handle.
 * Each client will occupy up to three descriptors.
 * While shortage of slots in the other process' will create a delay
 * for the client, shortage of i/o process' will prevent the client
 * from doing any i/o to it's destination untill a i/o slot has become
 * available.  It is therefore important that enough i/o slots are
 * available at all times.
*/
#define SOCKD_IOMAX			4


/*
 * For systems that do not have low watermarks.
 * The more accurate you can set this, the better performance. 
 * It is important not to set it to too high a value as it will degrade
 * performance for clients even more, causing starvation.
*/
#ifndef HAVE_SO_SNDLOWAT
#define SO_SNDLOWAT_SIZE	1024
#endif
