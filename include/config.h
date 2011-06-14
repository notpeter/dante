/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2005, 2008, 2009, 2010,
 *               2011
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

/* $Id: config.h,v 1.112 2011/06/08 09:43:17 karls Exp $ */

#ifndef _CONFIG_H_
#define _CONFIG_H_

/*
 * Everything in this file is put here so you can change it to suit
 * your particular installation. You should not need to change
 * any other files.
 *
 * Several of the variables can have a big impact on performance,
 * latency and throughput.  Tuning the server to the optimum for
 * your particular environment might be difficult, but hopefully
 * the defaults as set in this file will provide an adequate
 * compromise in most cases.
 */



/*
 * default client/server lockfile (put in $TMPDIR, or /tmp).
 * Put this on a fast, low-latency fs.  Under /tmp is usually good.
 * Note that if set, $TMPDIR is prefixed to this path.
 */
#define SOCKS_LOCKFILE            ".sockslockXXXXXXXXXX"

/*
 * default server file for shared memory mappings (put in $TMPDIR, or /tmp).
 * Put this on a fast, low-latency fs.  Under /tmp is usually good.
 * Note that if set, $TMPDIR is prefixed to this path.
 */
#define SOCKD_SHMEMFILE           ".sockdshmemXXXXXXXXXX"

/* default client config file. */
#if !HAVE_SOCKS_CONFIGFILE
#define SOCKS_CONFIGFILE         "/etc/socks.conf"
#else
#define SOCKS_CONFIGFILE         HAVE_ALT_SOCKS_CONFIGFILE
#endif /* !HAVE_SOCKS_CONFIGFILE */


#if COVENANT

/* max length of a http request.  XXX probably to small. */
#define MAXREQLEN              (2048)

#define DEFAULT_REALMNAME          "not the Inferno Nettverk A/S realm"

#elif SOCKS_SERVER /* !COVENANT */

/* max length of a socks request,  excluding gssapi-stuff. */
#define MAXREQLEN              (sizeof(struct request_t))

#endif /* SOCKS_SERVER */


/*
 * server send/receive socket buffer size for network i/o using TCP.
 * A value of 0 indicates we should not set any value, but use whatever
 * the kernel chooses.
 */
#define SOCKS_SOCKET_SNDBUF_TCP         (0)
#define SOCKS_SOCKET_RCVBUF_TCP         (0)

/*
 * server receive socket buffer size for network i/o using UDP.
 * If you expect having to handle many large udp packets, you
 * might want to increase this.
 * A value of 0 indicates we should not set any value, but use whatever
 * the kernel chooses.
 */
#define SOCKS_SOCKET_SNDBUF_UDP         (0)
#define SOCKS_SOCKET_RCVBUF_UDP         (1024 * 64 * 1)

#if BAREFOOTD
/*
 * Barefootd will possibly handle hundreds, even thousands, of udp clients
 * on one socket, so that socket buffer we want to be as big as possible.
 * A value of 0 indicates we should not set any value, but use whatever
 * the kernel chooses.
 */
#define SOCKS_SOCKET_RCVBUF_UDP_CLIENTSIDE (SOCKS_SOCKET_RCVBUF_UDP * 10)
#define SOCKS_SOCKET_SNDBUF_UDP_CLIENTSIDE (0)
#endif /* BAREFOOTD */


/* if profiling is enabled, directory to store profile files in. */
#define SOCKS_PROFILEDIR         "./.prof"


   /*
    * stuff only related to the server.
    */

/*
 * If we are compiling with libwrap support, this sets the maximum
 * line length for a libwrap line.  Should be the same or less as the
 * one libwrap uses internally, but we don't have access to that size.
 */
#if HAVE_LIBWRAP
#define LIBWRAPBUF         (150)
#endif /* HAVE_LIBWRAP */

/*
 * Name to give as servicename when starting pam for rules that don't
 * set it.
 */
#if SOCKS_SERVER
#define DEFAULT_PAMSERVICENAME   "sockd"
#elif BAREFOOTD
#define DEFAULT_PAMSERVICENAME   "barefootd"
#else
#define DEFAULT_PAMSERVICENAME   "httprelayd"
#endif

/*
 * Name to give as stylename when using bsdauth for rules that don't
 * set it.
 */
#define DEFAULT_BSDAUTHSTYLENAME "" /* use ""; NULL is default value */

/*
 * Name to give as servicename when starting gssapi for rules that don't
 * set it.
 */
#define DEFAULT_GSSAPISERVICENAME      "rcmd"
#define DEFAULT_GSSAPIKEYTAB           "FILE:/etc/sockd.keytab"


/*
 * Name to give as filter and attribute name for ldap server
 */
#define DEFAULT_LDAP_FILTER        "(memberuid=%s)"
#define DEFAULT_LDAP_ATTRIBUTE     "cn"

/*
 * Name to give as filter and attribute name for Active Directory server
 */
#define DEFAULT_LDAP_FILTER_AD     "(samaccountname=%s)"
#define DEFAULT_LDAP_ATTRIBUTE_AD  "memberof"

/*
 * Name to give as ca cert file or cert db path
 */
#define DEFAULT_LDAP_CACERTFILE    "/etc/ssl/certs/cert.pem"
#define DEFAULT_LDAP_CERTDBPATH    "/etc/certs"

/*
 * Name to give as USER when using PAM and username is not available
 * (such as when pam is used as a clientmethod).
 */

#define DEFAULT_PAM_USER "rhostusr"

/*
 * Name to give as RUSER when using PAM (corresponds to username of client).
 */

#define DEFAULT_PAM_RUSER "rhostusr"

/*
 * The file the server will write it's process id to.
 * Note that this file should be in a restricted directory.
 */
#if !HAVE_SOCKD_PIDFILE

#if SOCKS_SERVER
#define SOCKD_PIDFILE            "/var/run/sockd.pid"
#elif BAREFOOTD
#define SOCKD_PIDFILE            "/var/run/barefootd.pid"
#else
#define SOCKD_PIDFILE            "/var/run/httprelayd.pid"
#endif

#else
#define SOCKD_PIDFILE            HAVE_ALT_SOCKD_PIDFILE
#endif /* !HAVE_SOCKD_PIDFILE */

/* default port for server to listen on. */
#define SOCKD_PORT               (1080)

/* default server configfile */
#if !HAVE_SOCKD_CONFIGFILE

#if SOCKS_SERVER
#define SOCKD_CONFIGFILE         "/etc/sockd.conf"
#elif BAREFOOTD
#define SOCKD_CONFIGFILE         "/etc/barefootd.conf"
#else
#define SOCKD_CONFIGFILE         "/etc/httprelayd.conf"
#endif

#else
#define SOCKD_CONFIGFILE         HAVE_ALT_SOCKD_CONFIGFILE
#endif /* !HAVE_SOCKD_CONFIGFILE */


/*
 * Internal buffer size for network i/o.  This is the amount of
 * buffer space set aside internally by the server for each socket.
 * It is *not* the socket buffer size.
 */

#if HAVE_GSSAPI
/*
 * Warning: this size needs to be at least big enough to hold two max-size
 * gssapi encoded tokens, or two max-size gssapi decoded tokens.
 * Assuming a decoded token will never be bigger than an encoded token.
 */
#define SOCKD_BUFSIZE         (2 * (MAXGSSAPITOKENLEN + GSSAPI_HLEN))
#else /* !HAVE_GSSAPI */
/*
 * Warning: this size needs to be at least big enough to hold one max-size
 * udp packet.
 */
#define SOCKD_BUFSIZE         (1024 * 64 * 1)
#endif /* !HAVE_GSSAPI */

/* max number of clients pending to server (argument to listen()).
 * The Apache people say:
 *   It defaults to 511 instead of 512 because some systems store it
 *   as an 8-bit data type; 512 truncated to 8-bits is 0, while 511 is
 *   255 when truncated.
 */
#define SOCKD_MAXCLIENTQUE         (511)


/*
 * We try to cache resolved hostnames and addresses.  The following
 * values affect this.
 */

/* cache entries we should allocate for caching hostnames/addresses. */
#define SOCKD_HOSTCACHE            (512)

/* seconds a cache entry is to be considered valid.  Don't set below 1. */
#define SOCKD_CACHETIMEOUT         (60)

/*
 * Cache for LDAP stuff.
 */

/* number of entries in cache. */
#define SOCKD_LDAPCACHE            (512)

/* seconds a cache entry is to be considered valid.  Don't set below 1. */
#define SOCKD_LDAPCACHE_TIMEOUT    (60 * 15)

/* print some statistics for every SOCKD_CACHESTAT lookup.  0 to disable. */
#define SOCKD_LDAPCACHE_STAT       (0)


/*
 * Number of slots to try and keep available for new clients at any given time.
 * The server tries to be a little more intelligent about this, but not much.
 */
#define SOCKD_FREESLOTS_NEGOTIATE     (4)
#define SOCKD_FREESLOTS_REQUEST       (4)
#define SOCKD_FREESLOTS_IO            (4)

#if SOCKD_FREESLOTS_NEGOTIATE < 1
||  SOCKD_FREESLOTS_REQUEST < 1
||  SOCKD_FREESLOTS_IO < 1
#error "SOCKD_FREESLOTS_* can not be less than 1"
#endif /* SOCKD_FREESLOTS < 1 */

/*
 * Dante supports one process handling N clients, where the max value for
 * 'N' is limited by your system.
 *
 * There are two defines that govern this; SOCKD_NEGOTIATEMAX and SOCKD_IOMAX.
 * Note that these only govern how many clients a process can handle,
 * Dante will automatically create as many processes as it needs as
 * the need arises.
 */

/*
 * max number of clients each negotiate process will handle.
 * You can probably set this to a big number.
 * Each client will occupy one file descriptor.
 */
#ifndef SOCKD_NEGOTIATEMAX
#if DEBUG
#define SOCKD_NEGOTIATEMAX         (2)
#else
#define SOCKD_NEGOTIATEMAX         (24)
#endif /* DEBUG */
#endif /* SOCKD_NEGOTIATEMAX */

/*
 * max number of clients each i/o process will handle.
 * Each client will occupy up to three file descriptors.
 * While shortage of slots in the other processes will create a
 * delay for the client, shortage of i/o slots will prevent the client
 * from doing any i/o until a i/o slot has become available.  It is
 * therefore important that enough i/o slots are available at all times.
 */

#ifndef SOCKD_IOMAX
#if DEBUG
#define SOCKD_IOMAX               (2)
#else
#define SOCKD_IOMAX               (8)
#endif /* DEBUG */
#endif /* SOCKD_IOMAX */

#if SOCKD_NEGOTIATEMAX < 1 ||  SOCKD_IOMAX < 1
#error "SOCKD_IOMAX/NEGOTIATEMAX can not be less than 1"
#endif /* SOCKD_NEGOTIATEMAX < 1 || SOCKD_IOMAX < 1 */

#if BAREFOOTD
/*
 * each i/o process should attempt to handle at least this many udp clients.
 * Note that there is no hardcoded bound on this in Barefoot, this is only
 * limited by system resources.  If the system resources are too low for
 * this value, we will complain when starting up though.
 */
#define MIN_UDPCLIENTS           (512)
#endif /* BAREFOOTD */

#endif /* !_CONFIG_H_ */
