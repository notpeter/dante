/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011
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

/* $Id: sockd.h,v 1.478 2011/06/12 12:00:55 michaels Exp $ */

#ifndef _SOCKD_H_
#define _SOCKD_H_

#if HAVE_SOLARIS_PRIVS
#include <priv.h>
#endif /* HAVE_SOLARIS_PRIVS */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <regex.h>



/*
 * number of seconds a to wait for a connect initiated on behalf of a
 * client to complete.  Can be changed in configfile.
 */
#define SOCKD_CONNECTTIMEOUT   (30)


/*
 * number of seconds a client can negotiate with server.
 * Can be changed in configfile.
 */
#define SOCKD_NEGOTIATETIMEOUT   (30)

/*
 * number of seconds a client can be connected after negotiation is completed
 * without sending/receiving any data.  Can be changed in configfile.
 */
#define SOCKD_IOTIMEOUT_TCP          (86400) /* 24h */

#if SOCKS_SERVER
#define SOCKD_IOTIMEOUT_UDP          (86400) /* 24h */
#else /* BAREFOOTD */
#define SOCKD_IOTIMEOUT_UDP          (3600)  /* one hour */
#endif

/*
 * This is to handle a potentioal resource issue that can occur
 * in TCP when side 'A' of the TCP session closes it's end, but
 * the other end, side 'B', does not close it's end.  In this
 * situation, TCP will be forced to keep state for the TCP session
 * until side B closes it's end, or "never" if side B never closes.
 *
 * Some kernels have added kernel support for tuning this on a global
 * basis, but implementations may vary.
 *
 * If this value is set, it gives the number of seconds to wait
 * for B to close it's side.  Note that this may break the application
 * protocol, as there may be nothing wrong with B using a long time,
 * days even, to close it's end.  It may however produce an unfortunate
 * resource problem with both the Dante server and the kernels TCP having to
 * keep state for these sessions, which in 99.999% of the cases could
 * probably be closed as B will not send anything more.
 *
 * The default therfor is to not enable this "feature".
 */
#define SOCKD_FIN_WAIT_2_TIMEOUT  (0) /* Seconds.  Set to 0 to disable. */


#define SOCKD_SINGLEAUTH_LINGERTIMEOUT (60)  /* one minute */

#define SOCKD_SHMEM_TIMEOUT          (60) /*
                                           * never delete a shmem-segment
                                           * if the last deattch is less than
                                           * this many seconds ago.
                                           * Used to reduce the chance of
                                           * a shmem-segment id being
                                           * "in transit" between two
                                           * processes at the time we get a
                                           * SIGHUP.
                                           */

#define SOCKD_EXPLICIT_LDAP_PORT     (389)
#define SOCKD_EXPLICIT_LDAPS_PORT    (636)

#define SOCKD_LDAP_DEADTIME          (30)
#define SOCKD_LDAP_SEARCHTIME        (30)
#define SOCKD_LDAP_TIMEOUT           (2)

#define SOCKD_HTTP_PORT              (80)

/*
 * Depending on what kind of server we are, we will have different
 * phases to go through before we get to the i/o part.  This is
 * where we try to define the name of some generic phases, to reduce
 * the number of product-spesific defines in the code.
 *
 * Also we provivide wrappers to avoid linkage errors for functions that
 * are not used in different servers, to limit the amount of #ifdef's
 * in the code itself.
 */

#if BAREFOOTD

#define HAVE_NEGOTIATE_PHASE              (0)
#define HAVE_UDP_SUPPORT                  (1)
#define HAVE_TWO_LEVEL_ACL                (0)

#elif SOCKS_SERVER

#define HAVE_NEGOTIATE_PHASE              (1)
#define HAVE_UDP_SUPPORT                  (1)
#define HAVE_TWO_LEVEL_ACL                (1)

#elif COVENANT

#define HAVE_NEGOTIATE_PHASE              (1)
#define HAVE_UDP_SUPPORT                  (0)
#define HAVE_TWO_LEVEL_ACL                (0)

#else

#error "nothing is defined"

#endif


/* if state is mainained per address, memory for for client addresses. */
#define STATEADDRESSES_PER_RULE        64


/* which shmem object. */
#define SHMEM_BW                     (0x1)
#define SHMEM_SS                     (0x2)
#define SHMEM_ALL                    (SHMEM_BW | SHMEM_SS)

#if BAREFOOTD

/* minsize, used to get icmp errors.  */
#define RAW_SOCKETBUFFER              (1024 * 100)

#endif /* BAREFOOTD */

/* use caching versions directly, avoid overhead. */
#undef gethostbyname
#define gethostbyname(name)            cgethostbyname(name)
#undef gethostbyaddr
#define gethostbyaddr(addr, len, type) cgethostbyaddr(addr, len, type)

/* Search for POSIX groups */
#define DEFAULT_LDAP_FILTER_GROUP "(&(memberuid=%s)(objectclass=posixgroup))"
/* Search for Active Directory groups */
#define DEFAULT_LDAP_FILTER_GROUP_AD "(&(cn=%s)(objectclass=group))"


/*
 * This is a bunch of macros that are part of the implementation that
 * makes the negotiate children able to handle reading an unlimited
 * number of concurrent requests from the clients, without blocking
 * in any read call.
 * We treat blocking on write as an error, as there is no normal
 * reason that should happen during negotiating.
 */

#define INIT(length)                                                           \
   const size_t start   = state->start;      /* start of next block in mem. */ \
   const size_t end     = start + (length);  /* end of next block in mem.   */ \
   errno = 0

#define MEMLEFT()      (sizeof(state->mem) - state->reqread)

#define LEFT()   ((end) - state->reqread)
/*
 * Returns the number of bytes left to read.
 */

#define READ(s, length, auth)   \
   (socks_recvfromn((s), &state->mem[state->reqread], (length), 0, \
                    0, NULL, NULL, (auth)))
/*
 * "s" is the descriptor to read from.
 * "length" is how much to read.
 * Returns the number of bytes read, -1 on error.
 */



#define OBJECTFILL(object)   memcpy((object), &state->mem[start], end - start)
/*
 * Fills "object" with data.
 */

/*
 * Handle out of memory error (i.e., no more space in our inbuffer).
 * In the socks case, the max length is known, so we should never
 * experience that error.
 * In the http proxy case, there is no limit, so we have to make sure
 * the size of our buffer, as set at compile time, is big enough.
 */
#if SOCKS_SERVER
#define OUTOFMEM()                                                             \
do {                                                                           \
   SERRX(LEFT());                                                              \
} while (/*CONSTCOND*/0)
#else /* COVENANT */
#define OUTOFMEM() \
do {                                                                           \
   snprintf(state->emsg, sizeof(state->emsg),                                  \
           "http request is too long (more than %d bytes)."                    \
           "Either our compiled-in limit is too low, or the client is "        \
           "attempting something fishy",                                       \
           state->reqread);                                                    \
                                                                               \
   return NEGOTIATE_ERROR;                                                     \
} while (/*CONSTCOND*/0)
#endif /* COVENANT */

/*
 * Checks whether "object" has been filled with all data requested and
 * if so calls "function", if function is not NULL.
 * If "object" has not been filled it returns the number of bytes
 * that was added to object on this call, or error.
*/
#define CHECK(object, auth, nextfunction)                      \
do {                                                           \
   SASSERTX(state->reqread <= end);                            \
                                                               \
   if (LEFT()) {                                               \
      ssize_t p;                                               \
                                                               \
      SASSERT(LEFT() > 0);                                     \
                                                               \
      if (LEFT() > MEMLEFT())                                  \
          OUTOFMEM();                                          \
                                                               \
      errno = 0;                                               \
      if ((p = READ(s, LEFT(), auth)) <= 0) {                  \
         if (ERRNOISTMP(errno))                                \
            return NEGOTIATE_CONTINUE;                         \
         else                                                  \
            return NEGOTIATE_ERROR;                            \
      }                                                        \
                                                               \
      state->reqread += p;                                     \
                                                               \
      if (LEFT()) { /* read something, but not all. */         \
         errno = EWOULDBLOCK;                                  \
         return NEGOTIATE_CONTINUE;                            \
      }                                                        \
                                                               \
      state->start = end;                                      \
      OBJECTFILL((object));                                    \
      state->rcurrent = nextfunction;                          \
                                                               \
      if (state->rcurrent != NULL)                             \
         return state->rcurrent(s, request, state);            \
   }                                                           \
} while (/*CONSTCOND*/0)


/*
 * Unuses (decrements by one) any shared memory in use by "rule",
 * indicating one client-session has been closed, and then detaches from it.
 */
#define SHMEM_UNUSE(rule, addr, lock)                                          \
do {                                                                           \
   int need_attach = 0, need_detach = 0;                                       \
                                                                               \
   if ((rule)->bw_shmid != 0) {                                                \
      need_detach |= SHMEM_BW;                                                 \
                                                                               \
      if ((rule)->bw == NULL)                                                  \
         need_attach |= SHMEM_BW;                                              \
   }                                                                           \
                                                                               \
   if ((rule)->ss_shmid != 0) {                                                \
      need_detach |= SHMEM_SS;                                                 \
                                                                               \
      if ((rule)->ss == NULL)                                                  \
         need_attach |= SHMEM_SS;                                              \
   }                                                                           \
                                                                               \
   sockd_shmat((rule), need_attach);                                           \
                                                                               \
   bw_unuse((rule)->bw, lock);                                                 \
   session_unuse((rule)->ss, lock);                                            \
                                                                               \
   sockd_shmdt((rule), need_detach);                                           \
} while (/*CONSTCOND*/0)

/*
 * clears shmem stuff in "rule".
 */
#define SHMEM_CLEAR(rule, idtoo)                                               \
do {                                                                           \
   (rule)->bw    = (rule)->ss    = NULL;                                       \
   (rule)->bw_fd = (rule)->ss_fd = 0;                                          \
                                                                               \
   if (idtoo)                                                                  \
      (rule)->bw_shmid = (rule)->ss_shmid = 0;                                 \
} while (/*CONSTCOND*/0)

/*
 * build a string for the source and one for the destination that can
 * be used in iolog() and similar for logging the address related to
 * something.
 */
#define MAX_IOLOGADDR                                                          \
   MAXSOCKADDRSTRING + strlen(" ")                   /* local */               \
 + MAXAUTHINFOLEN + MAXSOCKSHOSTSTRING + strlen(" ") /* proxy */               \
 + MAXSOCKSHOSTSTRING + strlen(" ")                  /* proxy's ext addr. */   \
 + MAXAUTHINFOLEN + MAXSOCKSHOSTSTRING               /* peer  */

#define BUILD_ADDRSTR_SRC(peer, proxy_ext, proxy, local,                       \
                          peerauth, proxyauth, str, len)                       \
do {                                                                           \
   struct sockshost_t p;                                                       \
   char peerstr[MAXSOCKSHOSTSTRING], peerauthstr[MAXAUTHINFOLEN],              \
        proxyauthstr[MAXAUTHINFOLEN], pstr[MAXSOCKSHOSTSTRING],                \
        pe_str[MAXSOCKSHOSTSTRING], lstr[MAXSOCKSHOSTSTRING];                  \
                                                                               \
   snprintf((str), (len),                                                      \
            "%s%s "                                                            \
            "%s%s"                                                             \
            "%s%s%s"                                                           \
            "%s",                                                              \
                                                                               \
            authinfo((peerauth), peerauthstr, sizeof(peerauthstr)),            \
            (peer) == NULL ?                                                   \
            "0.0.0.0.0" : sockshost2string((peer), peerstr, sizeof(peerstr)),  \
                                                                               \
            (proxy_ext) == NULL ?                                              \
               "" : sockshost2string((proxy_ext), pe_str, sizeof(pe_str)),     \
            (proxy_ext) == NULL ? "" : " ",                                    \
                                                                               \
            authinfo((proxyauth), proxyauthstr, sizeof(proxyauthstr)),         \
            (proxy) == NULL ?                                                  \
             "" : sockshost2string(gwaddr2sockshost((proxy), &p),              \
                                   pstr,                                       \
                                   sizeof(pstr)),                              \
            (proxy) == NULL ? "" : " ",                                        \
                                                                               \
            (local) == NULL ?                                                  \
            "0.0.0.0.0" : sockaddr2string((local), lstr, sizeof(lstr)));       \
} while (/* CONSTCOND */ 0)

#define BUILD_ADDRSTR_DST(local, proxy, proxy_ext, peer,                       \
                          peerauth, proxyauth, str, len)                       \
do {                                                                           \
   struct sockshost_t p;                                                       \
   char peerstr[MAXSOCKSHOSTSTRING], peerauthstr[MAXAUTHINFOLEN],              \
        proxyauthstr[MAXAUTHINFOLEN], pstr[MAXSOCKSHOSTSTRING],                \
        pe_str[MAXSOCKSHOSTSTRING], lstr[MAXSOCKSHOSTSTRING];                  \
                                                                               \
   snprintf((str), (len),                                                      \
            "%s "                                                              \
            "%s%s%s"                                                           \
            "%s%s"                                                             \
            "%s%s",                                                            \
                                                                               \
            (local) == NULL ?                                                  \
            "0.0.0.0.0" : sockaddr2string((local), lstr, sizeof(lstr)),        \
                                                                               \
            authinfo((proxyauth), proxyauthstr, sizeof(proxyauthstr)),         \
            (proxy) == NULL ?                                                  \
             "" : sockshost2string(gwaddr2sockshost((proxy), &p),              \
                                   pstr,                                       \
                                   sizeof(pstr)),                              \
            (proxy) == NULL ? "" : " ",                                        \
                                                                               \
            (proxy_ext) == NULL ?                                              \
               "" : sockshost2string((proxy_ext), pe_str, sizeof(pe_str)),     \
            (proxy_ext) == NULL ? "" : " ",                                    \
                                                                               \
            authinfo((peerauth), peerauthstr, sizeof(peerauthstr)),            \
            (peer) == NULL ?                                                   \
            "0.0.0.0.0" : sockshost2string((peer), peerstr, sizeof(peerstr))); \
} while (/* CONSTCOND */ 0)

/* info sent by sockd children to mother. */
#define SOCKD_FREESLOT_TCP    (1)   /* free'd a tcp slot.                   */
#define SOCKD_FREESLOT_UDP    (2)   /* free'd a udp slot.                   */



/* a request child can currently only handle a maximum of one client. */
#define SOCKD_REQUESTMAX   1


/* types of children. */
#define CHILD_NOTOURS       0
#define CHILD_MOTHER        1
#define CHILD_NEGOTIATE     2
#define CHILD_REQUEST       3
#define CHILD_IO            4

#if SOCKS_SERVER
#define FDPASS_MAX         3   /* max number of descriptors we send/receive. */
#else
#define FDPASS_MAX         2   /* max number of descriptors we send/receive. */
#endif


   /*
    * config stuff
    */

#define VERDICT_BLOCKs     "block"
#define VERDICT_PASSs      "pass"

/* how to rotate addresses. */
#define ROTATION_NONE       0
#define ROTATION_ROUTE      1
#define ROTATION_SAMESAME   2

#define SOCKS_LOG_CONNECTs       "connect"
#define SOCKS_LOG_DISCONNECTs    "disconnect"
#define SOCKS_LOG_DATAs          "data"
#define SOCKS_LOG_ERRORs         "error"
#define SOCKS_LOG_IOOPERATIONs   "iooperation"

/*
 * privilege stuff.
 */
#if !HAVE_PRIVILEGES
typedef enum { PRIV_ON, PRIV_OFF } priv_op_t;
#endif /* !HAVE_PRIVILEGES */

typedef enum { SOCKD_PRIV_NOTSET = 0,
               SOCKD_PRIV_FILE_READ,
               SOCKD_PRIV_FILE_WRITE,
               SOCKD_PRIV_NET_ADDR,
               SOCKD_PRIV_NET_ICMPACCESS,
               SOCKD_PRIV_NET_ROUTESOCKET,
               SOCKD_PRIV_PRIVILEGED,
               SOCKD_PRIV_UNPRIVILEGED,
               SOCKD_PRIV_LIBWRAP,
               SOCKD_PRIV_PAM,
               SOCKD_PRIV_BSDAUTH,
               SOCKD_PRIV_GSSAPI
} privilege_t;


typedef enum {
   OPERATION_ACCEPT,
   OPERATION_CONNECT,
   OPERATION_DISCONNECT,
   OPERATION_IO,
   OPERATION_TIMEOUT,
   OPERATION_ERROR,
   OPERATION_BLOCK
} operation_t;

typedef enum { KEY_IPV4, KEY_MAC } keytype_t;
typedef enum { ACKPIPE, DATAPIPE } whichpipe_t;
typedef enum { NEGOTIATE_ERROR,     /* fatal error.                           */
               NEGOTIATE_CONTINUE,  /* have not finished, do continue.        */
               NEGOTIATE_FINISHED   /* have finshed, read request ok.         */
} negotiate_result_t;


#define fakesockaddr2sockshost sockaddr2sockshost/* no fakes in server. */
#define DENY_SESSIONLIMITs    "session-limit reached"

/* ok signals, i.e signals that do not indicate an error. */
#if HAVE_SIGNAL_SIGINFO
#define SIGNALISOK(sig) \
   (  (sig) == SIGHUP   \
   || (sig) == SIGINT   \
   || (sig) == SIGUSR1  \
   || (sig) == SIGINFO  \
   || (sig) == SIGQUIT  \
   || (sig) == SIGTERM  \
   || (sig) == SIGHUP)
#else /* !HAVE_SIGNAL_SIGINFO */
#define SIGNALISOK(sig) \
   (  (sig) == SIGHUP   \
   || (sig) == SIGINT   \
   || (sig) == SIGUSR1  \
   || (sig) == SIGQUIT  \
   || (sig) == SIGTERM  \
   || (sig) == SIGHUP)
#endif




struct compat_t {
   unsigned char sameport;     /* always try to use same port as client?   */
   unsigned char draft_5_05;   /* try to support parts of socks 5.05 draft */
};

struct log_t {
   unsigned char connect;
   unsigned char disconnect;
   unsigned char data;
   unsigned char error;
   unsigned char iooperation;
};


struct linkedname_t {
   char                  *name;
   struct linkedname_t   *next;   /* next name in list.                       */
};

typedef struct {
   ssize_t            clients;          /* # of clients using this object.    */
   unsigned char      isclientrule;     /* rule is a clientrule.              */
   size_t             rulenumber;       /* rule # this object is for.         */
   struct timeval     allocatedts;      /* when was it allocated.             */
} shmem_header_t;

typedef struct {
   struct in_addr       addr;             /*
                                           * address of client, if state
                                           * is maintainted per address.
                                           */

   size_t               bytes;            /* bytes transfered since iotime.   */
   struct timeval       iotime;
   size_t               maxbps;           /* maximal b/s allowed.  Const.     */
} bw_t;

typedef struct {
   struct in_addr       addr;             /*
                                           * address of client, if state
                                           * is maintainted per address.
                                           */
   size_t               maxsessions;      /* max number of sessions allowed.  */
} session_t;

typedef struct {
   shmem_header_t         mstate;
   union {
      bw_t                bw;
      session_t           ss;
   } object;
} shmem_object_t;


typedef struct {
   keytype_t key;

   union {
      struct in_addr ipv4;
      unsigned char  macaddr[ETHER_ADDR_LEN];
   } value;
} licensekey_t;

/* linked list over current rules. */
struct rule_t {
   int                     verdict;      /* verdict for this rule.            */

#if COVENANT
   /* if block, why.  XXX why not a more general textstring? */
   struct {
      unsigned char        missingproxyauth;
   } whyblock;
#endif /* COVENANT */


   struct ruleaddr_t       src;          /* src.                              */
   struct ruleaddr_t       dst;          /* dst.                              */
   struct ruleaddr_t       rdr_from;
   struct ruleaddr_t       rdr_to;

#if BAREFOOTD
   unsigned char           bounced;      /*
                                          * have we faked a request for the addr
                                          * "dst" already?  Only used for udp.
                                          */

   struct ruleaddr_t      internal;      /*
                                          * address packet from src to dst is
                                          * accepted on.
                                          */
#endif /* BAREFOOTD */

   struct log_t            log;          /* type of logging to do.            */
   size_t                  number;       /* rulenumber.                       */
   size_t                  linenumber;   /* linenumber; info/debugging only.  */

   struct serverstate_t    state;
   struct timeout_t        timeout;      /* default or specific for this one. */

   struct linkedname_t     *user;        /* name of users allowed.            */
   struct linkedname_t     *group;       /* name of groups allowed.           */

   struct {
      in_port_t            start;
      in_port_t            end;
      enum operator_t      op;
   } udprange;                           /* udprange, if limited.             */ 

#if HAVE_LDAP
   struct linkedname_t     *ldapgroup;   /* name of ldap groups allowed.      */
   struct linkedname_t     *ldapserver;  /* name of predefined ldap servers.  */
   unsigned char            ldapsettingsfromuser;
#endif /* HAVE_LDAP */

#if HAVE_LIBWRAP
   char                    libwrap[LIBWRAPBUF];   /* libwrapline.             */
#endif /* HAVE_LIBWRAP */

   shmem_object_t          *bw;            /* pointer, memory will be shared. */
   long                    bw_shmid;       /* shmid of bw.                    */
   int                     bw_fd;

   shmem_object_t          *ss;            /* pointer, memory will be shared. */
   long                    ss_shmid;       /* shmid of ss.                    */
   int                     ss_fd;

#if BAREFOOTD
   struct ruleaddr_t       bounce_to; /* XXX why ruleaddr and not sockshost? */

   struct rule_t           *crule;     /*
                                        * if srule, crule that was used to
                                        * generate it.
                                        */
#endif /* BAREFOOTD */


   struct rule_t           *next;      /* next rule in list.                  */
};

struct socketconfig_t {
   struct {
      size_t   rcvbuf;
      size_t   sndbuf;
   } tcp;

   struct {
      size_t   rcvbuf;
      size_t   sndbuf;
   } udp;

#if BAREFOOTD
   struct {
      size_t   rcvbuf;
      size_t   sndbuf;
   } clientside_udp;
#endif /* BAREFOOTD */

};

struct srchost_t {
   unsigned char nodnsmismatch;  /* deny if mismatch between dns claim/fact?  */
   unsigned char nodnsunknown;   /* deny if no dns record?                    */
   unsigned char checkreplyauth; /* check that method matches for replies?    */
};

struct option_t {
   char              *configfile;     /* name of configfile.                  */
   unsigned char     daemon;          /* run as a daemon?                     */
   int               debugrunopt;     /* debug value set on command line.     */
   int               debug;           /* debug level.                         */
   int               hosts_access;    /* do hosts_access() lookup.            */
   int               directfallback;  /* fallback to direct connections       */
   unsigned char     keepalive;       /* set SO_KEEPALIVE?                    */
   char              *pidfile;        /* name of pidfile.                     */
   size_t            serverc;         /* number of servers.                   */
};


#if HAVE_PRIVILEGES
typedef struct {
   unsigned char     noprivs;       /* no privilege-switching possible? */
   priv_set_t       *unprivileged;
   priv_set_t       *privileged;
} privileges_t;

#else /* !HAVE_PRIVILEGES */
struct userid_t {
   uid_t            privileged;
   unsigned char    privileged_isset;
   uid_t            unprivileged;
   unsigned char    unprivileged_isset;
   uid_t            libwrap;
   unsigned char    libwrap_isset;
   unsigned :0;
};
#endif /* !HAVE_PRIVILEGES */

struct sockd_mother_t {
   int                  ack;            /* connection for misc acks.          */
   int                  s;              /* connection to child for data.      */

#if HAVE_SENDMSG_DEADLOCK
   int                  lock;           /* lock on request connection.        */
#endif /* HAVE_SENDMSG_DEADLOCK */
};


struct configstate_t {
   unsigned char       inited;

   sig_atomic_t        insignal;          /* executing in signalhandler?      */
   struct {
      sig_atomic_t     signal;
      siginfo_t        siginfo;
   } signalv[_NSIG];                      /* stacked signals.                 */
   sig_atomic_t        signalc;           /* number of stacked signals.       */

#if HAVE_PAM
   /*
    * allows us to optimize a few things a little based on configuration.
    * If it is NULL, the value can vary from rule to rule, otherwise,
    * the value is fixed and this variable points to the fixed value.
    */
   const char          *pamservicename;
#endif /* HAVE_PAM */

#if HAVE_BSDAUTH
   /*
    * allows us to optimize a few things a little based on configuration.
    * If it is NULL, the value can vary from rule to rule, otherwise,
    * the value is fixed and this variable points to the fixed value.
    */
   const char          *bsdauthstylename;
#endif /* HAVE_BSDAUTH */

#if HAVE_GSSAPI
   /*
    * allows us to optimize a few things a little based on configuration.
    * If it is NULL, the values can vary from rule to rule, otherwise,
    * the value is fixed and these variables point to the fixed value.
    */
   const char          *gssapiservicename;    /* have rules with gssapidata.  */
   const char          *gssapikeytab;         /* have rules with gssapidata.  */
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
   const char          *ldapattribute;        /* rules with ldap attribute.   */
   const char          *ldapattribute_AD;     /*  ... with ldap AD attribute. */
   const char          *ldapcertfile;         /* ...  with ldap cert file.    */
   const char          *ldapcertpath;         /* ...  with ldap cert db path. */
   const char          *ldapfilter;           /* ...  with ldap filter.       */
   const char          *ldapfilter_AD;        /* ...  with ldap AD filter.    */
   const char          *ldapkeytab;           /* ...   with ldap keytab.      */
#endif /* HAVE_LDAP */

   uid_t          euid;                         /* original euid.             */
   pid_t          *motherpidv;                  /* pid of mothers.            */
   pid_t          pid;                          /* pid of current process.    */

   int            type;                         /* process type we are.       */

   struct sockd_mother_t mother;                 /* if child, mother info.    */

   rlim_t         maxopenfiles;

#if BAREFOOTD
   unsigned char  alludpbounced;                /* bounced all udp addresses? */
#endif /* BAREFOOTD */
};

struct listenaddress_t {
   struct sockaddr      addr;                     /* bound address.           */

#if NEED_ACCEPTLOCK
   int                  lock;                     /* lock on structure.       */
#endif /* NEED_ACCEPTLOCK */

   int                  protocol;                 /*
                                                   * SOCKS_TCP or SOCKS_UDP?
                                                   * UDP only applicable to
                                                   * barefoot.
                                                   */

   int                  s;                        /* bound socket.            */
};

struct externaladdress_t {
   struct ruleaddr_t       *addrv;           /* addresses.                    */
   size_t                  addrc;
   int                     rotation;         /* how to rotate, if at all.     */
};

struct statistic_t {
   size_t                  accepted;         /* accepts done.                 */
   time_t                  boot;             /* time of server start.         */
   time_t                  configload;       /* time config was last loaded.  */

   struct {
      size_t               sendt;            /* clients sent to children.     */
      size_t               received;         /* clients received back.        */
   } negotiate;

   struct {
      size_t               sendt;            /* clients sent to children.     */
      size_t               received;         /* clients received back.        */
   } request;

   struct {
      size_t               sendt;            /* clients sent to children.     */
      size_t               received;         /* acks received back.           */
   } io;
};

struct childstate_t {
#ifdef HAVE_VOLATILE_SIG_ATOMIC_T
   sig_atomic_t            addchild;            /* okay to do a addchild()?   */
#else
   volatile sig_atomic_t   addchild;            /* okay to do a addchild()?   */
#endif /* HAVE_VOLATILE_SIG_ATOMIC_T */

   struct {
      size_t               negotiate;
      size_t               request;
      size_t               io;
   } maxidle;              /* how many children of this type can be idle.     */

   size_t                  maxrequests;         /*
                                                 * max # of requests to handle
                                                 * before quiting.
                                                 */
};

typedef struct {
   long    id;
} oldshmeminfo_t;


/* Make sure to keep in sync with resetconfig(). */
struct config_t {
   struct listenaddress_t     *internalv;          /* internal addresses      */
   size_t                     internalc;

   struct externaladdress_t   external;            /* external addresses.     */

   struct rule_t              *crule;              /* clientrules, list.      */
   struct rule_t              *srule;              /* socksrules, list.       */

   routeoptions_t             routeoptions;        /* global route flags.     */
   struct route_t             *route;

   int                        hostfd;              /*
                                                    * shmem file/lock for
                                                    * hostcache.
                                                    */


#if HAVE_LDAP
   int                        ldapfd;              /*
                                                    * shmem file/lock for
                                                    * ldap cache.
                                                    */
#endif /* HAVE_LDAP */

   int                        shmemfd;             /*
                                                    * shmem file/lock for
                                                    * shmeminfo and the rest
                                                    * of shared memory.
                                                    */

   int                        configfd;            /* open sockd.conf. */

   struct {
      int                     sighupid; /*
                                         * id of last sighup to mother.  Should
                                         * be incremented each time mother
                                         * gets a  SIGHUP.
                                         */

      unsigned long           firstkey; /*
                                         * Each time main monther is about to
                                         * parse the config-file, we need to
                                         * set this value.  All children
                                         * then know what the starting point
                                         * is.  For each shared object we
                                         * need to allocate as we parse
                                         * the rules, the shmid of the object
                                         * is know based on this starting
                                         * point.  The first object will
                                         * have this id, the next will have
                                         * this id + 1, the one after that,
                                         * this id + 2, etc.  That way
                                         * all children will know what
                                         * shmid to use for attaching
                                         * memory to a given shmem object.
                                         *
                                         * That of course means, this object
                                         * also needs to be stored in shmem.
                                         */
   } *shmeminfo;
   char                       shmem_fnamebase[PATH_MAX];

   oldshmeminfo_t             *oldshmemv; /* old shmem, not yet deleted.      */
   size_t                     oldshmemc;

   struct compat_t            compat;               /* compatibility options. */
   struct extension_t         extension;            /* extensions set.        */

   struct logtype_t           errlog;               /* for errors only.       */
   struct logtype_t           log;                  /* where to log.          */
   int                        loglock;              /* lockfile for logging.  */

   struct option_t            option;               /* commandline options.   */
   int                        resolveprotocol;      /* resolve protocol.      */
   struct socketconfig_t      socket;               /* socket options.        */
   struct srchost_t           srchost;              /* relevant to srchost.   */
   struct statistic_t         stat;                 /* some statistics.       */
   struct configstate_t       state;
   struct timeout_t           timeout;
#if HAVE_PRIVILEGES
    privileges_t              privileges;
#else /* !HAVE_PRIVILEGES */
   struct userid_t            uid;
#endif /* !HAVE_PRIVILEGES */

   struct childstate_t        child;                /* childstate.            */

   int                        clientmethodv[MAXMETHOD]; /* clientmethods.     */
   size_t                     clientmethodc;        /* methods in list.       */

   int                        methodv[MAXMETHOD];  /* methods by priority.    */
   size_t                     methodc;             /* methods in list.        */

   unsigned char              udpconnectdst;       /* connect udp sockets?    */

#if COVENANT
   char                       realmname[256];
#endif /* COVENANT */
};

typedef struct {
   gwaddr_t             server;
   struct sockshost_t   extaddr;
} proxychaininfo_t;


struct connectionstate_t {
   int                  command;
   int                  clientcommand;
   int                  protocol;
   int                  proxyprotocol;
   int                  clientprotocol;


   proxychaininfo_t     proxychain;   /* only if proxyprotocol is not direct. */
   struct extension_t   extension;     /* extensions set.                     */

   struct {
      struct timeval    accepted;      /* time connection accepted.           */
      struct timeval    negotiate;     /* time negotiation started.           */
      struct timeval    established;   /* time session was fully established. */
      struct timeval    firstio;       /* time of first i/o operation.        */
   } time;
   int                  version;
};

typedef struct {
   uint64_t         bytes;        /* bytes in addition to count <metric>.     */
   uint64_t         packets;      /* packet count.  Only applicable for udp.  */
} iocount_t;


#if BAREFOOTD
struct udpclient {
   int             s;

   /* XXX can we change some of these to pointers? */
   struct rule_t   crule;      /* client-rule matched for this client.        */
   struct rule_t   rule;       /* socks-rule matched for this client.         */
   struct rule_t   replyrule;  /* replyrule matched for this client.          */
   unsigned char   use_saved_rule; /* can we use reuse last rule result?      */
   unsigned char   use_saved_replyrule; /* and last replyrule result too?     */

   struct sockaddr laddr;      /* address we receive remote replies on.       */
   struct sockaddr raddr;      /* address of clients destination.             */
   struct sockaddr client;     /* address of our client.                      */

   iocount_t       src_read;
   iocount_t       src_written;
   iocount_t       dst_read;
   iocount_t       dst_written;

   struct timeval  firstio;  /* time of first i/o operation.                  */
   struct timeval  iotime;   /* time of last i/o operation.                   */
};
#endif /* BAREFOOTD */


struct sockd_io_direction_t {
   int                        s;          /* socket connection.               */
   struct sockaddr            laddr;      /* local address of s.              */
   struct sockaddr            raddr;      /* address of s's peer.             */

   struct authmethod_t        auth;        /* authentication in use on s.     */
   struct sockshost_t         host;
   /*
    * Varies according to context.
    * src    : as raddr but on sockshost_t form.
    * dst    : name as given by client.
    * control: same as src
   */

#if HAVE_GSSAPI
   OM_uint32                  maxgssdata; /* max length of gss data pre-enc.  */
#endif /* HAVE_GSSAPI */

   iocount_t                  read;
   iocount_t                  written;

   int                        flags;      /* misc. flags                      */

   struct {
      int      err;           /* errno.                                       */

#if COVENANT
      unsigned char isclientside;/* is this side the clientside? */
#endif /* COVENANT */

      unsigned char fin;            /* received FIN on this socket.           */
      unsigned char shutdown_wr;    /* shutdown for writing.                  */
      unsigned char connected;      /* socket has finnished connecting?       */
   } state;
};


struct sockd_io_t {
   unsigned char                 allocated; /* object currently allocated?    */
   struct connectionstate_t      state;
   struct authmethod_t           clientauth;/* client authentication in use.  */
   requestflags_t                reqflags;  /* original client request flags. */

   struct sockd_io_direction_t   control;  /* clients controlconnection.      */
   struct sockd_io_direction_t   src;      /* client we receive data from.    */
   struct sockd_io_direction_t   dst;      /* remote peer.                    */

#if BAREFOOTD
   struct udpclient              *dstv;
   size_t                        dstcmax;  /* number of slots in dstv array.  */
   size_t                        dstc;     /* # of slots currently in use.    */
#endif /* BAREFOOTD */

   /*
    * data received from the client that should be sent to the remote server,
    * but has not yet.
    */
#if HAVE_NEGOTIATE_PHASE
   char                          clientdata[MAXREQLEN];
   size_t                        clientdatalen;
#endif /* HAVE_NEGOTIATE_PHASE */


   struct rule_t      crule;           /* client rule matched.                */
   struct rule_t      rule;            /* matched rule for i/o.               */
   struct rule_t      *replyrule;      /*
					* matched rule for (udp)reply i/o.  Is
					* a pointer since it's only used
					* in the i/o processes, so we can
					* save on the size of the i/o object
					* when passing it around.
					*/
                                       /*
                                        * XXX should be used for bindreply
                                        * also, as bind and bindreply might
                                        * have different loglevels.
                                        */
   unsigned char      use_saved_rule;  /* can we use reuse last rule result?  */
   unsigned char      use_saved_replyrule; /* and last replyrule result too?  */

   struct timeval     iotime;          /* time of last i/o operation.         */
   struct sockd_io_t  *next;           /* for some special cases.             */
};

struct sockd_client_t {
   int            s;          /* socket client was accepted on. */
   struct timeval accepted;   /* time client was accepted.      */

#if COVENANT
   /*
    * if not zero, this is an "old" client that has been sent back
    * to the negotiate process from the i/o process, due to the client
    * changing it's target (remote http server).
    * "clientdata" contains the request received from the client,
    * already parsed into "request".
    */
   char                       clientdata[MAXREQLEN];
   size_t                     clientdatalen;

   struct authmethod_t        auth;
   struct request_t           request;
#endif /* COVENANT */
};




struct negotiate_state_t {
   unsigned char        complete;                    /* completed?            */

#if SOCKS_SERVER
   unsigned char        mem[ 1                       /* VER                   */
                           + 1                       /* NMETHODS              */
                           + AUTHMETHOD_MAX          /* METHODS               */
#if HAVE_GSSAPI
                           + MAXGSSAPITOKENLEN
#endif /* HAVE_GSSAPI */
                           + sizeof(struct request_t)
                           + 1                       /* NUL                   */
                           ];
#elif COVENANT
   /* no fixed limit in the http protocol?  Try this for now. */
   unsigned char        mem[MAXREQLEN];

   unsigned char         haverequestedproxyauth;
   unsigned char         havedonerulespermit;
#endif /* COVENANT */

   size_t               reqread;                     /* read so far.          */
   size_t               start;                       /* start of current req  */
   char                 emsg[512];                   /* error message, if any.*/
   negotiate_result_t   (*rcurrent)(int s,
                                    struct request_t *request,
                                    struct negotiate_state_t *state);

   struct sockshost_t   src;          /* client's address.                    */
   struct sockshost_t   dst;          /* our address.                         */

#if HAVE_GSSAPI
   unsigned short       gssapitoken_len; /* length of token we're working on. */
#endif /* HAVE_GSSAPI */
};

struct sockd_negotiate_t {
   unsigned char              allocated;

   struct authmethod_t        clientauth;  /* authentication for clientrule.  */
   struct authmethod_t        socksauth;   /* authentication for socks-rule.  */

   struct request_t           req;
   struct negotiate_state_t   negstate;

   struct rule_t              rule;        /* rule matched for accept().      */
#if COVENANT
   struct rule_t              srule;       /* rule matched at socks-level.    */
#endif /* COVENANT */

   int                        s;           /* client connection.              */
   struct connectionstate_t   state;       /* state of connection.            */
};


struct sockd_request_t {
   struct sockaddr            from;      /* client's control address.         */
   struct sockaddr            to;        /* address client was accepted on.   */
   struct authmethod_t        clientauth;/* client authentication in use.     */
   struct authmethod_t        socksauth; /* socks authentication in use.      */
   struct request_t           req;       /* request to perform.               */
   struct rule_t              rule;      /* rule matched for accept().        */
#if COVENANT
   struct rule_t              srule;       /* rule matched at socks-level.    */
#endif /* COVENANT */
   int                        s;         /* clients control connection.       */
   struct connectionstate_t   state;     /* state of connection.              */

#if HAVE_NEGOTIATE_PHASE /* the initial request from the client. */
   char                       clientdata[MAXREQLEN];
   size_t                     clientdatalen;
#endif /* HAVE_NEGOTIATE_PHASE */
};


struct sockd_child_t {
#if HAVE_SENDMSG_DEADLOCK
   int              lock;           /* lock on request connection.            */
#endif /* HAVE_SENDMSG_DEADLOCK */
   int              ack;            /* connection for ack's.                  */
   int              s;              /* connection to mother for data.         */

   pid_t            pid;            /* childs pid.                            */
   int              type;           /* child type.                            */
   size_t           freec;          /* free slots at the moment.              */
   size_t           sentc;          /* clients sent to this child.            */

#if BAREFOOTD
   unsigned char    hasudpsession;  /*
                                     * is one of the slots taken by an udp
                                     * session at the moment?
                                     */
#endif /* BAREFOOTD */
};


int
sockd_bind(int s, struct sockaddr *addr, size_t retries);
/*
 * Binds the address "addr" to the socket "s".  The bind call will
 * be tried "retries" + 1 times if the error is EADDRINUSE, or until
 * successful, whatever comes first.
 * If the port number is privileged, it will set and reset the euid
 * as appropriate.
 *
 * If successful, "addr" is filled in with the bound address.
 * Returns:
 *      On success: 0.
 *      On failure:   -1
 */

int
bindinternal(const int protocol);
/*
 * Binds all internal addresses using protocol "protocol".
 * Returns 0 on success, -1 on failure.
 */

int
sockd_bindinrange(int s, struct sockaddr *addr, in_port_t first, in_port_t last,
                  const enum operator_t op);
/*
 * Like sockd_bind(), but keeps trying to sockd_bind a address in the
 * range given by "addr", as indicated by "first", "last" and "op",
 * until whole range has been tried.
*/


int
pidismother(pid_t pid);
/*
 * If "pid" refers to a mother, the number of "pid" in
 * state.motherpidv is returned.  Numbers are counted from 1.
 * IF "pid" is no mother, 0 is returned.
 */

int
descriptorisreserved(int d);
/*
 * If "d" is a descriptor reserved for use globally, the function
 * returns true.
 * Otherwise, false.
 */

int
childcheck(int type);
/*
 * Calculates the number of free slots every child of type "type" has,
 * combined, and returns that number.
 *
 * If "type" is negated, the function instead returns the total number of
 * slots (free or not) in every child of that type.
 * This function also adjusts the number of children of type "type" if needed,
 * according to configured variables.
 */

int
childtype(pid_t pid);
/*
 * Returns the type of child the child with pid "pid" is.
 */

void
removechild(pid_t childpid);
/*
 * Removes the child "child" with pid "childpid" and updates internal lists.
 * If "childpid" is 0, removes all childs.
 */

void
addclientrule(const struct rule_t *rule);
/*
 * Appends a copy of "rule" to our list of client rules.
 */

void
addsocksrule(const struct rule_t *rule);
/*
 * Appends a copy of "rule" to our list of socks rules.
 * Returns a pointer to the added rule (not "rule").
 */

void
addinternal(const struct ruleaddr_t *addr, const int protocol);
/*
 * Adds "addr" to the list of external addresses.
 * "protocol" gives the protocol to add, SOCKS_TCP or SOCKS_UDP.
 */

void
addexternal(const struct ruleaddr_t *addr);
/*
 * Adds "addr" to the list of internal addresses (to listen on).
 */

int
addrisbindable(const struct ruleaddr_t *addr);
/*
 * Checks whether "addr" is bindable.
 * Returns:
 *      On success: true.
 *      On failure: false.
 */

int isreplycommandonly(const struct command_t *command);
/*
 * Returns true if "command" specifies reply-commands only (bind/udp-replies),
 * false otherwise.
 */


struct linkedname_t *
addlinkedname(struct linkedname_t **linkedname, const char *name);
/*
 * Adds a link with the name "name" to the list hanging of "linkedname".
 * Returns:
 *      On success: a pointer to linkedname.
 *      On failure: NULL.
 */

void
showrule(const struct rule_t *rule, const int isclientrule);
/*
 * Prints the rule "rule" to logfile.  "isclientrule" says whether
 * the rule is a client-rule or a socks-rule.
 */


void
showlist(const struct linkedname_t *list, const char *prefix);
/*
 * shows user names in "list".
 */


const char *
authname(const struct authmethod_t *auth);
/*
 * Returns a pointer to the name contained in "auth", or NULL if none.
 */

const char *
authinfo(const struct authmethod_t *auth, char *info, size_t infolen)
      __attribute__((__bounded__(__string__, 2, 3)));
/*
 * Fills in "info" with a printable representation of the "auth".
 * Returns a pointer to "info".
 */

int
rulespermit(int s, const struct sockaddr *peer, const struct sockaddr *local,
            const struct authmethod_t *clientauth, struct authmethod_t *srcauth,
            struct rule_t *rule, const struct connectionstate_t *state,
            const struct sockshost_t *src, const struct sockshost_t *dst,
            char *msg, size_t msgsize)
      __attribute__((__bounded__(__buffer__, 10, 11)));
/*
 * Checks whether the rules permit data from "src" to "dst".
 *
 * In Dantes and Covenants case, "s" is the socket the control connection is
 * on, from the address "peer", and accepted on the address "local".

 * In Barefoots case, these arguments refer to socket the connection
 * or udp packet was received on, with "local" and "peer" being the local
 * and remote endpoints, respectivly.
 *
 * "clientauth" is the authentication established for the client-rule, or
 * NULL if no authentication has yet been established for the client rule.
 * "srcauth" is the current authentication established for communicating with
 * "src".  It may be AUTHMETHOD_NONE or AUTHMETHOD_NOTSET and may be updated
 * by this function if an authentication-method is successfully established.
 * "state" is the state of the connection.
 * "msg" is filled in with any message/information provided when checking
 * access, "msgsize" is the size of "msg".
 *
 * Wildcard fields are supported for the following fields;
 *      ipv4:         INADDR_ANY
 *      port:         none [enum]
 *
 * "rule" is filled in with the contents of the matching rule.
 * Returns:
 *      True if a connection should be allowed.
 *      False otherwise.
 *
 * Notes: the global shmemlock needs to be taken before calling this
 *        function if any of the shared memory in the matching rule
 *        may be attached to.
 */

int
sockd_connect(int s, const struct sockshost_t *dst);
/*
 * Tries to connect socket "s" to the host given in "dst".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

void
resetconfig(const int exiting);
/*
 * resets the current config back to default, freeing memory aswell.
 * If "exiting" is true, we are exiting and don't need to save
 * anything.
 */



int
send_req(int s, struct sockd_request_t *req);
/*
 * Sends "req" to "s".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
send_client(int s, const struct sockd_client_t *client,
            const char *req, const size_t reqlen);
/*
 * Sends the client "client" to the process connected to "s".
 * If "reqlen" is not 0, it is data that has already been read from the
 * client, but not forwarded.  This Can only happen in the case of COVENANT.
 *
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

/*
 * Returns a value indicating whether relaying from "src" to "dst" should
 * be permitted.
 */

int
selectmethod(const int *methodv, size_t methodc,
      const unsigned char *offeredv, size_t offeredc);
/*
 * Selects the best method based on available methods and given
 * priority.
 * "methodv" is a list over available methods, methodc in length.
 * "offerdv" is a list over offered methods, offeredc in length.
 * The function returns the value of the method that should be selected,
 * AUTMETHOD_NOACCEPT if none is acceptable.
 */

negotiate_result_t
method_uname(int s, struct request_t *request,
      struct negotiate_state_t *state);
/*
 * Enters username/password subnegotiation.  If successful,
 * "request->auth.mdata.uname" is filled in with values read from client.
 * If unsuccessful, the contents of "uname" is indeterminate.
 * After negotiation has finished and the response to client has been sent
 * the function returns.
 * Returns:
 *      On success: 0 (user/password accepted)
 *      On failure: -1  (user/password not accepted, communication failure,
 *                       or something else.)
 */

#if HAVE_GSSAPI
negotiate_result_t
method_gssapi(int s, struct request_t *request,
      struct negotiate_state_t *state);
/*
 * Enters gssapi subnegotiation.  If successful, "request->auth.mdata.gssapi"
 * is filled in with values read from client.
 * If unsuccessful, the contents of "gssapi" is indeterminate.
 *
 * After negotiation has finished and the response to client has been sent
 * the function returns.
 *
 * Returns:
 *      On success: 0 (authentication and encryption token accepted)
 *      On failure: -1  (authentication or encryption token not accepted,
 *                       communication failure, or something else.)
 */
#endif /* HAVE_GSSAPI */

void
iolog(struct rule_t *rule, const struct connectionstate_t *state,
      const operation_t operation,
      const struct sockaddr *src_local, const struct sockshost_t *src_peer,
      const struct authmethod_t *src_auth,
      const gwaddr_t *src_proxy, const struct sockshost_t *src_proxyext,
      const struct authmethod_t *src_proxyauth,
      const struct sockaddr *dst_local, const struct sockshost_t *dst_peer,
      const struct authmethod_t *dst_auth,
      const gwaddr_t *dst_proxy, const struct sockshost_t *dst_proxyext,
      const struct authmethod_t *dst_proxyauth,
      const char *data, size_t count);
/*
 * Called after each each complete io operation
 * (read then write, or read then block).
 * Does misc. logging based on the logoptions set in "log".
 * "rule" is the rule that matched the iooperation, not "const" due to
 * possible libwrap interaction.
 * "state" is the state of the connection.
 * "operation" is the operation that was performed.
 * "src_peer" is where data was received from, on the local endpoint
 *  "src_local".
 * "dst_peer" is where data was written to, on the local endpoint
 * "dst_local".
 *
 * "{src,dst}_proxy", if not NULL, is the proxyserver used in this
 * serverchain, for data to/from src_peer or to/from dst_peer,
 * with auth {src,dst}_proxyauth.
 *
 * "{src,dst}_proxyext", if not NULL, is the external address used by the
 * proxyserver in this serverchain, for data to/from src_peer or
 * to/from dst_peer,
 *
 * "data" and "count" are interpreted depending on "operation".
 *
 * If "operation" is
 *    OPERATION_ACCEPT
 *    OPERATION_CONNECT
 *       "count" is ignored.
 *       If "data" is not NULL or NUL, it is a string giving additional
 *       information about the operation.
 *
 *    OPERATION_ABORT
 *    OPERATION_ERROR
 *       "count" is ignored.
 *       If "data" is not NULL or NUL, it is a string giving the reason for
 *       abort or error.
 *       If "data" is NULL or NUL, the reason is the error message affiliated
 *       with the current errno.
 *
 *    OPERATION_IO
 *       "data" is the data that was read and written.
 *       "count" is the number of bytes that was read/written.
 */

void
close_iodescriptors(const struct sockd_io_t *io);
/*
 * A subset of delete_io().  Will just close all descriptors in
 * "io".
 */

int
sockdnegotiate(int s);
/*
 * Sends the connection "s" to a negotiator child.
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

void
run_io(void);
/*
 * Sets a io child running.  "mother" is the childs mother.
 *
 * A child starts running with zero clients and waits
 * indefinitely for mother to send at least one.
 */

void
run_negotiate(void);
/*
 * Sets a negotiator child running.
 * A child starts running with zero clients and waits
 * indefinitely for mother to send at least one.
 */

void
run_request(void);
/*
 * Sets a request child running.
 * A child starts running with zero clients and waits
 * indefinitely for mother to send at least one.
 */

int
send_io(int s, struct sockd_io_t *io);
/*
 * Sends the io-object "io" to "s".
 * Returns
 *    On success: 0
 *    On failure: -1
 */


int
recv_io(int mother, struct sockd_io_t *io);
/*
 * Attempts to read a new io object from "mother".
 * If a io is received it is either copied into "io", or it's copied
 * Returns:
 *      On success: 0
 *      On failure: -1.  Errno will be set.
 */

int
recv_req(int s, struct sockd_request_t *req);
/*
 * Receives a request from the socket "s" and stores it in "req".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

negotiate_result_t
recv_clientrequest(int s, struct request_t *request,
                   struct negotiate_state_t *state);
/*
 * Reads a request from the socket "s", which can be set to non-blocking.
 * "request" will be filled in as reading progresses but it should
 * be considered of indeterminate contents until the whole request
 * has been read.
 * Returns the result (continue, finished, error).
 */

negotiate_result_t
recv_sockspacket(int s, struct request_t *request,
      struct negotiate_state_t *state);
/*
 * When method negotiation has finished (if appropriate) this function
 * is called to receive the actual packet.
 */

struct sockd_child_t *
getchild(pid_t pid);
/*
 * Attempts to find a child with pid "pid".
 * Returns:
 *      On success: a pointer to the found child.
 *      On failure: NULL.
 */

void
sigchildbroadcast(int sig, int childtype);
/*
 * Sends signal "sig" to all children of type "childtype".
 */

int
fillset(fd_set *set, int *negc, int *reqc, int *ioc);
/*
 * Sets every child's descriptor in "set", aswell as sockets we listen on.
 * "negc", "reqc", and "ioc" is upon return filled in with the number of
 * currently free negotiate slots, request slots, and io slots, respectivly.
 *
 * Returns the number of the highest descriptor set, or -1 if none was set.
 */

void
clearset(whichpipe_t type, const struct sockd_child_t *child, fd_set *set);
/*
 * Clears every descriptor of type "type" in "child" from "set".
 * "type" gives the type of pipe that must be set.
 */

struct sockd_child_t *
getset(whichpipe_t type, fd_set *set);
/*
 * If there is a child with a descriptor set in "set", a pointer to
 * the child is returned.
 * "type" gives the type of pipe that must be set.
 * The children returned are returned in prioritized order.
 * If no child is found, NULL is returned.
 */

struct sockd_child_t *
nextchild(const int type, const int protocol);
/*
 * Returns:
 *      On success: pointer to a child of correct type with at least one free
 *      slot of protocol type "protocol".
 *      On failure: NULL.
 */

void
setsockoptions(const int s, const int type, const int isclientside);
/*
 * Sets options _all_ server sockets should have set on the socket "s".
 * "type" gives what type of socket "s" is, SOCK_STREAM or SOCK_DGRAM.
 * If "isclientside" is set, the socket is to be used to receive data
 * from the client.
 */

void
sockdexit(const int exitcode);
/*
 * Exits with the value of "exitcode".
 */

struct hostent *
cgethostbyname(const char *name);
/*
 * Identical to gethostbyname() but caches info.
 */

struct hostent *
cgethostbyaddr(const void *addr, socklen_t len, int type);
/*
 * Identical to gethostbyaddr() but caches info.
 */

int
socks_seteuid(uid_t *old, uid_t new);
/*
 * Sets euid to "new".  If "old" is not NULL, current euid is saved in it.
 * Returns 0 on success, -1 on failure.
 */

void
init_privs(void);
/*
 * Initializes the basic and permitted privilege set on.
 */

void
sockd_priv(const privilege_t privilege, const priv_op_t op);
/*
 * Acquires or releases the privilege associated with the privilege
 * "privilege".
 * "op" indicates whether the privilege should be acquired or relinquished,
 * and must have one of the values PRIV_ON or PRIV_OFF, correspondingly.
 */

int
usermatch(const struct authmethod_t *auth,
      const struct linkedname_t *userlist);
/*
 * Checks whether the username in "auth" matches a name in the
 * list "userlist".
 * Returns:
 *    If match: true.
 *      Else: false.
 */

int
groupmatch(const struct authmethod_t *auth,
      const struct linkedname_t *grouplist);
/*
 * Checks whether the username in "auth" matches groupname listed in "userlist".
 * Returns:
 *    If match: true.
 *      Else: false.
 */

#if HAVE_LDAP
int
ldapgroupmatch(const struct authmethod_t *auth, const struct rule_t *rule);
/*
 * Checks whether the username in "auth" matches ldap groupname listed
 * in "userlist".
 * Returns:
 *    If match: true.
 *    Else: false.
 */

int
ldapgroupmatches(const char *username, const char *userdomain,
                 const char *group, const char *groupdomain,
                 const struct rule_t *rule);
/*
 * Checks if user "username" in Kerberos domain "userdomain" is member of
 * ldap group "group" in Kerberos domain "groupdomain".
 * Rule "rule" contains further ldap parameters.
 */

void
cache_ldap_user(const char *username, int result);
/*
 * Add user "username" to cache.
 * "retval" gives the result to cache.
 * XXX result should be enum, and used in ldap_user_is_cached() also?
 */

int
ldap_user_is_cached(const char *username);
/*
 * Checks if user "ussername" is cached.
 * Returns:
 *    If not cached: -1
 *    Else: 0 or 1
 */

char
*asciitoutf8(char *input);
/*
 * Checks if string contains character > 127 and converts them to UTF8
 */

char
*hextoutf8(char *input, int flag);
/*
 * Convert hex input to UTF8 character string
 * flag = 2 convert input (all)
 * flag = 1 convert input (group name/basedn and realm)
 * flag = 0 convert input (only group name/basedn)
 * XXX flag should be enum.
 */

#endif /* HAVE_LDAP */

int
accesscheck(int s, struct authmethod_t *auth, const struct sockaddr *src,
      const struct sockaddr *dst, char *emsg, size_t emsgsize)
      __attribute__((__bounded__(__buffer__, 5, 6)));
/*
 * Checks whether access matches according to supplied arguments.
 * "auth" is the authentication to be matched against,
 * "s" is the socket the client is connected to,
 * "src" is address client connected from, "dst" is address client
 * connected to.
 * "emsg" is a buffer that information can be written into, "emsgsize"
 * is the size of that buffer.
 *
 * Returns:
 *      If access is ok: true.
 *      Otherwise: false.  Writes the reason into "emsg".
 */

int
passwordcheck(const char *name, const char *cleartextpassword,
      char *emsg, size_t emsglen)
      __attribute__((__bounded__(__buffer__, 3, 4)));
/*
 * Checks whether "name" is in the passwordfile.
 * If "cleartextpassword" is not NULL, also checks if "name"'s
 * password is "cleartextpassword".
 *
 * Returns:
 *      If "name" and "cleartextpassword" is matched: 0
 *      Otherwise: -1.  "emsg" is filled in with the error message.
 */

int
pam_passwordcheck(int s,
      const struct sockaddr *src, const struct sockaddr *dst,
      const struct authmethod_pam_t *auth, char *emsg, size_t emsglen)
      __attribute__((__bounded__(__buffer__, 5, 6)));
/*
 * Checks whether pam grants access to the client connected to the socket "s".
 * "src" is the clients source address, "dst" is address we accepted the
 * clients connection on.
 *
 * Returns:
 *      If "name" and "cleartext password" is matched: 0
 *      Otherwise: -1.  "emsg" is filled in with the error message.
 */

int
bsdauth_passwordcheck(int s,
      const struct sockaddr *src, const struct sockaddr *dst,
      struct authmethod_bsd_t *auth, char *emsg, size_t emsgsize)
      __attribute__((__bounded__(__buffer__, 5, 6)));
/*
 * Checks whether bsd authentication grants access to the client
 * connected to the socket "s".  "src" is the clients source address,
 * "dst" is address we accepted the clients connection on.
 *
 * Returns:
 *      If "name" and "cleartext password" is matched: 0
 *      Otherwise: -1.  "emsg" is filled in with the error message.
 */

void
redirectsetup(void);
/*
 * sets up things for using the redirect module.
 * Must be called at start and after sighup by main mother.
 */

int
redirect(int s, struct sockaddr *addr, struct sockshost_t *host,
      int command, const struct ruleaddr_t *from, const struct ruleaddr_t *to);
/*
 * "s" is the socket to use for performing "command".
 * The meaning of "addr" and "host" varies depending on what "command" is:
 *      SOCKS_BIND:
 *         "addr" is local address of "s", to accept remote connection on.
 *         "host" is ignored.
 *
 *      SOCKS_BINDREPLY:
 *         "addr" is the address to say connection is from.
 *         "host" is the address to send reply to.
 *
 *      SOCKS_CONNECT:
 *         "addr" is local address of "s".
 *         "host" is host to connect to.
 *
 *      case SOCKS_UDPASSOCIATE:
 *         "addr" is the address to tell the client the udp packet is from.
 *         "host" is the address to send packet to.
 *
 *      case SOCKS_UDPREPLY:
 *         "addr" is the address to say reply is from.
 *         "host" is the address to send reply to.
 *
 * "host", "addr", and the address of "s" will be changed if needed.
 * Returns:
 *      On success: 0.
 *      On failure: -1.
 */

void
hostcachesetup(void);
/*
 * Initalizes the hostcache.  Must be called before any calls to
 * cgethostby*().
 */

void
ldapcachesetup(void);
/*
 * Initalizes the ldapcache.  Must be called before any calls to
 * ldap functions.
 */

char *
sockd_getshmemname(const long id);
/*
 * Returns the shmemname coresponding to the id "id".
 */

void
sockd_shmdt(struct rule_t *rule, const int which);
/*
 * Detaches shared memory segments in rule "rule" as indicated by which,
 * and sets the value of the detached objects to not in use.
 */

void
sockd_shmat(struct rule_t *rule, const int which);
/*
 * Attaches shared memory segments in "rule" as indicated by which.
 * Warnings are printed if the attach fails, but the error is
 * not considered to be fatal.  The attachments that fail are
 * set to NULL/-1.
 */

void shmem_setup(void);
/*
 * sets up things for using shared memory.
 */

int
shmem_alloc(const size_t len, const key_t key);
/*
 * allocate shared memory of size "len" and the shmid of the memory.
 * Return -1 on failure.
 */

unsigned long
mem2shmem(const unsigned long firstid);
/*
 * Deallocates from all rules starting with "firstrule" ordinary memory for
 * objects that should be in shared memory and alloacates shared memory
 * for it instead.
 * "firstid" is the d to use for the first allocation.  The id of
 * subsequent allocations is incremented by one.
 *
 * Returns the id of the last id used.
 */

void
shmem_unuse(shmem_object_t *object, int lock);
/*
 * Says we are no longer using "object".
 * "lock" is used for locking, if it is -1, no locking is enforced.
 */

void
shmem_use(shmem_object_t *object, int lock);
/*
 * Marks "object" as in use.
 * "lock" is used for locking, if it is -1, no locking is enforced.
 */

void *
sockd_mmap(size_t size, const int fd, const int docreate);
/*
 * Allocates shared memory of size "size", using "fd" for storage
 * and mmap()s it.
 * If "docreate" is set, this is a call to create the memory, and the
 * function will make sure to extend the file referenced by fd to
 * atleast "size" bytes.
 * If "docreate" is not set, this is a remap of a previously created
 * shmem segment.
 *
 * Returns a pointer to the memory allocated.
 */

void
bw_use(shmem_object_t *bw, const int lock);
/*
 * Marks "bw" as in use.
 */

void
bw_unuse(shmem_object_t *bw, const int lock);
/*
 * Says we are no longer using "bw".
 * If "bw" is NULL, nothing is done.
 */

ssize_t
bw_left(const shmem_object_t *bw, const int lock);
/*
 * Returns how many bytes we should read if the client is restricted
 * by "bw".
 */

void
bw_update(shmem_object_t *bw, size_t bwused, const struct timeval *bwusedtime,
          const int lock);
/*
 * Updates "bw".  "bwused" is the bandwidth used (in bytes) at time
 * "bwusedtime".
 */

struct timeval *
bw_isoverflow(shmem_object_t *bw, const struct timeval *timenow,
              struct timeval *overflow, const int lock);
/*
 * Checks whether "bw" has overflowed.  I.e., used too much bandwidth.
 * "timenow" is the time now, and "overflow" is the object to store
 * the point in time when this object is no longer in overflowmode.
 *
 * If "bw" is not in overflowmode, this function resets the counters
 * related to determining whether to much bandwidth has been
 * used (bw.iotime and bw.bytes).
 *
 * Returns:
 *      If "bw" is in overflow mode: til what time we have to wait until
 *      we can again transfer data.  The memory used for this value is
 *      "overflow".
 *
 *      If "bw" is not in overflow mode: NULL.  "overflow" is not touched.
 */

int
session_use(shmem_object_t *ss, const int lock);
/*
 * If limits allow "ss" to be marked as in use, return true.
 * Else return false.
 */

void
session_unuse(shmem_object_t *ss, const int lock);
/*
 * Says we are no longer using "ss".
 */

int sockd_handledsignals(void);
/*
 * Check if we have received any signal, and calls the appropriate
 * signalhandler if so.
 *
 * Returns 1 if a signalhandler was called, 0 otherwise.
 */


#ifdef DEBUG
void
printfd(const struct sockd_io_t *io, const char *prefix);
/*
 * prints the contents of "io".  "prefix" is the string prepended
 * to the printing. (typically "received" or "sent".)
 */
#endif /* DEBUG */

struct in_addr
getoutaddr(const struct in_addr src, const struct in_addr dst);
/*
 * Returns the outgoing address to use for connecting to the IP address
 * "dst".
 *
 * "src" is the IP address the client, on whos behalf we are connecting to
 * "dst", was accepted on.
 */

void
sigserverbroadcast(int sig);
/*
 * Broadcasts "sig" to other "main" servers (started with "-N" option).
 *
 */

void
sockd_pushsignal(const int sig, const siginfo_t *siginfo);
/*
 * Adds the signal "sig" to the end of the internal signal stack.
 */


int
sockd_popsignal(siginfo_t *siginfo);
/*
 * Pops the first signal on the internal signal stack.
 * Returns the signalnumber, and stores the siginfo in "siginfo".
 */



unsigned char *
socks_getmacaddr(const char *ifname, unsigned char *macaddr);
/*
 * Writes the mac-address of the interface named "ifname" to "macaddr",
 * which must be of at least length ETHER_ADDR_LEN.
 * Returns a pointer to macaddress, or NULL if no mac-address
 * is set for the interface.
 */

ssize_t
addrindex_on_listenlist(const size_t listc, const struct listenaddress_t *listv,
                        const struct sockaddr *addr, const int protocol);
/*
 * Checks if "addr" is on the list of internal addresses, as
 * given by "listc" and 'listv".
 * "protocol" gives the protocol to check for, SOCKS_TCP or SOCKS_UDP.
 *
 * Returns the index of addr in listv if addr is on the list, or -1 if not.
 */

ssize_t
addrindex_on_externallist(const struct externaladdress_t *external,
                          const struct in_addr addr);
/*
 * Checks if "addr" is on the list of external addresses, as
 * given by "external".
 *
 * Returns the index of addr in listv if addr is on the list, or -1 if not.
 */


size_t maxfreeslots(const int childtype);
/*
 * Returns the maximum number of free slots a child of type "childtype"
 * can have.
 */

int
methodisvalid(const int method, const int forclientrules);
/*
 * Returns true if "method" is a valid method for either:
 *    - client-rules, if "forclientrules" is true.
 *    - for socks-rules if "forclientrules" is not true.
 */

int methodcanprovide(const int method, const methodinfo_t what);
/*
 * Returns true if method "method" can possibly provide "what".
 * It does not mean the method will always provide it, only
 * that it can in some cases.
 */

void
io_handlesighup(void);
/*
 * Called at sighup to let the i/o childs do what they need to do
 * upon receiving a sighup.
 */


#if BAREFOOTD
int
io_remove_session(const struct sockaddr *laddr, const int protocol);
/*
 * This function tries to find a session where the local address is "addr",
 * using protocol "protocol".  If found, the session is removed.
 *
 * If "addr" is NULL, all sessions using protocol "protocol" are removed.
 *
 * Returns:
 *    If a matching session was found: 0.
 *    If no matching sessionwas found: -1.
 */
#endif /* BAREFOOTD */


#if COVENANT

int
resend_client(struct sockd_io_t *io);
/*
 * Resends the client using "io" to mother, for renogotiation.
 * This happens when a http client wants to connect to a different
 * remote server.
 *
 * Returns 0 on success, -1 on error.
 */

int
recv_resentclient(int s, struct sockd_client_t *client);
/*
 * Receives the resent client from "s".  The resent client
 * stored in "client".
 *
 * Returns 0 on success, -1 on error.
 */

negotiate_result_t
recv_httprequest(int s, struct request_t *request,
                 struct negotiate_state_t *state);
/*
 * Reads a http request from the socket "s", which can be set to
 * non-blocking.
 * "request" will be filled in as reading progresses but it should
 * be considered of indeterminate contents until the whole request
 * has been read.
 * Returns:
 *    On success: > 0
 *    On failure: <= 0.  If errno does not indicate the request should be
 *                       be retried, the connection "s" should be dropped.
 */

int
parse_httprequest(struct request_t *reqinfo, const char *req,
                  char *emsg, size_t emsglen);
/*
 * Parses the http request present in the NUL-terminated string "req".
 * The information extracted from the request is stored in "reqinfo".
 *
 * Returns 0 on success, or -1 on error.  On error, "emsg", of size "emsglen"
 * is filled in with information about the error.
 */

size_t
httpresponse2mem(const int s, const struct response_t *response,
                 char *buf, const size_t buflen);

#endif /* COVENANT */

#if HAVE_NEGOTIATE_PHASE
struct response_t *
create_response(const struct sockshost_t *host, struct authmethod_t *auth,
                const int version, const int responsecode,
                struct response_t *response);
/*
 * Fills in the responseobject "response" based on data the passed data.
 * "responsecode" is the proxy version "version" code to set the reply to.
 * If "host" is not NULL, it is the host to use in response.
 * If "host" is NULL, an all-zero ipv4 address is used instead.
 */

void
send_failure(int s, struct response_t *response, int failure);
/*
 * Wrapper around send_response() that sends a failure message to the
 * client connected to "s" and deletes gss state if in use.
 *
 * "response" is the packet we send,
 * "failure" is the errno reason for failure,
 * and "auth" is the agreed on authentication.
 */

int
send_response(int s, const struct response_t *response);
/*
 * Sends "response" to "s".
 *      On success: 0
 *      On failure: -1
 */

#else /* !HAVE_NEGOTIATE_PHASE */

#define send_failure(s, response, failure)
#define send_response(s, response)            (0)

#endif /* !HAVE_NEGOTIATE_PHASE */


#endif /* !_SOCKD_H_ */
