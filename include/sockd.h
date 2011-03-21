/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010
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

/* $Id: sockd.h,v 1.317.2.6.2.3.2.10 2011/03/12 16:53:43 michaels Exp $ */

#ifndef _SOCKD_H_
#define _SOCKD_H_
#endif /* !_SOCKD_H_ */

#if HAVE_SOLARIS_PRIVS
#include <priv.h>
#endif /* HAVE_SOLARIS_PRIVS */

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
#define SOCKD_IOTIMEOUT_UDP          (3600)  /* 24h */
#endif

#if BAREFOOTD

/* minsize, used to get icmp errors.  */
#define RAW_SOCKETBUFFER              (1024 * 100)

#endif /* BAREFOOTD */

/* use caching versions directly, avoid overhead. */
#undef gethostbyname
#define gethostbyname(name)            cgethostbyname(name)
#undef gethostbyaddr
#define gethostbyaddr(addr, len, type) cgethostbyaddr(addr, len, type)


#define INIT(length)                                                           \
   const size_t start   = state->start;       /* start of next block. */       \
   const size_t end     = start + (length);   /* end of next block.   */       \
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
         SERRX(LEFT());                                        \
                                                               \
      errno = 0;                                               \
      if ((p = READ(s, LEFT(), auth)) <= 0)                    \
         return p;                                             \
      state->reqread += p;                                     \
                                                               \
      if (LEFT()) { /* read something, but not all. */         \
         errno = EWOULDBLOCK;                                  \
         return -1;                                            \
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
 * Checks whether "object" has been filled with all data requested and
 * if so calls "function", if function is not NULL.
 * If "object" has not been filled it returns the number of bytes
 * that was added to object on this call, or error.
*/

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


/* sent by sockd children to mother. */
#define SOCKD_NEWREQUEST   (1)   /* sending a new request.          */
#define SOCKD_FREESLOT     (2)   /* free'd a slot.                  */


/* a request child can currently only handle a maximum of one client. */
#define SOCKD_REQUESTMAX   1


/* types of children. */
#define CHILD_MOTHER        1
#define CHILD_NEGOTIATE     2
#define CHILD_REQUEST       3
#define CHILD_IO            4

#define FDPASS_MAX         3   /* max number of descriptors we send/receive. */


   /*
    * config stuff
    */

#define VERDICT_BLOCKs     "block"
#define VERDICT_PASSs      "pass"

/* how to rotate addresses. */
#define ROTATION_NONE       0
#define ROTATION_ROUTE      1

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
               SOCKD_PRIV_GSSAPI
} privilege_t;


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



#define fakesockaddr2sockshost sockaddr2sockshost/* no fakes in server. */

typedef enum { ACKPIPE, DATAPIPE } whichpipe_t;

struct compat_t {
   unsigned reuseaddr:1;       /* set SO_REUSEADDR?                        */
   unsigned sameport:1;        /* always try to use same port as client?   */
   unsigned draft_5_05:1;      /* try to support parts of socks 5.05 draft */
   unsigned :0;
};

struct log_t {
   unsigned connect:1;
   unsigned disconnect:1;
   unsigned data:1;
   unsigned error:1;
   unsigned iooperation:1;
   unsigned :0;
};


struct timeout_t {
   size_t         negotiate;  /* how long negotiation can last.               */
   size_t         tcpio;      /* how long connection lasts without i/o.       */
   size_t         udpio;      /* how long connection lasts without i/o.       */
};


struct linkedname_t {
   char                  *name;
   struct linkedname_t   *next;   /* next name in list.                       */
};

typedef struct {
   ssize_t           clients;           /* clients using this object.         */
   unsigned          expired:1;         /* the rule has expired.              */
   unsigned          isclientrule:1;    /* is used by clientrule.             */
   size_t            rulenumber;        /* rule number using this.            */
} shmem_header_t;

typedef struct {
   struct timeval        iotime;          /* time of last i/o operation.      */
   long                  bytes;           /* amount of bytes done at time.    */
   long                  maxbps;          /* maximal b/s allowed.             */
} bw_t;

typedef struct {
   int                  maxsessions;      /* max number of sessions allowed.  */
} session_t;

typedef struct {
   shmem_header_t         mstate;
   union {
      bw_t               bw;
      session_t         session;
   } object;
} shmem_object_t;


typedef enum { KEY_IPV4, KEY_MAC } keytype_t;
typedef struct {
   keytype_t key;

   union {
      struct in_addr ipv4;
      unsigned char  macaddr[ETHER_ADDR_LEN];
   } value;
} licensekey_t;

typedef enum { 
   OPERATION_ACCEPT,
   OPERATION_CONNECT,
   OPERATION_DISCONNECT,
   OPERATION_IO,
   OPERATION_TIMEOUT,
   OPERATION_TMPERROR,
   OPERATION_ERROR,
   OPERATION_BLOCK
} operation_t;

/* linked list over current rules. */
struct rule_t {
   struct ruleaddr_t       src;          /* src.                              */
   struct ruleaddr_t       dst;          /* dst.                              */
   struct log_t            log;          /* type of logging to do.            */
   size_t                  number;       /* rulenumber.                       */
   size_t                  linenumber;   /* linenumber; info/debugging only.  */
   struct serverstate_t    state;
   struct linkedname_t     *user;        /* name of users allowed.            */
   struct linkedname_t     *group;       /* name of groups allowed.           */
   int                     verdict;      /* verdict for this rule.            */

   struct {
      in_port_t            start;
      in_port_t            end;
      enum operator_t      op;
   } udprange;

#if HAVE_LIBWRAP
   char                    libwrap[LIBWRAPBUF];   /* libwrapline.             */
#endif /* HAVE_LIBWRAP */

#if BAREFOOTD
   unsigned                bounced:1; /*
                                       * have we faked a request for this addr
                                       * already?  Only used for udp.
                                       */
   struct ruleaddr_t       bounce_to;
   struct rule_t           *crule;     /*
                                        * if udp srule, crule used to generate
                                        * it.
                                        */
#endif /* BAREFOOTD */

   struct ruleaddr_t       rdr_from;
   struct ruleaddr_t       rdr_to;

   bw_t                    *bw;        /* pointer since will be shared.       */
   session_t               *ss;        /* pointer since will be shared.       */

   struct rule_t           *next;      /* next rule in list.                  */
};

struct srchost_t {
   unsigned nomismatch:1;     /* deny if dns mismatch between claim/fact?  */
   unsigned nounknown:1;      /* deny if no fact?                          */
   unsigned checkreplyauth:1; /* check that method matches for replies?    */
   unsigned :0;
};

struct option_t {
   char              *configfile;     /* name of configfile.                  */
   unsigned          daemon:1;        /* run as a daemon?                     */
   int               debug;           /* debug level.                         */
   unsigned          keepalive:1;     /* set SO_KEEPALIVE?                    */
   int               directfallback;  /* fallback to direct connections       */
   size_t            serverc;         /* number of servers.                   */
   unsigned          udpconnectdst:1; /* connect udp sockets?                 */
};


#if HAVE_PRIVILEGES
typedef struct {
   unsigned         noprivs:1;       /* no privilege-switching possible? */
   priv_set_t       *unprivileged;
   priv_set_t       *privileged;
} privileges_t;

#else /* !HAVE_PRIVILEGES */
struct userid_t {
   uid_t            privileged;
   unsigned         privileged_isset:1;
   uid_t            unprivileged;
   unsigned         unprivileged_isset:1;
   uid_t            libwrap;
   unsigned         libwrap_isset:1;
};
#endif /* !HAVE_PRIVILEGES */

struct configstate_t {
   unsigned            init:1;
   sig_atomic_t        insignal;          /* executing in signalhandler?      */
   sig_atomic_t        signalv[_NSIG];    /* stacked signals.                 */
   sig_atomic_t        signalc;           /* number of stacked signals.       */

#if HAVE_PAM
   /*
    * allows us to optimize a few things a little based on configuration.
    * If it is NULL, the value can vary from rule to rule, otherwise,
    * the value is fixed and this variable points to the fixed value.
    */
   const char          *pamservicename;
#endif /* HAVE_PAM */

#if HAVE_GSSAPI
   /*
    * allows us to optimize a few things a little based on configuration.
    * If it is NULL, the values can vary from rule to rule, otherwise,
    * the value is fixed and these variables point to the fixed value.
    */
   const char          *gssapiservicename;    /* have rules with gssapidata.  */
   const char          *gssapikeytab;         /* have rules with gssapidata.  */
#endif /* HAVE_GSSAPI */

   uid_t          euid;                         /* original euid.             */
   pid_t          *motherpidv;                  /* pid of mothers.            */
   pid_t          pid;                          /* pid of current process.    */
   int            type;                         /* process type we are.       */
   unsigned       upnpbroadcast_directroute:1;  /* direct upnp broadcast?     */

   rlim_t         maxopenfiles;

#if BAREFOOTD
   unsigned       alludpbounced:1;            /* bounced all udp addresses? */
#endif /* BAREFOOTD */

};

struct listenaddress_t {
   struct sockaddr      addr;                     /* bound address.           */
   int                  s;                        /* bound socket.            */
#if NEED_ACCEPTLOCK
   int                  lock;                     /* lock on structure.       */
#endif /* NEED_ACCEPTLOCK */
};

struct externaladdress_t {
   struct ruleaddr_t       *addrv;           /* addresses.                    */
   size_t                  addrc;
   int                     rotation;         /* how to rotate, if at all.     */
};

struct statistic_t {
   time_t                  boot;             /* time of server start.          */
   size_t                  accepted;         /* accepts done.                 */

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

   size_t                  maxidle;             /* how many can be idle.      */
   size_t                  maxrequests;         /*
                                                 * max # of requests to handle
                                                 * before quiting.
                                                 */
};


/* Make sure to keep in sync with resetconfig(). */
struct config_t {
   struct listenaddress_t     *internalv;          /* internal address'.      */
   size_t                     internalc;

   struct externaladdress_t   external;            /* external address'.      */

   struct rule_t              *crule;              /* clientrules, list.      */
   struct rule_t              *srule;              /* socksrules, list.       */
   struct route_t             *route;

   shmem_object_t             *bwv;                /* bwmem for rules.        */
   size_t                     bwc;
   /*
    * should have one for each rule instead, but sadly some systems seem to
    * have trouble with sysv-style shared memory/semaphores so we use
    * the older/better supported filelock, and a global too at that.
    */
   int                        bwlock;               /* lock for modifying bw. */

   shmem_object_t             *sessionv;            /* sessionmem for rules.  */
   size_t                     sessionc;
   int                        sessionlock;          /* lock for sessionv      */

   struct compat_t            compat;               /* compatibility options. */
   struct extension_t         extension;            /* extensions set.        */
   struct logtype_t           log;                  /* where to log.          */
   struct option_t            option;               /* commandline options.   */
   int                        resolveprotocol;      /* resolve protocol.      */
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
};

typedef struct {
   gwaddr_t             server;
   struct sockshost_t   extaddr;
} proxychaininfo_t;

struct connectionstate_t {
   int                  command;
   int                  clientcommand;
   int                  proxyprotocol;
   int                  protocol;
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
   size_t           bytes;        /* bytes in addition to count <metric>.     */
   size_t           packets;      /* packet count.  Only applicable to udp.   */
} iocount_t;


#if BAREFOOTD
struct udpclient {
   int             s;

   struct sockaddr laddr;
   struct sockaddr raddr;

   iocount_t       src_read;
   iocount_t       src_written;
   iocount_t       dst_read;
   iocount_t       dst_written;

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
    * control: same as src.
   */

   int                        sndlowat;   /* low-water mark for send.         */
#if HAVE_GSSAPI
   OM_uint32                  maxgssdata; /* max length of gss data pre-enc.  */
#endif /* HAVE_GSSAPI */

   iocount_t                  read;
   iocount_t                  written;

   int                        flags;      /* misc. flags                      */
   struct {
      unsigned fin:1;         /* received FIN on this socket.     */
      unsigned shutdown_wr:1; /* shutdown for writing.            */
      unsigned connected:1;   /* if udp socket, is it connected?  */
   } state;
};


struct sockd_io_t {
   unsigned                      allocated:1; /* object allocated?            */
   struct connectionstate_t      state;
   struct authmethod_t           clientauth;/* client authentication in use.  */

   struct sockd_io_direction_t   control;  /* clients controlconnection.      */
   struct sockd_io_direction_t   src;      /* client we receive data from.    */
   struct sockd_io_direction_t   dst;      /* remote peer.                    */
#if BAREFOOTD
   struct udpclient              *dstv;
   size_t                        dstcmax;  /* number of slots in dstv array.  */
   size_t                        dstc;     /* # of slots currently in use.    */
#endif /* BAREFOOTD */

   struct rule_t                 crule;    /* client rule matched.            */
   struct rule_t                 rule;     /* matched rule for i/o.           */

   struct rule_t                 replyrule;/* 
                                            * matched rule for reply i/o, 
                                            * if separate. 
                                            */

   struct timeval                iotime;   /* time of last i/o operation.     */
   struct sockd_io_t             *next;    /* for some special cases.         */
};

struct sockd_client_t {
   int            s;          /* socket client was accepted on. */
   struct timeval accepted;   /* time client was accepted.      */
};




struct negotiate_state_t {
   unsigned             complete:1;                  /* completed?            */
   unsigned char        mem[ 1                       /* VER                   */
                           + 1                       /* NMETHODS              */
                           + AUTHMETHOD_MAX          /* METHODS               */
#if HAVE_GSSAPI
                           + MAXGSSAPITOKENLEN
#endif /* HAVE_GSSAPI */
                           + sizeof(struct request_t)
                           ];
   size_t               reqread;                     /* read so far.          */
   size_t               start;                       /* start of current req  */
   char                 emsg[512];                   /* error message, if any.*/
   int                  (*rcurrent)(int s,
                                    struct request_t *request,
                                    struct negotiate_state_t *state);

   struct sockshost_t   src;          /* client's address.                    */
   struct sockshost_t   dst;          /* our address.                         */

#if HAVE_GSSAPI
   unsigned short       gssapitoken_len; /* length of token we're working on. */
#endif /* HAVE_GSSAPI */
};

struct sockd_negotiate_t {
   unsigned                   allocated:1;
   unsigned                   ignore:1;    /* ignore for now?                 */
   struct authmethod_t        clientauth;  /* authentication for clientrule.  */
   struct authmethod_t        socksauth;   /* authentication for socks-rule.  */
   struct request_t           req;
   struct negotiate_state_t   negstate;
   struct rule_t              rule;        /* rule matched for accept().      */
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
   int                        s;         /* clients control connection.       */
   struct connectionstate_t   state;     /* state of connection.              */
};

struct sockd_mother_t {
   int                  s;               /* connection to child for ancillary.*/
#if HAVE_SENDMSG_DEADLOCK
   int                  lock;            /* lock on request connection.       */
#endif /* HAVE_SENDMSG_DEADLOCK */
   int                  ack;            /* connection for ack's.              */
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
 * combined.
 * If "type" is negated, the function instead returns
 * the total number of slots (free or not) in every child of that type.
 * Also adjusts the number of children of type "type" if needed, according
 * to configure variables.
 *
 * If childcheck() is successful it also means there is at the minimum
 * one free descriptor available.
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

struct rule_t *
addclientrule(const struct rule_t *rule);
/*
 * Appends a copy of "rule" to our list of client rules.
 * Returns a pointer to the added rule (not "rule").
 */

struct rule_t *
addsocksrule(const struct rule_t *rule);
/*
 * Appends a copy of "rule" to our list of socks rules.
 * Returns a pointer to the added rule (not "rule").
 */

void
addinternal(const struct ruleaddr_t *addr);
/*
 * Adds "addr" to the list of external addresses.
 */

void
addexternal(const struct ruleaddr_t *addr);
/*
 * Adds "addr" to the list of internal addresses (to listen on).
 */

int
addressisbindable(const struct ruleaddr_t *addr);
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
showrule(const struct rule_t *rule);
/*
 * prints the rule "rule".
 */

void
showclient(const struct rule_t *rule);
/*
 * prints the clientrule "rule".
 */

void
showconfig(const struct config_t *config);
/*
 * prints out config "config".
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
            struct authmethod_t *clientauth, struct rule_t *rule,
            struct authmethod_t *srcauth, const struct connectionstate_t *state,
            const struct sockshost_t *src, const struct sockshost_t *dst,
            char *msg, size_t msgsize)
      __attribute__((__bounded__(__buffer__, 10, 11)));
/*
 * Checks whether the rules permit data from "src" to "dst".
 * "s" is the socket the connection is on, from the address "peer", accepted
 * on the address "local".
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
resetconfig(void);
/*
 * resets the current config back to default, freeing memory aswell.
 */

int
send_response(int s, const struct response_t *response);
/*
 * Sends "response" to "s".
 *      On success: 0
 *      On failure: -1
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
send_client(int s, const struct sockd_client_t *client);
/*
 * Sends the client "client" to the negotiate-child connected to "s".
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

int
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
int
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
run_io(struct sockd_mother_t *mother);
/*
 * Sets a io child running.  "mother" is the childs mother.
 *
 * A child starts running with zero clients and waits
 * indefinitely for mother to send at least one.
 */

void
run_negotiate(struct sockd_mother_t *mother);
/*
 * Sets a negotiator child running.  "mother" is the childs mother.
 * A child starts running with zero clients and waits
 * indefinitely for mother to send at least one.
 */

void
run_request(struct sockd_mother_t *mother);
/*
 * Sets a request child running.  "mother" is the childs mother.
 * "mread" is read connection to mother, "mwrite" is write connection.
 * A child starts running with zero clients and waits
 * indefinitely for mother to send at least one.
 */

int
send_io(int s, struct sockd_io_t *io);
/*
 * Tries to send the io-object "io" to "s".
 * Returns
 *    On success: 0
 *    On failure: -1
 */

int
recv_io(int mother, struct sockd_io_t *io);
/*
 * Attempts to read a new io object from "mother".
 * If a io is received it is either copied into "io", or it's copied
 * to a internal list depending on if "io" is NULL or not;  thus mother
 * vs child semantics.  If semantics are those of a child, the request
 * field of "io" is sent to the controlconnection in "io".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
recv_req(int s, struct sockd_request_t *req);
/*
 * Receives a request from "s" and writes it to "req".
 * Returns:
 *      On success: 0
 *      On failure: -1
 */

int
recv_request(int s, struct request_t *request,
      struct negotiate_state_t *state);
/*
 * Reads a socks request from the socket "s", which can be set to
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
recv_sockspacket(int s, struct request_t *request,
      struct negotiate_state_t *state);
/*
 * When method negotiation has finished (if appropriate) this function
 * is called to receive the actual packet.
 * Returns:
 *    On success: > 0
 *    On failure: <= 0.  If errno does not indicate the request should be
 *                       be retried, the connection "s" should be dropped.
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
fillset(fd_set *set);
/*
 * Sets every child's descriptor in "set", aswell as sockets we listen on.
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
nextchild(int type);
/*
 * Returns:
 *      On success: pointer to a child of correct type with at least one free slot.
 *      On failure: NULL.
 */

void
setsockoptions(int s);
/*
 * Sets options _all_ server sockets should have set.
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
 *         "addr" is local address of "s", to accept connection on.
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
shmem_setup(void);
/*
 * sets up shmem structures, must be called at start and after sighup by
 * main mother, but only main mother.
 */

shmem_object_t *
shmem_alloc(int isclientrule, size_t rulenumber,
            shmem_object_t *poolv, size_t poolc, int lock);
/*
 * Returns a pointer to an object allocated to rule number "number",
 * from the pool "poolv".  If a object has already been allocated,
 * return the previously allocated object.
 * "lock" is used for locking, if it is -1, no locking is enforced.
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
shmem_resize(size_t size, void *oldmem, size_t oldsize, int fd);
/*
 * Allocates shared memory of size "size", using "fd" for storage.
 * If "oldmem" is not NULL, it is a pointer to previously allocated
 * memory of size "oldsize".  The new memory will start at the same
 * address as "oldmem" if so.
 *
 * Returns a pointer to the memory allocated.
 */

void
bw_use(bw_t *bw);
/*
 * Marks "bw" as in use.
 */

void
bw_unuse(bw_t *bw);
/*
 * Says we are no longer using "bw".
 * If "bw" is NULL, nothing is done.
 */

ssize_t
bw_left(const bw_t *bw);
/*
 * Returns how many bytes we should read if the client is restricted
 * by "bw".
 */

void
bw_update(bw_t *bw, size_t bwused, const struct timeval *bwusedtime);
/*
 * Updates "bw".  "bwused" is the bandwidth used (in bytes) at time
 * "bwusedtime".
 */

struct timeval *
bw_isoverflow(bw_t *bw, const struct timeval *timenow,
      struct timeval *overflow);
/*
 * Checks whether "bw" would overflow if we transferred more data through it.
 * "timenow" is the time now,
 * Returns:
 *      If "bw" would overflow: til what time we have to wait until we can
 *      again transfer data through it.  The memory used for those values is
 *      "overflow".
 *
 *      If "bw" would not overflow: NULL.  "overflow" is not touched.
 */

int
session_use(session_t *ss);
/*
 * If limits allow "ss" to be marked as in use, return true.
 * Else return false.
 */

void
session_unuse(session_t *ss);
/*
 * Says we are no longer using "ss".
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
getifa(struct in_addr addr);
/*
 * Returns the address the system would chose to use for connecting
 * to the IP address "addr".
 * Returns INADDR_NONE on error.
 */

void
sigserverbroadcast(int sig);
/*
 * Broadcasts "sig" to other "main" servers (started with "-N" option).
 *
 */

void
sockd_pushsignal(const int sig);
/*
 * Adds the signal "sig" to the end of the internal signal stack.
 */


int
sockd_popsignal(void);
/*
 * Pops the first signal on the internal signal stack.
 */



unsigned char *
socks_getmacaddr(const char *ifname, unsigned char *macaddr);
/*
 * Writes the mac-address of the interface named "ifname" to "macaddr",
 * which must be of at least length ETHER_ADDR_LEN.
 * Returns a pointer to macaddress, or NULL if no mac-address
 * is set for the interface.
 */

size_t maxfreeslots(const int childtype);
/*
 * Returns the maximum number of free slots a child of type "childtype"
 * can have.
 */
