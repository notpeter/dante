/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2008, 2009, 2010, 2011, 2012
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
#include "config_parse.h"

static const char rcsid[] =
"$Id: sockd_io.c,v 1.907 2012/06/01 20:23:06 karls Exp $";

/*
 * IO-child:
 * Accept io objects from mother and do io on them.  Unless
 * Covenant, we never send back ancillary data, only ordinary data.
 *
 * XXX remove io_allocated()?  Add some variables instead that we
 * always keep updated.
 */

typedef enum { TIMEOUT_CONNECT = 1,
               TIMEOUT_IO,
               TIMEOUT_TCP_FIN_WAIT
} timeout_type_t;

typedef enum { RAWSOCKET_NOP,          /* nothing to care about. */
               RAWSOCKET_IO_DELETED    /* an io was deleted.     */
} rawsocketstatus_t;


#define SOCKD_IO_PACKETSTATS           (128)
struct iostat {
   struct timeval latencyv[SOCKD_IO_PACKETSTATS];
   size_t         latencyc;       /*
                                   * number of elements from latencyv in use
                                   * so far.
                                   */

   /* min/max/last observed latency. */
   unsigned long   min_us;
   unsigned long   max_us;
   unsigned long   last_us;
   unsigned long   average_us;
   unsigned long   median_us;
   unsigned long   stddev_us;
};

struct iostats {
   struct iostat io;
   struct iostat read;
} iostats;

static void siginfo(int sig, siginfo_t *sip, void *scp);

static int
io_timercmp(const void *a, const void *b);
/*
 * Comparison function compatible with qsort.
 * "a" and "b" are pointers to struct timeval.
 */

static void io_updatestat(struct iostat *iostat);
/*
 * Updates (recalculates) the info in "iostat".
 */

static int
io_calculatedlatency(const struct timeval *ts_recv,
                     const struct sockaddr *src, const struct sockaddr *dst,
                     struct timeval *latency);
/*
 * Calculates the packet latency for a packet going from "src" to "dst",
 * received from "src" at "ts_recv", and sent to "dst" just before
 * this function was called.
 * The calculated latency is stored in "latency" on success.
 *
 * Returns true if latency was calculated successfully, false on failure.
 */

static void io_addts(const size_t rbc, struct timeval *rbv,
                     size_t *rbc_used, const struct timeval *ts);
/*
 * Adds the timestamp "ts" to the ring buffer "rbv".
 * "rbv" is big enough to hold "rbc" elements, starting at "rbv".
 * "rbc_used" gives the number of elements in "rbv" that are currently
 * in use and is updated by this function.
 *
 * Note that this is not a real ring buffer implementation, but rather
 * a call to memmove(3).  May need to implement real ring buffer if rbc
 * grows large and we start getting performance issues.
 * XXX no need for this to be a ring buffer, we don't care about order
 * since we need to sort the array before using it anyway.  Only need
 * to know what the last element added was.  Hence we can make this much
 * more efficient than it currently is.
 */

static size_t
io_allocated(int *for_tcp, int *for_udp);
/*
 * Returns the number of allocated (active) ios.
 *
 * If "for_tcp" is not NULL, on return it will contain the number of ios
 * allocated for tcp.
 * If "for_udp" is not NULL, on return it will contain the number of ios
 * allocated for udp.
 */

static sockd_io_t *
io_getset(const int nfds, const fd_set *set);
/*
 * Goes through our list until it finds an io object where at least one of the
 * descriptors in "set" is set.  "nfds" gives the number of descriptors in
 * "set" to check
 *
 * Returns NULL if none found.
 */

static sockd_io_t *
io_finddescriptor(int d);
/*
 * Finds the io object where one of the descriptors matches "fd".
 */

static int
io_fillset(fd_set *set, int antiflags, struct timeval *bwoverflowtil);
/*
 * Sets all descriptors from our list, in "set".
 * If "antiflags" is set, ios with any of the flags in "antiflags" set
 * will be excluded.
 * In addition, ios with state.fin set, ios that have not finished
 * connecting, and ios that have overflown the bandwidth limit, will also be
 * excluded.
 *
 * If any ios were excluded due to having overflown the bandwidth limit,
 * the earliest time we can again do i/o over one of the bandwidth-excluded
 * ios will be stored in "bwoverflowtil", if not NULL.
 *
 * Returns the highest descriptor in our list, or -1 if we don't
 * have any descriptors we want to select() on currently.
 */

static int
io_fillset_connectinprogress(fd_set *set);
/*
 * Like io_fillset(), but fills "set" only with descriptors belonging
 * to connects that are marked as still being in progress.
 */

static void
io_clearset(const sockd_io_t *io, fd_set *set);
/*
 * Clears all file descriptors in "io" from "set".
 */

static iostatus_t
doio(sockd_io_t *io, fd_set *rset, fd_set *wset, const int flags, int *badfd);
/*
 * Does i/o over the descriptors in "io", in to out and out to in.
 * "io" is the object to do i/o over,
 * "flags" is the flags to set on the actual i/o calls
 * (read()/write(), recvfrom()/sendto()), currently only MSG_OOB.
 *
 * Returns the status of the doio() call, IO_NOERROR on success, or
 * some other value on error.  If "badfd" is not -1, it will have the value
 * of the file descriptor on which the error was detected.
 *
 * In most cases, delete_io() should be called upon error.
 */


static iostatus_t
doio_tcp(sockd_io_t *io, fd_set *rset, fd_set *wset,
         const int flags, int *badfd);

#if HAVE_UDP_SUPPORT

static int rawsocket = -1;
static void
send_icmperror(const int s, const sockshost_t *peer,
               const sockshost_t *local, const sockshost_t *dst,
               const int code);
/*
 * Handles packets output in on the raw socket "s".  Used
 * to send icmp-errors concerning packets we forward.
 * "peer" is the address that sent the problematic packet,
 * "local" is the address we received the packet on,
 * "dst" it the address the packet was intended for, and
 * "code" is the icmp code of the error.
 */


static udpheader_t *
getudptarget(const char *buf,
          const size_t buflen,
          const struct sockaddr *from,
#if BAREFOOTD
          const int s,
          const connectionstate_t *state,
          const int dstc,
          struct udpclient *dstv,
          const struct sockaddr *to,
          rule_t *rule,
#endif /* BAREFOOTD */
          udpheader_t *header,
          char *emsg,
          const size_t emsglen);
/*
 * The destination for a client's packet can vary each time in both
 * Dante and Barefoot.
 * In Dante it can vary because the client wants to send to a different
 * address this time.
 * In Barefoot it will normally not vary since the bounce-to address
 * is set in the rule and fixed there.  A sighup can change the
 * bounce-to address however, so we must be prepared to handle a change
 * of destination in Barefoot's case too.
 *
 * This function gets the destination address for the packet received on
 * the local address "to" from the client address "from".
 *
 * "rule" is the ruleinfo we have for this packet so far.  If no error
 * occurs, "rule" will upon return  contain the rule matched for this packet;
 * a client-rule if the packet received is from our Barefoot client, or a
 * socks-rule if from a socks-client.
 * "udpheader" is used to hold the destination address, and a pointer to it
 * returned.
 *
 * Returns "header" on success, filled in appropriately, or NULL on failure.
 * On failure, "emsg" of "emsglen" may contain an error string describing
 * the reason for failure.
 */

static iostatus_t
doio_udp(sockd_io_t *io, fd_set *rset, fd_set *wset, int *badfd);

/*
 * Wrappers for use  by doio_udp(), one for packets going from the
 * remote target/destination to the client, and one for packets going from
 * the client to the remote target/destination.
 */

static iostatus_t
io_udp_target2client(sockd_io_direction_t *control,
                     sockd_io_direction_t *in,
                     sockd_io_direction_t *out,
                     const authmethod_t *clientauth,
                     connectionstate_t *state,
                     int *bad, rule_t *packetrule, size_t *bwused);

static iostatus_t
io_udp_client2target(sockd_io_direction_t *control,
          sockd_io_direction_t *in,
          sockd_io_direction_t *out,
          const authmethod_t *clientauth,
          connectionstate_t *state,
          int *bad, rule_t *packetrule, size_t *bwused);
/*
 * Tries to read a udp packet from the socket in "in" and send it out on
 * the socket in "out".
 * "state" is the connection state of the io object "in" and "out" belong to.
 *
 * "packetrule" is the rule used for sending a packet from "in" to "out".
 * When called it will contain information necessary to call iolog() if
 * an error is detected before we get far enough to be be able to do a
 * full rule lookup.  If the sockets are connected, "packetrule" may contain
 * all the necessary information and no rule lookup may be necessary.
 * Upon return, if there was no error, it will contain the rule used for the
 * forwarded packet.
 *
 * Returns a status code indicating whether the packet was forwarded or not.
 * If a fatal error occurred and the session should be removed, "bad" is
 * set to the socket where the error occurred (the socket in "in" or "out"
 * if it can be determined, or it will remain unchanged if not.
 */

#endif /* HAVE_UDP_SUPPORT */

static int
io_tcp_rw(sockd_io_direction_t *in, sockd_io_direction_t *out,
      int *bad, const requestflags_t *reqflags, char *buf, size_t bufsize,
      size_t *bufused, int flags);
/*
 * Transfers TCP data from "in" to "out" using "buf" as a temporary buffer
 * to store the data, and sets flag "flags" in sendto()/recvfrom().
 * "reqflags" is flags for the client side of the request.
 *
 * The size of "buf" is given by bufsize, and "bufused", if not NULL,
 * indicates how much of "buf" has previously been used, but not
 * written to "out".  Upon return, "bufused" is updated with the
 * new value.  "bufused" is only used by the Covenant server, and should
 * be set to NULL when called by anyone else.
 *
 * "inauth" is the authentication used for reading from "in",
 * "outauth" is the authentication * used when writing to out.
 * The data transferred uses "buf" as a buffer, which is of size "bufsize".
 * The function never transfers more than the receive low watermark
 * of "out".
 *
 * Returns:
 *      On success: number of bytes transferred from "in" to "out".
 *      On failure: -1.  "bad" is set to the value of the descriptor that
 *                  "failure" was first detected on, or -1 if the "failure"
 *                  was temporary.
 *                  "failure" may also be eof, in which case the number of
 *                  bytes transferred will be zero.
 */

static void
delete_io(int mother, sockd_io_t *io, int fd, const iostatus_t status);
/*
 * deletes the io object "io".  "fd" is the descriptor on which "status"
 * was returned.  If "fd" is negative, it is ignored.
 * If "mother" is >= 0, the deletion of "io" is ACK'ed to her.
 * "status" is the reason for why the io was deleted.
 */

static void
proctitleupdate(void);
/*
 * Updates the title of this process.
 */

static int
io_timeoutispossible(const sockd_io_t *io);
/*
 * Returns true if it's possible the io object "io" could time out, i.e.,
 * the config and state of the io object is such that it is possible.
 *
 * Returns false if it is not possible for the i/o object to time out
 * in it's current state with the current config.
 */

static long
io_timetiltimeout(sockd_io_t *io, const struct timeval *tnow,
                  timeout_type_t *type);
/*
 * Returns the number of seconds til the io object "io" will timeout, at
 * the earliest.
 *
 * "tnow" is the current time.
 *
 * "type", if not NULL, is filled in with the type of timeout that will
 * occur at that time, if any.
 *
 * Returns -1 if no timeout on the io is currently present.
 */

static struct timeval *
io_gettimeout(struct timeval *timeout);
/*
 * If there is an applicable timeout on the current clients for how long
 * we should wait for them to do i/o again, this function fills in "timeout"
 * with the time remaining til then.
 *
 * Returns:
 *      If there is a timeout: timeout.
 *      If there is no applicable timeout currently: NULL.
 */

static sockd_io_t *
io_gettimedout(void);
/*
 * Scans all clients for one that has timed out according to sockscf
 * settings.
 *
 * Returns:
 *      If timed out client found: pointer to timed out i/o object.
 *      Else: NULL.
 */

static void
getnewios(void);
/*
 * Receives new ios from mother.  Closes mother and sets
 * mother sockets to -1 if there is an error.
 */

static void
freebuffers(const sockd_io_t *io);
/*
 * Frees buffers, if any, used by "io".
 */

static int
checkconnectstatus(sockd_io_t *io, int *badfd);
/*
 * Checks if the socket on "io->dst" has finished connecting, and fills
 * in status flags as appropriate.  Note that this function should only
 * be called once the connect has completed (successfully or otherwise).
 *
 * Note that this function must be called after the connect has completed,
 * as in the socks case (and some covenant cases) we need to send a
 * response back to the client before it will start sending us data.
 * We can thus not delay calling this function til we get ordinary i/o
 * from one side, as it's possible none will be coming til after we
 * have sent the response to the client.
 *
 * Returns 0 if the socket connected successfully.
 * Returns -1 if the socket was not connected successfully, or some other error
 *            occurred.  In this case, "badfd" has the value of the "bad" fd,
 *            otherwise it will be -1.
 */

static void
io_update(const struct timeval *timenow, const size_t bwused,
          rule_t *rule, const int lock);
/*
 * update the time/bw counters in "rule" according to "bwused" and "timenow"
 * "bwused" is the bandwidth used at time "timenow".
 */

/*
 * Returns the rule that hold the shmem-info.
 */
#define SHMEM_RULE(io) (HAVE_SOCKS_RULES ? &(io)->rule : &(io)->crule)

#if BAREFOOTD

static int
io_haveresources(rule_t *rule, const struct sockaddr *client,
               char *emsg, const size_t emsglen);
/*
 * (Re)allocates resources for client "client" as given by "rule".
 * Assumes that if the shared memory pointers in "rule" are not NULL,
 * the resources have been allocated already.
 *
 * Returns true if we have our could get the resources, or false on failure.
 * On failure, the reason is written to "emsg", which must be of size "emsglen".
 */

static struct udpclient *
initclient(const struct sockaddr *from, const sockshost_t *to,
           char *emsg, const size_t emsglen, struct udpclient *client);

/*
 * Fills in "client" with the necessary info for a new udp client, as well
 * as creating a socket for the client to send packets to the destination
 * ("to") on.
 * "from" and "to" give the client and destination, while "bounceto"
 * is the address packets should be bounced to.
 *
 * Returns "client" on success, NULL on failure.
 * On failure, "emsg" of "emsglen" may contain the reason the call failed.
 */

#define DUMMY_INDEX  (0)    /*
                             * first index in dstv is a dummy socket. Must
                             * be first.
                             */


#define UDP_MEMBLOCK (16)   /*
                             * by how many clients to increase allocated
                             * memory when needed.
                             */

#define MAX_ICMPLEN (60 /* MAX IP LEN */ + 8 + 60 + 8)
#define MIN_ICMPLEN (20 /* MIN IP LEN */ + 8)

static rawsocketstatus_t
rawsocket_recv(const int s);
/*
 * Handles packets input on the raw socket "s".
 * Used to read icmp-errors concerning packets we send to/from udp clients.
 */

static size_t
io_udpclients(void);
/*
 * Returns the number of active udp clients.
 */

static struct udpclient *
clientofclientaddr(const struct sockaddr *addr, const size_t udpclientc,
                      struct udpclient *udpclientv);
/*
 * Returns the udpclient that has the client address "addr", or NULL
 * if no such client exists.
 */

static struct udpclient *
clientofsocket(const int s, const size_t udpclientc,
               struct udpclient *udpclientv);
/*
 * Returns the udpclient belonging to socket "s", or NULL if no
 * such client.
 */

static struct udpclient *
addclient(const struct udpclient *client, const struct sockaddr *clientladdr,
          size_t *clientc, size_t *maxclientc, struct udpclient **clientv,
          const connectionstate_t *state, const rule_t *rule);
/*
 * Adds the udpclient "client" to the "clientv" array, which is large
 * enough to contain "maxclientc" clients.
 * "clientc" gives the index of the last slot in "clientv" that is
 * currently in use.
 * "clientladdr" is our local endpoint for packets from the client, and
 * "rule" is the rule that matched the client, and "state" is the state.
 *
 * Returns a pointer to the added client ("client"), or NULL if there
 * is no more room and clientv can not be expanded.
 */

static int
removeclient(const int s, size_t *clientc, struct udpclient *clientv);
/*
 * Removes the udpclient associated with the socket "s" from the
 * "clientv" array, which contains "clientc" elements, and decrements
 * "clientc".
 * Returns 0 on success, -1 on failure.
 */

static void
update_clientpointers(const size_t dstc, struct udpclient *dstv);

#define SYNC_UDPOUT(udpclient, out)                                            \
do {                                                                           \
   (out)->s                     = (udpclient)->s;                              \
                                                                               \
   (out)->laddr                 = (udpclient)->laddr;                          \
   (out)->host                  = (udpclient)->host;                           \
   sockshost2sockaddr(&((out)->host), TOSA(&((out)->raddr)));                  \
                                                                               \
   (out)->read    = (udpclient)->dst_read;                                     \
   (out)->written = (udpclient)->dst_written;                                  \
                                                                               \
   (out)->state.connected       = udpclient->connected;                        \
   (out)->state.use_saved_rule  = udpclient->use_saved_replyrule;              \
} while (0 /* CONSTCOND */)

#define SYNC_UDP(io, udpclient)                                                \
do {                                                                           \
   (io)->crule                  = (udpclient)->crule;                          \
   (io)->rule                   = (udpclient)->rule;                           \
   (io)->rule.crule             = &(udpclient)->crule;                         \
                                                                               \
   (io)->state.time.established = (udpclient)->firstio;                        \
                                                                               \
   /* (io)->src.laddr is the same for all clients and never changes. */        \
                                                                               \
   (io)->src.raddr              = (udpclient)->client;                         \
   sockaddr2sockshost(TOSA(&(io)->src.raddr), &(io)->src.host);                \
                                                                               \
   (io)->src.read     = (udpclient)->src_read;                                 \
   (io)->src.written  = (udpclient)->src_written;                              \
                                                                               \
   SYNC_UDPOUT((udpclient), &(io)->dst);                                       \
} while (/*CONSTCOND*/ 0)


#elif SOCKS_SERVER

static int
fromaddr_as_expected(const int s,
                     struct sockaddr *expected, const struct sockaddr *from,
                     char *emsg, size_t emsglen);

/*
 * Checks that the packet received on socket "s", from "from", matches the
 * expected address as given in "expected".
 * If so, the socket is connected to "from" and "expected" is updated to
 * contain the address of "from".
 *
 * Returns if the from address is as expected, or false otherwise.  If false,
 * "emsg" may be filled with more information as to what went wrong or did
 * not match.
 */

/*
 * instead of including memory for this as part of the i/o object, we
 * set up the pointer from the i/o object to the appropriate index into
 * this array when we receive the i/o object.  We can do that since
 * we only use the io.replyrule object in this process.
 * The only reason for going through with this hassle is so we can reduce
 * the size of the i/o object.  Since the i/o object is passed around between
 * processes, we want it to be as small as possible, reducing the min-size
 * of the socket buffers between mother and child.
 *
 * The rules are needed because while the original io.crule and io.rule
 * are used to establish the session, we also need to do a rulespermit()
 * on a per-packet basis (except in Dante when we have connected to the
 * destination).
 */
static rule_t fwdrulev[SOCKD_IOMAX];
static rule_t replyrulev[SOCKD_IOMAX];

#endif /* SOCKS_SERVER */

/*
 * In barefoot, udp is a point-to-multipoint case: we receive all client
 * packets on one socket, but use different outgoing sockets for each client.
 * We use this macro to sync the necessary parts of the udpclient to the
 * io object before usage.
 */

#define IOSTATUS_FATALERROR(error)     \
(!(  (error) == IO_NOERROR             \
  || (error) == IO_TMPERROR            \
  || (error) == IO_BLOCK               \
  || (error) == IO_EAGAIN))

/* calls io_clearset() on all fd_sets. */
#define IO_CLEAR_ALL_SETS(io)       \
do {                                \
   io_clearset((io), rset);         \
   io_clearset((io), wset);         \
   io_clearset((io), xset);         \
   io_clearset((io), newrset);      \
   io_clearset((io), tmpset);       \
   io_clearset((io), bufrset);      \
   io_clearset((io), buffwset);     \
} while (/* CONSTCOND */ 0)

#define _CHECK()                                                               \
do {                                                                           \
   size_t i;                                                                   \
                                                                               \
   for (i = 0; i < ioc; ++i) {                                                 \
      sockd_io_t *io = &iov[i];                                                \
                                                                               \
      if (!io->allocated)                                                      \
         continue;                                                             \
                                                                               \
      if (io->state.command == SOCKS_UDPASSOCIATE) {                           \
         size_t ii;                                                            \
                                                                               \
         for (ii = DUMMY_INDEX + 1; ii < io->dst.dstc; ++ii) {                 \
            SASSERTX(io->dst.dstv[ii].rule.timeout.udpio != 0);                \
         }                                                                     \
      }                                                                        \
      else                                                                     \
         SASSERTX(io->rule.timeout.udpio != 0);                                \
   }                                                                           \
} while (0)


static sockd_io_t iov[SOCKD_IOMAX];   /* each child has these ios. */
static const size_t ioc = ELEMENTS(iov);


/*
 * number of currently free file descriptors.  Should never become
 * a problem for Dante or Covenant, but Barefoot needs to keep track
 * of it so we does not end up using up all fds for udp clients, then
 * become unable to receive a new io from mother.
 */
static int freefds;

/*
 * if not 0, we have "overflowed" according to max bandwidth configured.
 * We can not attribute it to any given client though, so we penalize
 * all by delaying a little.  This object gives the earliest time at which we
 * can again do i/o over one of the object that has overflown it's bandwidth
 * limit.
 */
static struct timeval bwoverflowtil;

void
run_io()
{
   const char *function = "run_io()";
   struct sigaction sigact;
   fd_set *rset, *wset, *xset, *newrset, *tmpset, *bufrset, *buffwset;
   int p;
#if BAREFOOTD
   socklen_t optlen;
#endif /* BAREFOOTD */

   bzero(&sigact, sizeof(sigact));
   sigact.sa_flags     = SA_RESTART | SA_SIGINFO;
   sigact.sa_sigaction = siginfo;

#if HAVE_SIGNAL_SIGINFO
   if (sigaction(SIGINFO, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGINFO)", function);
#endif /* HAVE_SIGNAL_SIGINFO */

   /* same handler, for systems without SIGINFO. */
   if (sigaction(SIGUSR1, &sigact, NULL) != 0)
      serr(EXIT_FAILURE, "%s: sigaction(SIGUSR1)", function);

#if BAREFOOTD
   /*
    * Set up a raw socket so we can get icmp errors for
    * udp packets sent to clients, and delete the clients if so.
    */

   sockd_priv(SOCKD_PRIV_NET_ICMPACCESS, PRIV_ON);
   if ((rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
      swarn("%s: could not open raw socket", function);
   else
      slog(LOG_DEBUG, "%s: created raw socket, index %d", function, rawsocket);
   sockd_priv(SOCKD_PRIV_NET_ICMPACCESS, PRIV_OFF);

#if HAVE_PRIVILEGES
   /* don't need this privilege any more, permanently loose it. */

   if (sockscf.privileges.haveprivs) {
      priv_delset(sockscf.privileges.privileged, PRIV_NET_ICMPACCESS);
      if (setppriv(PRIV_SET, PRIV_PERMITTED, sockscf.privileges.privileged)
      != 0)
         swarn("%s: setppriv() to relinquish PRIV_NET_ICMPACCESS failed",
         function);
   }
#endif /* HAVE_PRIVILEGES */

   if (rawsocket != -1) {
      optlen = sizeof(p);
      if (getsockopt(rawsocket, SOL_SOCKET, SO_RCVBUF, &p, &optlen) != 0)
         swarn("%s: getsockopt(SO_RCVBUF)", function);
      else {
         if (p < RAW_SOCKETBUFFER) {
            p = RAW_SOCKETBUFFER;
            if (setsockopt(rawsocket, SOL_SOCKET, SO_RCVBUF, &p, sizeof(p))
            != 0)
               swarn("%s: failed setsockopt(SO_RCVBUF, %d) on raw socket",
               function, p);
            else
               slog(LOG_DEBUG, "%s: changed buffer size to %d bytes",
               function, p);
         }
         else
            slog(LOG_DEBUG, "%s: default buffer size is %d bytes, keeping it",
            function, p);
      }
   }

#endif /* BAREFOOTD */

   rset       = allocate_maxsize_fdset();
   wset       = allocate_maxsize_fdset();
   xset       = allocate_maxsize_fdset();
   newrset    = allocate_maxsize_fdset();
   tmpset     = allocate_maxsize_fdset();
   bufrset    = allocate_maxsize_fdset();
   buffwset   = allocate_maxsize_fdset();

   proctitleupdate();

   freefds = freedescriptors(NULL);
   sockd_print_child_ready_message((size_t)freefds);

   /* CONSTCOND */
   while (1) {
      /*
       * The heart and soul of the server.  This is the loop where
       * all i/o is done and involves some tricky stuff.
       *
       * We need to check for write separately to avoid busy-looping.
       * The problem is that if the descriptor is ready for reading but
       * the corresponding descriptor to write out on is not ready, we will
       * be busy-looping; above select will keep returning descriptors set,
       * but we will not be able to write (and thus won't read) them.
       *
       * Our solution to this is two select(2) calls.  One to see
       * what descriptors are readable, and another select(2) call to
       * block until at least one of the descriptors on the corresponding
       * write-side has become writable.
       * We therefore only set in wset the descriptors that have the
       * corresponding read descriptor readable, so that when the
       * second select() returns, the io objects we get from wset will
       * be both readable and writable.
       * XXX Now that we have the iobuffers, perhaps we can improve on the
       * above by not bothering with the select(2) for write?
       *
       * Another problem is that if while we wait for writability, a new
       * descriptor becomes readable, we thus can't block forever here.
       * We solve this by in the second select() also checking for
       * readability, but now only the descriptors that were not found
       * to be readable in the previous select().
       * This means that a positive return from the second select does not
       * necessarily indicate we have i/o to do, but it does mean we
       * either have it or a new descriptor became readable; in either
       * case, something has happened.
       * Reason we do not check for exceptions in this second select is that
       * there is nothing we do about them until the descriptor becomes
       * readable too, thus any new exceptions will be in newrset before
       * we have reason to care about them.
       */
      iostatus_t iostatus;
      sockd_io_t *io;
      struct timeval timeout, *timeoutpointer;
      int i, bits, first_rbits, rbits, wbits, newsocketsconnected, badfd, flags;

      errno = 0; /* reset for each iteration. */

      /* look for timed-out clients and calculate the next timeout, if any. */
      while ((io = io_gettimedout()) != NULL)
         delete_io(sockscf.state.mother.ack, io, -1, IO_TIMEOUT);

      /*
       * XXX should be possible to optimize as in most cases there will be
       * no difference between the results produced, as in most cases there
       * will be no OOB flag set.
       */
      io_fillset(xset, MSG_OOB, NULL);
      rbits = io_fillset(rset, 0, &bwoverflowtil);

      /*
       * buffwset.  What descriptors do we want to check whether have
       * data buffered for write?  Having data buffered for write means
       * we have data to write on them, thus we want to know if they
       * are writable.  Pretty much any client-related descriptor we want
       * to check for having data buffered for write, except those
       * specifically skipped (due to e.g., bw overflow).
       */
      FD_COPY(buffwset, rset);

      /* likewise for having data buffered for read. */
      FD_COPY(bufrset, rset);

      if (sockscf.state.mother.s != -1) {
         FD_SET(sockscf.state.mother.s, rset);
         rbits = MAX(rbits, sockscf.state.mother.s);

         /* checked so we know if mother goes away.  */
         FD_SET(sockscf.state.mother.ack, rset);
         rbits = MAX(rbits, sockscf.state.mother.ack);
      }
      else { /* no mother.  Do we have any other descriptors to work with? */
         if (rbits == -1 && !timerisset(&bwoverflowtil)) {
            /* no clients in fd_sets, and not due to bwoverflow ... */
            SASSERTX(io_allocated(NULL, NULL) == 0);

            slog(LOG_DEBUG, "%s: no connection to mother and no clients.  "
                            "Exiting",
                            function);

            sockdexit(EXIT_SUCCESS);
         }
      }
#if BAREFOOTD
      if (rawsocket != -1 && (io_udpclients() > 0)) {
         /* raw socket is only of interest if we have udp clients. */

         FD_SET(rawsocket, rset);
         rbits = MAX(rbits, rawsocket);
      }
#endif /* BAREFOOTD */

      /*
       * First check descriptors that are readable; we won't write if
       * we can't read.
       * Connects that are in progress is a special case that we also need
       * to check for here.  Once the connect has completed, successfully or
       * not, the socket will become writable and we may need to send a
       * response to the client.
       *
       * Also select for exceptions so we can tell the i/o function if
       * there's one pending later.
       */

      wbits               = io_fillset_connectinprogress(wset);
      newsocketsconnected = 0;
      bits                = MAX(rbits, wbits) + 1;

      slog(LOG_DEBUG,
           "%s: first select.  What is readable, what has finished connecting",
           function);

      switch (selectn(bits,
                      rset,
                      bufrset,
                      buffwset,
                      wset,
                      xset,
                      io_gettimeout(&timeout))) {
         case -1:
            if (errno == EINTR)
               continue;

            SERR(errno);
            /* NOTREACHED */

         case 0:
            continue; /* restart the loop. */
      }

      if (sockscf.state.mother.ack != -1
      && FD_ISSET(sockscf.state.mother.ack, rset)) { /* only eof expected. */
         slog(LOG_DEBUG, "%s: mother closed the connection to us", function);

         sockscf.state.mother.s = sockscf.state.mother.ack = -1;

#if BAREFOOTD
         /*
          * terminate all udp sessions as if we do not, a restart will
          * not be able to rebind the ports used.  Not a problem for
          * TCP, so those sessions can continue to run until the
          * session ends for other reasons.
          */
         io_remove_session(NULL, SOCKS_UDP, IO_ADMINTERMINATION);
#endif /* BAREFOOTD */

         continue; /* safest to regenerate the fd_sets. */
      }

      /* needs to be after check of ack-pipe to limit error messages. */
      if (sockscf.state.mother.s != -1
      && FD_ISSET(sockscf.state.mother.s, rset)) {
         getnewios();
         continue; /* need to scan rset again; should have a new client. */
                   /*
                    * XXX Or can we instead add it to newrset, and rescan as
                    * normal after that?
                    */
      }

      first_rbits = bits;

      FD_ZERO(tmpset);
      if (FD_CMP(tmpset, wset) != 0) {
         for (p = 0; p < bits; ++p)
            if (FD_ISSET(p, wset)) {

               io = io_finddescriptor(p);
               SASSERTX(io != NULL);
               SASSERTX(p == io->dst.s);

               if (checkconnectstatus(io, &badfd) == 0)
                  ++newsocketsconnected;
               else {
                  SASSERTX(badfd != -1);
                  SASSERTX(badfd == io->src.s
                  ||       badfd == io->dst.s
                  ||       badfd == io->control.s);

                  IO_CLEAR_ALL_SETS(io);
                  delete_io(sockscf.state.mother.ack, io, badfd, IO_ERROR);
               }
            }

         slog(LOG_DEBUG, "%s: %d new socket%s finished connecting",
              function,
              newsocketsconnected,
              newsocketsconnected == 1 ? "" : "s");
      }

      /*
       * Add bufrset to rset, so rset contains all sockets we can
       * read from, whether it's from the socket or from the buffer.
       */
      fdsetop(bits, '|', rset, bufrset, rset);

#if BAREFOOTD
      if (rawsocket != -1 && FD_ISSET(rawsocket, rset)) {
         FD_CLR(rawsocket, rset);

         if (rawsocket_recv(rawsocket) == RAWSOCKET_IO_DELETED)
            /*
             * one or more ios were deleted.  Don't know which, so
             * need to regenerate the descriptor sets for select.
             */
            continue;
      }
#endif /* BAREFOOTD */

      /*
       * We now know what descriptors are readable; rset.
       * Next prepare for the second select(2), where we want to
       * know which of the descriptors, paired with the above readable
       * descriptors, we can write to.  In that select(2) we also need to
       * check for read again, but only those descriptors that are not
       * already readable, as that constitutes at least a status change
       * which we should loop around for.  Likewise, we again need to
       * check whether some new sockets have finished connecting (and
       * thus become writable).
       */

      i     = io_fillset(tmpset, 0, &bwoverflowtil);
      rbits = fdsetop(i, '^', rset, tmpset, newrset);

      if (sockscf.state.mother.s != -1) { /* mother status may change too. */
         FD_SET(sockscf.state.mother.s, newrset);
         rbits = MAX(rbits, sockscf.state.mother.s);

         /* checked so we know if mother goes away.  */
         SASSERTX(sockscf.state.mother.ack != -1);
         FD_SET(sockscf.state.mother.ack, newrset);
         rbits = MAX(rbits, sockscf.state.mother.ack);
      }

      /*
       * descriptors to check for writability: those with the corresponding
       * read-descriptor set or data already buffered for write, as well
       * as the connects that are still in progress.
       * Initialize with the set of connects still in progress, and then add
       * those fds that have the corresponding other side readable.
       */
      wbits = io_fillset_connectinprogress(wset);

      for (p = 0; p < MAX(bits, first_rbits); ++p) {
         if (FD_ISSET(p, buffwset)) {
            /*
             * Descriptor has data buffered for write.  That means
             * we should mark the other side as readable as regardless
             * of whether we can read from the other side or not now, we have
             * data that we previously read from it and that we need to write.
             */
            int other_side;

            io = io_finddescriptor(p);
            SASSERTX(io != NULL);
            SASSERTX(socks_bufferhasbytes(p, WRITE_BUF));

            if (p == io->src.s)
               other_side = io->dst.s;
            else if (p == io->dst.s)
               other_side = io->src.s;
            else
               SERRX(p);

            slog(LOG_DEBUG, "%s: fd %d has data buffered for write; "
                            "checking it for writability and marking "
                            "other side, fd %d, as readable",
                            function, p, other_side);

            FD_SET(other_side, rset);
            rbits = MAX(other_side, rbits);

            /*
             * ok, we know we have data buffered for write, but /can/
             * we write?  Need to check.
             * XXX possible optimization target: if we have enough room
             *     in the writebuffer, we can pretend the fd is writable
             *     as long as we do not read too much (gssapi encapsulation
             *     included).  As of now, we just use the buffer to even
             *     out differences between the two sides, but if one side
             *     stops reading completely, the fd will not be writable
             *     and we won't try to write anything, not even to our own
             *     buffer even though that might be possible.  No big deal.
             */
            FD_SET(p, wset);
            wbits = MAX(wbits, p);
         }
         else {
            /*
             * No data buffered for write.  Is the socket readable,
             * from the buffer or from the socket itself?
             */

            if (!FD_ISSET(p, rset))
               continue; /* no. */

            /*
             * Yes, have data to read.
             */
            io = io_finddescriptor(p);
            SASSERTX(io != NULL);

            /*
             * find out what sockets we should check for writability.
             */

#if BAREFOOTD
            /*
             * The tcp case is the same as socks, but in the case of udp,
             * we have a one-to-many scenario, where packets received
             * on "in" can go out on many different "outs." and we don't
             * know which out socket to use until we have read the packet
             * to see who the sender is.
             *
             * UDP sockets shouldn't normally block though, so selecting
             * for writability is not really required.  Thus we just need
             * to make sure at all times that dst.s always contains one of
             * the valid out sockets.  If one is writable, assume all are.
             *
             * The reverse, when a packet comes in on one of the many
             * out sockets is slightly more complicated. In this case,
             * we need to select for readability on all the many out
             * sockets.  This is handled as usual in io_fillset(), but we
             * also need to make sure that io->dst.s is set to the (possibly
             * one of many) descriptors in dstv[] that is readable when
             * we call doio().
             */
#endif /* BAREFOOTD */

            if (io->src.s == p) { /* read from in requires writable out. */
               FD_SET(io->dst.s, wset);
               wbits = MAX(wbits, io->dst.s);
            }
            else if (io->dst.s == p) { /* read from out requires writable in. */
               FD_SET(io->src.s, wset);
               wbits = MAX(wbits, io->src.s);
            }
            else {
               /*
                * control connection is also readable without matching writable
                * and is used to signal session close in udp and bind extension
                * cases.
                * Since it doesn't have any side to forward the data to,
                * it is more optimal to read from it now so we can simplify
                * the rest of the code and make it more efficient.
                */
               ssize_t r;
               char buf[1024];

               SASSERTX(io->control.s == p);
               SASSERTX(io->control.s != io->src.s);
               SASSERTX(io->control.s != io->dst.s);

               SASSERTX(io->state.command  == SOCKS_UDPASSOCIATE
               ||       (io->state.command == SOCKS_BINDREPLY
                  &&     io->state.extension.bind));

               /*
                * Only thing we expect from client's control connection is
                * an eof.
                */
               r = socks_recvfrom(io->control.s,
                                  buf,
                                  sizeof(buf),
                                  0,
                                  NULL,
                                  NULL,
                                  &io->control.auth,
                                  NULL,
                                  NULL);

               if (r <= 0) {
                  IO_CLEAR_ALL_SETS(io);
                  delete_io(sockscf.state.mother.ack,
                            io,
                            io->control.s,
                            r == 0 ? IO_CLOSE : IO_ERROR);
               }
               else {
                  char visbuf[256];

                  slog(LOG_NOTICE, "%s: %ld unexpected byte%s over control "
                                   "connection from client %s:  %s",
                                   function,
                                   (long)r,
                                   r == 1 ? "" : "s",
                                   sockaddr2string(TOSA(&io->control.raddr), NULL, 0),
                                   str2vis(buf, r, visbuf, sizeof(visbuf)));

                  FD_CLR(io->control.s, rset);
                  FD_SET(io->control.s, newrset);
               }
            }
         }
      }

      if (wbits++ == -1)
         continue;

      if (newsocketsconnected) {
         /*
          * Don't wait.  Handle what we can now and then restart the loop,
          * which will then include handling of any new sockets.
          */
         bzero(&timeout, sizeof(timeout));
         timeoutpointer = &timeout;
      }
      else
         timeoutpointer = io_gettimeout(&timeout);

      bits = MAX(rbits, wbits) + 1;

      slog(LOG_DEBUG, "%s: second select, what is writable?", function);

      switch (selectn(bits, newrset, NULL, NULL, wset, NULL, timeoutpointer)) {
         case -1:
            if (errno == EINTR)
               continue;

            SERR(-1);
            /* NOTREACHED */

         case 0:
            continue;
      }

      if (sockscf.state.mother.ack != -1
      && FD_ISSET(sockscf.state.mother.ack, newrset))
         continue; /* eof presumably; handle it in one place, above. */

      if (sockscf.state.mother.s != -1
      && FD_ISSET(sockscf.state.mother.s, newrset)) {
         FD_CLR(sockscf.state.mother.s, newrset);
         getnewios();
      }

      /*
       * newrset: descriptors readable.  All new fds.
       *          Don't do anything with them here as we don't know if
       *          the write-side is writable; loop around and check for
       *          writability first.
       *
       * rset: descriptors readable, from buffer or from socket.
       *
       * xset: subset of rset with exceptions pending.
       *
       * wset: descriptors writable with at least one of:
       *          a) a matching descriptor in rset.
       *          b) data buffered for write.
       *          c) a connect previously in progress, and now completed.
       *       a) and b) we can do i/o over, c) we can't know for sure.
       *
       * In other words, the sockets in wset are the sockets we can
       * possibly do i/o over.  So we check which of a), b), or c)
       * is the case, do i/o if it's a) or b), remove the socket
       * from wset, and get the next socket set in wset.
       */

      FD_ZERO(tmpset);
      while ((io = io_getset(bits, wset)) != NULL) {
         if (io->state.command == SOCKS_CONNECT
         && !io->dst.state.connected) {

            SASSERTX(FD_ISSET(io->dst.s, wset));
            FD_CLR(io->dst.s, wset);

            if (checkconnectstatus(io, &badfd) == -1) {
               SASSERTX(badfd == io->src.s || badfd == io->dst.s);
               delete_io(sockscf.state.mother.ack, io, badfd, IO_ERROR);
            }

            /*
             * regardless of whether the connect was successful or not we
             * can't do anything here as we don't know what the status of
             * src.s is, so have to loop around.
             * XXX we could check though --- if we coincidentally know that
             * src is readable, and the connect succeeded, we can do i/o, no?
             */
            continue;
         }

#if BAREFOOTD
         if (io->state.command == SOCKS_UDPASSOCIATE) {
            /*
             * Since udp is a "point-to-multipoint" case, the descriptors
             * set in rset could be:
             * a) the one in io->src.s.
             * b) any of the descriptors in io->dst.dstv.
             *
             * If it's a), we need to find out which one(s) it is and set
             * io->dst.s appropriately, so that we try to read from
             * the correct target.
             *
             * If it's b), there could be many packets queued up, especially
             * since that one socket will be handling io->dst.dstc number
             * of clients.  If so, we'll want to read from the socket until
             * there are no more packets, to reduce the chance of packets
             * overflowing the kernels socket buffer.
             * That we don't know how many packets there are in Barefoot's
             * case is no different from any other udp case, but in
             * Barefoot's case there is a good chance there will be many
             * due to the multipoint-to-point nature of things, so read
             * packets until there are no more to read to reduce the chance
             * of packets being lost on this socket.
             *
             * XXX how to handle bwoverflow?
             */
            size_t i;

            if (FD_ISSET(io->src.s, rset)) {
               /*
                * case a): packet from a client.
                *
                * Don't know what the destination socket is until we've
                * read the packet and found the destination socket based
                * on what client sent the packet, so set it to the dummy
                * socket before calling the i/o function, which will then
                * demux it.
                *
                * Try to read as many packets as we can due to the
                * mp-t-p nature of things on this (internal) side.
                */

               FD_SET(io->dst.dstv[DUMMY_INDEX].s, wset);
               do {
                  SYNC_UDP(io, &io->dst.dstv[DUMMY_INDEX]);
                  iostatus  = doio(io, rset, wset, 0, &badfd);

                  if (iostatus == IO_NOERROR)
                     SASSERTX(io->dst.s != io->dst.dstv[DUMMY_INDEX].s);

                  if (io->dst.s != -1
                  &&  io->dst.s != io->dst.dstv[DUMMY_INDEX].s)
                     FD_CLR(io->dst.s, wset);

                  if (badfd == io->src.s)
                     break;
               } while (io->dst.dstc > DUMMY_INDEX + 1
               &&       iostatus    != IO_EAGAIN);

               FD_CLR(io->src.s, rset);
               FD_CLR(io->dst.dstv[DUMMY_INDEX].s, wset);
            }
            else {
               /*
                * case b): reply from a target.
                */

               /* find the correct target object. */
               for (i = DUMMY_INDEX + 1; i < io->dst.dstc; ++i)
                  if (FD_ISSET(io->dst.dstv[i].s, rset))
                     break;

               if (i >= io->dst.dstc) {
                  /*
                   * Must have read from all the readable io->dst->dstv sockets.
                   * Clear the one io->src.s socket from the wset to indicate
                   * that we don't care about it being writable (any longer),
                   * since we have no sockets to read from (any longer).
                   */
                  slog(LOG_DEBUG, "%s: no dstv socket found in rset.  Assuming "
                                  "no more target-sockets to read from",
                                  function);
                  FD_CLR(io->src.s, wset);
                  continue;
               }

               SYNC_UDP(io, &io->dst.dstv[i]);
               iostatus = doio(io, rset, wset, 0, &badfd);

               FD_CLR(io->dst.s, rset);

               if (badfd == io->src.s) {
                  /*
                   * don't want to read from only one target socket, even
                   * though we only have one client-socket as that's so
                   * suboptimal.
                   * Assuming UDP will in general not block, so write as
                   * to out-sockets long as we can write and only clear the
                   * client-socket from wset if an error occurs with it,
                   * (or if, as done above, we don't have any more readable
                   * target-sockets).
                  */

                  slog(LOG_DEBUG, "%s: clearing io->src.s from wset as it "
                                  "matches badfd (%d).  errno = %d (%s)",
                                  function, badfd, errno, strerror(errno));

                  FD_CLR(io->src.s, wset);
               }
            }

            if (IOSTATUS_FATALERROR(iostatus) && badfd != -1) {
               if (badfd == io->src.s) {
                  /*
                   * Is there any way this could happen unless we've
                   * messed something up internally?
                   */
                  swarn("%s: doio() failed with iostatus %d, but never "
                        "expected badfd to be io->src.s (%d).  Strange",
                        function, (int)iostatus, io->src.s);

                  io_remove_session(TOSA(&io->src.laddr), SOCKS_UDP, iostatus);
                  continue;/* Rare happening.  Easier to regenerate fd_sets */
               }
               else {
                  SASSERTX(badfd == io->dst.s);
                  delete_io(sockscf.state.mother.ack,
                            io,
                            badfd,
                            iostatus);
               }
            }
         }
         else { /* tcp; same as Dante. */
#endif /* BAREFOOTD */

         if (FD_CMP(tmpset, xset) != 0
         && (FD_ISSET(io->src.s, xset) || FD_ISSET(io->dst.s, xset)))
            flags = MSG_OOB;
         else
            flags = 0;

         iostatus = doio(io, rset, wset, flags, &badfd);
         io_clearset(io, rset);
         io_clearset(io, wset);

         if (IOSTATUS_FATALERROR(iostatus))
            delete_io(sockscf.state.mother.ack, io, badfd, iostatus);
#if BAREFOOTD
         }
#endif /* BAREFOOTD */
      }

      /* possible future optimization: if newrset not empty, use it? */
   }
}

void
io_handlesighup(void)
{
   const char *function = "io_handlesighup()";
   size_t i;

   slog(LOG_DEBUG, "%s: ioc = %ld", function, (long)ioc);

   for (i = 0; i < ioc; ++i) {
#if BAREFOOTD
      size_t clienti;
#endif /* BAREFOOTD */

      if (!iov[i].allocated)
         continue;

      if (iov[i].state.protocol == SOCKS_TCP)
         continue;

      SASSERTX(iov[i].state.protocol == SOCKS_UDP);

      /*
       * In the UDP case we should check rules on each packet, so indicate
       * we should not reuse the saved rules after sighup, which may have
       * changed the ACLs.
       * In the TCP case, we only check once.
       */

#if !BAREFOOTD
      iov[i].src.state.use_saved_rule = 0;
      iov[i].dst.state.use_saved_rule = 0;

#else /* BAREFOOTD */
      /*
       * No longer maintain resources for these clients.  If the
       * sockd.conf after the sighup still has these session and limits
       * on them, they will reallocated if still in use by the clients.
       */
      slog(LOG_DEBUG, "%s: iov #%ld, dstc = %ld",
           function, (long)ioc, (long)iov[i].dst.dstc);

      for (clienti = DUMMY_INDEX + 1; clienti < iov[i].dst.dstc; ++clienti) {
         SHMEM_UNUSE(&iov[i].dst.dstv[clienti].crule,
                     TOSA(&iov[i].dst.dstv[clienti].client),
                     sockscf.shmemfd,
                     SHMEM_ALL);

         SHMEM_CLEAR(&iov[i].dst.dstv[clienti].crule, 1);

         iov[i].dst.dstv[clienti].use_saved_rule      = 0;
         iov[i].dst.dstv[clienti].use_saved_replyrule = 0;


         /*
          * will need to do a new rule lookup, but keep the old one, sans
          * shmem ids, til then.
          */
         iov[i].dst.dstv[clienti].rule.crule
         = &iov[i].dst.dstv[clienti].crule;

         iov[i].dst.dstv[clienti].replyrule.crule
         = &iov[i].dst.dstv[clienti].crule;

         /*
          * will have to wait and see what the new address will be.  Zero
          * for now.
          */
         bzero(&iov[i].dst.dstv[clienti].host,
               sizeof(iov[i].dst.dstv[clienti].host));
         iov[i].dst.dstv[clienti].host.atype = (int)SOCKS_ADDR_IPV4;
      }
#endif /* BAREFOOTD */
   }
}

#if BAREFOOTD
int
io_remove_session(laddr, protocol, reason)
   const struct sockaddr  *laddr;
   const int protocol;
   const iostatus_t reason;
{
   const char *function = "io_remove_session()";
   size_t i;

   SASSERTX(protocol == SOCKS_UDP);

   slog(LOG_DEBUG, "%s: searching for local address %s.  Marked for removal "
                   "due to iostatus reason %d",
                   function,
                   laddr == NULL ? "<any>" : sockaddr2string(laddr, NULL, 0),
                   (int)reason);

   for (i = 0; i < ioc; ++i) {
      if (!iov[i].allocated
      ||  iov[i].state.protocol != protocol)
         continue;

      if (laddr != NULL
      &&  memcmp(&iov[i].src.laddr, laddr, sizeof(*laddr)) != 0)
         continue;

      slog(LOG_DEBUG, "removing iov #%lu with %lu active udp session%s",
                      (unsigned long)i,
                      (unsigned long)iov[i].dst.dstc - 1,
                      (iov[i].dst.dstc - 1) == 1 ? "" : "s");

      while (iov[i].dst.dstc > 1) {
         const size_t clienti = iov[i].dst.dstc;

         SYNC_UDP(&iov[i], &iov[i].dst.dstv[clienti - 1]);
         delete_io(-1 /* no ack to send */,
                   &iov[i],
                   -1,
                   reason);

         /*
          * delete_io() will call removeclient(), which will
          * decrement iov[i].dst.dstc.
          */
         SASSERTX(iov[i].dst.dstc < clienti);
      }

      SASSERTX(iov[i].dst.dstc == 1);
      close(iov[i].src.s); /* delete_io() does not close udp src in barefoot. */

      freebuffers(&iov[i]);
      free(iov[i].dst.dstv);
      bzero(&iov[i], sizeof(iov[i]));

      if (sockscf.state.mother.ack != -1) {
         const char p = SOCKD_FREESLOT_UDP;

         /* ack io slot free. */
         if (socks_sendton(sockscf.state.mother.ack,
                           &p,
                           sizeof(p),
                           sizeof(p),
                           0,
                           NULL,
                           0,
                           NULL) != sizeof(p))
             swarn("%s: socks_sendton(): mother", function);
      }

      proctitleupdate();
      return 0;
   }

   return -1;
}
#endif /* BAREFOOTD */

static void
delete_io(mother, io, badfd, status)
   int mother;
   sockd_io_t *io;
   int badfd;
   const iostatus_t status;
{
   const char *function = "delete_io()";
   const int errno_s = errno;
#if HAVE_GSSAPI
   gss_buffer_desc output_token;
   OM_uint32 minor_status;
#endif /* HAVE_GSSAPI */
   struct timeval tnow, timeestablished;
   uint64_t src_read, src_written, dst_read, dst_written,
            src_packetsread, src_packetswritten, dst_packetsread,
            dst_packetswritten;
   rule_t *rulev[] = {
                       &io->rule,
#if HAVE_SOCKS_HOSTID
                       io->hostidrule_isset ? &io->hostidrule : NULL,
#endif /* HAVE_SOCKS_HOSTID */
                       &io->crule,
                       };
   ruletype_t ruletypev[] = {
                              socksrule,
#if HAVE_SOCKS_HOSTID
                              hostidrule,
#endif /* HAVE_SOCKS_HOSTID */
                              clientrule
                            };
   size_t i;
   int command, protocol;
   rule_t *r;

   SASSERTX(  badfd < 0
           || badfd == io->src.s
           || badfd == io->control.s
           || badfd == io->dst.s);

   SASSERTX(io->allocated);

   /* AIX XLC does not like ifdefs in SHMEM_UNUSE macro call */
#if HAVE_SOCKS_RULES
   r = &io->rule;
#else /* !HAVE_SOCKS_RULES */
   r = &io->crule;
#endif /* !HAVE_SOCKS_RULES */

#if BAREFOOTD
   if (io->state.protocol != SOCKS_UDP) /* UDP is free'd by removeclient(). */
#endif /* BAREFOOTD */
      SHMEM_UNUSE(r, TOSA(&io->control.raddr), sockscf.shmemfd, SHMEM_ALL);

   gettimeofday(&tnow, NULL);

   /* log the disconnect if the rule says so. */
   for (i = 0; i < ELEMENTS(rulev); ++i) {
      const rule_t *rule = rulev[i];
      const ruletype_t ruletype = ruletypev[i];
      sockshost_t a, b;
      size_t bufused;
      char in[MAX_IOLOGADDR], out[MAX_IOLOGADDR],
           timeinfo[512],
           logmsg[sizeof(in) + sizeof(out) + 1024 + sizeof(timeinfo)];

      if (rule == NULL)
         continue;

#if !HAVE_SOCKS_RULES
      if (ruletype == clientrule && !sockscf.option.debug)
         continue; /* normally, only log from the autocreated socks-rule. */
#endif /* HAVE_SOCKS_RULES */

      if (rule->log.disconnect
      || (rule->log.error && status == IO_ERROR))
         /* LINTED */ /* EMPTY */;
      else
         continue;

      src_written        = io->src.written.bytes;
      src_packetswritten = io->src.written.packets;

      src_read           = io->src.read.bytes;
      src_packetsread    = io->src.read.packets;

      dst_written        = io->dst.written.bytes;
      dst_packetswritten = io->dst.written.packets;

      dst_read           = io->dst.read.bytes;
      dst_packetsread    = io->dst.read.packets;

      timeestablished    = io->state.time.established;

      if (ruletype == socksrule) {
         build_addrstr_src(GET_HOSTIDV(&io->state),
                           GET_HOSTIDC(&io->state),
                           &io->src.host,
                           NULL,
                           NULL,
                           sockaddr2sockshost(TOSA(&io->src.laddr), NULL),
                           &io->src.auth,
                           NULL,
                           in,
                           sizeof(in));

         switch (io->state.command) {
            case SOCKS_BIND:
            case SOCKS_BINDREPLY:
            case SOCKS_CONNECT:
               build_addrstr_dst(sockaddr2sockshost(TOSA(&io->dst.laddr), &a),
                                 io->state.proxyprotocol == PROXY_DIRECT ?
                                    NULL : sockaddr2sockshost(TOSA(&io->dst.raddr),
                                                              &b),
                                 io->state.proxyprotocol == PROXY_DIRECT
                                   ? NULL : &io->state.proxychain.extaddr,
                                 &io->dst.host,
                                 &io->dst.auth,
                                 NULL,
                                 (struct in_addr *)NULL,
                                 0,
                                 out,
                                 sizeof(out));
               break;

            case SOCKS_UDPASSOCIATE:
               if (io->dst.state.connected)
                  build_addrstr_dst(sockaddr2sockshost(TOSA(&io->dst.laddr), NULL),
                                    io->state.proxyprotocol == PROXY_DIRECT ?
                                       NULL : sockaddr2sockshost(TOSA(&io->dst.raddr),
                                                                 NULL),
                                    io->state.proxyprotocol == PROXY_DIRECT
                                       ? NULL : &io->state.proxychain.extaddr,
                                    &io->dst.host,
                                    &io->dst.auth,
                                    NULL,
                                    (struct in_addr *)NULL,
                                    0,
                                    out,
                                    sizeof(out));
               else {
                  sockshost_t a, b;

                  build_addrstr_dst(sockaddr2sockshost(TOSA(&io->dst.laddr), &a),
                                    io->state.proxyprotocol == PROXY_DIRECT ?
                                       NULL : sockaddr2sockshost(TOSA(&io->dst.raddr),
                                                                 &b),
                                    io->state.proxyprotocol == PROXY_DIRECT
                                       ? NULL : &io->state.proxychain.extaddr,
                                    NULL,
                                    &io->dst.auth,
                                    NULL,
                                    (struct in_addr *)NULL,
                                    0,
                                    out,
                                    sizeof(out));
               }

               break;

            default:
               SERRX(io->state.command);
         }

         command  = io->state.command;
         protocol = io->state.protocol;
      }
      else {
         /*
          * XXX if support for server chaining is added to bind, the
          * bindreply might involve a proxy on the src side.
          */

         protocol = io->state.clientprotocol;

#if !HAVE_SOCKS_RULES
         /*
          * we don't want to log the clientrule close of a udp session,
          * but only the individual clients closing the socksrule.
          */
         if (protocol == SOCKS_UDP)
            continue;
#endif /* !HAVE_SOCKS_RULES. */


      build_addrstr_src(GET_HOSTIDV(&io->state),
                        GET_HOSTIDC(&io->state),
#if HAVE_SOCKS_RULES
                        &io->control.host,
#else /* !HAVE_SOCKS_RULES */
                        (protocol == SOCKS_UDP && ruletype != socksrule) ?
                           NULL : &io->control.host,
#endif /* !HAVE_SOCKS_RULES */

                        NULL,
                        NULL,
                        sockaddr2sockshost(TOSA(&io->control.laddr), NULL),
                        &io->clientauth,
                        NULL,
                        in,
                        sizeof(in));

#if HAVE_SOCKS_RULES /* destination address is know upon accepting client. */

         *out = NUL; /* client-rule is from client to socks-server, and stop. */

#else /* HAVE_SOCKS_RULES */
         build_addrstr_dst(NULL, /* now known, but was not upon accepting. */
                           io->state.proxyprotocol == PROXY_DIRECT ?
                              NULL : sockaddr2sockshost(TOSA(&io->dst.raddr),
                                                        &b),
                           io->state.proxyprotocol == PROXY_DIRECT
                             ? NULL : &io->state.proxychain.extaddr,
                           &io->dst.host,
                           &io->dst.auth,
                           NULL,
                           (struct in_addr *)NULL,
                           0,
                           out,
                           sizeof(out));
#endif /* HAVE_SOCKS_RULES */

         SASSERTX(ruletype != socksrule);

#if HAVE_SOCKS_RULES
         command  = (ruletype == clientrule ? SOCKS_ACCEPT: SOCKS_HOSTID);
#else
         if (ruletype == clientrule) {
            if (protocol == SOCKS_TCP)
               command = SOCKS_ACCEPT;
            else
               command = SOCKS_UDPASSOCIATE;
         }
         else
            command = SOCKS_HOSTID;
#endif /* HAVE_SOCKS_RULES */
      }

      bufused = snprintf(logmsg, sizeof(logmsg), "%s(%lu): %s/%s ]: ",
                         rule->verdict == VERDICT_PASS ?
                         VERDICT_PASSs : VERDICT_BLOCKs,
#if BAREFOOTD
                        /* use the number from the user-created rule. */
                         io->state.protocol == SOCKS_UDP ?
                          (unsigned long)io->crule.number
                        : (unsigned long)rule->number,
#else /* !BAREFOOTD */
                        (unsigned long)rule->number,
#endif /* !BAREFOOTD */
                         protocol2string(protocol),
                         command2string(command));

      if (protocol == SOCKS_TCP) {
         if (*out == NUL) {
            const int isreversed
            = (io->state.command == SOCKS_BINDREPLY ? 1 : 0);

            bufused
            += snprintf(&logmsg[bufused], sizeof(logmsg) - bufused,
                       "%"PRIu64" -> %s -> %"PRIu64"",
                       (isreversed ? dst_written : src_written),
                       in,
                       (isreversed ? src_written  : dst_written));
         }
         else
            bufused
            += snprintf(&logmsg[bufused], sizeof(logmsg) - bufused,
                       "%"PRIu64" -> %s -> %"PRIu64", "
                       "%"PRIu64" -> %s -> %"PRIu64"",
                       src_written, in, src_read,
                       dst_written, out, dst_read);
      }
      else {
         SASSERTX(*out != NUL);
         SASSERTX(protocol == SOCKS_UDP);

         bufused += snprintf(&logmsg[bufused], sizeof(logmsg) - bufused,
                            "%"PRIu64"/%"PRIu64" -> %s -> %"PRIu64"/%"PRIu64", "
                            "%"PRIu64"/%"PRIu64" -> %s -> %"PRIu64"/%"PRIu64"",
                            src_written, src_packetswritten, in,
                            src_read, src_packetsread,
                            dst_written, dst_packetswritten, out,
                            dst_read, dst_packetsread);
      }

      bufused = snprintf(timeinfo, sizeof(timeinfo), "Session duration: %lds",
                         (long)(tnow.tv_sec - timeestablished.tv_sec));

      /*
       * XXX probably better to add another log-option, "stats" or similar,
       * that can be used to log some extra information, including this
       * and buffer-usage perhaps?
       */

      if (sockscf.option.debug
#if BAREFOOTD
      &&  protocol == SOCKS_TCP
#endif /* BAREFOOTD */
      ) {
         struct timeval accept2neg, negstart2negfinish,
                        negfinish2establish, sessionduration;
         char established2io_str[16];

         timersub(&io->state.time.negotiatestart,
                  &io->state.time.accepted,
                  &accept2neg);

         timersub(&io->state.time.negotiateend,
                  &io->state.time.negotiatestart,
                  &negstart2negfinish);

         timersub(&io->state.time.established,
                  &io->state.time.negotiateend,
                  &negfinish2establish);

         if (io->state.time.firstio.tv_sec == 0) {
            SASSERTX(sizeof(established2io_str) >= sizeof("N/A"));
            strcpy(established2io_str, "N/A");
         }
         else {
            struct timeval established2io;

            timersub(&io->state.time.firstio, &io->state.time.established,
                     &established2io);

            snprintf(established2io_str, sizeof(established2io_str),
                     "%ld.%06lds",
                    (long)established2io.tv_sec,
                    (long)established2io.tv_usec);
         }

         timersub(&tnow, &io->state.time.accepted, &sessionduration);

         bufused += snprintf(&timeinfo[bufused], sizeof(timeinfo) - bufused,
                             "\n"
                             "accept to negotiate start       : %ld.%06lds\n"
                             "negotiate duration              : %ld.%06lds\n"
                             "negotiate finish to established : %ld.%06lds\n"
                             "session establish to first i/o  : %s\n"
                             "total session duration          : %ld.%06lds\n",
                             (long)accept2neg.tv_sec,
                             (long)accept2neg.tv_usec,
                             (long)negstart2negfinish.tv_sec,
                             (long)negstart2negfinish.tv_usec,
                             (long)negfinish2establish.tv_sec,
                             (long)negfinish2establish.tv_usec,
                             established2io_str,
                             (long)sessionduration.tv_sec,
                             (long)sessionduration.tv_usec);
      }

      errno = errno_s;
      switch (status) {
         case IO_BLOCK:
            slog(LOG_INFO, "%s: blocked.  %s", logmsg, timeinfo);
            break;

         case IO_ERROR: {
            char errbuf[128];

            if (errno != 0)
               snprintf(errbuf, sizeof(errbuf), " (%s)", strerror(errno));
            else
               *errbuf = NUL;

            slog(LOG_INFO, "%s: %s error%s.  %s",
                 logmsg,
                 badfd < 0 ? "session"
                        : badfd == io->dst.s ? "remote peer" : "local client",
                 errbuf,
                 timeinfo);

            if (badfd >= 0) { /* try to generate a rst for the other end. */
               struct linger linger;

               linger.l_onoff  = 1;
               linger.l_linger = 0;

               if (setsockopt(badfd == io->dst.s ? io->src.s : io->dst.s,
                              SOL_SOCKET,
                              SO_LINGER,
                              &linger,
                              sizeof(linger)) != 0)
                  slog(LOG_DEBUG,
                       "%s: setsockopt(io->dst, SO_LINGER) failed: %s",
                       function, strerror(errno));
            }
            break;
         }

         case IO_CLOSE:
            slog(LOG_INFO, "%s: %s closed.  %s",
                logmsg,
                badfd < 0 ? "session" : badfd == io->dst.s ?
                "remote peer" : "local client",
                timeinfo);
            break;

         case IO_TIMEOUT: {
            const char *timeoutinfo;
            timeout_type_t timeouttype;
            long timetiltimeout;

            timetiltimeout = io_timetiltimeout(io, &tnow, &timeouttype);
            SASSERTX(timetiltimeout <= 0);

            switch (timeouttype) {
               case TIMEOUT_CONNECT:
                  timeoutinfo = "the connect to complete";
                  break;

               case TIMEOUT_IO:
                  timeoutinfo = "more data";
                  break;

               case TIMEOUT_TCP_FIN_WAIT:
                  SASSERTX(io->src.state.shutdown_wr
                  ||       io->dst.state.shutdown_wr);

                  if (io->dst.state.shutdown_wr)
                     timeoutinfo = "the client to close the connection";
                  else
                     timeoutinfo = "the remote peer to close the connection";
                  break;

              default:
               SERRX(timeouttype);
            }

            slog(LOG_INFO, "%s: timeout while waiting for %s.  %s",
            logmsg, timeoutinfo, timeinfo);

            break;
         }

         case IO_ADMINTERMINATION:
            slog(LOG_INFO, "%s: administrative termination.  %s",
                 logmsg, timeinfo);
            break;

         default:
            SERRX(status);
      }

#if SOCKS_SERVER
      if (io->state.command == SOCKS_BINDREPLY && ruletype == socksrule) {
         /*
          * log the close of the open'd bind session also.
          */
         const int original_command = io->state.command;
         iologaddr_t src, dst;

         init_iologaddr(&src,
                        SOCKADDR_OBJECT,
                        &io->src.laddr,
                        SOCKSHOST_OBJECT,
                        io->state.extension.bind ? NULL : &io->cmd.bind.host,
                        &io->src.auth,
                        GET_HOSTIDV(&io->state),
                        GET_HOSTIDC(&io->state));

         init_iologaddr(&dst,
                        SOCKADDR_OBJECT,
                        &io->dst.laddr,
                        SOCKADDR_OBJECT,
                        &io->dst.raddr,
                        &io->dst.auth,
                        NULL,
                        0);

         io->state.command = SOCKS_BIND;
         /*
          * The bindreply src/dst order is reversed compared to that of the
          * bind as the src for bindreply is the client that connects to the
          * address bound.
          */
         iolog(&io->cmd.bind.rule,
               &io->state,
               OPERATION_DISCONNECT,
               &dst,
               &src,
               NULL,
               NULL,
               NULL,
               0);
         io->state.command = original_command;
      }
#endif /* SOCKS_SERVER */
   }

#if HAVE_GSSAPI
   if (io->src.auth.method == AUTHMETHOD_GSSAPI) {
      if (gss_delete_sec_context(&minor_status,
      &io->src.auth.mdata.gssapi.state.id, &output_token) != GSS_S_COMPLETE)
         swarnx("%s: gss_delete_sec_context of src failed", function);

      CLEAN_GSS_TOKEN(output_token);
   }

   if (io->dst.auth.method == AUTHMETHOD_GSSAPI) {
      if (gss_delete_sec_context(&minor_status,
      &io->dst.auth.mdata.gssapi.state.id, &output_token) != GSS_S_COMPLETE)
         swarnx("%s: gss_delete_sec_context of dst failed", function);

      CLEAN_GSS_TOKEN(output_token);
   }
#endif /* HAVE_GSSAPI */

#if !HAVE_SOCKS_RULES
   if (io->state.command == SOCKS_UDPASSOCIATE) {
      /*
       * The io itself is normally not freed in the udp-case, as we can
       * always get new clients; only this one client is removed.
       */
      removeclient(io->dst.s, &io->dst.dstc, io->dst.dstv);
   }
   else { /* not UDP, must be TCP.  Free io as usual then. */
      SASSERTX(io->state.command == SOCKS_CONNECT);
#endif /* !HAVE_SOCKS_RULES */

   freebuffers(io);
   close_iodescriptors(io);

   if (mother != -1) {
      const char b = io->state.command
      == SOCKS_UDPASSOCIATE ? SOCKD_FREESLOT_UDP : SOCKD_FREESLOT_TCP;

      /* ack io slot free. */
      if (socks_sendton(mother, &b, sizeof(b), sizeof(b), 0, NULL, 0, NULL)
      != sizeof(b))
          swarn("%s: socks_sendton(): mother", function);
   }

   bzero(io, sizeof(*io));
   proctitleupdate();

#if BAREFOOTD
   }
#endif /* BAREFOOTD */
}

void
close_iodescriptors(io)
   const sockd_io_t *io;
{
   const char *function = "close_iodescriptors()";

   close(io->src.s);
   close(io->dst.s);
   freefds += 2;

#if SOCKS_SERVER  /* may have control connection also. */
   switch (io->state.command) {
      case SOCKS_CONNECT:
         break;

      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (!io->state.extension.bind)
            break;
         /* else: */ /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE:
         close(io->control.s);
         ++freefds;
         break;

      default:
         SERRX(io->state.command);
   }
#endif /* !SOCKS_SERVER */
}

int
recv_io(s, io)
   int s;
   sockd_io_t *io;
{
   const char *function = "recv_io()";
#if HAVE_GSSAPI
   gss_buffer_desc gssapistate;
   char gssapistatemem[MAX_GSS_STATE];
#endif /* HAVE_GSSAPI */
   sockd_io_t tmpio;
   struct iovec iovecv[2];
   struct msghdr msg;
   size_t ioi;
   ssize_t received;
   struct timeval tnow;
   int wearechild, fdexpect, fdreceived, iovecc;
   CMSG_AALLOC(cmsg, sizeof(int) * FDPASS_MAX);

   bzero(iovecv, sizeof(iovecv));
   iovecc = 0;

   iovecv[iovecc].iov_base = &tmpio;
   iovecv[iovecc].iov_len  = sizeof(tmpio);
   ++iovecc;

#if HAVE_GSSAPI
   iovecv[iovecc].iov_base = gssapistatemem;
   iovecv[iovecc].iov_len  = sizeof(gssapistatemem);
   ++iovecc;
#endif /* HAVE_GSSAPI */

   bzero(&msg, sizeof(msg));
   msg.msg_iov    = iovecv;
   msg.msg_iovlen = iovecc;
   msg.msg_name   = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

   if (io == NULL) /* child semantics; find a free io ourselves. */
      wearechild = 1;
   else
      wearechild = 0;

   if ((received = recvmsgn(s, &msg, 0)) < (ssize_t)sizeof(*io)) {
      if (received == -1 && errno == EAGAIN)
         ;
      else
         slog(LOG_DEBUG, "%s: recvmsg(): unexpected short read on socket "
                         "%d (%ld < %lu): %s",
                         function,
                         s,
                         (long)received,
                         (unsigned long)(sizeof(*io)),
                         strerror(errno));

      return -1;
   }

   if (socks_msghaserrors(function, &msg))
      return -1;

   /*
    * ok, received a io.  Find out where to store it.
    */
   ioi = 0;
   if (wearechild) { /* child semantics; find a free io ourselves. */
      SASSERTX(io == NULL);

      for (; ioi < ioc; ++ioi)
         if (!iov[ioi].allocated) {
            io = &iov[ioi];
            break;
         }

      if (io == NULL) {
         /*
          * Only reason this should happen is if mother died/closed connection,
          * and what we are getting now is not actually an i/o, but just an
          * error indicator.
          */
         char buf;

         if (recv(s, &buf, sizeof(buf), MSG_PEEK) > 0)
            /*
             * not an error indicator, but a mismatch between us and mother.
             * Should never happen.
             */
            SERRX(io_allocated(NULL, NULL));

         return -1;
      }
   }

   *io = tmpio;

   SASSERTX(io->crule.bw == NULL);
   SASSERTX(io->crule.ss == NULL);
   SASSERTX(io->rule.bw == NULL);
   SASSERTX(io->rule.ss == NULL);

#if HAVE_SOCKS_RULES
   SASSERTX(io->crule.bw_shmid == 0);
   SASSERTX(io->crule.ss_shmid == 0);

#else /* !HAVE_SOCKS_RULES */
   SASSERTX(io->rule.bw_shmid == 0);
   SASSERTX(io->rule.ss_shmid == 0);

#endif /* !HAVE_SOCKS_RULES */

#if SOCKS_SERVER
   if (wearechild) {
      if (io->state.command == SOCKS_UDPASSOCIATE) {
         io->cmd.udp.fwdrule   = &fwdrulev[ioi];
         io->cmd.udp.replyrule = &replyrulev[ioi];

         bzero(io->cmd.udp.replyrule, sizeof(*io->cmd.udp.replyrule));
         bzero(io->cmd.udp.fwdrule, sizeof(*io->cmd.udp.fwdrule));
      }
   }
#endif /* SOCKS_SERVER */

   /* figure out how many descriptors we are supposed to be passed. */
   switch (io->state.command) {
      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (io->state.extension.bind)
            fdexpect = 3;   /* in, out, control. */
         else
            fdexpect = 2;   /* in and out. */
         break;

      case SOCKS_CONNECT:
         fdexpect = 2;   /* in and out */
         break;

      case SOCKS_UDPASSOCIATE:
#if BAREFOOTD
         fdexpect = 2;   /* in and out. */
#else /* SOCKS_SERVER */
         fdexpect = 3;   /* in, out, control. */
#endif /* SOCKS_SERVER */
         break;

      default:
         SERRX(io->state.command);
   }

   if (!CMSG_RCPTLEN_ISOK(msg, sizeof(int) * fdexpect)) {
      swarnx("%s: received control message has the invalid len of %d",
              function, (int)CMSG_TOTLEN(msg));

      return -1;
   }

   /*
    * Get descriptors sent us.  Should be at least two.
    */

   SASSERTX(cmsg->cmsg_level == SOL_SOCKET);
   SASSERTX(cmsg->cmsg_type  == SCM_RIGHTS);

   fdreceived = 0;
   CMSG_GETOBJECT(io->src.s, cmsg, sizeof(io->src.s) * fdreceived++);
   CMSG_GETOBJECT(io->dst.s, cmsg, sizeof(io->dst.s) * fdreceived++);

#if DIAGNOSTIC
   checksockoptions(io->src.s,
                    io->state.protocol == SOCKS_TCP ? SOCK_STREAM : SOCK_DGRAM,
                    1);

   checksockoptions(io->dst.s,
                    io->state.protocol == SOCKS_TCP ? SOCK_STREAM : SOCK_DGRAM,
                    1);
#endif /* DIAGNOSTIC */

#if HAVE_GSSAPI
   gssapistate.value  = gssapistatemem;
   gssapistate.length = received - sizeof(*io);

   if (gssapistate.length > 0)
      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: read gssapistate of size %ld",
              function, (unsigned long)gssapistate.length);
#endif /* HAVE_GSSAPI */

   /* any more descriptors to expect? */
   switch (io->state.command) {
      case SOCKS_BINDREPLY:
#if HAVE_GSSAPI
         if (io->dst.auth.method == AUTHMETHOD_GSSAPI) {
            if (gssapi_import_state(&io->dst.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
         }
#endif /* HAVE_GSSAPI */

         if (io->state.extension.bind) {
            CMSG_GETOBJECT(io->control.s,
                           cmsg,
                           sizeof(io->control.s) * fdreceived++);
#if DIAGNOSTIC
            checksockoptions(io->control.s, SOCK_STREAM, 1);
#endif /* DIAGNOSTIC */
         }
         else
            io->control.s = -1;
         break;

      case SOCKS_CONNECT:
#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI) {
            if (gssapi_import_state(&io->src.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
         }
#endif /* HAVE_GSSAPI */

         io->control.s = -1;
         break;

      case SOCKS_UDPASSOCIATE:
#if SOCKS_SERVER
         /* LINTED pointer casts may be troublesome */
         CMSG_GETOBJECT(io->control.s,
                        cmsg,
                        sizeof(io->control.s) * fdreceived++);

#if HAVE_GSSAPI
         if (io->src.auth.method == AUTHMETHOD_GSSAPI) {
            if (gssapi_import_state(&io->src.auth.mdata.gssapi.state.id,
            &gssapistate) != 0)
               return -1;
         }
#endif /* HAVE_GSSAPI */
#else /* !SOCKS_SERVER */

         io->control.s = -1;
#endif /* !SOCKS_SERVER */

         break;

      default:
         SERRX(io->state.command);
   }

   if (wearechild) { /* only child does i/o, so wait til then before initing. */
      size_t i;

      for (i = 0; i < io->extsocketoptionc; ++i)
         io->extsocketoptionv[i].info
         = optval2sockopt(io->extsocketoptionv[i].level,
                          io->extsocketoptionv[i].optname);

      gettimeofday(&tnow, NULL);

      sockd_isoverloaded("client object received from request process",
                         &io->state.time.established,
                         &tnow,
                         &tnow);

      /* needs to be set now for correct bandwidth calculation/limiting. */
      io->lastio = tnow;

#if BAREFOOTD
      if (io->state.command == SOCKS_UDPASSOCIATE) {
         /*
          * prepare things for udp client
          */

         SASSERTX(io->src.auth.method == AUTHMETHOD_NONE);

         if ((io->dst.dstv = malloc(UDP_MEMBLOCK * sizeof(*io->dst.dstv)))
         == NULL) {
            swarn("%s: failed to allocate memory for udp clients", function);
            close(io->src.s);
            close(io->dst.s);

            return 0; /* strange, but not fatal. */
         }

         io->dst.dstc    = DUMMY_INDEX;
         io->dst.dstcmax = UDP_MEMBLOCK;

         /*
          * dummy-socket.  Need to put in something valid so
          * select(2) has something to select for write on, but it
          * is never actually used for any i/o, as each client will
          * require it's own outgoing socket, with it's own local address
          * so that we know what destinations are failing.
          *
          * The dst, as used for rulespermit(), is however the address
          * we receive the udp packet on (src.laddr), and that remains the
          * same for all our udp clients of course.
          */

         /*
          * Use the dummy-index to store the "global" session info too.
          */
         bzero(&io->dst.dstv[DUMMY_INDEX], sizeof(io->dst.dstv[DUMMY_INDEX]));
         io->dst.dstv[DUMMY_INDEX].s               = io->dst.s;
         io->dst.dstv[DUMMY_INDEX].laddr           = io->dst.laddr;
         io->dst.dstv[DUMMY_INDEX].host            = io->dst.host;
         io->dst.dstv[DUMMY_INDEX].client     = io->dst.dstv[DUMMY_INDEX].laddr;

         io->dst.dstv[DUMMY_INDEX].crule           = io->crule;
         io->dst.dstv[DUMMY_INDEX].rule            = io->rule;

         io->dst.dstv[DUMMY_INDEX].firstio         = io->state.time.established;
         io->dst.dstv[DUMMY_INDEX].lastio          = io->state.time.established;

         ++io->dst.dstc;
      }
#endif /* BAREFOOTD */

      if (io->control.s != -1)
         socks_allocbuffer(io->control.s, SOCK_STREAM);

      socks_allocbuffer(io->src.s,
                        io->state.command
                        == SOCKS_UDPASSOCIATE ? SOCK_DGRAM : SOCK_STREAM);

      socks_allocbuffer(io->dst.s,
                        io->state.command
                        == SOCKS_UDPASSOCIATE ? SOCK_DGRAM : SOCK_STREAM);

      io->src.isclientside = 1;

#if HAVE_NEGOTIATE_PHASE
      if (io->clientdatalen != 0) {
         int socket_to_add_to;

         slog(LOG_DEBUG, "%s: adding initial data of size %ld "
                         "from client %s to iobuf",
                         function,
                         (long)io->clientdatalen,
                         sockshost2string(&io->src.host, NULL, 0));

         /*
          * XXX if covenant, this request has already been parsed and we
          * already know we need to forward it; should optimize away
          * re-parsing.
          */

         switch (io->state.command) {
            case SOCKS_UDPASSOCIATE:
               socket_to_add_to = io->control.s;
               break;

            case SOCKS_CONNECT:
               socket_to_add_to = io->src.s;
               break;

            case SOCKS_BINDREPLY:
               /*
                * for a bindreply, src and dst is reversed; dst is our client.
                */
               socket_to_add_to = io->dst.s;
               break;

            default:
               SERRX(io->state.command);
         }

         socks_addtobuffer(socket_to_add_to,
                           READ_BUF,
                           0,
                           io->clientdata,
                           io->clientdatalen);

         io->clientdatalen = 0;
      }
#endif /* HAVE_NEGOTIATE_PHASE */
   }

   if (sockscf.option.debug >= DEBUG_VERBOSE) {
      slog(LOG_DEBUG, "%s: received %d descriptor(s) for command %d.  "
                      "Control: %d, src: %d, dst: %d.  Allocated to iov #%lu",
                      function,
                      fdreceived,
                      io->state.command,
                      io->control.s,
                      io->src.s,
                      io->dst.s,
                      (unsigned long)ioi);

      slog(LOG_DEBUG, "%s: received src socket %d (%s) ...",
                      function, io->src.s, socket2string(io->src.s, NULL, 0));

      slog(LOG_DEBUG, "%s: received dst socket %d (%s) ...",
                      function, io->dst.s, socket2string(io->dst.s, NULL, 0));

      if (io->control.s != -1) {
         slog(LOG_DEBUG, "%s: received control socket %d (%s) ...",
                         function,
                         io->control.s,
                         socket2string(io->control.s, NULL, 0));
      }
   }

   if (io->crule.bw_shmid != 0 || io->crule.ss_shmid != 0)
      slog(LOG_DEBUG, "%s: client-rule: bw_shmid: %ld, ss_shmid: %ld",
                      function, io->crule.bw_shmid, io->crule.ss_shmid);


   if (io->rule.bw_shmid != 0 || io->rule.ss_shmid != 0)
      slog(LOG_DEBUG, "%s: socks-rule: bw_shmid: %ld, ss_shmid: %ld",
                      function, io->rule.bw_shmid, io->rule.ss_shmid);

   if (sockscf.option.debug >= DEBUG_VERBOSE) {
      sockd_shmat(&io->rule, SHMEM_ALL);
      sockd_shmat(&io->crule, SHMEM_ALL);

      if (io->crule.bw_shmid != 0)
         slog(LOG_DEBUG, "%s: client-rule: "
                         "bw object at location %p, ts %ld.%06ld, "
                         "clients: %ld, rulenumber: %ld",
                         function, &io->crule.bw,
                         (long)io->crule.bw->mstate.allocatedts.tv_sec,
                         (long)io->crule.bw->mstate.allocatedts.tv_usec,
                         (long)io->crule.bw->mstate.clients,
                         (unsigned long)io->crule.bw->mstate.rulenumber);

      if (io->rule.bw_shmid != 0)
         slog(LOG_DEBUG, "%s: socks-rule: "
                         "bw object at location %p, ts %ld.%06ld, "
                         "clients: %ld, rulenumber: %ld",
                         function, &io->rule.bw,
                         (long)io->rule.bw->mstate.allocatedts.tv_sec,
                         (long)io->rule.bw->mstate.allocatedts.tv_usec,
                         (long)io->rule.bw->mstate.clients,
                         (unsigned long)io->rule.bw->mstate.rulenumber);

      if (io->crule.ss_shmid != 0)
         slog(LOG_DEBUG, "%s: client-rule: "
                         "ss object at location %p, ts %ld.%06ld, "
                         "clients: %ld, rulenumber: %ld",
                         function, &io->crule.ss,
                         (long)io->crule.ss->mstate.allocatedts.tv_sec,
                         (long)io->crule.ss->mstate.allocatedts.tv_usec,
                         (long)io->crule.ss->mstate.clients,
                         (unsigned long)io->crule.ss->mstate.rulenumber);

      if (io->rule.ss_shmid != 0)
         slog(LOG_DEBUG, "%s: socks-rule: "
                         "ss object at location %p, ts %ld.%06ld, "
                         "clients: %ld, rulenumber: %ld",
                         function, &io->rule.ss,
                         (long)io->rule.ss->mstate.allocatedts.tv_sec,
                         (long)io->rule.ss->mstate.allocatedts.tv_usec,
                         (long)io->rule.ss->mstate.clients,
                         (unsigned long)io->rule.ss->mstate.rulenumber);

      sockd_shmdt(&io->crule, SHMEM_ALL);
      sockd_shmdt(&io->rule, SHMEM_ALL);
   }


   if (wearechild)
      /*
       * attach now and keep attached, so we don't have to attach/detach
       * for every i/o op later.
       */
      sockd_shmat(HAVE_SOCKS_RULES ? &io->rule : &io->crule, SHMEM_ALL);

   freefds       -= fdreceived;
   io->allocated  = 1;

   return 0;
}

static void
io_clearset(io, set)
   const sockd_io_t *io;
   fd_set *set;
{

   SASSERTX(io->src.s != -1 && io->dst.s != -1);
   FD_CLR(io->src.s, set);
   FD_CLR(io->dst.s, set);

   switch (io->state.command) {
      case SOCKS_CONNECT:
         break;

      case SOCKS_BIND:
      case SOCKS_BINDREPLY:
         if (!io->state.extension.bind)
            break;
         /* else: */ /* FALLTHROUGH */

      case SOCKS_UDPASSOCIATE:
#if SOCKS_SERVER
         SASSERTX(io->control.s != -1);
         FD_CLR(io->control.s, set);
#endif /* SOCKS_SERVER */
         break;

      default:
         SERRX(io->state.command);
   }
}

static size_t
io_allocated(tcp_alloc, udp_alloc)
   int *tcp_alloc;
   int *udp_alloc;
{
   const char *function = "io_allocated()";
   size_t i;
   int tcp_alloc_mem, udp_alloc_mem;

   if (tcp_alloc == NULL)
      tcp_alloc = &tcp_alloc_mem;

   if (udp_alloc == NULL)
      udp_alloc = &udp_alloc_mem;

   *udp_alloc = *tcp_alloc = 0;
   for (i = 0; i < ioc; ++i) {
      if (!iov[i].allocated)
         continue;

      switch (iov[i].state.protocol) {
         case SOCKS_UDP:
            ++(*udp_alloc);
            break;

         case SOCKS_TCP:
            ++(*tcp_alloc);
            break;

         default:
            SERRX(iov[i].state.protocol);
      }

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: iov #%lu allocated for %s",
         function, (unsigned long)i, protocol2string(iov[i].state.protocol));
   }

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: allocated for tcp: %d, udp: %d",
      function, *tcp_alloc, *udp_alloc);

   return *tcp_alloc + *udp_alloc;
}

static iostatus_t
doio(io, rset, wset, flags, badfd)
   sockd_io_t *io;
   fd_set *rset, *wset;
   const int flags;
   int *badfd;
{
   const char *function = "doio()";

   slog(LOG_DEBUG, "%s: control: %d, src: %d, dst: %d",
        function, io->control.s, io->src.s, io->dst.s);

   SASSERTX(io->allocated);

   *badfd = -1;

   if ((FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset))
   ||  (FD_ISSET(io->dst.s, rset) && FD_ISSET(io->src.s, wset)))
      ;
   else {
      swarnx("%s: FD_ISSET(io->src.s, rset) = %d, "
                 "FD_ISSET(io->src.s, wset) = %d "
                 "FD_ISSET(io->dst.s, rset) = %d, "
                 "FD_ISSET(io->dst.s, wset) = %d, ",
                 function,
                 FD_ISSET(io->src.s, rset),
                 FD_ISSET(io->src.s, wset),
                 FD_ISSET(io->dst.s, rset),
                 FD_ISSET(io->dst.s, wset));

      SASSERTX(0);

      /* should only get here if asserts are disabled. */
      *badfd = io->dst.s;
      return IO_ERROR;
   }

   if (io->state.time.firstio.tv_sec  == 0
   &&  io->state.time.firstio.tv_usec == 0)
      gettimeofday(&io->state.time.firstio, NULL);

   errno = 0; /* reset before each call. */
   switch (io->state.protocol) {
      case SOCKS_TCP:
         return doio_tcp(io, rset, wset, flags, badfd);

#if HAVE_UDP_SUPPORT
      case SOCKS_UDP:
         return doio_udp(io, rset, wset, badfd);
#endif /* HAVE_UDP_SUPPORT */

      default:
         SERRX(io->state.protocol);
         /* NOTREACHED */
   }
}

static iostatus_t
doio_tcp(io, rset, wset, flags, bad)
   sockd_io_t *io;
   fd_set *rset, *wset;
   const int flags;
   int *bad;
{
   const char *function = "doio_tcp()";
   iologaddr_t src, dst, proxy;
   struct { objecttype_t type; void *object; } dstraddr;
   ssize_t r;
   size_t bwused;
   int bothways;
#if COVENANT
   char *buf      = io->clientdata;
   size_t buflen  = sizeof(io->clientdata) - io->clientdatalen;
   size_t bufused = io->clientdatalen;
#else
   /*
    * Static so that it gets allocated on the heap rather than the
    * stack, as the latter seems to cause some problems on Solaris
    * where under stress Solaris is unable to grow the stack by
    * that much.
    * XXX make this *one* object that can be used by all the three
    * functions instead of having a separate object in each one.
    */
   static char buf[SOCKD_BUFSIZE];
   size_t buflen  = sizeof(buf);
   size_t bufused = 0;
#endif /* !COVENANT */

   SASSERTX(io->state.protocol == SOCKS_TCP);
   if (io->state.command == SOCKS_CONNECT)
      SASSERTX(io->dst.state.connected);

   if (FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset)
   &&  FD_ISSET(io->dst.s, rset) && FD_ISSET(io->src.s, wset))
      bothways = 1;
   else
      bothways = 0;

   bwused = 0;
   if (SHMEM_RULE(io)->bw_shmid != 0) {
      /*
       * If most clients are active, this should distribute the bw
       * reasonably fair.  If not, this is suboptimal as we will
       * need to do more i/o operations than otherwise necessary
       * because our buflen is smaller than it needs to be.
       */

      buflen = MIN(SHMEM_RULE(io)->bw->object.bw.maxbps, buflen);

      SASSERTX(SHMEM_RULE(io)->bw->mstate.clients > 0);
      buflen = MAX(1,
                     (buflen / SHMEM_RULE(io)->bw->mstate.clients)
                   / (bothways ? 2 : 1));

      slog(LOG_DEBUG,
           "%s: # of clients is %lu, bothways? %s.  Buflen set to %lu",
           function,
           (unsigned long)SHMEM_RULE(io)->bw->mstate.clients,
           bothways ? "yes" : "no",
           (unsigned long)buflen);
   }

   init_iologaddr(&src,
                  SOCKADDR_OBJECT,
                  &io->src.laddr,
                  SOCKADDR_OBJECT,
                  &io->src.raddr,
                  &io->src.auth,
                  GET_HOSTIDV(&io->state),
                  GET_HOSTIDC(&io->state));

   if (io->state.proxyprotocol == PROXY_DIRECT) {
      dstraddr.object = &io->dst.raddr;
      dstraddr.type   = SOCKADDR_OBJECT;
   }
   else {
      dstraddr.object = &io->dst.host;
      dstraddr.type   = SOCKSHOST_OBJECT;
   }

   init_iologaddr(&dst,
                  SOCKADDR_OBJECT,
                  &io->dst.laddr,
                  dstraddr.type,
                  dstraddr.object,
                  &io->dst.auth,
                  NULL,
                  0);

   init_iologaddr(&proxy,
                  SOCKADDR_OBJECT,
                  io->state.proxyprotocol == PROXY_DIRECT ?
                     NULL : &io->dst.raddr,
                  SOCKSHOST_OBJECT,
                  io->state.proxyprotocol == PROXY_DIRECT ?
                     NULL : &io->state.proxychain.extaddr,
                  NULL,
                  NULL,
                  0);

   /* from in to out ... */
   if (FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset)) {
      int allflushed;

      /*
       * If we have previously tried to write, but could not write it
       * all, we will have data buffered for the socket. In that case
       * we need to flush the buffer before writing anything else.
       * Since that data has already been logged as written (even if
       * only to buffer), don't log it again.
       */
      if (socks_flushbuffer(io->dst.s, -1) == -1) {
         if (!ERRNOISTMP(errno)) {
            *bad = io->dst.s;
            return IO_ERROR;
         }

         allflushed = 0;
      }
      else
         allflushed = 1;

      if (allflushed) {
         r = io_tcp_rw(&io->src,
                       &io->dst,
                       bad,
                       &io->reqflags,
                       buf,
                       buflen,
                       &bufused,
                       flags);

         if (*bad != -1)
            return r == 0 ? IO_CLOSE : IO_ERROR;

         switch (r) {
            case -1:
               r = 0; /* bad is not set, so temporary error. */
               break;

            case 0:
               break;

            default:
               iolog(&io->rule,
                     &io->state,
                     OPERATION_IO,
                     &src,
                     &dst,
                     NULL,
                     &proxy,
                     buf,
                     (size_t)r);
         }

         bwused += r;
      }
   }

   /* ... and out to in. */
   if (FD_ISSET(io->dst.s, rset) && FD_ISSET(io->src.s, wset)) {
      int allflushed;

      /*
       * If we have previously tried to write, but could not write it
       * all, we will have data buffered for the socket. In that case
       * we need to flush the buffer before writing anything else.
       * Since that data has already been logged as written (even if
       * only to buffer), don't log it again.
       */
      if (socks_flushbuffer(io->src.s, -1) == -1) {
         if (!ERRNOISTMP(errno)) {
            *bad = io->src.s;
            return IO_ERROR;
         }

         allflushed = 0;
      }
      else
         allflushed = 1;

      if (allflushed) {
         r = io_tcp_rw(&io->dst,
                       &io->src,
                       bad,
                       &io->reqflags,
                       buf,
                       buflen,
                       &bufused,
                       flags);

         if (*bad != -1)
            return r == 0 ? IO_CLOSE : IO_ERROR;

         switch (r) {
            case -1:
               r = 0; /* bad is not set, so temporary error. */
               break;

            case 0:
               break;

            default:
               iolog(&io->rule,
                     &io->state,
                     OPERATION_IO,
                     &dst,
                     &src,
                     &proxy,
                     NULL,
                     buf,
                     (size_t)r);
         }

         bwused += r;
      }
   }

   gettimeofday(&io->lastio, NULL);
   io_update(&io->lastio, bwused, SHMEM_RULE(io), sockscf.shmemfd);

   slog(LOG_DEBUG, "%s: bwused = %ld", function, (unsigned long)bwused);

   if (bwused)
      return IO_NOERROR;
   else
      return IO_EAGAIN;
}

static int
io_tcp_rw(in, out, bad, reqflags, buf, bufsize, bufused, flag)
   sockd_io_direction_t *in;
   sockd_io_direction_t *out;
   int *bad;
   const requestflags_t *reqflags;
   char *buf;
   size_t bufsize;
   size_t *bufused;
   int flag;
{
   const char *function = "io_tcp_rw()";
   ssize_t r, w, p;
   size_t bufusedmem = 0;

   if (bufused == NULL)
      bufused = &bufusedmem;

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: %d -> %d, bufsize = %lu, bufused = %lu, flag = %d",
                      function,
                      in->s,
                      out->s,
                      (unsigned long)bufsize,
                      (unsigned long)*bufused,
                      flag);

   *bad = -1; /* no error so far. */

   if (in->state.err != 0) {
      slog(LOG_DEBUG, "%s: failure already detected on socket %d "
                      "(%s, errno = %d)",
                      function, in->s,
                      strerror(in->state.err), in->state.err);

      errno = in->state.err;
      *bad  = in->s;

      return -1;
   }

   if (out->state.err != 0) {
      slog(LOG_DEBUG, "%s: failure already detected on socket %d "
                      "(%s, errno = %d)",
                      function,
                      out->s,
                      strerror(out->state.err), out->state.err);

      errno = out->state.err;
      *bad  = out->s;

      return -1;
   }

   /*
    * read data from in ...
    */


   /*
    * We receive OOB in-line.  If flag has MSG_OOB set, it means we
    * are at the OOB marker.  The next byte we read (and it will be
    * only one) is the OOB byte, and since we receive it in-line,
    * we should turn off the MSG_OOB flag.
    *
    * When we write the data we will keep the MSG_OOB flag, and
    * hopefully that will work even if the write is combined with
    * data read from the buffer (so we send more than one byte).
    * The last byte, which we will now read from the socket, should then be
    * tagged as the "oob" data.  Possible this will not work 100% correctly
    * on some non-BSD implementations, but go with it for now.
    */

   if (in->flags & MSG_OOB)
      /*
       * The problem with oob is that select(2) signals we have oob until;
       * we've read past it (i.e., read at least one normal byte).
       *
       * To handle receiving two oob-bytes in a row, we need to check whether
       * the last byte we received on this socket was also an oob-byte, as
       * if it was, we can't use select(2) to check for it (select(2) would
       * keep returning, since the oob flag is set until we've read _past_ the
       * oob byte), and we must instead check here for oob regardless of what
       * flags says.
       */
      flag |= MSG_OOB;

   if (flag & MSG_OOB) {
      if (sockatmark(in->s) != 1)
         flag &= ~MSG_OOB;
      else
         slog(LOG_DEBUG, "%s: have OOB data on socket %d", function, in->s);
   }

   /*
    * never read more from in than we can write to out, iobuf included.
    * Since we don't know how much we can write to the socket, except
    * it should normally always be at least one byte, only count the
    * space left in the iobuf.
    * Also make sure we can always NUL-terminate buf if necessary, to
    * make things easier for covenant.
    */
   p = MIN(bufsize - *bufused, socks_freeinbuffer(out->s, WRITE_BUF));
   SASSERTX(p > 0);

#if HAVE_GSSAPI
   /*
    * If the data we are writing needs to be gssapi-encapsulated,
    * also make sure we don't read more than we can encapsulate in
    * a gssapi token; we don't want to deal with "segmentation" of
    * gssapi tokens.
    */
   if (out->auth.method == AUTHMETHOD_GSSAPI) {
      SASSERTX(out->auth.mdata.gssapi.state.maxgssdata > 0);
      p -= GSSAPI_OVERHEAD(&out->auth.mdata.gssapi.state);

      p = MIN(p, (ssize_t)out->auth.mdata.gssapi.state.maxgssdata);
      if (p <= 0) {
         /*
          * We are not expecting this to happen since we should not
          * get here as long as we have unflushed data left in
          * the buffer.
          */
         swarnx("%s: write buffer for socket %d is almost full.  "
                "Only %lu bytes free, with a gssapi overhead of %lu",
                function, out->s,
                (unsigned long)socks_freeinbuffer(out->s, WRITE_BUF),
                (unsigned long)GSSAPI_OVERHEAD(
                  &out->auth.mdata.gssapi.state));
         p = 1;
      }
   }
#endif /* HAVE_GSSAPI */

#if COVENANT
   if (in->isclientside && !reqflags->httpconnect)
      flag |= MSG_PEEK;
#endif /* COVENANT  */

   r = socks_recvfrom(in->s,
                      &buf[*bufused],
                      p,
                      flag & ~MSG_OOB,
                      NULL,
                      NULL,
                      &in->auth,
                      NULL,
                      NULL);

   if (r <= 0) {
      if (r == 0) {
         /*
          * FIN from "in".  It won't send us any more data, so
          * we shutdown "out" for writing to let it know.
          *
          * When "out" has nothing more to send, it will send us a
          * FIN too, and we will shutdown "in" for writing.
          * At that point, both "in" and "out" have sent a FIN,
          * meaning none of them will send us any more data.
          * Only then can we close the socket.  Since we may clear
          * state.fin however, state.shutdown should be used
          * for testing here.
          */

         slog(LOG_DEBUG, "%s: got EOF on in->s (%d) when trying to read up to "
                         "%ld bytes",
                         function, in->s, (long)p);

         in->state.fin = 1;

#if HAVE_DARWIN
         if (in->read.bytes == 0) {
            socklen_t optlen;
            int opt;

            optlen = sizeof(opt);
            if (getsockopt(in->s, SOL_SOCKET, SO_RCVBUF, &opt, &optlen) == -1)
               swarn("%s: getsockopt(SO_RCVBUF)", function);

            if (opt == 0)
               swarnx("%s: There appears to be a bug in the OS X Kernel, "
                      "v10.8.0 and earlier at least, that for some reason "
                      "makes a socket's SO_RCVBUF become zero sometimes "
                      "during the processes of passing the file descriptor "
                      "around between processes.  "
                      "Subsequent reads from it return 0 even if the other "
                      "side has not closed the connection.  "
                      "This makes TCP's EOF indication not work correctly, "
                      "and %s ends up closing the session prematurely.",
                      function, PACKAGE);
         }
#endif /* HAVE_DARWIN */

         SASSERTX(socks_bytesinbuffer(out->s, WRITE_BUF, 0) == 0);

         if (in->state.shutdown_wr) /* have already received FIN from out. */
            *bad = out->s; /* done with this socket, "out" closed first. */

         if (!out->state.shutdown_wr) {
            /*
             * use shutdown() to forward FIN, but continue reading.
             */
            slog(LOG_DEBUG, "%s: shutting down out->s (%d) for writing",
            function, out->s);

            if (shutdown(out->s, SHUT_WR) != 0) {
               slog(LOG_DEBUG,
                    "%s: shutdown() for write towards remote peer failed: %s",
                    function, strerror(errno));

               *bad = out->s;
            }
            else
               out->state.shutdown_wr = 1;
         }
      }
      else
         if (!ERRNOISTMP(errno))
            *bad = in->s;

      return r;
   }

#if COVENANT
   if (in->isclientside && !reqflags->httpconnect) {
      /*
       * As long as the target of the clients request does not change, we
       * can forward it as normal.  If it changes, we need to restart
       * negotiation however.
       * Since we have no other way to know when the target changes, we have
       * to parse all data from the the http client before we can forward it,
       * as if the request is to a different server, it should not be
       * forwarded to the current target.
       */
      const char *http_eof = "\r\n\r\n";
      sockd_client_t client;
      char *p, emsg[512];

      buf[*bufused + r] = NUL;
      p = strstr(buf, http_eof);

      slog(LOG_DEBUG, "%s: read %ld bytes now, %lu bytes in total.  "
                      "%s HTTP request eof",
                      function, (long)r, (unsigned long)*bufused + r,
                      p == NULL ? "Not yet at" : "Now have");

      if (p == NULL)
         ;  /* no eof yet, save all read. */
      else { /* got the end of the request.  How far out in the buffer is it? */
          r        = (p + strlen(http_eof)) - buf;
          *bufused = 0;
      }

      flag &= ~MSG_PEEK;

      /* re-read the data peeked at. */
      w = socks_recvfrom(in->s,
                         &buf[*bufused],
                         r,
                         flag & ~MSG_OOB,
                         NULL,
                         NULL,
                         &in->auth,
                         NULL,
                         NULL);
      SASSERTX(r == w);

      if (p == NULL)
         return 0; /* no eof.  Return. */

      /*
       * got the request.  Parse it and see if the target is still
       * the same.
       */
       client.request.auth = &client.auth;
       if (parse_httprequest(&client.request, buf, emsg, sizeof(emsg)) != 0) {
         char visbuf[2048];

         swarnx("%s: failed to parse http request \"%s\" from %s: %s",
                function,
                socket2string(in->s, NULL, 0),
                str2vis(buf, r, visbuf, sizeof(visbuf)),
                emsg);
      }

      if (!sockshostareeq(&out->host, &client.request.host)) {
         char old[MAXSOCKSHOSTSTRING], new[MAXSOCKSHOSTSTRING];

         slog(LOG_DEBUG,
              "%s: client at %s changed target from %s to %s.  "
              "Need to renegotiate before continuing",
              function,
              socket2string(in->s, NULL, 0),
              sockshost2string(&out->host, old, sizeof(old)),
              sockshost2string(&client.request.host, new, sizeof(new)));

         memcpy(client.clientdata, buf, *bufused + r);
         client.clientdatalen = *bufused + r;
         client.s             = in->s;
         gettimeofday(&client.accepted, NULL);

#warning "need to fix handling of race-condition between sending client/ack."

         send_client(sockscf.state.mother.s, &client, buf, *bufused);

         *bad = in->s;
         return 0;
      }
      else
         slog(LOG_DEBUG, "%s: no problem, target in the new request is the "
                         "same as before (%s)",
                         function,
                         sockshost2string(&client.request.host, NULL, 0));
   }
#endif /* COVENANT */

   in->read.bytes += r;

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: read %ld", function, (long)r);

   if (flag & MSG_OOB)
      in->flags |= MSG_OOB;   /* read oob data.            */
   else
      in->flags &= ~MSG_OOB;  /* did not read oob data.    */

   /*
    * ... and send the data read to out.
    */

   if ((w = socks_sendto(out->s, buf, (size_t)r, flag, NULL, 0, &out->auth))
   > 0)
      out->written.bytes += w;

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: wrote %ld", function, (long)w);

   if (w != r) {
      if (w == -1)
         *bad = out->s;
      else {
          /*
           * Should never read more than we can write/buffer.
           */
         swarn("%s: wrote %ld/%ld", function, (long)w, (long)r);
         SASSERT(0);
         *bad  = out->s;
      }
   }

   /*
    * we want to select for read again on socket we sent data out on,
    * regardless of whether we have received a FIN from it, to get
    * write errors.
    *
    * Unfortunately, there's no way to make select() not keep
    * returning ready-for-read once the client has sent the FIN,
    * and we do not want to busy-loop around this.  What we would want,
    * is to only select for error on the socket after we receive
    * a FIN.
    * Best we can do is to let io_fillset() skip sockets that
    * have state.fin set, and reset state.fin if we send data on on the
    * socket, hoping to catch any pending errors on second go round.
    * This means some sessions can occupy space for a long time, until
    * tcp keep-alive check kicks in.
    */
   out->state.fin = 0;

   return w;
}

#if HAVE_UDP_SUPPORT

static iostatus_t
doio_udp(io, rset, wset, bad)
   sockd_io_t *io;
   fd_set *rset, *wset;
   int *bad;
{
   const char *function = "doio_udp()";
   iostatus_t iostatus = IO_EAGAIN;
   rule_t *packetrule;
   size_t bwused;

   /*
    * In the socks case the client-side of udp i/o is always fixed.
    * In barefoot the client-side can/will vary for each packet,
    * as one socket can receive packets from multiple clients.
    *
    * Also note that we are less strict about bandwidth in the udp
    * case since we can't truncate packets.  Therefore we don't limit
    * the amount of i/o we do in one go for the udp-case; it has to be
    * whole packets.
    * (Now that we have the iobuffer mechanism, we could in theory check
    * if we have enough bandwidth allocated to send the packet, and
    * if not, buffer it for later, but don't bother for now.)
    *
    * In both Barefoot and Dante, we need to do both a rulespermit()
    * per packet, but we also need to save the original rule that
    * allowed the (in Barefoot's case, "virtual") udp session.
    *
    * In Dante, the "original" rule is the socks-rule that matched the
    * control-connection, while in Barefoot it is the client-rule that
    * was used to generate the corresponding socks-rule.
    *
    * The original rule is the rule we use for any resource limitations,
    * which implies that in Dante's case, resource limits are set
    * at the time the udp session is established, while in Barefoot
    * they are set when we add a new udp client.
    *
    * E.g., the following will work correctly since only one of the
    * rules below can be assigned to any udp client in Barefoot and the
    * assignment is fixed (until SIGHUP at least):
    *
    * client pass { from: 10.1/16 to: 10.1.1.1/32 port = echo
    *               bounce to: 10.10.10.1 port = echo
    *               maxsessions: 10 }
    *
    * client pass { from: 10.2/16 to: 10.1.1.1/32 port = echo
    *               bounce to: 10.10.10.2 port = echo
    *               maxsessions: 1 }
    *
    * Correspondingly, in Dante, the below will not work as the
    * socks udp client can change it's destination at any time.
    *
    * pass { from: 10/8 to: 10.1.1.1/32 port = echo
    *        maxsessions: 10 }
    *
    * pass { from: 10/8 to: 10.1.1.2/32 port = echo
    *        maxsessions: 1 }
    *
    * E.g., assume that the client first sends packets matching rule
    * #1, having a maxsessions value of 10.  It then sends a packet
    * matching rule #2, and then a packet matching rule #1 again.
    * Do we then allocate two sessions to this client, one from rule #1
    * and one from rule #2?  Or do we move the client from the session
    * belonging to rule #1 when it sends a packet matching rule #2?  And
    * then move it back again from rule #2 to rule #1?
    * Don't see any good way to handle this, so instead we do it simple
    * and lock the resource limits when the udp session is established,
    * which will be in the request child if the client sent it's address
    * then, or when we get the first packet in the i/o child if not.
    * XXX latter case not yet handled.
    */

   SASSERTX(io->state.protocol == SOCKS_UDP);

#if SOCKS_SERVER
   SASSERTX(io->cmd.udp.fwdrule   != NULL);
   SASSERTX(io->cmd.udp.replyrule != NULL);
#endif

   /*
    * UDP to relay from client to destination?
    */
   if (FD_ISSET(io->src.s, rset) && FD_ISSET(io->dst.s, wset)) {
      /*
       * Default to packetrule being the rule matched for this udp session,
       * unless we've progressed far enough to have a saved rule to use.
       */

#if SOCKS_SERVER
      if (!io->src.state.use_saved_rule)
         *io->cmd.udp.fwdrule = io->rule; /* default, until rulespermit(). */

      packetrule = io->cmd.udp.fwdrule;

#else /* BAREFTOOTD */
      packetrule = &io->rule;
#endif /* BAREFOOTD */

      bwused   = 0;
      iostatus = io_udp_client2target(&io->control,
                                      &io->src,
                                      &io->dst,
                                      &io->clientauth,
                                      &io->state,
                                      bad,
                                      packetrule,
                                      &bwused);

#if BAREFOOTD
      if (io->dst.s == -1) /* needs to point at something. */
         SYNC_UDP(io, &io->dst.dstv[DUMMY_INDEX]);
#endif /* BAREFOOTD */

      if (IOSTATUS_FATALERROR(iostatus))
         return iostatus;

      if (iostatus == IO_NOERROR) {
         gettimeofday(&io->lastio, NULL);
         io_update(&io->lastio,
                   bwused,
#if HAVE_SOCKS_RULES
                   packetrule,
#else /* !HAVE_SOCKS_RULES */
                   packetrule->crule,
#endif /* !HAVE_SOCKS_RULES */
                   sockscf.shmemfd);
      }
   }

   /*
    * Datagram reply from remote present?
    */
   if (FD_ISSET(io->dst.s, rset) && FD_ISSET(io->src.s, wset)) {
      /*
       * - io->dst is src of packet, and can vary for each packet unless
       *   the socket is connected.
       *
       * - io->src is dst of packet (socks client).
       */
      connectionstate_t replystate;
#if BAREFOOTD
      struct udpclient *udpclient = clientofsocket(io->dst.s,
                                                   io->dst.dstc,
                                                   io->dst.dstv);
      SASSERTX(udpclient != NULL);

      if (udpclient->use_saved_replyrule)
         packetrule = &udpclient->replyrule; /* default, until rulespermit(). */
      else
         packetrule = &io->rule;

      SYNC_UDPOUT(udpclient, &io->dst);

      io->src.raddr = udpclient->client;
      sockaddr2sockshost(TOSA(&io->src.raddr), &io->src.host);

#else /* SOCKS_SERVER */
      SASSERTX(io->cmd.udp.fwdrule   != NULL);
      SASSERTX(io->cmd.udp.replyrule != NULL);

      if (!io->dst.state.use_saved_rule)
         *io->cmd.udp.replyrule = io->rule; /* default, until rulespermit(). */

      packetrule = io->cmd.udp.replyrule;
#endif /* SOCKS_SERVER */

      replystate         = io->state;
      replystate.command = SOCKS_UDPREPLY;

      bwused   = 0;
      iostatus = io_udp_target2client(&io->control,
                                      &io->src,
                                      &io->dst,
                                      &io->clientauth,
                                      &replystate,
                                      bad,
                                      packetrule,
                                      &bwused);

      if (IOSTATUS_FATALERROR(iostatus)) {
#if BAREFOOTD
         if (io->dst.s == -1) /* needs to point at something. */
            SYNC_UDP(io, &io->dst.dstv[DUMMY_INDEX]);
#endif /* BAREFOOTD */
         return iostatus;
      }

      if (iostatus == IO_NOERROR) {
         gettimeofday(&io->lastio, NULL);
#if BAREFOOTD
         udpclient->lastio = io->lastio;
#endif /* BAREFOOTD */

         io_update(&io->lastio,
                   bwused,
#if HAVE_SOCKS_RULES
                   packetrule,
#else /* !HAVE_SOCKS_RULES */
                   packetrule->crule,
#endif /* !HAVE_SOCKS_RULES */
                   sockscf.shmemfd);
      }
   }

   return iostatus;
}

static iostatus_t
io_udp_client2target(control, client, target, clientauth, state, badfd,
                     packetrule, bwused)
   sockd_io_direction_t *control, *client, *target;
   const authmethod_t *clientauth;
   connectionstate_t *state;
   int *badfd;
   rule_t *packetrule;
   size_t *bwused;
{
   const char *function = "io_udp_client2target()";
   /* static so that it gets allocated on the heap rather than the stack. */
   static char buf[SOCKD_BUFSIZE + sizeof(udpheader_t)], *payload;
   struct timeval ts_recv, ts_read, latency;
   sockshost_t host;
   udpheader_t header;
   iostatus_t iostatus = IO_NOERROR;
   iologaddr_t src, dst;
#if BAREFOOTD
   struct udpclient *udpclient;
#endif /* BAREFOOTD */
   struct sockaddr_storage from;
   socklen_t len;
   ssize_t w, r;
   size_t payloadlen;
   char hosta[MAXSOCKSHOSTSTRING], hostb[MAXSOCKSHOSTSTRING], emsg[1024];
   int recvflags, sametarget, doconnect = 0, permit = 0;

   slog(LOG_DEBUG, "%s: sockets: %d->%d", function, client->s, target->s);

#if BAREFOOTD
   SASSERTX(target->s == target->dstv[DUMMY_INDEX].s);

   /*
    * Don't know what the target socket will be until we've read the packet
    * and figured out what udpclient it belongs to, if not from a new client.
    * Set it to -1 until then to indicate that errors occurring before we've
    * figured things out don't belong to any particular udpclient/target.
    */
   target->s = -1;
   udpclient = NULL;
#endif /* BAREFOOTD */

   *emsg = NUL;

   init_iologaddr(&src,
                  SOCKADDR_OBJECT,
                  &client->laddr,
                  SOCKADDR_OBJECT,
                  &client->raddr,
                  &client->auth,
                  NULL,
                  0);

   init_iologaddr(&dst,
                  SOCKADDR_OBJECT,
                  &target->laddr,
                  SOCKADDR_OBJECT,
                  sockshost2sockaddr(&target->host, NULL),
                  &target->auth,
                  NULL,
                  0);

   len = sizeof(from);
   if ((r = socks_recvfrom(client->s,
                           buf,
                           sizeof(buf),
                           0,
                           TOSA(&from),
                           &len,
                           &client->auth,
                           &recvflags,
                           &ts_recv)) == -1) {
      if (errno == ECONNREFUSED) {
         /*
          * error is from a previous packet sent by us out on this socket,
          * i.e., from target to client.
          * Note that Linux apparently can return this error even if the
          * socket is not connected.
          */

#if SOCKS_SERVER
         /*
          * Don't treat this as fatal; more packets could come
          * and they may be accepted by the client.  As long
          * as we still have the control connection, assume
          * the client is alive.  When we no longer have the
          * control connection, we delete this io.
          */
#else /* BAREFOOTD */
         /*
          * Should assume the target has closed and we should end the
          * session for now.
          */
#endif /* BAREFOOTD */

#if BAREFOOTD
         if (rawsocket == -1) {
            /*
             * Barefoot can have many udp clients and we can't know here
             * which one this error is for.  If we have a raw socket, it
             * should be picked up via the raw socket with more detailed
             * information and logged there.  Since we don't have a
             * raw socket however, do log something at least.
             */
            src.peer_isset = 0;
#endif /* BAREFOOTD */

         iolog(packetrule,
               state,
               OPERATION_ERROR_PACKET,
               &dst,
               &src,
               NULL,
               NULL,
#if BAREFOOTD
               "need raw socket access to provide more detailed information",
#else /* SOCKS_SERVER */
               NULL,
#endif /* SOCKS_SERVER */
               0);
#if BAREFOOTD
         }

         /*
          * no sense in returning a permanent error for this as we
          * have no idea which client it relates to here; will have
          * to wait til the client's session times out the regular way.
          */
#endif /* BAREFOOTD */

         return IO_TMPERROR;
      }
      else if (ERRNOISTMP(errno))
         return IO_EAGAIN;
      else if (recvflags & MSG_TRUNC) {
         swarn("%s: packet from %s was truncated.  This indicates our UDP "
               "socket receive buffer is too small to handle packets from "
               "this client",
               function, sockaddr2string(TOSA(&from), NULL, 0));

         return IO_TMPERROR;
      }
      else {
         swarn("%s: unknown error on client-side socket %d.  Assuming fatal",
               function, client->s);

         *badfd = client->s;
         return IO_ERROR;
      }
   }

   gettimeofday(&ts_read, NULL);
   timersub(&ts_read, &ts_recv, &latency);
   io_addts(ELEMENTS(iostats.read.latencyv),
            iostats.read.latencyv,
            &iostats.read.latencyc,
            &latency);

   /*
    * Ok, read a packet.  Now figure out if and where it should be forwarded.
    */

#if SOCKS_SERVER
   client->read.bytes         += r;
   client->read.packets       += 1;
#endif /* SOCKS_SERVER */

   slog(LOG_DEBUG, "%s: udp packet from %s, length = %ld",
        function, sockaddr2string(TOSA(&from), NULL, 0), (long)r);

#if SOCKS_SERVER
   if (!client->state.connected) {
      /*
       * Have not yet connected to the client, so need to check whether
       * the packet is really from our expected client.  After the connect,
       * the kernel takes care of this for us.
       *
       * XXX or, what happens if somebody else also sends packets that ends
       * up in client the socket buffer before we connect to the real client?
       * Do we get those packet too from recvfrom() even after we connect to
       * a different address?
       */
      int blocked;

      if (!fromaddr_as_expected(client->s,
                                TOSA(&client->raddr),
                                TOSA(&from),
                                emsg,
                                sizeof(emsg)))
         blocked = 1;
      else {
         blocked = 0;

         /*
          * More efficient to stay connected to the socks client if possible.
          * Not applicable to Barefoot because the client-socket is shared
          * amongst many clients.
          */
         if (connect(client->s, TOSA(&from), sockaddr2salen(TOSA(&from))) != 0){
            snprintf(emsg, sizeof(emsg),
                     "strange ... could not connect(2) back to thew new udp "
                     "client at %s: %s",
                     sockaddr2string(TOSA(&from), NULL, 0), strerror(errno));

            swarn("%s: %s", function, emsg);

            *badfd = client->s;
            iostatus = IO_ERROR;
         }
         else
            client->state.connected = 1;
      }

      SASSERTX(!(iostatus != IO_NOERROR && blocked));
      if (iostatus != IO_NOERROR || blocked) {
         iolog(packetrule,
               state,
               iostatus != IO_NOERROR ?
                  OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
               &src,
               &dst,
               NULL,
               NULL,
               emsg,
               0);

         return IO_TMPERROR;
      }

      SASSERTX(client->state.connected);
   }
   /* else: connected, so kernel should make sure address is as expected. */

#else /* BAREFOOTD */

   client->raddr = from;
   sockaddr2sockshost(TOSA(&client->raddr), &client->host);
   udpclient = clientofclientaddr(TOSA(&from), target->dstc, target->dstv);

   slog(LOG_DEBUG, "%s: packet from %s, %s client",
                   function,
                   sockaddr2string(TOSA(&from), NULL, 0),
                   udpclient == NULL ? "a new" : "an existing");

   if (udpclient != NULL) {
      SYNC_UDPOUT(udpclient, target);
      sockaddr2sockshost(TOSA(&udpclient->laddr), &dst.local);
   }
#endif /* BAREFOOTD */

   sockaddr2sockshost(TOSA(&client->raddr), &client->host);
   src.peer = client->host;

   if (getudptarget(buf,
                    (size_t)r,
                    TOSA(&from),
#if BAREFOOTD
                    client->s,
                    state,
                    target->dstc,
                    target->dstv,
                    TOSA(&client->laddr),
                    packetrule,
#endif /* BAREFOOTD */
                    &header,
                    emsg,
                    sizeof(emsg)) == NULL) {
       slog(LOG_DEBUG,
            "%s: getudptarget() failed on packet from %s, received on %s: %s",
            function,
            sockaddr2string(TOSA(&from), hosta, sizeof(hosta)),
            sockaddr2string(TOSA(&client->laddr), hostb, sizeof(hostb)),
            emsg);

       iostatus = IO_TMPERROR;
   }

   if (iostatus == IO_NOERROR)  {
#if SOCKS_SERVER

      payload    = &buf[PACKETSIZE_UDP(&header)];
      payloadlen = r - PACKETSIZE_UDP(&header);

#else /* BAREFOOTD */

      payload    = buf;
      payloadlen = r;

#endif /* BAREFOOTD */
   }

#if BAREFOOTD
   SASSERTX(packetrule->crule == NULL);
#endif /* BAREFOOTD */

   if (iostatus == IO_NOERROR && packetrule->verdict == VERDICT_PASS) {
      sockshost2sockaddr(&header.host, TOSA(&target->raddr));
      dst.peer = header.host;

      if (!ADDRISBOUND(TOIN(&target->raddr))) {
         r = snprintf(emsg, sizeof(emsg),
                      "can not resolve destination address %s for client %s",
                      sockshost2string(&header.host, NULL, 0),
                      sockaddr2string(TOSA(&from), NULL, 0));
         iostatus = IO_TMPERROR;
      }
   }

   if (iostatus != IO_NOERROR || packetrule->verdict == VERDICT_BLOCK) {
      sockshost_t host_laddr;

      if (header.host.atype != SOCKS_ADDR_NOTSET)
         dst.peer = header.host;
      else
         dst.peer_isset = 0;

      iolog(packetrule,
            state,

#if BAREFOOTD
            iostatus != IO_NOERROR ?
               OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
#else /* SOCKS_SERVER */
            iostatus != IO_NOERROR ? OPERATION_ERROR : OPERATION_BLOCK,
#endif /* SOCKS_SERVER */

            &src,
            &dst,
            NULL,
            NULL,
            emsg,
            0);

         send_icmperror(rawsocket,
                        sockaddr2sockshost(TOSA(&from), &host),
                        sockaddr2sockshost(TOSA(&client->laddr), &host_laddr),
                        header.host.atype == SOCKS_ADDR_NOTSET ?
                           NULL : &header.host,
                        -1);

      return IO_TMPERROR;
   }

   slog(LOG_DEBUG,
        "%s: udp packet #%"PRIu64" from client %s received on %s for dst %s",
        function,
#if SOCKS_SERVER
        client->read.packets + 1,
#else /* !SOCKS_SERVER */
        udpclient == NULL ? 1 : udpclient->src_read.packets + 1,
#endif /* !SOCKS_SERVER */
        sockaddr2string(TOSA(&from), NULL, 0),
        sockaddr2string(TOSA(&client->laddr), hosta, sizeof(hosta)),
        sockshost2string(&header.host, hostb, sizeof(hostb)));

   /*
    * Can we reuse the saved rule, if any, from the last time we received
    * a packet from this client, or must we do a rule-lookup again?
    */
#if BAREFOOTD
   if (udpclient != NULL && udpclient->use_saved_rule)
#else /* SOCKS_SERVER */
   if (client->state.use_saved_rule)
#endif /* SOCKS_SERVER */
   {
      /*
       * Yes.  That means if the target of this packet is the same as last time
       * (always the case in Barefoot), we can save ourselves a new rule lookup.
       */
#if BAREFOOTD
      *packetrule       = udpclient->rule;
      packetrule->crule = &udpclient->crule;
#endif /* BAREFOOTD */

      sametarget = sockshostareeq(&header.host, &target->host);

      slog(LOG_DEBUG,
           "%s: use_saved_rule set.  UDP packet #%"PRIu64" from %s.  "
           "Destination %s.  Already set up with "
#if BAREFOOTD
           "client-rule #%lu (%s) and "
#endif /* BAREFOOTD */
           "socks-rule #%lu (%s) for previous destination %s (%ssame as now)",
           function,
#if SOCKS_SERVER
           client->read.packets,
#else /* BAREFOOTD */
           udpclient->src_read.packets,
#endif /* BAREFOOT */
           sockaddr2string(TOSA(&from), NULL, 0),
           sockshost2string(&header.host, NULL, 0),
#if BAREFOOTD
           (unsigned long)packetrule->crule->number,
           verdict2string(packetrule->crule->verdict),
#endif /* BAREFOOTD */
           (unsigned long)packetrule->number,
           verdict2string(packetrule->verdict),
           sockshost2string(&target->host, hosta, sizeof(hosta)),
           sametarget ? "" : "not ");

#if BAREFOOTD /* can only change on sighup, which should clear use_saved_rule */

      SASSERTX(sametarget);
      permit = (packetrule->verdict == VERDICT_PASS);

#else /* SOCKS_SERVER; target can change on each packet. */
      if (sametarget)
         permit = (packetrule->verdict == VERDICT_PASS);
      else {
         /*
          * use a tmprule.  If the new destination is blocked, we might
          * as well continue to use the previously saved rule for future
          * packets to the previous destination.
          */
         rule_t tmprule;
         char clientstr[MAXSOCKADDRSTRING],
              dstbefore[MAXSOCKSHOSTSTRING],
              dstnow[MAXSOCKSHOSTSTRING];

         SASSERTX(iostatus == IO_NOERROR);

         dst.peer = header.host;

         permit = rulespermit(control->s,
                              TOSA(&control->raddr),
                              TOSA(&control->laddr),
                              clientauth,
                              &client->auth,
                              &tmprule,
                              state,
                              &client->host,
                              &header.host,
                              emsg,
                              sizeof(emsg));

         slog(LOG_DEBUG, "%s: destination host for packet from %s changed, "
                         "from %s to %s.  %s",
                         function,
                         sockaddr2string(TOSA(&control->raddr),
                                         clientstr,
                                         sizeof(clientstr)),
                         sockshost2string(&target->host,
                                          dstbefore,
                                          sizeof(dstbefore)),
                         sockshost2string(&header.host,
                                          dstnow,
                                          sizeof(dstnow)),
                         permit ?
                            ""
                          : "Packets to this address are not permitted however");

         if (!permit) {
            iolog(&tmprule,
                  state,
                  OPERATION_BLOCK,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  emsg,
                  0);

            send_icmperror(rawsocket,
                           &client->host,
                           sockaddr2sockshost(TOSA(&client->laddr), &host),
                           &header.host,
                           -1);

            return IO_BLOCK;
         }

         /*
          * Ok, destination changed and the new destination is permitted.
          * Unconnect the socket if it's connected and keep it unconnected,
          * so we can receive replies from the previous destination too.
          */

         if (target->state.connected)
            socks_unconnect(target->s);

         target->state.connected = 0;

         *packetrule = tmprule;

         /* possibly the socket options differ in this rule. */
         setconfsockoptions(target->s,
                            client->s,
                            SOCKS_UDP,
                            0,
                            packetrule->socketoptionc,
                            packetrule->socketoptionv,
                            SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                            0);
      }
#endif /* SOCKS_SERVER */

      if (permit) {
         if (redirect(target->s,
                      TOSA(&target->laddr),
                      &header.host,
                      state->command,
#if SOCKS_SERVER
                      &packetrule->rdr_from,
                      &packetrule->rdr_to
#else /* BAREFOOTD */
                      &packetrule->crule->rdr_from,
                      &packetrule->crule->rdr_to
#endif /* BAREFOOTD */
                      ) != 0) {

            snprintf(emsg, sizeof(emsg), "redirect failed (%s)",
                     strerror(errno));

            if (errno != 0)
               swarnx("%s: %s", function, emsg);

            iostatus = IO_TMPERROR;
         }
         else {
            sockaddr2sockshost(TOSA(&target->laddr), &dst.local);
            dst.peer  = header.host;
         }

         if (iostatus == IO_NOERROR) {
            sockshost2sockaddr(&header.host, TOSA(&target->raddr));
            dst.peer = header.host;

            if (!ADDRISBOUND(TOIN(&target->raddr))) {
               snprintf(emsg, sizeof(emsg),
                        "can not resolve destination address %s for client %s",
                        sockshost2string(&header.host, NULL, 0),
                        sockaddr2string(TOSA(&from), NULL, 0));

               iostatus = IO_TMPERROR;
            }
         }
      }
   }
   else {
      /*
       * No, must do a new rule-lookup.
       */
      permit = rulespermit(
#if SOCKS_SERVER
                           control->s,
                           TOSA(&control->raddr),
                           TOSA(&control->laddr),
#else /* BAREFOOTD */
                           client->s,
                           TOSA(&client->raddr),
                           TOSA(&client->laddr),
                           sockaddr2sockshost(TOSA(&client->laddr), &host),
#endif /* BAREFOOTD */
                           clientauth,
                           &client->auth,
                           packetrule,
                           state,
                           &client->host,
                           &header.host,
                           emsg,
                           sizeof(emsg));

#if BAREFOOTD
      SASSERTX(packetrule->crule->bw == NULL);
      SASSERTX(packetrule->crule->ss == NULL);
#endif /* BAREFOOTD */

      if (permit) {
#if BAREFOOTD
         /*
          * Need to have separate memory for rule->crule in each client.
          * Note that we need to save this upon new rule-lookup only, as
          * that's when we allocate the resources and it's those pointers
          * we need.
          */
         rule_t crule      = *packetrule->crule;
         packetrule->crule = &crule;

         SASSERTX(iostatus == IO_NOERROR);

         if (udpclient != NULL && udpclient->use_saved_replyrule)
            slog(LOG_DEBUG, "%s: unusual ... in this case the resources must "
                            "have been allocated upon receiving the reply",
                            function);
         else {
            if (io_haveresources(packetrule->crule,
                                 TOSA(&from),
                                 buf,
                                 sizeof(buf))) {
               if (udpclient == NULL) {
                  struct udpclient newclient;

                  if (initclient(TOSA(&from),
                                 &header.host,
                                 emsg,
                                 sizeof(emsg),
                                 &newclient) == NULL)
                     iostatus = IO_ERROR;
                  else if ((udpclient = addclient(&newclient,
                                                  TOSA(&client->laddr),
                                                  &target->dstc,
                                                  &target->dstcmax,
                                                  &target->dstv,
                                                  state,
                                                  packetrule)) == NULL) {
                     snprintf(emsg, sizeof(emsg),
                              "could not add udpclient %s (%s)",
                              sockaddr2string(TOSA(&from), NULL, 0),
                              strerror(errno));

                     swarnx("%s: %s", function, buf);
                     iostatus = IO_ERROR;
                  }
                  else {
                     doconnect = sockscf.udpconnectdst;
                     SYNC_UDPOUT(udpclient, target);
                     sockaddr2sockshost(TOSA(&target->laddr), &dst.local);
                  }
               }

               if (udpclient != NULL) {
                  udpclient->rule       = *packetrule;
                  udpclient->crule      = *packetrule->crule;
                  packetrule->crule     = &udpclient->crule;
                  udpclient->rule.crule = &udpclient->crule;
               }
            }
            else
               iostatus = IO_ERROR;
         }

         if (permit && iostatus == IO_NOERROR) {
            /* use redirected addresses if applicable. */
            if (redirect(target->s,
                         TOSA(&target->laddr),
                         &header.host,
                         state->command,
                         &packetrule->crule->rdr_from,
                         &packetrule->crule->rdr_to) != 0) {
               snprintf(emsg, sizeof(emsg), "redirect failed (%s)",
                        strerror(errno));
               iostatus = IO_TMPERROR;
            }
            else {
               dst.peer  = header.host;
               sockaddr2sockshost(TOSA(&target->laddr), &dst.local);

               /*
                * In Barefoot we should connect again whenever the destination
                * changes since changes can only occur on sighup and we are not
                * interested client packets from old destinations.  It therefor
                * does not matter whether this is a new client or not.
                */
               doconnect = sockscf.udpconnectdst;
            }

            setconfsockoptions(target->s,
                               client->s,
                               SOCKS_UDP,
                               0,
                               packetrule->socketoptionc,
                               packetrule->socketoptionv,
                               SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                               SOCKETOPT_PRE | SOCKETOPT_ANYTIME /*
                                                                  * XXX only if
                                                                  * new client.
                                                                  */);
         }

#else /* SOCKS_SERVER */
         /*
          * Resources are allocated based on the control-connection.  Since
          * that can never change, no need to reallocate even though the
          * packetrule can change on a packet-per-packet basis.
          */

         /*
          * Connect only once, to one destination.
          */
         doconnect = (sockscf.udpconnectdst && target->written.packets == 0);
#endif /* SOCKS_SERVER */
      }

      if (iostatus != IO_NOERROR || !permit) {
         iolog(packetrule,
               state,
#if BAREFOOTD
               iostatus != IO_NOERROR ?
                  OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
#else /* SOCKS_SERVER */
               iostatus != IO_NOERROR ? OPERATION_ERROR : OPERATION_BLOCK,
#endif /* SOCKS_SERVER */
               &src,
               &dst,
               NULL,
               NULL,
               emsg,
               0);

         send_icmperror(rawsocket,
                        &client->host,
                        sockaddr2sockshost(TOSA(&client->laddr), &host),
                        &header.host,
                        -1);

#if BAREFOOTD
         if (udpclient == NULL) {
            target->s = -1;

            if (iostatus == IO_NOERROR)
               iostatus = IO_ERROR;
         }
#endif /* BAREFOOTD */

         if (iostatus != IO_NOERROR)
            return iostatus;
         else
            return IO_BLOCK;
      }

#if BAREFOOTD
      SASSERTX(udpclient != NULL);
#endif /* BAREFOOTD */

#if SOCKS_SERVER
      sametarget = sockshostareeq(&header.host, &target->host);

      slog(LOG_DEBUG,
           "%s: socket: %d, previous target: %s, current: %s (%s before)",
           function,
           target->s,
           sockshost2string(&target->host, hosta, sizeof(hosta)),
           sockshost2string(&header.host, hostb, sizeof(hostb)),
           sametarget ? "same as" : "different from");

#if SOCKS_SERVER
      if (target->written.packets > 0)
#else /* BAREFOOTD */
      if (udpclient->dst_written.packets > 0)
#endif /* BAREFOOTD */

         slog(LOG_DEBUG, "%s: not first packet and use_saved_rule not set "
                         "... should only happen after SIGHUP",
                         function);

     if (target->state.connected && !sametarget) {
        /*
         * need to unconnect the socket so we can continue to receive
         * packets from the old destination.  Not applicable to Barefoot,
         * where we do not want to receive packets from the old destination.
         */
         socks_unconnect(target->s);
         target->state.connected = 0;
      }
#endif /* SOCKS_SERVER */
   }

   target->host = header.host;
   dst.peer     = target->host;
   sockaddr2sockshost(TOSA(&target->laddr), &dst.local);

   if (iostatus != IO_NOERROR || !permit)
      iolog(packetrule,
            state,
#if BAREFOOTD
            iostatus != IO_NOERROR ?
               OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
#else /* SOCKS_SERVER */
            iostatus != IO_NOERROR ? OPERATION_ERROR : OPERATION_BLOCK,
#endif /* SOCKS_SERVER */
            &src,
            &dst,
            NULL,
            NULL,
            emsg,
            0);

#if SOCKS_SERVER
   client->state.use_saved_rule = 1;

#else /* BAREFOOTD */
   udpclient->use_saved_rule   = 1;
   udpclient->host             = header.host;

   udpclient->src_read.bytes   += r;
   udpclient->src_read.packets += 1;

#endif /* BAREFOOTD */

   if (permit && iostatus == IO_NOERROR) {
      /*
       * Should we connect to the destination also?
       * If the client will only be sending udp packets to one address, it
       * is more efficient to connect the socket to that address.
       * This is always the case client barefootd, and may also be the
       * usual case with socks.
       * If we do that client Dante we must however be sure to unconnect the
       * socket before sending target on it again if the client wants to send
       * to a new address, and from that point on, leave the socket
       * unconnected, so that possible future packets from the address we
       * first sent/connected to will also be received.
       */
      if (doconnect) {
         char emsg[256];

         slog(LOG_DEBUG, "%s: connecting socket %d to %s, for client %s",
              function,
              target->s,
              sockshost2string(&header.host, hosta, sizeof(hosta)),
              sockshost2string(&client->host, hostb, sizeof(hostb)));

#if SOCKS_SERVER
         /*
          * XXX now that we have the target-address we should call getoutaddr()
          * to bind the correct address.  Should fix td/server_multaddr_ext.
          */
#endif

         if (socks_connecthost(target->s,
                               &header.host,
                               NULL,
                               -1,
                               emsg,
                               sizeof(emsg)) == -1) {
#if BAREFOOTD
            swarn("%s: could not connect to static target address %s given in "
                  "rule #%lu.  "
                  "This might be configuration error, either in the system "
                  "routes or in our %s file",
                  function,
                  sockshost2string(&header.host, NULL, 0),
                  (unsigned long)packetrule->number,
                  sockscf.option.configfile);
#endif /* BAREFOOTD */

            iolog(packetrule,
                  state,
                  OPERATION_ERROR_PACKET,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  emsg,
                  0);

#if BAREFOOTD
            iostatus = IO_ERROR;
            *badfd   = client->s;
#else
            iostatus = IO_TMPERROR;
#endif /* BAREFOOTD */

            return iostatus;
         }

#if BAREFOOTD
         udpclient->connected = 1;
#endif /* BAREFOOTD */

         target->state.connected = 1;
      }

      if ((w = socks_sendto(target->s,
                            payload,
                            payloadlen,
                            0,
                            target->state.connected ? NULL : TOSA(&target->raddr),
                            target->state.connected ? 0 : sizeof(target->raddr),
                            &target->auth))
      == (ssize_t)payloadlen) {
         if (io_calculatedlatency(&ts_recv,
                                  TOSA(&client->raddr),
                                  TOSA(&target->raddr),
                                  &latency))
            io_addts(ELEMENTS(iostats.io.latencyv),
                     iostats.io.latencyv,
                     &iostats.io.latencyc,
                     &latency);
      }
      else {
         snprintf(emsg, sizeof(emsg), "sendto() failed: %s", strerror(errno));
         slog(LOG_DEBUG, "%s: %s", function, emsg);

         if (ERRNOISTMP(errno))
            iostatus = IO_TMPERROR;
         else
            iostatus = IO_ERROR;
      }
   }
   else
      w = -1;

   if (iostatus != IO_NOERROR || !permit) {
#if BAREFOOTD
      if (iostatus == IO_NOERROR)
         iostatus = IO_ERROR;
#endif /* BAREFOOTD */

      iolog(packetrule,
            state,
#if BAREFOOTD
            iostatus != IO_NOERROR ?
               OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
#else /* SOCKS_SERVER */
            iostatus != IO_NOERROR ? OPERATION_ERROR : OPERATION_BLOCK,
#endif /* SOCKS_SERVER */
            &src,
            &dst,
            NULL,
            NULL,
            emsg,
            0);

      send_icmperror(rawsocket,
                     &client->host,
                     sockaddr2sockshost(TOSA(&client->laddr), &host),
                     &target->host,
                     -1);

      if (iostatus != IO_NOERROR)
         return iostatus;
      else
         return IO_BLOCK;
   }
   
   SASSERTX(w == (ssize_t)payloadlen);

   iolog(packetrule,
         state,
         OPERATION_IO,
         &src,
         &dst,
         NULL,
         NULL,
         payload,
         payloadlen);

   *bwused = w;

#if SOCKS_SERVER
   target->written.bytes         += w;
   target->written.packets       += 1;

#else /* !SOCKS_SERVER */
   udpclient->dst_written.bytes   += w;
   udpclient->dst_written.packets += 1;
   gettimeofday(&udpclient->lastio, NULL);
#endif /* !SOCKS_SERVER */

   if (bwused)
      return IO_NOERROR;
   else
      return IO_EAGAIN;
}

static iostatus_t
io_udp_target2client(control, client, target, clientauth, state, bad,
                     packetrule, bwused)
   sockd_io_direction_t *control, *client, *target;
   const authmethod_t *clientauth;
   connectionstate_t *state;
   int *bad;
   rule_t *packetrule;
   size_t *bwused;
{
   const char *function = "io_udp_target2client()";
   /* static so that it gets allocated on the heap rather than the stack. */
   static char buf[SOCKD_BUFSIZE + sizeof(udpheader_t)], *payload;
   struct timeval ts_recv, ts_read, latency;
   sockshost_t host;
   iologaddr_t src, dst;
   iostatus_t iostatus = IO_NOERROR;
#if BAREFOOTD
   struct udpclient *udpclient;
#endif /* BAREFOOTD */
   struct sockaddr_storage from;
   socklen_t len;
   ssize_t w, r;
   size_t payloadlen;
   char hosta[MAXSOCKSHOSTSTRING], hostb[MAXSOCKSHOSTSTRING], emsg[1024];
   int recvflags, samesrc, permit = 0;

   slog(LOG_DEBUG, "%s: sockets: %d->%d", function, target->s, client->s);

#if BAREFOOTD
   SASSERTX(target->s != target->dstv[DUMMY_INDEX].s);
#endif /* BAREFOOTD */

   *emsg = NUL;

   init_iologaddr(&dst,
                  SOCKADDR_OBJECT,
                  &client->laddr,
                  SOCKADDR_OBJECT,
                  sockshost2sockaddr(&client->host, NULL),
                  &client->auth,
                  NULL,
                  0);

   init_iologaddr(&src,
                  SOCKADDR_OBJECT,
                  &target->laddr,
                  SOCKADDR_OBJECT,
                  sockshost2sockaddr(&target->host, NULL),
                  &target->auth,
                  NULL,
                  0);

   len = sizeof(from);
   if ((r = socks_recvfrom(target->s,
                           buf,
                           sizeof(buf),
                           0,
                           TOSA(&from),
                           &len,
                           &target->auth,
                           &recvflags,
                           &ts_recv)) == -1) {
      if (ERRNOISTMP(errno) || errno == ECONNREFUSED) {
         if (errno == ECONNREFUSED) {
            /*
             * error is from the target of an earlier packet from client,
             * sent by us out on this socket.
             * Note that Linux apparently can return this error even if
             * the socket is not connected.
             * Don't treat it as fatal, more packets could come, and they
             * may be accepted by the target.
             */
#if BAREFOOTD
            if (rawsocket == -1) {
               /*
                * Error is from target.  Can not be sure here, but assume
                * the target is the same as before (i.e., no sighup has
                * changed it).  Otherwise, a better/more detailed logmessage
                * should be provided by the code handling the raw socket.
                */
#endif /* BAREFOOTD */

            iolog(packetrule,
                  state,
                  OPERATION_ERROR_PACKET,
                  &src,
                  &dst,
                  NULL,
                  NULL,
                  NULL,
                  0);
#if BAREFOOTD
            }
#endif /* BAREFOOTD */

            send_icmperror(rawsocket,
                           &target->host,
                           sockaddr2sockshost(TOSA(&target->laddr), &host),
                           &client->host,
                           -1);

#if SOCKS_SERVER
            /* tmp error; using control connection do detect fatal errors. */
            return IO_TMPERROR;

#else /* BAREFOOTD */

            return IO_ERROR;
#endif /* BAREFOOTD */

         }
         else
            return IO_EAGAIN;
      }
      else if (recvflags & MSG_TRUNC) {
         swarn("%s: packet from %s was truncated.  This indicates our UDP "
               "socket receive buffer is too small to handle packets from "
               "this client",
               function, sockaddr2string(TOSA(&from), NULL, 0));

         return IO_TMPERROR;
      }

      /* else: unknown error, assume fatal. */
      *bad = target->s;
      return IO_ERROR;
   }

   gettimeofday(&ts_read, NULL);
   timersub(&ts_read, &ts_recv, &latency);
   io_addts(ELEMENTS(iostats.read.latencyv),
            iostats.read.latencyv,
            &iostats.read.latencyc,
            &latency);

   /*
    * Read a packet.  Now check whether it should be forwarded.
    */

#if SOCKS_SERVER
   target->read.bytes           += r;
   target->read.packets         += 1;

#else /* !SOCKS_SERVER */

   udpclient = clientofsocket(target->s, target->dstc, target->dstv);
   SASSERTX(udpclient != NULL);

   udpclient->dst_read.bytes   += r;
   udpclient->dst_read.packets += 1;
#endif /* !SOCKS_SERVER */

   slog(LOG_DEBUG,
        "%s: udp packet #%"PRIu64" from target %s received for client %s "
        "on socket %d, length %ld",
        function,
#if SOCKS_SERVER
        target->read.packets,
#else /* !SOCKS_SERVER */
        udpclient->dst_read.packets,
#endif /* !SOCKS_SERVER */
        sockaddr2string(TOSA(&from), hosta, sizeof(hosta)),
        sockaddr2string(TOSA(&client->raddr), hostb, sizeof(hostb)),
        target->s,
        (long)r);

#if BAREFOOTD

   SASSERTX(udpclient->dst_written.packets > 0);

#else /* SOCKS_SERVER */

   if (target->written.packets == 0) {
         slog(LOG_DEBUG,
              "%s: how unusual ... the client at %s has not sent any "
              "packets yet, but already it has received a %ld byte reply.  "
              "On address %s from target %s",
              function,
              sockaddr2string(TOSA(&client->raddr), NULL, 0),
              (long)r,
              sockaddr2string(TOSA(&target->laddr), hosta, sizeof(hosta)),
              sockaddr2string(TOSA(&from), hostb, sizeof(hostb)));
   }

#endif /* SOCKS_SERVER */

   /*
    * Can we reuse the saved rule (passed us if so), if any, from the last time
    * we received a packet on this socket, or must we do a new rule-lookup?
    */
   if (target->state.use_saved_rule) {
      /*
       * Yes, previous rule lookup is valid, but only provided the packet is
       * received from the same address as previously.
       */

      if (target->state.connected) {
         slog(LOG_DEBUG, "%s: socket is connected.  Kernel should take care "
                         "of checking source address %s for us so that we can "
                         "reuse previous rule-lookup (rule #%lu, verdict: %s)",
                         function,
                         sockaddr2string(TOSA(&from), NULL, 0),
                         (unsigned long)packetrule->number,
                         verdict2string(packetrule->verdict));
         samesrc = 1;
      }
      else {
         struct sockaddr_storage clienttarget;

         sockshost2sockaddr(&target->host, TOSA(&clienttarget));
         if (!ADDRISBOUND(TOIN(&clienttarget))) {
            slog(LOG_DEBUG,
                 "%s: can not resolve target address %s for client %s.  "
                 "Checking against last ipaddress (%s) used instead",
                 function,
                 sockshost2string(&target->host, NULL, 0),
                 sockaddr2string(TOSA(&client->raddr), NULL, 0),
                 sockaddr2string(TOSA(&target->raddr), hosta, sizeof(hosta)));

            clienttarget = client->raddr;
         }

         if (! (samesrc = sockaddrareeq(TOSA(&clienttarget), TOSA(&from)))) {
            /*
             * ack, reply from a different target.
             */

            slog(LOG_DEBUG,
                 "%s: use_saved_rule set.  UDP packet #%"PRIu64" from %s.  "
                 "Destination %s.  Previously set up with "
#if BAREFOOTD
                 "client-rule #%lu (%s) and "
#endif /* BAREFOOTD */
                 "socks-rule #%lu (%s) for packets from target %s.  "
                 "Not the same as now, so have to do a new rule-lookup",
                 function,

#if SOCKS_SERVER
                 target->read.packets,
#else /* BAREFOOTD */
                 udpclient->dst_read.packets,
#endif /* BAREFOOT */

                 sockaddr2string(TOSA(&from), hosta, sizeof(hosta)),
                 sockshost2string(&client->host, NULL, 0),
#if BAREFOOTD
                 (unsigned long)packetrule->crule->number,
                 verdict2string(packetrule->crule->verdict),
#endif /* BAREFOOTD */
                 (unsigned long)packetrule->number,
                 verdict2string(packetrule->verdict),
                 sockaddr2string(TOSA(&target->raddr), hostb, sizeof(hostb)));
         }
      }
   }
   else
      samesrc = 0; /* have nothing we should compare with. */

   target->raddr = from;
   sockaddr2sockshost(TOSA(&target->raddr), &target->host);
   src.peer = target->host;

   if (samesrc) {
      permit = (packetrule->verdict == VERDICT_PASS);

#if BAREFOOTD
      SASSERTX(packetrule == &udpclient->replyrule);
#endif /* BAREFOOTD */
   }
   else {
      /*
       * Nope, can not reuse the last rule lookup.  Have to do a new.
       */
      slog(LOG_DEBUG,
           "%s: received packet from %s to %s on socket %d, "
           "use_saved_rule is %d, samesrc = %d",
           function,
           sockaddr2string(TOSA(&target->raddr), hosta, sizeof(hosta)),
           sockaddr2string(TOSA(&client->raddr), hostb, sizeof(hostb)),
           target->s,
           target->state.use_saved_rule,
           samesrc);

      if (!target->state.use_saved_rule) {
#if SOCKS_SERVER
         if (client->written.packets > 0)
#else /* BAREFOOTD */
         if (udpclient->src_written.packets > 0)
#endif /* BAREFOOTD */
         slog(LOG_DEBUG, "%s: not first packet and use_saved_rule not set "
                         "... should only happen after SIGHUP",
                         function);
      }

      SASSERTX(iostatus == IO_NOERROR);

      permit = rulespermit(
#if SOCKS_SERVER
                           control->s,
                           TOSA(&control->raddr),
                           TOSA(&control->laddr),
#else /* BAREFOOTD */
                           target->s,
                           TOSA(&target->raddr),
                           TOSA(&target->laddr),
                           sockaddr2sockshost(TOSA(&client->laddr), &host),
#endif /* BAREFOOTD */
                           clientauth,
                           &target->auth,
                           packetrule,
                           state,
                           &target->host,
                           &client->host,
                           NULL,
                           0);

      if (permit) {
#if BAREFOOTD
         SASSERTX(packetrule->crule != NULL);
         SASSERTX(packetrule->crule->bw == NULL);
         SASSERTX(packetrule->crule->ss == NULL);

         if (!udpclient->use_saved_rule) {
            /*
             * Will normally be allocated when forwarding packets from client,
             * but has not happened in this case.
             * This can happen if we receive a sighup and the first packet
             * related to this udpclient is from the target.  In that case we
             * need to reallocate the resources upon receiving the packet from
             * target instead.
             */
            slog(LOG_DEBUG, "%s: unusual ... resources not allocated yet, but "
                            "receiving a reply packet, so allocating resources "
                            "now.  A sighup perhaps?",
                            function);

            udpclient->crule = *packetrule->crule;
            if (!io_haveresources(&udpclient->crule,
                                  TOSA(&udpclient->client),
                                  buf,
                                  sizeof(buf)))
               iostatus = IO_ERROR;
            else
               setconfsockoptions(udpclient->s,
                                  client->s,
                                  SOCKS_UDP,
                                  0,
                                  udpclient->crule.socketoptionc,
                                  udpclient->crule.socketoptionv,
                                  SOCKETOPT_PRE | SOCKETOPT_ANYTIME,
                                  0);
         }

         /*
          * else: using the same client-rule for in and out, so resources must
          * have been allocated already.
          */

         packetrule->crule = &udpclient->crule;
#endif /* BAREFOOTD */

         if (iostatus == IO_NOERROR && permit) {
            /* use redirected addresses, if applicable. */
            /*
             * XXX make sure this does not change the address of s, as
             * we need to continue receiving packets on that socket.
             */
            if (redirect(client->s,
                         TOSA(&target->raddr),
                         &client->host,
                         state->command,
#if SOCKS_SERVER
                         &packetrule->rdr_from,
                         &packetrule->rdr_to
#else /* BAREFOOTD */
                         &packetrule->crule->rdr_from,
                         &packetrule->crule->rdr_to
#endif /* BAREFOOTD */
            ) != 0) {
               snprintf(emsg, sizeof(emsg), "redirect failed (%s)",
                        strerror(errno));
               iostatus = IO_TMPERROR;
            }
            else
               dst.peer = client->host;
         }
      }
   }

   if (iostatus != IO_NOERROR || !permit) {
      iolog(packetrule,
            state,
#if BAREFOOTD
            iostatus != IO_NOERROR ?
               OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
#else /* SOCKS_SERVER */
            iostatus != IO_NOERROR ? OPERATION_ERROR : OPERATION_BLOCK,
#endif /* SOCKS_SERVER */
            &src,
            &dst,
            NULL,
            NULL,
            emsg,
            0);

      send_icmperror(rawsocket,
                     &target->host,
                     sockaddr2sockshost(TOSA(&target->laddr), &host),
                     &client->host,
                     -1);

#if BAREFOOTD
      if (permit)
         iostatus = IO_ERROR;
#endif /* BAREFOOTD */

      if (iostatus != IO_NOERROR)
         return iostatus;
      else
         return IO_BLOCK;
   }

   target->state.use_saved_rule = 1;

#if BAREFOOTD

   udpclient->replyrule           = *packetrule;
   udpclient->replyrule.crule     = &udpclient->crule;
   udpclient->use_saved_replyrule = 1;

#endif /* BAREFOOTD */

   payloadlen = r;

   if (permit && iostatus == IO_NOERROR) {
#if SOCKS_SERVER
      payload = udpheader_add(&target->host, buf, &payloadlen, sizeof(buf));
      SASSERTX(payload == buf);
      SASSERTX(payloadlen > (size_t)r);

#else /* BAREFOOTD */

      payload    = buf;

#endif /* BAREFOOTD */

      if ((w = socks_sendto(client->s,
                            payload,
                            payloadlen,
                            0,
                            client->state.connected ?
                              NULL : TOSA(&client->raddr),
                            client->state.connected ?
                              0 : sizeof(client->raddr),
                            &client->auth))
      == (ssize_t)payloadlen) {
         if (io_calculatedlatency(&ts_recv,
                                  TOSA(&target->raddr),
                                  TOSA(&client->raddr),
                                  &latency))
            io_addts(ELEMENTS(iostats.io.latencyv),
                     iostats.io.latencyv,
                     &iostats.io.latencyc,
                     &latency);
      }
      else {
         snprintf(emsg, sizeof(emsg), "sendto() failed: %s", strerror(errno));
         slog(LOG_DEBUG, "%s: %s", function, emsg);

         if (ERRNOISTMP(errno))
            iostatus = IO_TMPERROR;
         else
            iostatus = IO_ERROR;
      }
   }
   else {
      w = 0;
      slog(LOG_DEBUG, "%s: did not forward packet, iostatus = %d, permit = %d",
           function, (int)iostatus, permit);
   }

   *bwused = w;

#if SOCKS_SERVER

   client->written.bytes          += MAX(0, w);
   client->written.packets += w   == -1 ? 0 : 1;
#else /* !SOCKS_SERVER */

   udpclient->src_written.bytes   += MAX(0, w);
   udpclient->src_written.packets += w == -1 ? 0 : 1;
#endif /* !SOCKS_SERVER */

   if (iostatus != IO_NOERROR || !permit) {
      iolog(packetrule,
            state,
#if BAREFOOTD
            iostatus != IO_NOERROR ?
               OPERATION_ERROR_PACKET : OPERATION_BLOCK_PACKET,
#else /* SOCKS_SERVER */
            iostatus != IO_NOERROR ? OPERATION_ERROR : OPERATION_BLOCK,
#endif /* SOCKS_SERVER */
            &src,
            &dst,
            NULL,
            NULL,
            emsg,
            0);

      send_icmperror(rawsocket,
                     &target->host,
                     sockaddr2sockshost(TOSA(&target->laddr), &host),
                     &client->host,
                     -1);

      if (iostatus != IO_NOERROR)
         return iostatus;
      else
         return IO_BLOCK;
   }

   SASSERTX(w == (ssize_t)payloadlen);

   iolog(packetrule,
         state,
         OPERATION_IO,
         &src,
         &dst,
         NULL,
         NULL,
         payload,
         payloadlen);

   if (bwused)
      return IO_NOERROR;
   else
      return IO_TMPERROR;
}

static void
send_icmperror(s, peer, local, dst, code)
   const int s;
   /* XXX why not sockaddr for all? */
   const sockshost_t *peer;
   const sockshost_t *local;
   const sockshost_t *dst;
   const int code;
{
   const char *function = "send_icmperror()";
   char peer_str[MAXSOCKSHOSTSTRING], local_str[MAXSOCKSHOSTSTRING],
        dst_str[MAXSOCKSHOSTSTRING];

   slog(LOG_DEBUG,
        "%s: XXX should send an icmp error with code %d to %s, concerning "
        "packet for %s received on %s, but that is not implemented yet",
        function,
        code,
        sockshost2string(peer, peer_str, sizeof(peer_str)),
        dst == NULL ?
           "0.0.0.0" : sockshost2string(dst, dst_str, sizeof(dst_str)),
        sockshost2string(local, local_str, sizeof(local_str)));
}

#endif /* HAVE_UDP_SUPPORT */

static void
proctitleupdate(void)
{

   setproctitle("iorelayer: %lu/%d",
   (unsigned long)io_allocated(NULL, NULL), SOCKD_IOMAX);
}

static sockd_io_t *
io_getset(nfds, set)
   const int nfds;
   const fd_set *set;
{
   sockd_io_t *best, *evaluating;
   size_t i;
   int s;

   for (s = 0, best = NULL; s < nfds; ++s) {
      if (!FD_ISSET(s, set))
         continue;

      /*
       * find the io 's' is part of.
       */
      for (i = 0, evaluating = NULL; i < ioc; ++i) {
         if (!iov[i].allocated)
            continue;

#if BAREFOOTD
         if (iov[i].state.protocol == SOCKS_TCP) /* udp case differs. */ {
#endif /* BAREFOOTD */

            if (s == iov[i].src.s || s == iov[i].dst.s) {
               evaluating = &iov[i];
               break;
            }

#if BAREFOOTD
         }
#endif /* BAREFOOTD */

         switch (iov[i].state.command) {
            case SOCKS_BINDREPLY:
               if (iov[i].state.extension.bind && s == iov[i].control.s)
                  evaluating = &iov[i];
               break;

            case SOCKS_UDPASSOCIATE: {
               if (s == iov[i].control.s)
                  evaluating = &iov[i];
#if BAREFOOTD
               else {
                  struct udpclient *client;

                  if (s == iov[i].src.s
                  ||  s == iov[i].dst.dstv[DUMMY_INDEX].s)
                     evaluating = &iov[i];
                  else {
                     if ((client = clientofsocket(s,
                                                  iov[i].dst.dstc,
                                                  iov[i].dst.dstv)) != NULL) {
                        SYNC_UDP(&iov[i], client);
                        evaluating = &iov[i];
                     }
                  }
               }
#endif /* BAREFOOTD */

               break;
            }

            default:
               break;
         }

         if (evaluating != NULL)
            break;
      }

      SASSERTX(evaluating != NULL);

      /* want the i/o object that has least recently done i/o. */
      if (best == NULL || timercmp(&evaluating->lastio, &best->lastio, <))
         best = evaluating;
   }

   return best;
}

static sockd_io_t *
io_finddescriptor(d)
   int d;
{
   size_t i;

   for (i = 0; i < ioc; ++i)
      if (iov[i].allocated) {
         if (d == iov[i].src.s || d == iov[i].dst.s) {
#if BAREFOOTD
            if (d == iov[i].src.s
            && iov[i].state.command == SOCKS_UDPASSOCIATE)
               /* dummy socket. demux later. */
               SYNC_UDP(&iov[i], &iov[i].dst.dstv[DUMMY_INDEX]);
#endif /* BAREFOOTD */

            return &iov[i];
         }

         switch (iov[i].state.command) {
            case SOCKS_BIND:
            case SOCKS_BINDREPLY:
               if (!iov[i].state.extension.bind)
                  break;
               /* else: */ /* FALLTHROUGH */

            case SOCKS_UDPASSOCIATE: {
#if BAREFOOTD
               struct udpclient *udpclient;
               if ((udpclient = clientofsocket(d,
                                               iov[i].dst.dstc,
                                               iov[i].dst.dstv)) != NULL) {
                  SYNC_UDP(&iov[i], udpclient);
                  return &iov[i];
               }
#else
               if (d == iov[i].control.s)
                  return &iov[i];
#endif /* BAREFOOTD */
               break;
            }

            default:
               break;
         }
      }

   return NULL;
}

static int
io_fillset(set, antiflags, bwoverflowtil)
   fd_set *set;
   int antiflags;
   struct timeval *bwoverflowtil;
{
   const char *function = "io_fillset()";
   struct timeval tnow, firstbwoverflowok;
   size_t i;
   int max;

   gettimeofday(&tnow, NULL);
   timerclear(&firstbwoverflowok);

   FD_ZERO(set);
   for (i = 0, max = -1; i < ioc; ++i) {
      sockd_io_t *io = &iov[i];

      if (!io->allocated)
         continue;

#if SOCKS_SERVER
   /*
    * Dante may have a control-connection to check, but don't care about
    * bandwidth-limits on those.
    */
   if (io->control.s != -1) {
      if (!(antiflags & io->control.flags)) {
         FD_SET(io->control.s, set);
         max = MAX(max, io->control.s);
      }
   }
#endif /* SOCKS_SERVER */


#if BAREFOOTD
      /*
       * udp-clients need special handling in barefootd regarding bw,
       * but the tcp case is the same.
       */
      if (io->state.protocol == SOCKS_TCP) {
#endif /* BAREFOOTD */

      if (SHMEM_RULE(io)->bw_shmid != 0) {
         struct timeval bwoverflowok, howlongtil;

         if (bw_rulehasoverflown(SHMEM_RULE(io),
                                 &tnow,
                                 &bwoverflowok,
                                 io->control.s == -1 ?
                                    io->src.s : io->control.s,
                                 io->src.s,
                                 io->dst.s)) {
               if (!timerisset(&firstbwoverflowok)
               ||  timercmp(&bwoverflowok, &firstbwoverflowok, <))
                  firstbwoverflowok = bwoverflowok;

            SASSERTX(timercmp(&bwoverflowok, &tnow, >));
            timersub(&bwoverflowok, &tnow, &howlongtil);
            slog(LOG_DEBUG,
                 "%s: skipping io #%lu belonging to rule #%lu/bw_shmid %lu "
                 "due to bwoverflow.  Fds are %d, %d, %d.  "
                 "Have to wait for %ld.%06lds, til %ld.%06ld",
                 function,
                 (unsigned long)i,
                 (unsigned long)(SHMEM_RULE(io)->number),
                 (unsigned long)(SHMEM_RULE(io)->bw_shmid),
                 io->control.s,
                 io->src.s,
                 io->dst.s,
                 (long)howlongtil.tv_sec,
                 (long)howlongtil.tv_usec,
                 (long)bwoverflowok.tv_sec,
                 (long)bwoverflowok.tv_usec);

            continue;
         }
      }

#if BAREFOOTD
      }
#endif /* BAREFOOTD */

      switch (io->state.command) {
         case SOCKS_BINDREPLY:
         case SOCKS_CONNECT:
            if (!io->src.state.fin && !(antiflags & io->src.flags)) {
               FD_SET(io->src.s, set);
               max = MAX(max, io->src.s);
            }

            if (io->dst.state.connected
            && !io->dst.state.fin
            && !(antiflags & io->dst.flags)) {
               FD_SET(io->dst.s, set);
               max = MAX(max, io->dst.s);
            }

            break;

         case SOCKS_UDPASSOCIATE: {
#if BAREFOOTD
            size_t ii;

            /*
             * this socket is shared among all clients, so set it
             * regardless of bw-limits as we don't know from what
             * client the packet is til we've read the packet.
             * XXX But what do we do if the bw overflows?  We can't
             * know that until we've read the packet and seen who it's
             * from.  Should we then drop the packet?  Probably.
             */

            /* no flags for udp so far. */
            SASSERTX(io->src.flags == 0);
            SASSERTX(io->dst.flags == 0);

            if (!(antiflags & io->src.flags)) {
               FD_SET(io->src.s, set);
               max = MAX(max, io->src.s);
            }

            for (ii = DUMMY_INDEX + 1; ii < io->dst.dstc; ++ii) {
               if (io->dst.dstv[ii].rule.crule->bw_shmid != 0) {
                  struct timeval bwoverflowok;

                  slog(LOG_DEBUG,
                       "%s: checking client %s for bw overflow "
                       "according to bw_shmid %lu ...",
                       function,
                       sockaddr2string(TOSA(&io->dst.dstv[ii].client), NULL, 0),
                       (unsigned long)io->dst.dstv[ii].rule.crule->bw_shmid);

                  SASSERTX(io->dst.dstv[ii].rule.crule->bw != NULL);
                  if (bw_rulehasoverflown(io->dst.dstv[ii].rule.crule,
                                          &tnow,
                                          &bwoverflowok,
                                          io->control.s,
                                          io->src.s,
                                          io->dst.dstv[ii].s)) {
                     if (!timerisset(&firstbwoverflowok)
                     ||  timercmp(&bwoverflowok, &firstbwoverflowok, <))
                        firstbwoverflowok = bwoverflowok;

                     continue;
                  }
               }

               FD_SET(io->dst.dstv[ii].s, set);
               max = MAX(max, io->dst.dstv[ii].s);
            }

#else /* SOCKS_SERVER */
            /* no flags for udp so far. */
            SASSERTX(io->src.flags == 0);
            SASSERTX(io->dst.flags == 0);

            if (!io->src.state.connected)
               /*
                * if client has not sent us it's address yet, we have nowhere
                * to forward the packet received from dst, so don't waste
                * time checking for packets from dst it either.
                */
               ;
            else {
               FD_SET(io->dst.s, set);
               max = MAX(max, io->dst.s);
            }

            FD_SET(io->src.s, set);
            max = MAX(max, io->src.s);
#endif /* SOCKS_SERVER */

            break;
         }
      }
   }

   if (bwoverflowtil != NULL)
      *bwoverflowtil = firstbwoverflowok;

   return max;
}

static int
io_fillset_connectinprogress(set)
   fd_set *set;
{
   const char *function = "io_fillset_connectinprogress()";
   int i, bits, count;

   FD_ZERO(set);
   for (i = count = 0, bits = -1; (size_t)i < ioc; ++i) {
      if (iov[i].allocated
      && !iov[i].dst.state.connected
      && iov[i].state.command == SOCKS_CONNECT) {

         FD_SET(iov[i].dst.s, set);
         bits = MAX(bits, iov[i].dst.s);

         slog(LOG_DEBUG, "%s: socket %d marked as still connecting",
         function, iov[i].dst.s);

         ++count;
      }
   }

   return bits;
}

static struct timeval *
io_gettimeout(timeout)
   struct timeval *timeout;
{
   const char *function = "io_gettimeout()";
   struct timeval tnow;
   size_t i;
   int havetimeout;

   gettimeofday(&tnow, NULL);

   if (timerisset(&bwoverflowtil)) {
      struct timeval time_havebw;

      slog(LOG_DEBUG, "%s: bwoverflowtil is set: %ld:%06ld",
           function,
           (unsigned long)bwoverflowtil.tv_sec,
           (unsigned long)bwoverflowtil.tv_usec);

      timersub(&bwoverflowtil, &tnow, &time_havebw);
      if (time_havebw.tv_sec < 0
      || (time_havebw.tv_sec == 0 && time_havebw.tv_usec <= 0)) {
         timerclear(&bwoverflowtil);
         timerclear(timeout);
      }
      else
          *timeout = time_havebw;

      if (timeout->tv_sec <= 1)
         /*
          * good enough; don't bother going through all i/os to find one
          * with a possibly slightly shorter timeout.
          */
         return timeout;
   }

   /*
    * Could perhaps add a "timeoutispossible" object also by checking
    * each io object as we receive it (and each udp client as we
    * add it).  If we find one where timeout is possible, set the
    * global timeoutispossible, if not, don't set it.  Each time
    * we delete_io(), we change timeoutispossible to true, and
    * upon scanning through all i/o's here, we may possible set it
    * to false again.
    */
   if (io_allocated(NULL, NULL) == 0)
      return NULL;

   for (i = 0, havetimeout = 0; i < ioc; ++i) {
      struct timeval timeout_found;

      timeout_found.tv_sec  = io_timetiltimeout(&iov[i], &tnow, NULL);
      timeout_found.tv_usec = 0;

      slog(LOG_DEBUG, "%s: timeout for iov #%lu is %ld",
           function, (unsigned long)i, (long)timeout_found.tv_sec);

      if (timeout_found.tv_sec != -1) {
         if (!havetimeout
         ||  timercmp(&timeout_found, timeout, <)) {
            *timeout    = timeout_found;
            havetimeout = 1;
         }
      }

      if (havetimeout && timeout->tv_sec <= 0)
         break; /* at or past timeout already, don't look further. */

      /* else; continue looking for the one that will time out most imminent. */
   }

   if (havetimeout)
      return timeout;
   else
      return NULL;
}

static sockd_io_t *
io_gettimedout(void)
{
   const char *function = "io_gettimedout()";
   struct timeval tnow;
   size_t i;

   gettimeofday(&tnow, NULL);
   for (i = 0; i < ioc; ++i) {
      struct timeval timeout;

      if (!iov[i].allocated)
         continue;

      if ((timeout.tv_sec = io_timetiltimeout(&iov[i], &tnow, NULL)) == -1)
         continue;  /* no timeout on this object. */

      timeout.tv_usec = 0; /* whole seconds is good enough. */
      if (timeout.tv_sec <= 0) { /* has timed out already. */
         slog(LOG_DEBUG, "%s: io #%lu with control %d, src %d, dst %d, "
                         "has reached the timeout point as of %lds ago.  "
                         "I/O last done at %ld:%06ld",
                         function,
                         (unsigned long)i,
                         iov[i].control.s,
                         iov[i].src.s,
                         iov[i].dst.s,
                         (long)timeout.tv_sec,
                         (long)iov[i].lastio.tv_sec,
                         (long)iov[i].lastio.tv_usec);

         return &iov[i];
      }
   }

   return NULL;
}

static int
io_timeoutispossible(io)
   const sockd_io_t *io;
{

   if (!io->allocated)
      return 0;

#if HAVE_UDP_SUPPORT
   if (io->state.command == SOCKS_UDPASSOCIATE) {
#if BAREFOOTD
      size_t i;

      for (i = DUMMY_INDEX + 1; i < io->dst.dstc; ++i) {
         if (io->dst.dstv[i].rule.timeout.udpio != 0)
            return 1;
      }

      return 0;
#else /* !BAREFOOTD */
      return io->rule.timeout.udpio != 0;
#endif /* !BAREFOOTD */
   }
#endif /* HAVE_UDP_SUPPORT */

   if (io->dst.state.connected) {
      if (io->src.state.shutdown_wr || io->dst.state.shutdown_wr)
         return io->rule.timeout.tcp_fin_wait != 0;
      else
         return io->rule.timeout.tcpio != 0;
   }
   else
      return io->rule.timeout.connect != 0;

   /* NOTREACHED */
   SERRX(0);
}

static long
io_timetiltimeout(io, tnow, timeouttype)
   sockd_io_t *io;
   const struct timeval *tnow;
   timeout_type_t *timeouttype;
{
   const char *function = "io_timetiltimeout()";
   timeout_type_t timeouttype_mem;
   time_t *lastio;
   long protocoltimeout;

   if (!io_timeoutispossible(io)) {
      slog(LOG_DEBUG, "%s: no timeout is possible for io", function);
      return -1;
   }

   if (timeouttype == NULL)
      timeouttype = &timeouttype_mem;

   /* 
    * First find out what the correct timeoutobject to use for this
    * io at this time is, and then see if a timeout value has been
    * set in that object (i.e., is not 0).
    */
   if (io->state.protocol == SOCKS_UDP)
#if BAREFOOTD
   {
      size_t i;
      long timetiltimeout;

      slog(LOG_DEBUG,
           "%s: scanning state of %lu udp clients for nearest timeout",
           function, (unsigned long)io->dst.dstc - 1 /* DUMMY */);

      for (i = DUMMY_INDEX + 1, timetiltimeout = -1; i < io->dst.dstc; ++i) {
         struct udpclient *udpclient = &io->dst.dstv[i];

         if (tnow->tv_sec < udpclient->lastio.tv_sec) {
            swarnx("%s: clock was stepped backwards?", function);

            udpclient->lastio = *tnow;
            continue;
         }

         timetiltimeout =   udpclient->rule.timeout.udpio
                          - (tnow->tv_sec - udpclient->lastio.tv_sec);

         slog(LOG_DEBUG, "%s: time til timeout for udpclient %s is %ld",
              function,
              sockaddr2string(TOSA(&udpclient->client), NULL, 0),
              timetiltimeout);

         timetiltimeout = MAX(0, timetiltimeout);
         *timeouttype   = TIMEOUT_IO;

         SYNC_UDP(io, udpclient);

         if (timetiltimeout <= 0)
            break; /* timeout is now. */
      }

      return timetiltimeout;
#else /* SOCKS_SERVER */
   {
      *timeouttype    = TIMEOUT_IO; /* only type possible for an udp client. */
      protocoltimeout = io->rule.timeout.udpio;
      lastio          = (time_t *)&io->lastio.tv_sec;
#endif /* SOCKS_SERVER */
   }
   else {
      SASSERTX(io->state.protocol == SOCKS_TCP);

      if (io->dst.state.connected) {
         if ((io->src.state.shutdown_wr || io->dst.state.shutdown_wr)
         && io->rule.timeout.tcp_fin_wait < io->rule.timeout.tcpio) {
            *timeouttype    = TIMEOUT_TCP_FIN_WAIT;
            protocoltimeout = io->rule.timeout.tcp_fin_wait;
         }
         else {
            *timeouttype    = TIMEOUT_IO;
            protocoltimeout = io->rule.timeout.tcpio;
         }

         lastio = (time_t *)&io->lastio.tv_sec;
      }
      else {
         *timeouttype    = TIMEOUT_CONNECT;
         protocoltimeout = io->rule.timeout.connect;
         lastio          = (time_t *)&io->state.time.established.tv_sec;
      }
   }

   if (protocoltimeout == 0)
      return -1;

   if (difftime(*lastio, tnow->tv_sec) > 0) {
      swarnx("%s: clock was stepped backwards?", function);
      *lastio = tnow->tv_sec;
   }

   if (MAX(0, protocoltimeout - difftime(tnow->tv_sec, *lastio)) == 0)
      slog(LOG_DEBUG, "%s: timeouttype = %d, protocoltimeout = %ld, "
                      "tnow = %ld, lastio = %ld",
                      function, (int)*timeouttype, protocoltimeout,
                      (long)tnow->tv_sec, (long)*lastio);

   return MAX(0,
              protocoltimeout - ROUNDFLOAT(difftime(tnow->tv_sec, *lastio)));
}

static void
getnewios()
{
   const char *function = "getnewios()";
   int rc, receivedc;

   receivedc = 0;
   while ((rc = recv_io(sockscf.state.mother.s, NULL)) == 0)
      ++receivedc;

   slog(LOG_DEBUG, "%s: received %d new io%s, errno = %d (%s)",
        function,
        receivedc,
        receivedc == 1 ? "" : "s",
        errno,
        strerror(errno));

   SASSERTX(rc == -1);

   if (receivedc == 0)
      slog(LOG_INFO, "%s: strange ... we were called to receive a new io, "
                     "but no new io was there to receive (%s)",
                     function, strerror(errno));
   else
      proctitleupdate();
}

/* ARGSUSED */
static void
siginfo(sig, sip, scp)
   int sig;
   siginfo_t *sip;
   void *scp;
{
   const char *function = "siginfo()";
   const int debug_s = sockscf.option.debug;
   struct sockaddr_storage addr;
   unsigned long seconds, days, hours, minutes;
   struct timeval tnow;
   size_t i;

   if (sig > 0) {
      sockd_pushsignal(sig, sip);
      return;
   }

   sig = -sig;

   slog(LOG_DEBUG, "%s: running due to previously received signal: %d",
        function, sig);

   gettimeofday(&tnow, NULL);
   seconds = ROUNDFLOAT(difftime(time((time_t *)&tnow.tv_sec),
                                 sockscf.stat.boot));
   seconds2days(&seconds, &days, &hours, &minutes);

   sockscf.option.debug = 1;

   slog(LOG_DEBUG, "io-child up %lu day%s, %lu:%.2lu:%.2lu",
                   days, days == 1 ? "" : "s", hours, minutes, seconds);

   if (iostats.io.latencyc == 0)
      slog(LOG_DEBUG, "no latency information available yet");
   else {
      io_updatestat(&iostats.read);
      slog(LOG_DEBUG, "read-only latency statistics based on last %lu packets: "
                      "min/max/median/average/last/stddev: "
                      "%lu/%lu/%lu/%lu/%lu/%lu (us)",
                      (unsigned long)iostats.io.latencyc,
                      iostats.read.min_us,
                      iostats.read.max_us,
                      iostats.read.median_us,
                      iostats.read.average_us,
                      iostats.read.last_us,
                      iostats.read.stddev_us);

      io_updatestat(&iostats.io);
      slog(LOG_DEBUG, "i/o latency statistics based on last %lu packets: "
                      "min/max/median/average/last/stddev: "
                      "%lu/%lu/%lu/%lu/%lu/%lu (us)",
                      (unsigned long)iostats.io.latencyc,
                      iostats.io.min_us,
                      iostats.io.max_us,
                      iostats.io.median_us,
                      iostats.io.average_us,
                      iostats.io.last_us,
                      iostats.io.stddev_us);
   }

   for (i = 0; i < ioc; ++i) {
      sockshost_t a, b;
      char srcstring[MAX_IOLOGADDR], dststring[MAX_IOLOGADDR],
           timeinfo[64], idlestr[64];

      if (!iov[i].allocated)
         continue;

      build_addrstr_src(GET_HOSTIDV(&iov[i].state),
                        GET_HOSTIDC(&iov[i].state),
                        sockaddr2sockshost(sockshost2sockaddr(&iov[i].src.host,
                                                              TOSA(&addr)),
                                           &a),
                        NULL,
                        NULL,
                        sockaddr2sockshost(TOSA(&iov[i].src.laddr), &b),
                        &iov[i].src.auth,
                        NULL,
                        srcstring,
                        sizeof(srcstring));

      build_addrstr_dst(sockaddr2sockshost(TOSA(&iov[i].dst.laddr), NULL),
                        iov[i].state.proxyprotocol == PROXY_DIRECT ?
                           NULL : sockaddr2sockshost(TOSA(&iov[i].dst.raddr), &a),
                        iov[i].state.proxyprotocol == PROXY_DIRECT
                           ? NULL : &iov[i].state.proxychain.extaddr,
                        sockaddr2sockshost(sockshost2sockaddr(&iov[i].dst.host,
                                                              TOSA(&addr)),
                                           &b),
                        &iov[i].dst.auth,
                        NULL,
                        (struct in_addr *)NULL,
                        0,
                        dststring,
                        sizeof(dststring));

      if (iov[i].state.protocol == SOCKS_UDP
      ||  iov[i].dst.state.connected)
         snprintfn(idlestr, sizeof(idlestr), "%lds",
                   (long)(tnow.tv_sec - iov[i].lastio.tv_sec));
      else
         snprintfn(idlestr, sizeof(idlestr),
                   "%lds (waiting for connect to complete)",
                   (long)(  tnow.tv_sec
                          - iov[i].state.time.established.tv_sec));

      snprintf(timeinfo, sizeof(timeinfo),
               "age: %lds, idle: %s",
               (long)(tnow.tv_sec - iov[i].state.time.accepted.tv_sec),
               idlestr);

      if (iov[i].state.protocol == SOCKS_UDP) {
#if HAVE_SOCKS_RULES
         slog(LOG_DEBUG,
              "%s: %s <-> %s: %s, "
              "bytes transferred: %"PRIu64" <-> %"PRIu64", "
              "packets: %"PRIu64" <-> %"PRIu64"",
              protocol2string(iov[i].state.protocol),
              srcstring, dststring,
              timeinfo,
              iov[i].dst.written.bytes, iov[i].src.written.bytes,
              iov[i].dst.written.packets, iov[i].src.written.packets);
#else /* !HAVE_SOCKS_RULES */
         struct udpclient *client;
         size_t srci;

         for (srci = DUMMY_INDEX + 1; srci < iov[i].dst.dstc; ++srci) {
            sockshost_t host;

            client = &iov[i].dst.dstv[srci];
            SYNC_UDP(&iov[i], client);

            build_addrstr_src(GET_HOSTIDV(&iov[i].state),
                              GET_HOSTIDC(&iov[i].state),
                              sockaddr2sockshost(TOSA(&client->client), &a),
                              NULL,
                              NULL,
                              sockaddr2sockshost(TOSA(&iov[i].src.laddr), &b),
                              &iov[i].src.auth,
                              NULL,
                              srcstring,
                              sizeof(srcstring));

            build_addrstr_dst(sockaddr2sockshost(TOSA(&iov[i].dst.laddr), &a),
                              iov[i].state.proxyprotocol == PROXY_DIRECT
                        ? NULL : sockaddr2sockshost(TOSA(&iov[i].dst.raddr), &b),
                              iov[i].state.proxyprotocol == PROXY_DIRECT
                                 ? NULL : &iov[i].state.proxychain.extaddr,
                              sockaddr2sockshost(
                                 sockshost2sockaddr(&iov[i].dst.host, TOSA(&addr)),
                                 &host),
                              &iov[i].dst.auth,
                              NULL,
                              (struct in_addr *)NULL,
                              0,
                              dststring,
                              sizeof(dststring));

            snprintf(timeinfo, sizeof(timeinfo),
                     "age: %lds, idle: %lds",
                     (long)(tnow.tv_sec - client->firstio.tv_sec),
                     (long)(tnow.tv_sec - client->lastio.tv_sec));

            slog(LOG_DEBUG, "%s: %s <-> %s: %s, "
                            "bytes transferred: %"PRIu64" <-> %"PRIu64", "
                            "packets: %"PRIu64" <-> %"PRIu64"",
                            protocol2string(iov[i].state.protocol),
                            srcstring, dststring,
                            timeinfo,
                            client->dst_written.bytes,
                            client->src_written.bytes,
                            client->dst_written.packets,
                            client->src_written.packets);
         }
#endif /* !HAVE_SOCKS_RULES */
      }
      else {
         size_t src_buffered, dst_buffered;
         char src_bufferinfo[64], dst_bufferinfo[64];
         int havesocketinfo;
#if HAVE_RECVBUF_IOCTL
         int src_so_rcvbuf, dst_so_rcvbuf;
#endif /* HAVE_RECVBUF_IOCTL */
#if HAVE_SENDBUF_IOCTL
         int src_so_sndbuf, dst_so_sndbuf;
#endif /* HAVE_SENDBUF_IOCTL */

         SASSERTX(iov[i].state.protocol == SOCKS_TCP);

         src_buffered = socks_bytesinbuffer(iov[i].src.s,
                                            WRITE_BUF,
#if SOCKS_SERVER && HAVE_GSSAPI
                                    iov[i].src.auth.method == AUTHMETHOD_GSSAPI
                                 && iov[i].src.auth.mdata.gssapi.state.wrap ?
                                    1 : 0
#else /* !SOCKS_SERVER */
                                  0
#endif /* !SOCKS_SERVER */
                                   );

         dst_buffered = socks_bytesinbuffer(iov[i].dst.s, WRITE_BUF, 0);

#if HAVE_RECVBUF_IOCTL
         if (ioctl(iov[i].dst.s, RECVBUF_IOCTLVAL, &dst_so_rcvbuf) != 0) {
            swarn("%s: rcvbuf size ioctl() on dst-socket %d failed",
                  function, iov[i].dst.s);
            havesocketinfo = 0;
         }
         else
            havesocketinfo = 1;

         if (havesocketinfo) {
            if (ioctl(iov[i].src.s, RECVBUF_IOCTLVAL, &src_so_rcvbuf) != 0) {
               swarn("%s: recvbuf size ioctl() on src-socket %d failed",
                     function, iov[i].src.s);
               havesocketinfo = 0;
            }
         }
#endif /* HAVE_RECVBUF_IOCTL */

#if HAVE_SENDBUF_IOCTL
         if (havesocketinfo) {
            if (ioctl(iov[i].src.s, SENDBUF_IOCTLVAL, &src_so_sndbuf) != 0) {
               swarn("%s: sendbuf size ioctl() on src-socket %d failed",
                     function, iov[i].src.s);
               havesocketinfo = 0;
            }
         }

         if (havesocketinfo) {
            if (ioctl(iov[i].dst.s, SENDBUF_IOCTLVAL, &dst_so_sndbuf) != 0) {
               swarn("%s: sendbuf size ioctl() on dst-socket %d failed",
                     function, iov[i].dst.s);
               havesocketinfo = 0;
            }
         }
#endif /* HAVE_SENDBUF_IOCTL */

#if HAVE_SENDBUF_IOCTL && HAVE_RECVBUF_IOCTL
         if (havesocketinfo) {
            snprintf(src_bufferinfo, sizeof(src_bufferinfo),
                     "%lu buffered (%lu + %lu + %lu)",
                     (unsigned long)(src_buffered
                                   + dst_so_rcvbuf
                                   + src_so_sndbuf),
                     (unsigned long)dst_so_rcvbuf,
                     (unsigned long)src_buffered,
                     (unsigned long)src_so_sndbuf);

            snprintf(dst_bufferinfo, sizeof(dst_bufferinfo),
                     "%lu buffered (%lu + %lu + %lu)",
                     (unsigned long)(dst_buffered
                                   + src_so_rcvbuf
                                   + dst_so_sndbuf),
                     (unsigned long)src_so_rcvbuf,
                     (unsigned long)dst_buffered,
                     (unsigned long)dst_so_sndbuf);
         }
#elif HAVE_SENDBUF_IOCTL && !HAVE_RECVBUF_IOCTL
         if (havesocketinfo) {
            snprintf(src_bufferinfo, sizeof(src_bufferinfo),
                     "%lu buffered (? + %lu + %lu)",
                     (unsigned long)(src_buffered
                                   + src_so_sndbuf),
                     (unsigned long)src_buffered,
                     (unsigned long)src_so_sndbuf);

            snprintf(dst_bufferinfo, sizeof(dst_bufferinfo),
                     "%lu buffered (? + %lu + %lu)",
                     (unsigned long)(dst_buffered
                                   + dst_so_sndbuf),
                     (unsigned long)dst_buffered,
                     (unsigned long)dst_so_sndbuf);
         }
#elif !HAVE_SENDBUF_IOCTL && HAVE_RECVBUF_IOCTL
         if (havesocketinfo) {
            snprintf(src_bufferinfo, sizeof(src_bufferinfo),
                     "%lu buffered (%lu + %lu + ?)",
                     (unsigned long)(src_buffered
                                   + dst_so_rcvbuf),
                     (unsigned long)dst_so_rcvbuf,
                     (unsigned long)src_buffered);

            snprintf(dst_bufferinfo, sizeof(dst_bufferinfo),
                     "%lu buffered (%lu + %lu + ?)",
                     (unsigned long)(dst_buffered
                                   + src_so_rcvbuf),
                     (unsigned long)src_so_rcvbuf,
                     (unsigned long)dst_buffered);
         }
#else /* !HAVE_SENDBUF_IOCTL && !HAVE_RECVBUF_IOCTL */

         havesocketinfo = 0;

#endif /* !HAVE_SENDBUF_IOCTL && !HAVE_RECVBUF_IOCTL */

         if (!havesocketinfo) {
            snprintf(src_bufferinfo, sizeof(src_bufferinfo),
                     "%lu buffered (? + %lu + ?)",
                     (unsigned long)src_buffered,
                     (unsigned long)src_buffered);

            snprintf(dst_bufferinfo, sizeof(dst_bufferinfo),
                     "%lu buffered (? + %lu + ?)",
                     (unsigned long)dst_buffered,
                     (unsigned long)dst_buffered);
         }

         slog(LOG_DEBUG,
              "%s: %s <-> %s: %s, bytes transferred: "
              "%"PRIu64" (+ %s) "
              "<-> "
              "%"PRIu64" (+ %s)",
              protocol2string(iov[i].state.protocol),
              srcstring, dststring,
              timeinfo,
              iov[i].dst.written.bytes,
              dst_bufferinfo,
              iov[i].src.written.bytes,
              src_bufferinfo);
      }
   }

   sockscf.option.debug = debug_s;
}

static void
freebuffers(io)
   const sockd_io_t *io;
{
   if (io->control.s != -1 && io->control.s != io->src.s)
      socks_freebuffer(io->control.s);

   socks_freebuffer(io->src.s);
   socks_freebuffer(io->dst.s);
}

static int
checkconnectstatus(io, badfd)
   sockd_io_t *io;
   int *badfd;
{
   const char *function = "checkconnectstatus()";
#if HAVE_NEGOTIATE_PHASE
   const int controlfd = (io->control.s == -1 ? io->src.s : io->control.s);
#endif /* HAVE_NEGOTIATE_PHASE */
   socklen_t len;
   int secondtry = 0;

again:
   SASSERTX(io->state.command == SOCKS_CONNECT && !io->dst.state.connected);
   SASSERTX(io->dst.state.err == 0);

   *badfd = -1;

   /*
    * Check if the socket connected successfully.
    */
   len = sizeof(io->dst.raddr);
   if (getpeername(io->dst.s, TOSA(&io->dst.raddr), &len) == 0) {
      iologaddr_t src, dst;

      slog(LOG_DEBUG, "%s: connect to %s on socket %d completed successfully",
           function, sockshost2string(&io->dst.host, NULL, 0), io->dst.s);

      io->dst.state.connected = 1;

#if HAVE_NEGOTIATE_PHASE
      if (SOCKS_SERVER || io->reqflags.httpconnect) {
         response_t response;
         sockshost_t host;

         if (SOCKS_SERVER)
            sockaddr2sockshost(TOSA(&io->dst.laddr), &host);
         else
            host = io->dst.host;

         create_response(&host,
                         &io->src.auth,
                         io->state.version,
                         SOCKS_SUCCESS,
                         &response);

         if (send_response(controlfd, &response) != 0) {
            *badfd = controlfd;
            return -1;
         }
      }
#endif /* HAVE_NEGOTIATE_PHASE */

      setconfsockoptions(io->dst.s,
                         io->control.s,
                         io->state.protocol,
                         0,
                         io->extsocketoptionc,
                         io->extsocketoptionv,
                         SOCKETOPT_POST,
                         SOCKETOPT_POST);

      init_iologaddr(&src,
                     SOCKADDR_OBJECT,
                     &io->src.laddr,
                     SOCKSHOST_OBJECT,
                     &io->src.host,
                     &io->src.auth,
                     GET_HOSTIDV(&io->state),
                     GET_HOSTIDC(&io->state));

      init_iologaddr(&dst,
                     SOCKADDR_OBJECT,
                     &io->dst.laddr,
                     SOCKSHOST_OBJECT,
                     &io->dst.host,
                     &io->dst.auth,
                     NULL,
                     0);

      iolog(&io->rule,
            &io->state,
            OPERATION_CONNECT,
            &src,
            &dst,
            NULL,
            NULL,
            NULL,
            0);

      return 0;
   }
   else { /* connect(2) failed. */
      char src[MAXSOCKSHOSTSTRING], dst[MAXSOCKSHOSTSTRING];

      slog(LOG_DEBUG, "%s: getpeername(%d) failed: %s",
           function, io->dst.s, strerror(errno));

      len               = sizeof(errno);
      getsockopt(io->dst.s, SOL_SOCKET, SO_ERROR, &errno, &len);
      io->dst.state.err = errno;

      slog(LOG_DEBUG, "%s: connect-attempt to %s on socket %d, on behalf of "
                      "client %s, has completed.  Status is: %s, errno = %d",
                      function,
                      sockshost2string(&io->dst.host, dst, sizeof(dst)),
                      io->dst.s,
                      sockshost2string(&io->src.host, src, sizeof(src)),
                      strerror(errno),
                      errno);

      if (errno == 0) {
         /*
          * still in progress?  Can't be, we should only be called when the
          * connect(2) has finished, as indicated by e.g. select(2).
          * Could also be a race-condition however, if the connect(2)
          * completed successfully between our getpeername(2) call above and
          * now.  Very unlikely, but have to check none the less.
          */
          char src[MAXSOCKADDRSTRING * 3], dst[MAXSOCKADDRSTRING * 3];

          if (!secondtry) {
            secondtry = 1;
            goto again;
          }

          swarnx("%s: bug detected regarding request %s from client %s, "
                 "destination %s.  Please report this to \"%s-bugs@inet.no\".",
                 function,
                 sockshost2string(&io->dst.host, NULL, 0),
                 socket2string(io->src.s, src, sizeof(src)),
                 socket2string(io->dst.s, dst, sizeof(dst)),
                 PACKAGE);

#if 1 /* work around the problem by deleting the session in question. */
         *badfd = io->dst.s;
         return -1;
#else
#warning "change before release"
         SERRX(0);
#endif
      }

      if (ERRNOISNOROUTE(errno))
         swarn("%s: no route to %s", function, dst);

#if HAVE_NEGOTIATE_PHASE
      if (SOCKS_SERVER || io->reqflags.httpconnect) {
         response_t response;

         create_response(NULL,
                         &io->src.auth,
                         io->state.version,
                         errno2reply(errno, io->state.version),
                         &response);

         if (send_response(controlfd, &response) != 0)
            /* want errno to be the previous errno, from connect(2). */
            errno = io->dst.state.err;
      }
#endif /* HAVE_NEGOTIATE_PHASE */

      *badfd = io->dst.s;
      return -1;
   }
}

static void
io_update(timenow, bwused, rule, lock)
   const struct timeval *timenow;
   const size_t bwused;
   rule_t *rule;
   const int lock;
{
   const char *function = "io_update()";
   const int needattach = ((rule->bw) == NULL);

   slog(LOG_DEBUG, "%s: bwused = %ld", function, (unsigned long)bwused);

   if (rule->bw_shmid == 0 || bwused == 0)
      return;

   if (needattach)
      sockd_shmat(rule, SHMEM_BW);

   if (rule->bw_shmid == 0)
      return;

   bw_update(rule->bw, bwused, timenow, lock);

   if (needattach)
      sockd_shmdt(rule, SHMEM_BW);
}

static int
io_calculatedlatency(ts_recv, src, dst, latency)
   const struct timeval *ts_recv;
   const struct sockaddr *src;
   const struct sockaddr *dst;
   struct timeval *latency;
{

#if !HAVE_SO_TIMESTAMP

   return 0;

#else /* HAVE_SO_TIMESTAMP */

   const char *function = "io_calculatedlatency()";
   struct timeval ts_sent;
   char srcstr[MAXSOCKADDRSTRING], dststr[MAXSOCKADDRSTRING];


   gettimeofday(&ts_sent, NULL);
   timersub(&ts_sent, ts_recv, latency);

   if (latency->tv_sec < 0 || latency->tv_usec < 0)
      swarnx("%s: clock was stepped backwards?", function);
   else {
      slog(LOG_DEBUG,
           "%s: packetlatency for packet from %s to %s: %ld.%06lds",
           function,
           sockaddr2string(src, srcstr, sizeof(srcstr)),
           sockaddr2string(dst, dststr, sizeof(dststr)),
           (long)latency->tv_sec, (long)latency->tv_usec);
   }

   return 1;
#endif /* HAVE_SO_TIMESTAMP */
}

static void
io_addts(rbc, rbv, rbc_used, ts)
   const size_t rbc;
   struct timeval *rbv;
   size_t *rbc_used;
   const struct timeval *ts;
{
   const char *function = "io_addts()";

   SASSERTX(*rbc_used <= rbc);

   if (*rbc_used == rbc) {
      memmove(&rbv[0], &rbv[1], sizeof(*rbv) * (rbc - 1));
      rbv[rbc - 1] = *ts;
   }
   else
      rbv[(*rbc_used)++] = *ts;

   slog(LOG_DEBUG, "%s: added ts %ld.%06ld.  Now have %d ts'",
        function, (long)ts->tv_sec, (long)ts->tv_usec, (int)*rbc_used);
}

static void io_updatestat(iostat)
   struct iostat *iostat;
{
   const char *function = "io_updatestat()";

   SASSERTX(iostat->latencyc > 0);
   SASSERTX(iostat->latencyc <= ELEMENTS(iostat->latencyv));

   /* save last ts before we start sorting the info. */
   iostat->last_us = tv2usec(&iostat->latencyv[iostat->latencyc - 1]);

   /*
    * the rest of the calculations require a sorted array.
    */
   qsort(iostat->latencyv,
         iostat->latencyc,
         sizeof(*iostat->latencyv),
         io_timercmp);

   iostat->min_us     = tv2usec(&iostat->latencyv[0]);
   iostat->max_us     = tv2usec(&iostat->latencyv[iostat->latencyc
                                                        - 1]);
   iostat->median_us  = medtv(iostat->latencyv, iostat->latencyc);
   iostat->average_us = avgtv(iostat->latencyv, iostat->latencyc);
   iostat->stddev_us  = stddevtv(iostat->latencyv,
                                    iostat->latencyc,
                                    iostat->average_us);

#if 0
   for (i = 0; i < iostat->latencyc; ++i) {
      slog(LOG_DEBUG, "%s: index #%lu, latency: %ld.%06ld",
           function,
           (unsigned long)i,
           iostat->latencyv[i].tv_sec,
           iostat->latencyv[i].tv_usec);
   }
#endif
}

static int
io_timercmp(a, b)
   const void *a;
   const void *b;
{

   if (timercmp((const struct timeval *)a, (const struct timeval *)b, <))
      return -1;

   if (timercmp((const struct timeval *)a, (const struct timeval *)b, ==))
      return 0;

   SASSERTX(timercmp((const struct timeval *)a, (const struct timeval *)b, >));
   return 1;
}


#if SOCKS_SERVER
static int
fromaddr_as_expected(s, expected, from, emsg, emsglen)
   const int s;
   struct sockaddr *expected;
   const struct sockaddr *from;
   char *emsg;
   size_t emsglen;
{
   const char *function = "fromaddr_as_expected()";
   char estr[MAXSOCKADDRSTRING], fstr[MAXSOCKADDRSTRING];

   slog(LOG_DEBUG, "%s: expected = %s, from = %s",
        function,
        sockaddr2string(expected, estr, sizeof(estr)),
        sockaddr2string(from, fstr, sizeof(fstr)));

   if (!ADDRISBOUND(TOIN(expected)) || !PORTISBOUND(TOIN(expected))) {
      /*
       * Client hasn't sent us it's complete address yet, but if
       * the parts of the address it has sent, if any, matches
       * the source of this packet, we have to assume this packet
       * is from it.  We then connect the socket to the client, for
       * better performance, for receiving errors from sendto(),
       * for getpeername() libwrap in rulespermit(), for ...
       * well, that's reasons enough.
       */
       struct sockaddr_storage test;
       sockaddrcpy(TOSA(&test), expected, sizeof(test));

      if (!ADDRISBOUND(TOIN(expected)))
         TOIN(&test)->sin_addr = TOCIN(from)->sin_addr;

      if (!PORTISBOUND(TOIN(expected)))
         TOIN(&test)->sin_port = TOCIN(from)->sin_port;

      if (sockaddrareeq(TOSA(&test), from)) {
         /* what we had matched, now we have the full addr. */
         sockaddrcpy(expected, TOSA(&test), sizeof(*expected));
         return 1;
      }
      else {
         char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];

          snprintf(emsg, emsglen,
                   "expected udp packet from %s, but got it from %s",
                   sockaddr2string(expected, src, sizeof(src)),
                   sockaddr2string(from, dst, sizeof(dst)));

         return 0;
      }
   }
   else {
      if (sockaddrareeq(expected, from))
         return 1;
      else {
         char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];

         snprintf(emsg, emsglen,
                  "expected udp packet from %s, but got it from %s",
                  sockaddr2string(expected, src, sizeof(src)),
                  sockaddr2string(from, dst, sizeof(dst)));

         return 0;
      }
   }
}

static udpheader_t *
getudptarget(buf, buflen, from, header, emsg, emsglen)
   const char *buf;
   const size_t buflen;
   const struct sockaddr *from;
   udpheader_t *header;
   char *emsg;
   const size_t emsglen;
{
   const char *function;

   if (string2udpheader(buf, buflen, header) == NULL) {
      snprintf(emsg, emsglen,
               "syntax error in received socks udp packet of length %lu",
               (unsigned long)buflen);

      return NULL;
   }

   if (header->frag != 0) {
      snprintf(emsg, emsglen, "fragmented socks udp packets are not supported");
      return NULL;
   }

   return header;
}

#elif BAREFOOTD

static udpheader_t *
getudptarget(buf, buflen, from, s, state, dstc, dstv, to, rule, header,
          emsg, emsglen)
   const char *buf;
   const size_t buflen;
   const struct sockaddr *from;
   const int s;
   const connectionstate_t *state;
   const int dstc;
   struct udpclient *dstv;
   const struct sockaddr *to;
   rule_t *rule;
   udpheader_t *header;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "getudptarget()";
   struct udpclient *udpclient;
   char src[MAXSOCKADDRSTRING], dst[MAXSOCKADDRSTRING];
   int use_saved_rule;

   /*
    * No socks header.  The dst is the fixed bounce-to address in the matching
    * client-rule, so we will only know what the destinations address is after
    * we've found the client-rule and looked up the bounce-to address of that.
    */

   SASSERTX(clientofsocket(s, dstc, dstv) == NULL);
   if ((udpclient = clientofclientaddr(from, dstc, dstv)) != NULL)
      use_saved_rule = udpclient->use_saved_rule;
   else
      use_saved_rule = 0;

   slog(LOG_DEBUG, "%s: received packet from client %s on socket %d (%s).  "
        "Length = %lu, udpclient = %p, use_saved_rule = %d",
        function,
        sockaddr2string(from, src, sizeof(src)),
        s,
        sockaddr2string(to, dst, sizeof(dst)),
        (unsigned long)buflen,
        udpclient,
        use_saved_rule);

   if (udpclient == NULL || !use_saved_rule) {
      authmethod_t clientauth, socksauth;
      sockshost_t fromhost, tohost;
      connectionstate_t rulestate;
      sockshost_t client_laddr;

      sockaddr2sockshost(from, &fromhost);
      sockaddr2sockshost(to,   &tohost);

      bzero(&clientauth, sizeof(clientauth));
      bzero(&socksauth, sizeof(socksauth));

      /* currently no auth is supported for udp in Barefoot. */
      clientauth.method = socksauth.method = AUTHMETHOD_NOTSET;

      rulestate         = *state;
      rulestate.command = SOCKS_BOUNCETO;
      sockaddr2sockshost(to, &client_laddr);

      rulespermit(s,
                  from,
                  to,
                  &client_laddr,
                  &clientauth,
                  &socksauth,
                  rule,
                  &rulestate,
                  &fromhost,
                  &tohost,
                  emsg,
                  emsglen);
   }
   else /* reuse rule from last time. */
      *rule = *udpclient->rule.crule;

   SASSERTX(rule->crule == NULL);
   SASSERTX(rule->extra.bounceto.atype != SOCKS_ADDR_NOTSET);

   ruleaddr2sockshost(&rule->extra.bounceto, &header->host, SOCKS_UDP);

   slog(LOG_DEBUG, "%s: target address for packet from %s on socket %d is %s",
        function,
        sockaddr2string(from, NULL, 0),
        s,
        sockshost2string(&header->host, NULL, 0));

   return header;
}

#endif /* BAREFOOTD */

#if BAREFOOTD

static int
io_haveresources(rule, client, emsg, emsglen)
   rule_t *rule;
   const struct sockaddr *client;
   char *emsg;
   const size_t emsglen;
{
   const char *function = "io_haveresources()";

   slog(LOG_DEBUG, "%s: checking if we have the needed resources for client %s",
        function, sockaddr2string(client, NULL, 0));

   if (rule->ss_shmid != 0 && rule->ss == NULL)
      sockd_shmat(rule, SHMEM_SS);

   if (rule->ss_shmid != 0) {
      if (!session_use(rule->ss, sockscf.shmemfd)) {
         snprintf(emsg, emsglen, DENY_SESSIONLIMITs);
         sockd_shmdt(rule, SHMEM_SS);

         return 0;
      }

      slog(LOG_DEBUG, "%s: used ss_shmid %ld, addr %s, clients %ld",
           function,
           rule->ss_shmid,
           sockaddr2string(client, NULL, 0),
           (long)rule->ss->mstate.clients);
   }

   if (rule->bw_shmid != 0 && rule->bw == NULL)
      sockd_shmat(rule, SHMEM_BW);

   if (rule->bw_shmid != 0) {
      bw_use(rule->bw, sockscf.shmemfd);

      slog(LOG_DEBUG, "%s: used bw_shmid %ld, addr %s, clients %ld",
           function,
           rule->bw_shmid,
           sockaddr2string(client, NULL, 0),
           (long)rule->bw->mstate.clients);
   }

   return 1;
}

static struct udpclient *
initclient(from, to, emsg, emsglen, udpdst)
   const struct sockaddr *from;
   const sockshost_t *to;
   char *emsg;
   const size_t emsglen;
   struct udpclient *udpdst;
{
   const char *function = "initclient()";
   struct sockaddr_storage toaddr;
   socklen_t len;

   slog(LOG_DEBUG, "%s: from %s to %s",
        function,
        sockaddr2string(from, NULL, 0),
        sockshost2string(to, NULL, 0));

   bzero(udpdst, sizeof(*udpdst));

   /*
    * Create a new socket and use that for sending out packets
    * from this client only.  When reading replies on this socket,
    * we will thus know who it's destined for (from).
    * Since we place no bound on the number of udp clients we
    * handle, we need to make sure we leave room for at least
    * SOCKD_IOMAX tcp clients, so we don't fail on recvmsg(2)
    * when mother sends us a new tcp client.
    */
   errno     = 0;
   udpdst->s = -1;
   if (freefds  <= ((SOCKD_IOMAX - 1) * FDPASS_MAX)
   || (udpdst->s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
      snprintf(emsg, emsglen, "could not create udp socket: %s",
               errno != 0 ? strerror(errno) : strerror(EMFILE));
      swarnx("%s: %s", function, emsg);

      if (udpdst->s != -1)
         close(udpdst->s);

      return NULL;
   }

   if (sockshost2sockaddr(to, TOSA(&toaddr)) == NULL) {
      snprintf(emsg, emsglen, "could not resolve %s: %s",
               sockshost2string(to, NULL, 0), hstrerror(h_errno));

      close(udpdst->s);
      return NULL;
   }

   setsockoptions(udpdst->s, SOCK_DGRAM, 0);

   SET_SOCKADDR(TOSA(&udpdst->laddr), AF_INET);
   TOIN(&udpdst->laddr)->sin_port   = htons(0);
   TOIN(&udpdst->laddr)->sin_addr   = getoutaddr(TOCIN(from)->sin_addr,
                                                 TOCIN(&toaddr)->sin_addr);

   if (sockd_bind(udpdst->s, TOSA(&udpdst->laddr), 0) != 0) {
      snprintf(emsg, emsglen, "could not bind udp address %s (%s)",
               sockaddr2string(TOSA(&udpdst->laddr), NULL, 0), strerror(errno));
      swarnx("%s: %s", function, emsg);

      if (udpdst->s != -1)
         close(udpdst->s);

      return NULL;
   }

   len = sizeof(udpdst->laddr);
   if (getsockname(udpdst->s, TOSA(&udpdst->laddr), &len) != 0) {
      snprintf(emsg, emsglen, "getsockname() on socket failed: %s",
               strerror(errno));
      swarnx("%s: %s", function, emsg);

      if (udpdst->s != -1)
         close(udpdst->s);

      return NULL;
   }

   gettimeofday(&udpdst->lastio, NULL);
   udpdst->firstio = udpdst->lastio;
   sockaddrcpy(TOSA(&udpdst->client), from, sizeof(udpdst->client));
   udpdst->host    = *to;

   --freefds;
   return udpdst;
}

static size_t
io_udpclients(void)
{
   const char *function = "io_udpclients()";
   size_t i, allocated;

   for (i = 0, allocated = 0; i < ioc; ++i) {
      if (!iov[i].allocated)
         continue;

      if (iov[i].state.protocol != SOCKS_UDP)
         continue;

      SASSERTX(iov[i].dst.dstc >= DUMMY_INDEX + 1);
      allocated += (iov[i].dst.dstc - (DUMMY_INDEX + 1));
   }

   slog(LOG_DEBUG, "%s: have %lu udp client%s",
   function, (unsigned long)allocated, allocated == 1 ? "" : "s");

   return allocated;
}

static struct udpclient *
clientofsocket(s, udpclientc, udpclientv)
   const int s;
   const size_t udpclientc;
   struct udpclient *udpclientv;
{
   static size_t i = DUMMY_INDEX + 1;

   if (i < udpclientc && udpclientv[i].s == s)
      return &udpclientv[i];

   for (i = DUMMY_INDEX + 1; i < udpclientc; ++i)
      if (udpclientv[i].s == s)
         return &udpclientv[i];

   return NULL;
}

static struct udpclient *
clientofclientaddr(addr, udpclientc, udpclientv)
   const struct sockaddr *addr;
   const size_t udpclientc;
   struct udpclient *udpclientv;
{
   size_t i;

   for (i = 0; i < udpclientc; ++i) {
      if (udpclientv[i].s == -1)
         continue;

      if (sockaddrareeq(TOCSA(addr), TOSA(&udpclientv[i].client)))
         return &udpclientv[i];
   }

   return NULL;
}

static struct udpclient *
addclient(client, clientladdr, clientc, maxclientc, clientv, state, rule)
   const struct udpclient *client;
   const struct sockaddr *clientladdr;
   size_t *clientc;
   size_t *maxclientc;
   struct udpclient **clientv;
   const connectionstate_t *state;
   const struct rule_t *rule;
{
   const char *function = "addclient()";
   iologaddr_t src, dst;

   char client_str[MAXSOCKADDRSTRING],
        laddr_str[MAXSOCKADDRSTRING],
        raddr_str[MAXSOCKSHOSTSTRING];

   slog(LOG_DEBUG,
        "%s: adding client on socket %d: client %s, bound %s, dst %s (%s).  "
        "New clientc will become %lu, new free fds will become %d.  ",
        function,
        client->s,
        sockaddr2string(TOCSA(&client->client), client_str, sizeof(client_str)),
        sockaddr2string(TOCSA(&client->laddr), laddr_str, sizeof(laddr_str)),
        sockshost2string(&client->host, raddr_str, sizeof(raddr_str)),
        sockshost2string(&client->host, NULL, 0),
        (unsigned long)*clientc + 1, freefds - 1);

   if (*clientc >= *maxclientc) {
      struct udpclient *pv;

      if ((pv = realloc(*clientv, (*maxclientc + UDP_MEMBLOCK) * sizeof(*pv)))
      == NULL) {
         swarn("%s: failed to allocate memory for new udp client from %s",
               function, sockaddr2string(TOCSA(&client->client), NULL, 0));
         return NULL;
      }

      if (pv != *clientv) {
         *clientv = pv;
         update_clientpointers(*clientc, *clientv);
      }

      *maxclientc += UDP_MEMBLOCK;

      slog(LOG_DEBUG, "%s: reallocated memory for udp clients, have memory "
                      "for %lu clients now",
                      function, (unsigned long)*maxclientc);

   }

   (*clientv)[*clientc] = *client;

   init_iologaddr(&src,
                  SOCKADDR_OBJECT,
                  clientladdr,
                  SOCKADDR_OBJECT,
                  &client->client,
                  NULL,
                  NULL,
                  0);

   init_iologaddr(&dst,
                  SOCKADDR_OBJECT,
                  &client->laddr,
                  SOCKSHOST_OBJECT,
                  &client->host,
                  NULL,
                  NULL,
                  0);

   iolog(rule,
         state,
         OPERATION_CONNECT,
         &src,
         &dst,
         NULL,
         NULL,
         NULL,
         0);

   return &(*clientv)[(*clientc)++];
}

static int
removeclient(s, clientc, clientv)
   const int s;
   size_t *clientc;
   struct udpclient *clientv;
{
   const char *function = "removeclient()";
   char client_str[MAXSOCKADDRSTRING],
        laddr_str[MAXSOCKADDRSTRING],
        raddr_str[MAXSOCKSHOSTSTRING];
   size_t i;

   for (i = DUMMY_INDEX + 1; i < *clientc; ++i)
      if (clientv[i].s == s) {
         slog(LOG_DEBUG,
              "%s: removing client at index %lu on socket %d using rule %lu.  "
              "client address %s, bound %s, dst %s.  "
              "New clientc will become %lu and free fds will become %d  ",
              function,
              (unsigned long)i,
              clientv[i].s,
              (unsigned long)clientv[i].rule.crule->number,
              sockaddr2string(TOSA(&clientv[i].client),
                              client_str,
                              sizeof(client_str)),
              sockaddr2string(TOSA(&clientv[i].laddr), laddr_str, sizeof(laddr_str)),
              sockshost2string(&clientv[i].host, raddr_str, sizeof(raddr_str)),
              (unsigned long)*clientc - 1, freefds + 1);

         close(clientv[i].s);
         ++freefds;

         SHMEM_UNUSE(clientv[i].rule.crule,
                     TOSA(&clientv[i].client),
                     sockscf.shmemfd,
                     SHMEM_ALL);

         memmove(&clientv[i],
                 &clientv[i + 1],
                 sizeof(*clientv) * (*clientc - (i + 1)));
         --(*clientc);

         update_clientpointers(*clientc, clientv);

         return 0;
      }

   if (s == clientv[DUMMY_INDEX].s) { /* removing the whole session. */
      --(*clientc);
      return 0;
   }

   /* NOTREACHED */
   SERRX(0);
}

static void
update_clientpointers(dstc, dstv)
   const size_t dstc;
   struct udpclient *dstv;
{
   size_t i;

   for (i = DUMMY_INDEX + 1; i < dstc; ++i)
      dstv[i].rule.crule = &dstv[i].crule;
}

static rawsocketstatus_t
rawsocket_recv(s)
   const int s;
{
   const char *function = "rawsocket_recv()";
   struct udpclient *client;
   struct icmp *icmp;
   struct ip *ip;
   struct udphdr *udp;
   in_port_t uh_dport, uh_sport;
   struct sockaddr_storage addr;
   socklen_t addrlen;
   ssize_t r;
   size_t ioi;
   char packet[MAX_ICMPLEN], fromstr[16];

   addrlen = sizeof(addr);
   if ((r = recvfrom(s, packet, sizeof(packet), 0, TOSA(&addr), &addrlen)) == -1) {
      swarn("%s: recvfrom() on raw socket %d failed", function, s);
      return RAWSOCKET_NOP;
   }

   if (r < MIN_ICMPLEN)    {
      swarn("%s: short read on recvfrom() from raw socket: %ld/%lu",
            function, (long)r, (unsigned long)MIN_ICMPLEN);

      return RAWSOCKET_NOP;
   }

   ip   = (struct ip *)packet;
   icmp = (struct icmp *)(packet + (ip->ip_hl << 2));

   if (r < (ip->ip_hl << 2)) {
      swarn("%s: strange ... kernel says ip hl in packet from %s is %d, "
            "but read packet size is %ld.  Are we reading too little?",
            function, sockaddr2string(TOSA(&addr), NULL, 0), ip->ip_hl << 2, (long)r);

      return RAWSOCKET_NOP;
   }

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG,
           "%s: received raw packet from %s, type/code %d/%d, length %ld",
           function,
           inet_ntop(AF_INET,
                     &(TOIN(&addr)->sin_addr),
                     fromstr,
                     sizeof(fromstr)),
           icmp->icmp_type, icmp->icmp_code, (long)r);

   if (icmp->icmp_type != ICMP_UNREACH)
      return RAWSOCKET_NOP;

   /* ip-packet the icmp error is in reply to. */
   ip = (struct ip *)(icmp->icmp_data);

   if (ip->ip_p != IPPROTO_UDP)
      return RAWSOCKET_NOP;

   udp                  = (struct udphdr *)((char *)ip + (ip->ip_hl << 2));
   uh_dport             = udphdr_dport(udp);
   uh_sport             = udphdr_sport(udp);
   TOIN(&addr)->sin_addr= ip->ip_src;
   TOIN(&addr)->sin_port= uh_dport;

   /*
    * Figure out of the icmp error is related to a packet we sent.
    * Two possibilities if so:
    *    1: Response to udp packet forwarded by us from client to target:
    *       - Addr and dstport in error packet should match a target address.
    *       - Srcport should match srcport of a laddr we use for forwarding
    *         packets to the given target address.
    *
    *    2: Response to udpreply forwarded by us from target to client:
    *       - Addr and dstport in error packet should match a client addr.
    *       - Srcport should match a address we listen on.
    */

   client = NULL;
   for (ioi = 0; ioi < ioc; ++ioi) {
      if (iov[ioi].state.protocol != SOCKS_UDP)
         continue;

      /*
       * Check possibility 2 first.
       */
      if ((client = clientofclientaddr(TOSA(&addr),
                                       iov[ioi].dst.dstc,
                                       iov[ioi].dst.dstv))
      != NULL) {
         slog(LOG_DEBUG, "%s: packet from %s matches a client ... checking "
                         "if srcport %u matches bound address too",
                         function, sockaddr2string(TOSA(&addr), NULL, 0),
                         ntohs(uh_sport));

         if (uh_sport == TOIN(&iov[ioi].src.laddr)->sin_port)
            break;
         else {
            slog(LOG_DEBUG, "%s: packet from %s matches a client address, but "
                            "the srcport %u does not match the %u port bound "
                            "by us",
                            function, sockaddr2string(TOSA(&addr), NULL, 0),
                            ntohs(uh_sport),
                            ntohs(TOIN(&iov[ioi].src.laddr)->sin_port));

            client = NULL;
         }
      }

      if (sockaddrareeq(TOSA(&iov[ioi].dst.raddr), TOSA(&addr)) == 0) {
         size_t dsti;

         slog(LOG_DEBUG, "%s: packet from %s matches a target ... checking "
                         "if srcport %u matches a laddr address too",
                         function, sockaddr2string(TOSA(&addr), NULL, 0),
                         ntohs(uh_sport));

         SASSERTX(client == NULL);

         for (dsti = 0; dsti < iov[ioi].dst.dstc; ++dsti) {
            if (iov[ioi].dst.dstv[dsti].s == -1)
               continue;

            if (uh_sport == TOIN(&iov[ioi].dst.dstv[dsti].laddr)->sin_port) {
               client = &iov[ioi].dst.dstv[dsti];
               break;
            }
         }

         if (client != NULL) { /* found our match. */
            SASSERTX(dsti < iov[ioi].dst.dstc);
            break;
         }
      }
   }

   if (client != NULL) {
      SASSERTX(ioi < ioc);

      slog(LOG_DEBUG, "%s: removing client %s from iov #%lu",
           function,
           sockaddr2string(TOSA(&client->client), NULL, 0),
           (unsigned long)ioi);

      SYNC_UDP(&iov[ioi], client);
      delete_io(-1 /* nothing to ack */, &iov[ioi], client->s, IO_CLOSE);

      return RAWSOCKET_IO_DELETED;
   }

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: icmp packet is in response to udp packet to %s.  "
                      "Not an address known to us",
                      function, sockaddr2string(TOSA(&addr), NULL, 0));

   return RAWSOCKET_NOP;
}

#elif COVENANT /* !BAREFOOT */

int
recv_resentclient(s, client)
   int s;
   sockd_client_t *client;
{
   const char *function = "recv_resentclient()";
   struct iovec iov[2];
   struct msghdr msg;
   int ioc, fdexpect, fdreceived, r;
   CMSG_AALLOC(cmsg, sizeof(int));

   ioc = 0;
   bzero(iov, sizeof(iov));
   iov[ioc].iov_base = client;
   iov[ioc].iov_len  = sizeof(*client);
   ++ioc;

   bzero(&msg, sizeof(msg));
   msg.msg_iov     = iov;
   msg.msg_iovlen  = ioc;
   msg.msg_name    = NULL;
   msg.msg_namelen = 0;

   /* LINTED pointer casts may be troublesome */
   CMSG_SETHDR_RECV(msg, cmsg, CMSG_MEMSIZE(cmsg));

   if ((r = recvmsgn(s, &msg, 0)) < (ssize_t)sizeof(*client)) {
      switch (r) {
         case -1:
            swarn("%s: recvmsg() failed", function);
            break;

         case 0:
            slog(LOG_DEBUG, "%s: recvmsg(): other side closed connection",
            function);
            break;

         default:
            swarnx("%s: recvmsg(): unexpected short read: %d/%ld",
                   function, r, (long)sizeof(*client));
      }

      return -1;
   }

   if (socks_msghaserrors(function, &msg))
      return -1;

   r       -= sizeof(*client);
   fdexpect = 1; /* client. */

   if (!CMSG_RCPTLEN_ISOK(msg, sizeof(int) * fdexpect)) {
      swarnx("%s: received control message has the invalid len of %d",
              function, (int)CMSG_TOTLEN(msg));

      return -1;
   }

   SASSERTX(cmsg->cmsg_level == SOL_SOCKET);
   SASSERTX(cmsg->cmsg_type  == SCM_RIGHTS);

   fdreceived = 0;
   if (fdexpect > 0) {
      SASSERTX(fdexpect == 1);
      CMSG_GETOBJECT(client->s, cmsg, sizeof(client->s) * fdreceived++);

      if (sockscf.option.debug >= DEBUG_VERBOSE)
         slog(LOG_DEBUG, "%s: received socket %d (%s) ...",
         function, client->s, socket2string(client->s, NULL, 0));
   }

   if (sockscf.option.debug >= DEBUG_VERBOSE)
      slog(LOG_DEBUG, "%s: received %d descriptors for client",
                      function, fdreceived);

   return 0;
}

#endif /* COVENANT */
