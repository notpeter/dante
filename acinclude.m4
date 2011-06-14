# -- acinclude start --
define([concat],
[$1$2]) dnl XXX likely a simpler way to do this
AC_DEFUN([L_MODVER],
[AC_MSG_CHECKING(for module $1)
 if test -f "licensed/$1.c"; then
	MINVER="$2"
	MODLINE=`head -1 licensed/$1.c | grep MODVER`
	if test x"$MODLINE" != x; then
		MODVER=`echo "$MODLINE" | cut -d: -f 2`
	fi

	dnl try old syntax if nothing returned
	dnl XXX two single quotes in first argument to split,
	dnl     prevents removal by m4
	if test x"$MODVER" = x; then
		MODVER=`awk '/Id:/{ split($''4,a,".");print a[[2]]; exit }' licensed/$1.c`
	fi
	if test "$MODVER" -lt "$MINVER"; then
		echo "" >&2
		echo "You have version 1.$MODVER of the $1 module, which is outdated." >&2
		echo "This version of Dante requires at least version 1.$MINVER." >&2
		echo "Please contact Inferno Nettverk A/S for an updated" >&2
		echo "version before you attempt to compile." >&2
		echo "Inferno Nettverk A/S can be reached at info@inet.no." >&2
		echo "" >&2
		echo "There is no additional cost for upgrading." >&2
		exit 1
	fi

	unset concat(MOD_, m4_toupper($1))
	AC_DEFINE(concat(HAVE_MODULE_, m4_toupper($1)), 1, [module $1 installed])dnl
	AC_MSG_RESULT(yes)
else
	concat(MOD_, m4_toupper($1))=un
	AC_MSG_RESULT(no)
fi
AC_LINK_FILES(${concat(MOD_, m4_toupper($1))}licensed/$1.c, $3/$1.c)
if test x"$4" != xnokey; then
    AC_LINK_FILES(${concat(MOD_, m4_toupper($1))}licensed/$1_key.c, $3/$1_key.c)
fi
])


AC_DEFUN([L_UNCON_SELECT],
[AC_MSG_CHECKING(for expected select behaviour)
AC_RUN_IFELSE([[
/*
 * ftp.inet.no:/pub/home/michaels/stuff/socket-select.c
 * $ cc socket-select.c && uname -a && ./a.out
 *
 * Thanks to Eric Anderson <anderse@hpl.hp.com>.
 *
*/

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#define BLOCKING(b)	(b ? ("blocking") : ("non-blocking"))

static int selectcheck(int s);
static int dotests(int s, int blocking);

int
main(void)
{
	int s, p;
	struct sigaction sigact;

	sigemptyset(&sigact.sa_mask);
	sigact.sa_handler = SIG_IGN;
	sigact.sa_flags	= 0;
	if (sigaction(SIGPIPE, &sigact, NULL) != 0) {
		perror("sigaction()");
		exit(1);
	}

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		exit(1);
	}

	if ((p = fcntl(s, F_GETFL, 0)) == -1
	|| fcntl(s, F_SETFL, p | O_NONBLOCK) == -1) {
		perror("fcntl()");
	   exit(1);
	}

	p = dotests(s, 0);
	close(s);

	return p;
}


static int
dotests(s, blocking)
	int s;
	int blocking;
{
	int p, rc;
	struct sockaddr_in addr;

	fprintf(stderr, "testing with %s, bound, socket:\n", BLOCKING(blocking));
	bzero(&addr, sizeof(addr));
	addr.sin_family		= AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port			= htons(0);

	/* LINTED pointer casts may be troublesome */
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind(), running linux?");
		exit(1);
	}

	fprintf(stderr, "\tselect() returned %d\n", selectcheck(s));
	p = read(s, NULL, 0);
	fprintf(stderr, "\tread() returned %d, errno = %d (%s)\n",
	p, errno, (strerror(errno)));
	p = write(s, &s, sizeof(s));
	fprintf(stderr, "\twrite() returned %d, errno = %d (%s)\n",
	p, errno, (strerror(errno)));

	fprintf(stderr, "testing with %s, bound, listening, socket:\n", BLOCKING(blocking));
	if (listen(s, 1) != 0) {
		perror("listen()");
		exit(1);
	}
	fprintf(stderr, "\tselect() returned %d\n", rc = selectcheck(s));
	p = read(s, NULL, 0);
	fprintf(stderr, "\tread() returned %d, errno = %d (%s)\n",
	p, errno, (strerror(errno)));
	p = write(s, &s, sizeof(s));
	fprintf(stderr, "\twrite() returned %d, errno = %d (%s)\n",
	p, errno, (strerror(errno)));

	return rc;
}

static int
selectcheck(s)
	int s;
{
	fd_set rset, wset, xset;
	struct timeval timeout;
	int ret;

	FD_ZERO(&rset);
	FD_SET(s, &rset);
	wset = xset = rset;

	timeout.tv_sec		= 0;
	timeout.tv_usec	= 0;

	errno = 0;
	ret = select(s + 1, &rset, &wset, &xset, &timeout);

	if (FD_ISSET(s, &rset))
	    fprintf(stderr, "\tsocket is readable\n");

	if (FD_ISSET(s, &wset))
	    fprintf(stderr, "\tsocket is writeable\n");

	if (FD_ISSET(s, &xset))
	    fprintf(stderr, "\tsocket has an exception pending\n");

	return ret;
}]], [AC_MSG_RESULT(yes)
     [$1]],
    [AC_MSG_RESULT(no)
     [$2]])])


dnl addproto - generate AC_DEFINE statements
define([addproto],
[AC_DEFINE_UNQUOTED(HAVE_PROT_$1_$2, [$3], [proto])dnl
ifelse([$4], , , [addproto($1, m4_incr($2), m4_shiftn(3, $@))])])

dnl tproto - generate statements for running AC_COMPILE_IFELSE
define([tproto],
[AC_COMPILE_IFELSE([
 AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>
#include <unistd.h>

m4_esyscmd([echo "$3" | cut -d, -f 1])dnl
$1(m4_esyscmd([echo "$3" | cut -d, -f 2-]));], [])],
 [addproto(m4_toupper($1), 0, $3)
  AC_MSG_RESULT(ok)],
 [ifelse([$4], ,
  [AC_MSG_RESULT(failure)
  $2],
 [tproto([$1], [$2], m4_shiftn(3, $@))])])])

dnl L_NSOCKPROTO - determine function prototypes by compilation
AC_DEFUN([L_NSOCKPROTO],[
AC_REQUIRE([AC_COMPILE_IFELSE])dnl
AC_MSG_CHECKING([prototypes for $1])dnl

tproto($@)])

dnl tstdioproto - generate statements for running AC_COMPILE_IFELSE
define([tstdioproto],
[AC_COMPILE_IFELSE([
 AC_LANG_PROGRAM([
  #include <stdio.h>
 #include <stdarg.h>
 #ifdef $1
 #undef $1
 #endif

m4_esyscmd([echo "$3" | cut -d, -f 1])dnl
$1(m4_esyscmd([echo "$3" | cut -d, -f 2-]));], [])],
 [addproto(m4_toupper($1), 0, $3)
  AC_MSG_RESULT(ok)],
 [ifelse([$4], ,
  [AC_MSG_RESULT(failure)
  $2],
 [tstdioproto([$1], [$2], m4_shiftn(3, $@))])])])

dnl L_NSTDIOPROTO - determine stdio function prototypes by compilation
AC_DEFUN([L_NSTDIOPROTO],[
AC_REQUIRE([AC_COMPILE_IFELSE])dnl
AC_MSG_CHECKING([prototypes for $1])dnl

tstdioproto($@)])

dnl L_SHMEM - verify expected shared memory behavior
AC_DEFUN([L_SHMEM],
[AC_MSG_CHECKING(for expected shmem behaviour)
AC_RUN_IFELSE([[
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define SHMEM_ELEMENTS (1024)

void sighandler(int sig);


int
main(argc,argv)
   int argc;
   char *argv[];
{
   int *mem;
   key_t key;
   int id;

   key = getpid();
   if ((id = shmget(key, sizeof(*mem) * SHMEM_ELEMENTS,
   IPC_CREAT | IPC_EXCL | 0660)) == -1) {
      fprintf(stderr, "failed to allocate shmem segment using key %ld: %s\n",
      (long)key, strerror(errno));

      exit(1);
   }

   if ((mem = shmat(id, NULL, 0)) == (void *)-1) {
      fprintf(stderr, "failed to attach to shmem segment with id %d: %s\n",
      id, strerror(errno));

      exit(1);
   }

   memset(mem, 0xdeadbeef, sizeof(*mem) * SHMEM_ELEMENTS);
   mem[SHMEM_ELEMENTS - 2] = 0xfeedbabe;
   mem[SHMEM_ELEMENTS - 1] = 0xdeadbeef;


   fprintf(stderr, "allocated shmem segment of size %ld with id %d, using key %ld.\n"
          "Now testing if we can remove it, but still access it with the "
          "same contents\n",
          (long)(sizeof(*mem) * SHMEM_ELEMENTS), id, (long)key);

   if (shmctl(id, IPC_RMID, NULL) != 0) {
      fprintf(stderr, "failed to remove to shmem segment with id %d: %s\n",
      id, strerror(errno));

      exit(1);
   }

   if (signal(SIGSEGV, sighandler) == SIG_ERR) {
      fprintf(stderr, "failed to install handler for SIGSEGV: %s\n",
      strerror(errno));

      exit(1);
   }


   if (mem[SHMEM_ELEMENTS - 2] != 0xfeedbabe
   ||  mem[SHMEM_ELEMENTS - 1] != 0xdeadbeef) {
      fprintf(stderr, "contents changed.  "
                      "Old value was 0x%d, 0x%d, new is %0xd, 0x%x\n",
                      0xfeedbabe, 0xdeadbeef,
                      mem[SHMEM_ELEMENTS - 2], mem[SHMEM_ELEMENTS - 1]);

      exit(1);
   }

   fprintf(stderr, "yes, all is ok\n");
   return 0;
}

void
sighandler(int sig)
{

   fprintf(stderr, "oops, did not work\n");
   exit(1);
}
]], [AC_MSG_RESULT(yes)
     [$1]],
    [AC_MSG_RESULT(no)
     [$2]])])

# -- acinclude end --
