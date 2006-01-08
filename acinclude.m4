# -- acinclude start --
define([concat],
[$1$2]) dnl XXX likely a simpler way to do this
AC_DEFUN([L_MODVER],
[AC_MSG_CHECKING(for module $1)
 if test -f "licensed/$1.c"; then
	dnl XXX two single quotes in first argument to split,
	dnl     prevents removal by m4
	MODVERSION=`awk '/Id:/{ split($''4,a,".");print a[[2]]; exit }' licensed/$1.c`
	if test "$MODVERSION" -lt "$2"; then
	        echo ""
		echo "You have a outdated version of the $1 module."
		echo "Please contact Inferno Nettverk A/S for an updated"
		echo "version before you attempt to compile."
		echo "Inferno Nettverk A/S can be reached at info@inet.no."
		echo ""
		echo "There is no additional cost for upgrading."
		exit 1
	fi

	unset concat(MOD_, m4_toupper($1))
	AC_DEFINE(concat(HAVE_MODULE_, m4_toupper($1)), 1, [module $1 installed])dnl
	AC_MSG_RESULT(yes)
else
	concat(MOD_, m4_toupper($1))=un
	AC_MSG_RESULT(no)
fi
AC_LINK_FILES(${concat(MOD_, m4_toupper($1))}licensed/$1.c, sockd/$1.c)
if test x"$3" != xnokey; then
    AC_LINK_FILES(${concat(MOD_, m4_toupper($1))}licensed/$1_key.c, sockd/$1_key.c)
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
	sigact.sa_flags 	= 0;
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
	addr.sin_family 		= AF_INET;
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

	timeout.tv_sec 	= 0;
	timeout.tv_usec 	= 0;

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

#can it really be this simple?
#nope, doesn't handle coff files which also have no underscore
AC_DEFUN([L_SYMBOL_UNDERSCORE],
[AC_MSG_CHECKING(for object file type)
AH_TEMPLATE([HAVE_NO_SYMBOL_UNDERSCORE], [platform symbol type])
AC_TRY_RUN([
/* look for ELF identification header at the start of argv[0] */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>

/*
 * ELF header, from ELF standard (Portable Formats Specification,
 *  Version 1.1).
 */
char elfheader[] = { 0x7f, 'E', 'L', 'F' };

int
main (argc, argv)
	int argc;
	char *argv[];
{
	int fd;
	int len = sizeof(elfheader);
	char header[len];

	if ((fd = open(argv[0], O_RDONLY, 0)) == -1) {
		perror("open");
		exit(1);
	}
	if (read(fd, header, len) != len) {
		perror("read");
		exit(1);
	}
	if (memcmp(header, elfheader, len) == 0)
		exit(0); /* pointy ears */
	else
		exit(1);
}
], [AC_MSG_RESULT(elf)
    AC_DEFINE(HAVE_NO_SYMBOL_UNDERSCORE)],
   [
	#XXX exceptions for coff platforms, should be detected automatically
	case $host in
		alpha*-dec-osf*)
			AC_DEFINE(HAVE_NO_SYMBOL_UNDERSCORE)
			AC_MSG_RESULT(coff)
			;;
		*-*-hpux*) #XXX apparently does not use underscore
			AC_DEFINE(HAVE_NO_SYMBOL_UNDERSCORE)
			AC_MSG_RESULT(a.out?)
			;;
		*)
			AC_MSG_RESULT(a.out)
			;;
	esac])])


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

# -- acinclude end --