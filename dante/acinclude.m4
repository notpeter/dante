# -- acinclude start --

AC_DEFUN([L_UNCON_SELECT],
[AC_MSG_CHECKING(for correct select behaviour on unconnected sockets)
AC_TRY_RUN([
/*
 * ftp.inet.no:/pub/home/michaels/stuff/unconnectedsocket-select.c
 * $ cc unconnectedsocket-select.c && uname -a && ./a.out
 * Modified by Eric Anderson <anderse@hpl.hp.com>
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

static int
selectcheck(int s);

int
main(void)
{
        char foo[5];
	int s, p;
	struct sigaction act;
	int res;
	
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE,&act,NULL);
	fprintf(stderr, "testing with a normal, unconnected socket:\n");
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		exit(1);
	}
	fprintf(stderr, "  created socket, select() returned %d\n",
	       selectcheck(s));
	p = read(s, NULL, 0);
	fprintf(stderr, "  read() returned %d, errno = %d (%s)\n", p, errno, (strerror(errno)));
	p = write(s, foo, 5);
	fprintf(stderr, "  write() returned %d, errno = %d (%s)\n", p, errno, (strerror(errno)));

	fprintf(stderr, "testing with a non-blocking, unconnected socket:\n");
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		exit(1);
	}
	if ((p = fcntl(s, F_GETFL, 0)) == -1
	    || fcntl(s, F_SETFL, p | O_NONBLOCK) == -1) {
	        perror("fcntl()");
	        exit(1);
	}
	res = selectcheck(s);
	fprintf(stderr, "  socket nonblocking, select() returned %d\n", res);

	p = read(s, NULL, 0);
	fprintf(stderr, "  read() returned %d, errno = %d (%s)\n", p, errno, (strerror(errno)));
	p = write(s, &foo, 5);
	fprintf(stderr, "  write() returned %d, errno = %d (%s)\n", p, errno, (strerror(errno)));

	if (res == 0)
		return 0; /* correct behaviour */
	else
		return 1; /* incorrect behaviour */
}

static int 
selectcheck(s)
	int s;
{
	fd_set rset, wset, xset;
	struct timeval timeout;
	int ret,i;

	FD_ZERO(&rset);
	FD_SET(s, &rset);
	wset = xset = rset;

	timeout.tv_sec 	= 0;
	timeout.tv_usec 	= 0;

	errno = 0;
	ret = select(s + 1, &rset, &wset, &xset, &timeout);
	if (FD_ISSET(s,&rset)) {
	    fprintf(stderr, "  socket is readable\n");
	}
	if (FD_ISSET(s,&wset)) {
	    fprintf(stderr, "  socket is writeable\n");
	}
	if (FD_ISSET(s,&xset)) {
	    fprintf(stderr, "  socket has an exception\n");
	}
	return ret;
}], [AC_MSG_RESULT(yes)
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