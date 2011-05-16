dnl libscompat.m4 - tests related to replacement code in libscompat directory

AC_MSG_CHECKING([for __attribute__ support])
AC_TRY_RUN([
#include <stdlib.h>

void errfunc(void) __attribute((noreturn));

void errfunc(void)
{
    exit(0);
}

int main()
{
    errfunc();
}], [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_DEFINE(__attribute__(a), , [empty __attribute__ macro])])

AC_MSG_CHECKING([for __printf__ attribute support])
if test x"$have_suncc" = xt; then
    AC_MSG_RESULT([disabled for sun cc])
    AC_DEFINE(format(a,b,c), , [empty format attribute macro])
else
    AC_TRY_RUN([
#include <stdlib.h>

void func(const char *fmt, ...)
   __attribute__((format(__printf__, 1, 2)));

void func(const char *fmt, ...) {
     (void)fmt;
     return;
}

int main()
{
    func("foo");
    return 0;
}], [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_DEFINE(format(a,b,c), , [empty format attribute macro])])
fi

AC_MSG_CHECKING([for timer macros])
AC_TRY_RUN([
#include <sys/time.h>

int main()
{
    struct timeval tv, tv2, tv3;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    tv2.tv_sec = 0;
    tv2.tv_usec = 0;
    tv3.tv_sec = 0;
    tv3.tv_usec = 0;

    timeradd(&tv, &tv2, &tv3);
    timersub(&tv3, &tv2, &tv);

    return 0; }],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_TIMER_MACROS, 1, [timeradd(), timersub etc. exist in sys/time.h])],
[AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for SIOCGIFHWADDR])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#ifndef SIOCGIFHWADDR
#error "SIOCGIFHWADDR not defined"
#endif
], [ 
struct ifreq ifr;
unsigned char c;

c = 0;
memcpy(c, ifr.ifr_hwaddr.sa_data, 1);],
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SIOCGIFHWADDR, 1, [have MAC retrieval interface])],
 [AC_MSG_RESULT(no)
  AC_DEFINE(HAVE_SIOCGIFHWADDR, 0, [missing MAC retrieval interface])])

AC_CHECK_FUNCS(daemon difftime getifaddrs freeifaddrs hstrerror inet_aton)
AC_CHECK_FUNCS(inet_pton issetugid memmove seteuid setegid)
AC_CHECK_FUNCS(setproctitle sockatmark strvis vsyslog)
AC_CHECK_FUNCS(bzero strlcpy backtrace)
#inet_ntoa - only checked for incorrect behavior

#try to detect gcc bug (irix 64 problem, affects among others inet_ntoa)
AC_MSG_CHECKING([for incorrect inet_ntoa behaviour])
AC_TRY_RUN([
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void)
{
    struct sockaddr_in addr;
    char *a, *b = "195.195.195.195";
    addr.sin_addr.s_addr = inet_addr(b);
    a = inet_ntoa(addr.sin_addr);
    if (strcmp(a, b) == 0)
	return 1;
    else
	return 0;
}
], [AC_DEFINE(HAVE_BROKEN_INET_NTOA, 1, [platform bug])
    AC_MSG_RESULT(yes)
    ac_cv_func_inet_ntoa=no],
    AC_MSG_RESULT(no))

if test x${ac_cv_func_sockatmark} = xyes; then
   AC_MSG_CHECKING([for working sockatmark])
   AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>

int
main()
{
    int s;
    int r;

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	return 1;
    if ((r = sockatmark(s)) == -1)
	return 1;
    return 0;
}], [AC_MSG_RESULT(yes)],
    [AC_MSG_RESULT(no)
     ac_cv_func_sockatmark=no])
fi

#only compile files that are needed
unset LIBSCSRC
for func in daemon difftime getifaddrs hstrerror inet_aton inet_ntoa    \
            inet_pton issetugid memmove seteuid setproctitle sockatmark \
            strlcpy strvis vsyslog; do
    var=ac_cv_func_${func}
    if test ! -s "libscompat/${func}.c"; then
	AC_MSG_WARN([error: libscompat file for $func missing])
	exit 1
    fi
    if eval "test x\"\$${var}\" = xno"; then
	LIBSCSRC="${LIBSCSRC}${LIBSCSRC:+ }${func}.lo"
    fi
done
AC_SUBST([LIBSCSRC])

if test x${ac_cv_func_bzero} = xno; then
    AC_DEFINE(bzero(b, len), memset((b), 0, (len)), [bzero replacement])
fi

m4_ifdef([dantebuild], [
#causes problems with packaging, allow test to be turned off
AC_ARG_WITH(glibc-secure,
[  --without-glibc-secure  disable libc_enable_secure check @<:@default=detect@:>@],
[GLIBCSEC=$withval])

if test "${GLIBCSEC}" != no; then
    AC_MSG_CHECKING([for __libc_enable_secure])
    AC_TRY_RUN([
extern int __libc_enable_secure;

int main()
{
    if (__libc_enable_secure == 0)
	return 0;

	return 1;
}],[AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_LIBC_ENABLE_SECURE, 1, [linux version of issetugid()])],
    AC_MSG_RESULT([no]))
fi
],
[AC_DEFINE(HAVE_LIBC_ENABLE_SECURE, 0, [not used])])
if test x"$GLIBCSEC" = xno; then
   AC_DEFINE(HAVE_LIBC_ENABLE_SECURE_DISABLED, 1, [glibc variable disable])
fi
