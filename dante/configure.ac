AC_INIT
AC_PREREQ(2.61)
AC_REVISION($Id: configure.ac,v 1.453.2.3.2.3.2.4 2011/03/03 20:17:06 karls Exp $)

version=1.2.3
#set this to enable prerelease, changes some defaults (debug enabled)
#prerelease="3"
if test x$prerelease != x; then
    prename="-pre$prerelease"
    TOPEXTRADIST="${TOPEXTRADIST} PRERELEASE"
else
    prename=""
fi

echo "Configuring Dante ${version}${prename}:"

AM_INIT_AUTOMAKE(dante, ${version}${prename})
AC_CONFIG_SRCDIR(include/common.h)
AM_CONFIG_HEADER(include/autoconf.h)

AC_DEFINE(BAREFOOTD, 0, [we are Dante])

#NOTE: save CFLAGS; wish to compile without -O2 when debugging
oCFLAGS=$CFLAGS
unset CFLAGS
AC_PROG_LIBTOOL
autoconf_compflags=$CFLAGS
CFLAGS=$oCFLAGS

if test x$prerelease != x; then
    AC_DEFINE(PRERELEASE, 1, [software prerelease])
else
    AC_DEFINE(PRERELEASE, 0, [software prerelease])
fi

AC_PROG_CPP

AM_CONDITIONAL(PRERELEASE, test x$prerelease != x)

#known keywords for --enable/disable-foo(=yes/no)?
LTINTERNAL="dlopen|dlopen_self|dlopen_self_static|fast_install|libtool_lock|win32_dll|shared_with_static_runtimes|shared_with_static_runtimes_CXX|shared_with_static_runtimes_F77|option_checking"
KNOWN_KEYWORDS="$LTINTERNAL|shared|static|debug|warnings|diagnostic|profiling|linting|libwrap|preload|serverdl|clientdl|internal|pidfile|drt_fallback|release|dependency_tracking|largefile"
for keyword in `set | egrep '^enable_' | sed -e 's/^enable_//' | \
                sed -e 's/=.*$//'`; do
    echo $keyword | egrep "^(${KNOWN_KEYWORDS})$" > /dev/null
    if test $? -ne 0; then
	AC_MSG_WARN([unknown option '$keyword', ignoring ...])
#	sleep 10;
    fi
done

case $host in
    *-*-osf*)
      	AC_MSG_WARN([OSF support might be removed in the near future.])
	AC_MSG_WARN([Please contact dante-bugs@inet.no if you are using this platform.])
	exit 1
	;;
esac

#disable acceptlock
#XXX add proper test for this?
case $host in
    *-*-*bsd* | alpha*-dec-osf* | *-*-hpux* | *-*-aix* | *-*-solaris*)
	no_acceptlock=t
	;;
esac

case $host in
    alpha*-dec-osf*)
	CPPFLAGS="${CPPFLAGS} -D_XOPEN_SOURCE_EXTENDED -DBYTE_ORDER=LITTLE_ENDIAN -D_POSIX_SOURCE -D_POSIX_C_SOURCE=199309L -D_OSF_SOURCE"
	;;

    *-*-hpux*)
	#HPUX needs _PROTOTYPES to include prototypes
	#for configure (for gcc and cc)
	CPPFLAGS="${CPPFLAGS} -D_PROTOTYPES"
	;;

    *-*-openbsd*)
	AC_DEFINE(HAVE_OPENBSD_BUGS, 1, [bug workaround])
	;;

    *-*-solaris*)
	AC_DEFINE(HAVE_SENDMSG_DEADLOCK, 1, [bug workaround])
	AC_DEFINE(HAVE_SOLARIS_BUGS, 1, [bug workaround])
	AC_DEFINE(BSD_COMP, 1, [enable BSD compatibility])
	AC_DEFINE(HAVE_SOLARIS_PAM_BUG, 1, [bug workaround])
	#for msghdr msg_flags
	CPPFLAGS="${CPPFLAGS} -D_XOPEN_SOURCE=500 -D_XOPEN_SOURCE_EXTENDED -D__EXTENSIONS__"
	;;

    *-*-linux-*) # XXX This might only concern 2.0.x kernels (add test?)
	AC_DEFINE(HAVE_DEFECT_RECVMSG, 1, [bug workaround])
	AC_DEFINE(HAVE_LINUX_BUGS, 1, [bug workaround])
	AC_DEFINE(HAVE_LINUX_ECCENTRICITIES, 1, [platform workarounds])
	CPPFLAGS="${CPPFLAGS} -D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED"
#	CPPFLAGS="${CPPFLAGS} -D_FORTIFY_SOURCE=2"
	CPPFLAGS="${CPPFLAGS} -D_BSD_SOURCE"
	if test x"$GCC" != x; then
		#XXX want to avoid extension used in struct cmsghdr
		CPPFLAGS="${CPPFLAGS} -U__GNUC__ -D__GNUC__=0"
	fi
	AC_DEFINE(SPT_PADCHAR, '\0', [setproctitle])
	;;

    *-*-aix*)
	OSPIDFILE="/etc/sockd.pid"
	AC_DEFINE(HAVE_SYSTEM_XMSG_MAGIC, 1, [platform workaround])
	AC_DEFINE(_ALL_SOURCE, 1, [contents from old AC_AIX test])
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS+ } -DXOPEN_SOURCE_EXTENDED=1"
	;;
esac

#XXX add proper test for this?
if test x$no_acceptlock != xt; then
    AC_DEFINE(NEED_ACCEPTLOCK, 1, [platform workaround])
fi

AC_MSG_CHECKING([for compiler flags])
case $host in
    #XXX check for compiler type, not architecture
    *-*-solaris*)
	if test "x$GCC" = x; then
	    #-xs provides allows easier debugging with gdb
	    comp_flags="-Xt -xs" #XXX -Xt needed to compile?
	    #XXX due to some problems with sockaddr alignment
	    #XXX sun cc needs -misalign
#	    comp_flags="$comp_flags -misalign -xO0"
#	    AC_MSG_RESULT([$comp_flags])
#	    AC_MSG_WARN([there might currenly be some performance problems with suncc - it needs -misalign])
	    have_suncc=t
	    $CC 2>&1 | grep ucbcc > /dev/null
	    if test $? -eq 0; then
		#XXX ucbcc uses includes from /usr/ucbinclude, but these are
		#not complete. add /usr/include to include path to get
		#all prototypes (read/write are missing)
		#XXX
		CPPFLAGS="-I/usr/include $CPPFLAGS${CPPFLAGS:+ } "
	    fi
	fi
#	AC_MSG_RESULT([$comp_flags])
    ;;

    alphaev6-dec-osf*)
	if test "x$GCC" = x; then
	    comp_flags="-std1"
	fi
	AC_MSG_RESULT([$comp_flags])
    ;;

    alpha*-dec-osf*) #XXX is it possible to get it to work with -newc?
	if test "x$GCC" = x; then
	    comp_flags="-std1 -oldc"
	fi
	AC_MSG_RESULT([$comp_flags])
    ;;

    *-*-hpux*)
	if test "x$GCC" = x; then
	    CPPFLAGS="${CPPFLAGS} -D_XOPEN_SOURCE"
	    #XXX when cc is used as CPP it needs -Ae to work
	    #    for L_SOCKPROTO; add -Ae to CPPFLAGS.
	    #    This won't work if CPP is specified by hand
	    #    and is something else than cc (when CC is hp cc)
#	    comp_flags="-Ae"
	    CPPFLAGS="${CPPFLAGS} -Ae"
	fi
	AC_MSG_RESULT([$comp_flags])
	;;

    *)
	AC_MSG_RESULT([none])
    ;;
    #XXX make sure compiling with compiler options works
esac

AC_MSG_CHECKING([for support for -pipe compiler flag])
oCFLAGS=$CFLAGS
CFLAGS="$CFLAGS -pipe"
AC_TRY_RUN([
int main()
{
	return 0;
}], [AC_MSG_RESULT([yes])
     comp_flags="${comp_flags} -pipe"],
    AC_MSG_RESULT([no]))
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for support for -Wbounded compiler flag])
oCFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Wbounded"
AC_TRY_RUN([
int main()
{
        return 0;
}], [AC_MSG_RESULT([yes])
     comp_flags="${comp_flags} -Wbounded"],
    [AC_MSG_RESULT([no])
     AC_DEFINE(__bounded__(a,b,c), , [empty __bounded__ macro])])
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for compilation with debugging])
AC_ARG_ENABLE(debug,
[  --enable-debug          compile with debugging support],
[debug_enabled=t],
[if test x$prerelease != x; then
    debug_enabled=t
 fi])

if test x$debug_enabled = xt; then
    #no optimization wanted
    if test $ac_cv_prog_cc_g = yes; then
	CFLAGS="$CFLAGS -g"
    fi
    CPPFLAGS="$CPPFLAGS${CPPFLAGS:+ }-DDEBUG=1"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
    #autoconf_compflags is set to "-g -O2" with GCC
    #override CFLAGS when running configure to avoid this
    CPPFLAGS="$CPPFLAGS${CPPFLAGS:+ }-DDEBUG=0"
    CFLAGS="$CFLAGS $autoconf_compflags"
fi

#-Wall ?
AC_MSG_CHECKING([for warning flags])
AC_ARG_ENABLE(warnings,
[  --enable-warnings       show compilation warnings],
[enable_warnings=t],
[if test x$prerelease != x; then
    enable_warnings=t
 fi])

#construct warning flags in $warn
if test x$enable_warnings != x; then
    #try to enable compiler specific warning flags
    if test "x$GCC" = x; then
	case $host in
	    alpha*-dec-osf*) #osf cc
#		warn="-w0 -check -portable -warnprotos"
		true
	    ;;

	    *-*-hpux*)
		warn="-v"
	    ;;

	    *-*-solaris*)
		warn="-v"
		true
	    ;;

	    *-*-irix*) #sgi cc
		warn="-fullwarn"
	    ;;

	    *) #try -Wall (gcc)
		warn="-Wall"
	    ;;
	esac
    else
	#gcc warnings
	warn="-Wall -Wformat -W -Wnested-externs -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wcast-align -Wcast-qual -Wbad-function-cast -Wpointer-arith -Wundef"
	#warn="$warn -Wold-style-cast -Winline -Waggregate-return -Wconversion -Wwrite-strings -Wtraditional -Wshadow"
    fi

    oCFLAGS=$CFLAGS
    CFLAGS="$CFLAGS $warn"
    #make sure compilation is still possible
    AC_TRY_COMPILE([], [],
		   [AC_MSG_RESULT([$warn])],
		   [AC_MSG_RESULT([none])
		    unset warn])
    CFLAGS=$oCFLAGS
else
    AC_MSG_RESULT([none])
fi

#NOTE: set warnings at the bottom; might interfere with tests
CFLAGS="$CFLAGS $comp_flags"

#-DDIAGNOSTICS?
AC_MSG_CHECKING([for compliation with DIAGNOSTIC])
AH_TEMPLATE([DIAGNOSTIC], [for debugging])
AC_ARG_ENABLE(diagnostic,
[  --enable-diagnostic     enable diagnostic],
[AC_DEFINE(DIAGNOSTIC, 1)
 AC_MSG_RESULT([yes])],
[if test x$prerelease != x; then
    AC_DEFINE(DIAGNOSTIC, 1)
    AC_MSG_RESULT([yes])
 else
    AC_DEFINE(DIAGNOSTIC, 0)
    AC_MSG_RESULT([no])
 fi])

AC_MSG_CHECKING([for profiled compilation])
AC_ARG_ENABLE(profiling,
[  --enable-profiling      compile with profiling support in server],
[AC_DEFINE(HAVE_PROFILING, 1, [for profiling])
 LDFLAGS="$LDFLAGS${LDFLAGS:+ } -pg"
 CFLAGS="$CFLAGS${CFLAGS:+ } -pg -DPROFILING"
 AC_MSG_RESULT([yes])

 case $host in
     *-*-openbsd* | *-*-freebsd*)
         #static linking, disable server preloading
      	 no_preload_server=t
	 #openbsd and freebsd appear to be happier if -lc is included
	 #when profiling is enabled
	 LIBS="$LIBS${LIBS:+ }-lc"
	 ;;
 esac],
[AC_MSG_RESULT([no])])

AC_ARG_ENABLE(linting,
[  --enable-linting        enable lint],
[AC_CHECK_PROG(LINT, lint, lint)
 if test x"$LINT" = x; then
     AC_MSG_WARN([linting requested, but lint not found])
 else
     s_linting=t
     LINTFLAGS=-abcebiprxz
 fi])
AM_CONDITIONAL(RUNLINT, test x$s_linting = xt)
AC_SUBST(LINT)
AC_SUBST(LINTFLAGS)

AC_MSG_CHECKING([whether libwrap should be disabled])
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       never use libwrap, even if it is available],
[if test x$enableval = xno; then
    no_libwrap=t
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi], AC_MSG_RESULT([no]))

dnl Checks for programs.
AC_PROG_YACC
AC_PROG_AWK
AM_PROG_LEX

dnl Checking variable sizes
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)

dnl Checks for header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h limits.h malloc.h paths.h strings.h syslog.h)
AC_CHECK_HEADERS(unistd.h crypt.h sys/file.h sys/ioctl.h sys/time.h)
AC_CHECK_HEADERS(tcpd.h shadow.h ifaddrs.h sys/sem.h netinet/in.h)
AC_CHECK_HEADERS(sys/ipc.h arpa/nameser.h net/if_dl.h execinfo.h)

case $host in
    #XXX only check for priv.h support on solaris for now
    *-*-solaris*)
	AC_CHECK_HEADERS(priv.h,
	    [AC_DEFINE(HAVE_PRIVILEGES, 1, [Some privilege type supported])
	     AC_DEFINE(HAVE_SOLARIS_PRIVS, 1, [Solaris priv.h support])])
	;;
esac

AC_CHECK_HEADERS([netinet/ip_var.h], [], [], [
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])

AC_CHECK_HEADERS([resolv.h], [], [], [
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
])

case $host in
    alpha*-dec-osf*)
	AC_CHECK_HEADERS(netinet/ip.h)
	;;

    *) ;;
esac

#allow default file locations to be overridden
AC_MSG_CHECKING([for config file location])
AC_ARG_WITH(socks-conf,
[  --with-socks-conf=FILE  change location of socks client configuration file],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKS_CONFIGFILE, 1, [alternate location])
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKS_CONFIGFILE, "$withval", [alternate location])],
[AC_MSG_RESULT(default)])

AC_MSG_CHECKING([for sockd config file location])
AC_ARG_WITH(sockd-conf,
[  --with-sockd-conf=FILE  change location of socks server configuration file],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKD_CONFIGFILE, 1, [alternate location])
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_CONFIGFILE, "$withval", [alternate location])],
[AC_MSG_RESULT(default)])

#pidfile
AC_ARG_ENABLE(pidfile,
[  --disable-pidfile       disable server pidfile creation],
[AC_DEFINE(HAVE_DISABLED_PIDFILE, 1, [pidfile disabled])])

AC_MSG_CHECKING([for pid file location])
AH_TEMPLATE([HAVE_SOCKD_PIDFILE], [alternate location])
AH_TEMPLATE([HAVE_ALT_SOCKD_PIDFILE], [alternate location])
AC_ARG_WITH(pidfile,
[  --with-pidfile=FILE     change location of server pidfile],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKD_PIDFILE, 1)
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_PIDFILE, "$withval")
 have_pidfile=t],
[AC_MSG_RESULT(default)])

#os default?
if test x"${have_pidfile}" != xt; then
    if test x"$OSPIDFILE" != x; then
	AC_DEFINE(HAVE_SOCKD_PIDFILE, 1)
	AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_PIDFILE, "$OSPIDFILE")
    fi
fi

AC_CHECK_HEADER(sys/sockio.h,
[AC_DEFINE(HAVE_SYS_SOCKIO_H, 1, [sys/sockio.h exists])
 have_sys_sockio_h=t])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_MSG_CHECKING([whether <sys/types.h> defines const])
AC_EGREP_CPP(yes, [
#include <sys/types.h>
#ifdef const
yes
#endif
], [AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)
    check_const="yes"])
if test x$check_const = xyes; then
    AC_C_CONST
fi

#looks for linux + systems with RTAX_GATEWAY defined in net/route.h
AC_MSG_CHECKING([for supported routing socket communication])
AH_TEMPLATE([HAVE_ROUTE_SOURCE], [routing socket communication supported])
unset no_routeinfo
AC_EGREP_CPP(yes, [
#include <net/route.h>
#ifdef linux
yes
#endif /* linux */
], [AC_DEFINE(HAVE_ROUTE_SOURCE, 1)
    AC_DEFINE(HAVE_ROUTEINFO_LINUX, 1, [Linux type routing socket])
    AC_MSG_RESULT(yes)],
   [AC_EGREP_CPP(yes, [
#include <net/route.h>
#ifdef RTA_GATEWAY
yes
#endif /* RTA_GATEWAY */
],  [AC_DEFINE(HAVE_ROUTE_SOURCE, 1)
     AC_DEFINE(HAVE_ROUTEINFO_BSD, 1, [BSD type routing socket])
     AC_MSG_RESULT(yes)],
     [AC_MSG_RESULT([no, might result in reduced functionality])
      no_routeinfo=t])])

AC_MSG_CHECKING([whether <netdb.h> declares h_errno])
AC_EGREP_CPP(h_errno, [
#include <netdb.h>
], [AC_DEFINE(HAVE_H_ERRNO, 1, [netdb.h defines h_errno])
    AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)])

#XXXsys/socket.h?
AC_MSG_CHECKING([for struct ip_opts in <netinet/in.h>])
AC_EGREP_CPP([struct.*ipoption], [
#include <netinet/ip_var.h>
], [AC_DEFINE(HAVE_STRUCT_IPOPTS, 1, [ip_opts defined in netinet/in.h])
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING([whether <sys/types.h> defines inline])
AC_EGREP_CPP(yes, [
#include <sys/types.h>
#ifdef inline
yes
#endif
], [AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)
    check_inline="yes"])
if test x$check_inline="yes";then
    AC_C_INLINE
fi

AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

AC_SYS_LARGEFILE

#XXX
AC_DEFINE(HAVE_IPV6_SUPPORT, 0, [ipv6 not supported currently])

AC_MSG_CHECKING([for in6_addr])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
], [
struct in6_addr sin6;
], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_IN6_ADDR, 1, [in6_addr defined])],
   [AC_MSG_RESULT(no)])

AC_MSG_CHECKING([to see if openlog accepts LOG_PERROR])
AC_EGREP_CPP(yes, [
#include <syslog.h>
#ifdef LOG_PERROR
yes
#endif
], [AC_DEFINE(HAVE_OPENLOG_LOG_PERROR, 1, [openlog supports LOG_PERROR])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))

AC_MSG_CHECKING([to see if stdlib.h defines EXIT_FAILURE])
AC_EGREP_CPP(yes, [
#include <stdlib.h>
#ifdef EXIT_FAILURE
yes
#endif
], [AC_MSG_RESULT(yes)],
   [AC_DEFINE(NEED_EXIT_FAILURE, 1, [EXIT_FAILURE not defined in stdlib.h])
    AC_MSG_RESULT(no)])

#XXX actually checks if AF_UNIX should be used instead of AF_LOCAL
AC_MSG_CHECKING([whether <sys/socket.h> uses AF_UNIX])
AC_EGREP_CPP(yes, [
#include <sys/types.h>
#include <sys/socket.h>
#ifdef AF_LOCAL
#else
#ifdef AF_UNIX
yes
#endif
#endif
], [AC_DEFINE(NEED_AF_LOCAL, 1, [use AF_LOCATL, not AF_UNIX])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))

AC_MSG_CHECKING([for SIGINFO])
AC_EGREP_CPP(yes, [
#include <signal.h>
#ifdef SIGINFO
yes
#endif
], [AC_DEFINE(HAVE_SIGNAL_SIGINFO, 1, [signal.h defined SIGINFO])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))

AC_MSG_CHECKING([to see if MSG_WAITALL exists])
AC_EGREP_CPP(yes, [
#include <sys/socket.h>
#ifdef MSG_WAITALL
yes
#endif
], [AC_DEFINE(HAVE_MSG_WAITALL, 1, [sys/socket.h defines MSG_WAITALL])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))

#SO_SNDLOWAT
#irix 6.2 only seems to look at lowest 8 bit of value
#Solaris also seems to be broken (up to 2.6 atleast)
AC_MSG_CHECKING([whether a working SO_SNDLOWAT exists])
AC_EGREP_CPP(yes, [
#include <sys/socket.h>
#ifdef SO_SNDLOWAT
yes
#endif
], [
case $host in
    *bsd*)
	so_sndlowat=t
	;;

    *-osf*)
	so_sndlowat=t
	;;

    *-aix*)
	so_sndlowat=t
	;;
esac
if test "x${so_sndlowat}" = xt; then
    AC_DEFINE(HAVE_SO_SNDLOWAT, 1, [platform supports SO_SNDLOWAT socket option])
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(disabled)
    AC_MSG_WARN([performance in the server might be degraded without support for the SO_SNDLOWAT socket option])
fi], [AC_MSG_RESULT(no)
      AC_MSG_WARN([performance in the server might be degraded without support for the SO_SNDLOWAT socket option])])

AC_MSG_CHECKING([whether realloc with a NULL pointer calls malloc])
AC_TRY_RUN([
#include <stdlib.h>
#ifndef NULL
#define NULL (char *)0
#endif

int main()
{
	/* will assume this test doesn\'t fail because of lack of memory */
	if (realloc(NULL, 1) == NULL)
		return 1;
	else
		return 0;
}], [AC_MSG_RESULT(yes)],
    [AC_DEFINE(HAVE_NOMALLOC_REALLOC, 1, [realloc never calls malloc])
     AC_MSG_RESULT(no)])

AC_MSG_CHECKING([whether free can be called with NULL])
AC_TRY_RUN([
#include <stdlib.h>
#ifndef NULL
#define NULL (char *)0
#endif

int main()
{
	/* will assume core dump/seg fault if it doesn\'t work */
	free(NULL);
	return 0;
}], [AC_MSG_RESULT(yes)],
    [AC_DEFINE(HAVE_NONULL_FREE, 1, [free does not accept NULL parameter])
     AC_MSG_RESULT(no)])

#A good time to save the cache (preload code might fail)
AC_CACHE_SAVE

m4_include(preload.m4)

#construct SUBDIRS variable
SUBDIRS="sockd unlicensed example doc bin SPECS capi contrib"
if test "x${no_preload_client}" = x; then
    SUBDIRS="dlib $SUBDIRS"
fi
#include should be done before compilation to ensure that
#redefac is executed first
#lib handles yacc/lex generation for dlib/sockd
TOPSUBDIRS="$subdirs include libscompat lib $SUBDIRS"

AC_SUBST(TOPSUBDIRS)

AC_MSG_CHECKING([if getsockopt needs cast])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
int getsockopt(int, int, int, char *, int *);
], [ 1 ],
 [AC_DEFINE(NEED_GETSOCKOPT_CAST, 1, [getsockopt needs cast])
  AC_MSG_RESULT(yes)],
  AC_MSG_RESULT(no))

#include both <sys/ioctl.h> and <sys/sockio.h>?
if test x$have_sys_sockio_h = xt; then
	AC_MSG_CHECKING([to see if <sys/sockio.h> should be included])
	AC_EGREP_CPP(yes, [
#include <sys/ioctl.h>
#ifdef SIOCATMARK
#else
#include <sys/sockio.h>
#ifdef SIOCATMARK
yes
#endif
#endif
], [AC_DEFINE(NEED_SYS_SOCKIO_H, 1, [sys/sockio.h must be included])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))
fi

#XXX should be more generic, check if nonexistent
#SV_INTERRUPT, but not SA_RESTART defined?
AC_MSG_CHECKING([to see if SV_INTERRUPT should be used])
AC_EGREP_CPP(yes, [
#include <signal.h>
#ifdef SA_RESTART
#else
# ifdef SV_INTERRUPT
yes
# endif
#endif
], [AC_DEFINE(NEED_SA_RESTART, 1, [use SA_RESTART, not SV_INTERRUPT])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))

#XXXseems to be supported on Solaris2.6, but there might be some
#defines that need to be set (should _XOPEN_SOURCE be defined on all
#platforms?)
AC_MSG_CHECKING([if cmsghdr exists in <sys/socket.h>])
case $host in
    *)
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [struct cmsghdr foo = {1,1,1};
 struct msghdr bar;
 foo.cmsg_len = 0;
 foo.cmsg_type = SCM_RIGHTS;
 foo.cmsg_level = SOL_SOCKET;
 bar.msg_controllen = 1;
], [AC_DEFINE(HAVE_CMSGHDR, 1, [struct cmsghdr exists])
    AC_MSG_RESULT(yes)],
    AC_MSG_RESULT(no))
	;;
esac

AC_MSG_CHECKING([for CMSG_SPACE in sys/socket.h])
AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>
int main()
{
   int d = CMSG_SPACE(4);
   return 0;
}
], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_CMSG_SPACE, 1, CMSG_SPACE exists)],
   [AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for CMSG_LEN in sys/socket.h])
AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>

int main()
{
   int d = CMSG_LEN(4);
   return 0;
}], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_CMSG_LEN, 1, [CMSG_LEN exists])],
   [AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for sa_len in sockaddr])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [struct sockaddr foo;
foo.sa_len = 0;
], [AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [sa_len exists in sockaddr])
    AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)])

AC_MSG_CHECKING([to see if malloc_options exists])
AC_TRY_LINK([extern char *malloc_options;],
[ malloc_options = 0; ],
[AC_DEFINE(HAVE_MALLOC_OPTIONS, 1, [support for malloc debugging])
 AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)])

AC_MSG_CHECKING([to see if __progname exists])
AC_TRY_LINK([extern char *__progname;],
[ __progname = 0; ],
[AC_DEFINE(HAVE_PROGNAME, 1, [programe name symbol exists])
 AC_MSG_RESULT(yes)],
[AC_MSG_RESULT(no)])

#AIX 6.1 needs sys/select.h, but can be problematic on other platforms
AC_MSG_CHECKING([is sys/select.h is needed])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
], [fd_set *fdp;
    size_t p;
    fdp = NULL;
    p = NFDBITS * sizeof(fd_mask);
], [AC_MSG_RESULT(no)],
   [dnl compilation failure, try with sys/select.h (ignore if this fails)
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <string.h>
#include <unistd.h>
], [fd_set *fdp;
    size_t p;
    fdp = NULL;
    p = NFDBITS * sizeof(fd_mask);],
    [AC_DEFINE(HAVE_SYS_SELECT_H, 1, [sys/select.h needed])
     AC_MSG_RESULT(yes)])])

dnl Checks for libraries.
AC_SEARCH_LIBS(crypt, crypt)

#HP-UX 11.00
AC_SEARCH_LIBS(getspnam, sec)

#FreeBSD has setproctitle in -lutil (Per Hedeland <per@erix.ericsson.se>)
AC_SEARCH_LIBS(setproctitle, util)

#miniupnpc
AC_ARG_WITH(upnp,
[  --without-upnp          disable upnp support @<:@default=detect@:>@],
[UPNP=$withval])

no_upnp=t
if test x"${UPNP}" != xno; then
    AC_MSG_CHECKING([for miniupnpc headers])
    AC_TRY_COMPILE([#include <miniupnpc/miniupnpc.h>],
        [struct UPNPDev upnpdev;],
        [AC_MSG_RESULT(yes)
         upnphdr=t],
        [AC_MSG_RESULT(no)
         unset upnphdr])

    if test "x$upnphdr" = "xt"; then
	oLIBS=$LIBS
        AC_SEARCH_LIBS(UPNP_GetValidIGD, miniupnpc, [have_libminiupnp=t])
	UPNPLIB=$LIBS
	LIBS=$oLIBS
    fi
    if test x"${have_libminiupnp}" = xt; then
	#only miniupnpc-1.3 API currently supported
        AC_MSG_CHECKING([for supported miniupnpc library])
	AC_TRY_COMPILE([
            #include <stdio.h>
            #include <miniupnpc/miniupnpc.h>
            #include <miniupnpc/upnpcommands.h>
            #include <miniupnpc/upnperrors.h>], [

            char *str = NULL;
            struct UPNPDev *UPNPDev;
            struct UPNPUrls *UPNPUrls = NULL;
            struct IGDdatas *IGDdatas = NULL;

            (void)UPNP_GetIGDFromUrl(str, UPNPUrls, IGDdatas, str, 0);
            (void)UPNP_GetValidIGD(UPNPDev, UPNPUrls, IGDdatas, str, 0);
            (void)UPNP_GetExternalIPAddress(str, str, str);
            (void)UPNP_AddPortMapping(str, str, str, str, str, str, str, str);
            (void)UPNP_DeletePortMapping(str, str, str, str, str);],
         [AC_MSG_RESULT(yes)
          AC_DEFINE(HAVE_LIBMINIUPNP, 1, [UPNP support library])
          unset no_upnp
	  SOCKDDEPS="${DLIBDEPS}${DLIBDEPS:+ }$UPNPLIB"
	  DLIBDEPS="${DLIBDEPS}${DLIBDEPS:+ }$UPNPLIB"],
         [AC_MSG_RESULT(no)])
    fi
fi

dnl #XXX include header in compilation test?
dnl normal library testing doesn't work for libwrap (doesn't link
dnl without allow/deny_severity)
if test "x${ac_cv_header_tcpd_h}" = "xyes"; then
    case $host in
	*-*-linux-*)
	    #XXX needed on atleast redhat
	    AC_SEARCH_LIBS(yp_get_default_domain, nsl)
	;;
    esac
    oLIBS=$LIBS
    AC_MSG_CHECKING([for libwrap])
    if test x$no_libwrap = xt; then
	echo "disabled"
    else
	LIBS="$LIBS -lwrap"
	AC_TRY_LINK([
int allow_severity;
int deny_severity;
], [hosts_access(0);],
        [AC_MSG_RESULT(yes)
         AC_DEFINE(HAVE_LIBWRAP, 1, [use tcpwrappers])
         want_libwrap=t],
        [AC_MSG_RESULT(no)])
    fi
    LIBS="$oLIBS"
fi
#programs wanting libwrap should test for this Makefile.am conditional
#(programs which don't use it probably won't enjoy being linked with it)
AM_CONDITIONAL(WANT_LIBWRAP, test "x${want_libwrap}" != "x")

AC_ARG_WITH(pam,
[  --without-pam           disable pam support @<:@default=detect@:>@],
[PAM=$withval])

if test "${PAM}" != no; then
    #look for PAM header and lib
    AC_CHECK_HEADERS(security/pam_appl.h, [have_pam_header=t])
    AC_SEARCH_LIBS(pam_start, pam, [have_libpam=t])

    if test x"${have_pam_header}" != x -a x"${have_libpam}" != x; then
	AC_DEFINE(HAVE_PAM, 1, [PAM support])
    fi
fi

#only relevant for platforms lacking issetugid()
AC_MSG_CHECKING([full environment usage])
AC_ARG_WITH(full-env,
[  --without-full-env      restrictive environment variable usage @<:@default=with@:>@],
[CONFENV=$withval])
if test x"$CONFENV" = xno; then
    AC_MSG_RESULT([no])
    AC_DEFINE(HAVE_CONFENV_DISABLE, 1, [Disable environment variables])
else
    AC_MSG_RESULT([yes])
fi

dnl determine GSSAPI support
no_gssapi=t
m4_include(gssapi.m4)

dnl compatibility library tests
m4_include(libscompat.m4)

dnl workaround for newer glibc versions (and opensolaris)
unset stdio_preload
case $host in
    *-*-linux-* | *-*-solaris*)
	#only do preloading  if gssapi is defined
	if test x"$no_gssapi" != xt; then
	    stdio_preload=t
	fi
	;;
esac

dnl 'generate' capi/socks.h file
AC_CONFIG_FILES(capi/socks.h)
if test x"$stdio_preload" = xt; then
    AC_DEFINE(HAVE_LINUX_GLIBC_WORKAROUND, 1, [stdio function preloading])
    #append contents for stdio preloading
    cat capi/socks_glibc.h >> capi/socks.h
fi

dnl generate mapfile (XXX suncc)
unset MAPOPT
if test x"$GCC" != x -a x"${no_preload}" != xt; then
   MAPFILE=dlib/socks.map

   cp /dev/null $MAPFILE
   echo "{
global:
" >> $MAPFILE
   cat include/symbols_common.txt >> $MAPFILE
   case $host in
       *-*-linux-*)
	   if test x"$stdio_preload" = xt; then
	       cat include/symbols_glibc.txt >> $MAPFILE
	   fi
	   ;;
       *-*-solaris*)
	   cat include/symbols_osol.txt >> $MAPFILE
	   if test x"$stdio_preload" = xt; then
	       cat include/symbols_osol_stdio.txt >> $MAPFILE
	   fi
	   ;;
       *-*-freebsd*)
	   cat include/symbols_freebsd.txt >> $MAPFILE
	   ;;
   esac
   echo "local:
*;
};" >> $MAPFILE
   #if gcc+sun ld, option in -Wl,-Msocks.map, otherwise --version-script
   gcc -Wl,-v 2>&1 | grep '/usr/ccs/bin/ld' > /dev/null
   if test $? -eq 0; then
       MAPOPT="-Wl,-Msocks.map"
   else
       MAPOPT="-Wl,--version-script=socks.map"
   fi
fi
AC_SUBST(MAPOPT)

#expected select behaviour?
unset nb_select_err
L_UNCON_SELECT([],
 [nb_select_err=t])

if test x"${nb_select_err}" = xt; then
   AC_MSG_WARN([operations on nonblocking sockets might fail on this platform])
fi

AC_MSG_CHECKING([direct route fallback in client enabled])
with_drtfallback=t
AC_ARG_ENABLE(drt-fallback,
[  --disable-drt-fallback  disable direct route fallback in client @<:@default=no@:>@],
[if test x$enableval = xyes; then
     with_drtfallback=t
 elif test x$enableval = xno; then
     unset with_drtfallback
 else
     AC_MSG_WARN([unexpected parameter])
 fi])

if test x${with_drtfallback} = xt; then
    AC_DEFINE(SOCKS_DIRECTROUTE_FALLBACK, 1, [use fallback])
    AC_MSG_RESULT([yes])
else
    AC_DEFINE(SOCKS_DIRECTROUTE_FALLBACK, 0, [do not use fallback])
    AC_MSG_RESULT([no])
fi

#Linux (redhat 5.2) defines socklen_t in <socketbits.h>, which is
#included by <sys/socket.h>.  check for this first.
AC_MSG_CHECKING([for socklen_t])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [socklen_t foo = 1;],
   [AC_MSG_RESULT(yes)
    socklen_found=t],
   [AC_MSG_RESULT(no)
    socklen_found=""])

AH_TEMPLATE([socklen_t], [platform workaround])
if test x"$socklen_found" = x; then
    case $host in
	alpha*-dec-osf* | *-*-aix*)
	    AC_DEFINE(socklen_t, size_t)
	    ;;

	*)
	    AC_DEFINE(socklen_t, int)
	    ;;
    esac
fi

#sig_atomic_t
AC_MSG_CHECKING([for sig_atomic_t in <signal.h>])
AC_EGREP_CPP(sig_atomic_t, [
#include <signal.h>
], [AC_DEFINE(HAVE_SIG_ATOMIC_T, 1, [sig_atomic_t defined in signal.h])
    case $host in
	*-*-aix*)
	    AC_DEFINE(HAVE_VOLATILE_SIG_ATOMIC_T, 1, [platform workaround])
	;;
    esac
    AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)])

AC_CHECK_TYPES([int8_t, int16_t, int32_t, uint8_t, uint16_t, uint32_t,
		in_port_t, in_addr_t],
		, ,
[
#include <sys/types.h>
#include <netinet/in.h>
])
AC_CHECK_TYPE(ssize_t, int)

dnl Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF

AC_CHECK_FUNCS(gethostbyname2 getaddrinfo getipnodebyname)
AC_CHECK_FUNCS(getprpwnam getspnam bindresvport)

AC_MSG_CHECKING([for system V getpwnam])
unset getpwnam_alt
if test x"${ac_cv_func_getprpwnam}" = xyes; then
    getpwnam_alt=t
fi

if test x"${ac_cv_func_getspnam}" = xyes; then
    getpwnam_alt=t
fi

#XXX
if test x"${getpwnam_alt}" = x; then
    AC_DEFINE(HAVE_WORKING_GETPWNAM, 1, [system V getpwnam])
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT(yes)
fi

if false; then
   AC_DEFINE(HAVE_DUMPCONF, 1, [GUI tool])
fi

#look for modules, and check version
servdir=sockd
L_MODVER(bandwidth, 44, $servdir) #module name, version
L_MODVER(redirect, 39, $servdir)
L_MODVER(session, 18, $servdir)

#helper files
L_MODVER(checkmodule, 27, $servdir, nokey)
L_MODVER(shmem, 29, $servdir, nokey)

#change all #undef's to #define foo 0
AH_BOTTOM([
#include "redefac.h"
])

#add any warning flags (value set above)
CFLAGS="$CFLAGS $warn"

if test "x${prerelease}" != "x"; then
    echo "warning flags: $warn"
    echo "compiler flags: $comp_flags"
    echo "CFLAGS: $CFLAGS"
    echo "LIBS: $LIBS"
    echo "CPPFLAGS: $CPPFLAGS"
    echo "LDFLAGS: $LDFLAGS"
    echo "DLIBDEPS: $DLIBDEPS"
    echo "SOCKDDEPS: $SOCKDDEPS"
fi

AC_SUBST(TOPEXTRADIST)
AC_SUBST(DLIBDEPS)
AC_SUBST(SOCKDDEPS)

AC_CONFIG_FILES(sockd/Makefile include/Makefile lib/Makefile dlib/Makefile)
AC_CONFIG_FILES(Makefile example/Makefile doc/Makefile bin/Makefile)
AC_CONFIG_FILES(capi/Makefile SPECS/Makefile SPECS/dante.spec)
AC_CONFIG_FILES(libscompat/Makefile contrib/Makefile)
AC_CONFIG_FILES(unlicensed/Makefile doc/module/Makefile VERSION)

AC_OUTPUT

echo ""
echo "                     Configure status:"
echo ""
if test x"${no_acceptlock}" = xt; then
    echo "Acceptlock:        OK (not required)"
else
    echo "Acceptlock:        workaround enabled on this platform"
fi
if test x"${no_preload}" = xt; then
   if test x"${blocked_preload}" = xt; then
	echo "Preloading:        client preloading might not be reliable on this platform"
   else   
	echo "Preloading:        disabled"
   fi
else
    echo "Preloading:        OK"
fi
if test x"${so_sndlowat}" = xt; then
    echo "SO_SNDLOWAT:       OK"
else
    echo "SO_SNDLOWAT:       not enabled for this platform"
fi
if test x"${nb_select_err}" = xt; then
    echo "select:            unexpected select behaviour on unconnected sockets,"
    echo "                   operations on nonblocking sockets might fail "
    echo "                   on this platform when using socksify"
else
    echo "select:            OK"
fi
if test x"${no_routeinfo}" = xt; then
    echo "Routeinfo:         not supported on this platform"
else
    echo "Routeinfo:         OK"
fi
if test x"${no_gssapi}" = xt; then
   if test x"${bad_gssapi}" = xt; then
	echo "GSSAPI:            located gssapi library not usable"
   else
	echo "GSSAPI:            not found"
   fi
else
	echo "GSSAPI:            OK"
fi
if test x"${no_upnp}" = xt; then
    if test x"${have_libminiupnp}" = xt; then
	echo "UPNP:              unsupported miniupnp library version"
    else
	echo "UPNP:              supported library not found"
    fi
else
    echo "UPNP:              OK"
fi

echo ""
echo "This software should perform optimally when all the lines above report 'OK'."
echo "This is not possible on all platforms."
echo ""

echo "                     Modules:"
echo ""
if test x"$MOD_REDIRECT" = x; then
    echo "redirect:          OK"
else
    echo "redirect:          not found"
fi
if test x"$MOD_BANDWIDTH" = x; then
    echo "bandwidth:         OK"
else
    echo "bandwidth:         not found"
fi
if test x"$MOD_SESSION" = x; then
    echo "session:           OK"
else
    echo "session:           not found"
fi
echo ""

if test x$prerelease != x; then
   echo "
This is a pre-release.  We ask that everyone who can, test it to the
extent possible, to help reduce problems in the upcoming release.
Problems can be reported to dante-bugs@inet.no.

Note that pre-releases are often configured in a way that can
significantly increase the load on the machine.  This is done to
stress the server more, increasing the chances of detecting potential
problems.
"
fi

VINFO=README.latest
test -s "$VINFO" && cat "$VINFO"

exit 0
