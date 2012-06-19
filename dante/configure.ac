AC_INIT
AC_PREREQ(2.61)
AC_REVISION($Id: configure.ac,v 1.603 2012/06/01 19:59:26 karls Exp $)

version=1.4.0
RPMVERSION1="$version"
#set this to enable prerelease, changes some defaults (debug enabled)
prerelease="1"
if test x$prerelease != x; then
    prename="pre$prerelease"
    version="${version}-$prename"
    RPMVERSION2="0.$prename"
    TOPEXTRADIST="${TOPEXTRADIST} PRERELEASE"
else
    RPMVERSION2="1"
fi

unset initCC initCPP initCFLAGS initCPPFLAGS initLDFLAGS initLIBS
if test x"$CC" != x; then
    initCC="($CC)"
fi
if test x"$CPP" != x; then
    initCPP="($CPP)"
fi
if test x"$CFLAGS" != x; then
    initCFLAGS="($CFLAGS)"
fi
if test x"$CPPFLAGS" != x; then
    initCPPFLAGS="($CPPFLAGS)"
fi
if test x"$LDFLAGS" != x; then
    initLDFLAGS="($LDFLAGS)"
fi
if test x"$LIBS" != x; then
    initLIBS="($LIBS)"
fi

APP=dante
UCAPP=Dante
SERVNAME=sockd
echo "Configuring $UCAPP ${version}:"

AM_INIT_AUTOMAKE(dante, ${version})
AC_CONFIG_SRCDIR(include/common.h)
AM_CONFIG_HEADER(include/autoconf.h)

AC_CONFIG_MACRO_DIR([m4])

if test x`uname` = xDarwin; then
   #XXX problem with -MD and -arch values
   enable_dependency_tracking=no
   AC_MSG_WARN([disabling dependency tracking on this platform])
fi

#NOTE: save CFLAGS; wish to compile without -O2 when debugging
oCFLAGS="$CFLAGS"
unset CFLAGS
LT_INIT
autoconf_compflags="$CFLAGS"
CFLAGS=$oCFLAGS

AC_SUBST(RPMVERSION1)
AC_SUBST(RPMVERSION2)

#compile silently, if possible
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AH_TOP([/* avoid warnings on Android */
#ifdef HAVE_ANDROID_OS
# undef /*XXX protect against redefinition */ HAVE_SCHED_SETSCHEDULER
# undef /*XXX protect against redefinition */ HAVE_MALLOC_H
#endif /* HAVE_ANDROID_OS */
])

AC_DEFINE(BAREFOOTD, 0, [we are Dante])
AC_DEFINE(COVENANT, 0, [we are Dante])
m4_define(dantebuild, yes)

ucase () {
      tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'
}

AC_ARG_ENABLE(release,
[  --enable-release        build prerelease as full release],
[unset prerelease])

if test x$prerelease != x; then
    AC_DEFINE(PRERELEASE, 1, [software prerelease])
else
    AC_DEFINE(PRERELEASE, 0, [software prerelease])
fi
AM_CONDITIONAL(PRERELEASE, test x$prerelease != x)

#known keywords for --enable/disable-foo(=yes/no)?
LTINTERNAL="dlopen|dlopen_self|dlopen_self_static|fast_install|libtool_lock|win32_dll|shared_with_static_runtimes|shared_with_static_runtimes_CXX|shared_with_static_runtimes_F77|option_checking|silent_rules"
KNOWN_KEYWORDS="$LTINTERNAL|shared|static|debug|warnings|diagnostic|profiling|coverage|linting|libwrap|preload|serverdl|clientdl|internal|pidfile|drt_fallback|release|dependency_tracking|largefile|livedebug|clientbuild|serverbuild|client|server"
for keyword in `set | egrep '^enable_' | sed -e 's/^enable_//' | \
                sed -e 's/=.*$//'`; do
    echo $keyword | egrep "^(${KNOWN_KEYWORDS})$" > /dev/null
    if test $? -ne 0; then
	AC_MSG_WARN([unknown --enable/disable keyword '$keyword'])
	#check is not entirely reliable, only exit in prerelease
	if test x$prerelease != x; then
	    exit 1
	fi
    fi
done

#known keywords for --with/without-foo?
LTINTERNAL="gnu_ld|pic|tags|gnu_ldcxx|sysroot"
KNOWN_KEYWORDS="$LTINTERNAL|socks_conf|sockd_conf|pidfile|iomax|negmax|libc|upnp|pam|bsdauth|full_env|gssapi_path|gssapi|krb5_config|krb5|krb5_path|ldap|ldap_path|sasl|sasl_path|glibc_secure|libwrap"
for keyword in `set | egrep '^with_' | sed -e 's/^with_//' | \
                sed -e 's/=.*$//'`; do
    echo $keyword | egrep "^(${KNOWN_KEYWORDS})$" > /dev/null
    if test $? -ne 0; then
	AC_MSG_WARN([unknown --with/without keyword '$keyword'])
	#check is not entirely reliable, only exit in prerelease
	if test x$prerelease != x; then
	    exit 1
	fi
    fi
done

dnl compiler tests, sets 'warn' with warnings, added to CFLAGS below
m4_include(compiler.m4)

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

#XXX add proper test for this?
if test x$no_acceptlock != xt; then
    AC_DEFINE(NEED_ACCEPTLOCK, 1, [platform workaround])
fi

AC_MSG_CHECKING([whether client compilation should be disabled])
AC_ARG_ENABLE(client,
[  --disable-client        disable compilation of client library],
[if test x$enableval = xno; then
    no_clientbuild=t
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi],
[AC_MSG_RESULT([no])])
AC_MSG_CHECKING([whether server compilation should be disabled])
AC_ARG_ENABLE(server,
[  --disable-server        disable compilation of server],
[if test x$enableval = xno; then
    if test x"${no_clientbuild}" = xt; then
       AC_MSG_WARN(cannot disable both client and server compilation)
       exit 1
    fi
    no_serverbuild=t
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi],
[AC_MSG_RESULT([no])])

#XXX for backwards compatibility
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       deprecated, use --without-libwrap],
[if test x$enableval = xno; then
    no_libwrap=t
 fi])

AC_MSG_CHECKING([whether to build with libwrap])
AC_ARG_WITH(libwrap,
[  --without-libwrap       never use libwrap, even if it is available],
[if test x$withval = xno; then
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
AC_CHECK_HEADERS(tcpd.h shadow.h ifaddrs.h sys/sem.h netinet/in.h rpc/rpc.h)
AC_CHECK_HEADERS(sys/ipc.h arpa/nameser.h net/if_dl.h execinfo.h sys/pstat.h)
AC_CHECK_HEADERS(sys/shm.h)

#some header dependencies for netinet/ip.h, use compilation test
AC_MSG_CHECKING([for netinet/ip.h])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
], [], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_NETINET_IP_H, 1, [netinet/ip.h header found])],
   [AC_MSG_RESULT(no)])

case $host in
    #XXX only check for priv.h support on Solaris for now
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

#SOCKD_IOMAX/NEGOTIATEMAX override?
AC_MSG_CHECKING([for SOCKD_IOMAX value])
AC_ARG_WITH(iomax,
[  --with-iomax=NUMBER     change number of clients per io process],
[AC_MSG_RESULT($withval)
 FEAT="$FEAT${FEAT:+ }iomax-$withval"
 CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-DSOCKD_IOMAX=$withval"],
[AC_MSG_RESULT(default)])

AC_MSG_CHECKING([for SOCKD_NEGOTIATEMAX value])
AC_ARG_WITH(negmax,
[  --with-negmax=NUMBER    change number of clients per negotiate process],
[AC_MSG_RESULT($withval)
 FEAT="$FEAT${FEAT:+ }negmax-$withval"
 CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-DSOCKD_NEGOTIATEMAX=$withval"],
[AC_MSG_RESULT(default)])

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

#looks for Linux + systems with RTAX_GATEWAY defined in net/route.h
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
], [AC_DEFINE(NEED_AF_LOCAL, 1, [need AF_LOCAL definition])
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
     AC_MSG_RESULT(no)],
    [dnl assume malloc is not called when cross-compiling
     AC_DEFINE(HAVE_NOMALLOC_REALLOC, 1, [realloc never calls malloc])
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
     AC_MSG_RESULT(no)],
    [dnl assume NULL is not accepted when cross-compiling
     AC_DEFINE(HAVE_NONULL_FREE, 1, [free does not accept NULL parameter])
     AC_MSG_RESULT(no)])

#A good time to save the cache (preload code might fail)
AC_CACHE_SAVE

m4_include(preload.m4)

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

#XXX seems to be supported on Solaris2.6, but there might be some
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
AC_TRY_LINK([
#include <sys/types.h>
#include <sys/socket.h>
], [int d = CMSG_SPACE(4);
   return 0;
], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_CMSG_SPACE, 1, CMSG_SPACE exists)],
   [AC_MSG_RESULT(no)])

AC_MSG_CHECKING([for CMSG_LEN in sys/socket.h])
AC_TRY_LINK([
#include <sys/types.h>
#include <sys/socket.h>
], [int d = CMSG_LEN(4);
    return 0;
], [AC_MSG_RESULT(yes)
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

#AIX 6.1 needs sys/select.h, but can be problematic on other platforms
AC_MSG_CHECKING([if sys/select.h is needed])
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
     AC_MSG_RESULT(yes)],
    [AC_MSG_RESULT(no)])])

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

dnl Checks for libraries.
AC_SEARCH_LIBS(crypt, crypt)

#HP-UX 11.00
AC_SEARCH_LIBS(getspnam, sec)

#FreeBSD has setproctitle in -lutil
AC_SEARCH_LIBS(setproctitle, util)

#miniupnpc tests
m4_include(miniupnpc.m4)
if test x"${no_upnp}" = x; then
    FEAT="$FEAT${FEAT:+ }upnp"
fi

dnl #XXX include header in compilation test?
dnl normal library testing doesn't work for libwrap (doesn't link
dnl without allow/deny_severity)
if test x"${ac_cv_header_tcpd_h}" = xyes; then
    case $host in
	*-*-linux-*)
	    #XXX needed on at least RedHat
	    AC_SEARCH_LIBS(yp_get_default_domain, nsl)
	;;
    esac
    oLIBS=$LIBS
    AC_MSG_CHECKING([for libwrap])
    if test x$no_libwrap = xt; then
        AC_MSG_RESULT(disabled)
    else
	LIBS="$LIBS -lwrap"
	AC_TRY_LINK([
int allow_severity;
int deny_severity;
], [hosts_access(0);],
        [AC_MSG_RESULT(yes)
         AC_DEFINE(HAVE_COND_LIBWRAP, 1, [use tcpwrappers])
         want_libwrap=t
         FEAT="$FEAT${FEAT:+ }libwrap"],
        [AC_MSG_RESULT(no)])
    fi
    LIBS="$oLIBS"
fi
#programs wanting libwrap should test for this Makefile.am conditional
#(programs which don't use it probably won't enjoy being linked with it)
AM_CONDITIONAL(WANT_LIBWRAP, test x"${want_libwrap}" != x)

AC_ARG_WITH(pam,
[  --without-pam           disable pam support @<:@default=detect@:>@],
[PAM=$withval])

if test "${PAM}" != no; then
    #look for PAM header and lib
    AC_CHECK_HEADERS(security/pam_appl.h, [have_pam_header=t])
    AC_SEARCH_LIBS(pam_start, pam, [have_libpam=t])

    if test x"${have_pam_header}" != x -a x"${have_libpam}" != x; then
	AC_DEFINE(HAVE_COND_PAM, 1, [PAM support])
	FEAT="$FEAT${FEAT:+ }pam"
    fi
fi

AC_ARG_WITH(bsdauth,
[  --without-bsdauth       disable bsdauth support @<:@default=detect@:>@],
[BSDAUTH=$withval])
if test "${BSDAUTH}" != no; then
    #look for bsd authentication support
    AC_CHECK_HEADERS(bsd_auth.h, [have_bsdauth_header=t])
    AC_CHECK_FUNC(auth_userokay, [have_bsdauth=t])

    if test x"${have_bsdauth_header}" != x -a x"${have_bsdauth}" != x; then
	AC_DEFINE(HAVE_BSDAUTH, 1, [BSD Authentication support])
	FEAT="$FEAT${FEAT:+ }bsdauth"
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

dnl determine GSSAPI/KERBEROS/LDAP/SASL support
no_gssapi=t
no_krb5=t
no_ldap=t
no_sasl=t

unset noldap
unset LDAPLIBS
m4_include(gssapi.m4)
if test x"${no_gssapi}" != xt; then
   FEAT="$FEAT${FEAT:+ }gssapi"

   LIBScpy="$LIBS"
   m4_include(kerberos.m4)
   if test x"${no_krb5}" != xt; then
       m4_include(sasl.m4)
   else
       noldap="KerberosV required"
   fi
   if test x"${no_sasl}" != xt; then
       m4_include(ldap.m4)
   else
       noldap="SASL required"
   fi
   if test x"$LIBS" != x -a x"$noldap" = x; then
       LDAPLIBS=${LIBS##$LIBScpy} #ensure only new libraries are added
   fi
   if test x"$LIBScpy" != x; then
      LIBS="$LIBScpy"
   fi
else
   noldap="GSSAPI required"
fi
if test x"$noldap" != x; then
   AC_MSG_WARN([ldap disabled: $noldap])
fi

dnl compatibility library tests
m4_include(libscompat.m4)

dnl generate socket option code
m4_include(sockopt.m4)

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

dnl preparation for library mapfile usage to control symbol export
unset MAPOPT
m4_include(mapfile.m4)

#expected select behavior?
unset nb_select_err
L_UNCON_SELECT([],
 [nb_select_err=t])

if test x"${nb_select_err}" = xt; then
   AC_MSG_WARN([operations on nonblocking sockets might fail on this platform])
fi

#expected shmem behavior
#L_SHMEM([], [l_shmem_fail=t])
#if test x"${l_shmem_fail}" = xt; then
#   AC_MSG_WARN(unsupported shmem behavior)
#   exit 1
#fi

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

#Linux (RedHat 5.2) defines socklen_t in <socketbits.h>, which is
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
AC_FUNC_MEMCMP
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF

AC_CHECK_FUNCS(gethostbyname2 getaddrinfo getipnodebyname)
AC_CHECK_FUNCS(getprpwnam getspnam bindresvport)
AC_CHECK_FUNCS(getpass)

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

#construct SUBDIRS variable
SUBDIRS="unlicensed example doc bin SPECS capi contrib"
DISTSUBDIRS="$SUBDIRS"
if test x"${no_serverbuild}" = x; then
   SUBDIRS="sockd ${SUBDIRS}"
fi
DISTSUBDIRS="$DISTSUBDIRS sockd"
if test x"${no_clientbuild}" = x; then
   if test x"${no_preload_client}" = x; then
       SUBDIRS="dlib $SUBDIRS"
       if test x"$sol64" != x; then
           SUBDIRS="dlib64 $SUBDIRS"
       fi
       FEAT="$FEAT${FEAT:+ }preload"
   fi
   #lib handles yacc/lex generation for dlib/sockd, should be before these
   SUBDIRS="lib $SUBDIRS"
fi
DISTSUBDIRS="include libscompat $DISTSUBDIRS lib dlib dlib64"

#include should be done before compilation to ensure that
#redefac is executed first
TOPSUBDIRS="$subdirs include"
if test x"$LIBSCSRC" != x; then
   TOPSUBDIRS="$TOPSUBDIRS libscompat"
fi
TOPSUBDIRS="$TOPSUBDIRS $SUBDIRS"
AC_SUBST(TOPSUBDIRS)
AC_SUBST(DISTSUBDIRS)

if false; then
   AC_DEFINE(HAVE_DUMPCONF, 1, [GUI tool])
fi

#look for modules, and check version
servdir=sockd
unset MOD_BANDWIDTH MOD_REDIRECT MOD_SESSION MOD_LDAP
L_MODVER(bandwidth,   72, $servdir, [MOD_BANDWIDTH=t])
L_MODVER(redirect,    47, $servdir, [MOD_REDIRECT=t])
L_MODVER(session,     30, $servdir, [MOD_SESSION=t])
L_MODVER(ldap,        47, $servdir, [MOD_LDAP=t])
L_MODVER(checkmodule, 39, $servdir, [], nokey) #helper file

if test x"$MOD_BANDWIDTH" != x; then
   FEAT="$FEAT${FEAT:+ }mod-bandwidth"
fi
if test x"$MOD_LDAP" != x; then
   FEAT="$FEAT${FEAT:+ }mod-ldap"
   SOCKDDEPS="${SOCKDDEPS}${SOCKDDEPS:+ }$LDAPLIBS"
fi
if test x"$MOD_REDIRECT" != x; then
   FEAT="$FEAT${FEAT:+ }mod-redirect"
fi
if test x"$MOD_SESSION" != x; then
   FEAT="$FEAT${FEAT:+ }mod-session"
fi

FEATURES=`echo $FEAT | xargs -n 1 echo | sort | xargs echo`
AC_DEFINE_UNQUOTED(DANTE_BUILD, "$FEATURES", [Features enabled in build])

#change all #undef's to #define foo 0
AH_BOTTOM([
#include "redefac.h"
])

#add any warning flags (value set above)
CFLAGS="$CFLAGS $warn"

#store build environment
cp /dev/null buildenv.txt
echo "flags: ${ac_configure_args}" >> buildenv.txt
echo "CC: $CC $initCC" >> buildenv.txt
echo "CFLAGS: $CFLAGS $initCFLAGS" >> buildenv.txt
echo "CPP: $CPP $initCPP" >> buildenv.txt
echo "CPPFLAGS: $CPPFLAGS $initCPPFLAGS" >> buildenv.txt
echo "LDFLAGS: $LDFLAGS $initLDFLAGS" >> buildenv.txt
echo "LIBS: $LIBS $initLIBS" >> buildenv.txt
echo "DLIBDEPS: $DLIBDEPS" >> buildenv.txt
echo "SOCKDDEPS: $SOCKDDEPS" >> buildenv.txt
echo "compiler flags: $comp_flags" >> buildenv.txt
echo "warning flags: $warn" >> buildenv.txt
echo "FEATURES: $FEAT" >> buildenv.txt
echo "socket options: `echo $OKSOCKOPTS | ucase`" >> buildenv.txt
echo "socket option arguments: `echo $OKSOCKOPTVALSYMS | ucase`" >> buildenv.txt

cat buildenv.txt

echo "#build environment
export CC=\"$CC\"
export CFLAGS=\"$CFLAGS\"
export CPP=\"$CPP\"
export CPPFLAGS=\"CPPFLAGS\"
export LDFLAGS=\"$LDFLAGS\"
export LIBS=\"$LIBS\"" > buildenvrc

AC_SUBST(TOPEXTRADIST)
AC_SUBST(DLIBDEPS)
AC_SUBST(SOCKDDEPS)

AC_CONFIG_FILES(sockd/Makefile include/Makefile lib/Makefile dlib/Makefile)
AC_CONFIG_FILES(Makefile example/Makefile doc/Makefile bin/Makefile)
AC_CONFIG_FILES(capi/Makefile SPECS/Makefile SPECS/dante.spec)
AC_CONFIG_FILES(libscompat/Makefile contrib/Makefile)
AC_CONFIG_FILES(unlicensed/Makefile VERSION dlib64/Makefile)

AC_OUTPUT

echo ""
echo "                     Configure status:"
echo ""

unset CONFVAR
if test x"${no_clientbuild}" = xt; then
    echo "Client:            Disabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }noclient"
else
    echo "Client:            Enabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }client"
fi
if test x"${no_serverbuild}" = xt; then
    echo "Server:            Disabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }noserver"
else
    echo "Server:            Enabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }server"
fi
if test x"${no_acceptlock}" = xt; then
#    echo "Acceptlock:        Disabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }noacceptlock"
else
    echo "Acceptlock:        Enabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }acceptlock"
fi
if test x"${no_preload}" = xt; then
   if test x"${blocked_preload}" = xt; then
	echo "Preloading:        Client preloading might not be reliable on this platform"
	CONFVAR="${CONFVAR}${CONFVAR:+ }badpreload"
   else
	echo "Preloading:        Disabled"
	CONFVAR="${CONFVAR}${CONFVAR:+ }nopreload"
   fi
else
    echo "Preloading:        Enabled"
    CONFVAR="${CONFVAR}${CONFVAR:+ }preload"
fi
if test x"${nb_select_err}" = xt; then
    echo "select:            Unexpected select behaviour on unconnected sockets,"
    echo "                   operations on nonblocking sockets might fail "
    echo "                   on this platform when using socksify"
    CONFVAR="${CONFVAR}${CONFVAR:+ }selecterr"
#else
#    echo "select:            OK"
fi
if test x"${no_routeinfo}" = xt; then
    echo "Routeinfo:         Not supported on this platform"
    CONFVAR="${CONFVAR}${CONFVAR:+ }norouteinfo"
else
#    echo "Routeinfo:         OK"
    CONFVAR="${CONFVAR}${CONFVAR:+ }routeinfo"
fi
if test x"${no_libwrap}" = xt; then
	echo "Libwrap:           Disabled"
elif test x"${want_libwrap}"; then
	echo "Libwrap:           Enabled"
else
	echo "Libwrap:           Not found"
fi
if test x"${no_gssapi}" = xt; then
   if test x"${bad_gssapi}" = xt; then
	echo "GSSAPI:            Located gssapi library not usable"
   else
	echo "GSSAPI:            Not found/disabled"
   fi
else
	echo "GSSAPI:            Enabled"
fi
if test x"${no_krb5}" = xt; then
	echo "KRB5:              Not found/disabled"
else
	echo "KRB5:              Enabled"
fi
if test x"${no_sasl}" = xt; then
	echo "SASL:              Not found/disabled"
else
	echo "SASL:              Enabled"
fi
if test x"${no_ldap}" = xt; then
	echo "LDAP:              Not found/disabled ($noldap)"
else
	echo "LDAP:              Enabled"
fi
if test x"${no_upnp}" = xt; then
    if test x"${have_libminiupnp}" = xt; then
	echo "UPNP:              Unsupported miniupnp library version"
    else
	echo "UPNP:              Not found/disabled"
    fi
else
    echo "UPNP:              Enabled"
fi

echo ""
echo "                     Modules:"
echo ""
if test x"$MOD_REDIRECT" != x; then
    echo "redirect:          Enabled"
else
    echo "redirect:          Not found"
fi
if test x"$MOD_BANDWIDTH" != x; then
    echo "bandwidth:         Enabled"
else
    echo "bandwidth:         Not found"
fi
if test x"$MOD_SESSION" != x; then
    echo "session:           Enabled"
else
    echo "session:           Not found"
fi
if test x"$MOD_LDAP" != x; then
    if test x"${no_ldap}" = xt; then
	echo "ldap:              Disabled ($noldap)"
    else
	echo "ldap:              Enabled"
    fi
else
    echo "ldap:              Not found"
fi
echo ""

echo "CONFRES: $CONFVAR" >> buildenv.txt

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
