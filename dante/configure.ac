AC_INIT
AC_PREREQ(2.59)
AC_REVISION($Id: configure.ac,v 1.359 2006/01/15 15:33:37 karls Exp $)

version=1.1.19
#set this to enable prerelease, changes some defaults (debug enabled)
#prerelease="1"
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

#NOTE: save CFLAGS; wish to compile without -O2 when debugging
oCFLAGS=$CFLAGS
unset CFLAGS
AC_AIX #evidently also modifies CFLAGS
AC_PROG_LIBTOOL
autoconf_compflags=$CFLAGS
CFLAGS=$oCFLAGS

AC_PROG_CPP

AM_CONDITIONAL(PRERELEASE, test x$prerelease != x)

#known keywords for --enable/disable-foo(=yes/no)?
LTINTERNAL="dlopen|dlopen_self|dlopen_self_static|fast_install|libtool_lock|win32_dll|shared_with_static_runtimes|shared_with_static_runtimes_CXX|shared_with_static_runtimes_F77"
KNOWN_KEYWORDS="$LTINTERNAL|shared|static|debug|warnings|diagnostic|profiling|linting|libwrap|preload|serverdl|clientdl|internal|pidfile"
for keyword in `set | egrep '^enable_' | sed -e 's/^enable_\(.*\)=.*/\1/'`;
do
	echo $keyword | egrep "^(${KNOWN_KEYWORDS})$" > /dev/null
	if test $? -ne 0; then
		AC_MSG_WARN([unknown option '$keyword', ignoring ...])
		sleep 10;
	fi
done

#Solaris 2.5.1 is broken in many places
case $host in
    *-*-solaris2.5.1)
	AC_MSG_WARN([the server might not work properly on solaris 2.5.1])
	AC_DEFINE(HAVE_SOLARIS_2_5_1, 1, [broken platform])
    ;;
esac

#disable acceptlock
#XXX add proper test for this?
case $host in
	*-*-*bsd* | alpha*-dec-osf* | *-*-hpux* | *-*-aix4* | *-*-aix5*)
		no_acceptlock=t
	;;

	*-*-solaris*)
		unset solaris_newversion
		ver=`echo $host | sed -e 's/.*solaris//'`
		ver_major=`echo $ver | cut -d. -f1`
		ver_minor=`echo $ver | cut -d. -f2`
		if test x"${ver_major}" != x -a x"${ver_minor}" != x; then
			if test $ver_major -ge 2 -a $ver_minor -gt 5; then
				solaris_newversion=t
			fi
		fi
		if test x"${solaris_newversion}" = x"t"; then
			no_acceptlock=t
		fi
	;;

esac

#XXX
SOLIB_POSTFIX=so

case $host in
	alpha*-dec-osf*)
		AC_DEFINE(HAVE_DEC_PROTO, 1, [DEC workarounds])
		AC_DEFINE(HAVE_EXTRA_OSF_SYMBOLS, 1, [DEC workarounds])
		PRELOAD="RLD"
		CPPFLAGS="${CPPFLAGS} -D_XOPEN_SOURCE_EXTENDED -DBYTE_ORDER=LITTLE_ENDIAN -D_POSIX_SOURCE -D_POSIX_C_SOURCE=199309L -D_OSF_SOURCE"
	;;

	*-*-hpux*)
		#HPUX needs _PROTOTYPES to include prototypes
		#for configure (for gcc and cc)
		CPPFLAGS="${CPPFLAGS} -D_PROTOTYPES"
		SOLIB_POSTFIX=sl
	;;

	*-*-sunos4*)
		#XXX hardcode library path (find better way to do this?)
		AC_DEFINE(LIBRARY_PATH, "/usr/lib/", [hardcoded path])
		base_library_path="/usr/lib/"
		AC_MSG_WARN([notice: hardcoding /usr/lib for dlopen])
		#nonstandard libfunction workaround #XXX proper test
		AC_DEFINE(HAVE_BROKEN_VSPRINTF, 1, [nonstandard])
		#link problems with libresolv, hardcode domainname
		if test -s /etc/resolv.conf; then
		    domainname_hardcoded=`grep domain /etc/resolv.conf | awk '{ print $2 }'`
		fi
		no_res_init=t
		AC_DEFINE(HAVE_NO_RESOLVESTUFF, 1, [primitive platform])
	;;

	*-*-solaris*)
		AC_DEFINE(HAVE_SENDMSG_DEADLOCK, 1, [bug workaround])
		AC_DEFINE(HAVE_SOLARIS_BUGS, 1, [bug workaround])
		AC_DEFINE(BSD_COMP, 1, [enable BSD compatibility])
		AC_DEFINE(HAVE_SOLARIS_PAM_BUG, 1, [bug workaround])
	;;

	*-*-linux-*) # XXX This might only concern 2.0.x kernels (add test?)
		AC_DEFINE(HAVE_DEFECT_RECVMSG, 1, [bug workaround])
		AC_DEFINE(HAVE_LINUX_BUGS, 1, [bug workaround])
		AC_DEFINE(HAVE_LINUX_ECCENTRICITIES, 1, [platform workarounds])
		AC_DEFINE(SPT_PADCHAR, '\0', [setproctitle])
	;;

	*-*-openbsd*) #static sockd when profiling is enabled
		no_dynamic_profiled_sockd=t
	;;

	*-*-irix*)
		PRELOAD="RLD"
	;;

	*-*-aix4* | *-*-aix5*)
		OSPIDFILE="/etc/sockd.pid"
		AC_DEFINE(HAVE_SYSTEM_XMSG_MAGIC, 1, [platform workaround])
	;;

	*-*-cygwin)
		AC_MSG_WARN([disabling preloading])
		no_preload_client=t
		no_preload_server=t
		no_preload=t
		no_res_init=t
		AC_DEFINE(HAVE_NO_RESOLVESTUFF, 1, [primitive platform])
	;;

esac

AC_SUBST(SOLIB_POSTFIX)

case $PRELOAD in
	RLD)
		PRELOAD_SEPERATOR=":"
		PRELOAD_VARIABLE="_RLD_LIST"
		PRELOAD_POSTFIX="DEFAULT"
	;;

	*)
		PRELOAD_SEPERATOR=" "
		PRELOAD_VARIABLE="LD_PRELOAD"
		PRELOAD_POSTFIX=""
	;;
esac

AC_SUBST(PRELOAD_SEPERATOR)
AC_SUBST(PRELOAD_VARIABLE)
AC_SUBST(PRELOAD_POSTFIX)

#define hosttype
AC_DEFINE_UNQUOTED(HAVE_HOST_TYPE, "$host", [system hosttype])

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
	    comp_flags="$comp_flags -misalign -xO0"
	    AC_MSG_RESULT([$comp_flags])
	    AC_MSG_WARN([there might currenly be some performance problems with suncc - it needs -misalign])
	    $CC 2>&1 | grep ucbcc > /dev/null
	    if test $? -eq 0; then
		#XXX ucbcc uses includes from /usr/ucbinclude, but these are
		#not complete. add /usr/include to include path to get
		#all prototypes (read/write are missing)
		#XXX
		host_cc="solaris-ucbcc"
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

    *-*-aix4* | *-*-aix5*)
	if test "x$GCC" = x; then
	    comp_flags="-qlanglvl=ansi"
	    #XXX
	    CPPFLAGS="${CPPFLAGS} -qlanglvl=ansi"
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
    AC_MSG_RESULT([no]))
CFLAGS="$oCFLAGS"

AC_ARG_ENABLE(internal,
[  --enable-internal       enable internal extensions],
   [if test -d "gui"; then
      TOPEXTRADIST="${TOPEXTRADIST} gui"
      AC_CONFIG_SUBDIRS(gui)
    else
      AC_MSG_WARN([--enable-internal option is for internal Dante development, ignoring])
    fi
    ],
   unset build_internal)

AC_MSG_CHECKING([for compilation with debugging])
AC_ARG_ENABLE(debug,
[  --enable-debug          compile with debugging support],
	debug_enabled=t,
	[if test x$prerelease != x; then
	   debug_enabled=t
	 fi])

if test x$debug_enabled = xt; then
    #no optimization wanted
    if test $ac_cv_prog_cc_g = yes; then
	CFLAGS="$CFLAGS -g"
    fi
    CPPFLAGS="-DDEBUG $CPPFLAGS"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
    #autoconf_compflags is set to "-g -O2" with GCC
    #override CFLAGS when running configure to avoid this
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
	    *sunos4*) #sunos cc
#		warn=""
		true
	    ;;

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
	warn="-Wall -W -Wnested-externs -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wcast-align -Wcast-qual -Wbad-function-cast -Wpointer-arith -Wundef"
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
	      AC_MSG_RESULT([no])
	 fi])

AC_ARG_ENABLE(profiling,
[  --enable-profiling      compile with profiling support in server],
[   AC_DEFINE(HAVE_PROFILING, 1, [for profiling])
    s_profiling=t])

AM_CONDITIONAL(SPROFIL, test x$s_profiling = xt)
#static or dynamic sockd?
AM_CONDITIONAL(STATIC_SOCKD, test x$no_dynamic_profiled_sockd = xt)
if test "x$s_profiling" = "xt" -a "x$no_dynamic_profiled_sockd" = "xt"; then
	no_preload_server=t
	AC_MSG_WARN([sockd is built static when profiling is enabled])
fi

AC_ARG_ENABLE(linting,
[  --enable-linting        enable lint],
	s_linting=t)
AM_CONDITIONAL(LINT, test x$s_linting = xt)

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
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h limits.h malloc.h paths.h strings.h syslog.h)
AC_CHECK_HEADERS(unistd.h crypt.h sys/file.h sys/ioctl.h sys/time.h)
AC_CHECK_HEADERS(tcpd.h shadow.h ifaddrs.h sys/sem.h netinet/in.h)
AC_CHECK_HEADERS(sys/ipc.h arpa/nameser.h)

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

#allow manual specification
AC_MSG_CHECKING([for hardcoded domainname])
AC_ARG_WITH(domainname,
[  --with-domainname=NAME  hardcode local domainname (only on broken platforms)], [domainname_hardcoded=$withval])

if test x${domainname_hardcoded} != x; then
    AC_DEFINE_UNQUOTED(SOCKS_DOMAINNAME, "${domainname_hardcoded}", [platform workaround])
    AC_MSG_RESULT([yes])
    AC_MSG_WARN([using hardcoded domainname ${domainname_hardcoded}])
else
    AC_MSG_RESULT([no])
    if test x${no_res_init} = xt; then
	AC_MSG_WARN([unable to locate domainname, specify if necessary])
    fi
fi

#allow default file locations to be overridden
AC_MSG_CHECKING([for socks config file location])
AC_ARG_WITH(socks-conf,
[  --with-socks-conf=FILE  change location of socks client configuration file],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKS_CONFIGFILE, 1, [alternate location])
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKS_CONFIGFILE, "$withval", [alternate location])
], [AC_MSG_RESULT(default)])

AC_MSG_CHECKING([for sockd config file location])
AC_ARG_WITH(sockd-conf,
[  --with-sockd-conf=FILE  change location of socks server configuration file],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKD_CONFIGFILE, 1, [alternate location])
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_CONFIGFILE, "$withval", [alternate location])
], [AC_MSG_RESULT(default)])

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
 have_pidfile=t
], [AC_MSG_RESULT(default)])

#os default?
if test x"${have_pidfile}" != xt; then
    if test x"$OSPIDFILE" != x; then
	AC_DEFINE(HAVE_SOCKD_PIDFILE, 1)
	AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_PIDFILE, "$OSPIDFILE")
    fi
fi

## preload related tests
#build without support for preloading?

# HAVE_DLFCN_H only determines if the include file exists
AC_CHECK_HEADER(dlfcn.h,
[AC_DEFINE(HAVE_DLFCN_H, 1, [dlfcn.h exists])
 have_dlfcn_h=t],
[AC_MSG_WARN([dlfcn.h missing, preloading disabled])
 no_preload_client=t
 no_preload_server=t
 no_preload=t])

if test "x$no_preload" = x; then
   AC_MSG_CHECKING([whether all interposition usage should be disabled])
   AC_ARG_ENABLE(preload,
   [  --disable-preload       disable preloading in server and client],
   [if test x$enableval = xno; then
	no_preload_client=t
	no_preload_server=t
	no_preload=t
	AC_MSG_RESULT([yes])
    else
	AC_MSG_RESULT([no])
    fi], AC_MSG_RESULT([no]))
fi

if test "x$no_preload" = x; then
    AC_MSG_CHECKING([whether interposition in the client should be disabled])
    AC_ARG_ENABLE(clientdl,
    [  --disable-clientdl      disable support for preloading in the client],
    [if test x$enableval = xno; then
	    no_preload_client=t
	    AC_MSG_RESULT([yes])
    else
	    AC_MSG_RESULT([no])
    fi], AC_MSG_RESULT([no]))

    AC_MSG_CHECKING([whether interposition in the server should be disabled])
    AC_ARG_ENABLE(serverdl,
    [  --disable-serverdl      disable support for preloading in the server],
    [if test x$enableval = xno; then
	    no_preload_server=t
	    AC_MSG_RESULT([yes])
    else
	    if text x$enableval = xyes; then
		serverdl_always_on=t
	    fi
	    AC_MSG_RESULT([no])
    fi], AC_MSG_RESULT([no]))
fi

AM_CONDITIONAL(SERVER_INTERPOSITION, test x$no_preload_server = x)
AM_CONDITIONAL(SERVER_INTERPOSITION_ALWAYS, test x$serverdl_always_on = xt)

if test "x${no_preload_client}" = "xt" -a "x${no_preload_server}" = "xt"; then
    unset preload_enabled
else
    preload_enabled=t
fi

#construct SUBDIRS variable
SUBDIRS="lib sockd unlicensed example doc bin SPECS capi contrib"
if test "x${no_preload_client}" = x; then
    SUBDIRS="dlib $SUBDIRS"
fi
#include should be done before compilation to ensure that
#redefac is executed first
TOPSUBDIRS="$subdirs include libscompat $SUBDIRS"

AC_SUBST(TOPSUBDIRS)


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

AC_MSG_CHECKING([for sockaddr_storage in sys/socket.h])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [
struct sockaddr_storage __ss;
struct sockaddr_in *sin;
sin = (struct sockaddr_in *) &__ss;
], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_SOCKADDR_STORAGE, 1, [sockaddr_storate defined])],
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

	return 0;
}], [AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_TIMER_MACROS, 1, [timeradd(), timersub etc. exist in sys/time.h])],
    [AC_MSG_RESULT(no)])


#A good time to save the cache (L_NSOCKPROTO might fail)
AC_CACHE_SAVE

#find prototypes from dlib/interposition.c
if test "x$preload_enabled" = "xt"; then

	unset failproto

	#prototypes; return value first, then parameters
	#
	# Example (accept from OpenBSD manual page):
	#
        # int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
	#
	# Remove variable names and the result is:
	# int, int, struct sockaddr *, socklen_t *
	# This is quoted and added to the L_NSOCKPROTO call below. 

	L_NSOCKPROTO(accept, [failproto=t], 
	 [int, int, struct sockaddr *, socklen_t *],
	 [int, int, struct sockaddr *, Psocklen_t])

	L_NSOCKPROTO(bind, [failproto=t], 
	 [int, int, const struct sockaddr *, socklen_t])

	L_NSOCKPROTO(connect, [failproto=t], 
	 [int, int, const struct sockaddr *, socklen_t])

	L_NSOCKPROTO(gethostbyaddr, [failproto=t], 
	 [struct hostent *, const char *, int, int],
	 [struct hostent *, const void *, socklen_t, int])

	L_NSOCKPROTO(getpeername, [failproto=t], 
	 [int, int, struct sockaddr *, socklen_t *],
	 [int, int, struct sockaddr *, Psocklen_t])

	L_NSOCKPROTO(getsockname, [failproto=t], 
	 [int, int, struct sockaddr *, socklen_t *],
	 [int, int, struct sockaddr *, Psocklen_t])

	L_NSOCKPROTO(read, [failproto=t], 
	 [ssize_t, int, void *, size_t])

	L_NSOCKPROTO(readv, [failproto=t], 
	 [ssize_t, int, const struct iovec *, int])

	L_NSOCKPROTO(recv, [failproto=t], 
	 [ssize_t, int, void *, size_t, int])

	L_NSOCKPROTO(recvfrom, [failproto=t], 
	 [ssize_t, int, void *, size_t, int, struct sockaddr *, socklen_t *],
	 [ssize_t, int, void *, size_t, int, struct sockaddr *, Psocklen_t])

	L_NSOCKPROTO(recvmsg, [failproto=t], 
	 [ssize_t, int, struct msghdr *, int])

	L_NSOCKPROTO(send, [failproto=t], 
	 [ssize_t, int, const void *, size_t, int])

	L_NSOCKPROTO(sendmsg, [failproto=t], 
	 [ssize_t, int, const struct msghdr *, int])

	L_NSOCKPROTO(sendto, [failproto=t], 
	 [ssize_t, int, const void *, size_t, int, const struct sockaddr *, socklen_t])

	L_NSOCKPROTO(write, [failproto=t], 
	 [ssize_t, int, const void *, size_t])

	L_NSOCKPROTO(writev, [failproto=t], 
	 [ssize_t, int, const struct iovec *, int])

	if test x$failproto != x; then
	    echo ""
	    echo "error: attempt to determine function prototypes failed,"
	    echo "       and will probably mean that building of libdsocks,"
	    echo "       which allows on-the-fly socksification of dynamic"
	    echo "       binaries, will not work."
	    echo ""
	    echo "       You have several options:"
	    echo ""
	    echo "       1. If you do not need libdsocks, run configure with the"
	    echo "          option --disable-preload."
	    echo "       2. Submit a bugreport."
	    echo "       3. Find the prototypes used on your platform for the"
	    echo "          failed functions, and add them to the configure.ac"
	    echo "          file. Then use autoconf (which must be installed)"
	    echo "          to regenerate the configure script."
	    echo "          Function prototype definitions can usually be found"
	    echo "          in the manual page for the function or in a system"
	    echo "          include file (usually located under /usr/include)."
	    exit 1
	fi
fi

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
AC_MSG_CHECKING([to see if dlopen param has DL_ and not RTLD_ prefix])
AC_EGREP_CPP(yes, [
#include <dlfcn.h>
#ifdef DL_LAZY
#else
# ifdef RTLD_LAZY
yes
# endif
#endif
], [AC_DEFINE(NEED_DYNA_RTLD, 1, [dlopen has RTLD_ prefix])
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

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
   AC_MSG_RESULT(no))

AC_MSG_CHECKING([to see if malloc_options exists])
AC_TRY_LINK([extern char *malloc_options;],
[ malloc_options = 0; ],
[AC_DEFINE(HAVE_MALLOC_OPTIONS, 1, [support for malloc debugging])
 AC_MSG_RESULT(yes)],
AC_MSG_RESULT(no))

AC_MSG_CHECKING([to see if __progname exists])
AC_TRY_LINK([extern char *__progname;],
[ __progname = 0; ],
[AC_DEFINE(HAVE_PROGNAME, 1, [programe name symbol exists])
 AC_MSG_RESULT(yes)],
AC_MSG_RESULT(no))

dnl Checks for libraries.
AC_SEARCH_LIBS(crypt, crypt)

#HP-UX 11.00
AC_SEARCH_LIBS(getspnam, sec)

#FreeBSD has setproctitle in -lutil (Per Hedeland <per@erix.ericsson.se>)
AC_SEARCH_LIBS(setproctitle, util)

#pthread mutexes is used if getipnodebyname is implemented
#XXX disable for now
#AC_HAVE_LIBRARY(pthread)

#Look for functions needed for socksify located in other places than libc
SOCKSIFY_PRELOAD_LIBS=""
oLIBS=$LIBS

#HP-UX 11.00
LIBS=""
AC_SEARCH_LIBS(bindresvport, rpcsoc)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

#ignore when preloading is disabled (only the AC_SEARCH_LIBS test is needed)
if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_bindresvport}" = "x-lrpcsoc"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBRPCSOC, "${base_library_path}librpcsoc.sl", [libname])
	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}librpcsoc.sl"

	AC_DEFINE(LIBRARY_BINDRESVPORT, LIBRARY_LIBRPCSOC, [function loc])
fi

LIBS=""
AC_SEARCH_LIBS(connect, socket)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

#ignore when preloading is disabled (only the AC_SEARCH_LIBS test is needed)
if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_connect}" = "x-lsocket"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBSOCKET, "${base_library_path}libsocket.${SOLIB_POSTFIX}", [libloc])
	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}libsocket.${SOLIB_POSTFIX}"

	AC_DEFINE(LIBRARY_CONNECT, LIBRARY_LIBSOCKET, [function loc])

	AC_CHECK_LIB(socket, accept,
		AC_DEFINE(LIBRARY_ACCEPT, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, bind,
		AC_DEFINE(LIBRARY_BIND, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, bindresvport,
		AC_DEFINE(LIBRARY_BINDRESVPORT, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, getpeername,
		AC_DEFINE(LIBRARY_GETPEERNAME, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, getsockname,
		AC_DEFINE(LIBRARY_GETSOCKNAME, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, getaddrinfo,
		AC_DEFINE(LIBRARY_GETADDRINFO, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, freehostent,
		AC_DEFINE(LIBRARY_FREEHOSTENT, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, recvfrom,
		AC_DEFINE(LIBRARY_RECVFROM, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, rresvport,
		AC_DEFINE(LIBRARY_RRESVPORT, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, recvmsg,
		AC_DEFINE(LIBRARY_RECVMSG, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, sendmsg,
		AC_DEFINE(LIBRARY_SENDMSG, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, send,
		AC_DEFINE(LIBRARY_SEND, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, recv,
		AC_DEFINE(LIBRARY_RECV, LIBRARY_LIBSOCKET, [function loc]))

	AC_CHECK_LIB(socket, sendto,
		AC_DEFINE(LIBRARY_SENDTO, LIBRARY_LIBSOCKET, [function loc]))
fi

#doesn't work if test links with -lsocket (Solaris)
AC_SEARCH_LIBS(inet_addr, nsl)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_inet_addr}" = "x-lnsl"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBNSL, "${base_library_path}libnsl.${SOLIB_POSTFIX}", [libloc])

	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}libnsl.${SOLIB_POSTFIX}"

	AC_CHECK_LIB(nsl, gethostbyname,
		[AC_DEFINE(LIBRARY_GETHOSTBYNAME, LIBRARY_LIBNSL, [function loc])])

	AC_CHECK_LIB(nsl, gethostbyaddr,
		[AC_DEFINE(LIBRARY_GETHOSTBYADDR, LIBRARY_LIBNSL, [function loc])])

	AC_CHECK_LIB(nsl, freehostent,
		AC_DEFINE(LIBRARY_FREEHOSTENT, LIBRARY_LIBNSL, [function loc]))

 	AC_CHECK_LIB(nsl, getipnodebyname,
 		[AC_DEFINE(LIBRARY_GETIPNODEBYNAME, LIBRARY_LIBNSL, [function loc])])
fi

#XXX used for anything but gethostbyname2? consider testing for it
# on Solaris (atleast 2.6, gcc)
#linking with -lresolv results in error unless -shared is included
#since gcc insists on linking statically with libresolv for which
#no static version exists
AC_SEARCH_LIBS(inet_aton, resolv)

AC_SEARCH_LIBS(res_9_init, resolv)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_inet_aton}" = "x-lresolv"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBRESOLV, "${base_library_path}libresolv.${SOLIB_POSTFIX}", [libloc])

	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}libresolv.${SOLIB_POSTFIX}"

	AC_CHECK_LIB(resolv, gethostbyname2,
		[AC_DEFINE(LIBRARY_GETHOSTBYNAME2, LIBRARY_LIBRESOLV, [function loc])])
fi

#XXX gcc on Solaris (using gnu ld) doesn't seems to implicitly link
#with libdl in this test, which means that libdl will not be included
#in socksify.

if test "x$preload_enabled" = "xt"; then
    AC_SEARCH_LIBS(dlopen, dl)

    NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
    LIBS=""
    if test "x${ac_cv_search_dlopen}" = "x-ldl"; then
	    case $host in
		*-*-sunos4*) #XXX attempt to get libdl name
		    libdl=`ls ${base_library_path}libdl.${SOLIB_POSTFIX}* | sed -e 's/.*\///' | sort -nr | head -n 1`
		    if test x$libdl = x; then
			AC_MSG_WARN([unable to locate libdl])
		    else
			LIBRARY_DLOPEN=${base_library_path}${libdl}
			AC_MSG_WARN([hardcoding libdl to $LIBRARY_DLOPEN])
		    fi
		;;

		*)
		    LIBRARY_DLOPEN="${base_library_path}libdl.${SOLIB_POSTFIX}"
		;;
	    esac
	    SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${LIBRARY_DLOPEN:+${PRELOAD_SEPERATOR}}${LIBRARY_DLOPEN}"
    fi
fi
LIBS="$oLIBS $NLIBS"

AC_SUBST(SOCKSIFY_PRELOAD_LIBS)

#specify location of the socks library in socksify too
#NOTE: exec_prefix and prefix have the value NONE here if they are unset
o_exec_prefix=${exec_prefix}
o_prefix=${prefix}
if test x${prefix} = xNONE; then
	prefix=$ac_default_prefix
fi
if test x${exec_prefix} = xNONE; then
	exec_prefix=$prefix
fi
LIBRARY_PREFIX=`eval echo \$libdir`
LIBRARY_PREFIX=`eval echo \$LIBRARY_PREFIX`
exec_prefix=${o_exec_prefix}
prefix=${o_prefix}
AC_SUBST(LIBRARY_PREFIX)

#allow user to specify libc name, use default value otherwise
AC_MSG_CHECKING([for libc name])
AC_ARG_WITH(libc,
 [  --with-libc=NAME        manually set name of c library if necessary],
 [LIBC_NAME=$withval])

#set default?
if test "x${LIBC_NAME}" = x; then
	case $host in
		*-*-linux-*)
		#XXX attempt to find latest c library
		#can't set it to libc.so directly, might be ld script
		LIBC_NAME=`ls /usr/lib/libc.so* /lib/libc.so* | sed -e 's/.*\///' | sort -nr | head -n 1`
		if test "x${LIBC_NAME}" = x; then
			#nothing found, set libc.so anyway
			LIBC_NAME="${base_library_path}libc.so"
		fi
	;;

	*)
		LIBC_NAME="${base_library_path}libc.${SOLIB_POSTFIX}"
	;;
	esac
fi

AC_MSG_RESULT(${LIBC_NAME})
AC_DEFINE_UNQUOTED(LIBRARY_LIBC, "${LIBC_NAME}", [libc name])

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

#expected select behaviour?
unset nb_select_err
L_UNCON_SELECT([],
 [nb_select_err=t])

if test x"${nb_select_err}" = xt; then
   AC_MSG_WARN([operations on nonblocking sockets might fail on this platform])
fi

L_SYMBOL_UNDERSCORE()

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
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING([for __libc_enable_secure])
AC_TRY_RUN([
extern int __libc_enable_secure;

int main()
{
	if (__libc_enable_secure == 0)
	   return 0;

	return 1;
}], [AC_MSG_RESULT([yes])
     AC_DEFINE(HAVE_LIBC_ENABLE_SECURE, 1, [linux version of issetugid()])],
     AC_MSG_RESULT([no]))

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
AC_CHECK_FUNCS(select socket strcspn strdup strspn hstrerror issetugid)
AC_CHECK_FUNCS(strvis vsnprintf getdtablesize sysconf inet_pton vsyslog)
AC_CHECK_FUNCS(daemon bzero sockatmark difftime memmove seteuid setproctitle)
AC_CHECK_FUNCS(inet_aton gethostbyname2 getaddrinfo getipnodebyname)
AC_CHECK_FUNCS(getprpwnam getspnam getifaddrs freeifaddrs bindresvport)
AC_CHECK_FUNCS(setegid)

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

#sun4 seems to have a profiled libc missing strerror
if test x$s_profiling = x; then
	AC_CHECK_FUNCS(strerror)
else
	case $host in
		*-*-sunos4*)
			AC_MSG_WARN([omitting strerror test on sunos4 with profiling enabled])
		;;

		*)
			AC_CHECK_FUNCS(strerror)
		;;
	esac
fi

if false; then
   AC_DEFINE(HAVE_DUMPCONF, 1, [GUI tool])
fi

#look for modules, and check version
L_MODVER(bandwidth, 31) #module name, version
L_MODVER(redirect, 18)
L_MODVER(session, 3)

#helper files
L_MODVER(checkmodule, 1, nokey)
L_MODVER(shmem, 1, nokey)

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
    echo "CPPFLAGS: $CPPFLAGS"
fi

AC_SUBST(TOPEXTRADIST)

AC_CONFIG_FILES(sockd/Makefile include/Makefile lib/Makefile dlib/Makefile)
AC_CONFIG_FILES(Makefile example/Makefile doc/Makefile bin/Makefile)
AC_CONFIG_FILES(capi/Makefile SPECS/Makefile SPECS/dante.spec bin/socksify)
AC_CONFIG_FILES(libscompat/Makefile contrib/Makefile unlicensed/Makefile)
AC_CONFIG_FILES(doc/module/Makefile VERSION)

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
	echo "Preloading:        disabled"
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
        echo "                   operations on nonblocking sockets might fail on this platform"
else
	echo "select:            OK"
fi


if test x"${no_routeinfo}" = xt; then
	echo "Routeinfo:         not supported on this platform"
else
	echo "Routeinfo:         OK"
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

Note that Dante pre-releases are often configured in a way that can
significantly increase the load on the machine.  This is done to
stress the server more, increasing the chances of detecting potential
problems.
"
fi

VINFO=README.latest
test -s "$VINFO" && cat "$VINFO"

exit 0
