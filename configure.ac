AC_INIT
AC_PREREQ(2.50)
AC_REVISION($Id: configure.ac,v 1.300 2002/04/11 13:41:17 karls Exp $)

version=1.1.12
#set this to enable prerelease, changes some defaults (debug enabled)
#prerelease="1"
if test x$prerelease != x; then
	prename="-pre$prerelease"
	TOPEXTRADIST="${TOPEXTRADIST} PRERELEASE"
else
	prename=""
fi

AM_INIT_AUTOMAKE(dante, ${version}${prename})
AC_CONFIG_SRCDIR(include/common.h)
AM_CONFIG_HEADER(include/autoconf.h)

#NOTE: save CFLAGS; wish to compile without -O2 when debugging
oCFLAGS=$CFLAGS
unset CFLAGS
AC_AIX #evidently also modifies CFLAGS
AM_PROG_LIBTOOL
autoconf_compflags=$CFLAGS
CFLAGS=$oCFLAGS

AC_PROG_CPP

AM_CONDITIONAL(PRERELEASE, test x$prerelease != x)

#known keywords for --enable/disable-foo(=yes/no)?
LTINTERNAL="dlopen|dlopen_self|dlopen_self_static|fast_install|libtool_lock|win32_dll"
KNOWN_KEYWORDS="$LTINTERNAL|shared|static|debug|warnings|diagnostic|profiling|linting|libwrap|preload|serverdl|clientdl|internal|pidfile"
for keyword in `set | egrep '^enable_' | sed -e 's/^enable_\(.*\)=.*/\1/'`;
do
	echo $keyword | egrep "^(${KNOWN_KEYWORDS})$" > /dev/null
	if test $? -ne 0; then
		AC_MSG_WARN(unknown option '$keyword', ignoring ...)
		sleep 10;
	fi
done

#Solaris 2.5.1 is broken in many places
case $host in
    *-*-solaris2.5.1)
	AC_MSG_WARN(the server might not work properly on solaris 2.5.1)
	AC_DEFINE(HAVE_SOLARIS_2_5_1)
    ;;
esac

#disable acceptlock
#XXX add proper test for this?
case $host in

	*-*-*bsd* | alpha*-dec-osf* | *-*-hpux* | *-*-aix4*)
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
		AC_DEFINE(HAVE_DEC_PROTO)
		AC_DEFINE(HAVE_EXTRA_OSF_SYMBOLS)
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
		AC_DEFINE(LIBRARY_PATH, "/usr/lib/")
		base_library_path="/usr/lib/"
		AC_MSG_WARN("notice: hardcoding /usr/lib for dlopen")
		#nonstandard libfunction workaround #XXX proper test
		AC_DEFINE(HAVE_BROKEN_VSPRINTF)
		#link problems with libresolv, hardcode domainname
		if test -s /etc/resolv.conf; then
		    domainname_hardcoded=`grep domain /etc/resolv.conf | awk '{ print $2 }'`
		fi
		no_res_init=t
		AC_DEFINE(HAVE_NO_RESOLVESTUFF)
	;;

	*-*-solaris*)
		AC_DEFINE(HAVE_SENDMSG_DEADLOCK)
		AC_DEFINE(HAVE_SOLARIS_BUGS)
		AC_DEFINE(BSD_COMP)
		AC_DEFINE(HAVE_SOLARIS_PAM_BUG)
	;;

	*-*-linux-*) # XXX This might only concern 2.0.x kernels (add test?)
		AC_DEFINE(HAVE_DEFECT_RECVMSG)
		AC_DEFINE(HAVE_LINUX_BUGS)
		AC_DEFINE(HAVE_LINUX_ECCENTRICITIES)
		AC_DEFINE(SPT_PADCHAR, '\0')
	;;

	*-*-openbsd*) #static sockd when profiling is enabled
		no_dynamic_profiled_sockd=t
	;;

	*-*-irix*)
		PRELOAD="RLD"
	;;
	*-*-aix4*)
		OSPIDFILE="/etc/sockd.pid"
	;;
	*-*-cygwin)
		AC_MSG_WARN(disabling preloading)
		no_preload_client=t
		no_preload_server=t
		no_preload=t
		no_res_init=t
		AC_DEFINE(HAVE_NO_RESOLVESTUFF)
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
AC_DEFINE_UNQUOTED(HAVE_HOST_TYPE, "$host")

#XXX add proper test for this?
if test x$no_acceptlock != xt; then
	AC_DEFINE(NEED_ACCEPTLOCK)
fi

AC_MSG_CHECKING(for compiler flags)
case $host in

    #XXX check for compiler type, not architecture
    *-*-solaris*)
	if test "x$GCC" = x; then
	    #-xs provides allows easier debugging with gdb
	    comp_flags="-Xt -xs" #XXX -Xt needed to compile?
	    #XXX due to some problems with sockaddr alignment
	    #XXX sun cc needs -misalign
	    comp_flags="$comp_flags -misalign -xO0"
	    AC_MSG_RESULT($comp_flags)
	    AC_MSG_WARN(there might currenly be some performance problems with suncc - it needs -misalign)
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
#	AC_MSG_RESULT($comp_flags)
    ;;

    alphaev6-dec-osf*)
	if test "x$GCC" = x; then
	    comp_flags="-std1"
	fi
	AC_MSG_RESULT($comp_flags)
    ;;

    alpha*-dec-osf*) #XXX is it possible to get it to work with -newc?
	if test "x$GCC" = x; then
	    comp_flags="-std1 -oldc"
	fi
	AC_MSG_RESULT($comp_flags)
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
	AC_MSG_RESULT($comp_flags)
	;;

    *-*-aix4*)
	if test "x$GCC" = x; then
	    comp_flags="-qlanglvl=ansi"
	    #XXX
	    CPPFLAGS="${CPPFLAGS} -qlanglvl=ansi"
	fi
	AC_MSG_RESULT($comp_flags)
     ;;

    *)
	AC_MSG_RESULT(none)
    ;;
    #XXX make sure compiling with compiler options works
esac

AC_MSG_CHECKING(for support for -pipe compiler flag)
oCFLAGS=$CFLAGS
CFLAGS="$CFLAGS -pipe"
AC_TRY_RUN([
int main()
{
	return 0;
}], [AC_MSG_RESULT(yes)
     comp_flags="${comp_flags} -pipe"],
    AC_MSG_RESULT(no))
CFLAGS="$oCFLAGS"

AC_ARG_ENABLE(internal,
[  --enable-internal       enable internal extensions],
   [TOPEXTRADIST="${TOPEXTRADIST} gui"
    AC_CONFIG_SUBDIRS(gui)
    ],
   unset build_internal)

AC_MSG_CHECKING(for compilation with debugging)
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
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
    #autoconf_compflags is set to "-g -O2" with GCC
    CFLAGS="$CFLAGS $autoconf_compflags"
fi

#-Wall ?
AC_MSG_CHECKING(for warning flags)
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
		   [AC_MSG_RESULT($warn)],
		   [AC_MSG_RESULT(none)
		    unset warn])
    CFLAGS=$oCFLAGS
else
    AC_MSG_RESULT(none)
fi

#NOTE: set warnings at the bottom; might interfere with tests
CFLAGS="$CFLAGS $comp_flags"

#-DDIAGNOSTICS?
AC_MSG_CHECKING(for compliation with DIAGNOSTIC)
AC_ARG_ENABLE(diagnostic,
[  --enable-diagnostic     enable diagnostic],
	[AC_DEFINE(DIAGNOSTIC)
	 AC_MSG_RESULT(yes)],
	[if test x$prerelease != x; then
	      AC_DEFINE(DIAGNOSTIC)
	      AC_MSG_RESULT(yes)
	 else
	      AC_MSG_RESULT(no)
	 fi])

AC_ARG_ENABLE(profiling,
[  --enable-profiling      compile with profiling support in server],
[   AC_DEFINE(HAVE_PROFILING)
    s_profiling=t])

AM_CONDITIONAL(SPROFIL, test x$s_profiling = xt)
#static or dynamic sockd?
AM_CONDITIONAL(STATIC_SOCKD, test x$no_dynamic_profiled_sockd = xt)
if test "x$s_profiling" = "xt" -a "x$no_dynamic_profiled_sockd" = "xt"; then
	no_preload_server=t
	AC_MSG_WARN(sockd is built static when profiling is enabled)
fi

AC_ARG_ENABLE(linting,
[  --enable-linting        enable lint],
	s_linting=t)
AM_CONDITIONAL(LINT, test x$s_linting = xt)

AC_MSG_CHECKING(whether libwrap should be disabled)
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       never use libwrap, even if it is available],
[if test x$enableval = xno; then
	no_libwrap=t
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi], AC_MSG_RESULT(no))

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
AC_CHECK_HEADERS(netinet/ip_var.h tcpd.h shadow.h ifaddrs.h sys/sem.h)
AC_CHECK_HEADERS(sys/ipc.h arpa/nameser.h resolv.h)

case $host in
	alpha*-dec-osf*)
		AC_CHECK_HEADERS(netinet/ip.h)
	;;
	*) ;;
esac

#build without support for preloading?
AC_MSG_CHECKING(whether all interposition usage should be disabled)
AC_ARG_ENABLE(preload,
[  --disable-preload       disable preloading in server and client],
[if test x$enableval = xno; then
	no_preload_client=t
	no_preload_server=t
	no_preload=t
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi], AC_MSG_RESULT(no))

if test "x$no_preload" = x; then
    AC_MSG_CHECKING(whether interposition in the client should be disabled)
    AC_ARG_ENABLE(clientdl,
    [  --disable-clientdl      disable support for preloading in the client],
    [if test x$enableval = xno; then
	    no_preload_client=t
	    AC_MSG_RESULT(yes)
    else
	    AC_MSG_RESULT(no)
    fi], AC_MSG_RESULT(no))

    AC_MSG_CHECKING(whether interposition in the server should be disabled)
    AC_ARG_ENABLE(serverdl,
    [  --disable-serverdl      disable support for preloading in the server],
    [if test x$enableval = xno; then
	    no_preload_server=t
	    AC_MSG_RESULT(yes)
    else
	    if text x$enableval = xyes; then
		serverdl_always_on=t
	    fi
	    AC_MSG_RESULT(no)
    fi], AC_MSG_RESULT(no))
fi

AM_CONDITIONAL(SERVER_INTERPOSITION, test x$no_preload_server = x)
AM_CONDITIONAL(SERVER_INTERPOSITION_ALWAYS, test x$serverdl_always_on = xt)

if test "x${no_preload_client}" = "xt" -a "x${no_preload_server}" = "xt"; then
    unset preload_enabled
else
    preload_enabled=t
fi


#allow manual specification
AC_MSG_CHECKING(for hardcoded domainname)
AC_ARG_WITH(domainname,
[  --with-domainname=NAME  hardcode local domainname (only on broken platforms)], [domainname_hardcoded=$withval])

if test x${domainname_hardcoded} != x; then
    AC_DEFINE_UNQUOTED(SOCKS_DOMAINNAME, "${domainname_hardcoded}")
    AC_MSG_RESULT(yes)
    AC_MSG_WARN(using hardcoded domainname ${domainname_hardcoded})
else
    AC_MSG_RESULT(no)
    if test x${no_res_init} = xt; then
	AC_MSG_WARN(unable to locate domainname, specify if necessary)
    fi
fi

#allow default file locations to be overridden
AC_MSG_CHECKING(for socks config file location)
AC_ARG_WITH(socks-conf,
[  --with-socks-conf=FILE  change location of socks client configuration file],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKS_CONFIGFILE)
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKS_CONFIGFILE, "$withval")
], [AC_MSG_RESULT(default)])

AC_MSG_CHECKING(for sockd config file location)
AC_ARG_WITH(sockd-conf,
[  --with-sockd-conf=FILE  change location of socks server configuration file],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKD_CONFIGFILE)
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_CONFIGFILE, "$withval")
], [AC_MSG_RESULT(default)])

#pidfile
AC_ARG_ENABLE(pidfile,
[  --disable-pidfile       disable server pidfile creation],
   [AC_DEFINE(HAVE_DISABLED_PIDFILE)])

AC_MSG_CHECKING(for pid file location)
AC_ARG_WITH(pidfile,
[  --with-pidfile=FILE     change location of server pidfile],
[AC_MSG_RESULT($withval)
 AC_DEFINE(HAVE_SOCKD_PIDFILE)
 AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_PIDFILE, "$withval")
 have_pidfile=t
], [AC_MSG_RESULT(default)])

#os default?
if test x"${have_pidfile}" != xt; then
    if test x"$OSPIDFILE" != x; then
	AC_DEFINE(HAVE_SOCKD_PIDFILE)
	AC_DEFINE_UNQUOTED(HAVE_ALT_SOCKD_PIDFILE, "$OSPIDFILE")
    fi
fi

# SOCKSLIBRARY_DYNAMIC is set in the lib directory when preloading
# is supported (and requested).
# HAVE_DLFCN_H only determines if the include file exists
AC_CHECK_HEADER(dlfcn.h,
[AC_DEFINE(HAVE_DLFCN_H)
 have_dlfcn_h=t])

#building of shared libraries enabled?
unset build_preload_lib
if test "x${no_preload_client}" = "x" -a "x$have_dlfcn_h" = "xt"; then
    build_preload_lib=t
fi


#construct SUBDIRS variable
SUBDIRS="lib sockd unlicensed example doc bin SPECS capi contrib"
if test x"${build_preload_lib}" = xt; then
    SUBDIRS="dlib $SUBDIRS"
fi
#include should be done before compilation to ensure that
#redefac is executed first
TOPSUBDIRS="$subdirs include libscompat $SUBDIRS"

AC_SUBST(TOPSUBDIRS)


AC_CHECK_HEADER(sys/sockio.h,
[AC_DEFINE(HAVE_SYS_SOCKIO_H)
 have_sys_sockio_h=t])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_MSG_CHECKING(whether <sys/types.h> defines const)
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
AC_MSG_CHECKING(for supported routing socket communication)
unset no_routeinfo
AC_EGREP_CPP(yes, [
#include <net/route.h>
#ifdef linux
yes
#endif /* linux */
], [AC_DEFINE(HAVE_ROUTE_SOURCE)
    AC_DEFINE(HAVE_ROUTEINFO_LINUX)
    AC_MSG_RESULT(yes)],
   [AC_EGREP_CPP(yes, [
#include <net/route.h>
#ifdef RTA_GATEWAY
yes
#endif /* RTA_GATEWAY */
],  [AC_DEFINE(HAVE_ROUTE_SOURCE)
     AC_DEFINE(HAVE_ROUTEINFO_BSD)
     AC_MSG_RESULT(yes)],
     [AC_MSG_RESULT(no, might result in reduced functionality)
      no_routeinfo=t])])

AC_MSG_CHECKING(whether <netdb.h> declares h_errno)
AC_EGREP_CPP(h_errno, [
#include <netdb.h>
], [AC_DEFINE(HAVE_H_ERRNO)
    AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)])

#XXXsys/socket.h?
AC_MSG_CHECKING(for struct ip_opts in <netinet/in.h>)
AC_EGREP_CPP([struct.*ipoption], [
#include <netinet/ip_var.h>
], [AC_DEFINE(HAVE_STRUCT_IPOPTS)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING(whether <sys/types.h> defines inline)
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

AC_MSG_CHECKING(for sockaddr_storage in sys/socket.h)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [
struct sockaddr_storage __ss;
struct sockaddr_in *sin;
sin = (struct sockaddr_in *) &__ss;
], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_SOCKADDR_STORAGE)],
   [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(to see if openlog accepts LOG_PERROR)
AC_EGREP_CPP(yes, [
#include <syslog.h>
#ifdef LOG_PERROR
yes
#endif
], [AC_DEFINE(HAVE_OPENLOG_LOG_PERROR)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING(to see if stdlib.h defines EXIT_FAILURE)
AC_EGREP_CPP(yes, [
#include <stdlib.h>
#ifdef EXIT_FAILURE
yes
#endif
], [AC_MSG_RESULT(yes)],
   [AC_DEFINE(NEED_EXIT_FAILURE)
    AC_MSG_RESULT(no)])

#XXX actually checks if AF_UNIX should be used instead of AF_LOCAL
AC_MSG_CHECKING(whether <sys/socket.h> uses AF_UNIX)
AC_EGREP_CPP(yes, [
#include <sys/types.h>
#include <sys/socket.h>
#ifdef AF_LOCAL
#else
#ifdef AF_UNIX
yes
#endif
#endif
], [AC_DEFINE(NEED_AF_LOCAL)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING(for SIGINFO)
AC_EGREP_CPP(yes, [
#include <signal.h>
#ifdef SIGINFO
yes
#endif
], [AC_DEFINE(HAVE_SIGNAL_SIGINFO)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING(to see if MSG_WAITALL exists)
AC_EGREP_CPP(yes, [
#include <sys/socket.h>
#ifdef MSG_WAITALL
yes
#endif
], [AC_DEFINE(HAVE_MSG_WAITALL)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

#SO_SNDLOWAT
#irix 6.2 only seems to look at lowest 8 bit of value
#Solaris also seems to be broken (up to 2.6 atleast)
AC_MSG_CHECKING(whether a working SO_SNDLOWAT exists)
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
	AC_DEFINE(HAVE_SO_SNDLOWAT)
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(disabled)
	AC_MSG_WARN(performance in the server might be degraded without support for the SO_SNDLOWAT socket option)
fi], [AC_MSG_RESULT(no)
      AC_MSG_WARN(performance in the server might be degraded without support for the SO_SNDLOWAT socket option)])

#correct select behaviour?
unset nb_select_err
L_UNCON_SELECT([],
 [nb_select_err=t])

if test x"${nb_select_err}" = xt; then
   AC_MSG_WARN(operations on nonblocking sockets might fail on this platform)
fi


AC_MSG_CHECKING(whether realloc with a NULL pointer calls malloc)
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
    [AC_DEFINE(HAVE_NOMALLOC_REALLOC)
     AC_MSG_RESULT(no)])

AC_MSG_CHECKING(whether free can be called with NULL)
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
    [AC_DEFINE(HAVE_NONULL_FREE)
     AC_MSG_RESULT(no)])

#A good time to save the cache (L_SOCKPROTO might fail)
AC_CACHE_SAVE

#find prototypes for interposition.c
if test "x$preload_enabled" = "xt"; then

    unset failproto

    if test "x${ac_cv_header_stdc}" = xyes; then

	#does $CPP define __STDC__?
	AC_EGREP_CPP(yes, [
#ifdef __STDC__
yes
#endif
	], [CPPFLAG_STDC=""], [CPPFLAG_STDC="-D__STDC__"])

	#L_SOCKPROTO is used to determine the argument types of the functions
	#which are used in dlib/interposition.c. It compares the prototypes in
	#(mainly) <sys/socket.h> and compares them to a list of known
	#values. The arguments to L_SOCKPROTO are:
	#1: the name of the function
	#2: shell code which is executed if no known prototype is found
	#3...: a list of known types, the first is a list of known return values,
	#      the second a list of known values for the first argument etc.
	#To add new values to the list simply add the new values at the end of
	#the list. (to add a new function a set of #undef statements in
	#acconfig.h is also needed).
	case $host in
		*-*-aix4*)
			PROTO_ACCEPT=naccept
			PROTO_GETPEERNAME=ngetpeername
			PROTO_GETSOCKNAME=ngetsockname
			PROTO_RECVFROM=nrecvfrom
			PROTO_RECVMSG=nrecvmsg
			PROTO_SENDMSG=nsendmsg
		;;
		*)
			PROTO_ACCEPT=accept
			PROTO_GETPEERNAME=getpeername
			PROTO_GETSOCKNAME=getsockname
			PROTO_RECVFROM=recvfrom
			PROTO_RECVMSG=recvmsg
			PROTO_SENDMSG=sendmsg
		;;
	esac

	L_SOCKPROTO(connect, [failproto=t],
	["int"],
	["int"],
	["const struct sockaddr *" "__CONST_SOCKADDR_ARG" "struct sockaddr *" "const void *" "__const struct sockaddr *"],
	["socklen_t" "int" "size_t" "__socklen_t"])

	L_SOCKPROTO(${PROTO_ACCEPT}.accept, [failproto=t],
	["int"],
	["int"],
	["struct sockaddr *" "__SOCKADDR_ARG" "__const struct sockaddr *" "void *"],
	["socklen_t *" "int *" "Psocklen_t" "size_t *" "__socklen_t *"])

	L_SOCKPROTO(bind, [failproto=t],
	["int"],
	["int"],
	["const struct sockaddr *" "__CONST_SOCKADDR_ARG" "struct sockaddr *" "const void *" "__const struct sockaddr *"],
	["socklen_t" "int" "size_t" "__socklen_t"])

	L_SOCKPROTO(${PROTO_GETPEERNAME}.getpeername, [failproto=t],
	["int"],
	["int"],
	["struct sockaddr *" "__SOCKADDR_ARG" "void *"],
	["socklen_t *" "int *" "Psocklen_t" "size_t *" "__socklen_t *"])

	L_SOCKPROTO(${PROTO_GETSOCKNAME}.getsockname, [failproto=t],
	["int"],
	["int"],
	["struct sockaddr *" "__SOCKADDR_ARG" "void *"],
	["int *" "socklen_t *" "Psocklen_t" "size_t *" "__socklen_t *"])

	L_SOCKPROTO(${PROTO_RECVFROM}.recvfrom, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["void *" "char *"],
	["size_t" "int"],
	["int" "unsigned int"],
	["struct sockaddr *" "__SOCKADDR_ARG" "void *"],
	["socklen_t *" "int *" "Psocklen_t" "size_t *" "__socklen_t *"])

	L_SOCKPROTO(send, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["const void *" "__const void *" "const char *"],
	["size_t" "int"],
	["int" "unsigned int"])

	L_SOCKPROTO(sendto, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["const void *" "__const void *" "const char *"],
	["size_t" "int"],
	["int" "unsigned int"],
	["const struct sockaddr *" "__CONST_SOCKADDR_ARG" "const void *" "__const struct sockaddr *"],
	["socklen_t" "int" "size_t" "__socklen_t"])

	L_SOCKPROTO(recv, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["void *" "char *"],
	["size_t" "int"],
	["int" "unsigned int"])

	L_SOCKPROTO(readv, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["const struct iovec *" "__const struct iovec *" "struct iovec *"],
	["int" "size_t"])

	L_SOCKPROTO(${PROTO_RECVMSG}.recvmsg, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["struct msghdr *"],
	["int" "unsigned int"])

	L_SOCKPROTO(writev, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["const struct iovec *" "__const struct iovec *"],
	["int" "size_t"])

	L_SOCKPROTO(${PROTO_SENDMSG}.sendmsg, [failproto=t],
	["ssize_t" "int"],
	["int"],
	["const struct msghdr *" "__const struct msghdr *"],
	["int" "unsigned int"])

	L_SOCKPROTO(write, [failproto=t],
	["ssize_t"],
	["int"],
	["const void *" "__const void *"],
	["size_t" "unsigned"])

	L_SOCKPROTO(read, [failproto=t],
	["ssize_t"],
	["int"],
	["void *"],
	["size_t" "unsigned"])


#XXX
case $host in
	mips-sgi-irix*)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_0, struct hostent *)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_1, const char *)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_2, int)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_3, int)
	;;
	*)

	L_SOCKPROTO(gethostbyaddr, [failproto=t],
	["struct hostent *"],
	["const char *" "const void *" "__const char *" "__const void *"],
	["int" "size_t" "__socklen_t"],
	["int"])
	;;
esac

	if test x$failproto != x; then
	    echo ""
	    echo "error: some unfamiliar function prototypes were found,"
	    echo "       and will probably mean that building of libdsocks,"
	    echo "       which allows on-the-fly socksification of dynamic"
	    echo "       binaries will not work."
	    echo ""
	    echo "       You have several options:"
	    echo ""
	    echo "       1. If you do not need libdsocks, run configure with the"
	    echo "          option --disable-preload."
	    echo "       2. Send the output from configure to dante-bugs@inet.no"
	    echo "          and if possible you'll get a patch fixing the problem."
	    echo "          If you think this might be a generic problem, sending"
	    echo "          the output might allow the problem to be solved for all"
	    echo "          users of your platform in the next release."
	    echo "       3. Fix the problem yourself. If you have autoconf installed,"
	    echo "          using the output above to modify configure.in should"
	    echo "          enable you to compile without problems."
	    #platform specific problems
	    case $host in
		 *-*-solaris*)
			echo "       4. Remove '/usr/ucb' if it is in the PATH."
			;;
			*-*-darwin*)
			echo "       4. The preprocessed header for unistd.h might be corrupt."
			echo "          Try to regenerate it or rename unistd.p while you build this package."
			;;
	    esac
	    echo ""
	    exit 1
	fi
    else #non ansi
	#defaults
	AC_DEFINE(HAVE_PROT_CONNECT_0, int)
	AC_DEFINE(HAVE_PROT_CONNECT_1, int)
	AC_DEFINE(HAVE_PROT_CONNECT_2, const struct sockaddr *)
	AC_DEFINE(HAVE_PROT_CONNECT_3, socklen_t)

	AC_DEFINE(HAVE_PROT_ACCEPT_0, int)
	AC_DEFINE(HAVE_PROT_ACCEPT_1, int)
	AC_DEFINE(HAVE_PROT_ACCEPT_2, struct sockaddr *)
	AC_DEFINE(HAVE_PROT_ACCEPT_3, socklen_t *)

	AC_DEFINE(HAVE_PROT_BIND_0, int)
	AC_DEFINE(HAVE_PROT_BIND_1, int)
	AC_DEFINE(HAVE_PROT_BIND_2, const struct sockaddr *)
	AC_DEFINE(HAVE_PROT_BIND_3, socklen_t)

	AC_DEFINE(HAVE_PROT_GETPEERNAME_0, int)
	AC_DEFINE(HAVE_PROT_GETPEERNAME_1, int)
	AC_DEFINE(HAVE_PROT_GETPEERNAME_2, struct sockaddr *)
	AC_DEFINE(HAVE_PROT_GETPEERNAME_3, socklen_t *)

	AC_DEFINE(HAVE_PROT_GETSOCKNAME_0, int)
	AC_DEFINE(HAVE_PROT_GETSOCKNAME_1, int)
	AC_DEFINE(HAVE_PROT_GETSOCKNAME_2, struct sockaddr *)
	AC_DEFINE(HAVE_PROT_GETSOCKNAME_3, socklen_t *)

	AC_DEFINE(HAVE_PROT_RECVFROM_0, ssize_t)
	AC_DEFINE(HAVE_PROT_RECVFROM_1, int)
	AC_DEFINE(HAVE_PROT_RECVFROM_2, void *)
	AC_DEFINE(HAVE_PROT_RECVFROM_3, size_t)
	AC_DEFINE(HAVE_PROT_RECVFROM_4, int)
	AC_DEFINE(HAVE_PROT_RECVFROM_5, struct sockaddr *)
	AC_DEFINE(HAVE_PROT_RECVFROM_6, socklen_t *)

	AC_DEFINE(HAVE_PROT_SEND_0, ssize_t)
	AC_DEFINE(HAVE_PROT_SEND_1, int)
	AC_DEFINE(HAVE_PROT_SEND_2, const void *)
	AC_DEFINE(HAVE_PROT_SEND_3, size_t)
	AC_DEFINE(HAVE_PROT_SEND_4, int)

	AC_DEFINE(HAVE_PROT_RECV_0, ssize_t)
	AC_DEFINE(HAVE_PROT_RECV_1, int)
	AC_DEFINE(HAVE_PROT_RECV_2, void *)
	AC_DEFINE(HAVE_PROT_RECV_3, size_t)
	AC_DEFINE(HAVE_PROT_RECV_4, int)

	AC_DEFINE(HAVE_PROT_SENDTO_0, ssize_t)
	AC_DEFINE(HAVE_PROT_SENDTO_1, int)
	AC_DEFINE(HAVE_PROT_SENDTO_2, const void *)
	AC_DEFINE(HAVE_PROT_SENDTO_3, size_t)
	AC_DEFINE(HAVE_PROT_SENDTO_4, int)
	AC_DEFINE(HAVE_PROT_SENDTO_5, const struct sockaddr *)
	AC_DEFINE(HAVE_PROT_SENDTO_6, socklen_t)

	AC_DEFINE(HAVE_PROT_READV_0, ssize_t)
	AC_DEFINE(HAVE_PROT_READV_1, int)
	AC_DEFINE(HAVE_PROT_READV_2, const struct iovec *)
	AC_DEFINE(HAVE_PROT_READV_3, int)

	AC_DEFINE(HAVE_PROT_WRITEV_0, ssize_t)
	AC_DEFINE(HAVE_PROT_WRITEV_1, int)
	AC_DEFINE(HAVE_PROT_WRITEV_2, const struct iovec *)
	AC_DEFINE(HAVE_PROT_WRITEV_3, int)

	AC_DEFINE(HAVE_PROT_RECVMSG_0, ssize_t)
	AC_DEFINE(HAVE_PROT_RECVMSG_1, int)
	AC_DEFINE(HAVE_PROT_RECVMSG_2, struct msghdr *)
	AC_DEFINE(HAVE_PROT_RECVMSG_3, int)

	AC_DEFINE(HAVE_PROT_SENDMSG_0, ssize_t)
	AC_DEFINE(HAVE_PROT_SENDMSG_1, int)
	AC_DEFINE(HAVE_PROT_SENDMSG_2, const struct msghdr *)
	AC_DEFINE(HAVE_PROT_SENDMSG_3, int)

	AC_DEFINE(HAVE_PROT_WRITE_0, ssize_t)
	AC_DEFINE(HAVE_PROT_WRITE_1, int)
	AC_DEFINE(HAVE_PROT_WRITE_2, const void *)
	AC_DEFINE(HAVE_PROT_WRITE_3, size_t)

	AC_DEFINE(HAVE_PROT_READ_0, ssize_t)
	AC_DEFINE(HAVE_PROT_READ_1, int)
	AC_DEFINE(HAVE_PROT_READ_2, void *)
	AC_DEFINE(HAVE_PROT_READ_3, size_t)

	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_0, struct hostent *)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_1, const char *)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_2, int)
	AC_DEFINE(HAVE_PROT_GETHOSTBYADDR_3, int)
    fi #stdc_headers
fi #no preload

AC_MSG_CHECKING(if getsockopt needs cast)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
int getsockopt(int, int, int, char *, int *);
], [ 1 ],
 [AC_DEFINE(NEED_GETSOCKOPT_CAST)
  AC_MSG_RESULT(yes)],
 AC_MSG_RESULT(no))

#include both <sys/ioctl.h> and <sys/sockio.h>?
if test x$have_sys_sockio_h = xt; then
	AC_MSG_CHECKING(to see if <sys/sockio.h> should be included)
	AC_EGREP_CPP(yes, [
#include <sys/ioctl.h>
#ifdef SIOCATMARK
#else
#include <sys/sockio.h>
#ifdef SIOCATMARK
yes
#endif
#endif
], [AC_DEFINE(NEED_SYS_SOCKIO_H)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))
fi

#XXX should be more generic, check if nonexistent
AC_MSG_CHECKING(to see if dlopen param has DL_ and not RTLD_ prefix)
AC_EGREP_CPP(yes, [
#include <dlfcn.h>
#ifdef DL_LAZY
#else
# ifdef RTLD_LAZY
yes
# endif
#endif
], [AC_DEFINE(NEED_DYNA_RTLD)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

#XXX should be more generic, check if nonexistent
#SV_INTERRUPT, but not SA_RESTART defined?
AC_MSG_CHECKING(to see if SV_INTERRUPT should be used)
AC_EGREP_CPP(yes, [
#include <signal.h>
#ifdef SA_RESTART
#else
# ifdef SV_INTERRUPT
yes
# endif
#endif
], [AC_DEFINE(NEED_SA_RESTART)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

#XXXseems to be supported on Solaris2.6, but there might be some
#defines that need to be set (should _XOPEN_SOURCE be defined on all
#platforms?)
AC_MSG_CHECKING(if cmsghdr exists in <sys/socket.h>)
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
], [AC_DEFINE(HAVE_CMSGHDR)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))
	;;
esac

AC_MSG_CHECKING(for sa_len in sockaddr)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [struct sockaddr foo;
foo.sa_len = 0;
], [AC_DEFINE(HAVE_SOCKADDR_SA_LEN)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

AC_MSG_CHECKING(to see if malloc_options exists)
AC_TRY_LINK([extern char *malloc_options;],
[ malloc_options = 0; ],
[AC_DEFINE(HAVE_MALLOC_OPTIONS)
 AC_MSG_RESULT(yes)],
AC_MSG_RESULT(no))

AC_MSG_CHECKING(to see if __progname exists)
AC_TRY_LINK([extern char *__progname;],
[ __progname = 0; ],
[AC_DEFINE(HAVE_PROGNAME)
 AC_MSG_RESULT(yes)],
AC_MSG_RESULT(no))

dnl Checks for libraries.
AC_SEARCH_LIBS(crypt, crypt)

#HP-UX 11.00
AC_SEARCH_LIBS(getspnam, sec)

#FreeBSD has setproctitle in -lutil (Per Hedeland <per@erix.ericsson.se>)
AC_SEARCH_LIBS(setproctitle, util)

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
	AC_DEFINE_UNQUOTED(LIBRARY_LIBRPCSOC, "${base_library_path}librpcsoc.sl")
	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}librpcsoc.sl"

	AC_DEFINE(LIBRARY_BINDRESVPORT, LIBRARY_LIBRPCSOC)
fi


LIBS=""
AC_SEARCH_LIBS(connect, socket)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

#ignore when preloading is disabled (only the AC_SEARCH_LIBS test is needed)
if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_connect}" = "x-lsocket"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBSOCKET, "${base_library_path}libsocket.${SOLIB_POSTFIX}")
	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}libsocket.${SOLIB_POSTFIX}"

	AC_DEFINE(LIBRARY_CONNECT, LIBRARY_LIBSOCKET)

	AC_CHECK_LIB(socket, accept,
		AC_DEFINE(LIBRARY_ACCEPT, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, bind,
		AC_DEFINE(LIBRARY_BIND, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, bindresvport,
		AC_DEFINE(LIBRARY_BINDRESVPORT, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, getpeername,
		AC_DEFINE(LIBRARY_GETPEERNAME, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, getsockname,
		AC_DEFINE(LIBRARY_GETSOCKNAME, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, recvfrom,
		AC_DEFINE(LIBRARY_RECVFROM, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, rresvport,
		AC_DEFINE(LIBRARY_RRESVPORT, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, recvmsg,
		AC_DEFINE(LIBRARY_RECVMSG, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, sendmsg,
		AC_DEFINE(LIBRARY_SENDMSG, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, send,
		AC_DEFINE(LIBRARY_SEND, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, recv,
		AC_DEFINE(LIBRARY_RECV, LIBRARY_LIBSOCKET))

	AC_CHECK_LIB(socket, sendto,
		AC_DEFINE(LIBRARY_SENDTO, LIBRARY_LIBSOCKET))
fi

#doesn't work if test links with -lsocket (Solaris)
AC_SEARCH_LIBS(inet_addr, nsl)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_inet_addr}" = "x-lnsl"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBNSL, "${base_library_path}libnsl.${SOLIB_POSTFIX}")

	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}libnsl.${SOLIB_POSTFIX}"

	AC_CHECK_LIB(nsl, gethostbyname,
		AC_DEFINE(LIBRARY_GETHOSTBYNAME, LIBRARY_LIBNSL))


	AC_CHECK_LIB(nsl, gethostbyaddr,
		[AC_DEFINE(LIBRARY_GETHOSTBYADDR, LIBRARY_LIBNSL)])
fi

#XXX used for anything but gethostbyname2? consider testing for it
# on Solaris (atleast 2.6, gcc)
#linking with -lresolv results in error unless -shared is included
#since gcc insists on linking statically with libresolv for which
#no static version exists
AC_SEARCH_LIBS(inet_aton, resolv)

NLIBS="${NLIBS}${NLIBS:+ }$LIBS"
LIBS=""

if test "x$preload_enabled" = "xt" -a "x${ac_cv_search_inet_aton}" = "x-lresolv"; then
	AC_DEFINE_UNQUOTED(LIBRARY_LIBRESOLV, "${base_library_path}libresolv.${SOLIB_POSTFIX}")

	SOCKSIFY_PRELOAD_LIBS="${SOCKSIFY_PRELOAD_LIBS}${SOCKSIFY_PRELOAD_LIBS:+${PRELOAD_SEPERATOR}}${base_library_path}libresolv.${SOLIB_POSTFIX}"

	AC_CHECK_LIB(resolv, gethostbyname2,
		[AC_DEFINE(LIBRARY_GETHOSTBYNAME2, LIBRARY_LIBRESOLV)])
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
		    libdl=`ls ${base_library_path}libdl.${SOLIB_POSTFIX}* | sed -e 's/.*\///' | sort -nr | head -1`
		    if test x$libdl = x; then
			AC_MSG_WARN(unable to locate libdl)
		    else
			LIBRARY_DLOPEN=${base_library_path}${libdl}
			AC_MSG_WARN(hardcoding libdl to $LIBRARY_DLOPEN)
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
AC_MSG_CHECKING(for libc name)
AC_ARG_WITH(libc,
 [  --with-libc=NAME        manually set name of c library if necessary],
 [LIBC_NAME=$withval])

#set default?
if test "x${LIBC_NAME}" = x; then
	case $host in
		*-*-linux-*)
		#XXX attempt to find latest c library
		#can't set it to libc.so directly, might be ld script
		LIBC_NAME=`ls /usr/lib/libc.so* /lib/libc.so* | sed -e 's/.*\///' | sort -nr | head -1`
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
AC_DEFINE_UNQUOTED(LIBRARY_LIBC, "${LIBC_NAME}")

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
    AC_MSG_CHECKING(for libwrap)
    if test x$no_libwrap = xt; then
	echo "disabled"
    else
	LIBS="$LIBS -lwrap"
	AC_TRY_LINK([
int allow_severity;
int deny_severity;
], [hosts_access(0);],
 [AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_LIBWRAP)
  want_libwrap=t],
 [AC_MSG_RESULT(no)])
    fi
    LIBS="$oLIBS"
fi
#programs wanting libwrap should test for this Makefile.am conditional
#(programs which don't use it probably won't enjoy being linked with it)
AM_CONDITIONAL(WANT_LIBWRAP, test "x${want_libwrap}" != "x")

#look for PAM header and lib
AC_CHECK_HEADERS(security/pam_appl.h, [have_pam_header=t])
AC_SEARCH_LIBS(pam_start, pam, [have_libpam=t])

if test x"${have_pam_header}" != x -a x"${have_libpam}" != x; then
	AC_DEFINE(HAVE_PAM)
fi

L_SYMBOL_UNDERSCORE()

#try to detect gcc bug (irix 64 problem, affects among others inet_ntoa)
AC_MSG_CHECKING(for incorrect inet_ntoa behaviour)
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
], [AC_DEFINE(HAVE_BROKEN_INET_NTOA)
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

#Linux (redhat 5.2) defines socklen_t in <socketbits.h>, which is
#included by <sys/socket.h>.  check for this first.
AC_MSG_CHECKING(for socklen_t)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
], [socklen_t foo = 1;],
   [AC_MSG_RESULT(yes)
    socklen_found=t],
   [AC_MSG_RESULT(no)
    socklen_found=""])

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
AC_MSG_CHECKING(for sig_atomic_t in <signal.h>)
AC_EGREP_CPP(sig_atomic_t, [
#include <signal.h>
], [AC_DEFINE(HAVE_SIG_ATOMIC_T)
    case $host in
	*-*-aix*)
		AC_DEFINE(HAVE_VOLATILE_SIG_ATOMIC_T)
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
AC_CHECK_FUNCS(inet_aton gethostbyname2 getprpwnam getspnam getifaddrs)
AC_CHECK_FUNCS(freeifaddrs)

AC_MSG_CHECKING(for system V getpwnam)
unset getpwnam_alt
if test x"${ac_cv_func_getprpwnam}" = xyes; then
    getpwnam_alt=t
fi

if test x"${ac_cv_func_getspnam}" = xyes; then
    getpwnam_alt=t
fi

#XXX
if test x"${getpwnam_alt}" = x; then
    AC_DEFINE(HAVE_WORKING_GETPWNAM)
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
			AC_MSG_WARN(omitting strerror test on sunos4 with profiling enabled)
		;;

		*)
			AC_CHECK_FUNCS(strerror)
		;;
	esac
fi

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

#XXXslow
dnl Creating symbolic links
AC_LINK_FILES(lib/config.c, sockd/config.c)
AC_LINK_FILES(lib/config_parse.y, sockd/config_parse.y)
AC_LINK_FILES(lib/config_scan.l, sockd/config_scan.l)
AC_LINK_FILES(lib/io.c, sockd/io.c)
AC_LINK_FILES(lib/log.c, sockd/log.c)
AC_LINK_FILES(lib/protocol.c, sockd/lib_protocol.c)
AC_LINK_FILES(lib/socket.c, sockd/socket.c)
AC_LINK_FILES(lib/util.c, sockd/util.c)
AC_LINK_FILES(lib/udp_util.c, sockd/udp_util.c)
AC_LINK_FILES(lib/debug.c, sockd/debug.c)
AC_LINK_FILES(lib/hostcache.c, sockd/hostcache.c)
AC_LINK_FILES(lib/serr.c, sockd/serr.c)
AC_LINK_FILES(lib/broken.c, sockd/broken.c)
AC_LINK_FILES(lib/tostring.c, sockd/tostring.c)
AC_LINK_FILES(lib/addressmatch.c, sockd/addressmatch.c)
AC_LINK_FILES(dlib/interposition.c, sockd/interposition.c)


if test -f "licensed/checkmodule.c"; then
	unset MOD_CHECKMODULE
else
	MOD_CHECKMODULE=un
fi
AC_LINK_FILES(${MOD_CHECKMODULE}licensed/checkmodule.c, sockd/checkmodule.c)

#redirect module
if test -f "licensed/redirect.c"; then
	unset MOD_REDIRECT
	AC_DEFINE(HAVE_MODULE_REDIRECT)
	echo "module found: redirect"
else
	MOD_REDIRECT=un
fi
AC_LINK_FILES(${MOD_REDIRECT}licensed/redirect.c, sockd/redirect.c)
AC_LINK_FILES(${MOD_REDIRECT}licensed/redirect_key.c, sockd/redirect_key.c)

#bandwidth
if test -f "licensed/bandwidth.c"; then
	unset MOD_BANDWIDTH
	AC_DEFINE(HAVE_MODULE_BANDWIDTH)
	echo "module found: bandwidth"
else
	MOD_BANDWIDTH=un
fi
AC_LINK_FILES(${MOD_BANDWIDTH}licensed/bandwidth.c, sockd/bandwidth.c)
AC_LINK_FILES(${MOD_BANDWIDTH}licensed/bandwidth_key.c, sockd/bandwidth_key.c)

#The dlib directory is for building a shared library with preloading
#support (SOCKSLIBRARY_DYNAMIC is defined), when dlopen support is
#available and requested.

AC_LINK_FILES(lib/Raccept.c, dlib/Raccept.c)
AC_LINK_FILES(lib/Rbind.c, dlib/Rbind.c)
AC_LINK_FILES(lib/Rbindresvport.c, dlib/Rbindresvport.c)
AC_LINK_FILES(lib/Rconnect.c, dlib/Rconnect.c)
AC_LINK_FILES(lib/Rgethostbyname.c, dlib/Rgethostbyname.c)
AC_LINK_FILES(lib/Rgetpeername.c, dlib/Rgetpeername.c)
AC_LINK_FILES(lib/Rgetsockname.c, dlib/Rgetsockname.c)
AC_LINK_FILES(lib/Rrresvport.c, dlib/Rrresvport.c)
AC_LINK_FILES(lib/Rcompat.c, dlib/Rcompat.c)
AC_LINK_FILES(lib/address.c, dlib/address.c)
AC_LINK_FILES(lib/authneg.c, dlib/authneg.c)
AC_LINK_FILES(lib/client.c, dlib/client.c)
AC_LINK_FILES(lib/clientconfig.c, dlib/clientconfig.c)
AC_LINK_FILES(lib/clientprotocol.c, dlib/clientprotocol.c)
AC_LINK_FILES(lib/msproxy_clientprotocol.c, dlib/msproxy_clientprotocol.c)
AC_LINK_FILES(lib/config.c, dlib/config.c)
AC_LINK_FILES(lib/config_parse.y, dlib/config_parse.y)
AC_LINK_FILES(lib/config_scan.l, dlib/config_scan.l)
AC_LINK_FILES(lib/debug.c, dlib/debug.c)
AC_LINK_FILES(lib/io.c, dlib/io.c)
AC_LINK_FILES(lib/log.c, dlib/log.c)
AC_LINK_FILES(lib/method_uname.c, dlib/method_uname.c)
AC_LINK_FILES(lib/protocol.c, dlib/protocol.c)
AC_LINK_FILES(lib/socket.c, dlib/socket.c)
AC_LINK_FILES(lib/connectchild.c, dlib/connectchild.c)
AC_LINK_FILES(lib/udp.c, dlib/udp.c)
AC_LINK_FILES(lib/udp_util.c, dlib/udp_util.c)
AC_LINK_FILES(lib/userio.c, dlib/userio.c)
AC_LINK_FILES(lib/util.c, dlib/util.c)
AC_LINK_FILES(lib/broken.c, dlib/broken.c)
AC_LINK_FILES(lib/hostcache.c, dlib/hostcache.c)
AC_LINK_FILES(lib/serr.c, dlib/serr.c)
AC_LINK_FILES(lib/httpproxy.c, dlib/httpproxy.c)
AC_LINK_FILES(lib/tostring.c, dlib/tostring.c)
AC_LINK_FILES(lib/addressmatch.c, dlib/addressmatch.c)

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
	echo "select:            incorrect select behaviour on unconnected sockets,"
        echo "                   operations on nonblocking sockets might fail on this platform"
else
	echo "select:            OK"
fi


if test x"${no_routeinfo}" = xt; then
	echo "Routeinfo:         no supported on this platform"
else
	echo "Routeinfo:         OK"
fi
echo ""
echo "This software should perform optimally when all the lines above report 'OK'."
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
echo ""
