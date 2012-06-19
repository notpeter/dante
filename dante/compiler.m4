#compiler related checks, updates CFLAGS and CPPFLAGS and sets
# 'warn' with flags for warnings

AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL

case $host in
    *-*-darwin*)
	AC_DEFINE(HAVE_DARWIN, 1, [enable darwin/osx workarounds])

	#XXX only needed for libraries (dante-only)?
	HW=`uname -m`
	case $HW in
	    ppc*)
		CFLAGS="$CFLAGS${CFLAGS:+ }-arch ppc -arch ppc64"
		LDFLAGS="$LDLAGS${LDLAGS:+ }-arch ppc -arch ppc64"
		;;
	    *)
		CFLAGS="$CFLAGS${CFLAGS:+ }-arch i386 -arch x86_64"
		LDFLAGS="$LDLAGS${LDLAGS:+ }-arch i386 -arch x86_64"
		;;
	esac

	;;

    alpha*-dec-osf*)
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_XOPEN_SOURCE_EXTENDED -DBYTE_ORDER=LITTLE_ENDIAN -D_POSIX_SOURCE -D_POSIX_C_SOURCE=199309L -D_OSF_SOURCE"
	;;

    *-*-hpux*)
	#HPUX needs _PROTOTYPES to include prototypes
	#for configure (for gcc and cc)
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_PROTOTYPES"
	;;

    *-*-openbsd*)
	AC_DEFINE(HAVE_OPENBSD_BUGS, 1, [bug workaround])
	;;

    *-*-solaris*)
	AC_DEFINE(HAVE_SENDMSG_DEADLOCK, 1, [bug workaround])
	AC_DEFINE(HAVE_SOLARIS_BUGS, 1, [bug workaround])
	#for msghdr msg_flags
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_XOPEN_SOURCE=500 -D_XOPEN_SOURCE_EXTENDED"
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D__EXTENSIONS__ -DBSD_COMP"
	;;

    *-*-linux-*)
	AC_DEFINE(HAVE_LINUX_BUGS, 1, [bug workaround])
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED"
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_FORTIFY_SOURCE=2"
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_BSD_SOURCE"
#	if test x"$GCC" != x; then
#		#XXX want to avoid extension used in struct cmsghdr
#		CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-U__GNUC__ -D__GNUC__=0"
#	fi
	AC_DEFINE(SPT_TYPE, SPT_REUSEARGV, [setproctitle replacement type])
	;;

    *-*-aix*)
	OSPIDFILE="/etc/${SERVNAME}.pid"
	AC_DEFINE(HAVE_SYSTEM_XMSG_MAGIC, 1, [platform workaround])
	AC_DEFINE(_ALL_SOURCE, 1, [contents from old AC_AIX test])
	CPPFLAGS="${CPPFLAGS}${CPPFLAGS+ }-DXOPEN_SOURCE_EXTENDED=1"
	;;
esac

#XXX cross compilation
case $host_alias in
    arm-linux-androideabi)
	LDFLAGS="$LDFLAGS${LDFLAGS:+ }-lgcc -ldl"
	;;
esac

unset COMPTYPE
unset FAILWARN
AC_MSG_CHECKING([for compiler type])
if $CC -v 2>&1 | tail -1 | egrep '^gcc ' >/dev/null; then
    COMPTYPE=gcc
    FAILWARN="-Werror"
elif $CC -V 2>&1 | grep 'Sun C ' >/dev/null; then
    COMPTYPE=suncc
    FAILWARN="-errwarn=%all"
elif $CC -v 2>&1 | egrep '^pcc ' >/dev/null; then
    COMPTYPE=pcc
elif $CC -qversion 2>&1 | egrep '^IBM XL C' >/dev/null; then
    COMPTYPE=xlc
    FAILWARN="-qhalt=w"
else
    #XXX
    case $host in
	alphaev6-dec-osf*)
	    COMPTYPE="osfcc"
	    ;;
	alpha*-dec-osf*)
	    COMPTYPE="oldosfcc"
	    ;;
	*-*-irix*) #sgi cc
	    COMPTYPE="sgicc"
	    ;;
	*-*-hpux*)
	    COMPTYPE="hpuxcc"
	    ;;
	*)
	    #gcc compatible compiler?
	    if test x"$GCC" != x; then
		COMPTYPE="gcc"
	    fi
	    ;;
    esac
fi
if test x"$COMPTYPE" = x; then
    AC_MSG_RESULT([unknown])
else
    AC_MSG_RESULT([$COMPTYPE])
fi

unset comp_flags
AC_MSG_CHECKING([for compiler flags])
case $COMPTYPE in
    suncc)
	#-xs provides easier debugging with gdb
	comp_flags="-Xa -xs"
    ;;

    osfcc)
	comp_flags="-std1"
    ;;

    oldosfcc) #XXX is it possible to get it to work with -newc?
	if test x"$GCC" = x; then
	    comp_flags="-std1 -oldc"
	fi
    ;;

    hpuxcc)
	if test x"$GCC" = x; then
	    CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-D_XOPEN_SOURCE"
	    #XXX when cc is used as CPP it needs -Ae to work
	    #    for L_SOCKPROTO; add -Ae to CPPFLAGS.
	    #    This won't work if CPP is specified by hand
	    #    and is something else than cc (when CC is hp cc)
#	    comp_flags="-Ae"
	    CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-Ae"
	fi
	;;

    xlc)
	comp_flags=""
	;;
esac
#make sure compiling with compiler options works
if test x"$comp_flags" != x; then
    oCFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS${CFLAGS:+ }$comp_flags"
    AC_TRY_COMPILE([], [],
		   [AC_MSG_RESULT([$comp_flags])],
		   [AC_MSG_RESULT([none])
		    unset comp_flags])
    CFLAGS="$oCFLAGS"
else
    AC_MSG_RESULT([none])
fi

AC_MSG_CHECKING([for support for -pipe compiler flag])
oCFLAGS="$CFLAGS"
CFLAGS="$CFLAGS${CFLAGS:+ }$FAILWARN -pipe"
AC_TRY_RUN([
int main()
{
	return 0;
}], [AC_MSG_RESULT([yes])
     comp_flags="${comp_flags}${comp_flags:+ }-pipe"],
    [AC_MSG_RESULT([no])],
    [dnl do not set when cross-compiling
     AC_MSG_RESULT([no])])
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for support for -Wbounded compiler flag])
oCFLAGS="$CFLAGS"
CFLAGS="$CFLAGS${CFLAGS:+ }$FAILWARN -Wbounded"
AC_TRY_RUN([
int main()
{
        return 0;
}], [AC_MSG_RESULT([yes])
     comp_flags="${comp_flags}${comp_flags:+ }-Wbounded"],
    [AC_MSG_RESULT([no])
     AC_DEFINE(__bounded__(a,b,c), , [empty __bounded__ macro])],
    [AC_MSG_RESULT([no]) dnl assume not supported when cross-compiling
     AC_DEFINE(__bounded__(a,b,c), , [empty __bounded__ macro])])
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for __attribute__ support])
oCFLAGS="$CFLAGS"
CFLAGS="$CFLAGS${CFLAGS:+ }$FAILWARN"
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
     AC_DEFINE(HAVE_DECL_ATTRIBUTE, 1, [__attribute__ macro support])],
    [AC_MSG_RESULT([no]) dnl assume not supported when cross-compiling])
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for __attribute__ nonnull support])
oCFLAGS="$CFLAGS"
CFLAGS="$CFLAGS${CFLAGS:+ }$FAILWARN"
AC_TRY_RUN([
#include <stdlib.h>

void func(char *) __attribute((__nonnull__(1)));

void func(char *f)
{
    char *d;
    d = f;
}

int main()
{
    func(NULL);
}], [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_DEFINE(HAVE_DECL_NONNULL, 1, [__nunnull__ attribute support])],
    [AC_MSG_RESULT([no]) dnl assume not supported when cross-compiling])
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for __printf__ format attribute support])
oCFLAGS="$CFLAGS"
CFLAGS="$CFLAGS${CFLAGS:+ }$FAILWARN"
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
     AC_DEFINE(HAVE_DECL_FORMAT, 1, [format attribute support])],
    [AC_MSG_RESULT([no]) dnl assume not supported when cross-compiling])
CFLAGS="$oCFLAGS"

AC_MSG_CHECKING([for compilation with debugging])
AC_ARG_ENABLE(debug,
[  --enable-debug          compile with debugging support],
[AC_MSG_RESULT([yes])
 debug_enabled=t
 FEAT="$FEAT${FEAT:+ }debug"],
[if test x$prerelease != x; then
    debug_enabled=t
    AC_MSG_RESULT([yes])
 else
    AC_MSG_RESULT([no])
 fi])

unset have_livedebug
AC_MSG_CHECKING([for live debugging])
AC_ARG_ENABLE(livedebug,
[  --enable-livedebug      enable low-overhead debugging mode],
[have_livedebug=t
 debug_enabled=t
 FEAT="$FEAT${FEAT:+ }livedebug"
 AC_DEFINE(HAVE_COND_LIVEDEBUG, 1, [low-overhead debugging enabled])])

if test x$debug_enabled = xt; then
    #no optimization wanted
    if test $ac_cv_prog_cc_g = yes; then
	CFLAGS="$CFLAGS${CFLAGS:+ }-g"
    fi
    CPPFLAGS="$CPPFLAGS${CPPFLAGS:+ }-DDEBUG=1"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
    #autoconf_compflags is set to "-g -O2" with GCC
    #override CFLAGS when running configure to avoid this
    CPPFLAGS="$CPPFLAGS${CPPFLAGS:+ }-DDEBUG=0"
    CFLAGS="$CFLAGS${CFLAGS:+ }$autoconf_compflags"
fi

AC_MSG_CHECKING([for warning flags])
AC_ARG_ENABLE(warnings,
[  --enable-warnings       show compilation warnings],
[enable_warnings=t], [])

#place warning flags in $warn
if test x$enable_warnings != x; then
    #try to enable compiler specific warning flags
    case $COMPTYPE in
	gcc)
	    warn="-Wall -Wformat -W -Wnested-externs -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wcast-align -Wcast-qual -Wbad-function-cast -Wpointer-arith -Wundef"
	    #warn="$warn -Wold-style-cast -Winline -Waggregate-return -Wconversion -Wwrite-strings -Wtraditional -Wshadow"
	    ;;

	hpuxcc)
	    warn="-v"
	    ;;

	*osfcc) #osf cc
#	    warn="-w0 -check -portable -warnprotos"
	    true
	    ;;

#	pcc)
#	    warn="-Wall --warn-common --warn-constructors --warn-multiple-gp --warn-once --warn-section-align --error-unresolved-symbols"
#	    ;;

	sgicc) #sgi cc
	    warn="-fullwarn"
	    ;;

	suncc)
	    warn="-v"
	    case $host in
		#XXX only available for some platforms
		sparc-*solaris*)
		    warn="$warn -xanalyze=code"
		    ;;
	    esac
	    ;;

	xlc)
	    warn="-qinfo=all:noppt"
	    ;;

	*) #try -Wall (gcc)
	    warn="-Wall"
	    ;;
    esac

    oCFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS${CFLAGS:+ }$warn"
    #make sure compilation is still possible
    AC_TRY_COMPILE([], [],
		   [AC_MSG_RESULT([$warn])],
		   [AC_MSG_RESULT([none])
		    unset warn])
    CFLAGS="$oCFLAGS"
else
    AC_MSG_RESULT([none])
fi

#for Solaris, generate 64-bit binaries if running in 64-bit mode.
#building 32-bit binaries (the default) causes problems with
#LD_PRELOAD if running in a 64-bit environment.
#XXX more general solution would be to build and install both
unset sol64
case $host in
    *-*-solaris*)
	if test x`isainfo -b` = x64; then
	    ISA64DIR=`isainfo -n`
	    if test x"$ISA64DIR" != x; then
		AC_MSG_CHECKING([for support for -m64 compiler flag])
		oCFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS${CFLAGS:+ }-m64"
		AC_TRY_RUN([
			int main() {
			    return 0;
		}], [AC_MSG_RESULT([yes])
		     sol64=t
		     AC_SUBST(ISA64DIR)
		     AC_MSG_WARN([building for 64-bit addressing model])])
		CFLAGS="$oCFLAGS"
	    fi
	fi
	;;
esac

#NOTE: set warnings at the bottom; might interfere with tests
CFLAGS="$CFLAGS${CFLAGS:+ }$comp_flags"

#-DDIAGNOSTICS?
AC_MSG_CHECKING([for compliation with DIAGNOSTIC])
AH_TEMPLATE([DIAGNOSTIC], [for debugging])
AC_ARG_ENABLE(diagnostic,
[  --enable-diagnostic     enable diagnostic],
[if test x"${have_livedebug}" != x; then
    AC_MSG_WARN([--enable-livedebug cannot be used with --enable-diagnostic])
    exit 1
 fi
 FEAT="$FEAT${FEAT:+ }diagnostic"
 AC_DEFINE(DIAGNOSTIC, 1)
 AC_MSG_RESULT([yes])],
[if test x$prerelease != x; then
    FEAT="$FEAT${FEAT:+ }diagnostic"
    AC_DEFINE(DIAGNOSTIC, 1)
    AC_MSG_RESULT([yes])
 else
    AC_DEFINE(DIAGNOSTIC, 0)
    AC_MSG_RESULT([no])
 fi])

AC_MSG_CHECKING([whether profiled compilation requested])
AC_ARG_ENABLE(profiling,
[  --enable-profiling      compile with profiling support in server],
[AC_MSG_RESULT([yes])
 AC_MSG_CHECKING([if compiling profiled binaries works])
 oLDFLAGS="$LDFLAGS"
 oCFLAGS="$CFLAGS"
 LDFLAGS="$LDFLAGS${LDFLAGS:+ }-pg"
 CFLAGS="$CFLAGS${CFLAGS:+ }-pg -DPROFILING"
 AC_TRY_RUN([
int main()
{
	return 0;
}], [AC_MSG_RESULT([yes])
     FEAT="$FEAT${FEAT:+ }profiling"
     AC_DEFINE(HAVE_PROFILING, 1, [for profiling])

     case $host in
	 *-*-openbsd* | *-*-freebsd*)
	     #static linking, disable server preloading
	     no_preload_server=t
	     #OpenBSD and FreeBSD appear to be happier if -lc is included
	     #when profiling is enabled
	     LIBS="$LIBS${LIBS:+ }-lc"
	     ;;
     esac],
   [AC_MSG_RESULT([no])
    AC_MSG_WARN([profiling requested, but compilation with profiling fails])
    CFLAGS="$oCFLAGS"
    LDFLAGS="$oLDFLAGS"])],
[AC_MSG_RESULT([no])])

AC_CHECK_FUNCS(moncontrol)

AC_MSG_CHECKING([whether coverage requested])
AC_ARG_ENABLE(coverage,
[  --enable-coverage       compile with coverage],
[AC_MSG_RESULT([yes])
 AC_MSG_CHECKING([if compiling with coverage works])
 oLDFLAGS="$LDFLAGS"
 oCFLAGS="$CFLAGS"
 LDFLAGS="$LDFLAGS${LDFLAGS:+ }--coverage"
 CFLAGS="$CFLAGS${CFLAGS:+ }--coverage"
AC_TRY_RUN([
#include <sys/types.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <unistd.h>

int main()
{
	int res;
	/* look for darwin() fork problem */
	if ((res = fork()) == 0)
	    exit(0); /* child */
	else if (res == -1)
	    exit(1); /* err */
	else {
	    if (waitpid(res, NULL, 0) == res)
		exit(0);
	    else
		exit(1);
	}
}], [AC_MSG_RESULT([yes])
     FEAT="$FEAT${FEAT:+ }coverage"],
    [AC_MSG_RESULT([no])
     AC_MSG_WARN([coverage requested, but compilation with --coverage fails])
     CFLAGS="$oCFLAGS"
     LDFLAGS="$oLDFLAGS"])],
[AC_MSG_RESULT([no])])

AC_ARG_ENABLE(linting,
[  --enable-linting        enable lint],
[AC_CHECK_PROG(LINT, lint, lint)
 if test x"$LINT" = x; then
     AC_MSG_WARN([linting requested, but lint not found])
 else
     s_linting=t
     case $host in
	 *-*-openbsd* | *-*-freebsd*)
	     LINTFLAGS="-abcebprxz"
	     LINTPASS1="-i"
	     LINTPASS2=""
	     LINTLIBOPT="-C"
	     ;;
	 *-*-solaris*)
#	     LINTFLAGS=-c -errchk=%all -errsecurity=extended -fd -Ncheck=%all -Nlevel=3 -p -s
#	     SUPPRESS="-x -erroff=E_FUNC_DECL_VAR_ARG2"
	     LINTLIBS="-lnsl -lsocket -lwrap"
	     LINTWARN="-errsecurity=extended -errchk=%all -errhdr -Ncheck=%all -Nlevel=3"
	     LINTFLAGS="-fd -s -errfmt=simple $SUPPRESS $LINTWARN"
	     LINTPASS1="-c"
	     LINTPASS2="$LINTFLAGS $LINTLIBS"
	     LINTLIBOPT="-o"
	     ;;
     esac
 fi])
AM_CONDITIONAL(RUNLINT, test x$s_linting = xt)
AC_SUBST(LINT)
AC_SUBST(LINTFLAGS)
AC_SUBST(LINTPASS1)
AC_SUBST(LINTPASS2)
AC_SUBST(LINTLIBOPT)
