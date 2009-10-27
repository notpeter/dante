SOLIB_POSTFIX=so

case $host in
	alpha*-dec-osf*)
		AC_DEFINE(HAVE_DEC_PROTO, 1, [DEC workarounds])
		AC_DEFINE(HAVE_EXTRA_OSF_SYMBOLS, 1, [DEC workarounds])
		PRELOAD="RLD"
	;;

	*-*-hpux*)
		SOLIB_POSTFIX=sl
	;;

	*-*-irix*)
		PRELOAD="RLD"
	;;

	*-*-cygwin)
		AC_MSG_WARN([disabling preloading])
		no_preload_client=t
		no_preload_server=t
		no_preload=t
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

if test x"$no_preload" = x; then
    AC_MSG_CHECKING([whether interposition in the client should be disabled])
    AC_ARG_ENABLE(clientdl,
    [  --disable-clientdl      disable support for preloading in the client],
    [if test x"$enableval" = xno; then
	    no_preload_client=t
	    AC_MSG_RESULT([yes])
    else
	    AC_MSG_RESULT([no])
    fi], AC_MSG_RESULT([no]))

    AC_MSG_CHECKING([whether interposition in the server should be disabled])
    AC_ARG_ENABLE(serverdl,
    [  --disable-serverdl      disable support for preloading in the server],
    [if test x"$enableval" = xno; then
	    no_preload_server=t
	    AC_MSG_RESULT([yes])
    else
	    if text x"$enableval" = xyes; then
		serverdl_always_on=t
	    fi
	    AC_MSG_RESULT([no])
    fi], AC_MSG_RESULT([no]))
fi


AM_CONDITIONAL(SERVER_INTERPOSITION, test x"$no_preload_server" = x)
AM_CONDITIONAL(SERVER_INTERPOSITION_ALWAYS, test x"$serverdl_always_on" = xt)

if test "x${no_preload_client}" = "xt" -a "x${no_preload_server}" = "xt"; then
    unset preload_enabled
else
    preload_enabled=t
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
], [AC_DEFINE(DL_LAZY, RTLD_LAZY, [dlopen has RTLD_ prefix])
    AC_MSG_RESULT(yes)],
   AC_MSG_RESULT(no))

dnl XXX Some Linux specific calls - possibly more required
AC_CHECK_FUNCS(__fprintf_chk __vfprintf_chk)

dnl XXX Some Linux glibc getc,putc replacements
AC_CHECK_FUNCS(_IO_getc _IO_putc)

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
	 [struct hostent *, const void *, socklen_t, int],
	 [struct hostent *, const void *, int, int])

	L_NSOCKPROTO(getpeername, [failproto=t],
	 [int, int, struct sockaddr *, socklen_t *],
	 [int, int, struct sockaddr *, Psocklen_t])

	L_NSOCKPROTO(getsockname, [failproto=t],
	 [int, int, struct sockaddr *, socklen_t *],
	 [int, int, struct sockaddr *, Psocklen_t])

	L_NSOCKPROTO(listen, [failproto=t],
	 [int, int, int])

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

	#XXX stdio related functions
	L_NSTDIOPROTO(getc, [failproto=t],
	 [int, FILE *])

	L_NSTDIOPROTO(fgetc, [failproto=t],
	 [int, FILE *])

	L_NSTDIOPROTO(gets, [failproto=t],
	 [char *, char *])

	L_NSTDIOPROTO(fgets, [failproto=t],
	 [char *, char *, int, FILE *])

	L_NSTDIOPROTO(putc, [failproto=t],
	 [int, int, FILE *])

	L_NSTDIOPROTO(fputc, [failproto=t],
	 [int, int, FILE *])

	L_NSTDIOPROTO(puts, [failproto=t],
	 [int, const char *])

	L_NSTDIOPROTO(fputs, [failproto=t],
	 [int, const char *, FILE *])

	L_NSTDIOPROTO(fflush, [failproto=t],
	 [int, FILE *])

	L_NSTDIOPROTO(fclose, [failproto=t],
	 [int, FILE *])

	L_NSTDIOPROTO(fprintf, [failproto=t],
	 [int, FILE *, const char *, ...])

	L_NSTDIOPROTO(vfprintf, [failproto=t],
	 [int, FILE *, const char *, va_list])

	L_NSTDIOPROTO(printf, [failproto=t],
	 [int, const char *, ...])

	L_NSTDIOPROTO(vprintf, [failproto=t],
	 [int, const char *, va_list])

	L_NSTDIOPROTO(fwrite, [failproto=t],
	 [size_t, const void *, size_t, size_t, FILE *])

	L_NSTDIOPROTO(fread, [failproto=t],
	 [size_t, void *, size_t, size_t, FILE *])

	if test x$ac_cv_func__IO_getc = xyes; then
	   L_NSTDIOPROTO(_IO_getc, [failproto=t],
	    [int, FILE *])
	fi

	if test x$ac_cv_func__IO_putc = xyes; then
	   L_NSTDIOPROTO(_IO_putc, [failproto=t],
	    [int, int, FILE *])
	fi

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

#do not wish to link directly with libpthreads, included only if needed
AC_CHECK_HEADER(pthread.h,
[AC_DEFINE(HAVE_PTHREAD_H, 1, [have pthread header])
 tLIBS=$LIBS
 AC_SEARCH_LIBS(pthread_mutexattr_init, pthread)
 LIBS=$tLIBS
 if test x"${ac_cv_search_pthread_mutexattr_init}" = x"-lpthread"; then
    case $host in
       *-*-linux-*)
	#XXX  attempt to find latest pthread library
	  PATH=$PATH:/sbin
	  export PATH
	  unset LIBPT_ALTS
	  for file in `ldconfig -p | grep /libpthread.so| xargs -n 1 echo | grep /libpthread.so`; do
	     test -s "$file" && LIBPT_ALTS="${LIBPT_ALTS}${LIBPT_ALTS:+ }$file"
	  done
		LIBPT_NAME=`echo ${LIBPT_ALTS} | sed -e 's/.*\///' | sort -nr | head -n 1`
		if test "x${LIBPT_NAME}" = x; then
			#nothing found, set something anyway
			LIBPT_NAME="${base_library_path}libc.so"
		fi
       ;;

       *)
	  LIBPT_NAME="libpthread.${SOLIB_POSTFIX}"
       ;;
    esac
    AC_DEFINE_UNQUOTED(LIBRARY_PTHREAD, "${base_library_path}$LIBPT_NAME", [libloc])
 fi],
 [AC_DEFINE(HAVE_PTHREAD_H, 0, [no pthread header])])

LIBS=""
AC_SEARCH_LIBS(connect, socket)
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

	AC_CHECK_LIB(socket, listen,
		AC_DEFINE(LIBRARY_LISTEN, LIBRARY_LIBSOCKET, [function loc]))

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
		#XXX
		#can't set it to libc.so directly, might be ld script
		unset LIBC_ALTS
		for file in `ldconfig -p | grep /libc.so| xargs -n 1 echo | grep /libc.so`; do
		    test -s "$file" && LIBC_ALTS="${LIBC_ALTS}${LIBC_ALTS:+ }$file"
		done
		LIBC_NAME=`echo ${LIBC_ALTS} | sed -e 's/.*\///' | sort -nr | head -n 1`
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

L_SYMBOL_UNDERSCORE()

AC_MSG_CHECKING([for working dlsym])
AC_TRY_RUN([
#include <dlfcn.h>
#include <stdio.h>

#include "include/symbols.h"

int main()
{
	void *lib;
	void *sym;

	if ((lib = dlopen(LIBRARY_CONNECT, DL_LAZY)) == NULL) {
		fprintf(stderr, "dlopen: %s", dlerror());
		return 1;
	}
	(void)dlerror();
	if ((sym = dlsym(lib, SYMBOL_CONNECT)) == NULL) {
		fprintf(stderr, "dlsym: %s", dlerror());
		return 1;
	}
	return 0;
}], [AC_MSG_RESULT(yes)],
    [AC_MSG_RESULT(no)
     no_preload_client=t
     no_preload_server=t
     no_preload=t])

AC_MSG_CHECKING([for working RTLD_NEXT])
AC_TRY_RUN([
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#include "include/symbols.h"

int main()
{
	void *sym;

	if ((sym = dlsym(RTLD_NEXT, SYMBOL_READ)) == NULL) {
		fprintf(stderr, "dlsym: %s", dlerror());
		return 1;
	}
	return 0;
}], [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_RTLD_NEXT, 1, [have working dlsym RTLD_NEXT])],
    [AC_MSG_RESULT(no)
     AC_DEFINE(HAVE_RTLD_NEXT, 0, [no working dlsym RTLD_NEXT])])

#solaris might block preloading
AC_MSG_CHECKING([libc preload blocking])
AC_TRY_RUN([
#include <stdlib.h>
#include <string.h>
#include <unistd.h>                                                             
int
main(int argc, char *argv[])
{
   char buf[1024];
  
   strcpy(buf, "lari -V ");
   strcat(buf, argv[0]);
   strcat(buf, " | grep read | grep protected > /dev/null");

   /*
    * return error if 'protected'
    * (ignore errors, not indicative of blocking) */ 
   if (system(buf) == 0)
        return 1;
   else
        return 0;
}

ssize_t
read(d, buf, nbytes)
   int d;
   void *buf;
   size_t nbytes;
{
   return 0;
}
], [AC_MSG_RESULT(no)],
   [AC_MSG_RESULT(yes)
    AC_MSG_WARN([this platform blocks preloading of libraries])
    blocked_preload=t])

AC_CONFIG_FILES(bin/socksify)
