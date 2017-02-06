dnl kerberos.m4 -- find compiler and linker flags for Kerberos 5
dnl Based on patch from Markus Moeller (markus_moeller at compuserve.com)

dnl default prefix for kerberos headers/libs
krb5dir=/usr
AC_ARG_WITH(krb5,
 [  --without-krb5          disable kerberos 5 support @<:@default=detect@:>@],
 [KRB5=$withval])

AC_ARG_WITH(krb5-path,
 [  --with-krb5-path=PATH   specify kerberos 5 path],
 [krb5dir=$withval])

AC_ARG_WITH(krb5-config,
 [  --with-krb5-config=PATH specify path to krb5-config @<:@default=detect@:>@],
 [if test x"$withval" = xyes; then
     unset krb5confpath
  elif test x"$withval" != xno; then
     krb5confpath=$withval
  else
     krb5confpath=no
  fi])

if test x"$KRB5" != xno; then
   unset krb5fail
   if test x"$krb5confpath" != xno; then
      if test x"$krb5confpath" != x; then
         if test ! -x "$krb5confpath"; then
                AC_MSG_WARN([krb5-config '$krb5confpath' not executable, ignoring])
         else
            ac_krb5_cflags=`$krb5confpath --cflags krb5 2>/dev/null`
           if test $? != 0; then
               krb5fail=t
           fi
           ac_krb5_libs=`$krb5confpath --libs krb5 2>/dev/null`
           if test $? != 0; then
               krb5fail=t
           fi
           ac_krb5_heimdal="`$krb5confpath --version 2>/dev/null | grep -i heimdal`"
         fi
      else
         AC_CHECK_PROG(ac_krb5_config, krb5-config, yes, no)
         if test x"${ac_krb5_config}" = xyes; then
           ac_krb5_cflags=`krb5-config --cflags krb5 2>/dev/null`
           if test $? != 0; then
               krb5fail=t
           fi
           ac_krb5_libs=`krb5-config --libs krb5 2>/dev/null`
           if test $? != 0; then
               krb5fail=t
           fi
           ac_krb5_heimdal="`krb5-config --version 2>/dev/null | grep -i heimdal`"
         fi
      fi
   fi
   dnl working krb5-config?
   if test x"$krb5fail" = xt; then
      ac_krb5_cflags=
      ac_krb5_libs=
   fi

   dnl any cflags values obtained from krb5-config?
   if test x"${ac_krb5_cflags}" != x; then
      CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }$ac_krb5_cflags"
   else
      dnl add cppflags values needed for default compilation (openbsd)
      if test -d $krb5dir/include/kerberosV; then
         CPPFLAGS="${CPPFLAGS}${CPPFLAGS:+ }-I${krb5dir}/include/kerberosV"
      fi
   fi

   dnl look for krb5 headers
   AC_CHECK_HEADERS(krb5.h com_err.h et/com_err.h)

   ac_com_error_message=no
   AC_EGREP_HEADER(com_err.h, krb5.h, ac_com_err_krb5=yes)
   if test x"${ac_com_err_krb5}" = xyes; then
      AC_DEFINE(HAVE_COM_ERR_IN_KRB5, 1, [Define to 1 if you have com_err in krb5.h])
   fi
   if test x"${ac_cv_header_com_err_h}" = xyes; then
      AC_EGREP_HEADER(error_message, com_err.h, ac_com_error_message=yes)
   elif test x"${ac_cv_header_et_com_err_h}" = xyes; then
      AC_EGREP_HEADER(error_message, et/com_err.h, ac_com_error_message=yes)
   fi

   dnl might be used by libkrb5, but not returned by krb5-config
   AC_CHECK_LIB(pthread, main)

   dnl look for libs
   if test x"${ac_krb5_libs}" != x; then
      _libsonly=`echo $ac_krb5_libs | xargs -n1 | egrep '^-l' | xargs echo`
      _optsonly=`echo $ac_krb5_libs | xargs -n1 | egrep -v '^-l' | xargs echo`

      LIBS="${LIBS}${LIBS:+ }${_libsonly}"
      LDFLAGS="${LDFLAGS}${LDFLAGS:+ }${_optsonly}"
   else
      #AC_CHECK_LIB(crypto, main) #XXX only very old mit kerberos
      AC_CHECK_LIB(des, main)
      AC_CHECK_LIB(crypt, main)
      AC_CHECK_LIB(roken, main)

      AC_CHECK_LIB(com_err, main)
      AC_CHECK_LIB(des425, main)
      AC_CHECK_LIB(k5crypto, main)

      AC_CHECK_LIB(asn1, main)
      AC_CHECK_LIB(krb5, main)

      AC_CHECK_LIB(ksvc, main)
   fi

   if test `echo $LIBS | grep -c com_err` -ne 0 -a x"$ac_com_error_message" = xyes; then
      AC_CHECK_LIB(com_err, error_message,
         AC_DEFINE(HAVE_ERROR_MESSAGE, 1, [Define to 1 if you have error_message]),)
   elif test x"${ac_com_error_message}" = xyes; then
      AC_CHECK_LIB(krb5, error_message,
         AC_DEFINE(HAVE_ERROR_MESSAGE, 1, [Define to 1 if you have error_message]),)
   fi

   AC_CHECK_LIB(krb5, krb5_get_err_text,
      AC_DEFINE(HAVE_KRB5_GET_ERR_TEXT, 1, [Define to 1 if you have krb5_get_err_text]),)
   AC_CHECK_LIB(krb5, krb5_get_error_message,
      AC_DEFINE(HAVE_KRB5_GET_ERROR_MESSAGE, 1, [Define to 1 if you have krb5_get_error_message]),)

   dnl do compile check
   AC_MSG_CHECKING([for working krb5])
   AC_TRY_RUN([
#if HAVE_KRB5_H
#include <krb5.h>
#endif

int
main(void)
{
        krb5_context context;

        krb5_init_context(&context);

       return 0;
}
], [unset no_krb5
    AC_DEFINE(HAVE_KRB5, 1, [KRB5 support])
    AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)],
   [dnl assume it works when cross-compiling
    unset no_krb5
    AC_DEFINE(HAVE_KRB5, 1, [KRB5 support])
    AC_MSG_RESULT(assuming yes)])

   AC_CHECK_DECLS(krb5_kt_free_entry,,, [#include <krb5.h>])
   AC_CHECK_LIB(krb5, krb5_kt_free_entry,
      AC_DEFINE(HAVE_KRB5_KT_FREE_ENTRY, 1, [Define to 1 if you have krb5_kt_free_entry]),)
   AC_CHECK_LIB(krb5, krb5_get_init_creds_keytab,
      AC_DEFINE(HAVE_GET_INIT_CREDS_KEYTAB, 1, [Define to 1 if you have krb5_get_init_creds_keytab]),)
   AC_CHECK_LIB(krb5, krb5_get_init_creds_opt_alloc,
      AC_DEFINE(HAVE_GET_INIT_CREDS_OPT_ALLOC, 1, [Define to 1 if you have krb5_get_init_creds_opt_alloc]),)

   AC_MSG_CHECKING([for krb5_get_init_creds_opt_free with krb5 context ])
AC_TRY_COMPILE([
#include <krb5.h>
], [
krb5_context context;
krb5_get_init_creds_opt options;
krb5_get_init_creds_opt_free(context, &options);
], [AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_GET_INIT_CREDS_OPT_FREE_CTX, 1, [Define to 1 if you have krb5_get_init_creds_opt_free with krb5 context])],
   [AC_MSG_RESULT(no)])

   case $host in
    *-*-solaris*)
       dnl It seems memory cache does not work on Solaris with Sun SDK
       AC_MSG_WARN([disabling Kerberos memory cache on this platform])
       ;;
    *)
       AC_TRY_RUN([
#include <krb5.h>
main()
{
    krb5_context context;
    krb5_ccache cc;

    krb5_init_context(&context);
    return krb5_cc_resolve(context, "MEMORY:test_cache", &cc);
}],
	[AC_DEFINE(HAVE_KRB5_MEMORY_CACHE, 1, [Define to 1 if you have MEMORY: cache support])],
	[],
	[dnl cross-compiling assume non-working
	 true])
	;;
   esac
fi
