# -- acinclude --

define(testparam,[
_arg=[$2]
_param=[$3]
_func=[$4]
_ucfunc=[$5]

unset _nofunc

for val in [$1]
do
	cat ${_param} | egrep "^${val}" > /dev/null
	test $? -eq 0 && _nofunc="" && break
	_nofunc=t
done
if test "x${_nofunc}" = xt; then
	if test "x[$$6]" != x; then
		[$6]="$$6|"
	fi
	[$6]="[$$6] ${_func} (${_arg}): (`cat ${_param}`)"
else
	AC_DEFINE_UNQUOTED(HAVE_PROT_${_ucfunc}_${_arg}, ${val})
fi
])dnl

dnl #XXXugly
dnl #attempt to speed up runtime by avoiding subshells
AC_DEFUN(L_SOCKPROTO,
[
dnl this function is not very generic, and only supports nine arguments
syscmd(if test $# -gt 9; then exit 1;fi) dnl
ifelse(sysval, 0, , [errprint(__file__:__line__: error in acinclude.m4: too many arguments to function [$0]
) m4exit(1)])dnl

nargs=[$#]

paramcnt=decr(decr([$#]))

func=translit([$1], ` ')
ucfunc=translit(translit([$1], ` '), `a-z', `A-Z')

AC_MSG_CHECKING([prototypes for $func])

unset failure

cat > conftest.$ac_ext <<EOF
#include "confdefs.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
EOF

changequote(<<, >>)dnl
${CPP} ${CPPFLAGS} -D__STDC__ conftest.$ac_ext | $AWK "{ if (/[^a-z0-9]${func}[^a-z0-9]/) { s=10 }; if ( s > 0 ) { s -= 1; print; } }" | egrep -v '^#' | tr '\n' ' ' | tr -s '/' |  tr ';' '\n'  | grep -v "__${func}" | egrep "[^a-z0-9]${func}[^a-z0-9]" | tr -s '[:blank:]' | sed -e 's/extern//' > conftest.out_proto

cnt=0
while test $cnt -lt $paramcnt; do
	if test $cnt -eq 0; then
    		cat conftest.out_proto | sed -e "s/${func}.*//" | sed -e 's/^[ 	]*//' | sed -e 's/[ 	]*$//g' > conftest.out_param
	else
    		cat conftest.out_proto | sed -e "s/.*${func}//" | sed -e "s/[\(\)]//g" | cut -d, -f $cnt | sed -e 's/^[ 	]*//' | sed -e 's/[ 	]*$//g' > conftest.out_param
	fi
dnl	XXXstrip whatever's behind any *?

	cat conftest.out_param | tr -s '[:blank:]' > conftest.out_nospace
	if test -s conftest.out_nospace; then
		cp -f conftest.out_param conftest.out_param_${cnt}
	else
dnl		#XXX
		echo "(not found)" > conftest.out_param_${cnt}
		echo "warning: found no argument"
	fi

	#XXX avoid subshell
	case $cnt in
		0) cnt=1;;
		1) cnt=2;;
		2) cnt=3;;
		3) cnt=4;;
		4) cnt=5;;
		5) cnt=6;;
		6) cnt=7;;
		7) cnt=8;;
		8) cnt=9;;
		9) cnt=10;;
		10) cnt=11;;
	esac

done

changequote([, ])dnl

ifelse([$3], , ,
[	#return value
	testparam([$3], 0, conftest.out_param_0, $func, $ucfunc, failure)dnl
])dnl

ifelse([$4], , ,
[	#first argument
	testparam([$4], 1, conftest.out_param_1, $func, $ucfunc, failure)dnl
])dnl

ifelse([$5], , ,
[	#second argument
	testparam([$5], 2, conftest.out_param_2, $func, $ucfunc, failure)dnl
])dnl

ifelse([$6], , ,
[	#third argument
	testparam([$6], 3, conftest.out_param_3, $func, $ucfunc, failure)dnl
])dnl

ifelse([$7], , ,
[	#fourth argument
	testparam([$7], 4, conftest.out_param_4, $func, $ucfunc, failure)dnl
])dnl

ifelse([$8], , ,
[	#fifth argument
	testparam([$8], 5, conftest.out_param_5, $func, $ucfunc, failure)dnl
])dnl

ifelse([$9], , ,
[	#sixth argument
	testparam([$9], 6, conftest.out_param_6, $func, $ucfunc, failure)dnl
])dnl

ifelse([$10], , ,
[	#seventh argument
	testparam([$10], 7, conftest.out_param_7, $func, $ucfunc, failure)dnl
])dnl

#failure
if test "x$failure" != x; then
AC_MSG_RESULT(failure)

echo "$failure" | tr '|' '\n'

ifelse([$2], , ,
[ $2
])dnl
else
	AC_MSG_RESULT(ok)
fi

rm -f conftest.*
])dnl
