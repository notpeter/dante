#!/bin/sh
# $Id: redefgen.sh,v 1.5 2000/07/21 16:22:45 karls Exp $
#
# generate redefac.h from autoheader.h.in
#
PATH=/bin:/usr/bin:/sbin:/usr/sbin

IN=$1/autoconf.h.in
OUT=$1/redefac.h

echo "/* Do not modify, generated from ${IN} */
" > ${OUT}

for define in `egrep '^#undef' < $IN | egrep 'HAVE|NEED' | awk '{ print $2 }'`; do
    echo "#ifndef ${define}
#define ${define} 0
#endif

" >> $OUT
done