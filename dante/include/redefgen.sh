#!/bin/sh
# $Id: redefgen.sh,v 1.3 2000/02/20 15:32:28 karls Exp $
#
# generate redefac.h from autoheader.h.in
#
# XXX should check for real changes
#
PATH=/bin:/usr/bin:/sbin:/usr/sbin

IN=autoconf.h.in
OUT=redefac.h

echo "/* ${OUT} generated from ${IN} on" `date` " */
" > ${OUT}

for define in `egrep '^#undef' < $IN | egrep 'HAVE|NEED' | awk '{ print $2 }'`; do
    echo "#ifndef ${define}
#define ${define} 0
#endif

" >> $OUT
done