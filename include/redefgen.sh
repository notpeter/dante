#!/bin/sh
# $Id: redefgen.sh,v 1.1 1999/04/19 14:41:29 karls Exp $
#
# generate redefac.h from autoheader.h.in
#
PATH=/bin:/usr/bin:/sbin:/usr/sbin

IN=autoconf.h.in
OUT=redefac.h

echo -e "/* ${OUT} generated from ${IN} on" `date` " */\n" > ${OUT}

for define in `egrep '^#undef' < $IN | egrep 'HAVE|NEED' | awk '{ print $2 }'`; do
    echo -e "#ifndef ${define}\n#define ${define} 0\n#endif\n\n" >> $OUT
done