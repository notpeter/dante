#!/bin/sh
# $Id: redefgen.sh,v 1.2 1999/12/08 11:37:00 karls Exp $
#
# generate redefac.h from autoheader.h.in
#
# XXX should check for real changes
#
PATH=/bin:/usr/bin:/sbin:/usr/sbin

IN=autoconf.h.in
OUT=redefac.h

echo -e "/* ${OUT} generated from ${IN} on" `date` " */\n" > ${OUT}

for define in `egrep '^#undef' < $IN | egrep 'HAVE|NEED' | awk '{ print $2 }'`; do
    echo -e "#ifndef ${define}\n#define ${define} 0\n#endif\n\n" >> $OUT
done