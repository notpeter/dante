noinst_HEADERS = common.h sockd.h socks.h config.h yacconfig.h redefac.h \
		 interposition.h tostring.h
EXTRA_DIST = redefgen.sh

redefac.h: autoconf.h.in
	sh $(top_srcdir)/include/redefgen.sh $(top_srcdir)/include
