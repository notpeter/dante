noinst_HEADERS = common.h sockd.h socks.h config.h yacconfig.h redefac.h \
		 interposition.h tostring.h osdep.h upnp.h \
		 socks_gssapi.h symbols.h
EXTRA_DIST = redefgen.sh symbols_common.txt symbols_freebsd.txt \
             symbols_glibc.txt symbols_osol.txt symbols_osol_stdio.txt

redefac.h: autoconf.h.in
	sh $(top_srcdir)/include/redefgen.sh $(top_srcdir)/include
