noinst_HEADERS = common.h sockd.h socks.h config.h yacconfig.h redefac.h
EXTRA_DIST = redefgen.sh

redefac.h: autoconf.h.in
	sh redefgen.sh
