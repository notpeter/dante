#XXX should only build shared library
lib_LTLIBRARIES = libdsocks.la
libdsocks_la_SOURCES = interposition.c int_osf1.c int_osf2.c int_osf3.c   \
	config_parse.y io.c debug.c Rgetpeername.c Rgetsockname.c udp.c   \
	Rrresvport.c Rbind.c config_scan.l address.c authneg.c client.c   \
	clientconfig.c clientprotocol.c Raccept.c userio.c method_uname.c \
	connectchild.c config.c log.c protocol.c socket.c udp_util.c      \
	Rbindresvport.c Rconnect.c util.c Rgethostbyname.c Rcompat.c      \
	msproxy_clientprotocol.c broken.c hostcache.c serr.c httpproxy.c	\
	tostring.c addressmatch.c

#libdsocks version info, interfaceversion:revision:old interfaces supported
#XXX SPEC/dante.spec.in must have the same value as version info
libdsocks_la_LDFLAGS = -avoid-version -all-dynamic
libdsocks_la_LIBADD = ../libscompat/libscompat.la

noinst_HEADERS = config_parse.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libscompat
#XXX
AM_CFLAGS = -DSOCKS_CLIENT=1 -DSOCKS_SERVER=0 -DSOCKSLIBRARY_DYNAMIC=1
#XXXlibrary name needed for socksify
PREFIX = socks_yy
AM_YFLAGS = -d -p${PREFIX}
AM_LFLAGS = -P${PREFIX} -olex.yy.c
