lib_LTLIBRARIES = libsocks.la
libsocks_la_SOURCES = config_parse.y config_scan.l Raccept.c Rbind.c \
	Rgetpeername.c Rgetsockname.c Rrresvport.c io.c    \
	address.c authneg.c client.c clientconfig.c clientprotocol.c \
	udp.c userio.c method_uname.c connectchild.c config.c  \
	log.c protocol.c socket.c udp_util.c util.c Rbindresvport.c  \
	Rconnect.c Rgethostbyname.c debug.c Rcompat.c \
	msproxy_clientprotocol.c hostcache.c broken.c
#libsocks version info, interfaceversion:revision:old interfaces supported
#XXX SPEC/dante.spec.in must have the same value as version info
libsocks_la_LDFLAGS = -version-info 1:0:1

libsocks_la_LIBADD = ../libscompat/libscompat.la

noinst_HEADERS = config_parse.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

INCLUDES = -I../libscompat
#XXX
AM_CFLAGS =-DSOCKS_CLIENT=1 -DSOCKS_SERVER=0
PREFIX = socks_yy
YFLAGS = -d -p${PREFIX}
LFLAGS = -P${PREFIX} -olex.yy.c
