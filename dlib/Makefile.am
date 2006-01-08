lib_LTLIBRARIES = libdsocks.la
libdsocks_la_SOURCES = interposition.c int_osf1.c int_osf2.c int_osf3.c \
	../lib/config_parse.y ../lib/io.c ../lib/debug.c ../lib/udp.c \
	../lib/Rgetpeername.c ../lib/Rgetsockname.c \
	../lib/Rrresvport.c ../lib/Rbind.c ../lib/config_scan.l \
	../lib/address.c ../lib/authneg.c ../lib/client.c   \
	../lib/clientconfig.c ../lib/clientprotocol.c ../lib/Raccept.c \
	../lib/userio.c ../lib/connectchild.c \
	../lib/config.c ../lib/log.c ../lib/protocol.c ../lib/socket.c \
	../lib/udp_util.c ../lib/Rbindresvport.c ../lib/Rconnect.c \
	../lib/util.c ../lib/Rgethostbyname.c ../lib/Rcompat.c \
	../lib/msproxy_clientprotocol.c ../lib/broken.c ../lib/hostcache.c \
	../lib/serr.c ../lib/httpproxy.c ../lib/tostring.c \
	../lib/addressmatch.c

libdsocks_la_LDFLAGS = -version-info 1:0:1 -all-dynamic
libdsocks_la_LIBADD = ../libscompat/libscompat.la

noinst_HEADERS = config_parse.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libscompat
#XXX
AM_CFLAGS = -DSOCKS_CLIENT=1 -DSOCKS_SERVER=0 -DSOCKSLIBRARY_DYNAMIC=1
PREFIX = socks_yy
AM_YFLAGS = -d -p${PREFIX}
AM_LFLAGS = -P${PREFIX} -olex.yy.c
