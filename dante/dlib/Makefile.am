#XXX should only build shared library
lib_LTLIBRARIES = libdsocks.la
libdsocks_la_SOURCES = config_parse.y config_scan.l udp.c Rbind.c io.c  \
	Rgetpeername.c Rgetsockname.c Rrresvport.c compat.c   \
	address.c authneg.c client.c clientconfig.c clientprotocol.c    \
	Raccept.c userio.c method_uname.c connectchild.c config.c \
	protocol.c socket.c udp_util.c util.c Rbindresvport.c debug.c   \
	Rconnect.c Rgethostbyname.c interposition.c log.c Rcompat.c

noinst_HEADERS = config_parse.h compat.h interposition.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

INCLUDES = -I../../include -I../
CFLAGS += -DSOCKS_CLIENT -DSOCKSLIBRARY_DYNAMIC
LDFLAGS += -all-dynamic
PREFIX = socks_yy
YFLAGS = -d -p${PREFIX}
LFLAGS = -P${PREFIX} -olex.yy.c
