dlib64dir = $(libdir)/@ISA64DIR@

dlib64_LTLIBRARIES = libdsocks.la
libdsocks_la_SOURCES = ../dlib/interposition.c \
	../lib/config_parse.c ../lib/config_scan.c \
	../lib/io.c ../lib/debug.c ../lib/udp.c \
	../lib/Rgetpeername.c ../lib/Rgetsockname.c ../lib/Rgetsockopt.c \
	../lib/Rrresvport.c ../lib/Rbind.c \
	../lib/address.c ../lib/authneg.c ../lib/client.c   \
	../lib/clientconfig.c ../lib/clientprotocol.c ../lib/Raccept.c \
	../lib/userio.c ../lib/connectchild.c \
	../lib/config.c ../lib/log.c ../lib/protocol.c ../lib/socket.c \
	../lib/udp_util.c ../lib/Rbindresvport.c ../lib/Rconnect.c \
	../lib/util.c ../lib/Rgethostbyname.c ../lib/Rcompat.c \
	../lib/broken.c ../lib/hostcache.c \
	../lib/serr.c ../lib/httpproxy.c ../lib/tostring.c \
	../lib/addressmatch.c ../lib/Rlisten.c ../lib/upnp.c ../lib/gssapi.c \
	../lib/iobuf.c \
	../libscompat/getifaddrs.c ../libscompat/setproctitle.c \
	../libscompat/strvis.c

libdsocks_la_LDFLAGS = -avoid-version -all-dynamic @MAPOPT@
#../libscompat/libscompat.la XXX used files hardcoded above
libdsocks_la_LIBADD =  @DLIBDEPS@

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libscompat \
	   -I$(top_srcdir)/lib

AM_CFLAGS = -DSOCKS_CLIENT=1 -DSOCKS_SERVER=0 -DSOCKSLIBRARY_DYNAMIC=1 -m64

#lint files
LINT = @LINT@
LINTFLAGS = @LINTFLAGS@

if RUNLINT
SUFFIXES = .ln
LINTFILESa = $(libdsocks_la_SOURCES:.c=.ln)
LINTFILESb = $(LINTFILESa:.y=.ln)
LINTFILES = $(LINTFILESb:.l=.ln)
libdsocks_la_DEPENDENCIES = $(LINTFILES)

CLEANFILES = $(LINTFILES)

.c.ln:
	$(LINT) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(AM_CFLAGS) $<
endif #RUNLINT
