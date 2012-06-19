dlib64dir = $(libdir)/@ISA64DIR@

dlib64_LTLIBRARIES = libdsocks.la
libdsocks_la_SOURCES = ../dlib/interposition.c ../lib/config_parse.c	\
   ../lib/config_scan.c ../lib/Raccept.c ../lib/Rbind.c			\
   ../lib/Rbindresvport.c ../lib/Rcompat.c ../lib/Rconnect.c		\
   ../lib/Rgethostbyname.c ../lib/Rgetpeername.c			\
   ../lib/Rgetsockname.c ../lib/Rgetsockopt.c ../lib/Rlisten.c		\
   ../lib/Rrresvport.c ../lib/address.c ../lib/addressmatch.c		\
   ../lib/authneg.c ../lib/broken.c ../lib/client.c			\
   ../lib/clientconfig.c ../lib/clientprotocol.c ../lib/config.c	\
   ../lib/connectchild.c ../lib/debug.c ../lib/gssapi.c			\
   ../lib/hostcache.c ../lib/httpproxy.c ../lib/io.c ../lib/iobuf.c	\
   ../lib/log.c ../lib/protocol.c ../lib/serr.c ../lib/socket.c		\
   ../lib/socketopt.c ../lib/sockopt_gen.c ../lib/tostring.c		\
   ../lib/udp.c ../lib/udp_util.c ../lib/upnp.c ../lib/userio.c		\
   ../lib/util.c

EXTRA_libdsocks_la_SOURCES = ../libscompat/daemon.c		\
   ../libscompat/difftime.c ../libscompat/getifaddrs.c		\
   ../libscompat/hstrerror.c ../libscompat/inet_aton.c		\
   ../libscompat/inet_ntoa.c ../libscompat/inet_pton.c		\
   ../libscompat/issetugid.c ../libscompat/memmove.c		\
   ../libscompat/pselect.c ../libscompat/seteuid.c		\
   ../libscompat/setproctitle.c ../libscompat/sockatmark.c	\
   ../libscompat/strlcpy.c ../libscompat/strvis.c		\
   ../libscompat/vsyslog.c

libdsocks_la_LDFLAGS = -avoid-version -all-dynamic @MAPOPT@
libdsocks_la_LIBADD = @LIBDSCSRC@ @DLIBDEPS@
libdsocks_la_DEPENDENCIES = @LIBDSCSRC@
libdsocks_la_LIBTOOLFLAGS = --tag=disable-static

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
libdsocks_la_DEPENDENCIES += $(LINTFILES) llib-ldsocks.ln

CLEANFILES = $(LINTFILES)

.c.ln:
	-$(LINT) $(LINTPASS1) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(AM_CFLAGS) $< > $@.lint 2>&1
llib-ldsocks.ln: $(LINTFILES)
	-$(LINT) $(LINTPASS2) $(LINTFLAGS) $(LINTLIBOPT)dsocks $(LINTFILES) > $@.lint 2>&1
endif #RUNLINT
