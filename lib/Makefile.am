lib_LTLIBRARIES = libsocks.la
libsocks_la_SOURCES = config_parse.c config_scan.c Raccept.c Rbind.c \
	Rgetpeername.c Rgetsockname.c Rgetsockopt.c Rrresvport.c io.c    \
	address.c authneg.c client.c clientconfig.c clientprotocol.c \
	udp.c userio.c connectchild.c config.c  \
	log.c protocol.c socket.c udp_util.c util.c Rbindresvport.c  \
	Rconnect.c Rgethostbyname.c debug.c Rcompat.c \
	hostcache.c broken.c serr.c httpproxy.c \
	tostring.c addressmatch.c Rlisten.c upnp.c gssapi.c iobuf.c

#libsocks version info, interfaceversion:revision:old interfaces supported
#XXX SPEC/dante.spec.in must have the same value as version info
libsocks_la_LDFLAGS = -version-info 1:1:1
libsocks_la_LIBADD = ../libscompat/libscompat.la @DLIBDEPS@

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libscompat

AM_CFLAGS = -DSOCKS_CLIENT=1 -DSOCKS_SERVER=0 -DSOCKSLIBRARY_DYNAMIC=0

EXTRA_DIST = config_parse.y config_scan.l
noinst_HEADERS = config_parse.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

PREFIX = socks_yy
AM_YFLAGS = -d -p${PREFIX}
AM_LFLAGS = -P${PREFIX} -olex.yy.c
YFLAGS = @YFLAGS@
#LFLAGS = @LFLAGS@

#XXX ensure common.h is included before any other headers for lex/yacc;
#    keep the generation rules here, with a slight modification
#    XXX likely no longer needed
config_parse.c: config_parse.y
	$(YACC) $(YFLAGS) $(AM_YFLAGS) config_parse.y
	@if test -f y.tab.h; then \
	  to=`echo "$*_H" | sed \
                -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/' \
                -e 's/[^ABCDEFGHIJKLMNOPQRSTUVWXYZ]/_/g'`; \
	  sed -e "/^#/!b" -e "s/Y_TAB_H/$$to/g" -e "s|y\.tab\.h|$*.h|" \
            y.tab.h >$*.ht; \
	  rm -f y.tab.h; \
	  if cmp -s $*.ht $*.h; then \
	    rm -f $*.ht ;\
	  else \
	    mv $*.ht $*.h; \
	  fi; \
	fi
	@if test -f y.output; then \
	  mv y.output $*.output; \
	fi
	@echo '#include "common.h"' > $@
	@sed '/^#/ s|y\.tab\.c|$@|' y.tab.c >$@t && cat $@t >> $@ && \
	   rm -f $@t
	@rm -f y.tab.c

config_scan.c: config_scan.l
	$(LEX) $(LFLAGS) $(AM_LFLAGS) config_scan.l
	@echo '#include "common.h"' > $@
	@sed '/^#/ s|$(LEX_OUTPUT_ROOT)\.c|$@|' $(LEX_OUTPUT_ROOT).c >> $@
	@rm -f $(LEX_OUTPUT_ROOT).c

#lint files
LINT = @LINT@
LINTFLAGS = @LINTFLAGS@

if RUNLINT
SUFFIXES = .ln
LINTFILESa = $(libsocks_la_SOURCES:.c=.ln)
LINTFILESb = $(LINTFILESa:.y=.ln)
LINTFILES = $(LINTFILESb:.l=.ln)
libsocks_la_DEPENDENCIES = $(LINTFILES) llib-lsocks.ln

CLEANFILES = $(LINTFILES)

.c.ln:
	$(LINT) $(LINTPASS1) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(AM_CFLAGS) $< > $@.lint 2>&1

llib-lsocks.ln: $(LINTFILES)
	$(LINT) $(LINTPASS2) $(LINTFLAGS) $(LINTLIBOPT)socks $(LINTFILES) > $@.lint 2>&1
endif #RUNLINT
