sbin_PROGRAMS = sockd
sockd_SOURCES = ../lib/config_parse.c ../lib/config_scan.c                  \
	sockd.c sockd_child.c ../lib/io.c sockd_negotiate.c sockd_request.c \
	method_uname.c ../lib/debug.c ../lib/udp_util.c ../lib/util.c       \
	../lib/log.c ../lib/socket.c sockd_socket.c  ../lib/config.c        \
	sockd_util.c sockd_protocol.c serverconfig.c ../lib/protocol.c      \
	../lib/hostcache.c ../dlib/interposition.c ../lib/broken.c          \
        ../lib/serr.c sockd_io.c accesscheck.c auth_password.c              \
	auth_pam.c ../lib/tostring.c					    \
	redirect.c redirect_key.c                                           \
	../lib/addressmatch.c checkmodule.c shmem.c                         \
	bandwidth.c bandwidth_key.c					    \
	getifa.c ../lib/clientprotocol.c ../lib/httpproxy.c                 \
	../lib/authneg.c  ../lib/userio.c                                   \
	session.c session_key.c                                             \
	../lib/upnp.c method_gssapi.c ../lib/gssapi.c ../lib/iobuf.c        \
	privileges.c

#use libwrap if it is available
if WANT_LIBWRAP
LIBWRAP=-lwrap

#use preloading for libwrap if enabled and possible
if SERVER_INTERPOSITION
SERVDL=1
else
SERVDL=0
endif #SERVER_INTERPOSITION

else #WANT_LIBWRAP

#use preloading anyway?
if SERVER_INTERPOSITION_ALWAYS
SERVDL=1
else
SERVDL=0
endif #SERVER_INTERPOSITION_ALWAYS

endif #WANT_LIBWRAP

sockd_LDADD = ../libscompat/libscompat.la ${LIBWRAP} @SOCKDDEPS@

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libscompat \
	   -I$(top_srcdir)/lib

AM_CFLAGS = -DSOCKS_SERVER=1 -DSOCKS_CLIENT=0 -DSOCKSLIBRARY_DYNAMIC=${SERVDL}

#lint files
LINT = @LINT@
LINTFLAGS = @LINTFLAGS@

if RUNLINT
SUFFIXES = .ln
LINTFILESa = $(sockd_SOURCES:.c=.ln)
LINTFILESb = $(LINTFILESa:.y=.ln)
LINTFILES = $(LINTFILESb:.l=.ln)
sockd_DEPENDENCIES = $(LINTFILES)

CLEANFILES = $(LINTFILES)

.c.ln:
	$(LINT) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(AM_CFLAGS) $<
endif #RUNLINT
