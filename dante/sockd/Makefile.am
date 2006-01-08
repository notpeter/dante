sbin_PROGRAMS = sockd
sockd_SOURCES = ../lib/config_parse.y ../lib/config_scan.l \
	sockd.c sockd_child.c ../lib/io.c sockd_negotiate.c sockd_request.c \
	method_uname.c ../lib/debug.c ../lib/udp_util.c ../lib/util.c \
	../lib/log.c ../lib/socket.c sockd_socket.c  ../lib/config.c \
	sockd_util.c sockd_protocol.c serverconfig.c ../lib/protocol.c \
	../lib/hostcache.c ../dlib/interposition.c ../lib/broken.c \
        ../lib/serr.c sockd_io.c accesscheck.c auth_password.c \
	auth_pam.c ../lib/tostring.c redirect.c redirect_key.c \
	../lib/addressmatch.c checkmodule.c shmem.c bandwidth.c bandwidth_key.c \
	getifa.c ../lib/clientprotocol.c ../lib/httpproxy.c ../lib/authneg.c \
	session.c session_key.c
	

noinst_HEADERS = config_parse.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

#use libwrap if it is available
if WANT_LIBWRAP
LIBWRAP=-lwrap

#use preloading for libwrap if enabled and possible
if SERVER_INTERPOSITION
SERVDL = -DSOCKSLIBRARY_DYNAMIC=1
endif #SERVER_INTERPOSITION

else #WANT_LIBWRAP

#use preloading anyway?
if SERVER_INTERPOSITION_ALWAYS
SERVDL = -DSOCKSLIBRARY_DYNAMIC=1
endif #SERVER_INTERPOSITION_ALWAYS

endif #WANT_LIBWRAP

#XXXhack
if STATIC_SOCKD
sockd_LDADD = ../libscompat/sockatmark.o ${LIBWRAP}
else
sockd_LDADD = ../libscompat/libscompat.la ${LIBWRAP}
endif

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/libscompat
PREFIX = socks_yy
AM_YFLAGS = -d -p${PREFIX}
AM_LFLAGS = -P${PREFIX} -olex.yy.c

if STATIC_SOCKD
STATIC = -all-static
endif

if SPROFIL
PROFIL = -pg -DPROFILING
#XXX some systems do not appear to need this
sockd_LDFLAGS = ${STATIC}
else
PROFIL =
endif

#XXX
AM_CFLAGS = ${PROFIL} -DSOCKS_SERVER=1 -DSOCKS_CLIENT=0 ${SERVDL}
#lint files
SUFFIXES=.ln
if LINT
LINTFILES = sockd.ln sockd_child.ln sockd_io.ln io.ln udp_util.ln       \
	sockd_request.ln method_uname.ln debug.ln util.ln socket.ln     \
	log.ln sockd_socket.ln config_parse.ln config_scan.ln           \
	sockd_util.ln sockd_protocol.ln serverconfig.ln protocol.ln \
	sockd_negotiate.ln config.ln interposition.ln

sockd_DEPENDENCIES= $(LINTFILES)

CLEANFILES=$(LINTFILES)

LINT=lint
LINTFLAGS=-abcebiprxz

.c.ln:
	$(LINT) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $<
endif
