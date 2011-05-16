sbin_PROGRAMS = sockd
sockd_SOURCES = ../lib/addressmatch.c ../lib/authneg.c ../lib/broken.c	\
	../lib/clientprotocol.c ../lib/config.c ../lib/config_parse.c	\
	../lib/config_scan.c ../lib/debug.c ../lib/gssapi.c		\
	../lib/hostcache.c ../lib/httpproxy.c ../lib/io.c		\
	../lib/iobuf.c ../lib/log.c ../lib/protocol.c ../lib/serr.c	\
	../lib/socket.c ../lib/tostring.c ../lib/udp_util.c		\
	../lib/upnp.c ../lib/userio.c ../lib/util.c accesscheck.c	\
	auth_bsd.c auth_pam.c auth_password.c bandwidth.c		\
	bandwidth_key.c checkmodule.c getoutaddr.c iface.c ldap.c	\
	ldap_util.c method.c method_gssapi.c method_uname.c		\
	privileges.c redirect.c redirect_key.c rule.c serverconfig.c	\
	session.c session_key.c shmem.c sockd.c sockd_child.c		\
	sockd_io.c sockd_negotiate.c sockd_protocol.c sockd_request.c	\
	sockd_socket.c sockd_util.c

#use libwrap if it is available
if WANT_LIBWRAP
LIBWRAP=-lwrap

#use preloading for libwrap if enabled and possible
if SERVER_INTERPOSITION
SERVDL=1
sockd_SOURCES += ../dlib/interposition.c
else
SERVDL=0
endif #SERVER_INTERPOSITION

else #WANT_LIBWRAP

#use preloading anyway?
if SERVER_INTERPOSITION_ALWAYS
SERVDL=1
sockd_SOURCES += ../dlib/interposition.c
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
sockd_DEPENDENCIES = $(LINTFILES) pass2.ln

CLEANFILES = $(LINTFILES)

.c.ln:
	$(LINT) $(LINTPASS1) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(AM_CFLAGS) $< > $@.lint 2>&1

pass2.ln: $(LINTFILES)
	-@test -s interposition.ln && cp interposition.ln ../dlib #XXX
	$(LINT) $(LINTPASS2) $(LINTFLAGS) -L../libscompat -L../lib -lscompat -lsocks  $(LINTFILES) > $@ > $@.lint 2>&1
endif #RUNLINT
