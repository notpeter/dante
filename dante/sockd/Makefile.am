sbin_PROGRAMS = sockd
sockd_SOURCES = sockd.c sockd_child.c sockd_io.c io.c sockd_negotiate.c     \
        sockd_request.c method_uname.c debug.c compat.c udp_util.c util.c   \
	socket.c log.c sockd_socket.c config_parse.y config_scan.l config.c \
	sockd_util.c sockd_protocol.c serverconfig.c lib_protocol.c 

noinst_HEADERS = config_parse.h
MAINTAINERCLEANFILES = config_parse.h config_parse.c config_scan.c

INCLUDES = -I../include -I../lib
PREFIX = socks_yy
YFLAGS = -d -p${PREFIX}
LFLAGS = -P${PREFIX} -olex.yy.c

if STATIC_SOCKD
STATIC = -all-static
endif

if SPROFIL
PROFIL = -pg
#XXX some systems do not appear to need this
sockd_LDFLAGS = ${STATIC}
else
PROFIL =
endif

CFLAGS += ${PROFIL} -DSOCKS_SERVER
#lint files
SUFFIXES=.ln
if LINT
LINTFILES = sockd.ln sockd_child.ln sockd_io.ln io.ln udp_util.ln       \
        sockd_request.ln method_uname.ln debug.ln compat.ln util.ln     \
	socket.ln log.ln sockd_socket.ln config_parse.ln config_scan.ln \
	sockd_util.ln sockd_protocol.ln serverconfig.ln lib_protocol.ln \
	sockd_negotiate.ln config.ln

sockd_DEPENDENCIES= $(LINTFILES)

CLEANFILES=$(LINTFILES)

LINT=lint
LINTFLAGS=-abcebiprxz

.c.ln:
	$(LINT) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $<
endif
