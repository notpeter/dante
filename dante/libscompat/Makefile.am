noinst_LTLIBRARIES = libscompat.la
libscompat_la_SOURCES =
EXTRA_libscompat_la_SOURCES = difftime.c daemon.c hstrerror.c \
   inet_aton.c inet_ntoa.c inet_pton.c issetugid.c memmove.c \
   setproctitle.c sockatmark.c strlcpy.c strvis.c vsyslog.c seteuid.c \
   getifaddrs.c

libscompat_la_LIBADD = @LIBSCSRC@
#libscompat_la_DEPENDENCIES = @LIBSCSRC@
LIBDEPS=@LIBSCSRC@

noinst_HEADERS = daemon.h difftime.h ifaddrs_compat.h sockatmark.h strlcpy.h \
      timers.h vis_compat.h issetugid.h

INCLUDES = -I$(top_srcdir)/include -I.

AM_CFLAGS = -DSOCKS_CLIENT=0 -DSOCKS_SERVER=0 -DSOCKSLIBRARY_DYNAMIC=0

#lint files
LINT = @LINT@
LINTFLAGS = @LINTFLAGS@

if RUNLINT
SUFFIXES = .ln
LINTFILES = $(LIBSCSRC:.lo=.ln)
LIBDEPS += $(LINTFILES) llib-lscompat.ln

CLEANFILES = $(LINTFILES)

.c.ln:
	$(LINT) $(LINTPASS1) $(LINTFLAGS) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(AM_CFLAGS) $< > $@.lint 2>&1

llib-lscompat.ln: $(LINTFILES)
	$(LINT) $(LINTPASS2) $(LINTFLAGS) $(LINTLIBOPT)scompat $(LINTFILES) > $@.lint 2>&1
endif #RUNLINT

libscompat_la_DEPENDENCIES = $(LIBDEPS)
