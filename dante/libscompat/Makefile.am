# should only build static library
noinst_LTLIBRARIES = libscompat.la
libscompat_la_SOURCES = difftime.c daemon.c getdtablesize.c hstrerror.c \
	inet_aton.c inet_ntoa.c inet_pton.c issetugid.c memmove.c       \
	setproctitle.c snprintf.c sockatmark.c strerror.c strvis.c      \
	vsyslog.c seteuid.c getifaddrs.c

noinst_HEADERS = compat.h

INCLUDES = -I$(top_srcdir)/include
