AUTOMAKE_OPTIONS = foreign
if BUILD_PRELOAD_LIB
SUBDIRS = libscompat dlib lib sockd include example doc bin SPECS capi contrib
else
SUBDIRS = libscompat      lib sockd include example doc bin SPECS capi contrib
endif

#XXX this is not very pretty, but EXTRA_DIST does not accept conditionals
if PRERELEASE
DIST_COMMON = PRERELEASE README INSTALL Makefile.am Makefile.in NEWS TODO    \
	aclocal.m4 config.guess config.sub configure configure.in install-sh \
	ltconfig ltmain.sh missing mkinstalldirs acinclude.m4 acconfig.h
else
DIST_COMMON = README INSTALL Makefile.am Makefile.in NEWS TODO aclocal.m4  \
	config.guess config.sub configure configure.in install-sh ltconfig \
	ltmain.sh missing mkinstalldirs acinclude.m4 acconfig.h
endif

EXTRA_DIST = BUGS CREDITS LICENSE SUPPORT VERSION VERSION.in
