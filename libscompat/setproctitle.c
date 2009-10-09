/* $Id: setproctitle.c,v 1.10 2009/07/07 12:54:47 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif /* HAVE_CONFIG_H */

int
initsetproctitle(argc, argv, envp)
   int argc;
   char **argv;
   char **envp;
{
   return 0;
}

void
setproctitle(const char *fmt, ...)
{
   return;
}
