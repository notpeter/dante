/* $Id: sockatmark.c,v 1.8 2009/07/07 12:54:47 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "sockatmark.h"

int
sockatmark(s)
   int s;
{
   int argp;

   if (ioctl(s, SIOCATMARK, &argp) == -1)
      return -1;

   return argp == 0 ? 0 : 1;
}
