/* $Id: sockatmark.c,v 1.4 2008/07/25 08:49:06 michaels Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_SOCKATMARK

int
sockatmark(s)
   int s;
{
   int argp;

   if (ioctl(s, SIOCATMARK, &argp) == -1)
      return -1;

   return argp == 0 ? 0 : 1;
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
   avoid_error();
}
#endif  /* HAVE_SOCKATMARK */
