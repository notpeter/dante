/* $Id: difftime.c,v 1.4 2008/07/25 08:49:04 michaels Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_DIFFTIME

double
difftime(t1, t0)
   long t1;
   long t0;
{
   return (double)(t1 - t0);
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
   avoid_error();
}
#endif  /* !HAVE_DIFFTIME */
