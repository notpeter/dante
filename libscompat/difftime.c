/* $Id: difftime.c,v 1.3 1999/05/13 16:35:55 karls Exp $ */

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
