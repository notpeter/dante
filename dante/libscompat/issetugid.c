/* $Id: issetugid.c,v 1.6 1999/05/13 16:35:57 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_ISSETUGID

int
issetugid()
{
	return 1;	/* don't know, better safe than sorry. */
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
	avoid_error();
}
#endif /* !HAVE_ISSETUGID */
