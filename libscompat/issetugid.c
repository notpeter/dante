/* $Id: issetugid.c,v 1.7 2005/12/30 21:23:20 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_ISSETUGID

#if HAVE_LIBC_ENABLE_SECURE
extern int __libc_enable_secure;
#endif /* HAVE_LIBC_ENABLE_SECURE */

int
issetugid()
{
#if HAVE_LIBC_ENABLE_SECURE
	if (__libc_enable_secure)
		return 1;
	else
		return 0;
#endif /* HAVE_LIBC_ENABLE_SECURE */
	return 1;	/* don't know, better safe than sorry. */
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
	avoid_error();
}
#endif /* !HAVE_ISSETUGID */
