/* $Id: getdtablesize.c,v 1.3 1999/05/13 16:35:55 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_GETDTABLESIZE

int
getdtablesize(void)
{
#if HAVE_SYSCONF
		const int res = sysconf(_SC_OPEN_MAX);

		if (res == -1)
			return SOCKS_FD_MAX;
		else
			return res;
#else
		return SOCKS_FD_MAX;	/* XXX, won't work. */
#endif  /* HAVE_SYSCONF */
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
	avoid_error();
}
#endif  /* HAVE_GETDTABLESIZE */
