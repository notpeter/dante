/* $Id: seteuid.c,v 1.1 1999/09/29 10:18:03 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_SETEUID

int
seteuid(uid_t euid)
{
	return setreuid(-1, euid);
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
	avoid_error();
}
#endif /* !HAVE_ISSETUGID */
