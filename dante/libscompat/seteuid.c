/* $Id: seteuid.c,v 1.2 2004/11/09 07:10:24 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_SETEGID
int
setegid(gid_t egid)
{
	return setresgid(-1, egid, -1);
}
#endif /* !HAVE_SETEGID */

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
