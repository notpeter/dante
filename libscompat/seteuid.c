/* $Id: seteuid.c,v 1.3 2008/07/25 08:49:05 michaels Exp $ */

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
