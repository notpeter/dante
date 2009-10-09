/* $Id: seteuid.c,v 1.6 2009/07/07 12:54:47 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif /* HAVE_CONFIG_H */

#include "common.h"

int
setegid(gid_t egid)
{
   return setresgid(-1, egid, -1);
}

int
seteuid(uid_t euid)
{
   return setreuid(-1, euid);
}
