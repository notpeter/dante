/*
 * $Id: redirect_key.c,v 1.5 2009/10/07 15:52:20 michaels Exp $
 *
 * Copyright (c) 2001, 2002, 2003
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 */

#include "common.h"

static const char rcsid[] =
"$Id: redirect_key.c,v 1.5 2009/10/07 15:52:20 michaels Exp $";

const licensekey_t module_redirect_keyv[1] = {
   {
      .key               = KEY_IPV4,
      .value.ipv4.s_addr = 16777343 /* inet_addr("127.0.0.1") */
   },
};
const int module_redirect_keyc = ELEMENTS(module_redirect_keyv);
