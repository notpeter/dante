/*
 * $Id: session_key.c,v 1.3 2009/10/07 15:52:20 michaels Exp $
 *
 * Copyright (c) 2005
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 */

#include "common.h"

static const char rcsid[] =
"$Id: session_key.c,v 1.3 2009/10/07 15:52:20 michaels Exp $";

const licensekey_t module_session_keyv[] = {
   {
      .key               = KEY_IPV4,
      .value.ipv4.s_addr = 16777343 /* inet_addr("127.0.0.1") */
   },
};
const int module_session_keyc = ELEMENTS(module_session_keyv);
