/*
 * $Id: session_key.c,v 1.7 2011/05/18 13:48:47 karls Exp $
 *
 * Copyright (c) 2005, 2009, 2011
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 */

#include "common.h"

static const char rcsid[] =
"$Id: session_key.c,v 1.7 2011/05/18 13:48:47 karls Exp $";

const licensekey_t module_session_keyv[] = {
   {
      .key               = KEY_IPV4,
      .value.ipv4.s_addr = 16777343 /* inet_addr("127.0.0.1") */
   },
};
const int module_session_keyc = ELEMENTS(module_session_keyv);
