/*
 * $Id: ldap_key.c,v 1.4 2011/12/19 08:46:07 michaels Exp $
 *
 * Copyright (c) 2009, 2011
 *      Inferno Nettverk A/S, Norway.  All rights reserved.
 */

#include "common.h"

static const char rcsid[] =
"$Id: ldap_key.c,v 1.4 2011/12/19 08:46:07 michaels Exp $";

const licensekey_t module_ldap_keyv[1] = {
   {
      .key               = KEY_IPV4,
      .value.ipv4.s_addr = 16777343 /* inet_addr("127.0.0.1") */
   },
};
const int module_ldap_keyc = ELEMENTS(module_ldap_keyv);
