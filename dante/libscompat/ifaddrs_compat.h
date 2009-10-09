/* $Id: ifaddrs_compat.h,v 1.2 2009/07/07 13:08:18 karls Exp $ */
#if HAVE_GETIFADDRS
#include <ifaddrs.h>
#else
/*
 * Copyright (c) 2000 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id: ifaddrs_compat.h,v 1.2 2009/07/07 13:08:18 karls Exp $ */

#ifndef __ifaddrs_h__
#define __ifaddrs_h__

#if 0
#ifndef ROKEN_LIB_FUNCTION
#ifdef _WIN32
#define ROKEN_LIB_FUNCTION _stdcall
#else
#define ROKEN_LIB_FUNCTION
#endif
#endif
#endif
#define ROKEN_LIB_FUNCTION

/*
 * the interface is defined in terms of the fields below, and this is
 * sometimes #define'd, so there seems to be no simple way of solving
 * this and this seemed the best. */

#undef ifa_dstaddr

struct ifaddrs {
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned int ifa_flags;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    struct sockaddr *ifa_dstaddr;
    void *ifa_data;
};

#ifndef ifa_broadaddr
#define ifa_broadaddr ifa_dstaddr
#endif

int ROKEN_LIB_FUNCTION
getifaddrs(struct ifaddrs**);

void ROKEN_LIB_FUNCTION
freeifaddrs(struct ifaddrs*);

#endif /* __ifaddrs_h__ */
#endif /* !HAVE_GETIFADDRS */

/*
 * BSDI 4.1 doesn't have freeifaddrs(), but uses free()
 *  Problem reported by "Zand, Nooshin" <nooshin.zand@intel.com>
 */
#if HAVE_GETIFADDRS && !HAVE_FREEIFADDRS
#define freeifaddrs free
#endif /* HAVE_GETIFADDRS && !HAVE_FREEIFADDRS */
