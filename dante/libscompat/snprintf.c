/* $Id: snprintf.c,v 1.5 2000/08/31 06:57:00 karls Exp $ */

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif  /* HAVE_CONFIG_H */

#include "common.h"

#if !HAVE_VSNPRINTF

/*
 * Revision 12: http://theos.com/~deraadt/snprintf.c
 *
 * Copyright (c) 1997 Theo de Raadt
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if 0
#ifndef _COMMON_H_
#include <sys/types.h>
#endif  /* !_COMMON_H_ */
#include <sys/mman.h>
#include <signal.h>
#include <stdio.h>
#if STDC_HEADERS
#include <stdarg.h>
#include <stdlib.h>
#else
#include <varargs.h>
#endif  /* STDC_HEADERS */
#include <setjmp.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif  /* HAVE_UNISTD_H */
#endif

#ifndef roundup
#define roundup(x, y) ((((x)+((y)-1))/(y))*(y))
#endif

static int pgsize;
static char *curobj;
/*static int caught;*/
static sigjmp_buf bail;

static char *msetup __P((char *, size_t));
static void mcatch __P((void));
static void mcleanup __P((char *, size_t, char *));

#define EXTRABYTES      2       /* XXX: why 2? you don't want to know */

static char *
msetup(str, n)
	char *str;
	size_t n;
{
	char *e;

	if (n == 0)
		return NULL;
	if (pgsize == 0)
		pgsize = getpagesize();
	curobj = (char *)malloc(n + EXTRABYTES + pgsize * 2);
	if (curobj == NULL)
		return NULL;
	e = curobj + n + EXTRABYTES;
	e = (char *)roundup((unsigned long)e, pgsize);
	if (mprotect(e, pgsize, PROT_NONE) == -1) {
		free(curobj);
		curobj = NULL;
		return NULL;
	}
	e = e - n - EXTRABYTES;
	*e = '\0';
	return (e);
}

static void
mcatch()
{
	siglongjmp(bail, 1);
}

static void
mcleanup(str, n, p)
	char *str;
	size_t n;
	char *p;
{
	strncpy(str, p, n-1);
	str[n-1] = '\0';
	if (mprotect((caddr_t)(p + n + EXTRABYTES), pgsize,
		PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
		mprotect((caddr_t)(p + n + EXTRABYTES), pgsize,
			PROT_READ|PROT_WRITE);
	free(curobj);
}

int
#ifdef STDC_HEADERS
snprintf(char *str, size_t n, char const *fmt, ...)
#else
snprintf(str, n, fmt, va_alist)
	char *str;
	size_t n;
	char *fmt;
	va_dcl
#endif  /* STDC_HEADERS */
{
	va_list ap;
#ifdef STDC_HEADERS
	va_start(ap, fmt);
#else
	va_start(ap);
#endif  /* STDC_HEADERS */

	return (vsnprintf(str, n, fmt, ap));
	va_end(ap);
}

int
vsnprintf(str, n, fmt, ap)
	char *str;
	size_t n;
	const char *fmt;
	va_list ap;
{
	struct sigaction osa, nsa;
	char *p;
	int ret = n + 1;        /* if we bail, indicated we overflowed */

	memset(&nsa, 0, sizeof nsa);
	nsa.sa_handler = mcatch;
	sigemptyset(&nsa.sa_mask);

	p = msetup(str, n);
	if (p == NULL) {
		*str = '\0';
		return 0;
	}
	if (sigsetjmp(bail, 1) == 0) {
		if (sigaction(SIGSEGV, &nsa, &osa) == -1) {
			mcleanup(str, n, p);
			return (0);
		}
		ret = vsprintf(p, fmt, ap);
#if HAVE_BROKEN_VSPRINTF
		ret = strlen(p);
#endif  /* HAVE_BROKEN_VSPRINTF */
	}
	mcleanup(str, n, p);
	(void) sigaction(SIGSEGV, &osa, NULL);
	return (ret);
}
#else
static void avoid_error __P((void));
static void avoid_error()
{
	avoid_error();
}
#endif  /* !HAVE_VSNPRINTF */
