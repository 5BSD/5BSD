/*-
 * Copyright (c) 2002-2003 Luigi Rizzo
 * Copyright (c) 1996 Alex Nash, Paul Traina, Poul-Henning Kamp
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Idea and grammar partially left from:
 * Copyright (c) 1993 Daniel Boulet
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * NEW command line interface for IP firewall facility
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include "dnctl.h"


int
bp_alloc(struct buf_pr *b, size_t size)
{
	memset(b, 0, sizeof(struct buf_pr));

	if ((b->buf = calloc(1, size)) == NULL)
		return (ENOMEM);

	b->ptr = b->buf;
	b->size = size;
	b->avail = b->size;

	return (0);
}

void
bp_free(struct buf_pr *b)
{

	free(b->buf);
}

void
bp_flush(struct buf_pr *b)
{

	b->ptr = b->buf;
	b->avail = b->size;
	b->buf[0] = '\0';
}

int
bprintf(struct buf_pr *b, const char *format, ...)
{
	va_list args;
	int i;

	va_start(args, format);

	i = vsnprintf(b->ptr, b->avail, format, args);
	va_end(args);

	if (i < 0 || (size_t)i > b->avail) {
		/* Overflow or print error */
		b->avail = 0;
	} else {
		b->ptr += i;
		b->avail -= i;
	}

	b->needed += i;

	return (i);
}

int
pr_u64(struct buf_pr *b, void *pd, int width)
{
#ifdef TCC
#define U64_FMT "I64"
#else
#define U64_FMT "llu"
#endif
	uint64_t u;
	unsigned long long d;

	bcopy (pd, &u, sizeof(u));
	d = u;
	return (width > 0) ?
		bprintf(b, "%*" U64_FMT " ", width, d) :
		snprintf(NULL, 0, "%" U64_FMT, d) ;
#undef U64_FMT
}

void *
safe_calloc(size_t number, size_t size)
{
	void *ret = calloc(number, size);

	if (ret == NULL)
		err(EX_OSERR, "calloc");
	return ret;
}

void *
safe_realloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);

	if (ret == NULL)
		err(EX_OSERR, "realloc");
	return ret;
}

int
match_token(struct _s_x *table, const char *string)
{
	struct _s_x *pt;
	uint i = strlen(string);

	for (pt = table ; i && pt->s != NULL ; pt++)
		if (strlen(pt->s) == i && !bcmp(string, pt->s, i))
			return pt->x;
	return (-1);
}

int
_substrcmp(const char *str1, const char* str2)
{

	if (strncmp(str1, str2, strlen(str1)) != 0)
		return 1;

	if (strlen(str1) != strlen(str2))
		warnx("DEPRECATED: '%s' matched '%s' as a sub-string",
		    str1, str2);
	return 0;
}

int
_substrcmp2(const char *str1, const char* str2, const char* str3)
{

	if (strncmp(str1, str2, strlen(str2)) != 0)
		return 1;

	if (strcmp(str1, str3) != 0)
		warnx("DEPRECATED: '%s' matched '%s'",
		    str1, str3);
	return 0;
}

void
n2mask(struct in6_addr *mask, int n)
{
	static int	minimask[9] =
	    { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
	u_char		*p;

	memset(mask, 0, sizeof(struct in6_addr));
	p = (u_char *) mask;
	for (; n > 0; p++, n -= 8) {
		if (n >= 8)
			*p = 0xff;
		else
			*p = minimask[n];
	}
	return;
}
