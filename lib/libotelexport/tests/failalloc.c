/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Allocation-failure injection for tests; see failalloc.h.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "failalloc.h"

long failalloc_countdown = -1;
long failalloc_failures;

void	*__real_malloc(size_t);
void	*__real_calloc(size_t, size_t);
void	*__real_realloc(void *, size_t);
void	*__real_reallocarray(void *, size_t, size_t);
char	*__real_strdup(const char *);
char	*__real_strndup(const char *, size_t);
void	*__wrap_malloc(size_t);
void	*__wrap_calloc(size_t, size_t);
void	*__wrap_realloc(void *, size_t);
void	*__wrap_reallocarray(void *, size_t, size_t);
char	*__wrap_strdup(const char *);
char	*__wrap_strndup(const char *, size_t);

static int
should_fail(void)
{

	if (failalloc_countdown < 0)
		return (0);
	if (failalloc_countdown-- == 0) {
		failalloc_failures++;
		errno = ENOMEM;
		return (1);
	}
	return (0);
}

void *
__wrap_malloc(size_t n)
{

	return (should_fail() ? NULL : __real_malloc(n));
}

void *
__wrap_calloc(size_t n, size_t s)
{

	return (should_fail() ? NULL : __real_calloc(n, s));
}

void *
__wrap_realloc(void *p, size_t n)
{

	return (should_fail() ? NULL : __real_realloc(p, n));
}

void *
__wrap_reallocarray(void *p, size_t n, size_t s)
{

	return (should_fail() ? NULL : __real_reallocarray(p, n, s));
}

char *
__wrap_strdup(const char *s)
{

	return (should_fail() ? NULL : __real_strdup(s));
}

char *
__wrap_strndup(const char *s, size_t n)
{

	return (should_fail() ? NULL : __real_strndup(s, n));
}
