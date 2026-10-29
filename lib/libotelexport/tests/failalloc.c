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

extern long failalloc_countdown;
extern long failalloc_failures;
long failalloc_countdown = -1;
long failalloc_failures;

void	*failalloc_malloc(size_t);
void	*failalloc_calloc(size_t, size_t);
void	*failalloc_realloc(void *, size_t);
void	*failalloc_reallocarray(void *, size_t, size_t);
char	*failalloc_strdup(const char *);

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
failalloc_malloc(size_t n)
{

	return (should_fail() ? NULL : malloc(n));
}

void *
failalloc_calloc(size_t n, size_t s)
{

	return (should_fail() ? NULL : calloc(n, s));
}

void *
failalloc_realloc(void *p, size_t n)
{

	return (should_fail() ? NULL : realloc(p, n));
}

void *
failalloc_reallocarray(void *p, size_t n, size_t s)
{

	return (should_fail() ? NULL : reallocarray(p, n, s));
}

char *
failalloc_strdup(const char *s)
{

	return (should_fail() ? NULL : strdup(s));
}
