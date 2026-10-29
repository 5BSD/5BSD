/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Allocation-failure injection for tests.  Force-included (-include)
 * when a test compiles a library source a second time, so only that
 * source's own allocations are redirected; the library proper is not
 * affected.
 */

#ifndef _FAILALLOC_H_
#define	_FAILALLOC_H_

#include <stdlib.h>
#include <string.h>

/* <0: never fail; otherwise the allocation after this many fails. */
extern long failalloc_countdown;
/* Number of injected failures since the last reset. */
extern long failalloc_failures;

void	*failalloc_malloc(size_t);
void	*failalloc_calloc(size_t, size_t);
void	*failalloc_realloc(void *, size_t);
void	*failalloc_reallocarray(void *, size_t, size_t);
char	*failalloc_strdup(const char *);

#define	malloc(n)		failalloc_malloc(n)
#define	calloc(n, s)		failalloc_calloc((n), (s))
#define	realloc(p, n)		failalloc_realloc((p), (n))
#define	reallocarray(p, n, s)	failalloc_reallocarray((p), (n), (s))
#define	strdup(s)		failalloc_strdup(s)

#endif /* !_FAILALLOC_H_ */
