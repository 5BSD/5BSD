/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of the kernel <sys/malloc.h>.  The kernel
 * malloc/free spellings are macros, so test code that follows a DUT
 * inclusion must use the kmock_* names (or #undef) for libc allocation.
 */
#ifndef _KMOCK_SYS_MALLOC_H_
#define	_KMOCK_SYS_MALLOC_H_

#include <sys/types.h>

#include <stdlib.h>

struct malloc_type {
	const char *ks_shortdesc;
};

#define	MALLOC_DEFINE(type, shortdesc, longdesc)			\
	struct malloc_type type[1] = {{ shortdesc }}
#define	MALLOC_DECLARE(type)						\
	extern struct malloc_type type[1]

#define	M_NOWAIT	0x0001
#define	M_WAITOK	0x0002
#define	M_ZERO		0x0100

static inline void *
kmock_malloc(size_t size, struct malloc_type *type __unused,
    int flags __unused)
{

	/* M_ZERO unconditionally; the DUTs all pass it or memset anyway. */
	return (calloc(1, size));
}

static inline void
kmock_free(void *addr, struct malloc_type *type __unused)
{

	free(addr);
}

#define	malloc(size, type, flags)	kmock_malloc((size), (type), (flags))
#define	free(addr, type)		kmock_free((addr), (type))

#endif /* !_KMOCK_SYS_MALLOC_H_ */
