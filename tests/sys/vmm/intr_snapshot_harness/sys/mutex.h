/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of the kernel <sys/mutex.h>.  Single-threaded
 * tests only need recursion-depth bookkeeping so mtx_owned() assertions in
 * the device code stay meaningful.
 */
#ifndef _KMOCK_SYS_MUTEX_H_
#define	_KMOCK_SYS_MUTEX_H_

#include <sys/types.h>

struct mtx {
	int	kmock_depth;
};

#define	MTX_DEF		0x00000000
#define	MTX_SPIN	0x00000001

static inline void
mtx_init(struct mtx *m, const char *name __unused, const char *type __unused,
    int opts __unused)
{
	m->kmock_depth = 0;
}

static inline void
mtx_destroy(struct mtx *m)
{
	m->kmock_depth = 0;
}

static inline void
mtx_lock_spin(struct mtx *m)
{
	m->kmock_depth++;
}

static inline void
mtx_unlock_spin(struct mtx *m)
{
	m->kmock_depth--;
}

static inline void
mtx_lock(struct mtx *m)
{
	m->kmock_depth++;
}

static inline void
mtx_unlock(struct mtx *m)
{
	m->kmock_depth--;
}

static inline int
mtx_owned(struct mtx *m)
{
	return (m->kmock_depth != 0);
}

#endif /* !_KMOCK_SYS_MUTEX_H_ */
