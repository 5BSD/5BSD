/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_MIGRATION_DIRTY_H_
#define _BHYVE_MIGRATION_DIRTY_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	MIGRATION_DIRTY_GRANULARITY	4096ULL

struct vmctx;

enum migration_dirty_collect_mode {
	MIGRATION_DIRTY_OBSERVE,
	MIGRATION_DIRTY_CLEAR,
};

/*
 * The ticket is a process-local transaction credential, not checkpoint or
 * migration wire state.  It contains no pointer, descriptor, native bitmap,
 * or host-page-size value.
 */
struct migration_dirty_ticket {
	uint64_t identity;
	uint64_t generation;
	uint64_t gpa;
	uint64_t length;
	uint32_t mode;
	uint32_t reserved;
};

int	migration_dirty_enable(struct vmctx *, uint64_t, uint64_t);
int	migration_dirty_disable(struct vmctx *);
int	migration_dirty_bitmap_bytes(struct vmctx *, size_t *);
int	migration_dirty_range_bitmap_bytes(uint64_t, uint64_t, size_t *);
int	migration_dirty_mark(struct vmctx *, uint64_t, size_t);
void	migration_dirty_fail(struct vmctx *, int);
int	migration_dirty_begin(struct vmctx *,
	    enum migration_dirty_collect_mode, uint8_t *, size_t,
	    struct migration_dirty_ticket *);
int	migration_dirty_begin_range(struct vmctx *, uint64_t, uint64_t,
	    enum migration_dirty_collect_mode, uint8_t *, size_t,
	    struct migration_dirty_ticket *);
int	migration_dirty_finish(struct vmctx *,
	    const struct migration_dirty_ticket *);
int	migration_dirty_abort(struct vmctx *,
	    const struct migration_dirty_ticket *);

#endif /* _BHYVE_MIGRATION_DIRTY_H_ */
