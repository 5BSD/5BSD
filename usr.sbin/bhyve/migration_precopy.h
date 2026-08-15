/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_MIGRATION_PRECOPY_H_
#define _BHYVE_MIGRATION_PRECOPY_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include "migration_dirty.h"

struct vmctx;

struct migration_precopy_cpu_generation {
	uint64_t identity;
	uint64_t map_generation;
	uint64_t dirty_generation;
};

struct migration_precopy_generation {
	uint64_t gpa;
	uint64_t length;
	uint64_t cpu_identity;
	uint64_t cpu_map_generation;
	uint64_t cpu_dirty_generation;
	uint64_t device_identity;
	uint64_t device_dirty_generation;
	uint32_t cpu_mode;
	uint32_t device_mode;
};

/* Injectable CPU boundary used by the deterministic transaction tests. */
struct migration_precopy_cpu_ops {
	int (*enable)(void *, uint64_t, uint64_t);
	int (*collect)(void *, uint64_t, uint64_t,
	    enum migration_dirty_collect_mode, uint8_t *, size_t,
	    struct migration_precopy_cpu_generation *);
	int (*disable)(void *);
};

/*
 * Advisory free-page set: an OPTIMIZATION layered on top of dirty tracking.
 *
 * A balloon FREE_PAGE_HINT round reports guest-physical ranges the guest
 * considers free.  Those pages carry no content the destination needs, so the
 * INITIAL pre-copy walk may skip them.  The set is purely advisory: it never
 * overrides dirty tracking, is consulted only for the first (initial) memory
 * generation, and defaults to "skip nothing" whenever anything is uncertain
 * (no balloon, declined feature, timed-out/failed round, unmappable range).
 *
 * One bit per MIGRATION_DIRTY_GRANULARITY page over [gpa, gpa+length).  A bit
 * is set only for pages fully covered by a reported-free range; a set becomes
 * usable only after an explicit commit, so a partially collected or failed
 * round leaves it invalid and every page is copied.
 */
struct migration_precopy_free_set {
	uint64_t gpa;
	uint64_t length;
	uint8_t *bitmap;
	size_t bitmap_bytes;
	bool valid;
};

int	migration_precopy_free_set_init(struct migration_precopy_free_set *,
	    uint64_t, uint64_t);
void	migration_precopy_free_set_reset(struct migration_precopy_free_set *);
int	migration_precopy_free_set_mark(struct migration_precopy_free_set *,
	    uint64_t, uint64_t);
void	migration_precopy_free_set_commit(struct migration_precopy_free_set *);
bool	migration_precopy_free_set_contains(
	    const struct migration_precopy_free_set *, uint64_t);
/*
 * Predicate used by the initial memory walk: returns true only when the page
 * at gpa may be skipped on the INITIAL generation because the guest reported
 * it free.  `initial_generation` gates the whole optimization off for every
 * dirty-driven round after the first.
 */
bool	migration_precopy_free_set_skip(
	    const struct migration_precopy_free_set *, bool initial_generation,
	    uint64_t gpa);

int	migration_precopy_enable(struct vmctx *, uint64_t, uint64_t);
int	migration_precopy_disable(struct vmctx *);
int	migration_precopy_collect(struct vmctx *, uint64_t, uint64_t,
	    enum migration_dirty_collect_mode, uint8_t *, size_t,
	    struct migration_precopy_generation *);

int	migration_precopy_enable_with_ops(struct vmctx *, uint64_t, uint64_t,
	    const struct migration_precopy_cpu_ops *, void *);
int	migration_precopy_disable_with_ops(struct vmctx *,
	    const struct migration_precopy_cpu_ops *, void *);
int	migration_precopy_collect_with_ops(struct vmctx *, uint64_t, uint64_t,
	    enum migration_dirty_collect_mode, uint8_t *, size_t,
	    struct migration_precopy_generation *,
	    const struct migration_precopy_cpu_ops *, void *);

#endif /* _BHYVE_MIGRATION_PRECOPY_H_ */
