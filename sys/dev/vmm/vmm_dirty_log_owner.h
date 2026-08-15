/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_DIRTY_LOG_OWNER_H_
#define _DEV_VMM_VMM_DIRTY_LOG_OWNER_H_

#include <dev/vmm/vmm_dirty_log.h>

struct vmm_dirty_log_map_entry;

/*
 * This owner only defines the common transaction ordering.  The caller owns
 * synchronization and supplies a nonzero, non-reused frozen-map generation.
 * It neither enables a hardware dirty bit nor retains map or bitmap storage.
 */
enum vmm_dirty_log_owner_phase {
	VMM_DIRTY_LOG_OWNER_OFF,
	VMM_DIRTY_LOG_OWNER_TRACKING,
	VMM_DIRTY_LOG_OWNER_COLLECTING,
	/* Generation exhaustion permanently disables this owner. */
	VMM_DIRTY_LOG_OWNER_EXHAUSTED,
};

enum vmm_dirty_log_collect_mode {
	/* Return a bitmap without changing the backend's tracked generation. */
	VMM_DIRTY_LOG_COLLECT_OBSERVE,
	/* Clear only after the caller has successfully published the bitmap. */
	VMM_DIRTY_LOG_COLLECT_CLEAR,
};

struct vmm_dirty_log_ticket {
	struct vmm_dirty_log_range range;
	uint64_t	map_generation;
	uint64_t	dirty_generation;
	uint64_t	identity;
	uint32_t	mode;
};

struct vmm_dirty_log_owner {
	struct vmm_dirty_log_range range;
	struct vmm_dirty_log_range collection_range;
	uint64_t	map_generation;
	uint64_t	dirty_generation;
	uint64_t	identity;
	uint32_t	collection_mode;
	uint32_t	phase;
};

/*
 * Enable validates a caller-owned frozen map and establishes generation 1.
 * Every enable, new collection, and invalidation consumes identity so an old
 * ticket cannot be accepted by a later transaction.  An abort first leaves
 * the owner non-collecting, and the next collection consumes identity.  At
 * UINT64_MAX the owner becomes permanently EXHAUSTED and must never be
 * reused.
 */
int	vmm_dirty_log_owner_enable(struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_map_entry *, size_t, uint64_t,
	    const struct vmm_dirty_log_range *);
int	vmm_dirty_log_owner_begin(struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_map_entry *, size_t, uint64_t,
	    const struct vmm_dirty_log_range *, enum vmm_dirty_log_collect_mode,
	    struct vmm_dirty_log_ticket *);

/*
 * Revalidate a live ticket immediately before a backend observes or clears
 * hardware dirty state.  It is read-only: ESTALE means reset, map change,
 * snapshot cancellation, or a different collection revoked the ticket, and
 * neither the common owner nor backend state may be changed.  This keeps
 * EPT/NPT-specific collectors out of the common ownership implementation.
 */
int	vmm_dirty_log_owner_ticket_check(const struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_ticket *);

/*
 * finish is called only after the bitmap was published and, for CLEAR, after
 * the architecture backend has cleared the ticket's generation.  Begin
 * rejects a CLEAR whose next generation cannot be represented, before any
 * backend state changes.  abort leaves the dirty generation intact.
 * invalidate is used by reset, map change, snapshot abort, restore, destroy,
 * and backend detach.
 */
int	vmm_dirty_log_owner_finish(struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_ticket *);
int	vmm_dirty_log_owner_abort(struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_ticket *);
int	vmm_dirty_log_owner_invalidate(struct vmm_dirty_log_owner *);

#endif /* _DEV_VMM_VMM_DIRTY_LOG_OWNER_H_ */
