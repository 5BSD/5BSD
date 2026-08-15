/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_DIRTY_LOG_COLLECTOR_H_
#define _DEV_VMM_VMM_DIRTY_LOG_COLLECTOR_H_

#include <dev/vmm/vmm_dirty_log_owner.h>

/*
 * A backend returns only a logical GPA range and its observed dirty state.
 * The range may describe a 4 KiB, 2 MiB, 1 GiB, or other hardware leaf, but
 * its page-table representation and host page size stay private to the
 * backend.
 */
struct vmm_dirty_log_leaf {
	struct vmm_dirty_log_range range;
	bool		dirty;
};

struct vmm_dirty_log_collector {
	/* Return the leaf containing gpa without changing backend dirty state. */
	int	(*query)(void *, uint64_t, struct vmm_dirty_log_leaf *);
	/* Clear and return the same leaf; the caller has frozen all guest CPUs. */
	int	(*clear)(void *, uint64_t, struct vmm_dirty_log_leaf *);
};

/*
 * Observe every leaf covering ticket->range into staging, then copy it to
 * bitmap only after the complete operation succeeds.  Both buffers must be
 * distinct, exactly the ticket bitmap size, and caller-owned.  The caller
 * holds the frozen map/vCPU boundary and passes the current owner so a stale
 * ticket is rejected before any backend callback and again before bitmap
 * publication.  Clearing is intentionally separate and occurs only after
 * this bitmap has been published.
 */
int	vmm_dirty_log_collect(const struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_ticket *, const struct vmm_dirty_log_collector *,
	    void *, uint8_t *staging, size_t, uint8_t *bitmap, size_t);

/*
 * Validate the complete leaf walk first, then clear the captured hardware
 * generation.  The caller keeps every vCPU frozen and the map exclusively
 * locked across collect, userspace publication, clear, and owner finish.
 */
int	vmm_dirty_log_clear(const struct vmm_dirty_log_owner *,
	    const struct vmm_dirty_log_ticket *,
	    const struct vmm_dirty_log_collector *, void *);

#endif /* _DEV_VMM_VMM_DIRTY_LOG_COLLECTOR_H_ */
