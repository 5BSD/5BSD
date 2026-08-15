/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_collector.h>

static int
vmm_dirty_log_collector_last(const struct vmm_dirty_log_range *range,
    uint64_t *last)
{

	if (last == NULL || vmm_dirty_log_range_validate(range, NULL) != 0)
		return (EINVAL);
	*last = range->gpa + range->length - 1;
	return (0);
}

int
vmm_dirty_log_collect(const struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket,
    const struct vmm_dirty_log_collector *collector, void *arg,
    uint8_t *staging, size_t staging_bytes, uint8_t *bitmap,
    size_t bitmap_bytes)
{
	struct vmm_dirty_log_leaf leaf;
	uint64_t current, leaf_last, ticket_last;
	size_t required;
	int error;

	if (owner == NULL || ticket == NULL || collector == NULL ||
	    collector->query == NULL || staging == NULL || bitmap == NULL)
		return (EINVAL);
	if ((error = vmm_dirty_log_owner_ticket_check(owner, ticket)) != 0)
		return (error);
	if (vmm_dirty_log_range_validate(&ticket->range, &required) != 0 ||
	    staging_bytes != required || bitmap_bytes != required ||
	    vmm_address_ranges_overlap(staging, staging_bytes, bitmap,
	    bitmap_bytes))
		return (EINVAL);
	if (vmm_dirty_log_collector_last(&ticket->range, &ticket_last) != 0)
		return (EPROTO);

	memset(staging, 0, staging_bytes);
	current = ticket->range.gpa;
	for (;;) {
		memset(&leaf, 0, sizeof(leaf));
		error = collector->query(arg, current, &leaf);
		if (error != 0)
			return (error);
		if (vmm_dirty_log_collector_last(&leaf.range, &leaf_last) != 0 ||
		    leaf.range.gpa > current || leaf_last < current)
			return (EPROTO);
		if (leaf.dirty &&
		    (error = vmm_dirty_log_bitmap_mark_range(&ticket->range,
		    staging, staging_bytes, &leaf.range)) != 0)
			return (EPROTO);
		if (leaf_last >= ticket_last)
			break;
		/* leaf_last is before ticket_last, so increment cannot overflow. */
		current = leaf_last + 1;
	}
	/*
	 * The caller normally holds the frozen map/vCPU boundary throughout the
	 * backend queries.  Recheck anyway before the sole externally visible
	 * publication: a future callback path must not turn a re-entrant reset,
	 * detach, or map invalidation into a bitmap for a revoked generation.
	 */
	if ((error = vmm_dirty_log_owner_ticket_check(owner, ticket)) != 0)
		return (error);
	memcpy(bitmap, staging, bitmap_bytes);
	return (0);
}

static int
vmm_dirty_log_walk(const struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket,
    int (*callback)(void *, uint64_t, struct vmm_dirty_log_leaf *), void *arg)
{
	struct vmm_dirty_log_leaf leaf;
	uint64_t current, leaf_last, ticket_last;
	int error;

	if (owner == NULL || ticket == NULL || callback == NULL)
		return (EINVAL);
	if ((error = vmm_dirty_log_owner_ticket_check(owner, ticket)) != 0)
		return (error);
	if (vmm_dirty_log_collector_last(&ticket->range, &ticket_last) != 0)
		return (EPROTO);
	current = ticket->range.gpa;
	for (;;) {
		memset(&leaf, 0, sizeof(leaf));
		if ((error = callback(arg, current, &leaf)) != 0)
			return (error);
		if (vmm_dirty_log_collector_last(&leaf.range, &leaf_last) != 0 ||
		    leaf.range.gpa > current || leaf_last < current)
			return (EPROTO);
		if (leaf_last >= ticket_last)
			break;
		current = leaf_last + 1;
	}
	return (vmm_dirty_log_owner_ticket_check(owner, ticket));
}

int
vmm_dirty_log_clear(const struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket,
    const struct vmm_dirty_log_collector *collector, void *arg)
{
	int error;

	if (collector == NULL || collector->query == NULL ||
	    collector->clear == NULL || ticket == NULL ||
	    ticket->mode != VMM_DIRTY_LOG_COLLECT_CLEAR)
		return (EINVAL);
	/*
	 * Prove that the complete stable map is queryable before changing a
	 * single hardware dirty bit.  With the map locked and all vCPUs frozen,
	 * a later clear failure is an architecture-backend invariant violation.
	 */
	if ((error = vmm_dirty_log_walk(owner, ticket, collector->query,
	    arg)) != 0)
		return (error);
	return (vmm_dirty_log_walk(owner, ticket, collector->clear, arg));
}
