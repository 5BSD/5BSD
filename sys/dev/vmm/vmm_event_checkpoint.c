/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/limits.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include <dev/vmm/vmm_event_checkpoint.h>
#include <dev/vmm/vmm_address_range.h>

static bool
vmm_event_checkpoint_range_valid(const void *base, size_t length)
{
	return (vmm_address_range_valid(base, length));
}

static bool
vmm_event_checkpoint_range(const void *base, size_t count, size_t item_size,
    size_t *lengthp)
{
	size_t length;

	if (count > SIZE_MAX / item_size)
		return (false);
	length = count * item_size;
	*lengthp = length;
	return (vmm_event_checkpoint_range_valid(base, length));
}

static bool
vmm_event_checkpoint_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_event_checkpoint_empty(const struct vmm_event_checkpoint *checkpoint)
{

	return (checkpoint->owner_id == 0 && checkpoint->entries == NULL &&
	    checkpoint->storage_cookie == 0 && checkpoint->entries_cookie == 0 &&
	    checkpoint->count == 0 && checkpoint->active == 0 &&
	    checkpoint->reserved == 0);
}

static int
vmm_event_checkpoint_entries_validate(
    const struct vmm_event_checkpoint_entry *entries, size_t count,
    bool active)
{
	const struct vmm_event_checkpoint_entry *entry;
	size_t entries_length, i, j;

	if (count == 0 || !vmm_event_checkpoint_range(entries, count,
	    sizeof(*entries), &entries_length))
		return (EINVAL);
	for (i = 0; i < count; i++) {
		entry = &entries[i];
		if (entry->state == NULL ||
		    vmm_event_checkpoint_overlap(entries, entries_length,
		    entry->state, sizeof(*entry->state)) ||
		    vmm_event_ingress_validate(entry->state) != 0)
			return (EINVAL);
		for (j = 0; j < i; j++) {
			if (entries[j].state == entry->state ||
			    vmm_event_checkpoint_overlap(entries[j].state,
			    sizeof(*entries[j].state), entry->state,
			    sizeof(*entry->state)))
				return (EINVAL);
		}
		if (active) {
			if (entry->lease.active != 1 ||
			    entry->lease.reserved != 0 ||
			    entry->lease.state_cookie !=
			    (uintptr_t)entry->state ||
			    entry->lease.storage_cookie !=
			    (uintptr_t)&entry->lease ||
			    entry->lease.owner_id != entry->state->owner_id ||
			    entry->lease.lease_id !=
			    entry->state->current_lease_id)
				return (ESTALE);
		} else if (entry->lease.owner_id != 0 ||
		    entry->lease.lease_id != 0 || entry->lease.state_cookie != 0 ||
		    entry->lease.storage_cookie != 0 || entry->lease.active != 0 ||
		    entry->lease.reserved != 0 || entry->deferred_mask != 0) {
			return (EBUSY);
		}
	}
	return (0);
}

static int
vmm_event_checkpoint_validate(const struct vmm_event_checkpoint *checkpoint)
{
	size_t entries_length, i;

	if (checkpoint == NULL || checkpoint->owner_id == 0 ||
	    checkpoint->entries == NULL || checkpoint->count == 0 ||
	    checkpoint->storage_cookie != (uintptr_t)checkpoint ||
	    checkpoint->entries_cookie != (uintptr_t)checkpoint->entries ||
	    checkpoint->active != 1 || checkpoint->reserved != 0 ||
	    !vmm_event_checkpoint_range(checkpoint->entries, checkpoint->count,
	    sizeof(checkpoint->entries[0]), &entries_length) ||
	    vmm_event_checkpoint_overlap(checkpoint, sizeof(*checkpoint),
	    checkpoint->entries, entries_length))
		return (EINVAL);
	for (i = 0; i < checkpoint->count; i++) {
		if (vmm_event_checkpoint_overlap(checkpoint,
		    sizeof(*checkpoint), checkpoint->entries[i].state,
		    sizeof(*checkpoint->entries[i].state)))
			return (EINVAL);
	}
	return (vmm_event_checkpoint_entries_validate(checkpoint->entries,
	    checkpoint->count, true));
}

int
vmm_event_checkpoint_begin(struct vmm_event_checkpoint *checkpoint,
    struct vmm_event_checkpoint_entry *entries, size_t count,
    uint64_t owner_id)
{
	struct vmm_event_checkpoint candidate;
	size_t entries_length, i;
	int error;

	if (checkpoint == NULL || owner_id == 0 ||
	    !vmm_event_checkpoint_range(entries, count, sizeof(*entries),
	    &entries_length) || count == 0 ||
	    vmm_event_checkpoint_overlap(checkpoint, sizeof(*checkpoint), entries,
	    entries_length) || !vmm_event_checkpoint_empty(checkpoint))
		return (EINVAL);
	error = vmm_event_checkpoint_entries_validate(entries, count, false);
	if (error != 0)
		return (error);
	for (i = 0; i < count; i++) {
		if (vmm_event_checkpoint_overlap(checkpoint,
		    sizeof(*checkpoint), entries[i].state,
		    sizeof(*entries[i].state)))
			return (EINVAL);
		if (entries[i].state->mode != VMM_EVENT_INGRESS_OPEN)
			return (EBUSY);
		if (entries[i].state->last_lease_id == UINT64_MAX ||
		    entries[i].state->publisher_generation == UINT64_MAX)
			return (EOVERFLOW);
	}
	candidate = (struct vmm_event_checkpoint) {
		.owner_id = owner_id,
		.entries = entries,
		.storage_cookie = (uintptr_t)checkpoint,
		.entries_cookie = (uintptr_t)entries,
		.count = count,
		.active = 1,
	};
	/* All possible failures were checked while every ingress lock was held. */
	for (i = 0; i < count; i++) {
		error = vmm_event_ingress_quiesce_begin(entries[i].state,
		    &entries[i].lease);
		if (error != 0) {
#ifdef _KERNEL
			panic("%s: prevalidated begin failed at %zu: %d", __func__, i,
			    error);
#else
			return (error);
#endif
		}
	}
	*checkpoint = candidate;
	return (0);
}

int
vmm_event_checkpoint_ready(const struct vmm_event_checkpoint *checkpoint,
    bool *readyp)
{
	bool ready;
	size_t entries_length, i;
	int error;

	if (readyp == NULL)
		return (EINVAL);
	error = vmm_event_checkpoint_validate(checkpoint);
	if (error != 0)
		return (error);
	(void)vmm_event_checkpoint_range(checkpoint->entries, checkpoint->count,
	    sizeof(checkpoint->entries[0]), &entries_length);
	if (vmm_event_checkpoint_overlap(checkpoint, sizeof(*checkpoint), readyp,
	    sizeof(*readyp)) || vmm_event_checkpoint_overlap(checkpoint->entries,
	    entries_length, readyp, sizeof(*readyp)))
		return (EINVAL);
	for (i = 0; i < checkpoint->count; i++) {
		if (vmm_event_checkpoint_overlap(checkpoint->entries[i].state,
		    sizeof(*checkpoint->entries[i].state), readyp,
		    sizeof(*readyp)))
			return (EINVAL);
	}
	ready = true;
	for (i = 0; i < checkpoint->count; i++) {
		if (checkpoint->entries[i].state->mode ==
		    VMM_EVENT_INGRESS_DRAINING)
			ready = false;
		else if (checkpoint->entries[i].state->mode !=
		    VMM_EVENT_INGRESS_QUIESCED)
			return (EINVAL);
	}
	*readyp = ready;
	return (0);
}

static int
vmm_event_checkpoint_reopen(struct vmm_event_checkpoint *checkpoint,
    bool aborting)
{
	struct vmm_event_checkpoint_entry *entry;
	size_t i;
	int error;

	error = vmm_event_checkpoint_validate(checkpoint);
	if (error != 0)
		return (error);
	for (i = 0; i < checkpoint->count; i++) {
		entry = &checkpoint->entries[i];
		if (!aborting && entry->state->mode !=
		    VMM_EVENT_INGRESS_QUIESCED)
			return (EBUSY);
		if (entry->state->active_publishers == 0 &&
		    entry->state->publisher_generation == UINT64_MAX)
			return (EOVERFLOW);
	}
	/*
	 * With every ingress lock still held, validate() plus the loop above
	 * preflight every error returned by the single-state reopen operation.
	 * The commit loop therefore cannot partially reopen a valid group.
	 */
	for (i = 0; i < checkpoint->count; i++) {
		entry = &checkpoint->entries[i];
		if (aborting)
			error = vmm_event_ingress_quiesce_abort(entry->state,
			    &entry->lease, &entry->deferred_mask);
		else
			error = vmm_event_ingress_quiesce_finish(entry->state,
			    &entry->lease, &entry->deferred_mask);
		if (error != 0) {
#ifdef _KERNEL
			panic("%s: prevalidated reopen failed at %zu: %d", __func__, i,
			    error);
#else
			return (error);
#endif
		}
	}
	memset(checkpoint, 0, sizeof(*checkpoint));
	return (0);
}

int
vmm_event_checkpoint_finish(struct vmm_event_checkpoint *checkpoint)
{

	return (vmm_event_checkpoint_reopen(checkpoint, false));
}

int
vmm_event_checkpoint_abort(struct vmm_event_checkpoint *checkpoint)
{

	return (vmm_event_checkpoint_reopen(checkpoint, true));
}
