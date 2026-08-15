/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <sys/limits.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_dirty_log_map.h>
#include <dev/vmm/vmm_dirty_log_owner.h>

static bool
vmm_dirty_log_owner_phase_valid(uint32_t phase)
{

	return (phase == VMM_DIRTY_LOG_OWNER_OFF ||
	    phase == VMM_DIRTY_LOG_OWNER_TRACKING ||
	    phase == VMM_DIRTY_LOG_OWNER_COLLECTING ||
	    phase == VMM_DIRTY_LOG_OWNER_EXHAUSTED);
}

static bool
vmm_dirty_log_range_contains(const struct vmm_dirty_log_range *outer,
    const struct vmm_dirty_log_range *inner);

static void
vmm_dirty_log_owner_exhaust(struct vmm_dirty_log_owner *owner)
{

	/* A wrapped generation must never make a completed clear reusable. */
	owner->phase = VMM_DIRTY_LOG_OWNER_EXHAUSTED;
	owner->identity = UINT64_MAX;
	owner->map_generation = 0;
	owner->dirty_generation = 0;
	memset(&owner->range, 0, sizeof(owner->range));
	memset(&owner->collection_range, 0, sizeof(owner->collection_range));
	owner->collection_mode = 0;
}

static int
vmm_dirty_log_owner_state_validate(const struct vmm_dirty_log_owner *owner)
{

	if (owner == NULL || !vmm_dirty_log_owner_phase_valid(owner->phase))
		return (EINVAL);
	switch (owner->phase) {
	case VMM_DIRTY_LOG_OWNER_OFF:
		if (owner->range.gpa != 0 || owner->range.length != 0 ||
		    owner->collection_range.gpa != 0 ||
		    owner->collection_range.length != 0 ||
		    owner->map_generation != 0 || owner->dirty_generation != 0 ||
		    owner->collection_mode != 0)
			return (EPROTO);
		break;
	case VMM_DIRTY_LOG_OWNER_TRACKING:
		if (vmm_dirty_log_range_validate(&owner->range, NULL) != 0 ||
		    owner->collection_range.gpa != 0 ||
		    owner->collection_range.length != 0 ||
		    owner->map_generation == 0 || owner->dirty_generation == 0 ||
		    owner->identity == 0 || owner->collection_mode != 0)
			return (EPROTO);
		break;
	case VMM_DIRTY_LOG_OWNER_COLLECTING:
		if (vmm_dirty_log_range_validate(&owner->range, NULL) != 0 ||
		    vmm_dirty_log_range_validate(&owner->collection_range, NULL) != 0 ||
		    !vmm_dirty_log_range_contains(&owner->range,
		    &owner->collection_range) || owner->map_generation == 0 ||
		    owner->dirty_generation == 0 || owner->identity == 0 ||
		    (owner->collection_mode != VMM_DIRTY_LOG_COLLECT_OBSERVE &&
		    owner->collection_mode != VMM_DIRTY_LOG_COLLECT_CLEAR))
			return (EPROTO);
		break;
	case VMM_DIRTY_LOG_OWNER_EXHAUSTED:
		if (owner->identity != UINT64_MAX || owner->range.gpa != 0 ||
		    owner->range.length != 0 || owner->collection_range.gpa != 0 ||
		    owner->collection_range.length != 0 ||
		    owner->map_generation != 0 || owner->dirty_generation != 0 ||
		    owner->collection_mode != 0)
			return (EPROTO);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static bool
vmm_dirty_log_range_contains(const struct vmm_dirty_log_range *outer,
    const struct vmm_dirty_log_range *inner)
{
	uint64_t outer_offset, inner_last;

	if (vmm_dirty_log_range_validate(outer, NULL) != 0 ||
	    vmm_dirty_log_range_validate(inner, NULL) != 0 ||
	    inner->gpa < outer->gpa)
		return (false);
	outer_offset = inner->gpa - outer->gpa;
	if (outer_offset >= outer->length)
		return (false);
	/* The two validated inclusive ranges make this subtraction safe. */
	inner_last = inner->length - 1;
	return (inner_last <= outer->length - outer_offset - 1);
}

static int
vmm_dirty_log_owner_advance_identity(struct vmm_dirty_log_owner *owner)
{
	uint64_t next;

	if (owner->identity == UINT64_MAX) {
		vmm_dirty_log_owner_exhaust(owner);
		return (EOVERFLOW);
	}
	if (vmm_dirty_log_generation_next(owner->identity, &next) != 0)
		return (EOVERFLOW);
	owner->identity = next;
	return (0);
}

int
vmm_dirty_log_owner_ticket_check(const struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket)
{

	int error;

	if (owner == NULL || ticket == NULL)
		return (EINVAL);
	error = vmm_dirty_log_owner_state_validate(owner);
	if (error != 0)
		return (error);
	if (owner->phase != VMM_DIRTY_LOG_OWNER_COLLECTING)
		return (ESTALE);
	/*
	 * This is the last common fence before an architecture backend reads
	 * or clears dirty state.  A matching ticket is not sufficient if a
	 * corrupted private owner describes an impossible collection: accepting
	 * it could hand a malformed range or mode to a hardware callback.
	 */
	if (ticket->mode > VMM_DIRTY_LOG_COLLECT_CLEAR ||
	    ticket->identity != owner->identity ||
	    ticket->map_generation != owner->map_generation ||
	    ticket->dirty_generation != owner->dirty_generation ||
	    ticket->mode != owner->collection_mode ||
	    ticket->range.gpa != owner->collection_range.gpa ||
	    ticket->range.length != owner->collection_range.length)
		return (ESTALE);
	return (0);
}

int
vmm_dirty_log_owner_enable(struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_map_entry *entries, size_t nentries,
    uint64_t map_generation, const struct vmm_dirty_log_range *range)
{
	struct vmm_dirty_log_owner candidate;
	int error;

	if (owner == NULL || map_generation == 0)
		return (EINVAL);
	error = vmm_dirty_log_owner_state_validate(owner);
	if (error != 0)
		return (error);
	if (owner->phase == VMM_DIRTY_LOG_OWNER_EXHAUSTED)
		return (EOVERFLOW);
	if (owner->phase != VMM_DIRTY_LOG_OWNER_OFF)
		return (EBUSY);
	if (vmm_dirty_log_range_validate(range, NULL) != 0)
		return (EINVAL);
	if ((error = vmm_dirty_log_map_covers(entries, nentries, range)) != 0)
		return (error);
	candidate = *owner;
	if ((error = vmm_dirty_log_owner_advance_identity(&candidate)) != 0) {
		*owner = candidate;
		return (error);
	}
	candidate.range = *range;
	memset(&candidate.collection_range, 0, sizeof(candidate.collection_range));
	candidate.map_generation = map_generation;
	candidate.dirty_generation = 1;
	candidate.collection_mode = 0;
	candidate.phase = VMM_DIRTY_LOG_OWNER_TRACKING;
	*owner = candidate;
	return (0);
}

int
vmm_dirty_log_owner_begin(struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_map_entry *entries, size_t nentries,
    uint64_t map_generation, const struct vmm_dirty_log_range *range,
    enum vmm_dirty_log_collect_mode mode, struct vmm_dirty_log_ticket *ticket)
{
	struct vmm_dirty_log_owner candidate;
	struct vmm_dirty_log_ticket candidate_ticket;
	int error;

	if (owner == NULL || range == NULL || ticket == NULL ||
	    !vmm_address_range_valid(ticket, sizeof(*ticket)) ||
	    vmm_address_ranges_overlap(owner, sizeof(*owner), ticket,
	    sizeof(*ticket)) ||
	    (mode != VMM_DIRTY_LOG_COLLECT_OBSERVE &&
	    mode != VMM_DIRTY_LOG_COLLECT_CLEAR))
		return (EINVAL);
	error = vmm_dirty_log_owner_state_validate(owner);
	if (error != 0)
		return (error);
	if (owner->phase != VMM_DIRTY_LOG_OWNER_TRACKING)
		return (owner->phase == VMM_DIRTY_LOG_OWNER_EXHAUSTED ? EOVERFLOW :
		    EBUSY);
	if (map_generation == 0 || map_generation != owner->map_generation)
		return (ESTALE);
	if (!vmm_dirty_log_range_contains(&owner->range, range))
		return (EINVAL);
	if ((error = vmm_dirty_log_map_covers(entries, nentries, range)) != 0)
		return (error);
	candidate = *owner;
	/* Never begin a clear which cannot be committed after publication. */
	if (mode == VMM_DIRTY_LOG_COLLECT_CLEAR &&
	    candidate.dirty_generation == UINT64_MAX) {
		vmm_dirty_log_owner_exhaust(&candidate);
		*owner = candidate;
		return (EOVERFLOW);
	}
	if ((error = vmm_dirty_log_owner_advance_identity(&candidate)) != 0) {
		*owner = candidate;
		return (error);
	}
	candidate.phase = VMM_DIRTY_LOG_OWNER_COLLECTING;
	candidate.collection_range = *range;
	candidate.collection_mode = mode;
	candidate_ticket = (struct vmm_dirty_log_ticket) {
		.range = *range,
		.map_generation = candidate.map_generation,
		.dirty_generation = candidate.dirty_generation,
		.identity = candidate.identity,
		.mode = mode,
	};
	*owner = candidate;
	*ticket = candidate_ticket;
	return (0);
}

static int
vmm_dirty_log_owner_settle(struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket, bool clear)
{
	struct vmm_dirty_log_owner candidate;
	uint64_t next;
	int error;

	if ((error = vmm_dirty_log_owner_ticket_check(owner, ticket)) != 0)
		return (error);
	if (clear && ticket->mode != VMM_DIRTY_LOG_COLLECT_CLEAR)
		return (EINVAL);
	candidate = *owner;
	if (clear && (error = vmm_dirty_log_generation_next(
	    candidate.dirty_generation, &next)) != 0) {
		/*
		 * Begin rejects the last generation before backend access, so this
		 * branch denotes private-state corruption rather than an expected
		 * post-clear failure.  Retire the owner fail closed.
		 */
		vmm_dirty_log_owner_exhaust(&candidate);
		*owner = candidate;
		return (error);
	}
	if (clear)
		candidate.dirty_generation = next;
	candidate.phase = VMM_DIRTY_LOG_OWNER_TRACKING;
	memset(&candidate.collection_range, 0, sizeof(candidate.collection_range));
	candidate.collection_mode = 0;
	*owner = candidate;
	return (0);
}

int
vmm_dirty_log_owner_finish(struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket)
{

	if (owner == NULL || ticket == NULL)
		return (EINVAL);
	if (!vmm_dirty_log_owner_phase_valid(owner->phase))
		return (EINVAL);
	return (vmm_dirty_log_owner_settle(owner, ticket,
	    ticket->mode == VMM_DIRTY_LOG_COLLECT_CLEAR));
}

int
vmm_dirty_log_owner_abort(struct vmm_dirty_log_owner *owner,
    const struct vmm_dirty_log_ticket *ticket)
{

	if (owner == NULL || ticket == NULL)
		return (EINVAL);
	if (!vmm_dirty_log_owner_phase_valid(owner->phase))
		return (EINVAL);
	return (vmm_dirty_log_owner_settle(owner, ticket, false));
}

int
vmm_dirty_log_owner_invalidate(struct vmm_dirty_log_owner *owner)
{
	struct vmm_dirty_log_owner candidate;
	int error;

	if (owner == NULL)
		return (EINVAL);
	error = vmm_dirty_log_owner_state_validate(owner);
	if (error != 0)
		return (error);
	if (owner->phase == VMM_DIRTY_LOG_OWNER_EXHAUSTED)
		return (EOVERFLOW);
	candidate = *owner;
	if ((error = vmm_dirty_log_owner_advance_identity(&candidate)) != 0) {
		*owner = candidate;
		return (error);
	}
	candidate.phase = VMM_DIRTY_LOG_OWNER_OFF;
	candidate.map_generation = 0;
	candidate.dirty_generation = 0;
	memset(&candidate.range, 0, sizeof(candidate.range));
	memset(&candidate.collection_range, 0, sizeof(candidate.collection_range));
	candidate.collection_mode = 0;
	*owner = candidate;
	return (0);
}
