/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include "vmm_event_ingress.h"
#include <dev/vmm/vmm_address_range.h>

static bool
vmm_event_ingress_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_event_ingress_ticket_empty(const struct vmm_event_ingress_ticket *ticket)
{

	return (ticket->owner_id == 0 && ticket->publisher_generation == 0 &&
	    ticket->state_cookie == 0 && ticket->storage_cookie == 0 &&
	    ticket->active == 0 &&
	    ticket->reserved == 0);
}

static bool
vmm_event_ingress_lease_empty(const struct vmm_event_ingress_lease *lease)
{

	return (lease->owner_id == 0 && lease->lease_id == 0 &&
	    lease->state_cookie == 0 && lease->storage_cookie == 0 &&
	    lease->active == 0 &&
	    lease->reserved == 0);
}

int
vmm_event_ingress_validate(const struct vmm_event_ingress *state)
{

	if (state == NULL || state->owner_id == 0 ||
	    state->publisher_generation == 0 ||
	    state->storage_cookie != (uintptr_t)state ||
	    state->mode >= VMM_EVENT_INGRESS_MODE_LAST ||
	    state->current_lease_id > state->last_lease_id)
		return (EINVAL);
	switch (state->mode) {
	case VMM_EVENT_INGRESS_OPEN:
		if (state->current_lease_id != 0 || state->deferred_mask != 0)
			return (EINVAL);
		break;
	case VMM_EVENT_INGRESS_DRAINING:
		if (state->current_lease_id == 0 ||
		    state->active_publishers == 0)
			return (EINVAL);
		break;
	case VMM_EVENT_INGRESS_QUIESCED:
		if (state->current_lease_id == 0 ||
		    state->active_publishers != 0)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmm_event_ingress_init(struct vmm_event_ingress *state, uint64_t owner_id)
{

	if (state == NULL || owner_id == 0)
		return (EINVAL);
	memset(state, 0, sizeof(*state));
	state->owner_id = owner_id;
	state->publisher_generation = 1;
	state->storage_cookie = (uintptr_t)state;
	state->mode = VMM_EVENT_INGRESS_OPEN;
	return (0);
}

int
vmm_event_ingress_publisher_enter(struct vmm_event_ingress *state,
    struct vmm_event_ingress_ticket *ticket)
{
	struct vmm_event_ingress_ticket candidate;
	int error;

	if (state == NULL || ticket == NULL ||
	    vmm_event_ingress_overlap(state, sizeof(*state), ticket,
	    sizeof(*ticket)))
		return (EINVAL);
	error = vmm_event_ingress_validate(state);
	if (error != 0 || !vmm_event_ingress_ticket_empty(ticket))
		return (error != 0 ? error : EBUSY);
	if (state->mode != VMM_EVENT_INGRESS_OPEN)
		return (EBUSY);
	if (state->active_publishers == UINT32_MAX)
		return (EOVERFLOW);
	candidate = (struct vmm_event_ingress_ticket) {
		.owner_id = state->owner_id,
		.publisher_generation = state->publisher_generation,
		.state_cookie = (uintptr_t)state,
		.storage_cookie = (uintptr_t)ticket,
		.active = 1,
	};
	state->active_publishers++;
	*ticket = candidate;
	return (0);
}

int
vmm_event_ingress_publisher_exit(struct vmm_event_ingress *state,
    struct vmm_event_ingress_ticket *ticket)
{
	int error;

	if (state == NULL || ticket == NULL ||
	    vmm_event_ingress_overlap(state, sizeof(*state), ticket,
	    sizeof(*ticket)))
		return (EINVAL);
	error = vmm_event_ingress_validate(state);
	if (error != 0)
		return (error);
	if (ticket->active != 1 || ticket->reserved != 0 ||
	    ticket->state_cookie != (uintptr_t)state ||
	    ticket->storage_cookie != (uintptr_t)ticket ||
	    ticket->owner_id != state->owner_id ||
	    ticket->publisher_generation != state->publisher_generation ||
	    state->active_publishers == 0)
		return (ESTALE);
	state->active_publishers--;
	if (state->mode == VMM_EVENT_INGRESS_DRAINING &&
	    state->active_publishers == 0)
		state->mode = VMM_EVENT_INGRESS_QUIESCED;
	memset(ticket, 0, sizeof(*ticket));
	return (0);
}

int
vmm_event_ingress_quiesce_begin(struct vmm_event_ingress *state,
    struct vmm_event_ingress_lease *lease)
{
	struct vmm_event_ingress_lease candidate;
	int error;

	if (state == NULL || lease == NULL ||
	    vmm_event_ingress_overlap(state, sizeof(*state), lease,
	    sizeof(*lease)))
		return (EINVAL);
	error = vmm_event_ingress_validate(state);
	if (error != 0 || !vmm_event_ingress_lease_empty(lease))
		return (error != 0 ? error : EBUSY);
	if (state->mode != VMM_EVENT_INGRESS_OPEN)
		return (EBUSY);
	if (state->last_lease_id == UINT64_MAX)
		return (EOVERFLOW);
	candidate = (struct vmm_event_ingress_lease) {
		.owner_id = state->owner_id,
		.lease_id = state->last_lease_id + 1,
		.state_cookie = (uintptr_t)state,
		.storage_cookie = (uintptr_t)lease,
		.active = 1,
	};
	state->last_lease_id = candidate.lease_id;
	state->current_lease_id = candidate.lease_id;
	state->mode = state->active_publishers == 0 ?
	    VMM_EVENT_INGRESS_QUIESCED : VMM_EVENT_INGRESS_DRAINING;
	*lease = candidate;
	return (0);
}

int
vmm_event_ingress_defer_idempotent(struct vmm_event_ingress *state,
    uint64_t event_bit, uint64_t valid_mask)
{
	int error;

	error = vmm_event_ingress_validate(state);
	if (error != 0)
		return (error);
	if (state->mode == VMM_EVENT_INGRESS_OPEN)
		return (EINVAL);
	if (event_bit == 0 || (event_bit & (event_bit - 1)) != 0 ||
	    (event_bit & ~valid_mask) != 0)
		return (EINVAL);
	state->deferred_mask |= event_bit;
	return (0);
}

static int
vmm_event_ingress_reopen(struct vmm_event_ingress *state,
    struct vmm_event_ingress_lease *lease, uint64_t *deferredp, bool aborting)
{
	uint64_t deferred;
	int error;

	if (state == NULL || lease == NULL || deferredp == NULL ||
	    vmm_event_ingress_overlap(state, sizeof(*state), lease,
	    sizeof(*lease)) || vmm_event_ingress_overlap(state, sizeof(*state),
	    deferredp, sizeof(*deferredp)) ||
	    vmm_event_ingress_overlap(lease, sizeof(*lease), deferredp,
	    sizeof(*deferredp)))
		return (EINVAL);
	error = vmm_event_ingress_validate(state);
	if (error != 0)
		return (error);
	if (lease->active != 1 || lease->reserved != 0 ||
	    lease->state_cookie != (uintptr_t)state ||
	    lease->storage_cookie != (uintptr_t)lease ||
	    lease->owner_id != state->owner_id ||
	    lease->lease_id != state->current_lease_id)
		return (ESTALE);
	if (!aborting && state->mode != VMM_EVENT_INGRESS_QUIESCED)
		return (EBUSY);
	if (aborting && state->mode == VMM_EVENT_INGRESS_OPEN)
		return (EINVAL);
	if (state->active_publishers == 0 &&
	    state->publisher_generation == UINT64_MAX)
		return (EOVERFLOW);

	deferred = state->deferred_mask;
	state->deferred_mask = 0;
	state->current_lease_id = 0;
	state->mode = VMM_EVENT_INGRESS_OPEN;
	if (state->active_publishers == 0)
		state->publisher_generation++;
	memset(lease, 0, sizeof(*lease));
	*deferredp = deferred;
	return (0);
}

int
vmm_event_ingress_quiesce_finish(struct vmm_event_ingress *state,
    struct vmm_event_ingress_lease *lease, uint64_t *deferredp)
{

	return (vmm_event_ingress_reopen(state, lease, deferredp, false));
}

int
vmm_event_ingress_quiesce_abort(struct vmm_event_ingress *state,
    struct vmm_event_ingress_lease *lease, uint64_t *deferredp)
{

	return (vmm_event_ingress_reopen(state, lease, deferredp, true));
}
