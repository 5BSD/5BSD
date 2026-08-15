/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_startup_controller.h>
#include <dev/vmm/vmm_address_range.h>

static bool startup_controller_reserved_empty(const uint8_t *, size_t);

static bool
startup_controller_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	if (left == NULL || right == NULL || left_length == 0 ||
	    right_length == 0)
		return (false);
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
startup_controller_ticket_empty(
    const struct vmm_startup_controller_ticket *ticket)
{

	return (ticket != NULL && ticket->owner_id == 0 &&
	    ticket->generation == 0 && ticket->controller_id == 0 &&
	    ticket->state_cookie == 0 && ticket->storage_cookie == 0 &&
	    ticket->active == 0 &&
	    startup_controller_reserved_empty(ticket->reserved8,
	    sizeof(ticket->reserved8)));
}

static bool
startup_controller_ticket_valid(
    const struct vmm_startup_controller_ticket *ticket)
{

	return (ticket->owner_id != 0 && ticket->generation != 0 &&
	    ticket->controller_id != 0 && ticket->state_cookie != 0 &&
	    ticket->storage_cookie == (uintptr_t)ticket &&
	    ticket->active == 1 &&
	    startup_controller_reserved_empty(ticket->reserved8,
	    sizeof(ticket->reserved8)));
}

static bool
startup_controller_reserved_empty(const uint8_t *reserved, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (reserved[i] != 0)
			return (false);
	}
	return (true);
}

int
vmm_startup_controller_validate(
    const struct vmm_startup_controller_state *state)
{

	if (state == NULL || state->owner_id == 0 || state->generation == 0 ||
	    state->storage_cookie != (uintptr_t)state ||
	    state->phase >= VMM_STARTUP_CONTROLLER_PHASE_LAST ||
	    !startup_controller_reserved_empty(state->reserved8,
	    sizeof(state->reserved8)))
		return (EINVAL);
	if ((state->phase == VMM_STARTUP_CONTROLLER_CLAIMED) !=
	    (state->controller_id != 0))
		return (EINVAL);
	return (0);
}

int
vmm_startup_controller_init(struct vmm_startup_controller_state *state,
    uint64_t owner_id)
{
	struct vmm_startup_controller_state candidate;

	if (state == NULL || owner_id == 0)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.owner_id = owner_id;
	candidate.generation = 1;
	candidate.storage_cookie = (uintptr_t)state;
	*state = candidate;
	return (0);
}

int
vmm_startup_controller_claim(struct vmm_startup_controller_state *state,
    struct vmm_startup_controller_ticket *ticket, uint64_t controller_id)
{
	struct vmm_startup_controller_state state_candidate;
	struct vmm_startup_controller_ticket ticket_candidate;
	int error;

	if (state == NULL || ticket == NULL || controller_id == 0 ||
	    startup_controller_overlap(state, sizeof(*state), ticket,
	    sizeof(*ticket)))
		return (EINVAL);
	error = vmm_startup_controller_validate(state);
	if (error != 0)
		return (error);
	if (!startup_controller_ticket_empty(ticket))
		return (EBUSY);
	if (state->phase != VMM_STARTUP_CONTROLLER_UNCLAIMED)
		return (state->phase == VMM_STARTUP_CONTROLLER_REVOKED ?
		    ECANCELED : EBUSY);
	/* A claim must always retain a failure-atomic abort generation. */
	if (state->generation == UINT64_MAX)
		return (EOVERFLOW);
	state_candidate = *state;
	state_candidate.controller_id = controller_id;
	state_candidate.phase = VMM_STARTUP_CONTROLLER_CLAIMED;
	memset(&ticket_candidate, 0, sizeof(ticket_candidate));
	ticket_candidate.owner_id = state->owner_id;
	ticket_candidate.generation = state->generation;
	ticket_candidate.controller_id = controller_id;
	ticket_candidate.state_cookie = (uintptr_t)state;
	ticket_candidate.storage_cookie = (uintptr_t)ticket;
	ticket_candidate.active = 1;
	*state = state_candidate;
	*ticket = ticket_candidate;
	return (0);
}

int
vmm_startup_controller_check(
    const struct vmm_startup_controller_state *state,
    const struct vmm_startup_controller_ticket *ticket)
{
	int error;

	if (state == NULL || ticket == NULL ||
	    startup_controller_overlap(state, sizeof(*state), ticket,
	    sizeof(*ticket)))
		return (EINVAL);
	error = vmm_startup_controller_validate(state);
	if (error != 0)
		return (error);
	if (state->phase == VMM_STARTUP_CONTROLLER_REVOKED)
		return (ECANCELED);
	/* Authenticate the credential before reporting mutable owner state. */
	if (!startup_controller_ticket_valid(ticket) ||
	    ticket->owner_id != state->owner_id ||
	    ticket->generation != state->generation ||
	    ticket->controller_id != state->controller_id ||
	    ticket->state_cookie != (uintptr_t)state)
		return (ESTALE);
	if (state->phase != VMM_STARTUP_CONTROLLER_CLAIMED)
		return (EBUSY);
	return (0);
}

int
vmm_startup_controller_abort(struct vmm_startup_controller_state *state,
    struct vmm_startup_controller_ticket *ticket)
{
	struct vmm_startup_controller_state candidate;
	int error;

	error = vmm_startup_controller_check(state, ticket);
	if (error != 0)
		return (error);
	if (state->generation == UINT64_MAX)
		return (EOVERFLOW);
	candidate = *state;
	candidate.generation++;
	candidate.controller_id = 0;
	candidate.phase = VMM_STARTUP_CONTROLLER_UNCLAIMED;
	*state = candidate;
	memset(ticket, 0, sizeof(*ticket));
	return (0);
}

int
vmm_startup_controller_retire(struct vmm_startup_controller_state *state)
{
	struct vmm_startup_controller_state candidate;
	int error;

	error = vmm_startup_controller_validate(state);
	if (error != 0)
		return (error);
	if (state->phase == VMM_STARTUP_CONTROLLER_REVOKED)
		return (0);
	candidate = *state;
	if (candidate.generation != UINT64_MAX)
		candidate.generation++;
	candidate.controller_id = 0;
	candidate.phase = VMM_STARTUP_CONTROLLER_REVOKED;
	*state = candidate;
	return (0);
}

int
vmm_startup_controller_ticket_forget(
    struct vmm_startup_controller_ticket *ticket)
{

	if (ticket == NULL || !startup_controller_ticket_valid(ticket))
		return (ESTALE);
	memset(ticket, 0, sizeof(*ticket));
	return (0);
}
