/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_startup_event.h>
#include <dev/vmm/vmm_address_range.h>

static bool
vmm_startup_event_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	if (left == NULL || right == NULL || left_length == 0 ||
	    right_length == 0)
		return (false);
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_startup_event_receipt_empty(
    const struct vmm_startup_event_receipt *receipt)
{

	return (receipt->owner_id == 0 && receipt->generation == 0 &&
	    receipt->state_cookie == 0 && receipt->storage_cookie == 0 &&
	    receipt->vcpuid == 0 && receipt->kind == 0 &&
	    receipt->vector == 0 && receipt->active == 0 &&
	    receipt->reserved8 == 0 && receipt->reserved32 == 0);
}

static bool
vmm_startup_event_claim_empty(const struct vmm_startup_event_claim *claim)
{

	return (claim->owner_id == 0 && claim->claim_id == 0 &&
	    claim->state_cookie == 0 && claim->storage_cookie == 0 &&
	    claim->vcpuid == 0 && claim->kind == 0 && claim->vector == 0 &&
	    claim->active == 0 && claim->reserved8 == 0 &&
	    claim->reserved32 == 0);
}

static bool
vmm_startup_event_run_token_empty(
    const struct vmm_startup_event_run_token *token)
{

	return (token->owner_id == 0 && token->generation == 0 &&
	    token->next_claim_id == 0 && token->active_claim_id == 0 &&
	    token->vcpuid == 0 && token->pending == 0 &&
	    token->sipi_vector == 0 && token->active_kind == 0 &&
	    token->active_vector == 0 && token->reserved == 0);
}

int
vmm_startup_event_run_token_validate(
    const struct vmm_startup_event_run_token *token)
{

	if (token == NULL || token->owner_id == 0 || token->generation == 0 ||
	    token->next_claim_id == 0 || token->reserved != 0 ||
	    (token->pending & ~VMM_STARTUP_EVENT_PENDING_VALID) != 0 ||
	    ((token->pending & VMM_STARTUP_EVENT_PENDING_SIPI) == 0 &&
	    token->sipi_vector != 0) ||
	    (token->active_claim_id == 0 &&
	    (token->active_kind != VMM_STARTUP_EVENT_NONE ||
	    token->active_vector != 0)) ||
	    (token->active_claim_id != 0 &&
	    (token->active_claim_id >= token->next_claim_id ||
	    token->active_kind <= VMM_STARTUP_EVENT_NONE ||
	    token->active_kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (token->active_kind == VMM_STARTUP_EVENT_INIT &&
	    token->active_vector != 0))))
		return (EINVAL);
	return (0);
}

int
vmm_startup_event_validate(const struct vmm_startup_event_state *state)
{

	if (state == NULL || state->owner_id == 0 || state->generation == 0 ||
	    state->next_claim_id == 0 ||
	    state->storage_cookie != (uintptr_t)state || state->reserved != 0 ||
	    (state->pending & ~VMM_STARTUP_EVENT_PENDING_VALID) != 0 ||
	    ((state->pending & VMM_STARTUP_EVENT_PENDING_SIPI) == 0 &&
	    state->sipi_vector != 0) ||
	    (state->active_claim_id == 0 &&
	    (state->active_kind != VMM_STARTUP_EVENT_NONE ||
	    state->active_vector != 0)) ||
	    (state->active_claim_id != 0 &&
	    (state->active_claim_id >= state->next_claim_id ||
	    state->active_kind <= VMM_STARTUP_EVENT_NONE ||
	    state->active_kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (state->active_kind == VMM_STARTUP_EVENT_INIT &&
	    state->active_vector != 0))))
		return (EINVAL);
	return (0);
}

int
vmm_startup_event_init(struct vmm_startup_event_state *state,
    uint64_t owner_id, uint32_t vcpuid)
{

	if (state == NULL || owner_id == 0)
		return (EINVAL);
	memset(state, 0, sizeof(*state));
	state->owner_id = owner_id;
	state->generation = 1;
	state->next_claim_id = 1;
	state->storage_cookie = (uintptr_t)state;
	state->vcpuid = vcpuid;
	return (0);
}

static int
vmm_startup_event_advance(struct vmm_startup_event_state *state)
{
	int error;

	error = vmm_startup_event_validate(state);
	if (error != 0)
		return (error);
	if (state->generation == UINT64_MAX)
		return (EOVERFLOW);
	state->generation++;
	return (0);
}

int
vmm_startup_event_publish_init(struct vmm_startup_event_state *state)
{
	int error;

	error = vmm_startup_event_advance(state);
	if (error != 0)
		return (error);
	/* INIT supersedes every SIPI published before this generation. */
	state->pending = VMM_STARTUP_EVENT_PENDING_INIT;
	state->sipi_vector = 0;
	return (0);
}

int
vmm_startup_event_publish_sipi(struct vmm_startup_event_state *state,
    uint8_t vector)
{
	int error;

	error = vmm_startup_event_advance(state);
	if (error != 0)
		return (error);
	state->pending |= VMM_STARTUP_EVENT_PENDING_SIPI;
	state->sipi_vector = vector;
	return (0);
}

int
vmm_startup_event_peek(struct vmm_startup_event_state *state,
    struct vmm_startup_event_receipt *receipt)
{
	struct vmm_startup_event_receipt candidate;
	int error;

	if (state == NULL || receipt == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), receipt,
	    sizeof(*receipt)))
		return (EINVAL);
	error = vmm_startup_event_validate(state);
	if (error != 0 || !vmm_startup_event_receipt_empty(receipt))
		return (error != 0 ? error : EBUSY);
	if (state->active_claim_id != 0)
		return (EBUSY);
	if (state->pending == 0)
		return (ENOENT);
	memset(&candidate, 0, sizeof(candidate));
	candidate.owner_id = state->owner_id;
	candidate.generation = state->generation;
	candidate.state_cookie = (uintptr_t)state;
	candidate.storage_cookie = (uintptr_t)receipt;
	candidate.vcpuid = state->vcpuid;
	candidate.active = 1;
	if ((state->pending & VMM_STARTUP_EVENT_PENDING_INIT) != 0) {
		candidate.kind = VMM_STARTUP_EVENT_INIT;
	} else {
		candidate.kind = VMM_STARTUP_EVENT_SIPI;
		candidate.vector = state->sipi_vector;
	}
	*receipt = candidate;
	return (0);
}

int
vmm_startup_event_consume(struct vmm_startup_event_state *state,
    struct vmm_startup_event_receipt *receipt)
{
	enum vmm_startup_event_kind selected;
	uint8_t vector;
	int error;

	if (state == NULL || receipt == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), receipt,
	    sizeof(*receipt)))
		return (EINVAL);
	error = vmm_startup_event_validate(state);
	if (error != 0)
		return (error);
	if (state->active_claim_id != 0)
		return (EBUSY);
	if (receipt->active != 1 || receipt->reserved8 != 0 ||
	    receipt->reserved32 != 0 ||
	    receipt->kind <= VMM_STARTUP_EVENT_NONE ||
	    receipt->kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    receipt->owner_id != state->owner_id ||
	    receipt->generation != state->generation ||
	    receipt->state_cookie != (uintptr_t)state ||
	    receipt->storage_cookie != (uintptr_t)receipt ||
	    receipt->vcpuid != state->vcpuid)
		return (ESTALE);
	if ((state->pending & VMM_STARTUP_EVENT_PENDING_INIT) != 0) {
		selected = VMM_STARTUP_EVENT_INIT;
		vector = 0;
	} else if ((state->pending & VMM_STARTUP_EVENT_PENDING_SIPI) != 0) {
		selected = VMM_STARTUP_EVENT_SIPI;
		vector = state->sipi_vector;
	} else {
		return (ESTALE);
	}
	if (receipt->kind != selected || receipt->vector != vector)
		return (ESTALE);
	if (state->generation == UINT64_MAX)
		return (EOVERFLOW);
	state->generation++;
	if (selected == VMM_STARTUP_EVENT_INIT) {
		state->pending &= ~VMM_STARTUP_EVENT_PENDING_INIT;
	} else {
		state->pending &= ~VMM_STARTUP_EVENT_PENDING_SIPI;
		state->sipi_vector = 0;
	}
	memset(receipt, 0, sizeof(*receipt));
	return (0);
}

static int
vmm_startup_event_claim_validate(
    const struct vmm_startup_event_state *state,
    const struct vmm_startup_event_claim *claim)
{

	if (claim->active != 1 || claim->reserved8 != 0 ||
	    claim->reserved32 != 0 ||
	    claim->kind <= VMM_STARTUP_EVENT_NONE ||
	    claim->kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    claim->owner_id != state->owner_id ||
	    claim->claim_id != state->active_claim_id ||
	    claim->state_cookie != (uintptr_t)state ||
	    claim->storage_cookie != (uintptr_t)claim ||
	    claim->vcpuid != state->vcpuid ||
	    claim->kind != state->active_kind ||
	    claim->vector != state->active_vector)
		return (ESTALE);
	return (0);
}

int
vmm_startup_event_claim_check(const struct vmm_startup_event_state *state,
    const struct vmm_startup_event_claim *claim)
{
	int error;

	if (state == NULL || claim == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), claim,
	    sizeof(*claim)))
		return (EINVAL);
	error = vmm_startup_event_validate(state);
	if (error != 0)
		return (error);
	return (vmm_startup_event_claim_validate(state, claim));
}

int
vmm_startup_event_claim_begin(struct vmm_startup_event_state *state,
    struct vmm_startup_event_claim *claim)
{
	struct vmm_startup_event_claim candidate;
	enum vmm_startup_event_kind selected;
	uint8_t vector;
	int error;

	if (state == NULL || claim == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), claim,
	    sizeof(*claim)))
		return (EINVAL);
	error = vmm_startup_event_validate(state);
	if (error != 0 || !vmm_startup_event_claim_empty(claim))
		return (error != 0 ? error : EBUSY);
	if (state->active_claim_id != 0)
		return (EBUSY);
	if ((state->pending & VMM_STARTUP_EVENT_PENDING_INIT) != 0) {
		selected = VMM_STARTUP_EVENT_INIT;
		vector = 0;
	} else if ((state->pending & VMM_STARTUP_EVENT_PENDING_SIPI) != 0) {
		selected = VMM_STARTUP_EVENT_SIPI;
		vector = state->sipi_vector;
	} else {
		return (ENOENT);
	}
	if (state->generation == UINT64_MAX ||
	    state->next_claim_id == UINT64_MAX)
		return (EOVERFLOW);
	memset(&candidate, 0, sizeof(candidate));
	candidate.owner_id = state->owner_id;
	candidate.claim_id = state->next_claim_id;
	candidate.state_cookie = (uintptr_t)state;
	candidate.storage_cookie = (uintptr_t)claim;
	candidate.vcpuid = state->vcpuid;
	candidate.kind = selected;
	candidate.vector = vector;
	candidate.active = 1;

	state->generation++;
	state->next_claim_id++;
	state->active_claim_id = candidate.claim_id;
	state->active_kind = selected;
	state->active_vector = vector;
	if (selected == VMM_STARTUP_EVENT_INIT) {
		state->pending &= ~VMM_STARTUP_EVENT_PENDING_INIT;
	} else {
		state->pending &= ~VMM_STARTUP_EVENT_PENDING_SIPI;
		state->sipi_vector = 0;
	}
	*claim = candidate;
	return (0);
}

int
vmm_startup_event_run_token_capture(
    const struct vmm_startup_event_state *state,
    struct vmm_startup_event_run_token *token)
{
	struct vmm_startup_event_run_token candidate;

	if (state == NULL || token == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), token,
	    sizeof(*token)) || vmm_startup_event_validate(state) != 0 ||
	    !vmm_startup_event_run_token_empty(token))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.owner_id = state->owner_id;
	candidate.generation = state->generation;
	candidate.next_claim_id = state->next_claim_id;
	candidate.active_claim_id = state->active_claim_id;
	candidate.vcpuid = state->vcpuid;
	candidate.pending = state->pending;
	candidate.sipi_vector = state->sipi_vector;
	candidate.active_kind = state->active_kind;
	candidate.active_vector = state->active_vector;
	*token = candidate;
	return (0);
}

int
vmm_startup_event_run_token_check(
    const struct vmm_startup_event_state *state,
    const struct vmm_startup_event_run_token *token)
{

	if (state == NULL || token == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), token,
	    sizeof(*token)) || vmm_startup_event_validate(state) != 0 ||
	    vmm_startup_event_run_token_validate(token) != 0)
		return (EINVAL);
	if (token->owner_id != state->owner_id ||
	    token->vcpuid != state->vcpuid)
		return (ESTALE);
	if (token->generation != state->generation ||
	    token->next_claim_id != state->next_claim_id ||
	    token->active_claim_id != state->active_claim_id ||
	    token->pending != state->pending ||
	    token->sipi_vector != state->sipi_vector ||
	    token->active_kind != state->active_kind ||
	    token->active_vector != state->active_vector)
		return (EAGAIN);
	return (0);
}

int
vmm_startup_event_publish_claim(struct vmm_startup_event_state *state,
    enum vmm_startup_event_kind kind, uint8_t vector,
    struct vmm_startup_event_claim *claim)
{
	struct vmm_startup_event_claim candidate_claim;
	struct vmm_startup_event_state candidate_state;
	int error;

	if (state == NULL || claim == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), claim,
	    sizeof(*claim)) || kind <= VMM_STARTUP_EVENT_NONE ||
	    kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (kind == VMM_STARTUP_EVENT_INIT && vector != 0) ||
	    vmm_startup_event_validate(state) != 0 ||
	    !vmm_startup_event_claim_empty(claim))
		return (EINVAL);

	/*
	 * Build the complete result against private storage.  Rebinding the
	 * cookies only after both value operations succeed makes publication
	 * and exact claim acquisition one failure-atomic caller operation.
	 */
	candidate_state = *state;
	candidate_state.storage_cookie = (uintptr_t)&candidate_state;
	memset(&candidate_claim, 0, sizeof(candidate_claim));
	if (kind == VMM_STARTUP_EVENT_INIT)
		error = vmm_startup_event_publish_init(&candidate_state);
	else
		error = vmm_startup_event_publish_sipi(&candidate_state, vector);
	if (error == 0)
		error = vmm_startup_event_claim_begin(&candidate_state,
		    &candidate_claim);
	if (error != 0)
		return (error);

	candidate_state.storage_cookie = (uintptr_t)state;
	candidate_claim.state_cookie = (uintptr_t)state;
	candidate_claim.storage_cookie = (uintptr_t)claim;
	*state = candidate_state;
	*claim = candidate_claim;
	return (0);
}

static int
vmm_startup_event_claim_end(struct vmm_startup_event_state *state,
    struct vmm_startup_event_claim *claim, bool aborting)
{
	int error;

	if (state == NULL || claim == NULL ||
	    vmm_startup_event_overlap(state, sizeof(*state), claim,
	    sizeof(*claim)))
		return (EINVAL);
	error = vmm_startup_event_claim_check(state, claim);
	if (error != 0)
		return (error);

	if (aborting && claim->kind == VMM_STARTUP_EVENT_INIT &&
	    (state->pending & VMM_STARTUP_EVENT_PENDING_INIT) == 0) {
		state->pending |= VMM_STARTUP_EVENT_PENDING_INIT;
	} else if (aborting && claim->kind == VMM_STARTUP_EVENT_SIPI &&
	    state->pending == 0) {
		state->pending = VMM_STARTUP_EVENT_PENDING_SIPI;
		state->sipi_vector = claim->vector;
	}
	state->active_claim_id = 0;
	state->active_kind = VMM_STARTUP_EVENT_NONE;
	state->active_vector = 0;
	memset(claim, 0, sizeof(*claim));
	return (0);
}

int
vmm_startup_event_claim_finish(struct vmm_startup_event_state *state,
    struct vmm_startup_event_claim *claim)
{

	return (vmm_startup_event_claim_end(state, claim, false));
}

int
vmm_startup_event_claim_abort(struct vmm_startup_event_state *state,
    struct vmm_startup_event_claim *claim)
{

	return (vmm_startup_event_claim_end(state, claim, true));
}

int
vmm_startup_event_reset(struct vmm_startup_event_state *state)
{
	int error;

	error = vmm_startup_event_validate(state);
	if (error != 0)
		return (error);
	if (state->active_claim_id != 0)
		return (EBUSY);
	if (state->generation == UINT64_MAX)
		return (EOVERFLOW);
	state->generation++;
	state->pending = 0;
	state->sipi_vector = 0;
	return (0);
}
