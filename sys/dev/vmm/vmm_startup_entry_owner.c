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

#include <dev/vmm/vmm_startup_entry_owner.h>
#include <dev/vmm/vmm_address_range.h>

static bool
vmm_startup_entry_owner_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_startup_entry_owner_empty(const struct vmm_startup_entry_owner *owner)
{
	const struct vmm_startup_event_run_token *token;
	const struct vmm_startup_entry_handoff *handoff;

	if (owner == NULL)
		return (false);
	token = &owner->coordinator;
	handoff = &owner->notification;
	return (token->owner_id == 0 && token->generation == 0 &&
	    token->next_claim_id == 0 && token->active_claim_id == 0 &&
	    token->vcpuid == 0 && token->pending == 0 &&
	    token->sipi_vector == 0 && token->active_kind == 0 &&
	    token->active_vector == 0 && token->reserved == 0 &&
	    handoff->notification_generation == 0 && handoff->armed == 0 &&
	    handoff->reserved == 0 &&
	    vmm_startup_entry_runtime_validate(&owner->runtime) == 0 &&
	    vmm_startup_entry_loop_validate(&owner->loop) == 0 &&
	    owner->deferred.error == 0 &&
	    owner->deferred.action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST &&
	    owner->deferred.reserved8[0] == 0 &&
	    owner->deferred.reserved8[1] == 0 &&
	    owner->deferred.reserved8[2] == 0 &&
	    owner->deferred_exit.error == 0 &&
	    owner->deferred_exit.action == VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT &&
	    owner->deferred_exit.reserved8[0] == 0 &&
	    owner->deferred_exit.reserved8[1] == 0 &&
	    owner->deferred_exit.reserved8[2] == 0 &&
	    owner->deferred_kind == VMM_STARTUP_ENTRY_OWNER_DEFERRED_NONE &&
	    owner->deferred_reserved8[0] == 0 &&
	    owner->deferred_reserved8[1] == 0 &&
	    owner->deferred_reserved8[2] == 0 &&
	    owner->phase == VMM_STARTUP_ENTRY_OWNER_BOUND &&
	    owner->armed == 0 && owner->reserved16 == 0 &&
	    owner->reserved32 == 0);
}

static bool
vmm_startup_entry_owner_deferred_exit_empty(
    const struct vmm_startup_entry_owner *owner)
{

	return (owner->deferred_exit.error == 0 &&
	    owner->deferred_exit.action ==
	    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT &&
	    owner->deferred_exit.reserved8[0] == 0 &&
	    owner->deferred_exit.reserved8[1] == 0 &&
	    owner->deferred_exit.reserved8[2] == 0);
}

/*
 * The loop-result validator is private to the loop implementation.  Keep the
 * stack-owner's stored-result contract local and explicit rather than making
 * a new cross-module validation API solely for this transient field.
 */
static int
vmm_startup_entry_owner_deferred_runtime_validate(
    const struct vmm_startup_entry_runtime_result *result)
{

	if (result->error <= 0 || result->action >=
	    VMM_STARTUP_ENTRY_RUNTIME_ACTION_LAST || result->reserved8[0] != 0 ||
	    result->reserved8[1] != 0 || result->reserved8[2] != 0 ||
	    result->action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST)
		return (EINVAL);
	if (result->action == VMM_STARTUP_ENTRY_RUNTIME_REPLAY)
		return (result->error == EAGAIN ? 0 : EINVAL);
	return (result->action == VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR &&
	    result->error != EAGAIN ? 0 : EINVAL);
}

static int
vmm_startup_entry_owner_deferred_exit_validate(
    const struct vmm_startup_entry_loop_result *result)
{

	if (result->error < 0 || result->action >=
	    VMM_STARTUP_ENTRY_LOOP_ACTION_LAST || result->reserved8[0] != 0 ||
	    result->reserved8[1] != 0 || result->reserved8[2] != 0 ||
	    result->action == VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT)
		return (EINVAL);
	switch (result->action) {
	case VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT:
		return (result->error == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_LOOP_REPLAY:
		return (result->error == EAGAIN ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR:
		return (result->error > 0 && result->error != EAGAIN ? 0 :
		    EINVAL);
	default:
		return (EINVAL);
	}
}

static bool
vmm_startup_entry_owner_deferred_empty(
    const struct vmm_startup_entry_owner *owner)
{

	return (owner->deferred.error == 0 &&
	    owner->deferred.action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST &&
	    owner->deferred.reserved8[0] == 0 &&
	    owner->deferred.reserved8[1] == 0 &&
	    owner->deferred.reserved8[2] == 0);
}

static int
vmm_startup_entry_owner_return_history_validate(
    const struct vmm_startup_entry_owner *owner)
{

	if (owner->loop.entry_count == 0 &&
	    owner->loop.disposition.action ==
	    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT)
		return (EINVAL);
	return (0);
}

static int
vmm_startup_entry_owner_relation_validate(
    const struct vmm_startup_entry_owner *owner)
{

	switch (owner->phase) {
	case VMM_STARTUP_ENTRY_OWNER_BOUND:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
		    owner->loop.check_count != 0 || owner->loop.entry_count != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_FROZEN ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_CRITICAL:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
		    owner->loop.check_count != 0 || owner->loop.entry_count != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CRITICAL ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_GUEST_FPU:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
		    owner->loop.check_count != 0 || owner->loop.entry_count != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_RUNNING:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
		    owner->loop.check_count != 0 || owner->loop.entry_count != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_RUNNING ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_CHECKED ||
		    owner->loop.check_count == 0 ||
		    owner->loop.check_count != owner->loop.entry_count + 1)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_DEFERRED:
		switch (owner->deferred_kind) {
		case VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY:
			if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
			    vmm_startup_entry_owner_deferred_runtime_validate(
			    &owner->deferred) != 0)
				return (EINVAL);
			if (owner->runtime.phase == VMM_STARTUP_ENTRY_RUNTIME_RUNNING)
				return (owner->loop.entry_count == 0 ? 0 : EINVAL);
			if (owner->runtime.phase == VMM_STARTUP_ENTRY_RUNTIME_CHECKED)
				return (owner->loop.entry_count != 0 ? 0 : EINVAL);
			return (EINVAL);
		case VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY:
			if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_IN_GUEST ||
			    owner->runtime.phase != VMM_STARTUP_ENTRY_RUNTIME_CHECKED ||
			    owner->loop.entry_count == 0)
				return (EINVAL);
			return (0);
		default:
			return (EINVAL);
		}
	case VMM_STARTUP_ENTRY_OWNER_IN_GUEST:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_IN_GUEST ||
		    owner->loop.entry_count == 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_RECHECK:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
		    owner->loop.entry_count == 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_RETURNABLE:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_COMPLETE ||
		    vmm_startup_entry_owner_return_history_validate(owner) != 0)
			return (EINVAL);
		if (owner->runtime.phase == VMM_STARTUP_ENTRY_RUNTIME_RUNNING)
			return (owner->loop.entry_count == 0 ? 0 : EINVAL);
		if (owner->runtime.phase == VMM_STARTUP_ENTRY_RUNTIME_CHECKED) {
			if (owner->loop.entry_count != 0)
				return (0);
			return ((owner->loop.disposition.action ==
			    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT ||
			    owner->loop.disposition.action ==
			    VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR) ? 0 : EINVAL);
		}
		return (EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_REFROZEN:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_COMPLETE ||
		    vmm_startup_entry_owner_return_history_validate(owner) != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_REFROZEN ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_HOST_FPU:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_COMPLETE ||
		    vmm_startup_entry_owner_return_history_validate(owner) != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_OWNER_COMPLETE:
		if (owner->loop.phase != VMM_STARTUP_ENTRY_LOOP_COMPLETE ||
		    vmm_startup_entry_owner_return_history_validate(owner) != 0)
			return (EINVAL);
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_COMPLETE ? 0 : EINVAL);
	default:
		return (EINVAL);
	}
}

int
vmm_startup_entry_owner_validate(
    const struct vmm_startup_entry_owner *owner)
{

	if (owner == NULL || owner->phase >=
	    VMM_STARTUP_ENTRY_OWNER_PHASE_LAST || owner->armed != 1 ||
	    owner->reserved16 != 0 ||
	    owner->reserved32 != 0 ||
	    vmm_startup_event_run_token_validate(&owner->coordinator) != 0 ||
	    vmm_startup_entry_handoff_validate(&owner->notification) != 0 ||
	    vmm_startup_entry_runtime_validate(&owner->runtime) != 0 ||
	    vmm_startup_entry_loop_validate(&owner->loop) != 0 ||
	    owner->deferred_kind >= VMM_STARTUP_ENTRY_OWNER_DEFERRED_KIND_LAST ||
	    owner->deferred_reserved8[0] != 0 || owner->deferred_reserved8[1] != 0 ||
	    owner->deferred_reserved8[2] != 0 ||
	    (owner->phase != VMM_STARTUP_ENTRY_OWNER_DEFERRED &&
	    (!vmm_startup_entry_owner_deferred_empty(owner) ||
	    !vmm_startup_entry_owner_deferred_exit_empty(owner) ||
	    owner->deferred_kind != VMM_STARTUP_ENTRY_OWNER_DEFERRED_NONE)) ||
	    (owner->phase == VMM_STARTUP_ENTRY_OWNER_DEFERRED &&
	    ((owner->deferred_kind == VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY &&
	    (vmm_startup_entry_owner_deferred_runtime_validate(&owner->deferred) != 0 ||
	    !vmm_startup_entry_owner_deferred_exit_empty(owner))) ||
	    (owner->deferred_kind == VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY &&
	    (!vmm_startup_entry_owner_deferred_empty(owner) ||
	    vmm_startup_entry_owner_deferred_exit_validate(&owner->deferred_exit) != 0)) ||
	    owner->deferred_kind == VMM_STARTUP_ENTRY_OWNER_DEFERRED_NONE)) ||
	    vmm_startup_entry_owner_relation_validate(owner) != 0)
		return (EINVAL);
	return (0);
}

int
vmm_startup_entry_owner_init(
    const struct vmm_startup_event_run_token *coordinator,
    const struct vmm_startup_entry_handoff *notification,
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;

	if (coordinator == NULL || notification == NULL || owner == NULL ||
	    vmm_startup_entry_owner_overlap(coordinator, sizeof(*coordinator),
	    notification, sizeof(*notification)) ||
	    vmm_startup_entry_owner_overlap(coordinator, sizeof(*coordinator),
	    owner, sizeof(*owner)) ||
	    vmm_startup_entry_owner_overlap(notification, sizeof(*notification),
	    owner, sizeof(*owner)) ||
	    vmm_startup_event_run_token_validate(coordinator) != 0 ||
	    vmm_startup_entry_handoff_validate(notification) != 0 ||
	    !vmm_startup_entry_owner_empty(owner))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.coordinator = *coordinator;
	candidate.notification = *notification;
	vmm_startup_entry_runtime_init(&candidate.runtime);
	vmm_startup_entry_loop_init(&candidate.loop);
	candidate.armed = 1;
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_admit(
    const struct vmm_startup_event_run_token *coordinator,
    const struct vmm_startup_entry_admission *admission,
    struct vmm_startup_entry_owner *owner)
{

	if (coordinator == NULL || admission == NULL || owner == NULL ||
	    vmm_startup_entry_owner_overlap(coordinator, sizeof(*coordinator),
	    admission, sizeof(*admission)) ||
	    vmm_startup_entry_owner_overlap(admission, sizeof(*admission),
	    owner, sizeof(*owner)) ||
	    vmm_startup_entry_admission_validate(admission) != 0 ||
	    admission->action != VMM_STARTUP_ENTRY_ENTER_GUEST)
		return (EINVAL);
	return (vmm_startup_entry_owner_init(coordinator,
	    &admission->handoff, owner));
}

int
vmm_startup_entry_owner_enter_critical(
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_BOUND)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_enter_critical(&candidate.runtime);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_CRITICAL;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_restore_guest_fpu(
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_CRITICAL)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_restore_guest_fpu(&candidate.runtime);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_GUEST_FPU;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_publish_running(
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_GUEST_FPU)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_publish_running(&candidate.runtime);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_RUNNING;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_guard_before(struct vmm_startup_entry_owner *owner,
    int coordinator_error, int notification_error,
    struct vmm_startup_entry_runtime_result *result)
{
	struct vmm_startup_entry_loop_result loop_result;
	struct vmm_startup_entry_owner candidate;
	struct vmm_startup_entry_runtime_result candidate_result;
	uint8_t expected_action;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    (owner->phase != VMM_STARTUP_ENTRY_OWNER_RUNNING &&
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_RECHECK) || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_guard_before(&candidate.runtime,
	    &candidate.loop, coordinator_error, notification_error,
	    &candidate_result);
	if (error != 0)
		return (error);
	if (candidate_result.action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
		candidate.phase = VMM_STARTUP_ENTRY_OWNER_IN_GUEST;
	} else {
		error = vmm_startup_entry_loop_finish(&candidate.loop,
		    &loop_result);
		if (error != 0)
			return (error);
		expected_action = candidate_result.action ==
		    VMM_STARTUP_ENTRY_RUNTIME_REPLAY ?
		    VMM_STARTUP_ENTRY_LOOP_REPLAY :
		    VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
		if (loop_result.error != candidate_result.error ||
		    loop_result.action != expected_action)
			return (EPROTO);
		candidate.phase = VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	}
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_guard_before_defer(
    struct vmm_startup_entry_owner *owner, int coordinator_error,
    int notification_error, struct vmm_startup_entry_runtime_result *result)
{
	struct vmm_startup_entry_owner candidate;
	struct vmm_startup_entry_runtime_result candidate_result;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    (owner->phase != VMM_STARTUP_ENTRY_OWNER_RUNNING &&
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_RECHECK) || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_check(&candidate.runtime,
	    coordinator_error, notification_error, &candidate_result);
	if (error != 0)
		return (error);
	if (candidate_result.action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
		error = vmm_startup_entry_loop_check(&candidate.loop,
		    &candidate_result);
		if (error != 0)
			return (error);
		error = vmm_startup_entry_loop_enter(&candidate.loop);
		if (error != 0)
			return (error);
		candidate.phase = VMM_STARTUP_ENTRY_OWNER_IN_GUEST;
	} else {
		candidate.deferred = candidate_result;
		candidate.deferred_kind =
		    VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY;
		candidate.phase = VMM_STARTUP_ENTRY_OWNER_DEFERRED;
	}
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_guard_before_attempt(
    struct vmm_startup_entry_owner *owner, int coordinator_error,
    int notification_error, struct vmm_startup_entry_runtime_result *result)
{
	struct vmm_startup_entry_owner candidate;
	struct vmm_startup_entry_runtime_result candidate_result;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    (owner->phase != VMM_STARTUP_ENTRY_OWNER_RUNNING &&
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_RECHECK) || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_check(&candidate.runtime,
	    coordinator_error, notification_error, &candidate_result);
	if (error != 0)
		return (error);
	if (candidate_result.action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
		error = vmm_startup_entry_loop_check(&candidate.loop,
		    &candidate_result);
		if (error != 0)
			return (error);
		candidate.phase = VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING;
	} else {
		candidate.deferred = candidate_result;
		candidate.deferred_kind =
		    VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY;
		candidate.phase = VMM_STARTUP_ENTRY_OWNER_DEFERRED;
	}
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_commit_attempt(struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_loop_enter(&candidate.loop);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_IN_GUEST;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_abort_attempt(struct vmm_startup_entry_owner *owner,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_owner candidate;
	struct vmm_startup_entry_loop_result candidate_result;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_loop_software_exit_checked(&candidate.loop,
	    &candidate_result);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_abort_attempt_error(
    struct vmm_startup_entry_owner *owner, int terminal_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_owner candidate;
	struct vmm_startup_entry_loop_result candidate_result;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING ||
	    terminal_error <= 0 || terminal_error == EAGAIN || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_loop_fail_checked(&candidate.loop,
	    terminal_error, &candidate_result);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_resolve_deferred(
    struct vmm_startup_entry_owner *owner, int terminal_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_DEFERRED ||
	    owner->deferred_kind !=
	    VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY || result == NULL ||
	    terminal_error < 0 || terminal_error == EAGAIN ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = terminal_error != 0 ? terminal_error :
	    candidate.deferred.error;
	if (error <= 0)
		return (EPROTO);
	error = vmm_startup_entry_loop_fail_before_entry(&candidate.loop,
	    error, &candidate_result);
	if (error != 0)
		return (error);
	memset(&candidate.deferred, 0, sizeof(candidate.deferred));
	candidate.deferred_kind = VMM_STARTUP_ENTRY_OWNER_DEFERRED_NONE;
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_guard_after_defer(
    struct vmm_startup_entry_owner *owner, int backend_error)
{
	struct vmm_startup_entry_loop loop_candidate;
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_IN_GUEST || backend_error < 0)
		return (EINVAL);
	candidate = *owner;
	loop_candidate = candidate.loop;
	error = vmm_startup_entry_loop_exit(&loop_candidate, false,
	    backend_error);
	if (error != 0)
		return (error);
	error = vmm_startup_entry_loop_finish(&loop_candidate,
	    &candidate.deferred_exit);
	if (error != 0)
		return (error);
	candidate.deferred_kind = VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY;
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_DEFERRED;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_resolve_deferred_after(
    struct vmm_startup_entry_owner *owner, int terminal_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_DEFERRED ||
	    owner->deferred_kind !=
	    VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY || result == NULL ||
	    terminal_error < 0 || terminal_error == EAGAIN ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	error = terminal_error != 0 ? terminal_error :
	    candidate.deferred_exit.error;
	error = vmm_startup_entry_loop_exit(&candidate.loop, false, error);
	if (error != 0)
		return (error);
	error = vmm_startup_entry_loop_finish(&candidate.loop,
	    &candidate_result);
	if (error != 0)
		return (error);
	memset(&candidate.deferred_exit, 0, sizeof(candidate.deferred_exit));
	candidate.deferred_kind = VMM_STARTUP_ENTRY_OWNER_DEFERRED_NONE;
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_guard_after(struct vmm_startup_entry_owner *owner,
    bool handled, int backend_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_IN_GUEST ||
	    (handled && result != NULL) || (!handled && result == NULL) ||
	    (result != NULL && vmm_startup_entry_owner_overlap(owner,
	    sizeof(*owner), result, sizeof(*result))))
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_guard_after(&candidate.loop, handled,
	    backend_error, handled ? NULL : &candidate_result);
	if (error != 0)
		return (error);
	candidate.phase = handled ? VMM_STARTUP_ENTRY_OWNER_RECHECK :
	    VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	if (!handled)
		*result = candidate_result;
	return (0);
}

static int
vmm_startup_entry_owner_return_before_entry(
    struct vmm_startup_entry_owner *owner, bool software_exit, int error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_owner candidate;
	int transition_error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    (owner->phase != VMM_STARTUP_ENTRY_OWNER_RUNNING &&
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_RECHECK) || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *owner;
	if (software_exit) {
		transition_error = vmm_startup_entry_loop_software_exit(
		    &candidate.loop, &candidate_result);
	} else {
		transition_error = vmm_startup_entry_loop_fail_before_entry(
		    &candidate.loop, error, &candidate_result);
	}
	if (transition_error != 0)
		return (transition_error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_RETURNABLE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_owner_software_exit(
    struct vmm_startup_entry_owner *owner,
    struct vmm_startup_entry_loop_result *result)
{

	return (vmm_startup_entry_owner_return_before_entry(owner, true, 0,
	    result));
}

int
vmm_startup_entry_owner_fail_before_entry(
    struct vmm_startup_entry_owner *owner, int error,
    struct vmm_startup_entry_loop_result *result)
{

	return (vmm_startup_entry_owner_return_before_entry(owner, false, error,
	    result));
}

int
vmm_startup_entry_owner_publish_frozen(
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_RETURNABLE)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_publish_frozen(&candidate.runtime);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_REFROZEN;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_save_guest_fpu(
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_REFROZEN)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_save_guest_fpu(&candidate.runtime);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_HOST_FPU;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_exit_critical(
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_owner candidate;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_HOST_FPU)
		return (EINVAL);
	candidate = *owner;
	error = vmm_startup_entry_runtime_exit_critical(&candidate.runtime);
	if (error != 0)
		return (error);
	candidate.phase = VMM_STARTUP_ENTRY_OWNER_COMPLETE;
	if (vmm_startup_entry_owner_validate(&candidate) != 0)
		return (EINVAL);
	*owner = candidate;
	return (0);
}

int
vmm_startup_entry_owner_retire(struct vmm_startup_entry_owner *owner,
    int coordinator_error, int notification_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	int error;

	if (vmm_startup_entry_owner_validate(owner) != 0 ||
	    owner->phase != VMM_STARTUP_ENTRY_OWNER_COMPLETE || result == NULL ||
	    vmm_startup_entry_owner_overlap(owner, sizeof(*owner), result,
	    sizeof(*result)))
		return (EINVAL);
	error = vmm_startup_entry_guard_complete(&owner->loop.disposition,
	    coordinator_error, notification_error, &candidate_result);
	if (error != 0)
		return (error);
	memset(owner, 0, sizeof(*owner));
	*result = candidate_result;
	return (0);
}
