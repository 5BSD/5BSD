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

#include "vmx_nested_continuation.h"
#include "vmx_nested_state_range.h"

static bool
nvmxc_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmxc_id_equal(const struct vmx_nested_vmcs02_id *first,
    const struct vmx_nested_vmcs02_id *second)
{

	return (nvmxc_id_valid(first) && nvmxc_id_valid(second) &&
	    vmx_nested_vmcs02_id_equal(first, second));
}

static bool
nvmxc_completion_valid(enum vmx_nested_l0_completion completion)
{

	return (completion == VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    completion == VMX_NESTED_L0_COMPLETE_REFLECT_L1);
}

void
vmx_nested_l0_continuation_init(
    struct vmx_nested_l0_continuation *continuation)
{

	if (continuation == NULL)
		return;
	memset(continuation, 0, sizeof(*continuation));
	continuation->state = VMX_NESTED_L0_CONTINUATION_IDLE;
}

int
vmx_nested_l0_continuation_begin(
    struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_context *context,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t exit_sequence,
    enum vmx_nested_exit_action action)
{
	enum vmx_nested_l0_completion completion;

	if (continuation == NULL || context == NULL || runtime == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    id->state_generation != context->state_generation ||
	    id->execution_epoch != context->execution_epoch ||
	    id->vmcs12_gpa != context->machine.current_vmcs_gpa ||
	    exit_sequence == 0)
		return (EINVAL);
	switch (action) {
	case VMX_NESTED_EXIT_HANDLE_L0:
		completion = VMX_NESTED_L0_COMPLETE_RESUME_L2;
		break;
	case VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1:
		completion = VMX_NESTED_L0_COMPLETE_REFLECT_L1;
		break;
	case VMX_NESTED_EXIT_REFLECT_L1:
	default:
		/*
		 * A directly reflected exit does not have an L0 continuation.
		 */
		return (EINVAL);
	}
	continuation->id = *id;
	continuation->exit_sequence = exit_sequence;
	continuation->completion = completion;
	continuation->state = VMX_NESTED_L0_CONTINUATION_HOT;
	return (0);
}

int
vmx_nested_l0_continuation_freeze(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg)
{
	uint64_t portable_generation;
	bool rollback_complete;
	int error;

	if (continuation == NULL || runtime == NULL || ops == NULL ||
	    ops->freeze == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    !nvmxc_id_equal(&continuation->id, id))
		return (EINVAL);
	error = vmx_nested_entry_runtime_l0_freeze_begin(runtime, id);
	if (error != 0)
		return (error);
	continuation->state = VMX_NESTED_L0_CONTINUATION_FREEZING;
	portable_generation = 0;
	rollback_complete = false;
	error = ops->freeze(arg, id, &portable_generation,
	    &rollback_complete);
	if (error < 0)
		error = EPROTO;
	if (error != 0) {
		if (vmx_nested_entry_runtime_l0_freeze_abort(runtime, id,
		    rollback_complete) != 0)
			return (EPROTO);
		if (rollback_complete) {
			continuation->state =
			    VMX_NESTED_L0_CONTINUATION_HOT;
		} else {
			continuation->rollback_failed = true;
			continuation->state =
			    VMX_NESTED_L0_CONTINUATION_ABORTED;
		}
		return (error);
	}
	if (portable_generation == 0) {
		(void)vmx_nested_entry_runtime_l0_freeze_abort(runtime, id,
		    false);
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
		return (EPROTO);
	}
	error = vmx_nested_entry_runtime_l0_freeze_complete(runtime, id);
	if (error != 0) {
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
		return (EPROTO);
	}
	continuation->portable_generation = portable_generation;
	continuation->state = VMX_NESTED_L0_CONTINUATION_COLD;
	return (0);
}

int
vmx_nested_l0_continuation_thaw(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg)
{
	uint64_t resource_generation;
	bool rollback_complete;
	int error;

	if (continuation == NULL || runtime == NULL || ops == NULL ||
	    ops->thaw == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    continuation->portable_generation == 0 ||
	    !nvmxc_id_equal(&continuation->id, id))
		return (EINVAL);
	error = vmx_nested_entry_runtime_l0_thaw_begin(runtime, id);
	if (error != 0)
		return (error);
	continuation->state = VMX_NESTED_L0_CONTINUATION_THAWING;
	resource_generation = 0;
	rollback_complete = false;
	error = ops->thaw(arg, id, continuation->portable_generation,
	    &resource_generation, &rollback_complete);
	if (error < 0)
		error = EPROTO;
	if (error != 0) {
		if (vmx_nested_entry_runtime_l0_thaw_abort(runtime, id,
		    rollback_complete) != 0)
			return (EPROTO);
		if (rollback_complete) {
			continuation->state =
			    VMX_NESTED_L0_CONTINUATION_COLD;
		} else {
			continuation->rollback_failed = true;
			continuation->state =
			    VMX_NESTED_L0_CONTINUATION_ABORTED;
		}
		return (error);
	}
	if (resource_generation == 0 ||
	    vmx_nested_entry_runtime_l0_thaw_complete(runtime, id,
	    resource_generation) != 0) {
		(void)vmx_nested_entry_runtime_l0_thaw_abort(runtime, id,
		    false);
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
		return (EPROTO);
	}
	continuation->state = VMX_NESTED_L0_CONTINUATION_HOT;
	return (0);
}

int
vmx_nested_l0_continuation_thaw_prepare(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_l2_thaw_staged *staged,
    const struct vmx_nested_l2_thaw_input *input,
    const struct vmx_nested_l2_thaw_frozen_ops *ops, void *arg)
{
	int error;

	if (continuation == NULL || runtime == NULL || staged == NULL ||
	    input == NULL || input->portable == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    continuation->portable_generation == 0 ||
	    continuation->portable_generation !=
	    input->portable->portable_generation ||
	    !nvmxc_id_equal(id, &input->portable->id) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_IDLE)
		return (EINVAL);
	error = vmx_nested_entry_runtime_l0_thaw_begin(runtime, id);
	if (error != 0)
		return (error);
	continuation->state = VMX_NESTED_L0_CONTINUATION_THAWING;
	error = vmx_nested_l2_thaw_staged_prepare(staged, input, ops, arg);
	if (error == 0)
		return (0);
	if (staged->state == VMX_NESTED_L2_THAW_STAGED_IDLE) {
		if (vmx_nested_entry_runtime_l0_thaw_abort(runtime, id,
		    true) != 0)
			return (EPROTO);
		continuation->state = VMX_NESTED_L0_CONTINUATION_COLD;
	} else {
		(void)vmx_nested_entry_runtime_l0_thaw_abort(runtime, id,
		    false);
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
	}
	return (error);
}

int
vmx_nested_l0_continuation_thaw_commit_hot(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_l2_thaw_staged *staged,
    const struct vmx_nested_l2_thaw_hot_ops *ops, void *arg,
    struct vmx_nested_vmcs02_plan *plan, uint64_t *resource_generation)
{
	uint64_t generation;
	int error;

	if (continuation == NULL || runtime == NULL || staged == NULL ||
	    plan == NULL || resource_generation == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_THAWING ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_THAWING ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_PREPARED)
		return (EINVAL);
	error = vmx_nested_l2_thaw_staged_commit_hot(staged, ops, arg);
	if (error != 0) {
		if (staged->state ==
		    VMX_NESTED_L2_THAW_STAGED_POISONED) {
			(void)vmx_nested_entry_runtime_l0_thaw_abort(runtime,
			    id, false);
			continuation->rollback_failed = true;
			continuation->state =
			    VMX_NESTED_L0_CONTINUATION_ABORTED;
		}
		return (error);
	}
	generation = staged->resource_generation;
	if (generation == 0 ||
	    vmx_nested_entry_runtime_l0_thaw_complete(runtime, id,
	    generation) != 0) {
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
		return (EPROTO);
	}
	error = vmx_nested_l2_thaw_staged_take(staged, plan,
	    resource_generation);
	if (error != 0 || *resource_generation != generation) {
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
		return (EPROTO);
	}
	continuation->state = VMX_NESTED_L0_CONTINUATION_HOT;
	return (0);
}

int
vmx_nested_l0_continuation_thaw_cancel_frozen(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_l2_thaw_staged *staged,
    const struct vmx_nested_l2_thaw_frozen_ops *ops, void *arg)
{
	int error;

	if (continuation == NULL || runtime == NULL || staged == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_THAWING ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_THAWING ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_PREPARED)
		return (EINVAL);
	error = vmx_nested_l2_thaw_staged_cancel(staged, ops, arg);
	if (error == 0) {
		if (vmx_nested_entry_runtime_l0_thaw_abort(runtime, id,
		    true) != 0)
			return (EPROTO);
		continuation->state = VMX_NESTED_L0_CONTINUATION_COLD;
		return (0);
	}
	(void)vmx_nested_entry_runtime_l0_thaw_abort(runtime, id, false);
	continuation->rollback_failed = true;
	continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
	return (error);
}

int
vmx_nested_l0_continuation_resolve(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg)
{
	enum vmx_nested_l0_continuation_state prior;
	bool portable;
	int error;

	if (continuation == NULL || runtime == NULL || ops == NULL ||
	    ops->resolve == NULL ||
	    (continuation->state != VMX_NESTED_L0_CONTINUATION_HOT &&
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD) ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    (continuation->state == VMX_NESTED_L0_CONTINUATION_HOT &&
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT) ||
	    (continuation->state == VMX_NESTED_L0_CONTINUATION_COLD &&
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD) ||
	    !nvmxc_id_equal(&runtime->id, id) ||
	    !nvmxc_id_equal(&continuation->id, id))
		return (EINVAL);
	if (continuation->state == VMX_NESTED_L0_CONTINUATION_COLD &&
	    continuation->completion == VMX_NESTED_L0_COMPLETE_RESUME_L2)
		return (EAGAIN);
	prior = continuation->state;
	portable = prior == VMX_NESTED_L0_CONTINUATION_COLD;
	continuation->state = VMX_NESTED_L0_CONTINUATION_RESOLVING;
	error = ops->resolve(arg, id, continuation->completion, portable);
	if (error < 0)
		error = EPROTO;
	if (error != 0) {
		/*
		 * resolve() is required to be transactional, so the exact
		 * prior residency remains available for a frozen-vCPU retry.
		 */
		continuation->state = prior;
		return (error);
	}
	if (continuation->completion ==
	    VMX_NESTED_L0_COMPLETE_RESUME_L2)
		error = vmx_nested_entry_runtime_l0_resume(runtime, id);
	else
		error = vmx_nested_entry_runtime_l0_reflect_complete(runtime,
		    id);
	if (error != 0) {
		continuation->rollback_failed = true;
		continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
		return (EPROTO);
	}
	vmx_nested_l0_continuation_init(continuation);
	return (0);
}

int
vmx_nested_l0_continuation_quarantine_hot(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{
	int error;

	if (continuation == NULL || runtime == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    runtime->rollback_failed ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    !nvmxc_id_equal(&runtime->id, id))
		return (EINVAL);
	error = vmx_nested_entry_runtime_l0_abort(runtime, id);
	if (error != 0)
		return (error);
	continuation->rollback_failed = true;
	continuation->state = VMX_NESTED_L0_CONTINUATION_ABORTED;
	return (0);
}

int
vmx_nested_l0_continuation_refreeze_unentered(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t portable_generation)
{
	int error;

	if (continuation == NULL || runtime == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    continuation->completion != VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    continuation->portable_generation == 0 ||
	    continuation->portable_generation != portable_generation ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    runtime->rollback_failed ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    !nvmxc_id_equal(&runtime->id, id))
		return (EINVAL);
	error = vmx_nested_entry_runtime_l0_refreeze(runtime, id);
	if (error != 0)
		return (error);
	continuation->state = VMX_NESTED_L0_CONTINUATION_COLD;
	return (0);
}

int
vmx_nested_l0_continuation_refreeze_late_entry(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t portable_generation)
{

	if (continuation == NULL || runtime == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    continuation->completion != VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    continuation->portable_generation == 0 ||
	    continuation->portable_generation != portable_generation ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    runtime->resource_generation == 0 ||
	    runtime->entry_msr_count != 0 || runtime->rollback_failed ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    !nvmxc_id_equal(&runtime->id, id))
		return (EINVAL);
	/*
	 * Resource release has already completed.  Publish the resource-free
	 * captured state and retire continuation ownership together; no
	 * fallible hardware operation remains.
	 */
	runtime->resource_generation = 0;
	runtime->state = VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD;
	vmx_nested_l0_continuation_init(continuation);
	return (0);
}

int
vmx_nested_l0_continuation_exit_captured(
    struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	if (continuation == NULL || runtime == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED ||
	    runtime->rollback_failed ||
	    !nvmxc_id_equal(&continuation->id, id) ||
	    !nvmxc_id_equal(&runtime->id, id))
		return (EINVAL);
	/*
	 * Destructive VMCS02 capture has already made hot resume
	 * impossible.  Retire only the L0 continuation owner; the captured
	 * runtime remains bound to the frozen VM-exit publication.
	 */
	vmx_nested_l0_continuation_init(continuation);
	return (0);
}

int
vmx_nested_l0_continuation_export(
    const struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_l0_continuation_record *record)
{
	struct vmx_nested_l0_continuation_record candidate;
	int error;

	if (continuation == NULL || record == NULL)
		return (EINVAL);
	error = vmx_nested_l0_continuation_validate(continuation);
	if (error != 0)
		return (error);
	if (continuation->state != VMX_NESTED_L0_CONTINUATION_COLD)
		return (EBUSY);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = continuation->id;
	candidate.exit_sequence = continuation->exit_sequence;
	candidate.portable_generation =
	    continuation->portable_generation;
	candidate.completion = continuation->completion;
	memcpy(record, &candidate, sizeof(candidate));
	return (0);
}

int
vmx_nested_l0_continuation_restore(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l0_continuation_record *record, bool frozen)
{
	struct vmx_nested_l0_continuation candidate;

	if (continuation == NULL || runtime == NULL || record == NULL ||
	    !frozen ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_valid(&record->id) || record->exit_sequence == 0 ||
	    record->portable_generation == 0 ||
	    !nvmxc_completion_valid(record->completion))
		return (EINVAL);
	vmx_nested_l0_continuation_init(&candidate);
	candidate.id = record->id;
	candidate.exit_sequence = record->exit_sequence;
	candidate.portable_generation = record->portable_generation;
	candidate.completion = record->completion;
	candidate.state = VMX_NESTED_L0_CONTINUATION_COLD;
	if (vmx_nested_entry_runtime_l0_cold_restore(runtime,
	    &record->id) != 0)
		return (EPROTO);
	*continuation = candidate;
	return (0);
}

int
vmx_nested_l0_continuation_quiesce(
    const struct vmx_nested_l0_continuation *continuation)
{

	if (continuation == NULL ||
	    vmx_nested_l0_continuation_validate(continuation) != 0)
		return (EINVAL);
	if (continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE &&
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD)
		return (EBUSY);
	return (0);
}

int
vmx_nested_l0_continuation_quiesce_context(
    const struct vmx_nested_context *context,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l2_portable_state *portable)
{
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL)
		return (EINVAL);
	error = vmx_nested_l0_continuation_validate(continuation);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_runtime_validate(runtime);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_validate(portable);
	if (error != 0)
		return (error);
	error = vmx_nested_context_guest_continuation_validate(context,
	    continuation);
	if (error != 0)
		return (error);
	if (context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD)
		return (EBUSY);
	id = &continuation->id;
	if (!vmx_nested_vmcs02_id_equal(id, &runtime->id) ||
	    !vmx_nested_vmcs02_id_equal(id, &portable->id) ||
	    portable->portable_generation !=
	    continuation->portable_generation)
		return (ESTALE);
	return (0);
}

int
vmx_nested_l0_continuation_discard_cold(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    struct vmx_nested_l2_portable_state *portable, bool frozen)
{

	if (continuation == NULL || runtime == NULL || portable == NULL ||
	    !frozen ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    vmx_nested_l2_portable_validate(portable) != 0 ||
	    continuation->portable_generation !=
	    portable->portable_generation ||
	    !nvmxc_id_equal(&continuation->id, &runtime->id) ||
	    !nvmxc_id_equal(&continuation->id, &portable->id))
		return (EINVAL);
	memset(portable, 0, sizeof(*portable));
	vmx_nested_entry_runtime_init(runtime);
	vmx_nested_l0_continuation_init(continuation);
	return (0);
}

int
vmx_nested_l0_continuation_reset(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime, bool frozen,
    bool recovery_complete)
{
	int error;

	if (continuation == NULL || runtime == NULL || !frozen ||
	    !recovery_complete ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), runtime, sizeof(*runtime)) ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_ABORTED ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_ABORTED ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    !nvmxc_id_equal(&continuation->id, &runtime->id))
		return (EINVAL);
	error = vmx_nested_entry_runtime_reset(runtime, &continuation->id,
	    true, true);
	if (error != 0)
		return (EPROTO);
	vmx_nested_l0_continuation_init(continuation);
	return (0);
}

int
vmx_nested_l0_continuation_validate(
    const struct vmx_nested_l0_continuation *continuation)
{

	if (continuation == NULL ||
	    continuation->state < VMX_NESTED_L0_CONTINUATION_IDLE ||
	    continuation->state > VMX_NESTED_L0_CONTINUATION_ABORTED)
		return (EINVAL);
	if (continuation->state == VMX_NESTED_L0_CONTINUATION_IDLE) {
		if (continuation->id.state_generation != 0 ||
		    continuation->id.execution_epoch != 0 ||
		    continuation->id.vmcs12_gpa != 0 ||
		    continuation->exit_sequence != 0 ||
		    continuation->portable_generation != 0 ||
		    continuation->completion !=
		    VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
		    continuation->rollback_failed)
			return (EPROTO);
		return (0);
	}
	if (!nvmxc_id_valid(&continuation->id) ||
	    continuation->exit_sequence == 0 ||
	    !nvmxc_completion_valid(continuation->completion))
		return (EPROTO);
	if (continuation->state == VMX_NESTED_L0_CONTINUATION_ABORTED)
		return (continuation->rollback_failed ? 0 : EPROTO);
	if (continuation->rollback_failed)
		return (EPROTO);
	if (continuation->state == VMX_NESTED_L0_CONTINUATION_COLD ||
	    continuation->state == VMX_NESTED_L0_CONTINUATION_THAWING) {
		if (continuation->portable_generation == 0)
			return (EPROTO);
	} else if (continuation->portable_generation != 0 &&
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT &&
	    continuation->state != VMX_NESTED_L0_CONTINUATION_RESOLVING) {
		return (EPROTO);
	}
	return (0);
}
