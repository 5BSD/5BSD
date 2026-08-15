/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_hardware_entry.h"
#include "vmx_nested_state_range.h"

static bool
nvmxhe_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (a != NULL && b != NULL &&
	    vmx_nested_vmcs02_id_equal(a, b));
}

static int
nvmxhe_callback_error(int error)
{

	return (error < 0 ? EPROTO : error);
}

static int
nvmxhe_validate(const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_hardware_entry_ops *ops)
{
	int error;

	if (runtime == NULL || id == NULL || ops == NULL ||
	    ops->install_msrs == NULL || ops->rollback_msrs == NULL ||
	    ops->commit_msrs == NULL ||
	    ops->commit_vmcs_launch == NULL ||
	    ops->program_vmcs02 == NULL || ops->leave_vmcs02 == NULL ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), ops,
	    sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_entry_runtime_validate(runtime);
	if (error != 0)
		return (error);
	if (!nvmxhe_id_equal(&runtime->id, id))
		return (ESTALE);
	return (0);
}

int
vmx_nested_hardware_entry_prepare(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint32_t entry_msr_count,
    const struct vmx_nested_software_msrs *software,
    const struct vmx_nested_vmcs02_program *program,
    const struct vmx_nested_hardware_entry_ops *ops, void *arg)
{
	struct vmx_nested_hardware_entry_ops ops_snapshot;
	bool rollback_complete;
	int error, rollback_error, transition_error;

	error = nvmxhe_validate(runtime, id, ops);
	if (error != 0)
		return (error);
	if (software == NULL || program == NULL ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    !nvmxhe_id_equal(id, &program->id) ||
	    program->resource_generation != runtime->resource_generation ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime),
	    software, sizeof(*software)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime),
	    program, sizeof(*program)) ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), software,
	    sizeof(*software)) ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), program,
	    sizeof(*program)))
		return (EINVAL);
	ops_snapshot = *ops;

	/*
	 * Publish ownership before touching hardware.  A failed adapter call
	 * is then represented explicitly as either a clean rollback or a
	 * poisoned runtime that cannot be reused silently.
	 */
	error = vmx_nested_entry_runtime_msrs(runtime, id, entry_msr_count);
	if (error != 0)
		return (error);
	rollback_complete = false;
	error = nvmxhe_callback_error(ops_snapshot.install_msrs(arg, software,
	    &rollback_complete));
	if (error != 0) {
		transition_error = vmx_nested_entry_runtime_rollback(runtime,
		    id, rollback_complete);
		return (transition_error != 0 ? transition_error : error);
	}

	/*
	 * Record the restore obligation before the adapter can select VMCS02.
	 * A transactional programming failure has already restored VMCS01, so
	 * acknowledge that restoration before rolling the MSR bank back.
	 */
	error = vmx_nested_entry_runtime_vmcs02(runtime, id);
	if (error != 0)
		goto rollback_msrs;
	rollback_complete = false;
	error = nvmxhe_callback_error(ops_snapshot.program_vmcs02(arg, program,
	    &rollback_complete));
	if (error == 0)
		return (0);
	if (!rollback_complete) {
		transition_error =
		    vmx_nested_entry_runtime_vmcs02_abort(runtime, id);
		return (transition_error != 0 ? transition_error : error);
	}
	transition_error = vmx_nested_entry_runtime_restore_vmcs01(runtime,
	    id);
	if (transition_error != 0)
		return (transition_error);

rollback_msrs:
	rollback_error = nvmxhe_callback_error(
	    ops_snapshot.rollback_msrs(arg));
	transition_error = vmx_nested_entry_runtime_rollback(runtime, id,
	    rollback_error == 0);
	if (transition_error != 0)
		return (transition_error);
	return (rollback_error != 0 ? rollback_error : error);
}

int
vmx_nested_hardware_entry_commit(
    struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_hardware_entry_ops *ops, void *arg)
{
	struct vmx_nested_hardware_entry_ops ops_snapshot;
	int error;

	error = nvmxhe_validate(runtime, id, ops);
	if (error != 0)
		return (error);
	if (runtime->state != VMX_NESTED_ENTRY_RUNTIME_VMCS02 ||
	    context == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), ops,
	    sizeof(*ops)))
		return (EINVAL);
	ops_snapshot = *ops;
	error = vmx_nested_context_commit_hardware_entry(context, runtime,
	    id);
	if (error != 0)
		return (error);
	ops_snapshot.commit_vmcs_launch(arg);
	ops_snapshot.commit_msrs(arg);
	return (0);
}

static int
nvmxhe_unwind_unlaunched(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_hardware_entry_ops *ops, void *arg)
{
	struct vmx_nested_hardware_entry_ops ops_snapshot;
	int error, rollback_error, transition_error;

	error = nvmxhe_validate(runtime, id, ops);
	if (error != 0)
		return (error);
	if (runtime->state != VMX_NESTED_ENTRY_RUNTIME_VMCS02)
		return (EINVAL);
	ops_snapshot = *ops;
	error = nvmxhe_callback_error(ops_snapshot.leave_vmcs02(arg));
	if (error != 0) {
		transition_error = vmx_nested_entry_runtime_vmcs02_abort(runtime,
		    id);
		if (transition_error != 0)
			return (transition_error);
		return (error);
	}
	error = vmx_nested_entry_runtime_restore_vmcs01(runtime, id);
	if (error != 0) {
		transition_error = vmx_nested_entry_runtime_vmcs02_abort(runtime,
		    id);
		if (transition_error != 0)
			return (transition_error);
		return (error);
	}
	rollback_error = nvmxhe_callback_error(
	    ops_snapshot.rollback_msrs(arg));
	transition_error = vmx_nested_entry_runtime_rollback(runtime, id,
	    rollback_error == 0);
	if (transition_error != 0)
		return (transition_error);
	return (rollback_error);
}

int
vmx_nested_hardware_entry_rollback(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_hardware_entry_ops *ops, void *arg)
{

	return (nvmxhe_unwind_unlaunched(runtime, id, ops, arg));
}

int
vmx_nested_hardware_entry_reject(
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_hardware_entry_ops *ops, void *arg)
{

	return (nvmxhe_unwind_unlaunched(runtime, id, ops, arg));
}

int
vmx_nested_hardware_entry_finish(
    struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_hardware_report_result *report,
	const struct vmx_nested_hardware_entry_ops *ops, void *arg,
	const struct vmx_nested_hardware_event_ops *event_ops, void *event_arg,
	enum vmx_nested_hardware_entry_finish_completion *completion,
	struct vmx_nested_vmentry_result *rejection)
{
	struct vmx_nested_hardware_event_ops event_ops_snapshot;
	struct vmx_nested_vmentry_result candidate;
	int error;

	if (context == NULL || report == NULL || completion == NULL ||
	    event_ops == NULL ||
	    event_ops->commit_entered == NULL || event_ops->abort == NULL ||
	    vmx_nested_hardware_report_result_validate(report) != 0)
		return (EINVAL);
	if (runtime == NULL || ops == NULL ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), event_ops,
	    sizeof(*event_ops)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(completion, sizeof(*completion),
	    context, sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(completion, sizeof(*completion),
	    runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(completion, sizeof(*completion),
	    report, sizeof(*report)) ||
	    vmx_nested_state_ranges_overlap(completion, sizeof(*completion),
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(completion, sizeof(*completion),
	    event_ops, sizeof(*event_ops)) ||
	    (rejection != NULL &&
	    vmx_nested_state_ranges_overlap(completion, sizeof(*completion),
	    rejection, sizeof(*rejection))) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime),
	    event_ops, sizeof(*event_ops)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    event_ops, sizeof(*event_ops)) ||
	    (rejection != NULL &&
	    (vmx_nested_state_ranges_overlap(rejection, sizeof(*rejection),
	    context, sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(rejection, sizeof(*rejection),
	    runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(rejection, sizeof(*rejection),
	    report, sizeof(*report)) ||
	    vmx_nested_state_ranges_overlap(rejection, sizeof(*rejection),
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(rejection, sizeof(*rejection),
	    event_ops, sizeof(*event_ops)))))
		return (EINVAL);
	/* Valid calls never leave a stale completion fact behind on failure. */
	*completion = VMX_NESTED_HARDWARE_ENTRY_FINISH_NONE;
	/*
	 * The hardware unwind can invoke private callbacks before the event
	 * transition below.  Keep the complete event callback pair stable for
	 * this one transaction: a callback-side table mutation must not redirect
	 * the later commit/abort operation or leave its owner unconsumed.
	 */
	event_ops_snapshot = *event_ops;
	switch (report->disposition) {
	case VMX_NESTED_HARDWARE_L2_EXIT:
		error = vmx_nested_hardware_entry_commit(context, runtime, id,
		    ops, arg);
		if (error != 0)
			return (error);
		event_ops_snapshot.commit_entered(event_arg);
		*completion = VMX_NESTED_HARDWARE_ENTRY_FINISH_ENTERED;
		return (0);
	case VMX_NESTED_HARDWARE_REJECTION:
		if (rejection == NULL)
			return (EINVAL);
		candidate = report->rejection;
		error = vmx_nested_hardware_entry_reject(runtime, id, ops,
		    arg);
		event_ops_snapshot.abort(event_arg);
		if (error != 0)
			return (error);
		*rejection = candidate;
		*completion =
		    VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK;
		return (0);
	case VMX_NESTED_HARDWARE_L0_FAILURE:
		error = vmx_nested_hardware_entry_rollback(runtime, id, ops,
		    arg);
		event_ops_snapshot.abort(event_arg);
		if (error != 0)
			return (error);
		*completion =
		    VMX_NESTED_HARDWARE_ENTRY_FINISH_UNENTERED_ROLLED_BACK;
		return (EIO);
	}
	return (EINVAL);
}
