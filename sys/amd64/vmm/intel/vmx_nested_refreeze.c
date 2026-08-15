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

#include "vmx_nested_refreeze.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_refreeze_mutable_overlap(
    struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime)
{

	return (vmx_nested_state_ranges_overlap(staged, sizeof(*staged),
	    continuation, continuation == NULL ? 0 : sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged), runtime,
	    runtime == NULL ? 0 : sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    continuation == NULL ? 0 : sizeof(*continuation), runtime,
	    runtime == NULL ? 0 : sizeof(*runtime)));
}

static bool
nvmx_refreeze_mutable_overlaps_retained(
    struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime, const void *retained,
    size_t retained_length)
{

	return (vmx_nested_state_ranges_overlap(staged, sizeof(*staged),
	    retained, retained_length) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    continuation == NULL ? 0 : sizeof(*continuation), retained,
	    retained_length) ||
	    vmx_nested_state_ranges_overlap(runtime,
	    runtime == NULL ? 0 : sizeof(*runtime), retained,
	    retained_length));
}

static bool
nvmx_refreeze_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (vmx_nested_vmcs02_id_equal(a, b));
}

int
vmx_nested_refreeze_request_value_validate(
    const struct vmx_nested_refreeze_request *request)
{
	struct vmx_nested_late_entry zero;

	if (request == NULL || !vmx_nested_vmcs02_id_valid(&request->id) ||
	    request->portable_generation == 0 ||
	    request->resource_generation == 0 ||
	    request->purpose < VMX_NESTED_REFREEZE_RETRY ||
	    request->purpose > VMX_NESTED_REFREEZE_LATE_ENTRY)
		return (EINVAL);
	memset(&zero, 0, sizeof(zero));
	if (request->purpose == VMX_NESTED_REFREEZE_RETRY)
		return (vmx_nested_late_entry_equal(&request->late_entry,
		    &zero) ? 0 : EINVAL);
	if (vmx_nested_late_entry_validate_request(
	    &request->late_entry) != 0 ||
	    !nvmx_refreeze_id_equal(&request->id,
	    &request->late_entry.id) ||
	    request->portable_generation !=
	    request->late_entry.portable_generation)
		return (EINVAL);
	return (0);
}

static int
nvmx_refreeze_quarantine(
    struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{

	staged->state = VMX_NESTED_REFREEZE_POISONED;
	if (vmx_nested_l0_continuation_quarantine_hot(continuation, runtime,
	    id) != 0)
		return (EPROTO);
	return (EIO);
}

static int
nvmx_refreeze_validate(
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    uint64_t resource_generation)
{
	const struct vmx_nested_vmcs02_id *id;

	if (continuation == NULL || runtime == NULL || plan == NULL ||
	    portable == NULL || resource_generation == 0)
		return (EINVAL);
	id = &plan->id;
	if (plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY ||
	    !nvmx_refreeze_id_equal(&plan->image.id, id) ||
	    vmx_nested_l2_portable_validate(portable) != 0 ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    continuation->completion != VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    continuation->portable_generation == 0 ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    runtime->entry_msr_count != 0 || runtime->rollback_failed ||
	    runtime->resource_generation == 0)
		return (EPROTO);
	if (!nvmx_refreeze_id_equal(&portable->id, id) ||
	    continuation->portable_generation !=
	    portable->portable_generation ||
	    !nvmx_refreeze_id_equal(&continuation->id, id) ||
	    runtime->resource_generation != resource_generation ||
	    !nvmx_refreeze_id_equal(&runtime->id, id))
		return (ESTALE);
	return (0);
}

void
vmx_nested_refreeze_staged_init(struct vmx_nested_refreeze_staged *staged)
{

	if (staged != NULL)
		memset(staged, 0, sizeof(*staged));
}

static int
nvmx_refreeze_prepare_hot(struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    uint64_t resource_generation,
    enum vmx_nested_refreeze_purpose purpose,
    const struct vmx_nested_late_entry *late_entry,
    const struct vmx_nested_refreeze_hot_ops *ops, void *arg)
{
	struct vmx_nested_refreeze_hot_ops ops_snapshot;
	bool complete;
	int error;

	if (staged == NULL || ops == NULL || ops->provider_id == 0 ||
	    ops->detach_hot == NULL ||
	    staged->state != VMX_NESTED_REFREEZE_IDLE)
		return (EINVAL);
	if (nvmx_refreeze_mutable_overlap(staged, continuation, runtime) ||
	    nvmx_refreeze_mutable_overlaps_retained(staged, continuation,
	    runtime, plan, plan == NULL ? 0 : sizeof(*plan)) ||
	    nvmx_refreeze_mutable_overlaps_retained(staged, continuation,
	    runtime, portable, portable == NULL ? 0 : sizeof(*portable)) ||
	    nvmx_refreeze_mutable_overlaps_retained(staged, continuation,
	    runtime, late_entry, late_entry == NULL ? 0 :
	    sizeof(*late_entry)) ||
	    nvmx_refreeze_mutable_overlaps_retained(staged, continuation,
	    runtime, ops, sizeof(*ops)))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	error = nvmx_refreeze_validate(continuation, runtime, plan, portable,
	    resource_generation);
	if (error != 0)
		return (error);
	if (purpose < VMX_NESTED_REFREEZE_RETRY ||
	    purpose > VMX_NESTED_REFREEZE_LATE_ENTRY ||
	    (purpose == VMX_NESTED_REFREEZE_RETRY &&
	    late_entry != NULL))
		return (EINVAL);
	if (purpose == VMX_NESTED_REFREEZE_LATE_ENTRY) {
		if (late_entry == NULL)
			return (EINVAL);
		error = vmx_nested_late_entry_validate(late_entry, plan,
		    portable);
		if (error != 0)
			return (error);
	}
	complete = false;
	error = ops->detach_hot(arg, &plan->id, resource_generation,
	    &complete);
	if (error != 0) {
		if (complete)
			return (error < 0 ? EPROTO : error);
		return (nvmx_refreeze_quarantine(staged, continuation, runtime,
		    &plan->id));
	}
	if (!complete)
		return (nvmx_refreeze_quarantine(staged, continuation, runtime,
		    &plan->id));
	staged->id = plan->id;
	staged->portable_generation = portable->portable_generation;
	staged->resource_generation = resource_generation;
	staged->provider_id = ops->provider_id;
	staged->purpose = purpose;
	if (late_entry != NULL)
		staged->late_entry = *late_entry;
	staged->state = VMX_NESTED_REFREEZE_DETACHED;
	return (0);
}

int
vmx_nested_refreeze_prepare_hot(struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    uint64_t resource_generation,
    const struct vmx_nested_refreeze_hot_ops *ops, void *arg)
{

	return (nvmx_refreeze_prepare_hot(staged, continuation, runtime, plan,
	    portable, resource_generation, VMX_NESTED_REFREEZE_RETRY, NULL,
	    ops, arg));
}

int
vmx_nested_refreeze_prepare_late_entry_hot(
    struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    uint64_t resource_generation,
    const struct vmx_nested_late_entry *late_entry,
    const struct vmx_nested_refreeze_hot_ops *ops, void *arg)
{

	return (nvmx_refreeze_prepare_hot(staged, continuation, runtime, plan,
	    portable, resource_generation, VMX_NESTED_REFREEZE_LATE_ENTRY,
	    late_entry, ops, arg));
}

int
vmx_nested_refreeze_commit_frozen(
    struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_refreeze_frozen_ops *ops, void *arg)
{
	struct vmx_nested_refreeze_frozen_ops ops_snapshot;
	bool complete;
	int error;

	if (staged == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL || ops == NULL || ops->provider_id == 0 ||
	    ops->release_resources == NULL ||
	    staged->state != VMX_NESTED_REFREEZE_DETACHED ||
	    staged->portable_generation == 0 ||
	    staged->resource_generation == 0 ||
	    staged->purpose < VMX_NESTED_REFREEZE_RETRY ||
	    staged->purpose > VMX_NESTED_REFREEZE_LATE_ENTRY)
		return (EINVAL);
	if (nvmx_refreeze_mutable_overlap(staged, continuation, runtime) ||
	    nvmx_refreeze_mutable_overlaps_retained(staged, continuation,
	    runtime, portable, sizeof(*portable)) ||
	    nvmx_refreeze_mutable_overlaps_retained(staged, continuation,
	    runtime, ops, sizeof(*ops)))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	if (ops->provider_id != staged->provider_id)
		return (ESTALE);
	if (vmx_nested_l2_portable_validate(portable) != 0 ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    vmx_nested_entry_runtime_validate(runtime) != 0)
		return (EPROTO);
	if (continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    continuation->completion !=
	    VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT ||
	    runtime->entry_msr_count != 0 || runtime->rollback_failed)
		return (EPROTO);
	if (!nvmx_refreeze_id_equal(&portable->id, &staged->id) ||
	    !nvmx_refreeze_id_equal(&continuation->id, &staged->id) ||
	    !nvmx_refreeze_id_equal(&runtime->id, &staged->id) ||
	    portable->portable_generation !=
	    staged->portable_generation ||
	    continuation->portable_generation !=
	    staged->portable_generation ||
	    runtime->resource_generation != staged->resource_generation)
		return (ESTALE);
	if (staged->purpose == VMX_NESTED_REFREEZE_LATE_ENTRY &&
	    (vmx_nested_late_entry_validate_request(
	    &staged->late_entry) != 0 ||
	    !nvmx_refreeze_id_equal(&staged->id,
	    &staged->late_entry.id) ||
	    staged->portable_generation !=
	    staged->late_entry.portable_generation))
		return (EPROTO);

	complete = false;
	error = ops->release_resources(arg, &staged->id,
	    staged->resource_generation, &complete);
	if (error != 0)
		return (complete ? (error < 0 ? EPROTO : error) :
		    nvmx_refreeze_quarantine(staged, continuation, runtime,
		    &staged->id));
	if (!complete)
		return (nvmx_refreeze_quarantine(staged, continuation, runtime,
		    &staged->id));
	if (staged->purpose == VMX_NESTED_REFREEZE_RETRY)
		error = vmx_nested_l0_continuation_refreeze_unentered(
		    continuation, runtime, &staged->id,
		    staged->portable_generation);
	else
		error = vmx_nested_l0_continuation_refreeze_late_entry(
		    continuation, runtime, &staged->id,
		    staged->portable_generation);
	if (error != 0)
		return (nvmx_refreeze_quarantine(staged, continuation, runtime,
		    &staged->id));
	vmx_nested_refreeze_staged_init(staged);
	return (0);
}

int
vmx_nested_refreeze_staged_reset(
    struct vmx_nested_refreeze_staged *staged, bool hardware_recovered)
{

	if (staged == NULL ||
	    staged->state != VMX_NESTED_REFREEZE_POISONED ||
	    !hardware_recovered)
		return (EINVAL);
	vmx_nested_refreeze_staged_init(staged);
	return (0);
}

int
vmx_nested_refreeze_request_build(
    const struct vmx_nested_refreeze_staged *staged,
    struct vmx_nested_refreeze_request *request)
{
	struct vmx_nested_refreeze_request candidate;
	int error;

	if (staged == NULL || request == NULL ||
	    staged->state != VMX_NESTED_REFREEZE_DETACHED ||
	    staged->portable_generation == 0 ||
	    staged->resource_generation == 0 || staged->provider_id == 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(request, sizeof(*request), staged,
	    sizeof(*staged)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = staged->id;
	candidate.portable_generation = staged->portable_generation;
	candidate.resource_generation = staged->resource_generation;
	candidate.purpose = staged->purpose;
	candidate.late_entry = staged->late_entry;
	error = vmx_nested_refreeze_request_value_validate(&candidate);
	if (error != 0)
		return (error);
	*request = candidate;
	return (0);
}

int
vmx_nested_refreeze_request_validate(
    const struct vmx_nested_refreeze_staged *staged,
    const struct vmx_nested_refreeze_request *request)
{

	if (staged == NULL || request == NULL ||
	    staged->state != VMX_NESTED_REFREEZE_DETACHED)
		return (EINVAL);
	if (vmx_nested_refreeze_request_value_validate(request) != 0)
		return (EINVAL);
	if (!nvmx_refreeze_id_equal(&staged->id, &request->id) ||
	    staged->portable_generation != request->portable_generation ||
	    staged->resource_generation != request->resource_generation ||
	    staged->purpose != request->purpose ||
	    !vmx_nested_late_entry_equal(&staged->late_entry,
	    &request->late_entry))
		return (ESTALE);
	return (0);
}
