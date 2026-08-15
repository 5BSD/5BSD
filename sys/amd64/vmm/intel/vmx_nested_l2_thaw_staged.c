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

#include "vmx_nested_caps.h"
#include "vmx_nested_l2_thaw_staged.h"
#include "vmx_nested_state_range.h"

static int
nvmxts_plan(const struct vmx_nested_l2_thaw_input *input,
    int (*rebind)(void *, const struct vmx_nested_l2_portable_state *,
    const struct vmx_nested_vmcs02_plan *,
    struct vmx_nested_vmcs02_plan *), void *arg,
    struct vmx_nested_vmcs02_plan *plan)
{
	struct vmx_nested_vmcs02_plan candidate;
	int error;

	if (input == NULL || input->portable == NULL ||
	    input->capabilities == NULL || input->frozen_plan == NULL ||
	    rebind == NULL || plan == NULL)
		return (EINVAL);
	error = vmx_nested_l2_portable_apply(input->portable,
	    input->capabilities, input->frozen_plan, &candidate);
	if (error != 0)
		return (error);
	error = rebind(arg, input->portable, &candidate, &candidate);
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	if (candidate.vmentry.disposition !=
	    VMX_NESTED_VMENTRY_READY ||
	    !vmx_nested_vmcs02_id_equal(&candidate.id,
	    &input->portable->id) ||
	    !vmx_nested_vmcs02_id_equal(&candidate.image.id,
	    &input->portable->id) ||
	    !vmx_nested_guest_control_state_equal(
	    &candidate.image.l2_control,
	    &input->portable->runtime.control) ||
	    !vmx_nested_guest_arch_state_equal(&candidate.image.l2_arch,
	    &input->portable->runtime.arch) ||
	    !vmx_nested_pdpte_state_equal(&candidate.image.pdpte,
	    &input->portable->pdpte) ||
	    candidate.image.entry_intr_info !=
	    input->portable->entry_intr_info ||
	    candidate.image.entry_exception_error !=
	    input->portable->entry_exception_error ||
	    candidate.image.entry_instruction_length !=
	    input->portable->entry_instruction_length)
		return (EPROTO);
	*plan = candidate;
	return (0);
}

void
vmx_nested_l2_thaw_staged_init(
    struct vmx_nested_l2_thaw_staged *staged)
{

	if (staged != NULL)
		memset(staged, 0, sizeof(*staged));
}

int
vmx_nested_l2_thaw_staged_prepare(
    struct vmx_nested_l2_thaw_staged *staged,
    const struct vmx_nested_l2_thaw_input *input,
    const struct vmx_nested_l2_thaw_frozen_ops *ops, void *arg)
{
	struct vmx_nested_l2_thaw_frozen_ops ops_snapshot;
	struct vmx_nested_vmcs02_plan candidate;
	uint64_t generation;
	bool complete;
	int error;

	if (staged == NULL || ops == NULL || ops->provider_id == 0 ||
	    ops->rebind_runtime == NULL || ops->acquire_resources == NULL ||
	    ops->release_resources == NULL ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged), input,
	    input == NULL ? 0 : sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged), ops,
	    sizeof(*ops)) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_IDLE)
		return (EINVAL);
	if (input != NULL &&
	    (vmx_nested_state_ranges_overlap(staged, sizeof(*staged),
	    input->portable, input->portable == NULL ? 0 :
	    sizeof(*input->portable)) ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged),
	    input->capabilities, input->capabilities == NULL ? 0 :
	    sizeof(*input->capabilities)) ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged),
	    input->frozen_plan, input->frozen_plan == NULL ? 0 :
	    sizeof(*input->frozen_plan))))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	error = nvmxts_plan(input, ops->rebind_runtime, arg, &candidate);
	if (error != 0)
		return (error);
	generation = 0;
	complete = false;
	error = ops->acquire_resources(arg, &candidate, &generation,
	    &complete);
	if (error != 0) {
		if (complete)
			return (error < 0 ? EPROTO : error);
		staged->plan = candidate;
		staged->resource_generation = generation;
		staged->frozen_provider_id = ops->provider_id;
		staged->state = VMX_NESTED_L2_THAW_STAGED_POISONED;
		return (EIO);
	}
	if (generation == 0) {
		staged->plan = candidate;
		staged->frozen_provider_id = ops->provider_id;
		staged->state = VMX_NESTED_L2_THAW_STAGED_POISONED;
		return (EPROTO);
	}
	staged->plan = candidate;
	staged->software = input->portable->software_msrs;
	staged->resource_generation = generation;
	staged->frozen_provider_id = ops->provider_id;
	staged->state = VMX_NESTED_L2_THAW_STAGED_PREPARED;
	return (0);
}

int
vmx_nested_l2_thaw_staged_commit_hot(
    struct vmx_nested_l2_thaw_staged *staged,
    const struct vmx_nested_l2_thaw_hot_ops *ops, void *arg)
{
	struct vmx_nested_l2_thaw_hot_ops ops_snapshot;
	bool complete, rollback_complete;
	int error, rollback_error;

	if (staged == NULL || ops == NULL || ops->install_l2 == NULL ||
	    ops->program_vmcs02 == NULL || ops->rollback_hot == NULL ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged), ops,
	    sizeof(*ops)) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_PREPARED ||
	    staged->resource_generation == 0)
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	staged->state = VMX_NESTED_L2_THAW_STAGED_APPLYING;
	complete = false;
	error = ops->install_l2(arg, &staged->plan.id, &staged->software,
	    &complete);
	if (error != 0) {
		staged->state = complete ?
		    VMX_NESTED_L2_THAW_STAGED_PREPARED :
		    VMX_NESTED_L2_THAW_STAGED_POISONED;
		return (complete ? (error < 0 ? EPROTO : error) : EIO);
	}
	complete = false;
	error = ops->program_vmcs02(arg, &staged->plan,
	    staged->resource_generation, &complete);
	if (error == 0) {
		staged->state = VMX_NESTED_L2_THAW_STAGED_READY;
		return (0);
	}
	rollback_complete = false;
	rollback_error = ops->rollback_hot(arg, &staged->plan.id,
	    staged->resource_generation, &rollback_complete);
	if (!complete || rollback_error != 0 || !rollback_complete) {
		staged->state = VMX_NESTED_L2_THAW_STAGED_POISONED;
		return (EIO);
	}
	staged->state = VMX_NESTED_L2_THAW_STAGED_PREPARED;
	return (error < 0 ? EPROTO : error);
}

int
vmx_nested_l2_thaw_staged_take(
    struct vmx_nested_l2_thaw_staged *staged,
    struct vmx_nested_vmcs02_plan *plan, uint64_t *resource_generation)
{

	if (staged == NULL || plan == NULL || resource_generation == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), staged,
	    sizeof(*staged)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), staged, sizeof(*staged)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    resource_generation, sizeof(*resource_generation)) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_READY)
		return (EINVAL);
	*plan = staged->plan;
	*resource_generation = staged->resource_generation;
	vmx_nested_l2_thaw_staged_init(staged);
	return (0);
}

int
vmx_nested_l2_thaw_staged_cancel(
    struct vmx_nested_l2_thaw_staged *staged,
    const struct vmx_nested_l2_thaw_frozen_ops *ops, void *arg)
{
	struct vmx_nested_l2_thaw_frozen_ops ops_snapshot;
	bool complete;
	int error;

	if (staged == NULL || ops == NULL || ops->provider_id == 0 ||
	    ops->release_resources == NULL ||
	    vmx_nested_state_ranges_overlap(staged, sizeof(*staged), ops,
	    sizeof(*ops)) ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_PREPARED)
		return (EINVAL);
	if (ops->provider_id != staged->frozen_provider_id)
		return (ESTALE);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	complete = false;
	error = ops->release_resources(arg, &staged->plan.id,
	    staged->resource_generation, &complete);
	if (complete) {
		vmx_nested_l2_thaw_staged_init(staged);
		return (error < 0 ? EPROTO : error);
	}
	staged->state = VMX_NESTED_L2_THAW_STAGED_POISONED;
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	return (EIO);
}

int
vmx_nested_l2_thaw_staged_reset(
    struct vmx_nested_l2_thaw_staged *staged, bool hardware_recovered)
{

	if (staged == NULL ||
	    staged->state != VMX_NESTED_L2_THAW_STAGED_POISONED ||
	    !hardware_recovered)
		return (EINVAL);
	vmx_nested_l2_thaw_staged_init(staged);
	return (0);
}
