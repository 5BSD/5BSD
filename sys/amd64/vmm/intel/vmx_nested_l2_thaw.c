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
#include "vmx_nested_l2_thaw.h"
#include "vmx_nested_state_range.h"

static int
nvmx_l2_thaw_rollback(const struct vmx_nested_l2_thaw_ops *ops, void *arg,
    const struct vmx_nested_vmcs02_id *id, uint64_t resource_generation,
    bool *rollback_complete)
{
	bool complete;
	int error;

	complete = false;
	error = ops->rollback_cold(arg, id, resource_generation, &complete);
	*rollback_complete = error == 0 && complete;
	return (*rollback_complete ? 0 : EIO);
}

int
vmx_nested_l2_thaw(const struct vmx_nested_l2_thaw_input *input,
    const struct vmx_nested_l2_thaw_ops *ops, void *arg,
    struct vmx_nested_vmcs02_plan *plan, uint64_t *resource_generation,
    bool *rollback_complete)
{
	struct vmx_nested_l2_thaw_ops ops_snapshot;
	struct vmx_nested_vmcs02_plan candidate;
	uint64_t generation;
	bool complete;
	int error, rollback_error;

	if (input == NULL || ops == NULL || plan == NULL ||
	    resource_generation == NULL || input->portable == NULL ||
	    input->capabilities == NULL ||
	    input->frozen_plan == NULL ||
	    ops->rebind_runtime == NULL ||
	    ops->acquire_resources == NULL || ops->install_l2 == NULL ||
	    ops->program_vmcs02 == NULL || ops->rollback_cold == NULL ||
	    rollback_complete == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->portable, sizeof(*input->portable)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->capabilities, sizeof(*input->capabilities)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->frozen_plan, sizeof(*input->frozen_plan)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), input, sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), input->portable,
	    sizeof(*input->portable)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), input->capabilities,
	    sizeof(*input->capabilities)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), input->frozen_plan,
	    sizeof(*input->frozen_plan)) ||
	    vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input, sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input->portable,
	    sizeof(*input->portable)) ||
	    vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input->capabilities,
	    sizeof(*input->capabilities)) ||
	    vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input->frozen_plan,
	    sizeof(*input->frozen_plan)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    resource_generation, sizeof(*resource_generation)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    rollback_complete, sizeof(*rollback_complete)) ||
	    vmx_nested_state_ranges_overlap(resource_generation,
	    sizeof(*resource_generation), rollback_complete,
	    sizeof(*rollback_complete)))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	*rollback_complete = true;
	error = vmx_nested_l2_portable_apply(input->portable,
	    input->capabilities,
	    input->frozen_plan, &candidate);
	if (error != 0)
		return (error);
	error = ops->rebind_runtime(arg, input->portable,
	    &candidate, &candidate);
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	/*
	 * A platform adapter may alter only runtime-derived fields.  Require
	 * the complete portable architectural overlay to survive rebinding.
	 */
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

	generation = 0;
	complete = false;
	error = ops->acquire_resources(arg, &candidate, &generation,
	    &complete);
	if (error != 0) {
		*rollback_complete = complete;
		return (error < 0 ? EPROTO : error);
	}
	if (generation == 0) {
		*rollback_complete = false;
		return (EPROTO);
	}
	complete = false;
	error = ops->install_l2(arg, &candidate.id,
	    &input->portable->software_msrs, &complete);
	if (error != 0) {
		rollback_error = nvmx_l2_thaw_rollback(ops, arg,
		    &candidate.id, generation, rollback_complete);
		if (!complete) {
			*rollback_complete = false;
			return (EIO);
		}
		return (rollback_error != 0 ? rollback_error :
		    (error < 0 ? EPROTO : error));
	}
	complete = false;
	error = ops->program_vmcs02(arg, &candidate, generation, &complete);
	if (error != 0) {
		rollback_error = nvmx_l2_thaw_rollback(ops, arg,
		    &candidate.id, generation, rollback_complete);
		if (!complete) {
			*rollback_complete = false;
			return (EIO);
		}
		return (rollback_error != 0 ? rollback_error :
		    (error < 0 ? EPROTO : error));
	}

	*plan = candidate;
	*resource_generation = generation;
	*rollback_complete = true;
	return (0);
}
