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
#include "vmx_nested_l2_freeze.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_l2_freeze_storage_valid(
    const struct vmx_nested_l2_freeze_input *input,
    const struct vmx_nested_l2_freeze_ops *ops,
    const struct vmx_nested_l2_portable_state *portable,
    const bool *rollback_complete)
{

	return (!vmx_nested_state_ranges_overlap(portable,
	    sizeof(*portable), rollback_complete, sizeof(*rollback_complete)) &&
	    !vmx_nested_state_ranges_overlap(portable, sizeof(*portable),
	    input, sizeof(*input)) &&
	    !vmx_nested_state_ranges_overlap(portable, sizeof(*portable),
	    ops, sizeof(*ops)) &&
	    !vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input, sizeof(*input)) &&
	    !vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), ops, sizeof(*ops)) &&
	    !vmx_nested_state_ranges_overlap(portable, sizeof(*portable),
	    input->executed_plan, sizeof(*input->executed_plan)) &&
	    !vmx_nested_state_ranges_overlap(portable, sizeof(*portable),
	    input->capabilities, sizeof(*input->capabilities)) &&
	    !vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input->executed_plan,
	    sizeof(*input->executed_plan)) &&
	    !vmx_nested_state_ranges_overlap(rollback_complete,
	    sizeof(*rollback_complete), input->capabilities,
	    sizeof(*input->capabilities)));
}

static int
nvmx_l2_freeze_rollback(const struct vmx_nested_l2_freeze_ops *ops,
    void *arg, const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    bool *rollback_complete)
{
	bool complete;
	int error;

	complete = false;
	error = ops->rollback_hot(arg, plan, portable, &complete);
	*rollback_complete = error == 0 && complete;
	return (*rollback_complete ? 0 : EIO);
}

int
vmx_nested_l2_freeze(const struct vmx_nested_l2_freeze_input *input,
    const struct vmx_nested_l2_freeze_ops *ops, void *arg,
    struct vmx_nested_l2_portable_state *portable,
    bool *rollback_complete)
{
	struct vmx_nested_l2_freeze_ops ops_snapshot;
	struct vmx_nested_l2_portable_input portable_input;
	struct vmx_nested_l2_portable_state candidate;
	struct vmx_nested_l2_capture_values captured;
	struct vmx_nested_software_msrs software;
	bool complete;
	int error, rollback_error;

	if (rollback_complete == NULL)
		return (EINVAL);
	if (input == NULL || ops == NULL || portable == NULL ||
	    input->executed_plan == NULL ||
	    input->capabilities == NULL ||
	    input->resource_generation == 0 ||
	    input->portable_generation == 0 ||
	    ops->capture_software == NULL || ops->detach == NULL ||
	    ops->install_l1 == NULL || ops->release_resources == NULL ||
	    ops->rollback_hot == NULL)
		return (EINVAL);
	if (!nvmx_l2_freeze_storage_valid(input, ops, portable,
	    rollback_complete))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	*rollback_complete = true;

	memset(&software, 0, sizeof(software));
	error = ops->capture_software(arg, &software);
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	memset(&captured, 0, sizeof(captured));
	complete = false;
	error = ops->detach(arg, input->executed_plan,
	    input->resource_generation, input->l1_virtual_tsc, &captured,
	    &complete);
	if (error != 0) {
		*rollback_complete = complete;
		return (error < 0 ? EPROTO : error);
	}

	memset(&portable_input, 0, sizeof(portable_input));
	portable_input.executed_plan = input->executed_plan;
	portable_input.capabilities = input->capabilities;
	portable_input.runtime = &captured.runtime;
	portable_input.software_msrs = &software;
	portable_input.exit = &captured.exit;
	portable_input.pdpte = &captured.pdpte;
	portable_input.preemption_timer = &captured.preemption_timer;
	portable_input.portable_generation = input->portable_generation;
	portable_input.entry_intr_info = captured.entry_intr_info;
	portable_input.entry_exception_error =
	    captured.entry_exception_error;
	portable_input.entry_instruction_length =
	    captured.entry_instruction_length;
	portable_input.guest_interrupt_status =
	    captured.guest_interrupt_status;
	portable_input.guest_interrupt_status_valid =
	    captured.guest_interrupt_status_valid;
	error = vmx_nested_l2_portable_capture(&portable_input, &candidate);
	if (error != 0) {
		/*
		 * Malformed hardware output cannot safely reconstruct L2: no
		 * validated rollback image exists after destructive detach.
		 */
		*rollback_complete = false;
		return (EPROTO);
	}

	complete = false;
	error = ops->install_l1(arg, &input->executed_plan->id, &complete);
	if (error != 0) {
		if (!complete) {
			*rollback_complete = false;
			return (EIO);
		}
		rollback_error = nvmx_l2_freeze_rollback(ops, arg,
		    input->executed_plan, &candidate, rollback_complete);
		return (rollback_error != 0 ? rollback_error :
		    (error < 0 ? EPROTO : error));
	}
	complete = false;
	error = ops->release_resources(arg, &input->executed_plan->id,
	    input->resource_generation, &complete);
	if (error != 0) {
		if (!complete) {
			*rollback_complete = false;
			return (EIO);
		}
		rollback_error = nvmx_l2_freeze_rollback(ops, arg,
		    input->executed_plan, &candidate, rollback_complete);
		return (rollback_error != 0 ? rollback_error :
		    (error < 0 ? EPROTO : error));
	}

	*portable = candidate;
	*rollback_complete = true;
	return (0);
}
