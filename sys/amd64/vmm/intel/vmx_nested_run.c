/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#include "vmx_nested_run.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_run_select(const struct vmx_nested_run_input *input,
    enum vmx_nested_run_target *target)
{
	enum vmx_nested_run_target candidate;

	if (input == NULL || target == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(target, sizeof(*target), input,
	    sizeof(*input)))
		return (EINVAL);
	if (input->rollback_failed ||
	    input->refreeze_state == VMX_NESTED_REFREEZE_POISONED)
		return (EIO);
	if (input->internal_pending) {
		*target = VMX_NESTED_RUN_INTERNAL;
		return (0);
	}

	if (input->context_phase == VMX_NESTED_CONTEXT_ROOT &&
	    input->runtime_state == VMX_NESTED_ENTRY_RUNTIME_IDLE &&
	    input->continuation_state ==
	    VMX_NESTED_L0_CONTINUATION_IDLE &&
	    input->thaw_state == VMX_NESTED_L2_THAW_STAGED_IDLE &&
	    input->refreeze_state == VMX_NESTED_REFREEZE_IDLE &&
	    !input->plan_valid && !input->thaw_resources_valid) {
		candidate = VMX_NESTED_RUN_L1;
	} else if (input->context_phase ==
	    VMX_NESTED_CONTEXT_ENTRY_PENDING &&
	    input->runtime_state == VMX_NESTED_ENTRY_RUNTIME_RESOURCES &&
	    input->continuation_state ==
	    VMX_NESTED_L0_CONTINUATION_IDLE &&
	    input->thaw_state == VMX_NESTED_L2_THAW_STAGED_IDLE &&
	    input->refreeze_state == VMX_NESTED_REFREEZE_IDLE &&
	    input->plan_valid && !input->thaw_resources_valid) {
		candidate = VMX_NESTED_RUN_L2_INITIAL;
	} else if (input->context_phase == VMX_NESTED_CONTEXT_GUEST &&
	    input->runtime_state ==
	    VMX_NESTED_ENTRY_RUNTIME_L0_THAWING &&
	    input->continuation_state ==
	    VMX_NESTED_L0_CONTINUATION_THAWING &&
	    input->thaw_state ==
	    VMX_NESTED_L2_THAW_STAGED_PREPARED &&
	    input->refreeze_state == VMX_NESTED_REFREEZE_IDLE &&
	    input->plan_valid && input->thaw_resources_valid) {
		candidate = VMX_NESTED_RUN_L2_RESUME;
	} else {
		return (EPROTO);
	}
	*target = candidate;
	return (0);
}

int
vmx_nested_run_unwind_select(
    const struct vmx_nested_run_unwind_input *input,
    enum vmx_nested_run_unwind_action *action)
{
	enum vmx_nested_run_unwind_action candidate;

	if (input == NULL || action == NULL ||
	    input->runtime_state < VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    input->runtime_state > VMX_NESTED_ENTRY_RUNTIME_ABORTED ||
	    input->continuation_state <
	    VMX_NESTED_L0_CONTINUATION_IDLE ||
	    input->continuation_state >
	    VMX_NESTED_L0_CONTINUATION_ABORTED)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(action, sizeof(*action), input,
	    sizeof(*input)))
		return (EINVAL);

	candidate = VMX_NESTED_RUN_UNWIND_FAIL_STOP;
	switch (input->runtime_state) {
	case VMX_NESTED_ENTRY_RUNTIME_RESOURCES:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_IDLE &&
		    !input->portable_valid && !input->detached)
			candidate = VMX_NESTED_RUN_UNWIND_CLEAN;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_L0_COLD:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_COLD &&
		    input->portable_valid && !input->detached)
			candidate = VMX_NESTED_RUN_UNWIND_CLEAN;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_L0_THAWING:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_THAWING &&
		    input->portable_valid && !input->detached)
			candidate = VMX_NESTED_RUN_UNWIND_CLEAN;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_VMCS02:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_IDLE &&
		    !input->portable_valid && !input->detached)
			candidate =
			    VMX_NESTED_RUN_UNWIND_ROLLBACK_INITIAL;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_GUEST:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_IDLE &&
		    !input->portable_valid && !input->detached)
			candidate = VMX_NESTED_RUN_UNWIND_DETACH_FATAL;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_L0_EXIT:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_HOT &&
		    !input->detached)
			candidate = input->portable_valid ?
			    VMX_NESTED_RUN_UNWIND_REFREEZE_UNENTERED :
			    VMX_NESTED_RUN_UNWIND_FREEZE_HOT;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_ABORTED:
		if (input->continuation_state ==
		    VMX_NESTED_L0_CONTINUATION_IDLE &&
		    !input->portable_valid && input->detached)
			candidate =
			    VMX_NESTED_RUN_UNWIND_ALREADY_DETACHED;
		break;
	case VMX_NESTED_ENTRY_RUNTIME_IDLE:
	case VMX_NESTED_ENTRY_RUNTIME_PREPARING:
	case VMX_NESTED_ENTRY_RUNTIME_MSRS:
	case VMX_NESTED_ENTRY_RUNTIME_L0_FREEZING:
	case VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED:
	case VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD:
	default:
		break;
	}
	*action = candidate;
	return (0);
}
