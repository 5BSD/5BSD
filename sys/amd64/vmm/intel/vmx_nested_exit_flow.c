/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#include "vmx_nested_exit_flow.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_exit_flow_prepare(
    const struct vmx_nested_exit_flow_input *input,
    enum vmx_nested_exit_flow_action *action)
{
	enum vmx_nested_exit_flow_action candidate;

	if (input == NULL || action == NULL ||
	    input->dispatch < VMX_NESTED_OUTER_EXIT_ROUTE ||
	    input->dispatch > VMX_NESTED_OUTER_EXIT_EPT_WALK ||
	    input->route < VMX_NESTED_EXIT_HANDLE_L0 ||
	    input->route > VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1 ||
	    input->l0_result < VMX_NESTED_L0_EXIT_NOT_RUN ||
	    input->l0_result > VMX_NESTED_L0_EXIT_USER)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(action, sizeof(*action), input,
	    sizeof(*input)))
		return (EINVAL);

	if (input->dispatch == VMX_NESTED_OUTER_EXIT_EPT_WALK) {
		if (input->l0_result != VMX_NESTED_L0_EXIT_NOT_RUN)
			return (EINVAL);
		candidate = VMX_NESTED_EXIT_FLOW_EPT_WALK;
	} else {
		switch (input->route) {
		case VMX_NESTED_EXIT_REFLECT_L1:
			if (input->l0_result !=
			    VMX_NESTED_L0_EXIT_NOT_RUN)
				return (EINVAL);
			candidate = VMX_NESTED_EXIT_FLOW_REFLECT;
			break;
		case VMX_NESTED_EXIT_HANDLE_L0:
			if (input->l0_result ==
			    VMX_NESTED_L0_EXIT_HANDLED)
				candidate =
				    VMX_NESTED_EXIT_FLOW_RESUME_HOT;
			else if (input->l0_result ==
			    VMX_NESTED_L0_EXIT_USER)
				candidate =
				    VMX_NESTED_EXIT_FLOW_FREEZE_RESUME;
			else
				return (EINVAL);
			break;
		case VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1:
			if (input->l0_result ==
			    VMX_NESTED_L0_EXIT_HANDLED)
				candidate =
				    VMX_NESTED_EXIT_FLOW_REFLECT;
			else if (input->l0_result ==
			    VMX_NESTED_L0_EXIT_USER)
				candidate =
				    VMX_NESTED_EXIT_FLOW_FREEZE_REFLECT;
			else
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
	}
	*action = candidate;
	return (0);
}
