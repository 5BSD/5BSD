/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_instruction_publish.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_instruction_capture_publish(
    struct vmx_nested_context *context,
    const struct vmx_nested_instruction_capture_input *input,
    struct vmx_nested_instruction_capture_result *result,
    struct vmx_nested_instruction_handoff_id *id)
{
	struct vmx_nested_instruction_capture_input capture_input;
	struct vmx_nested_instruction_capture_result candidate;
	struct vmx_nested_instruction_handoff_id candidate_id;
	int error;

	if (context == NULL || input == NULL || result == NULL || id == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), context,
	    sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(id, sizeof(*id), context,
	    sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(id, sizeof(*id), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(id, sizeof(*id), result,
	    sizeof(*result)))
		return (EINVAL);

	/*
	 * The context, not the VM-exit adapter, owns virtual VMX operation.
	 * Use that state for permission/fault-priority checks and let the
	 * context publisher bind the same state to a fresh request ID.
	 */
	capture_input = *input;
	capture_input.machine = context->machine;
	error = vmx_nested_instruction_capture(&capture_input, &candidate);
	if (error != 0)
		return (error);
	memset(&candidate_id, 0, sizeof(candidate_id));
	if (candidate.disposition ==
	    VMX_NESTED_INSTRUCTION_CAPTURE_REQUEST) {
		error = vmx_nested_context_publish_instruction(context,
		    &candidate.request, &candidate_id);
		if (error != 0)
			return (error);
	}
	*result = candidate;
	*id = candidate_id;
	return (0);
}
