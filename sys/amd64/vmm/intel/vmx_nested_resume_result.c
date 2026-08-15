/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_attempt.h"
#include "vmx_nested_resume_result.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_resume_report_classify(
    const struct vmx_nested_hardware_report_input *input,
    const struct vmx_nested_exit_information *exit,
    struct vmx_nested_resume_result *result)
{
	struct vmx_nested_attempt_plan plan;
	struct vmx_nested_resume_result candidate;
	int error;

	if (result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), exit,
	    sizeof(*exit)))
		return (EINVAL);
	error = vmx_nested_attempt_classify(VMX_NESTED_ATTEMPT_RESUME,
	    input, exit, &plan);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	switch (plan.action) {
	case VMX_NESTED_ATTEMPT_RESUMED_EXIT:
		candidate.disposition = VMX_NESTED_RESUME_ENTERED_EXIT;
		candidate.commit_event = plan.commit_event;
		break;
	case VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY:
		candidate.disposition =
		    VMX_NESTED_RESUME_REFLECT_FAILED_ENTRY;
		candidate.failed_entry = plan.exit;
		break;
	case VMX_NESTED_ATTEMPT_RESUMED_L0_FAILURE:
		candidate.disposition = VMX_NESTED_RESUME_L0_FAILURE;
		break;
	case VMX_NESTED_ATTEMPT_INITIAL_EXIT:
	case VMX_NESTED_ATTEMPT_INITIAL_REJECTION:
	case VMX_NESTED_ATTEMPT_INITIAL_L0_FAILURE:
		return (EPROTO);
	}
	*result = candidate;
	return (0);
}
