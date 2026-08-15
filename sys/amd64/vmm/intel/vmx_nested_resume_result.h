/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_RESUME_RESULT_H_
#define	_VMM_INTEL_VMX_NESTED_RESUME_RESULT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_hardware_result.h"
#include "vmx_nested_reflect.h"

enum vmx_nested_resume_disposition {
	VMX_NESTED_RESUME_ENTERED_EXIT = 0,
	VMX_NESTED_RESUME_REFLECT_FAILED_ENTRY,
	VMX_NESTED_RESUME_L0_FAILURE,
};

struct vmx_nested_resume_result {
	enum vmx_nested_resume_disposition disposition;
	struct vmx_nested_exit_information failed_entry;
	bool commit_event;
};

/*
 * Classify a hardware report for an L0 continuation that is resuming L2.
 * The runtime VMCS02 may be freshly rebuilt and therefore clear, or it may
 * still be launched; its separate launch owner selects the actual hardware
 * instruction.  Raw VMfail belongs to L0 and must never be converted into
 * the architectural result of L1's earlier VMLAUNCH/VMRESUME instruction.
 */
int	vmx_nested_resume_report_classify(
	    const struct vmx_nested_hardware_report_input *,
	    const struct vmx_nested_exit_information *,
	    struct vmx_nested_resume_result *);

#endif /* _VMM_INTEL_VMX_NESTED_RESUME_RESULT_H_ */
