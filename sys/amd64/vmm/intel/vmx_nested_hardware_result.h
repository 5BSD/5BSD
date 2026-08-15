/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_HARDWARE_RESULT_H_
#define	_VMM_INTEL_VMX_NESTED_HARDWARE_RESULT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_vmentry.h"

struct vmx_nested_exit_information;

enum vmx_nested_hardware_report {
	VMX_NESTED_HARDWARE_REPORT_VMEXIT = 0,
	VMX_NESTED_HARDWARE_REPORT_VMFAIL_VALID,
	VMX_NESTED_HARDWARE_REPORT_VMFAIL_INVALID,
	VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK,
};

enum vmx_nested_hardware_disposition {
	VMX_NESTED_HARDWARE_L2_EXIT = 0,
	VMX_NESTED_HARDWARE_REJECTION,
	VMX_NESTED_HARDWARE_L0_FAILURE,
};

struct vmx_nested_hardware_report_input {
	enum vmx_nested_hardware_report report;
	uint32_t	exit_reason;
	uint64_t	exit_qualification;
	uint32_t	exit_instruction_length;
	uint32_t	instruction_error;
};

struct vmx_nested_hardware_report_result {
	enum vmx_nested_hardware_disposition disposition;
	struct vmx_nested_vmentry_result rejection;
	bool		commit_launch;
};

int	vmx_nested_hardware_report_prepare(
	    enum vmx_nested_hardware_report,
	    const struct vmx_nested_exit_information *, uint32_t,
	    struct vmx_nested_hardware_report_input *);
int	vmx_nested_hardware_report_classify(
	    const struct vmx_nested_hardware_report_input *,
	    struct vmx_nested_hardware_report_result *);
int	vmx_nested_hardware_report_result_validate(
	    const struct vmx_nested_hardware_report_result *);

#endif /* _VMM_INTEL_VMX_NESTED_HARDWARE_RESULT_H_ */
