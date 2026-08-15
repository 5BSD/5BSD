/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EXIT_CAPTURE_H_
#define	_VMM_INTEL_VMX_NESTED_EXIT_CAPTURE_H_

#include <sys/types.h>

struct vmx_nested_exit_information;

/*
 * Abstract exit fields keep the independently testable capture transaction
 * separate from Intel VMCS encodings and the privileged VMREAD instruction.
 */
enum vmx_nested_exit_capture_field {
	VMX_NESTED_EXIT_CAPTURE_QUALIFICATION = 0,
	VMX_NESTED_EXIT_CAPTURE_GUEST_LINEAR_ADDRESS,
	VMX_NESTED_EXIT_CAPTURE_GUEST_PHYSICAL_ADDRESS,
	VMX_NESTED_EXIT_CAPTURE_REASON,
	VMX_NESTED_EXIT_CAPTURE_INTERRUPTION_INFO,
	VMX_NESTED_EXIT_CAPTURE_INTERRUPTION_ERROR,
	VMX_NESTED_EXIT_CAPTURE_IDT_VECTORING_INFO,
	VMX_NESTED_EXIT_CAPTURE_IDT_VECTORING_ERROR,
	VMX_NESTED_EXIT_CAPTURE_INSTRUCTION_LENGTH,
	VMX_NESTED_EXIT_CAPTURE_INSTRUCTION_INFO,
	VMX_NESTED_EXIT_CAPTURE_ENTRY_INTERRUPTION_INFO,
	VMX_NESTED_EXIT_CAPTURE_FIELD_COUNT,
};

struct vmx_nested_exit_capture_ops {
	int	(*read)(void *, enum vmx_nested_exit_capture_field, uint64_t *);
};

int	vmx_nested_exit_capture(
	    const struct vmx_nested_exit_capture_ops *, void *,
	    struct vmx_nested_exit_information *);

#endif /* _VMM_INTEL_VMX_NESTED_EXIT_CAPTURE_H_ */
