/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_FAULT_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_FAULT_H_

#include "vmx_nested_types.h"

struct vmx_nested_ept_result;

enum vmx_nested_ept_fault_action {
	VMX_NESTED_EPT_FAULT_POPULATE = 0,
	VMX_NESTED_EPT_FAULT_REFLECT_VIOLATION,
	VMX_NESTED_EPT_FAULT_REFLECT_MISCONFIGURATION,
};

struct vmx_nested_ept_fault_input {
	const struct vmx_nested_ept_result *result;
	uint64_t	l2_gpa;
	bool		linear_address_valid;
	bool		final_translation;
	bool		nmi_unblocking_due_to_iret;
	bool		mode_based_execute;
	bool		user_mode;
	bool		advanced_exit_information;
	bool		guest_page_writable;
	bool		guest_page_execute_disable;
};

struct vmx_nested_ept_fault_plan {
	enum vmx_nested_ept_fault_action action;
	uint64_t	l2_page;
	uint64_t	l1_page;
	uint64_t	exit_qualification;
	uint8_t		permissions;
	bool		mode_based_execute;
};

int	vmx_nested_ept_fault_plan(
	    const struct vmx_nested_ept_fault_input *,
	    struct vmx_nested_ept_fault_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_FAULT_H_ */
