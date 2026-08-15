/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_ept.h"
#include "vmx_nested_ept_fault.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_ept_fault_plan(
    const struct vmx_nested_ept_fault_input *input,
    struct vmx_nested_ept_fault_plan *plan)
{
	struct vmx_nested_ept_fault_plan candidate;
	struct vmx_nested_ept_exit_provenance provenance;
	const struct vmx_nested_ept_result *result;
	uint8_t effective_access;
	uint64_t qualification;
	int error;

	if (input == NULL || plan == NULL || input->result == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input->result,
	    sizeof(*input->result)))
		return (EINVAL);
	if (!input->advanced_exit_information &&
	    (input->guest_page_writable ||
	    input->guest_page_execute_disable))
		return (EINVAL);
	result = input->result;
	if ((result->permissions & ~(VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE |
	    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE)) != 0 ||
	    (!input->mode_based_execute &&
	    (result->permissions &
	    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE) != 0))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	memset(&provenance, 0, sizeof(provenance));
	candidate.mode_based_execute = input->mode_based_execute;
	switch (result->outcome) {
	case VMX_NESTED_EPT_TRANSLATED:
		if (result->access == 0 ||
		    (result->access & ~(VMX_NESTED_EPT_ACCESS_READ |
		    VMX_NESTED_EPT_ACCESS_WRITE |
		    VMX_NESTED_EPT_ACCESS_EXECUTE)) != 0)
			return (EINVAL);
		effective_access = result->access;
		if (input->mode_based_execute && input->user_mode &&
		    (effective_access & VMX_NESTED_EPT_ACCESS_EXECUTE) != 0) {
			effective_access &=
			    ~VMX_NESTED_EPT_ACCESS_EXECUTE;
			effective_access |=
			    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE;
		}
		if ((result->permissions & effective_access) !=
		    effective_access)
			return (EINVAL);
		if (result->page_shift != 12 && result->page_shift != 21 &&
		    result->page_shift != 30)
			return (EINVAL);
		/*
		 * Every EPT leaf preserves at least the 4-KiB page offset.
		 * Refuse a malformed handoff before it can alias a different
		 * byte of L1 memory.
		 */
		if ((input->l2_gpa & PAGE_MASK) !=
		    (result->translated_address & PAGE_MASK))
			return (EINVAL);
		candidate.action = VMX_NESTED_EPT_FAULT_POPULATE;
		candidate.l2_page = trunc_page(input->l2_gpa);
		candidate.l1_page =
		    trunc_page(result->translated_address);
		candidate.permissions = result->permissions;
		if (candidate.permissions == 0)
			return (EINVAL);
		break;
	case VMX_NESTED_EPT_VIOLATION:
		provenance.linear_address_valid =
		    input->linear_address_valid;
		provenance.final_translation = input->final_translation;
		provenance.nmi_unblocking_due_to_iret =
		    input->nmi_unblocking_due_to_iret;
		provenance.advanced_information =
		    input->advanced_exit_information;
		if (input->advanced_exit_information) {
			provenance.user_mode = input->user_mode;
			provenance.guest_page_writable =
			    input->guest_page_writable;
			provenance.guest_page_execute_disable =
			    input->guest_page_execute_disable;
		}
		error = vmx_nested_ept_exit_qualification(result, &provenance,
		    &qualification);
		if (error != 0)
			return (error);
		candidate.action =
		    VMX_NESTED_EPT_FAULT_REFLECT_VIOLATION;
		candidate.exit_qualification = qualification;
		break;
	case VMX_NESTED_EPT_MISCONFIGURATION:
		provenance.linear_address_valid =
		    input->linear_address_valid;
		provenance.final_translation = input->final_translation;
		provenance.nmi_unblocking_due_to_iret =
		    input->nmi_unblocking_due_to_iret;
		provenance.advanced_information =
		    input->advanced_exit_information;
		if (input->advanced_exit_information) {
			provenance.user_mode = input->user_mode;
			provenance.guest_page_writable =
			    input->guest_page_writable;
			provenance.guest_page_execute_disable =
			    input->guest_page_execute_disable;
		}
		error = vmx_nested_ept_exit_qualification(result, &provenance,
		    &qualification);
		if (error != 0 || qualification != 0)
			return (error != 0 ? error : EPROTO);
		candidate.action =
		    VMX_NESTED_EPT_FAULT_REFLECT_MISCONFIGURATION;
		break;
	default:
		return (EINVAL);
	}
	*plan = candidate;
	return (0);
}
