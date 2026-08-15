/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_hardware_result.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_state_range.h"

#define	NVMXHR_FAILED_VMENTRY	(UINT32_C(1) << 31)
#define	NVMXHR_BASIC_REASON_MASK	UINT32_C(0xffff)
#define	NVMXHR_MSR_LOAD_FAILURE	UINT32_C(34)
#define	NVMXHR_MACHINE_CHECK	UINT32_C(41)

static bool
nvmxhr_rejection_empty(const struct vmx_nested_vmentry_result *rejection)
{
	unsigned int i;

	if (rejection->disposition != VMX_NESTED_VMENTRY_READY ||
	    rejection->stage != VMX_NESTED_VMENTRY_STAGE_NONE ||
	    rejection->instruction_error != 0 || rejection->exit_reason != 0 ||
	    rejection->exit_qualification != 0 || rejection->detail != 0 ||
	    rejection->pdpte.active)
		return (false);
	for (i = 0; i < nitems(rejection->pdpte.value); i++) {
		if (rejection->pdpte.value[i] != 0)
			return (false);
	}
	return (true);
}

int
vmx_nested_hardware_report_result_validate(
    const struct vmx_nested_hardware_report_result *result)
{

	if (result == NULL ||
	    result->disposition < VMX_NESTED_HARDWARE_L2_EXIT ||
	    result->disposition > VMX_NESTED_HARDWARE_L0_FAILURE ||
	    result->commit_launch !=
	    (result->disposition == VMX_NESTED_HARDWARE_L2_EXIT))
		return (EINVAL);
	if (result->disposition == VMX_NESTED_HARDWARE_REJECTION)
		return (vmx_nested_vmentry_rejection_validate(
		    &result->rejection));
	return (nvmxhr_rejection_empty(&result->rejection) ? 0 : EPROTO);
}

int
vmx_nested_hardware_report_prepare(enum vmx_nested_hardware_report report,
    const struct vmx_nested_exit_information *exit,
    uint32_t instruction_error,
    struct vmx_nested_hardware_report_input *input)
{
	struct vmx_nested_hardware_report_input candidate;

	if (report < VMX_NESTED_HARDWARE_REPORT_VMEXIT ||
	    report > VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK ||
	    input == NULL ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), exit,
	    sizeof(*exit)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.report = report;
	switch (report) {
	case VMX_NESTED_HARDWARE_REPORT_VMEXIT:
		if (exit == NULL || instruction_error != 0)
			return (EINVAL);
		candidate.exit_reason = exit->exit_reason;
		candidate.exit_qualification = exit->exit_qualification;
		candidate.exit_instruction_length =
		    exit->exit_instruction_length;
		break;
	case VMX_NESTED_HARDWARE_REPORT_VMFAIL_VALID:
		if (exit != NULL || instruction_error == 0)
			return (EINVAL);
		candidate.instruction_error = instruction_error;
		break;
	case VMX_NESTED_HARDWARE_REPORT_VMFAIL_INVALID:
	case VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK:
		if (exit != NULL || instruction_error != 0)
			return (EINVAL);
		break;
	}
	*input = candidate;
	return (0);
}

int
vmx_nested_hardware_report_classify(
    const struct vmx_nested_hardware_report_input *input,
    struct vmx_nested_hardware_report_result *result)
{
	struct vmx_nested_hardware_report_result candidate;
	int error;

	if (input == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), input,
	    sizeof(*input)) ||
	    input->report < VMX_NESTED_HARDWARE_REPORT_VMEXIT ||
	    input->report > VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK)
		return (EINVAL);
	if ((input->report == VMX_NESTED_HARDWARE_REPORT_VMEXIT &&
	    input->instruction_error != 0) ||
	    (input->report != VMX_NESTED_HARDWARE_REPORT_VMEXIT &&
	    (input->exit_reason != 0 || input->exit_qualification != 0 ||
	    input->exit_instruction_length != 0)) ||
	    ((input->report ==
	    VMX_NESTED_HARDWARE_REPORT_VMFAIL_INVALID ||
	    input->report == VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK) &&
	    input->instruction_error != 0))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	switch (input->report) {
	case VMX_NESTED_HARDWARE_REPORT_VMEXIT:
		if ((input->exit_reason & NVMXHR_FAILED_VMENTRY) == 0) {
			candidate.disposition = VMX_NESTED_HARDWARE_L2_EXIT;
			candidate.commit_launch = true;
			break;
		}
		/*
		 * VMCS02 uses L0's VMCS01 entry-MSR area.  L1's requested
		 * entry list was already validated and applied in software
		 * before hardware entry, so neither a hardware MSR-load
		 * failure nor machine-check-during-entry is attributable to
		 * L1.  Both are L0 failures and still need the normal
		 * unlaunched hardware unwind.
		 */
		if ((input->exit_reason & NVMXHR_BASIC_REASON_MASK) ==
		    NVMXHR_MSR_LOAD_FAILURE ||
		    (input->exit_reason & NVMXHR_BASIC_REASON_MASK) ==
		    NVMXHR_MACHINE_CHECK) {
			candidate.disposition =
			    VMX_NESTED_HARDWARE_L0_FAILURE;
			break;
		}
		error = vmx_nested_vmentry_hardware_failed_entry(
		    input->exit_reason, input->exit_qualification,
		    0, &candidate.rejection);
		candidate.disposition = error == 0 ?
		    VMX_NESTED_HARDWARE_REJECTION :
		    VMX_NESTED_HARDWARE_L0_FAILURE;
		break;
	case VMX_NESTED_HARDWARE_REPORT_VMFAIL_VALID:
		error = vmx_nested_vmentry_hardware_vmfail_valid(
		    input->instruction_error, &candidate.rejection);
		candidate.disposition = error == 0 ?
		    VMX_NESTED_HARDWARE_REJECTION :
		    VMX_NESTED_HARDWARE_L0_FAILURE;
		break;
	case VMX_NESTED_HARDWARE_REPORT_VMFAIL_INVALID:
	case VMX_NESTED_HARDWARE_REPORT_MACHINE_CHECK:
		candidate.disposition = VMX_NESTED_HARDWARE_L0_FAILURE;
		break;
	}
	if (vmx_nested_hardware_report_result_validate(&candidate) != 0)
		return (EPROTO);
	*result = candidate;
	return (0);
}
