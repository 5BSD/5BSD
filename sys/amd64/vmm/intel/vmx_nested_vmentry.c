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

#include "vmx_nested_caps.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_host.h"
#include "vmx_nested_link.h"
#include "vmx_nested_memory.h"
#include "vmx_nested_msr.h"
#include "vmx_nested_pdpte.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmentry.h"

#define	NVMX_EXIT_ENTRY_FAILURE		(UINT32_C(1) << 31)
#define	NVMX_EXIT_INVALID_GUEST		33
#define	NVMX_EXIT_MSR_LOADING		34
#define	NVMX_PIPE_INTR_VALID		(UINT32_C(1) << 31)
#define	NVMX_PIPE_INTR_TYPE_MASK	(UINT32_C(7) << 8)
#define	NVMX_PIPE_INTR_TYPE_NMI		(UINT32_C(2) << 8)
#define	NVMX_HARDWARE_DETAIL		UINT32_MAX

static bool
nvmx_vmentry_output_overlaps_input(const void *output, size_t output_length,
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmentry_input *input)
{

	if (vmx_nested_state_ranges_overlap(output, output_length,
	    capabilities, capabilities == NULL ? 0 : sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(output, output_length, input,
	    input == NULL ? 0 : sizeof(*input)))
		return (true);
	if (input == NULL)
		return (false);
	return (vmx_nested_state_ranges_overlap(output, output_length,
	    input->controls, input->controls == NULL ? 0 :
	    sizeof(*input->controls)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->execution, input->execution == NULL ? 0 :
	    sizeof(*input->execution)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->host, input->host == NULL ? 0 : sizeof(*input->host)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->guest_control, input->guest_control == NULL ? 0 :
	    sizeof(*input->guest_control)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->guest_arch, input->guest_arch == NULL ? 0 :
	    sizeof(*input->guest_arch)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->memory, input->memory == NULL ? 0 :
	    sizeof(*input->memory)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->msr_policy, input->msr_policy == NULL ? 0 :
	    sizeof(*input->msr_policy)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    input->vmcs_pdpte, input->vmcs_pdpte == NULL ? 0 :
	    4 * sizeof(*input->vmcs_pdpte)));
}

static void
nvmx_vmfail(struct vmx_nested_vmentry_result *result,
    enum vmx_nested_vmentry_stage stage, uint32_t error, uint32_t detail)
{

	result->disposition = VMX_NESTED_VMENTRY_VMFAIL_VALID;
	result->stage = stage;
	result->instruction_error = error;
	result->detail = detail;
}

static void
nvmx_entry_failure(struct vmx_nested_vmentry_result *result,
    enum vmx_nested_vmentry_stage stage, uint32_t reason,
    uint64_t qualification, uint32_t detail)
{

	result->disposition = VMX_NESTED_VMENTRY_ENTRY_FAILURE;
	result->stage = stage;
	result->exit_reason = NVMX_EXIT_ENTRY_FAILURE | reason;
	result->exit_qualification = qualification;
	result->detail = detail;
	/*
	 * A stage may fail after the PDPTE stage already loaded prospective
	 * PDPTEs into the candidate (the MSR-load stage runs last, so a
	 * PAE L2 with a rejected VM-entry MSR list reaches here with
	 * pdpte.active set).  A rejection publishes no guest state, so the
	 * candidate must be fully unwound; a stale active PDPTE set would
	 * otherwise make the canonical rejection validator refuse the
	 * architectural entry-failure (basic exit reason 34) as EPROTO.
	 */
	memset(&result->pdpte, 0, sizeof(result->pdpte));
}

bool
vmx_nested_vmentry_memory_required(
    const struct vmx_nested_vmentry_input *input)
{
	uint32_t secondary;

	if (input == NULL || input->controls == NULL)
		return (false);
	secondary = (input->controls->primary & (UINT32_C(1) << 31)) != 0 ?
	    input->controls->secondary : 0;
	return (vmx_nested_link_pointer_memory_required(input->link_pointer) ||
	    vmx_nested_guest_pdpte_memory_required(input->controls->primary,
	    secondary, input->controls->vmentry, input->guest_control) ||
	    input->controls->entry_msr_load_count != 0);
}

int
vmx_nested_vmentry_rejection_validate(
    const struct vmx_nested_vmentry_result *result)
{
	uint32_t basic;

	if (result == NULL || result->detail == 0 || result->pdpte.active)
		return (result == NULL ? EINVAL : EPROTO);
	for (unsigned int i = 0; i < nitems(result->pdpte.value); i++) {
		if (result->pdpte.value[i] != 0)
			return (EPROTO);
	}
	switch (result->disposition) {
	case VMX_NESTED_VMENTRY_VMFAIL_VALID:
		if (result->exit_reason != 0 ||
		    result->exit_qualification != 0)
			return (EPROTO);
		if ((result->stage == VMX_NESTED_VMENTRY_STAGE_CONTROLS &&
		    result->instruction_error == 7) ||
		    (result->stage == VMX_NESTED_VMENTRY_STAGE_HOST &&
		    result->instruction_error == 8))
			return (0);
		return (EPROTO);
	case VMX_NESTED_VMENTRY_ENTRY_FAILURE:
		if (result->instruction_error != 0 ||
		    (result->exit_reason & NVMX_EXIT_ENTRY_FAILURE) == 0)
			return (EPROTO);
		basic = result->exit_reason & ~NVMX_EXIT_ENTRY_FAILURE;
		switch (result->stage) {
		case VMX_NESTED_VMENTRY_STAGE_GUEST_CONTROL:
			return (basic == NVMX_EXIT_INVALID_GUEST &&
			    result->exit_qualification == 0 ? 0 : EPROTO);
		case VMX_NESTED_VMENTRY_STAGE_GUEST_ARCH:
			return (basic == NVMX_EXIT_INVALID_GUEST &&
			    (result->exit_qualification == 0 ||
			    result->exit_qualification == 3) ? 0 : EPROTO);
		case VMX_NESTED_VMENTRY_STAGE_LINK:
			return (basic == NVMX_EXIT_INVALID_GUEST &&
			    result->exit_qualification == 4 ? 0 : EPROTO);
		case VMX_NESTED_VMENTRY_STAGE_PDPTE:
			return (basic == NVMX_EXIT_INVALID_GUEST &&
			    result->exit_qualification == 2 ? 0 : EPROTO);
		case VMX_NESTED_VMENTRY_STAGE_MSR:
			return (basic == NVMX_EXIT_MSR_LOADING &&
			    result->exit_qualification != 0 ? 0 : EPROTO);
		default:
			return (EPROTO);
		}
	case VMX_NESTED_VMENTRY_READY:
	default:
		return (EINVAL);
	}
}

int
vmx_nested_vmentry_hardware_vmfail_valid(uint32_t instruction_error,
    struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_vmentry_result candidate;

	if (result == NULL ||
	    (instruction_error != 7 && instruction_error != 8))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	nvmx_vmfail(&candidate,
	    instruction_error == 7 ? VMX_NESTED_VMENTRY_STAGE_CONTROLS :
	    VMX_NESTED_VMENTRY_STAGE_HOST, instruction_error,
	    NVMX_HARDWARE_DETAIL);
	if (vmx_nested_vmentry_rejection_validate(&candidate) != 0)
		return (EPROTO);
	*result = candidate;
	return (0);
}

int
vmx_nested_vmentry_hardware_failed_entry(uint32_t exit_reason,
    uint64_t exit_qualification, uint32_t entry_msr_count,
    struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_vmentry_result candidate;
	enum vmx_nested_vmentry_stage stage;
	uint32_t basic;

	if (result == NULL ||
	    (exit_reason & NVMX_EXIT_ENTRY_FAILURE) == 0 ||
	    (exit_reason & ~(NVMX_EXIT_ENTRY_FAILURE | UINT32_C(0xffff))) != 0)
		return (EINVAL);
	basic = exit_reason & UINT32_C(0xffff);
	if (basic == NVMX_EXIT_INVALID_GUEST) {
		switch (exit_qualification) {
		case 0:
		case 3:
			stage = VMX_NESTED_VMENTRY_STAGE_GUEST_ARCH;
			break;
		case 2:
			stage = VMX_NESTED_VMENTRY_STAGE_PDPTE;
			break;
		case 4:
			stage = VMX_NESTED_VMENTRY_STAGE_LINK;
			break;
		default:
			return (EINVAL);
		}
	} else if (basic == NVMX_EXIT_MSR_LOADING) {
		if (entry_msr_count == 0 || exit_qualification == 0 ||
		    exit_qualification > entry_msr_count)
			return (EINVAL);
		stage = VMX_NESTED_VMENTRY_STAGE_MSR;
	} else {
		/* In particular, machine-check-during-entry is L0-owned. */
		return (ENOTSUP);
	}
	memset(&candidate, 0, sizeof(candidate));
	nvmx_entry_failure(&candidate, stage, basic, exit_qualification,
	    NVMX_HARDWARE_DETAIL);
	if (vmx_nested_vmentry_rejection_validate(&candidate) != 0)
		return (EPROTO);
	*result = candidate;
	return (0);
}

int
vmx_nested_vmentry_validate(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmentry_input *input,
    struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_vmentry_result candidate;
	enum vmx_nested_entry_control_failure control_failure;
	enum vmx_nested_guest_arch_failure arch_failure;
	enum vmx_nested_guest_control_failure guest_failure;
	enum vmx_nested_host_failure host_failure;
	enum vmx_nested_link_failure link_failure;
	enum vmx_nested_msr_failure msr_failure;
	enum vmx_nested_pdpte_failure pdpte_failure;
	uint32_t failed_msr, secondary;
	uint64_t qualification;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    input == NULL || result == NULL || input->controls == NULL ||
	    input->host == NULL || input->guest_control == NULL ||
	    input->guest_arch == NULL)
		return (EINVAL);
	if (nvmx_vmentry_output_overlaps_input(result, sizeof(*result),
	    capabilities, input))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.disposition = VMX_NESTED_VMENTRY_READY;

	if (vmx_nested_entry_controls_validate_for_guest(capabilities,
	    input->controls, input->guest_control->cr0,
	    &control_failure) != 0) {
		nvmx_vmfail(&candidate, VMX_NESTED_VMENTRY_STAGE_CONTROLS, 7,
		    control_failure);
		*result = candidate;
		return (0);
	}
	if (vmx_nested_host_state_validate(capabilities,
	    input->controls->vmexit, input->controls->vmentry, input->host,
	    &host_failure) != 0) {
		nvmx_vmfail(&candidate, VMX_NESTED_VMENTRY_STAGE_HOST, 8,
		    host_failure);
		*result = candidate;
		return (0);
	}
	secondary = (input->controls->primary & (UINT32_C(1) << 31)) != 0 ?
	    input->controls->secondary : 0;
	if (vmx_nested_guest_control_state_validate(capabilities,
	    input->controls->primary, secondary, input->controls->vmentry,
	    input->guest_control, &guest_failure) != 0) {
		nvmx_entry_failure(&candidate,
		    VMX_NESTED_VMENTRY_STAGE_GUEST_CONTROL,
		    NVMX_EXIT_INVALID_GUEST, 0, guest_failure);
		*result = candidate;
		return (0);
	}
	if (vmx_nested_guest_arch_state_validate(capabilities,
	    input->controls->pinbased, input->controls->primary, secondary,
	    input->controls->vmentry, input->controls->entry_intr_info,
	    input->guest_control, input->guest_arch, &arch_failure) != 0) {
		qualification = 0;
		if (arch_failure == VMX_NESTED_GUEST_INTERRUPTIBILITY &&
		    (input->controls->entry_intr_info &
		    (NVMX_PIPE_INTR_VALID | NVMX_PIPE_INTR_TYPE_MASK)) ==
		    (NVMX_PIPE_INTR_VALID | NVMX_PIPE_INTR_TYPE_NMI) &&
		    (input->guest_arch->interruptibility & 1) != 0)
			qualification = 3;
		nvmx_entry_failure(&candidate,
		    VMX_NESTED_VMENTRY_STAGE_GUEST_ARCH,
		    NVMX_EXIT_INVALID_GUEST, qualification, arch_failure);
		*result = candidate;
		return (0);
	}
	if (vmx_nested_link_pointer_validate(capabilities,
	    input->controls->primary, secondary, input->controls->vmentry,
	    input->link_pointer, input->current_vmcs,
	    input->executive_vmcs_valid ? input->executive_vmcs : UINT64_MAX,
	    input->controls->in_smm,
	    input->memory, &link_failure) != 0) {
		nvmx_entry_failure(&candidate, VMX_NESTED_VMENTRY_STAGE_LINK,
		    NVMX_EXIT_INVALID_GUEST, 4, link_failure);
		*result = candidate;
		return (0);
	}
	if (vmx_nested_pdpte_validate(capabilities,
	    input->controls->primary, secondary, input->controls->vmentry,
	    input->guest_control, input->vmcs_pdpte, input->memory,
	    &candidate.pdpte, &pdpte_failure) != 0) {
		nvmx_entry_failure(&candidate, VMX_NESTED_VMENTRY_STAGE_PDPTE,
		    NVMX_EXIT_INVALID_GUEST, 2, pdpte_failure);
		*result = candidate;
		return (0);
	}
	if (vmx_nested_entry_msr_list_validate(capabilities,
	    input->controls->entry_msr_load_address,
	    input->controls->entry_msr_load_count, input->controls->in_smm,
	    input->memory, input->msr_policy, &msr_failure,
	    &failed_msr) != 0) {
		nvmx_entry_failure(&candidate, VMX_NESTED_VMENTRY_STAGE_MSR,
		    NVMX_EXIT_MSR_LOADING, failed_msr, msr_failure);
		*result = candidate;
		return (0);
	}
	*result = candidate;
	return (0);
}

int
vmx_nested_vmentry_snapshot_validate(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmentry_input *input,
    struct vmx_nested_msr_entry *entries, uint32_t capacity,
    uint32_t *snapshot_count, struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_vmentry_input without_msr;
	struct vmx_nested_entry_controls controls;
	struct vmx_nested_vmentry_result candidate;
	enum vmx_nested_msr_failure msr_failure;
	uint32_t count, failed_msr;
	size_t entries_length;
	int error;

	if (input == NULL || input->controls == NULL ||
	    snapshot_count == NULL || result == NULL ||
	    (input->controls->entry_msr_load_count != 0 && entries == NULL))
		return (EINVAL);
	if (capacity != 0 && SIZE_MAX / capacity < sizeof(*entries))
		return (EOVERFLOW);
	entries_length = (size_t)capacity * sizeof(*entries);
	if (nvmx_vmentry_output_overlaps_input(entries, entries_length,
	    capabilities, input) ||
	    nvmx_vmentry_output_overlaps_input(snapshot_count,
	    sizeof(*snapshot_count), capabilities, input) ||
	    nvmx_vmentry_output_overlaps_input(result, sizeof(*result),
	    capabilities, input) ||
	    vmx_nested_state_ranges_overlap(entries, entries_length,
	    snapshot_count, sizeof(*snapshot_count)) ||
	    vmx_nested_state_ranges_overlap(entries, entries_length, result,
	    sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(snapshot_count,
	    sizeof(*snapshot_count), result, sizeof(*result)))
		return (EINVAL);

	/*
	 * Preserve the architectural validation order while suppressing the
	 * old validate-only MSR read.  The snapshot below performs the same
	 * list checks and captures the exact values that the entry
	 * transaction will apply.
	 */
	controls = *input->controls;
	controls.entry_msr_load_count = 0;
	controls.entry_msr_load_address = 0;
	without_msr = *input;
	without_msr.controls = &controls;
	error = vmx_nested_vmentry_validate(capabilities, &without_msr,
	    &candidate);
	if (error != 0)
		return (error);
	if (candidate.disposition != VMX_NESTED_VMENTRY_READY) {
		*snapshot_count = 0;
		*result = candidate;
		return (0);
	}

	count = 0;
	error = vmx_nested_entry_msr_list_snapshot(capabilities,
	    input->controls->entry_msr_load_address,
	    input->controls->entry_msr_load_count,
	    input->controls->in_smm, input->memory, input->msr_policy,
	    entries, capacity, &count, &msr_failure, &failed_msr);
	if (error != 0) {
		if (msr_failure == VMX_NESTED_MSR_CAPACITY)
			return (ENOSPC);
		nvmx_entry_failure(&candidate,
		    VMX_NESTED_VMENTRY_STAGE_MSR, NVMX_EXIT_MSR_LOADING,
		    failed_msr, msr_failure);
		count = 0;
	}
	*snapshot_count = count;
	*result = candidate;
	return (0);
}

int
vmx_nested_vmentry_msr_apply_failure(uint32_t failed_entry,
    enum vmx_nested_msr_failure failure,
    struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_vmentry_result candidate;

	if (failed_entry == 0 || result == NULL ||
	    failure <= VMX_NESTED_MSR_OK ||
	    failure > VMX_NESTED_MSR_RUNTIME ||
	    failure == VMX_NESTED_MSR_CAPACITY)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	nvmx_entry_failure(&candidate, VMX_NESTED_VMENTRY_STAGE_MSR,
	    NVMX_EXIT_MSR_LOADING, failed_entry, failure);
	*result = candidate;
	return (0);
}
