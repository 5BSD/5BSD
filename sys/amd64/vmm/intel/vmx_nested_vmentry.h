/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMENTRY_H_
#define	_VMM_INTEL_VMX_NESTED_VMENTRY_H_

#include "vmx_nested_types.h"

#include "vmx_nested_msr.h"
#include "vmx_nested_pdpte.h"

struct vmx_nested_capabilities;
struct vmx_nested_entry_controls;
struct vmx_nested_execution_state;
struct vmx_nested_guest_arch_state;
struct vmx_nested_guest_control_state;
struct vmx_nested_host_state;
struct vmx_nested_memory;
struct vmx_nested_msr_policy;
struct vmx_nested_msr_entry;

struct vmx_nested_vmentry_input {
	const struct vmx_nested_entry_controls		*controls;
	const struct vmx_nested_execution_state		*execution;
	const struct vmx_nested_host_state		*host;
	const struct vmx_nested_guest_control_state	*guest_control;
	const struct vmx_nested_guest_arch_state		*guest_arch;
	const struct vmx_nested_memory			*memory;
	const struct vmx_nested_msr_policy		*msr_policy;
	const uint64_t				*vmcs_pdpte;
	uint64_t	link_pointer;
	uint64_t	current_vmcs;
	uint64_t	executive_vmcs;
	bool		executive_vmcs_valid;
};

enum vmx_nested_vmentry_disposition {
	VMX_NESTED_VMENTRY_READY = 0,
	VMX_NESTED_VMENTRY_VMFAIL_VALID,
	VMX_NESTED_VMENTRY_ENTRY_FAILURE,
};

enum vmx_nested_vmentry_stage {
	VMX_NESTED_VMENTRY_STAGE_NONE = 0,
	VMX_NESTED_VMENTRY_STAGE_CONTROLS,
	VMX_NESTED_VMENTRY_STAGE_HOST,
	VMX_NESTED_VMENTRY_STAGE_GUEST_CONTROL,
	VMX_NESTED_VMENTRY_STAGE_GUEST_ARCH,
	VMX_NESTED_VMENTRY_STAGE_LINK,
	VMX_NESTED_VMENTRY_STAGE_PDPTE,
	VMX_NESTED_VMENTRY_STAGE_MSR,
};

/*
 * On VMfailValid, instruction_error is 7 or 8.  On a late VM-entry failure,
 * exit_reason includes bit 31 and exit_qualification follows SDM 29.8.
 * detail is the stage-specific diagnostic enum and is not guest-visible.
 */
struct vmx_nested_vmentry_result {
	enum vmx_nested_vmentry_disposition	disposition;
	enum vmx_nested_vmentry_stage		stage;
	uint32_t	instruction_error;
	uint32_t	exit_reason;
	uint64_t	exit_qualification;
	uint32_t	detail;
	struct vmx_nested_pdpte_state	pdpte;
};

static __inline bool
vmx_nested_vmentry_result_equal(
    const struct vmx_nested_vmentry_result *a,
    const struct vmx_nested_vmentry_result *b)
{

	return (a != NULL && b != NULL &&
	    a->disposition == b->disposition && a->stage == b->stage &&
	    a->instruction_error == b->instruction_error &&
	    a->exit_reason == b->exit_reason &&
	    a->exit_qualification == b->exit_qualification &&
	    a->detail == b->detail &&
	    vmx_nested_pdpte_state_equal(&a->pdpte, &b->pdpte));
}

bool	vmx_nested_vmentry_memory_required(
	    const struct vmx_nested_vmentry_input *);
int	vmx_nested_vmentry_validate(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_vmentry_input *,
	    struct vmx_nested_vmentry_result *);
/*
 * Frozen-entry variant.  It validates all non-MSR state first, then reads
 * and validates the VMCS12 entry MSR list exactly once into caller-owned
 * immutable storage.  This avoids a validate-then-reread race before L2
 * state is applied.
 */
int	vmx_nested_vmentry_snapshot_validate(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_vmentry_input *,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *,
	    struct vmx_nested_vmentry_result *);
/*
 * Convert a failure discovered while applying the already snapshotted list
 * to prospective L2 state into Intel's failed-VM-entry result.  This covers
 * ordering dependencies between otherwise valid duplicate MSR entries.
 */
int	vmx_nested_vmentry_msr_apply_failure(uint32_t,
	    enum vmx_nested_msr_failure, struct vmx_nested_vmentry_result *);
/*
 * Convert the two failure forms reported only at the hardware entry
 * boundary into the same value-only rejection image used by software
 * validation.  VMfailInvalid and machine-check-during-entry remain L0
 * failures and are deliberately not representable here.
 */
int	vmx_nested_vmentry_hardware_vmfail_valid(uint32_t,
	    struct vmx_nested_vmentry_result *);
int	vmx_nested_vmentry_hardware_failed_entry(uint32_t, uint64_t, uint32_t,
	    struct vmx_nested_vmentry_result *);
int	vmx_nested_vmentry_rejection_validate(
	    const struct vmx_nested_vmentry_result *);

#endif /* _VMM_INTEL_VMX_NESTED_VMENTRY_H_ */
