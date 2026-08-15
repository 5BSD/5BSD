/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS12_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS12_H_

#include "vmx_nested_types.h"

#include "vmx_nested_caps.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_execution.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_host.h"

struct vmx_nested_memory;
struct vmx_nested_msr_policy;
struct vmx_nested_vmentry_input;

/*
 * Immutable, value-only capture of the VMCS12 fields consumed by one
 * nested-entry attempt.  It deliberately contains neither registry pointers
 * nor hardware VMCS state.  Callers may release the registry lock after this
 * capture and must not reread VMCS12 during the same attempt.
 */
struct vmx_nested_vmcs12_snapshot {
	/*
	 * Freeze the virtual capability contract together with the fields it
	 * controls.  The instruction handoff that supplied this policy is
	 * consumed before VMCS02 preparation, so reconstructing it later
	 * would create a time-of-check/time-of-use boundary.
	 */
	struct vmx_nested_capabilities capabilities;
	uint64_t capability_signature;
	struct vmx_nested_entry_controls controls;
	struct vmx_nested_execution_state execution;
	struct vmx_nested_guest_control_state guest_control;
	struct vmx_nested_guest_arch_state guest_arch;
	struct vmx_nested_host_state host;
	uint64_t pdpte[4];
	uint64_t link_pointer;
	uint64_t executive_vmcs;
	uint64_t tsc_offset;
	uint64_t tsc_multiplier;
	uint64_t vmcs12_gpa;
	uint64_t launch_epoch;
	uint32_t preemption_timer_value;
	bool launched;
	bool executive_vmcs_valid;
};

int	vmx_nested_vmcs12_snapshot_region(const void *, size_t,
	    const struct vmx_nested_capabilities *, uint64_t, bool,
	    struct vmx_nested_vmcs12_snapshot *);
int	vmx_nested_vmcs12_snapshot_validate(
	    const struct vmx_nested_vmcs12_snapshot *);
int	vmx_nested_vmcs12_vmentry_input(
	    const struct vmx_nested_vmcs12_snapshot *,
	    const struct vmx_nested_memory *, const struct vmx_nested_msr_policy *,
	    struct vmx_nested_vmentry_input *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS12_H_ */
