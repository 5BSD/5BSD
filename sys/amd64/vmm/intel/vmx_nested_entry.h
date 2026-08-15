/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_ENTRY_H_
#define	_VMM_INTEL_VMX_NESTED_ENTRY_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;

/*
 * VMCS12 execution fields that do not participate directly in the first
 * control-dependency checks but are required to construct a complete VMCS02.
 * They are architectural values, not host bitmap or EPT-root addresses.
 */
struct vmx_nested_execution_state {
	uint64_t	cr0_mask;
	uint64_t	cr0_shadow;
	uint64_t	cr4_mask;
	uint64_t	cr4_shadow;
	uint64_t	cr3_target[4];
	uint64_t	eoi_exit_bitmap[4];
	uint32_t	exception_bitmap;
	uint32_t	pf_error_mask;
	uint32_t	pf_error_match;
	uint32_t	ple_gap;
	uint32_t	ple_window;
	uint16_t	guest_intr_status;
};

/*
 * Canonical VMCS12 control fields consumed by the first VM-entry validation
 * pass.  This contains architectural values only; it is not a hardware VMCS.
 */
struct vmx_nested_entry_controls {
	uint32_t pinbased;
	uint32_t primary;
	uint32_t secondary;
	uint32_t vmexit;
	uint32_t vmentry;
	uint32_t cr3_target_count;
	uint32_t tpr_threshold;
	uint32_t entry_intr_info;
	uint32_t entry_exception_error;
	uint32_t entry_instruction_length;
	uint16_t vpid;
	uint16_t posted_interrupt_vector;
	uint64_t io_bitmap_a;
	uint64_t io_bitmap_b;
	uint64_t msr_bitmap;
	uint64_t virtual_apic;
	uint64_t apic_access;
	uint64_t posted_interrupt_descriptor;
	uint64_t eptp;
	uint64_t tsc_multiplier;
	uint64_t exit_msr_store_address;
	uint64_t exit_msr_load_address;
	uint64_t entry_msr_load_address;
	uint32_t exit_msr_store_count;
	uint32_t exit_msr_load_count;
	uint32_t entry_msr_load_count;
	bool in_smm;
};

/*
 * Stable diagnostic classification.  VM entry reports architectural
 * instruction error 7 for every one of these failures.
 */
enum vmx_nested_entry_control_failure {
	VMX_NESTED_ENTRY_CONTROL_OK = 0,
	VMX_NESTED_ENTRY_EXECUTION_CONTROLS,
	VMX_NESTED_ENTRY_CR3_TARGET_COUNT,
	VMX_NESTED_ENTRY_CONTROL_ADDRESS,
	VMX_NESTED_ENTRY_TPR_DEPENDENCY,
	VMX_NESTED_ENTRY_NMI_DEPENDENCY,
	VMX_NESTED_ENTRY_APIC_DEPENDENCY,
	VMX_NESTED_ENTRY_POSTED_INTERRUPT,
	VMX_NESTED_ENTRY_VPID,
	VMX_NESTED_ENTRY_EPT_DEPENDENCY,
	VMX_NESTED_ENTRY_EPTP,
	VMX_NESTED_ENTRY_TSC_MULTIPLIER,
	VMX_NESTED_ENTRY_EXIT_CONTROLS,
	VMX_NESTED_ENTRY_MSR_AREA,
	VMX_NESTED_ENTRY_ENTRY_CONTROLS,
	VMX_NESTED_ENTRY_EVENT_INJECTION,
	VMX_NESTED_ENTRY_SMM_CONTROLS,
};

int	vmx_nested_entry_controls_validate(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_entry_controls *,
	    enum vmx_nested_entry_control_failure *);
int	vmx_nested_entry_controls_validate_for_guest(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_entry_controls *, uint64_t,
	    enum vmx_nested_entry_control_failure *);
bool	vmx_nested_eptp_valid(const struct vmx_nested_capabilities *,
	    uint64_t);

#endif /* _VMM_INTEL_VMX_NESTED_ENTRY_H_ */
