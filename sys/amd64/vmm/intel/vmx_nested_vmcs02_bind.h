/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_BIND_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_BIND_H_

#include "vmx_nested_types.h"

#include "vmx_nested_entry.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_host.h"
#include "vmx_nested_pdpte.h"
#include "vmx_nested_vmcs02.h"

/*
 * Host-owned resources that may safely be installed in VMCS02.  None of
 * these values comes directly from a VMCS12 address field.  The owner must
 * rebuild them after restore and bump resource_generation whenever their
 * identity changes.
 */
struct vmx_nested_vmcs02_resources {
	struct vmx_nested_vmcs02_id	id;
	uint64_t	resource_generation;
	uint64_t	eptp01;
	uint64_t	ept_capability_signature;
	uint64_t	eptp02;
	uint64_t	io_bitmap_a;
	uint64_t	io_bitmap_b;
	uint64_t	msr_bitmap;
	uint64_t	virtual_apic;
	uint64_t	apic_access;
	uint64_t	posted_interrupt_descriptor;
	uint64_t	exit_msr_store;
	uint64_t	exit_msr_load;
	uint64_t	entry_msr_load;
	uint32_t	exit_msr_store_count;
	uint32_t	exit_msr_load_count;
	uint32_t	entry_msr_load_count;
};

/*
 * Value-only hardware programming input.  In particular it has no VMCS12
 * EPTP, bitmap GPA, MSR-list GPA, callback, pointer, or file descriptor.
 * The hardware writer may consume this only while the matching vCPU and
 * resource generation remain frozen.
 */
struct vmx_nested_vmcs02_hardware_plan {
	struct vmx_nested_vmcs02_id	id;
	uint64_t	resource_generation;
	struct vmx_nested_vmcs02_controls controls;
	struct vmx_nested_execution_state execution;
	struct vmx_nested_host_state	host;
	struct vmx_nested_guest_control_state guest_control;
	struct vmx_nested_guest_arch_state guest_arch;
	struct vmx_nested_pdpte_state	pdpte;
	uint64_t	tsc_offset;
	uint64_t	tsc_multiplier;
	uint64_t	eptp;
	uint64_t	io_bitmap_a;
	uint64_t	io_bitmap_b;
	uint64_t	msr_bitmap;
	uint64_t	virtual_apic;
	uint64_t	apic_access;
	uint64_t	posted_interrupt_descriptor;
	uint64_t	exit_msr_store;
	uint64_t	exit_msr_load;
	uint64_t	entry_msr_load;
	uint32_t	exit_msr_store_count;
	uint32_t	exit_msr_load_count;
	uint32_t	entry_msr_load_count;
	uint32_t	entry_intr_info;
	uint32_t	entry_exception_error;
	uint32_t	entry_instruction_length;
	uint32_t	tpr_threshold;
	uint32_t	cr3_target_count;
	uint32_t	preemption_timer_value;
	uint16_t	vpid;
	uint16_t	posted_interrupt_vector;
	bool		ept_enabled;
	bool		preemption_timer_enabled;
	bool		tsc_scaling_enabled;
};

int	vmx_nested_vmcs02_bind(
	    const struct vmx_nested_vmcs02_image *,
	    const struct vmx_nested_host_state *,
	    const struct vmx_nested_vmcs02_resources *,
	    struct vmx_nested_vmcs02_hardware_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_BIND_H_ */
