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

struct seg_desc;

#include "vmcs.h"
#include "vmx_nested_caps.h"
#include "vmx_nested_memory.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"
#include "vmx_nested_vmcs_fields.h"
#include "vmx_nested_vmcs12.h"
#include "vmx_nested_vmcs_store.h"
#include "vmx_nested_tsc.h"
#include "vmx_nested_vmentry.h"

#define	NVMX_EXIT_HOST_ADDRESS_SPACE_SIZE	(UINT32_C(1) << 9)

static int
nvmx12_read(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, uint32_t encoding,
    uint64_t *value)
{

	if (!vmx_nested_vmcs_field_available(capabilities, encoding)) {
		*value = 0;
		return (0);
	}
	return (vmx_nested_vmcs_region_read(region, length, capabilities,
	    false, encoding, value));
}

#define	NVMX12_READ(member, encoding) do {				\
	uint64_t nvmx12_value;						\
	error = nvmx12_read(region, length, capabilities, (encoding),	\
	    &nvmx12_value);						\
	if (error != 0)						\
		return (error);						\
	candidate.member = nvmx12_value;					\
} while (0)

int
vmx_nested_vmcs12_snapshot_region(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, uint64_t vmcs12_gpa,
    bool in_smm, struct vmx_nested_vmcs12_snapshot *snapshot)
{
	struct vmx_nested_vmcs12_snapshot candidate;
	uint64_t value;
	int error;

	if (region == NULL || snapshot == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    !vmx_nested_region_gpa_valid(capabilities, vmcs12_gpa))
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(snapshot, sizeof(*snapshot), region,
	    length) ||
	    vmx_nested_state_ranges_overlap(snapshot, sizeof(*snapshot),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	error = vmx_nested_vmcs_region_validate(region, length, capabilities,
	    false);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	candidate.capabilities = *capabilities;
	error = vmx_nested_capabilities_signature(capabilities,
	    &candidate.capability_signature);
	if (error != 0)
		return (error);
	candidate.vmcs12_gpa = vmcs12_gpa;
	candidate.controls.in_smm = in_smm;
	candidate.guest_arch.in_smm = in_smm;

	NVMX12_READ(controls.vpid, VMCS_VPID);
	NVMX12_READ(controls.posted_interrupt_vector, VMCS_PIR_VECTOR);
	NVMX12_READ(controls.io_bitmap_a, VMCS_IO_BITMAP_A);
	NVMX12_READ(controls.io_bitmap_b, VMCS_IO_BITMAP_B);
	NVMX12_READ(controls.msr_bitmap, VMCS_MSR_BITMAP);
	NVMX12_READ(controls.exit_msr_store_address, VMCS_EXIT_MSR_STORE);
	NVMX12_READ(controls.exit_msr_load_address, VMCS_EXIT_MSR_LOAD);
	NVMX12_READ(controls.entry_msr_load_address, VMCS_ENTRY_MSR_LOAD);
	NVMX12_READ(executive_vmcs, VMCS_EXECUTIVE_VMCS);
	NVMX12_READ(tsc_offset, VMCS_TSC_OFFSET);
	NVMX12_READ(controls.virtual_apic, VMCS_VIRTUAL_APIC);
	NVMX12_READ(controls.apic_access, VMCS_APIC_ACCESS);
	NVMX12_READ(controls.posted_interrupt_descriptor, VMCS_PIR_DESC);
	NVMX12_READ(controls.eptp, VMCS_EPTP);
	for (u_int i = 0; i < nitems(candidate.execution.eoi_exit_bitmap);
	    i++)
		NVMX12_READ(execution.eoi_exit_bitmap[i],
		    VMCS_EOI_EXIT0 + i * 2);

	NVMX12_READ(link_pointer, VMCS_LINK_POINTER);
	NVMX12_READ(guest_control.dr7, VMCS_GUEST_DR7);
	NVMX12_READ(guest_arch.debugctl, VMCS_GUEST_IA32_DEBUGCTL);
	NVMX12_READ(guest_control.pat, VMCS_GUEST_IA32_PAT);
	NVMX12_READ(guest_control.efer, VMCS_GUEST_IA32_EFER);
	for (u_int i = 0; i < nitems(candidate.pdpte); i++)
		NVMX12_READ(pdpte[i], VMCS_GUEST_PDPTE0 + i * 2);
	NVMX12_READ(host.pat, VMCS_HOST_IA32_PAT);
	NVMX12_READ(host.efer, VMCS_HOST_IA32_EFER);

	NVMX12_READ(controls.pinbased, VMCS_PIN_BASED_CTLS);
	NVMX12_READ(controls.primary, VMCS_PRI_PROC_BASED_CTLS);
	NVMX12_READ(execution.exception_bitmap, VMCS_EXCEPTION_BITMAP);
	NVMX12_READ(execution.pf_error_mask, VMCS_PF_ERROR_MASK);
	NVMX12_READ(execution.pf_error_match, VMCS_PF_ERROR_MATCH);
	NVMX12_READ(controls.cr3_target_count, VMCS_CR3_TARGET_COUNT);
	NVMX12_READ(controls.vmexit, VMCS_EXIT_CTLS);
	NVMX12_READ(controls.exit_msr_store_count,
	    VMCS_EXIT_MSR_STORE_COUNT);
	NVMX12_READ(controls.exit_msr_load_count, VMCS_EXIT_MSR_LOAD_COUNT);
	NVMX12_READ(controls.vmentry, VMCS_ENTRY_CTLS);
	NVMX12_READ(controls.entry_msr_load_count,
	    VMCS_ENTRY_MSR_LOAD_COUNT);
	NVMX12_READ(controls.entry_intr_info, VMCS_ENTRY_INTR_INFO);
	NVMX12_READ(controls.entry_exception_error,
	    VMCS_ENTRY_EXCEPTION_ERROR);
	NVMX12_READ(controls.entry_instruction_length,
	    VMCS_ENTRY_INST_LENGTH);
	NVMX12_READ(controls.tpr_threshold, VMCS_TPR_THRESHOLD);
	NVMX12_READ(controls.secondary, VMCS_SEC_PROC_BASED_CTLS);
	NVMX12_READ(execution.ple_gap, VMCS_PLE_GAP);
	NVMX12_READ(execution.ple_window, VMCS_PLE_WINDOW);

	for (u_int i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		uint32_t encoding;

		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_SELECTOR, &encoding);
		if (error != 0)
			return (error);
		NVMX12_READ(guest_arch.segment[i].selector, encoding);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_LIMIT, &encoding);
		if (error != 0)
			return (error);
		NVMX12_READ(guest_arch.segment[i].limit, encoding);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_ACCESS, &encoding);
		if (error != 0)
			return (error);
		NVMX12_READ(guest_arch.segment[i].access, encoding);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_BASE, &encoding);
		if (error != 0)
			return (error);
		NVMX12_READ(guest_arch.segment[i].base, encoding);
	}
	NVMX12_READ(execution.guest_intr_status, VMCS_GUEST_INTR_STATUS);
	NVMX12_READ(guest_arch.gdtr_limit, VMCS_GUEST_GDTR_LIMIT);
	NVMX12_READ(guest_arch.idtr_limit, VMCS_GUEST_IDTR_LIMIT);
	NVMX12_READ(guest_arch.interruptibility, VMCS_GUEST_INTERRUPTIBILITY);
	NVMX12_READ(guest_arch.activity, VMCS_GUEST_ACTIVITY);
	NVMX12_READ(guest_control.sysenter_cs, VMCS_GUEST_IA32_SYSENTER_CS);
	NVMX12_READ(host.sysenter_cs, VMCS_HOST_IA32_SYSENTER_CS);
	NVMX12_READ(preemption_timer_value, VMCS_PREEMPTION_TIMER_VALUE);

	NVMX12_READ(execution.cr0_mask, VMCS_CR0_MASK);
	NVMX12_READ(execution.cr4_mask, VMCS_CR4_MASK);
	NVMX12_READ(execution.cr0_shadow, VMCS_CR0_SHADOW);
	NVMX12_READ(execution.cr4_shadow, VMCS_CR4_SHADOW);
	for (u_int i = 0; i < nitems(candidate.execution.cr3_target); i++)
		NVMX12_READ(execution.cr3_target[i], VMCS_CR3_TARGET0 + i * 2);

	NVMX12_READ(guest_control.cr0, VMCS_GUEST_CR0);
	NVMX12_READ(guest_control.cr3, VMCS_GUEST_CR3);
	NVMX12_READ(guest_control.cr4, VMCS_GUEST_CR4);
	NVMX12_READ(guest_arch.gdtr_base, VMCS_GUEST_GDTR_BASE);
	NVMX12_READ(guest_arch.idtr_base, VMCS_GUEST_IDTR_BASE);
	NVMX12_READ(guest_arch.rsp, VMCS_GUEST_RSP);
	NVMX12_READ(guest_arch.rip, VMCS_GUEST_RIP);
	NVMX12_READ(guest_arch.rflags, VMCS_GUEST_RFLAGS);
	NVMX12_READ(guest_arch.pending_debug,
	    VMCS_GUEST_PENDING_DBG_EXCEPTIONS);
	NVMX12_READ(guest_control.sysenter_esp, VMCS_GUEST_IA32_SYSENTER_ESP);
	NVMX12_READ(guest_control.sysenter_eip, VMCS_GUEST_IA32_SYSENTER_EIP);

	NVMX12_READ(host.cr0, VMCS_HOST_CR0);
	NVMX12_READ(host.cr3, VMCS_HOST_CR3);
	NVMX12_READ(host.cr4, VMCS_HOST_CR4);
	NVMX12_READ(host.fs_base, VMCS_HOST_FS_BASE);
	NVMX12_READ(host.gs_base, VMCS_HOST_GS_BASE);
	NVMX12_READ(host.tr_base, VMCS_HOST_TR_BASE);
	NVMX12_READ(host.gdtr_base, VMCS_HOST_GDTR_BASE);
	NVMX12_READ(host.idtr_base, VMCS_HOST_IDTR_BASE);
	NVMX12_READ(host.sysenter_esp, VMCS_HOST_IA32_SYSENTER_ESP);
	NVMX12_READ(host.sysenter_eip, VMCS_HOST_IA32_SYSENTER_EIP);
	NVMX12_READ(host.rsp, VMCS_HOST_RSP);
	NVMX12_READ(host.rip, VMCS_HOST_RIP);
	NVMX12_READ(host.es_selector, VMCS_HOST_ES_SELECTOR);
	NVMX12_READ(host.cs_selector, VMCS_HOST_CS_SELECTOR);
	NVMX12_READ(host.ss_selector, VMCS_HOST_SS_SELECTOR);
	NVMX12_READ(host.ds_selector, VMCS_HOST_DS_SELECTOR);
	NVMX12_READ(host.fs_selector, VMCS_HOST_FS_SELECTOR);
	NVMX12_READ(host.gs_selector, VMCS_HOST_GS_SELECTOR);
	NVMX12_READ(host.tr_selector, VMCS_HOST_TR_SELECTOR);
	candidate.host.root_ia32e =
	    (candidate.controls.vmexit & NVMX_EXIT_HOST_ADDRESS_SPACE_SIZE) != 0;

	/*
	 * TSC scaling is optional and its VMCS encoding is unavailable unless
	 * the virtual capability advertises it.  Keep the architectural
	 * identity multiplier when the field does not exist.
	 */
	value = VMX_NESTED_TSC_MULTIPLIER_ONE;
	if (vmx_nested_vmcs_field_available(capabilities,
	    VMCS_TSC_MULTIPLIER)) {
		error = nvmx12_read(region, length, capabilities,
		    VMCS_TSC_MULTIPLIER, &value);
		if (error != 0)
			return (error);
	}
	candidate.tsc_multiplier = value;
	candidate.controls.tsc_multiplier = value;

	error = vmx_nested_vmcs_region_launched(region, length, capabilities,
	    false, &candidate.launched, &candidate.launch_epoch);
	if (error != 0)
		return (error);
	candidate.executive_vmcs_valid = in_smm;
	*snapshot = candidate;
	return (0);
}

int
vmx_nested_vmcs12_snapshot_validate(
    const struct vmx_nested_vmcs12_snapshot *snapshot)
{
	uint64_t signature;
	bool host_ia32e, tsc_multiplier_available;
	int error;

	if (snapshot == NULL ||
	    vmx_nested_capabilities_validate(&snapshot->capabilities) != 0 ||
	    !vmx_nested_region_gpa_valid(&snapshot->capabilities,
	    snapshot->vmcs12_gpa) ||
	    snapshot->launched == (snapshot->launch_epoch == 0) ||
	    snapshot->controls.in_smm != snapshot->guest_arch.in_smm ||
	    snapshot->executive_vmcs_valid != snapshot->controls.in_smm)
		return (EINVAL);
	error = vmx_nested_capabilities_signature(&snapshot->capabilities,
	    &signature);
	if (error != 0)
		return (error);
	host_ia32e = (snapshot->controls.vmexit &
	    NVMX_EXIT_HOST_ADDRESS_SPACE_SIZE) != 0;
	tsc_multiplier_available = vmx_nested_vmcs_field_available(
	    &snapshot->capabilities, VMCS_TSC_MULTIPLIER);
	if (signature != snapshot->capability_signature ||
	    snapshot->host.root_ia32e != host_ia32e ||
	    snapshot->controls.tsc_multiplier != snapshot->tsc_multiplier ||
	    (!tsc_multiplier_available &&
	    snapshot->tsc_multiplier != VMX_NESTED_TSC_MULTIPLIER_ONE))
		return (EINVAL);
	return (0);
}

int
vmx_nested_vmcs12_vmentry_input(
    const struct vmx_nested_vmcs12_snapshot *snapshot,
    const struct vmx_nested_memory *memory,
    const struct vmx_nested_msr_policy *msr_policy,
    struct vmx_nested_vmentry_input *input)
{
	struct vmx_nested_vmentry_input candidate;

	if (input == NULL ||
	    vmx_nested_vmcs12_snapshot_validate(snapshot) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(input, sizeof(*input), snapshot,
	    sizeof(*snapshot)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), memory,
	    memory == NULL ? 0 : sizeof(*memory)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), msr_policy,
	    msr_policy == NULL ? 0 : sizeof(*msr_policy)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.controls = &snapshot->controls;
	candidate.execution = &snapshot->execution;
	candidate.host = &snapshot->host;
	candidate.guest_control = &snapshot->guest_control;
	candidate.guest_arch = &snapshot->guest_arch;
	candidate.memory = memory;
	candidate.msr_policy = msr_policy;
	candidate.vmcs_pdpte = snapshot->pdpte;
	candidate.link_pointer = snapshot->link_pointer;
	candidate.current_vmcs = snapshot->vmcs12_gpa;
	candidate.executive_vmcs = snapshot->executive_vmcs;
	candidate.executive_vmcs_valid = snapshot->executive_vmcs_valid;
	*input = candidate;
	return (0);
}

#undef NVMX12_READ
