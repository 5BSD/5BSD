/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
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
#include "vmx_controls.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs02_program.h"

#define	NVMXP_SECONDARY_TSC_SCALING	(UINT32_C(1) << 25)
#define	NVMXP_VM_EXIT_SAVE_PERF_GLOBAL_CTRL	(UINT32_C(1) << 30)

static int
nvmxp_add(struct vmx_nested_vmcs02_program *program, uint32_t encoding,
    uint64_t value)
{
	uint32_t count;

	count = program->count;
	if (count >= nitems(program->fields) ||
	    (count != 0 &&
	    encoding <= program->fields[count - 1].encoding))
		return (EOVERFLOW);
	program->fields[count].encoding = encoding;
	program->fields[count].value = value;
	program->count++;
	return (0);
}

#define	NVMXP_ADD(program, encoding, value) do {			\
	error = nvmxp_add((program), (encoding), (value));		\
	if (error != 0)						\
		return (error);						\
} while (0)

static int
nvmxp_validate(const struct vmx_nested_vmcs02_hardware_plan *plan)
{
	bool ept, posted, preemption_timer, tsc_scaling, vpid;

	if (plan == NULL || !vmx_nested_vmcs02_id_valid(&plan->id) ||
	    plan->resource_generation == 0 ||
	    plan->cr3_target_count > nitems(plan->execution.cr3_target) ||
	    plan->guest_arch.in_smm ||
	    (plan->controls.vmentry &
	    VM_ENTRY_LOAD_PERF_GLOBAL_CTRL) != 0 ||
	    (plan->controls.vmexit &
	    (VM_EXIT_LOAD_PERF_GLOBAL_CTRL |
	    NVMXP_VM_EXIT_SAVE_PERF_GLOBAL_CTRL)) != 0)
		return (EINVAL);
	ept = (plan->controls.secondary &
	    PROCBASED2_ENABLE_EPT) != 0;
	vpid = (plan->controls.secondary &
	    PROCBASED2_ENABLE_VPID) != 0;
	posted = (plan->controls.pinbased &
	    PINBASED_POSTED_INTERRUPT) != 0;
	preemption_timer = (plan->controls.pinbased &
	    PINBASED_PREMPTION_TIMER) != 0;
	tsc_scaling = (plan->controls.secondary &
	    NVMXP_SECONDARY_TSC_SCALING) != 0;
	if (ept != plan->ept_enabled ||
	    (vpid && plan->vpid == 0) ||
	    (posted && plan->posted_interrupt_vector > UINT8_MAX) ||
	    preemption_timer != plan->preemption_timer_enabled ||
	    tsc_scaling != plan->tsc_scaling_enabled ||
	    (ept && plan->eptp == 0) ||
	    (!ept && plan->eptp != 0) ||
	    (!tsc_scaling && plan->tsc_multiplier !=
	    VMX_NESTED_TSC_MULTIPLIER_ONE))
		return (EINVAL);
	return (0);
}

int
vmx_nested_vmcs02_program_build(
    const struct vmx_nested_vmcs02_hardware_plan *plan,
    struct vmx_nested_vmcs02_program *program)
{
	static const uint8_t segment_index[] = {
		VMX_NESTED_GUEST_ES, VMX_NESTED_GUEST_CS,
		VMX_NESTED_GUEST_SS, VMX_NESTED_GUEST_DS,
		VMX_NESTED_GUEST_FS, VMX_NESTED_GUEST_GS,
		VMX_NESTED_GUEST_LDTR, VMX_NESTED_GUEST_TR,
	};
	static const uint32_t guest_selector[] = {
		VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_CS_SELECTOR,
		VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_DS_SELECTOR,
		VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_GS_SELECTOR,
		VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_TR_SELECTOR,
	};
	static const uint32_t guest_limit[] = {
		VMCS_GUEST_ES_LIMIT, VMCS_GUEST_CS_LIMIT,
		VMCS_GUEST_SS_LIMIT, VMCS_GUEST_DS_LIMIT,
		VMCS_GUEST_FS_LIMIT, VMCS_GUEST_GS_LIMIT,
		VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_TR_LIMIT,
	};
	static const uint32_t guest_access[] = {
		VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_GUEST_CS_ACCESS_RIGHTS,
		VMCS_GUEST_SS_ACCESS_RIGHTS, VMCS_GUEST_DS_ACCESS_RIGHTS,
		VMCS_GUEST_FS_ACCESS_RIGHTS, VMCS_GUEST_GS_ACCESS_RIGHTS,
		VMCS_GUEST_LDTR_ACCESS_RIGHTS, VMCS_GUEST_TR_ACCESS_RIGHTS,
	};
	static const uint32_t guest_base[] = {
		VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE,
		VMCS_GUEST_SS_BASE, VMCS_GUEST_DS_BASE,
		VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE,
		VMCS_GUEST_LDTR_BASE, VMCS_GUEST_TR_BASE,
	};
	struct vmx_nested_vmcs02_program candidate;
	bool debugctl, efer, pat, vid;
	int error;

	if (program == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(program, sizeof(*program), plan,
	    sizeof(*plan)))
		return (EINVAL);
	error = nvmxp_validate(plan);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = plan->id;
	candidate.resource_generation = plan->resource_generation;

	if ((plan->controls.secondary & PROCBASED2_ENABLE_VPID) != 0)
		NVMXP_ADD(&candidate, VMCS_VPID, plan->vpid);
	if ((plan->controls.pinbased & PINBASED_POSTED_INTERRUPT) != 0)
		NVMXP_ADD(&candidate, VMCS_PIR_VECTOR,
		    plan->posted_interrupt_vector);

	for (uint32_t i = 0; i < nitems(guest_selector); i++)
		NVMXP_ADD(&candidate, guest_selector[i],
		    plan->guest_arch.segment[segment_index[i]].selector);
	vid = (plan->controls.secondary &
	    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY) != 0;
	if (vid)
		NVMXP_ADD(&candidate, VMCS_GUEST_INTR_STATUS,
		    plan->execution.guest_intr_status);

	NVMXP_ADD(&candidate, VMCS_HOST_ES_SELECTOR,
	    plan->host.es_selector);
	NVMXP_ADD(&candidate, VMCS_HOST_CS_SELECTOR,
	    plan->host.cs_selector);
	NVMXP_ADD(&candidate, VMCS_HOST_SS_SELECTOR,
	    plan->host.ss_selector);
	NVMXP_ADD(&candidate, VMCS_HOST_DS_SELECTOR,
	    plan->host.ds_selector);
	NVMXP_ADD(&candidate, VMCS_HOST_FS_SELECTOR,
	    plan->host.fs_selector);
	NVMXP_ADD(&candidate, VMCS_HOST_GS_SELECTOR,
	    plan->host.gs_selector);
	NVMXP_ADD(&candidate, VMCS_HOST_TR_SELECTOR,
	    plan->host.tr_selector);

	if ((plan->controls.primary & PROCBASED_IO_BITMAPS) != 0) {
		NVMXP_ADD(&candidate, VMCS_IO_BITMAP_A, plan->io_bitmap_a);
		NVMXP_ADD(&candidate, VMCS_IO_BITMAP_B, plan->io_bitmap_b);
	}
	if ((plan->controls.primary & PROCBASED_MSR_BITMAPS) != 0)
		NVMXP_ADD(&candidate, VMCS_MSR_BITMAP, plan->msr_bitmap);
	NVMXP_ADD(&candidate, VMCS_EXIT_MSR_STORE,
	    plan->exit_msr_store_count == 0 ? 0 : plan->exit_msr_store);
	NVMXP_ADD(&candidate, VMCS_EXIT_MSR_LOAD,
	    plan->exit_msr_load_count == 0 ? 0 : plan->exit_msr_load);
	NVMXP_ADD(&candidate, VMCS_ENTRY_MSR_LOAD,
	    plan->entry_msr_load_count == 0 ? 0 : plan->entry_msr_load);
	NVMXP_ADD(&candidate, VMCS_TSC_OFFSET, plan->tsc_offset);
	if ((plan->controls.primary & PROCBASED_USE_TPR_SHADOW) != 0)
		NVMXP_ADD(&candidate, VMCS_VIRTUAL_APIC,
		    plan->virtual_apic);
	if ((plan->controls.secondary &
	    PROCBASED2_VIRTUALIZE_APIC_ACCESSES) != 0)
		NVMXP_ADD(&candidate, VMCS_APIC_ACCESS,
		    plan->apic_access);
	if ((plan->controls.pinbased & PINBASED_POSTED_INTERRUPT) != 0)
		NVMXP_ADD(&candidate, VMCS_PIR_DESC,
		    plan->posted_interrupt_descriptor);
	if (plan->ept_enabled)
		NVMXP_ADD(&candidate, VMCS_EPTP, plan->eptp);
	if (vid) {
		NVMXP_ADD(&candidate, VMCS_EOI_EXIT0,
		    plan->execution.eoi_exit_bitmap[0]);
		NVMXP_ADD(&candidate, VMCS_EOI_EXIT1,
		    plan->execution.eoi_exit_bitmap[1]);
		NVMXP_ADD(&candidate, VMCS_EOI_EXIT2,
		    plan->execution.eoi_exit_bitmap[2]);
		NVMXP_ADD(&candidate, VMCS_EOI_EXIT3,
		    plan->execution.eoi_exit_bitmap[3]);
	}
	if (plan->tsc_scaling_enabled)
		NVMXP_ADD(&candidate, VMCS_TSC_MULTIPLIER,
		    plan->tsc_multiplier);

	NVMXP_ADD(&candidate, VMCS_LINK_POINTER, UINT64_MAX);
	debugctl = (plan->controls.vmentry &
	    VM_ENTRY_LOAD_DEBUG_CONTROLS) != 0 ||
	    (plan->controls.vmexit & VM_EXIT_SAVE_DEBUG_CONTROLS) != 0;
	if (debugctl)
		NVMXP_ADD(&candidate, VMCS_GUEST_IA32_DEBUGCTL,
		    plan->guest_arch.debugctl);
	pat = (plan->controls.vmentry & VM_ENTRY_LOAD_PAT) != 0 ||
	    (plan->controls.vmexit & VM_EXIT_SAVE_PAT) != 0;
	if (pat)
		NVMXP_ADD(&candidate, VMCS_GUEST_IA32_PAT,
		    plan->guest_control.pat);
	efer = (plan->controls.vmentry & VM_ENTRY_LOAD_EFER) != 0 ||
	    (plan->controls.vmexit & VM_EXIT_SAVE_EFER) != 0;
	if (efer)
		NVMXP_ADD(&candidate, VMCS_GUEST_IA32_EFER,
		    plan->guest_control.efer);
	if (plan->pdpte.active) {
		NVMXP_ADD(&candidate, VMCS_GUEST_PDPTE0,
		    plan->pdpte.value[0]);
		NVMXP_ADD(&candidate, VMCS_GUEST_PDPTE1,
		    plan->pdpte.value[1]);
		NVMXP_ADD(&candidate, VMCS_GUEST_PDPTE2,
		    plan->pdpte.value[2]);
		NVMXP_ADD(&candidate, VMCS_GUEST_PDPTE3,
		    plan->pdpte.value[3]);
	}
	if ((plan->controls.vmexit & VM_EXIT_LOAD_PAT) != 0)
		NVMXP_ADD(&candidate, VMCS_HOST_IA32_PAT,
		    plan->host.pat);
	if ((plan->controls.vmexit & VM_EXIT_LOAD_EFER) != 0)
		NVMXP_ADD(&candidate, VMCS_HOST_IA32_EFER,
		    plan->host.efer);

	NVMXP_ADD(&candidate, VMCS_PIN_BASED_CTLS,
	    plan->controls.pinbased);
	NVMXP_ADD(&candidate, VMCS_PRI_PROC_BASED_CTLS,
	    plan->controls.primary);
	NVMXP_ADD(&candidate, VMCS_EXCEPTION_BITMAP,
	    plan->execution.exception_bitmap);
	NVMXP_ADD(&candidate, VMCS_PF_ERROR_MASK,
	    plan->execution.pf_error_mask);
	NVMXP_ADD(&candidate, VMCS_PF_ERROR_MATCH,
	    plan->execution.pf_error_match);
	NVMXP_ADD(&candidate, VMCS_CR3_TARGET_COUNT,
	    plan->cr3_target_count);
	NVMXP_ADD(&candidate, VMCS_EXIT_CTLS, plan->controls.vmexit);
	NVMXP_ADD(&candidate, VMCS_EXIT_MSR_STORE_COUNT,
	    plan->exit_msr_store_count);
	NVMXP_ADD(&candidate, VMCS_EXIT_MSR_LOAD_COUNT,
	    plan->exit_msr_load_count);
	NVMXP_ADD(&candidate, VMCS_ENTRY_CTLS, plan->controls.vmentry);
	NVMXP_ADD(&candidate, VMCS_ENTRY_MSR_LOAD_COUNT,
	    plan->entry_msr_load_count);
	NVMXP_ADD(&candidate, VMCS_ENTRY_INTR_INFO,
	    plan->entry_intr_info);
	NVMXP_ADD(&candidate, VMCS_ENTRY_EXCEPTION_ERROR,
	    plan->entry_exception_error);
	NVMXP_ADD(&candidate, VMCS_ENTRY_INST_LENGTH,
	    plan->entry_instruction_length);
	if ((plan->controls.primary & PROCBASED_USE_TPR_SHADOW) != 0)
		NVMXP_ADD(&candidate, VMCS_TPR_THRESHOLD,
		    plan->tpr_threshold);
	NVMXP_ADD(&candidate, VMCS_SEC_PROC_BASED_CTLS,
	    plan->controls.secondary);
	if ((plan->controls.secondary &
	    PROCBASED2_PAUSE_LOOP_EXITING) != 0) {
		NVMXP_ADD(&candidate, VMCS_PLE_GAP,
		    plan->execution.ple_gap);
		NVMXP_ADD(&candidate, VMCS_PLE_WINDOW,
		    plan->execution.ple_window);
	}

	for (uint32_t i = 0; i < nitems(guest_limit); i++)
		NVMXP_ADD(&candidate, guest_limit[i],
		    plan->guest_arch.segment[segment_index[i]].limit);
	NVMXP_ADD(&candidate, VMCS_GUEST_GDTR_LIMIT,
	    plan->guest_arch.gdtr_limit);
	NVMXP_ADD(&candidate, VMCS_GUEST_IDTR_LIMIT,
	    plan->guest_arch.idtr_limit);
	for (uint32_t i = 0; i < nitems(guest_access); i++)
		NVMXP_ADD(&candidate, guest_access[i],
		    plan->guest_arch.segment[segment_index[i]].access);
	NVMXP_ADD(&candidate, VMCS_GUEST_INTERRUPTIBILITY,
	    plan->guest_arch.interruptibility);
	NVMXP_ADD(&candidate, VMCS_GUEST_ACTIVITY,
	    plan->guest_arch.activity);
	NVMXP_ADD(&candidate, VMCS_GUEST_IA32_SYSENTER_CS,
	    plan->guest_control.sysenter_cs);
	if (plan->preemption_timer_enabled)
		NVMXP_ADD(&candidate, VMCS_PREEMPTION_TIMER_VALUE,
		    plan->preemption_timer_value);
	NVMXP_ADD(&candidate, VMCS_HOST_IA32_SYSENTER_CS,
	    plan->host.sysenter_cs);

	NVMXP_ADD(&candidate, VMCS_CR0_MASK,
	    plan->execution.cr0_mask);
	NVMXP_ADD(&candidate, VMCS_CR4_MASK,
	    plan->execution.cr4_mask);
	NVMXP_ADD(&candidate, VMCS_CR0_SHADOW,
	    plan->execution.cr0_shadow);
	NVMXP_ADD(&candidate, VMCS_CR4_SHADOW,
	    plan->execution.cr4_shadow);
	for (uint32_t i = 0; i < plan->cr3_target_count; i++)
		NVMXP_ADD(&candidate, VMCS_CR3_TARGET0 + i * 2,
		    plan->execution.cr3_target[i]);

	NVMXP_ADD(&candidate, VMCS_GUEST_CR0,
	    plan->guest_control.cr0);
	NVMXP_ADD(&candidate, VMCS_GUEST_CR3,
	    plan->guest_control.cr3);
	NVMXP_ADD(&candidate, VMCS_GUEST_CR4,
	    plan->guest_control.cr4);
	for (uint32_t i = 0; i < nitems(guest_base); i++)
		NVMXP_ADD(&candidate, guest_base[i],
		    plan->guest_arch.segment[segment_index[i]].base);
	NVMXP_ADD(&candidate, VMCS_GUEST_GDTR_BASE,
	    plan->guest_arch.gdtr_base);
	NVMXP_ADD(&candidate, VMCS_GUEST_IDTR_BASE,
	    plan->guest_arch.idtr_base);
	NVMXP_ADD(&candidate, VMCS_GUEST_DR7,
	    plan->guest_control.dr7);
	NVMXP_ADD(&candidate, VMCS_GUEST_RSP,
	    plan->guest_arch.rsp);
	NVMXP_ADD(&candidate, VMCS_GUEST_RIP,
	    plan->guest_arch.rip);
	NVMXP_ADD(&candidate, VMCS_GUEST_RFLAGS,
	    plan->guest_arch.rflags);
	NVMXP_ADD(&candidate, VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
	    plan->guest_arch.pending_debug);
	NVMXP_ADD(&candidate, VMCS_GUEST_IA32_SYSENTER_ESP,
	    plan->guest_control.sysenter_esp);
	NVMXP_ADD(&candidate, VMCS_GUEST_IA32_SYSENTER_EIP,
	    plan->guest_control.sysenter_eip);

	NVMXP_ADD(&candidate, VMCS_HOST_CR0, plan->host.cr0);
	NVMXP_ADD(&candidate, VMCS_HOST_CR3, plan->host.cr3);
	NVMXP_ADD(&candidate, VMCS_HOST_CR4, plan->host.cr4);
	NVMXP_ADD(&candidate, VMCS_HOST_FS_BASE,
	    plan->host.fs_base);
	NVMXP_ADD(&candidate, VMCS_HOST_GS_BASE,
	    plan->host.gs_base);
	NVMXP_ADD(&candidate, VMCS_HOST_TR_BASE,
	    plan->host.tr_base);
	NVMXP_ADD(&candidate, VMCS_HOST_GDTR_BASE,
	    plan->host.gdtr_base);
	NVMXP_ADD(&candidate, VMCS_HOST_IDTR_BASE,
	    plan->host.idtr_base);
	NVMXP_ADD(&candidate, VMCS_HOST_IA32_SYSENTER_ESP,
	    plan->host.sysenter_esp);
	NVMXP_ADD(&candidate, VMCS_HOST_IA32_SYSENTER_EIP,
	    plan->host.sysenter_eip);
	NVMXP_ADD(&candidate, VMCS_HOST_RSP, plan->host.rsp);
	NVMXP_ADD(&candidate, VMCS_HOST_RIP, plan->host.rip);

	*program = candidate;
	return (0);
}

#undef NVMXP_ADD
