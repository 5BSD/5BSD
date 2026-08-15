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
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"
#include "vmx_nested_vmexit.h"

#define	NVMXOUT_EXIT_SAVE_DEBUG		(1U << 2)
#define	NVMXOUT_EXIT_HOST_LMA		(1U << 9)
#define	NVMXOUT_EXIT_SAVE_PAT		(1U << 18)
#define	NVMXOUT_EXIT_LOAD_PAT		(1U << 19)
#define	NVMXOUT_EXIT_SAVE_EFER		(1U << 20)
#define	NVMXOUT_EXIT_LOAD_EFER		(1U << 21)
#define	NVMXOUT_ENTRY_GUEST_LMA		(1U << 9)
#define	NVMXOUT_ENTRY_INTR_VALID	(1U << 31)

#define	NVMXOUT_EFER_LME		(1ULL << 8)
#define	NVMXOUT_EFER_LMA		(1ULL << 10)
#define	NVMXOUT_EFER_VALID		((1ULL << 0) | NVMXOUT_EFER_LME | \
	    NVMXOUT_EFER_LMA | (1ULL << 11))

static bool
nvmx_vmexit_msr_storage_valid(const void *base, size_t base_size,
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_software_msrs *base_software,
    const struct vmx_nested_msr_entry *entries, uint32_t count,
    struct vmx_nested_msr_entry *rollback, uint32_t rollback_capacity,
    void *plan, size_t plan_size, struct vmx_nested_software_msrs *software,
    enum vmx_nested_exit_msr_load_outcome *outcome, uint32_t *failed_entry)
{
	const void *immutable[] = { capabilities, base, base_software, entries };
	size_t immutable_size[] = { sizeof(*capabilities), base_size,
	    sizeof(*base_software), 0 };
	void *mutable[] = { rollback, plan, software, outcome, failed_entry };
	size_t mutable_size[] = { 0, plan_size, sizeof(*software),
	    sizeof(*outcome), sizeof(*failed_entry) };

	if ((count != 0 && SIZE_MAX / count < sizeof(*entries)) ||
	    (rollback_capacity != 0 &&
	    SIZE_MAX / rollback_capacity < sizeof(*rollback)))
		return (false);
	immutable_size[3] = (size_t)count * sizeof(*entries);
	mutable_size[0] = (size_t)rollback_capacity * sizeof(*rollback);
	for (u_int i = 0; i < nitems(mutable); i++) {
		for (u_int j = i + 1; j < nitems(mutable); j++) {
			if (vmx_nested_state_ranges_overlap(mutable[i],
			    mutable_size[i], mutable[j], mutable_size[j]))
				return (false);
		}
		for (u_int j = 0; j < nitems(immutable); j++) {
			if (vmx_nested_state_ranges_overlap(mutable[i],
			    mutable_size[i], immutable[j], immutable_size[j]))
				return (false);
		}
	}
	return (true);
}

static bool
nvmx_vmexit_efer_valid(uint64_t efer)
{

	return ((efer & ~NVMXOUT_EFER_VALID) == 0);
}

static int
nvmx_l1_host_load(uint32_t vmexit,
    const struct vmx_nested_host_state *host,
    const struct vmx_nested_l1_runtime_state *prior,
    struct vmx_nested_l1_runtime_state *runtime)
{
	bool host_lma;

	if (host == NULL || prior == NULL || runtime == NULL)
		return (EINVAL);
	memset(runtime, 0, sizeof(*runtime));
	runtime->dr7 = 0x400;
	runtime->debugctl = 0;
	runtime->pat = (vmexit & NVMXOUT_EXIT_LOAD_PAT) != 0 ?
	    host->pat : prior->pat;
	if (!vmx_nested_pat_valid(runtime->pat))
		return (EINVAL);

	host_lma = (vmexit & NVMXOUT_EXIT_HOST_LMA) != 0;
	if (host->root_ia32e != host_lma)
		return (EINVAL);
	if ((vmexit & NVMXOUT_EXIT_LOAD_EFER) != 0) {
		runtime->efer = host->efer;
	} else {
		runtime->efer = prior->efer;
		runtime->efer &= ~(NVMXOUT_EFER_LMA | NVMXOUT_EFER_LME);
		if (host_lma)
			runtime->efer |= NVMXOUT_EFER_LMA | NVMXOUT_EFER_LME;
	}
	if (!nvmx_vmexit_efer_valid(runtime->efer) ||
	    ((runtime->efer & NVMXOUT_EFER_LMA) != 0) != host_lma ||
	    ((runtime->efer & NVMXOUT_EFER_LME) != 0) != host_lma)
		return (EINVAL);
	return (0);
}

static void
nvmx_l1_processor_state(const struct vmx_nested_host_state *host,
    const struct vmx_nested_l1_runtime_state *runtime,
    struct vmx_nested_guest_control_state *control,
    struct vmx_nested_guest_arch_state *arch)
{

	memset(control, 0, sizeof(*control));
	memset(arch, 0, sizeof(*arch));
	control->cr0 = host->cr0;
	control->cr3 = host->cr3;
	control->cr4 = host->cr4;
	control->dr7 = runtime->dr7;
	control->sysenter_cs = host->sysenter_cs;
	control->sysenter_esp = host->sysenter_esp;
	control->sysenter_eip = host->sysenter_eip;
	control->pat = runtime->pat;
	control->efer = runtime->efer;

#define	NVMX_L1_DATA_SEGMENT(segment_id, selector_value, base_value) do { \
	arch->segment[(segment_id)].selector = (selector_value);	\
	arch->segment[(segment_id)].limit = UINT32_MAX;		\
	arch->segment[(segment_id)].access = 0xc093;		\
	arch->segment[(segment_id)].base = (base_value);		\
} while (0)
	NVMX_L1_DATA_SEGMENT(VMX_NESTED_GUEST_ES, host->es_selector, 0);
	NVMX_L1_DATA_SEGMENT(VMX_NESTED_GUEST_SS, host->ss_selector, 0);
	NVMX_L1_DATA_SEGMENT(VMX_NESTED_GUEST_DS, host->ds_selector, 0);
	NVMX_L1_DATA_SEGMENT(VMX_NESTED_GUEST_FS, host->fs_selector,
	    host->fs_base);
	NVMX_L1_DATA_SEGMENT(VMX_NESTED_GUEST_GS, host->gs_selector,
	    host->gs_base);
#undef NVMX_L1_DATA_SEGMENT
	arch->segment[VMX_NESTED_GUEST_CS] =
	    (struct vmx_nested_guest_segment) {
		.selector = host->cs_selector,
		.limit = UINT32_MAX,
		.access = host->root_ia32e ? 0xa09b : 0xc09b,
	    };
	arch->segment[VMX_NESTED_GUEST_TR] =
	    (struct vmx_nested_guest_segment) {
		.selector = host->tr_selector,
		.limit = 0x67,
		.access = 0x8b,
		.base = host->tr_base,
	    };
	arch->segment[VMX_NESTED_GUEST_LDTR].access = 0x10000;
	arch->gdtr_limit = UINT16_MAX;
	arch->idtr_limit = UINT16_MAX;
	arch->gdtr_base = host->gdtr_base;
	arch->idtr_base = host->idtr_base;
	arch->rsp = host->rsp;
	arch->rip = host->rip;
	arch->rflags = 2;
	arch->debugctl = runtime->debugctl;
}

int
vmx_nested_vmexit_state_prepare(
    const struct vmx_nested_vmexit_state_input *input,
    struct vmx_nested_vmexit_state_plan *plan)
{
	struct vmx_nested_vmexit_state_plan candidate;
	int error;

	if (input == NULL || plan == NULL || input->l1_host == NULL ||
	    input->l2_runtime == NULL || input->vmcs12_control == NULL ||
	    input->vmcs12_arch == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->l1_host, sizeof(*input->l1_host)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->l2_runtime, sizeof(*input->l2_runtime)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->vmcs12_control, sizeof(*input->vmcs12_control)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->vmcs12_arch, sizeof(*input->vmcs12_arch)))
		return (EINVAL);
	if (!vmx_nested_pat_valid(input->l2_runtime->control.pat) ||
	    !nvmx_vmexit_efer_valid(input->l2_runtime->control.efer))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.saved_l2_control = input->l2_runtime->control;
	candidate.saved_l2_arch = input->l2_runtime->arch;
	candidate.saved_vmcs12_vmentry = input->vmcs12_vmentry;
	if (input->save_guest_lma) {
		if ((input->l2_runtime->control.efer &
		    NVMXOUT_EFER_LMA) != 0)
			candidate.saved_vmcs12_vmentry |=
			    NVMXOUT_ENTRY_GUEST_LMA;
		else
			candidate.saved_vmcs12_vmentry &=
			    ~NVMXOUT_ENTRY_GUEST_LMA;
	}
	candidate.saved_vmcs12_entry_intr_info =
	    input->vmcs12_entry_intr_info & ~NVMXOUT_ENTRY_INTR_VALID;
	if ((input->vmexit & NVMXOUT_EXIT_SAVE_DEBUG) == 0) {
		candidate.saved_l2_control.dr7 = input->vmcs12_control->dr7;
		candidate.saved_l2_arch.debugctl = input->vmcs12_arch->debugctl;
	}
	if ((input->vmexit & NVMXOUT_EXIT_SAVE_PAT) == 0)
		candidate.saved_l2_control.pat = input->vmcs12_control->pat;
	if ((input->vmexit & NVMXOUT_EXIT_SAVE_EFER) == 0)
		candidate.saved_l2_control.efer = input->vmcs12_control->efer;

	candidate.l1_host = *input->l1_host;
	error = nvmx_l1_host_load(input->vmexit, input->l1_host,
	    &(struct vmx_nested_l1_runtime_state) {
		.dr7 = input->l2_runtime->control.dr7,
		.debugctl = input->l2_runtime->arch.debugctl,
		.pat = input->l2_runtime->control.pat,
		.efer = input->l2_runtime->control.efer,
	    }, &candidate.l1_runtime);
	if (error != 0)
		return (error);
	nvmx_l1_processor_state(input->l1_host, &candidate.l1_runtime,
	    &candidate.l1_control, &candidate.l1_arch);

	*plan = candidate;
	return (0);
}

int
vmx_nested_failed_entry_state_prepare(
    const struct vmx_nested_failed_entry_state_input *input,
    struct vmx_nested_failed_entry_state_plan *plan)
{
	struct vmx_nested_failed_entry_state_plan candidate;
	int error;

	if (input == NULL || plan == NULL || input->l1_host == NULL ||
	    input->pre_entry_l1 == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->l1_host, sizeof(*input->l1_host)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan),
	    input->pre_entry_l1, sizeof(*input->pre_entry_l1)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.l1_host = *input->l1_host;
	error = nvmx_l1_host_load(input->vmexit, input->l1_host,
	    input->pre_entry_l1, &candidate.l1_runtime);
	if (error != 0)
		return (error);

	nvmx_l1_processor_state(input->l1_host, &candidate.l1_runtime,
	    &candidate.l1_control, &candidate.l1_arch);
	*plan = candidate;
	return (0);
}

int
vmx_nested_vmexit_msr_load_prepare(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmexit_state_plan *base,
    const struct vmx_nested_software_msrs *base_software,
    bool syscall_available, bool tsc_aux_available,
    const struct vmx_nested_msr_entry *entries, uint32_t count,
    struct vmx_nested_msr_entry *rollback, uint32_t rollback_capacity,
    struct vmx_nested_vmexit_state_plan *plan,
    struct vmx_nested_software_msrs *software,
    enum vmx_nested_exit_msr_load_outcome *outcome,
    uint32_t *failed_entry)
{
	struct vmx_nested_vmexit_state_plan candidate;
	struct vmx_nested_software_msrs software_candidate;
	struct vmx_nested_virtual_msr virtual_msr;
	enum vmx_nested_exit_msr_load_outcome candidate_outcome;
	uint32_t candidate_failed;
	int error;

	if (capabilities == NULL || base == NULL || base_software == NULL ||
	    plan == NULL || software == NULL || outcome == NULL ||
	    failed_entry == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    (count != 0 && entries == NULL))
		return (EINVAL);
	if (!nvmx_vmexit_msr_storage_valid(base, sizeof(*base), capabilities,
	    base_software, entries, count, rollback, rollback_capacity, plan,
	    sizeof(*plan), software, outcome, failed_entry))
		return (EINVAL);
	candidate = *base;
	software_candidate = *base_software;
	memset(&virtual_msr, 0, sizeof(virtual_msr));
	virtual_msr.capabilities = capabilities;
	virtual_msr.control = &candidate.l1_control;
	virtual_msr.arch = &candidate.l1_arch;
	virtual_msr.software = &software_candidate;
	virtual_msr.syscall_available = syscall_available;
	virtual_msr.tsc_aux_available = tsc_aux_available;
	candidate_outcome = VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
	candidate_failed = 0;
	error = vmx_nested_exit_msr_load_apply(entries, count,
	    vmx_nested_virtual_msr_apply_ops(), &virtual_msr, rollback,
	    rollback_capacity, &candidate_outcome, &candidate_failed);
	*outcome = candidate_outcome;
	*failed_entry = candidate_failed;
	if (error != 0)
		return (error);
	*plan = candidate;
	*software = software_candidate;
	return (0);
}

int
vmx_nested_failed_entry_msr_load_prepare(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_failed_entry_state_plan *base,
    const struct vmx_nested_software_msrs *base_software,
    bool syscall_available, bool tsc_aux_available,
    const struct vmx_nested_msr_entry *entries, uint32_t count,
    struct vmx_nested_msr_entry *rollback, uint32_t rollback_capacity,
    struct vmx_nested_failed_entry_state_plan *plan,
    struct vmx_nested_software_msrs *software,
    enum vmx_nested_exit_msr_load_outcome *outcome,
    uint32_t *failed_entry)
{
	struct vmx_nested_failed_entry_state_plan candidate;
	struct vmx_nested_software_msrs software_candidate;
	struct vmx_nested_virtual_msr virtual_msr;
	enum vmx_nested_exit_msr_load_outcome candidate_outcome;
	uint32_t candidate_failed;
	int error;

	if (capabilities == NULL || base == NULL || base_software == NULL ||
	    plan == NULL || software == NULL || outcome == NULL ||
	    failed_entry == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    (count != 0 && entries == NULL))
		return (EINVAL);
	if (!nvmx_vmexit_msr_storage_valid(base, sizeof(*base), capabilities,
	    base_software, entries, count, rollback, rollback_capacity, plan,
	    sizeof(*plan), software, outcome, failed_entry))
		return (EINVAL);
	candidate = *base;
	software_candidate = *base_software;
	memset(&virtual_msr, 0, sizeof(virtual_msr));
	virtual_msr.capabilities = capabilities;
	virtual_msr.control = &candidate.l1_control;
	virtual_msr.arch = &candidate.l1_arch;
	virtual_msr.software = &software_candidate;
	virtual_msr.syscall_available = syscall_available;
	virtual_msr.tsc_aux_available = tsc_aux_available;
	candidate_outcome = VMX_NESTED_EXIT_MSR_LOAD_HOST_FAILED;
	candidate_failed = 0;
	error = vmx_nested_exit_msr_load_apply(entries, count,
	    vmx_nested_virtual_msr_apply_ops(), &virtual_msr, rollback,
	    rollback_capacity, &candidate_outcome, &candidate_failed);
	*outcome = candidate_outcome;
	*failed_entry = candidate_failed;
	if (error != 0)
		return (error);
	*plan = candidate;
	*software = software_candidate;
	return (0);
}
