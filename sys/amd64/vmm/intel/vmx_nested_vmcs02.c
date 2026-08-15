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
#include "vmx_nested_msr_state.h"
#include "vmx_nested_validate.h"
#include "vmx_nested_vmcs02.h"
#include "vmx_nested_state_range.h"

#define	NVMX_PIN_PREEMPTION_TIMER	(UINT32_C(1) << 6)
#define	NVMX_PIN_POSTED_INTERRUPT	(UINT32_C(1) << 7)
#define	NVMX_PRIMARY_TSC_OFFSET		(UINT32_C(1) << 3)
#define	NVMX_PRIMARY_CR3_LOAD_EXITING	(UINT32_C(1) << 15)
#define	NVMX_PRIMARY_CR8_LOAD_EXITING	(UINT32_C(1) << 19)
#define	NVMX_PRIMARY_CR8_STORE_EXITING	(UINT32_C(1) << 20)
#define	NVMX_PRIMARY_TPR_SHADOW		(UINT32_C(1) << 21)
#define	NVMX_PRIMARY_UNCONDITIONAL_IO	(UINT32_C(1) << 24)
#define	NVMX_PRIMARY_IO_BITMAPS		(UINT32_C(1) << 25)
#define	NVMX02_ENTRY_LOAD_DEBUG		(UINT32_C(1) << 2)
#define	NVMX02_ENTRY_GUEST_LMA		(UINT32_C(1) << 9)
#define	NVMX02_ENTRY_LOAD_PAT		(UINT32_C(1) << 14)
#define	NVMX02_ENTRY_LOAD_EFER		(UINT32_C(1) << 15)
#define	NVMX02_CR0_PG			(UINT64_C(1) << 31)
#define	NVMX02_EFER_LME			(UINT64_C(1) << 8)
#define	NVMX02_EFER_LMA			(UINT64_C(1) << 10)
#define	NVMX02_EFER_VALID		((UINT64_C(1) << 0) | \
	    NVMX02_EFER_LME | NVMX02_EFER_LMA | (UINT64_C(1) << 11))
#define	NVMX_SECONDARY_EPT		(UINT32_C(1) << 1)
#define	NVMX_SECONDARY_APIC_MASK	\
	((UINT32_C(1) << 0) | (UINT32_C(1) << 4) |		\
	 (UINT32_C(1) << 8) | (UINT32_C(1) << 9))
#define	NVMX_SECONDARY_VPID		(UINT32_C(1) << 5)
#define	NVMX_SECONDARY_MBEC		(UINT32_C(1) << 22)
#define	NVMX_SECONDARY_PLE		(UINT32_C(1) << 10)
#define	NVMX_SECONDARY_TSC_SCALING	(UINT32_C(1) << 25)
#define	NVMX_MISC_SAVE_EFER_LMA		(UINT64_C(1) << 5)

static bool
nvmx_vmcs02_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmx_vmcs02_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (vmx_nested_vmcs02_id_equal(a, b));
}

static void
nvmx_control_capabilities(const struct vmx_nested_capabilities *source,
    struct vmx_nested_vmcs02_capabilities *result)
{

	result->pinbased = source->pinbased;
	result->primary = source->primary;
	result->secondary = source->secondary;
	result->vmexit = source->vmexit;
	result->vmentry = source->vmentry;
}

static bool
nvmx_l1_runtime_valid(const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_l1_runtime_state *runtime)
{

	return (runtime != NULL && (runtime->dr7 >> 32) == 0 &&
	    (runtime->debugctl & ~capabilities->debugctl_allowed) == 0 &&
	    vmx_nested_pat_valid(runtime->pat) &&
	    (runtime->efer & ~NVMX02_EFER_VALID) == 0);
}

int
vmx_nested_vmcs02_effective_guest_state(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_entry_controls *entry,
    const struct vmx_nested_l1_runtime_state *runtime,
    const struct vmx_nested_guest_control_state *vmcs12_control,
    const struct vmx_nested_guest_arch_state *vmcs12_arch,
    struct vmx_nested_guest_control_state *effective_control,
    struct vmx_nested_guest_arch_state *effective_arch)
{
	struct vmx_nested_guest_control_state control;
	struct vmx_nested_guest_arch_state arch;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    entry == NULL || !nvmx_l1_runtime_valid(capabilities, runtime) ||
	    vmcs12_control == NULL || vmcs12_arch == NULL ||
	    effective_control == NULL || effective_arch == NULL)
		return (EINVAL);
	control = *vmcs12_control;
	arch = *vmcs12_arch;
	if ((entry->vmentry & NVMX02_ENTRY_LOAD_DEBUG) == 0) {
		control.dr7 = runtime->dr7;
		arch.debugctl = runtime->debugctl;
	}
	if ((entry->vmentry & NVMX02_ENTRY_LOAD_PAT) == 0)
		control.pat = runtime->pat;
	if ((entry->vmentry & NVMX02_ENTRY_LOAD_EFER) == 0) {
		control.efer = runtime->efer;
		if ((entry->vmentry & NVMX02_ENTRY_GUEST_LMA) != 0)
			control.efer |= NVMX02_EFER_LMA;
		else
			control.efer &= ~NVMX02_EFER_LMA;
		if ((control.cr0 & NVMX02_CR0_PG) != 0) {
			if ((entry->vmentry & NVMX02_ENTRY_GUEST_LMA) != 0)
				control.efer |= NVMX02_EFER_LME;
			else
				control.efer &= ~NVMX02_EFER_LME;
		}
	}
	*effective_control = control;
	*effective_arch = arch;
	return (0);
}

static int
nvmx_vmcs02_preflight(const struct vmx_nested_vmcs02_input *input)
{
	struct vmx_nested_vmcs02_capabilities virtual;
	uint64_t capability_signature;
	int error;

	if (input == NULL || !nvmx_vmcs02_id_valid(&input->id) ||
	    vmx_nested_capabilities_validate(input->virtual_capabilities) != 0 ||
	    input->hardware_capabilities == NULL ||
	    input->control_policy == NULL || input->l0_controls == NULL ||
	    input->l0_execution == NULL ||
	    input->l1_runtime == NULL ||
	    input->vmentry == NULL || input->vmentry->controls == NULL ||
	    input->vmentry->execution == NULL ||
	    input->tsc == NULL || input->vpid == NULL ||
	    input->capability_signature == 0 ||
	    input->preemption_timer_rate > 31)
		return (EINVAL);
	if (!nvmx_l1_runtime_valid(input->virtual_capabilities,
	    input->l1_runtime))
		return (EINVAL);
	if (!vmx_nested_region_gpa_valid(input->virtual_capabilities,
	    input->id.vmcs12_gpa) ||
	    input->vmentry->current_vmcs != input->id.vmcs12_gpa ||
	    input->preemption_timer_rate !=
	    (input->virtual_capabilities->misc & UINT64_C(0x1f)))
		return (EINVAL);
	error = vmx_nested_capabilities_signature(
	    input->virtual_capabilities, &capability_signature);
	if (error != 0)
		return (error);
	if (input->capability_signature != capability_signature)
		return (EINVAL);

	nvmx_control_capabilities(input->virtual_capabilities, &virtual);
	error = vmx_nested_vmcs02_policy_validate(input->control_policy,
	    &virtual, input->hardware_capabilities);
	if (error != 0)
		return (error);
	return (0);
}

static int
nvmx_vmcs02_prepare(const struct vmx_nested_vmcs02_input *input,
    const struct vmx_nested_vmentry_result *validated,
    struct vmx_nested_vmcs02_plan *plan)
{
	struct vmx_nested_vmcs02_controls l1;
	struct vmx_nested_execution_compose_input execution;
	struct vmx_nested_vmcs02_plan candidate;
	const struct vmx_nested_entry_controls *entry;
	bool ept_enabled, timer_enabled, tsc_offset, tsc_scaling;
	bool vpid_enabled;
	int error;

	if (plan == NULL)
		return (EINVAL);
	error = nvmx_vmcs02_preflight(input);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = input->id;
	if (validated == NULL) {
		error = vmx_nested_vmentry_validate(
		    input->virtual_capabilities, input->vmentry,
		    &candidate.vmentry);
		if (error != 0)
			return (error);
	} else {
		candidate.vmentry = *validated;
	}
	if (candidate.vmentry.disposition != VMX_NESTED_VMENTRY_READY) {
		*plan = candidate;
		return (0);
	}

	entry = input->vmentry->controls;
	ept_enabled = (entry->secondary & NVMX_SECONDARY_EPT) != 0;
	vpid_enabled = (entry->secondary & NVMX_SECONDARY_VPID) != 0;
	timer_enabled = (entry->pinbased & NVMX_PIN_PREEMPTION_TIMER) != 0;
	tsc_offset = (entry->primary & NVMX_PRIMARY_TSC_OFFSET) != 0;
	tsc_scaling =
	    (entry->secondary & NVMX_SECONDARY_TSC_SCALING) != 0;
	if (timer_enabled != input->preemption_timer_enabled ||
	    tsc_offset != input->tsc->l2_offset_enabled ||
	    tsc_scaling != input->tsc->l2_scaling_enabled ||
	    input->vpid->direction != VMX_NESTED_VPID_ENTER_L2 ||
	    input->vpid->next_virtual_vpid_enabled != vpid_enabled ||
	    input->vpid->next_virtual_vpid !=
	    (vpid_enabled ? entry->vpid : 0))
		return (EINVAL);

	memset(&l1, 0, sizeof(l1));
	l1.pinbased = entry->pinbased;
	l1.primary = entry->primary;
	l1.secondary = entry->secondary;
	l1.vmexit = entry->vmexit;
	l1.vmentry = entry->vmentry;
	error = vmx_nested_vmcs02_controls_compose(input->l0_controls, &l1,
	    input->control_policy, input->hardware_capabilities,
	    &candidate.image.controls);
	if (error != 0)
		return (error);
	/*
	 * Production does not yet expose APIC virtualization controls to L1.
	 * Do not carry L0's APICv and posted-interrupt accelerations into L2:
	 * their singleton VMCS resources and event ownership cannot be
	 * inherited safely.  Use explicit CR8 exits until the L1-visible
	 * APICv path has complete entry, exit, interrupt, and restore logic.
	 *
	 * If a future virtual capability contract exposes one of these bits,
	 * the policy above makes it L1-owned and this fallback no longer
	 * removes it.
	 */
	if (((uint32_t)(input->virtual_capabilities->pinbased >> 32) &
	    NVMX_PIN_POSTED_INTERRUPT) == 0)
		candidate.image.controls.pinbased &=
		    ~NVMX_PIN_POSTED_INTERRUPT;
	if (((uint32_t)(input->virtual_capabilities->primary >> 32) &
	    NVMX_PRIMARY_TPR_SHADOW) == 0) {
		candidate.image.controls.primary &=
		    ~NVMX_PRIMARY_TPR_SHADOW;
		candidate.image.controls.primary |=
		    NVMX_PRIMARY_CR8_LOAD_EXITING |
		    NVMX_PRIMARY_CR8_STORE_EXITING;
	}
	candidate.image.controls.secondary &=
	    ~((~(uint32_t)(input->virtual_capabilities->secondary >> 32)) &
	    NVMX_SECONDARY_APIC_MASK);
	/*
	 * Unconditional I/O exiting dominates the I/O bitmaps in hardware.
	 * Canonicalize VMCS02 to the single stronger control so an L0 that
	 * intentionally exits on every I/O instruction never needs to map a
	 * VMCS12 bitmap into hardware.  Exit reflection still consults the
	 * preserved VMCS12 controls and bitmap through the software VMCS
	 * registry.
	 */
	if ((candidate.image.controls.primary &
	    NVMX_PRIMARY_UNCONDITIONAL_IO) != 0)
		candidate.image.controls.primary &=
		    ~NVMX_PRIMARY_IO_BITMAPS;
	if (!vmx_nested_control_valid(candidate.image.controls.pinbased,
	    input->hardware_capabilities->pinbased) ||
	    !vmx_nested_control_valid(candidate.image.controls.primary,
	    input->hardware_capabilities->primary) ||
	    !vmx_nested_control_valid(candidate.image.controls.secondary,
	    input->hardware_capabilities->secondary))
		return (ENOTSUP);
	memset(&execution, 0, sizeof(execution));
	execution.l0 = input->l0_execution;
	execution.l1 = input->vmentry->execution;
	execution.l0_cr3_target_count = input->l0_cr3_target_count;
	execution.l1_cr3_target_count = entry->cr3_target_count;
	execution.l0_cr3_load_exiting =
	    (input->l0_controls->primary &
	    NVMX_PRIMARY_CR3_LOAD_EXITING) != 0;
	execution.l1_cr3_load_exiting =
	    (entry->primary & NVMX_PRIMARY_CR3_LOAD_EXITING) != 0;
	execution.l0_ple_enabled =
	    (input->l0_controls->secondary & NVMX_SECONDARY_PLE) != 0;
	execution.l1_ple_enabled =
	    (entry->secondary & NVMX_SECONDARY_PLE) != 0;
	error = vmx_nested_execution_compose(&execution,
	    &candidate.image.execution);
	if (error != 0)
		return (error);
	error = vmx_nested_tsc_scale_compose(input->tsc,
	    &candidate.image.tsc);
	if (error != 0)
		return (error);
	error = vmx_nested_vpid_transition_plan(input->vpid,
	    &candidate.image.vpid);
	if (error != 0)
		return (error);
	if (timer_enabled) {
		error = vmx_nested_timer_prepare(
		    input->preemption_timer_value,
		    &candidate.image.preemption_timer);
		if (error != 0)
			return (error);
	}

	candidate.image.id = input->id;
	candidate.image.l1_runtime = *input->l1_runtime;
	candidate.image.l1_host = *input->vmentry->host;
	candidate.image.vmcs12_control = *input->vmentry->guest_control;
	candidate.image.vmcs12_arch = *input->vmentry->guest_arch;
	error = vmx_nested_vmcs02_effective_guest_state(
	    input->virtual_capabilities, entry, input->l1_runtime,
	    input->vmentry->guest_control, input->vmentry->guest_arch,
	    &candidate.image.l2_control, &candidate.image.l2_arch);
	if (error != 0)
		return (error);

	/*
	 * A hardware VM exit from L2 returns to L0, not directly to L1.
	 * Therefore VMCS02 uses VMCS01's exit controls verbatim; VMCS12's
	 * save/load requests are implemented by the nested-exit transaction.
	 *
	 * Conversely, entering L2 must load the already-computed effective
	 * debug, PAT, and EFER values from the VMCS02 guest-state area.  The
	 * processor is currently in L0 host state, so leaving one of these
	 * hardware load controls clear would retain host state rather than
	 * the architecturally required pre-entry L1 value.  IA-32e mode is
	 * derived from that effective EFER, not copied from VMCS01.
	 */
	candidate.image.controls.vmexit = input->l0_controls->vmexit;
	candidate.image.controls.vmentry |= NVMX02_ENTRY_LOAD_DEBUG |
	    NVMX02_ENTRY_LOAD_PAT | NVMX02_ENTRY_LOAD_EFER;
	if ((candidate.image.l2_control.efer & NVMX02_EFER_LMA) != 0)
		candidate.image.controls.vmentry |= NVMX02_ENTRY_GUEST_LMA;
	else
		candidate.image.controls.vmentry &= ~NVMX02_ENTRY_GUEST_LMA;
	if (!vmx_nested_control_valid(candidate.image.controls.vmexit,
	    input->hardware_capabilities->vmexit) ||
	    !vmx_nested_control_valid(candidate.image.controls.vmentry,
	    input->hardware_capabilities->vmentry))
		return (ENOTSUP);

	candidate.image.pdpte = candidate.vmentry.pdpte;
	candidate.image.entry_intr_info = entry->entry_intr_info;
	candidate.image.entry_exception_error =
	    entry->entry_exception_error;
	candidate.image.entry_instruction_length =
	    entry->entry_instruction_length;
	candidate.image.vmcs12_vmexit = entry->vmexit;
	candidate.image.vmcs12_vmentry = entry->vmentry;
	candidate.image.vmcs12_entry_intr_info = entry->entry_intr_info;
	candidate.image.tpr_threshold = entry->tpr_threshold;
	candidate.image.cr3_target_count =
	    candidate.image.execution.cr3_target_count;
	candidate.image.posted_interrupt_vector =
	    entry->posted_interrupt_vector;
	candidate.image.preemption_timer_rate =
	    timer_enabled ? input->preemption_timer_rate : 0;
	candidate.image.ept_enabled = ept_enabled;
	candidate.image.preemption_timer_enabled = timer_enabled;
	candidate.image.save_guest_lma =
	    (input->virtual_capabilities->misc &
	    NVMX_MISC_SAVE_EFER_LMA) != 0;
	if (ept_enabled) {
		candidate.image.ept.eptp = entry->eptp;
		candidate.image.ept.capability_signature =
		    input->capability_signature;
		candidate.image.ept.mode_based_execute =
		    (entry->secondary & NVMX_SECONDARY_MBEC) != 0;
	}
	*plan = candidate;
	return (0);
}

int
vmx_nested_vmcs02_arm_timer(struct vmx_nested_vmcs02_plan *plan,
    uint64_t l1_virtual_tsc)
{
	struct vmx_nested_vmcs02_plan candidate;
	int error;

	if (plan == NULL ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY)
		return (EINVAL);
	if (!plan->image.preemption_timer_enabled) {
		if (plan->image.preemption_timer.deadline_ticks != 0 ||
		    plan->image.preemption_timer.remaining != 0 ||
		    plan->image.preemption_timer.armed ||
		    plan->image.preemption_timer.expired)
			return (EPROTO);
		return (0);
	}
	if (plan->image.preemption_timer.armed)
		return (EALREADY);
	candidate = *plan;
	error = vmx_nested_timer_start(l1_virtual_tsc,
	    candidate.image.preemption_timer_rate,
	    candidate.image.preemption_timer.remaining,
	    &candidate.image.preemption_timer);
	if (error != 0)
		return (error);
	*plan = candidate;
	return (0);
}

int
vmx_nested_vmcs02_rearm_timer(struct vmx_nested_vmcs02_plan *plan,
    uint64_t l1_virtual_tsc)
{
	struct vmx_nested_vmcs02_plan candidate;
	int error;

	if (plan == NULL ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY)
		return (EINVAL);
	if (!plan->image.preemption_timer_enabled) {
		if (plan->image.preemption_timer.deadline_ticks != 0 ||
		    plan->image.preemption_timer.remaining != 0 ||
		    plan->image.preemption_timer.armed ||
		    plan->image.preemption_timer.expired)
			return (EPROTO);
		return (0);
	}
	if (!plan->image.preemption_timer.armed)
		return (EINVAL);
	candidate = *plan;
	error = vmx_nested_timer_start(l1_virtual_tsc,
	    candidate.image.preemption_timer_rate,
	    candidate.image.preemption_timer.remaining,
	    &candidate.image.preemption_timer);
	if (error != 0)
		return (error);
	*plan = candidate;
	return (0);
}

int
vmx_nested_vmcs02_prepare(const struct vmx_nested_vmcs02_input *input,
    struct vmx_nested_vmcs02_plan *plan)
{

	return (nvmx_vmcs02_prepare(input, NULL, plan));
}

int
vmx_nested_vmcs02_prepare_frozen(
    const struct vmx_nested_vmcs02_input *input,
    struct vmx_nested_msr_entry *entries, uint32_t capacity,
    uint32_t *snapshot_count, struct vmx_nested_vmcs02_plan *plan)
{
	struct vmx_nested_vmentry_result validated;
	uint32_t count;
	int error;

	if (input == NULL || input->vmentry == NULL ||
	    snapshot_count == NULL || plan == NULL)
		return (EINVAL);
	error = nvmx_vmcs02_preflight(input);
	if (error != 0)
		return (error);
	count = 0;
	error = vmx_nested_vmentry_snapshot_validate(
	    input->virtual_capabilities, input->vmentry, entries, capacity,
	    &count, &validated);
	if (error != 0)
		return (error);
	error = nvmx_vmcs02_prepare(input, &validated, plan);
	if (error != 0)
		return (error);
	*snapshot_count = count;
	return (0);
}

int
vmx_nested_vmcs02_recompose_frozen(
    const struct vmx_nested_vmcs02_input *input,
    const struct vmx_nested_vmentry_result *validated,
    struct vmx_nested_vmcs02_plan *plan)
{

	if (validated == NULL ||
	    validated->disposition != VMX_NESTED_VMENTRY_READY ||
	    validated->stage != VMX_NESTED_VMENTRY_STAGE_NONE ||
	    validated->instruction_error != 0 ||
	    validated->exit_reason != 0 ||
	    validated->exit_qualification != 0 ||
	    validated->detail != 0)
		return (EINVAL);
	/*
	 * nvmx_vmcs02_prepare() consumes the prior validation result directly.
	 * It therefore cannot invoke a guest-memory or MSR-policy callback
	 * while recomposing L0 controls and execution state on the launch CPU.
	 */
	return (nvmx_vmcs02_prepare(input, validated, plan));
}

int
vmx_nested_vmcs02_apply_frozen_msrs(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_msr_entry *entries, uint32_t count,
    const struct vmx_nested_software_msrs *base_software,
    struct vmx_nested_msr_entry *rollback, uint32_t rollback_capacity,
    bool syscall_available, bool tsc_aux_available,
    const struct vmx_nested_vmcs02_plan *plan,
    struct vmx_nested_vmcs02_plan *result,
    struct vmx_nested_software_msrs *software)
{
	struct vmx_nested_virtual_msr virtual_msr;
	struct vmx_nested_vmcs02_plan candidate;
	struct vmx_nested_software_msrs software_candidate;
	enum vmx_nested_msr_apply_outcome outcome;
	uint32_t failed_entry;
	int error;

	if (capabilities == NULL || base_software == NULL || plan == NULL ||
	    result == NULL || software == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    !nvmx_vmcs02_id_valid(&plan->id) ||
	    !nvmx_vmcs02_id_equal(&plan->id, &plan->image.id) ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY ||
	    plan->vmentry.stage != VMX_NESTED_VMENTRY_STAGE_NONE ||
	    plan->vmentry.instruction_error != 0 ||
	    plan->vmentry.exit_reason != 0 ||
	    plan->vmentry.exit_qualification != 0 ||
	    plan->vmentry.detail != 0 ||
	    (count != 0 && (entries == NULL || rollback == NULL)) ||
	    rollback_capacity < count)
		return (EINVAL);

	candidate = *plan;
	software_candidate = *base_software;
	memset(&virtual_msr, 0, sizeof(virtual_msr));
	virtual_msr.capabilities = capabilities;
	virtual_msr.control = &candidate.image.l2_control;
	virtual_msr.arch = &candidate.image.l2_arch;
	virtual_msr.software = &software_candidate;
	virtual_msr.syscall_available = syscall_available;
	virtual_msr.tsc_aux_available = tsc_aux_available;
	outcome = VMX_NESTED_MSR_APPLY_OK;
	failed_entry = 0;
	error = vmx_nested_msr_list_apply(entries, count,
	    vmx_nested_virtual_msr_apply_ops(), &virtual_msr, rollback,
	    rollback_capacity, &outcome, &failed_entry);
	if (error != 0)
		return (error);
	if (outcome != VMX_NESTED_MSR_APPLY_OK || failed_entry != 0)
		return (EPROTO);
	*result = candidate;
	*software = software_candidate;
	return (0);
}

void
vmx_nested_vmcs02_commit_init(struct vmx_nested_vmcs02_commit *commit)
{

	if (commit != NULL)
		memset(commit, 0, sizeof(*commit));
}

static void
nvmx_vmcs02_resolve_host_error(struct vmx_nested_vmcs02_commit *commit,
    int error)
{

	memset(&commit->result, 0, sizeof(commit->result));
	commit->result.id = commit->image.id;
	commit->result.disposition = VMX_NESTED_VMCS02_HOST_ERROR;
	commit->result.host_error = error != 0 ? error : EIO;
	commit->state = VMX_NESTED_VMCS02_COMMIT_RESOLVED;
}

int
vmx_nested_vmcs02_commit_publish(struct vmx_nested_vmcs02_commit *commit,
    const struct vmx_nested_vmcs02_plan *plan)
{

	if (commit == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), commit,
	    sizeof(*commit)) ||
	    !nvmx_vmcs02_id_valid(&plan->id) ||
	    !nvmx_vmcs02_id_equal(&plan->id, &plan->image.id) ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY)
		return (EINVAL);
	if (commit->state != VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (EBUSY);
	commit->image = plan->image;
	commit->state = VMX_NESTED_VMCS02_COMMIT_PENDING;
	return (0);
}

int
vmx_nested_vmcs02_commit_apply(struct vmx_nested_vmcs02_commit *commit,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmcs02_apply_ops *ops, void *arg)
{
	enum vmx_nested_vmcs02_apply_outcome outcome;
	struct vmx_nested_vmcs02_apply_ops ops_snapshot;
	struct vmx_nested_vmcs02_image image_snapshot;
	int host_error;

	if (commit == NULL || !nvmx_vmcs02_id_valid(id) || ops == NULL ||
	    ops->apply == NULL ||
	    vmx_nested_state_ranges_overlap(commit, sizeof(*commit), ops,
	    sizeof(*ops)))
		return (EINVAL);
	if (commit->state == VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (ENOENT);
	if (!nvmx_vmcs02_id_equal(id, &commit->image.id))
		return (ESTALE);
	if (commit->state != VMX_NESTED_VMCS02_COMMIT_PENDING)
		return (EBUSY);

	/* The adapter gets one immutable VMCS02 programming image per attempt. */
	ops_snapshot = *ops;
	image_snapshot = commit->image;
	commit->state = VMX_NESTED_VMCS02_COMMIT_APPLYING;
	host_error = 0;
	outcome = ops_snapshot.apply(arg, &image_snapshot, &host_error);
	if (commit->state != VMX_NESTED_VMCS02_COMMIT_APPLYING) {
		/* A private adapter changed transaction ownership behind our back. */
		commit->image = image_snapshot;
		commit->state = VMX_NESTED_VMCS02_COMMIT_PENDING;
		return (EPROTO);
	}
	if (outcome == VMX_NESTED_VMCS02_APPLY_RETRY) {
		commit->state = VMX_NESTED_VMCS02_COMMIT_PENDING;
		return (host_error != 0 ? host_error : EAGAIN);
	}
	memset(&commit->result, 0, sizeof(commit->result));
	commit->result.id = commit->image.id;
	if (outcome == VMX_NESTED_VMCS02_APPLY_OK) {
		if (host_error != 0) {
			nvmx_vmcs02_resolve_host_error(commit, EPROTO);
			return (0);
		}
		commit->result.disposition = VMX_NESTED_VMCS02_COMMITTED;
	} else if (outcome == VMX_NESTED_VMCS02_APPLY_FATAL) {
		nvmx_vmcs02_resolve_host_error(commit, host_error);
		return (0);
	} else {
		nvmx_vmcs02_resolve_host_error(commit, EPROTO);
		return (0);
	}
	commit->state = VMX_NESTED_VMCS02_COMMIT_RESOLVED;
	return (0);
}

int
vmx_nested_vmcs02_commit_take(struct vmx_nested_vmcs02_commit *commit,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_vmcs02_commit_result *result)
{

	if (commit == NULL || !nvmx_vmcs02_id_valid(id) || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), commit,
	    sizeof(*commit)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), id,
	    sizeof(*id)))
		return (EINVAL);
	if (commit->state == VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (ENOENT);
	if (!nvmx_vmcs02_id_equal(id, &commit->image.id))
		return (ESTALE);
	if (commit->state != VMX_NESTED_VMCS02_COMMIT_RESOLVED)
		return (EBUSY);
	*result = commit->result;
	memset(commit, 0, sizeof(*commit));
	return (0);
}

int
vmx_nested_vmcs02_commit_cancel(struct vmx_nested_vmcs02_commit *commit,
    const struct vmx_nested_vmcs02_id *id)
{

	if (commit == NULL || !nvmx_vmcs02_id_valid(id))
		return (EINVAL);
	if (commit->state == VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (ENOENT);
	if (!nvmx_vmcs02_id_equal(id, &commit->image.id))
		return (ESTALE);
	if (commit->state != VMX_NESTED_VMCS02_COMMIT_PENDING)
		return (EBUSY);
	memset(commit, 0, sizeof(*commit));
	return (0);
}
