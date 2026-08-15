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
#include "vmx_nested_entry_environment.h"
#include "vmx_nested_state_range.h"

/* Intel SDM Vol. 3C, secondary processor-based execution controls. */
#define	NVMX_ENV_APIC_REGISTER_VIRTUALIZATION	(UINT32_C(1) << 8)
#define	NVMX_ENV_VIRTUAL_INTERRUPT_DELIVERY	(UINT32_C(1) << 9)
#define	NVMX_ENV_PAUSE_LOOP_EXITING		(UINT32_C(1) << 10)
#define	NVMX_ENV_TSC_OFFSETTING			(UINT32_C(1) << 3)
#define	NVMX_ENV_VPID				(UINT32_C(1) << 5)
#define	NVMX_ENV_TSC_SCALING			(UINT32_C(1) << 25)
#define	NVMX_ENV_PREEMPTION_TIMER		(UINT32_C(1) << 6)
#define	NVMX_ENV_HOST_ADDRESS_SPACE_SIZE	(UINT32_C(1) << 9)

static int
nvmx_environment_read(
    const struct vmx_nested_entry_environment_capture_ops *ops, void *arg,
    enum vmx_nested_entry_environment_field field, uint64_t *value)
{
	int error;

	*value = 0;
	error = ops->read(arg, field, value);
	if (error < 0)
		return (EPROTO);
	return (error);
}

static bool
nvmx_environment_id_equal(const struct vmx_nested_vmcs02_id *left,
    const struct vmx_nested_vmcs02_id *right)
{

	return (vmx_nested_vmcs02_id_equal(left, right));
}

static bool
nvmx_environment_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static int
nvmx_environment_controls_valid(
    const struct vmx_nested_entry_environment *environment)
{

#define	NVMX_ENV_CONTROL_VALID(member)					\
	if (!vmx_nested_control_valid(environment->l0_controls.member,	\
	    environment->hardware_controls.member))			\
		return (ENOTSUP)
	NVMX_ENV_CONTROL_VALID(pinbased);
	NVMX_ENV_CONTROL_VALID(primary);
	NVMX_ENV_CONTROL_VALID(secondary);
	NVMX_ENV_CONTROL_VALID(vmexit);
	NVMX_ENV_CONTROL_VALID(vmentry);
#undef NVMX_ENV_CONTROL_VALID
	return (0);
}

static int
nvmx_environment_l1_tsc_valid(
    const struct vmx_nested_tsc_scale_input *tsc)
{
	struct vmx_nested_tsc_scale_input l1;
	struct vmx_nested_tsc_scale_plan plan;

	if (tsc == NULL)
		return (EINVAL);
	l1 = *tsc;
	/*
	 * VMCS12 values may still be architecturally invalid at capture
	 * time.  Validate only the hardware-owned L0-to-L1 half here; the
	 * frozen VM-entry validator must classify invalid L2 offset/scaling
	 * state as VMfail or an entry failure before VMCS02 composition.
	 */
	l1.l2_offset = 0;
	l1.l2_multiplier = VMX_NESTED_TSC_MULTIPLIER_ONE;
	l1.l2_offset_enabled = false;
	l1.l2_scaling_enabled = false;
	return (vmx_nested_tsc_scale_compose(&l1, &plan));
}

int
vmx_nested_entry_environment_validate(
    const struct vmx_nested_entry_environment *environment)
{
	struct vmx_nested_vpid_plan vpid_plan;
	uint32_t i;
	int error;

	if (environment == NULL ||
	    !nvmx_environment_id_valid(&environment->id) ||
	    environment->capability_signature == 0 ||
	    environment->l0_cr3_target_count > 4 ||
	    environment->preemption_timer_rate > 31 ||
	    environment->l0_host.root_ia32e !=
	    ((environment->l0_controls.vmexit &
	    NVMX_ENV_HOST_ADDRESS_SPACE_SIZE) != 0))
		return (EINVAL);
	error = vmx_nested_vmcs02_policy_validate(
	    &environment->control_policy, &environment->virtual_controls,
	    &environment->hardware_controls);
	if (error != 0)
		return (error);
	error = nvmx_environment_controls_valid(environment);
	if (error != 0)
		return (error);
	for (i = environment->l0_cr3_target_count; i < 4; i++) {
		if (environment->l0_execution.cr3_target[i] != 0)
			return (EPROTO);
	}
	if ((environment->l0_controls.secondary &
	    NVMX_ENV_PAUSE_LOOP_EXITING) == 0 &&
	    (environment->l0_execution.ple_gap != 0 ||
	    environment->l0_execution.ple_window != 0))
		return (EPROTO);
	if ((environment->l0_controls.secondary &
	    NVMX_ENV_APIC_REGISTER_VIRTUALIZATION) == 0) {
		for (i = 0; i < 4; i++) {
			if (environment->l0_execution.eoi_exit_bitmap[i] != 0)
				return (EPROTO);
		}
	}
	if ((environment->l0_controls.secondary &
	    NVMX_ENV_VIRTUAL_INTERRUPT_DELIVERY) == 0 &&
	    environment->l0_execution.guest_intr_status != 0)
		return (EPROTO);
	if (environment->tsc.l1_scaling_enabled !=
	    ((environment->l0_controls.secondary &
	    NVMX_ENV_TSC_SCALING) != 0) ||
	    (!environment->tsc.l1_scaling_enabled &&
	    environment->tsc.l1_multiplier !=
	    VMX_NESTED_TSC_MULTIPLIER_ONE) ||
	    ((environment->l0_controls.primary &
	    NVMX_ENV_TSC_OFFSETTING) == 0 &&
	    environment->tsc.l1_offset != 0))
		return (EPROTO);
	error = nvmx_environment_l1_tsc_valid(&environment->tsc);
	if (error != 0)
		return (error);
	if (environment->vpid.direction != VMX_NESTED_VPID_ENTER_L2)
		return (EINVAL);
	return (vmx_nested_vpid_transition_plan(&environment->vpid,
	    &vpid_plan));
}

int
vmx_nested_entry_environment_prepare(
    const struct vmx_nested_entry_environment_input *input,
    struct vmx_nested_entry_environment *environment)
{
	struct vmx_nested_entry_environment candidate;
	uint32_t i;
	int error;

	if (input == NULL || environment == NULL ||
	    input->virtual_controls == NULL ||
	    input->hardware_controls == NULL ||
	    input->control_policy == NULL || input->l0_controls == NULL ||
	    input->l0_execution == NULL || input->l0_host == NULL ||
	    input->l1_runtime == NULL ||
	    input->tsc == NULL || input->vpid == NULL ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input, sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->virtual_controls,
	    sizeof(*input->virtual_controls)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->hardware_controls,
	    sizeof(*input->hardware_controls)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->control_policy,
	    sizeof(*input->control_policy)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->l0_controls,
	    sizeof(*input->l0_controls)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->l0_execution,
	    sizeof(*input->l0_execution)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->l0_host,
	    sizeof(*input->l0_host)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->l1_runtime,
	    sizeof(*input->l1_runtime)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->tsc, sizeof(*input->tsc)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), input->vpid, sizeof(*input->vpid)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = input->id;
	candidate.virtual_controls = *input->virtual_controls;
	candidate.hardware_controls = *input->hardware_controls;
	candidate.control_policy = *input->control_policy;
	candidate.l0_controls = *input->l0_controls;
	candidate.l0_execution = *input->l0_execution;
	candidate.l0_host = *input->l0_host;
	candidate.l1_runtime = *input->l1_runtime;
	candidate.tsc = *input->tsc;
	candidate.vpid = *input->vpid;
	candidate.capability_signature = input->capability_signature;
	candidate.l1_virtual_tsc = input->l1_virtual_tsc;
	candidate.preemption_timer_value = input->preemption_timer_value;
	candidate.l0_cr3_target_count = input->l0_cr3_target_count;
	candidate.preemption_timer_rate = input->preemption_timer_rate;
	candidate.preemption_timer_enabled = input->preemption_timer_enabled;

	/*
	 * Inactive VMCS fields are architecturally ignored.  Canonicalizing
	 * them here prevents stale hardware values from influencing equality,
	 * diagnostics, or a later refactor which consumes the snapshot.
	 */
	if (candidate.l0_cr3_target_count <= 4) {
		for (i = candidate.l0_cr3_target_count; i < 4; i++)
			candidate.l0_execution.cr3_target[i] = 0;
	}
	if ((candidate.l0_controls.secondary &
	    NVMX_ENV_PAUSE_LOOP_EXITING) == 0) {
		candidate.l0_execution.ple_gap = 0;
		candidate.l0_execution.ple_window = 0;
	}
	if ((candidate.l0_controls.secondary &
	    NVMX_ENV_APIC_REGISTER_VIRTUALIZATION) == 0) {
		for (i = 0; i < 4; i++)
			candidate.l0_execution.eoi_exit_bitmap[i] = 0;
	}
	if ((candidate.l0_controls.secondary &
	    NVMX_ENV_VIRTUAL_INTERRUPT_DELIVERY) == 0)
		candidate.l0_execution.guest_intr_status = 0;

	error = vmx_nested_entry_environment_validate(&candidate);
	if (error != 0)
		return (error);
	*environment = candidate;
	return (0);
}

int
vmx_nested_entry_environment_capture_validate(
    const struct vmx_nested_entry_environment_capture *capture)
{
	struct vmx_nested_vpid_plan vpid_plan;
	int error;

	/*
	 * Reject all value-only metadata before invoking the adapter.  A
	 * malformed or stale request must perform no VMREAD and must not
	 * acquire any architecture-specific capture state.
	 */
	if (capture == NULL || !nvmx_environment_id_valid(&capture->id) ||
	    capture->capability_signature == 0 ||
	    capture->preemption_timer_rate > 31 ||
	    capture->tsc.l1_offset != 0 ||
	    capture->tsc.l1_multiplier !=
	    VMX_NESTED_TSC_MULTIPLIER_ONE ||
	    capture->tsc.l1_scaling_enabled ||
	    capture->vpid.direction != VMX_NESTED_VPID_ENTER_L2)
		return (EINVAL);
	error = vmx_nested_vmcs02_policy_validate(&capture->control_policy,
	    &capture->virtual_controls, &capture->hardware_controls);
	if (error != 0)
		return (error);
	error = nvmx_environment_l1_tsc_valid(&capture->tsc);
	if (error != 0)
		return (error);
	error = vmx_nested_vpid_transition_plan(&capture->vpid, &vpid_plan);
	if (error != 0)
		return (error);
	return (0);
}

int
vmx_nested_entry_environment_from_vmcs12(
    const struct vmx_nested_vmcs12_snapshot *snapshot,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmcs02_capabilities *hardware_controls,
    uint16_t vmcs01_vpid, uint16_t effective_vpid, bool distinct_ept_tag,
    struct vmx_nested_entry_environment_capture *capture)
{
	struct vmx_nested_entry_environment_capture candidate;
	bool tsc_offsetting, tsc_scaling, vpid_enabled;
	int error;

	if (snapshot == NULL || id == NULL || hardware_controls == NULL ||
	    capture == NULL ||
	    vmx_nested_state_ranges_overlap(capture, sizeof(*capture), snapshot,
	    sizeof(*snapshot)) ||
	    vmx_nested_state_ranges_overlap(capture, sizeof(*capture), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(capture, sizeof(*capture),
	    hardware_controls, sizeof(*hardware_controls)) ||
	    vmx_nested_vmcs12_snapshot_validate(snapshot) != 0 ||
	    !nvmx_environment_id_valid(id) ||
	    id->vmcs12_gpa != snapshot->vmcs12_gpa)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = *id;
	candidate.virtual_controls.pinbased = snapshot->capabilities.pinbased;
	candidate.virtual_controls.primary = snapshot->capabilities.primary;
	candidate.virtual_controls.secondary =
	    snapshot->capabilities.secondary;
	candidate.virtual_controls.vmexit = snapshot->capabilities.vmexit;
	candidate.virtual_controls.vmentry = snapshot->capabilities.vmentry;
	candidate.hardware_controls = *hardware_controls;
	error = vmx_nested_vmcs02_policy_build(&candidate.virtual_controls,
	    &candidate.hardware_controls, &candidate.control_policy);
	if (error != 0)
		return (error);

	/*
	 * The hardware-owned L0 half is captured by the architecture adapter.
	 * Keep identity placeholders here so stale caller values can never be
	 * confused with the coherent VMCS01 capture.
	 */
	candidate.tsc.l1_multiplier = VMX_NESTED_TSC_MULTIPLIER_ONE;
	tsc_offsetting = (snapshot->controls.primary &
	    NVMX_ENV_TSC_OFFSETTING) != 0;
	tsc_scaling = (snapshot->controls.secondary &
	    NVMX_ENV_TSC_SCALING) != 0;
	candidate.tsc.l2_offset_enabled = tsc_offsetting;
	candidate.tsc.l2_offset =
	    tsc_offsetting ? snapshot->tsc_offset : 0;
	candidate.tsc.l2_scaling_enabled = tsc_scaling;
	candidate.tsc.l2_multiplier = tsc_scaling ?
	    snapshot->tsc_multiplier : VMX_NESTED_TSC_MULTIPLIER_ONE;

	candidate.vpid.direction = VMX_NESTED_VPID_ENTER_L2;
	candidate.vpid.vmcs01_vpid = vmcs01_vpid;
	candidate.vpid.effective_vpid = effective_vpid;
	candidate.vpid.distinct_ept_tag = distinct_ept_tag;
	vpid_enabled = (snapshot->controls.secondary & NVMX_ENV_VPID) != 0 &&
	    snapshot->controls.vpid != 0;
	candidate.vpid.next_virtual_vpid_enabled = vpid_enabled;
	candidate.vpid.next_virtual_vpid =
	    vpid_enabled ? snapshot->controls.vpid : 0;

	candidate.capability_signature = snapshot->capability_signature;
	candidate.preemption_timer_rate =
	    snapshot->capabilities.misc & UINT64_C(0x1f);
	candidate.preemption_timer_enabled =
	    (snapshot->controls.pinbased & NVMX_ENV_PREEMPTION_TIMER) != 0;
	candidate.preemption_timer_value =
	    candidate.preemption_timer_enabled ?
	    snapshot->preemption_timer_value : 0;

	error = vmx_nested_entry_environment_capture_validate(&candidate);
	if (error != 0)
		return (error);
	*capture = candidate;
	return (0);
}

int
vmx_nested_entry_environment_capture(
    const struct vmx_nested_entry_environment_capture *capture,
    const struct vmx_nested_entry_environment_capture_ops *ops, void *arg,
    struct vmx_nested_entry_environment *environment)
{
	struct vmx_nested_entry_environment_capture_ops ops_snapshot;
	struct vmx_nested_entry_environment_input input;
	struct vmx_nested_execution_state execution;
	struct vmx_nested_host_state host;
	struct vmx_nested_l1_runtime_state runtime;
	struct vmx_nested_tsc_scale_input tsc;
	struct vmx_nested_vmcs02_controls controls;
	enum vmx_nested_entry_environment_field field;
	uint64_t host_tsc, value;
	uint32_t count, i;
	int error;

	if (ops == NULL || ops->read == NULL || environment == NULL ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), capture, sizeof(*capture)) ||
	    vmx_nested_state_ranges_overlap(environment,
	    sizeof(*environment), ops, sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_entry_environment_capture_validate(capture);
	if (error != 0)
		return (error);
	/*
	 * Capture is a single frozen-VMCS01 observation.  The reader may be a
	 * private hardware adapter; retain its identity before the first field so
	 * a callback cannot replace a later read within the same environment.
	 */
	ops_snapshot = *ops;
	memset(&controls, 0, sizeof(controls));
#define	NVMX_ENV_READ32(member, capture_field) do {			\
	error = nvmx_environment_read(&ops_snapshot, arg, (capture_field), &value);\
	if (error != 0)						\
		return (error);						\
	if (value > UINT32_MAX)					\
		return (EOVERFLOW);					\
	(member) = (uint32_t)value;					\
} while (0)
#define	NVMX_ENV_READ16(member, capture_field) do {			\
	error = nvmx_environment_read(&ops_snapshot, arg, (capture_field), &value);\
	if (error != 0)						\
		return (error);						\
	if (value > UINT16_MAX)					\
		return (EOVERFLOW);					\
	(member) = (uint16_t)value;					\
} while (0)
#define	NVMX_ENV_READ64(member, capture_field) do {			\
	error = nvmx_environment_read(&ops_snapshot, arg, (capture_field), &value);\
	if (error != 0)						\
		return (error);						\
	(member) = value;						\
} while (0)
	NVMX_ENV_READ32(controls.pinbased, VMX_NESTED_ENV_PINBASED);
	NVMX_ENV_READ32(controls.primary, VMX_NESTED_ENV_PRIMARY);
	NVMX_ENV_READ32(controls.secondary, VMX_NESTED_ENV_SECONDARY);
	NVMX_ENV_READ32(controls.vmexit, VMX_NESTED_ENV_VMEXIT);
	NVMX_ENV_READ32(controls.vmentry, VMX_NESTED_ENV_VMENTRY);

	tsc = capture->tsc;
	if ((controls.primary & NVMX_ENV_TSC_OFFSETTING) != 0)
		NVMX_ENV_READ64(tsc.l1_offset,
		    VMX_NESTED_ENV_L0_TSC_OFFSET);
	else
		tsc.l1_offset = 0;
	if ((controls.secondary & NVMX_ENV_TSC_SCALING) != 0) {
		NVMX_ENV_READ64(tsc.l1_multiplier,
		    VMX_NESTED_ENV_L0_TSC_MULTIPLIER);
		tsc.l1_scaling_enabled = true;
	} else {
		tsc.l1_multiplier = VMX_NESTED_TSC_MULTIPLIER_ONE;
		tsc.l1_scaling_enabled = false;
	}
	NVMX_ENV_READ64(host_tsc, VMX_NESTED_ENV_HOST_TSC);

	memset(&execution, 0, sizeof(execution));
	NVMX_ENV_READ32(execution.exception_bitmap,
	    VMX_NESTED_ENV_EXCEPTION_BITMAP);
	NVMX_ENV_READ32(execution.pf_error_mask,
	    VMX_NESTED_ENV_PF_ERROR_MASK);
	NVMX_ENV_READ32(execution.pf_error_match,
	    VMX_NESTED_ENV_PF_ERROR_MATCH);
	NVMX_ENV_READ64(execution.cr0_mask, VMX_NESTED_ENV_CR0_MASK);
	NVMX_ENV_READ64(execution.cr0_shadow, VMX_NESTED_ENV_CR0_SHADOW);
	NVMX_ENV_READ64(execution.cr4_mask, VMX_NESTED_ENV_CR4_MASK);
	NVMX_ENV_READ64(execution.cr4_shadow, VMX_NESTED_ENV_CR4_SHADOW);
	NVMX_ENV_READ32(count, VMX_NESTED_ENV_CR3_TARGET_COUNT);
	if (count > nitems(execution.cr3_target))
		return (EINVAL);
	for (i = 0; i < count; i++) {
		field = (enum vmx_nested_entry_environment_field)
		    (VMX_NESTED_ENV_CR3_TARGET0 + i);
		NVMX_ENV_READ64(execution.cr3_target[i], field);
	}
	if ((controls.secondary &
	    NVMX_ENV_APIC_REGISTER_VIRTUALIZATION) != 0) {
		for (i = 0; i < nitems(execution.eoi_exit_bitmap); i++) {
			field = (enum vmx_nested_entry_environment_field)
			    (VMX_NESTED_ENV_EOI_EXIT0 + i);
			NVMX_ENV_READ64(execution.eoi_exit_bitmap[i], field);
		}
	}
	if ((controls.secondary & NVMX_ENV_PAUSE_LOOP_EXITING) != 0) {
		NVMX_ENV_READ32(execution.ple_gap,
		    VMX_NESTED_ENV_PLE_GAP);
		NVMX_ENV_READ32(execution.ple_window,
		    VMX_NESTED_ENV_PLE_WINDOW);
	}
	if ((controls.secondary &
	    NVMX_ENV_VIRTUAL_INTERRUPT_DELIVERY) != 0) {
		NVMX_ENV_READ16(execution.guest_intr_status,
		    VMX_NESTED_ENV_GUEST_INTR_STATUS);
	}

	memset(&runtime, 0, sizeof(runtime));
	NVMX_ENV_READ64(runtime.dr7, VMX_NESTED_ENV_L1_DR7);
	NVMX_ENV_READ64(runtime.debugctl, VMX_NESTED_ENV_L1_DEBUGCTL);
	NVMX_ENV_READ64(runtime.pat, VMX_NESTED_ENV_L1_PAT);
	NVMX_ENV_READ64(runtime.efer, VMX_NESTED_ENV_L1_EFER);

	memset(&host, 0, sizeof(host));
	NVMX_ENV_READ64(host.cr0, VMX_NESTED_ENV_L0_HOST_CR0);
	NVMX_ENV_READ64(host.cr3, VMX_NESTED_ENV_L0_HOST_CR3);
	NVMX_ENV_READ64(host.cr4, VMX_NESTED_ENV_L0_HOST_CR4);
	NVMX_ENV_READ64(host.fs_base, VMX_NESTED_ENV_L0_HOST_FS_BASE);
	NVMX_ENV_READ64(host.gs_base, VMX_NESTED_ENV_L0_HOST_GS_BASE);
	NVMX_ENV_READ64(host.tr_base, VMX_NESTED_ENV_L0_HOST_TR_BASE);
	NVMX_ENV_READ64(host.gdtr_base, VMX_NESTED_ENV_L0_HOST_GDTR_BASE);
	NVMX_ENV_READ64(host.idtr_base, VMX_NESTED_ENV_L0_HOST_IDTR_BASE);
	NVMX_ENV_READ32(host.sysenter_cs,
	    VMX_NESTED_ENV_L0_HOST_SYSENTER_CS);
	NVMX_ENV_READ64(host.sysenter_esp,
	    VMX_NESTED_ENV_L0_HOST_SYSENTER_ESP);
	NVMX_ENV_READ64(host.sysenter_eip,
	    VMX_NESTED_ENV_L0_HOST_SYSENTER_EIP);
	NVMX_ENV_READ64(host.rsp, VMX_NESTED_ENV_L0_HOST_RSP);
	NVMX_ENV_READ64(host.rip, VMX_NESTED_ENV_L0_HOST_RIP);
	NVMX_ENV_READ64(host.pat, VMX_NESTED_ENV_L0_HOST_PAT);
	NVMX_ENV_READ64(host.efer, VMX_NESTED_ENV_L0_HOST_EFER);
	NVMX_ENV_READ16(host.es_selector,
	    VMX_NESTED_ENV_L0_HOST_ES_SELECTOR);
	NVMX_ENV_READ16(host.cs_selector,
	    VMX_NESTED_ENV_L0_HOST_CS_SELECTOR);
	NVMX_ENV_READ16(host.ss_selector,
	    VMX_NESTED_ENV_L0_HOST_SS_SELECTOR);
	NVMX_ENV_READ16(host.ds_selector,
	    VMX_NESTED_ENV_L0_HOST_DS_SELECTOR);
	NVMX_ENV_READ16(host.fs_selector,
	    VMX_NESTED_ENV_L0_HOST_FS_SELECTOR);
	NVMX_ENV_READ16(host.gs_selector,
	    VMX_NESTED_ENV_L0_HOST_GS_SELECTOR);
	NVMX_ENV_READ16(host.tr_selector,
	    VMX_NESTED_ENV_L0_HOST_TR_SELECTOR);
	host.root_ia32e = (controls.vmexit &
	    NVMX_ENV_HOST_ADDRESS_SPACE_SIZE) != 0;
#undef NVMX_ENV_READ64
#undef NVMX_ENV_READ16
#undef NVMX_ENV_READ32

	memset(&input, 0, sizeof(input));
	input.id = capture->id;
	input.virtual_controls = &capture->virtual_controls;
	input.hardware_controls = &capture->hardware_controls;
	input.control_policy = &capture->control_policy;
	input.l0_controls = &controls;
	input.l0_execution = &execution;
	input.l0_host = &host;
	input.l1_runtime = &runtime;
	input.tsc = &tsc;
	input.vpid = &capture->vpid;
	input.capability_signature = capture->capability_signature;
	input.l1_virtual_tsc = vmx_nested_tsc_scaled_ticks(host_tsc,
	    tsc.l1_multiplier, tsc.l1_offset);
	input.preemption_timer_value = capture->preemption_timer_value;
	input.l0_cr3_target_count = count;
	input.preemption_timer_rate = capture->preemption_timer_rate;
	input.preemption_timer_enabled = capture->preemption_timer_enabled;
	return (vmx_nested_entry_environment_prepare(&input, environment));
}

int
vmx_nested_entry_environment_bind(
    const struct vmx_nested_entry_environment *environment,
    const struct vmx_nested_vmcs02_id *expected,
    const struct vmx_nested_capabilities *virtual_capabilities,
    const struct vmx_nested_vmentry_input *vmentry,
    struct vmx_nested_vmcs02_input *input)
{
	uint64_t signature;
	int error;

	if (expected == NULL || virtual_capabilities == NULL ||
	    vmentry == NULL || input == NULL ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), environment,
	    sizeof(*environment)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), expected,
	    sizeof(*expected)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input),
	    virtual_capabilities, sizeof(*virtual_capabilities)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), vmentry,
	    sizeof(*vmentry)))
		return (EINVAL);
	error = vmx_nested_entry_environment_validate(environment);
	if (error != 0)
		return (error);
	if (!nvmx_environment_id_equal(&environment->id, expected))
		return (ESTALE);
	error = vmx_nested_capabilities_signature(virtual_capabilities,
	    &signature);
	if (error != 0)
		return (error);
	if (signature != environment->capability_signature ||
	    virtual_capabilities->pinbased !=
	    environment->virtual_controls.pinbased ||
	    virtual_capabilities->primary !=
	    environment->virtual_controls.primary ||
	    virtual_capabilities->secondary !=
	    environment->virtual_controls.secondary ||
	    virtual_capabilities->vmexit !=
	    environment->virtual_controls.vmexit ||
	    virtual_capabilities->vmentry !=
	    environment->virtual_controls.vmentry)
		return (ESTALE);
	memset(input, 0, sizeof(*input));
	input->id = environment->id;
	input->virtual_capabilities = virtual_capabilities;
	input->hardware_capabilities = &environment->hardware_controls;
	input->control_policy = &environment->control_policy;
	input->l0_controls = &environment->l0_controls;
	input->l0_execution = &environment->l0_execution;
	input->l1_runtime = &environment->l1_runtime;
	input->vmentry = vmentry;
	input->tsc = &environment->tsc;
	input->vpid = &environment->vpid;
	input->l1_virtual_tsc = environment->l1_virtual_tsc;
	input->capability_signature = environment->capability_signature;
	input->preemption_timer_value =
	    environment->preemption_timer_value;
	input->l0_cr3_target_count = environment->l0_cr3_target_count;
	input->preemption_timer_rate = environment->preemption_timer_rate;
	input->preemption_timer_enabled =
	    environment->preemption_timer_enabled;
	return (0);
}
