/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/cpufunc.h>

#include <dev/vmm/vmm_vm.h>

struct seg_desc;

#include "vmx_cpufunc.h"
#include "vmcs.h"
#include "vmx.h"
#include "vmx_nested_entry_event.h"
#include "vmx_nested_entry_environment_intel.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_msr_state.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs02_bind.h"
#include "vmx_nested_vmcs02_intel.h"
#include "vmx_nested_vmcs02_program.h"
#include "vmx_nested_vmcs12.h"

static bool
nvmx_environment_intel_outputs_disjoint(const void *const *outputs,
    const size_t *output_sizes, u_int output_count,
    const void *const *inputs, const size_t *input_sizes, u_int input_count)
{

	for (u_int i = 0; i < output_count; i++) {
		for (u_int j = i + 1; j < output_count; j++) {
			if (vmx_nested_state_ranges_overlap(outputs[i],
			    output_sizes[i], outputs[j], output_sizes[j]))
				return (false);
		}
		for (u_int j = 0; j < input_count; j++) {
			if (vmx_nested_state_ranges_overlap(outputs[i],
			    output_sizes[i], inputs[j], input_sizes[j]))
				return (false);
		}
	}
	return (true);
}

static int
nvmx_environment_intel_vpid_owner_validate(const struct vmx_vcpu *vcpu)
{
	int error;

	if (vcpu == NULL)
		return (EINVAL);
	error = vmx_nested_vpid_owner_validate(&vcpu->nested_vpid_owner);
	if (error != 0)
		return (error);
	if (vcpu->state.vpid == 0) {
		return (!vcpu->nested_vpid_owner.active &&
		    !vmx_nested_vpid_owner_flush_required(
		    &vcpu->nested_vpid_owner) ? 0 : EPROTO);
	}
	return (vcpu->nested_vpid_owner.active &&
	    vcpu->nested_vpid_owner.vmcs01_vpid == vcpu->state.vpid ? 0 :
	    EPROTO);
}

static int
nvmx_environment_intel_encoding(
    enum vmx_nested_entry_environment_field field, uint32_t *encoding)
{

	switch (field) {
	case VMX_NESTED_ENV_PINBASED:
		*encoding = VMCS_PIN_BASED_CTLS;
		break;
	case VMX_NESTED_ENV_PRIMARY:
		*encoding = VMCS_PRI_PROC_BASED_CTLS;
		break;
	case VMX_NESTED_ENV_SECONDARY:
		*encoding = VMCS_SEC_PROC_BASED_CTLS;
		break;
	case VMX_NESTED_ENV_VMEXIT:
		*encoding = VMCS_EXIT_CTLS;
		break;
	case VMX_NESTED_ENV_VMENTRY:
		*encoding = VMCS_ENTRY_CTLS;
		break;
	case VMX_NESTED_ENV_EXCEPTION_BITMAP:
		*encoding = VMCS_EXCEPTION_BITMAP;
		break;
	case VMX_NESTED_ENV_PF_ERROR_MASK:
		*encoding = VMCS_PF_ERROR_MASK;
		break;
	case VMX_NESTED_ENV_PF_ERROR_MATCH:
		*encoding = VMCS_PF_ERROR_MATCH;
		break;
	case VMX_NESTED_ENV_CR0_MASK:
		*encoding = VMCS_CR0_MASK;
		break;
	case VMX_NESTED_ENV_CR0_SHADOW:
		*encoding = VMCS_CR0_SHADOW;
		break;
	case VMX_NESTED_ENV_CR4_MASK:
		*encoding = VMCS_CR4_MASK;
		break;
	case VMX_NESTED_ENV_CR4_SHADOW:
		*encoding = VMCS_CR4_SHADOW;
		break;
	case VMX_NESTED_ENV_CR3_TARGET_COUNT:
		*encoding = VMCS_CR3_TARGET_COUNT;
		break;
	case VMX_NESTED_ENV_CR3_TARGET0:
	case VMX_NESTED_ENV_CR3_TARGET1:
	case VMX_NESTED_ENV_CR3_TARGET2:
	case VMX_NESTED_ENV_CR3_TARGET3:
		*encoding = VMCS_CR3_TARGET0 +
		    2 * (field - VMX_NESTED_ENV_CR3_TARGET0);
		break;
	case VMX_NESTED_ENV_EOI_EXIT0:
	case VMX_NESTED_ENV_EOI_EXIT1:
	case VMX_NESTED_ENV_EOI_EXIT2:
	case VMX_NESTED_ENV_EOI_EXIT3:
		*encoding = VMCS_EOI_EXIT0 +
		    2 * (field - VMX_NESTED_ENV_EOI_EXIT0);
		break;
	case VMX_NESTED_ENV_PLE_GAP:
		*encoding = VMCS_PLE_GAP;
		break;
	case VMX_NESTED_ENV_PLE_WINDOW:
		*encoding = VMCS_PLE_WINDOW;
		break;
	case VMX_NESTED_ENV_GUEST_INTR_STATUS:
		*encoding = VMCS_GUEST_INTR_STATUS;
		break;
	case VMX_NESTED_ENV_L1_DR7:
		*encoding = VMCS_GUEST_DR7;
		break;
	case VMX_NESTED_ENV_L1_DEBUGCTL:
		*encoding = VMCS_GUEST_IA32_DEBUGCTL;
		break;
	case VMX_NESTED_ENV_L1_EFER:
		*encoding = VMCS_GUEST_IA32_EFER;
		break;
	case VMX_NESTED_ENV_L0_HOST_CR0:
		*encoding = VMCS_HOST_CR0;
		break;
	case VMX_NESTED_ENV_L0_HOST_CR3:
		*encoding = VMCS_HOST_CR3;
		break;
	case VMX_NESTED_ENV_L0_HOST_CR4:
		*encoding = VMCS_HOST_CR4;
		break;
	case VMX_NESTED_ENV_L0_HOST_FS_BASE:
		*encoding = VMCS_HOST_FS_BASE;
		break;
	case VMX_NESTED_ENV_L0_HOST_GS_BASE:
		*encoding = VMCS_HOST_GS_BASE;
		break;
	case VMX_NESTED_ENV_L0_HOST_TR_BASE:
		*encoding = VMCS_HOST_TR_BASE;
		break;
	case VMX_NESTED_ENV_L0_HOST_GDTR_BASE:
		*encoding = VMCS_HOST_GDTR_BASE;
		break;
	case VMX_NESTED_ENV_L0_HOST_IDTR_BASE:
		*encoding = VMCS_HOST_IDTR_BASE;
		break;
	case VMX_NESTED_ENV_L0_HOST_SYSENTER_CS:
		*encoding = VMCS_HOST_IA32_SYSENTER_CS;
		break;
	case VMX_NESTED_ENV_L0_HOST_SYSENTER_ESP:
		*encoding = VMCS_HOST_IA32_SYSENTER_ESP;
		break;
	case VMX_NESTED_ENV_L0_HOST_SYSENTER_EIP:
		*encoding = VMCS_HOST_IA32_SYSENTER_EIP;
		break;
	case VMX_NESTED_ENV_L0_HOST_RSP:
		*encoding = VMCS_HOST_RSP;
		break;
	case VMX_NESTED_ENV_L0_HOST_RIP:
		*encoding = VMCS_HOST_RIP;
		break;
	case VMX_NESTED_ENV_L0_HOST_PAT:
		*encoding = VMCS_HOST_IA32_PAT;
		break;
	case VMX_NESTED_ENV_L0_HOST_EFER:
		*encoding = VMCS_HOST_IA32_EFER;
		break;
	case VMX_NESTED_ENV_L0_HOST_ES_SELECTOR:
		*encoding = VMCS_HOST_ES_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_HOST_CS_SELECTOR:
		*encoding = VMCS_HOST_CS_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_HOST_SS_SELECTOR:
		*encoding = VMCS_HOST_SS_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_HOST_DS_SELECTOR:
		*encoding = VMCS_HOST_DS_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_HOST_FS_SELECTOR:
		*encoding = VMCS_HOST_FS_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_HOST_GS_SELECTOR:
		*encoding = VMCS_HOST_GS_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_HOST_TR_SELECTOR:
		*encoding = VMCS_HOST_TR_SELECTOR;
		break;
	case VMX_NESTED_ENV_L0_TSC_OFFSET:
		*encoding = VMCS_TSC_OFFSET;
		break;
	case VMX_NESTED_ENV_L0_TSC_MULTIPLIER:
		*encoding = VMCS_TSC_MULTIPLIER;
		break;
	case VMX_NESTED_ENV_HOST_TSC:
	case VMX_NESTED_ENV_L1_PAT:
	case VMX_NESTED_ENV_FIELD_COUNT:
		return (EINVAL);
	}
	return (0);
}

static int
nvmx_environment_intel_read(void *arg,
    enum vmx_nested_entry_environment_field field, uint64_t *value)
{
	struct vmx_vcpu *vcpu;
	uint32_t encoding;
	int error;

	vcpu = arg;
	if (field == VMX_NESTED_ENV_L1_PAT) {
		/*
		 * bhyve intercepts IA32_PAT and keeps the effective L1 value
		 * in the per-vCPU software MSR bank.  VMCS01's PAT field is
		 * not authoritative unless its transition controls are used.
		 */
		*value = vcpu->guest_msrs[IDX_MSR_PAT];
		return (0);
	}
	if (field == VMX_NESTED_ENV_HOST_TSC) {
		*value = rdtsc();
		return (0);
	}
	error = nvmx_environment_intel_encoding(field, &encoding);
	if (error != 0)
		return (error);
	error = vmread(encoding, value);
	if (error != VM_SUCCESS)
		return (EIO);
	return (0);
}

int
vmx_nested_entry_environment_intel_capture_current(struct vmx_vcpu *vcpu,
    const struct vmx_nested_entry_environment_capture *capture,
    struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_resources *fixed_resources)
{
	static const struct vmx_nested_entry_environment_capture_ops ops = {
		.read = nvmx_environment_intel_read,
	};
	const void *inputs[] = { vcpu, capture };
	const size_t input_sizes[] = { sizeof(*vcpu), sizeof(*capture) };
	const void *outputs[] = { environment, fixed_resources };
	const size_t output_sizes[] = { sizeof(*environment),
	    sizeof(*fixed_resources) };
	struct vmx_nested_entry_environment candidate_environment;
	struct vmx_nested_vmcs02_resources candidate_resources;
	int error;

	if (vcpu == NULL || capture == NULL || environment == NULL ||
	    fixed_resources == NULL)
		return (EINVAL);
	if (!nvmx_environment_intel_outputs_disjoint(outputs, output_sizes,
	    nitems(outputs), inputs, input_sizes, nitems(inputs)))
		return (EINVAL);
	error = vmx_nested_entry_environment_capture_validate(capture);
	if (error != 0)
		return (error);
	memset(&candidate_resources, 0, sizeof(candidate_resources));
	candidate_resources.id = capture->id;
	/*
	 * The resource capture verifies both the critical-section ownership
	 * and that VMCS01 is current before any environment VMREAD occurs.
	 * Publish neither result unless both captures complete.
	 */
	error = vmx_nested_vmcs02_intel_capture_vmcs01_resources(
	    &vcpu->nested_vmcs02_intel, &candidate_resources);
	if (error == 0)
		error = vmx_nested_entry_environment_capture(capture, &ops,
		    vcpu, &candidate_environment);
	if (error != 0)
		return (error);
	*environment = candidate_environment;
	*fixed_resources = candidate_resources;
	return (0);
}

int
vmx_nested_entry_environment_intel_capture(struct vmx_vcpu *vcpu,
    const struct vmx_nested_entry_environment_capture *capture,
    struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_resources *fixed_resources)
{
	const void *inputs[] = { vcpu, capture };
	const size_t input_sizes[] = { sizeof(*vcpu), sizeof(*capture) };
	const void *outputs[] = { environment, fixed_resources };
	const size_t output_sizes[] = { sizeof(*environment),
	    sizeof(*fixed_resources) };
	struct vmx_nested_entry_environment candidate_environment;
	struct vmx_nested_vmcs02_resources candidate_resources;
	int clear_error, error;

	if (vcpu == NULL || capture == NULL || environment == NULL ||
	    fixed_resources == NULL)
		return (EINVAL);
	if (!nvmx_environment_intel_outputs_disjoint(outputs, output_sizes,
	    nitems(outputs), inputs, input_sizes, nitems(inputs)))
		return (EINVAL);
	/*
	 * A current-VMCS association is per logical processor.  Keep this
	 * short, non-sleeping capture on one CPU and always return VMCS01 to
	 * the clear state expected by the frozen internal-exit path.
	 */
	critical_enter();
	error = vmptrld(vcpu->vmcs);
	if (error == VM_SUCCESS) {
		error = vmx_nested_entry_environment_intel_capture_current(vcpu,
		    capture, &candidate_environment, &candidate_resources);
		clear_error = vmclear(vcpu->vmcs);
		/*
		 * A failed VMCLEAR does not prove that the per-CPU current-VMCS
		 * association was removed.  Returning through critical_exit() in
		 * that state would allow this thread to migrate while VMCS01 still
		 * belongs to the old CPU.  There is no recoverable owner to which
		 * this standalone capture can transfer that residency.
		 */
		if (clear_error != VM_SUCCESS)
			panic("%s: cannot detach captured VMCS01: %d", __func__,
			    clear_error);
	} else {
		error = EIO;
	}
	critical_exit();
	if (error == 0) {
		*environment = candidate_environment;
		*fixed_resources = candidate_resources;
	}
	return (error);
}

static bool
nvmx_environment_intel_fixed_resources_match(
    const struct vmx_nested_vmcs02_resources *captured,
    const struct vmx_nested_vmcs02_resources *retained)
{

	return (vmx_nested_vmcs02_id_equal(&captured->id, &retained->id) &&
	    captured->eptp01 == retained->eptp01 &&
	    captured->exit_msr_store == retained->exit_msr_store &&
	    captured->exit_msr_load == retained->exit_msr_load &&
	    captured->entry_msr_load == retained->entry_msr_load &&
	    captured->exit_msr_store_count ==
	    retained->exit_msr_store_count &&
	    captured->exit_msr_load_count ==
	    retained->exit_msr_load_count &&
	    captured->entry_msr_load_count ==
	    retained->entry_msr_load_count);
}

int
vmx_nested_entry_environment_intel_final_program(struct vmx_vcpu *vcpu,
    const struct vmx_nested_entry_event_plan *event,
    struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_plan *plan,
    struct vmx_nested_software_msrs *software,
    struct vmx_nested_vmcs02_program *program)
{
	const void *inputs[] = { vcpu, event };
	const size_t input_sizes[] = { sizeof(*vcpu), sizeof(*event) };
	const void *outputs[] = { environment, plan, software, program };
	const size_t output_sizes[] = { sizeof(*environment), sizeof(*plan),
	    sizeof(*software), sizeof(*program) };
	struct vmx_nested_entry_environment_capture capture;
	struct vmx_nested_entry_environment environment_candidate;
	struct vmx_nested_vmcs02_hardware_plan hardware;
	struct vmx_nested_vmcs02_input input;
	struct vmx_nested_vmcs02_plan plan_candidate, reapplied, with_event;
	struct vmx_nested_vmcs02_program program_candidate;
	struct vmx_nested_vmcs02_resources fixed;
	struct vmx_nested_software_msrs software_candidate;
	struct vmx_nested_vmentry_input vmentry;
	int error;

	if (vcpu == NULL || event == NULL || environment == NULL || plan == NULL ||
	    software == NULL || program == NULL ||
	    !vcpu->nested_vmcs02_plan_valid ||
	    vcpu->nested_entry_runtime.state !=
	    VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    !vcpu->nested_msr_workspace.active ||
	    vcpu->nested_msr_generation == 0 ||
	    vcpu->nested_entry_msr_count !=
	    vcpu->nested_vmcs12_snapshot.controls.entry_msr_load_count ||
	    curthread->td_critnest == 0)
		return (EINVAL);
	if (!nvmx_environment_intel_outputs_disjoint(outputs, output_sizes,
	    nitems(outputs), inputs, input_sizes, nitems(inputs)))
		return (EINVAL);
	error = nvmx_environment_intel_vpid_owner_validate(vcpu);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_environment_from_vmcs12(
	    &vcpu->nested_vmcs12_snapshot,
	    &vcpu->nested_vmcs02_plan.id,
	    &vcpu->nested_entry_environment.hardware_controls,
	    vcpu->nested_entry_environment.vpid.vmcs01_vpid,
	    vcpu->nested_entry_environment.vpid.effective_vpid,
	    vcpu->nested_entry_environment.vpid.distinct_ept_tag, &capture);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_environment_intel_capture_current(vcpu,
	    &capture, &environment_candidate, &fixed);
	if (error != 0)
		return (error);
	if (!nvmx_environment_intel_fixed_resources_match(&fixed,
	    &vcpu->nested_vmcs02_resources))
		return (ESTALE);

	/*
	 * Rebuild only pointer-bearing synchronous views.  The prior
	 * validation result and immutable MSR snapshot remain authoritative;
	 * neither memory nor a validation callback is installed here.
	 */
	error = vmx_nested_vmcs12_vmentry_input(
	    &vcpu->nested_vmcs12_snapshot, NULL, NULL, &vmentry);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_environment_bind(&environment_candidate,
	    &vcpu->nested_vmcs02_plan.id,
	    &vcpu->nested_vmcs12_snapshot.capabilities, &vmentry, &input);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_recompose_frozen(&input,
	    &vcpu->nested_vmcs02_plan.vmentry, &plan_candidate);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_apply_frozen_msrs(
	    &vcpu->nested_vmcs12_snapshot.capabilities,
	    vcpu->nested_msr_workspace.plan, vcpu->nested_entry_msr_count,
	    &vcpu->nested_l1_software_msrs,
	    vcpu->nested_msr_workspace.rollback,
	    vcpu->nested_msr_workspace.capacity, true,
	    vmx_have_msr_tsc_aux, &plan_candidate, &reapplied,
	    &software_candidate);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_event_apply(event, &reapplied, &with_event);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_arm_timer(&with_event,
	    environment_candidate.l1_virtual_tsc);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_bind(&with_event.image,
	    &environment_candidate.l0_host,
	    &vcpu->nested_vmcs02_resources, &hardware);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_program_build(&hardware,
	    &program_candidate);
	if (error != 0)
		return (error);
	*environment = environment_candidate;
	*plan = with_event;
	*software = software_candidate;
	*program = program_candidate;
	return (0);
}

static int
nvmx_environment_intel_rebind_portable(struct vmx_vcpu *vcpu,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs02_plan *frozen,
    const struct vmx_nested_vmcs02_capabilities *hardware_controls,
    bool current,
    struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_resources *fixed_resources,
    struct vmx_nested_vmcs02_plan *plan)
{
	const void *inputs[] = { vcpu, portable, frozen, hardware_controls };
	const size_t input_sizes[] = { sizeof(*vcpu), sizeof(*portable),
	    sizeof(*frozen), sizeof(*hardware_controls) };
	const void *outputs[] = { environment, fixed_resources, plan };
	const size_t output_sizes[] = { sizeof(*environment),
	    sizeof(*fixed_resources), sizeof(*plan) };
	struct vmx_nested_entry_environment_capture capture;
	struct vmx_nested_entry_environment environment_candidate;
	struct vmx_nested_vmcs02_input input;
	struct vmx_nested_vmcs02_plan recomposed, rebound;
	struct vmx_nested_vmcs02_resources fixed_candidate;
	struct vmx_nested_vmentry_input vmentry;
	int error;

	if (vcpu == NULL || portable == NULL || frozen == NULL ||
	    hardware_controls == NULL ||
	    environment == NULL || fixed_resources == NULL || plan == NULL ||
	    !vcpu->nested_vmcs02_plan_valid)
		return (EINVAL);
	if (!nvmx_environment_intel_outputs_disjoint(outputs, output_sizes,
	    nitems(outputs), inputs, input_sizes, nitems(inputs)))
		return (EINVAL);
	error = nvmx_environment_intel_vpid_owner_validate(vcpu);
	if (error != 0)
		return (error);
	if ((!current &&
	    vcpu_get_state(vcpu->vcpu, NULL) != VCPU_FROZEN) ||
	    (current && curthread->td_critnest == 0))
		return (EINVAL);
	error = vmx_nested_entry_environment_from_vmcs12(
	    &vcpu->nested_vmcs12_snapshot, &frozen->id,
	    hardware_controls, vcpu->state.vpid,
	    vcpu->nested_vpid_owner.active ?
	    vcpu->nested_vpid_owner.effective_vpid : 0, false,
	    &capture);
	if (error != 0)
		return (error);
	if (current) {
		error = vmx_nested_entry_environment_intel_capture_current(vcpu,
		    &capture, &environment_candidate, &fixed_candidate);
	} else {
		error = vmx_nested_entry_environment_intel_capture(vcpu,
		    &capture, &environment_candidate, &fixed_candidate);
	}
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs12_vmentry_input(
	    &vcpu->nested_vmcs12_snapshot, NULL, NULL, &vmentry);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_environment_bind(&environment_candidate,
	    &frozen->id, &vcpu->nested_vmcs12_snapshot.capabilities,
	    &vmentry, &input);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs02_recompose_frozen(&input,
	    &frozen->vmentry, &recomposed);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_apply(portable,
	    &vcpu->nested_vmcs12_snapshot.capabilities, &recomposed,
	    &rebound);
	if (error != 0)
		return (error);
	/*
	 * portable_apply() intentionally strips the source hardware VPID.
	 * The recomposition above derived the destination-safe selection.
	 */
	rebound.image.vpid = recomposed.image.vpid;
	error = vmx_nested_vmcs02_rearm_timer(&rebound,
	    environment_candidate.l1_virtual_tsc);
	if (error != 0)
		return (error);

	*environment = environment_candidate;
	*fixed_resources = fixed_candidate;
	*plan = rebound;
	return (0);
}

int
vmx_nested_entry_environment_intel_rebind_portable(struct vmx_vcpu *vcpu,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs02_plan *frozen,
    const struct vmx_nested_vmcs02_capabilities *hardware_controls,
    struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_resources *fixed_resources,
    struct vmx_nested_vmcs02_plan *plan)
{

	return (nvmx_environment_intel_rebind_portable(vcpu, portable,
	    frozen, hardware_controls, false, environment, fixed_resources,
	    plan));
}

int
vmx_nested_entry_environment_intel_refresh_portable_current(
    struct vmx_vcpu *vcpu,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs02_plan *frozen,
    const struct vmx_nested_vmcs02_capabilities *hardware_controls,
    const struct vmx_nested_vmcs02_resources *resources,
    struct vmx_nested_entry_environment *environment,
    struct vmx_nested_vmcs02_plan *plan)
{
	const void *inputs[] = { vcpu, portable, frozen, hardware_controls,
	    resources };
	const size_t input_sizes[] = { sizeof(*vcpu), sizeof(*portable),
	    sizeof(*frozen), sizeof(*hardware_controls), sizeof(*resources) };
	const void *outputs[] = { environment, plan };
	const size_t output_sizes[] = { sizeof(*environment), sizeof(*plan) };
	struct vmx_nested_entry_environment environment_candidate;
	struct vmx_nested_vmcs02_resources fixed_candidate;
	struct vmx_nested_vmcs02_plan plan_candidate;
	int error;

	if (vcpu == NULL || portable == NULL || frozen == NULL ||
	    hardware_controls == NULL || resources == NULL ||
	    environment == NULL || plan == NULL)
		return (EINVAL);
	if (!nvmx_environment_intel_outputs_disjoint(outputs, output_sizes,
	    nitems(outputs), inputs, input_sizes, nitems(inputs)))
		return (EINVAL);
	error = nvmx_environment_intel_rebind_portable(vcpu, portable,
	    frozen, hardware_controls, true, &environment_candidate,
	    &fixed_candidate, &plan_candidate);
	if (error != 0)
		return (error);
	if (!nvmx_environment_intel_fixed_resources_match(&fixed_candidate,
	    resources))
		return (ESTALE);
	/*
	 * The retained VMCS02 owns one hardware translation context.  A
	 * final-CPU host-state refresh may change only CPU-local host fields;
	 * it must not silently select a different VPID after the resource
	 * generation was acquired.
	 */
	if (plan_candidate.image.vpid.hardware_vpid !=
	    frozen->image.vpid.hardware_vpid)
		return (ESTALE);
	*environment = environment_candidate;
	*plan = plan_candidate;
	return (0);
}
