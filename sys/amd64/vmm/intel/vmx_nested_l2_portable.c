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

#include "vmx_nested_entry.h"
#include "vmx_nested_caps.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_state_range.h"

#define	NVMX_L2P_PRIMARY_MTF	(UINT32_C(1) << 27)
#define	NVMX_L2P_EXIT_MTF	UINT32_C(37)

/* Intel SDM Vol. 3C, VM-entry interruption-information field. */
#define	NVMX_L2P_ENTRY_VALID		(UINT32_C(1) << 31)
#define	NVMX_L2P_ENTRY_TYPE_MASK	(UINT32_C(7) << 8)
#define	NVMX_L2P_ENTRY_ERROR_VALID	(UINT32_C(1) << 11)
#define	NVMX_L2P_ENTRY_ALLOWED		UINT32_C(0x80000fff)

/* Intel SDM Vol. 3C, secondary processor-based execution controls. */
#define	NVMX_L2P_VIRTUAL_INTERRUPT_DELIVERY	(UINT32_C(1) << 9)

/* Intel SDM Vol. 3C, guest interruptibility-state field. */
#define	NVMX_L2P_STI_BLOCKING		(UINT32_C(1) << 0)
#define	NVMX_L2P_MOVSS_BLOCKING	(UINT32_C(1) << 1)

static bool
nvmxl2p_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmxl2p_id_equal(const struct vmx_nested_vmcs02_id *left,
    const struct vmx_nested_vmcs02_id *right)
{

	return (vmx_nested_vmcs02_id_equal(left, right));
}

static int
nvmxl2p_entry_event_validate(uint32_t info, uint32_t error,
    uint32_t instruction_length)
{
	uint32_t type, vector;
	bool software;

	if ((info & NVMX_L2P_ENTRY_VALID) == 0)
		/*
		 * Intel specifies the other VM-entry event fields as ignored
		 * when VALID is clear.  Preserve them exactly; canonicalizing
		 * ignored values here would make a freeze/thaw cycle observable.
		 */
		return (0);
	if ((info & ~NVMX_L2P_ENTRY_ALLOWED) != 0 ||
	    instruction_length > 15)
		return (EINVAL);
	type = (info & NVMX_L2P_ENTRY_TYPE_MASK) >> 8;
	vector = info & 0xff;
	software = type == 4 || type == 5 || type == 6;
	if (type == 1 || type == 7 ||
	    (type == 2 && vector != 2) ||
	    (type == 3 && vector >= 32) ||
	    (type == 5 && vector != 1) ||
	    (type == 6 && vector != 3 && vector != 4) ||
	    ((info & NVMX_L2P_ENTRY_ERROR_VALID) == 0 && error != 0) ||
	    (!software && instruction_length != 0))
		return (EINVAL);
	return (0);
}

static int
nvmxl2p_plan_validate(const struct vmx_nested_vmcs02_plan *plan)
{

	if (plan == NULL ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY ||
	    !nvmxl2p_id_valid(&plan->id) ||
	    !nvmxl2p_id_equal(&plan->id, &plan->image.id))
		return (EINVAL);
	return (0);
}

static int
nvmxl2p_runtime_validate(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_runtime_state *runtime,
    uint32_t entry_intr_info)
{
	enum vmx_nested_guest_arch_failure arch_failure;
	enum vmx_nested_guest_control_failure control_failure;
	int error;

	if (capabilities == NULL || runtime == NULL ||
	    nvmxl2p_plan_validate(plan) != 0)
		return (EINVAL);
	error = vmx_nested_guest_control_state_validate(capabilities,
	    plan->image.controls.primary, plan->image.controls.secondary,
	    plan->image.controls.vmentry, &runtime->control,
	    &control_failure);
	if (error != 0)
		return (EINVAL);
	error = vmx_nested_guest_arch_state_validate(capabilities,
	    plan->image.controls.pinbased, plan->image.controls.primary,
	    plan->image.controls.secondary, plan->image.controls.vmentry,
	    entry_intr_info, &runtime->control, &runtime->arch,
	    &arch_failure);
	return (error == 0 ? 0 : EINVAL);
}

int
vmx_nested_l2_portable_validate(
    const struct vmx_nested_l2_portable_state *state)
{
	struct vmx_nested_exit_information normalized, zero;
	uint32_t i;
	int error;

	if (state == NULL || !nvmxl2p_id_valid(&state->id) ||
	    state->portable_generation == 0 ||
	    state->capability_signature == 0 || !state->exit_valid ||
	    !state->exit.launched ||
	    state->preemption_timer.armed !=
	    state->preemption_timer_enabled ||
	    vmx_nested_timer_state_validate(&state->preemption_timer,
	    state->preemption_timer_enabled) != 0 ||
	    state->runtime.preemption_timer_valid !=
	    state->preemption_timer_enabled ||
	    state->runtime.preemption_timer_value !=
	    (state->preemption_timer_enabled ?
	    state->preemption_timer.remaining : 0) ||
	    (!state->guest_interrupt_status_valid &&
	    state->guest_interrupt_status != 0) ||
	    nvmxl2p_entry_event_validate(state->entry_intr_info,
	    state->entry_exception_error,
	    state->entry_instruction_length) != 0)
		return (EINVAL);
	if (!state->pdpte.active) {
		for (i = 0; i < nitems(state->pdpte.value); i++) {
			if (state->pdpte.value[i] != 0)
				return (EINVAL);
		}
	}
	memset(&zero, 0, sizeof(zero));
	error = vmx_nested_exit_information_prepare(&zero, &state->exit,
	    &normalized);
	if (error != 0 ||
	    !vmx_nested_exit_information_equal(&normalized, &state->exit))
		return (EINVAL);
	return (0);
}

int
vmx_nested_l2_portable_capture(
    const struct vmx_nested_l2_portable_input *input,
    struct vmx_nested_l2_portable_state *state)
{
	struct vmx_nested_l2_portable_state candidate;
	struct vmx_nested_exit_information zero;
	bool vid;
	int error;

	if (input == NULL || state == NULL || input->runtime == NULL ||
	    input->capabilities == NULL ||
	    input->software_msrs == NULL || input->exit == NULL ||
	    input->pdpte == NULL || input->preemption_timer == NULL ||
	    input->portable_generation == 0 ||
	    nvmxl2p_plan_validate(input->executed_plan) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state),
	    input->runtime, sizeof(*input->runtime)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state),
	    input->capabilities, sizeof(*input->capabilities)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state),
	    input->software_msrs, sizeof(*input->software_msrs)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), input->exit,
	    sizeof(*input->exit)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), input->pdpte,
	    sizeof(*input->pdpte)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state),
	    input->preemption_timer, sizeof(*input->preemption_timer)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state),
	    input->executed_plan, sizeof(*input->executed_plan)))
		return (EINVAL);
	vid = (input->executed_plan->image.controls.secondary &
	    NVMX_L2P_VIRTUAL_INTERRUPT_DELIVERY) != 0;
	if (input->pdpte->active !=
	    input->executed_plan->image.pdpte.active ||
	    input->preemption_timer->armed !=
	    input->executed_plan->image.preemption_timer_enabled ||
	    input->guest_interrupt_status_valid != vid)
		return (EINVAL);
	error = nvmxl2p_runtime_validate(input->capabilities,
	    input->executed_plan, input->runtime,
	    input->entry_intr_info);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = input->executed_plan->id;
	candidate.portable_generation = input->portable_generation;
	error = vmx_nested_capabilities_signature(input->capabilities,
	    &candidate.capability_signature);
	if (error != 0)
		return (error);
	candidate.runtime = *input->runtime;
	candidate.software_msrs = *input->software_msrs;
	memset(&zero, 0, sizeof(zero));
	error = vmx_nested_exit_information_prepare(&zero, input->exit,
	    &candidate.exit);
	if (error != 0)
		return (error);
	candidate.exit_valid = true;
	candidate.pdpte = *input->pdpte;
	candidate.preemption_timer = *input->preemption_timer;
	candidate.preemption_timer_enabled =
	    input->executed_plan->image.preemption_timer_enabled;
	candidate.entry_intr_info = input->entry_intr_info;
	candidate.entry_exception_error = input->entry_exception_error;
	candidate.entry_instruction_length =
	    input->entry_instruction_length;
	candidate.guest_interrupt_status = input->guest_interrupt_status;
	candidate.guest_interrupt_status_valid =
	    input->guest_interrupt_status_valid;
	error = vmx_nested_l2_portable_validate(&candidate);
	if (error != 0)
		return (error);
	*state = candidate;
	return (0);
}

int
vmx_nested_l2_portable_apply(
    const struct vmx_nested_l2_portable_state *state,
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmcs02_plan *frozen_plan,
    struct vmx_nested_vmcs02_plan *next)
{
	struct vmx_nested_vmcs02_plan candidate;
	uint64_t capability_signature;
	bool vid;
	int error;

	if (next == NULL || capabilities == NULL ||
	    nvmxl2p_plan_validate(frozen_plan) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(next, sizeof(*next), state,
	    state == NULL ? 0 : sizeof(*state)) ||
	    vmx_nested_state_ranges_overlap(next, sizeof(*next), capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(next, sizeof(*next), frozen_plan,
	    sizeof(*frozen_plan)))
		return (EINVAL);
	error = vmx_nested_l2_portable_validate(state);
	if (error != 0)
		return (error);
	error = vmx_nested_capabilities_signature(capabilities,
	    &capability_signature);
	if (error != 0)
		return (error);
	if (capability_signature != state->capability_signature)
		return (ESTALE);
	if (!nvmxl2p_id_equal(&state->id, &frozen_plan->id) ||
	    state->pdpte.active != frozen_plan->image.pdpte.active ||
	    state->preemption_timer_enabled !=
	    frozen_plan->image.preemption_timer_enabled ||
	    (state->mtf_pending &&
	    (frozen_plan->image.controls.primary & NVMX_L2P_PRIMARY_MTF) == 0))
		return (ESTALE);
	vid = (frozen_plan->image.controls.secondary &
	    NVMX_L2P_VIRTUAL_INTERRUPT_DELIVERY) != 0;
	if (state->guest_interrupt_status_valid != vid)
		return (ESTALE);
	error = nvmxl2p_runtime_validate(capabilities, frozen_plan,
	    &state->runtime, state->entry_intr_info);
	if (error != 0)
		return (EINVAL);

	candidate = *frozen_plan;
	candidate.image.l2_control = state->runtime.control;
	candidate.image.l2_arch = state->runtime.arch;
	candidate.image.pdpte = state->pdpte;
	candidate.image.preemption_timer = state->preemption_timer;
	candidate.image.entry_intr_info = state->entry_intr_info;
	candidate.image.entry_exception_error =
	    state->entry_exception_error;
	candidate.image.entry_instruction_length =
	    state->entry_instruction_length;
	if (state->guest_interrupt_status_valid)
		candidate.image.execution.state.guest_intr_status =
		    state->guest_interrupt_status;
	/*
	 * A host VPID is a per-runtime lease.  Keeping the virtual VPID is
	 * useful to the rebinder, but carrying a hardware identifier or a
	 * previous flush decision across CPUs would alias unrelated state.
	 */
	candidate.image.vpid.hardware_vpid = 0;
	candidate.image.vpid.flush_effective_context = true;
	*next = candidate;
	return (0);
}

int
vmx_nested_l2_portable_complete_instruction(
    struct vmx_nested_l2_portable_state *state,
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_vmcs02_plan *frozen_plan,
    uint64_t instruction_rip, uint32_t instruction_length,
    uint64_t next_rip, bool *retired)
{
	struct vmx_nested_l2_portable_state candidate;
	uint64_t capability_signature, expected;
	int error;

	if (state == NULL || capabilities == NULL || frozen_plan == NULL ||
	    retired == NULL ||
	    vmx_nested_state_ranges_overlap(retired, sizeof(*retired), state,
	    sizeof(*state)) ||
	    vmx_nested_state_ranges_overlap(retired, sizeof(*retired),
	    capabilities, sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(retired, sizeof(*retired),
	    frozen_plan, sizeof(*frozen_plan)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), frozen_plan,
	    sizeof(*frozen_plan)))
		return (EINVAL);
	error = vmx_nested_l2_portable_validate(state);
	if (error != 0 || nvmxl2p_plan_validate(frozen_plan) != 0 ||
	    !nvmxl2p_id_equal(&state->id, &frozen_plan->id) ||
	    instruction_rip != state->runtime.arch.rip ||
	    instruction_length > 15)
		return (EINVAL);
	error = vmx_nested_capabilities_signature(capabilities,
	    &capability_signature);
	if (error != 0)
		return (error);
	if (capability_signature != state->capability_signature)
		return (ESTALE);
	if (next_rip == state->runtime.arch.rip) {
		*retired = false;
		return (0);
	}
	if (state->mtf_pending)
		return (EBUSY);
	if (instruction_length == 0 || state->runtime.arch.rip >
	    UINT64_MAX - instruction_length)
		return (EINVAL);
	expected = state->runtime.arch.rip + instruction_length;
	if (next_rip != expected)
		return (ESTALE);

	candidate = *state;
	candidate.runtime.arch.rip = next_rip;
	/*
	 * A successfully emulated instruction has retired.  Match the normal
	 * VMX run path by removing STI/MOVSS one-instruction blocking before
	 * the next event-selection and VM-entry transaction.
	 */
	candidate.runtime.arch.interruptibility &=
	    ~(NVMX_L2P_STI_BLOCKING | NVMX_L2P_MOVSS_BLOCKING);
	candidate.mtf_pending =
	    (frozen_plan->image.controls.primary &
	    NVMX_L2P_PRIMARY_MTF) != 0;
	error = nvmxl2p_runtime_validate(capabilities, frozen_plan,
	    &candidate.runtime, candidate.entry_intr_info);
	if (error != 0)
		return (EINVAL);
	*state = candidate;
	*retired = true;
	return (0);
}

int
vmx_nested_l2_portable_mtf_peek(
    const struct vmx_nested_l2_portable_state *state,
    uint64_t portable_generation,
    struct vmx_nested_exit_information *information)
{
	struct vmx_nested_exit_information candidate;

	if (state == NULL || information == NULL ||
	    vmx_nested_state_ranges_overlap(information,
	    sizeof(*information), state, sizeof(*state)) ||
	    vmx_nested_l2_portable_validate(state) != 0)
		return (EINVAL);
	if (portable_generation == 0 ||
	    portable_generation != state->portable_generation)
		return (ESTALE);
	if (!state->mtf_pending)
		return (ENOENT);

	memset(&candidate, 0, sizeof(candidate));
	candidate.exit_reason = NVMX_L2P_EXIT_MTF;
	candidate.launched = true;
	*information = candidate;
	return (0);
}

int
vmx_nested_l2_portable_mtf_commit(
    struct vmx_nested_l2_portable_state *state,
    uint64_t portable_generation)
{

	if (state == NULL || vmx_nested_l2_portable_validate(state) != 0)
		return (EINVAL);
	if (portable_generation == 0 ||
	    portable_generation != state->portable_generation)
		return (ESTALE);
	if (!state->mtf_pending)
		return (ENOENT);
	state->mtf_pending = false;
	return (0);
}
