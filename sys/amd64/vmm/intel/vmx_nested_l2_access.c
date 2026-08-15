/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmx_nested_l2_access.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_l2_scalar_get(const struct vmx_nested_l2_portable_state *state,
    enum vmx_nested_l2_scalar scalar, uint64_t *value)
{
	const struct vmx_nested_guest_control_state *control;
	const struct vmx_nested_guest_arch_state *arch;

	if (state == NULL || value == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), value,
	    sizeof(*value)))
		return (EINVAL);
	control = &state->runtime.control;
	arch = &state->runtime.arch;
	switch (scalar) {
	case VMX_NESTED_L2_CR0:
		*value = control->cr0;
		break;
	case VMX_NESTED_L2_CR3:
		*value = control->cr3;
		break;
	case VMX_NESTED_L2_CR4:
		*value = control->cr4;
		break;
	case VMX_NESTED_L2_DR7:
		*value = control->dr7;
		break;
	case VMX_NESTED_L2_SYSENTER_CS:
		*value = control->sysenter_cs;
		break;
	case VMX_NESTED_L2_SYSENTER_ESP:
		*value = control->sysenter_esp;
		break;
	case VMX_NESTED_L2_SYSENTER_EIP:
		*value = control->sysenter_eip;
		break;
	case VMX_NESTED_L2_PAT:
		*value = control->pat;
		break;
	case VMX_NESTED_L2_EFER:
		*value = control->efer;
		break;
	case VMX_NESTED_L2_RSP:
		*value = arch->rsp;
		break;
	case VMX_NESTED_L2_RIP:
		*value = arch->rip;
		break;
	case VMX_NESTED_L2_RFLAGS:
		*value = arch->rflags;
		break;
	case VMX_NESTED_L2_PENDING_DEBUG:
		*value = arch->pending_debug;
		break;
	case VMX_NESTED_L2_DEBUGCTL:
		*value = arch->debugctl;
		break;
	case VMX_NESTED_L2_ACTIVITY:
		*value = arch->activity;
		break;
	case VMX_NESTED_L2_INTERRUPTIBILITY:
		*value = arch->interruptibility;
		break;
	case VMX_NESTED_L2_IN_SMM:
		*value = arch->in_smm;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmx_nested_l2_scalar_set(struct vmx_nested_l2_portable_state *state,
    enum vmx_nested_l2_scalar scalar, uint64_t value)
{
	struct vmx_nested_guest_control_state *control;
	struct vmx_nested_guest_arch_state *arch;

	if (state == NULL)
		return (EINVAL);
	control = &state->runtime.control;
	arch = &state->runtime.arch;
	switch (scalar) {
	case VMX_NESTED_L2_CR0:
		control->cr0 = value;
		break;
	case VMX_NESTED_L2_CR3:
		control->cr3 = value;
		break;
	case VMX_NESTED_L2_CR4:
		control->cr4 = value;
		break;
	case VMX_NESTED_L2_DR7:
		control->dr7 = value;
		break;
	case VMX_NESTED_L2_SYSENTER_CS:
		if ((value >> 32) != 0)
			return (ERANGE);
		control->sysenter_cs = (uint32_t)value;
		break;
	case VMX_NESTED_L2_SYSENTER_ESP:
		control->sysenter_esp = value;
		break;
	case VMX_NESTED_L2_SYSENTER_EIP:
		control->sysenter_eip = value;
		break;
	case VMX_NESTED_L2_PAT:
		control->pat = value;
		break;
	case VMX_NESTED_L2_EFER:
		control->efer = value;
		break;
	case VMX_NESTED_L2_RSP:
		arch->rsp = value;
		break;
	case VMX_NESTED_L2_RIP:
		arch->rip = value;
		break;
	case VMX_NESTED_L2_RFLAGS:
		arch->rflags = value;
		break;
	case VMX_NESTED_L2_PENDING_DEBUG:
		arch->pending_debug = value;
		break;
	case VMX_NESTED_L2_DEBUGCTL:
		arch->debugctl = value;
		break;
	case VMX_NESTED_L2_ACTIVITY:
		if ((value >> 32) != 0)
			return (ERANGE);
		arch->activity = (uint32_t)value;
		break;
	case VMX_NESTED_L2_INTERRUPTIBILITY:
		if ((value >> 32) != 0)
			return (ERANGE);
		arch->interruptibility = (uint32_t)value;
		break;
	case VMX_NESTED_L2_IN_SMM:
		if (value > 1)
			return (ERANGE);
		arch->in_smm = value != 0;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmx_nested_l2_segment_get(const struct vmx_nested_l2_portable_state *state,
    enum vmx_nested_guest_segment_id segment,
    struct vmx_nested_guest_segment *value)
{

	if (state == NULL || value == NULL || segment < 0 ||
	    segment >= VMX_NESTED_GUEST_SEGMENT_COUNT)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), value,
	    sizeof(*value)))
		return (EINVAL);
	*value = state->runtime.arch.segment[segment];
	return (0);
}

int
vmx_nested_l2_segment_set(struct vmx_nested_l2_portable_state *state,
    enum vmx_nested_guest_segment_id segment,
    const struct vmx_nested_guest_segment *value)
{

	if (state == NULL || value == NULL || segment < 0 ||
	    segment >= VMX_NESTED_GUEST_SEGMENT_COUNT)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), value,
	    sizeof(*value)))
		return (EINVAL);
	state->runtime.arch.segment[segment] = *value;
	return (0);
}

int
vmx_nested_l2_table_get(const struct vmx_nested_l2_portable_state *state,
    enum vmx_nested_l2_table table, struct vmx_nested_l2_table_value *value)
{

	if (state == NULL || value == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), value,
	    sizeof(*value)))
		return (EINVAL);
	switch (table) {
	case VMX_NESTED_L2_GDTR:
		value->base = state->runtime.arch.gdtr_base;
		value->limit = state->runtime.arch.gdtr_limit;
		break;
	case VMX_NESTED_L2_IDTR:
		value->base = state->runtime.arch.idtr_base;
		value->limit = state->runtime.arch.idtr_limit;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmx_nested_l2_table_set(struct vmx_nested_l2_portable_state *state,
    enum vmx_nested_l2_table table,
    const struct vmx_nested_l2_table_value *value)
{

	if (state == NULL || value == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), value,
	    sizeof(*value)))
		return (EINVAL);
	switch (table) {
	case VMX_NESTED_L2_GDTR:
		state->runtime.arch.gdtr_base = value->base;
		state->runtime.arch.gdtr_limit = value->limit;
		break;
	case VMX_NESTED_L2_IDTR:
		state->runtime.arch.idtr_base = value->base;
		state->runtime.arch.idtr_limit = value->limit;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}
