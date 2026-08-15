/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#include "vmx_nested_tsc_aux.h"

int
vmx_nested_tsc_aux_value_validate(uint64_t value)
{

	return ((value >> 32) == 0 ? 0 : EINVAL);
}

int
vmx_nested_tsc_aux_guest_bank(
    enum vmx_nested_tsc_aux_residency residency,
    enum vmx_nested_tsc_aux_guest_bank *bank)
{

	if (bank == NULL)
		return (EINVAL);
	switch (residency) {
	case VMX_NESTED_TSC_AUX_L1:
		*bank = VMX_NESTED_TSC_AUX_GUEST_L1;
		break;
	case VMX_NESTED_TSC_AUX_L2:
	case VMX_NESTED_TSC_AUX_L2_PAUSED:
		/*
		 * PAUSED means the physical CPU carries L0's per-CPU host
		 * value, not either architectural guest value.  L2 remains
		 * the active guest until the nested exit is destructively
		 * reflected or frozen, so an intercepted access still
		 * targets L2's retained software bank.
		 */
		*bank = VMX_NESTED_TSC_AUX_GUEST_L2;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
vmx_nested_tsc_aux_enter_l2(enum vmx_nested_tsc_aux_residency *residency)
{

	if (residency == NULL ||
	    *residency != VMX_NESTED_TSC_AUX_L1)
		return (EINVAL);
	*residency = VMX_NESTED_TSC_AUX_L2;
	return (0);
}

int
vmx_nested_tsc_aux_pause_l2(enum vmx_nested_tsc_aux_residency *residency)
{

	if (residency == NULL ||
	    *residency != VMX_NESTED_TSC_AUX_L2)
		return (EINVAL);
	*residency = VMX_NESTED_TSC_AUX_L2_PAUSED;
	return (0);
}

int
vmx_nested_tsc_aux_resume_l2(enum vmx_nested_tsc_aux_residency *residency)
{

	if (residency == NULL ||
	    *residency != VMX_NESTED_TSC_AUX_L2_PAUSED)
		return (EINVAL);
	*residency = VMX_NESTED_TSC_AUX_L2;
	return (0);
}

int
vmx_nested_tsc_aux_leave_l2(enum vmx_nested_tsc_aux_residency *residency,
    enum vmx_nested_tsc_aux_residency *previous)
{

	if (residency == NULL || previous == NULL ||
	    (*residency != VMX_NESTED_TSC_AUX_L2 &&
	    *residency != VMX_NESTED_TSC_AUX_L2_PAUSED))
		return (EINVAL);
	*previous = *residency;
	*residency = VMX_NESTED_TSC_AUX_L1;
	return (0);
}

int
vmx_nested_tsc_aux_rollback_leave(
    enum vmx_nested_tsc_aux_residency *residency,
    enum vmx_nested_tsc_aux_residency previous)
{

	if (residency == NULL ||
	    *residency != VMX_NESTED_TSC_AUX_L1 ||
	    (previous != VMX_NESTED_TSC_AUX_L2 &&
	    previous != VMX_NESTED_TSC_AUX_L2_PAUSED))
		return (EINVAL);
	*residency = previous;
	return (0);
}

int
vmx_nested_tsc_aux_rollback_enter(
    enum vmx_nested_tsc_aux_residency *residency)
{

	if (residency == NULL ||
	    *residency != VMX_NESTED_TSC_AUX_L2)
		return (EINVAL);
	*residency = VMX_NESTED_TSC_AUX_L1;
	return (0);
}
