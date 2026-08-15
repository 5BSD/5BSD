/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_control_msr.h"
#include "vmx_nested_state_range.h"

#define	NVMX_MSR_FEATURE_CONTROL	UINT32_C(0x3a)

void
vmx_nested_control_msr_init(struct vmx_nested_control_msr_state *state)
{

	if (state != NULL)
		memset(state, 0, sizeof(*state));
}

int
vmx_nested_control_msr_validate(
    const struct vmx_nested_control_msr_state *state)
{

	if (state == NULL ||
	    (state->feature_control &
	    ~VMX_NESTED_FEATURE_CONTROL_VALID) != 0)
		return (EINVAL);
	return (0);
}

int
vmx_nested_control_msr_read(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_control_msr_state *state, uint32_t msr,
    uint64_t *value)
{
	uint64_t candidate;
	int error;

	if (value == NULL ||
	    vmx_nested_state_ranges_overlap(value, sizeof(*value), capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(value, sizeof(*value), state,
	    sizeof(*state)) ||
	    vmx_nested_control_msr_validate(state) != 0 ||
	    vmx_nested_capabilities_validate(capabilities) != 0)
		return (EINVAL);
	if (msr == NVMX_MSR_FEATURE_CONTROL) {
		candidate = state->feature_control;
	} else {
		error = vmx_nested_capability_read_msr(capabilities, msr,
		    &candidate);
		if (error != 0)
			return (error);
	}
	*value = candidate;
	return (0);
}

int
vmx_nested_control_msr_write(
    const struct vmx_nested_capabilities *capabilities,
    struct vmx_nested_control_msr_state *state, uint32_t msr,
    uint64_t value)
{
	uint64_t ignored;
	int error;

	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_control_msr_validate(state) != 0 ||
	    vmx_nested_capabilities_validate(capabilities) != 0)
		return (EINVAL);
	if (msr == NVMX_MSR_FEATURE_CONTROL) {
		if ((value & ~VMX_NESTED_FEATURE_CONTROL_VALID) != 0)
			return (EINVAL);
		if ((state->feature_control &
		    VMX_NESTED_FEATURE_CONTROL_LOCK) != 0)
			return (EPERM);
		state->feature_control = value;
		return (0);
	}
	error = vmx_nested_capability_read_msr(capabilities, msr, &ignored);
	if (error == 0)
		return (EROFS);
	return (error);
}
