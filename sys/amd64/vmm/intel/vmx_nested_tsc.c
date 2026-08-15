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

#include "vmx_nested_tsc.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_tsc_offset_plan(const struct vmx_nested_tsc_offsets *offsets,
    struct vmx_nested_tsc_plan *plan)
{
	struct vmx_nested_tsc_plan candidate;

	if (offsets == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), offsets,
	    sizeof(*offsets)) ||
	    (!offsets->l2_offset_enabled && offsets->l2_offset != 0))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.vmcs01_offset = offsets->l1_offset;
	candidate.vmcs02_offset = offsets->l1_offset;
	if (offsets->l2_offset_enabled)
		candidate.vmcs02_offset += offsets->l2_offset;
	*plan = candidate;
	return (0);
}

uint64_t
vmx_nested_tsc_virtual_ticks(uint64_t host_tsc, uint64_t offset)
{

	return (host_tsc + offset);
}

static uint64_t
nvmx_tsc_multiply(uint64_t value, uint64_t multiplier)
{
	__uint128_t product;

	product = (__uint128_t)value * multiplier;
	return ((uint64_t)(product >> VMX_NESTED_TSC_FRAC_BITS));
}

static int
nvmx_tsc_multiplier_compose(uint64_t first, uint64_t second,
    uint64_t *result)
{
	__uint128_t product, shifted;

	product = (__uint128_t)first * second;
	shifted = product >> VMX_NESTED_TSC_FRAC_BITS;
	if (shifted == 0 || shifted > (__uint128_t)~0ULL)
		return (ERANGE);
	*result = (uint64_t)shifted;
	return (0);
}

static uint64_t
nvmx_tsc_multiply_signed(uint64_t value, uint64_t multiplier)
{
	uint64_t magnitude, result;

	/*
	 * Match the architectural/KVM composition convention: scale the
	 * magnitude, truncate the fixed-point fraction, then restore the sign.
	 * Unsigned subtraction handles INT64_MIN without signed overflow.
	 */
	if ((value & (1ULL << 63)) == 0)
		return (nvmx_tsc_multiply(value, multiplier));
	magnitude = 0ULL - value;
	result = nvmx_tsc_multiply(magnitude, multiplier);
	return (0ULL - result);
}

int
vmx_nested_tsc_scale_compose(
    const struct vmx_nested_tsc_scale_input *input,
    struct vmx_nested_tsc_scale_plan *plan)
{
	struct vmx_nested_tsc_scale_plan candidate;
	uint64_t l1_multiplier, l2_multiplier;
	int error;

	if (input == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    (!input->l1_scaling_enabled &&
	    input->l1_multiplier != VMX_NESTED_TSC_MULTIPLIER_ONE) ||
	    (!input->l2_scaling_enabled &&
	    input->l2_multiplier != VMX_NESTED_TSC_MULTIPLIER_ONE) ||
	    (!input->l2_offset_enabled && input->l2_offset != 0) ||
	    (input->l1_scaling_enabled && input->l1_multiplier == 0) ||
	    (input->l2_scaling_enabled && input->l2_multiplier == 0))
		return (EINVAL);
	l1_multiplier = input->l1_scaling_enabled ?
	    input->l1_multiplier : VMX_NESTED_TSC_MULTIPLIER_ONE;
	/*
	 * Intel applies the VMCS TSC multiplier only when both "use TSC
	 * scaling" and "use TSC offsetting" are set.  Scaling without
	 * offsetting is legal (the multiplier must still be nonzero), but
	 * has no architectural effect on L2.
	 */
	l2_multiplier = input->l2_scaling_enabled &&
	    input->l2_offset_enabled ?
	    input->l2_multiplier : VMX_NESTED_TSC_MULTIPLIER_ONE;

	memset(&candidate, 0, sizeof(candidate));
	candidate.vmcs01_offset = input->l1_offset;
	candidate.vmcs01_multiplier = l1_multiplier;
	candidate.vmcs01_scaling_enabled = input->l1_scaling_enabled;
	error = nvmx_tsc_multiplier_compose(l1_multiplier, l2_multiplier,
	    &candidate.vmcs02_multiplier);
	if (error != 0)
		return (error);
	candidate.vmcs02_offset =
	    nvmx_tsc_multiply_signed(input->l1_offset, l2_multiplier);
	if (input->l2_offset_enabled)
		candidate.vmcs02_offset += input->l2_offset;
	candidate.vmcs02_scaling_enabled = input->l1_scaling_enabled ||
	    (input->l2_scaling_enabled && input->l2_offset_enabled);
	*plan = candidate;
	return (0);
}

uint64_t
vmx_nested_tsc_scaled_ticks(uint64_t host_tsc, uint64_t multiplier,
    uint64_t offset)
{

	return (nvmx_tsc_multiply(host_tsc, multiplier) + offset);
}

int
vmx_nested_tsc_write_plan(const struct vmx_nested_tsc_write_input *input,
    struct vmx_nested_tsc_write_plan *plan)
{
	struct vmx_nested_tsc_write_plan candidate;
	uint64_t l1_virtual_tsc, scaled_host;
	int error;

	if (input == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    input->timer_rate > 31 ||
	    vmx_nested_timer_state_validate(&input->timer,
	    input->timer_enabled) != 0 ||
	    (input->timer_enabled && !input->timer.armed) ||
	    (!input->timer_enabled && input->timer_rate != 0))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.updated = input->current;
	scaled_host = vmx_nested_tsc_scaled_ticks(input->write_host_tsc,
	    candidate.updated.l1_multiplier, 0);
	candidate.updated.l1_offset = input->target_tsc - scaled_host;
	error = vmx_nested_tsc_scale_compose(&candidate.updated,
	    &candidate.composed);
	if (error != 0)
		return (error);
	if (input->timer_enabled) {
		l1_virtual_tsc = vmx_nested_tsc_scaled_ticks(
		    input->timer_host_tsc, candidate.updated.l1_multiplier,
		    candidate.updated.l1_offset);
		error = vmx_nested_timer_remaining(l1_virtual_tsc,
		    input->timer_rate, input->timer.deadline_ticks,
		    &candidate.timer);
		if (error != 0)
			return (error);
	}
	*plan = candidate;
	return (0);
}
