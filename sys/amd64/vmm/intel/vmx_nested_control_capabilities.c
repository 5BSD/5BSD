/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_control_capabilities.h"
#include "vmx_nested_state_range.h"

#define	NVMX_BASIC_TRUE_CONTROLS	(UINT64_C(1) << 55)
#define	NVMX_PRIMARY_SECONDARY_CONTROLS	(UINT32_C(1) << 31)

static bool
nvmx_control_capability_valid(uint64_t capability)
{
	uint32_t allowed, required;

	required = (uint32_t)capability;
	allowed = (uint32_t)(capability >> 32);
	return ((required & ~allowed) == 0);
}

int
vmx_nested_control_capabilities_select(
    const struct vmx_nested_control_capabilities_raw *raw,
    struct vmx_nested_vmcs02_capabilities *capabilities)
{
	struct vmx_nested_vmcs02_capabilities candidate;
	bool true_controls;

	if (raw == NULL || capabilities == NULL ||
	    vmx_nested_state_ranges_overlap(capabilities,
	    sizeof(*capabilities), raw, sizeof(*raw)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	true_controls = (raw->basic & NVMX_BASIC_TRUE_CONTROLS) != 0;
	if (true_controls) {
		candidate.pinbased = raw->true_pinbased;
		candidate.primary = raw->true_primary;
		candidate.vmexit = raw->true_vmexit;
		candidate.vmentry = raw->true_vmentry;
	} else {
		candidate.pinbased = raw->legacy_pinbased;
		candidate.primary = raw->legacy_primary;
		candidate.vmexit = raw->legacy_vmexit;
		candidate.vmentry = raw->legacy_vmentry;
	}
	if (!nvmx_control_capability_valid(candidate.pinbased) ||
	    !nvmx_control_capability_valid(candidate.primary) ||
	    !nvmx_control_capability_valid(candidate.vmexit) ||
	    !nvmx_control_capability_valid(candidate.vmentry))
		return (EINVAL);

	/*
	 * IA32_VMX_PROCBASED_CTLS2 is usable only when activation of
	 * secondary controls may be 1.  Canonicalize it to zero otherwise
	 * so an irrelevant or synthetic MSR value cannot leak into policy.
	 */
	if (((uint32_t)(candidate.primary >> 32) &
	    NVMX_PRIMARY_SECONDARY_CONTROLS) != 0) {
		if (!nvmx_control_capability_valid(raw->secondary))
			return (EINVAL);
		candidate.secondary = raw->secondary;
	}
	*capabilities = candidate;
	return (0);
}
