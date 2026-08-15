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

#include "vmx_nested_ept_reflect.h"
#include "vmx_nested_state_range.h"

#define	NVMX_EPT_EXIT_VIOLATION	48U
#define	NVMX_EPT_EXIT_MISCONFIGURATION	49U
#define	NVMX_EPT_QUAL_GLA_VALID	(1ULL << 7)

int
vmx_nested_ept_reflection_information(
    const struct vmx_nested_ept_handoff_result *result,
    const struct vmx_nested_exit_information *vmcs02,
    struct vmx_nested_exit_information *vmcs12)
{
	struct vmx_nested_exit_information candidate;
	bool gla_valid;

	if (result == NULL || vmcs02 == NULL || vmcs12 == NULL ||
	    result->id.vmcs_generation == 0 ||
	    result->id.execution_epoch == 0 ||
	    vmcs02->exit_reason != NVMX_EPT_EXIT_VIOLATION ||
	    vmcs02->exit_interruption_info != 0 ||
	    vmcs02->guest_physical_address !=
	    result->guest_physical_address ||
	    (result->guest_linear_address_valid &&
	    vmcs02->guest_linear_address != result->guest_linear_address))
		return (EINVAL);
	/*
	 * This is an internal handoff result rather than caller-supplied VMCS
	 * input.  An invalid optional field must therefore be reported as a
	 * malformed handoff, not silently normalized or conflated with a bad
	 * invocation.
	 */
	if (!result->guest_linear_address_valid &&
	    result->guest_linear_address != 0)
		return (EPROTO);
	if (vmx_nested_state_ranges_overlap(vmcs12, sizeof(*vmcs12), result,
	    sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(vmcs12, sizeof(*vmcs12), vmcs02,
	    sizeof(*vmcs02)))
		return (EINVAL);

	candidate = *vmcs02;
	candidate.guest_physical_address =
	    result->guest_physical_address;
	candidate.guest_linear_address =
	    result->guest_linear_address_valid ?
	    result->guest_linear_address : 0;
	candidate.launched = false;
	switch (result->plan.action) {
	case VMX_NESTED_EPT_FAULT_REFLECT_VIOLATION:
		gla_valid = (result->plan.exit_qualification &
		    NVMX_EPT_QUAL_GLA_VALID) != 0;
		if (gla_valid != result->guest_linear_address_valid ||
		    result->plan.l2_page != 0 ||
		    result->plan.l1_page != 0 ||
		    result->plan.permissions != 0)
			return (EPROTO);
		candidate.exit_reason = NVMX_EPT_EXIT_VIOLATION;
		candidate.exit_qualification =
		    result->plan.exit_qualification;
		break;
	case VMX_NESTED_EPT_FAULT_REFLECT_MISCONFIGURATION:
		if (result->plan.exit_qualification != 0 ||
		    result->plan.l2_page != 0 ||
		    result->plan.l1_page != 0 ||
		    result->plan.permissions != 0)
			return (EPROTO);
		candidate.exit_reason =
		    NVMX_EPT_EXIT_MISCONFIGURATION;
		candidate.exit_qualification = 0;
		candidate.guest_linear_address = 0;
		break;
	default:
		return (ENOTSUP);
	}
	*vmcs12 = candidate;
	return (0);
}
