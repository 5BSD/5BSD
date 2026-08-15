/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"

#define	NVMX_SECONDARY_EPT		(UINT32_C(1) << 1)
#define	NVMX_SECONDARY_VPID		(UINT32_C(1) << 5)

#define	NVMX_EPT_INVEPT		(UINT64_C(1) << 20)
#define	NVMX_EPT_INVEPT_SINGLE		(UINT64_C(1) << 25)
#define	NVMX_EPT_INVEPT_ALL		(UINT64_C(1) << 26)

#define	NVMX_VPID_INVVPID		(UINT64_C(1) << 32)
#define	NVMX_VPID_ADDRESS		(UINT64_C(1) << 40)
#define	NVMX_VPID_SINGLE		(UINT64_C(1) << 41)
#define	NVMX_VPID_ALL			(UINT64_C(1) << 42)
#define	NVMX_VPID_SINGLE_GLOBALS	(UINT64_C(1) << 43)

static bool
nvmx_secondary_allowed(const struct vmx_nested_capabilities *capabilities,
    uint32_t bit)
{

	return (((uint32_t)(capabilities->secondary >> 32) & bit) != 0);
}

bool
vmx_nested_invept_type_valid(
    const struct vmx_nested_capabilities *capabilities, uint64_t type)
{

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    !nvmx_secondary_allowed(capabilities, NVMX_SECONDARY_EPT) ||
	    (capabilities->ept_vpid & NVMX_EPT_INVEPT) == 0)
		return (false);
	if (type == 1)
		return ((capabilities->ept_vpid &
		    NVMX_EPT_INVEPT_SINGLE) != 0);
	if (type == 2)
		return ((capabilities->ept_vpid & NVMX_EPT_INVEPT_ALL) != 0);
	return (false);
}

int
vmx_nested_invept_validate(
    const struct vmx_nested_capabilities *capabilities, uint64_t type,
    const struct vmx_nested_invalidation_descriptor *descriptor,
    struct vmx_nested_invalidation *invalidation)
{
	struct vmx_nested_invalidation candidate;

	if (!vmx_nested_invept_type_valid(capabilities, type) ||
	    descriptor == NULL || invalidation == NULL ||
	    descriptor->address != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(invalidation,
	    sizeof(*invalidation), capabilities, sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(invalidation,
	    sizeof(*invalidation), descriptor, sizeof(*descriptor)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	switch (type) {
	case 1:
		if (!vmx_nested_eptp_valid(capabilities, descriptor->context))
			return (EINVAL);
		candidate.scope = VMX_NESTED_INVALIDATE_EPT_SINGLE;
		candidate.context = descriptor->context;
		candidate.address = 0;
		break;
	case 2:
		candidate.scope = VMX_NESTED_INVALIDATE_EPT_ALL;
		candidate.context = 0;
		candidate.address = 0;
		break;
	default:
		return (EINVAL);
	}
	*invalidation = candidate;
	return (0);
}

int
vmx_nested_invept_translate(
    const struct vmx_nested_invalidation *virtual_invalidation,
    struct vmx_nested_invalidation *root_invalidation)
{
	struct vmx_nested_invalidation candidate;

	if (virtual_invalidation == NULL || root_invalidation == NULL ||
	    virtual_invalidation->address != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(root_invalidation,
	    sizeof(*root_invalidation), virtual_invalidation,
	    sizeof(*virtual_invalidation)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	switch (virtual_invalidation->scope) {
	case VMX_NESTED_INVALIDATE_EPT_SINGLE:
		candidate.scope = VMX_NESTED_INVALIDATE_EPT_SINGLE;
		candidate.context = virtual_invalidation->context &
		    VMX_NESTED_EPT_ROOT_ADDRESS_MASK;
		break;
	case VMX_NESTED_INVALIDATE_EPT_ALL:
		if (virtual_invalidation->context != 0)
			return (EINVAL);
		candidate.scope = VMX_NESTED_INVALIDATE_EPT_ALL;
		break;
	default:
		return (EINVAL);
	}
	*root_invalidation = candidate;
	return (0);
}

bool
vmx_nested_invvpid_type_valid(
    const struct vmx_nested_capabilities *capabilities, uint64_t type)
{
	uint64_t type_capability;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    !nvmx_secondary_allowed(capabilities, NVMX_SECONDARY_VPID) ||
	    (capabilities->ept_vpid & NVMX_VPID_INVVPID) == 0 ||
	    type > 3)
		return (false);
	type_capability = NVMX_VPID_ADDRESS << type;
	return ((capabilities->ept_vpid & type_capability) != 0);
}

int
vmx_nested_invvpid_validate(
    const struct vmx_nested_capabilities *capabilities, uint64_t type,
    const struct vmx_nested_invalidation_descriptor *descriptor,
    struct vmx_nested_invalidation *invalidation)
{
	struct vmx_nested_invalidation candidate;
	uint16_t vpid;

	if (!vmx_nested_invvpid_type_valid(capabilities, type) ||
	    descriptor == NULL || invalidation == NULL ||
	    (descriptor->context >> 16) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(invalidation,
	    sizeof(*invalidation), capabilities, sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(invalidation,
	    sizeof(*invalidation), descriptor, sizeof(*descriptor)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	vpid = descriptor->context;
	candidate.context = vpid;
	candidate.address = 0;
	switch (type) {
	case 0:
		if (vpid == 0 || !vmx_nested_canonical_address(
		    descriptor->address, capabilities->linear_address_width))
			return (EINVAL);
		candidate.scope = VMX_NESTED_INVALIDATE_VPID_ADDRESS;
		candidate.address = descriptor->address;
		break;
	case 1:
		if (vpid == 0)
			return (EINVAL);
		candidate.scope = VMX_NESTED_INVALIDATE_VPID_SINGLE;
		break;
	case 2:
		candidate.scope = VMX_NESTED_INVALIDATE_VPID_ALL;
		candidate.context = 0;
		break;
	case 3:
		if (vpid == 0)
			return (EINVAL);
		candidate.scope =
		    VMX_NESTED_INVALIDATE_VPID_SINGLE_GLOBALS;
		break;
	default:
		return (EINVAL);
	}
	*invalidation = candidate;
	return (0);
}

int
vmx_nested_invvpid_translate(
    const struct vmx_nested_invalidation *virtual_invalidation,
    uint16_t effective_vpid,
    struct vmx_nested_invalidation *hardware_invalidation)
{
	struct vmx_nested_invalidation candidate;

	if (virtual_invalidation == NULL || hardware_invalidation == NULL ||
	    effective_vpid == 0 || (virtual_invalidation->context >> 16) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(hardware_invalidation,
	    sizeof(*hardware_invalidation), virtual_invalidation,
	    sizeof(*virtual_invalidation)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.context = effective_vpid;
	candidate.address = 0;
	switch (virtual_invalidation->scope) {
	case VMX_NESTED_INVALIDATE_VPID_ADDRESS:
		if (virtual_invalidation->context == 0)
			return (EINVAL);
		candidate.scope = VMX_NESTED_INVALIDATE_VPID_ADDRESS;
		candidate.address = virtual_invalidation->address;
		break;
	case VMX_NESTED_INVALIDATE_VPID_SINGLE:
	case VMX_NESTED_INVALIDATE_VPID_SINGLE_GLOBALS:
		if (virtual_invalidation->context == 0 ||
		    virtual_invalidation->address != 0)
			return (EINVAL);
		candidate.scope = VMX_NESTED_INVALIDATE_VPID_SINGLE;
		break;
	case VMX_NESTED_INVALIDATE_VPID_ALL:
		if (virtual_invalidation->context != 0 ||
		    virtual_invalidation->address != 0)
			return (EINVAL);
		/*
		 * L0 has one effective VPID02 for this vCPU.  A context flush
		 * is permitted to be stronger than L1 requested and must not
		 * invalidate unrelated host VPIDs.
		 */
		candidate.scope = VMX_NESTED_INVALIDATE_VPID_SINGLE;
		break;
	default:
		return (EINVAL);
	}
	*hardware_invalidation = candidate;
	return (0);
}

int
vmx_nested_vpid_transition_plan(
    const struct vmx_nested_vpid_transition *transition,
    struct vmx_nested_vpid_plan *plan)
{
	struct vmx_nested_vpid_plan candidate;
	uint16_t effective;
	bool shared;

	if (transition == NULL || plan == NULL ||
	    (unsigned int)transition->direction > VMX_NESTED_VPID_EXIT_L2 ||
	    transition->previous_virtual_vpid_valid !=
	    (transition->previous_virtual_vpid != 0) ||
	    transition->next_virtual_vpid_enabled !=
	    (transition->next_virtual_vpid != 0))
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(plan, sizeof(*plan), transition,
	    sizeof(*transition)))
		return (EINVAL);
	/*
	 * VPID is an optional hardware facility.  An outer VPID of zero
	 * represents a VMCS01 that runs without it and is valid only when
	 * neither nested level attempts to use a tagged context.
	 */
	if (transition->vmcs01_vpid == 0) {
		if (transition->effective_vpid != 0 ||
		    transition->previous_virtual_vpid_valid ||
		    transition->next_virtual_vpid_enabled ||
		    transition->distinct_ept_tag)
			return (EINVAL);
		memset(&candidate, 0, sizeof(candidate));
		*plan = candidate;
		return (0);
	}
	effective = transition->effective_vpid != 0 ?
	    transition->effective_vpid : transition->vmcs01_vpid;
	shared = effective == transition->vmcs01_vpid;

	memset(&candidate, 0, sizeof(candidate));
	candidate.hardware_vpid = effective;
	candidate.next_virtual_vpid =
	    transition->next_virtual_vpid_enabled ?
	    transition->next_virtual_vpid : 0;
	candidate.next_virtual_vpid_valid =
	    transition->next_virtual_vpid_enabled;

	if (transition->direction == VMX_NESTED_VPID_ENTER_L2) {
		candidate.flush_effective_context =
		    !transition->next_virtual_vpid_enabled ||
		    !transition->previous_virtual_vpid_valid ||
		    transition->previous_virtual_vpid !=
		    transition->next_virtual_vpid ||
		    (shared && !transition->distinct_ept_tag);
	} else {
		candidate.flush_effective_context =
		    !transition->next_virtual_vpid_enabled ||
		    (shared && !transition->distinct_ept_tag);
	}
	*plan = candidate;
	return (0);
}
