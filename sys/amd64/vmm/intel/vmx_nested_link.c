/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_link.h"
#include "vmx_nested_memory.h"

#define	NVMX_LINK_PRIMARY_SECONDARY	(1U << 31)
#define	NVMX_LINK_SECONDARY_SHADOW	(1U << 14)
#define	NVMX_LINK_ENTRY_SMM		(1U << 10)
#define	NVMX_LINK_ENTRY_DUAL_MONITOR	(1U << 11)

static int
nvmx_link_fail(enum vmx_nested_link_failure value,
    enum vmx_nested_link_failure *failure)
{

	if (failure != NULL)
		*failure = value;
	return (EINVAL);
}

bool
vmx_nested_link_pointer_memory_required(uint64_t link_pointer)
{

	return (link_pointer != ~(uint64_t)0);
}

bool
vmx_nested_link_state_required(uint32_t primary, uint32_t secondary,
    uint32_t vmentry, bool in_smm, bool guest_in_smm,
    uint64_t link_pointer)
{

	if (!vmx_nested_link_pointer_memory_required(link_pointer))
		return (false);
	if ((primary & NVMX_LINK_PRIMARY_SECONDARY) == 0)
		secondary = 0;
	/*
	 * A non-all-ones link pointer is valid even when VMCS shadowing is
	 * disabled.  In ordinary non-SMM operation the pointed-to VMCS is not
	 * part of the active L2 execution image and guest RAM preserves its
	 * revision header.  A separate architectural field image is required
	 * only when the exposed controls can actually consume linked state.
	 */
	return ((secondary & NVMX_LINK_SECONDARY_SHADOW) != 0 || in_smm ||
	    guest_in_smm ||
	    (vmentry & (NVMX_LINK_ENTRY_SMM |
	    NVMX_LINK_ENTRY_DUAL_MONITOR)) != 0);
}

int
vmx_nested_link_pointer_validate(
    const struct vmx_nested_capabilities *capabilities, uint32_t primary,
    uint32_t secondary, uint32_t vmentry, uint64_t link_pointer,
    uint64_t current_vmcs, uint64_t executive_vmcs, bool in_smm,
    const struct vmx_nested_memory *memory,
    enum vmx_nested_link_failure *failure)
{
	uint8_t bytes[sizeof(uint32_t)];
	uint32_t revision;
	bool shadow;

	if (failure != NULL)
		*failure = VMX_NESTED_LINK_OK;
	if (vmx_nested_capabilities_validate(capabilities) != 0)
		return (nvmx_link_fail(VMX_NESTED_LINK_ADDRESS, failure));
	if (!vmx_nested_link_pointer_memory_required(link_pointer))
		return (0);
	if (!vmx_nested_region_gpa_valid(capabilities, link_pointer))
		return (nvmx_link_fail(VMX_NESTED_LINK_ADDRESS, failure));
	if (memory == NULL || memory->read == NULL ||
	    memory->read(memory->arg, link_pointer, bytes, sizeof(bytes)) != 0) {
		if (failure != NULL)
			*failure = VMX_NESTED_LINK_MEMORY;
		return (EFAULT);
	}
	if ((primary & NVMX_LINK_PRIMARY_SECONDARY) == 0)
		secondary = 0;
	shadow = (secondary & NVMX_LINK_SECONDARY_SHADOW) != 0;
	revision = le32dec(bytes);
	if ((revision & 0x7fffffffU) !=
	    capabilities->revision_id ||
	    ((revision >> 31) != 0) != shadow)
		return (nvmx_link_fail(VMX_NESTED_LINK_REVISION, failure));
	if ((!in_smm || (vmentry & NVMX_LINK_ENTRY_SMM) != 0) &&
	    link_pointer == current_vmcs)
		return (nvmx_link_fail(VMX_NESTED_LINK_CURRENT, failure));
	if (in_smm && (vmentry & NVMX_LINK_ENTRY_SMM) == 0 &&
	    link_pointer == executive_vmcs)
		return (nvmx_link_fail(VMX_NESTED_LINK_EXECUTIVE, failure));
	return (0);
}
