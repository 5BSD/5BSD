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
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_host.h"
#include "vmx_nested_memory.h"
#include "vmx_nested_pdpte.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"

#define	NVMX_PDPTE_PRIMARY_SECONDARY	(1U << 31)
#define	NVMX_PDPTE_SECONDARY_EPT	(1U << 1)
#define	NVMX_PDPTE_ENTRY_GUEST_LMA	(1U << 9)
#define	NVMX_PDPTE_CR0_PG		(1ULL << 31)
#define	NVMX_PDPTE_CR4_PAE		(1ULL << 5)
#define	NVMX_PDPTE_PRESENT		1ULL
#define	NVMX_PDPTE_RESERVED_LOW		0x1e6ULL

static int
nvmx_pdpte_fail(enum vmx_nested_pdpte_failure value,
    enum vmx_nested_pdpte_failure *failure)
{

	if (failure != NULL)
		*failure = value;
	return (EINVAL);
}

bool
vmx_nested_host_pdpte_active(const struct vmx_nested_host_state *host)
{

	return (host != NULL &&
	    (host->cr0 & NVMX_PDPTE_CR0_PG) != 0 &&
	    (host->cr4 & NVMX_PDPTE_CR4_PAE) != 0 &&
	    !host->root_ia32e);
}

bool
vmx_nested_guest_pdpte_memory_required(uint32_t primary,
    uint32_t secondary, uint32_t vmentry,
    const struct vmx_nested_guest_control_state *control)
{

	if (control == NULL ||
	    (control->cr0 & NVMX_PDPTE_CR0_PG) == 0 ||
	    (control->cr4 & NVMX_PDPTE_CR4_PAE) == 0 ||
	    (vmentry & NVMX_PDPTE_ENTRY_GUEST_LMA) != 0)
		return (false);
	if ((primary & NVMX_PDPTE_PRIMARY_SECONDARY) == 0)
		secondary = 0;
	return ((secondary & NVMX_PDPTE_SECONDARY_EPT) == 0);
}

int
vmx_nested_pdpte_validate(
    const struct vmx_nested_capabilities *capabilities, uint32_t primary,
    uint32_t secondary, uint32_t vmentry,
    const struct vmx_nested_guest_control_state *control,
    const uint64_t vmcs_values[4], const struct vmx_nested_memory *memory,
    struct vmx_nested_pdpte_state *result,
    enum vmx_nested_pdpte_failure *failure)
{
	struct vmx_nested_pdpte_state candidate;
	uint8_t bytes[sizeof(candidate.value)];
	uint64_t address, high_reserved;
	bool ept;

	if (result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), failure,
	    failure == NULL ? 0 : sizeof(*failure)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result),
	    capabilities, capabilities == NULL ? 0 : sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), control,
	    control == NULL ? 0 : sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result),
	    vmcs_values, vmcs_values == NULL ? 0 : sizeof(candidate.value)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), memory,
	    memory == NULL ? 0 : sizeof(*memory)) ||
	    (failure != NULL &&
	    (vmx_nested_state_ranges_overlap(failure, sizeof(*failure),
	    capabilities, capabilities == NULL ? 0 :
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(failure, sizeof(*failure), control,
	    control == NULL ? 0 : sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(failure, sizeof(*failure),
	    vmcs_values, vmcs_values == NULL ? 0 : sizeof(candidate.value)) ||
	    vmx_nested_state_ranges_overlap(failure, sizeof(*failure), memory,
	    memory == NULL ? 0 : sizeof(*memory)))))
		return (EINVAL);
	if (failure != NULL)
		*failure = VMX_NESTED_PDPTE_OK;
	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    control == NULL)
		return (nvmx_pdpte_fail(VMX_NESTED_PDPTE_PREREQUISITE,
		    failure));
	memset(&candidate, 0, sizeof(candidate));
	if ((control->cr0 & NVMX_PDPTE_CR0_PG) == 0 ||
	    (control->cr4 & NVMX_PDPTE_CR4_PAE) == 0 ||
	    (vmentry & NVMX_PDPTE_ENTRY_GUEST_LMA) != 0) {
		*result = candidate;
		return (0);
	}
	candidate.active = true;
	if ((primary & NVMX_PDPTE_PRIMARY_SECONDARY) == 0)
		secondary = 0;
	ept = !vmx_nested_guest_pdpte_memory_required(primary, secondary,
	    vmentry, control);
	if (ept) {
		if (vmcs_values == NULL)
			return (nvmx_pdpte_fail(
			    VMX_NESTED_PDPTE_PREREQUISITE, failure));
		memcpy(candidate.value, vmcs_values, sizeof(candidate.value));
	} else {
		address = control->cr3 & ~0x1fULL;
		if (!vmx_nested_physical_range_valid(capabilities, address,
		    sizeof(bytes), sizeof(bytes)))
			return (nvmx_pdpte_fail(VMX_NESTED_PDPTE_ADDRESS,
			    failure));
		if (memory == NULL || memory->read == NULL ||
		    memory->read(memory->arg, address, bytes,
		    sizeof(bytes)) != 0) {
			if (failure != NULL)
				*failure = VMX_NESTED_PDPTE_MEMORY;
			return (EFAULT);
		}
		for (unsigned int i = 0; i < nitems(candidate.value); i++)
			candidate.value[i] =
			    le64dec(bytes + i * sizeof(uint64_t));
	}
	high_reserved = ~((1ULL << capabilities->physical_address_width) - 1);
	for (unsigned int i = 0; i < nitems(candidate.value); i++) {
		if ((candidate.value[i] & NVMX_PDPTE_PRESENT) != 0 &&
		    (candidate.value[i] &
		    (NVMX_PDPTE_RESERVED_LOW | high_reserved)) != 0)
			return (nvmx_pdpte_fail(VMX_NESTED_PDPTE_RESERVED,
			    failure));
	}
	*result = candidate;
	return (0);
}

int
vmx_nested_host_pdpte_snapshot(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_host_state *host,
    const struct vmx_nested_memory *memory,
    struct vmx_nested_pdpte_state *result,
    enum vmx_nested_pdpte_failure *failure)
{
	struct vmx_nested_guest_control_state control;
	uint32_t vmentry;

	if (host == NULL)
		return (nvmx_pdpte_fail(VMX_NESTED_PDPTE_PREREQUISITE,
		    failure));
	if (result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), host,
	    sizeof(*host)) ||
	    vmx_nested_state_ranges_overlap(failure,
	    failure == NULL ? 0 : sizeof(*failure), host, sizeof(*host)))
		return (EINVAL);
	memset(&control, 0, sizeof(control));
	control.cr0 = host->cr0;
	control.cr3 = host->cr3;
	control.cr4 = host->cr4;
	vmentry = host->root_ia32e ? NVMX_PDPTE_ENTRY_GUEST_LMA : 0;
	return (vmx_nested_pdpte_validate(capabilities, 0, 0, vmentry,
	    &control, NULL, memory, result, failure));
}
