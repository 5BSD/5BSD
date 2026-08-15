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

#include "vmx_nested_caps.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_ept.h"
#include "vmx_nested_ept_memory.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"

#define	NVMX_EPTW_CAP_EXECUTE_ONLY	(1ULL << 0)
#define	NVMX_EPTW_CAP_PAGE_2M		(1ULL << 16)
#define	NVMX_EPTW_CAP_PAGE_1G		(1ULL << 17)
#define	NVMX_EPTW_SECONDARY_MBEC	(1U << 22)

#define	NVMX_EPTW_ADDRESS_MASK		0x000ffffffffff000ULL
#define	NVMX_EPTW_LARGE			(1ULL << 7)
#define	NVMX_EPTW_EPTP_AD		(1ULL << 6)

static uint64_t
nvmx_physical_mask(uint8_t width)
{

	return ((1ULL << width) - 1);
}

static bool
nvmx_ept_present(uint64_t entry, bool mbec)
{

	return ((entry & 7) != 0 || (mbec && (entry & (1ULL << 10)) != 0));
}

static uint8_t
nvmx_ept_entry_permissions(uint64_t entry, bool mbec)
{
	uint8_t permissions;

	permissions = entry & 3;
	if ((entry & (1ULL << 2)) != 0)
		permissions |= VMX_NESTED_EPT_ACCESS_EXECUTE;
	if (mbec && (entry & (1ULL << 10)) != 0)
		permissions |= VMX_NESTED_EPT_PERMISSION_USER_EXECUTE;
	return (permissions);
}

static bool
nvmx_ept_entry_misconfigured(
    const struct vmx_nested_capabilities *capabilities, uint64_t entry,
    uint8_t level, bool leaf, uint8_t page_shift, bool mbec)
{
	uint64_t high_reserved, low_reserved, physical_mask;
	uint8_t memory_type;
	bool executable;

	executable = (entry & (1ULL << 2)) != 0 ||
	    (mbec && (entry & (1ULL << 10)) != 0);
	if ((entry & 1) == 0 &&
	    (((entry & (1ULL << 1)) != 0) ||
	    (executable &&
	    (capabilities->ept_vpid & NVMX_EPTW_CAP_EXECUTE_ONLY) == 0)))
		return (true);

	physical_mask = nvmx_physical_mask(
	    capabilities->physical_address_width);
	high_reserved = NVMX_EPTW_ADDRESS_MASK & ~physical_mask;
	if ((entry & high_reserved) != 0)
		return (true);

	if (!leaf) {
		low_reserved = level >= 4 ? 0xf8ULL : 0x78ULL;
		return ((entry & low_reserved) != 0);
	}
	if (level == 3 &&
	    (capabilities->ept_vpid & NVMX_EPTW_CAP_PAGE_1G) == 0)
		return (true);
	if (level == 2 &&
	    (capabilities->ept_vpid & NVMX_EPTW_CAP_PAGE_2M) == 0)
		return (true);
	if (page_shift > 12 &&
	    (entry & (((1ULL << page_shift) - 1) & ~0xfffULL)) != 0)
		return (true);
	memory_type = (entry >> 3) & 7;
	return (memory_type == 2 || memory_type == 3 || memory_type == 7);
}

int
vmx_nested_ept_walk(const struct vmx_nested_ept_walk *walk,
    struct vmx_nested_ept_result *result)
{
	struct vmx_nested_ept_result candidate;
	uint64_t entry, entry_address, index, next, offset_mask, root;
	uint8_t entry_permissions, level, page_shift, permissions;
	uint8_t effective_access, required_access, walk_length;
	bool leaf;
	int error;

	if (walk == NULL || result == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(result, sizeof(*result), walk,
	    sizeof(*walk)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result),
	    walk->capabilities, walk->capabilities == NULL ? 0 :
	    sizeof(*walk->capabilities)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result),
	    walk->memory, walk->memory == NULL ? 0 : sizeof(*walk->memory)))
		return (EINVAL);
	if (vmx_nested_capabilities_validate(walk->capabilities) != 0 ||
	    walk->memory == NULL || walk->memory->load == NULL ||
	    walk->access == 0 ||
	    (walk->access & ~(VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE)) != 0 ||
	    !vmx_nested_eptp_valid(walk->capabilities, walk->eptp))
		return (EINVAL);
	if (walk->mode_based_execute &&
	    (((uint32_t)(walk->capabilities->secondary >> 32) &
	    NVMX_EPTW_SECONDARY_MBEC) == 0))
		return (ENOTSUP);
	if ((walk->eptp & NVMX_EPTW_EPTP_AD) != 0 &&
	    walk->memory->compare_exchange == NULL)
		return (ENOTSUP);

	memset(&candidate, 0, sizeof(candidate));
	candidate.outcome = VMX_NESTED_EPT_VIOLATION;
	required_access = walk->access;
	if ((walk->eptp & NVMX_EPTW_EPTP_AD) != 0 &&
	    walk->guest_paging_structure_access)
		required_access |= VMX_NESTED_EPT_ACCESS_WRITE;
	candidate.access = required_access;
	effective_access = required_access;
	if (walk->mode_based_execute && walk->user_mode &&
	    (effective_access & VMX_NESTED_EPT_ACCESS_EXECUTE) != 0) {
		effective_access &= ~VMX_NESTED_EPT_ACCESS_EXECUTE;
		effective_access |= VMX_NESTED_EPT_PERMISSION_USER_EXECUTE;
	}
	walk_length = ((walk->eptp >> 3) & 7) + 1;
	if (!vmx_nested_physical_range_valid(walk->capabilities,
	    walk->guest_physical_address, 1, 1) ||
	    (walk_length == 4 &&
	    (walk->guest_physical_address >> 48) != 0)) {
		*result = candidate;
		return (0);
	}

	root = walk->eptp & NVMX_EPTW_ADDRESS_MASK;
	next = root;
	permissions = VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE | VMX_NESTED_EPT_ACCESS_EXECUTE;
	if (walk->mode_based_execute)
		permissions |= VMX_NESTED_EPT_PERMISSION_USER_EXECUTE;
	for (level = walk_length; level != 0; level--) {
		index = (walk->guest_physical_address >>
		    (12 + 9 * (level - 1))) & 0x1ff;
		entry_address = next + index * sizeof(uint64_t);
		error = vmx_nested_ept_entry_load(walk->memory, entry_address,
		    &entry);
		if (error != 0)
			return (error);
		candidate.entry_address = entry_address;
		candidate.entry = entry;
		candidate.level = level;
		entry_permissions = nvmx_ept_entry_permissions(entry,
		    walk->mode_based_execute);
		permissions &= entry_permissions;
		candidate.permissions = permissions;
		if (!nvmx_ept_present(entry, walk->mode_based_execute)) {
			*result = candidate;
			return (0);
		}

		leaf = level == 1 ||
		    ((level == 2 || level == 3) &&
		    (entry & NVMX_EPTW_LARGE) != 0);
		page_shift = leaf ? 12 + 9 * (level - 1) : 0;
		if (nvmx_ept_entry_misconfigured(walk->capabilities, entry,
		    level, leaf, page_shift, walk->mode_based_execute)) {
			candidate.outcome = VMX_NESTED_EPT_MISCONFIGURATION;
			*result = candidate;
			return (0);
		}
		if (leaf) {
			candidate.page_shift = page_shift;
			if ((walk->eptp & NVMX_EPTW_EPTP_AD) != 0) {
				error = vmx_nested_ept_ad_update(walk->memory,
				    entry_address, entry,
				    (required_access &
				    VMX_NESTED_EPT_ACCESS_WRITE) != 0 &&
				    (permissions & effective_access) ==
				    effective_access, &entry);
				if (error != 0)
					return (error);
				candidate.entry = entry;
			}
			if ((permissions & effective_access) != effective_access) {
				*result = candidate;
				return (0);
			}
			offset_mask = (1ULL << page_shift) - 1;
			candidate.translated_address =
			    (entry & nvmx_physical_mask(
			    walk->capabilities->physical_address_width) &
			    ~offset_mask) |
			    (walk->guest_physical_address & offset_mask);
			candidate.outcome = VMX_NESTED_EPT_TRANSLATED;
			*result = candidate;
			return (0);
		}
		if ((walk->eptp & NVMX_EPTW_EPTP_AD) != 0) {
			error = vmx_nested_ept_ad_update(walk->memory,
			    entry_address, entry, false, &entry);
			if (error != 0)
				return (error);
			candidate.entry = entry;
		}
		next = entry & NVMX_EPTW_ADDRESS_MASK;
	}
	return (EPROTO);
}

int
vmx_nested_ept_exit_qualification(
    const struct vmx_nested_ept_result *result,
    const struct vmx_nested_ept_exit_provenance *provenance,
    uint64_t *qualification)
{
	uint64_t candidate;

	if (result == NULL || provenance == NULL || qualification == NULL ||
	    result->outcome == VMX_NESTED_EPT_TRANSLATED ||
	    (result->access & ~(VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE)) != 0 ||
	    (result->permissions & ~(VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE |
	    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE)) != 0 ||
	    (provenance->final_translation &&
	    !provenance->linear_address_valid) ||
	    (provenance->advanced_information &&
	    (!provenance->linear_address_valid ||
	    !provenance->final_translation)) ||
	    (!provenance->advanced_information &&
	    (provenance->user_mode || provenance->guest_page_writable ||
	    provenance->guest_page_execute_disable)))
		return (EINVAL);
	if (result->outcome == VMX_NESTED_EPT_MISCONFIGURATION) {
		*qualification = 0;
		return (0);
	}
	if (result->outcome != VMX_NESTED_EPT_VIOLATION ||
	    result->access == 0)
		return (EINVAL);

	candidate = result->access;
	candidate |= (uint64_t)(result->permissions &
	    (VMX_NESTED_EPT_ACCESS_READ | VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE)) << 3;
	if ((result->permissions &
	    VMX_NESTED_EPT_PERMISSION_USER_EXECUTE) != 0)
		candidate |= 1ULL << 6;
	if (provenance->linear_address_valid)
		candidate |= 1ULL << 7;
	if (provenance->final_translation)
		candidate |= 1ULL << 8;
	if (provenance->nmi_unblocking_due_to_iret)
		candidate |= 1ULL << 12;
	if (provenance->advanced_information) {
		if (provenance->user_mode)
			candidate |= 1ULL << 9;
		if (provenance->guest_page_writable)
			candidate |= 1ULL << 10;
		if (provenance->guest_page_execute_disable)
			candidate |= 1ULL << 11;
	}
	*qualification = candidate;
	return (0);
}
