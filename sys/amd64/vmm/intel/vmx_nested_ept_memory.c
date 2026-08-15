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

#include "vmx_nested_ept_memory.h"
#include "vmx_nested_state_range.h"

#define	NVMX_EPT_ACCESSED	(1ULL << 8)
#define	NVMX_EPT_DIRTY		(1ULL << 9)

static bool
nvmx_ept_entry_address_valid(uint64_t gpa)
{

	return ((gpa & (sizeof(uint64_t) - 1)) == 0);
}

int
vmx_nested_ept_entry_load(const struct vmx_nested_ept_memory *memory,
    uint64_t gpa, uint64_t *value)
{
	uint8_t bytes[sizeof(uint64_t)];
	uint64_t candidate;
	int error;

	if (memory == NULL || memory->load == NULL || value == NULL ||
	    !nvmx_ept_entry_address_valid(gpa))
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(memory, sizeof(*memory), value,
	    sizeof(*value)))
		return (EINVAL);
	error = memory->load(memory->arg, gpa, bytes);
	if (error != 0)
		return (error);
	candidate = le64dec(bytes);
	*value = candidate;
	return (0);
}

int
vmx_nested_ept_ad_update(const struct vmx_nested_ept_memory *memory,
    uint64_t gpa, uint64_t entry, bool dirty, uint64_t *updated)
{
	uint8_t desired_bytes[sizeof(uint64_t)];
	uint8_t entry_bytes[sizeof(uint64_t)];
	uint8_t observed_bytes[sizeof(uint64_t)];
	uint64_t desired;
	bool exchanged;
	int error;

	if (memory == NULL || updated == NULL ||
	    !nvmx_ept_entry_address_valid(gpa))
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(memory, sizeof(*memory), updated,
	    sizeof(*updated)))
		return (EINVAL);
	desired = entry | NVMX_EPT_ACCESSED;
	if (dirty)
		desired |= NVMX_EPT_DIRTY;
	if (desired == entry) {
		*updated = entry;
		return (0);
	}
	if (memory->compare_exchange == NULL)
		return (ENOTSUP);
	le64enc(entry_bytes, entry);
	le64enc(desired_bytes, desired);
	error = memory->compare_exchange(memory->arg, gpa, entry_bytes,
	    desired_bytes, observed_bytes, &exchanged);
	if (error != 0)
		return (error);
	if (exchanged && le64dec(observed_bytes) != entry)
		return (EPROTO);
	if (!exchanged)
		return (EAGAIN);
	*updated = desired;
	return (0);
}
