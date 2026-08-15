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

#include "vmx_nested_bitmap.h"
#include "vmx_nested_memory.h"
#include "vmx_nested_state_range.h"

#define	PRI_UNCONDITIONAL_IO_EXITING	(1U << 24)
#define	PRI_USE_IO_BITMAPS		(1U << 25)
#define	PRI_USE_MSR_BITMAPS		(1U << 28)

static bool
nvmx_bitmap_overlap(const void *a, const void *b)
{

	return (vmx_nested_state_ranges_overlap(a,
	    VMX_NESTED_MSR_BITMAP_SIZE, b, VMX_NESTED_MSR_BITMAP_SIZE));
}

int
vmx_nested_io_intercept(uint32_t primary, uint64_t bitmap_a,
    uint64_t bitmap_b, uint32_t port, uint8_t size,
    const struct vmx_nested_memory *memory, bool *intercept)
{
	struct vmx_nested_memory memory_snapshot;
	uint64_t address, base;
	uint32_t current;
	uint8_t byte;
	bool candidate;
	int error;

	if (intercept == NULL || (size != 1 && size != 2 && size != 4) ||
	    port >= 0x10000U || size > 0x10000U - port)
		return (EINVAL);
	if ((primary & PRI_USE_IO_BITMAPS) == 0) {
		*intercept = (primary & PRI_UNCONDITIONAL_IO_EXITING) != 0;
		return (0);
	}
	if (memory == NULL || memory->read == NULL)
		return (EINVAL);
	memory_snapshot = *memory;
	memory = &memory_snapshot;
	candidate = false;
	for (uint8_t i = 0; i < size; i++) {
		current = port + i;
		base = current < 0x8000U ? bitmap_a : bitmap_b;
		address = base + ((current & 0x7fffU) >> 3);
		if (address < base)
			return (EOVERFLOW);
		error = memory->read(memory->arg, address, &byte, sizeof(byte));
		if (error != 0)
			return (error);
		if ((byte & (1U << (current & 7))) != 0) {
			candidate = true;
			break;
		}
	}
	*intercept = candidate;
	return (0);
}

int
vmx_nested_io_bitmap_materialize(uint32_t l1_primary, uint64_t bitmap_a,
    uint64_t bitmap_b, const struct vmx_nested_memory *memory,
    uint8_t target[VMX_NESTED_IO_BITMAP_SIZE],
    uint8_t scratch[VMX_NESTED_IO_BITMAP_SIZE])
{
	struct vmx_nested_memory memory_snapshot;
	int error;

	if (target == NULL || scratch == NULL ||
	    vmx_nested_state_ranges_overlap(target,
	    VMX_NESTED_IO_BITMAP_SIZE, scratch,
	    VMX_NESTED_IO_BITMAP_SIZE))
		return (EINVAL);
	if ((l1_primary & PRI_USE_IO_BITMAPS) == 0) {
		memset(scratch,
		    (l1_primary & PRI_UNCONDITIONAL_IO_EXITING) != 0 ?
		    0xff : 0, VMX_NESTED_IO_BITMAP_SIZE);
	} else {
		if (memory == NULL || memory->read == NULL ||
		    (bitmap_a & (VMX_NESTED_BITMAP_PAGE_SIZE - 1)) != 0 ||
		    (bitmap_b & (VMX_NESTED_BITMAP_PAGE_SIZE - 1)) != 0)
			return (EINVAL);
		memory_snapshot = *memory;
		memory = &memory_snapshot;
		error = memory->read(memory->arg, bitmap_a, scratch,
		    VMX_NESTED_BITMAP_PAGE_SIZE);
		if (error != 0)
			return (error);
		error = memory->read(memory->arg, bitmap_b,
		    scratch + VMX_NESTED_BITMAP_PAGE_SIZE,
		    VMX_NESTED_BITMAP_PAGE_SIZE);
		if (error != 0)
			return (error);
	}
	memcpy(target, scratch, VMX_NESTED_IO_BITMAP_SIZE);
	return (0);
}

int
vmx_nested_io_policy_intercept(
    const uint8_t policy[VMX_NESTED_IO_BITMAP_SIZE], uint32_t port,
    uint8_t size, bool *intercept)
{
	uint32_t current;
	bool candidate;

	if (policy == NULL || intercept == NULL ||
	    (size != 1 && size != 2 && size != 4) ||
	    port >= 0x10000U || size > 0x10000U - port)
		return (EINVAL);
	candidate = false;
	for (uint8_t i = 0; i < size; i++) {
		current = port + i;
		if ((policy[current >> 3] & (1U << (current & 7))) != 0) {
			candidate = true;
			break;
		}
	}
	*intercept = candidate;
	return (0);
}

int
vmx_nested_msr_intercept(uint32_t primary, uint64_t bitmap,
    uint32_t index, bool write, const struct vmx_nested_memory *memory,
    bool *intercept)
{
	uint64_t address;
	uint32_t bit, region;
	uint8_t byte;
	int error;

	if (intercept == NULL)
		return (EINVAL);
	if ((primary & PRI_USE_MSR_BITMAPS) == 0) {
		*intercept = true;
		return (0);
	}
	if (index <= 0x1fffU) {
		bit = index;
		region = write ? 2048 : 0;
	} else if (index >= 0xc0000000U && index <= 0xc0001fffU) {
		bit = index - 0xc0000000U;
		region = write ? 3072 : 1024;
	} else {
		*intercept = true;
		return (0);
	}
	if (memory == NULL || memory->read == NULL)
		return (EINVAL);
	address = bitmap + region + (bit >> 3);
	if (address < bitmap)
		return (EOVERFLOW);
	error = memory->read(memory->arg, address, &byte, sizeof(byte));
	if (error != 0)
		return (error);
	*intercept = (byte & (1U << (bit & 7))) != 0;
	return (0);
}

int
vmx_nested_msr_bitmap_materialize(uint32_t l1_primary,
    uint64_t l1_bitmap, const struct vmx_nested_memory *memory,
    const uint8_t l0[VMX_NESTED_MSR_BITMAP_SIZE],
    uint8_t target[VMX_NESTED_MSR_BITMAP_SIZE],
    uint8_t l1_policy[VMX_NESTED_MSR_BITMAP_SIZE],
    uint8_t scratch[VMX_NESTED_MSR_BITMAP_SIZE])
{
	int error;

	if (l0 == NULL || target == NULL || l1_policy == NULL ||
	    scratch == NULL ||
	    nvmx_bitmap_overlap(target, scratch) ||
	    nvmx_bitmap_overlap(l1_policy, scratch) ||
	    nvmx_bitmap_overlap(target, l1_policy) ||
	    nvmx_bitmap_overlap(l0, target) ||
	    nvmx_bitmap_overlap(l0, scratch) ||
	    nvmx_bitmap_overlap(l0, l1_policy))
		return (EINVAL);

	if ((l1_primary & PRI_USE_MSR_BITMAPS) == 0) {
		memset(scratch, 0xff, VMX_NESTED_MSR_BITMAP_SIZE);
	} else {
		if (memory == NULL || memory->read == NULL ||
		    (l1_bitmap & (VMX_NESTED_MSR_BITMAP_SIZE - 1)) != 0)
			return (EINVAL);
		error = memory->read(memory->arg, l1_bitmap, scratch,
		    VMX_NESTED_MSR_BITMAP_SIZE);
		if (error != 0)
			return (error);
	}
	memcpy(l1_policy, scratch, VMX_NESTED_MSR_BITMAP_SIZE);
	if ((l1_primary & PRI_USE_MSR_BITMAPS) != 0) {
		for (size_t i = 0; i < VMX_NESTED_MSR_BITMAP_SIZE; i++)
			scratch[i] |= l0[i];
	}
	memcpy(target, scratch, VMX_NESTED_MSR_BITMAP_SIZE);
	return (0);
}

int
vmx_nested_msr_policy_intercept(
    const uint8_t policy[VMX_NESTED_MSR_BITMAP_SIZE], uint32_t index,
    bool write, bool *intercept)
{
	uint32_t bit, region;

	if (policy == NULL || intercept == NULL)
		return (EINVAL);
	if (index <= 0x1fffU) {
		bit = index;
		region = write ? 2048 : 0;
	} else if (index >= 0xc0000000U && index <= 0xc0001fffU) {
		bit = index - 0xc0000000U;
		region = write ? 3072 : 1024;
	} else {
		*intercept = true;
		return (0);
	}
	*intercept =
	    (policy[region + (bit >> 3)] & (1U << (bit & 7))) != 0;
	return (0);
}

int
vmx_nested_vmcs_access_intercept(bool shadow_vmcs, uint64_t bitmap,
    uint64_t field, const struct vmx_nested_memory *memory, bool *intercept)
{
	uint64_t address;
	uint8_t byte;
	int error;

	if (intercept == NULL)
		return (EINVAL);
	if (!shadow_vmcs || field >= (1U << 15)) {
		*intercept = true;
		return (0);
	}
	if (memory == NULL || memory->read == NULL)
		return (EINVAL);
	address = bitmap + (field >> 3);
	if (address < bitmap)
		return (EOVERFLOW);
	error = memory->read(memory->arg, address, &byte, sizeof(byte));
	if (error != 0)
		return (error);
	*intercept = (byte & (1U << (field & 7))) != 0;
	return (0);
}
