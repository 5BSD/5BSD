/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_validate.h"

bool
vmx_nested_canonical_address(uint64_t address, uint8_t width)
{
	uint64_t high, sign;

	if (width == 0 || width >= 64)
		return (false);
	sign = (address >> (width - 1)) & 1;
	high = address >> width;
	return (high == (sign != 0 ? ((uint64_t)-1 >> width) : 0));
}

bool
vmx_nested_high_bits_identical(uint64_t value, uint8_t width)
{
	uint64_t high;

	if (width == 0 || width >= 64)
		return (false);
	high = value >> width;
	return (high == 0 || high == ((uint64_t)-1 >> width));
}

bool
vmx_nested_fixed_bits_valid(uint64_t value, uint64_t fixed0, uint64_t fixed1,
    uint64_t ignored)
{

	return (((value | ignored) & fixed0) == fixed0 &&
	    (value & ~(fixed1 | ignored)) == 0);
}

bool
vmx_nested_pat_valid(uint64_t pat)
{

	for (unsigned int i = 0; i < 8; i++) {
		uint8_t type;

		type = pat >> (i * 8);
		if (type != 0 && type != 1 && type != 4 && type != 5 &&
		    type != 6 && type != 7)
			return (false);
	}
	return (true);
}

bool
vmx_nested_physical_range_valid(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint64_t length, uint64_t alignment)
{
	uint64_t limit;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    alignment == 0 || (alignment & (alignment - 1)) != 0 ||
	    (address & (alignment - 1)) != 0 || length == 0)
		return (false);
	limit = 1ULL << capabilities->physical_address_width;
	return (address < limit && length <= limit - address);
}

bool
vmx_nested_vmx_physical_range_valid(
    const struct vmx_nested_capabilities *capabilities, uint64_t address,
    uint64_t length, uint64_t alignment)
{

	if (!vmx_nested_physical_range_valid(capabilities, address, length,
	    alignment))
		return (false);
	return ((capabilities->flags & VMX_NESTED_CAP_F_REGION_32BIT) == 0 ||
	    (address < 0x100000000ULL &&
	    length <= 0x100000000ULL - address));
}
