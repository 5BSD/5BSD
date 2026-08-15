/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_decode.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"

static int
nvmx_decode_fail(enum vmx_nested_decode_failure value,
    enum vmx_nested_decode_failure *failure)
{

	if (failure != NULL)
		*failure = value;
	return (EINVAL);
}

static int
nvmx_address_fail(enum vmx_nested_address_failure value,
    enum vmx_nested_address_failure *failure)
{

	if (failure != NULL)
		*failure = value;
	return (EINVAL);
}

int
vmx_nested_operand_decode(uint32_t information, bool memory_required,
    bool register_allowed, bool mode64, struct vmx_nested_operand *operand,
    enum vmx_nested_decode_failure *failure)
{
	struct vmx_nested_operand candidate;

	if (vmx_nested_state_ranges_overlap(operand, sizeof(*operand), failure,
	    sizeof(*failure)))
		return (EINVAL);
	if (failure != NULL)
		*failure = VMX_NESTED_DECODE_OK;
	if (operand == NULL)
		return (nvmx_decode_fail(VMX_NESTED_DECODE_FORM, failure));
	memset(&candidate, 0, sizeof(candidate));
	candidate.scale = information & 3;
	candidate.register1 = (information >> 3) & 0xf;
	candidate.address_size = (information >> 7) & 7;
	candidate.register_operand = (information & (1U << 10)) != 0;
	candidate.segment = (information >> 15) & 7;
	candidate.index_register = (information >> 18) & 0xf;
	candidate.index_valid = (information & (1U << 22)) == 0;
	candidate.base_register = (information >> 23) & 0xf;
	candidate.base_valid = (information & (1U << 27)) == 0;
	candidate.register2 = (information >> 28) & 0xf;
	if ((memory_required && candidate.register_operand) ||
	    (!register_allowed && candidate.register_operand))
		return (nvmx_decode_fail(VMX_NESTED_DECODE_FORM, failure));
	if (!candidate.register_operand) {
		if (candidate.address_size > 2 ||
		    (candidate.address_size == 2 && !mode64))
			return (nvmx_decode_fail(
			    VMX_NESTED_DECODE_ADDRESS_SIZE, failure));
		if (candidate.segment > 5)
			return (nvmx_decode_fail(VMX_NESTED_DECODE_SEGMENT,
			    failure));
	}
	*operand = candidate;
	return (0);
}

int
vmx_nested_operand_address(const struct vmx_nested_operand *operand,
    uint64_t displacement, const uint64_t registers[16],
    const struct vmx_nested_address_segment segments[6], bool mode64,
    bool write, size_t length, uint8_t linear_address_width,
    uint64_t *address, enum vmx_nested_address_failure *failure)
{
	const struct vmx_nested_address_segment *segment;
	uint64_t candidate, offset, upper;
	bool expand_down;

	if (vmx_nested_state_ranges_overlap(address, sizeof(*address), failure,
	    sizeof(*failure)) ||
	    vmx_nested_state_ranges_overlap(address, sizeof(*address), operand,
	    sizeof(*operand)) ||
	    vmx_nested_state_ranges_overlap(address, sizeof(*address), registers,
	    sizeof(uint64_t) * 16) ||
	    vmx_nested_state_ranges_overlap(address, sizeof(*address), segments,
	    sizeof(*segments) * 6) ||
	    vmx_nested_state_ranges_overlap(failure, sizeof(*failure), operand,
	    sizeof(*operand)) ||
	    vmx_nested_state_ranges_overlap(failure, sizeof(*failure), registers,
	    sizeof(uint64_t) * 16) ||
	    vmx_nested_state_ranges_overlap(failure, sizeof(*failure), segments,
	    sizeof(*segments) * 6))
		return (EINVAL);
	if (failure != NULL)
		*failure = VMX_NESTED_ADDRESS_OK;
	if (operand == NULL || registers == NULL || segments == NULL ||
	    address == NULL || operand->register_operand || length == 0 ||
	    operand->address_size > 2 ||
	    (operand->address_size == 2 && !mode64) || operand->segment > 5)
		return (nvmx_address_fail(VMX_NESTED_ADDRESS_FORM, failure));
	if (operand->address_size == 0)
		offset = (uint64_t)(int64_t)(int16_t)displacement;
	else if (operand->address_size == 1)
		offset = (uint64_t)(int64_t)(int32_t)displacement;
	else
		offset = displacement;
	if (operand->base_valid)
		offset += registers[operand->base_register];
	if (operand->index_valid)
		offset += registers[operand->index_register] << operand->scale;
	if (operand->address_size == 0)
		offset &= 0xffff;
	else if (operand->address_size == 1)
		offset &= 0xffffffff;
	segment = &segments[operand->segment];
	if (mode64) {
		candidate = (operand->segment == 4 || operand->segment == 5) ?
		    segment->base + offset : offset;
		if (!vmx_nested_canonical_address(candidate,
		    linear_address_width) ||
		    length - 1 > UINT64_MAX - candidate ||
		    !vmx_nested_canonical_address(candidate + length - 1,
		    linear_address_width))
			return (nvmx_address_fail(
			    VMX_NESTED_ADDRESS_NONCANONICAL, failure));
	} else {
		candidate = (segment->base + offset) & 0xffffffff;
		if ((write && ((segment->type & 0xa) == 0 ||
		    (segment->type & 8) != 0)) ||
		    (!write && (segment->type & 0xa) == 8))
			return (nvmx_address_fail(
			    VMX_NESTED_ADDRESS_SEGMENT_TYPE, failure));
		if (segment->unusable)
			return (nvmx_address_fail(
			    VMX_NESTED_ADDRESS_SEGMENT_UNUSABLE, failure));
		expand_down = (segment->type & 0xc) == 0x4;
		/*
		 * All VMX implementations ignore the limit for a flat
		 * expand-up data or code segment.
		 */
		if (!expand_down &&
		    !(segment->base == 0 && segment->limit == UINT32_MAX &&
		    ((segment->type & 8) != 0 ||
		    (segment->type & 4) == 0)) &&
		    (offset > segment->limit ||
		    length - 1 > segment->limit - offset))
			return (nvmx_address_fail(
			    VMX_NESTED_ADDRESS_SEGMENT_LIMIT, failure));
		if (expand_down) {
			upper = segment->default_big ? UINT32_MAX : UINT16_MAX;
			if (offset <= segment->limit || offset > upper ||
			    length - 1 > upper - offset)
				return (nvmx_address_fail(
				    VMX_NESTED_ADDRESS_SEGMENT_LIMIT,
				    failure));
		}
	}
	*address = candidate;
	return (0);
}
