/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _DEV_VMM_VMM_ADDRESS_RANGE_H_
#define _DEV_VMM_VMM_ADDRESS_RANGE_H_

#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

/*
 * Architecture-neutral object-range helpers.  These use uintptr_t only to
 * validate and compare object addresses; callers must not serialize either
 * the address or a result derived from it.  In particular, size_t is allowed
 * to be wider than uintptr_t on a future target, so lengths are checked
 * before they are narrowed for address-space arithmetic.
 */
static __inline bool
vmm_address_range_valid(const void *base, size_t length)
{
	uintptr_t extent, limit, start;

	if (length == 0)
		return (true);
	if (base == NULL)
		return (false);
	limit = ~(uintptr_t)0;
	if (length > (size_t)limit)
		return (false);
	start = (uintptr_t)base;
	extent = (uintptr_t)(length - 1);
	return (start <= limit - extent);
}

/*
 * Invalid non-empty ranges are conservatively treated as overlapping.  This
 * is suitable for private alias guards, which must reject ambiguous caller
 * storage rather than continue with a truncated address calculation.
 */
static __inline bool
vmm_address_ranges_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	uintptr_t left_extent, left_start, right_extent, right_start;

	if (left_length == 0 || right_length == 0)
		return (false);
	if (!vmm_address_range_valid(left, left_length) ||
	    !vmm_address_range_valid(right, right_length))
		return (true);
	left_start = (uintptr_t)left;
	right_start = (uintptr_t)right;
	left_extent = (uintptr_t)(left_length - 1);
	right_extent = (uintptr_t)(right_length - 1);
	if (left_start <= right_start)
		return (right_start - left_start <= left_extent);
	return (left_start - right_start <= right_extent);
}

#endif /* _DEV_VMM_VMM_ADDRESS_RANGE_H_ */
