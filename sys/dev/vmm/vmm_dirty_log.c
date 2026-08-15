/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <sys/limits.h>
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_dirty_log.h>

static int
vmm_dirty_log_page_index(const struct vmm_dirty_log_range *range,
    uint64_t gpa, uint64_t *index)
{
	uint64_t offset;

	if (range == NULL || index == NULL ||
	    vmm_dirty_log_range_validate(range, NULL) != 0 ||
	    (gpa & (VMM_DIRTY_LOG_GRANULARITY - 1)) != 0)
		return (EINVAL);
	/*
	 * Do not form the exclusive end: a range ending exactly at 2^64 is
	 * valid, but its end cannot be represented by uint64_t.
	 */
	if (gpa < range->gpa)
		return (EINVAL);
	offset = gpa - range->gpa;
	if (offset >= range->length)
		return (EINVAL);
	*index = offset / VMM_DIRTY_LOG_GRANULARITY;
	return (0);
}

int
vmm_dirty_log_range_validate(const struct vmm_dirty_log_range *range,
    size_t *bitmap_bytes)
{
	uint64_t pages, bytes;

	if (range == NULL || range->length == 0 ||
	    (range->gpa & (VMM_DIRTY_LOG_GRANULARITY - 1)) != 0 ||
	    (range->length & (VMM_DIRTY_LOG_GRANULARITY - 1)) != 0 ||
	    range->gpa > UINT64_MAX - (range->length - 1))
		return (EINVAL);
	pages = range->length / VMM_DIRTY_LOG_GRANULARITY;
	/* pages is nonzero, so this rounded division cannot underflow. */
	bytes = (pages - 1) / NBBY + 1;
	if (bytes > SIZE_MAX)
		return (EOVERFLOW);
	if (bitmap_bytes != NULL)
		*bitmap_bytes = (size_t)bytes;
	return (0);
}

int
vmm_dirty_log_bitmap_mark(const struct vmm_dirty_log_range *range,
    uint8_t *bitmap, size_t bitmap_bytes, uint64_t gpa)
{
	uint64_t index;
	size_t required;
	int error;

	error = vmm_dirty_log_page_index(range, gpa, &index);
	if (error != 0)
		return (error);
	if (bitmap == NULL || vmm_dirty_log_range_validate(range, &required) != 0 ||
	    bitmap_bytes != required)
		return (EINVAL);
	bitmap[index / NBBY] |= UINT8_C(1) << (index % NBBY);
	return (0);
}

int
vmm_dirty_log_bitmap_mark_range(const struct vmm_dirty_log_range *range,
    uint8_t *bitmap, size_t bitmap_bytes,
    const struct vmm_dirty_log_range *dirty_range)
{
	uint64_t dirty_last, end, gpa, index, start, tracked_last;
	size_t required;

	/* Validate every value before changing even the first bitmap bit. */
	if (bitmap == NULL || dirty_range == NULL ||
	    vmm_dirty_log_range_validate(range, &required) != 0 ||
	    vmm_dirty_log_range_validate(dirty_range, NULL) != 0 ||
	    bitmap_bytes != required)
		return (EINVAL);
	tracked_last = range->gpa + range->length - 1;
	dirty_last = dirty_range->gpa + dirty_range->length - 1;
	start = range->gpa > dirty_range->gpa ? range->gpa : dirty_range->gpa;
	end = tracked_last < dirty_last ? tracked_last : dirty_last;
	if (start > end)
		return (0);

	/* Every validated boundary is 4 KiB aligned, including start and end + 1. */
	for (gpa = start;; gpa += VMM_DIRTY_LOG_GRANULARITY) {
		index = (gpa - range->gpa) / VMM_DIRTY_LOG_GRANULARITY;
		bitmap[index / NBBY] |= UINT8_C(1) << (index % NBBY);
		if (gpa == end - (VMM_DIRTY_LOG_GRANULARITY - 1))
			break;
	}
	return (0);
}

int
vmm_dirty_log_bitmap_isset(const struct vmm_dirty_log_range *range,
    const uint8_t *bitmap, size_t bitmap_bytes, uint64_t gpa, bool *isset)
{
	uint64_t index;
	size_t required;
	int error;

	if (isset == NULL)
		return (EINVAL);
	error = vmm_dirty_log_page_index(range, gpa, &index);
	if (error != 0)
		return (error);
	if (bitmap == NULL || vmm_dirty_log_range_validate(range, &required) != 0 ||
	    bitmap_bytes != required)
		return (EINVAL);
	*isset = (bitmap[index / NBBY] & (UINT8_C(1) << (index % NBBY))) != 0;
	return (0);
}

int
vmm_dirty_log_generation_next(uint64_t generation, uint64_t *next)
{

	if (next == NULL)
		return (EINVAL);
	if (generation == UINT64_MAX)
		return (EOVERFLOW);
	*next = generation + 1;
	return (0);
}
