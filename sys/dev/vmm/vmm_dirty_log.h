/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_DIRTY_LOG_H_
#define _DEV_VMM_VMM_DIRTY_LOG_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

/*
 * This is a logical guest-physical transfer unit, not PAGE_SIZE.  Backends
 * with a larger host or hardware page must conservatively mark every covered
 * unit; neither their page size nor their page-table representation belongs
 * in this common contract.
 */
#define	VMM_DIRTY_LOG_GRANULARITY	4096ULL
_Static_assert((VMM_DIRTY_LOG_GRANULARITY &
    (VMM_DIRTY_LOG_GRANULARITY - 1)) == 0,
    "dirty-log granularity must be a power of two");

struct vmm_dirty_log_range {
	uint64_t	gpa;
	uint64_t	length;
};

/* Value-only helpers shared by the kernel collector and management ABI. */
int	vmm_dirty_log_range_validate(const struct vmm_dirty_log_range *,
	    size_t *);
int	vmm_dirty_log_bitmap_mark(const struct vmm_dirty_log_range *, uint8_t *,
	    size_t, uint64_t);
/*
 * Mark the intersection of a dirty hardware leaf and a tracked logical range.
 * Both values use the fixed logical 4 KiB unit; callers may therefore pass a
 * 4 KiB, 2 MiB, 1 GiB, or future hardware leaf without exporting its page
 * format into this contract.
 */
int	vmm_dirty_log_bitmap_mark_range(const struct vmm_dirty_log_range *,
	    uint8_t *, size_t, const struct vmm_dirty_log_range *);
int	vmm_dirty_log_bitmap_isset(const struct vmm_dirty_log_range *,
	    const uint8_t *, size_t, uint64_t, bool *);
int	vmm_dirty_log_generation_next(uint64_t, uint64_t *);

#endif /* _DEV_VMM_VMM_DIRTY_LOG_H_ */
