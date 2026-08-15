/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_DIRTY_LOG_MAP_H_
#define _DEV_VMM_VMM_DIRTY_LOG_MAP_H_

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_mem.h>

/*
 * A map entry is a by-value description captured while the caller has
 * established the vmm_mem frozen-map boundary.  It is deliberately not a
 * vm_mem_map: segment IDs, object references, permissions, host addresses,
 * and host page sizes must not cross into the common dirty-log contract.
 */
#define VMM_DIRTY_LOG_MAP_F_COLLECTABLE 0x00000001U
#define VMM_DIRTY_LOG_MAP_MAX_ENTRIES VM_MAX_MEMMAPS

struct vmm_dirty_log_map_entry {
	struct vmm_dirty_log_range range;
	uint32_t	flags;
};

/*
 * The entries must be nonempty, bounded by the current common VMM map
 * capacity, ascending, and nonoverlapping.  Adjacent entries are permitted.
 * A noncollectable entry describes a valid mapping (for example, MMIO) whose
 * dirty state cannot be requested.
 */
int	vmm_dirty_log_map_validate(const struct vmm_dirty_log_map_entry *,
	    size_t);

/*
 * Classify a requested logical range against a previously frozen map:
 * EFAULT is a hole and EOPNOTSUPP is a valid but noncollectable mapping.
 * No map or collection state is retained or changed.
 */
int	vmm_dirty_log_map_covers(const struct vmm_dirty_log_map_entry *,
	    size_t, const struct vmm_dirty_log_range *);

#endif /* _DEV_VMM_VMM_DIRTY_LOG_MAP_H_ */
