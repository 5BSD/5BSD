/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_LIBRARY_CACHE_STATS_H
#define SWITCHBOARD_LIBRARY_CACHE_STATS_H
#include <sys/types.h>
#include <sys/user.h>
#include <errno.h>
#include <stdint.h>

struct library_cache_stats {
	uint64_t executable_mappings;
	uint64_t executable_virtual_bytes;
};

/* File identity survives renames. Count executable slices only, excluding
 * the loader's index mapping. Virtual bytes are not resident/physical bytes. */
static inline int
library_cache_stats_collect(const struct kinfo_vmentry *maps, int count,
    uint64_t device, uint64_t inode, struct library_cache_stats *stats)
{
	struct library_cache_stats result = {0};

	if (count < 0)
		return (EINVAL);
	for (int i = 0; i < count; i++) {
		const struct kinfo_vmentry *map = &maps[i];
		uint64_t bytes;

		if (map->kve_type != KVME_TYPE_VNODE ||
		    map->kve_vn_fsid != device || map->kve_vn_fileid != inode ||
		    (map->kve_protection & KVME_PROT_EXEC) == 0)
			continue;
		if (map->kve_end < map->kve_start)
			return (EFTYPE);
		bytes = map->kve_end - map->kve_start;
		if (bytes > UINT64_MAX - result.executable_virtual_bytes)
			return (EOVERFLOW);
		result.executable_virtual_bytes += bytes;
		result.executable_mappings++;
	}
	*stats = result;
	return (0);
}
#endif
