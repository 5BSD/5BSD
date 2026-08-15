/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_map.h>

static int
vmm_dirty_log_range_last(const struct vmm_dirty_log_range *range,
    uint64_t *last)
{

	if (last == NULL || vmm_dirty_log_range_validate(range, NULL) != 0)
		return (EINVAL);
	/* range validation proves that this inclusive calculation cannot wrap. */
	*last = range->gpa + range->length - 1;
	return (0);
}

int
vmm_dirty_log_map_validate(const struct vmm_dirty_log_map_entry *entries,
    size_t nentries)
{
	uint64_t last, previous_last;
	size_t i;

	if (entries == NULL || nentries == 0)
		return (EINVAL);
	if (nentries > VMM_DIRTY_LOG_MAP_MAX_ENTRIES)
		return (E2BIG);
	previous_last = 0;
	for (i = 0; i < nentries; i++) {
		if ((entries[i].flags & ~VMM_DIRTY_LOG_MAP_F_COLLECTABLE) != 0 ||
		    vmm_dirty_log_range_last(&entries[i].range, &last) != 0)
			return (EINVAL);
		if (i != 0 && entries[i].range.gpa <= previous_last)
			return (EINVAL);
		previous_last = last;
	}
	return (0);
}

int
vmm_dirty_log_map_covers(const struct vmm_dirty_log_map_entry *entries,
    size_t nentries, const struct vmm_dirty_log_range *range)
{
	uint64_t entry_last, requested_last, next;
	size_t i;
	int error;

	error = vmm_dirty_log_map_validate(entries, nentries);
	if (error != 0)
		return (error);
	if (vmm_dirty_log_range_last(range, &requested_last) != 0)
		return (EINVAL);
	next = range->gpa;
	for (i = 0; i < nentries; i++) {
		error = vmm_dirty_log_range_last(&entries[i].range, &entry_last);
		if (error != 0)
			return (EPROTO);
		if (entry_last < next)
			continue;
		if (entries[i].range.gpa > next)
			return (EFAULT);
		if ((entries[i].flags & VMM_DIRTY_LOG_MAP_F_COLLECTABLE) == 0)
			return (EOPNOTSUPP);
		if (entry_last >= requested_last)
			return (0);
		/* requested_last is later, so entry_last cannot be UINT64_MAX. */
		next = entry_last + 1;
	}
	return (EFAULT);
}
