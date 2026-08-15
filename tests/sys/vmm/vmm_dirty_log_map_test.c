/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>

#include <atf-c.h>

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_map.h>

#include "../../../sys/dev/vmm/vmm_dirty_log.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_map.c"

#define DLPAGE UINT64_C(4096)

ATF_TC_WITHOUT_HEAD(adjacent_collectable_entries_cover_range);
ATF_TC_BODY(adjacent_collectable_entries_cover_range, tc)
{
	const struct vmm_dirty_log_map_entry entries[] = {
		{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
		{ .range = { .gpa = 3 * DLPAGE, .length = 3 * DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
	};
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE,
		.length = 3 * DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_map_validate(entries, nitems(entries)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(entries, nitems(entries), &request),
	    0);
}

ATF_TC_WITHOUT_HEAD(hole_and_uncollectable_mapping_are_distinct);
ATF_TC_BODY(hole_and_uncollectable_mapping_are_distinct, tc)
{
	const struct vmm_dirty_log_map_entry hole_entries[] = {
		{ .range = { .gpa = DLPAGE, .length = DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
		{ .range = { .gpa = 3 * DLPAGE, .length = DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
	};
	const struct vmm_dirty_log_map_entry unavailable_entries[] = {
		{ .range = { .gpa = DLPAGE, .length = DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
		{ .range = { .gpa = 2 * DLPAGE, .length = DLPAGE }, .flags = 0 },
	};
	const struct vmm_dirty_log_range request = {
		.gpa = DLPAGE,
		.length = 2 * DLPAGE,
	};

	(void)tc;
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(hole_entries, nitems(hole_entries),
	    &request), EFAULT);
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(unavailable_entries,
	    nitems(unavailable_entries), &request), EOPNOTSUPP);
}

ATF_TC_WITHOUT_HEAD(rejects_noncanonical_map_without_mutation);
ATF_TC_BODY(rejects_noncanonical_map_without_mutation, tc)
{
	const struct vmm_dirty_log_range request = {
		.gpa = DLPAGE,
		.length = DLPAGE,
	};
	const struct vmm_dirty_log_map_entry overlapping[] = {
		{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
		{ .range = { .gpa = 2 * DLPAGE, .length = DLPAGE },
		  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
	};
	const struct vmm_dirty_log_map_entry invalid_flags[] = {
		{ .range = { .gpa = DLPAGE, .length = DLPAGE },
		  .flags = UINT32_C(0x80000000) },
	};
	const struct vmm_dirty_log_map_entry top[] = {
		{ .range = { .gpa = UINT64_MAX - (DLPAGE - 1),
		    .length = DLPAGE }, .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
	};
	const struct vmm_dirty_log_range top_request = {
		.gpa = UINT64_MAX - (DLPAGE - 1),
		.length = DLPAGE,
	};

	(void)tc;
	ATF_CHECK_EQ(vmm_dirty_log_map_validate(NULL, 0), EINVAL);
	ATF_CHECK_EQ(vmm_dirty_log_map_validate(top,
	    VMM_DIRTY_LOG_MAP_MAX_ENTRIES + 1), E2BIG);
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(top,
	    VMM_DIRTY_LOG_MAP_MAX_ENTRIES + 1, &request), E2BIG);
	ATF_CHECK_EQ(vmm_dirty_log_map_validate(overlapping, nitems(overlapping)),
	    EINVAL);
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(overlapping, nitems(overlapping),
	    &request), EINVAL);
	ATF_CHECK_EQ(vmm_dirty_log_map_validate(invalid_flags,
	    nitems(invalid_flags)), EINVAL);
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(invalid_flags,
	    nitems(invalid_flags), &request), EINVAL);
	ATF_REQUIRE_EQ(vmm_dirty_log_map_validate(top, nitems(top)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_map_covers(top, nitems(top), &top_request), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, adjacent_collectable_entries_cover_range);
	ATF_TP_ADD_TC(tp, hole_and_uncollectable_mapping_are_distinct);
	ATF_TP_ADD_TC(tp, rejects_noncanonical_map_without_mutation);
	return (atf_no_error());
}
