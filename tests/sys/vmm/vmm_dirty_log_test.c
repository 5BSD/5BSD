/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <dev/vmm/vmm_dirty_log.h>

#include "../../../sys/dev/vmm/vmm_dirty_log.c"

ATF_TC_WITHOUT_HEAD(range_and_bitmap_layout);
ATF_TC_BODY(range_and_bitmap_layout, tc)
{
	const struct vmm_dirty_log_range range = {
		.gpa = UINT64_C(0x2000),
		.length = 9 * VMM_DIRTY_LOG_GRANULARITY,
	};
	uint8_t bitmap[2];
	size_t bytes;
	bool isset;

	(void)tc;
	memset(bitmap, 0, sizeof(bitmap));
	ATF_REQUIRE_EQ(vmm_dirty_log_range_validate(&range, &bytes), 0);
	ATF_CHECK_EQ(bytes, sizeof(bitmap));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark(&range, bitmap, sizeof(bitmap),
	    range.gpa), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark(&range, bitmap, sizeof(bitmap),
	    range.gpa + 7 * VMM_DIRTY_LOG_GRANULARITY), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark(&range, bitmap, sizeof(bitmap),
	    range.gpa + 8 * VMM_DIRTY_LOG_GRANULARITY), 0);
	/* The canonical bitmap order is low GPA to low bit, independent of host word size. */
	ATF_CHECK_EQ(bitmap[0], UINT8_C(0x81));
	ATF_CHECK_EQ(bitmap[1], UINT8_C(0x01));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_isset(&range, bitmap, sizeof(bitmap),
	    range.gpa + 7 * VMM_DIRTY_LOG_GRANULARITY, &isset), 0);
	ATF_CHECK(isset);
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_isset(&range, bitmap, sizeof(bitmap),
	    range.gpa + VMM_DIRTY_LOG_GRANULARITY, &isset), 0);
	ATF_CHECK(!isset);
}

ATF_TC_WITHOUT_HEAD(rejects_invalid_or_partial_values);
ATF_TC_BODY(rejects_invalid_or_partial_values, tc)
{
	struct vmm_dirty_log_range range;
	uint8_t bitmap[2], before[sizeof(bitmap)];
	size_t bytes = SIZE_MAX, bytes_before;
	bool isset;

	(void)tc;
	range = (struct vmm_dirty_log_range) {
		.gpa = UINT64_C(0x2001),
		.length = VMM_DIRTY_LOG_GRANULARITY,
	};
	ATF_CHECK_EQ(vmm_dirty_log_range_validate(&range, &bytes), EINVAL);
	ATF_CHECK_EQ(bytes, SIZE_MAX);
	range.gpa = UINT64_C(0x2000);
	range.length = 0;
	bytes_before = bytes;
	ATF_CHECK_EQ(vmm_dirty_log_range_validate(&range, &bytes), EINVAL);
	ATF_CHECK_EQ(bytes, bytes_before);
	range.length = VMM_DIRTY_LOG_GRANULARITY - 1;
	ATF_CHECK_EQ(vmm_dirty_log_range_validate(&range, &bytes), EINVAL);
	range.gpa = UINT64_MAX - (VMM_DIRTY_LOG_GRANULARITY - 2);
	range.length = VMM_DIRTY_LOG_GRANULARITY;
	ATF_CHECK_EQ(vmm_dirty_log_range_validate(&range, &bytes), EINVAL);
	range.gpa = UINT64_MAX - (VMM_DIRTY_LOG_GRANULARITY - 1);
	ATF_REQUIRE_EQ(vmm_dirty_log_range_validate(&range, &bytes), 0);
	ATF_REQUIRE_EQ(bytes, 1);
	memset(bitmap, 0, sizeof(bitmap));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark(&range, bitmap, 1,
	    range.gpa), 0);
	ATF_CHECK_EQ(bitmap[0], UINT8_C(0x01));

	range = (struct vmm_dirty_log_range) {
		.gpa = UINT64_C(0x4000),
		.length = 2 * VMM_DIRTY_LOG_GRANULARITY,
	};
	memset(bitmap, 0x5a, sizeof(bitmap));
	memcpy(before, bitmap, sizeof(bitmap));
	ATF_CHECK_EQ(vmm_dirty_log_bitmap_mark(&range, bitmap, 0, range.gpa),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_bitmap_mark(&range, bitmap, 1,
	    range.gpa + 1), EINVAL);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_bitmap_isset(&range, bitmap, 1,
	    range.gpa + 2 * VMM_DIRTY_LOG_GRANULARITY, &isset), EINVAL);
	ATF_CHECK_EQ(vmm_dirty_log_bitmap_isset(&range, bitmap, 1, range.gpa,
	    NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(generation_does_not_wrap);
ATF_TC_BODY(generation_does_not_wrap, tc)
{
	uint64_t next = UINT64_C(0xaaaaaaaaaaaaaaaa);

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_generation_next(0, &next), 0);
	ATF_CHECK_EQ(next, 1);
	ATF_REQUIRE_EQ(vmm_dirty_log_generation_next(UINT64_MAX - 1, &next), 0);
	ATF_CHECK_EQ(next, UINT64_MAX);
	next = UINT64_C(0xaaaaaaaaaaaaaaaa);
	ATF_CHECK_EQ(vmm_dirty_log_generation_next(UINT64_MAX, &next), EOVERFLOW);
	ATF_CHECK_EQ(next, UINT64_C(0xaaaaaaaaaaaaaaaa));
	ATF_CHECK_EQ(vmm_dirty_log_generation_next(0, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(dirty_leaf_intersection_is_canonical);
ATF_TC_BODY(dirty_leaf_intersection_is_canonical, tc)
{
	const struct vmm_dirty_log_range range = {
		.gpa = UINT64_C(0x2000),
		.length = 9 * VMM_DIRTY_LOG_GRANULARITY,
	};
	const struct vmm_dirty_log_range partial_leaf = {
		.gpa = 0,
		.length = 4 * VMM_DIRTY_LOG_GRANULARITY,
	};
	const struct vmm_dirty_log_range large_leaf = {
		.gpa = 0,
		.length = UINT64_C(0x40000000),
	};
	const struct vmm_dirty_log_range final_page = {
		.gpa = UINT64_MAX - (VMM_DIRTY_LOG_GRANULARITY - 1),
		.length = VMM_DIRTY_LOG_GRANULARITY,
	};
	uint8_t bitmap[2], before[sizeof(bitmap)];
	bool isset;

	(void)tc;
	memset(bitmap, 0, sizeof(bitmap));
	/* Only the two pages shared with [0, 16 KiB) are marked. */
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark_range(&range, bitmap,
	    sizeof(bitmap), &partial_leaf), 0);
	ATF_CHECK_EQ(bitmap[0], UINT8_C(0x03));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_isset(&range, bitmap, sizeof(bitmap),
	    range.gpa + 2 * VMM_DIRTY_LOG_GRANULARITY, &isset), 0);
	ATF_CHECK(!isset);
	/* A disjoint leaf is a successful no-op, not an out-of-range bitmap bit. */
	memset(bitmap, 0, sizeof(bitmap));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark_range(&range, bitmap,
	    sizeof(bitmap), &(const struct vmm_dirty_log_range) {
		.gpa = UINT64_C(0x10000), .length = VMM_DIRTY_LOG_GRANULARITY,
	}), 0);
	ATF_CHECK_EQ(bitmap[0], 0);
	ATF_CHECK_EQ(bitmap[1], 0);

	/* A 1 GiB leaf is clipped to the requested range, not host page size. */
	memset(bitmap, 0, sizeof(bitmap));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark_range(&range, bitmap,
	    sizeof(bitmap), &large_leaf), 0);
	ATF_CHECK_EQ(bitmap[0], UINT8_C(0xff));
	ATF_CHECK_EQ(bitmap[1], UINT8_C(0x01));

	/* The final legal GPA page remains representable without end overflow. */
	memset(bitmap, 0, sizeof(bitmap));
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_mark_range(&final_page, bitmap, 1,
	    &final_page), 0);
	ATF_CHECK_EQ(bitmap[0], UINT8_C(0x01));

	memset(bitmap, 0x5a, sizeof(bitmap));
	memcpy(before, bitmap, sizeof(bitmap));
	ATF_CHECK_EQ(vmm_dirty_log_bitmap_mark_range(&range, bitmap,
	    sizeof(bitmap), &(const struct vmm_dirty_log_range) {
		.gpa = UINT64_C(0x2001), .length = VMM_DIRTY_LOG_GRANULARITY,
	}), EINVAL);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_bitmap_mark_range(&range, bitmap, 1,
	    &partial_leaf), EINVAL);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, range_and_bitmap_layout);
	ATF_TP_ADD_TC(tp, rejects_invalid_or_partial_values);
	ATF_TP_ADD_TC(tp, generation_does_not_wrap);
	ATF_TP_ADD_TC(tp, dirty_leaf_intersection_is_canonical);
	return (atf_no_error());
}
