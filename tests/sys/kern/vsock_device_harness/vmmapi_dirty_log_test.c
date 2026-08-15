/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* Exercise the userspace publication validator independently of the kernel. */
#include "vmmapi_dirty_log.c"

static struct vmm_dirty_log_result
valid_result(uint16_t operation)
{
	struct vmm_dirty_log_result result;

	memset(&result, 0, sizeof(result));
	result.version = VMM_DIRTY_LOG_RESULT_VERSION;
	result.size = VMM_DIRTY_LOG_RESULT_SIZE;
	result.operation = operation;
	result.gpa = 2 * VMM_DIRTY_LOG_GRANULARITY;
	result.length = 16 * VMM_DIRTY_LOG_GRANULARITY;
	result.identity = 3;
	result.map_generation = 5;
	result.dirty_generation = 7;
	result.bitmap_offset = sizeof(result);
	result.bitmap_bytes = 2;
	return (result);
}

ATF_TC_WITHOUT_HEAD(accepts_exact_publications);
ATF_TC_BODY(accepts_exact_publications, tc)
{
	struct vmm_dirty_log_result result;

	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), 0);
	result.operation = VMM_DIRTY_LOG_REQUEST_OBSERVE;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), 0);
}

ATF_TC_WITHOUT_HEAD(rejects_header_and_reserved_fields);
ATF_TC_BODY(rejects_header_and_reserved_fields, tc)
{
	struct vmm_dirty_log_result result;

#define CHECK_BAD(member, value) do { \
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR); \
	result.member = (value); \
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result, \
	    sizeof(result) + 2), EINVAL); \
} while (0)
	CHECK_BAD(version, VMM_DIRTY_LOG_RESULT_VERSION + 1);
	CHECK_BAD(size, VMM_DIRTY_LOG_RESULT_SIZE - 1);
	CHECK_BAD(operation, VMM_DIRTY_LOG_REQUEST_ENABLE);
	CHECK_BAD(flags, 1);
	CHECK_BAD(identity, 0);
	CHECK_BAD(map_generation, 0);
	CHECK_BAD(dirty_generation, 0);
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.reserved8[sizeof(result.reserved8) - 1] = 1;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), EINVAL);
#undef CHECK_BAD
}

ATF_TC_WITHOUT_HEAD(rejects_range_and_extent_mismatch);
ATF_TC_BODY(rejects_range_and_extent_mismatch, tc)
{
	struct vmm_dirty_log_result result;

	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.gpa++;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), EINVAL);
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.length = 0;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), EINVAL);
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.bitmap_offset++;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), EINVAL);
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.bitmap_bytes++;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), EINVAL);
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 1), EINVAL);
	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.gpa = UINT64_MAX - VMM_DIRTY_LOG_GRANULARITY + 1;
	result.length = 2 * VMM_DIRTY_LOG_GRANULARITY;
	result.bitmap_bytes = 1;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result) + 1), EINVAL);
}

ATF_TC_WITHOUT_HEAD(rejects_oversized_bitmap);
ATF_TC_BODY(rejects_oversized_bitmap, tc)
{
	struct vmm_dirty_log_result result;

	result = valid_result(VMM_DIRTY_LOG_REQUEST_CLEAR);
	result.length = (VMM_DIRTY_LOG_MAX_BITMAP_BYTES + 1) * 8 *
	    VMM_DIRTY_LOG_GRANULARITY;
	result.bitmap_bytes = VMM_DIRTY_LOG_MAX_BITMAP_BYTES + 1;
	ATF_CHECK_EQ(vm_dirty_log_result_validate(&result,
	    sizeof(result)), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, accepts_exact_publications);
	ATF_TP_ADD_TC(tp, rejects_header_and_reserved_fields);
	ATF_TP_ADD_TC(tp, rejects_range_and_extent_mismatch);
	ATF_TP_ADD_TC(tp, rejects_oversized_bitmap);
	return (atf_no_error());
}
