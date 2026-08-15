/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_request.h>

#include "../../../sys/dev/vmm/vmm_dirty_log.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_request.c"

#define TEST_GPA UINT64_C(0x2000)
#define TEST_LENGTH (9 * UINT64_C(4096))

static struct vmm_dirty_log_request
valid_request(uint16_t operation)
{
	struct vmm_dirty_log_request request;

	memset(&request, 0, sizeof(request));
	request.version = VMM_DIRTY_LOG_REQUEST_VERSION;
	request.size = VMM_DIRTY_LOG_REQUEST_SIZE;
	request.operation = operation;
	if (operation != VMM_DIRTY_LOG_REQUEST_DISABLE) {
		request.gpa = TEST_GPA;
		request.length = TEST_LENGTH;
	}
	if (operation == VMM_DIRTY_LOG_REQUEST_OBSERVE ||
	    operation == VMM_DIRTY_LOG_REQUEST_CLEAR) {
		request.output_address = UINT64_C(0x10000);
		request.output_bytes = sizeof(struct vmm_dirty_log_result) + 2;
	}
	return (request);
}

ATF_TC_WITHOUT_HEAD(valid_operations);
ATF_TC_BODY(valid_operations, tc)
{
	struct vmm_dirty_log_request request;

	(void)tc;
	for (uint16_t operation = VMM_DIRTY_LOG_REQUEST_ENABLE;
	    operation < VMM_DIRTY_LOG_REQUEST_OPERATION_LAST; operation++) {
		request = valid_request(operation);
		ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), 0);
	}
}

ATF_TC_WITHOUT_HEAD(rejects_unknown_and_noncanonical_input);
ATF_TC_BODY(rejects_unknown_and_noncanonical_input, tc)
{
	struct vmm_dirty_log_request request, before;

	(void)tc;
	request = valid_request(VMM_DIRTY_LOG_REQUEST_CLEAR);
	before = request;
	request.version++;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = before;
	request.size--;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = before;
	request.flags = 1;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = before;
	request.reserved8[15] = 1;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = before;
	request.reserved64[0] = 1;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = before;
	request.output_bytes--;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = before;
	request.gpa++;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = valid_request(VMM_DIRTY_LOG_REQUEST_ENABLE);
	request.output_address = UINT64_C(0x10000);
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
	request = valid_request(VMM_DIRTY_LOG_REQUEST_DISABLE);
	request.length = UINT64_C(4096);
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
}

ATF_TC_WITHOUT_HEAD(result_encoding_and_validation);
ATF_TC_BODY(result_encoding_and_validation, tc)
{
	struct vmm_dirty_log_request input;
	struct vmm_dirty_log_result result, before;

	(void)tc;
	input = valid_request(VMM_DIRTY_LOG_REQUEST_CLEAR);
	memset(&result, 0xa5, sizeof(result));
	ATF_REQUIRE_EQ(vmm_dirty_log_result_encode(&input, 7, 11, 13,
	    &result), 0);
	ATF_CHECK_EQ(result.identity, 7);
	ATF_CHECK_EQ(result.map_generation, 11);
	ATF_CHECK_EQ(result.dirty_generation, 13);
	ATF_CHECK_EQ(result.bitmap_offset, sizeof(result));
	ATF_CHECK_EQ(result.bitmap_bytes, 2);
	ATF_CHECK_EQ(vmm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), 0);

	memset(&result, 0xa5, sizeof(result));
	before = result;
	ATF_CHECK_EQ(vmm_dirty_log_result_encode(&input, 0, 11, 13,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_result_encode(&input, 7, 11, 13,
	    &result), 0);
	result.reserved8[0] = 1;
	ATF_CHECK_EQ(vmm_dirty_log_result_validate(&result,
	    sizeof(result) + 2), EINVAL);
}

ATF_TC_WITHOUT_HEAD(rejects_unbounded_synchronous_output);
ATF_TC_BODY(rejects_unbounded_synchronous_output, tc)
{
	struct vmm_dirty_log_request request;

	(void)tc;
	request = valid_request(VMM_DIRTY_LOG_REQUEST_CLEAR);
	request.length = (VMM_DIRTY_LOG_MAX_BITMAP_BYTES + 1) *
	    UINT64_C(8) * VMM_DIRTY_LOG_GRANULARITY;
	request.output_bytes = sizeof(struct vmm_dirty_log_result) +
	    VMM_DIRTY_LOG_MAX_BITMAP_BYTES + 1;
	ATF_CHECK_EQ(vmm_dirty_log_request_validate(&request), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, valid_operations);
	ATF_TP_ADD_TC(tp, rejects_unknown_and_noncanonical_input);
	ATF_TP_ADD_TC(tp, result_encoding_and_validation);
	ATF_TP_ADD_TC(tp, rejects_unbounded_synchronous_output);
	return (atf_no_error());
}
