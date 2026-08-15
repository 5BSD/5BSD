/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioccom.h>

#if defined(__amd64__)
#include <amd64/include/vmm.h>
#include <amd64/include/vmm_dev.h>
#elif defined(__aarch64__)
#include <arm64/include/vmm_dev.h>
#elif defined(__riscv)
#include <riscv/include/vmm_dev.h>
#else
#error unsupported VMM architecture
#endif

#include <atf-c.h>
#include <stddef.h>
#include <stdint.h>

#define TEST_VERSION UINT16_C(1)
#define TEST_SIZE UINT16_C(80)
#define TEST_IOCTL_NUMBER UINT32_C(118)

ATF_TC_WITHOUT_HEAD(layout);
ATF_TC_BODY(layout, tc)
{
	struct vmm_dirty_log_request request;
	struct vmm_dirty_log_result result;

	(void)tc;
	ATF_REQUIRE_EQ(sizeof(request), TEST_SIZE);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_request, version), 0);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_request, operation), 4);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_request, gpa), 8);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_request, output_address),
	    24);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_request, reserved64), 40);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_request, reserved8), 64);
	ATF_REQUIRE_EQ(sizeof(result), TEST_SIZE);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_result, gpa), 8);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_result, identity), 24);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_result, bitmap_offset), 48);
	ATF_REQUIRE_EQ(offsetof(struct vmm_dirty_log_result, reserved8), 64);
}

ATF_TC_WITHOUT_HEAD(constants);
ATF_TC_BODY(constants, tc)
{

	(void)tc;
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_REQUEST_VERSION, TEST_VERSION);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_REQUEST_SIZE, TEST_SIZE);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_RESULT_VERSION, TEST_VERSION);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_RESULT_SIZE, TEST_SIZE);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_REQUEST_ENABLE, 1);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_REQUEST_OBSERVE, 2);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_REQUEST_CLEAR, 3);
	ATF_REQUIRE_EQ(VMM_DIRTY_LOG_REQUEST_DISABLE, 4);
	ATF_REQUIRE_EQ(VM_DIRTY_LOG_REQUEST & 0xff, TEST_IOCTL_NUMBER);
	ATF_REQUIRE_EQ(IOCGROUP(VM_DIRTY_LOG_REQUEST), 'v');
	ATF_REQUIRE_EQ(IOCPARM_LEN(VM_DIRTY_LOG_REQUEST), TEST_SIZE);
	ATF_REQUIRE((VM_DIRTY_LOG_REQUEST & IOC_DIRMASK & IOC_IN) != 0);
	ATF_REQUIRE((VM_DIRTY_LOG_REQUEST & IOC_DIRMASK & IOC_OUT) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, layout);
	ATF_TP_ADD_TC(tp, constants);
	return (atf_no_error());
}
