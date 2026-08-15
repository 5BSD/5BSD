/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../../sys/dev/vmm/vmm_startup_run_request.c"

#define	TEST_VERSION		UINT16_C(1)
#define	TEST_SIZE		UINT16_C(64)
#define	TEST_MAX_VCPUS		UINT32_C(64)
#define	TEST_CPUSET_SIZE	UINT64_C(128)
#define	TEST_EXIT_SIZE		UINT64_C(256)
#define	TEST_ADDRESS_MAX_64	UINT64_MAX
#define	TEST_ADDRESS_MAX_32	UINT64_C(0xffffffff)

static struct vmm_startup_run_request
valid_request(void)
{
	struct vmm_startup_run_request request;

	memset(&request, 0, sizeof(request));
	request.version = TEST_VERSION;
	request.size = TEST_SIZE;
	request.vcpuid = 7;
	request.generation = UINT64_C(19);
	request.cpuset_address = UINT64_C(0x10000);
	request.cpuset_size = TEST_CPUSET_SIZE;
	request.exit_address = UINT64_C(0x20000);
	request.exit_size = TEST_EXIT_SIZE;
	return (request);
}

ATF_TC_WITHOUT_HEAD(layout_is_fixed_width);
ATF_TC_BODY(layout_is_fixed_width, tc)
{
	struct vmm_startup_run_request request;

	ATF_REQUIRE_EQ(sizeof(request), TEST_SIZE);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, vcpuid), 0);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, version), 4);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, flags), 8);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, generation), 16);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, cpuset_address),
	    24);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, exit_address),
	    40);
	ATF_REQUIRE_EQ(offsetof(struct vmm_startup_run_request, reserved8), 56);
}

ATF_TC_WITHOUT_HEAD(version_flags_and_reserved_are_closed);
ATF_TC_BODY(version_flags_and_reserved_are_closed, tc)
{
	struct vmm_startup_run_request request;

	request = valid_request();
	ATF_REQUIRE_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), 0);
	request.version++;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.size--;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.flags = 1;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.reserved8[7] = 1;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
}

ATF_TC_WITHOUT_HEAD(generation_vcpu_and_sizes_are_exact);
ATF_TC_BODY(generation_vcpu_and_sizes_are_exact, tc)
{
	struct vmm_startup_run_request request;

	request = valid_request();
	request.generation = 0;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.vcpuid = -1;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.vcpuid = TEST_MAX_VCPUS;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.cpuset_size = TEST_CPUSET_SIZE + 1;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.exit_size--;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
}

ATF_TC_WITHOUT_HEAD(address_ranges_cover_32_and_64_bit_callers);
ATF_TC_BODY(address_ranges_cover_32_and_64_bit_callers, tc)
{
	struct vmm_startup_run_request request;

	request = valid_request();
	ATF_REQUIRE_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_32), 0);
	request.cpuset_address = TEST_ADDRESS_MAX_32 -
	    TEST_CPUSET_SIZE + 1;
	ATF_REQUIRE_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_32), 0);
	request.cpuset_address++;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_32), EINVAL);
	request = valid_request();
	request.exit_address = UINT64_MAX - TEST_EXIT_SIZE + 1;
	ATF_REQUIRE_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), 0);
	request.exit_address++;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.cpuset_address = 0;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
	request = valid_request();
	request.exit_address = request.cpuset_address + request.cpuset_size;
	ATF_REQUIRE_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), 0);
	request.exit_address--;
	ATF_CHECK_EQ(vmm_startup_run_request_validate(&request,
	    TEST_MAX_VCPUS, TEST_CPUSET_SIZE, TEST_EXIT_SIZE,
	    TEST_ADDRESS_MAX_64), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, layout_is_fixed_width);
	ATF_TP_ADD_TC(tp, version_flags_and_reserved_are_closed);
	ATF_TP_ADD_TC(tp, generation_vcpu_and_sizes_are_exact);
	ATF_TP_ADD_TC(tp, address_ranges_cover_32_and_64_bit_callers);
	return (atf_no_error());
}
