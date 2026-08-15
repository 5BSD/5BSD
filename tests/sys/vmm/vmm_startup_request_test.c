/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_startup_mode.c"
#include "../../../sys/dev/vmm/vmm_startup_request.c"

#define	TEST_VERSION	UINT16_C(1)
#define	TEST_SIZE	UINT16_C(48)

static struct vmm_startup_request
request_fixture(uint16_t operation)
{
	struct vmm_startup_request request;

	memset(&request, 0, sizeof(request));
	request.version = TEST_VERSION;
	request.size = TEST_SIZE;
	request.operation = operation;
	return (request);
}

ATF_TC_WITHOUT_HEAD(layout_and_closed_operations);
ATF_TC_BODY(layout_and_closed_operations, tc)
{
	struct vmm_startup_request request;

	(void)tc;
	ATF_CHECK_EQ(sizeof(request), TEST_SIZE);
	request = request_fixture(0);
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 8), EINVAL);
	request.operation = 5;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 8), EINVAL);
	request.operation = VMM_STARTUP_REQUEST_STATUS;
	ATF_REQUIRE_EQ(vmm_startup_request_validate(&request, 8), 0);
	request.version++;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 8), EINVAL);
}

ATF_TC_WITHOUT_HEAD(operation_specific_inputs);
ATF_TC_BODY(operation_specific_inputs, tc)
{
	struct vmm_startup_request request;

	(void)tc;
	request = request_fixture(VMM_STARTUP_REQUEST_CONFIGURE);
	request.expected_vcpus = 4;
	ATF_REQUIRE_EQ(vmm_startup_request_validate(&request, 4), 0);
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 3), EINVAL);
	request.expected_vcpus = UINT32_C(65536);
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, UINT32_MAX),
	    EINVAL);
	request.expected_vcpus = 4;
	request.generation = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);

	request = request_fixture(VMM_STARTUP_REQUEST_WAIT_READY);
	request.generation = 7;
	ATF_REQUIRE_EQ(vmm_startup_request_validate(&request, 4), 0);
	request.operation = VMM_STARTUP_REQUEST_COMMIT;
	ATF_REQUIRE_EQ(vmm_startup_request_validate(&request, 4), 0);
	request.generation = 0;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);

	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	ATF_REQUIRE_EQ(vmm_startup_request_validate(&request, 4), 0);
	request.expected_vcpus = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);
}

ATF_TC_WITHOUT_HEAD(reserved_and_output_fields_rejected);
ATF_TC_BODY(reserved_and_output_fields_rejected, tc)
{
	struct vmm_startup_request request;

	(void)tc;
	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	request.flags = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);
	request.flags = 0;
	request.entered_vcpus = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);
	request.entered_vcpus = 0;
	request.bootstrap_entered = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);
	request.bootstrap_entered = 0;
	request.reserved8[19] = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 4), EINVAL);
}

ATF_TC_WITHOUT_HEAD(status_encoding_is_failure_atomic);
ATF_TC_BODY(status_encoding_is_failure_atomic, tc)
{
	union {
		uint64_t align;
		uint8_t bytes[96];
	} overlap;
	struct vmm_startup_handshake_status status;
	struct vmm_startup_request *overlap_output, *overlap_request;
	struct vmm_startup_request before, output, request;

	(void)tc;
	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	memset(&status, 0, sizeof(status));
	vmm_startup_mode_init(&status.mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&status.mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&status.mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	status.generation = 9;
	status.expected_vcpus = 4;
	status.entered_vcpus = 3;
	status.bootstrap_entered = 1;
	status.phase = VMM_STARTUP_HANDSHAKE_COLLECTING;
	memset(&output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), 0);
	ATF_CHECK_EQ(output.version, TEST_VERSION);
	ATF_CHECK_EQ(output.size, TEST_SIZE);
	ATF_CHECK_EQ(output.generation, 9);
	ATF_CHECK_EQ(output.expected_vcpus, 4);
	ATF_CHECK_EQ(output.entered_vcpus, 3);
	ATF_CHECK_EQ(output.owner, VMM_STARTUP_REQUEST_OWNER_KERNEL);
	ATF_CHECK_EQ(output.execution,
	    VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED);

	before = output;
	status.entered_vcpus = 5;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), EINVAL);
	ATF_CHECK(memcmp(&output, &before, sizeof(output)) == 0);

	status.entered_vcpus = 3;
	ATF_REQUIRE_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &request), 0);
	ATF_CHECK_EQ(request.generation, 9);

	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	memset(&status, 0, sizeof(status));
	vmm_startup_mode_init(&status.mode);
	status.generation = 10;
	status.phase = VMM_STARTUP_HANDSHAKE_OPEN;
	ATF_REQUIRE_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), 0);
	ATF_CHECK_EQ(output.expected_vcpus, 0);
	ATF_CHECK_EQ(output.phase, VMM_STARTUP_REQUEST_PHASE_OPEN);
	before = output;
	status.mode.locked = 1;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), EINVAL);
	ATF_CHECK(memcmp(&output, &before, sizeof(output)) == 0);

	status.mode.locked = 0;
	memset(&overlap, 0, sizeof(overlap));
	overlap_request = (struct vmm_startup_request *)(void *)&overlap.bytes[0];
	overlap_output = (struct vmm_startup_request *)(void *)&overlap.bytes[8];
	*overlap_request = request;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(overlap_request, 4,
	    &status, overlap_output), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, layout_and_closed_operations);
	ATF_TP_ADD_TC(tp, operation_specific_inputs);
	ATF_TP_ADD_TC(tp, reserved_and_output_fields_rejected);
	ATF_TP_ADD_TC(tp, status_encoding_is_failure_atomic);
	return (atf_no_error());
}
