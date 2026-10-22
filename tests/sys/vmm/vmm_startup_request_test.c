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

ATF_TC_WITHOUT_HEAD(committed_phase_encoding);
ATF_TC_BODY(committed_phase_encoding, tc)
{
	struct vmm_startup_handshake_status status;
	struct vmm_startup_request output, request;

	(void)tc;
	/*
	 * A COMMITTED handshake pins the kernel as owner with a locked mode
	 * and every expected vCPU (including the bootstrap) accounted for.
	 * Independent oracle: the encoded request must echo those totals and
	 * report the COMMITTED phase with kernel/prestarted encodings.
	 */
	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	memset(&status, 0, sizeof(status));
	vmm_startup_mode_init(&status.mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&status.mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&status.mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&status.mode), 0);
	status.generation = 11;
	status.expected_vcpus = 4;
	status.entered_vcpus = 4;
	status.bootstrap_entered = 1;
	status.phase = VMM_STARTUP_HANDSHAKE_COMMITTED;

	memset(&output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), 0);
	ATF_CHECK_EQ(output.generation, 11);
	ATF_CHECK_EQ(output.expected_vcpus, 4);
	ATF_CHECK_EQ(output.entered_vcpus, 4);
	ATF_CHECK_EQ(output.bootstrap_entered, 1);
	ATF_CHECK_EQ(output.phase, VMM_STARTUP_REQUEST_PHASE_COMMITTED);
	ATF_CHECK_EQ(output.owner, VMM_STARTUP_REQUEST_OWNER_KERNEL);
	ATF_CHECK_EQ(output.execution,
	    VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED);

	/* A COMMITTED phase that is short a vCPU is not internally valid. */
	status.entered_vcpus = 3;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), EINVAL);
	status.entered_vcpus = 4;
	/* Losing the mode lock likewise invalidates a COMMITTED status. */
	status.mode.locked = 0;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 4, &status,
	    &output), EINVAL);
}

ATF_TC_WITHOUT_HEAD(defensive_helpers_reject_bad_values);
ATF_TC_BODY(defensive_helpers_reject_bad_values, tc)
{
	struct vmm_startup_handshake_status status;
	uint8_t execution, owner, phase;
	struct vmm_startup_request scratch;

	(void)tc;
	memset(&scratch, 0, sizeof(scratch));
	/* An empty or NULL range never overlaps anything. */
	ATF_CHECK(!vmm_startup_request_overlap(NULL, 0, &scratch,
	    sizeof(scratch)));
	ATF_CHECK(!vmm_startup_request_overlap(&scratch, 0, &scratch,
	    sizeof(scratch)));
	ATF_CHECK(!vmm_startup_request_overlap(&scratch, sizeof(scratch),
	    NULL, 0));

	/*
	 * The value encoder rejects any enum outside the wire vocabulary.
	 * Spec oracle: out-of-range phase/owner/execution must all map to
	 * EINVAL rather than silently emitting a garbage wire value.
	 */
	memset(&status, 0, sizeof(status));
	vmm_startup_mode_init(&status.mode);
	status.phase = VMM_STARTUP_HANDSHAKE_PHASE_LAST;
	ATF_CHECK_EQ(vmm_startup_request_status_encode_values(&status, &phase,
	    &owner, &execution), EINVAL);

	status.phase = VMM_STARTUP_HANDSHAKE_OPEN;
	status.mode.owner = VMM_STARTUP_OWNER_LAST;
	ATF_CHECK_EQ(vmm_startup_request_status_encode_values(&status, &phase,
	    &owner, &execution), EINVAL);

	status.mode.owner = VMM_STARTUP_OWNER_USERSPACE;
	status.mode.execution = VMM_STARTUP_EXECUTION_LAST;
	ATF_CHECK_EQ(vmm_startup_request_status_encode_values(&status, &phase,
	    &owner, &execution), EINVAL);
}

ATF_TC_WITHOUT_HEAD(status_state_space);
ATF_TC_BODY(status_state_space, tc)
{
	struct vmm_startup_handshake_status status, saved_status;
	struct vmm_startup_request request, saved_request, output, expected;
	unsigned sample, value, phase, owner, execution, locked, total, entered, bsp;
	bool valid;

	(void)tc;
	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	saved_request = request;
	/* Enumerate the small protocol state space, including invalid enums. */
	for (sample = 0; sample < 4860; sample++) {
		value = sample;
		phase = value % 5; value /= 5;
		owner = value % 3; value /= 3;
		execution = value % 3; value /= 3;
		locked = value % 3; value /= 3;
		total = value % 3; value /= 3;
		entered = value % 4; value /= 4;
		bsp = value % 3;
		/* The wire contract admits only these three state families. */
		valid = (phase == 0 && owner == 0 && execution == 0 &&
		    locked == 0 && total == 0 && entered == 0 && bsp == 0) ||
		    (phase == 1 && owner == 1 && execution == 1 &&
		    locked == 0 && total > 0 && entered <= total &&
		    bsp <= 1 && bsp <= entered) ||
		    (phase == 2 && owner == 1 && execution == 1 &&
		    locked == 1 && total > 0 && entered == total && bsp == 1);
		memset(&status, 0, sizeof(status));
		status.generation = 17;
		status.phase = phase;
		status.mode.owner = owner;
		status.mode.execution = execution;
		status.mode.locked = locked;
		status.expected_vcpus = total;
		status.entered_vcpus = entered;
		status.bootstrap_entered = bsp;
		saved_status = status;
		memset(&output, 0xa5, sizeof(output));
		expected = output;
		if (valid) {
			expected = request;
			expected.generation = 17;
			expected.expected_vcpus = total;
			expected.entered_vcpus = entered;
			expected.bootstrap_entered = bsp;
			expected.phase = phase;
			expected.owner = owner;
			expected.execution = execution;
		}
		ATF_REQUIRE_EQ_MSG(vmm_startup_request_encode_status(&request, 2,
		    &status, &output), valid ? 0 : EINVAL, "sample %u", sample);
		ATF_CHECK_EQ(memcmp(&output, &expected, sizeof(output)), 0);
		ATF_CHECK_EQ(memcmp(&status, &saved_status, sizeof(status)), 0);
		ATF_CHECK_EQ(memcmp(&request, &saved_request, sizeof(request)), 0);
	}
}

ATF_TC_WITHOUT_HEAD(header_and_status_fault_fields);
ATF_TC_BODY(header_and_status_fault_fields, tc)
{
	struct vmm_startup_handshake_status status;
	struct vmm_startup_request request, output, before;
	unsigned i;

	(void)tc;
	memset(&status, 0, sizeof(status));
	status.generation = 1;
	memset(&output, 0xa5, sizeof(output));
	before = output;
	for (i = 0; i < 5; i++) {
		request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
		switch (i) {
		case 0: request.size++; break;
		case 1: request.phase = 1; break;
		case 2: request.owner = 1; break;
		case 3: request.execution = 1; break;
		case 4: request.generation = 1; break;
		}
		ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 2,
		    &status, &output), EINVAL);
		ATF_CHECK_EQ(memcmp(&output, &before, sizeof(output)), 0);
	}
	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	for (i = 0; i < 5; i++) {
		memset(&status, 0, sizeof(status));
		status.generation = 1;
		switch (i) {
		case 0: status.generation = 0; break;
		case 1: status.reserved16 = 1; break;
		case 2: status.reserved32 = 1; break;
		case 3: status.mode.reserved8 = 1; break;
		case 4: status.mode.reserved32 = 1; break;
		}
		ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 2,
		    &status, &output), EINVAL);
		ATF_CHECK_EQ(memcmp(&output, &before, sizeof(output)), 0);
	}
	ATF_CHECK_EQ(vmm_startup_request_validate(NULL, 2), EINVAL);
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 0), EINVAL);
	ATF_CHECK_EQ(vmm_startup_request_encode_status(NULL, 2, &status,
	    &output), EINVAL);
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 2, &status,
	    NULL), EINVAL);
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 2, NULL,
	    &output), EINVAL);
	ATF_CHECK_EQ(memcmp(&output, &before, sizeof(output)), 0);
}

ATF_TC_WITHOUT_HEAD(limits_and_status_output_alias);
ATF_TC_BODY(limits_and_status_output_alias, tc)
{
	union {
		struct vmm_startup_handshake_status status;
		struct vmm_startup_request output;
	} overlap, saved;
	struct vmm_startup_request request, output, before;

	(void)tc;
	request = request_fixture(VMM_STARTUP_REQUEST_CONFIGURE);
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 2), EINVAL);
	request = request_fixture(VMM_STARTUP_REQUEST_WAIT_READY);
	request.generation = 1;
	request.expected_vcpus = 1;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 2), EINVAL);
	request.operation = VMM_STARTUP_REQUEST_COMMIT;
	ATF_CHECK_EQ(vmm_startup_request_validate(&request, 2), EINVAL);
	request = request_fixture(VMM_STARTUP_REQUEST_STATUS);
	memset(&overlap, 0, sizeof(overlap));
	overlap.status.generation = 1;
	saved = overlap;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 2,
	    &overlap.status, &overlap.output), EINVAL);
	ATF_CHECK_EQ(memcmp(&overlap, &saved, sizeof(overlap)), 0);
	overlap.status.phase = VMM_STARTUP_HANDSHAKE_COLLECTING;
	overlap.status.mode.owner = VMM_STARTUP_OWNER_KERNEL;
	overlap.status.mode.execution = VMM_STARTUP_EXECUTION_PRESTARTED_WAIT;
	overlap.status.expected_vcpus = 3;
	memset(&output, 0xa5, sizeof(output));
	before = output;
	ATF_CHECK_EQ(vmm_startup_request_encode_status(&request, 2,
	    &overlap.status, &output), EINVAL);
	ATF_CHECK_EQ(memcmp(&output, &before, sizeof(output)), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, layout_and_closed_operations);
	ATF_TP_ADD_TC(tp, operation_specific_inputs);
	ATF_TP_ADD_TC(tp, reserved_and_output_fields_rejected);
	ATF_TP_ADD_TC(tp, status_encoding_is_failure_atomic);
	ATF_TP_ADD_TC(tp, committed_phase_encoding);
	ATF_TP_ADD_TC(tp, defensive_helpers_reject_bad_values);
	ATF_TP_ADD_TC(tp, status_state_space);
	ATF_TP_ADD_TC(tp, header_and_status_fault_fields);
	ATF_TP_ADD_TC(tp, limits_and_status_output_alias);
	return (atf_no_error());
}
