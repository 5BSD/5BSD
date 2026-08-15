/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_intinfo.c"
#include "../../../sys/amd64/vmm/vmm_event_state.c"

#define	TEST_GP	13U
#define	TEST_PF	14U

ATF_TC_WITHOUT_HEAD(canonical_values);
ATF_TC_BODY(canonical_values, tc)
{
	struct vmm_event_state state;
	uint64_t intinfo;

	(void)tc;
	memset(&state, 0, sizeof(state));
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);
	ATF_REQUIRE_EQ(vmm_event_state_exception_intinfo(&state, &intinfo),
	    0);
	ATF_CHECK_EQ(intinfo, 0);

	state.flags = VMM_EVENT_STATE_F_NMI_PENDING |
	    VMM_EVENT_STATE_F_EXTINT_PENDING;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);

	state.flags |= VMM_EVENT_STATE_F_EXCEPTION_PENDING |
	    VMM_EVENT_STATE_F_EXCEPTION_ERROR;
	state.exception_vector = TEST_PF;
	state.exception_error = UINT32_C(0x1234);
	state.exception_class = VMM_EVENT_EXCEPTION_FAULT;
	ATF_REQUIRE_EQ(vmm_event_state_exception_intinfo(&state, &intinfo),
	    0);
	ATF_CHECK_EQ(intinfo, VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION |
	    VM_INTINFO_DEL_ERRCODE | TEST_PF |
	    (UINT64_C(0x1234) << 32));
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);

	/* Real-mode injection can legitimately suppress an error code. */
	state.flags &= ~VMM_EVENT_STATE_F_EXCEPTION_ERROR;
	state.exception_vector = TEST_GP;
	state.exception_error = 0;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);
}

ATF_TC_WITHOUT_HEAD(rejects_noncanonical_values);
ATF_TC_BODY(rejects_noncanonical_values, tc)
{
	struct vmm_event_state state;
	uint64_t before, intinfo;

	(void)tc;
	memset(&state, 0, sizeof(state));
	state.flags = UINT32_C(0x10);
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);

	state.flags = VMM_EVENT_STATE_F_EXCEPTION_ERROR;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.flags = VMM_EVENT_STATE_F_EXCEPTION_PENDING;
	state.exception_vector = 32;
	state.exception_class = VMM_EVENT_EXCEPTION_FAULT;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_vector = 8;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_vector = TEST_GP;
	state.exception_error = 1;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_error = 0;
	state.exception_class = VMM_EVENT_EXCEPTION_NONE;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_class = VMM_EVENT_EXCEPTION_CLASS_LAST;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_class = VMM_EVENT_EXCEPTION_ICEBP;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_vector = 1;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);

	state.flags = 0;
	state.exception_vector = TEST_GP;
	state.exception_class = VMM_EVENT_EXCEPTION_NONE;
	state.exception_error = 0;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exception_vector = 0;
	state.exitintinfo = 1;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);
	state.exitintinfo = VM_INTINFO_VALID | VM_INTINFO_NMI | 3;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), EINVAL);

	before = UINT64_C(0xa5a5a5a5a5a5a5a5);
	intinfo = before;
	ATF_CHECK_EQ(vmm_event_state_exception_intinfo(NULL, &intinfo),
	    EINVAL);
	ATF_CHECK_EQ(intinfo, before);
	ATF_CHECK_EQ(vmm_event_state_exception_intinfo(&state, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_event_state_validate(NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(folding_is_validated);
ATF_TC_BODY(folding_is_validated, tc)
{
	struct vmm_event_state state;

	(void)tc;
	memset(&state, 0, sizeof(state));
	state.flags = VMM_EVENT_STATE_F_EXCEPTION_PENDING |
	    VMM_EVENT_STATE_F_EXCEPTION_ERROR;
	state.exception_vector = TEST_GP;
	state.exception_error = 7;
	state.exception_class = VMM_EVENT_EXCEPTION_FAULT;
	state.exitintinfo = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION |
	    VM_INTINFO_DEL_ERRCODE | TEST_PF | (UINT64_C(9) << 32);
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);

	/* A reinjected double fault plus a new exception is a valid shutdown. */
	state.exitintinfo = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION |
	    VM_INTINFO_DEL_ERRCODE | 8;
	ATF_CHECK_EQ(vmm_event_state_validate(&state), 0);
}

ATF_TC_WITHOUT_HEAD(all_vcpu_capture_generation);
ATF_TC_BODY(all_vcpu_capture_generation, tc)
{

	(void)tc;
	ATF_CHECK_EQ(vmm_event_capture_commit_validate(7, 7, 4, 4), 0);
	ATF_CHECK_EQ(vmm_event_capture_commit_validate(7, 8, 4, 4), EAGAIN);
	ATF_CHECK_EQ(vmm_event_capture_commit_validate(7, 7, 4, 3), EINVAL);
	ATF_CHECK_EQ(vmm_event_capture_commit_validate(UINT64_MAX, 0, 4, 4),
	    EAGAIN);
}

ATF_TC_WITHOUT_HEAD(capture_output_ranges);
ATF_TC_BODY(capture_output_ranges, tc)
{
	uint8_t bytes[16];
	const void *wrapping;

	(void)tc;
	wrapping = (const void *)(uintptr_t)(UINTPTR_MAX - 1);
	ATF_CHECK(vmm_event_range_valid(NULL, 0));
	ATF_CHECK(!vmm_event_range_valid(NULL, 1));
	ATF_CHECK(vmm_event_range_valid(bytes, sizeof(bytes)));
	ATF_CHECK(!vmm_event_range_valid(wrapping, 3));
	ATF_CHECK(!vmm_event_ranges_overlap(bytes, 0, bytes, sizeof(bytes)));
	/* Alias guards reject an invalid non-empty range conservatively. */
	ATF_CHECK(vmm_event_ranges_overlap(wrapping, 3, bytes, 1));
	ATF_CHECK(vmm_event_ranges_overlap(bytes, 1, NULL, 1));
	ATF_CHECK(vmm_event_ranges_overlap(bytes, 8, bytes + 7, 1));
	ATF_CHECK(!vmm_event_ranges_overlap(bytes, 8, bytes + 8, 8));
	ATF_CHECK(vmm_event_ranges_overlap(bytes + 7, 1, bytes, 8));
}

ATF_TC_WITHOUT_HEAD(named_equality_ignores_padding);
ATF_TC_BODY(named_equality_ignores_padding, tc)
{
	struct vmm_event_state left, right;

	(void)tc;
	memset(&left, 0xa5, sizeof(left));
	memset(&right, 0x5a, sizeof(right));
	left.flags = right.flags = VMM_EVENT_STATE_F_NMI_PENDING;
	left.exitintinfo = right.exitintinfo = 0;
	left.exception_vector = right.exception_vector = 0;
	left.exception_error = right.exception_error = 0;
	left.exception_class = right.exception_class =
	    VMM_EVENT_EXCEPTION_NONE;
	ATF_CHECK(vmm_event_state_equal(&left, &right));
	right.flags |= VMM_EVENT_STATE_F_EXTINT_PENDING;
	ATF_CHECK(!vmm_event_state_equal(&left, &right));
	right.flags = left.flags;
	right.exitintinfo = 1;
	ATF_CHECK(!vmm_event_state_equal(&left, &right));
	right.exitintinfo = left.exitintinfo;
	right.exception_vector = 1;
	ATF_CHECK(!vmm_event_state_equal(&left, &right));
	right.exception_vector = left.exception_vector;
	right.exception_error = 1;
	ATF_CHECK(!vmm_event_state_equal(&left, &right));
	right.exception_error = left.exception_error;
	right.exception_class = VMM_EVENT_EXCEPTION_FAULT;
	ATF_CHECK(!vmm_event_state_equal(&left, &right));
	ATF_CHECK(!vmm_event_state_equal(NULL, &right));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, canonical_values);
	ATF_TP_ADD_TC(tp, rejects_noncanonical_values);
	ATF_TP_ADD_TC(tp, folding_is_validated);
	ATF_TP_ADD_TC(tp, all_vcpu_capture_generation);
	ATF_TP_ADD_TC(tp, capture_output_ranges);
	ATF_TP_ADD_TC(tp, named_equality_ignores_padding);
	return (atf_no_error());
}
