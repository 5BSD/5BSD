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

#define	INTINFO_DF_ENTRY	(IDT_DF | VM_INTINFO_VALID | \
	VM_INTINFO_HWEXCEPTION | VM_INTINFO_DEL_ERRCODE)

static struct vm_intinfo_plan
fold(uint64_t info1, uint64_t info2)
{
	struct vm_intinfo_plan plan;

	memset(&plan, 0x5a, sizeof(plan));
	ATF_REQUIRE_EQ(vm_intinfo_plan(info1, info2, &plan), 0);
	return (plan);
}

ATF_TC_WITHOUT_HEAD(intinfo_plan_rejects_bad_inputs);
ATF_TC_BODY(intinfo_plan_rejects_bad_inputs, tc)
{
	struct vm_intinfo_plan plan;

	(void)tc;
	/* A NULL result pointer is rejected before any work. */
	ATF_CHECK_EQ(vm_intinfo_plan(0, 0, NULL), EINVAL);

	/*
	 * An error code occupying the high dword requires the DEL_ERRCODE flag;
	 * without it the encoding is malformed.  (Intel SDM: the error code is
	 * only meaningful for exceptions that deliver one.)
	 */
	memset(&plan, 0, sizeof(plan));
	ATF_CHECK_EQ(vm_intinfo_plan(VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION |
	    IDT_GP | (UINT64_C(1) << 32), 0, &plan), EINVAL);
	/* Any reserved bit set is rejected. */
	ATF_CHECK_EQ(vm_intinfo_plan(VM_INTINFO_VALID | VM_INTINFO_RSVD, 0,
	    &plan), EINVAL);
	/* A malformed second event is rejected just like the first. */
	ATF_CHECK_EQ(vm_intinfo_plan(VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION |
	    IDT_GP, VM_INTINFO_VALID | VM_INTINFO_RSVD, &plan), EINVAL);
}

ATF_TC_WITHOUT_HEAD(intinfo_plan_single_event);
ATF_TC_BODY(intinfo_plan_single_event, tc)
{
	struct vm_intinfo_plan plan;
	uint64_t info1;

	(void)tc;
	/* Only the first event valid: it is delivered unchanged. */
	info1 = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_GP;
	plan = fold(info1, 0);
	ATF_CHECK(plan.valid);
	ATF_CHECK(!plan.triple_fault);
	ATF_CHECK_EQ(plan.entry, info1);

	/* Neither event valid: nothing to deliver. */
	plan = fold(0, 0);
	ATF_CHECK(!plan.valid);
	ATF_CHECK(!plan.triple_fault);
	ATF_CHECK_EQ(plan.entry, 0);
}

ATF_TC_WITHOUT_HEAD(intinfo_plan_benign_delivers_second);
ATF_TC_BODY(intinfo_plan_benign_delivers_second, tc)
{
	struct vm_intinfo_plan plan;
	uint64_t benign[3], second;
	unsigned int i;

	(void)tc;
	/*
	 * Intel SDM, Table 6-4: external interrupts, NMIs and software
	 * interrupts are benign regardless of vector, so folding any of them
	 * ahead of a second event simply delivers the second event.
	 */
	benign[0] = VM_INTINFO_VALID | VM_INTINFO_HWINTR | 0x21;
	benign[1] = VM_INTINFO_VALID | VM_INTINFO_SWINTR | 0x80;
	benign[2] = VM_INTINFO_VALID | VM_INTINFO_NMI | IDT_NMI;
	second = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_GP;
	for (i = 0; i < 3; i++) {
		plan = fold(benign[i], second);
		ATF_CHECK(plan.valid);
		ATF_CHECK(!plan.triple_fault);
		ATF_CHECK_EQ(plan.entry, second);
	}

	/* A benign hardware exception vector (e.g. #UD) is also benign. */
	plan = fold(VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | 6, second);
	ATF_CHECK(plan.valid);
	ATF_CHECK(!plan.triple_fault);
	ATF_CHECK_EQ(plan.entry, second);
}

ATF_TC_WITHOUT_HEAD(intinfo_plan_double_fault_generation);
ATF_TC_BODY(intinfo_plan_double_fault_generation, tc)
{
	struct vm_intinfo_plan plan;
	uint64_t contributory[5];
	uint64_t pf, second;
	unsigned int i;

	(void)tc;
	/*
	 * Intel SDM, Table 6-5: two contributory exceptions fold into a
	 * double fault.  Each contributory vector (#DE, #TS, #NP, #SS, #GP)
	 * must be recognized.
	 */
	contributory[0] = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_DE;
	contributory[1] = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_TS;
	contributory[2] = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_NP;
	contributory[3] = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_SS;
	contributory[4] = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_GP;
	second = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_GP;
	for (i = 0; i < 5; i++) {
		plan = fold(contributory[i], second);
		ATF_CHECK(plan.valid);
		ATF_CHECK(!plan.triple_fault);
		ATF_CHECK_EQ(plan.entry, INTINFO_DF_ENTRY);
	}

	/* Page fault followed by a contributory exception also folds to #DF. */
	pf = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | IDT_PF;
	plan = fold(pf, second);
	ATF_CHECK(plan.valid);
	ATF_CHECK(!plan.triple_fault);
	ATF_CHECK_EQ(plan.entry, INTINFO_DF_ENTRY);

	/* Page fault followed by a benign exception delivers the second. */
	plan = fold(pf, VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | 6);
	ATF_CHECK(plan.valid);
	ATF_CHECK_EQ(plan.entry, VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION | 6);

	/* An exception while delivering #DF triggers shutdown (triple fault). */
	plan = fold(INTINFO_DF_ENTRY, second);
	ATF_CHECK(!plan.valid);
	ATF_CHECK(plan.triple_fault);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, canonical_values);
	ATF_TP_ADD_TC(tp, rejects_noncanonical_values);
	ATF_TP_ADD_TC(tp, folding_is_validated);
	ATF_TP_ADD_TC(tp, all_vcpu_capture_generation);
	ATF_TP_ADD_TC(tp, capture_output_ranges);
	ATF_TP_ADD_TC(tp, named_equality_ignores_padding);
	ATF_TP_ADD_TC(tp, intinfo_plan_rejects_bad_inputs);
	ATF_TP_ADD_TC(tp, intinfo_plan_single_event);
	ATF_TP_ADD_TC(tp, intinfo_plan_benign_delivers_second);
	ATF_TP_ADD_TC(tp, intinfo_plan_double_fault_generation);
	return (atf_no_error());
}
