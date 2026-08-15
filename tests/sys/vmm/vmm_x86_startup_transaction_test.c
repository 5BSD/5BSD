/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_x86_startup_transaction.c"
#include "../../../sys/amd64/vmm/intel/vmx_nested_startup_policy.c"

enum phase {
	PHASE_CAPTURE = 1,
	PHASE_APPLY,
	PHASE_COMMIT_EVENT,
	PHASE_FINALIZE,
	PHASE_ROLLBACK,
};

struct fixture {
	int order[8];
	unsigned int count;
	int capture_error;
	int apply_error;
	int commit_error;
	int rollback_error;
	struct vmm_x86_startup_transaction_input *input;
	struct vmm_x86_startup_transaction_ops *mutable_ops;
	int mutate_input_phase;
	int mutate_ops_phase;
	int check_sipi_input;
};

static void
record(struct fixture *fixture, int phase)
{

	ATF_REQUIRE(fixture->count < nitems(fixture->order));
	fixture->order[fixture->count++] = phase;
	if (fixture->mutate_input_phase == phase)
		fixture->input->reserved32 = 1;
	if (fixture->mutate_ops_phase == phase)
		fixture->mutable_ops->rollback = NULL;
}

static int
capture(void *arg, const struct vmm_x86_startup_transaction_input *input)
{
	struct fixture *fixture = arg;

	ATF_REQUIRE(input->kind == VMM_STARTUP_EVENT_INIT ||
	    input->kind == VMM_STARTUP_EVENT_SIPI);
	if (fixture->check_sipi_input) {
		ATF_CHECK_EQ(input->kind, VMM_STARTUP_EVENT_SIPI);
		ATF_CHECK_EQ(input->vector, 0x5a);
		ATF_CHECK_EQ(input->bootstrap_processor, 0);
	}
	record(fixture, PHASE_CAPTURE);
	return (fixture->capture_error);
}

static int
apply(void *arg)
{
	struct fixture *fixture = arg;

	record(fixture, PHASE_APPLY);
	return (fixture->apply_error);
}

static int
rollback(void *arg)
{
	struct fixture *fixture = arg;

	record(fixture, PHASE_ROLLBACK);
	return (fixture->rollback_error);
}

static int
commit_event(void *arg)
{
	struct fixture *fixture = arg;

	record(fixture, PHASE_COMMIT_EVENT);
	return (fixture->commit_error);
}

static void
finalize(void *arg)
{
	struct fixture *fixture = arg;

	record(fixture, PHASE_FINALIZE);
}

static const struct vmm_x86_startup_transaction_ops ops = {
	.capture = capture,
	.apply = apply,
	.rollback = rollback,
	.commit_event = commit_event,
	.finalize = finalize,
};

static struct vmm_x86_startup_transaction_input
valid_input(void)
{
	struct vmm_x86_startup_transaction_input input;

	memset(&input, 0, sizeof(input));
	input.kind = VMM_STARTUP_EVENT_INIT;
	return (input);
}

static void
check_order(const struct fixture *fixture, const int *expected, size_t count)
{
	size_t i;

	ATF_REQUIRE_EQ(fixture->count, count);
	for (i = 0; i < count; i++)
		ATF_CHECK_EQ(fixture->order[i], expected[i]);
}

ATF_TC_WITHOUT_HEAD(success_commit_order);
ATF_TC_BODY(success_commit_order, tc)
{
	const int expected[] = { PHASE_CAPTURE, PHASE_APPLY,
	    PHASE_COMMIT_EVENT, PHASE_FINALIZE };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	input = valid_input();
	ATF_REQUIRE_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), 0);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.committed, 1);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(result.poisoned, 0);
}

ATF_TC_WITHOUT_HEAD(capture_failure_has_no_rollback);
ATF_TC_BODY(capture_failure_has_no_rollback, tc)
{
	const int expected[] = { PHASE_CAPTURE };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	fixture.capture_error = EBUSY;
	input = valid_input();
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EBUSY);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(result.poisoned, 0);
}

ATF_TC_WITHOUT_HEAD(sipi_input_reaches_capture);
ATF_TC_BODY(sipi_input_reaches_capture, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	memset(&input, 0, sizeof(input));
	input.kind = VMM_STARTUP_EVENT_SIPI;
	input.vector = 0x5a;
	input.bootstrap_processor = 0;
	fixture.check_sipi_input = 1;
	ATF_REQUIRE_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), 0);
	ATF_CHECK_EQ(result.committed, 1);
}

ATF_TC_WITHOUT_HEAD(sipi_rejects_bootstrap_processor);
ATF_TC_BODY(sipi_rejects_bootstrap_processor, tc)
{
	struct vmm_x86_startup_transaction_result before, result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	memset(&result, 0xa5, sizeof(result));
	before = result;
	memset(&input, 0, sizeof(input));
	input.kind = VMM_STARTUP_EVENT_SIPI;
	input.vector = 0x5a;
	input.bootstrap_processor = 1;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EINVAL);
	ATF_CHECK_EQ(fixture.count, 0);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
}

ATF_TC_WITHOUT_HEAD(negative_callback_error_is_protocol_error);
ATF_TC_BODY(negative_callback_error_is_protocol_error, tc)
{
	const int expected[] = { PHASE_CAPTURE };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	fixture.capture_error = -1;
	input = valid_input();
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EPROTO);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(result.poisoned, 0);
}

ATF_TC_WITHOUT_HEAD(apply_failure_rolls_back);
ATF_TC_BODY(apply_failure_rolls_back, tc)
{
	const int expected[] = { PHASE_CAPTURE, PHASE_APPLY, PHASE_ROLLBACK };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	fixture.apply_error = ENOMEM;
	input = valid_input();
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), ENOMEM);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.rollback_complete, 1);
}

ATF_TC_WITHOUT_HEAD(event_race_rolls_back);
ATF_TC_BODY(event_race_rolls_back, tc)
{
	const int expected[] = { PHASE_CAPTURE, PHASE_APPLY,
	    PHASE_COMMIT_EVENT, PHASE_ROLLBACK };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	fixture.commit_error = EAGAIN;
	input = valid_input();
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EAGAIN);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.rollback_complete, 1);
}

ATF_TC_WITHOUT_HEAD(rollback_failure_poisoned);
ATF_TC_BODY(rollback_failure_poisoned, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	fixture.apply_error = EINVAL;
	fixture.rollback_error = EBUSY;
	input = valid_input();
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EIO);
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(result.rollback_complete, 0);
	ATF_CHECK_EQ(result.poisoned, 1);
}

ATF_TC_WITHOUT_HEAD(apply_contract_violation_uses_captured_rollback);
ATF_TC_BODY(apply_contract_violation_uses_captured_rollback, tc)
{
	const int expected[] = { PHASE_CAPTURE, PHASE_APPLY, PHASE_ROLLBACK };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct vmm_x86_startup_transaction_ops mutable_ops;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	input = valid_input();
	mutable_ops = ops;
	fixture.input = &input;
	fixture.mutable_ops = &mutable_ops;
	fixture.mutate_input_phase = PHASE_APPLY;
	fixture.mutate_ops_phase = PHASE_APPLY;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &mutable_ops,
	    &fixture, &result), EIO);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.rollback_complete, 0);
	ATF_CHECK_EQ(result.poisoned, 1);
}

ATF_TC_WITHOUT_HEAD(post_event_violation_does_not_fake_rollback);
ATF_TC_BODY(post_event_violation_does_not_fake_rollback, tc)
{
	const int expected[] = { PHASE_CAPTURE, PHASE_APPLY,
	    PHASE_COMMIT_EVENT };
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	input = valid_input();
	fixture.input = &input;
	fixture.mutate_input_phase = PHASE_COMMIT_EVENT;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EPROTO);
	check_order(&fixture, expected, nitems(expected));
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(result.rollback_complete, 0);
	ATF_CHECK_EQ(result.poisoned, 1);
}

ATF_TC_WITHOUT_HEAD(input_equality_uses_named_fields);
ATF_TC_BODY(input_equality_uses_named_fields, tc)
{
	struct vmm_x86_startup_transaction_input left, right;

	(void)tc;
	memset(&left, 0xa5, sizeof(left));
	memset(&right, 0x5a, sizeof(right));
	left.kind = right.kind = VMM_STARTUP_EVENT_SIPI;
	left.vector = right.vector = 0x63;
	left.bootstrap_processor = right.bootstrap_processor = 0;
	left.reserved8 = right.reserved8 = 0;
	left.reserved32 = right.reserved32 = 0;
	ATF_CHECK(vmm_x86_startup_transaction_input_equal(&left, &right));
	right.vector++;
	ATF_CHECK(!vmm_x86_startup_transaction_input_equal(&left, &right));
}

ATF_TC_WITHOUT_HEAD(rejection_is_failure_atomic);
ATF_TC_BODY(rejection_is_failure_atomic, tc)
{
	struct vmm_x86_startup_transaction_result before, result;
	struct vmm_x86_startup_transaction_input input;
	struct fixture fixture;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	memset(&result, 0xa5, sizeof(result));
	before = result;
	input = valid_input();
	input.reserved32 = 1;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
	ATF_CHECK_EQ(fixture.count, 0);

	input = valid_input();
	ATF_CHECK_EQ(vmm_x86_startup_transaction_execute(&input, &ops,
	    &fixture, (struct vmm_x86_startup_transaction_result *)(void *)&input),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(result_outcome_classification);
ATF_TC_BODY(result_outcome_classification, tc)
{
	static const struct {
		int error;
		uint8_t committed;
		uint8_t rollback_complete;
		uint8_t poisoned;
		enum vmm_x86_startup_transaction_outcome outcome;
	} cases[] = {
		{ 0, 0, 0, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ 0, 0, 0, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ 0, 0, 1, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ 0, 0, 1, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ 0, 1, 0, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ 0, 1, 0, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ 0, 1, 1, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_COMMITTED },
		{ 0, 1, 1, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ EIO, 0, 0, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ EIO, 0, 0, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_POISONED },
		{ EIO, 0, 1, 0,
		    VMM_X86_STARTUP_TRANSACTION_OUTCOME_ROLLED_BACK },
		{ EIO, 0, 1, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_POISONED },
		{ EIO, 1, 0, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ EIO, 1, 0, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ EIO, 1, 1, 0, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
		{ EIO, 1, 1, 1, VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID },
	};
	struct vmm_x86_startup_transaction_result result;
	size_t i;

	(void)tc;
	for (i = 0; i < nitems(cases); i++) {
		memset(&result, 0, sizeof(result));
		result.committed = cases[i].committed;
		result.rollback_complete = cases[i].rollback_complete;
		result.poisoned = cases[i].poisoned;
		ATF_CHECK_EQ_MSG(vmm_x86_startup_transaction_result_classify(
		    cases[i].error, &result), cases[i].outcome, "case %zu", i);
	}

	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(-1, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(EIO, NULL),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);

	memset(&result, 0, sizeof(result));
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(EIO, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	result.committed = 1;
	result.rollback_complete = 1;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(EIO, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	result.committed = 2;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(0, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	result.committed = 1;
	result.rollback_complete = 2;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(0, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	result.rollback_complete = 1;
	result.poisoned = 2;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(0, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	result.poisoned = 0;
	result.reserved8 = 1;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(0, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	result.reserved8 = 0;
	result.committed = 1;
	result.reserved32 = 1;
	ATF_CHECK_EQ(vmm_x86_startup_transaction_result_classify(0, &result),
	    VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
}

ATF_TC_WITHOUT_HEAD(intel_outer_disposition);
ATF_TC_BODY(intel_outer_disposition, tc)
{
	static const struct {
		int error;
		uint8_t committed;
		uint8_t rollback_complete;
		uint8_t poisoned;
		enum vmx_nested_startup_machine_disposition disposition;
	} cases[] = {
		{ 0, 0, 0, 0, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ 0, 0, 0, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ 0, 0, 1, 0, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ 0, 0, 1, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ 0, 1, 0, 0, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ 0, 1, 0, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ 0, 1, 1, 0, VMX_NESTED_STARTUP_MACHINE_COMMITTED },
		{ 0, 1, 1, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 0, 0, 0, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 0, 0, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 0, 1, 0, VMX_NESTED_STARTUP_MACHINE_RETRY },
		{ EIO, 0, 1, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 1, 0, 0, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 1, 0, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 1, 1, 0, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
		{ EIO, 1, 1, 1, VMX_NESTED_STARTUP_MACHINE_FAIL_STOP },
	};
	struct vmm_x86_startup_transaction_result result;
	size_t i;

	(void)tc;
	for (i = 0; i < nitems(cases); i++) {
		memset(&result, 0, sizeof(result));
		result.committed = cases[i].committed;
		result.rollback_complete = cases[i].rollback_complete;
		result.poisoned = cases[i].poisoned;
		ATF_CHECK_EQ_MSG(vmx_nested_startup_machine_disposition(
		    cases[i].error, &result), cases[i].disposition,
		    "case %zu", i);
	}

	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(-1, &result),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(EIO, NULL),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	memset(&result, 0, sizeof(result));
	result.committed = 1;
	result.rollback_complete = 1;
	result.reserved8 = 1;
	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(0, &result),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	result.reserved8 = 0;
	result.reserved32 = 1;
	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(0, &result),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	memset(&result, 0, sizeof(result));
	result.committed = 2;
	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(0, &result),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	memset(&result, 0, sizeof(result));
	result.rollback_complete = 2;
	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(EIO, &result),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
	memset(&result, 0, sizeof(result));
	result.poisoned = 2;
	ATF_CHECK_EQ(vmx_nested_startup_machine_disposition(EIO, &result),
	    VMX_NESTED_STARTUP_MACHINE_FAIL_STOP);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, success_commit_order);
	ATF_TP_ADD_TC(tp, capture_failure_has_no_rollback);
	ATF_TP_ADD_TC(tp, sipi_input_reaches_capture);
	ATF_TP_ADD_TC(tp, sipi_rejects_bootstrap_processor);
	ATF_TP_ADD_TC(tp, negative_callback_error_is_protocol_error);
	ATF_TP_ADD_TC(tp, apply_failure_rolls_back);
	ATF_TP_ADD_TC(tp, event_race_rolls_back);
	ATF_TP_ADD_TC(tp, rollback_failure_poisoned);
	ATF_TP_ADD_TC(tp, apply_contract_violation_uses_captured_rollback);
	ATF_TP_ADD_TC(tp, post_event_violation_does_not_fake_rollback);
	ATF_TP_ADD_TC(tp, input_equality_uses_named_fields);
	ATF_TP_ADD_TC(tp, rejection_is_failure_atomic);
	ATF_TP_ADD_TC(tp, result_outcome_classification);
	ATF_TP_ADD_TC(tp, intel_outer_disposition);
	return (atf_no_error());
}
