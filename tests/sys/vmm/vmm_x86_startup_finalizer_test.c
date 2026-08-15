/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_x86_startup_finalizer.c"

enum finalizer_step {
	STEP_NESTED = 1,
	STEP_LAPIC,
	STEP_RESIDENCY,
	STEP_NEXTRIP,
	STEP_WAIT,
};

struct finalizer_fixture {
	uint8_t step[8];
	size_t count;
	uint64_t nextrip;
	bool wait;
};

static void
record(struct finalizer_fixture *fixture, enum finalizer_step step)
{

	ATF_REQUIRE(fixture->count < nitems(fixture->step));
	fixture->step[fixture->count++] = step;
}

static void
reset_nested(void *arg)
{
	record(arg, STEP_NESTED);
}

static void
reset_lapic(void *arg)
{
	record(arg, STEP_LAPIC);
}

static void
retire_translation_residency(void *arg)
{
	record(arg, STEP_RESIDENCY);
}

static void
set_nextrip(void *arg, uint64_t nextrip)
{
	struct finalizer_fixture *fixture = arg;

	record(fixture, STEP_NEXTRIP);
	fixture->nextrip = nextrip;
}

static void
publish_wait(void *arg, bool wait)
{
	struct finalizer_fixture *fixture = arg;

	record(fixture, STEP_WAIT);
	fixture->wait = wait;
}

static const struct vmm_x86_startup_finalizer_ops finalizer_ops = {
	.reset_nested = reset_nested,
	.reset_lapic = reset_lapic,
	.retire_translation_residency = retire_translation_residency,
	.set_nextrip = set_nextrip,
	.publish_startup_wait = publish_wait,
};

static void
run_plan(const struct vmm_x86_startup_transaction_input *input,
    struct finalizer_fixture *fixture)
{
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_plan plan;

	memset(&finalizer, 0, sizeof(finalizer));
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(input, &plan), 0);
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, fixture,
	    &plan, &finalizer), 0);
	ATF_CHECK(!vmm_x86_startup_finalizer_consumed(&finalizer));
	vmm_x86_startup_finalizer_commit(&finalizer);
	ATF_CHECK(vmm_x86_startup_finalizer_consumed(&finalizer));
}

ATF_TC_WITHOUT_HEAD(init_ap_order);
ATF_TC_BODY(init_ap_order, tc)
{
	const struct vmm_x86_startup_transaction_input input = {
		.kind = VMM_STARTUP_EVENT_INIT,
	};
	struct finalizer_fixture fixture;
	const uint8_t expected[] = {
		STEP_NESTED, STEP_LAPIC, STEP_RESIDENCY, STEP_NEXTRIP, STEP_WAIT,
	};

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	run_plan(&input, &fixture);
	ATF_CHECK_EQ(fixture.count, nitems(expected));
	ATF_CHECK_EQ(memcmp(fixture.step, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(fixture.nextrip, UINT64_C(0xfff0));
	ATF_CHECK(fixture.wait);
}

ATF_TC_WITHOUT_HEAD(init_bsp_remains_runnable);
ATF_TC_BODY(init_bsp_remains_runnable, tc)
{
	const struct vmm_x86_startup_transaction_input input = {
		.kind = VMM_STARTUP_EVENT_INIT,
		.bootstrap_processor = 1,
	};
	struct finalizer_fixture fixture;
	const uint8_t expected[] = {
		STEP_NESTED, STEP_LAPIC, STEP_RESIDENCY, STEP_NEXTRIP, STEP_WAIT,
	};

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	run_plan(&input, &fixture);
	ATF_CHECK_EQ(fixture.count, nitems(expected));
	ATF_CHECK_EQ(memcmp(fixture.step, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(fixture.nextrip, UINT64_C(0xfff0));
	ATF_CHECK(!fixture.wait);
}

ATF_TC_WITHOUT_HEAD(sipi_changes_only_nextrip_and_wait);
ATF_TC_BODY(sipi_changes_only_nextrip_and_wait, tc)
{
	const struct vmm_x86_startup_transaction_input input = {
		.kind = VMM_STARTUP_EVENT_SIPI,
		.vector = 0xa5,
	};
	struct finalizer_fixture fixture;
	const uint8_t expected[] = { STEP_NEXTRIP, STEP_WAIT };

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	run_plan(&input, &fixture);
	ATF_CHECK_EQ(fixture.count, nitems(expected));
	ATF_CHECK_EQ(memcmp(fixture.step, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(fixture.nextrip, UINT64_C(0xa5) << 12);
	ATF_CHECK(!fixture.wait);
}

ATF_TC_WITHOUT_HEAD(sipi_plan_binds_vector_and_entrypoint);
ATF_TC_BODY(sipi_plan_binds_vector_and_entrypoint, tc)
{
	const struct vmm_x86_startup_transaction_input input = {
		.kind = VMM_STARTUP_EVENT_SIPI,
		.vector = 0x44,
	};
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_plan plan;
	struct finalizer_fixture fixture;

	(void)tc;
	memset(&plan, 0, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), 0);
	ATF_CHECK_EQ(plan.kind, VMM_STARTUP_EVENT_SIPI);
	ATF_CHECK_EQ(plan.vector, input.vector);
	ATF_CHECK_EQ(plan.nextrip, UINT64_C(0x44) << 12);
	memset(&fixture, 0, sizeof(fixture));
	memset(&finalizer, 0, sizeof(finalizer));
	plan.vector++;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, &fixture,
	    &plan, &finalizer), EINVAL);
	ATF_CHECK(vmm_x86_startup_finalizer_consumed(&finalizer));
	plan.vector--;
	plan.nextrip++;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, &fixture,
	    &plan, &finalizer), EINVAL);
	ATF_CHECK(vmm_x86_startup_finalizer_consumed(&finalizer));
}

ATF_TC_WITHOUT_HEAD(rejection_is_failure_atomic);
ATF_TC_BODY(rejection_is_failure_atomic, tc)
{
	struct vmm_x86_startup_transaction_input input;
	struct vmm_x86_startup_finalizer finalizer, finalizer_before;
	struct vmm_x86_startup_finalizer_ops incomplete;
	struct vmm_x86_startup_finalizer_plan before, plan;
	struct finalizer_fixture fixture;

	(void)tc;
	memset(&input, 0, sizeof(input));
	input.kind = VMM_STARTUP_EVENT_SIPI;
	input.vector = 1;
	input.bootstrap_processor = 1;
	memset(&plan, 0xa5, sizeof(plan));
	before = plan;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), EINVAL);
	ATF_CHECK_EQ(memcmp(&plan, &before, sizeof(plan)), 0);
	input.bootstrap_processor = 0;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_plan(&input,
	    (struct vmm_x86_startup_finalizer_plan *)(void *)&input), EINVAL);
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), 0);

	memset(&fixture, 0, sizeof(fixture));
	memset(&finalizer, 0, sizeof(finalizer));
	incomplete = finalizer_ops;
	incomplete.reset_lapic = NULL;
	finalizer_before = finalizer;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_init(&incomplete, &fixture,
	    &plan, &finalizer), EINVAL);
	ATF_CHECK_EQ(memcmp(&finalizer, &finalizer_before,
	    sizeof(finalizer)), 0);
	memset(&input, 0, sizeof(input));
	input.kind = VMM_STARTUP_EVENT_INIT;
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), 0);
	plan.startup_wait = 0;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, &fixture,
	    &plan, &finalizer), EINVAL);
	ATF_CHECK_EQ(memcmp(&finalizer, &finalizer_before,
	    sizeof(finalizer)), 0);
	input.kind = VMM_STARTUP_EVENT_SIPI;
	input.vector = 1;
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), 0);
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, &fixture,
	    &plan, &finalizer), 0);
	finalizer_before = finalizer;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, &fixture,
	    &plan, &finalizer), EINVAL);
	ATF_CHECK_EQ(memcmp(&finalizer, &finalizer_before,
	    sizeof(finalizer)), 0);
}

ATF_TC_WITHOUT_HEAD(binding_copies_plan_and_callbacks);
ATF_TC_BODY(binding_copies_plan_and_callbacks, tc)
{
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_ops mutable_ops;
	struct vmm_x86_startup_finalizer_plan plan;
	struct vmm_x86_startup_transaction_input input;
	struct finalizer_fixture fixture;
	const uint8_t expected[] = {
		STEP_NESTED, STEP_LAPIC, STEP_RESIDENCY, STEP_NEXTRIP, STEP_WAIT,
	};

	(void)tc;
	memset(&input, 0, sizeof(input));
	input.kind = VMM_STARTUP_EVENT_INIT;
	memset(&plan, 0, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), 0);
	mutable_ops = finalizer_ops;
	memset(&fixture, 0, sizeof(fixture));
	memset(&finalizer, 0, sizeof(finalizer));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_init(&mutable_ops, &fixture,
	    &plan, &finalizer), 0);
	/* Binding is bookkeeping only; no architectural callback may run yet. */
	ATF_CHECK_EQ(fixture.count, 0);
	memset(&mutable_ops, 0, sizeof(mutable_ops));
	memset(&plan, 0, sizeof(plan));
	vmm_x86_startup_finalizer_commit(&finalizer);
	ATF_CHECK_EQ(fixture.count, nitems(expected));
	ATF_CHECK_EQ(memcmp(fixture.step, expected, sizeof(expected)), 0);
	ATF_CHECK_EQ(fixture.nextrip, UINT64_C(0xfff0));
	ATF_CHECK(fixture.wait);
}

ATF_TC_WITHOUT_HEAD(binding_matches_exact_input);
ATF_TC_BODY(binding_matches_exact_input, tc)
{
	struct vmm_x86_startup_finalizer copied, finalizer;
	struct vmm_x86_startup_finalizer_plan plan;
	struct vmm_x86_startup_transaction_input bound, other;
	struct finalizer_fixture fixture;

	(void)tc;
	memset(&bound, 0, sizeof(bound));
	bound.kind = VMM_STARTUP_EVENT_INIT;
	memset(&plan, 0, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&bound, &plan), 0);
	memset(&fixture, 0, sizeof(fixture));
	memset(&finalizer, 0, sizeof(finalizer));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_init(&finalizer_ops, &fixture,
	    &plan, &finalizer), 0);
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(&finalizer, &bound), 0);
	other = bound;
	other.bootstrap_processor = 1;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(&finalizer, &other),
	    ESTALE);
	other = bound;
	other.kind = VMM_STARTUP_EVENT_SIPI;
	other.vector = 1;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(&finalizer, &other),
	    ESTALE);
	copied = finalizer;
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(&copied, &bound), EINVAL);
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(&finalizer,
	    (const struct vmm_x86_startup_transaction_input *)(const void *)
	    &finalizer), EINVAL);
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(NULL, &bound), EINVAL);
	ATF_CHECK_EQ(vmm_x86_startup_finalizer_check(&finalizer, NULL), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_ap_order);
	ATF_TP_ADD_TC(tp, init_bsp_remains_runnable);
	ATF_TP_ADD_TC(tp, sipi_changes_only_nextrip_and_wait);
	ATF_TP_ADD_TC(tp, sipi_plan_binds_vector_and_entrypoint);
	ATF_TP_ADD_TC(tp, rejection_is_failure_atomic);
	ATF_TP_ADD_TC(tp, binding_copies_plan_and_callbacks);
	ATF_TP_ADD_TC(tp, binding_matches_exact_input);
	return (atf_no_error());
}
