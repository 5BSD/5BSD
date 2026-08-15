/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_intinfo.c"
#include "../../../sys/amd64/vmm/vmm_event_state.c"
#include "../../../sys/amd64/vmm/vmm_x86_startup_state.c"
#include "../../../sys/amd64/vmm/vmm_x86_startup_transaction.c"
#include "../../../sys/amd64/vmm/vmm_x86_startup_finalizer.c"
#include "../../../sys/amd64/vmm/vmm_x86_startup_machine.c"

struct fake_machine {
	uint64_t reg[VMM_X86_STARTUP_REG_COUNT];
	struct vmm_x86_startup_desc desc[VMM_X86_STARTUP_DESC_COUNT];
	struct vmm_event_state event;
	unsigned int get_calls;
	unsigned int set_calls;
	unsigned int fail_get_call;
	unsigned int fail_set_call;
	unsigned int mutate_on_fail_call;
	unsigned int silent_set_call;
	unsigned int finalize_calls;
	unsigned int event_capture_calls;
	unsigned int event_compare_clear_calls;
	uint64_t published_nextrip;
	bool published_wait;
	int event_race;
	struct vmm_x86_startup_transaction_input *external_input;
	struct vmm_x86_startup_machine_ops *external_ops;
	struct vmm_x86_startup_finalizer *external_finalizer;
	int mutate_external_input;
	int mutate_external_ops;
	int mutate_external_finalizer;
	int mutate_finalizer_after_commit;
};

static void fake_finalizer_alternate_noop(void *);

static int
fake_getreg(void *arg, enum vmm_x86_startup_register reg, uint64_t *value)
{
	struct fake_machine *machine = arg;

	machine->get_calls++;
	if (machine->fail_get_call == machine->get_calls)
		return (EIO);
	ATF_REQUIRE(reg >= 0 && reg < VMM_X86_STARTUP_REG_COUNT);
	*value = machine->reg[reg];
	return (0);
}

static int
fake_setreg(void *arg, enum vmm_x86_startup_register reg, uint64_t value)
{
	struct fake_machine *machine = arg;

	machine->set_calls++;
	ATF_REQUIRE(reg >= 0 && reg < VMM_X86_STARTUP_REG_COUNT);
	if (machine->fail_set_call == machine->set_calls) {
		if (machine->mutate_on_fail_call == machine->set_calls)
			machine->reg[reg] = value;
		machine->fail_set_call = 0;
		return (EIO);
	}
	if (machine->silent_set_call == machine->set_calls)
		return (0);
	machine->reg[reg] = value;
	return (0);
}

static int
fake_getdesc(void *arg, enum vmm_x86_startup_descriptor desc,
    struct vmm_x86_startup_desc *value)
{
	struct fake_machine *machine = arg;

	machine->get_calls++;
	if (machine->fail_get_call == machine->get_calls)
		return (EIO);
	ATF_REQUIRE(desc >= 0 && desc < VMM_X86_STARTUP_DESC_COUNT);
	*value = machine->desc[desc];
	return (0);
}

static int
fake_setdesc(void *arg, enum vmm_x86_startup_descriptor desc,
    const struct vmm_x86_startup_desc *value)
{
	struct fake_machine *machine = arg;

	machine->set_calls++;
	ATF_REQUIRE(desc >= 0 && desc < VMM_X86_STARTUP_DESC_COUNT);
	if (machine->fail_set_call == machine->set_calls) {
		if (machine->mutate_on_fail_call == machine->set_calls)
			machine->desc[desc] = *value;
		machine->fail_set_call = 0;
		return (EIO);
	}
	if (machine->silent_set_call == machine->set_calls)
		return (0);
	machine->desc[desc] = *value;
	return (0);
}

static int
fake_event_capture(void *arg, struct vmm_event_state *event)
{
	struct fake_machine *machine = arg;

	machine->event_capture_calls++;
	if (machine->mutate_external_input)
		machine->external_input->reserved32 = 1;
	if (machine->mutate_external_ops)
		machine->external_ops->event_compare_clear = NULL;
	if (machine->mutate_external_finalizer)
		machine->external_finalizer->ops.reset_nested =
		    fake_finalizer_alternate_noop;
	*event = machine->event;
	return (0);
}

static int
fake_event_compare_clear(void *arg, const struct vmm_event_state *event)
{
	struct fake_machine *machine = arg;

	machine->event_compare_clear_calls++;
	if (machine->event_race)
		return (EAGAIN);
	if (!vmm_event_state_equal(event, &machine->event))
		return (EAGAIN);
	memset(&machine->event, 0, sizeof(machine->event));
	return (0);
}

static void
fake_finalizer_noop(void *arg)
{

	ATF_REQUIRE(arg != NULL);
}

static void
fake_finalizer_alternate_noop(void *arg)
{

	ATF_REQUIRE(arg != NULL);
}

static void
fake_finalizer_nextrip(void *arg, uint64_t nextrip)
{
	struct fake_machine *machine = arg;

	ATF_REQUIRE(machine != NULL);
	machine->published_nextrip = nextrip;
}

static void
fake_finalizer_wait(void *arg, bool wait)
{
	struct fake_machine *machine = arg;

	machine->published_wait = wait;
	machine->finalize_calls++;
	if (machine->mutate_finalizer_after_commit)
		machine->external_finalizer->plan.kind =
		    VMM_STARTUP_EVENT_INIT;
}

static const struct vmm_x86_startup_machine_ops fake_ops = {
	.getreg = fake_getreg,
	.setreg = fake_setreg,
	.getdesc = fake_getdesc,
	.setdesc = fake_setdesc,
	.event_capture = fake_event_capture,
	.event_compare_clear = fake_event_compare_clear,
};

static const struct vmm_x86_startup_finalizer_ops fake_finalizer_ops = {
	.reset_nested = fake_finalizer_noop,
	.reset_lapic = fake_finalizer_noop,
	.retire_translation_residency = fake_finalizer_noop,
	.set_nextrip = fake_finalizer_nextrip,
	.publish_startup_wait = fake_finalizer_wait,
};

static int
fake_execute(const struct vmm_x86_startup_transaction_input *input,
    uint32_t processor_signature,
    const struct vmm_x86_startup_machine_ops *ops,
    struct fake_machine *machine,
    struct vmm_x86_startup_transaction_result *result)
{
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_plan plan;
	int error;

	memset(&finalizer, 0, sizeof(finalizer));
	memset(&plan, 0, sizeof(plan));
	error = vmm_x86_startup_finalizer_plan(input, &plan);
	if (error == 0)
		error = vmm_x86_startup_finalizer_init(&fake_finalizer_ops,
		    machine, &plan, &finalizer);
	if (error != 0)
		return (error);
	machine->external_finalizer = &finalizer;
	return (vmm_x86_startup_machine_execute(input, processor_signature,
	    ops, machine, &finalizer, result));
}

static void
fake_init(struct fake_machine *machine)
{
	unsigned int i;

	memset(machine, 0, sizeof(*machine));
	for (i = 0; i < nitems(machine->reg); i++)
		machine->reg[i] = UINT64_C(0x100000000) + i;
	/* The plan accepts architectural 32-bit CR0 state. */
	machine->reg[VMM_X86_STARTUP_REG_CR0] = UINT64_C(0x60000011);
	for (i = 0; i < nitems(machine->desc); i++) {
		machine->desc[i].base = UINT64_C(0x200000000) + i;
		machine->desc[i].limit = UINT32_C(0x10000) + i;
		machine->desc[i].access = UINT32_C(0x80) + i;
		machine->desc[i].selector = (uint16_t)(i << 3);
	}
	machine->event.flags = VMM_EVENT_STATE_F_NMI_PENDING;
}

static void
check_machine_value_equal(const struct fake_machine *left,
    const struct fake_machine *right)
{

	ATF_CHECK_EQ(memcmp(left->reg, right->reg, sizeof(left->reg)), 0);
	ATF_CHECK_EQ(memcmp(left->desc, right->desc, sizeof(left->desc)), 0);
	ATF_CHECK(vmm_event_state_equal(&left->event, &right->event));
}

static struct vmm_x86_startup_transaction_input
startup_input(uint8_t kind, uint8_t vector)
{
	struct vmm_x86_startup_transaction_input input;

	memset(&input, 0, sizeof(input));
	input.kind = kind;
	input.vector = vector;
	return (input);
}

ATF_TC_WITHOUT_HEAD(init_commits_complete_architectural_value);
ATF_TC_BODY(init_commits_complete_architectural_value, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine machine;
	unsigned int i;
	int error;

	(void)tc;
	fake_init(&machine);
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	error = fake_execute(&input,
	    UINT32_C(0x000806f8), &fake_ops, &machine, &result);
	ATF_REQUIRE_EQ_MSG(error, 0, "startup transaction failed: %d", error);
	ATF_CHECK_EQ(result.committed, 1);
	ATF_CHECK_EQ(machine.finalize_calls, 1);
	ATF_CHECK_EQ(machine.event_capture_calls, 1);
	ATF_CHECK_EQ(machine.event_compare_clear_calls, 1);
	ATF_CHECK_EQ(machine.event.flags, 0);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_RFLAGS], 2);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_RIP], 0xfff0);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_CR0], 0x60000010);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_RDX], 0x000806f8);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_DR6], 0xffff0ff0);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_DR7], 0x400);
	for (i = VMM_X86_STARTUP_REG_RAX;
	    i <= VMM_X86_STARTUP_REG_R15; i++) {
		if (i != VMM_X86_STARTUP_REG_RDX)
			ATF_CHECK_EQ(machine.reg[i], 0);
	}
	ATF_CHECK_EQ(machine.desc[VMM_X86_STARTUP_DESC_CS].selector, 0xf000);
	ATF_CHECK_EQ(machine.desc[VMM_X86_STARTUP_DESC_CS].base,
	    0xffff0000);
}

ATF_TC_WITHOUT_HEAD(sipi_changes_only_cs_and_rip);
ATF_TC_BODY(sipi_changes_only_cs_and_rip, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;
	unsigned int i;

	(void)tc;
	fake_init(&machine);
	before = machine;
	input = startup_input(VMM_STARTUP_EVENT_SIPI, 0x5a);
	ATF_REQUIRE_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), 0);
	ATF_CHECK_EQ(result.committed, 1);
	ATF_CHECK_EQ(machine.finalize_calls, 1);
	ATF_CHECK_EQ(machine.reg[VMM_X86_STARTUP_REG_RIP], 0);
	ATF_CHECK_EQ(machine.desc[VMM_X86_STARTUP_DESC_CS].selector, 0x5a00);
	ATF_CHECK_EQ(machine.desc[VMM_X86_STARTUP_DESC_CS].base, 0x5a000);
	ATF_CHECK_EQ(machine.published_nextrip, UINT64_C(0x5a000));
	ATF_CHECK(!machine.published_wait);
	ATF_CHECK(vmm_event_state_equal(&machine.event, &before.event));
	ATF_CHECK_EQ(machine.event_capture_calls, 0);
	ATF_CHECK_EQ(machine.event_compare_clear_calls, 0);
	for (i = 0; i < nitems(machine.reg); i++) {
		if (i != VMM_X86_STARTUP_REG_RIP)
			ATF_CHECK_EQ(machine.reg[i], before.reg[i]);
	}
	for (i = 0; i < nitems(machine.desc); i++) {
		if (i != VMM_X86_STARTUP_DESC_CS)
			ATF_CHECK_EQ(memcmp(&machine.desc[i], &before.desc[i],
			    sizeof(machine.desc[i])), 0);
	}
}

ATF_TC_WITHOUT_HEAD(each_init_setter_failure_rolls_back);
ATF_TC_BODY(each_init_setter_failure_rolls_back, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;
	unsigned int failure, operations;

	(void)tc;
	operations = nitems(init_descriptors) + nitems(init_registers);
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	for (failure = 1; failure <= operations; failure++) {
		fake_init(&machine);
		before = machine;
		machine.fail_set_call = failure;
		ATF_CHECK_EQ(fake_execute(&input,
		    UINT32_C(0x1234), &fake_ops, &machine, &result), EIO);
		ATF_CHECK_EQ(result.rollback_complete, 1);
		ATF_CHECK_EQ(machine.finalize_calls, 0);
		check_machine_value_equal(&machine, &before);
	}
}

ATF_TC_WITHOUT_HEAD(event_race_rolls_back_machine_state);
ATF_TC_BODY(event_race_rolls_back_machine_state, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;

	(void)tc;
	fake_init(&machine);
	before = machine;
	machine.event_race = 1;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EAGAIN);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(machine.finalize_calls, 0);
	check_machine_value_equal(&machine, &before);
}

ATF_TC_WITHOUT_HEAD(capture_failure_never_mutates_machine);
ATF_TC_BODY(capture_failure_never_mutates_machine, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;

	(void)tc;
	fake_init(&machine);
	before = machine;
	machine.fail_get_call = 7;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EIO);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(machine.set_calls, 0);
	check_machine_value_equal(&machine, &before);
}

ATF_TC_WITHOUT_HEAD(silent_register_write_is_detected_and_rolled_back);
ATF_TC_BODY(silent_register_write_is_detected_and_rolled_back, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;

	(void)tc;
	fake_init(&machine);
	before = machine;
	/* All descriptors precede the first register write. */
	machine.silent_set_call = nitems(init_descriptors) + 1;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EIO);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(machine.finalize_calls, 0);
	check_machine_value_equal(&machine, &before);
}

ATF_TC_WITHOUT_HEAD(silent_descriptor_write_is_detected_and_rolled_back);
ATF_TC_BODY(silent_descriptor_write_is_detected_and_rolled_back, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;

	(void)tc;
	fake_init(&machine);
	before = machine;
	machine.silent_set_call = 1;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EIO);
	ATF_CHECK_EQ(result.rollback_complete, 1);
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(machine.finalize_calls, 0);
	check_machine_value_equal(&machine, &before);
}

ATF_TC_WITHOUT_HEAD(each_sipi_setter_failure_rolls_back);
ATF_TC_BODY(each_sipi_setter_failure_rolls_back, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;
	unsigned int failure;

	(void)tc;
	input = startup_input(VMM_STARTUP_EVENT_SIPI, 0x5a);
	for (failure = 1; failure <= 2; failure++) {
		fake_init(&machine);
		before = machine;
		machine.fail_set_call = failure;
		ATF_CHECK_EQ(fake_execute(&input, 0,
		    &fake_ops, &machine, &result), EIO);
		ATF_CHECK_EQ(result.rollback_complete, 1);
		ATF_CHECK_EQ(result.committed, 0);
		ATF_CHECK_EQ(machine.finalize_calls, 0);
		check_machine_value_equal(&machine, &before);
	}
}

ATF_TC_WITHOUT_HEAD(silent_rollback_is_poisoned);
ATF_TC_BODY(silent_rollback_is_poisoned, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine machine;

	(void)tc;
	fake_init(&machine);
	/* Apply descriptor zero, fail descriptor one, then drop the restore. */
	machine.fail_set_call = 2;
	machine.silent_set_call = 3;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EIO);
	ATF_CHECK_EQ(result.rollback_complete, 0);
	ATF_CHECK_EQ(result.poisoned, 1);
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(machine.finalize_calls, 0);
}

ATF_TC_WITHOUT_HEAD(mutating_setter_error_is_rolled_back);
ATF_TC_BODY(mutating_setter_error_is_rolled_back, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;
	unsigned int failure, failures[2];

	(void)tc;
	failures[0] = 1;
	failures[1] = nitems(init_descriptors) + 1;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	for (failure = 0; failure < nitems(failures); failure++) {
		fake_init(&machine);
		before = machine;
		machine.fail_set_call = failures[failure];
		machine.mutate_on_fail_call = failures[failure];
		ATF_CHECK_EQ(fake_execute(&input, 0,
		    &fake_ops, &machine, &result), EPROTO);
		ATF_CHECK_EQ(result.rollback_complete, 1);
		ATF_CHECK_EQ(result.poisoned, 0);
		ATF_CHECK_EQ(result.committed, 0);
		ATF_CHECK_EQ(machine.finalize_calls, 0);
		check_machine_value_equal(&machine, &before);
	}
}

ATF_TC_WITHOUT_HEAD(external_input_mutation_is_poisoned);
ATF_TC_BODY(external_input_mutation_is_poisoned, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine machine;

	(void)tc;
	fake_init(&machine);
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	machine.external_input = &input;
	machine.mutate_external_input = 1;
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EPROTO);
	ATF_CHECK_EQ(result.poisoned, 1);
	ATF_CHECK_EQ(result.committed, 0);
}

ATF_TC_WITHOUT_HEAD(external_callback_mutation_is_poisoned);
ATF_TC_BODY(external_callback_mutation_is_poisoned, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct vmm_x86_startup_machine_ops ops;
	struct fake_machine machine;

	(void)tc;
	fake_init(&machine);
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	ops = fake_ops;
	machine.external_ops = &ops;
	machine.mutate_external_ops = 1;
	ATF_CHECK_EQ(fake_execute(&input, 0, &ops,
	    &machine, &result), EPROTO);
	ATF_CHECK_EQ(result.poisoned, 1);
	ATF_CHECK_EQ(result.committed, 0);
}

ATF_TC_WITHOUT_HEAD(mismatched_finalizer_is_rejected_before_capture);
ATF_TC_BODY(mismatched_finalizer_is_rejected_before_capture, tc)
{
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_plan plan;
	struct vmm_x86_startup_transaction_result result, result_before;
	struct vmm_x86_startup_transaction_input bound, input;
	struct fake_machine before, machine;

	(void)tc;
	fake_init(&machine);
	before = machine;
	bound = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	input = bound;
	input.bootstrap_processor = 1;
	memset(&plan, 0, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&bound, &plan), 0);
	memset(&finalizer, 0, sizeof(finalizer));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_init(&fake_finalizer_ops,
	    &machine, &plan, &finalizer), 0);
	memset(&result, 0xa5, sizeof(result));
	result_before = result;
	ATF_CHECK_EQ(vmm_x86_startup_machine_execute(&input, 0, &fake_ops,
	    &machine, &finalizer, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
	ATF_CHECK_EQ(machine.get_calls, 0);
	ATF_CHECK_EQ(machine.set_calls, 0);
	check_machine_value_equal(&machine, &before);
}

ATF_TC_WITHOUT_HEAD(external_finalizer_mutation_is_poisoned);
ATF_TC_BODY(external_finalizer_mutation_is_poisoned, tc)
{
	struct vmm_x86_startup_finalizer finalizer;
	struct vmm_x86_startup_finalizer_plan plan;
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine before, machine;

	(void)tc;
	fake_init(&machine);
	before = machine;
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	memset(&plan, 0, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_plan(&input, &plan), 0);
	memset(&finalizer, 0, sizeof(finalizer));
	ATF_REQUIRE_EQ(vmm_x86_startup_finalizer_init(&fake_finalizer_ops,
	    &machine, &plan, &finalizer), 0);
	machine.external_finalizer = &finalizer;
	machine.mutate_external_finalizer = 1;
	ATF_CHECK_EQ(vmm_x86_startup_machine_execute(&input, 0, &fake_ops,
	    &machine, &finalizer, &result), EPROTO);
	ATF_CHECK_EQ(result.poisoned, 1);
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(machine.finalize_calls, 0);
	check_machine_value_equal(&machine, &before);
}

ATF_TC_WITHOUT_HEAD(postcommit_finalizer_repopulation_is_poisoned);
ATF_TC_BODY(postcommit_finalizer_repopulation_is_poisoned, tc)
{
	struct vmm_x86_startup_transaction_result result;
	struct vmm_x86_startup_transaction_input input;
	struct fake_machine machine;

	(void)tc;
	fake_init(&machine);
	input = startup_input(VMM_STARTUP_EVENT_INIT, 0);
	machine.mutate_finalizer_after_commit = 1;
	ATF_CHECK_EQ(fake_execute(&input, 0, &fake_ops,
	    &machine, &result), EPROTO);
	ATF_CHECK_EQ(result.poisoned, 1);
	ATF_CHECK_EQ(result.committed, 0);
	ATF_CHECK_EQ(machine.finalize_calls, 1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_commits_complete_architectural_value);
	ATF_TP_ADD_TC(tp, sipi_changes_only_cs_and_rip);
	ATF_TP_ADD_TC(tp, each_init_setter_failure_rolls_back);
	ATF_TP_ADD_TC(tp, event_race_rolls_back_machine_state);
	ATF_TP_ADD_TC(tp, capture_failure_never_mutates_machine);
	ATF_TP_ADD_TC(tp, silent_register_write_is_detected_and_rolled_back);
	ATF_TP_ADD_TC(tp, silent_descriptor_write_is_detected_and_rolled_back);
	ATF_TP_ADD_TC(tp, each_sipi_setter_failure_rolls_back);
	ATF_TP_ADD_TC(tp, silent_rollback_is_poisoned);
	ATF_TP_ADD_TC(tp, mutating_setter_error_is_rolled_back);
	ATF_TP_ADD_TC(tp, external_input_mutation_is_poisoned);
	ATF_TP_ADD_TC(tp, external_callback_mutation_is_poisoned);
	ATF_TP_ADD_TC(tp, mismatched_finalizer_is_rejected_before_capture);
	ATF_TP_ADD_TC(tp, external_finalizer_mutation_is_poisoned);
	ATF_TP_ADD_TC(tp, postcommit_finalizer_repopulation_is_poisoned);
	return (atf_no_error());
}
