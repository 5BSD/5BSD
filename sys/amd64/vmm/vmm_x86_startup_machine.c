/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#include "../../dev/vmm/vmm_address_range.h"

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmm_x86_startup_machine.h"

struct vmm_x86_startup_machine_transaction {
	struct vmm_x86_startup_transaction_input input;
	struct vmm_x86_startup_machine_ops ops;
	void *arg;
	struct vmm_x86_startup_finalizer *finalizer;
	struct vmm_x86_startup_finalizer finalizer_expected;
	uint32_t processor_signature;
	uint32_t applied_regs;
	uint32_t applied_descs;
	uint64_t rollback_reg[VMM_X86_STARTUP_REG_COUNT];
	struct vmm_x86_startup_desc
	    rollback_desc[VMM_X86_STARTUP_DESC_COUNT];
	struct vmm_event_state event;
	union {
		struct vmm_x86_init_state_plan init;
		struct vmm_x86_sipi_state_plan sipi;
	} plan;
};

static const enum vmm_x86_startup_register init_registers[] = {
	VMM_X86_STARTUP_REG_RAX,
	VMM_X86_STARTUP_REG_RBX,
	VMM_X86_STARTUP_REG_RCX,
	VMM_X86_STARTUP_REG_RDX,
	VMM_X86_STARTUP_REG_RSI,
	VMM_X86_STARTUP_REG_RDI,
	VMM_X86_STARTUP_REG_RBP,
	VMM_X86_STARTUP_REG_RSP,
	VMM_X86_STARTUP_REG_R8,
	VMM_X86_STARTUP_REG_R9,
	VMM_X86_STARTUP_REG_R10,
	VMM_X86_STARTUP_REG_R11,
	VMM_X86_STARTUP_REG_R12,
	VMM_X86_STARTUP_REG_R13,
	VMM_X86_STARTUP_REG_R14,
	VMM_X86_STARTUP_REG_R15,
	VMM_X86_STARTUP_REG_RFLAGS,
	VMM_X86_STARTUP_REG_RIP,
	VMM_X86_STARTUP_REG_CR2,
	VMM_X86_STARTUP_REG_CR3,
	VMM_X86_STARTUP_REG_CR4,
	VMM_X86_STARTUP_REG_EFER,
	VMM_X86_STARTUP_REG_CR0,
	VMM_X86_STARTUP_REG_DR0,
	VMM_X86_STARTUP_REG_DR1,
	VMM_X86_STARTUP_REG_DR2,
	VMM_X86_STARTUP_REG_DR3,
	VMM_X86_STARTUP_REG_DR6,
	VMM_X86_STARTUP_REG_DR7,
	VMM_X86_STARTUP_REG_INTR_SHADOW,
};

static const enum vmm_x86_startup_descriptor init_descriptors[] = {
	VMM_X86_STARTUP_DESC_CS,
	VMM_X86_STARTUP_DESC_SS,
	VMM_X86_STARTUP_DESC_DS,
	VMM_X86_STARTUP_DESC_ES,
	VMM_X86_STARTUP_DESC_FS,
	VMM_X86_STARTUP_DESC_GS,
	VMM_X86_STARTUP_DESC_TR,
	VMM_X86_STARTUP_DESC_LDTR,
	VMM_X86_STARTUP_DESC_GDTR,
	VMM_X86_STARTUP_DESC_IDTR,
};

static bool
startup_machine_ranges_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{

	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
startup_machine_ops_equal(const struct vmm_x86_startup_machine_ops *left,
    const struct vmm_x86_startup_machine_ops *right)
{

	return (left->getreg == right->getreg &&
	    left->setreg == right->setreg &&
	    left->getdesc == right->getdesc &&
	    left->setdesc == right->setdesc &&
	    left->event_capture == right->event_capture &&
	    left->event_compare_clear == right->event_compare_clear);
}

static bool
startup_machine_finalizer_equal(
    const struct vmm_x86_startup_finalizer *left,
    const struct vmm_x86_startup_finalizer *right)
{

	return (left->ops.reset_nested == right->ops.reset_nested &&
	    left->ops.reset_lapic == right->ops.reset_lapic &&
	    left->ops.retire_translation_residency ==
	    right->ops.retire_translation_residency &&
	    left->ops.set_nextrip == right->ops.set_nextrip &&
	    left->ops.publish_startup_wait ==
	    right->ops.publish_startup_wait &&
	    left->plan.nextrip == right->plan.nextrip &&
	    left->plan.kind == right->plan.kind &&
	    left->plan.vector == right->plan.vector &&
	    left->plan.bootstrap_processor ==
	    right->plan.bootstrap_processor &&
	    left->plan.reset_nested == right->plan.reset_nested &&
	    left->plan.reset_lapic == right->plan.reset_lapic &&
	    left->plan.retire_translation_residency ==
	    right->plan.retire_translation_residency &&
	    left->plan.startup_wait == right->plan.startup_wait &&
	    left->plan.reserved8 == right->plan.reserved8 &&
	    left->arg == right->arg &&
	    left->storage_cookie == right->storage_cookie);
}

static int
startup_machine_init_reg_value(const struct vmm_x86_init_state_plan *plan,
    enum vmm_x86_startup_register reg, uint64_t *value)
{

	if (reg >= VMM_X86_STARTUP_REG_RAX &&
	    reg <= VMM_X86_STARTUP_REG_R15) {
		*value = plan->gpr[reg - VMM_X86_STARTUP_REG_RAX];
		return (0);
	}
	switch (reg) {
	case VMM_X86_STARTUP_REG_RFLAGS:
		*value = plan->rflags;
		break;
	case VMM_X86_STARTUP_REG_RIP:
		*value = plan->rip;
		break;
	case VMM_X86_STARTUP_REG_CR0:
		*value = plan->cr0;
		break;
	case VMM_X86_STARTUP_REG_CR2:
		*value = plan->cr2;
		break;
	case VMM_X86_STARTUP_REG_CR3:
		*value = plan->cr3;
		break;
	case VMM_X86_STARTUP_REG_CR4:
		*value = plan->cr4;
		break;
	case VMM_X86_STARTUP_REG_EFER:
		*value = plan->efer;
		break;
	case VMM_X86_STARTUP_REG_DR0:
	case VMM_X86_STARTUP_REG_DR1:
	case VMM_X86_STARTUP_REG_DR2:
	case VMM_X86_STARTUP_REG_DR3:
		*value = plan->dr[reg - VMM_X86_STARTUP_REG_DR0];
		break;
	case VMM_X86_STARTUP_REG_DR6:
		*value = plan->dr6;
		break;
	case VMM_X86_STARTUP_REG_DR7:
		*value = plan->dr7;
		break;
	case VMM_X86_STARTUP_REG_INTR_SHADOW:
		*value = plan->interrupt_shadow;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static const struct vmm_x86_startup_desc *
startup_machine_init_desc(const struct vmm_x86_init_state_plan *plan,
    enum vmm_x86_startup_descriptor desc)
{

	if (desc <= VMM_X86_STARTUP_DESC_LDTR)
		return (&plan->segment[desc]);
	if (desc == VMM_X86_STARTUP_DESC_GDTR)
		return (&plan->gdtr);
	if (desc == VMM_X86_STARTUP_DESC_IDTR)
		return (&plan->idtr);
	return (NULL);
}

static bool
startup_machine_desc_equal(const struct vmm_x86_startup_desc *left,
    const struct vmm_x86_startup_desc *right)
{

	return (left->base == right->base && left->limit == right->limit &&
	    left->access == right->access && left->selector == right->selector);
}

static int
startup_machine_setreg_verified(
    struct vmm_x86_startup_machine_transaction *transaction,
    enum vmm_x86_startup_register reg, uint64_t value)
{
	uint64_t observed;
	int error;

	error = transaction->ops.setreg(transaction->arg, reg, value);
	if (error != 0) {
		if (transaction->ops.getreg(transaction->arg, reg,
		    &observed) == 0 && observed == transaction->rollback_reg[reg])
			return (error);
		/* The failed setter may have mutated this location. */
		transaction->applied_regs++;
		return (EPROTO);
	}
	transaction->applied_regs++;
	error = transaction->ops.getreg(transaction->arg, reg, &observed);
	if (error != 0)
		return (error);
	return (observed == value ? 0 : EIO);
}

static int
startup_machine_setdesc_verified(
    struct vmm_x86_startup_machine_transaction *transaction,
    enum vmm_x86_startup_descriptor desc,
    const struct vmm_x86_startup_desc *value)
{
	struct vmm_x86_startup_desc observed;
	int error;

	error = transaction->ops.setdesc(transaction->arg, desc, value);
	if (error != 0) {
		memset(&observed, 0, sizeof(observed));
		if (transaction->ops.getdesc(transaction->arg, desc,
		    &observed) == 0 && startup_machine_desc_equal(&observed,
		    &transaction->rollback_desc[desc]))
			return (error);
		/* The failed setter may have mutated this location. */
		transaction->applied_descs++;
		return (EPROTO);
	}
	transaction->applied_descs++;
	memset(&observed, 0, sizeof(observed));
	error = transaction->ops.getdesc(transaction->arg, desc, &observed);
	if (error != 0)
		return (error);
	return (startup_machine_desc_equal(&observed, value) ? 0 : EIO);
}

static int
startup_machine_restore_reg_verified(
    struct vmm_x86_startup_machine_transaction *transaction,
    enum vmm_x86_startup_register reg, uint64_t value)
{
	uint64_t observed;
	int error;

	error = transaction->ops.setreg(transaction->arg, reg, value);
	if (error != 0)
		return (error);
	error = transaction->ops.getreg(transaction->arg, reg, &observed);
	if (error != 0)
		return (error);
	return (observed == value ? 0 : EIO);
}

static int
startup_machine_restore_desc_verified(
    struct vmm_x86_startup_machine_transaction *transaction,
    enum vmm_x86_startup_descriptor desc,
    const struct vmm_x86_startup_desc *value)
{
	struct vmm_x86_startup_desc observed;
	int error;

	error = transaction->ops.setdesc(transaction->arg, desc, value);
	if (error != 0)
		return (error);
	memset(&observed, 0, sizeof(observed));
	error = transaction->ops.getdesc(transaction->arg, desc, &observed);
	if (error != 0)
		return (error);
	return (startup_machine_desc_equal(&observed, value) ? 0 : EIO);
}

static int
startup_machine_capture(void *arg,
    const struct vmm_x86_startup_transaction_input *input)
{
	struct vmm_x86_startup_machine_transaction *transaction;
	uint64_t cr0;
	size_t i;
	int error;

	transaction = arg;
	if (!vmm_x86_startup_transaction_input_equal(input,
	    &transaction->input))
		return (ESTALE);
	if (input->kind == VMM_STARTUP_EVENT_INIT) {
		for (i = 0; i < nitems(init_registers); i++) {
			error = transaction->ops.getreg(transaction->arg,
			    init_registers[i],
			    &transaction->rollback_reg[init_registers[i]]);
			if (error != 0)
				return (error);
		}
		for (i = 0; i < nitems(init_descriptors); i++) {
			error = transaction->ops.getdesc(transaction->arg,
			    init_descriptors[i],
			    &transaction->rollback_desc[init_descriptors[i]]);
			if (error != 0)
				return (error);
		}
		cr0 = transaction->rollback_reg[VMM_X86_STARTUP_REG_CR0];
		error = vmm_x86_init_state_plan(cr0,
		    transaction->processor_signature, &transaction->plan.init);
	} else {
		error = transaction->ops.getreg(transaction->arg,
		    VMM_X86_STARTUP_REG_RIP,
		    &transaction->rollback_reg[VMM_X86_STARTUP_REG_RIP]);
		if (error == 0)
			error = transaction->ops.getdesc(transaction->arg,
			    VMM_X86_STARTUP_DESC_CS,
			    &transaction->rollback_desc[VMM_X86_STARTUP_DESC_CS]);
		if (error == 0)
			error = vmm_x86_sipi_state_plan(input->vector,
			    &transaction->plan.sipi);
	}
	if (error != 0)
		return (error);
	/* SIPI does not clear exception, NMI, interrupt, or reinjection state. */
	if (input->kind == VMM_STARTUP_EVENT_SIPI)
		return (0);
	error = transaction->ops.event_capture(transaction->arg,
	    &transaction->event);
	if (error != 0)
		return (error);
	return (vmm_event_state_validate(&transaction->event));
}

static int
startup_machine_apply(void *arg)
{
	struct vmm_x86_startup_machine_transaction *transaction;
	const struct vmm_x86_startup_desc *desc;
	uint64_t value;
	size_t i;
	int error;

	transaction = arg;
	transaction->applied_regs = 0;
	transaction->applied_descs = 0;
	if (transaction->input.kind == VMM_STARTUP_EVENT_SIPI) {
		error = startup_machine_setdesc_verified(transaction,
		    VMM_X86_STARTUP_DESC_CS, &transaction->plan.sipi.cs);
		if (error != 0)
			return (error);
		error = startup_machine_setreg_verified(transaction,
		    VMM_X86_STARTUP_REG_RIP, transaction->plan.sipi.rip);
		return (error);
	}

	for (i = 0; i < nitems(init_descriptors); i++) {
		desc = startup_machine_init_desc(&transaction->plan.init,
		    init_descriptors[i]);
		if (desc == NULL)
			return (EPROTO);
		error = startup_machine_setdesc_verified(transaction,
		    init_descriptors[i], desc);
		if (error != 0)
			return (error);
	}
	for (i = 0; i < nitems(init_registers); i++) {
		error = startup_machine_init_reg_value(&transaction->plan.init,
		    init_registers[i], &value);
		if (error != 0)
			return (error);
		error = startup_machine_setreg_verified(transaction,
		    init_registers[i], value);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
startup_machine_rollback(void *arg)
{
	struct vmm_x86_startup_machine_transaction *transaction;
	size_t i;
	int error;

	transaction = arg;
	if (transaction->input.kind == VMM_STARTUP_EVENT_SIPI) {
		if (transaction->applied_regs != 0) {
			error = startup_machine_restore_reg_verified(transaction,
			    VMM_X86_STARTUP_REG_RIP,
			    transaction->rollback_reg[VMM_X86_STARTUP_REG_RIP]);
			if (error != 0)
				return (error);
			transaction->applied_regs = 0;
		}
		if (transaction->applied_descs != 0) {
			error = startup_machine_restore_desc_verified(transaction,
			    VMM_X86_STARTUP_DESC_CS,
			    &transaction->rollback_desc[VMM_X86_STARTUP_DESC_CS]);
			if (error != 0)
				return (error);
			transaction->applied_descs = 0;
		}
		return (0);
	}
	while (transaction->applied_regs != 0) {
		i = transaction->applied_regs - 1;
		error = startup_machine_restore_reg_verified(transaction,
		    init_registers[i],
		    transaction->rollback_reg[init_registers[i]]);
		if (error != 0)
			return (error);
		transaction->applied_regs--;
	}
	while (transaction->applied_descs != 0) {
		i = transaction->applied_descs - 1;
		error = startup_machine_restore_desc_verified(transaction,
		    init_descriptors[i],
		    &transaction->rollback_desc[init_descriptors[i]]);
		if (error != 0)
			return (error);
		transaction->applied_descs--;
	}
	return (0);
}

static int
startup_machine_commit_event(void *arg)
{
	struct vmm_x86_startup_machine_transaction *transaction;
	int error;

	transaction = arg;
	error = vmm_x86_startup_finalizer_check(transaction->finalizer,
	    &transaction->input);
	if (error != 0 || !startup_machine_finalizer_equal(
	    transaction->finalizer, &transaction->finalizer_expected))
		return (error != 0 ? error : ESTALE);
	if (transaction->input.kind == VMM_STARTUP_EVENT_SIPI)
		return (0);
	return (transaction->ops.event_compare_clear(transaction->arg,
	    &transaction->event));
}

static void
startup_machine_finalize(void *arg)
{
	struct vmm_x86_startup_machine_transaction *transaction;

	transaction = arg;
	vmm_x86_startup_finalizer_commit(transaction->finalizer);
}

int
vmm_x86_startup_machine_execute(
    const struct vmm_x86_startup_transaction_input *input,
    uint32_t processor_signature,
    const struct vmm_x86_startup_machine_ops *ops, void *arg,
    struct vmm_x86_startup_finalizer *finalizer,
    struct vmm_x86_startup_transaction_result *result)
{
	static const struct vmm_x86_startup_transaction_ops transaction_ops = {
		.capture = startup_machine_capture,
		.apply = startup_machine_apply,
		.rollback = startup_machine_rollback,
		.commit_event = startup_machine_commit_event,
		.finalize = startup_machine_finalize,
	};
	struct vmm_x86_startup_transaction_input input_candidate;
	struct vmm_x86_startup_transaction_input input_expected;
	struct vmm_x86_startup_machine_ops ops_expected;
	struct vmm_x86_startup_machine_transaction transaction;
	int error;

	if (input == NULL || ops == NULL || arg == NULL || finalizer == NULL ||
	    result == NULL ||
	    ops->getreg == NULL || ops->setreg == NULL ||
	    ops->getdesc == NULL || ops->setdesc == NULL ||
	    ops->event_capture == NULL || ops->event_compare_clear == NULL ||
	    vmm_x86_startup_finalizer_check(finalizer, input) != 0 ||
	    startup_machine_ranges_overlap(input, sizeof(*input), ops,
	    sizeof(*ops)) || startup_machine_ranges_overlap(input,
	    sizeof(*input), result, sizeof(*result)) ||
	    startup_machine_ranges_overlap(input, sizeof(*input), finalizer,
	    sizeof(*finalizer)) ||
	    startup_machine_ranges_overlap(ops, sizeof(*ops), result,
	    sizeof(*result)) || startup_machine_ranges_overlap(ops,
	    sizeof(*ops), finalizer, sizeof(*finalizer)) ||
	    startup_machine_ranges_overlap(finalizer, sizeof(*finalizer), result,
	    sizeof(*result)) || arg == input || arg == ops || arg == finalizer ||
	    arg == result)
		return (EINVAL);

	memset(&transaction, 0, sizeof(transaction));
	input_candidate = *input;
	input_expected = input_candidate;
	ops_expected = *ops;
	transaction.input = input_candidate;
	transaction.ops = ops_expected;
	transaction.arg = arg;
	transaction.finalizer = finalizer;
	transaction.finalizer_expected = *finalizer;
	transaction.processor_signature = processor_signature;
	error = vmm_x86_startup_transaction_execute(&input_candidate,
	    &transaction_ops, &transaction, result);
	if (!vmm_x86_startup_transaction_input_equal(input, &input_expected) ||
	    !startup_machine_ops_equal(ops, &ops_expected) ||
	    (error == 0 && !vmm_x86_startup_finalizer_consumed(finalizer)) ||
	    (error != 0 && !startup_machine_finalizer_equal(finalizer,
	    &transaction.finalizer_expected))) {
		/* External callback/input corruption makes completion unknowable. */
		memset(result, 0, sizeof(*result));
		result->poisoned = 1;
		return (EPROTO);
	}
	return (error);
}
