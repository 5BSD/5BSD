/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#include "../../dev/vmm/vmm_address_range.h"

#ifndef _KERNEL
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmm_x86_startup_finalizer.h"

#define	VMM_X86_INIT_NEXTRIP	UINT64_C(0xfff0)
#define	VMM_X86_SIPI_SHIFT	12

static bool
startup_finalizer_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{

	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
startup_finalizer_plan_valid(
    const struct vmm_x86_startup_finalizer_plan *plan)
{

	if (plan == NULL || plan->bootstrap_processor > 1 ||
	    plan->reset_nested > 1 || plan->reset_lapic > 1 ||
	    plan->retire_translation_residency > 1 || plan->startup_wait > 1 ||
	    plan->reserved8 != 0 ||
	    (plan->kind != VMM_STARTUP_EVENT_INIT &&
	    plan->kind != VMM_STARTUP_EVENT_SIPI))
		return (false);
	if (plan->kind == VMM_STARTUP_EVENT_INIT)
		return (plan->vector == 0 &&
		    plan->nextrip == VMM_X86_INIT_NEXTRIP &&
		    plan->reset_nested == 1 && plan->reset_lapic == 1 &&
		    plan->retire_translation_residency == 1 &&
		    plan->startup_wait == !plan->bootstrap_processor);
	return (plan->bootstrap_processor == 0 &&
	    plan->nextrip == (uint64_t)plan->vector << VMM_X86_SIPI_SHIFT &&
	    plan->reset_nested == 0 && plan->reset_lapic == 0 &&
	    plan->retire_translation_residency == 0 && plan->startup_wait == 0);
}

static bool
startup_finalizer_empty(const struct vmm_x86_startup_finalizer *finalizer)
{

	return (finalizer != NULL && finalizer->ops.reset_nested == NULL &&
	    finalizer->ops.reset_lapic == NULL &&
	    finalizer->ops.retire_translation_residency == NULL &&
	    finalizer->ops.set_nextrip == NULL &&
	    finalizer->ops.publish_startup_wait == NULL &&
	    finalizer->plan.nextrip == 0 && finalizer->plan.kind == 0 &&
	    finalizer->plan.vector == 0 &&
	    finalizer->plan.bootstrap_processor == 0 &&
	    finalizer->plan.reset_nested == 0 &&
	    finalizer->plan.reset_lapic == 0 &&
	    finalizer->plan.retire_translation_residency == 0 &&
	    finalizer->plan.startup_wait == 0 &&
	    finalizer->plan.reserved8 == 0 &&
	    finalizer->arg == NULL && finalizer->storage_cookie == 0);
}

static bool
startup_finalizer_valid(const struct vmm_x86_startup_finalizer *finalizer)
{

	return (finalizer != NULL && finalizer->ops.reset_nested != NULL &&
	    finalizer->ops.reset_lapic != NULL &&
	    finalizer->ops.retire_translation_residency != NULL &&
	    finalizer->ops.set_nextrip != NULL &&
	    finalizer->ops.publish_startup_wait != NULL &&
	    finalizer->arg != NULL &&
	    startup_finalizer_plan_valid(&finalizer->plan) &&
	    finalizer->storage_cookie == (uintptr_t)finalizer);
}

static bool
startup_finalizer_plan_equal(
    const struct vmm_x86_startup_finalizer_plan *left,
    const struct vmm_x86_startup_finalizer_plan *right)
{

	return (left->nextrip == right->nextrip &&
	    left->kind == right->kind &&
	    left->vector == right->vector &&
	    left->bootstrap_processor == right->bootstrap_processor &&
	    left->reset_nested == right->reset_nested &&
	    left->reset_lapic == right->reset_lapic &&
	    left->retire_translation_residency ==
	    right->retire_translation_residency &&
	    left->startup_wait == right->startup_wait &&
	    left->reserved8 == right->reserved8);
}

int
vmm_x86_startup_finalizer_plan(
    const struct vmm_x86_startup_transaction_input *input,
    struct vmm_x86_startup_finalizer_plan *plan)
{
	struct vmm_x86_startup_finalizer_plan candidate;

	if (input == NULL || plan == NULL || input->reserved8 != 0 ||
	    input->reserved32 != 0 || input->bootstrap_processor > 1 ||
	    (input->kind != VMM_STARTUP_EVENT_INIT &&
	    input->kind != VMM_STARTUP_EVENT_SIPI) ||
	    (input->kind == VMM_STARTUP_EVENT_INIT && input->vector != 0) ||
	    (input->kind == VMM_STARTUP_EVENT_SIPI &&
	    input->bootstrap_processor != 0) ||
	    startup_finalizer_overlap(input, sizeof(*input), plan,
	    sizeof(*plan)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.kind = input->kind;
	candidate.vector = input->vector;
	candidate.bootstrap_processor = input->bootstrap_processor;
	if (input->kind == VMM_STARTUP_EVENT_INIT) {
		candidate.nextrip = VMM_X86_INIT_NEXTRIP;
		candidate.reset_nested = 1;
		candidate.reset_lapic = 1;
		candidate.retire_translation_residency = 1;
		candidate.startup_wait = !input->bootstrap_processor;
	} else {
		candidate.nextrip =
		    (uint64_t)input->vector << VMM_X86_SIPI_SHIFT;
	}
	*plan = candidate;
	return (0);
}

int
vmm_x86_startup_finalizer_init(
    const struct vmm_x86_startup_finalizer_ops *ops, void *arg,
    const struct vmm_x86_startup_finalizer_plan *plan,
    struct vmm_x86_startup_finalizer *finalizer)
{
	struct vmm_x86_startup_finalizer candidate;

	if (ops == NULL || arg == NULL || plan == NULL || finalizer == NULL ||
	    ops->reset_nested == NULL || ops->reset_lapic == NULL ||
	    ops->retire_translation_residency == NULL ||
	    ops->set_nextrip == NULL ||
	    ops->publish_startup_wait == NULL ||
	    !startup_finalizer_plan_valid(plan) ||
	    !startup_finalizer_empty(finalizer) || arg == ops || arg == plan ||
	    arg == finalizer || startup_finalizer_overlap(ops, sizeof(*ops),
	    plan, sizeof(*plan)) || startup_finalizer_overlap(ops, sizeof(*ops),
	    finalizer, sizeof(*finalizer)) ||
	    startup_finalizer_overlap(plan, sizeof(*plan), finalizer,
	    sizeof(*finalizer)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.ops = *ops;
	candidate.plan = *plan;
	candidate.arg = arg;
	candidate.storage_cookie = (uintptr_t)finalizer;
	*finalizer = candidate;
	return (0);
}

int
vmm_x86_startup_finalizer_check(
    const struct vmm_x86_startup_finalizer *finalizer,
    const struct vmm_x86_startup_transaction_input *input)
{
	struct vmm_x86_startup_finalizer_plan expected;
	int error;

	if (!startup_finalizer_valid(finalizer) || input == NULL ||
	    startup_finalizer_overlap(finalizer, sizeof(*finalizer), input,
	    sizeof(*input)))
		return (EINVAL);
	memset(&expected, 0, sizeof(expected));
	error = vmm_x86_startup_finalizer_plan(input, &expected);
	if (error != 0)
		return (error);
	return (startup_finalizer_plan_equal(&finalizer->plan, &expected) ?
	    0 : ESTALE);
}

bool
vmm_x86_startup_finalizer_consumed(
    const struct vmm_x86_startup_finalizer *finalizer)
{

	return (startup_finalizer_empty(finalizer));
}

void
vmm_x86_startup_finalizer_commit(
    struct vmm_x86_startup_finalizer *finalizer)
{
	struct vmm_x86_startup_finalizer bound;

#ifdef _KERNEL
	if (__predict_false(!startup_finalizer_valid(finalizer)))
		panic("%s: corrupt finalizer", __func__);
#else
	assert(startup_finalizer_valid(finalizer));
#endif
	bound = *finalizer;
	memset(finalizer, 0, sizeof(*finalizer));
	if (bound.plan.reset_nested != 0)
		bound.ops.reset_nested(bound.arg);
	if (bound.plan.reset_lapic != 0)
		bound.ops.reset_lapic(bound.arg);
	if (bound.plan.retire_translation_residency != 0)
		bound.ops.retire_translation_residency(bound.arg);
	bound.ops.set_nextrip(bound.arg, bound.plan.nextrip);
	bound.ops.publish_startup_wait(bound.arg,
	    bound.plan.startup_wait != 0);
}
