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

#include "vmm_x86_startup_transaction.h"

static bool
vmm_x86_startup_transaction_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{

	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static int
vmm_x86_startup_transaction_input_validate(
    const struct vmm_x86_startup_transaction_input *input)
{

	if (input == NULL || input->reserved8 != 0 ||
	    input->reserved32 != 0 || input->bootstrap_processor > 1 ||
	    (input->kind != VMM_STARTUP_EVENT_INIT &&
	    input->kind != VMM_STARTUP_EVENT_SIPI) ||
	    (input->kind == VMM_STARTUP_EVENT_INIT && input->vector != 0) ||
	    (input->kind == VMM_STARTUP_EVENT_SIPI &&
	    input->bootstrap_processor != 0))
		return (EINVAL);
	return (0);
}

static bool
vmm_x86_startup_transaction_ops_equal(
    const struct vmm_x86_startup_transaction_ops *left,
    const struct vmm_x86_startup_transaction_ops *right)
{

	return (left->capture == right->capture && left->apply == right->apply &&
	    left->rollback == right->rollback &&
	    left->commit_event == right->commit_event &&
	    left->finalize == right->finalize);
}

bool
vmm_x86_startup_transaction_input_equal(
    const struct vmm_x86_startup_transaction_input *left,
    const struct vmm_x86_startup_transaction_input *right)
{

	return (left != NULL && right != NULL && left->kind == right->kind &&
	    left->vector == right->vector &&
	    left->bootstrap_processor == right->bootstrap_processor &&
	    left->reserved8 == right->reserved8 &&
	    left->reserved32 == right->reserved32);
}

enum vmm_x86_startup_transaction_outcome
vmm_x86_startup_transaction_result_classify(int error,
    const struct vmm_x86_startup_transaction_result *result)
{

	if (error < 0 || result == NULL || result->committed > 1 ||
	    result->rollback_complete > 1 || result->poisoned > 1 ||
	    result->reserved8 != 0 || result->reserved32 != 0)
		return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	if (error == 0) {
		if (result->committed == 1 && result->rollback_complete == 1 &&
		    result->poisoned == 0)
			return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_COMMITTED);
		return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	}
	if (result->committed != 0)
		return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
	if (result->poisoned != 0)
		return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_POISONED);
	if (result->rollback_complete == 1)
		return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_ROLLED_BACK);
	return (VMM_X86_STARTUP_TRANSACTION_OUTCOME_INVALID);
}

static bool
vmm_x86_startup_transaction_inputs_unchanged(
    const struct vmm_x86_startup_transaction_input *input,
    const struct vmm_x86_startup_transaction_input *expected,
    const struct vmm_x86_startup_transaction_ops *ops,
    const struct vmm_x86_startup_transaction_ops *ops_expected)
{

	return (vmm_x86_startup_transaction_input_equal(input, expected) &&
	    vmm_x86_startup_transaction_ops_equal(ops, ops_expected));
}

static int
vmm_x86_startup_transaction_error(int error)
{

	return (error < 0 ? EPROTO : error);
}

int
vmm_x86_startup_transaction_execute(
    const struct vmm_x86_startup_transaction_input *input,
    const struct vmm_x86_startup_transaction_ops *ops, void *arg,
    struct vmm_x86_startup_transaction_result *result)
{
	struct vmm_x86_startup_transaction_input input_expected;
	struct vmm_x86_startup_transaction_ops ops_expected;
	struct vmm_x86_startup_transaction_result candidate;
	bool contract_violation;
	int error, rollback_error;

	if (vmm_x86_startup_transaction_input_validate(input) != 0 ||
	    ops == NULL || result == NULL || ops->capture == NULL ||
	    ops->apply == NULL || ops->rollback == NULL ||
	    ops->commit_event == NULL || ops->finalize == NULL ||
	    vmm_x86_startup_transaction_overlap(input, sizeof(*input), ops,
	    sizeof(*ops)) ||
	    vmm_x86_startup_transaction_overlap(input, sizeof(*input), result,
	    sizeof(*result)) ||
	    vmm_x86_startup_transaction_overlap(ops, sizeof(*ops), result,
	    sizeof(*result)) || arg == input || arg == ops || arg == result)
		return (EINVAL);

	input_expected = *input;
	ops_expected = *ops;
	memset(&candidate, 0, sizeof(candidate));
	candidate.rollback_complete = 1;
	contract_violation = false;

	error = ops_expected.capture(arg, input);
	if (!vmm_x86_startup_transaction_inputs_unchanged(input,
	    &input_expected, ops, &ops_expected)) {
		candidate.rollback_complete = 0;
		candidate.poisoned = 1;
		*result = candidate;
		return (EPROTO);
	}
	if (error != 0) {
		*result = candidate;
		return (vmm_x86_startup_transaction_error(error));
	}

	error = ops_expected.apply(arg);
	if (!vmm_x86_startup_transaction_inputs_unchanged(input,
	    &input_expected, ops, &ops_expected)) {
		error = EPROTO;
		contract_violation = true;
	}
	if (error == 0) {
		error = ops_expected.commit_event(arg);
		if (!vmm_x86_startup_transaction_inputs_unchanged(input,
		    &input_expected, ops, &ops_expected)) {
			/* The event commit may already be irreversible. */
			candidate.rollback_complete = 0;
			candidate.poisoned = 1;
			*result = candidate;
			return (EPROTO);
		}
		if (error == 0) {
			ops_expected.finalize(arg);
			if (!vmm_x86_startup_transaction_inputs_unchanged(input,
			    &input_expected, ops, &ops_expected)) {
				candidate.rollback_complete = 0;
				candidate.poisoned = 1;
				*result = candidate;
				return (EPROTO);
			}
			candidate.committed = 1;
			*result = candidate;
			return (0);
		}
	}

	rollback_error = ops_expected.rollback(arg);
	if (rollback_error != 0 ||
	    !vmm_x86_startup_transaction_inputs_unchanged(input,
	    &input_expected, ops, &ops_expected)) {
		candidate.rollback_complete = 0;
		candidate.poisoned = 1;
		*result = candidate;
		return (EIO);
	}
	if (contract_violation)
		candidate.poisoned = 1;
	*result = candidate;
	return (vmm_x86_startup_transaction_error(error));
}
