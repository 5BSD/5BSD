/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_startup_transaction.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_l0_startup_preflight_validate(
    const struct vmx_nested_l0_startup_preflight *preflight)
{

	if (preflight == NULL ||
	    preflight->version != VMX_NESTED_L0_STARTUP_PREFLIGHT_VERSION ||
	    (preflight->kind != VMX_NESTED_STARTUP_INIT &&
	    preflight->kind != VMX_NESTED_STARTUP_SIPI))
		return (EINVAL);
	if ((preflight->blockers & ~VMX_NESTED_L0_STARTUP_BLOCKERS) != 0 ||
	    preflight->context_generation == 0)
		return (EPROTO);
	if (preflight->kind == VMX_NESTED_STARTUP_INIT &&
	    preflight->context_generation == UINT64_MAX)
		return (EOVERFLOW);
	return (preflight->blockers == 0 ? 0 : EBUSY);
}

static bool
nvmx_startup_transaction_empty(
    const struct vmx_nested_startup_transaction *transaction)
{

	return (transaction->plan.kind == VMX_NESTED_STARTUP_NONE &&
	    transaction->plan.action == VMX_NESTED_STARTUP_ACTION_NONE &&
	    transaction->plan.exit_reason == 0 &&
	    transaction->plan.exit_qualification == 0 &&
	    transaction->plan.vector == 0 &&
	    !transaction->plan.active_l2 &&
	    !transaction->plan.consume_claim && !transaction->plan.discard_mtf &&
	    transaction->owner_id == 0 && transaction->claim_id == 0 &&
	    transaction->state_cookie == 0 &&
	    transaction->claim_cookie == 0 && transaction->storage_cookie == 0 &&
	    transaction->vcpuid == 0);
}

static int
nvmx_startup_claim_validate(const struct vmm_startup_event_claim *claim)
{

	if (claim == NULL || claim->owner_id == 0 || claim->claim_id == 0 ||
	    claim->state_cookie == 0 ||
	    claim->storage_cookie != (uintptr_t)claim || claim->active != 1 ||
	    claim->reserved8 != 0 || claim->reserved32 != 0 ||
	    claim->kind <= VMM_STARTUP_EVENT_NONE ||
	    claim->kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (claim->kind == VMM_STARTUP_EVENT_INIT && claim->vector != 0))
		return (EINVAL);
	return (0);
}

static bool
nvmx_startup_claim_empty(const struct vmm_startup_event_claim *claim)
{

	return (claim->owner_id == 0 && claim->claim_id == 0 &&
	    claim->state_cookie == 0 && claim->storage_cookie == 0 &&
	    claim->vcpuid == 0 && claim->kind == 0 && claim->vector == 0 &&
	    claim->active == 0 && claim->reserved8 == 0 &&
	    claim->reserved32 == 0);
}

static bool
nvmx_startup_claim_equal(const struct vmm_startup_event_claim *left,
    const struct vmm_startup_event_claim *right)
{

	return (left->owner_id == right->owner_id &&
	    left->claim_id == right->claim_id &&
	    left->state_cookie == right->state_cookie &&
	    left->storage_cookie == right->storage_cookie &&
	    left->vcpuid == right->vcpuid && left->kind == right->kind &&
	    left->vector == right->vector && left->active == right->active &&
	    left->reserved8 == right->reserved8 &&
	    left->reserved32 == right->reserved32);
}

bool
vmx_nested_startup_transaction_equal(
    const struct vmx_nested_startup_transaction *left,
    const struct vmx_nested_startup_transaction *right)
{

	return (left != NULL && right != NULL &&
	    left->plan.kind == right->plan.kind &&
	    left->plan.action == right->plan.action &&
	    left->plan.exit_reason == right->plan.exit_reason &&
	    left->plan.exit_qualification == right->plan.exit_qualification &&
	    left->plan.vector == right->plan.vector &&
	    left->plan.active_l2 == right->plan.active_l2 &&
	    left->plan.consume_claim == right->plan.consume_claim &&
	    left->plan.discard_mtf == right->plan.discard_mtf &&
	    left->owner_id == right->owner_id &&
	    left->claim_id == right->claim_id &&
	    left->state_cookie == right->state_cookie &&
	    left->claim_cookie == right->claim_cookie &&
	    left->storage_cookie == right->storage_cookie &&
	    left->vcpuid == right->vcpuid && left->state == right->state);
}

static bool
nvmx_startup_claim_matches(
    const struct vmx_nested_startup_transaction *transaction,
    const struct vmm_startup_event_claim *claim)
{

	return (nvmx_startup_claim_validate(claim) == 0 &&
	    transaction->owner_id == claim->owner_id &&
	    transaction->claim_id == claim->claim_id &&
	    transaction->state_cookie == claim->state_cookie &&
	    transaction->claim_cookie == (uintptr_t)claim &&
	    transaction->vcpuid == claim->vcpuid &&
	    transaction->plan.kind == (claim->kind == VMM_STARTUP_EVENT_INIT ?
	    VMX_NESTED_STARTUP_INIT : VMX_NESTED_STARTUP_SIPI) &&
	    transaction->plan.vector == claim->vector);
}

static bool
nvmx_startup_ops_equal(
    const struct vmx_nested_startup_transaction_ops *left,
    const struct vmx_nested_startup_transaction_ops *right)
{

	return (left->prepare_l0 == right->prepare_l0 &&
	    left->apply_l0 == right->apply_l0 &&
	    left->commit_active_l2 == right->commit_active_l2 &&
	    left->claim_finish == right->claim_finish);
}

void
vmx_nested_startup_transaction_init(
    struct vmx_nested_startup_transaction *transaction)
{

	if (transaction != NULL) {
		memset(transaction, 0, sizeof(*transaction));
		transaction->state = VMX_NESTED_STARTUP_TRANSACTION_EMPTY;
	}
}

static int
nvmx_startup_transaction_validate_storage(
    const struct vmx_nested_startup_transaction *transaction,
    uintptr_t storage_cookie)
{

	if (transaction == NULL ||
	    transaction->state < VMX_NESTED_STARTUP_TRANSACTION_EMPTY ||
	    transaction->state >= VMX_NESTED_STARTUP_TRANSACTION_STATE_LAST)
		return (EINVAL);
	if (transaction->state == VMX_NESTED_STARTUP_TRANSACTION_EMPTY)
		return (nvmx_startup_transaction_empty(transaction) ? 0 : EPROTO);
	if (transaction->owner_id == 0 || transaction->claim_id == 0 ||
	    transaction->state_cookie == 0 ||
	    transaction->claim_cookie == 0 ||
	    transaction->storage_cookie != storage_cookie ||
	    vmx_nested_startup_plan_validate(&transaction->plan) != 0)
		return (EPROTO);
	return (0);
}

int
vmx_nested_startup_transaction_validate(
    const struct vmx_nested_startup_transaction *transaction)
{

	return (nvmx_startup_transaction_validate_storage(transaction,
	    (uintptr_t)transaction));
}

int
vmx_nested_startup_transaction_begin(
    struct vmx_nested_startup_transaction *transaction,
    struct vmm_startup_event_claim *claim,
    const struct vmx_nested_startup_input *input)
{
	struct vmx_nested_startup_transaction candidate;
	int error;

	if (transaction == NULL || claim == NULL || input == NULL ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    claim, sizeof(*claim)) ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    input, sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(claim, sizeof(*claim), input,
	    sizeof(*input)) ||
	    vmx_nested_startup_transaction_validate(transaction) != 0 ||
	    transaction->state != VMX_NESTED_STARTUP_TRANSACTION_EMPTY ||
	    nvmx_startup_claim_validate(claim) != 0)
		return (EINVAL);
	if ((claim->kind == VMM_STARTUP_EVENT_INIT &&
	    (input->kind != VMX_NESTED_STARTUP_INIT || input->vector != 0)) ||
	    (claim->kind == VMM_STARTUP_EVENT_SIPI &&
	    (input->kind != VMX_NESTED_STARTUP_SIPI ||
	    input->vector != claim->vector)))
		return (ESTALE);

	memset(&candidate, 0, sizeof(candidate));
	error = vmx_nested_startup_plan(input, &candidate.plan);
	if (error != 0)
		return (error);
	candidate.owner_id = claim->owner_id;
	candidate.claim_id = claim->claim_id;
	candidate.state_cookie = claim->state_cookie;
	candidate.claim_cookie = (uintptr_t)claim;
	candidate.storage_cookie = (uintptr_t)transaction;
	candidate.vcpuid = claim->vcpuid;
	candidate.state = VMX_NESTED_STARTUP_TRANSACTION_PLANNED;
	if (nvmx_startup_transaction_validate_storage(&candidate,
	    (uintptr_t)transaction) != 0)
		return (EPROTO);
	*transaction = candidate;
	return (0);
}

int
vmx_nested_startup_transaction_replan(
    struct vmx_nested_startup_transaction *transaction,
    struct vmm_startup_event_claim *claim,
    const struct vmx_nested_startup_input *input)
{
	struct vmx_nested_startup_transaction candidate;
	int error;

	if (transaction == NULL || claim == NULL || input == NULL ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    claim, sizeof(*claim)) ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    input, sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(claim, sizeof(*claim), input,
	    sizeof(*input)) ||
	    vmx_nested_startup_transaction_validate(transaction) != 0 ||
	    transaction->state != VMX_NESTED_STARTUP_TRANSACTION_RETAINED ||
	    !nvmx_startup_claim_matches(transaction, claim))
		return (EINVAL);
	if ((claim->kind == VMM_STARTUP_EVENT_INIT &&
	    (input->kind != VMX_NESTED_STARTUP_INIT || input->vector != 0)) ||
	    (claim->kind == VMM_STARTUP_EVENT_SIPI &&
	    (input->kind != VMX_NESTED_STARTUP_SIPI ||
	    input->vector != claim->vector)))
		return (ESTALE);

	candidate = *transaction;
	error = vmx_nested_startup_plan(input, &candidate.plan);
	if (error != 0)
		return (error);
	candidate.state = VMX_NESTED_STARTUP_TRANSACTION_PLANNED;
	if (nvmx_startup_transaction_validate_storage(&candidate,
	    (uintptr_t)transaction) != 0)
		return (EPROTO);
	*transaction = candidate;
	return (0);
}

static int
nvmx_startup_side_effect(
    const struct vmx_nested_startup_transaction *transaction,
    const struct vmx_nested_startup_transaction_ops *ops, void *arg,
    bool *poisoned)
{
	enum vmx_nested_startup_machine_disposition disposition;
	int error;

	*poisoned = false;

	switch (transaction->plan.action) {
	case VMX_NESTED_STARTUP_ACTION_APPLY_L0:
		error = -1;
		disposition = ops->apply_l0(arg, transaction->plan.kind,
		    transaction->plan.vector, &error);
		if (disposition == VMX_NESTED_STARTUP_MACHINE_COMMITTED &&
		    error == 0)
			return (0);
		if (disposition == VMX_NESTED_STARTUP_MACHINE_RETRY &&
		    error > 0)
			return (error);
		*poisoned = true;
		return (EPROTO);
	case VMX_NESTED_STARTUP_ACTION_REFLECT_L1:
		return (ops->commit_active_l2(arg, &transaction->plan));
	case VMX_NESTED_STARTUP_ACTION_DISCARD:
		return (transaction->plan.active_l2 ?
		    ops->commit_active_l2(arg, &transaction->plan) : 0);
	case VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY:
		return (0);
	default:
		return (EINVAL);
	}
}

int
vmx_nested_startup_transaction_execute(
    struct vmx_nested_startup_transaction *transaction,
    struct vmm_startup_event_claim *claim,
    const struct vmx_nested_startup_transaction_ops *ops, void *arg)
{
	struct vmx_nested_startup_transaction expected;
	struct vmx_nested_startup_transaction_ops ops_snapshot;
	struct vmm_startup_event_claim claim_expected;
	bool side_poisoned;
	int error;

	if (transaction == NULL || claim == NULL || ops == NULL ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    claim, sizeof(*claim)) ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(claim, sizeof(*claim), ops,
	    sizeof(*ops)) ||
	    vmx_nested_startup_transaction_validate(transaction) != 0 ||
	    transaction->state != VMX_NESTED_STARTUP_TRANSACTION_PLANNED ||
	    !nvmx_startup_claim_matches(transaction, claim))
		return (EINVAL);
	if ((transaction->plan.action == VMX_NESTED_STARTUP_ACTION_APPLY_L0 &&
	    (ops->prepare_l0 == NULL || ops->apply_l0 == NULL)) ||
	    ((transaction->plan.action ==
	    VMX_NESTED_STARTUP_ACTION_REFLECT_L1 ||
	    (transaction->plan.action == VMX_NESTED_STARTUP_ACTION_DISCARD &&
	    transaction->plan.active_l2)) &&
	    ops->commit_active_l2 == NULL))
		return (EINVAL);
	ops_snapshot = *ops;

	if (transaction->plan.action ==
	    VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY) {
		/*
		 * Keep the exact claim resident.  Releasing and reacquiring it would
		 * create both a self-notification loop and an ordering window against
		 * a newer INIT or SIPI.  The frozen target replans this same claim
		 * after the blocking architectural state changes.
		 */
		transaction->state = VMX_NESTED_STARTUP_TRANSACTION_RETAINED;
		return (0);
	}
	expected = *transaction;
	expected.state = VMX_NESTED_STARTUP_TRANSACTION_EXECUTING;
	claim_expected = *claim;
	transaction->state = VMX_NESTED_STARTUP_TRANSACTION_EXECUTING;
	if (transaction->plan.action ==
	    VMX_NESTED_STARTUP_ACTION_APPLY_L0) {
		error = ops_snapshot.prepare_l0(arg, transaction->plan.kind,
		    transaction->plan.vector);
		if (!vmx_nested_startup_transaction_equal(transaction,
		    &expected) || !nvmx_startup_claim_equal(claim,
		    &claim_expected) || !nvmx_startup_ops_equal(ops,
		    &ops_snapshot)) {
			transaction->state =
			    VMX_NESTED_STARTUP_TRANSACTION_POISONED;
			return (EPROTO);
		}
		if (error != 0) {
			if (error < 0) {
				transaction->state =
				    VMX_NESTED_STARTUP_TRANSACTION_POISONED;
				return (EPROTO);
			}
			transaction->state =
			    VMX_NESTED_STARTUP_TRANSACTION_PLANNED;
			return (error);
		}
	}
	error = nvmx_startup_side_effect(transaction, &ops_snapshot, arg,
	    &side_poisoned);
	if (!vmx_nested_startup_transaction_equal(transaction, &expected) ||
	    !nvmx_startup_claim_equal(claim, &claim_expected) ||
	    !nvmx_startup_ops_equal(ops, &ops_snapshot)) {
		transaction->state = VMX_NESTED_STARTUP_TRANSACTION_POISONED;
		return (EPROTO);
	}
	if (side_poisoned) {
		transaction->state = VMX_NESTED_STARTUP_TRANSACTION_POISONED;
		return (EPROTO);
	}
	if (error != 0) {
		if (error < 0) {
			transaction->state =
			    VMX_NESTED_STARTUP_TRANSACTION_POISONED;
			return (EPROTO);
		}
		transaction->state = VMX_NESTED_STARTUP_TRANSACTION_PLANNED;
		return (error);
	}
	transaction->state = VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING;
	return (0);
}

int
vmx_nested_startup_transaction_release(
    struct vmx_nested_startup_transaction *transaction,
    struct vmm_startup_event_claim *claim,
    const struct vmx_nested_startup_transaction_ops *ops, void *arg)
{
	struct vmx_nested_startup_transaction expected;
	struct vmx_nested_startup_transaction_ops ops_snapshot;
	struct vmm_startup_event_claim claim_expected;
	int error;

	if (transaction == NULL || claim == NULL || ops == NULL ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    claim, sizeof(*claim)) ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(claim, sizeof(*claim), ops,
	    sizeof(*ops)) ||
	    vmx_nested_startup_transaction_validate(transaction) != 0 ||
	    transaction->state !=
	    VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING ||
	    !nvmx_startup_claim_matches(transaction, claim))
		return (EINVAL);
	if (ops->claim_finish == NULL)
		return (EINVAL);
	ops_snapshot = *ops;
	expected = *transaction;
	expected.state = VMX_NESTED_STARTUP_TRANSACTION_RELEASING;
	claim_expected = *claim;
	transaction->state = VMX_NESTED_STARTUP_TRANSACTION_RELEASING;
	error = ops_snapshot.claim_finish(arg, claim);
	if (!vmx_nested_startup_transaction_equal(transaction, &expected) ||
	    !nvmx_startup_ops_equal(ops, &ops_snapshot) ||
	    (error == 0 && !nvmx_startup_claim_empty(claim)) ||
	    (error != 0 && !nvmx_startup_claim_equal(claim,
	    &claim_expected))) {
		/* Callback mutation makes ownership outcome unknowable. */
		transaction->state = VMX_NESTED_STARTUP_TRANSACTION_POISONED;
		return (EPROTO);
	}
	if (error != 0) {
		if (error < 0) {
			transaction->state =
			    VMX_NESTED_STARTUP_TRANSACTION_POISONED;
			return (EPROTO);
		}
		/*
		 * The side effect was completed by execute(), not by this release
		 * callback.  An unchanged failed claim remains exactly owned, so
		 * retry only claim_finish without executing the side effect again.
		 */
		transaction->state =
		    VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING;
		return (error);
	}
	transaction->state = VMX_NESTED_STARTUP_TRANSACTION_COMPLETE;
	return (0);
}

int
vmx_nested_startup_transaction_resolve(
    struct vmx_nested_startup_transaction *transaction,
    struct vmm_startup_event_claim *claim,
    const struct vmx_nested_startup_transaction_ops *ops, void *arg)
{
	struct vmx_nested_startup_transaction_ops ops_snapshot;
	int error;

	if (transaction == NULL || claim == NULL || ops == NULL ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    claim, sizeof(*claim)) ||
	    vmx_nested_state_ranges_overlap(transaction, sizeof(*transaction),
	    ops, sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(claim, sizeof(*claim), ops,
	    sizeof(*ops)) || ops->claim_finish == NULL)
		return (EINVAL);
	ops_snapshot = *ops;
	error = vmx_nested_startup_transaction_execute(transaction, claim,
	    &ops_snapshot,
	    arg);
	if (error != 0)
		return (error);
	if (transaction->state == VMX_NESTED_STARTUP_TRANSACTION_RETAINED)
		return (EAGAIN);
	return (vmx_nested_startup_transaction_release(transaction, claim,
	    &ops_snapshot, arg));
}
