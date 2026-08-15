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

#include "vmx_nested_startup_dispatch.h"
#include "vmx_nested_state_range.h"

static bool
nvmxsd_claim_empty(const struct vmm_startup_event_claim *claim)
{

	return (claim->owner_id == 0 && claim->claim_id == 0 &&
	    claim->state_cookie == 0 && claim->storage_cookie == 0 &&
	    claim->vcpuid == 0 && claim->kind == VMM_STARTUP_EVENT_NONE &&
	    claim->vector == 0 && claim->active == 0 && claim->reserved8 == 0 &&
	    claim->reserved32 == 0);
}

static bool
nvmxsd_claim_valid(const struct vmm_startup_event_claim *claim)
{

	return (claim->owner_id != 0 && claim->claim_id != 0 &&
	    claim->state_cookie != 0 &&
	    claim->storage_cookie == (uintptr_t)claim && claim->active == 1 &&
	    claim->reserved8 == 0 && claim->reserved32 == 0 &&
	    claim->kind > VMM_STARTUP_EVENT_NONE &&
	    claim->kind < VMM_STARTUP_EVENT_KIND_LAST &&
	    (claim->kind != VMM_STARTUP_EVENT_INIT || claim->vector == 0));
}

static bool
nvmxsd_claim_equal(const struct vmm_startup_event_claim *left,
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

static bool
nvmxsd_dispatch_equal(const struct vmx_nested_startup_dispatch *left,
    const struct vmx_nested_startup_dispatch *right)
{

	return (nvmxsd_claim_equal(&left->claim, &right->claim) &&
	    vmx_nested_startup_transaction_equal(&left->transaction,
	    &right->transaction) &&
	    left->storage_cookie == right->storage_cookie &&
	    left->ops_cookie == right->ops_cookie &&
	    left->arg_cookie == right->arg_cookie && left->state == right->state);
}

static bool
nvmxsd_ops_valid(const struct vmx_nested_startup_dispatch_ops *ops)
{

	return (ops != NULL && ops->claim_begin != NULL &&
	    ops->claim_check != NULL && ops->claim_abort != NULL &&
	    ops->derive != NULL && ops->transaction.prepare_l0 != NULL &&
	    ops->transaction.apply_l0 != NULL &&
	    ops->transaction.commit_active_l2 != NULL &&
	    ops->transaction.claim_finish != NULL);
}

static bool
nvmxsd_ops_equal(const struct vmx_nested_startup_dispatch_ops *left,
    const struct vmx_nested_startup_dispatch_ops *right)
{

	return (left->claim_begin == right->claim_begin &&
	    left->claim_check == right->claim_check &&
	    left->claim_abort == right->claim_abort &&
	    left->derive == right->derive &&
	    left->transaction.prepare_l0 ==
	    right->transaction.prepare_l0 &&
	    left->transaction.apply_l0 == right->transaction.apply_l0 &&
	    left->transaction.commit_active_l2 ==
	    right->transaction.commit_active_l2 &&
	    left->transaction.claim_finish ==
	    right->transaction.claim_finish);
}

void
vmx_nested_startup_dispatch_init(
    struct vmx_nested_startup_dispatch *dispatch)
{

	if (dispatch != NULL) {
		memset(dispatch, 0, sizeof(*dispatch));
		vmx_nested_startup_transaction_init(&dispatch->transaction);
		dispatch->storage_cookie = (uintptr_t)dispatch;
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_EMPTY;
	}
}

int
vmx_nested_startup_dispatch_validate(
    const struct vmx_nested_startup_dispatch *dispatch)
{

	if (dispatch == NULL ||
	    dispatch->storage_cookie != (uintptr_t)dispatch ||
	    dispatch->state < VMX_NESTED_STARTUP_DISPATCH_EMPTY ||
	    dispatch->state >= VMX_NESTED_STARTUP_DISPATCH_STATE_LAST)
		return (EINVAL);
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_POISONED)
		return (0);
	if (vmx_nested_startup_transaction_validate(
	    &dispatch->transaction) != 0)
		return (EPROTO);
	switch (dispatch->state) {
	case VMX_NESTED_STARTUP_DISPATCH_EMPTY:
		return (nvmxsd_claim_empty(&dispatch->claim) &&
		    dispatch->ops_cookie == 0 && dispatch->arg_cookie == 0 &&
		    dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_EMPTY ? 0 : EPROTO);
	case VMX_NESTED_STARTUP_DISPATCH_CLAIMED:
		return (nvmxsd_claim_valid(&dispatch->claim) &&
		    dispatch->ops_cookie != 0 && dispatch->arg_cookie != 0 &&
		    dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_EMPTY ? 0 : EPROTO);
	case VMX_NESTED_STARTUP_DISPATCH_ACTIVE:
		return (nvmxsd_claim_valid(&dispatch->claim) &&
		    dispatch->ops_cookie != 0 && dispatch->arg_cookie != 0 &&
		    (dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_PLANNED ||
		    dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_RETAINED ||
		    dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING) ? 0 : EPROTO);
	default:
		return (EINVAL);
	}
}

static int
nvmxsd_abort(struct vmx_nested_startup_dispatch *dispatch,
    const struct vmx_nested_startup_dispatch_ops *ops, void *arg)
{
	struct vmx_nested_startup_dispatch_ops ops_before;
	struct vmx_nested_startup_transaction transaction_before;
	struct vmm_startup_event_claim claim_before;
	uintptr_t storage_cookie;
	uintptr_t ops_cookie, arg_cookie;
	enum vmx_nested_startup_dispatch_state state;
	int error;

	ops_before = *ops;
	claim_before = dispatch->claim;
	transaction_before = dispatch->transaction;
	storage_cookie = dispatch->storage_cookie;
	ops_cookie = dispatch->ops_cookie;
	arg_cookie = dispatch->arg_cookie;
	state = dispatch->state;
	error = ops->claim_abort(arg, &dispatch->claim);
	if (!nvmxsd_ops_equal(ops, &ops_before) ||
	    !vmx_nested_startup_transaction_equal(&dispatch->transaction,
	    &transaction_before) ||
	    dispatch->storage_cookie != storage_cookie ||
	    dispatch->ops_cookie != ops_cookie ||
	    dispatch->arg_cookie != arg_cookie ||
	    dispatch->state != state) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	if (error != 0) {
		if (!nvmxsd_claim_equal(&dispatch->claim, &claim_before)) {
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
			return (EPROTO);
		}
		if (error < 0) {
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
			return (EPROTO);
		}
		return (error);
	}
	if (!nvmxsd_claim_empty(&dispatch->claim)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	return (0);
}

static int
nvmxsd_claim(struct vmx_nested_startup_dispatch *dispatch,
    const struct vmx_nested_startup_dispatch_ops *ops, void *arg)
{
	struct vmx_nested_startup_dispatch_ops ops_before;
	struct vmx_nested_startup_transaction transaction_before;
	struct vmm_startup_event_claim before;
	uintptr_t storage_cookie;
	uintptr_t ops_cookie, arg_cookie;
	enum vmx_nested_startup_dispatch_state state;
	int error;

	ops_before = *ops;
	before = dispatch->claim;
	transaction_before = dispatch->transaction;
	storage_cookie = dispatch->storage_cookie;
	ops_cookie = dispatch->ops_cookie;
	arg_cookie = dispatch->arg_cookie;
	state = dispatch->state;
	error = ops->claim_begin(arg, &dispatch->claim);
	if (!nvmxsd_ops_equal(ops, &ops_before) ||
	    !vmx_nested_startup_transaction_equal(&dispatch->transaction,
	    &transaction_before) ||
	    dispatch->storage_cookie != storage_cookie ||
	    dispatch->ops_cookie != ops_cookie ||
	    dispatch->arg_cookie != arg_cookie ||
	    dispatch->state != state) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	if (error != 0) {
		if (!nvmxsd_claim_equal(&dispatch->claim, &before)) {
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
			return (EPROTO);
		}
		if (error < 0) {
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
			return (EPROTO);
		}
		return (error);
	}
	if (!nvmxsd_claim_valid(&dispatch->claim)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	dispatch->ops_cookie = (uintptr_t)ops;
	dispatch->arg_cookie = (uintptr_t)arg;
	dispatch->state = VMX_NESTED_STARTUP_DISPATCH_CLAIMED;
	return (0);
}

static int
nvmxsd_plan(struct vmx_nested_startup_dispatch *dispatch,
    const struct vmx_nested_startup_dispatch_ops *ops, void *arg)
{
	struct vmx_nested_startup_dispatch before;
	struct vmx_nested_startup_dispatch_ops ops_before;
	struct vmx_nested_startup_input input;
	int error;

	before = *dispatch;
	ops_before = *ops;
	memset(&input, 0, sizeof(input));
	error = ops->derive(arg, &dispatch->claim, &input);
	if (!nvmxsd_ops_equal(ops, &ops_before) ||
	    !nvmxsd_dispatch_equal(dispatch, &before)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	if (error != 0) {
		if (error < 0) {
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
			return (EPROTO);
		}
		return (error);
	}
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_CLAIMED)
		error = vmx_nested_startup_transaction_begin(
		    &dispatch->transaction, &dispatch->claim, &input);
	else
		error = vmx_nested_startup_transaction_replan(
		    &dispatch->transaction, &dispatch->claim, &input);
	if (error == 0)
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_ACTIVE;
	return (error);
}

int
vmx_nested_startup_dispatch_step(
    struct vmx_nested_startup_dispatch *dispatch,
    const struct vmx_nested_startup_dispatch_ops *ops, void *arg,
    enum vmx_nested_startup_dispatch_result *result)
{
	struct vmx_nested_startup_dispatch_ops ops_before;
	int error;

	if (dispatch == NULL || !nvmxsd_ops_valid(ops) || arg == NULL ||
	    result == NULL ||
	    vmx_nested_state_ranges_overlap(dispatch, sizeof(*dispatch), ops,
	    sizeof(*ops)) || vmx_nested_state_ranges_overlap(dispatch,
	    sizeof(*dispatch), result, sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), result,
	    sizeof(*result)) ||
	    vmx_nested_startup_dispatch_validate(dispatch) != 0)
		return (EINVAL);
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_POISONED)
		return (EPROTO);
	ops_before = *ops;
	if (dispatch->state != VMX_NESTED_STARTUP_DISPATCH_EMPTY &&
	    (dispatch->ops_cookie != (uintptr_t)ops ||
	    dispatch->arg_cookie != (uintptr_t)arg))
		return (ESTALE);
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_EMPTY) {
		error = nvmxsd_claim(dispatch, ops, arg);
		if (error == ENOENT) {
			*result = VMX_NESTED_STARTUP_DISPATCH_IDLE;
			return (0);
		}
		if (error != 0)
			return (error);
	}
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_CLAIMED ||
	    dispatch->transaction.state ==
	    VMX_NESTED_STARTUP_TRANSACTION_RETAINED) {
		error = nvmxsd_plan(dispatch, ops, arg);
		if (error == EAGAIN || error == EBUSY) {
			*result = VMX_NESTED_STARTUP_DISPATCH_RETAINED;
			return (0);
		}
		if (error != 0)
			return (error);
	}
	if (dispatch->transaction.state ==
	    VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING)
		error = vmx_nested_startup_transaction_release(
		    &dispatch->transaction, &dispatch->claim,
		    &ops_before.transaction, arg);
	else
		error = vmx_nested_startup_transaction_resolve(
		    &dispatch->transaction, &dispatch->claim,
		    &ops_before.transaction, arg);
	if (!nvmxsd_ops_equal(ops, &ops_before)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	if (error == EAGAIN || error == EBUSY) {
		*result = VMX_NESTED_STARTUP_DISPATCH_RETAINED;
		return (0);
	}
	if (error != 0) {
		if (dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_POISONED)
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (error);
	}
	if (dispatch->transaction.state !=
	    VMX_NESTED_STARTUP_TRANSACTION_COMPLETE ||
	    !nvmxsd_claim_empty(&dispatch->claim)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	vmx_nested_startup_dispatch_init(dispatch);
	*result = VMX_NESTED_STARTUP_DISPATCH_CONSUMED;
	return (0);
}

int
vmx_nested_startup_dispatch_cleanup_check(
    const struct vmx_nested_startup_dispatch *dispatch,
    const struct vmx_nested_startup_dispatch_ops *ops, void *arg)
{
	struct vmx_nested_startup_dispatch before;
	struct vmx_nested_startup_dispatch_ops ops_before;
	int error;

	if (dispatch == NULL || !nvmxsd_ops_valid(ops) || arg == NULL ||
	    vmx_nested_state_ranges_overlap(dispatch, sizeof(*dispatch), ops,
	    sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_startup_dispatch_validate(dispatch);
	if (error != 0)
		return (error);
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_POISONED)
		return (EPROTO);
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_EMPTY)
		return (0);
	if (dispatch->ops_cookie != (uintptr_t)ops ||
	    dispatch->arg_cookie != (uintptr_t)arg)
		return (ESTALE);
	before = *dispatch;
	ops_before = *ops;
	error = ops->claim_check(arg, &dispatch->claim);
	if (!nvmxsd_ops_equal(ops, &ops_before) ||
	    !nvmxsd_dispatch_equal(dispatch, &before))
		return (EPROTO);
	return (error < 0 ? EPROTO : error);
}

int
vmx_nested_startup_dispatch_cleanup(
    struct vmx_nested_startup_dispatch *dispatch,
    const struct vmx_nested_startup_dispatch_ops *ops, void *arg)
{
	struct vmx_nested_startup_dispatch_ops ops_before;
	int error;

	if (dispatch == NULL || !nvmxsd_ops_valid(ops) || arg == NULL ||
	    vmx_nested_state_ranges_overlap(dispatch, sizeof(*dispatch), ops,
	    sizeof(*ops)) ||
	    vmx_nested_startup_dispatch_validate(dispatch) != 0)
		return (EINVAL);
	if (dispatch->state == VMX_NESTED_STARTUP_DISPATCH_POISONED)
		return (EPROTO);
	if (dispatch->state != VMX_NESTED_STARTUP_DISPATCH_EMPTY &&
	    (dispatch->ops_cookie != (uintptr_t)ops ||
	    dispatch->arg_cookie != (uintptr_t)arg))
		return (ESTALE);
	ops_before = *ops;
	switch (dispatch->state) {
	case VMX_NESTED_STARTUP_DISPATCH_EMPTY:
		return (0);
	case VMX_NESTED_STARTUP_DISPATCH_CLAIMED:
		error = nvmxsd_abort(dispatch, ops, arg);
		break;
	case VMX_NESTED_STARTUP_DISPATCH_ACTIVE:
		switch (dispatch->transaction.state) {
		case VMX_NESTED_STARTUP_TRANSACTION_PLANNED:
		case VMX_NESTED_STARTUP_TRANSACTION_RETAINED:
			error = nvmxsd_abort(dispatch, ops, arg);
			break;
		case VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING:
			error = vmx_nested_startup_transaction_release(
			    &dispatch->transaction, &dispatch->claim,
			    &ops_before.transaction, arg);
			break;
		default:
			return (EBUSY);
		}
		break;
	case VMX_NESTED_STARTUP_DISPATCH_POISONED:
		return (EPROTO);
	default:
		return (EINVAL);
	}
	if (error != 0) {
		if (dispatch->transaction.state ==
		    VMX_NESTED_STARTUP_TRANSACTION_POISONED)
			dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
	}
	if (!nvmxsd_ops_equal(ops, &ops_before)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	if (!nvmxsd_claim_empty(&dispatch->claim)) {
		dispatch->state = VMX_NESTED_STARTUP_DISPATCH_POISONED;
		return (EPROTO);
	}
	vmx_nested_startup_dispatch_init(dispatch);
	return (0);
}
