/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#include "vmx_nested_continuation_handoff.h"
#include "vmx_nested_hot_exit.h"
#include "vmx_nested_internal.h"

int
vmx_nested_hot_exit_resume(
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg)
{
	int error;

	error = vmx_nested_l0_continuation_resolve(continuation, runtime, id,
	    ops, arg);
	if (error < 0)
		return (EPROTO);
	return (error);
}

int
vmx_nested_hot_exit_begin(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t exit_sequence,
    enum vmx_nested_exit_action action)
{
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    id == NULL || exit_sequence == 0 ||
	    (action != VMX_NESTED_EXIT_HANDLE_L0 &&
	    action != VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1))
		return (EINVAL);
	error = vmx_nested_entry_runtime_l0_exit(runtime, id);
	if (error != 0)
		return (error);
	error = vmx_nested_l0_continuation_begin(continuation, context,
	    runtime, id, exit_sequence, action);
	if (error != 0) {
		if (vmx_nested_entry_runtime_l0_resume(runtime, id) != 0)
			return (EPROTO);
		return (error);
	}
	return (0);
}

int
vmx_nested_hot_exit_freeze_publish(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg)
{
	struct vmx_nested_l0_continuation_ops ops_snapshot;
	struct vmx_nested_continuation_handoff_request request;
	int error, original_error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    id == NULL || ops == NULL || ops->freeze == NULL ||
	    ops->resolve == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_HOT ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_EXIT)
		return (EINVAL);
	if (context->internal.kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	ops_snapshot = *ops;
	ops = &ops_snapshot;

	error = vmx_nested_l0_continuation_freeze(continuation, runtime, id,
	    ops, arg);
	if (error != 0) {
		original_error = error;
		if (continuation->state ==
		    VMX_NESTED_L0_CONTINUATION_ABORTED)
			return (original_error);
		error = vmx_nested_hot_exit_resume(continuation, runtime, id, ops,
		    arg);
		if (error != 0) {
			if (vmx_nested_l0_continuation_quarantine_hot(
			    continuation, runtime, id) != 0)
				return (EPROTO);
			return (EIO);
		}
		return (original_error);
	}

	/*
	 * The cold state uniquely determines this request.  Publication has
	 * no callback and cannot fail after the validated freeze unless the
	 * state machine itself is inconsistent; preserve that state for
	 * diagnosis rather than pretending L2 is resumable.
	 */
	error = vmx_nested_continuation_handoff_request_build(continuation,
	    &request);
	if (error != 0)
		return (EPROTO);
	error = vmx_nested_internal_publish_continuation(&context->internal,
	    &request);
	if (error != 0)
		return (EPROTO);
	return (0);
}

int
vmx_nested_hot_exit_publish(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t exit_sequence,
    enum vmx_nested_exit_action action,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg)
{
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    id == NULL || ops == NULL || ops->freeze == NULL ||
	    ops->resolve == NULL || exit_sequence == 0 ||
	    (action != VMX_NESTED_EXIT_HANDLE_L0 &&
	    action != VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1))
		return (EINVAL);
	if (context->internal.kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	error = vmx_nested_hot_exit_begin(context, continuation, runtime, id,
	    exit_sequence, action);
	if (error != 0)
		return (error);
	return (vmx_nested_hot_exit_freeze_publish(context, continuation,
	    runtime, id, ops, arg));
}
