/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_hot_ept.h"

static int
nvmx_hot_ept_resume(struct vmx_nested_l0_continuation *continuation,
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
vmx_nested_hot_ept_publish(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id, uint64_t exit_sequence,
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_exit_information *hardware, uint64_t eptp,
    bool mode_based_execute,
    const struct vmx_nested_l0_continuation_ops *ops, void *arg,
    struct vmx_nested_ept_handoff_id *handoff_id)
{
	struct vmx_nested_ept_handoff_request request;
	struct vmx_nested_ept_handoff_id candidate_id;
	int error, original_error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    id == NULL || ops == NULL || ops->freeze == NULL ||
	    ops->resolve == NULL || handoff_id == NULL)
		return (EINVAL);

	/*
	 * Decode and validate every hardware-derived field before changing
	 * runtime ownership.  In particular, request_prepare() rejects an
	 * invalid EPTP, impossible qualification, or a launched/normalized
	 * exit image.
	 */
	error = vmx_nested_ept_handoff_request_prepare(capabilities, hardware,
	    eptp, mode_based_execute, &request);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_runtime_l0_exit(runtime, id);
	if (error != 0)
		return (error);
	error = vmx_nested_l0_continuation_begin(continuation, context,
	    runtime, id, exit_sequence, VMX_NESTED_EXIT_HANDLE_L0);
	if (error != 0) {
		if (vmx_nested_entry_runtime_l0_resume(runtime, id) != 0)
			return (EPROTO);
		return (error);
	}
	error = vmx_nested_context_publish_ept(context, &request,
	    &candidate_id);
	if (error != 0) {
		original_error = error;
		error = nvmx_hot_ept_resume(continuation, runtime, id, ops,
		    arg);
		if (error == 0)
			return (original_error);
		if (vmx_nested_l0_continuation_quarantine_hot(continuation,
		    runtime, id) != 0)
			return (EPROTO);
		return (EIO);
	}

	error = vmx_nested_l0_continuation_freeze(continuation, runtime, id,
	    ops, arg);
	if (error != 0) {
		original_error = error;
		/*
		 * An incomplete architecture rollback is already quarantined by
		 * continuation_freeze().  Retain the matching EPT request so an
		 * owner inspecting the failed vCPU can identify the exact exit.
		 */
		if (continuation->state ==
		    VMX_NESTED_L0_CONTINUATION_ABORTED)
			return (original_error);
		/*
		 * A clean rollback restored the hot VMCS02.  Resume L2 before
		 * canceling the value-only EPT request; if resume fails, keeping
		 * the request preserves rather than loses the exit provenance.
		 */
		error = nvmx_hot_ept_resume(continuation, runtime, id, ops,
		    arg);
		if (error != 0) {
			if (vmx_nested_l0_continuation_quarantine_hot(
			    continuation, runtime, id) != 0)
				return (EPROTO);
			return (EIO);
		}
		error = vmx_nested_context_cancel_ept(context, &candidate_id,
		    true);
		if (error != 0)
			return (EPROTO);
		return (original_error);
	}

	*handoff_id = candidate_id;
	return (0);
}
