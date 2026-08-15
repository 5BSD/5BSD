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

#include "vmx_nested_internal.h"
#include "vmx_nested_state_range.h"

void
vmx_nested_internal_init(struct vmx_nested_internal *internal)
{

	if (internal != NULL)
		memset(internal, 0, sizeof(*internal));
}

int
vmx_nested_internal_publish_ept(struct vmx_nested_internal *internal,
    const struct vmx_nested_ept_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	vmx_nested_ept_handoff_init(&internal->operation.ept);
	error = vmx_nested_ept_handoff_publish(&internal->operation.ept,
	    request);
	if (error == 0)
		internal->kind = VMX_NESTED_INTERNAL_EPT;
	return (error);
}

int
vmx_nested_internal_publish_instruction(struct vmx_nested_internal *internal,
    const struct vmx_nested_instruction_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	vmx_nested_instruction_handoff_init(&internal->operation.instruction);
	error = vmx_nested_instruction_handoff_publish(
	    &internal->operation.instruction, request);
	if (error == 0)
		internal->kind = VMX_NESTED_INTERNAL_INSTRUCTION;
	return (error);
}

int
vmx_nested_internal_publish_vmexit(struct vmx_nested_internal *internal,
    const struct vmx_nested_vmexit_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	vmx_nested_vmexit_handoff_init(&internal->operation.vmexit);
	error = vmx_nested_vmexit_handoff_publish(
	    &internal->operation.vmexit, request);
	if (error == 0)
		internal->kind = VMX_NESTED_INTERNAL_VMEXIT;
	return (error);
}

int
vmx_nested_internal_publish_vmentry_reject(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	vmx_nested_vmentry_handoff_init(&internal->operation.vmentry);
	error = vmx_nested_vmentry_handoff_publish(
	    &internal->operation.vmentry, request);
	if (error == 0)
		internal->kind = VMX_NESTED_INTERNAL_VMENTRY_REJECT;
	return (error);
}

int
vmx_nested_internal_publish_late_vmentry(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	vmx_nested_vmentry_handoff_init(&internal->operation.vmentry);
	error = vmx_nested_vmentry_handoff_publish(
	    &internal->operation.vmentry, request);
	if (error == 0)
		internal->kind = VMX_NESTED_INTERNAL_LATE_VMENTRY;
	return (error);
}

int
vmx_nested_internal_publish_continuation(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_continuation_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	vmx_nested_continuation_handoff_init(
	    &internal->operation.continuation);
	error = vmx_nested_continuation_handoff_publish(
	    &internal->operation.continuation, request);
	if (error == 0)
		internal->kind = VMX_NESTED_INTERNAL_CONTINUATION;
	return (error);
}

int
vmx_nested_internal_publish_refreeze(struct vmx_nested_internal *internal,
    const struct vmx_nested_refreeze_request *request)
{
	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)) ||
	    vmx_nested_refreeze_request_value_validate(request) != 0)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_NONE)
		return (EBUSY);
	internal->operation.refreeze = *request;
	internal->kind = VMX_NESTED_INTERNAL_REFREEZE;
	return (0);
}

int
vmx_nested_internal_handle_ept(struct vmx_nested_internal *internal,
    const struct vmx_nested_ept_handoff_id *id,
    const struct vmx_nested_ept_memory *memory,
    const struct vmx_nested_ept_handoff_ops *ops, void *arg)
{

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_EPT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	return (vmx_nested_ept_handoff_handle(&internal->operation.ept, id,
	    memory, ops, arg));
}

int
vmx_nested_internal_handle_instruction(struct vmx_nested_internal *internal,
    const struct vmx_nested_instruction_handoff_id *id,
    const struct vmx_nested_instruction_handoff_ops *ops, void *arg)
{

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_INSTRUCTION)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	return (vmx_nested_instruction_handoff_handle(
	    &internal->operation.instruction, id, ops, arg));
}

int
vmx_nested_internal_handle_vmexit(struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmexit_handoff_ops *ops, void *arg)
{

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_VMEXIT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	return (vmx_nested_vmexit_handoff_handle(
	    &internal->operation.vmexit, id, ops, arg));
}

int
vmx_nested_internal_handle_vmentry_reject(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmentry_handoff_ops *ops, void *arg)
{

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_VMENTRY_REJECT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	return (vmx_nested_vmentry_handoff_handle(
	    &internal->operation.vmentry, id, ops, arg));
}

int
vmx_nested_internal_handle_late_vmentry(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmentry_handoff_ops *ops, void *arg)
{

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_LATE_VMENTRY)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	return (vmx_nested_vmentry_handoff_handle(
	    &internal->operation.vmentry, id, ops, arg));
}

int
vmx_nested_internal_handle_continuation(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_continuation_handoff_ops *ops, void *arg)
{

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_CONTINUATION)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	return (vmx_nested_continuation_handoff_handle(
	    &internal->operation.continuation, id, ops, arg));
}

int
vmx_nested_internal_take_ept(struct vmx_nested_internal *internal,
    const struct vmx_nested_ept_handoff_id *id,
    struct vmx_nested_ept_handoff_result *result)
{
	int error;

	if (internal == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_EPT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_ept_handoff_take(&internal->operation.ept, id,
	    result);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_take_vmexit(struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_vmexit_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_VMEXIT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_vmexit_handoff_take(
	    &internal->operation.vmexit, id, request);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_take_vmentry_reject(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_vmentry_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_VMENTRY_REJECT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_vmentry_handoff_take(
	    &internal->operation.vmentry, id, request);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_take_late_vmentry(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_vmentry_handoff_request *request)
{
	int error;

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_LATE_VMENTRY)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_vmentry_handoff_take(
	    &internal->operation.vmentry, id, request);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_take_continuation(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_continuation_handoff_request *request,
    struct vmx_nested_continuation_handoff_result *result)
{
	int error;

	if (internal == NULL || request == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), internal,
	    sizeof(*internal)) ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), result,
	    sizeof(*result)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_CONTINUATION)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_continuation_handoff_take(
	    &internal->operation.continuation, id, request, result);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_take_refreeze(struct vmx_nested_internal *internal,
    const struct vmx_nested_refreeze_request *request)
{

	if (internal == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_REFREEZE)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	if (!vmx_nested_refreeze_request_equal(
	    &internal->operation.refreeze, request))
		return (ESTALE);
	vmx_nested_internal_init(internal);
	return (0);
}

int
vmx_nested_internal_take_instruction(struct vmx_nested_internal *internal,
    const struct vmx_nested_instruction_handoff_id *id,
    struct vmx_nested_instruction_handoff_result *result)
{
	int error;

	if (internal == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), internal,
	    sizeof(*internal)))
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_INSTRUCTION)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_instruction_handoff_take(
	    &internal->operation.instruction, id, result);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_cancel_vmexit(struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id)
{
	int error;

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_VMEXIT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_vmexit_handoff_cancel(
	    &internal->operation.vmexit, id);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_cancel_vmentry_reject(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id)
{
	int error;

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_VMENTRY_REJECT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_vmentry_handoff_cancel(
	    &internal->operation.vmentry, id);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_cancel_late_vmentry(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id)
{
	int error;

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_LATE_VMENTRY)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_vmentry_handoff_cancel(
	    &internal->operation.vmentry, id);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_cancel_continuation(
    struct vmx_nested_internal *internal,
    const struct vmx_nested_vmcs02_id *id)
{
	int error;

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_CONTINUATION)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_continuation_handoff_cancel(
	    &internal->operation.continuation, id);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_cancel_ept(struct vmx_nested_internal *internal,
    const struct vmx_nested_ept_handoff_id *id)
{
	int error;

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_EPT)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_ept_handoff_cancel(&internal->operation.ept, id);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}

int
vmx_nested_internal_cancel_instruction(struct vmx_nested_internal *internal,
    const struct vmx_nested_instruction_handoff_id *id)
{
	int error;

	if (internal == NULL)
		return (EINVAL);
	if (internal->kind != VMX_NESTED_INTERNAL_INSTRUCTION)
		return (internal->kind == VMX_NESTED_INTERNAL_NONE ? ENOENT :
		    EPROTO);
	error = vmx_nested_instruction_handoff_cancel(
	    &internal->operation.instruction, id);
	if (error == 0)
		vmx_nested_internal_init(internal);
	return (error);
}
