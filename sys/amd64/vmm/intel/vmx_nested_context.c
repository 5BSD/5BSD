/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_context.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_context_output_overlap(const void *output, size_t output_length,
    const void *retained, size_t retained_length)
{

	return (vmx_nested_state_ranges_overlap(output, output_length,
	    retained, retained_length));
}

static bool
nvmx_context_id_equal(const struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id)
{

	return (id != NULL &&
	    id->state_generation == context->state_generation &&
	    id->execution_epoch == context->execution_epoch &&
	    id->vmcs12_gpa == context->machine.current_vmcs_gpa);
}

static bool
nvmx_context_entry_origin_zero(
    const struct vmx_nested_vmentry_origin *origin)
{

	return (origin->rflags == 0 && origin->instruction_length == 0 &&
	    !origin->launch && !origin->valid);
}

static bool
nvmx_context_idle(const struct vmx_nested_context *context)
{

	return (context->internal.kind == VMX_NESTED_INTERNAL_NONE &&
	    context->vmcs02.state == VMX_NESTED_VMCS02_COMMIT_IDLE &&
	    nvmx_context_entry_origin_zero(&context->entry_origin));
}

static bool
nvmx_context_machine_equal(const struct vmx_nested_machine *first,
    const struct vmx_nested_machine *second)
{

	return (first->vmxon == second->vmxon &&
	    first->vmxon_gpa == second->vmxon_gpa &&
	    first->current_vmcs_gpa == second->current_vmcs_gpa &&
	    first->epoch == second->epoch);
}

static bool
nvmx_context_machine_zero(const struct vmx_nested_machine *machine)
{

	return (!machine->vmxon && machine->vmxon_gpa == 0 &&
	    machine->current_vmcs_gpa == 0 && machine->epoch == 0);
}

static bool
nvmx_context_machine_valid(const struct vmx_nested_machine *machine)
{

	if (machine->vmxon)
		return (machine->vmxon_gpa != UINT64_MAX &&
		    machine->current_vmcs_gpa != machine->vmxon_gpa &&
		    machine->epoch != 0);
	return (machine->vmxon_gpa == UINT64_MAX &&
	    machine->current_vmcs_gpa == UINT64_MAX);
}

static bool
nvmx_context_fault_zero(const struct vmx_nested_instruction_fault *fault)
{

	return (fault->linear_address == 0 && fault->error_code == 0 &&
	    fault->vector == 0 && !fault->error_code_valid &&
	    !fault->injected);
}

static int
nvmx_context_instruction_result_validate(
    const struct vmx_nested_instruction_handoff *handoff,
    const struct vmx_nested_instruction_handoff_id *id)
{
	const struct vmx_nested_instruction_handoff_request *request;
	const struct vmx_nested_instruction_handoff_result *result;

	request = &handoff->request;
	result = &handoff->result;
	if (result->id.state_generation != id->state_generation ||
	    result->id.execution_epoch != id->execution_epoch)
		return (EPROTO);
	if (result->disposition < VMX_NESTED_INSTRUCTION_COMPLETE ||
	    result->disposition > VMX_NESTED_INSTRUCTION_ENTRY_READY)
		return (EPROTO);
	switch (result->disposition) {
	case VMX_NESTED_INSTRUCTION_COMPLETE:
		if (result->instruction.kind < VMX_NESTED_SUCCEED ||
		    result->instruction.kind > VMX_NESTED_FAIL_VALID ||
		    !nvmx_context_machine_valid(&result->machine) ||
		    result->host_error != 0 ||
		    !nvmx_context_fault_zero(&result->fault) ||
		    result->rip_advance != request->instruction_length ||
		    result->rflags != vmx_nested_result_rflags(
		    result->instruction, request->rflags))
			return (EPROTO);
		if ((result->instruction.kind == VMX_NESTED_FAIL_VALID) !=
		    (result->instruction.instruction_error != 0))
			return (EPROTO);
		if (result->output_register) {
			if (request->operation != VMX_NESTED_INSTRUCTION_VMREAD ||
			    !request->value_in_register ||
			    result->output_size != request->operand_size ||
			    result->output_register_index !=
			    request->register_index)
				return (EPROTO);
		} else if (result->output_size != 0 ||
		    result->output_value != 0 ||
		    result->output_register_index != 0) {
			return (EPROTO);
		}
		break;
	case VMX_NESTED_INSTRUCTION_GUEST_FAULT:
		if (!nvmx_context_machine_equal(&result->machine,
		    &request->machine) || result->fault.vector == 0 ||
		    !result->fault.injected || result->host_error != 0 ||
		    result->instruction.kind != VMX_NESTED_SUCCEED ||
		    result->instruction.instruction_error != 0 ||
		    result->rip_advance != 0 || result->output_register ||
		    result->output_size != 0 ||
		    result->output_register_index != 0 ||
		    result->output_value != 0 ||
		    result->rflags != request->rflags)
			return (EPROTO);
		break;
	case VMX_NESTED_INSTRUCTION_HOST_ERROR:
		if (!nvmx_context_machine_equal(&result->machine,
		    &request->machine) || result->host_error <= 0 ||
		    result->instruction.kind != VMX_NESTED_SUCCEED ||
		    result->instruction.instruction_error != 0 ||
		    !nvmx_context_fault_zero(&result->fault) ||
		    result->rip_advance != 0 || result->output_register ||
		    result->output_size != 0 ||
		    result->output_register_index != 0 ||
		    result->output_value != 0 ||
		    result->rflags != request->rflags)
			return (EPROTO);
		break;
	case VMX_NESTED_INSTRUCTION_ENTRY_READY:
		if (!nvmx_context_machine_equal(&result->machine,
		    &request->machine) ||
		    (request->operation != VMX_NESTED_INSTRUCTION_VMLAUNCH &&
		    request->operation != VMX_NESTED_INSTRUCTION_VMRESUME) ||
		    result->host_error != 0 ||
		    result->instruction.kind != VMX_NESTED_SUCCEED ||
		    result->instruction.instruction_error != 0 ||
		    !nvmx_context_fault_zero(&result->fault) ||
		    result->rip_advance != 0 || result->output_register ||
		    result->output_size != 0 ||
		    result->output_register_index != 0 ||
		    result->output_value != 0 ||
		    result->rflags != request->rflags)
			return (EPROTO);
		break;
	default:
		return (EPROTO);
	}
	return (0);
}

void
vmx_nested_context_init(struct vmx_nested_context *context)
{

	if (context == NULL)
		return;
	memset(context, 0, sizeof(*context));
	vmx_nested_machine_init(&context->machine);
	vmx_nested_internal_init(&context->internal);
	vmx_nested_vmcs02_commit_init(&context->vmcs02);
	context->state_generation = 1;
	context->phase = VMX_NESTED_CONTEXT_ROOT;
}

int
vmx_nested_context_destroy(struct vmx_nested_context *context, bool frozen)
{
	enum vmx_nested_ept_handoff_state ept_state;
	enum vmx_nested_instruction_handoff_state instruction_state;
	enum vmx_nested_vmexit_handoff_state vmexit_state;
	enum vmx_nested_vmentry_handoff_state vmentry_state;
	enum vmx_nested_continuation_handoff_state continuation_state;

	if (context == NULL || !frozen || context->state_generation == 0)
		return (EINVAL);
	switch (context->vmcs02.state) {
	case VMX_NESTED_VMCS02_COMMIT_IDLE:
	case VMX_NESTED_VMCS02_COMMIT_PENDING:
	case VMX_NESTED_VMCS02_COMMIT_RESOLVED:
		break;
	case VMX_NESTED_VMCS02_COMMIT_APPLYING:
		return (EBUSY);
	default:
		return (EPROTO);
	}
	switch (context->internal.kind) {
	case VMX_NESTED_INTERNAL_NONE:
		break;
	case VMX_NESTED_INTERNAL_EPT:
		ept_state = context->internal.operation.ept.state;
		switch (ept_state) {
		case VMX_NESTED_EPT_HANDOFF_PENDING:
		case VMX_NESTED_EPT_HANDOFF_RESOLVED:
			break;
		case VMX_NESTED_EPT_HANDOFF_HANDLING:
			return (EBUSY);
		default:
			return (EPROTO);
		}
		break;
	case VMX_NESTED_INTERNAL_INSTRUCTION:
		instruction_state =
		    context->internal.operation.instruction.state;
		switch (instruction_state) {
		case VMX_NESTED_INSTRUCTION_HANDOFF_PENDING:
		case VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED:
			break;
		case VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING:
			return (EBUSY);
		default:
			return (EPROTO);
		}
		break;
	case VMX_NESTED_INTERNAL_VMEXIT:
		vmexit_state = context->internal.operation.vmexit.state;
		switch (vmexit_state) {
		case VMX_NESTED_VMEXIT_HANDOFF_PENDING:
		case VMX_NESTED_VMEXIT_HANDOFF_RESOLVED:
			break;
		case VMX_NESTED_VMEXIT_HANDOFF_COMMITTING:
			return (EBUSY);
		default:
			return (EPROTO);
		}
		break;
	case VMX_NESTED_INTERNAL_VMENTRY_REJECT:
	case VMX_NESTED_INTERNAL_LATE_VMENTRY:
		vmentry_state = context->internal.operation.vmentry.state;
		switch (vmentry_state) {
		case VMX_NESTED_VMENTRY_HANDOFF_PENDING:
		case VMX_NESTED_VMENTRY_HANDOFF_RESOLVED:
			break;
		case VMX_NESTED_VMENTRY_HANDOFF_COMMITTING:
			return (EBUSY);
		default:
			return (EPROTO);
		}
		break;
	case VMX_NESTED_INTERNAL_CONTINUATION:
		continuation_state =
		    context->internal.operation.continuation.state;
		switch (continuation_state) {
		case VMX_NESTED_CONTINUATION_HANDOFF_PENDING:
		case VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED:
			break;
		case VMX_NESTED_CONTINUATION_HANDOFF_HANDLING:
			return (EBUSY);
		default:
			return (EPROTO);
		}
		break;
	case VMX_NESTED_INTERNAL_REFREEZE:
		/*
		 * Refreeze has no callback-active substate.  Publication is a
		 * single value copy and resource release is owned by the
		 * separate staged transaction on the frozen vCPU.
		 */
		if (vmx_nested_refreeze_request_value_validate(
		    &context->internal.operation.refreeze) != 0)
			return (EPROTO);
		break;
	default:
		return (EPROTO);
	}
	/*
	 * VM destruction, unlike snapshot quiesce, intentionally abandons L2,
	 * pending handoffs, and unconsumed results.  No runtime pointer is
	 * retained in this value-only owner.
	 */
	memset(context, 0, sizeof(*context));
	return (0);
}

int
vmx_nested_context_quiesce(const struct vmx_nested_context *context)
{

	if (context == NULL || context->state_generation == 0)
		return (EINVAL);
	/*
	 * Quiescence is a typed ownership boundary, not merely an idle-bit
	 * query.  Callers use EBUSY to mean that a well-formed live owner may
	 * become idle and can therefore be retried.  Do not let malformed
	 * portable machine state, an unrecognized phase, or an impossible
	 * abort/phase pairing masquerade as that retryable condition.
	 */
	if (context->phase > VMX_NESTED_CONTEXT_ABORTED ||
	    !nvmx_context_machine_valid(&context->machine) ||
	    context->abort_indicator > 6 ||
	    ((context->phase == VMX_NESTED_CONTEXT_ABORTED) !=
	    (context->abort_indicator != 0)))
		return (EPROTO);
	if (!nvmx_context_idle(context) ||
	    context->phase == VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    context->phase == VMX_NESTED_CONTEXT_GUEST ||
	    context->phase == VMX_NESTED_CONTEXT_EXIT_PENDING)
		return (EBUSY);
	return (0);
}

int
vmx_nested_context_guest_validate(
    const struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id)
{

	if (context == NULL || id == NULL || context->state_generation == 0)
		return (EINVAL);
	if (context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    !nvmx_context_idle(context))
		return (EBUSY);
	if (!nvmx_context_id_equal(context, id))
		return (ESTALE);
	return (0);
}

int
vmx_nested_context_guest_continuation_validate(
    const struct vmx_nested_context *context,
    const struct vmx_nested_l0_continuation *continuation)
{
	struct vmx_nested_continuation_handoff_request expected;
	const struct vmx_nested_continuation_handoff *handoff;
	int error;

	if (context == NULL || continuation == NULL ||
	    context->state_generation == 0)
		return (EINVAL);
	if (context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    context->internal.kind != VMX_NESTED_INTERNAL_CONTINUATION ||
	    context->vmcs02.state != VMX_NESTED_VMCS02_COMMIT_IDLE ||
	    !nvmx_context_entry_origin_zero(&context->entry_origin))
		return (EBUSY);
	error = vmx_nested_continuation_handoff_request_build(continuation,
	    &expected);
	if (error != 0)
		return (error);
	if (!nvmx_context_id_equal(context, &expected.id))
		return (ESTALE);
	handoff = &context->internal.operation.continuation;
	if (handoff->state != VMX_NESTED_CONTINUATION_HANDOFF_PENDING)
		return (handoff->state ==
		    VMX_NESTED_CONTINUATION_HANDOFF_HANDLING ? EBUSY :
		    EPROTO);
	if (!vmx_nested_continuation_handoff_request_equal(
	    &handoff->request, &expected))
		return (ESTALE);
	return (0);
}

int
vmx_nested_context_reset(struct vmx_nested_context *context, bool frozen)
{
	uint64_t generation;
	int error;

	if (context == NULL || !frozen)
		return (EINVAL);
	error = vmx_nested_context_quiesce(context);
	if (error != 0)
		return (error);
	generation = context->state_generation;
	if (generation == UINT64_MAX)
		return (EOVERFLOW);
	vmx_nested_context_init(context);
	context->state_generation = generation + 1;
	return (0);
}

int
vmx_nested_context_begin_entry(struct vmx_nested_context *context,
    uint64_t vmcs12_gpa, struct vmx_nested_vmcs02_id *id)
{
	struct vmx_nested_vmcs02_id candidate;

	if (context == NULL || id == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ROOT ||
	    !context->machine.vmxon ||
	    context->machine.current_vmcs_gpa != vmcs12_gpa ||
	    vmcs12_gpa == UINT64_MAX || !nvmx_context_idle(context))
		return (EINVAL);
	if (nvmx_context_output_overlap(id, sizeof(*id), context,
	    sizeof(*context)))
		return (EINVAL);
	if (context->execution_epoch == UINT64_MAX)
		return (EOVERFLOW);
	candidate.state_generation = context->state_generation;
	candidate.execution_epoch = context->execution_epoch + 1;
	candidate.vmcs12_gpa = vmcs12_gpa;
	context->execution_epoch = candidate.execution_epoch;
	context->phase = VMX_NESTED_CONTEXT_ENTRY_PENDING;
	*id = candidate;
	return (0);
}

int
vmx_nested_context_commit_entry(struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id)
{

	if (context == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    !nvmx_context_id_equal(context, id))
		return (ESTALE);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_GUEST;
	return (0);
}

int
vmx_nested_context_commit_hardware_entry(
    struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id)
{
	int error;

	if (context == NULL || runtime == NULL || id == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    !nvmx_context_id_equal(context, id) ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_VMCS02 ||
	    !vmx_nested_vmcs02_id_equal(&runtime->id, id))
		return (ESTALE);

	/*
	 * Both state machines were validated before either is mutated.  Their
	 * individual transitions are now infallible under the frozen-vCPU
	 * ownership contract; treat any disagreement as an implementation
	 * invariant failure instead of exposing a partially published entry.
	 */
	error = vmx_nested_entry_runtime_launch(runtime, id);
	if (error != 0)
		return (EPROTO);
	error = vmx_nested_context_commit_entry(context, id);
	if (error != 0)
		return (EPROTO);
	return (0);
}

int
vmx_nested_context_cancel_entry(struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id)
{

	if (context == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    !nvmx_context_id_equal(context, id))
		return (ESTALE);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	return (0);
}

int
vmx_nested_context_resolve_vmentry(struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmentry_result *result, bool frozen,
    const struct vmx_nested_vmentry_resolution_ops *ops, void *arg,
    struct vmx_nested_vmentry_resolution *resolution)
{
	struct vmx_nested_vmentry_resolution candidate;
	struct vmx_nested_result instruction;
	int error;

	if (context == NULL || result == NULL || ops == NULL ||
	    ops->commit == NULL || resolution == NULL || !frozen ||
	    context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    !nvmx_context_id_equal(context, id) ||
	    !context->entry_origin.valid)
		return (EINVAL);
	if (nvmx_context_output_overlap(resolution, sizeof(*resolution),
	    context, sizeof(*context)) ||
	    nvmx_context_output_overlap(resolution, sizeof(*resolution), id,
	    id == NULL ? 0 : sizeof(*id)) ||
	    nvmx_context_output_overlap(resolution, sizeof(*resolution), result,
	    sizeof(*result)) ||
	    nvmx_context_output_overlap(resolution, sizeof(*resolution), ops,
	    sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_vmentry_rejection_validate(result);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = *id;
	candidate.origin = context->entry_origin;
	candidate.result = *result;
	switch (result->disposition) {
	case VMX_NESTED_VMENTRY_VMFAIL_VALID:
		instruction.kind = VMX_NESTED_FAIL_VALID;
		instruction.instruction_error = result->instruction_error;
		candidate.rflags = vmx_nested_result_rflags(instruction,
		    context->entry_origin.rflags);
		candidate.rip_advance =
		    context->entry_origin.instruction_length;
		break;
	case VMX_NESTED_VMENTRY_ENTRY_FAILURE:
		candidate.rflags = context->entry_origin.rflags;
		break;
	case VMX_NESTED_VMENTRY_READY:
	default:
		return (EINVAL);
	}
	error = ops->commit(arg, &candidate);
	if (error < 0)
		return (EPROTO);
	if (error != 0)
		return (error);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	*resolution = candidate;
	return (0);
}

int
vmx_nested_context_begin_exit(struct vmx_nested_context *context,
    struct vmx_nested_vmcs02_id *id)
{

	if (context == NULL || id == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST)
		return (EINVAL);
	if (nvmx_context_output_overlap(id, sizeof(*id), context,
	    sizeof(*context)))
		return (EINVAL);
	id->state_generation = context->state_generation;
	id->execution_epoch = context->execution_epoch;
	id->vmcs12_gpa = context->machine.current_vmcs_gpa;
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	return (0);
}

int
vmx_nested_context_commit_exit(struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id)
{

	if (context == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING ||
	    !nvmx_context_id_equal(context, id))
		return (ESTALE);
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	return (0);
}

int
vmx_nested_context_commit_vmexit(struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id, bool frozen,
    const struct vmx_nested_vmexit_commit_ops *ops, void *arg)
{
	int error;

	if (context == NULL || id == NULL || !frozen || ops == NULL ||
	    ops->commit == NULL ||
	    (context->phase != VMX_NESTED_CONTEXT_GUEST &&
	    context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING) ||
	    !nvmx_context_id_equal(context, id))
		return (EINVAL);
	if (context->phase == VMX_NESTED_CONTEXT_GUEST)
		context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	error = ops->commit(arg, id);
	if (error < 0)
		return (EPROTO);
	if (error != 0)
		return (error);
	/*
	 * Ownership was checked before the callback and this assignment is
	 * the sole publication point, so no fallible work remains.
	 */
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	return (0);
}

int
vmx_nested_context_publish_vmexit(struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_exit_information *information,
    const struct vmx_nested_l2_runtime_state *l2_runtime)
{
	struct vmx_nested_vmexit_handoff_request request;
	int error;

	if (context == NULL || id == NULL || information == NULL ||
	    l2_runtime == NULL || context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    !nvmx_context_id_equal(context, id) ||
	    context->internal.kind != VMX_NESTED_INTERNAL_NONE)
		return (EINVAL);
	memset(&request, 0, sizeof(request));
	request.id = *id;
	request.information = *information;
	request.l2_runtime = *l2_runtime;
	error = vmx_nested_internal_publish_vmexit(&context->internal,
	    &request);
	if (error != 0)
		return (error);
	/*
	 * Publication above is the only fallible operation.  Make the phase
	 * change last so an observer can never see EXIT_PENDING without the
	 * complete immutable exit image.
	 */
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	return (0);
}

int
vmx_nested_context_publish_synthetic_vmexit(
    struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_exit_information *information,
    const struct vmx_nested_l2_runtime_state *l2_runtime)
{
	struct vmx_nested_context context_candidate;
	struct vmx_nested_entry_runtime runtime_candidate;
	int error;

	if (context == NULL || runtime == NULL || id == NULL ||
	    information == NULL || l2_runtime == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    !nvmx_context_id_equal(context, id) ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_RESOURCES ||
	    !vmx_nested_vmcs02_id_equal(&runtime->id, id))
		return (ESTALE);

	context_candidate = *context;
	runtime_candidate = *runtime;
	error = vmx_nested_context_commit_entry(&context_candidate, id);
	if (error != 0)
		return (EPROTO);
	error = vmx_nested_entry_runtime_synthetic_exit_captured(
	    &runtime_candidate, id);
	if (error != 0)
		return (EPROTO);
	error = vmx_nested_context_publish_vmexit(&context_candidate, id,
	    information, l2_runtime);
	if (error != 0)
		return (error);

	/*
	 * Every fallible operation ran on local copies.  Publish both owners
	 * only after the immutable handoff is complete.
	 */
	*runtime = runtime_candidate;
	*context = context_candidate;
	return (0);
}

struct nvmx_context_vmexit_commit {
	const struct vmx_nested_vmexit_commit_ops *ops;
	void *arg;
};

static int
nvmx_context_vmexit_commit_apply(void *arg,
    const struct vmx_nested_vmexit_handoff_request *request)
{
	struct nvmx_context_vmexit_commit *commit;

	commit = arg;
	return (commit->ops->commit(commit->arg, &request->id));
}

int
vmx_nested_context_commit_published_vmexit(
    struct vmx_nested_context *context, bool frozen,
    const struct vmx_nested_vmexit_commit_ops *ops, void *arg,
    struct vmx_nested_vmexit_handoff_request *request)
{
	static const struct vmx_nested_vmexit_handoff_ops handoff_ops = {
		.commit = nvmx_context_vmexit_commit_apply,
	};
	struct nvmx_context_vmexit_commit commit;
	struct vmx_nested_vmexit_handoff_request candidate;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (context == NULL || !frozen || ops == NULL ||
	    ops->commit == NULL || request == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING ||
	    context->internal.kind != VMX_NESTED_INTERNAL_VMEXIT)
		return (EINVAL);
	if (nvmx_context_output_overlap(request, sizeof(*request), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(request, sizeof(*request), ops,
	    sizeof(*ops)))
		return (EINVAL);
	id = &context->internal.operation.vmexit.request.id;
	if (!nvmx_context_id_equal(context, id))
		return (ESTALE);
	commit.ops = ops;
	commit.arg = arg;
	error = vmx_nested_internal_handle_vmexit(&context->internal, id,
	    &handoff_ops, &commit);
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_internal_take_vmexit(&context->internal, id,
	    &candidate);
	if (error != 0)
		return (error);
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	*request = candidate;
	return (0);
}

struct nvmx_context_vmexit_abort {
	const struct vmx_nested_vmexit_abort_ops *ops;
	void *arg;
	uint32_t indicator;
};

static int
nvmx_context_vmexit_abort_apply(void *arg,
    const struct vmx_nested_vmexit_handoff_request *request)
{
	struct nvmx_context_vmexit_abort *abort;

	abort = arg;
	return (abort->ops->publish(abort->arg, &request->id,
	    abort->indicator));
}

int
vmx_nested_context_abort_published_vmexit(
    struct vmx_nested_context *context, bool frozen, uint32_t indicator,
    const struct vmx_nested_vmexit_abort_ops *ops, void *arg,
    struct vmx_nested_vmexit_handoff_request *request)
{
	static const struct vmx_nested_vmexit_handoff_ops handoff_ops = {
		.commit = nvmx_context_vmexit_abort_apply,
	};
	struct nvmx_context_vmexit_abort abort;
	struct vmx_nested_vmexit_handoff_request candidate;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (context == NULL || !frozen || indicator == 0 || indicator > 6 ||
	    ops == NULL || ops->publish == NULL || request == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING ||
	    context->internal.kind != VMX_NESTED_INTERNAL_VMEXIT ||
	    context->vmcs02.state != VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (EINVAL);
	if (nvmx_context_output_overlap(request, sizeof(*request), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(request, sizeof(*request), ops,
	    sizeof(*ops)))
		return (EINVAL);
	id = &context->internal.operation.vmexit.request.id;
	if (!nvmx_context_id_equal(context, id))
		return (ESTALE);
	abort.ops = ops;
	abort.arg = arg;
	abort.indicator = indicator;
	error = vmx_nested_internal_handle_vmexit(&context->internal, id,
	    &handoff_ops, &abort);
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_internal_take_vmexit(&context->internal, id,
	    &candidate);
	if (error != 0)
		return (error);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_ABORTED;
	context->abort_indicator = indicator;
	*request = candidate;
	return (0);
}

struct nvmx_context_vmentry_abort {
	const struct vmx_nested_vmexit_abort_ops *ops;
	void *arg;
	uint32_t indicator;
};

static int
nvmx_context_vmentry_abort_apply(void *arg,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	struct nvmx_context_vmentry_abort *abort;

	abort = arg;
	return (abort->ops->publish(abort->arg, &request->id,
	    abort->indicator));
}

int
vmx_nested_context_abort_published_vmentry(
    struct vmx_nested_context *context, bool frozen, uint32_t indicator,
    const struct vmx_nested_vmexit_abort_ops *ops, void *arg,
    struct vmx_nested_vmentry_handoff_request *request)
{
	static const struct vmx_nested_vmentry_handoff_ops handoff_ops = {
		.commit = nvmx_context_vmentry_abort_apply,
	};
	struct nvmx_context_vmentry_abort abort;
	struct vmx_nested_vmentry_handoff_request candidate;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (context == NULL || !frozen || indicator == 0 || indicator > 6 ||
	    ops == NULL || ops->publish == NULL || request == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING ||
	    context->internal.kind != VMX_NESTED_INTERNAL_VMENTRY_REJECT ||
	    context->vmcs02.state != VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (EINVAL);
	if (nvmx_context_output_overlap(request, sizeof(*request), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(request, sizeof(*request), ops,
	    sizeof(*ops)))
		return (EINVAL);
	id = &context->internal.operation.vmentry.request.id;
	if (!nvmx_context_id_equal(context, id))
		return (ESTALE);
	abort.ops = ops;
	abort.arg = arg;
	abort.indicator = indicator;
	error = vmx_nested_internal_handle_vmentry_reject(
	    &context->internal, id, &handoff_ops, &abort);
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_internal_take_vmentry_reject(
	    &context->internal, id, &candidate);
	if (error != 0)
		return (error);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_ABORTED;
	context->abort_indicator = indicator;
	*request = candidate;
	return (0);
}

int
vmx_nested_context_abort(struct vmx_nested_context *context,
    uint32_t indicator)
{

	if (context == NULL || indicator == 0 || indicator > 6 ||
	    context->phase == VMX_NESTED_CONTEXT_ABORTED ||
	    !context->machine.vmxon ||
	    context->machine.current_vmcs_gpa == UINT64_MAX)
		return (EINVAL);
	if (context->internal.kind != VMX_NESTED_INTERNAL_NONE ||
	    context->vmcs02.state != VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (EBUSY);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_ABORTED;
	context->abort_indicator = indicator;
	return (0);
}

int
vmx_nested_context_publish_instruction(struct vmx_nested_context *context,
    const struct vmx_nested_instruction_handoff_request *request,
    struct vmx_nested_instruction_handoff_id *id)
{
	struct vmx_nested_instruction_handoff_request candidate;
	struct vmx_nested_instruction_handoff_id candidate_id;
	int error;

	if (context == NULL || request == NULL || id == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_ROOT ||
	    context->state_generation == 0 ||
	    request->id.state_generation != 0 ||
	    request->id.execution_epoch != 0 ||
	    !nvmx_context_machine_zero(&request->machine))
		return (EINVAL);
	if (nvmx_context_output_overlap(id, sizeof(*id), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(id, sizeof(*id), request,
	    sizeof(*request)))
		return (EINVAL);
	if (context->handoff_epoch == UINT64_MAX)
		return (EOVERFLOW);
	candidate = *request;
	candidate_id.state_generation = context->state_generation;
	candidate_id.execution_epoch = context->handoff_epoch + 1;
	candidate.id = candidate_id;
	candidate.machine = context->machine;
	error = vmx_nested_internal_publish_instruction(&context->internal,
	    &candidate);
	if (error != 0)
		return (error);
	context->handoff_epoch = candidate_id.execution_epoch;
	*id = candidate_id;
	return (0);
}

int
vmx_nested_context_commit_instruction(struct vmx_nested_context *context,
    const struct vmx_nested_instruction_handoff_id *id, bool frozen,
    const struct vmx_nested_instruction_commit_ops *ops, void *arg,
    struct vmx_nested_instruction_handoff_result *result)
{
	struct vmx_nested_instruction_handoff *handoff;
	struct vmx_nested_instruction_handoff_result candidate;
	int error;

	if (context == NULL || id == NULL || result == NULL || !frozen ||
	    context->state_generation == 0 ||
	    context->phase != VMX_NESTED_CONTEXT_ROOT)
		return (EINVAL);
	if (nvmx_context_output_overlap(result, sizeof(*result), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), id,
	    sizeof(*id)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), ops,
	    ops == NULL ? 0 : sizeof(*ops)))
		return (EINVAL);
	if (context->internal.kind == VMX_NESTED_INTERNAL_NONE)
		return (ENOENT);
	if (context->internal.kind != VMX_NESTED_INTERNAL_INSTRUCTION)
		return (EPROTO);
	handoff = &context->internal.operation.instruction;
	if (handoff->request.id.state_generation != id->state_generation ||
	    handoff->request.id.execution_epoch != id->execution_epoch)
		return (ESTALE);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_PENDING)
		return (EAGAIN);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED)
		return (EPROTO);
	if (id->state_generation != context->state_generation ||
	    id->execution_epoch != context->handoff_epoch)
		return (ESTALE);
	if (!nvmx_context_machine_equal(&handoff->request.machine,
	    &context->machine))
		return (EPROTO);
	error = nvmx_context_instruction_result_validate(handoff, id);
	if (error != 0)
		return (error);

	candidate = handoff->result;
	if (candidate.disposition == VMX_NESTED_INSTRUCTION_ENTRY_READY)
		return (EOPNOTSUPP);
	if (candidate.disposition == VMX_NESTED_INSTRUCTION_COMPLETE) {
		if (ops == NULL || ops->commit == NULL)
			return (ENOTSUP);
		error = ops->commit(arg, &candidate);
		if (error < 0)
			return (EPROTO);
		if (error != 0)
			return (error);
		context->machine = candidate.machine;
	}
	/*
	 * Guest faults were already injected by the frozen memory adapter.
	 * Host errors have no L1 architectural effects.  Clearing the
	 * value-only handoff after validation cannot fail.
	 */
	vmx_nested_internal_init(&context->internal);
	*result = candidate;
	return (0);
}

int
vmx_nested_context_commit_vmentry_instruction(
    struct vmx_nested_context *context,
    const struct vmx_nested_instruction_handoff_id *id, bool frozen,
    struct vmx_nested_vmcs02_id *entry_id,
    struct vmx_nested_instruction_handoff_result *result)
{
	struct vmx_nested_instruction_handoff *handoff;
	struct vmx_nested_instruction_handoff_result candidate;
	struct vmx_nested_vmcs02_id candidate_id;
	int error;

	if (context == NULL || id == NULL || entry_id == NULL ||
	    result == NULL || !frozen || context->state_generation == 0 ||
	    context->phase != VMX_NESTED_CONTEXT_ROOT)
		return (EINVAL);
	if (nvmx_context_output_overlap(entry_id, sizeof(*entry_id), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(entry_id, sizeof(*entry_id), id,
	    sizeof(*id)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), id,
	    sizeof(*id)) ||
	    nvmx_context_output_overlap(entry_id, sizeof(*entry_id), result,
	    sizeof(*result)))
		return (EINVAL);
	if (context->internal.kind == VMX_NESTED_INTERNAL_NONE)
		return (ENOENT);
	if (context->internal.kind != VMX_NESTED_INTERNAL_INSTRUCTION)
		return (EPROTO);
	handoff = &context->internal.operation.instruction;
	if (handoff->request.id.state_generation != id->state_generation ||
	    handoff->request.id.execution_epoch != id->execution_epoch)
		return (ESTALE);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_PENDING)
		return (EAGAIN);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED)
		return (EPROTO);
	if (id->state_generation != context->state_generation ||
	    id->execution_epoch != context->handoff_epoch)
		return (ESTALE);
	if (!nvmx_context_machine_equal(&handoff->request.machine,
	    &context->machine))
		return (EPROTO);
	error = nvmx_context_instruction_result_validate(handoff, id);
	if (error != 0)
		return (error);
	candidate = handoff->result;
	if (candidate.disposition != VMX_NESTED_INSTRUCTION_ENTRY_READY)
		return (EOPNOTSUPP);
	if (context->vmcs02.state != VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (EBUSY);
	if (context->execution_epoch == UINT64_MAX)
		return (EOVERFLOW);
	candidate_id.state_generation = context->state_generation;
	candidate_id.execution_epoch = context->execution_epoch + 1;
	candidate_id.vmcs12_gpa = context->machine.current_vmcs_gpa;
	if (candidate_id.vmcs12_gpa == UINT64_MAX)
		return (EPROTO);

	/*
	 * This is the sole successful-instruction handoff that does not
	 * update L1 RIP or flags.  Publish the execution identifier and clear
	 * the resolved instruction atomically under the frozen-vCPU owner.
	 */
	context->execution_epoch = candidate_id.execution_epoch;
	context->phase = VMX_NESTED_CONTEXT_ENTRY_PENDING;
	context->entry_origin.rflags = handoff->request.rflags;
	context->entry_origin.instruction_length =
	    handoff->request.instruction_length;
	context->entry_origin.launch =
	    handoff->request.operation == VMX_NESTED_INSTRUCTION_VMLAUNCH;
	context->entry_origin.valid = true;
	vmx_nested_internal_init(&context->internal);
	*entry_id = candidate_id;
	*result = candidate;
	return (0);
}

int
vmx_nested_context_cancel_instruction(struct vmx_nested_context *context,
    const struct vmx_nested_instruction_handoff_id *id, bool frozen)
{

	if (context == NULL || id == NULL || !frozen ||
	    context->state_generation == 0 ||
	    context->phase != VMX_NESTED_CONTEXT_ROOT)
		return (EINVAL);
	if (id->state_generation != context->state_generation ||
	    id->execution_epoch != context->handoff_epoch)
		return (ESTALE);
	return (vmx_nested_internal_cancel_instruction(&context->internal,
	    id));
}

int
vmx_nested_context_publish_ept(struct vmx_nested_context *context,
    const struct vmx_nested_ept_handoff_request *request,
    struct vmx_nested_ept_handoff_id *id)
{
	struct vmx_nested_ept_handoff_request candidate;
	struct vmx_nested_ept_handoff_id candidate_id;
	int error;

	if (context == NULL || request == NULL || id == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    request->id.vmcs_generation != 0 ||
	    request->id.execution_epoch != 0 ||
	    context->state_generation == 0 ||
	    context->execution_epoch == 0)
		return (EINVAL);
	if (nvmx_context_output_overlap(id, sizeof(*id), context,
	    sizeof(*context)) ||
	    nvmx_context_output_overlap(id, sizeof(*id), request,
	    sizeof(*request)))
		return (EINVAL);
	candidate = *request;
	candidate_id.vmcs_generation = context->state_generation;
	candidate_id.execution_epoch = context->execution_epoch;
	candidate.id = candidate_id;
	error = vmx_nested_internal_publish_ept(&context->internal,
	    &candidate);
	if (error != 0)
		return (error);
	*id = candidate_id;
	return (0);
}

static int nvmx_context_ept_resolved(
    struct vmx_nested_context *,
    const struct vmx_nested_ept_handoff_id *, bool,
    struct vmx_nested_ept_handoff **);

int
vmx_nested_context_commit_ept_population(
    struct vmx_nested_context *context,
    const struct vmx_nested_ept_handoff_id *id, bool frozen,
    struct vmx_nested_ept_handoff_result *result)
{
	struct vmx_nested_ept_handoff *handoff;
	struct vmx_nested_ept_handoff_result candidate;
	int error;

	if (result == NULL)
		return (EINVAL);
	if (nvmx_context_output_overlap(result, sizeof(*result), context,
	    context == NULL ? 0 : sizeof(*context)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), id,
	    id == NULL ? 0 : sizeof(*id)))
		return (EINVAL);
	error = nvmx_context_ept_resolved(context, id, frozen, &handoff);
	if (error != 0)
		return (error);
	candidate = handoff->result;
	if (candidate.plan.action != VMX_NESTED_EPT_FAULT_POPULATE)
		return (ENOTSUP);
	if (candidate.plan.l2_page !=
	    (candidate.guest_physical_address & ~UINT64_C(0xfff)) ||
	    (candidate.plan.l1_page & UINT64_C(0xfff)) != 0 ||
	    candidate.plan.exit_qualification != 0 ||
	    candidate.plan.permissions == 0)
		return (EPROTO);
	error = vmx_nested_internal_take_ept(&context->internal, id,
	    &candidate);
	if (error != 0)
		return (error);
	*result = candidate;
	return (0);
}

static int
nvmx_context_ept_resolved(
    struct vmx_nested_context *context,
    const struct vmx_nested_ept_handoff_id *id, bool frozen,
    struct vmx_nested_ept_handoff **result)
{
	struct vmx_nested_ept_handoff *handoff;

	if (context == NULL || id == NULL || result == NULL || !frozen ||
	    context->state_generation == 0 ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST)
		return (EINVAL);
	if (context->internal.kind == VMX_NESTED_INTERNAL_NONE)
		return (ENOENT);
	if (context->internal.kind != VMX_NESTED_INTERNAL_EPT)
		return (EPROTO);
	handoff = &context->internal.operation.ept;
	if (handoff->request.id.vmcs_generation != id->vmcs_generation ||
	    handoff->request.id.execution_epoch != id->execution_epoch ||
	    id->vmcs_generation != context->state_generation ||
	    id->execution_epoch != context->execution_epoch)
		return (ESTALE);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_PENDING)
		return (EAGAIN);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_HANDLING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_EPT_HANDOFF_RESOLVED)
		return (EPROTO);
	if (handoff->result.id.vmcs_generation != id->vmcs_generation ||
	    handoff->result.id.execution_epoch != id->execution_epoch ||
	    handoff->result.guest_physical_address !=
	    handoff->request.l2_gpa ||
	    handoff->result.guest_linear_address !=
	    handoff->request.guest_linear_address ||
	    handoff->result.guest_linear_address_valid !=
	    handoff->request.linear_address_valid ||
	    !vmx_nested_exit_information_equal(
	    &handoff->result.vmcs02_exit,
	    &handoff->request.vmcs02_exit))
		return (EPROTO);
	*result = handoff;
	return (0);
}

int
vmx_nested_context_commit_ept_reflection(
    struct vmx_nested_context *context,
    const struct vmx_nested_ept_handoff_id *id, bool frozen,
    const struct vmx_nested_ept_reflection_commit_ops *ops, void *arg,
    struct vmx_nested_ept_handoff_result *result)
{
	struct vmx_nested_ept_handoff *handoff;
	struct vmx_nested_ept_handoff_result candidate;
	struct vmx_nested_vmcs02_id exit_id;
	int error;

	if (result == NULL)
		return (EINVAL);
	if (nvmx_context_output_overlap(result, sizeof(*result), context,
	    context == NULL ? 0 : sizeof(*context)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), id,
	    id == NULL ? 0 : sizeof(*id)) ||
	    nvmx_context_output_overlap(result, sizeof(*result), ops,
	    ops == NULL ? 0 : sizeof(*ops)))
		return (EINVAL);
	error = nvmx_context_ept_resolved(context, id, frozen, &handoff);
	if (error != 0)
		return (error);
	candidate = handoff->result;
	switch (candidate.plan.action) {
	case VMX_NESTED_EPT_FAULT_REFLECT_VIOLATION:
		if (candidate.plan.l2_page != 0 ||
		    candidate.plan.l1_page != 0 ||
		    candidate.plan.permissions != 0)
			return (EPROTO);
		break;
	case VMX_NESTED_EPT_FAULT_REFLECT_MISCONFIGURATION:
		if (candidate.plan.exit_qualification != 0 ||
		    candidate.plan.l2_page != 0 ||
		    candidate.plan.l1_page != 0 ||
		    candidate.plan.permissions != 0)
			return (EPROTO);
		break;
	default:
		return (ENOTSUP);
	}
	if (ops == NULL || ops->commit == NULL)
		return (ENOTSUP);
	exit_id.state_generation = context->state_generation;
	exit_id.execution_epoch = context->execution_epoch;
	exit_id.vmcs12_gpa = context->machine.current_vmcs_gpa;
	error = ops->commit(arg, &exit_id, &candidate);
	if (error < 0)
		return (EPROTO);
	if (error != 0)
		return (error);

	/*
	 * The callback contract includes every externally visible part of the
	 * exit.  Only after it succeeds may the value-only owner consume the
	 * handoff and make L1 the running nested context again.
	 */
	vmx_nested_internal_init(&context->internal);
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	*result = candidate;
	return (0);
}

int
vmx_nested_context_cancel_ept(struct vmx_nested_context *context,
    const struct vmx_nested_ept_handoff_id *id, bool frozen)
{

	if (context == NULL || id == NULL || !frozen ||
	    context->state_generation == 0 ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST)
		return (EINVAL);
	if (id->vmcs_generation != context->state_generation ||
	    id->execution_epoch != context->execution_epoch)
		return (ESTALE);
	return (vmx_nested_internal_cancel_ept(&context->internal, id));
}

/*
 * Validate the value-only transaction before a frozen-vCPU runtime selects
 * guest-memory or EPT callbacks.  This deliberately performs no callback and
 * cannot make progress by itself: until a complete runtime supplies the
 * operation-specific resources, the caller must remain fail-closed.
 */
int
vmx_nested_context_validate_internal(
    const struct vmx_nested_context *context, bool frozen)
{
	const struct vmx_nested_ept_handoff *ept;
	const struct vmx_nested_instruction_handoff *instruction;
	const struct vmx_nested_vmexit_handoff *vmexit;
	const struct vmx_nested_vmentry_handoff *vmentry;
	const struct vmx_nested_continuation_handoff *continuation;
	bool resolved;
	int error;

	if (context == NULL || !frozen || context->state_generation == 0)
		return (EINVAL);
	switch (context->internal.kind) {
	case VMX_NESTED_INTERNAL_NONE:
		return (ENOENT);
	case VMX_NESTED_INTERNAL_EPT:
		if (context->phase != VMX_NESTED_CONTEXT_GUEST)
			return (EBUSY);
		ept = &context->internal.operation.ept;
		resolved = false;
		switch (ept->state) {
		case VMX_NESTED_EPT_HANDOFF_PENDING:
			break;
		case VMX_NESTED_EPT_HANDOFF_HANDLING:
			return (EBUSY);
		case VMX_NESTED_EPT_HANDOFF_RESOLVED:
			resolved = true;
			break;
		default:
			return (EPROTO);
		}
		if (ept->request.id.vmcs_generation !=
		    context->state_generation ||
		    ept->request.id.execution_epoch !=
		    context->execution_epoch)
			return (ESTALE);
		return (resolved ? EALREADY : 0);
	case VMX_NESTED_INTERNAL_INSTRUCTION:
		if (context->phase != VMX_NESTED_CONTEXT_ROOT)
			return (EBUSY);
		instruction = &context->internal.operation.instruction;
		resolved = false;
		switch (instruction->state) {
		case VMX_NESTED_INSTRUCTION_HANDOFF_PENDING:
			break;
		case VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING:
			return (EBUSY);
		case VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED:
			resolved = true;
			break;
		default:
			return (EPROTO);
		}
		if (instruction->request.id.state_generation !=
		    context->state_generation ||
		    instruction->request.id.execution_epoch !=
		    context->handoff_epoch)
			return (ESTALE);
		if (!nvmx_context_machine_equal(&instruction->request.machine,
		    &context->machine))
			return (EPROTO);
		if (resolved) {
			error = nvmx_context_instruction_result_validate(
			    instruction, &instruction->request.id);
			if (error != 0)
				return (error);
		}
		return (resolved ? EALREADY : 0);
	case VMX_NESTED_INTERNAL_VMEXIT:
		if (context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING)
			return (EBUSY);
		vmexit = &context->internal.operation.vmexit;
		resolved = false;
		switch (vmexit->state) {
		case VMX_NESTED_VMEXIT_HANDOFF_PENDING:
			break;
		case VMX_NESTED_VMEXIT_HANDOFF_COMMITTING:
			return (EBUSY);
		case VMX_NESTED_VMEXIT_HANDOFF_RESOLVED:
			resolved = true;
			break;
		default:
			return (EPROTO);
		}
		if (!nvmx_context_id_equal(context, &vmexit->request.id))
			return (ESTALE);
		return (resolved ? EALREADY : 0);
	case VMX_NESTED_INTERNAL_VMENTRY_REJECT:
		if (context->phase != VMX_NESTED_CONTEXT_ENTRY_PENDING)
			return (EBUSY);
		vmentry = &context->internal.operation.vmentry;
		resolved = false;
		switch (vmentry->state) {
		case VMX_NESTED_VMENTRY_HANDOFF_PENDING:
			break;
		case VMX_NESTED_VMENTRY_HANDOFF_COMMITTING:
			return (EBUSY);
		case VMX_NESTED_VMENTRY_HANDOFF_RESOLVED:
			resolved = true;
			break;
		default:
			return (EPROTO);
		}
		if (!nvmx_context_id_equal(context, &vmentry->request.id))
			return (ESTALE);
		error = vmx_nested_vmentry_rejection_validate(
		    &vmentry->request.result);
		if (error != 0)
			return (error);
		return (resolved ? EALREADY : 0);
	case VMX_NESTED_INTERNAL_LATE_VMENTRY:
		if (context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING)
			return (EBUSY);
		vmentry = &context->internal.operation.vmentry;
		resolved = false;
		switch (vmentry->state) {
		case VMX_NESTED_VMENTRY_HANDOFF_PENDING:
			break;
		case VMX_NESTED_VMENTRY_HANDOFF_COMMITTING:
			return (EBUSY);
		case VMX_NESTED_VMENTRY_HANDOFF_RESOLVED:
			resolved = true;
			break;
		default:
			return (EPROTO);
		}
		if (!nvmx_context_id_equal(context, &vmentry->request.id))
			return (ESTALE);
		if (vmentry->request.result.disposition !=
		    VMX_NESTED_VMENTRY_ENTRY_FAILURE)
			return (EPROTO);
		error = vmx_nested_vmentry_rejection_validate(
		    &vmentry->request.result);
		if (error != 0)
			return (error);
		return (resolved ? EALREADY : 0);
	case VMX_NESTED_INTERNAL_CONTINUATION:
		if (context->phase != VMX_NESTED_CONTEXT_GUEST)
			return (EBUSY);
		continuation = &context->internal.operation.continuation;
		resolved = false;
		switch (continuation->state) {
		case VMX_NESTED_CONTINUATION_HANDOFF_PENDING:
			break;
		case VMX_NESTED_CONTINUATION_HANDOFF_HANDLING:
			return (EBUSY);
		case VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED:
			resolved = true;
			break;
		default:
			return (EPROTO);
		}
		if (!nvmx_context_id_equal(context,
		    &continuation->request.id))
			return (ESTALE);
		if (continuation->request.exit_sequence == 0 ||
		    continuation->request.portable_generation == 0)
			return (EPROTO);
		if (continuation->request.completion !=
		    VMX_NESTED_L0_COMPLETE_RESUME_L2 &&
		    continuation->request.completion !=
		    VMX_NESTED_L0_COMPLETE_REFLECT_L1)
			return (EPROTO);
		if (resolved &&
		    ((continuation->request.completion ==
		    VMX_NESTED_L0_COMPLETE_RESUME_L2 &&
		    continuation->result.disposition !=
		    VMX_NESTED_CONTINUATION_RESUME_PREPARED &&
		    continuation->result.disposition !=
		    VMX_NESTED_CONTINUATION_MTF_REFLECTED) ||
		    (continuation->request.completion ==
		    VMX_NESTED_L0_COMPLETE_REFLECT_L1 &&
		    continuation->result.disposition !=
		    VMX_NESTED_CONTINUATION_REFLECTED)))
			return (EPROTO);
		return (resolved ? EALREADY : 0);
	case VMX_NESTED_INTERNAL_REFREEZE:
		if (context->phase != VMX_NESTED_CONTEXT_GUEST)
			return (EBUSY);
		if (!nvmx_context_id_equal(context,
		    &context->internal.operation.refreeze.id))
			return (ESTALE);
		if (vmx_nested_refreeze_request_value_validate(
		    &context->internal.operation.refreeze) != 0)
			return (EPROTO);
		if (context->internal.operation.refreeze.purpose ==
		    VMX_NESTED_REFREEZE_LATE_ENTRY &&
		    (!nvmx_context_id_equal(context,
		    &context->internal.operation.refreeze.late_entry.id) ||
		    context->internal.operation.refreeze.
		    portable_generation != context->internal.operation.
		    refreeze.late_entry.portable_generation))
			return (EPROTO);
		return (0);
	default:
		return (EPROTO);
	}
}

int
vmx_nested_context_internal_dispatch(
    const struct vmx_nested_context *context, bool frozen,
    enum vmx_nested_internal_dispatch *dispatch)
{
	enum vmx_nested_internal_dispatch candidate;
	int error;

	if (dispatch == NULL)
		return (EINVAL);
	if (nvmx_context_output_overlap(dispatch, sizeof(*dispatch), context,
	    context == NULL ? 0 : sizeof(*context)))
		return (EINVAL);
	error = vmx_nested_context_validate_internal(context, frozen);
	if (error == 0)
		candidate = VMX_NESTED_INTERNAL_DISPATCH_HANDLE;
	else if (error == EALREADY)
		candidate = VMX_NESTED_INTERNAL_DISPATCH_COMMIT;
	else
		return (error);
	*dispatch = candidate;
	return (0);
}
