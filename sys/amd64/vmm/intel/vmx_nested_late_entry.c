/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_late_entry.h"
#include "vmx_nested_context.h"
#include "vmx_nested_state_range.h"

#define	NVMXLE_FAILED_VMENTRY	(UINT32_C(1) << 31)
#define	NVMXLE_BASIC_REASON_MASK	UINT32_C(0xffff)
#define	NVMXLE_INVALID_GUEST_STATE	UINT32_C(33)

static bool
nvmxle_id_equal(const struct vmx_nested_vmcs02_id *first,
    const struct vmx_nested_vmcs02_id *second)
{

	return (vmx_nested_vmcs02_id_equal(first, second));
}

static bool
nvmxle_result_storage_valid(const struct vmx_nested_context *context,
    const struct vmx_nested_entry_runtime *runtime, const void *ops,
    size_t ops_size,
    const struct vmx_nested_vmentry_handoff_request *result)
{

	return (!vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    runtime, sizeof(*runtime)) &&
	    !vmx_nested_state_ranges_overlap(result, sizeof(*result),
	    context, sizeof(*context)) &&
	    !vmx_nested_state_ranges_overlap(result, sizeof(*result),
	    runtime, sizeof(*runtime)) &&
	    !vmx_nested_state_ranges_overlap(result, sizeof(*result), ops,
	    ops_size));
}

static int
nvmxle_validate_request(const struct vmx_nested_late_entry *late)
{
	struct vmx_nested_vmentry_result result;
	int error;

	if (late == NULL || !vmx_nested_vmcs02_id_valid(&late->id) ||
	    late->portable_generation == 0)
		return (EINVAL);
	if ((late->exit.exit_reason & NVMXLE_FAILED_VMENTRY) == 0 ||
	    (late->exit.exit_reason & NVMXLE_BASIC_REASON_MASK) !=
	    NVMXLE_INVALID_GUEST_STATE || !late->exit.launched)
		return (EINVAL);
	error = vmx_nested_vmentry_hardware_failed_entry(
	    late->exit.exit_reason, late->exit.exit_qualification, 0,
	    &result);
	if (error != 0)
		return (error);
	if (!vmx_nested_vmentry_result_equal(&result, &late->result))
		return (EPROTO);
	return (0);
}

int
vmx_nested_late_entry_validate_request(
    const struct vmx_nested_late_entry *late)
{

	return (nvmxle_validate_request(late));
}

static int
nvmxle_validate(const struct vmx_nested_late_entry *late,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable)
{
	int error;

	if (plan == NULL || portable == NULL ||
	    plan->vmentry.disposition != VMX_NESTED_VMENTRY_READY ||
	    !nvmxle_id_equal(&plan->id, &plan->image.id))
		return (EINVAL);
	error = nvmxle_validate_request(late);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_validate(portable);
	if (error != 0)
		return (error);
	if (!nvmxle_id_equal(&late->id, &plan->id) ||
	    !nvmxle_id_equal(&late->id, &portable->id) ||
	    late->portable_generation != portable->portable_generation)
		return (ESTALE);
	return (0);
}

int
vmx_nested_late_entry_prepare(const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_attempt_plan *attempt,
    struct vmx_nested_late_entry *late)
{
	struct vmx_nested_late_entry candidate;
	int error;

	if (plan == NULL || portable == NULL || attempt == NULL ||
	    late == NULL || attempt->action !=
	    VMX_NESTED_ATTEMPT_RESUMED_FAILED_ENTRY ||
	    vmx_nested_attempt_plan_validate(attempt) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(late, sizeof(*late), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(late, sizeof(*late), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(late, sizeof(*late), attempt,
	    sizeof(*attempt)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = plan->id;
	candidate.portable_generation = portable->portable_generation;
	error = vmx_nested_exit_information_prepare(&portable->exit,
	    &attempt->exit, &candidate.exit);
	if (error != 0)
		return (error);
	error = vmx_nested_vmentry_hardware_failed_entry(
	    candidate.exit.exit_reason, candidate.exit.exit_qualification, 0,
	    &candidate.result);
	if (error != 0)
		return (error);
	error = nvmxle_validate(&candidate, plan, portable);
	if (error != 0)
		return (error);
	*late = candidate;
	return (0);
}

int
vmx_nested_late_entry_validate(const struct vmx_nested_late_entry *late,
    const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable)
{

	return (nvmxle_validate(late, plan, portable));
}

int
vmx_nested_late_entry_publish(struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_late_entry *late)
{
	struct vmx_nested_vmentry_handoff_request request;
	int error;

	if (context == NULL || runtime == NULL ||
	    nvmxle_validate_request(late) != 0 ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    context->internal.kind != VMX_NESTED_INTERNAL_NONE ||
	    runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD ||
	    !nvmxle_id_equal(&runtime->id, &late->id) ||
	    context->state_generation != late->id.state_generation ||
	    context->execution_epoch != late->id.execution_epoch ||
	    context->machine.current_vmcs_gpa != late->id.vmcs12_gpa)
		return (EINVAL);
	memset(&request, 0, sizeof(request));
	request.id = late->id;
	request.result = late->result;
	error = vmx_nested_internal_publish_late_vmentry(
	    &context->internal, &request);
	if (error != 0)
		return (error);
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	return (0);
}

struct nvmxle_commit {
	const struct vmx_nested_late_entry_commit_ops *ops;
	void *arg;
};

static int
nvmxle_commit_apply(void *arg,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	struct nvmxle_commit *commit;

	commit = arg;
	return (commit->ops->commit(commit->arg, &request->id,
	    &request->result));
}

int
vmx_nested_late_entry_commit(struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime, bool frozen,
    const struct vmx_nested_late_entry_commit_ops *ops, void *arg,
    struct vmx_nested_vmentry_handoff_request *result)
{
	static const struct vmx_nested_vmentry_handoff_ops handoff_ops = {
		.commit = nvmxle_commit_apply,
	};
	struct vmx_nested_vmentry_handoff_request request;
	struct vmx_nested_vmcs02_id commit_id;
	struct nvmxle_commit commit;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (context == NULL || runtime == NULL || !frozen || ops == NULL ||
	    ops->commit == NULL || result == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING ||
	    context->internal.kind !=
	    VMX_NESTED_INTERNAL_LATE_VMENTRY)
		return (EINVAL);
	if (!nvmxle_result_storage_valid(context, runtime, ops,
	    sizeof(*ops), result))
		return (EINVAL);
	/*
	 * Complete all value-only validation before invoking the architectural
	 * commit callback.  EALREADY means a previous callback succeeded but
	 * the frozen owner has not yet consumed its resolved handoff.
	 */
	error = vmx_nested_context_validate_internal(context, true);
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_entry_runtime_validate(runtime);
	if (error != 0)
		return (EPROTO);
	/*
	 * Taking the handoff reinitializes context->internal.  Preserve the
	 * identity by value so the subsequent runtime transition cannot observe
	 * the zeroed request through an alias into the consumed handoff.
	 */
	commit_id = context->internal.operation.vmentry.request.id;
	id = &commit_id;
	if (runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD ||
	    !nvmxle_id_equal(&runtime->id, id))
		return (ESTALE);
	commit.ops = ops;
	commit.arg = arg;
	error = vmx_nested_internal_handle_late_vmentry(&context->internal,
	    id, &handoff_ops, &commit);
	if (error != 0 && error != EALREADY)
		return (error);
	/*
	 * The frozen owner is the sole mutator.  After a successful callback,
	 * the prevalidated take and runtime retirement are commit-only
	 * operations; an error here denotes an internal invariant violation.
	 */
	error = vmx_nested_internal_take_late_vmentry(&context->internal,
	    id, &request);
	if (error != 0)
		return (EPROTO);
	error = vmx_nested_entry_runtime_exit_committed(runtime, id);
	if (error != 0)
		return (EPROTO);
	context->phase = VMX_NESTED_CONTEXT_ROOT;
	*result = request;
	return (0);
}

struct nvmxle_abort {
	const struct vmx_nested_late_entry_abort_ops *ops;
	void *arg;
	uint32_t indicator;
};

static int
nvmxle_abort_apply(void *arg,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	struct nvmxle_abort *abort;

	abort = arg;
	return (abort->ops->publish(abort->arg, &request->id,
	    abort->indicator));
}

int
vmx_nested_late_entry_abort(struct vmx_nested_context *context,
    struct vmx_nested_entry_runtime *runtime, bool frozen,
    uint32_t indicator, const struct vmx_nested_late_entry_abort_ops *ops,
    void *arg, struct vmx_nested_vmentry_handoff_request *result)
{
	static const struct vmx_nested_vmentry_handoff_ops handoff_ops = {
		.commit = nvmxle_abort_apply,
	};
	struct vmx_nested_vmentry_handoff_request request;
	struct vmx_nested_vmcs02_id commit_id;
	struct nvmxle_abort abort;
	const struct vmx_nested_vmcs02_id *id;
	int error;

	if (context == NULL || runtime == NULL || !frozen ||
	    indicator == 0 || indicator > 6 || ops == NULL ||
	    ops->publish == NULL || result == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_EXIT_PENDING ||
	    context->internal.kind != VMX_NESTED_INTERNAL_LATE_VMENTRY ||
	    context->vmcs02.state != VMX_NESTED_VMCS02_COMMIT_IDLE)
		return (EINVAL);
	if (!nvmxle_result_storage_valid(context, runtime, ops,
	    sizeof(*ops), result))
		return (EINVAL);
	error = vmx_nested_context_validate_internal(context, true);
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_entry_runtime_validate(runtime);
	if (error != 0)
		return (EPROTO);
	commit_id = context->internal.operation.vmentry.request.id;
	id = &commit_id;
	if (runtime->state !=
	    VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD ||
	    !nvmxle_id_equal(&runtime->id, id))
		return (ESTALE);
	abort.ops = ops;
	abort.arg = arg;
	abort.indicator = indicator;
	error = vmx_nested_internal_handle_late_vmentry(
	    &context->internal, id, &handoff_ops, &abort);
	if (error != 0 && error != EALREADY)
		return (error);
	error = vmx_nested_internal_take_late_vmentry(
	    &context->internal, id, &request);
	if (error != 0)
		return (EPROTO);
	error = vmx_nested_entry_runtime_exit_committed(runtime, id);
	if (error != 0)
		return (EPROTO);
	memset(&context->entry_origin, 0, sizeof(context->entry_origin));
	context->phase = VMX_NESTED_CONTEXT_ABORTED;
	context->abort_indicator = indicator;
	*result = request;
	return (0);
}
