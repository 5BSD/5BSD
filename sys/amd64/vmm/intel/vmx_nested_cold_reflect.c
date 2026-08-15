/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_cold_reflect.h"
#include "vmx_nested_state_range.h"

static bool
nvmxcr_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (a != NULL && b != NULL &&
	    vmx_nested_vmcs02_id_equal(a, b));
}

static bool
nvmxcr_startup_plan_equal(const struct vmx_nested_startup_plan *a,
    const struct vmx_nested_startup_plan *b)
{

	return (a->kind == b->kind && a->action == b->action &&
	    a->exit_reason == b->exit_reason &&
	    a->exit_qualification == b->exit_qualification &&
	    a->vector == b->vector && a->active_l2 == b->active_l2 &&
	    a->consume_claim == b->consume_claim &&
	    a->discard_mtf == b->discard_mtf);
}

int
vmx_nested_cold_reflect_publish(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l2_portable_state *portable)
{
	struct vmx_nested_continuation_handoff *handoff;
	struct vmx_nested_internal candidate;
	struct vmx_nested_vmexit_handoff_request request;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    continuation, sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    context->internal.kind != VMX_NESTED_INTERNAL_CONTINUATION ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    continuation->completion !=
	    VMX_NESTED_L0_COMPLETE_REFLECT_L1 ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    vmx_nested_l2_portable_validate(portable) != 0 ||
	    !portable->exit_valid)
		return (EINVAL);
	handoff = &context->internal.operation.continuation;
	if (handoff->state !=
	    VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED)
		return (EINVAL);
	if (handoff->result.disposition !=
	    VMX_NESTED_CONTINUATION_REFLECTED ||
	    handoff->request.completion != continuation->completion)
		return (EPROTO);
	if (!nvmxcr_id_equal(&handoff->request.id, &continuation->id) ||
	    !nvmxcr_id_equal(&runtime->id, &continuation->id) ||
	    !nvmxcr_id_equal(&portable->id, &continuation->id) ||
	    handoff->request.exit_sequence !=
	    continuation->exit_sequence ||
	    handoff->request.portable_generation !=
	    continuation->portable_generation ||
	    portable->portable_generation !=
	    continuation->portable_generation)
		return (ESTALE);

	memset(&candidate, 0, sizeof(candidate));
	vmx_nested_internal_init(&candidate);
	memset(&request, 0, sizeof(request));
	request.id = continuation->id;
	request.information = portable->exit;
	request.l2_runtime = portable->runtime;
	error = vmx_nested_internal_publish_vmexit(&candidate, &request);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_runtime_l0_reflect_captured(runtime,
	    &continuation->id);
	if (error != 0)
		return (error);

	/*
	 * All fallible validation and candidate construction is complete.
	 * Publish the new handoff, phase, and continuation ownership together.
	 */
	context->internal = candidate;
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	vmx_nested_l0_continuation_init(continuation);
	return (0);
}

int
vmx_nested_cold_mtf_reflect_publish(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    struct vmx_nested_l2_portable_state *portable,
    uint64_t portable_generation)
{
	struct vmx_nested_continuation_handoff *handoff;
	struct vmx_nested_l0_continuation continuation_candidate;
	struct vmx_nested_l2_portable_state portable_candidate;
	struct vmx_nested_entry_runtime runtime_candidate;
	struct vmx_nested_exit_information information;
	struct vmx_nested_internal internal_candidate;
	struct vmx_nested_vmexit_handoff_request request;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    continuation, sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    context->internal.kind != VMX_NESTED_INTERNAL_CONTINUATION ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    continuation->completion != VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    vmx_nested_l2_portable_validate(portable) != 0)
		return (EINVAL);
	handoff = &context->internal.operation.continuation;
	if (handoff->state != VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED)
		return (EINVAL);
	if (handoff->result.disposition !=
	    VMX_NESTED_CONTINUATION_MTF_REFLECTED ||
	    handoff->request.completion != continuation->completion)
		return (EPROTO);
	if (!nvmxcr_id_equal(&handoff->request.id, &continuation->id) ||
	    !nvmxcr_id_equal(&runtime->id, &continuation->id) ||
	    !nvmxcr_id_equal(&portable->id, &continuation->id) ||
	    handoff->request.exit_sequence != continuation->exit_sequence ||
	    handoff->request.portable_generation !=
	    continuation->portable_generation ||
	    portable->portable_generation !=
	    continuation->portable_generation ||
	    portable_generation != continuation->portable_generation)
		return (ESTALE);

	/* Construct and validate every candidate before changing an owner. */
	error = vmx_nested_l2_portable_mtf_peek(portable,
	    portable_generation, &information);
	if (error != 0)
		return (error);
	memset(&internal_candidate, 0, sizeof(internal_candidate));
	vmx_nested_internal_init(&internal_candidate);
	memset(&request, 0, sizeof(request));
	request.id = continuation->id;
	request.information = information;
	request.l2_runtime = portable->runtime;
	error = vmx_nested_internal_publish_vmexit(&internal_candidate,
	    &request);
	if (error != 0)
		return (error);
	runtime_candidate = *runtime;
	error = vmx_nested_entry_runtime_l0_reflect_captured(
	    &runtime_candidate, &continuation->id);
	if (error != 0)
		return (error);
	portable_candidate = *portable;
	error = vmx_nested_l2_portable_mtf_commit(&portable_candidate,
	    portable_generation);
	if (error != 0)
		return (error);
	continuation_candidate = *continuation;
	vmx_nested_l0_continuation_init(&continuation_candidate);

	context->internal = internal_candidate;
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	*runtime = runtime_candidate;
	*portable = portable_candidate;
	*continuation = continuation_candidate;
	return (0);
}

int
vmx_nested_cold_startup_commit(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_startup_plan *plan)
{
	struct vmx_nested_l0_continuation continuation_candidate;
	struct vmx_nested_l2_portable_state portable_candidate;
	struct vmx_nested_entry_runtime runtime_candidate;
	struct vmx_nested_startup_input input;
	struct vmx_nested_startup_plan expected;
	struct vmx_nested_internal internal_candidate;
	struct vmx_nested_vmexit_handoff_request request;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    continuation, sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), plan, sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(portable, sizeof(*portable), plan,
	    sizeof(*plan)) ||
	    vmx_nested_startup_plan_validate(plan) != 0 ||
	    !plan->active_l2 ||
	    (plan->action != VMX_NESTED_STARTUP_ACTION_REFLECT_L1 &&
	    plan->action != VMX_NESTED_STARTUP_ACTION_DISCARD))
		return (EINVAL);

	/* Re-derive the complete plan from the still-frozen ownership image. */
	error = vmx_nested_startup_input_from_frozen_target(plan->kind,
	    plan->vector, context, continuation, runtime, portable, true, &input);
	if (error != 0)
		return (error);
	error = vmx_nested_startup_plan(&input, &expected);
	if (error != 0)
		return (error);
	if (!nvmxcr_startup_plan_equal(plan, &expected))
		return (ESTALE);

	if (plan->action == VMX_NESTED_STARTUP_ACTION_DISCARD) {
		if (!plan->discard_mtf)
			return (0);
		portable_candidate = *portable;
		error = vmx_nested_l2_portable_mtf_commit(&portable_candidate,
		    portable->portable_generation);
		if (error != 0)
			return (error);
		*portable = portable_candidate;
		return (0);
	}

	memset(&internal_candidate, 0, sizeof(internal_candidate));
	vmx_nested_internal_init(&internal_candidate);
	memset(&request, 0, sizeof(request));
	request.id = continuation->id;
	request.information.exit_reason = plan->exit_reason;
	request.information.exit_qualification = plan->exit_qualification;
	request.information.launched = true;
	request.l2_runtime = portable->runtime;
	error = vmx_nested_internal_publish_vmexit(&internal_candidate,
	    &request);
	if (error != 0)
		return (error);
	runtime_candidate = *runtime;
	error = vmx_nested_entry_runtime_l0_reflect_captured(
	    &runtime_candidate, &continuation->id);
	if (error != 0)
		return (error);
	continuation_candidate = *continuation;
	vmx_nested_l0_continuation_init(&continuation_candidate);

	context->internal = internal_candidate;
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	*runtime = runtime_candidate;
	*continuation = continuation_candidate;
	return (0);
}
