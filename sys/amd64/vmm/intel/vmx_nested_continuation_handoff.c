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

#include "vmx_nested_continuation.h"
#include "vmx_nested_continuation_handoff.h"
#include "vmx_nested_state_range.h"

static bool
nvmxch_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmxch_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (nvmxch_id_valid(a) && nvmxch_id_valid(b) &&
	    vmx_nested_vmcs02_id_equal(a, b));
}

static bool
nvmxch_request_valid(
    const struct vmx_nested_continuation_handoff_request *request)
{

	return (request != NULL && nvmxch_id_valid(&request->id) &&
	    request->exit_sequence != 0 &&
	    request->portable_generation != 0 &&
	    (request->completion == VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    request->completion == VMX_NESTED_L0_COMPLETE_REFLECT_L1));
}

static bool
nvmxch_handoff_equal(const struct vmx_nested_continuation_handoff *first,
    const struct vmx_nested_continuation_handoff *second)
{

	return (vmx_nested_continuation_handoff_request_equal(&first->request,
	    &second->request) && first->result.disposition ==
	    second->result.disposition && first->state == second->state);
}

int
vmx_nested_continuation_handoff_request_build(
    const struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_continuation_handoff_request *request)
{
	struct vmx_nested_continuation_handoff_request candidate;

	if (continuation == NULL || request == NULL ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    continuation->rollback_failed ||
	    !nvmxch_id_valid(&continuation->id) ||
	    continuation->exit_sequence == 0 ||
	    continuation->portable_generation == 0 ||
	    (continuation->completion !=
	    VMX_NESTED_L0_COMPLETE_RESUME_L2 &&
	    continuation->completion !=
	    VMX_NESTED_L0_COMPLETE_REFLECT_L1))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = continuation->id;
	candidate.exit_sequence = continuation->exit_sequence;
	candidate.portable_generation =
	    continuation->portable_generation;
	candidate.completion = continuation->completion;
	*request = candidate;
	return (0);
}

void
vmx_nested_continuation_handoff_init(
    struct vmx_nested_continuation_handoff *handoff)
{

	if (handoff != NULL)
		memset(handoff, 0, sizeof(*handoff));
}

int
vmx_nested_continuation_handoff_publish(
    struct vmx_nested_continuation_handoff *handoff,
    const struct vmx_nested_continuation_handoff_request *request)
{

	if (handoff == NULL || !nvmxch_request_valid(request) ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)) ||
	    handoff->state != VMX_NESTED_CONTINUATION_HANDOFF_IDLE)
		return (EINVAL);
	handoff->request = *request;
	handoff->state = VMX_NESTED_CONTINUATION_HANDOFF_PENDING;
	return (0);
}

int
vmx_nested_continuation_handoff_handle(
    struct vmx_nested_continuation_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_continuation_handoff_ops *ops, void *arg)
{
	struct vmx_nested_continuation_handoff expected;
	struct vmx_nested_continuation_handoff_ops ops_snapshot;
	struct vmx_nested_continuation_handoff_request request_snapshot;
	struct vmx_nested_continuation_handoff_result result;
	int error;

	if (handoff == NULL || ops == NULL || ops->handle == NULL ||
	    vmx_nested_state_ranges_overlap(handoff, sizeof(*handoff), ops,
	    sizeof(*ops)) ||
	    handoff->state != VMX_NESTED_CONTINUATION_HANDOFF_PENDING ||
	    !nvmxch_id_equal(&handoff->request.id, id))
		return (EINVAL);
	/* Bind one hot-to-cold continuation operation to immutable values. */
	ops_snapshot = *ops;
	request_snapshot = handoff->request;
	memset(&result, 0, sizeof(result));
	handoff->state = VMX_NESTED_CONTINUATION_HANDOFF_HANDLING;
	expected = *handoff;
	error = ops_snapshot.handle(arg, &request_snapshot, &result);
	if (!nvmxch_handoff_equal(handoff, &expected)) {
		/* Do not retain callback-corrupted continuation provenance. */
		handoff->request = expected.request;
		handoff->result = expected.result;
		handoff->state = VMX_NESTED_CONTINUATION_HANDOFF_PENDING;
		return (EPROTO);
	}
	if (error != 0) {
		handoff->state = VMX_NESTED_CONTINUATION_HANDOFF_PENDING;
		return (error < 0 ? EPROTO : error);
	}
	if ((handoff->request.completion ==
	    VMX_NESTED_L0_COMPLETE_RESUME_L2 &&
	    result.disposition != VMX_NESTED_CONTINUATION_RESUME_PREPARED &&
	    result.disposition != VMX_NESTED_CONTINUATION_MTF_REFLECTED) ||
	    (handoff->request.completion ==
	    VMX_NESTED_L0_COMPLETE_REFLECT_L1 &&
	    result.disposition != VMX_NESTED_CONTINUATION_REFLECTED)) {
		handoff->state = VMX_NESTED_CONTINUATION_HANDOFF_PENDING;
		return (EPROTO);
	}
	handoff->result = result;
	handoff->state = VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED;
	return (0);
}

int
vmx_nested_continuation_handoff_take(
    struct vmx_nested_continuation_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_continuation_handoff_request *request,
    struct vmx_nested_continuation_handoff_result *result)
{

	if (handoff == NULL || request == NULL || result == NULL || id == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), result,
	    sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), id,
	    sizeof(*id)) ||
	    handoff->state != VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED ||
	    !nvmxch_id_equal(&handoff->request.id, id))
		return (EINVAL);
	*request = handoff->request;
	*result = handoff->result;
	vmx_nested_continuation_handoff_init(handoff);
	return (0);
}

int
vmx_nested_continuation_handoff_cancel(
    struct vmx_nested_continuation_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id)
{

	if (handoff == NULL ||
	    handoff->state != VMX_NESTED_CONTINUATION_HANDOFF_PENDING ||
	    !nvmxch_id_equal(&handoff->request.id, id))
		return (EINVAL);
	vmx_nested_continuation_handoff_init(handoff);
	return (0);
}
