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

#include "vmx_nested_vmentry_handoff.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_eh_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmx_eh_id_equal(const struct vmx_nested_vmcs02_id *first,
    const struct vmx_nested_vmcs02_id *second)
{

	return (nvmx_eh_id_valid(first) && nvmx_eh_id_valid(second) &&
	    vmx_nested_vmcs02_id_equal(first, second));
}

static bool
nvmx_eh_request_equal(const struct vmx_nested_vmentry_handoff_request *first,
    const struct vmx_nested_vmentry_handoff_request *second)
{

	return (nvmx_eh_id_equal(&first->id, &second->id) &&
	    vmx_nested_vmentry_result_equal(&first->result, &second->result));
}

static bool
nvmx_eh_equal(const struct vmx_nested_vmentry_handoff *first,
    const struct vmx_nested_vmentry_handoff *second)
{

	return (first->state == second->state &&
	    nvmx_eh_request_equal(&first->request, &second->request));
}

void
vmx_nested_vmentry_handoff_init(
    struct vmx_nested_vmentry_handoff *handoff)
{

	if (handoff != NULL)
		memset(handoff, 0, sizeof(*handoff));
}

int
vmx_nested_vmentry_handoff_publish(
    struct vmx_nested_vmentry_handoff *handoff,
    const struct vmx_nested_vmentry_handoff_request *request)
{
	int error;

	if (handoff == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)) ||
	    handoff->state != VMX_NESTED_VMENTRY_HANDOFF_IDLE ||
	    !nvmx_eh_id_valid(&request->id))
		return (EINVAL);
	error = vmx_nested_vmentry_rejection_validate(&request->result);
	if (error != 0)
		return (error);
	handoff->request = *request;
	handoff->state = VMX_NESTED_VMENTRY_HANDOFF_PENDING;
	return (0);
}

int
vmx_nested_vmentry_handoff_handle(
    struct vmx_nested_vmentry_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmentry_handoff_ops *ops, void *arg)
{
	struct vmx_nested_vmentry_handoff expected;
	struct vmx_nested_vmentry_handoff_ops ops_snapshot;
	struct vmx_nested_vmentry_handoff_request request_snapshot;
	int error;

	if (handoff == NULL || id == NULL || ops == NULL ||
	    ops->commit == NULL ||
	    vmx_nested_state_ranges_overlap(handoff, sizeof(*handoff), ops,
	    sizeof(*ops)))
		return (EINVAL);
	if (!nvmx_eh_id_equal(&handoff->request.id, id))
		return (ESTALE);
	switch (handoff->state) {
	case VMX_NESTED_VMENTRY_HANDOFF_PENDING:
		break;
	case VMX_NESTED_VMENTRY_HANDOFF_COMMITTING:
		return (EBUSY);
	case VMX_NESTED_VMENTRY_HANDOFF_RESOLVED:
		return (EALREADY);
	default:
		return (EPROTO);
	}
	/* Preserve one immutable failure record and callback identity per retry. */
	ops_snapshot = *ops;
	request_snapshot = handoff->request;
	handoff->state = VMX_NESTED_VMENTRY_HANDOFF_COMMITTING;
	expected = *handoff;
	error = ops_snapshot.commit(arg, &request_snapshot);
	if (!nvmx_eh_equal(handoff, &expected)) {
		/* Callback mutation leaves the external commit outcome unknowable. */
		handoff->request = expected.request;
		handoff->state = VMX_NESTED_VMENTRY_HANDOFF_PENDING;
		return (EPROTO);
	}
	if (error < 0)
		error = EPROTO;
	if (error != 0) {
		handoff->state = VMX_NESTED_VMENTRY_HANDOFF_PENDING;
		return (error);
	}
	handoff->state = VMX_NESTED_VMENTRY_HANDOFF_RESOLVED;
	return (0);
}

int
vmx_nested_vmentry_handoff_take(
    struct vmx_nested_vmentry_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_vmentry_handoff_request *request)
{

	if (handoff == NULL || id == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), id,
	    sizeof(*id)))
		return (EINVAL);
	if (!nvmx_eh_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state != VMX_NESTED_VMENTRY_HANDOFF_RESOLVED)
		return (handoff->state ==
		    VMX_NESTED_VMENTRY_HANDOFF_COMMITTING ? EBUSY : EAGAIN);
	*request = handoff->request;
	vmx_nested_vmentry_handoff_init(handoff);
	return (0);
}

int
vmx_nested_vmentry_handoff_cancel(
    struct vmx_nested_vmentry_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id)
{

	if (handoff == NULL || id == NULL)
		return (EINVAL);
	if (!nvmx_eh_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state == VMX_NESTED_VMENTRY_HANDOFF_COMMITTING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_VMENTRY_HANDOFF_PENDING &&
	    handoff->state != VMX_NESTED_VMENTRY_HANDOFF_RESOLVED)
		return (EPROTO);
	vmx_nested_vmentry_handoff_init(handoff);
	return (0);
}
