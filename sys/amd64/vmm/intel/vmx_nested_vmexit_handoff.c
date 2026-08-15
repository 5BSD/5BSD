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

#include "vmx_nested_vmexit_handoff.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_vh_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmx_vh_id_equal(const struct vmx_nested_vmcs02_id *first,
    const struct vmx_nested_vmcs02_id *second)
{

	return (nvmx_vh_id_valid(first) && nvmx_vh_id_valid(second) &&
	    vmx_nested_vmcs02_id_equal(first, second));
}

static bool
nvmx_vh_l2_runtime_equal(const struct vmx_nested_l2_runtime_state *first,
    const struct vmx_nested_l2_runtime_state *second)
{

	return (vmx_nested_guest_control_state_equal(&first->control,
	    &second->control) && vmx_nested_guest_arch_state_equal(&first->arch,
	    &second->arch) &&
	    first->preemption_timer_value == second->preemption_timer_value &&
	    first->preemption_timer_valid == second->preemption_timer_valid);
}

static bool
nvmx_vh_request_equal(const struct vmx_nested_vmexit_handoff_request *first,
    const struct vmx_nested_vmexit_handoff_request *second)
{

	return (nvmx_vh_id_equal(&first->id, &second->id) &&
	    vmx_nested_exit_information_equal(&first->information,
	    &second->information) && nvmx_vh_l2_runtime_equal(&first->l2_runtime,
	    &second->l2_runtime));
}

static bool
nvmx_vh_equal(const struct vmx_nested_vmexit_handoff *first,
    const struct vmx_nested_vmexit_handoff *second)
{

	return (first->state == second->state &&
	    nvmx_vh_request_equal(&first->request, &second->request));
}

void
vmx_nested_vmexit_handoff_init(struct vmx_nested_vmexit_handoff *handoff)
{

	if (handoff != NULL)
		memset(handoff, 0, sizeof(*handoff));
}

int
vmx_nested_vmexit_handoff_publish(struct vmx_nested_vmexit_handoff *handoff,
    const struct vmx_nested_vmexit_handoff_request *request)
{

	if (handoff == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)) ||
	    handoff->state != VMX_NESTED_VMEXIT_HANDOFF_IDLE ||
	    !nvmx_vh_id_valid(&request->id))
		return (EINVAL);
	handoff->request = *request;
	handoff->state = VMX_NESTED_VMEXIT_HANDOFF_PENDING;
	return (0);
}

int
vmx_nested_vmexit_handoff_handle(struct vmx_nested_vmexit_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmexit_handoff_ops *ops, void *arg)
{
	struct vmx_nested_vmexit_handoff expected;
	struct vmx_nested_vmexit_handoff_ops ops_snapshot;
	struct vmx_nested_vmexit_handoff_request request_snapshot;
	int error;

	if (handoff == NULL || id == NULL || ops == NULL ||
	    ops->commit == NULL ||
	    vmx_nested_state_ranges_overlap(handoff, sizeof(*handoff), ops,
	    sizeof(*ops)))
		return (EINVAL);
	if (!nvmx_vh_id_equal(&handoff->request.id, id))
		return (ESTALE);
	switch (handoff->state) {
	case VMX_NESTED_VMEXIT_HANDOFF_PENDING:
		break;
	case VMX_NESTED_VMEXIT_HANDOFF_COMMITTING:
		return (EBUSY);
	case VMX_NESTED_VMEXIT_HANDOFF_RESOLVED:
		return (EALREADY);
	default:
		return (EPROTO);
	}
	/*
	 * The request is an immutable architectural record.  Keep both it and
	 * the callback identity private to this transaction: a hardware adapter
	 * must not be able to replace or rewrite the retained handoff while it is
	 * committing an exit.
	 */
	ops_snapshot = *ops;
	request_snapshot = handoff->request;
	handoff->state = VMX_NESTED_VMEXIT_HANDOFF_COMMITTING;
	expected = *handoff;
	error = ops_snapshot.commit(arg, &request_snapshot);
	if (!nvmx_vh_equal(handoff, &expected)) {
		/* The external outcome is no longer trustworthy; retain retry state. */
		handoff->request = expected.request;
		handoff->state = VMX_NESTED_VMEXIT_HANDOFF_PENDING;
		return (EPROTO);
	}
	if (error < 0)
		error = EPROTO;
	if (error != 0) {
		handoff->state = VMX_NESTED_VMEXIT_HANDOFF_PENDING;
		return (error);
	}
	handoff->state = VMX_NESTED_VMEXIT_HANDOFF_RESOLVED;
	return (0);
}

int
vmx_nested_vmexit_handoff_take(struct vmx_nested_vmexit_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id,
    struct vmx_nested_vmexit_handoff_request *request)
{

	if (handoff == NULL || id == NULL || request == NULL ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(request, sizeof(*request), id,
	    sizeof(*id)))
		return (EINVAL);
	if (!nvmx_vh_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state != VMX_NESTED_VMEXIT_HANDOFF_RESOLVED)
		return (handoff->state == VMX_NESTED_VMEXIT_HANDOFF_COMMITTING ?
		    EBUSY : EAGAIN);
	*request = handoff->request;
	vmx_nested_vmexit_handoff_init(handoff);
	return (0);
}

int
vmx_nested_vmexit_handoff_cancel(struct vmx_nested_vmexit_handoff *handoff,
    const struct vmx_nested_vmcs02_id *id)
{

	if (handoff == NULL || id == NULL)
		return (EINVAL);
	if (!nvmx_vh_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state == VMX_NESTED_VMEXIT_HANDOFF_COMMITTING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_VMEXIT_HANDOFF_PENDING &&
	    handoff->state != VMX_NESTED_VMEXIT_HANDOFF_RESOLVED)
		return (EPROTO);
	vmx_nested_vmexit_handoff_init(handoff);
	return (0);
}
