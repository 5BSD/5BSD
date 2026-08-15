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

#include "vmx_nested_cold_ept.h"
#include "vmx_nested_ept_reflect.h"
#include "vmx_nested_state_range.h"

/* Intel SDM Vol. 3C, guest interruptibility-state: blocking by NMI. */
#define	NVMXCE_NMI_BLOCKING	(UINT32_C(1) << 3)

static bool
nvmxce_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (a != NULL && b != NULL &&
	    vmx_nested_vmcs02_id_equal(a, b));
}

static int
nvmxce_validate(const struct vmx_nested_context *context,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_ept_handoff **handoffp)
{
	const struct vmx_nested_ept_handoff *handoff;
	struct vmx_nested_exit_information normalized, zero;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL || handoffp == NULL ||
	    context->phase != VMX_NESTED_CONTEXT_GUEST ||
	    context->internal.kind != VMX_NESTED_INTERNAL_EPT ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_COLD ||
	    continuation->completion !=
	    VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
	    continuation->rollback_failed ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_L0_COLD ||
	    vmx_nested_entry_runtime_validate(runtime) != 0 ||
	    vmx_nested_l2_portable_validate(portable) != 0)
		return (EINVAL);
	handoff = &context->internal.operation.ept;
	if (handoff->state != VMX_NESTED_EPT_HANDOFF_RESOLVED ||
	    !nvmxce_id_equal(&runtime->id, &continuation->id) ||
	    !nvmxce_id_equal(&portable->id, &continuation->id) ||
	    continuation->id.state_generation !=
	    context->state_generation ||
	    continuation->id.execution_epoch !=
	    context->execution_epoch ||
	    continuation->id.vmcs12_gpa !=
	    context->machine.current_vmcs_gpa ||
	    handoff->request.id.vmcs_generation !=
	    continuation->id.state_generation ||
	    handoff->request.id.execution_epoch !=
	    continuation->id.execution_epoch ||
	    handoff->result.id.vmcs_generation !=
	    handoff->request.id.vmcs_generation ||
	    handoff->result.id.execution_epoch !=
	    handoff->request.id.execution_epoch ||
	    continuation->portable_generation !=
	    portable->portable_generation)
		return (ESTALE);
	if (!vmx_nested_exit_information_equal(
	    &handoff->result.vmcs02_exit,
	    &handoff->request.vmcs02_exit) ||
	    handoff->result.guest_physical_address !=
	    handoff->request.l2_gpa ||
	    handoff->result.guest_linear_address !=
	    handoff->request.guest_linear_address ||
	    handoff->result.guest_linear_address_valid !=
	    handoff->request.linear_address_valid)
		return (EPROTO);
	memset(&zero, 0, sizeof(zero));
	error = vmx_nested_exit_information_prepare(&zero,
	    &handoff->request.vmcs02_exit, &normalized);
	if (error != 0 ||
	    !vmx_nested_exit_information_equal(&normalized, &portable->exit))
		return (EPROTO);
	*handoffp = handoff;
	return (0);
}

int
vmx_nested_cold_ept_resolve(struct vmx_nested_context *context,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    struct vmx_nested_l2_portable_state *portable,
    enum vmx_nested_cold_ept_disposition *disposition)
{
	const struct vmx_nested_ept_handoff *handoff;
	struct vmx_nested_exit_information information;
	struct vmx_nested_internal candidate;
	struct vmx_nested_vmexit_handoff_request request;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL || disposition == NULL ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    continuation, sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context),
	    disposition, sizeof(*disposition)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation,
	    sizeof(*continuation), disposition, sizeof(*disposition)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime),
	    disposition, sizeof(*disposition)) ||
	    vmx_nested_state_ranges_overlap(portable, sizeof(*portable),
	    disposition, sizeof(*disposition)))
		return (EINVAL);
	error = nvmxce_validate(context, continuation, runtime, portable,
	    &handoff);
	if (error != 0)
		return (error);

	switch (handoff->result.plan.action) {
	case VMX_NESTED_EPT_FAULT_POPULATE:
		if (handoff->result.plan.l2_page !=
		    (handoff->result.guest_physical_address &
		    ~UINT64_C(0xfff)) ||
		    (handoff->result.plan.l1_page & UINT64_C(0xfff)) != 0 ||
		    handoff->result.plan.exit_qualification != 0 ||
		    handoff->result.plan.permissions == 0)
			return (EPROTO);
		/*
		 * Hardware clears virtual-NMI blocking before reporting an EPT
		 * violation encountered by IRET.  Because L0 handled this fault by
		 * installing an EPT02 mapping, L2 will not see bit 12 and L0 must
		 * restore the pre-IRET blocking state before thawing it.  Reflected
		 * faults deliberately retain the unblocked state and report bit 12
		 * to L1 instead.
		 */
		if (handoff->request.nmi_unblocking_due_to_iret)
			portable->runtime.arch.interruptibility |=
			    NVMXCE_NMI_BLOCKING;
		vmx_nested_internal_init(&context->internal);
		*disposition = VMX_NESTED_COLD_EPT_POPULATED;
		return (0);
	case VMX_NESTED_EPT_FAULT_REFLECT_VIOLATION:
	case VMX_NESTED_EPT_FAULT_REFLECT_MISCONFIGURATION:
		error = vmx_nested_ept_reflection_information(
		    &handoff->result, &portable->exit, &information);
		if (error != 0)
			return (error);
		break;
	default:
		return (EPROTO);
	}

	memset(&candidate, 0, sizeof(candidate));
	vmx_nested_internal_init(&candidate);
	memset(&request, 0, sizeof(request));
	request.id = continuation->id;
	request.information = information;
	request.l2_runtime = portable->runtime;
	error = vmx_nested_internal_publish_vmexit(&candidate, &request);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_runtime_l0_reflect_captured(runtime,
	    &continuation->id);
	if (error != 0)
		return (error);

	context->internal = candidate;
	context->phase = VMX_NESTED_CONTEXT_EXIT_PENDING;
	vmx_nested_l0_continuation_init(continuation);
	*disposition = VMX_NESTED_COLD_EPT_REFLECTED;
	return (0);
}
