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

#include "vmx_nested_caps.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_ept.h"
#include "vmx_nested_ept_fault.h"
#include "vmx_nested_ept_handoff.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_ept_memory.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_validate.h"

#define	NVMX_EPTQ_ACCESS_MASK		UINT64_C(0x7)
#define	NVMX_EPTQ_GLA_VALID		(UINT64_C(1) << 7)
#define	NVMX_EPTQ_FINAL_TRANSLATION	(UINT64_C(1) << 8)
#define	NVMX_EPTQ_USER_MODE		(UINT64_C(1) << 9)
#define	NVMX_EPTQ_GUEST_WRITABLE	(UINT64_C(1) << 10)
#define	NVMX_EPTQ_GUEST_XD		(UINT64_C(1) << 11)
#define	NVMX_EPTQ_NMI_UNBLOCKING	(UINT64_C(1) << 12)
#define	NVMX_EPT_CAP_ADVANCED_EXIT_INFO	(UINT64_C(1) << 22)
#define	NVMX_SECONDARY_MBEC		(UINT32_C(1) << 22)
#define	NVMX_EVENT_INFO_VALID		(UINT32_C(1) << 31)

static bool
vmx_nested_ept_handoff_id_valid(
    const struct vmx_nested_ept_handoff_id *id)
{

	return (id != NULL && id->vmcs_generation != 0 &&
	    id->execution_epoch != 0);
}

static bool
vmx_nested_ept_handoff_id_equal(
    const struct vmx_nested_ept_handoff_id *first,
    const struct vmx_nested_ept_handoff_id *second)
{

	return (first->vmcs_generation == second->vmcs_generation &&
	    first->execution_epoch == second->execution_epoch);
}

static bool
vmx_nested_ept_handoff_request_equal(
    const struct vmx_nested_ept_handoff_request *first,
    const struct vmx_nested_ept_handoff_request *second)
{

	return (first != NULL && second != NULL &&
	    vmx_nested_ept_handoff_id_equal(&first->id, &second->id) &&
	    vmx_nested_capabilities_equal(&first->capabilities,
	    &second->capabilities) && vmx_nested_exit_information_equal(
	    &first->vmcs02_exit, &second->vmcs02_exit) &&
	    first->eptp == second->eptp && first->l2_gpa == second->l2_gpa &&
	    first->guest_linear_address == second->guest_linear_address &&
	    first->access == second->access &&
	    first->mode_based_execute == second->mode_based_execute &&
	    first->user_mode == second->user_mode &&
	    first->guest_paging_structure_access ==
	    second->guest_paging_structure_access &&
	    first->linear_address_valid == second->linear_address_valid &&
	    first->final_translation == second->final_translation &&
	    first->nmi_unblocking_due_to_iret ==
	    second->nmi_unblocking_due_to_iret &&
	    first->advanced_exit_information == second->advanced_exit_information &&
	    first->guest_page_writable == second->guest_page_writable &&
	    first->guest_page_execute_disable ==
	    second->guest_page_execute_disable);
}

static bool
vmx_nested_ept_handoff_result_equal(
    const struct vmx_nested_ept_handoff_result *first,
    const struct vmx_nested_ept_handoff_result *second)
{

	return (first != NULL && second != NULL &&
	    vmx_nested_ept_handoff_id_equal(&first->id, &second->id) &&
	    first->plan.action == second->plan.action &&
	    first->plan.l2_page == second->plan.l2_page &&
	    first->plan.l1_page == second->plan.l1_page &&
	    first->plan.exit_qualification == second->plan.exit_qualification &&
	    first->plan.permissions == second->plan.permissions &&
	    first->plan.mode_based_execute == second->plan.mode_based_execute &&
	    vmx_nested_exit_information_equal(&first->vmcs02_exit,
	    &second->vmcs02_exit) &&
	    first->guest_physical_address == second->guest_physical_address &&
	    first->guest_linear_address == second->guest_linear_address &&
	    first->guest_linear_address_valid == second->guest_linear_address_valid);
}

static bool
vmx_nested_ept_handoff_equal(const struct vmx_nested_ept_handoff *first,
    const struct vmx_nested_ept_handoff *second)
{

	return (first != NULL && second != NULL &&
	    first->state == second->state &&
	    vmx_nested_ept_handoff_request_equal(&first->request,
	    &second->request) && vmx_nested_ept_handoff_result_equal(
	    &first->result, &second->result));
}

static int
vmx_nested_ept_handoff_request_validate(
    const struct vmx_nested_ept_handoff_request *request)
{
	struct vmx_nested_exit_information normalized, zero;
	uint64_t qualification;
	bool advanced, nmi_unblocking;
	int error;

	if (request == NULL ||
	    !vmx_nested_ept_handoff_id_valid(&request->id) ||
	    vmx_nested_capabilities_validate(&request->capabilities) != 0 ||
	    request->access == 0 ||
	    (request->access & ~(VMX_NESTED_EPT_ACCESS_READ |
	    VMX_NESTED_EPT_ACCESS_WRITE |
	    VMX_NESTED_EPT_ACCESS_EXECUTE)) != 0 ||
	    (request->final_translation &&
	    !request->linear_address_valid) ||
	    (!request->linear_address_valid &&
	    request->guest_linear_address != 0) ||
	    (request->advanced_exit_information &&
	    (!request->linear_address_valid ||
	    !request->final_translation)) ||
	    (!request->advanced_exit_information &&
	    (request->user_mode || request->guest_page_writable ||
	    request->guest_page_execute_disable)) ||
	    (request->mode_based_execute &&
	    ((uint32_t)(request->capabilities.secondary >> 32) &
	    NVMX_SECONDARY_MBEC) == 0) ||
	    request->vmcs02_exit.exit_reason != 48 ||
	    request->vmcs02_exit.guest_physical_address !=
	    request->l2_gpa ||
	    request->vmcs02_exit.guest_linear_address !=
	    (request->linear_address_valid ?
	    request->guest_linear_address : 0) ||
	    request->vmcs02_exit.launched)
		return (EINVAL);

	/*
	 * Validate and canonicalize the complete retained hardware-exit image,
	 * not merely the fields consumed by the walk.  A malformed valid event
	 * or an ignored-field mismatch must be rejected before a callback can
	 * observe the request.
	 */
	memset(&zero, 0, sizeof(zero));
	error = vmx_nested_exit_information_prepare(&zero,
	    &request->vmcs02_exit, &normalized);
	if (error != 0)
		return (error);
	normalized.launched = false;
	if (!vmx_nested_exit_information_equal(&normalized,
	    &request->vmcs02_exit))
		return (EINVAL);

	qualification = request->vmcs02_exit.exit_qualification;
	advanced = (request->capabilities.ept_vpid &
	    NVMX_EPT_CAP_ADVANCED_EXIT_INFO) != 0 &&
	    request->final_translation;
	nmi_unblocking =
	    (request->vmcs02_exit.idt_vectoring_info &
	    NVMX_EVENT_INFO_VALID) == 0 &&
	    (qualification & NVMX_EPTQ_NMI_UNBLOCKING) != 0;
	if (request->access !=
	    (qualification & NVMX_EPTQ_ACCESS_MASK) ||
	    request->linear_address_valid !=
	    ((qualification & NVMX_EPTQ_GLA_VALID) != 0) ||
	    request->final_translation !=
	    ((qualification & NVMX_EPTQ_FINAL_TRANSLATION) != 0) ||
	    request->guest_paging_structure_access !=
	    (request->linear_address_valid &&
	    !request->final_translation) ||
	    request->nmi_unblocking_due_to_iret != nmi_unblocking ||
	    request->advanced_exit_information != advanced ||
	    request->user_mode != (advanced &&
	    (qualification & NVMX_EPTQ_USER_MODE) != 0) ||
	    request->guest_page_writable != (advanced &&
	    (qualification & NVMX_EPTQ_GUEST_WRITABLE) != 0) ||
	    request->guest_page_execute_disable != (advanced &&
	    (qualification & NVMX_EPTQ_GUEST_XD) != 0))
		return (EINVAL);
	return (0);
}

void
vmx_nested_ept_handoff_init(struct vmx_nested_ept_handoff *handoff)
{

	if (handoff != NULL)
		memset(handoff, 0, sizeof(*handoff));
}

int
vmx_nested_ept_handoff_request_prepare(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_exit_information *hardware, uint64_t eptp,
    bool mode_based_execute,
    struct vmx_nested_ept_handoff_request *request)
{
	struct vmx_nested_ept_handoff_request candidate;
	struct vmx_nested_exit_information normalized, zero;
	uint64_t qualification;
	bool advanced;
	int error;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    hardware == NULL || request == NULL ||
	    hardware->exit_reason != 48 || hardware->launched ||
	    (hardware->exit_interruption_info &
	    NVMX_EVENT_INFO_VALID) != 0 ||
	    !vmx_nested_eptp_valid(capabilities, eptp))
		return (EINVAL);
	qualification = hardware->exit_qualification;
	if ((qualification & NVMX_EPTQ_ACCESS_MASK) == 0)
		return (EINVAL);
	advanced = (capabilities->ept_vpid &
	    NVMX_EPT_CAP_ADVANCED_EXIT_INFO) != 0;
	if (mode_based_execute &&
	    ((uint32_t)(capabilities->secondary >> 32) &
	    NVMX_SECONDARY_MBEC) == 0)
		return (ENOTSUP);
	memset(&zero, 0, sizeof(zero));
	error = vmx_nested_exit_information_prepare(&zero, hardware,
	    &normalized);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	candidate.capabilities = *capabilities;
	candidate.vmcs02_exit = normalized;
	/*
	 * This is an L0 hardware-exit capture, not an already committed VMCS12
	 * image.  Keep the common exit validator's canonical fields while the
	 * handoff identity remains unlaunched until reflection commits it.
	 */
	candidate.vmcs02_exit.launched = false;
	candidate.eptp = eptp;
	candidate.l2_gpa = hardware->guest_physical_address;
	candidate.access = qualification & NVMX_EPTQ_ACCESS_MASK;
	candidate.mode_based_execute = mode_based_execute;
	candidate.linear_address_valid =
	    (qualification & NVMX_EPTQ_GLA_VALID) != 0;
	candidate.final_translation =
	    (qualification & NVMX_EPTQ_FINAL_TRANSLATION) != 0;
	/*
	 * SDM 30.2.3 defines bit 12 only when original-event identification
	 * is invalid.  Canonicalize the otherwise undefined hardware bit now;
	 * a populated EPT02 fault uses it to restore NMI blocking, while a
	 * reflected fault publishes it to L1.
	 */
	candidate.nmi_unblocking_due_to_iret =
	    (candidate.vmcs02_exit.idt_vectoring_info &
	    NVMX_EVENT_INFO_VALID) == 0 &&
	    (qualification & NVMX_EPTQ_NMI_UNBLOCKING) != 0;
	if ((candidate.vmcs02_exit.idt_vectoring_info &
	    NVMX_EVENT_INFO_VALID) != 0)
		qualification &= ~NVMX_EPTQ_NMI_UNBLOCKING;
	if (candidate.final_translation &&
	    !candidate.linear_address_valid)
		return (EINVAL);
	if (candidate.linear_address_valid) {
		candidate.guest_linear_address =
		    hardware->guest_linear_address;
	} else {
		candidate.vmcs02_exit.guest_linear_address = 0;
	}
	candidate.guest_paging_structure_access =
	    candidate.linear_address_valid &&
	    !candidate.final_translation;
	candidate.advanced_exit_information = advanced &&
	    candidate.final_translation;
	if (!candidate.advanced_exit_information)
		qualification &= ~(NVMX_EPTQ_USER_MODE |
		    NVMX_EPTQ_GUEST_WRITABLE | NVMX_EPTQ_GUEST_XD);
	candidate.vmcs02_exit.exit_qualification = qualification;
	if (candidate.advanced_exit_information) {
		candidate.user_mode =
		    (qualification & NVMX_EPTQ_USER_MODE) != 0;
		candidate.guest_page_writable =
		    (qualification & NVMX_EPTQ_GUEST_WRITABLE) != 0;
		candidate.guest_page_execute_disable =
		    (qualification & NVMX_EPTQ_GUEST_XD) != 0;
	}

	/*
	 * The context publisher supplies both identity generations.  Validate
	 * all remaining request invariants with a temporary nonzero identity
	 * so malformed hardware metadata cannot become an internal handoff.
	 */
	candidate.id.vmcs_generation = 1;
	candidate.id.execution_epoch = 1;
	if (vmx_nested_ept_handoff_request_validate(&candidate) != 0)
		return (EINVAL);
	candidate.id.vmcs_generation = 0;
	candidate.id.execution_epoch = 0;
	*request = candidate;
	return (0);
}

int
vmx_nested_ept_handoff_publish(struct vmx_nested_ept_handoff *handoff,
    const struct vmx_nested_ept_handoff_request *request)
{
	int error;

	if (handoff == NULL)
		return (EINVAL);
	error = vmx_nested_ept_handoff_request_validate(request);
	if (error != 0)
		return (error);
	if (vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)))
		return (EINVAL);
	if (handoff->state != VMX_NESTED_EPT_HANDOFF_IDLE)
		return (EBUSY);
	handoff->request = *request;
	memset(&handoff->result, 0, sizeof(handoff->result));
	handoff->state = VMX_NESTED_EPT_HANDOFF_PENDING;
	return (0);
}

int
vmx_nested_ept_handoff_handle(struct vmx_nested_ept_handoff *handoff,
    const struct vmx_nested_ept_handoff_id *id,
    const struct vmx_nested_ept_memory *memory,
    const struct vmx_nested_ept_handoff_ops *ops, void *arg)
{
	struct vmx_nested_ept_handoff expected;
	struct vmx_nested_ept_fault_input input;
	struct vmx_nested_ept_handoff_result resolved;
	struct vmx_nested_ept_handoff_ops ops_snapshot;
	struct vmx_nested_ept_memory memory_snapshot;
	struct vmx_nested_ept_handoff_request request_snapshot;
	struct vmx_nested_ept_result result;
	struct vmx_nested_ept_walk walk;
	const struct vmx_nested_ept_handoff_request *request;
	int error;

	if (handoff == NULL || !vmx_nested_ept_handoff_id_valid(id) ||
	    memory == NULL || memory->load == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(memory, sizeof(*memory), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(memory, sizeof(*memory), id,
	    sizeof(*id)) ||
	    (ops != NULL &&
	    (vmx_nested_state_ranges_overlap(ops, sizeof(*ops), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), memory,
	    sizeof(*memory)))))
		return (EINVAL);
	/* One frozen walk uses one immutable memory/provider identity. */
	memory_snapshot = *memory;
	if (ops != NULL) {
		ops_snapshot = *ops;
		ops = &ops_snapshot;
	}
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_IDLE)
		return (ENOENT);
	if (!vmx_nested_ept_handoff_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_RESOLVED)
		return (EALREADY);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_HANDLING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_EPT_HANDOFF_PENDING)
		return (EPROTO);

	/*
	 * The walk and optional EPT02 population use callbacks.  Do not let a
	 * callback-side mutation turn this retained transaction into a different
	 * fault, or publish a result after its provenance has been changed.  The
	 * continuation handoff follows the same value-snapshot contract.
	 */
	request_snapshot = handoff->request;
	handoff->state = VMX_NESTED_EPT_HANDOFF_HANDLING;
	expected = *handoff;
	request = &request_snapshot;
	memset(&walk, 0, sizeof(walk));
	walk.capabilities = &request->capabilities;
	walk.memory = &memory_snapshot;
	walk.eptp = request->eptp;
	walk.guest_physical_address = request->l2_gpa;
	walk.access = request->access;
	walk.mode_based_execute = request->mode_based_execute;
	walk.user_mode = request->user_mode;
	walk.guest_paging_structure_access =
	    request->guest_paging_structure_access;
	error = vmx_nested_ept_walk(&walk, &result);
	if (!vmx_nested_ept_handoff_equal(handoff, &expected)) {
		*handoff = expected;
		handoff->state = VMX_NESTED_EPT_HANDOFF_PENDING;
		return (EPROTO);
	}
	if (error != 0)
		goto retry;

	memset(&input, 0, sizeof(input));
	input.result = &result;
	input.l2_gpa = request->l2_gpa;
	input.linear_address_valid = request->linear_address_valid;
	input.final_translation = request->final_translation;
	input.nmi_unblocking_due_to_iret =
	    request->nmi_unblocking_due_to_iret;
	input.mode_based_execute = request->mode_based_execute;
	input.user_mode = request->user_mode;
	input.advanced_exit_information =
	    request->advanced_exit_information;
	input.guest_page_writable = request->guest_page_writable;
	input.guest_page_execute_disable =
	    request->guest_page_execute_disable;
	memset(&resolved, 0, sizeof(resolved));
	resolved.id = request->id;
	resolved.vmcs02_exit = request->vmcs02_exit;
	resolved.guest_physical_address = request->l2_gpa;
	resolved.guest_linear_address = request->guest_linear_address;
	resolved.guest_linear_address_valid =
	    request->linear_address_valid;
	error = vmx_nested_ept_fault_plan(&input, &resolved.plan);
	if (error != 0)
		goto retry;

	if (resolved.plan.action == VMX_NESTED_EPT_FAULT_POPULATE) {
		if (ops == NULL || ops->populate == NULL) {
			error = ENOTSUP;
			goto retry;
		}
		error = ops->populate(arg, resolved.plan.l2_page,
		    resolved.plan.l1_page, resolved.plan.permissions,
		    resolved.plan.mode_based_execute);
		if (!vmx_nested_ept_handoff_equal(handoff, &expected)) {
			*handoff = expected;
			handoff->state = VMX_NESTED_EPT_HANDOFF_PENDING;
			return (EPROTO);
		}
		if (error != 0)
			goto retry;
	}
	handoff->result = resolved;
	handoff->state = VMX_NESTED_EPT_HANDOFF_RESOLVED;
	return (0);

retry:
	if (handoff->state != VMX_NESTED_EPT_HANDOFF_HANDLING)
		return (EPROTO);
	handoff->state = VMX_NESTED_EPT_HANDOFF_PENDING;
	return (error);
}

int
vmx_nested_ept_handoff_take(struct vmx_nested_ept_handoff *handoff,
    const struct vmx_nested_ept_handoff_id *id,
    struct vmx_nested_ept_handoff_result *result)
{
	struct vmx_nested_ept_handoff_result candidate;

	if (handoff == NULL || !vmx_nested_ept_handoff_id_valid(id) ||
	    result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), id,
	    sizeof(*id)))
		return (EINVAL);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_IDLE)
		return (ENOENT);
	if (!vmx_nested_ept_handoff_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state != VMX_NESTED_EPT_HANDOFF_RESOLVED)
		return (EAGAIN);
	candidate = handoff->result;
	vmx_nested_ept_handoff_init(handoff);
	*result = candidate;
	return (0);
}

int
vmx_nested_ept_handoff_cancel(struct vmx_nested_ept_handoff *handoff,
    const struct vmx_nested_ept_handoff_id *id)
{

	if (handoff == NULL || !vmx_nested_ept_handoff_id_valid(id))
		return (EINVAL);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_IDLE)
		return (ENOENT);
	if (!vmx_nested_ept_handoff_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state == VMX_NESTED_EPT_HANDOFF_HANDLING)
		return (EBUSY);
	vmx_nested_ept_handoff_init(handoff);
	return (0);
}
