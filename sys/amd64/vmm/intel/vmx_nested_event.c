/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_event.h"
#include "vmx_nested_context.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_state_range.h"

#define	NVMXE_EXIT_EXCEPTION_NMI		UINT32_C(0)
#define	NVMXE_EXIT_EXTERNAL_INTERRUPT	UINT32_C(1)
#define	NVMXE_EXIT_INTERRUPT_WINDOW	UINT32_C(7)
#define	NVMXE_EXIT_NMI_WINDOW		UINT32_C(8)
#define	NVMXE_INTR_VALID		(UINT32_C(1) << 31)
#define	NVMXE_INTR_NMI			(UINT32_C(2) << 8)
#define	NVMXE_PRIMARY_INTERRUPT_WINDOW	(UINT32_C(1) << 2)
#define	NVMXE_PRIMARY_NMI_WINDOW	(UINT32_C(1) << 22)
#define	NVMXE_INTINFO_VECTOR(info)	((info) & UINT32_C(0xff))
#define	NVMXE_INTINFO_TYPE		UINT32_C(0x700)
#define	NVMXE_INTINFO_HWEXCEPTION	(UINT32_C(3) << 8)
#define	NVMXE_INTINFO_DEL_ERRCODE	UINT32_C(0x800)
#define	NVMXE_INTINFO_RSVD		UINT32_C(0x7ffff000)
#define	NVMXE_INTINFO_VALID		(UINT32_C(1) << 31)
#define	NVMXE_EXIT_INIT		UINT32_C(3)
#define	NVMXE_EXIT_SIPI		UINT32_C(4)
#define	NVMXE_GUEST_ACTIVITY_WAIT_FOR_SIPI	UINT32_C(3)

static bool
nvmxe_startup_id_matches_context(const struct vmx_nested_context *context,
    const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id) &&
	    id->state_generation == context->state_generation &&
	    id->execution_epoch == context->execution_epoch &&
	    id->vmcs12_gpa == context->machine.current_vmcs_gpa);
}

static bool
nvmxe_startup_runtime_preentry(
    const struct vmx_nested_entry_runtime *runtime)
{

	switch (runtime->state) {
	case VMX_NESTED_ENTRY_RUNTIME_IDLE:
	case VMX_NESTED_ENTRY_RUNTIME_PREPARING:
	case VMX_NESTED_ENTRY_RUNTIME_RESOURCES:
	case VMX_NESTED_ENTRY_RUNTIME_MSRS:
	case VMX_NESTED_ENTRY_RUNTIME_VMCS02:
		return (true);
	default:
		return (false);
	}
}

int
vmx_nested_startup_input_from_frozen_target(
    enum vmx_nested_startup_kind kind, uint8_t vector,
    const struct vmx_nested_context *context,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l2_portable_state *portable,
    bool portable_valid, struct vmx_nested_startup_input *input)
{
	const struct vmx_nested_continuation_handoff *handoff;
	struct vmx_nested_startup_input candidate;
	int error;

	if (context == NULL || continuation == NULL || runtime == NULL ||
	    portable == NULL || input == NULL ||
	    kind <= VMX_NESTED_STARTUP_NONE ||
	    kind >= VMX_NESTED_STARTUP_KIND_LAST ||
	    (kind == VMX_NESTED_STARTUP_INIT && vector != 0) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), context,
	    sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), portable,
	    sizeof(*portable)))
		return (EINVAL);
	error = vmx_nested_context_validate_internal(context, true);
	if (error != 0 && error != ENOENT)
		return (error);
	if (vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    vmx_nested_entry_runtime_validate(runtime) != 0)
		return (EPROTO);

	memset(&candidate, 0, sizeof(candidate));
	candidate.kind = kind;
	candidate.vector = vector;
	candidate.vmx_operation = context->machine.vmxon;
	switch (context->phase) {
	case VMX_NESTED_CONTEXT_ROOT:
		if (portable_valid ||
		    continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
		    runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE ||
		    vmx_nested_context_quiesce(context) != 0)
			return (EPROTO);
		break;
	case VMX_NESTED_CONTEXT_ENTRY_PENDING:
		if (portable_valid ||
		    continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
		    !nvmxe_startup_runtime_preentry(runtime))
			return (EPROTO);
		if (runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE &&
		    !nvmxe_startup_id_matches_context(context, &runtime->id))
			return (ESTALE);
		candidate.nested_entry_pending = true;
		break;
	case VMX_NESTED_CONTEXT_GUEST:
		if (!portable_valid)
			return (EPROTO);
		error = vmx_nested_l0_continuation_quiesce_context(context,
		    continuation, runtime, portable);
		if (error != 0)
			return (error);
		handoff = &context->internal.operation.continuation;
		candidate.active_l2 = true;
		/*
		 * The pending cold RESUME_L2 handoff is the frozen arbitration
		 * point: no result has been selected yet, and a higher-priority
		 * startup event may replace the planned re-entry.  A pending
		 * REFLECT_L1 handoff already owns a captured L2 exit, so retain the
		 * startup claim until that exact exit has been published.
		 */
		if (handoff->state !=
		    VMX_NESTED_CONTINUATION_HANDOFF_PENDING ||
		    continuation->completion !=
		    VMX_NESTED_L0_COMPLETE_RESUME_L2 ||
		    handoff->request.completion !=
		    VMX_NESTED_L0_COMPLETE_RESUME_L2) {
			candidate.continuation_pending = true;
			break;
		}
		if (portable->runtime.arch.activity >
		    NVMXE_GUEST_ACTIVITY_WAIT_FOR_SIPI)
			return (EPROTO);
		candidate.reinjection_pending =
		    (portable->exit.idt_vectoring_info & NVMXE_INTINFO_VALID) != 0;
		candidate.wait_for_sipi = portable->runtime.arch.activity ==
		    NVMXE_GUEST_ACTIVITY_WAIT_FOR_SIPI;
		candidate.mtf_pending = portable->mtf_pending;
		break;
	case VMX_NESTED_CONTEXT_EXIT_PENDING:
		return (EBUSY);
	case VMX_NESTED_CONTEXT_ABORTED:
	default:
		return (EPROTO);
	}
	*input = candidate;
	return (0);
}

int
vmx_nested_startup_plan_validate(
    const struct vmx_nested_startup_plan *plan)
{

	if (plan == NULL ||
	    plan->kind <= VMX_NESTED_STARTUP_NONE ||
	    plan->kind >= VMX_NESTED_STARTUP_KIND_LAST ||
	    plan->action <= VMX_NESTED_STARTUP_ACTION_NONE ||
	    plan->action > VMX_NESTED_STARTUP_ACTION_DISCARD)
		return (EINVAL);
	if ((plan->kind == VMX_NESTED_STARTUP_INIT && plan->vector != 0) ||
	    (plan->kind == VMX_NESTED_STARTUP_SIPI &&
	    plan->exit_qualification > UINT8_MAX))
		return (EINVAL);
	switch (plan->action) {
	case VMX_NESTED_STARTUP_ACTION_APPLY_L0:
		return (!plan->active_l2 && plan->consume_claim &&
		    !plan->discard_mtf &&
		    plan->exit_reason == 0 && plan->exit_qualification == 0 ?
		    0 : EINVAL);
	case VMX_NESTED_STARTUP_ACTION_REFLECT_L1:
		if (!plan->active_l2 || !plan->consume_claim ||
		    plan->discard_mtf)
			return (EINVAL);
		if (plan->kind == VMX_NESTED_STARTUP_INIT)
			return (plan->exit_reason == NVMXE_EXIT_INIT &&
			    plan->exit_qualification == 0 ? 0 : EINVAL);
		return (plan->exit_reason == NVMXE_EXIT_SIPI &&
		    plan->exit_qualification == plan->vector ? 0 : EINVAL);
	case VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY:
		return (!plan->consume_claim && !plan->discard_mtf &&
		    plan->exit_reason == 0 && plan->exit_qualification == 0 ?
		    0 : EINVAL);
	case VMX_NESTED_STARTUP_ACTION_DISCARD:
		if (!plan->consume_claim || plan->exit_reason != 0 ||
		    plan->exit_qualification != 0)
			return (EINVAL);
		/*
		 * Outside active L2, only SIPI can be architecturally ignored.
		 * INIT remains blocked throughout VMX operation and therefore must
		 * retain its exact claim rather than accepting a forged discard plan.
		 */
		if (!plan->active_l2)
			return (plan->kind == VMX_NESTED_STARTUP_SIPI &&
			    !plan->discard_mtf ? 0 : EINVAL);
		return (plan->kind == VMX_NESTED_STARTUP_SIPI &&
		    plan->discard_mtf ? EINVAL : 0);
	default:
		return (EINVAL);
	}
}

int
vmx_nested_startup_plan(const struct vmx_nested_startup_input *input,
    struct vmx_nested_startup_plan *plan)
{
	struct vmx_nested_startup_plan candidate;

	if (input == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    input->kind <= VMX_NESTED_STARTUP_NONE ||
	    input->kind >= VMX_NESTED_STARTUP_KIND_LAST ||
	    (input->kind == VMX_NESTED_STARTUP_INIT && input->vector != 0) ||
	    (input->active_l2 && input->nested_entry_pending) ||
	    ((input->active_l2 || input->nested_entry_pending) &&
	    !input->vmx_operation) ||
	    (!input->active_l2 && (input->continuation_pending ||
	    input->reinjection_pending || input->wait_for_sipi ||
	    input->mtf_pending)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.kind = input->kind;
	candidate.vector = input->vector;
	candidate.active_l2 = input->active_l2;
	if (input->nested_entry_pending || input->continuation_pending ||
	    input->reinjection_pending) {
		candidate.action = VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY;
	} else if (!input->active_l2 && input->vmx_operation &&
	    input->kind == VMX_NESTED_STARTUP_INIT) {
		/* INIT is blocked, rather than consumed, during VMX operation. */
		candidate.action = VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY;
	} else if (!input->active_l2 && input->vmx_operation) {
		/* SIPI is ignored during VMX operation. */
		candidate.action = VMX_NESTED_STARTUP_ACTION_DISCARD;
		candidate.consume_claim = true;
	} else if (!input->active_l2) {
		candidate.action = VMX_NESTED_STARTUP_ACTION_APPLY_L0;
		candidate.consume_claim = true;
	} else if (input->kind == VMX_NESTED_STARTUP_INIT) {
		candidate.consume_claim = true;
		if (input->wait_for_sipi) {
			candidate.action = VMX_NESTED_STARTUP_ACTION_DISCARD;
			candidate.discard_mtf = input->mtf_pending;
		} else {
			candidate.action = VMX_NESTED_STARTUP_ACTION_REFLECT_L1;
			candidate.exit_reason = NVMXE_EXIT_INIT;
		}
	} else if (input->wait_for_sipi) {
		candidate.action = VMX_NESTED_STARTUP_ACTION_REFLECT_L1;
		candidate.exit_reason = NVMXE_EXIT_SIPI;
		candidate.exit_qualification = input->vector;
		candidate.consume_claim = true;
	} else {
		candidate.action = VMX_NESTED_STARTUP_ACTION_DISCARD;
		candidate.consume_claim = true;
	}
	if (vmx_nested_startup_plan_validate(&candidate) != 0)
		return (EINVAL);
	*plan = candidate;
	return (0);
}

int
vmx_nested_event_window_controls(uint32_t current, uint32_t l0,
    uint32_t l1, const struct vmx_nested_event_plan *plan,
    uint32_t *next)
{
	const uint32_t mask = NVMXE_PRIMARY_INTERRUPT_WINDOW |
	    NVMXE_PRIMARY_NMI_WINDOW;
	uint32_t candidate;

	if (next == NULL ||
	    vmx_nested_state_ranges_overlap(next, sizeof(*next), plan,
	    sizeof(*plan)) || (plan != NULL &&
	    vmx_nested_event_plan_validate(plan) != 0))
		return (EINVAL);
	candidate = (current & ~mask) | ((l0 | l1) & mask);
	if (plan != NULL &&
	    plan->action == VMX_NESTED_EVENT_ACTION_WAIT_FOR_WINDOW) {
		if (plan->arm_interrupt_window)
			candidate |= NVMXE_PRIMARY_INTERRUPT_WINDOW;
		if (plan->arm_nmi_window)
			candidate |= NVMXE_PRIMARY_NMI_WINDOW;
	}
	*next = candidate;
	return (0);
}

int
vmx_nested_event_reflected_exit(const struct vmx_nested_event_plan *plan,
    struct vmx_nested_exit_information *information)
{
	struct vmx_nested_exit_information candidate;

	if (information == NULL ||
	    vmx_nested_state_ranges_overlap(information, sizeof(*information),
	    plan, sizeof(*plan)) ||
	    vmx_nested_event_plan_validate(plan) != 0 ||
	    (plan->action != VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW &&
	    plan->action != VMX_NESTED_EVENT_ACTION_REFLECT_EVENT))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	if (plan->action == VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW) {
		candidate.exit_reason =
		    plan->kind == VMX_NESTED_EVENT_NMI ?
		    NVMXE_EXIT_NMI_WINDOW : NVMXE_EXIT_INTERRUPT_WINDOW;
	} else {
		candidate.exit_reason =
		    plan->kind == VMX_NESTED_EVENT_NMI ?
		    NVMXE_EXIT_EXCEPTION_NMI :
		    NVMXE_EXIT_EXTERNAL_INTERRUPT;
		if (plan->interruption_info_valid) {
			candidate.exit_interruption_info = NVMXE_INTR_VALID |
			    (plan->kind == VMX_NESTED_EVENT_NMI ?
			    NVMXE_INTR_NMI : 0) | plan->vector;
		}
	}
	candidate.launched = true;
	*information = candidate;
	return (0);
}

int
vmx_nested_event_plan_validate(const struct vmx_nested_event_plan *plan)
{
	bool empty;

	if (plan == NULL ||
	    (unsigned int)plan->kind > VMX_NESTED_EVENT_NMI ||
	    (unsigned int)plan->action > VMX_NESTED_EVENT_ACTION_INJECT_L2)
		return (EINVAL);
	empty = !plan->arm_interrupt_window && !plan->arm_nmi_window &&
	    !plan->consume_event && !plan->block_nmi &&
	    !plan->interruption_info_valid && plan->vector == 0;
	switch (plan->action) {
	case VMX_NESTED_EVENT_ACTION_NONE:
	case VMX_NESTED_EVENT_ACTION_DEFER:
	case VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW:
		return (empty ? 0 : EINVAL);
	case VMX_NESTED_EVENT_ACTION_WAIT_FOR_WINDOW:
		if (plan->consume_event || plan->block_nmi ||
		    plan->interruption_info_valid || plan->vector != 0)
			return (EINVAL);
		if (plan->kind == VMX_NESTED_EVENT_NMI)
			return (plan->arm_nmi_window &&
			    !plan->arm_interrupt_window ? 0 : EINVAL);
		return (plan->arm_interrupt_window &&
		    !plan->arm_nmi_window ? 0 : EINVAL);
	case VMX_NESTED_EVENT_ACTION_REFLECT_EVENT:
		if (plan->arm_interrupt_window || plan->arm_nmi_window ||
		    plan->block_nmi !=
		    (plan->kind == VMX_NESTED_EVENT_NMI) ||
		    plan->consume_event != plan->interruption_info_valid)
			return (EINVAL);
		if (!plan->interruption_info_valid)
			return (plan->vector == 0 ? 0 : EINVAL);
		return (plan->kind == VMX_NESTED_EVENT_NMI ?
		    (plan->vector == 2 ? 0 : EINVAL) : 0);
	case VMX_NESTED_EVENT_ACTION_INJECT_L2:
		if (plan->arm_interrupt_window || plan->arm_nmi_window ||
		    !plan->consume_event || !plan->interruption_info_valid ||
		    plan->block_nmi !=
		    (plan->kind == VMX_NESTED_EVENT_NMI))
			return (EINVAL);
		return (plan->kind == VMX_NESTED_EVENT_NMI &&
		    plan->vector != 2 ? EINVAL : 0);
	default:
		return (EINVAL);
	}
}

int
vmx_nested_event_select(uint32_t pending, uint32_t *selected)
{
	static const uint32_t priority[] = {
		VMX_NESTED_PENDING_SMI,
		VMX_NESTED_PENDING_INIT,
		VMX_NESTED_PENDING_SIPI,
		VMX_NESTED_PENDING_HIGH_EXCEPTION,
		VMX_NESTED_PENDING_MTF,
		VMX_NESTED_PENDING_LOW_EXCEPTION,
		VMX_NESTED_PENDING_PREEMPT_TIMER,
		VMX_NESTED_PENDING_NMI_WINDOW,
		VMX_NESTED_PENDING_NMI,
		VMX_NESTED_PENDING_INTERRUPT_WINDOW,
		VMX_NESTED_PENDING_EXTERNAL_INTERRUPT,
	};
	size_t i;

	if (selected == NULL || (pending & ~VMX_NESTED_PENDING_ALL) != 0)
		return (EINVAL);
	*selected = 0;
	for (i = 0; i < nitems(priority); i++) {
		if ((pending & priority[i]) != 0) {
			*selected = priority[i];
			break;
		}
	}
	return (0);
}

int
vmx_nested_mtf_plan_validate(const struct vmx_nested_mtf_plan *plan)
{

	if (plan == NULL ||
	    (unsigned int)plan->action > VMX_NESTED_MTF_REFLECT)
		return (EINVAL);
	if (plan->consume_mtf != (plan->action == VMX_NESTED_MTF_DISCARD ||
	    plan->action == VMX_NESTED_MTF_REFLECT))
		return (EINVAL);
	return (0);
}

int
vmx_nested_mtf_input_from_snapshot(
    const struct vmx_nested_mtf_event_snapshot *snapshot, bool mtf_pending,
    bool nested_entry_pending, bool init_processed_in_wait_for_sipi,
    struct vmx_nested_mtf_input *input)
{
	struct vmx_nested_mtf_input candidate;
	uint32_t exception_info, exit_info;
	bool exception_valid;

	if (snapshot == NULL || input == NULL ||
	    vmx_nested_state_ranges_overlap(input, sizeof(*input), snapshot,
	    sizeof(*snapshot)))
		return (EINVAL);
	exception_info = (uint32_t)snapshot->exception;
	exception_valid =
	    (exception_info & NVMXE_INTINFO_VALID) != 0;
	if (!exception_valid) {
		if (snapshot->exception != 0 ||
		    snapshot->exception_class != VMX_NESTED_EXCEPTION_NONE)
			return (EINVAL);
	} else if ((exception_info & NVMXE_INTINFO_RSVD) != 0 ||
	    (exception_info & NVMXE_INTINFO_TYPE) !=
	    NVMXE_INTINFO_HWEXCEPTION ||
	    NVMXE_INTINFO_VECTOR(exception_info) >= 32 ||
	    snapshot->exception_class <= VMX_NESTED_EXCEPTION_NONE ||
	    snapshot->exception_class >= VMX_NESTED_EXCEPTION_LAST ||
	    ((snapshot->exception >> 32) != 0 &&
	    (exception_info & NVMXE_INTINFO_DEL_ERRCODE) == 0)) {
		return (EINVAL);
	}
	exit_info = (uint32_t)snapshot->exitintinfo;
	if ((exit_info & NVMXE_INTINFO_VALID) == 0) {
		if (snapshot->exitintinfo != 0)
			return (EINVAL);
	} else if ((exit_info & NVMXE_INTINFO_RSVD) != 0 ||
	    ((snapshot->exitintinfo >> 32) != 0 &&
	    (exit_info & NVMXE_INTINFO_DEL_ERRCODE) == 0)) {
		return (EINVAL);
	}
	if (snapshot->triple_fault && snapshot->valid)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.pending = mtf_pending;
	candidate.nested_entry_pending = nested_entry_pending;
	candidate.reinjection_pending =
	    (snapshot->exitintinfo & NVMXE_INTINFO_VALID) != 0;
	candidate.init_processed_in_wait_for_sipi =
	    init_processed_in_wait_for_sipi;
	if (snapshot->triple_fault) {
		candidate.high_priority_non_debug_pending = true;
	} else if (exception_valid) {
		if (NVMXE_INTINFO_VECTOR(exception_info) != 1) {
			candidate.high_priority_non_debug_pending = true;
		} else {
			switch (snapshot->exception_class) {
			case VMX_NESTED_EXCEPTION_FAULT:
				candidate.debug_event =
				    VMX_NESTED_DEBUG_FAULT;
				break;
			case VMX_NESTED_EXCEPTION_TRAP:
				candidate.debug_event = VMX_NESTED_DEBUG_TRAP;
				break;
			case VMX_NESTED_EXCEPTION_ICEBP:
				candidate.debug_event =
				    VMX_NESTED_DEBUG_ICEBP;
				break;
			case VMX_NESTED_EXCEPTION_TASK_SWITCH:
				candidate.debug_event =
				    VMX_NESTED_DEBUG_TASK_SWITCH;
				break;
			default:
				return (EINVAL);
			}
		}
	}
	*input = candidate;
	return (0);
}

int
vmx_nested_mtf_plan(const struct vmx_nested_mtf_input *input,
    struct vmx_nested_mtf_plan *plan)
{
	struct vmx_nested_mtf_plan candidate;

	if (input == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    (unsigned int)input->debug_event >
	    VMX_NESTED_DEBUG_TASK_SWITCH)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	if (!input->pending) {
		candidate.action = VMX_NESTED_MTF_NONE;
	} else if (input->nested_entry_pending ||
	    input->reinjection_pending) {
		candidate.action = VMX_NESTED_MTF_DEFER;
	} else if (input->init_processed_in_wait_for_sipi) {
		candidate.action = VMX_NESTED_MTF_DISCARD;
		candidate.consume_mtf = true;
	} else if (input->high_priority_non_debug_pending ||
	    input->debug_event == VMX_NESTED_DEBUG_FAULT ||
	    input->debug_event == VMX_NESTED_DEBUG_ICEBP ||
	    input->debug_event == VMX_NESTED_DEBUG_TASK_SWITCH) {
		candidate.action = VMX_NESTED_MTF_DEFER;
	} else {
		/* A trap-like #DB is lower priority and remains pending for L1. */
		candidate.action = VMX_NESTED_MTF_REFLECT;
		candidate.consume_mtf = true;
	}
	if (vmx_nested_mtf_plan_validate(&candidate) != 0)
		return (EINVAL);
	*plan = candidate;
	return (0);
}

int
vmx_nested_event_plan(const struct vmx_nested_event_input *input,
    struct vmx_nested_event_plan *plan)
{
	struct vmx_nested_event_plan candidate;

	if (input == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    (unsigned int)input->kind > VMX_NESTED_EVENT_NMI ||
	    (input->kind == VMX_NESTED_EVENT_NMI &&
	    (input->vector != 0 || input->vector_valid ||
	    input->acknowledge_on_exit)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.kind = input->kind;
	if (input->nested_entry_pending || input->reinjection_pending) {
		candidate.action = VMX_NESTED_EVENT_ACTION_DEFER;
	} else if (input->guest_blocked) {
		if (input->pending || input->l1_window_exiting) {
			candidate.action =
			    VMX_NESTED_EVENT_ACTION_WAIT_FOR_WINDOW;
			if (input->kind == VMX_NESTED_EVENT_NMI)
				candidate.arm_nmi_window = true;
			else
				candidate.arm_interrupt_window = true;
		}
	} else if (input->l1_window_exiting) {
		candidate.action = VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW;
	} else if (!input->pending) {
		candidate.action = VMX_NESTED_EVENT_ACTION_NONE;
	} else if (input->l1_event_exiting) {
		candidate.action = VMX_NESTED_EVENT_ACTION_REFLECT_EVENT;
		if (input->kind == VMX_NESTED_EVENT_NMI) {
			candidate.consume_event = true;
			candidate.block_nmi = true;
			candidate.interruption_info_valid = true;
			candidate.vector = 2;
		} else if (input->acknowledge_on_exit) {
			if (!input->vector_valid)
				return (EINVAL);
			candidate.consume_event = true;
			candidate.interruption_info_valid = true;
			candidate.vector = input->vector;
		}
	} else {
		candidate.action = VMX_NESTED_EVENT_ACTION_INJECT_L2;
		if (input->kind == VMX_NESTED_EVENT_EXTERNAL_INTERRUPT) {
			if (!input->vector_valid)
				return (EINVAL);
			candidate.vector = input->vector;
		} else {
			candidate.vector = 2;
			candidate.block_nmi = true;
		}
		candidate.consume_event = true;
		candidate.interruption_info_valid = true;
	}
	if (vmx_nested_event_plan_validate(&candidate) != 0)
		return (EINVAL);
	*plan = candidate;
	return (0);
}
