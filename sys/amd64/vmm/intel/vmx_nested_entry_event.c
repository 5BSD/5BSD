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

#include <machine/vmm.h>

#include "vmx_nested_entry_event.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs02.h"

#define	NVMX_ENTRY_VALID	(UINT32_C(1) << 31)
#define	NVMX_ENTRY_TYPE_MASK	(UINT32_C(7) << 8)
#define	NVMX_ENTRY_ERROR_VALID	(UINT32_C(1) << 11)
#define	NVMX_ENTRY_ALLOWED	(UINT32_C(0x80000fff))
#define	NVMX_ENTRY_SW_EXCEPTION	(UINT32_C(6) << 8)
#define	NVMX_PRIMARY_INTERRUPT_WINDOW	(UINT32_C(1) << 2)
#define	NVMX_PRIMARY_NMI_WINDOW		(UINT32_C(1) << 22)
#define	NVMX_SECONDARY_UNRESTRICTED	(UINT32_C(1) << 7)
#define	NVMX_ENTRY_EXTERNAL_INTERRUPT	(UINT32_C(0) << 8)
#define	NVMX_ENTRY_NMI			(UINT32_C(2) << 8)

static bool
nvmxee_exception_has_error(uint32_t vector)
{

	/*
	 * Keep this independent of the generic exception queue.  These are the
	 * Intel VM-entry event-injection vectors whose hardware-exception form
	 * carries an error code in protected mode.
	 */
	return (vector == 8 || (vector >= 10 && vector <= 14) ||
	    vector == 17);
}

static bool
nvmxee_async_absent(const struct vmx_nested_event_plan *event)
{

	return (event->kind == VMX_NESTED_EVENT_EXTERNAL_INTERRUPT &&
	    event->action == VMX_NESTED_EVENT_ACTION_NONE &&
	    !event->arm_interrupt_window && !event->arm_nmi_window &&
	    !event->consume_event && !event->block_nmi &&
	    !event->interruption_info_valid && event->vector == 0);
}

static int
nvmxee_l0_event_validate(uint32_t info, uint32_t error,
    uint32_t instruction_length, bool zero_instruction_length_allowed,
    bool mode_known, bool protected_mode)
{
	uint32_t type, vector;
	bool deliver_error, error_required, software;

	if ((info & NVMX_ENTRY_VALID) == 0)
		return (EINVAL);
	if ((info & ~NVMX_ENTRY_ALLOWED) != 0 || instruction_length > 15)
		return (EINVAL);
	type = (info & NVMX_ENTRY_TYPE_MASK) >> 8;
	vector = info & 0xff;
	software = type == 4 || type == 5 || type == 6;
	deliver_error = (info & NVMX_ENTRY_ERROR_VALID) != 0;
	error_required = type == 3 && protected_mode &&
	    nvmxee_exception_has_error(vector);
	if (type == 1 || type == 7 ||
	    (type == 2 && vector != 2) ||
	    (type == 3 && vector >= 32) ||
	    (type == 5 && vector != 1) ||
	    (type == 6 && vector != 3 && vector != 4) ||
	    (deliver_error &&
	    (type != 3 || !nvmxee_exception_has_error(vector) ||
	    (error >> 16) != 0)) ||
	    (!deliver_error && error != 0) ||
	    (mode_known && deliver_error != error_required) ||
	    (!software && instruction_length != 0) ||
	    (software && instruction_length == 0 &&
	    !zero_instruction_length_allowed))
		return (EINVAL);
	return (0);
}

int
vmx_nested_entry_event_plan(
    const struct vmx_nested_entry_event_input *input,
    struct vmx_nested_entry_event_plan *plan)
{
	struct vmx_nested_entry_event_plan candidate;
	uint32_t info, type, vector;
	int error;

	if (input == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    !input->vmcs12_event_validated ||
	    (input->async_valid &&
	    vmx_nested_event_plan_validate(&input->async_event) != 0) ||
	    (!input->async_valid &&
	    !nvmxee_async_absent(&input->async_event)) ||
	    (input->l0_valid && input->l0_triple_fault) ||
	    (!input->l0_valid && !input->l0_triple_fault &&
	    (input->l0_intinfo != 0 ||
	    input->l0_instruction_length != 0)))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	if (input->l0_triple_fault) {
		if (input->l0_intinfo != 0 ||
		    input->l0_instruction_length != 0)
			return (EINVAL);
		candidate.action = VMX_NESTED_ENTRY_EVENT_SHUTDOWN;
		candidate.zero_instruction_length_allowed =
		    input->zero_instruction_length_allowed;
		candidate.consume_l0 = true;
		*plan = candidate;
		return (0);
	}
	if (input->l0_valid) {
		info = (uint32_t)input->l0_intinfo;
		if ((input->l0_intinfo >> 32) != 0 &&
		    (info & VM_INTINFO_DEL_ERRCODE) == 0)
			return (EINVAL);
		if ((info & VM_INTINFO_VALID) == 0 ||
		    (info & VM_INTINFO_RSVD) != 0)
			return (EINVAL);
		type = info & VM_INTINFO_TYPE;
		vector = VM_INTINFO_VECTOR(info);
		if ((type == VM_INTINFO_NMI && vector != 2) ||
		    (type == VM_INTINFO_HWEXCEPTION && vector >= 32))
			return (EINVAL);
		/*
		 * VT-x requires #BP and #OF to use the software-exception
		 * type even when the generic x86 exception queue represents
		 * them as hardware exceptions.
		 */
		if (type == VM_INTINFO_HWEXCEPTION &&
		    (vector == 3 || vector == 4)) {
			info &= ~NVMX_ENTRY_TYPE_MASK;
			info |= NVMX_ENTRY_SW_EXCEPTION;
			type = NVMX_ENTRY_SW_EXCEPTION;
		}
		error = nvmxee_l0_event_validate(info,
		    (uint32_t)(input->l0_intinfo >> 32),
		    input->l0_instruction_length,
		    input->zero_instruction_length_allowed, false, false);
		if (error != 0)
			return (error);
	}
	if ((input->vmcs12_intr_info & NVMX_ENTRY_VALID) != 0) {
		candidate.action = VMX_NESTED_ENTRY_EVENT_VMCS12;
		candidate.zero_instruction_length_allowed =
		    input->zero_instruction_length_allowed;
		candidate.entry_intr_info = input->vmcs12_intr_info;
		candidate.entry_exception_error =
		    input->vmcs12_exception_error;
		candidate.entry_instruction_length =
		    input->vmcs12_instruction_length;
		*plan = candidate;
		return (0);
	}
	if (!input->l0_valid) {
		candidate.action = VMX_NESTED_ENTRY_EVENT_NONE;
		candidate.zero_instruction_length_allowed =
		    input->zero_instruction_length_allowed;
		candidate.entry_intr_info = input->vmcs12_intr_info;
		candidate.entry_exception_error =
		    input->vmcs12_exception_error;
		candidate.entry_instruction_length =
		    input->vmcs12_instruction_length;
		if (input->async_valid &&
		    input->async_event.action !=
		    VMX_NESTED_EVENT_ACTION_NONE &&
		    input->async_event.action !=
		    VMX_NESTED_EVENT_ACTION_DEFER) {
			candidate.async_valid = true;
			candidate.async_event = input->async_event;
		}
		*plan = candidate;
		return (0);
	}

	candidate.action = VMX_NESTED_ENTRY_EVENT_INJECT_L0;
	candidate.zero_instruction_length_allowed =
	    input->zero_instruction_length_allowed;
	candidate.entry_intr_info = info;
	candidate.entry_exception_error =
	    (uint32_t)(input->l0_intinfo >> 32);
	if (type == VM_INTINFO_SWINTR || type == (UINT32_C(5) << 8) ||
	    type == NVMX_ENTRY_SW_EXCEPTION)
		candidate.entry_instruction_length =
		    input->l0_instruction_length;
	candidate.consume_l0 = true;
	*plan = candidate;
	return (0);
}

int
vmx_nested_entry_event_apply(
    const struct vmx_nested_entry_event_plan *event,
    const struct vmx_nested_vmcs02_plan *current,
    struct vmx_nested_vmcs02_plan *next)
{
	struct vmx_nested_vmcs02_plan candidate;
	int error;

	if (event == NULL || current == NULL || next == NULL ||
	    current->vmentry.disposition != VMX_NESTED_VMENTRY_READY ||
	    !vmx_nested_vmcs02_id_equal(&current->id, &current->image.id))
		return (EINVAL);
	switch (event->action) {
	case VMX_NESTED_ENTRY_EVENT_NONE:
	case VMX_NESTED_ENTRY_EVENT_VMCS12:
		if (event->consume_l0 ||
		    event->entry_intr_info != current->image.entry_intr_info ||
		    event->entry_exception_error !=
		    current->image.entry_exception_error ||
		    event->entry_instruction_length !=
		    current->image.entry_instruction_length)
			return (EINVAL);
		break;
	case VMX_NESTED_ENTRY_EVENT_INJECT_L0:
		if (!event->consume_l0)
			return (EINVAL);
		error = nvmxee_l0_event_validate(event->entry_intr_info,
		    event->entry_exception_error,
		    event->entry_instruction_length,
		    event->zero_instruction_length_allowed, true,
		    (current->image.controls.secondary &
		    NVMX_SECONDARY_UNRESTRICTED) == 0 ||
		    (current->image.l2_control.cr0 & 1) != 0);
		if (error != 0)
			return (error);
		break;
	case VMX_NESTED_ENTRY_EVENT_SHUTDOWN:
	default:
		return (EINVAL);
	}
	if (event->async_valid &&
	    vmx_nested_event_plan_validate(&event->async_event) != 0)
		return (EINVAL);
	if (!event->async_valid &&
	    !nvmxee_async_absent(&event->async_event))
		return (EINVAL);
	if (event->async_valid &&
	    event->action != VMX_NESTED_ENTRY_EVENT_NONE)
		return (EINVAL);
	candidate = *current;
	candidate.image.entry_intr_info = event->entry_intr_info;
	candidate.image.entry_exception_error =
	    event->entry_exception_error;
	candidate.image.entry_instruction_length =
	    event->entry_instruction_length;
	if (event->async_valid) {
		switch (event->async_event.action) {
		case VMX_NESTED_EVENT_ACTION_WAIT_FOR_WINDOW:
			if (event->async_event.arm_interrupt_window)
				candidate.image.controls.primary |=
				    NVMX_PRIMARY_INTERRUPT_WINDOW;
			if (event->async_event.arm_nmi_window)
				candidate.image.controls.primary |=
				    NVMX_PRIMARY_NMI_WINDOW;
			break;
		case VMX_NESTED_EVENT_ACTION_INJECT_L2:
			candidate.image.entry_intr_info = NVMX_ENTRY_VALID |
			    (event->async_event.kind ==
			    VMX_NESTED_EVENT_NMI ? NVMX_ENTRY_NMI :
			    NVMX_ENTRY_EXTERNAL_INTERRUPT) |
			    event->async_event.vector;
			candidate.image.entry_exception_error = 0;
			candidate.image.entry_instruction_length = 0;
			break;
		case VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW:
		case VMX_NESTED_EVENT_ACTION_REFLECT_EVENT:
			/*
			 * These actions synthesize an L1 VM exit and must not
			 * be mistaken for a hardware-entry image.
			 */
			return (EAGAIN);
		default:
			return (EINVAL);
		}
	}
	*next = candidate;
	return (0);
}
