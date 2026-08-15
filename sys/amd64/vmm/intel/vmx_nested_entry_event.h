/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_ENTRY_EVENT_H_
#define	_VMM_INTEL_VMX_NESTED_ENTRY_EVENT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_event.h"

struct vmx_nested_vmcs02_plan;

enum vmx_nested_entry_event_action {
	VMX_NESTED_ENTRY_EVENT_NONE = 0,
	VMX_NESTED_ENTRY_EVENT_VMCS12,
	VMX_NESTED_ENTRY_EVENT_INJECT_L0,
	VMX_NESTED_ENTRY_EVENT_SHUTDOWN,
};

struct vmx_nested_entry_event_input {
	uint64_t	l0_intinfo;
	uint32_t	l0_instruction_length;
	uint32_t	vmcs12_intr_info;
	uint32_t	vmcs12_exception_error;
	uint32_t	vmcs12_instruction_length;
	bool		vmcs12_event_validated;
	bool		zero_instruction_length_allowed;
	bool		l0_valid;
	bool		l0_triple_fault;
	bool		async_valid;
	struct vmx_nested_event_plan async_event;
};

/*
 * Value-only event image for the final VMCS02 build.  consume_l0 is an
 * obligation, not an action: the owner may commit the matching generic
 * vm_intinfo snapshot only after VM entry succeeds (or when committing the
 * planned shutdown).
 */
struct vmx_nested_entry_event_plan {
	enum vmx_nested_entry_event_action	action;
	uint32_t	entry_intr_info;
	uint32_t	entry_exception_error;
	uint32_t	entry_instruction_length;
	bool		zero_instruction_length_allowed;
	bool		consume_l0;
	bool		async_valid;
	struct vmx_nested_event_plan async_event;
};

int	vmx_nested_entry_event_plan(
	    const struct vmx_nested_entry_event_input *,
	    struct vmx_nested_entry_event_plan *);
/*
 * Apply a non-shutdown event plan to an unpublished value-only VMCS02 plan.
 * The original VMCS12 entry-event field remains unchanged for later
 * VM-exit reconstruction.  Output is unchanged on failure.
 */
int	vmx_nested_entry_event_apply(
	    const struct vmx_nested_entry_event_plan *,
	    const struct vmx_nested_vmcs02_plan *,
	    struct vmx_nested_vmcs02_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_ENTRY_EVENT_H_ */
