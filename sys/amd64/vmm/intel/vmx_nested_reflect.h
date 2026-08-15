/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_REFLECT_H_
#define	_VMM_INTEL_VMX_NESTED_REFLECT_H_

#include "vmx_nested_types.h"

struct vmx_nested_entry_controls;
struct vmx_nested_execution_state;

enum vmx_nested_exit_action {
	VMX_NESTED_EXIT_HANDLE_L0 = 0,
	VMX_NESTED_EXIT_REFLECT_L1,
	VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1,
};

enum vmx_nested_ept_fault_source {
	VMX_NESTED_EPT_FAULT_NONE = 0,
	VMX_NESTED_EPT_FAULT_L0,
	VMX_NESTED_EPT_FAULT_L1,
};

enum vmx_nested_event_source {
	VMX_NESTED_EVENT_NONE = 0,
	VMX_NESTED_EVENT_L0,
	VMX_NESTED_EVENT_L1,
};

enum vmx_nested_outer_exit_dispatch {
	VMX_NESTED_OUTER_EXIT_ROUTE = 0,
	VMX_NESTED_OUTER_EXIT_EPT_WALK,
};

/*
 * Facts known by the outer VMCS02 owner before exit routing.  In particular,
 * a hardware EPT violation against a composed root has no architectural
 * L0/L1 provenance until L0 walks L1's EPT.  Keep that case distinct from
 * ordinary routing rather than guessing an owner.
 */
struct vmx_nested_outer_exit_facts {
	bool	l0_must_handle;
	bool	l1_ept_enabled;
	bool	l1_preemption_timer_armed;
};

/*
 * Inputs which require decoding a bitmap, qualification, or L0 policy are
 * supplied as decisions by the corresponding decoder.  Keeping those
 * decisions explicit prevents this routing layer from dereferencing guest
 * memory or silently conflating L0 and L1 intercepts.
 */
struct vmx_nested_exit_context {
	uint16_t	reason;
	uint8_t		vector;
	bool		interruption_valid;
	bool		interruption_is_nmi;
	bool		entry_failure;
	bool		l0_must_handle;
	bool		dynamic_l1_intercept;
	bool		vmcs12_other_event;
	bool		l1_timer_expired;
	uint32_t	pinbased;
	uint32_t	primary;
	uint32_t	secondary;
	uint32_t	exception_bitmap;
	uint32_t	page_fault_error;
	uint32_t	page_fault_mask;
	uint32_t	page_fault_match;
	enum vmx_nested_event_source event_source;
	enum vmx_nested_ept_fault_source ept_fault_source;
	enum vmx_nested_ept_fault_source ept_misconfiguration_source;
};

/*
 * Frozen L1 policy and explicit L0 decisions used to classify one hardware
 * VM exit.  Hardware-derived fields are deliberately absent so callers
 * cannot accidentally route a reason, vector, or entry-failure indication
 * that differs from the captured VMCS02 exit state.
 */
struct vmx_nested_exit_policy {
	bool		l0_must_handle;
	bool		dynamic_l1_intercept;
	bool		vmcs12_other_event;
	bool		l1_timer_expired;
	uint32_t	pinbased;
	uint32_t	primary;
	uint32_t	secondary;
	uint32_t	exception_bitmap;
	uint32_t	page_fault_mask;
	uint32_t	page_fault_match;
	enum vmx_nested_event_source event_source;
	enum vmx_nested_ept_fault_source ept_fault_source;
	enum vmx_nested_ept_fault_source ept_misconfiguration_source;
};

/*
 * Per-exit facts owned by L0.  These cannot be inferred from VMCS12 control
 * bits: an interrupt may originate at either virtualization level, and an
 * EPT exit is not reflectable until the nested walk identifies its source.
 */
struct vmx_nested_exit_provenance {
	bool		l0_must_handle;
	bool		l1_timer_expired;
	enum vmx_nested_event_source event_source;
	enum vmx_nested_ept_fault_source ept_fault_source;
	enum vmx_nested_ept_fault_source ept_misconfiguration_source;
};

struct vmx_nested_cr_context {
	uint64_t	qualification;
	uint64_t	gpr_value;
	uint64_t	cr0_mask;
	uint64_t	cr0_shadow;
	uint64_t	cr4_mask;
	uint64_t	cr4_shadow;
	uint64_t	cr3_target[4];
	uint32_t	primary;
	uint32_t	cr3_target_count;
};

struct vmx_nested_dynamic_exit {
	const struct vmx_nested_entry_controls *controls;
	const struct vmx_nested_execution_state *execution;
	const uint8_t	*io_policy;
	const uint8_t	*msr_policy;
	uint64_t	qualification;
	uint64_t	gpr_value;
	uint32_t	reason;
	uint32_t	msr_index;
};

/*
 * Architecturally visible VMCS12 exit state.  This structure contains values,
 * not a hardware VMCS image, so callers can validate and commit the complete
 * transition before touching guest memory.
 */
struct vmx_nested_exit_information {
	uint64_t	exit_qualification;
	uint64_t	guest_linear_address;
	uint64_t	guest_physical_address;
	uint32_t	exit_reason;
	uint32_t	exit_interruption_info;
	uint32_t	exit_interruption_error;
	uint32_t	idt_vectoring_info;
	uint32_t	idt_vectoring_error;
	uint32_t	exit_instruction_length;
	uint32_t	exit_instruction_info;
	uint32_t	entry_interruption_info;
	bool		launched;
};

static __inline bool
vmx_nested_exit_information_equal(
    const struct vmx_nested_exit_information *a,
    const struct vmx_nested_exit_information *b)
{

	return (a != NULL && b != NULL &&
	    a->exit_qualification == b->exit_qualification &&
	    a->guest_linear_address == b->guest_linear_address &&
	    a->guest_physical_address == b->guest_physical_address &&
	    a->exit_reason == b->exit_reason &&
	    a->exit_interruption_info == b->exit_interruption_info &&
	    a->exit_interruption_error == b->exit_interruption_error &&
	    a->idt_vectoring_info == b->idt_vectoring_info &&
	    a->idt_vectoring_error == b->idt_vectoring_error &&
	    a->exit_instruction_length == b->exit_instruction_length &&
	    a->exit_instruction_info == b->exit_instruction_info &&
	    a->entry_interruption_info == b->entry_interruption_info &&
	    a->launched == b->launched);
}

int	vmx_nested_exit_route(const struct vmx_nested_exit_context *,
	    enum vmx_nested_exit_action *);
int	vmx_nested_exit_context_prepare(
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_exit_policy *,
	    struct vmx_nested_exit_context *);
int	vmx_nested_exit_policy_prepare(
	    const struct vmx_nested_entry_controls *,
	    const struct vmx_nested_execution_state *,
	    const struct vmx_nested_exit_provenance *,
	    struct vmx_nested_exit_policy *);
int	vmx_nested_exit_provenance_prepare(
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_exit_provenance *,
	    struct vmx_nested_exit_provenance *);
int	vmx_nested_outer_exit_prepare(
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_outer_exit_facts *,
	    enum vmx_nested_outer_exit_dispatch *,
	    struct vmx_nested_exit_provenance *);
int	vmx_nested_dynamic_intercept_prepare(
	    const struct vmx_nested_dynamic_exit *, bool *);
int	vmx_nested_exit_dispatch_prepare(
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_exit_policy *,
	    const struct vmx_nested_dynamic_exit *,
	    struct vmx_nested_exit_context *,
	    enum vmx_nested_exit_action *);
bool	vmx_nested_exit_reason_is_dynamic(uint32_t);
int	vmx_nested_cr_intercept(const struct vmx_nested_cr_context *, bool *);
int	vmx_nested_exit_information_prepare(
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_exit_information *,
	    struct vmx_nested_exit_information *);

#endif /* _VMM_INTEL_VMX_NESTED_REFLECT_H_ */
