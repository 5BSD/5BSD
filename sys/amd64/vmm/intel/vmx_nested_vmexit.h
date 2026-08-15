/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMEXIT_H_
#define	_VMM_INTEL_VMX_NESTED_VMEXIT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_guest.h"
#include "vmx_nested_host.h"
#include "vmx_nested_msr.h"
#include "vmx_nested_msr_state.h"
#include "vmx_nested_pdpte.h"
#include "vmx_nested_runtime.h"

/*
 * Architectural processor state captured at the start of a nested VM exit.
 * The hardware-facing layer must populate this value before modifying VMCS01
 * or any L1-visible VMCS12 field.
 *
 * preemption_timer_value is the VMX-preemption timer residual observed by
 * the same destructive capture, and is meaningful only while
 * preemption_timer_valid is set (the timer was programmed for this L2
 * execution).  The exit-state commit consumes it to honor the "save
 * VMX-preemption timer value" exit control; a runtime image whose L2 never
 * reached hardware carries an invalid capture, and the unconsumed VMCS12
 * value is then already the current residual.
 */
struct vmx_nested_l2_runtime_state {
	struct vmx_nested_guest_control_state	control;
	struct vmx_nested_guest_arch_state	arch;
	uint32_t	preemption_timer_value;
	bool		preemption_timer_valid;
};

struct vmx_nested_vmexit_state_input {
	const struct vmx_nested_host_state		*l1_host;
	const struct vmx_nested_l2_runtime_state	*l2_runtime;
	const struct vmx_nested_guest_control_state	*vmcs12_control;
	const struct vmx_nested_guest_arch_state	*vmcs12_arch;
	uint32_t	vmexit;
	uint32_t	vmcs12_vmentry;
	uint32_t	vmcs12_entry_intr_info;
	bool		save_guest_lma;
};

/*
 * Value-only nested-exit state transition.  saved_l2_* is the prospective
 * VMCS12 guest-state area.  l1_runtime is the effective processor state after
 * loading the VMCS12 host-state area; it is not simply the pre-entry L1 state.
 */
struct vmx_nested_vmexit_state_plan {
	struct vmx_nested_guest_control_state	saved_l2_control;
	struct vmx_nested_guest_arch_state	saved_l2_arch;
	struct vmx_nested_host_state		l1_host;
	struct vmx_nested_l1_runtime_state	l1_runtime;
	struct vmx_nested_guest_control_state	l1_control;
	struct vmx_nested_guest_arch_state	l1_arch;
	struct vmx_nested_pdpte_state		l1_pdpte;
	uint32_t	saved_vmcs12_vmentry;
	uint32_t	saved_vmcs12_entry_intr_info;
};

struct vmx_nested_failed_entry_state_input {
	const struct vmx_nested_host_state		*l1_host;
	const struct vmx_nested_l1_runtime_state	*pre_entry_l1;
	uint32_t	vmexit;
};

/*
 * A late VM-entry failure never starts L2 and therefore saves no guest
 * state, but it performs the VM-exit host-state load.  Keep that transition
 * separate from an ordinary nested VM exit so callers cannot accidentally
 * publish prospective L2 state as executed state.
 */
struct vmx_nested_failed_entry_state_plan {
	struct vmx_nested_host_state		l1_host;
	struct vmx_nested_l1_runtime_state	l1_runtime;
	struct vmx_nested_guest_control_state	l1_control;
	struct vmx_nested_guest_arch_state	l1_arch;
	struct vmx_nested_pdpte_state		l1_pdpte;
};

int	vmx_nested_vmexit_state_prepare(
	    const struct vmx_nested_vmexit_state_input *,
	    struct vmx_nested_vmexit_state_plan *);
int	vmx_nested_failed_entry_state_prepare(
	    const struct vmx_nested_failed_entry_state_input *,
	    struct vmx_nested_failed_entry_state_plan *);

/*
 * Apply the already snapshotted VM-exit MSR-load list to value-only L1
 * processor state.  Both outputs are atomic: a rejected MSR or a rollback
 * failure leaves the caller's plan and software bank unchanged.
 */
int	vmx_nested_vmexit_msr_load_prepare(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_vmexit_state_plan *,
	    const struct vmx_nested_software_msrs *,
	    bool, bool, const struct vmx_nested_msr_entry *, uint32_t,
	    struct vmx_nested_msr_entry *, uint32_t,
	    struct vmx_nested_vmexit_state_plan *,
	    struct vmx_nested_software_msrs *,
	    enum vmx_nested_exit_msr_load_outcome *, uint32_t *);
int	vmx_nested_failed_entry_msr_load_prepare(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_failed_entry_state_plan *,
	    const struct vmx_nested_software_msrs *,
	    bool, bool, const struct vmx_nested_msr_entry *, uint32_t,
	    struct vmx_nested_msr_entry *, uint32_t,
	    struct vmx_nested_failed_entry_state_plan *,
	    struct vmx_nested_software_msrs *,
	    enum vmx_nested_exit_msr_load_outcome *, uint32_t *);

#endif /* _VMM_INTEL_VMX_NESTED_VMEXIT_H_ */
