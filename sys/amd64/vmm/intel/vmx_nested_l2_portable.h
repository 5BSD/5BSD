/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_PORTABLE_H_
#define	_VMM_INTEL_VMX_NESTED_L2_PORTABLE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_msr_state.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_vmcs02.h"
#include "vmx_nested_vmexit.h"

/*
 * Canonical, value-only state needed to continue an L0-owned exit from L2.
 * This is an internal architectural image, not an on-disk wire encoding.
 * A checkpoint encoder must serialize each field explicitly.
 *
 * General-purpose registers remain in the enclosing vCPU state.  Hardware
 * VMCS identities, EPT roots, VPID leases, host pointers, and backend
 * handles are deliberately absent and must be reconstructed on thaw.
 */
struct vmx_nested_l2_portable_state {
	struct vmx_nested_vmcs02_id		id;
	uint64_t				portable_generation;
	uint64_t				capability_signature;
	struct vmx_nested_l2_runtime_state	runtime;
	struct vmx_nested_software_msrs		software_msrs;
	struct vmx_nested_exit_information	exit;
	struct vmx_nested_pdpte_state		pdpte;
	struct vmx_nested_timer_state		preemption_timer;
	uint32_t				entry_intr_info;
	uint32_t				entry_exception_error;
	uint32_t				entry_instruction_length;
	uint16_t				guest_interrupt_status;
	bool					exit_valid;
	bool					preemption_timer_enabled;
	bool					guest_interrupt_status_valid;
	/*
	 * A pending monitor-trap exit belongs to this exact portable
	 * generation.  It is set only when an L0-emulated L2 instruction
	 * retires with VMCS12 monitor-trap exiting enabled, and must be
	 * consumed before another L2 instruction executes.
	 */
	bool					mtf_pending;
};

/*
 * Architecture-adapter capture before the portable generation is assigned.
 * Software-owned MSRs are captured separately because their transition back
 * to L1 is an independently rollbackable CPU-state operation.
 */
struct vmx_nested_l2_capture_values {
	struct vmx_nested_l2_runtime_state	runtime;
	struct vmx_nested_exit_information	exit;
	struct vmx_nested_pdpte_state		pdpte;
	struct vmx_nested_timer_state		preemption_timer;
	uint32_t				entry_intr_info;
	uint32_t				entry_exception_error;
	uint32_t				entry_instruction_length;
	uint16_t				guest_interrupt_status;
	bool					guest_interrupt_status_valid;
};

struct vmx_nested_l2_portable_input {
	const struct vmx_nested_vmcs02_plan	*executed_plan;
	const struct vmx_nested_capabilities	*capabilities;
	const struct vmx_nested_l2_runtime_state	*runtime;
	const struct vmx_nested_software_msrs	*software_msrs;
	const struct vmx_nested_exit_information	*exit;
	const struct vmx_nested_pdpte_state	*pdpte;
	const struct vmx_nested_timer_state	*preemption_timer;
	uint64_t				portable_generation;
	uint32_t				entry_intr_info;
	uint32_t				entry_exception_error;
	uint32_t				entry_instruction_length;
	uint16_t				guest_interrupt_status;
	bool					guest_interrupt_status_valid;
};

int	vmx_nested_l2_portable_capture(
	    const struct vmx_nested_l2_portable_input *,
	    struct vmx_nested_l2_portable_state *);
int	vmx_nested_l2_portable_validate(
	    const struct vmx_nested_l2_portable_state *);
/*
 * Overlay a validated architectural image on the original value-only plan.
 * Runtime resource identity is stripped.  The caller must bind fresh EPT,
 * VPID, bitmap, APIC, and MSR resources before programming VMCS02.
 */
int	vmx_nested_l2_portable_apply(
	    const struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_vmcs02_plan *,
	    struct vmx_nested_vmcs02_plan *);
/*
 * Commit the machine-independent instruction-emulation boundary to a cold
 * L2 image before resource acquisition.  A next RIP equal to the common
 * exit RIP means that the instruction was explicitly restarted.  Otherwise
 * it must be exactly the architecture-neutral decoder's instruction
 * boundary; the Intel VM-exit instruction-length field is not authoritative
 * for EPT/MMIO exits.
 */
int	vmx_nested_l2_portable_complete_instruction(
	    struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_vmcs02_plan *, uint64_t, uint32_t,
	    uint64_t, bool *);
/*
 * Construct an immutable reflected-exit image without consuming the pending
 * MTF owner, then clear that owner only after the caller has published the
 * exit.  Both operations compare the portable generation.  Callers must first
 * arbitrate VMX_NESTED_PENDING_MTF against other eligible events.
 */
int	vmx_nested_l2_portable_mtf_peek(
	    const struct vmx_nested_l2_portable_state *, uint64_t,
	    struct vmx_nested_exit_information *);
int	vmx_nested_l2_portable_mtf_commit(
	    struct vmx_nested_l2_portable_state *, uint64_t);

#endif /* _VMM_INTEL_VMX_NESTED_L2_PORTABLE_H_ */
