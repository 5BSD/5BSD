/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_H_

#include "vmx_nested_types.h"

#include "vmx_nested_compose.h"
#include "vmx_nested_ept_cache.h"
#include "vmx_nested_execution.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_host.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_pdpte.h"
#include "vmx_nested_runtime.h"
#include "vmx_nested_timer.h"
#include "vmx_nested_tsc.h"
#include "vmx_nested_vmentry.h"

struct vmx_nested_capabilities;
struct vmx_nested_software_msrs;

struct vmx_nested_vmcs02_id {
	uint64_t	state_generation;
	uint64_t	execution_epoch;
	uint64_t	vmcs12_gpa;
};

/* Intel VMX regions are 4-Kbyte aligned; UINT64_MAX means no current VMCS. */
static __inline bool
vmx_nested_vmcs02_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (id != NULL && id->state_generation != 0 &&
	    id->execution_epoch != 0 && id->vmcs12_gpa != ~(uint64_t)0 &&
	    (id->vmcs12_gpa & 0xfffULL) == 0);
}

static __inline bool
vmx_nested_vmcs02_id_equal(const struct vmx_nested_vmcs02_id *left,
    const struct vmx_nested_vmcs02_id *right)
{

	return (left != NULL && right != NULL &&
	    left->state_generation == right->state_generation &&
	    left->execution_epoch == right->execution_epoch &&
	    left->vmcs12_gpa == right->vmcs12_gpa);
}

/*
 * Pointer-bearing inputs are consumed synchronously by prepare().  They are
 * never retained and are deliberately absent from the prepared image.
 */
struct vmx_nested_vmcs02_input {
	struct vmx_nested_vmcs02_id		id;
	const struct vmx_nested_capabilities	*virtual_capabilities;
	const struct vmx_nested_vmcs02_capabilities *hardware_capabilities;
	const struct vmx_nested_vmcs02_policy	*control_policy;
	const struct vmx_nested_vmcs02_controls	*l0_controls;
	const struct vmx_nested_execution_state	*l0_execution;
	const struct vmx_nested_l1_runtime_state	*l1_runtime;
	const struct vmx_nested_vmentry_input	*vmentry;
	const struct vmx_nested_tsc_scale_input	*tsc;
	const struct vmx_nested_vpid_transition	*vpid;
	uint64_t	l1_virtual_tsc;
	uint64_t	capability_signature;
	uint32_t	preemption_timer_value;
	uint32_t	l0_cr3_target_count;
	uint8_t		preemption_timer_rate;
	bool		preemption_timer_enabled;
};

/*
 * A canonical, value-only representation of one prospective L2 execution.
 * It is runtime state, not a portable checkpoint format and not a hardware
 * VMCS.  Runtime-only EPT roots and VPIDs are reconstructed after restore.
 */
struct vmx_nested_vmcs02_image {
	struct vmx_nested_vmcs02_id		id;
	struct vmx_nested_vmcs02_controls	controls;
	struct vmx_nested_execution_plan	execution;
	struct vmx_nested_l1_runtime_state	l1_runtime;
	struct vmx_nested_host_state		l1_host;
	/*
	 * Preserve the original VMCS12 values separately from effective L2
	 * state.  VM-exit save controls select between these values and the
	 * captured L2 runtime values; the composed VMCS02 image alone cannot
	 * reconstruct that choice.
	 */
	struct vmx_nested_guest_control_state	vmcs12_control;
	struct vmx_nested_guest_arch_state	vmcs12_arch;
	struct vmx_nested_guest_control_state	l2_control;
	struct vmx_nested_guest_arch_state	l2_arch;
	struct vmx_nested_pdpte_state		pdpte;
	struct vmx_nested_tsc_scale_plan	tsc;
	struct vmx_nested_vpid_plan		vpid;
	struct vmx_nested_ept_cache_key		ept;
	struct vmx_nested_timer_state		preemption_timer;
	uint32_t	entry_intr_info;
	uint32_t	entry_exception_error;
	uint32_t	entry_instruction_length;
	uint32_t	vmcs12_vmexit;
	uint32_t	vmcs12_vmentry;
	uint32_t	vmcs12_entry_intr_info;
	uint32_t	tpr_threshold;
	uint32_t	cr3_target_count;
	uint16_t	posted_interrupt_vector;
	uint8_t		preemption_timer_rate;
	bool		ept_enabled;
	bool		preemption_timer_enabled;
	bool		save_guest_lma;
};

struct vmx_nested_vmcs02_plan {
	struct vmx_nested_vmcs02_id		id;
	struct vmx_nested_vmentry_result	vmentry;
	struct vmx_nested_vmcs02_image		image;
};

int	vmx_nested_vmcs02_prepare(
	    const struct vmx_nested_vmcs02_input *,
	    struct vmx_nested_vmcs02_plan *);
/*
 * Construct the effective pre-MSR-load L2 state without creating or
 * publishing a VMCS02 image.  Frozen entry uses this value-owned state as
 * the validation and apply context for VMCS12 MSR lists.
 */
int	vmx_nested_vmcs02_effective_guest_state(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_entry_controls *,
	    const struct vmx_nested_l1_runtime_state *,
	    const struct vmx_nested_guest_control_state *,
	    const struct vmx_nested_guest_arch_state *,
	    struct vmx_nested_guest_control_state *,
	    struct vmx_nested_guest_arch_state *);
int	vmx_nested_vmcs02_arm_timer(struct vmx_nested_vmcs02_plan *,
	    uint64_t);
/*
 * Rebase a captured running timer on a destination L1 virtual-TSC.  This
 * preserves the architectural remaining count while discarding the source
 * host's deadline origin.
 */
int	vmx_nested_vmcs02_rearm_timer(struct vmx_nested_vmcs02_plan *,
	    uint64_t);
/*
 * Production frozen-entry boundary.  It validates and snapshots the VMCS12
 * entry MSR list exactly once, then composes VMCS02 from that same validation
 * result without invoking the validate-only MSR path.
 */
int	vmx_nested_vmcs02_prepare_frozen(
	    const struct vmx_nested_vmcs02_input *,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *,
	    struct vmx_nested_vmcs02_plan *);
/*
 * Recompose an already validated frozen entry against a refreshed L0
 * execution environment.  This performs no guest-memory access and is used
 * after migration to the final host CPU, where VMCS01 controls may differ
 * from the earlier instruction-emulation capture.  Callers reapply the
 * immutable snapshotted MSR list to the returned prospective image.
 */
int	vmx_nested_vmcs02_recompose_frozen(
	    const struct vmx_nested_vmcs02_input *,
	    const struct vmx_nested_vmentry_result *,
	    struct vmx_nested_vmcs02_plan *);
/*
 * Reapply the immutable entry-MSR snapshot after final-CPU recomposition.
 * This is value-only and performs no guest-memory access.  Both output
 * objects are published together only after every entry succeeds; rollback
 * scratch is caller-owned bounded storage and is not retained.
 */
int	vmx_nested_vmcs02_apply_frozen_msrs(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_msr_entry *, uint32_t,
	    const struct vmx_nested_software_msrs *,
	    struct vmx_nested_msr_entry *, uint32_t,
	    bool, bool,
	    const struct vmx_nested_vmcs02_plan *,
	    struct vmx_nested_vmcs02_plan *,
	    struct vmx_nested_software_msrs *);

enum vmx_nested_vmcs02_apply_outcome {
	VMX_NESTED_VMCS02_APPLY_OK = 0,
	VMX_NESTED_VMCS02_APPLY_RETRY,
	VMX_NESTED_VMCS02_APPLY_FATAL,
};

/*
 * apply() owns the hardware-VMCS commit boundary.  Before returning RETRY or
 * FATAL it must restore VMCS01 and undo all externally visible runtime
 * changes.  The callback is invoked without retaining either it or arg.
 */
struct vmx_nested_vmcs02_apply_ops {
	enum vmx_nested_vmcs02_apply_outcome (*apply)(void *,
	    const struct vmx_nested_vmcs02_image *, int *);
};

enum vmx_nested_vmcs02_commit_state {
	VMX_NESTED_VMCS02_COMMIT_IDLE = 0,
	VMX_NESTED_VMCS02_COMMIT_PENDING,
	VMX_NESTED_VMCS02_COMMIT_APPLYING,
	VMX_NESTED_VMCS02_COMMIT_RESOLVED,
};

enum vmx_nested_vmcs02_commit_disposition {
	VMX_NESTED_VMCS02_COMMITTED = 0,
	VMX_NESTED_VMCS02_HOST_ERROR,
};

struct vmx_nested_vmcs02_commit_result {
	struct vmx_nested_vmcs02_id id;
	enum vmx_nested_vmcs02_commit_disposition disposition;
	int host_error;
};

struct vmx_nested_vmcs02_commit {
	enum vmx_nested_vmcs02_commit_state state;
	struct vmx_nested_vmcs02_image image;
	struct vmx_nested_vmcs02_commit_result result;
};

void	vmx_nested_vmcs02_commit_init(struct vmx_nested_vmcs02_commit *);
int	vmx_nested_vmcs02_commit_publish(struct vmx_nested_vmcs02_commit *,
	    const struct vmx_nested_vmcs02_plan *);
int	vmx_nested_vmcs02_commit_apply(struct vmx_nested_vmcs02_commit *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmcs02_apply_ops *, void *);
int	vmx_nested_vmcs02_commit_take(struct vmx_nested_vmcs02_commit *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_vmcs02_commit_result *);
int	vmx_nested_vmcs02_commit_cancel(struct vmx_nested_vmcs02_commit *,
	    const struct vmx_nested_vmcs02_id *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_H_ */
