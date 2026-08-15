/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_ENTRY_RUNTIME_H_
#define	_VMM_INTEL_VMX_NESTED_ENTRY_RUNTIME_H_

#include "vmx_nested_types.h"

#include "vmx_nested_vmcs02.h"

/*
 * Value-only ownership state for one L2 hardware run.  It deliberately owns
 * no allocation, VMCS pointer, guest-memory callback, or unwire cookie.  The
 * Intel adapter retains those runtime objects while this state machine makes
 * their publication and cleanup order explicit and testable.
 */
enum vmx_nested_entry_runtime_state {
	VMX_NESTED_ENTRY_RUNTIME_IDLE = 0,
	VMX_NESTED_ENTRY_RUNTIME_PREPARING,
	VMX_NESTED_ENTRY_RUNTIME_RESOURCES,
	VMX_NESTED_ENTRY_RUNTIME_MSRS,
	VMX_NESTED_ENTRY_RUNTIME_VMCS02,
	VMX_NESTED_ENTRY_RUNTIME_GUEST,
	VMX_NESTED_ENTRY_RUNTIME_L0_EXIT,
	VMX_NESTED_ENTRY_RUNTIME_L0_FREEZING,
	VMX_NESTED_ENTRY_RUNTIME_L0_COLD,
	VMX_NESTED_ENTRY_RUNTIME_L0_THAWING,
	VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED,
	VMX_NESTED_ENTRY_RUNTIME_EXIT_CAPTURED_COLD,
	VMX_NESTED_ENTRY_RUNTIME_ABORTED,
};

enum vmx_nested_entry_cleanup {
	VMX_NESTED_ENTRY_CLEANUP_NONE		= 0,
	VMX_NESTED_ENTRY_CLEANUP_CANCEL		= 1U << 0,
	VMX_NESTED_ENTRY_CLEANUP_ROLLBACK_MSRS	= 1U << 1,
	VMX_NESTED_ENTRY_CLEANUP_RESTORE_VMCS01	= 1U << 2,
	VMX_NESTED_ENTRY_CLEANUP_RELEASE		= 1U << 3,
	VMX_NESTED_ENTRY_CLEANUP_CAPTURE_EXIT	= 1U << 4,
	VMX_NESTED_ENTRY_CLEANUP_COMMIT_EXIT	= 1U << 5,
	VMX_NESTED_ENTRY_CLEANUP_CONTINUATION	= 1U << 6,
};

struct vmx_nested_entry_runtime {
	struct vmx_nested_vmcs02_id id;
	uint64_t resource_generation;
	uint32_t entry_msr_count;
	uint32_t abort_cleanup;
	enum vmx_nested_entry_runtime_state state;
	bool rollback_failed;
};

void	vmx_nested_entry_runtime_init(struct vmx_nested_entry_runtime *);
int	vmx_nested_entry_runtime_begin(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_resources(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t);
int	vmx_nested_entry_runtime_vmcs02(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_msrs(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint32_t);
int	vmx_nested_entry_runtime_launch(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_exit(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_resume(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_abort(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * A raw failure of a later hot VMRESUME did not enter L2 and did not
 * produce architectural VM-exit state.  Quarantine the resident hardware
 * transaction without requesting capture/commit of stale exit fields.
 */
int	vmx_nested_entry_runtime_hot_entry_abort(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_freeze_begin(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_freeze_complete(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_freeze_abort(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, bool);
int	vmx_nested_entry_runtime_l0_thaw_begin(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_thaw_complete(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t);
int	vmx_nested_entry_runtime_l0_thaw_abort(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, bool);
int	vmx_nested_entry_runtime_l0_refreeze(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_cold_restore(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_reflect_complete(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_exit_captured(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * Model an architecturally successful entry followed by an immediate
 * synthetic exit (for example, an L1-requested interrupt-window exit).
 * Hardware and CPU-local MSRs were never entered, so the retained opaque
 * resources move directly from the prepared state to captured-exit
 * ownership.
 */
int	vmx_nested_entry_runtime_synthetic_exit_captured(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_l0_reflect_captured(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_exit_committed(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_exit_poison(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_cancel(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_rollback(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, bool);
int	vmx_nested_entry_runtime_restore_vmcs01(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * Quarantine an unentered VMCS02 transaction when the architecture adapter
 * cannot prove that VMCS01 was restored.  The retained identity and cleanup
 * fields describe the unresolved CPU-local and resource obligations.
 */
int	vmx_nested_entry_runtime_vmcs02_abort(
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_entry_runtime_release(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * Clear fail-stop state only after the architecture adapter has proved that
 * every CPU-local and opaque hardware obligation named by id was recovered.
 * Merely freezing the vCPU is not evidence that rollback completed.
 */
int	vmx_nested_entry_runtime_reset(struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, bool, bool);
/*
 * Report every obligation still owned by the current stage.  Bits describe
 * the complete remaining path, not operations that may be performed out of
 * order: callers acknowledge each successful step through the transition
 * functions above before attempting the next one.
 */
uint32_t vmx_nested_entry_runtime_cleanup(
	    const struct vmx_nested_entry_runtime *);
int	vmx_nested_entry_runtime_validate(
	    const struct vmx_nested_entry_runtime *);

#endif /* _VMM_INTEL_VMX_NESTED_ENTRY_RUNTIME_H_ */
