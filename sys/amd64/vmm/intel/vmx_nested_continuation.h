/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTINUATION_H_
#define	_VMM_INTEL_VMX_NESTED_CONTINUATION_H_

#include "vmx_nested_types.h"

#include "vmx_nested_continuation_types.h"
#include "vmx_nested_context.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_l2_thaw_staged.h"
#include "vmx_nested_reflect.h"

/*
 * An L0-owned exit may be handled without leaving the kernel, or it may have
 * to cross the userspace VM_RUN boundary.  The latter cannot retain a
 * current hardware VMCS or CPU-local MSR ownership.  This value-only state
 * machine makes that distinction explicit.
 */
enum vmx_nested_l0_continuation_state {
	VMX_NESTED_L0_CONTINUATION_IDLE = 0,
	VMX_NESTED_L0_CONTINUATION_HOT,
	VMX_NESTED_L0_CONTINUATION_FREEZING,
	VMX_NESTED_L0_CONTINUATION_COLD,
	VMX_NESTED_L0_CONTINUATION_THAWING,
	VMX_NESTED_L0_CONTINUATION_RESOLVING,
	VMX_NESTED_L0_CONTINUATION_ABORTED,
};

struct vmx_nested_l0_continuation {
	struct vmx_nested_vmcs02_id id;
	uint64_t exit_sequence;
	uint64_t portable_generation;
	enum vmx_nested_l0_continuation_state state;
	enum vmx_nested_l0_completion completion;
	bool rollback_failed;
};

/*
 * The adapters are transactional.  freeze() must capture all authoritative
 * L2 architectural state, restore L1's CPU-local state, and detach VMCS02.
 * thaw() performs the inverse from the named portable generation.  On error,
 * rollback_complete says whether the pre-call residency was restored.
 *
 * resolve() either resumes L2 or publishes the nested exit to L1.  It must
 * leave the continuation's pre-call state unchanged on error.
 */
struct vmx_nested_l0_continuation_ops {
	int	(*freeze)(void *, const struct vmx_nested_vmcs02_id *,
		    uint64_t *, bool *);
	int	(*thaw)(void *, const struct vmx_nested_vmcs02_id *,
		    uint64_t, uint64_t *, bool *);
	int	(*resolve)(void *, const struct vmx_nested_vmcs02_id *,
		    enum vmx_nested_l0_completion, bool);
};

struct vmx_nested_l0_continuation_record {
	struct vmx_nested_vmcs02_id id;
	uint64_t exit_sequence;
	uint64_t portable_generation;
	enum vmx_nested_l0_completion completion;
};

void	vmx_nested_l0_continuation_init(
	    struct vmx_nested_l0_continuation *);
int	vmx_nested_l0_continuation_begin(
	    struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_context *,
	    const struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    enum vmx_nested_exit_action);
int	vmx_nested_l0_continuation_freeze(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_l0_continuation_ops *, void *);
int	vmx_nested_l0_continuation_thaw(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_l0_continuation_ops *, void *);
/*
 * Production cold restore is split across execution domains.  prepare()
 * runs with the vCPU frozen and may acquire resources.  commit_hot() runs
 * CPU-pinned and may touch only VMCS/MSR state.  A clean hot failure remains
 * THAWING until cancel_frozen() releases the staged resources.
 */
int	vmx_nested_l0_continuation_thaw_prepare(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_l2_thaw_staged *,
	    const struct vmx_nested_l2_thaw_input *,
	    const struct vmx_nested_l2_thaw_frozen_ops *, void *);
int	vmx_nested_l0_continuation_thaw_commit_hot(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_l2_thaw_staged *,
	    const struct vmx_nested_l2_thaw_hot_ops *, void *,
	    struct vmx_nested_vmcs02_plan *, uint64_t *);
int	vmx_nested_l0_continuation_thaw_cancel_frozen(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_l2_thaw_staged *,
	    const struct vmx_nested_l2_thaw_frozen_ops *, void *);
int	vmx_nested_l0_continuation_resolve(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_l0_continuation_ops *, void *);
int	vmx_nested_l0_continuation_quarantine_hot(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * A staged thaw may be reversed without recapturing VMCS02 only before
 * hardware has re-entered L2 and while the named portable image is retained.
 */
int	vmx_nested_l0_continuation_refreeze_unentered(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t);
int	vmx_nested_l0_continuation_refreeze_late_entry(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t);
int	vmx_nested_l0_continuation_exit_captured(
	    struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_l0_continuation_export(
	    const struct vmx_nested_l0_continuation *,
	    struct vmx_nested_l0_continuation_record *);
int	vmx_nested_l0_continuation_restore(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_l0_continuation_record *, bool);
int	vmx_nested_l0_continuation_quiesce(
	    const struct vmx_nested_l0_continuation *);
/*
 * A GUEST-phase architectural context is checkpointable only when its
 * paired continuation and hardware runtime are cold and the complete
 * portable L2 image names the same execution.
 */
int	vmx_nested_l0_continuation_quiesce_context(
	    const struct vmx_nested_context *,
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_l2_portable_state *);
/*
 * Teardown may intentionally discard a fully detached continuation.  Hot,
 * mutating, or fail-stop state still requires an architecture adapter to
 * unwind hardware resources and is never silently erased here.
 */
int	vmx_nested_l0_continuation_discard_cold(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    struct vmx_nested_l2_portable_state *, bool);
int	vmx_nested_l0_continuation_reset(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *, bool, bool);
int	vmx_nested_l0_continuation_validate(
	    const struct vmx_nested_l0_continuation *);

#endif /* _VMM_INTEL_VMX_NESTED_CONTINUATION_H_ */
