/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_REFREEZE_H_
#define	_VMM_INTEL_VMX_NESTED_REFREEZE_H_

#include "vmx_nested_types.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_l2_portable.h"
#include "vmx_nested_refreeze_types.h"

/*
 * Reversing an unentered thaw crosses two execution domains.  CPU-local
 * MSRs and VMCS02 are detached while the run loop is pinned; opaque EPT,
 * VPID, and guest-memory resources are released only later by the frozen
 * owner.  This value-only state makes the gap explicit and retryable.  A
 * nonzero runtime provider identity binds the hot detach to the later frozen
 * release; VMCS02 identity and resource_generation bind the concrete lease.
 * The provider identity is not part of the portable refreeze request.
 */
enum vmx_nested_refreeze_state {
	VMX_NESTED_REFREEZE_IDLE = 0,
	VMX_NESTED_REFREEZE_DETACHED,
	VMX_NESTED_REFREEZE_POISONED,
};

struct vmx_nested_refreeze_staged {
	struct vmx_nested_vmcs02_id id;
	uint64_t portable_generation;
	uint64_t resource_generation;
	uint64_t provider_id;
	enum vmx_nested_refreeze_purpose purpose;
	struct vmx_nested_late_entry late_entry;
	enum vmx_nested_refreeze_state state;
};

struct vmx_nested_refreeze_hot_ops {
	uint64_t provider_id;
	int	(*detach_hot)(void *, const struct vmx_nested_vmcs02_id *,
		    uint64_t, bool *);
};

struct vmx_nested_refreeze_frozen_ops {
	uint64_t provider_id;
	int	(*release_resources)(void *,
		    const struct vmx_nested_vmcs02_id *, uint64_t, bool *);
};

void	vmx_nested_refreeze_staged_init(
	    struct vmx_nested_refreeze_staged *);
int	vmx_nested_refreeze_prepare_hot(
	    struct vmx_nested_refreeze_staged *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_plan *,
	    const struct vmx_nested_l2_portable_state *, uint64_t,
	    const struct vmx_nested_refreeze_hot_ops *, void *);
int	vmx_nested_refreeze_prepare_late_entry_hot(
	    struct vmx_nested_refreeze_staged *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_plan *,
	    const struct vmx_nested_l2_portable_state *, uint64_t,
	    const struct vmx_nested_late_entry *,
	    const struct vmx_nested_refreeze_hot_ops *, void *);
int	vmx_nested_refreeze_commit_frozen(
	    struct vmx_nested_refreeze_staged *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_refreeze_frozen_ops *, void *);
int	vmx_nested_refreeze_staged_reset(
	    struct vmx_nested_refreeze_staged *, bool);
int	vmx_nested_refreeze_request_build(
	    const struct vmx_nested_refreeze_staged *,
	    struct vmx_nested_refreeze_request *);
int	vmx_nested_refreeze_request_validate(
	    const struct vmx_nested_refreeze_staged *,
	    const struct vmx_nested_refreeze_request *);

#endif /* _VMM_INTEL_VMX_NESTED_REFREEZE_H_ */
