/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_THAW_STAGED_H_
#define	_VMM_INTEL_VMX_NESTED_L2_THAW_STAGED_H_

#include "vmx_nested_types.h"

#include "vmx_nested_l2_thaw.h"

/*
 * Cold restore crosses two mutually exclusive execution domains:
 * rebind/acquire/release may sleep while the vCPU is frozen, whereas
 * software-MSR installation and VMCS02 programming must run CPU-pinned.
 * This value-only owner prevents either class of callback from leaking into
 * the other domain.  provider_id is a nonzero runtime identity retained as a
 * value so a later frozen cancellation cannot release through a different
 * backend table.  Each call snapshots its table before the first callback.
 */
enum vmx_nested_l2_thaw_staged_state {
	VMX_NESTED_L2_THAW_STAGED_IDLE = 0,
	VMX_NESTED_L2_THAW_STAGED_PREPARED,
	VMX_NESTED_L2_THAW_STAGED_APPLYING,
	VMX_NESTED_L2_THAW_STAGED_READY,
	VMX_NESTED_L2_THAW_STAGED_POISONED,
};

struct vmx_nested_l2_thaw_staged {
	struct vmx_nested_vmcs02_plan plan;
	struct vmx_nested_software_msrs software;
	uint64_t resource_generation;
	uint64_t frozen_provider_id;
	enum vmx_nested_l2_thaw_staged_state state;
};

struct vmx_nested_l2_thaw_frozen_ops {
	uint64_t provider_id;
	int	(*rebind_runtime)(void *,
		    const struct vmx_nested_l2_portable_state *,
		    const struct vmx_nested_vmcs02_plan *,
		    struct vmx_nested_vmcs02_plan *);
	int	(*acquire_resources)(void *,
		    const struct vmx_nested_vmcs02_plan *, uint64_t *, bool *);
	int	(*release_resources)(void *,
		    const struct vmx_nested_vmcs02_id *, uint64_t, bool *);
};

struct vmx_nested_l2_thaw_hot_ops {
	int	(*install_l2)(void *, const struct vmx_nested_vmcs02_id *,
		    const struct vmx_nested_software_msrs *, bool *);
	int	(*program_vmcs02)(void *,
		    const struct vmx_nested_vmcs02_plan *, uint64_t, bool *);
	int	(*rollback_hot)(void *,
		    const struct vmx_nested_vmcs02_id *, uint64_t, bool *);
};

void	vmx_nested_l2_thaw_staged_init(
	    struct vmx_nested_l2_thaw_staged *);
int	vmx_nested_l2_thaw_staged_prepare(
	    struct vmx_nested_l2_thaw_staged *,
	    const struct vmx_nested_l2_thaw_input *,
	    const struct vmx_nested_l2_thaw_frozen_ops *, void *);
int	vmx_nested_l2_thaw_staged_commit_hot(
	    struct vmx_nested_l2_thaw_staged *,
	    const struct vmx_nested_l2_thaw_hot_ops *, void *);
int	vmx_nested_l2_thaw_staged_take(
	    struct vmx_nested_l2_thaw_staged *,
	    struct vmx_nested_vmcs02_plan *, uint64_t *);
int	vmx_nested_l2_thaw_staged_cancel(
	    struct vmx_nested_l2_thaw_staged *,
	    const struct vmx_nested_l2_thaw_frozen_ops *, void *);
int	vmx_nested_l2_thaw_staged_reset(
	    struct vmx_nested_l2_thaw_staged *, bool);

#endif /* _VMM_INTEL_VMX_NESTED_L2_THAW_STAGED_H_ */
