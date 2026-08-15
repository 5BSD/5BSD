/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_FREEZE_H_
#define	_VMM_INTEL_VMX_NESTED_L2_FREEZE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_l2_portable.h"

struct vmx_nested_l2_freeze_input {
	const struct vmx_nested_vmcs02_plan	*executed_plan;
	const struct vmx_nested_capabilities	*capabilities;
	uint64_t				resource_generation;
	uint64_t				portable_generation;
	uint64_t				l1_virtual_tsc;
};

/*
 * Ordered architecture/runtime operations for one freeze transaction.
 *
 * capture_software is observational.  detach captures VMCS-owned state,
 * clears VMCS02, and restores VMCS01.  install_l1 switches software-owned
 * MSRs back to L1.  release_resources drops every opaque runtime lease.
 *
 * rollback_hot reconstructs VMCS02 and L2 software state from the validated
 * portable image while the original resources are still owned.  Each
 * mutating callback reports whether failure left its pre-call state intact.
 * The implementation snapshots this complete table before the first callback;
 * callers may not redirect a transaction by mutating its source table.
 */
struct vmx_nested_l2_freeze_ops {
	int	(*capture_software)(void *,
		    struct vmx_nested_software_msrs *);
	int	(*detach)(void *, const struct vmx_nested_vmcs02_plan *,
		    uint64_t, uint64_t, struct vmx_nested_l2_capture_values *,
		    bool *);
	int	(*install_l1)(void *, const struct vmx_nested_vmcs02_id *,
		    bool *);
	int	(*release_resources)(void *,
		    const struct vmx_nested_vmcs02_id *, uint64_t, bool *);
	int	(*rollback_hot)(void *,
		    const struct vmx_nested_vmcs02_plan *,
		    const struct vmx_nested_l2_portable_state *, bool *);
};

int	vmx_nested_l2_freeze(
	    const struct vmx_nested_l2_freeze_input *,
	    const struct vmx_nested_l2_freeze_ops *, void *,
	    struct vmx_nested_l2_portable_state *, bool *);

#endif /* _VMM_INTEL_VMX_NESTED_L2_FREEZE_H_ */
