/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_THAW_H_
#define	_VMM_INTEL_VMX_NESTED_L2_THAW_H_

#include "vmx_nested_types.h"

#include "vmx_nested_l2_portable.h"

struct vmx_nested_l2_thaw_input {
	const struct vmx_nested_l2_portable_state	*portable;
	const struct vmx_nested_capabilities		*capabilities;
	const struct vmx_nested_vmcs02_plan		*frozen_plan;
};

/*
 * acquire_resources reconstructs every opaque lease and publishes a new
 * nonzero generation only on success.  install_l2 switches software-owned
 * MSRs from L1 to the portable L2 bank.  program_vmcs02 creates the hardware
 * VMCS from the value-only plan and newly acquired resources.
 *
 * rollback_cold must clear any new VMCS02, restore L1 software state, and
 * release the new generation.  It is called only after acquire succeeds.
 * The implementation snapshots this complete table before the first callback;
 * callers may not redirect a transaction by mutating its source table.
 */
struct vmx_nested_l2_thaw_ops {
	/*
	 * Recompose every host-derived value before acquiring resources.
	 * The portable overlay deliberately has no hardware VPID, host VMCS
	 * state, physical address, or destination timer origin.
	 */
	int	(*rebind_runtime)(void *,
		    const struct vmx_nested_l2_portable_state *,
		    const struct vmx_nested_vmcs02_plan *,
		    struct vmx_nested_vmcs02_plan *);
	int	(*acquire_resources)(void *,
		    const struct vmx_nested_vmcs02_plan *, uint64_t *, bool *);
	int	(*install_l2)(void *, const struct vmx_nested_vmcs02_id *,
		    const struct vmx_nested_software_msrs *, bool *);
	int	(*program_vmcs02)(void *,
		    const struct vmx_nested_vmcs02_plan *, uint64_t, bool *);
	int	(*rollback_cold)(void *,
		    const struct vmx_nested_vmcs02_id *, uint64_t, bool *);
};

int	vmx_nested_l2_thaw(
	    const struct vmx_nested_l2_thaw_input *,
	    const struct vmx_nested_l2_thaw_ops *, void *,
	    struct vmx_nested_vmcs02_plan *, uint64_t *, bool *);

#endif /* _VMM_INTEL_VMX_NESTED_L2_THAW_H_ */
