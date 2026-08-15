/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_REBUILD_H_
#define	_VMM_INTEL_VMX_NESTED_L2_REBUILD_H_

#include "vmx_nested_types.h"

struct vmx_nested_entry_environment;
struct vmx_nested_l2_portable_state;
struct vmx_nested_vmcs02_plan;
struct vmx_nested_vmcs12_snapshot;

/*
 * Rebuild the CPU-independent VMCS02 basis after checkpoint restore.
 * Source-time entry-only memory validation is not repeated: the retained
 * snapshot proves that it completed, while portable contains the resulting
 * live L2 state.  Destination-local EPT, VPID, bitmap, VMCS and MSR
 * resources remain absent from the returned plan.
 */
int	vmx_nested_l2_rebuild_plan(
	    const struct vmx_nested_vmcs12_snapshot *,
	    const struct vmx_nested_entry_environment *,
	    const struct vmx_nested_l2_portable_state *, bool,
	    struct vmx_nested_vmcs02_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_L2_REBUILD_H_ */
