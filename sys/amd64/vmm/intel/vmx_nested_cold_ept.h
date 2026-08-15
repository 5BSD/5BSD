/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_COLD_EPT_H_
#define	_VMM_INTEL_VMX_NESTED_COLD_EPT_H_

#include "vmx_nested_context.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_l2_portable.h"

enum vmx_nested_cold_ept_disposition {
	VMX_NESTED_COLD_EPT_POPULATED = 0,
	VMX_NESTED_COLD_EPT_REFLECTED,
};

/*
 * Resolve an EPT02 fault after L2 has been frozen into portable state.
 * Population consumes only the EPT handoff and leaves the cold continuation
 * ready for staged thaw.  Reflection atomically replaces the EPT handoff
 * with an immutable VM-exit handoff and retires continuation ownership.
 */
int	vmx_nested_cold_ept_resolve(struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_cold_ept_disposition *);

#endif /* _VMM_INTEL_VMX_NESTED_COLD_EPT_H_ */
