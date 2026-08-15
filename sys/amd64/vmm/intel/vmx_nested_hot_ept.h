/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_HOT_EPT_H_
#define	_VMM_INTEL_VMX_NESTED_HOT_EPT_H_

#include "vmx_nested_types.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_ept_handoff.h"

/*
 * Publish an L0-owned EPT exit while VMCS02 is still resident, then freeze
 * the complete L2 execution before crossing the VM_RUN boundary.
 *
 * The caller owns the vCPU and supplies CPU-specific freeze and hot-resume
 * adapters.  All request validation happens before the first state change.
 * A clean freeze failure is unwound to GUEST.  An incomplete rollback is
 * deliberately left fail-stop with the EPT request still published.
 */
int	vmx_nested_hot_ept_publish(
	    struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_exit_information *, uint64_t, bool,
	    const struct vmx_nested_l0_continuation_ops *, void *,
	    struct vmx_nested_ept_handoff_id *);

#endif /* _VMM_INTEL_VMX_NESTED_HOT_EPT_H_ */
