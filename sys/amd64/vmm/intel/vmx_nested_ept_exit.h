/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_EXIT_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_EXIT_H_

#include "vmx_nested_ept_handoff.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_vmcs02.h"
#include "vmx_nested_vmexit.h"

/*
 * Complete value-only plan for returning an EPT02 miss to L1.  It contains
 * no hardware VMCS, guest-memory pointer, callback, file descriptor, or
 * runtime EPT root.
 */
struct vmx_nested_ept_exit_plan {
	struct vmx_nested_vmcs02_id	id;
	struct vmx_nested_exit_information exit_information;
	struct vmx_nested_vmexit_state_plan state;
};

int	vmx_nested_ept_exit_prepare(
	    const struct vmx_nested_vmcs02_image *,
	    const struct vmx_nested_l2_runtime_state *,
	    const struct vmx_nested_ept_handoff_result *,
	    struct vmx_nested_ept_exit_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_EXIT_H_ */
