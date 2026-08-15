/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMEXIT_HANDOFF_H_
#define	_VMM_INTEL_VMX_NESTED_VMEXIT_HANDOFF_H_

#include <sys/types.h>

#include "vmx_nested_reflect.h"
#include "vmx_nested_vmcs02.h"
#include "vmx_nested_vmexit.h"

/*
 * A hardware VM exit is captured while VMCS02 is current, but publishing it
 * to VMCS12 and restoring L1 may take sleepable locks.  Carry only immutable
 * architectural values across that boundary.
 */
enum vmx_nested_vmexit_handoff_state {
	VMX_NESTED_VMEXIT_HANDOFF_IDLE = 0,
	VMX_NESTED_VMEXIT_HANDOFF_PENDING,
	VMX_NESTED_VMEXIT_HANDOFF_COMMITTING,
	VMX_NESTED_VMEXIT_HANDOFF_RESOLVED,
};

struct vmx_nested_vmexit_handoff_request {
	struct vmx_nested_vmcs02_id id;
	struct vmx_nested_exit_information information;
	struct vmx_nested_l2_runtime_state l2_runtime;
};

struct vmx_nested_vmexit_handoff {
	struct vmx_nested_vmexit_handoff_request request;
	enum vmx_nested_vmexit_handoff_state state;
};

struct vmx_nested_vmexit_handoff_ops {
	int	(*commit)(void *,
		    const struct vmx_nested_vmexit_handoff_request *);
};

void	vmx_nested_vmexit_handoff_init(
	    struct vmx_nested_vmexit_handoff *);
int	vmx_nested_vmexit_handoff_publish(
	    struct vmx_nested_vmexit_handoff *,
	    const struct vmx_nested_vmexit_handoff_request *);
int	vmx_nested_vmexit_handoff_handle(
	    struct vmx_nested_vmexit_handoff *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmexit_handoff_ops *, void *);
int	vmx_nested_vmexit_handoff_take(
	    struct vmx_nested_vmexit_handoff *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_vmexit_handoff_request *);
int	vmx_nested_vmexit_handoff_cancel(
	    struct vmx_nested_vmexit_handoff *,
	    const struct vmx_nested_vmcs02_id *);

#endif /* _VMM_INTEL_VMX_NESTED_VMEXIT_HANDOFF_H_ */
