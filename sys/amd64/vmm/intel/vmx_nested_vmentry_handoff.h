/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMENTRY_HANDOFF_H_
#define	_VMM_INTEL_VMX_NESTED_VMENTRY_HANDOFF_H_

#include <sys/types.h>

#include "vmx_nested_vmcs02.h"
#include "vmx_nested_vmentry.h"

/*
 * VM-entry failure is discovered while VMCS02 and CPU-local state are hot,
 * while restoring architectural L1/VMCS12 state requires the frozen owner.
 * Carry only the immutable Intel-defined rejection result across that
 * boundary.
 */
enum vmx_nested_vmentry_handoff_state {
	VMX_NESTED_VMENTRY_HANDOFF_IDLE = 0,
	VMX_NESTED_VMENTRY_HANDOFF_PENDING,
	VMX_NESTED_VMENTRY_HANDOFF_COMMITTING,
	VMX_NESTED_VMENTRY_HANDOFF_RESOLVED,
};

struct vmx_nested_vmentry_handoff_request {
	struct vmx_nested_vmcs02_id id;
	struct vmx_nested_vmentry_result result;
};

struct vmx_nested_vmentry_handoff {
	struct vmx_nested_vmentry_handoff_request request;
	enum vmx_nested_vmentry_handoff_state state;
};

struct vmx_nested_vmentry_handoff_ops {
	int	(*commit)(void *,
		    const struct vmx_nested_vmentry_handoff_request *);
};

void	vmx_nested_vmentry_handoff_init(
	    struct vmx_nested_vmentry_handoff *);
int	vmx_nested_vmentry_handoff_publish(
	    struct vmx_nested_vmentry_handoff *,
	    const struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_vmentry_handoff_handle(
	    struct vmx_nested_vmentry_handoff *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmentry_handoff_ops *, void *);
int	vmx_nested_vmentry_handoff_take(
	    struct vmx_nested_vmentry_handoff *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_vmentry_handoff_cancel(
	    struct vmx_nested_vmentry_handoff *,
	    const struct vmx_nested_vmcs02_id *);

#endif /* _VMM_INTEL_VMX_NESTED_VMENTRY_HANDOFF_H_ */
