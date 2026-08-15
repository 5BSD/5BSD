/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_RUNTIME_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_RUNTIME_H_

#include <sys/types.h>

#include "vmx_nested_ept_handoff.h"
#include "vmx_nested_ept_memory.h"

struct vcpu;

/*
 * Ephemeral frozen-vCPU binding for an already referenced EPT02 root.
 * It owns neither the vCPU nor the root and never enters portable state.
 */
struct vmx_nested_ept_runtime {
	struct vcpu *vcpu;
	void *runtime_root;
	struct vmx_nested_ept_memory memory;
};

int	vmx_nested_ept_runtime_init(struct vmx_nested_ept_runtime *,
	    struct vcpu *, void *);
const struct vmx_nested_ept_memory *
	vmx_nested_ept_runtime_memory(
	    const struct vmx_nested_ept_runtime *);
const struct vmx_nested_ept_handoff_ops *
	vmx_nested_ept_runtime_ops(void);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_RUNTIME_H_ */
