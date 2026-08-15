/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_GUEST_MEMORY_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_GUEST_MEMORY_INTEL_H_

#include "vmx_nested_memory.h"

struct vcpu;

/*
 * Synchronous guest-physical access for a frozen vCPU.  The callbacks retain
 * no mapping after return.  Writes acquire every participating page before
 * modifying memory so a failed acquisition cannot publish a partial write.
 */
struct vmx_nested_guest_memory_intel {
	struct vcpu			*vcpu;
	struct vmx_nested_memory	 memory;
};

int	vmx_nested_guest_memory_intel_init(
	    struct vmx_nested_guest_memory_intel *, struct vcpu *);
const struct vmx_nested_memory *
	vmx_nested_guest_memory_intel_memory(
	    const struct vmx_nested_guest_memory_intel *);

#endif /* _VMM_INTEL_VMX_NESTED_GUEST_MEMORY_INTEL_H_ */
