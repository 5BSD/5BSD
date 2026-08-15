/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_APIC_PRIORITY_H_
#define	_VMM_INTEL_VMX_NESTED_APIC_PRIORITY_H_

#include <sys/types.h>

#include "vmx_nested_memory.h"

/*
 * CR8 is not an unconditional VMCS guest-state scalar.  With TPR shadowing
 * disabled it names the shared virtual LAPIC priority.  With TPR shadowing
 * enabled its architectural backing is the TPR in L1's virtual-APIC page.
 * Keep that distinction explicit so a cold L2 never aliases L1 VMCS state or
 * duplicates guest-memory state in a checkpoint image.
 */
struct vmx_nested_apic_priority_ops {
	int	(*shared_get)(void *, uint64_t *);
	int	(*shared_set)(void *, uint64_t);
};

int	vmx_nested_apic_priority_get(uint32_t, uint64_t,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_apic_priority_ops *, void *, uint64_t *);
int	vmx_nested_apic_priority_set(uint32_t, uint64_t,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_apic_priority_ops *, void *, uint64_t);

#endif /* _VMM_INTEL_VMX_NESTED_APIC_PRIORITY_H_ */
