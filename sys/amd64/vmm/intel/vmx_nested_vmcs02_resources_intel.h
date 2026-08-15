/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_RESOURCES_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_RESOURCES_INTEL_H_

#include "vmx_nested_vmcs02_bind.h"

struct vmx_nested_entry_controls;
struct vmx_nested_memory;
struct vmx_nested_vmcs02_image;
struct vmx_vcpu;

/*
 * Acquire every host-owned object referenced by one prospective VMCS02.
 * The caller owns a frozen vCPU but must not hold a VMX critical section:
 * guest-page holds and EPT allocation may sleep.  l0_fixed is an immutable
 * VMCS01 resource snapshot captured separately while VMCS01 was current.
 * Failure leaves resources unchanged and no lease or EPT binding active.
 */
int	vmx_nested_vmcs02_resources_intel_acquire(
	    struct vmx_vcpu *, const struct vmx_nested_vmcs02_image *,
	    const struct vmx_nested_entry_controls *,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_vmcs02_resources *,
	    struct vmx_nested_vmcs02_resources *);
/*
 * Reacquire a cold L0 continuation while architectural ownership remains
 * in GUEST phase.  The resource rules are identical to initial entry, but
 * the phase distinction prevents an entry callback from being reused at
 * the wrong lifecycle boundary.
 */
int	vmx_nested_vmcs02_resources_intel_reacquire(
	    struct vmx_vcpu *, const struct vmx_nested_vmcs02_image *,
	    const struct vmx_nested_entry_controls *,
	    const struct vmx_nested_memory *,
	    const struct vmx_nested_vmcs02_resources *,
	    struct vmx_nested_vmcs02_resources *);

/*
 * Call only after VMCS02 has been cleared and VMCS01 restored.  Release may
 * sleep and therefore also runs outside the VMX critical section.  It is
 * generation checked so a stale exit cannot tear down a newer execution.
 */
int	vmx_nested_vmcs02_resources_intel_release(
	    struct vmx_vcpu *, const struct vmx_nested_vmcs02_resources *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_RESOURCES_INTEL_H_ */
