/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_LEASE_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_LEASE_INTEL_H_

#include "vmx_nested_vmcs02_lease.h"

struct vcpu;

/*
 * Intel runtime adapter for the architecture-neutral VMCS02 lease owner.
 * The vCPU must remain frozen from acquisition through release.
 */
struct vmx_nested_vmcs02_lease_intel {
	struct vcpu	*vcpu;
};

int	vmx_nested_vmcs02_lease_intel_init(
	    struct vmx_nested_vmcs02_lease_intel *, struct vcpu *);
const struct vmx_nested_vmcs02_lease_ops *
	vmx_nested_vmcs02_lease_intel_ops(void);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_LEASE_INTEL_H_ */
