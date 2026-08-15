/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INSTRUCTION_RUNTIME_H_
#define	_VMM_INTEL_VMX_NESTED_INSTRUCTION_RUNTIME_H_

#include <sys/types.h>

#include <machine/vmm.h>

#include "vmx_nested_caps.h"
#include "vmx_nested_ept_cache.h"
#include "vmx_nested_instruction_handoff.h"
#include "vmx_nested_vmcs_registry.h"
#include "vmx_nested_vpid_owner.h"

/*
 * Short-lived binding between the value-only instruction engine and a
 * frozen bhyve vCPU.  It owns no mapping: every callback pins and releases
 * the required L1 page before returning.
 */
struct vmx_nested_instruction_runtime {
	struct vcpu *vcpu;
	struct sx *vmcs_sx;
	struct vmx_nested_vmcs_registry *registry;
	struct vmx_nested_ept_cache *ept_cache;
	struct vmx_nested_vpid_owner *vpid_owner;
	uint32_t owner;
	struct vm_guest_paging paging;
	struct vmx_nested_capabilities capabilities;
};

int	vmx_nested_instruction_runtime_init(
	    struct vmx_nested_instruction_runtime *, struct vcpu *,
	    struct sx *, struct vmx_nested_vmcs_registry *,
	    struct vmx_nested_ept_cache *, struct vmx_nested_vpid_owner *,
	    const struct vm_guest_paging *,
	    const struct vmx_nested_capabilities *);
const struct vmx_nested_instruction_handoff_ops *
	vmx_nested_instruction_runtime_ops(void);

#endif /* _VMM_INTEL_VMX_NESTED_INSTRUCTION_RUNTIME_H_ */
