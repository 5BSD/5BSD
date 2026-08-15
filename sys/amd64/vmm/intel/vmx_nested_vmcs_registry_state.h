/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS_REGISTRY_STATE_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS_REGISTRY_STATE_H_

#include <sys/types.h>

#include "vmx_nested_state.h"
#include "vmx_nested_vmcs_registry.h"

#define	VMX_NESTED_VMCS_REGISTRY_STATE_HEADER_SIZE	64U
#define	VMX_NESTED_VMCS_REGISTRY_STATE_MAX_SIZE			\
	(VMX_NESTED_VMCS_REGISTRY_STATE_HEADER_SIZE +			\
	 VMX_NESTED_CAPABILITIES_WIRE_SIZE +				\
	 VMX_NESTED_VMCS_REGISTRY_LIMIT *				\
	 (32U + VMX_NESTED_STATE_MAX_FIELDS * 16U))

/*
 * Callers serialize registry access.  Runtime vCPU owners are deliberately
 * not encoded; restore reconstructs every VMCS as inactive and unowned.
 */
int	vmx_nested_vmcs_registry_state_size(
	    const struct vmx_nested_vmcs_registry *, size_t *);
int	vmx_nested_vmcs_registry_state_encode(
	    const struct vmx_nested_vmcs_registry *, void *, size_t, size_t *);
int	vmx_nested_vmcs_registry_state_restore(
	    struct vmx_nested_vmcs_registry *, const void *, size_t);
int	vmx_nested_vmcs_registry_state_restore_matching(
	    struct vmx_nested_vmcs_registry *, const void *, size_t,
	    const struct vmx_nested_state_view *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS_REGISTRY_STATE_H_ */
