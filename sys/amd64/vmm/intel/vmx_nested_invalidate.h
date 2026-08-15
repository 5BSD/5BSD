/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INVALIDATE_H_
#define	_VMM_INTEL_VMX_NESTED_INVALIDATE_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;

#define	VMX_NESTED_EPT_ROOT_ADDRESS_MASK	UINT64_C(0x000ffffffffff000)

struct vmx_nested_invalidation_descriptor {
	uint64_t	context;
	uint64_t	address;
};

enum vmx_nested_invalidation_scope {
	VMX_NESTED_INVALIDATE_EPT_SINGLE = 0,
	VMX_NESTED_INVALIDATE_EPT_ALL,
	VMX_NESTED_INVALIDATE_VPID_ADDRESS,
	VMX_NESTED_INVALIDATE_VPID_SINGLE,
	VMX_NESTED_INVALIDATE_VPID_ALL,
	VMX_NESTED_INVALIDATE_VPID_SINGLE_GLOBALS,
};

struct vmx_nested_invalidation {
	enum vmx_nested_invalidation_scope	scope;
	uint64_t	context;
	uint64_t	address;
};

enum vmx_nested_vpid_transition_direction {
	VMX_NESTED_VPID_ENTER_L2 = 0,
	VMX_NESTED_VPID_EXIT_L2,
};

/*
 * Host VPIDs are reconstructed runtime resources and are never serialized.
 * A zero effective_vpid requests the safe VMCS01 VPID fallback.
 */
struct vmx_nested_vpid_transition {
	enum vmx_nested_vpid_transition_direction direction;
	uint16_t	vmcs01_vpid;
	uint16_t	effective_vpid;
	uint16_t	previous_virtual_vpid;
	uint16_t	next_virtual_vpid;
	bool		distinct_ept_tag;
	bool		previous_virtual_vpid_valid;
	bool		next_virtual_vpid_enabled;
};

struct vmx_nested_vpid_plan {
	uint16_t	hardware_vpid;
	uint16_t	next_virtual_vpid;
	bool		next_virtual_vpid_valid;
	bool		flush_effective_context;
};

int	vmx_nested_invept_validate(const struct vmx_nested_capabilities *,
	    uint64_t, const struct vmx_nested_invalidation_descriptor *,
	    struct vmx_nested_invalidation *);
bool	vmx_nested_invept_type_valid(
	    const struct vmx_nested_capabilities *, uint64_t);
int	vmx_nested_invept_translate(
	    const struct vmx_nested_invalidation *,
	    struct vmx_nested_invalidation *);
int	vmx_nested_invvpid_validate(const struct vmx_nested_capabilities *,
	    uint64_t, const struct vmx_nested_invalidation_descriptor *,
	    struct vmx_nested_invalidation *);
bool	vmx_nested_invvpid_type_valid(
	    const struct vmx_nested_capabilities *, uint64_t);
int	vmx_nested_invvpid_translate(
	    const struct vmx_nested_invalidation *, uint16_t,
	    struct vmx_nested_invalidation *);
int	vmx_nested_vpid_transition_plan(
	    const struct vmx_nested_vpid_transition *,
	    struct vmx_nested_vpid_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_INVALIDATE_H_ */
