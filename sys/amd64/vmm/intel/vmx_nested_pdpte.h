/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_PDPTE_H_
#define	_VMM_INTEL_VMX_NESTED_PDPTE_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;
struct vmx_nested_guest_control_state;
struct vmx_nested_host_state;
struct vmx_nested_memory;

struct vmx_nested_pdpte_state {
	uint64_t value[4];
	bool active;
};

static __inline bool
vmx_nested_pdpte_state_equal(const struct vmx_nested_pdpte_state *a,
    const struct vmx_nested_pdpte_state *b)
{
	unsigned int i;

	if (a == NULL || b == NULL || a->active != b->active)
		return (false);
	for (i = 0; i < 4; i++) {
		if (a->value[i] != b->value[i])
			return (false);
	}
	return (true);
}

enum vmx_nested_pdpte_failure {
	VMX_NESTED_PDPTE_OK = 0,
	VMX_NESTED_PDPTE_PREREQUISITE,
	VMX_NESTED_PDPTE_ADDRESS,
	VMX_NESTED_PDPTE_MEMORY,
	VMX_NESTED_PDPTE_RESERVED,
};

bool	vmx_nested_host_pdpte_active(
	    const struct vmx_nested_host_state *);
bool	vmx_nested_guest_pdpte_memory_required(uint32_t, uint32_t,
	    uint32_t, const struct vmx_nested_guest_control_state *);
int	vmx_nested_pdpte_validate(
	    const struct vmx_nested_capabilities *, uint32_t, uint32_t,
	    uint32_t, const struct vmx_nested_guest_control_state *,
	    const uint64_t [4], const struct vmx_nested_memory *,
	    struct vmx_nested_pdpte_state *,
	    enum vmx_nested_pdpte_failure *);
int	vmx_nested_host_pdpte_snapshot(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_host_state *,
	    const struct vmx_nested_memory *,
	    struct vmx_nested_pdpte_state *,
	    enum vmx_nested_pdpte_failure *);

#endif /* _VMM_INTEL_VMX_NESTED_PDPTE_H_ */
