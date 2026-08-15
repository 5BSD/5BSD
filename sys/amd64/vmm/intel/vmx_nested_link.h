/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_LINK_H_
#define	_VMM_INTEL_VMX_NESTED_LINK_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;
struct vmx_nested_memory;

enum vmx_nested_link_failure {
	VMX_NESTED_LINK_OK = 0,
	VMX_NESTED_LINK_ADDRESS,
	VMX_NESTED_LINK_MEMORY,
	VMX_NESTED_LINK_REVISION,
	VMX_NESTED_LINK_CURRENT,
	VMX_NESTED_LINK_EXECUTIVE,
};

bool	vmx_nested_link_pointer_memory_required(uint64_t);
bool	vmx_nested_link_state_required(uint32_t, uint32_t, uint32_t, bool,
	    bool, uint64_t);
int	vmx_nested_link_pointer_validate(
	    const struct vmx_nested_capabilities *, uint32_t, uint32_t,
	    uint32_t, uint64_t, uint64_t, uint64_t, bool,
	    const struct vmx_nested_memory *,
	    enum vmx_nested_link_failure *);

#endif /* _VMM_INTEL_VMX_NESTED_LINK_H_ */
