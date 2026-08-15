/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_MSR_WORKSPACE_H_
#define	_VMM_INTEL_VMX_NESTED_MSR_WORKSPACE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_msr.h"

struct vmx_nested_capabilities;

/*
 * Runtime-only storage for transactional VM-entry and VM-exit MSR lists.
 * The owner allocates the two arrays outside VMX critical sections.  No
 * pointer in this object is part of the portable nested-VMX state.
 */
struct vmx_nested_msr_workspace {
	struct vmx_nested_msr_entry	*plan;
	struct vmx_nested_msr_entry	*rollback;
	uint64_t			 capability_signature;
	uint64_t			 generation;
	uint32_t			 capacity;
	bool				 active;
};

int	vmx_nested_msr_workspace_capacity(
	    const struct vmx_nested_capabilities *, uint32_t *);
void	vmx_nested_msr_workspace_init(struct vmx_nested_msr_workspace *);
int	vmx_nested_msr_workspace_bind(struct vmx_nested_msr_workspace *,
	    const struct vmx_nested_capabilities *,
	    struct vmx_nested_msr_entry *, struct vmx_nested_msr_entry *,
	    uint32_t);
int	vmx_nested_msr_workspace_begin(struct vmx_nested_msr_workspace *,
	    const struct vmx_nested_capabilities *, uint32_t, uint32_t,
	    uint32_t, uint64_t *);
int	vmx_nested_msr_workspace_end(struct vmx_nested_msr_workspace *,
	    uint64_t);
int	vmx_nested_msr_workspace_unbind(struct vmx_nested_msr_workspace *);
int	vmx_nested_msr_workspace_validate(
	    const struct vmx_nested_msr_workspace *);

#endif /* _VMM_INTEL_VMX_NESTED_MSR_WORKSPACE_H_ */
