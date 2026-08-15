/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_APPLY_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_APPLY_H_

#include "vmx_nested_types.h"

#include "vmx_nested_vmcs02_program.h"

/*
 * Transactional boundary between the value-only programming image and an
 * implementation-owned hardware VMCS02.  begin() must select a private,
 * unpublished VMCS02.  commit() is the sole publication point.  abort()
 * must make a successfully begun transaction unreachable and restore the
 * caller's prior current-VMCS selection.
 */
struct vmx_nested_vmcs02_program_apply_ops {
	int	(*begin)(void *, const struct vmx_nested_vmcs02_id *,
		    uint64_t);
	int	(*write)(void *, uint32_t, uint64_t);
	int	(*commit)(void *);
	void	(*abort)(void *);
};

struct vmx_nested_vmcs02_apply_result {
	struct vmx_nested_vmcs02_id	id;
	uint64_t	resource_generation;
	uint32_t	writes_completed;
	bool		committed;
};

int	vmx_nested_vmcs02_program_apply(
	    const struct vmx_nested_vmcs02_program *,
	    const struct vmx_nested_vmcs02_program_apply_ops *, void *,
	    struct vmx_nested_vmcs02_apply_result *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_APPLY_H_ */
