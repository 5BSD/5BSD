/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_BINDING_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_BINDING_H_

#include "vmx_nested_types.h"
#include "vmx_nested_ept_cache.h"

/*
 * One reference held for the complete lifetime of an L2 execution.  Binding
 * replacement acquires the new root before releasing the old root, so a
 * backend allocation failure cannot strand the vCPU without its prior EPT02.
 */
struct vmx_nested_ept_binding {
	struct vmx_nested_ept_cache_key key;
	struct vmx_nested_ept_cache_ref reference;
	bool active;
};

void	vmx_nested_ept_binding_init(struct vmx_nested_ept_binding *);
int	vmx_nested_ept_binding_validate(
	    const struct vmx_nested_ept_binding *);
int	vmx_nested_ept_binding_bind(struct vmx_nested_ept_cache *,
	    struct vmx_nested_ept_binding *,
	    const struct vmx_nested_ept_cache_key *);
int	vmx_nested_ept_binding_resolve(
	    const struct vmx_nested_ept_cache *,
	    const struct vmx_nested_ept_binding *,
	    const struct vmx_nested_ept_cache_key *, void **);
int	vmx_nested_ept_binding_unbind(struct vmx_nested_ept_cache *,
	    struct vmx_nested_ept_binding *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_BINDING_H_ */
