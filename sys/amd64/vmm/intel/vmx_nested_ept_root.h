/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_ROOT_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_ROOT_H_

#include "vmx_nested_types.h"

struct vmx_nested_ept_cache_key;
struct vcpu;

struct vmx_nested_ept_root_backend {
	vm_offset_t min_address;
	vm_offset_t max_address;
};

/*
 * Cache callbacks for an L0-owned EPT02 pmap.  The root is runtime-only and
 * is reconstructed empty after restore; mappings are populated lazily from
 * the EPT12 walker.
 */
int	vmx_nested_ept_root_create(void *,
	    const struct vmx_nested_ept_cache_key *, void **);
void	vmx_nested_ept_root_destroy(void *, void *);
int	vmx_nested_ept_root_invalidate(void *, void *);
uint64_t vmx_nested_ept_root_eptp(const void *);
/*
 * Protect one composed EPT root across hardware execution.  Activation
 * participates in the pmap EPT SMR and generation protocol; callers must
 * pair it on the same CPU and may not sleep between these operations.
 */
void	vmx_nested_ept_root_activate(void *);
void	vmx_nested_ept_root_deactivate(void *);
int	vmx_nested_ept_root_populate(void *, struct vcpu *, uint64_t,
	    uint64_t, uint8_t, bool);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_ROOT_H_ */
