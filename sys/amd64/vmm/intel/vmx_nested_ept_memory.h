/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_MEMORY_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_MEMORY_H_

#include "vmx_nested_types.h"

/*
 * Atomic access to L1-owned EPT paging-structure entries.
 *
 * Callbacks exchange exact eight-byte memory images and are endian-blind.
 * The common helper alone encodes and decodes Intel little-endian values.
 * Both callbacks must operate atomically with respect to other accesses to
 * the same naturally aligned entry.  compare_exchange() reports the image
 * observed at the comparison and whether the exchange occurred.
 *
 * The caller owns translation, pinning, and fault handling.  Nested-VMX code
 * never retains the callbacks, argument, or a mapping derived from them.
 */
struct vmx_nested_ept_memory {
	int	(*load)(void *, uint64_t, uint8_t [8]);
	int	(*compare_exchange)(void *, uint64_t, const uint8_t [8],
		    const uint8_t [8], uint8_t [8], bool *);
	void	*arg;
};

int	vmx_nested_ept_entry_load(const struct vmx_nested_ept_memory *,
	    uint64_t, uint64_t *);
int	vmx_nested_ept_ad_update(const struct vmx_nested_ept_memory *,
	    uint64_t, uint64_t, bool, uint64_t *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_MEMORY_H_ */
