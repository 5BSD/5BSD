/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_STATE_RANGE_H_
#define	_VMM_INTEL_VMX_NESTED_STATE_RANGE_H_

#include "vmx_nested_types.h"

#include <dev/vmm/vmm_address_range.h>

/*
 * Preserve the private codecs' NULL/zero-length convention while delegating
 * all non-empty address arithmetic to the architecture-neutral VMM helper.
 * That helper treats an address-space wrap as overlap and rejects malformed
 * ranges that cannot be represented by uintptr_t.
 */
static __inline bool
vmx_nested_state_ranges_overlap(const void *first, size_t first_length,
    const void *second, size_t second_length)
{
	if (first == NULL || second == NULL ||
	    first_length == 0 || second_length == 0)
		return (false);
	return (vmm_address_ranges_overlap(first, first_length, second,
	    second_length));
}

#endif /* _VMM_INTEL_VMX_NESTED_STATE_RANGE_H_ */
