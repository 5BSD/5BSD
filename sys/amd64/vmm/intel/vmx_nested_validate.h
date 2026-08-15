/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VALIDATE_H_
#define	_VMM_INTEL_VMX_NESTED_VALIDATE_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;

bool	vmx_nested_canonical_address(uint64_t, uint8_t);
bool	vmx_nested_high_bits_identical(uint64_t, uint8_t);
bool	vmx_nested_fixed_bits_valid(
	    uint64_t, uint64_t, uint64_t, uint64_t);
bool	vmx_nested_pat_valid(uint64_t);
bool	vmx_nested_physical_range_valid(
	    const struct vmx_nested_capabilities *, uint64_t, uint64_t,
	    uint64_t);
bool	vmx_nested_vmx_physical_range_valid(
	    const struct vmx_nested_capabilities *, uint64_t, uint64_t,
	    uint64_t);

#endif /* _VMM_INTEL_VMX_NESTED_VALIDATE_H_ */
