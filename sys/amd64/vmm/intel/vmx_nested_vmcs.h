/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS_H_

#include "vmx_nested_types.h"

struct vmx_nested_vmcs_field_info {
	uint32_t encoding;
	uint8_t width;
	bool readonly;
	bool high_half;
};

struct vmx_nested_capabilities;

int	vmx_nested_vmcs_field_info(uint32_t,
	    struct vmx_nested_vmcs_field_info *);
bool	vmx_nested_vmcs_field_available(
	    const struct vmx_nested_capabilities *, uint32_t);
uint64_t vmx_nested_vmcs_schema_signature(void);
uint64_t vmx_nested_vmcs_enum(void);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS_H_ */
