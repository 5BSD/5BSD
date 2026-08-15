/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_PROGRAM_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_PROGRAM_H_

#include <sys/types.h>

#include "vmx_nested_vmcs02_bind.h"

#define	VMX_NESTED_VMCS02_PROGRAM_MAX_FIELDS	144U

struct vmx_nested_vmcs02_program_field {
	uint32_t	encoding;
	uint64_t	value;
};

/*
 * Canonical, value-only hardware-VMCS write image.  Encodings are strictly
 * increasing, so duplicate or order-dependent writes cannot be hidden in a
 * production adapter.  This is runtime state, not a checkpoint ABI.
 */
struct vmx_nested_vmcs02_program {
	struct vmx_nested_vmcs02_id	id;
	uint64_t	resource_generation;
	uint32_t	count;
	struct vmx_nested_vmcs02_program_field
	    fields[VMX_NESTED_VMCS02_PROGRAM_MAX_FIELDS];
};

int	vmx_nested_vmcs02_program_build(
	    const struct vmx_nested_vmcs02_hardware_plan *,
	    struct vmx_nested_vmcs02_program *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_PROGRAM_H_ */
