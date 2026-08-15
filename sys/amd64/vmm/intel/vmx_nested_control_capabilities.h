/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTROL_CAPABILITIES_H_
#define	_VMM_INTEL_VMX_NESTED_CONTROL_CAPABILITIES_H_

#include <sys/types.h>

#include "vmx_nested_compose.h"

/*
 * Raw architectural MSR values.  Keeping selection value-only makes the
 * Intel "true controls" rule independently testable and keeps rdmsr() out of
 * common nested-entry composition.
 */
struct vmx_nested_control_capabilities_raw {
	uint64_t basic;
	uint64_t legacy_pinbased;
	uint64_t legacy_primary;
	uint64_t legacy_vmexit;
	uint64_t legacy_vmentry;
	uint64_t true_pinbased;
	uint64_t true_primary;
	uint64_t true_vmexit;
	uint64_t true_vmentry;
	uint64_t secondary;
};

int	vmx_nested_control_capabilities_select(
	    const struct vmx_nested_control_capabilities_raw *,
	    struct vmx_nested_vmcs02_capabilities *);

#endif /* _VMM_INTEL_VMX_NESTED_CONTROL_CAPABILITIES_H_ */
