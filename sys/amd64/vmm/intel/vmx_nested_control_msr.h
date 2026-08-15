/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTROL_MSR_H_
#define	_VMM_INTEL_VMX_NESTED_CONTROL_MSR_H_

#include <sys/types.h>

#include "vmx_nested_caps.h"

#define	VMX_NESTED_FEATURE_CONTROL_LOCK		(1UL << 0)
#define	VMX_NESTED_FEATURE_CONTROL_VMX_OUTSIDE_SMX	(1UL << 2)
#define	VMX_NESTED_FEATURE_CONTROL_VALID		\
	(VMX_NESTED_FEATURE_CONTROL_LOCK |		\
	 VMX_NESTED_FEATURE_CONTROL_VMX_OUTSIDE_SMX)

struct vmx_nested_control_msr_state {
	uint64_t feature_control;
};

void	vmx_nested_control_msr_init(
	    struct vmx_nested_control_msr_state *);
int	vmx_nested_control_msr_validate(
	    const struct vmx_nested_control_msr_state *);
int	vmx_nested_control_msr_read(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_control_msr_state *, uint32_t, uint64_t *);
int	vmx_nested_control_msr_write(
	    const struct vmx_nested_capabilities *,
	    struct vmx_nested_control_msr_state *, uint32_t, uint64_t);

#endif /* _VMM_INTEL_VMX_NESTED_CONTROL_MSR_H_ */
