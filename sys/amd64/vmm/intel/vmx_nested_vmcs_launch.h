/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS_LAUNCH_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS_LAUNCH_H_

#include "vmx_nested_types.h"

/*
 * VMCS launch state belongs to one hardware VMCS, not to the vCPU run loop.
 * VM-entry failure does not launch a VMCS; a successful VM-exit proves that
 * the selected VMCS was launched and must subsequently use VMRESUME.
 */
struct vmx_nested_vmcs_launch {
	bool	current;
	bool	launched;
};

void	vmx_nested_vmcs_launch_init(struct vmx_nested_vmcs_launch *);
int	vmx_nested_vmcs_launch_select(struct vmx_nested_vmcs_launch *);
int	vmx_nested_vmcs_launch_instruction(
	    const struct vmx_nested_vmcs_launch *, int *);
int	vmx_nested_vmcs_launch_commit_entered(
	    struct vmx_nested_vmcs_launch *);
int	vmx_nested_vmcs_launch_clear(struct vmx_nested_vmcs_launch *);
int	vmx_nested_vmcs_launch_validate(
	    const struct vmx_nested_vmcs_launch *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS_LAUNCH_H_ */
