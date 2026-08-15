/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INSTRUCTION_GATE_H_
#define	_VMM_INTEL_VMX_NESTED_INSTRUCTION_GATE_H_

#include "vmx_nested_types.h"

enum vmx_nested_instruction_gate_result {
	VMX_NESTED_INSTRUCTION_GATE_ALLOW = 0,
	VMX_NESTED_INSTRUCTION_GATE_UD,
	VMX_NESTED_INSTRUCTION_GATE_GP,
};

struct vmx_nested_instruction_gate_input {
	uint64_t cr0;
	uint64_t cr4;
	uint64_t rflags;
	uint64_t feature_control;
	uint8_t cpl;
	bool vmxon_instruction;
	bool vmx_operation;
};

struct vmx_nested_capabilities;

/*
 * Reconstruct the control-register value visible to L1.  VMCS guest state
 * owns bits outside the guest/host mask while the read shadow owns masked
 * bits.  Neither source is a complete architectural value by itself.
 */
int	vmx_nested_visible_control_register(uint64_t, uint64_t, uint64_t,
	    uint64_t *);
int	vmx_nested_instruction_gate(
	    const struct vmx_nested_instruction_gate_input *,
	    const struct vmx_nested_capabilities *,
	    enum vmx_nested_instruction_gate_result *);

#endif /* _VMM_INTEL_VMX_NESTED_INSTRUCTION_GATE_H_ */
