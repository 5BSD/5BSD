/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_instruction_gate.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_validate.h"

#define	NVMX_GATE_CR0_PE			(1UL << 0)
#define	NVMX_GATE_CR4_VMXE		(1UL << 13)
#define	NVMX_GATE_RFLAGS_VM		(1UL << 17)
#define	NVMX_GATE_FEATURE_CONTROL_LOCK	(1UL << 0)
#define	NVMX_GATE_FEATURE_CONTROL_VMX_OUTSIDE_SMX	(1UL << 2)

int
vmx_nested_visible_control_register(uint64_t guest, uint64_t mask,
    uint64_t shadow, uint64_t *visible)
{

	if (visible == NULL)
		return (EINVAL);
	*visible = (guest & ~mask) | (shadow & mask);
	return (0);
}

int
vmx_nested_instruction_gate(
    const struct vmx_nested_instruction_gate_input *input,
    const struct vmx_nested_capabilities *capabilities,
    enum vmx_nested_instruction_gate_result *result)
{

	if (input == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), capabilities,
	    sizeof(*capabilities)) || input->cpl > 3 ||
	    vmx_nested_capabilities_validate(capabilities) != 0)
		return (EINVAL);

	if (!input->vmxon_instruction) {
		/*
		 * Hardware has already performed the pre-VM-exit mode checks.
		 * L0 must still emulate the architectural nested state and CPL
		 * checks because those refer to L1's virtual VMX operation.
		 */
		if (!input->vmx_operation) {
			*result = VMX_NESTED_INSTRUCTION_GATE_UD;
			return (0);
		}
		*result = input->cpl == 0 ?
		    VMX_NESTED_INSTRUCTION_GATE_ALLOW :
		    VMX_NESTED_INSTRUCTION_GATE_GP;
		return (0);
	}

	/*
	 * VMXON's CR4.VMXE, protected-mode, and VM86 checks precede its
	 * VM-exit behavior.  Repeat them defensively because L0 virtualizes
	 * CR4 and can force hardware VMXE independently of L1.
	 */
	if ((input->cr4 & NVMX_GATE_CR4_VMXE) == 0 ||
	    (input->cr0 & NVMX_GATE_CR0_PE) == 0 ||
	    (input->rflags & NVMX_GATE_RFLAGS_VM) != 0) {
		*result = VMX_NESTED_INSTRUCTION_GATE_UD;
		return (0);
	}
	if (input->cpl != 0) {
		*result = VMX_NESTED_INSTRUCTION_GATE_GP;
		return (0);
	}
	/*
	 * A repeated VMXON is VMfailValid and is therefore allowed through
	 * to the instruction state machine before fixed-bit and
	 * IA32_FEATURE_CONTROL checks.
	 */
	if (input->vmx_operation) {
		*result = VMX_NESTED_INSTRUCTION_GATE_ALLOW;
		return (0);
	}
	if (!vmx_nested_fixed_bits_valid(input->cr0,
	    capabilities->cr0_fixed0, capabilities->cr0_fixed1, 0) ||
	    !vmx_nested_fixed_bits_valid(input->cr4,
	    capabilities->cr4_fixed0, capabilities->cr4_fixed1, 0) ||
	    (input->feature_control &
	    (NVMX_GATE_FEATURE_CONTROL_LOCK |
	    NVMX_GATE_FEATURE_CONTROL_VMX_OUTSIDE_SMX)) !=
	    (NVMX_GATE_FEATURE_CONTROL_LOCK |
	    NVMX_GATE_FEATURE_CONTROL_VMX_OUTSIDE_SMX)) {
		*result = VMX_NESTED_INSTRUCTION_GATE_GP;
		return (0);
	}
	*result = VMX_NESTED_INSTRUCTION_GATE_ALLOW;
	return (0);
}
