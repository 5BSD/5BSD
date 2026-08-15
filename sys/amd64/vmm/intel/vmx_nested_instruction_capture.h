/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INSTRUCTION_CAPTURE_H_
#define	_VMM_INTEL_VMX_NESTED_INSTRUCTION_CAPTURE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_decode.h"
#include "vmx_nested_instruction_handoff.h"

enum vmx_nested_instruction_capture_disposition {
	VMX_NESTED_INSTRUCTION_CAPTURE_REQUEST = 0,
	VMX_NESTED_INSTRUCTION_CAPTURE_UD,
	VMX_NESTED_INSTRUCTION_CAPTURE_GP,
	VMX_NESTED_INSTRUCTION_CAPTURE_SS,
};

struct vmx_nested_instruction_capture_input {
	struct vmx_nested_capabilities capabilities;
	/*
	 * Used only for architectural permission and priority checks.  The
	 * captured request remains unbound; the context publisher supplies
	 * its authoritative machine state and generation identifier.
	 */
	struct vmx_nested_machine machine;
	enum vmx_nested_instruction_operation operation;
	uint64_t registers[16];
	struct vmx_nested_address_segment segments[6];
	uint64_t displacement;
	uint64_t cr0;
	uint64_t cr4;
	uint64_t rflags;
	uint64_t feature_control;
	uint32_t instruction_information;
	uint8_t instruction_length;
	uint8_t cpl;
	bool mode64;
	bool movss_blocked;
};

struct vmx_nested_instruction_capture_result {
	enum vmx_nested_instruction_capture_disposition disposition;
	struct vmx_nested_instruction_handoff_request request;
	uint32_t exception_error;
};

int	vmx_nested_instruction_capture(
	    const struct vmx_nested_instruction_capture_input *,
	    struct vmx_nested_instruction_capture_result *);

#endif /* _VMM_INTEL_VMX_NESTED_INSTRUCTION_CAPTURE_H_ */
