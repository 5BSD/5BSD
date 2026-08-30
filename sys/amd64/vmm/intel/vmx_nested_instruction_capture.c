/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_instruction_capture.h"
#include "vmx_nested_instruction_gate.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"

#define	NVMX_SEGMENT_SS	2
#define	NVMX_SECONDARY_EPT	(UINT32_C(1) << 1)
#define	NVMX_SECONDARY_VPID	(UINT32_C(1) << 5)
#define	NVMX_EPT_INVEPT		(UINT64_C(1) << 20)
#define	NVMX_VPID_INVVPID	(UINT64_C(1) << 32)

static bool
nvmx_capture_operation_supported(
    const struct vmx_nested_instruction_capture_input *input)
{
	uint32_t secondary;

	secondary = (uint32_t)(input->capabilities.secondary >> 32);
	switch (input->operation) {
	case VMX_NESTED_INSTRUCTION_INVEPT:
		return ((secondary & NVMX_SECONDARY_EPT) != 0 &&
		    (input->capabilities.ept_vpid & NVMX_EPT_INVEPT) != 0);
	case VMX_NESTED_INSTRUCTION_INVVPID:
		return ((secondary & NVMX_SECONDARY_VPID) != 0 &&
		    (input->capabilities.ept_vpid & NVMX_VPID_INVVPID) != 0);
	default:
		return (true);
	}
}

/*
 * Intel resolves several VMfail conditions before the data memory operand is
 * accessed: with no current VMCS, VMREAD and VMWRITE complete as
 * VMfailInvalid before their memory operand is touched; VMREAD fails with
 * error 12 for an unsupported component before its destination is written;
 * and INVEPT/INVVPID fail with error 28 for an unsupported type before the
 * 16-byte descriptor is read.  An effective-address exception must not
 * preempt those architectural results, so the operand address is left
 * unvalidated and the frozen handoff resolves the failure without touching
 * guest memory.
 */
static bool
nvmx_capture_address_deferred(
    const struct vmx_nested_instruction_capture_input *input,
    const struct vmx_nested_operand *operand)
{
	struct vmx_nested_vmcs_field_info field;
	uint64_t encoding;

	switch (input->operation) {
	case VMX_NESTED_INSTRUCTION_VMREAD:
		if (input->machine.current_vmcs_gpa == UINT64_MAX)
			return (true);
		encoding = input->registers[operand->register2];
		if (!input->mode64)
			encoding &= UINT32_MAX;
		return (encoding > UINT32_MAX ||
		    vmx_nested_vmcs_field_info((uint32_t)encoding,
		    &field) != 0 ||
		    !vmx_nested_vmcs_field_available(&input->capabilities,
		    (uint32_t)encoding));
	case VMX_NESTED_INSTRUCTION_VMWRITE:
		/*
		 * VMWRITE reads its memory source before checking the field
		 * encoding, so only the current-VMCS check precedes it.
		 */
		return (input->machine.current_vmcs_gpa == UINT64_MAX);
	case VMX_NESTED_INSTRUCTION_INVEPT:
		return (!vmx_nested_invept_type_valid(&input->capabilities,
		    input->registers[operand->register2]));
	case VMX_NESTED_INSTRUCTION_INVVPID:
		return (!vmx_nested_invvpid_type_valid(&input->capabilities,
		    input->registers[operand->register2]));
	default:
		return (false);
	}
}

static int
nvmx_capture_operand(
    const struct vmx_nested_instruction_capture_input *input,
    struct vmx_nested_instruction_capture_result *result,
    bool memory_required, bool register_allowed, bool write, size_t length,
    struct vmx_nested_operand *operand, uint64_t *linear)
{
	enum vmx_nested_address_failure address_failure;
	enum vmx_nested_decode_failure decode_failure;
	int error;

	error = vmx_nested_operand_decode(input->instruction_information,
	    memory_required, register_allowed, input->mode64, operand,
	    &decode_failure);
	if (error != 0)
		return (EPROTO);
	if (operand->register_operand ||
	    nvmx_capture_address_deferred(input, operand)) {
		*linear = 0;
		return (0);
	}
	error = vmx_nested_operand_address(operand, input->displacement,
	    input->registers, input->segments, input->mode64, write, length,
	    input->capabilities.linear_address_width, linear,
	    &address_failure);
	if (error == 0)
		return (0);
	if (address_failure == VMX_NESTED_ADDRESS_FORM)
		return (EPROTO);
	result->disposition = operand->segment == NVMX_SEGMENT_SS ?
	    VMX_NESTED_INSTRUCTION_CAPTURE_SS :
	    VMX_NESTED_INSTRUCTION_CAPTURE_GP;
	result->exception_error = 0;
	return (EINPROGRESS);
}

int
vmx_nested_instruction_capture(
    const struct vmx_nested_instruction_capture_input *input,
    struct vmx_nested_instruction_capture_result *result)
{
	struct vmx_nested_instruction_capture_result candidate;
	struct vmx_nested_instruction_gate_input gate_input;
	enum vmx_nested_instruction_gate_result gate;
	struct vmx_nested_operand operand;
	struct vmx_nested_instruction_handoff_request *request;
	uint64_t linear;
	size_t memory_length;
	bool memory_required, register_allowed, write;
	int error;

	if (input == NULL || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), input,
	    sizeof(*input)) ||
	    input->operation < VMX_NESTED_INSTRUCTION_VMXON ||
	    input->operation > VMX_NESTED_INSTRUCTION_INVVPID ||
	    input->instruction_length == 0 ||
	    input->instruction_length > 15 ||
	    vmx_nested_capabilities_validate(&input->capabilities) != 0)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	/*
	 * Intel recognizes INVEPT and INVVPID only when their controlling
	 * feature and instruction capability are exposed.  This #UD has
	 * priority over CPL and operand checks, matching the instruction
	 * pseudocode and preventing a hidden feature from becoming VMfail.
	 */
	if (!nvmx_capture_operation_supported(input)) {
		candidate.disposition = VMX_NESTED_INSTRUCTION_CAPTURE_UD;
		*result = candidate;
		return (0);
	}
	memset(&gate_input, 0, sizeof(gate_input));
	gate_input.cr0 = input->cr0;
	gate_input.cr4 = input->cr4;
	gate_input.rflags = input->rflags;
	gate_input.feature_control = input->feature_control;
	gate_input.cpl = input->cpl;
	gate_input.vmxon_instruction =
	    input->operation == VMX_NESTED_INSTRUCTION_VMXON;
	gate_input.vmx_operation = input->machine.vmxon;
	error = vmx_nested_instruction_gate(&gate_input,
	    &input->capabilities, &gate);
	if (error != 0)
		return (error);
	if (gate != VMX_NESTED_INSTRUCTION_GATE_ALLOW) {
		candidate.disposition =
		    gate == VMX_NESTED_INSTRUCTION_GATE_UD ?
		    VMX_NESTED_INSTRUCTION_CAPTURE_UD :
		    VMX_NESTED_INSTRUCTION_CAPTURE_GP;
		*result = candidate;
		return (0);
	}

	request = &candidate.request;
	request->capabilities = input->capabilities;
	request->operation = input->operation;
	request->instruction_length = input->instruction_length;
	request->rflags = input->rflags;
	request->movss_blocked = input->movss_blocked;
	request->operand_size = 8;

	/*
	 * A VMXON executed while already in VMX operation fails valid before
	 * the operand is read.  Do not let effective-address validation change
	 * that architectural priority; the frozen handoff resolves the failure.
	 */
	if (input->operation == VMX_NESTED_INSTRUCTION_VMXON &&
	    input->machine.vmxon) {
		candidate.disposition =
		    VMX_NESTED_INSTRUCTION_CAPTURE_REQUEST;
		*result = candidate;
		return (0);
	}

	memory_required = false;
	register_allowed = false;
	write = false;
	memory_length = 8;
	switch (input->operation) {
	case VMX_NESTED_INSTRUCTION_VMXOFF:
	case VMX_NESTED_INSTRUCTION_VMLAUNCH:
	case VMX_NESTED_INSTRUCTION_VMRESUME:
		candidate.disposition =
		    VMX_NESTED_INSTRUCTION_CAPTURE_REQUEST;
		*result = candidate;
		return (0);
	case VMX_NESTED_INSTRUCTION_VMXON:
	case VMX_NESTED_INSTRUCTION_VMCLEAR:
	case VMX_NESTED_INSTRUCTION_VMPTRLD:
		memory_required = true;
		break;
	case VMX_NESTED_INSTRUCTION_VMPTRST:
		memory_required = true;
		write = true;
		break;
	case VMX_NESTED_INSTRUCTION_VMREAD:
		register_allowed = true;
		write = true;
		request->operand_size = input->mode64 ? 8 : 4;
		memory_length = request->operand_size;
		break;
	case VMX_NESTED_INSTRUCTION_VMWRITE:
		register_allowed = true;
		request->operand_size = input->mode64 ? 8 : 4;
		memory_length = request->operand_size;
		break;
	case VMX_NESTED_INSTRUCTION_INVEPT:
	case VMX_NESTED_INSTRUCTION_INVVPID:
		memory_required = true;
		memory_length = 16;
		break;
	default:
		return (EINVAL);
	}
	error = nvmx_capture_operand(input, &candidate, memory_required,
	    register_allowed, write, memory_length, &operand, &linear);
	if (error == EINPROGRESS) {
		*result = candidate;
		return (0);
	}
	if (error != 0)
		return (error);
	request->linear_address = linear;

	switch (input->operation) {
	case VMX_NESTED_INSTRUCTION_VMREAD:
		request->field_encoding =
		    input->registers[operand.register2];
		if (!input->mode64)
			request->field_encoding &= UINT32_MAX;
		if (operand.register_operand) {
			request->value_in_register = true;
			request->register_index = operand.register1;
		}
		break;
	case VMX_NESTED_INSTRUCTION_VMWRITE:
		request->field_encoding =
		    input->registers[operand.register2];
		if (!input->mode64)
			request->field_encoding &= UINT32_MAX;
		if (operand.register_operand) {
			request->value_in_register = true;
			request->register_index = operand.register1;
			request->register_value =
			    input->registers[operand.register1];
			if (!input->mode64)
				request->register_value &= UINT32_MAX;
		}
		break;
	case VMX_NESTED_INSTRUCTION_INVEPT:
	case VMX_NESTED_INSTRUCTION_INVVPID:
		request->value_in_register = true;
		request->register_index = operand.register2;
		request->register_value =
		    input->registers[operand.register2];
		break;
	default:
		break;
	}
	candidate.disposition = VMX_NESTED_INSTRUCTION_CAPTURE_REQUEST;
	*result = candidate;
	return (0);
}
