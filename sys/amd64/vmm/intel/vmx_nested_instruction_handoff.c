/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_instruction.h"
#include "vmx_nested_instruction_handoff.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"

static bool
nvmx_ih_id_valid(const struct vmx_nested_instruction_handoff_id *id)
{

	return (id != NULL && id->state_generation != 0 &&
	    id->execution_epoch != 0);
}

static bool
nvmx_ih_id_equal(const struct vmx_nested_instruction_handoff_id *first,
    const struct vmx_nested_instruction_handoff_id *second)
{

	return (first->state_generation == second->state_generation &&
	    first->execution_epoch == second->execution_epoch);
}

static bool
nvmx_ih_machine_valid(const struct vmx_nested_machine *machine)
{

	if (machine->vmxon)
		return (machine->vmxon_gpa != UINT64_MAX &&
		    machine->current_vmcs_gpa != machine->vmxon_gpa &&
		    machine->epoch != 0);
	return (machine->vmxon_gpa == UINT64_MAX &&
	    machine->current_vmcs_gpa == UINT64_MAX);
}

static bool
nvmx_ih_machine_equal(const struct vmx_nested_machine *first,
    const struct vmx_nested_machine *second)
{

	return (first->vmxon == second->vmxon &&
	    first->vmxon_gpa == second->vmxon_gpa &&
	    first->current_vmcs_gpa == second->current_vmcs_gpa &&
	    first->epoch == second->epoch);
}

static bool
nvmx_ih_result_equal(const struct vmx_nested_result *first,
    const struct vmx_nested_result *second)
{

	return (first->kind == second->kind &&
	    first->instruction_error == second->instruction_error);
}

static bool
nvmx_ih_fault_equal(const struct vmx_nested_instruction_fault *first,
    const struct vmx_nested_instruction_fault *second)
{

	return (first->linear_address == second->linear_address &&
	    first->error_code == second->error_code &&
	    first->vector == second->vector &&
	    first->error_code_valid == second->error_code_valid &&
	    first->injected == second->injected);
}

static bool
nvmx_ih_request_equal(
    const struct vmx_nested_instruction_handoff_request *first,
    const struct vmx_nested_instruction_handoff_request *second)
{

	return (nvmx_ih_id_equal(&first->id, &second->id) &&
	    vmx_nested_capabilities_equal(&first->capabilities,
	    &second->capabilities) && nvmx_ih_machine_equal(&first->machine,
	    &second->machine) && first->operation == second->operation &&
	    first->linear_address == second->linear_address &&
	    first->register_value == second->register_value &&
	    first->rflags == second->rflags &&
	    first->field_encoding == second->field_encoding &&
	    first->operand_size == second->operand_size &&
	    first->instruction_length == second->instruction_length &&
	    first->register_index == second->register_index &&
	    first->value_in_register == second->value_in_register &&
	    first->movss_blocked == second->movss_blocked);
}

static bool
nvmx_ih_handoff_result_equal(
    const struct vmx_nested_instruction_handoff_result *first,
    const struct vmx_nested_instruction_handoff_result *second)
{

	return (nvmx_ih_id_equal(&first->id, &second->id) &&
	    nvmx_ih_machine_equal(&first->machine, &second->machine) &&
	    nvmx_ih_result_equal(&first->instruction, &second->instruction) &&
	    nvmx_ih_fault_equal(&first->fault, &second->fault) &&
	    first->output_value == second->output_value &&
	    first->rflags == second->rflags && first->host_error ==
	    second->host_error && first->disposition == second->disposition &&
	    first->output_size == second->output_size &&
	    first->output_register_index == second->output_register_index &&
	    first->rip_advance == second->rip_advance && first->output_register ==
	    second->output_register);
}

static bool
nvmx_ih_handoff_equal(const struct vmx_nested_instruction_handoff *first,
    const struct vmx_nested_instruction_handoff *second)
{

	return (first->state == second->state && nvmx_ih_request_equal(
	    &first->request, &second->request) && nvmx_ih_handoff_result_equal(
	    &first->result, &second->result));
}

static int
nvmx_ih_request_valid(
    const struct vmx_nested_instruction_handoff_request *request)
{

	if (request == NULL || !nvmx_ih_id_valid(&request->id) ||
	    vmx_nested_capabilities_validate(&request->capabilities) != 0 ||
	    !nvmx_ih_machine_valid(&request->machine) ||
	    request->operation < VMX_NESTED_INSTRUCTION_VMXON ||
	    request->operation > VMX_NESTED_INSTRUCTION_INVVPID)
		return (EINVAL);
	if (request->operand_size != 4 && request->operand_size != 8)
		return (EINVAL);
	if (request->instruction_length == 0 ||
	    request->instruction_length > 15 || (request->rflags & 2) == 0)
		return (EINVAL);
	if (request->operation == VMX_NESTED_INSTRUCTION_VMXON) {
		if (request->operand_size != 8 || request->value_in_register ||
		    request->register_index != 0 ||
		    request->register_value != 0 || request->field_encoding != 0)
			return (EINVAL);
	} else if (!request->machine.vmxon) {
		return (EINVAL);
	}
	switch (request->operation) {
	case VMX_NESTED_INSTRUCTION_VMXOFF:
		if (request->operand_size != 8 ||
		    request->linear_address != 0 ||
		    request->register_value != 0 ||
		    request->field_encoding != 0 ||
		    request->value_in_register ||
		    request->register_index != 0)
			return (EINVAL);
		break;
	case VMX_NESTED_INSTRUCTION_VMCLEAR:
	case VMX_NESTED_INSTRUCTION_VMPTRLD:
	case VMX_NESTED_INSTRUCTION_VMPTRST:
		if (request->operand_size != 8 || request->value_in_register ||
		    request->register_index != 0 ||
		    request->register_value != 0 ||
		    request->field_encoding != 0)
			return (EINVAL);
		break;
	case VMX_NESTED_INSTRUCTION_VMREAD:
		if (request->register_value != 0 ||
		    (request->value_in_register &&
		    (request->linear_address != 0 ||
		    request->register_index > 15)) ||
		    (!request->value_in_register &&
		    request->register_index != 0))
			return (EINVAL);
		break;
	case VMX_NESTED_INSTRUCTION_VMWRITE:
		if (request->value_in_register) {
			if (request->linear_address != 0 ||
			    request->register_index > 15)
				return (EINVAL);
		} else if (request->register_value != 0 ||
		    request->register_index != 0) {
			return (EINVAL);
		}
		break;
	case VMX_NESTED_INSTRUCTION_INVEPT:
	case VMX_NESTED_INSTRUCTION_INVVPID:
		if (request->operand_size != 8 ||
		    !request->value_in_register ||
		    request->register_index > 15 ||
		    request->field_encoding != 0)
			return (EINVAL);
		break;
	case VMX_NESTED_INSTRUCTION_VMLAUNCH:
	case VMX_NESTED_INSTRUCTION_VMRESUME:
		if (request->operand_size != 8 ||
		    request->linear_address != 0 ||
		    request->register_value != 0 ||
		    request->field_encoding != 0 ||
		    request->value_in_register ||
		    request->register_index != 0)
			return (EINVAL);
		break;
	default:
		break;
	}
	if (request->movss_blocked &&
	    request->operation != VMX_NESTED_INSTRUCTION_VMLAUNCH &&
	    request->operation != VMX_NESTED_INSTRUCTION_VMRESUME)
		return (EINVAL);
	return (0);
}

static int
nvmx_ih_access_validate(
    const struct vmx_nested_instruction_access_result *access)
{

	if (access->kind < VMX_NESTED_INSTRUCTION_ACCESS_OK ||
	    access->kind > VMX_NESTED_INSTRUCTION_ACCESS_FATAL)
		return (EPROTO);
	if (access->kind == VMX_NESTED_INSTRUCTION_ACCESS_OK ||
	    access->kind == VMX_NESTED_INSTRUCTION_ACCESS_INVALID_REGION ||
	    access->kind == VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT) {
		if (access->error != 0)
			return (EPROTO);
	} else if (access->error <= 0) {
		return (EPROTO);
	}
	if (access->kind == VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT &&
	    access->fault.vector == 0)
		return (EPROTO);
	return (0);
}

static int
nvmx_ih_access(struct vmx_nested_instruction_handoff *handoff,
    struct vmx_nested_instruction_handoff_result *resolved,
    struct vmx_nested_instruction_access_result access, uint32_t allowed)
{
	int error;

	error = nvmx_ih_access_validate(&access);
	if (error != 0)
		return (error);
	if ((allowed & (UINT32_C(1) << access.kind)) == 0)
		return (EPROTO);
	switch (access.kind) {
	case VMX_NESTED_INSTRUCTION_ACCESS_OK:
		return (0);
	case VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT:
		resolved->disposition = VMX_NESTED_INSTRUCTION_GUEST_FAULT;
		resolved->fault = access.fault;
		resolved->rflags = handoff->request.rflags;
		handoff->result = *resolved;
		handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED;
		return (EINPROGRESS);
	case VMX_NESTED_INSTRUCTION_ACCESS_INVALID_REGION:
		return (ENOEXEC);
	case VMX_NESTED_INSTRUCTION_ACCESS_RETRY:
		return (access.error);
	case VMX_NESTED_INSTRUCTION_ACCESS_FATAL:
		resolved->disposition = VMX_NESTED_INSTRUCTION_HOST_ERROR;
		resolved->host_error = access.error;
		resolved->rflags = handoff->request.rflags;
		handoff->result = *resolved;
		handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED;
		return (EINPROGRESS);
	default:
		return (EPROTO);
	}
}

static int
nvmx_ih_complete(struct vmx_nested_instruction_handoff *handoff,
    struct vmx_nested_instruction_handoff_result *resolved,
    const struct vmx_nested_instruction_handoff_ops *ops, void *arg)
{
	int error;

	if (resolved->instruction.kind == VMX_NESTED_FAIL_VALID) {
		if (ops->vmcs_set_error == NULL)
			return (ENOTSUP);
		error = nvmx_ih_access(handoff, resolved,
		    ops->vmcs_set_error(arg,
		    handoff->request.machine.current_vmcs_gpa,
		    resolved->instruction.instruction_error),
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
		if (error != 0)
			return (error);
	}
	resolved->rflags = vmx_nested_result_rflags(resolved->instruction,
	    handoff->request.rflags);
	resolved->rip_advance = handoff->request.instruction_length;
	handoff->result = *resolved;
	handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED;
	return (0);
}

static int
nvmx_ih_linear_read(struct vmx_nested_instruction_handoff *handoff,
    struct vmx_nested_instruction_handoff_result *resolved,
    const struct vmx_nested_instruction_handoff_ops *ops, void *arg,
    uint64_t address, void *value, size_t length)
{

	if (ops->linear_read == NULL)
		return (ENOTSUP);
	return (nvmx_ih_access(handoff, resolved,
	    ops->linear_read(arg, address, value, length),
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL)));
}

static int
nvmx_ih_linear_write(struct vmx_nested_instruction_handoff *handoff,
    struct vmx_nested_instruction_handoff_result *resolved,
    const struct vmx_nested_instruction_handoff_ops *ops, void *arg,
    uint64_t address, const void *value, size_t length)
{

	if (ops->linear_write == NULL)
		return (ENOTSUP);
	return (nvmx_ih_access(handoff, resolved,
	    ops->linear_write(arg, address, value, length),
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL)));
}

static int
nvmx_ih_check_region(struct vmx_nested_instruction_handoff *handoff,
    struct vmx_nested_instruction_handoff_result *resolved,
    const struct vmx_nested_instruction_handoff_ops *ops, void *arg,
    uint64_t gpa, bool vmxon)
{

	if (ops->check_region == NULL)
		return (ENOTSUP);
	return (nvmx_ih_access(handoff, resolved,
	    ops->check_region(arg, gpa, vmxon),
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_INVALID_REGION) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
	    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL)));
}

void
vmx_nested_instruction_handoff_init(
    struct vmx_nested_instruction_handoff *handoff)
{

	if (handoff != NULL)
		memset(handoff, 0, sizeof(*handoff));
}

int
vmx_nested_instruction_handoff_publish(
    struct vmx_nested_instruction_handoff *handoff,
    const struct vmx_nested_instruction_handoff_request *request)
{
	int error;

	if (handoff == NULL)
		return (EINVAL);
	error = nvmx_ih_request_valid(request);
	if (error != 0)
		return (error);
	if (vmx_nested_state_ranges_overlap(request, sizeof(*request), handoff,
	    sizeof(*handoff)))
		return (EINVAL);
	if (handoff->state != VMX_NESTED_INSTRUCTION_HANDOFF_IDLE)
		return (EBUSY);
	handoff->request = *request;
	memset(&handoff->result, 0, sizeof(handoff->result));
	handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_PENDING;
	return (0);
}

int
vmx_nested_instruction_handoff_handle(
    struct vmx_nested_instruction_handoff *handoff,
    const struct vmx_nested_instruction_handoff_id *id,
    const struct vmx_nested_instruction_handoff_ops *ops, void *arg)
{
	struct vmx_nested_instruction_access_result access;
	struct vmx_nested_instruction_handoff *owner;
	struct vmx_nested_instruction_handoff owner_before, working;
	struct vmx_nested_instruction_handoff_result resolved;
	struct vmx_nested_instruction_handoff_ops ops_snapshot;
	struct vmx_nested_vmcs_field_info field;
	struct vmx_nested_machine candidate;
	struct vmx_nested_invalidation invalidation;
	struct vmx_nested_invalidation_descriptor descriptor;
	const struct vmx_nested_instruction_handoff_request *request;
	uint8_t bytes[16];
	uint64_t gpa, value;
	bool address_valid, launched, revision_valid, supported;
	uint64_t launch_epoch;
	int error;

	if (handoff == NULL || !nvmx_ih_id_valid(id) || ops == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(ops, sizeof(*ops), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(ops, sizeof(*ops), id,
	    sizeof(*id)))
		return (EINVAL);
	/* One instruction uses one immutable provider identity. */
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_IDLE)
		return (ENOENT);
	if (!nvmx_ih_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED)
		return (EALREADY);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING)
		return (EBUSY);
	if (handoff->state != VMX_NESTED_INSTRUCTION_HANDOFF_PENDING)
		return (EPROTO);

	/*
	 * Execute through a local value owner.  No callback is given a pointer to
	 * the retained request/result state, and an adapter which reaches the real
	 * owner through private context cannot publish a changed instruction.
	 */
	owner = handoff;
	owner_before = *owner;
	working = *owner;
	handoff = &working;
	request = &handoff->request;
	handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING;
	memset(&resolved, 0, sizeof(resolved));
	resolved.id = request->id;
	resolved.machine = request->machine;
	resolved.rflags = request->rflags;
	resolved.disposition = VMX_NESTED_INSTRUCTION_COMPLETE;
	candidate = request->machine;
	memset(&field, 0, sizeof(field));
	gpa = 0;
	value = request->register_value;

	if (request->operation == VMX_NESTED_INSTRUCTION_VMXON &&
	    request->machine.vmxon) {
		resolved.instruction = vmx_nested_machine_vmxon(&candidate, 0,
		    false);
		goto complete;
	}
	if (request->operation == VMX_NESTED_INSTRUCTION_VMXON ||
	    request->operation == VMX_NESTED_INSTRUCTION_VMCLEAR ||
	    request->operation == VMX_NESTED_INSTRUCTION_VMPTRLD) {
		error = nvmx_ih_linear_read(handoff, &resolved, ops, arg,
		    request->linear_address, bytes, sizeof(uint64_t));
		if (error != 0)
			goto out;
		gpa = le64dec(bytes);
		address_valid = vmx_nested_region_gpa_valid(
		    &request->capabilities, gpa);
	} else {
		address_valid = true;
	}

	switch (request->operation) {
	case VMX_NESTED_INSTRUCTION_VMXON:
		revision_valid = false;
		if (address_valid) {
			error = nvmx_ih_check_region(handoff, &resolved, ops, arg,
			    gpa, true);
			if (error != 0 && error != ENOEXEC) {
				goto out;
			}
			if (error == 0)
				revision_valid = true;
		}
		resolved.instruction = vmx_nested_machine_vmxon(&candidate,
		    gpa, address_valid && revision_valid);
		break;
	case VMX_NESTED_INSTRUCTION_VMXOFF:
		resolved.instruction = vmx_nested_machine_vmxoff(&candidate);
		if (resolved.instruction.kind == VMX_NESTED_SUCCEED) {
			if (ops->vmxoff_release == NULL) {
				error = ENOTSUP;
				goto out;
			}
			error = nvmx_ih_access(handoff, &resolved,
			    ops->vmxoff_release(arg),
			    (UINT32_C(1) <<
			    VMX_NESTED_INSTRUCTION_ACCESS_OK) |
			    (UINT32_C(1) <<
			    VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
			    (UINT32_C(1) <<
			    VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
			if (error != 0)
				goto out;
		}
		break;
	case VMX_NESTED_INSTRUCTION_VMCLEAR:
		resolved.instruction = vmx_nested_machine_vmclear(&candidate,
		    gpa, address_valid);
		if (resolved.instruction.kind == VMX_NESTED_SUCCEED) {
			if (ops->vmcs_clear == NULL) {
				error = ENOTSUP;
				goto out;
			}
			error = nvmx_ih_access(handoff, &resolved,
			    ops->vmcs_clear(arg, gpa),
			    (UINT32_C(1) <<
			    VMX_NESTED_INSTRUCTION_ACCESS_OK) |
			    (UINT32_C(1) <<
			    VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
			    (UINT32_C(1) <<
			    VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
			if (error != 0)
				goto out;
		}
		break;
	case VMX_NESTED_INSTRUCTION_VMPTRLD:
		revision_valid = false;
		if (address_valid && gpa != request->machine.vmxon_gpa) {
			error = nvmx_ih_check_region(handoff, &resolved, ops, arg,
			    gpa, false);
			if (error != 0 && error != ENOEXEC) {
				goto out;
			}
			if (error == 0)
				revision_valid = true;
		}
		resolved.instruction = vmx_nested_machine_vmptrld(&candidate,
		    gpa, address_valid, revision_valid);
		break;
	case VMX_NESTED_INSTRUCTION_VMPTRST:
		le64enc(bytes, vmx_nested_machine_vmptrst(&candidate));
		error = nvmx_ih_linear_write(handoff, &resolved, ops, arg,
		    request->linear_address, bytes, sizeof(uint64_t));
		if (error != 0)
			goto out;
		resolved.instruction = (struct vmx_nested_result){
		    VMX_NESTED_SUCCEED, 0 };
		break;
	case VMX_NESTED_INSTRUCTION_VMREAD:
		supported = request->field_encoding <= UINT32_MAX &&
		    vmx_nested_vmcs_field_info((uint32_t)request->field_encoding,
		    &field) == 0 && vmx_nested_vmcs_field_available(
		    &request->capabilities, (uint32_t)request->field_encoding);
		resolved.instruction = vmx_nested_machine_vmread(&candidate,
		    supported);
		if (resolved.instruction.kind != VMX_NESTED_SUCCEED)
			break;
		if (ops->vmcs_read == NULL) {
			error = ENOTSUP;
			goto out;
		}
		access = ops->vmcs_read(arg, candidate.current_vmcs_gpa,
		    (uint32_t)request->field_encoding, &value);
		error = nvmx_ih_access(handoff, &resolved, access,
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
		if (error != 0)
			goto out;
		if (request->operand_size == 4)
			value &= UINT32_MAX;
		if (request->value_in_register) {
			resolved.output_register = true;
			resolved.output_value = value;
			resolved.output_size = request->operand_size;
			resolved.output_register_index =
			    request->register_index;
		} else {
			le64enc(bytes, value);
			error = nvmx_ih_linear_write(handoff, &resolved, ops,
			    arg, request->linear_address, bytes,
			    request->operand_size);
			if (error != 0)
				goto out;
		}
		break;
	case VMX_NESTED_INSTRUCTION_VMWRITE:
		/*
		 * Intel checks for a current VMCS before reading a memory
		 * source, but checks the field encoding after that read.
		 * Preserve that fault priority explicitly.
		 */
		resolved.instruction = vmx_nested_machine_vmwrite(&candidate,
		    true, false);
		if (resolved.instruction.kind != VMX_NESTED_SUCCEED)
			break;
		if (!request->value_in_register) {
			error = nvmx_ih_linear_read(handoff, &resolved, ops, arg,
			    request->linear_address, bytes,
			    request->operand_size);
			if (error != 0)
				goto out;
			value = request->operand_size == 8 ? le64dec(bytes) :
			    le32dec(bytes);
		}
		supported = request->field_encoding <= UINT32_MAX &&
		    vmx_nested_vmcs_field_info((uint32_t)request->field_encoding,
		    &field) == 0 && vmx_nested_vmcs_field_available(
		    &request->capabilities, (uint32_t)request->field_encoding);
		resolved.instruction = vmx_nested_machine_vmwrite(&candidate,
		    supported, supported && field.readonly);
		if (resolved.instruction.kind != VMX_NESTED_SUCCEED)
			break;
		if (field.high_half || field.width == 4)
			value &= UINT32_MAX;
		else if (field.width == 2)
			value &= UINT16_MAX;
		if (ops->vmcs_write == NULL) {
			error = ENOTSUP;
			goto out;
		}
		error = nvmx_ih_access(handoff, &resolved,
		    ops->vmcs_write(arg, candidate.current_vmcs_gpa,
		    (uint32_t)request->field_encoding, value),
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
		if (error != 0)
			goto out;
		break;
	case VMX_NESTED_INSTRUCTION_INVEPT:
		/*
		 * Intel checks the type register before touching the mandatory
		 * 16-byte memory operand, including for all-context INVEPT.
		 */
		if (!vmx_nested_invept_type_valid(&request->capabilities,
		    request->register_value)) {
			resolved.instruction =
			    vmx_nested_machine_invalidation(&candidate, false);
			break;
		}
		error = nvmx_ih_linear_read(handoff, &resolved, ops, arg,
		    request->linear_address, bytes, sizeof(bytes));
		if (error != 0)
			goto out;
		descriptor.context = le64dec(bytes);
		descriptor.address = le64dec(bytes + 8);
		if (vmx_nested_invept_validate(&request->capabilities,
		    request->register_value, &descriptor,
		    &invalidation) != 0) {
			resolved.instruction =
			    vmx_nested_machine_invalidation(&candidate, false);
			break;
		}
		if (ops->invept == NULL) {
			error = ENOTSUP;
			goto out;
		}
		error = nvmx_ih_access(handoff, &resolved,
		    ops->invept(arg, &invalidation),
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
		if (error != 0)
			goto out;
		resolved.instruction =
		    vmx_nested_machine_invalidation(&candidate, true);
		break;
	case VMX_NESTED_INSTRUCTION_INVVPID:
		/*
		 * As with INVEPT, Intel validates the type register before
		 * reading the mandatory 16-byte descriptor.  The callback
		 * receives a virtual invalidation; the runtime owner must map it
		 * to its dedicated effective VPID02 and must never target VPID01.
		 */
		if (!vmx_nested_invvpid_type_valid(&request->capabilities,
		    request->register_value)) {
			resolved.instruction =
			    vmx_nested_machine_invalidation(&candidate, false);
			break;
		}
		error = nvmx_ih_linear_read(handoff, &resolved, ops, arg,
		    request->linear_address, bytes, sizeof(bytes));
		if (error != 0)
			goto out;
		descriptor.context = le64dec(bytes);
		descriptor.address = le64dec(bytes + 8);
		if (vmx_nested_invvpid_validate(&request->capabilities,
		    request->register_value, &descriptor,
		    &invalidation) != 0) {
			resolved.instruction =
			    vmx_nested_machine_invalidation(&candidate, false);
			break;
		}
		if (ops->invvpid == NULL) {
			error = ENOTSUP;
			goto out;
		}
		error = nvmx_ih_access(handoff, &resolved,
		    ops->invvpid(arg, &invalidation),
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
		if (error != 0)
			goto out;
		resolved.instruction =
		    vmx_nested_machine_invalidation(&candidate, true);
		break;
	case VMX_NESTED_INSTRUCTION_VMLAUNCH:
	case VMX_NESTED_INSTRUCTION_VMRESUME:
		if (ops->vmcs_launch_state == NULL) {
			error = ENOTSUP;
			goto out;
		}
		/*
		 * SDM 33.3 (VMLAUNCH/VMRESUME): with no current VMCS the
		 * instruction completes as VMfailInvalid.  The registry has no
		 * entry for the UINT64_MAX sentinel, so consulting the
		 * launch-state callback first would turn this guest-recoverable
		 * case into a host error.  Resolve it from the machine model
		 * alone; the launch/epoch operands are dead in this branch
		 * because the no-current-VMCS check precedes them.
		 */
		if (candidate.current_vmcs_gpa == UINT64_MAX) {
			resolved.instruction = vmx_nested_machine_vmentry(
			    &candidate, request->operation ==
			    VMX_NESTED_INSTRUCTION_VMLAUNCH, false, 0,
			    request->movss_blocked);
			if (resolved.instruction.kind == VMX_NESTED_SUCCEED) {
				error = EPROTO;
				goto out;
			}
			break;
		}
		launched = false;
		launch_epoch = 0;
		error = nvmx_ih_access(handoff, &resolved,
		    ops->vmcs_launch_state(arg, candidate.current_vmcs_gpa,
		    &launched, &launch_epoch),
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_OK) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_RETRY) |
		    (UINT32_C(1) << VMX_NESTED_INSTRUCTION_ACCESS_FATAL));
		if (error != 0)
			goto out;
		resolved.instruction = vmx_nested_machine_vmentry(&candidate,
		    request->operation == VMX_NESTED_INSTRUCTION_VMLAUNCH,
		    launched, launch_epoch, request->movss_blocked);
		if (resolved.instruction.kind != VMX_NESTED_SUCCEED)
			break;
		/*
		 * A successful VM-entry instruction does not architecturally
		 * complete in L1.  Preserve RIP and RFLAGS and transfer the
		 * resolved handoff to the frozen entry owner.
		 */
		resolved.machine = candidate;
		resolved.disposition = VMX_NESTED_INSTRUCTION_ENTRY_READY;
		resolved.rflags = request->rflags;
		resolved.rip_advance = 0;
		handoff->result = resolved;
		handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED;
		error = 0;
		goto finish;
	default:
		error = EPROTO;
		goto out;
	}

	resolved.machine = candidate;
complete:
	resolved.machine = candidate;
	error = nvmx_ih_complete(handoff, &resolved, ops, arg);
	if (error == 0)
		goto finish;

out:
	if (error == EINPROGRESS)
		error = 0;
	if (error != 0) {
		if (handoff->state != VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING)
			error = EPROTO;
		else
			handoff->state = VMX_NESTED_INSTRUCTION_HANDOFF_PENDING;
	}
finish:
	if (!nvmx_ih_handoff_equal(owner, &owner_before)) {
		*owner = owner_before;
		return (EPROTO);
	}
	*owner = working;
	return (error);
}

int
vmx_nested_instruction_handoff_take(
    struct vmx_nested_instruction_handoff *handoff,
    const struct vmx_nested_instruction_handoff_id *id,
    struct vmx_nested_instruction_handoff_result *result)
{
	struct vmx_nested_instruction_handoff_result candidate;

	if (handoff == NULL || !nvmx_ih_id_valid(id) || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), handoff,
	    sizeof(*handoff)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), id,
	    sizeof(*id)))
		return (EINVAL);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_IDLE)
		return (ENOENT);
	if (!nvmx_ih_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state != VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED)
		return (EAGAIN);
	candidate = handoff->result;
	vmx_nested_instruction_handoff_init(handoff);
	*result = candidate;
	return (0);
}

int
vmx_nested_instruction_handoff_cancel(
    struct vmx_nested_instruction_handoff *handoff,
    const struct vmx_nested_instruction_handoff_id *id)
{

	if (handoff == NULL || !nvmx_ih_id_valid(id))
		return (EINVAL);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_IDLE)
		return (ENOENT);
	if (!nvmx_ih_id_equal(&handoff->request.id, id))
		return (ESTALE);
	if (handoff->state == VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING)
		return (EBUSY);
	vmx_nested_instruction_handoff_init(handoff);
	return (0);
}
