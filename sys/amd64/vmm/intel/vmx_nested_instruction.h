/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INSTRUCTION_H_
#define	_VMM_INTEL_VMX_NESTED_INSTRUCTION_H_

#include "vmx_nested_types.h"

enum vmx_nested_result_kind {
	VMX_NESTED_SUCCEED = 0,
	VMX_NESTED_FAIL_INVALID,
	VMX_NESTED_FAIL_VALID,
};

struct vmx_nested_result {
	enum vmx_nested_result_kind kind;
	uint32_t instruction_error;
};

struct vmx_nested_machine {
	bool vmxon;
	uint64_t vmxon_gpa;
	uint64_t current_vmcs_gpa;
	uint64_t epoch;
};

/*
 * Exception, privilege, mode, and guest-memory-fault checks precede these
 * architectural transitions.  A caller performs VMCS-region mutations before
 * committing a successful transition that depends on such a mutation.
 */
void	vmx_nested_machine_init(struct vmx_nested_machine *);
struct vmx_nested_result vmx_nested_machine_vmxon(
	    struct vmx_nested_machine *, uint64_t, bool);
struct vmx_nested_result vmx_nested_machine_vmxoff(
	    struct vmx_nested_machine *);
struct vmx_nested_result vmx_nested_machine_vmclear(
	    struct vmx_nested_machine *, uint64_t, bool);
struct vmx_nested_result vmx_nested_machine_vmptrld(
	    struct vmx_nested_machine *, uint64_t, bool, bool);
uint64_t vmx_nested_machine_vmptrst(const struct vmx_nested_machine *);
struct vmx_nested_result vmx_nested_machine_vmread(
	    const struct vmx_nested_machine *, bool);
struct vmx_nested_result vmx_nested_machine_vmwrite(
	    const struct vmx_nested_machine *, bool, bool);
struct vmx_nested_result vmx_nested_machine_invalidation(
	    const struct vmx_nested_machine *, bool);
struct vmx_nested_result vmx_nested_machine_vmentry(
	    const struct vmx_nested_machine *, bool, bool, uint64_t, bool);
uint64_t vmx_nested_result_rflags(struct vmx_nested_result, uint64_t);

#endif /* _VMM_INTEL_VMX_NESTED_INSTRUCTION_H_ */
