/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_instruction.h"

#define	NVMX_RFLAGS_CF		(UINT64_C(1) << 0)
#define	NVMX_RFLAGS_PF		(UINT64_C(1) << 2)
#define	NVMX_RFLAGS_AF		(UINT64_C(1) << 4)
#define	NVMX_RFLAGS_ZF		(UINT64_C(1) << 6)
#define	NVMX_RFLAGS_SF		(UINT64_C(1) << 7)
#define	NVMX_RFLAGS_OF		(UINT64_C(1) << 11)
#define	NVMX_RFLAGS_RESULT_MASK	(NVMX_RFLAGS_CF | NVMX_RFLAGS_PF | \
	    NVMX_RFLAGS_AF | NVMX_RFLAGS_ZF | NVMX_RFLAGS_SF | NVMX_RFLAGS_OF)

static struct vmx_nested_result
nvmx_succeed(void)
{

	return ((struct vmx_nested_result){ VMX_NESTED_SUCCEED, 0 });
}

static struct vmx_nested_result
nvmx_fail(const struct vmx_nested_machine *machine, uint32_t error)
{

	if (machine->current_vmcs_gpa == UINT64_MAX)
		return ((struct vmx_nested_result){
		    VMX_NESTED_FAIL_INVALID, 0 });
	return ((struct vmx_nested_result){ VMX_NESTED_FAIL_VALID, error });
}

void
vmx_nested_machine_init(struct vmx_nested_machine *machine)
{

	memset(machine, 0, sizeof(*machine));
	machine->vmxon_gpa = UINT64_MAX;
	machine->current_vmcs_gpa = UINT64_MAX;
}

struct vmx_nested_result
vmx_nested_machine_vmxon(struct vmx_nested_machine *machine, uint64_t gpa,
    bool operand_valid)
{

	if (machine->vmxon)
		return (nvmx_fail(machine, 15));
	if (!operand_valid)
		return ((struct vmx_nested_result){
		    VMX_NESTED_FAIL_INVALID, 0 });
	/* Never recycle a VMXON-session identity used by launched VMCS state. */
	if (machine->epoch == UINT64_MAX)
		return ((struct vmx_nested_result){
		    VMX_NESTED_FAIL_INVALID, 0 });
	machine->epoch++;
	machine->vmxon = true;
	machine->vmxon_gpa = gpa;
	machine->current_vmcs_gpa = UINT64_MAX;
	return (nvmx_succeed());
}

struct vmx_nested_result
vmx_nested_machine_vmxoff(struct vmx_nested_machine *machine)
{

	machine->vmxon = false;
	machine->vmxon_gpa = UINT64_MAX;
	machine->current_vmcs_gpa = UINT64_MAX;
	return (nvmx_succeed());
}

struct vmx_nested_result
vmx_nested_machine_vmclear(struct vmx_nested_machine *machine, uint64_t gpa,
    bool address_valid)
{

	if (!address_valid)
		return (nvmx_fail(machine, 2));
	if (gpa == machine->vmxon_gpa)
		return (nvmx_fail(machine, 3));
	if (gpa == machine->current_vmcs_gpa)
		machine->current_vmcs_gpa = UINT64_MAX;
	return (nvmx_succeed());
}

struct vmx_nested_result
vmx_nested_machine_vmptrld(struct vmx_nested_machine *machine, uint64_t gpa,
    bool address_valid, bool revision_valid)
{

	if (!address_valid)
		return (nvmx_fail(machine, 9));
	if (gpa == machine->vmxon_gpa)
		return (nvmx_fail(machine, 10));
	if (!revision_valid)
		return (nvmx_fail(machine, 11));
	machine->current_vmcs_gpa = gpa;
	return (nvmx_succeed());
}

uint64_t
vmx_nested_machine_vmptrst(const struct vmx_nested_machine *machine)
{

	return (machine->current_vmcs_gpa);
}

struct vmx_nested_result
vmx_nested_machine_vmread(const struct vmx_nested_machine *machine,
    bool supported)
{

	if (machine->current_vmcs_gpa == UINT64_MAX)
		return ((struct vmx_nested_result){
		    VMX_NESTED_FAIL_INVALID, 0 });
	if (!supported)
		return (nvmx_fail(machine, 12));
	return (nvmx_succeed());
}

struct vmx_nested_result
vmx_nested_machine_vmwrite(const struct vmx_nested_machine *machine,
    bool supported, bool readonly)
{

	if (machine->current_vmcs_gpa == UINT64_MAX)
		return ((struct vmx_nested_result){
		    VMX_NESTED_FAIL_INVALID, 0 });
	if (!supported)
		return (nvmx_fail(machine, 12));
	if (readonly)
		return (nvmx_fail(machine, 13));
	return (nvmx_succeed());
}

struct vmx_nested_result
vmx_nested_machine_invalidation(const struct vmx_nested_machine *machine,
    bool operand_valid)
{

	if (!operand_valid)
		return (nvmx_fail(machine, 28));
	return (nvmx_succeed());
}

struct vmx_nested_result
vmx_nested_machine_vmentry(const struct vmx_nested_machine *machine,
    bool launch, bool launched, uint64_t launch_epoch, bool movss_blocked)
{

	if (machine->current_vmcs_gpa == UINT64_MAX)
		return ((struct vmx_nested_result){
		    VMX_NESTED_FAIL_INVALID, 0 });
	if (movss_blocked)
		return (nvmx_fail(machine, 26));
	if (launch && launched)
		return (nvmx_fail(machine, 4));
	if (!launch && !launched)
		return (nvmx_fail(machine, 5));
	if (!launch && launch_epoch != machine->epoch)
		return (nvmx_fail(machine, 6));
	return (nvmx_succeed());
}

uint64_t
vmx_nested_result_rflags(struct vmx_nested_result result, uint64_t rflags)
{

	rflags &= ~NVMX_RFLAGS_RESULT_MASK;
	if (result.kind == VMX_NESTED_FAIL_INVALID)
		rflags |= NVMX_RFLAGS_CF;
	else if (result.kind == VMX_NESTED_FAIL_VALID)
		rflags |= NVMX_RFLAGS_ZF;
	return (rflags);
}
