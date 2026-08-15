/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>

#include "vmm_x86_startup_vmreg.h"

int
vmm_x86_startup_register_vmreg(enum vmm_x86_startup_register source,
    enum vm_reg_name *destination)
{
	enum vm_reg_name candidate;

	if (destination == NULL)
		return (EINVAL);
	switch (source) {
	case VMM_X86_STARTUP_REG_RFLAGS:
		candidate = VM_REG_GUEST_RFLAGS;
		break;
	case VMM_X86_STARTUP_REG_RIP:
		candidate = VM_REG_GUEST_RIP;
		break;
	case VMM_X86_STARTUP_REG_CR0:
		candidate = VM_REG_GUEST_CR0;
		break;
	case VMM_X86_STARTUP_REG_CR2:
		candidate = VM_REG_GUEST_CR2;
		break;
	case VMM_X86_STARTUP_REG_CR3:
		candidate = VM_REG_GUEST_CR3;
		break;
	case VMM_X86_STARTUP_REG_CR4:
		candidate = VM_REG_GUEST_CR4;
		break;
	case VMM_X86_STARTUP_REG_EFER:
		candidate = VM_REG_GUEST_EFER;
		break;
	case VMM_X86_STARTUP_REG_RAX:
		candidate = VM_REG_GUEST_RAX;
		break;
	case VMM_X86_STARTUP_REG_RBX:
		candidate = VM_REG_GUEST_RBX;
		break;
	case VMM_X86_STARTUP_REG_RCX:
		candidate = VM_REG_GUEST_RCX;
		break;
	case VMM_X86_STARTUP_REG_RDX:
		candidate = VM_REG_GUEST_RDX;
		break;
	case VMM_X86_STARTUP_REG_RSI:
		candidate = VM_REG_GUEST_RSI;
		break;
	case VMM_X86_STARTUP_REG_RDI:
		candidate = VM_REG_GUEST_RDI;
		break;
	case VMM_X86_STARTUP_REG_RBP:
		candidate = VM_REG_GUEST_RBP;
		break;
	case VMM_X86_STARTUP_REG_RSP:
		candidate = VM_REG_GUEST_RSP;
		break;
	case VMM_X86_STARTUP_REG_R8:
		candidate = VM_REG_GUEST_R8;
		break;
	case VMM_X86_STARTUP_REG_R9:
		candidate = VM_REG_GUEST_R9;
		break;
	case VMM_X86_STARTUP_REG_R10:
		candidate = VM_REG_GUEST_R10;
		break;
	case VMM_X86_STARTUP_REG_R11:
		candidate = VM_REG_GUEST_R11;
		break;
	case VMM_X86_STARTUP_REG_R12:
		candidate = VM_REG_GUEST_R12;
		break;
	case VMM_X86_STARTUP_REG_R13:
		candidate = VM_REG_GUEST_R13;
		break;
	case VMM_X86_STARTUP_REG_R14:
		candidate = VM_REG_GUEST_R14;
		break;
	case VMM_X86_STARTUP_REG_R15:
		candidate = VM_REG_GUEST_R15;
		break;
	case VMM_X86_STARTUP_REG_DR0:
		candidate = VM_REG_GUEST_DR0;
		break;
	case VMM_X86_STARTUP_REG_DR1:
		candidate = VM_REG_GUEST_DR1;
		break;
	case VMM_X86_STARTUP_REG_DR2:
		candidate = VM_REG_GUEST_DR2;
		break;
	case VMM_X86_STARTUP_REG_DR3:
		candidate = VM_REG_GUEST_DR3;
		break;
	case VMM_X86_STARTUP_REG_DR6:
		candidate = VM_REG_GUEST_DR6;
		break;
	case VMM_X86_STARTUP_REG_DR7:
		candidate = VM_REG_GUEST_DR7;
		break;
	case VMM_X86_STARTUP_REG_INTR_SHADOW:
		candidate = VM_REG_GUEST_INTR_SHADOW;
		break;
	default:
		return (EINVAL);
	}
	*destination = candidate;
	return (0);
}

int
vmm_x86_startup_descriptor_vmreg(enum vmm_x86_startup_descriptor source,
    enum vm_reg_name *destination)
{
	enum vm_reg_name candidate;

	if (destination == NULL)
		return (EINVAL);
	switch (source) {
	case VMM_X86_STARTUP_DESC_CS:
		candidate = VM_REG_GUEST_CS;
		break;
	case VMM_X86_STARTUP_DESC_SS:
		candidate = VM_REG_GUEST_SS;
		break;
	case VMM_X86_STARTUP_DESC_DS:
		candidate = VM_REG_GUEST_DS;
		break;
	case VMM_X86_STARTUP_DESC_ES:
		candidate = VM_REG_GUEST_ES;
		break;
	case VMM_X86_STARTUP_DESC_FS:
		candidate = VM_REG_GUEST_FS;
		break;
	case VMM_X86_STARTUP_DESC_GS:
		candidate = VM_REG_GUEST_GS;
		break;
	case VMM_X86_STARTUP_DESC_TR:
		candidate = VM_REG_GUEST_TR;
		break;
	case VMM_X86_STARTUP_DESC_LDTR:
		candidate = VM_REG_GUEST_LDTR;
		break;
	case VMM_X86_STARTUP_DESC_GDTR:
		candidate = VM_REG_GUEST_GDTR;
		break;
	case VMM_X86_STARTUP_DESC_IDTR:
		candidate = VM_REG_GUEST_IDTR;
		break;
	default:
		return (EINVAL);
	}
	*destination = candidate;
	return (0);
}
