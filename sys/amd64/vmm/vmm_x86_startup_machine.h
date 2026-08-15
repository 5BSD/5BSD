/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_X86_STARTUP_MACHINE_H_
#define	_AMD64_VMM_VMM_X86_STARTUP_MACHINE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

#include "vmm_event_state.h"
#include "vmm_x86_startup_finalizer.h"
#include "vmm_x86_startup_state.h"
#include "vmm_x86_startup_transaction.h"

/*
 * Architecture-shared names for the state changed by x86 INIT.  These are
 * transient adapter identifiers, not VM_REG_* values, a save-state format,
 * or a stable KPI.  Intel and AMD adapters translate them explicitly.
 */
enum vmm_x86_startup_register {
	VMM_X86_STARTUP_REG_RFLAGS = 0,
	VMM_X86_STARTUP_REG_RIP,
	VMM_X86_STARTUP_REG_CR0,
	VMM_X86_STARTUP_REG_CR2,
	VMM_X86_STARTUP_REG_CR3,
	VMM_X86_STARTUP_REG_CR4,
	VMM_X86_STARTUP_REG_EFER,
	VMM_X86_STARTUP_REG_RAX,
	VMM_X86_STARTUP_REG_RBX,
	VMM_X86_STARTUP_REG_RCX,
	VMM_X86_STARTUP_REG_RDX,
	VMM_X86_STARTUP_REG_RSI,
	VMM_X86_STARTUP_REG_RDI,
	VMM_X86_STARTUP_REG_RBP,
	VMM_X86_STARTUP_REG_RSP,
	VMM_X86_STARTUP_REG_R8,
	VMM_X86_STARTUP_REG_R9,
	VMM_X86_STARTUP_REG_R10,
	VMM_X86_STARTUP_REG_R11,
	VMM_X86_STARTUP_REG_R12,
	VMM_X86_STARTUP_REG_R13,
	VMM_X86_STARTUP_REG_R14,
	VMM_X86_STARTUP_REG_R15,
	VMM_X86_STARTUP_REG_DR0,
	VMM_X86_STARTUP_REG_DR1,
	VMM_X86_STARTUP_REG_DR2,
	VMM_X86_STARTUP_REG_DR3,
	VMM_X86_STARTUP_REG_DR6,
	VMM_X86_STARTUP_REG_DR7,
	VMM_X86_STARTUP_REG_INTR_SHADOW,
	VMM_X86_STARTUP_REG_COUNT,
};

enum vmm_x86_startup_descriptor {
	VMM_X86_STARTUP_DESC_CS = 0,
	VMM_X86_STARTUP_DESC_SS,
	VMM_X86_STARTUP_DESC_DS,
	VMM_X86_STARTUP_DESC_ES,
	VMM_X86_STARTUP_DESC_FS,
	VMM_X86_STARTUP_DESC_GS,
	VMM_X86_STARTUP_DESC_TR,
	VMM_X86_STARTUP_DESC_LDTR,
	VMM_X86_STARTUP_DESC_GDTR,
	VMM_X86_STARTUP_DESC_IDTR,
	VMM_X86_STARTUP_DESC_COUNT,
};

struct vmm_x86_startup_machine_ops {
	/* A nonzero getter or setter result promises no mutation. */
	int	(*getreg)(void *, enum vmm_x86_startup_register, uint64_t *);
	int	(*setreg)(void *, enum vmm_x86_startup_register, uint64_t);
	int	(*getdesc)(void *, enum vmm_x86_startup_descriptor,
	    struct vmm_x86_startup_desc *);
	/* Selector and descriptor-cache publication are one atomic operation. */
	int	(*setdesc)(void *, enum vmm_x86_startup_descriptor,
	    const struct vmm_x86_startup_desc *);
	/* INIT-only exact pending-event capture and compare-clear. */
	int	(*event_capture)(void *, struct vmm_event_state *);
	int	(*event_compare_clear)(void *, const struct vmm_event_state *);
};

int	vmm_x86_startup_machine_execute(
	    const struct vmm_x86_startup_transaction_input *, uint32_t,
	    const struct vmm_x86_startup_machine_ops *, void *,
	    struct vmm_x86_startup_finalizer *,
	    struct vmm_x86_startup_transaction_result *);

#endif /* _AMD64_VMM_VMM_X86_STARTUP_MACHINE_H_ */
