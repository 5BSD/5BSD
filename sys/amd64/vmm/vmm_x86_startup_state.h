/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_X86_STARTUP_STATE_H_
#define	_AMD64_VMM_VMM_X86_STARTUP_STATE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

/*
 * Pointer-free architectural value plans for x86 INIT and SIPI.
 *
 * These structures are transient kernel-private values.  They are neither a
 * save-state format nor a userspace ABI.  INIT deliberately describes only
 * architecturally changed state represented by the VMM.  In particular, an
 * adapter must not use it to reset x87, vector, performance-monitoring, or
 * other state which Intel defines as unchanged by INIT.  LAPIC reset and the
 * wait-for-SIPI run-state transition are separate common-VMM operations.
 */

enum vmm_x86_startup_gpr {
	VMM_X86_STARTUP_RAX = 0,
	VMM_X86_STARTUP_RBX,
	VMM_X86_STARTUP_RCX,
	VMM_X86_STARTUP_RDX,
	VMM_X86_STARTUP_RSI,
	VMM_X86_STARTUP_RDI,
	VMM_X86_STARTUP_RBP,
	VMM_X86_STARTUP_RSP,
	VMM_X86_STARTUP_R8,
	VMM_X86_STARTUP_R9,
	VMM_X86_STARTUP_R10,
	VMM_X86_STARTUP_R11,
	VMM_X86_STARTUP_R12,
	VMM_X86_STARTUP_R13,
	VMM_X86_STARTUP_R14,
	VMM_X86_STARTUP_R15,
	VMM_X86_STARTUP_GPR_COUNT,
};

enum vmm_x86_startup_segment {
	VMM_X86_STARTUP_CS = 0,
	VMM_X86_STARTUP_SS,
	VMM_X86_STARTUP_DS,
	VMM_X86_STARTUP_ES,
	VMM_X86_STARTUP_FS,
	VMM_X86_STARTUP_GS,
	VMM_X86_STARTUP_TR,
	VMM_X86_STARTUP_LDTR,
	VMM_X86_STARTUP_SEGMENT_COUNT,
};

struct vmm_x86_startup_desc {
	uint64_t base;
	uint32_t limit;
	uint32_t access;
	uint16_t selector;
	uint16_t reserved16;
	uint32_t reserved32;
};

struct vmm_x86_init_state_plan {
	uint64_t rflags;
	uint64_t rip;
	uint64_t cr0;
	uint64_t cr2;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t efer;
	uint64_t gpr[VMM_X86_STARTUP_GPR_COUNT];
	struct vmm_x86_startup_desc segment[VMM_X86_STARTUP_SEGMENT_COUNT];
	struct vmm_x86_startup_desc gdtr;
	struct vmm_x86_startup_desc idtr;
	uint64_t dr[4];
	uint64_t dr6;
	uint64_t dr7;
	uint64_t interrupt_shadow;
};

struct vmm_x86_sipi_state_plan {
	uint64_t rip;
	struct vmm_x86_startup_desc cs;
};

int	vmm_x86_init_state_plan(uint64_t, uint32_t,
	    struct vmm_x86_init_state_plan *);
int	vmm_x86_sipi_state_plan(uint32_t,
	    struct vmm_x86_sipi_state_plan *);
int	vmm_x86_startup_apicbase_classify(uint64_t, bool *);

#endif /* _AMD64_VMM_VMM_X86_STARTUP_STATE_H_ */
