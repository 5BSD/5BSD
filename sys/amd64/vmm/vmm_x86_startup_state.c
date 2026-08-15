/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmm_x86_startup_state.h"

#define	X86_CR0_ET	UINT64_C(0x00000010)
#define	X86_CR0_NW	UINT64_C(0x20000000)
#define	X86_CR0_CD	UINT64_C(0x40000000)
#define	X86_CR0_VALID	UINT64_C(0xffffffff)
#define	X86_APICBASE_BSP	UINT64_C(0x00000100)

#define	X86_RESET_DATA_ACCESS	UINT32_C(0x0093)
#define	X86_RESET_TR_ACCESS	UINT32_C(0x008b)
#define	X86_RESET_LDTR_ACCESS	UINT32_C(0x0082)

static void
vmm_x86_startup_desc_set(struct vmm_x86_startup_desc *desc, uint16_t selector,
    uint64_t base, uint32_t limit, uint32_t access)
{

	desc->selector = selector;
	desc->base = base;
	desc->limit = limit;
	desc->access = access;
}

int
vmm_x86_startup_apicbase_classify(uint64_t apicbase,
    bool *bootstrap_processor)
{
	bool candidate;

	if (bootstrap_processor == NULL)
		return (EINVAL);
	candidate = (apicbase & X86_APICBASE_BSP) != 0;
	*bootstrap_processor = candidate;
	return (0);
}

int
vmm_x86_init_state_plan(uint64_t current_cr0, uint32_t processor_signature,
    struct vmm_x86_init_state_plan *plan)
{
	struct vmm_x86_init_state_plan candidate;
	unsigned int i;

	if (plan == NULL || (current_cr0 & ~X86_CR0_VALID) != 0)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.rflags = UINT64_C(0x2);
	candidate.rip = UINT64_C(0xfff0);
	/* Intel preserves CD and NW across INIT, sets ET, and clears the rest. */
	candidate.cr0 = (current_cr0 & (X86_CR0_CD | X86_CR0_NW)) |
	    X86_CR0_ET;
	candidate.gpr[VMM_X86_STARTUP_RDX] = processor_signature;

	vmm_x86_startup_desc_set(&candidate.segment[VMM_X86_STARTUP_CS],
	    UINT16_C(0xf000), UINT64_C(0xffff0000), UINT32_C(0xffff),
	    X86_RESET_DATA_ACCESS);
	for (i = VMM_X86_STARTUP_SS; i <= VMM_X86_STARTUP_GS; i++)
		vmm_x86_startup_desc_set(&candidate.segment[i], 0, 0,
		    UINT32_C(0xffff), X86_RESET_DATA_ACCESS);
	vmm_x86_startup_desc_set(&candidate.segment[VMM_X86_STARTUP_TR], 0, 0,
	    UINT32_C(0xffff), X86_RESET_TR_ACCESS);
	vmm_x86_startup_desc_set(&candidate.segment[VMM_X86_STARTUP_LDTR], 0, 0,
	    UINT32_C(0xffff), X86_RESET_LDTR_ACCESS);
	vmm_x86_startup_desc_set(&candidate.gdtr, 0, 0, UINT32_C(0xffff), 0);
	vmm_x86_startup_desc_set(&candidate.idtr, 0, 0, UINT32_C(0xffff), 0);
	candidate.dr6 = UINT64_C(0xffff0ff0);
	candidate.dr7 = UINT64_C(0x400);

	*plan = candidate;
	return (0);
}

int
vmm_x86_sipi_state_plan(uint32_t vector, struct vmm_x86_sipi_state_plan *plan)
{
	struct vmm_x86_sipi_state_plan candidate;

	if (plan == NULL || vector > UINT8_MAX)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	vmm_x86_startup_desc_set(&candidate.cs, (uint16_t)(vector << 8),
	    (uint64_t)vector << 12, UINT32_C(0xffff), X86_RESET_DATA_ACCESS);
	*plan = candidate;
	return (0);
}
