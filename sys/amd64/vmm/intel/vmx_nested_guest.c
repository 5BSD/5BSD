/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_guest.h"
#include "vmx_nested_validate.h"

#define	NVMX_PRIMARY_SECONDARY		(UINT32_C(1) << 31)
#define	NVMX_PIN_VIRTUAL_NMIS		(UINT32_C(1) << 5)
#define	NVMX_SECONDARY_UNRESTRICTED	(UINT32_C(1) << 7)

#define	NVMX_ENTRY_LOAD_DEBUG		(UINT32_C(1) << 2)
#define	NVMX_ENTRY_GUEST_LMA		(UINT32_C(1) << 9)
#define	NVMX_ENTRY_LOAD_PAT		(UINT32_C(1) << 14)
#define	NVMX_ENTRY_LOAD_EFER		(UINT32_C(1) << 15)
#define	NVMX_ENTRY_SMM			(UINT32_C(1) << 10)

#define	NVMX_RFLAGS_IF			(UINT64_C(1) << 9)
#define	NVMX_RFLAGS_TF			(UINT64_C(1) << 8)
#define	NVMX_RFLAGS_VM			(UINT64_C(1) << 17)

#define	NVMX_PENDING_DEBUG_ENABLED_BP	(UINT64_C(1) << 12)
#define	NVMX_PENDING_DEBUG_BS		(UINT64_C(1) << 14)
#define	NVMX_PENDING_DEBUG_RTM		(UINT64_C(1) << 16)
#define	NVMX_PENDING_DEBUG_RESERVED	UINT64_C(0xfffffffffffeaff0)

#define	NVMX_GUEST_INTR_VALID			(UINT32_C(1) << 31)
#define	NVMX_GUEST_INTR_TYPE_MASK		(UINT32_C(7) << 8)
#define	NVMX_GUEST_INTR_EXTERNAL		(UINT32_C(0) << 8)
#define	NVMX_GUEST_INTR_NMI			(UINT32_C(2) << 8)
#define	NVMX_GUEST_INTR_HARD_EXCEPTION		(UINT32_C(3) << 8)
#define	NVMX_GUEST_INTR_OTHER			(UINT32_C(7) << 8)

#define	NVMX_SEG_TYPE_MASK		0x0000000fU
#define	NVMX_SEG_S			0x00000010U
#define	NVMX_SEG_DPL_MASK		0x00000060U
#define	NVMX_SEG_PRESENT			0x00000080U
#define	NVMX_SEG_L			0x00002000U
#define	NVMX_SEG_DB			0x00004000U
#define	NVMX_SEG_GRANULAR		0x00008000U
#define	NVMX_SEG_UNUSABLE		0x00010000U
#define	NVMX_SEG_RESERVED		0xfffe0f00U

#define	NVMX_CR0_PE			(UINT64_C(1) << 0)
#define	NVMX_CR0_NW			(UINT64_C(1) << 29)
#define	NVMX_CR0_CD			(UINT64_C(1) << 30)
#define	NVMX_CR0_PG			(UINT64_C(1) << 31)
#define	NVMX_CR4_PAE			(UINT64_C(1) << 5)
#define	NVMX_CR4_PCIDE			(UINT64_C(1) << 17)

#define	NVMX_EFER_SCE			(UINT64_C(1) << 0)
#define	NVMX_EFER_LME			(UINT64_C(1) << 8)
#define	NVMX_EFER_LMA			(UINT64_C(1) << 10)
#define	NVMX_EFER_NXE			(UINT64_C(1) << 11)
#define	NVMX_EFER_VALID			(NVMX_EFER_SCE | NVMX_EFER_LME | \
	    NVMX_EFER_LMA | NVMX_EFER_NXE)

static int
nvmx_guest_fail(enum vmx_nested_guest_control_failure failure,
    enum vmx_nested_guest_control_failure *reported)
{

	if (reported != NULL)
		*reported = failure;
	return (EINVAL);
}

static int
nvmx_guest_arch_fail(enum vmx_nested_guest_arch_failure failure,
    enum vmx_nested_guest_arch_failure *reported)
{

	if (reported != NULL)
		*reported = failure;
	return (EINVAL);
}

static bool
nvmx_segment_limit_valid(const struct vmx_nested_guest_segment *segment)
{

	if ((segment->limit & 0xfffU) != 0xfffU &&
	    (segment->access & NVMX_SEG_GRANULAR) != 0)
		return (false);
	if ((segment->limit & 0xfff00000U) != 0 &&
	    (segment->access & NVMX_SEG_GRANULAR) == 0)
		return (false);
	return (true);
}

static bool
nvmx_segment_access_common(const struct vmx_nested_guest_segment *segment)
{

	return ((segment->access & (NVMX_SEG_S | NVMX_SEG_PRESENT)) ==
	    (NVMX_SEG_S | NVMX_SEG_PRESENT) &&
	    (segment->access & NVMX_SEG_RESERVED) == 0);
}

static bool
nvmx_event_allowed_while_inactive(uint32_t activity, uint32_t intr_info)
{
	uint32_t type, vector;

	if ((intr_info & NVMX_GUEST_INTR_VALID) == 0)
		return (true);
	type = intr_info & NVMX_GUEST_INTR_TYPE_MASK;
	vector = intr_info & 0xff;
	switch (activity) {
	case 0:		/* active */
		return (true);
	case 1:		/* HLT */
		return (type == NVMX_GUEST_INTR_EXTERNAL || type == NVMX_GUEST_INTR_NMI ||
		    (type == NVMX_GUEST_INTR_HARD_EXCEPTION &&
		    (vector == 1 || vector == 18)) ||
		    (type == NVMX_GUEST_INTR_OTHER && vector == 0));
	case 2:		/* shutdown */
		return (type == NVMX_GUEST_INTR_NMI ||
		    (type == NVMX_GUEST_INTR_HARD_EXCEPTION && vector == 18));
	case 3:		/* wait-for-SIPI */
	default:
		return (false);
	}
}

int
vmx_nested_guest_control_state_validate(
    const struct vmx_nested_capabilities *capabilities, uint32_t primary,
    uint32_t secondary, uint32_t vmentry,
    const struct vmx_nested_guest_control_state *guest,
    enum vmx_nested_guest_control_failure *failure)
{
	uint64_t cr0_ignored;
	bool guest_lma, unrestricted;

	if (failure != NULL)
		*failure = VMX_NESTED_GUEST_CONTROL_OK;
	if (vmx_nested_capabilities_validate(capabilities) != 0 || guest == NULL)
		return (EINVAL);
	if ((primary & NVMX_PRIMARY_SECONDARY) == 0)
		secondary = 0;
	unrestricted = (secondary & NVMX_SECONDARY_UNRESTRICTED) != 0;
	cr0_ignored = NVMX_CR0_NW | NVMX_CR0_CD;
	if (unrestricted)
		cr0_ignored |= NVMX_CR0_PE | NVMX_CR0_PG;
	if (!vmx_nested_fixed_bits_valid(guest->cr0,
	    capabilities->cr0_fixed0, capabilities->cr0_fixed1, cr0_ignored) ||
	    ((guest->cr0 & NVMX_CR0_PG) != 0 &&
	    (guest->cr0 & NVMX_CR0_PE) == 0))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_CR0, failure));
	if (!vmx_nested_physical_range_valid(capabilities, guest->cr3, 1, 1))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_CR3, failure));
	if (!vmx_nested_fixed_bits_valid(guest->cr4,
	    capabilities->cr4_fixed0, capabilities->cr4_fixed1, 0))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_CR4, failure));
	if ((vmentry & NVMX_ENTRY_LOAD_DEBUG) != 0 &&
	    (guest->dr7 >> 32) != 0)
		return (nvmx_guest_fail(VMX_NESTED_GUEST_DEBUG, failure));
	if (!vmx_nested_canonical_address(guest->sysenter_esp,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(guest->sysenter_eip,
	    capabilities->linear_address_width))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_SYSENTER, failure));
	if ((vmentry & NVMX_ENTRY_LOAD_PAT) != 0 &&
	    !vmx_nested_pat_valid(guest->pat))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_PAT, failure));
	guest_lma = (vmentry & NVMX_ENTRY_GUEST_LMA) != 0;
	if ((vmentry & NVMX_ENTRY_LOAD_EFER) != 0 &&
	    ((guest->efer & ~NVMX_EFER_VALID) != 0 ||
	    ((guest->efer & NVMX_EFER_LMA) != 0) != guest_lma ||
	    ((guest->cr0 & NVMX_CR0_PG) != 0 &&
	    ((guest->efer & NVMX_EFER_LME) != 0) != guest_lma)))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_EFER, failure));
	if ((guest_lma && ((guest->cr0 & NVMX_CR0_PG) == 0 ||
	    (guest->cr4 & NVMX_CR4_PAE) == 0)) ||
	    (!guest_lma && (guest->cr4 & NVMX_CR4_PCIDE) != 0))
		return (nvmx_guest_fail(VMX_NESTED_GUEST_ADDRESS_SPACE,
		    failure));
	return (0);
}

int
vmx_nested_guest_arch_state_validate(
    const struct vmx_nested_capabilities *capabilities, uint32_t pinbased,
    uint32_t primary, uint32_t secondary, uint32_t vmentry,
    uint32_t entry_intr_info,
    const struct vmx_nested_guest_control_state *control,
    const struct vmx_nested_guest_arch_state *guest,
    enum vmx_nested_guest_arch_failure *failure)
{
	const struct vmx_nested_guest_segment *cs, *ss, *segment;
	uint32_t cs_type, event_type, ss_dpl;
	bool guest_lma, unrestricted, virtual8086;

	if (failure != NULL)
		*failure = VMX_NESTED_GUEST_ARCH_OK;
	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    control == NULL || guest == NULL)
		return (nvmx_guest_arch_fail(
		    VMX_NESTED_GUEST_ARCH_PREREQUISITE, failure));
	if ((primary & NVMX_PRIMARY_SECONDARY) == 0)
		secondary = 0;
	if ((vmentry & NVMX_ENTRY_LOAD_DEBUG) != 0 &&
	    (guest->debugctl & ~capabilities->debugctl_allowed) != 0)
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_DEBUGCTL,
		    failure));
	unrestricted = (secondary & NVMX_SECONDARY_UNRESTRICTED) != 0;
	guest_lma = (vmentry & NVMX_ENTRY_GUEST_LMA) != 0;
	virtual8086 = (guest->rflags & NVMX_RFLAGS_VM) != 0;
	cs = &guest->segment[VMX_NESTED_GUEST_CS];
	ss = &guest->segment[VMX_NESTED_GUEST_SS];
	cs_type = cs->access & NVMX_SEG_TYPE_MASK;
	ss_dpl = (ss->access & NVMX_SEG_DPL_MASK) >> 5;

	if ((guest->segment[VMX_NESTED_GUEST_TR].selector & 4) != 0 ||
	    (((guest->segment[VMX_NESTED_GUEST_LDTR].access &
	    NVMX_SEG_UNUSABLE) == 0) &&
	    (guest->segment[VMX_NESTED_GUEST_LDTR].selector & 4) != 0) ||
	    (!virtual8086 && !unrestricted &&
	    (ss->selector & 3) != (cs->selector & 3)))
		return (nvmx_guest_arch_fail(
		    VMX_NESTED_GUEST_SEGMENT_SELECTOR, failure));

	for (unsigned int i = VMX_NESTED_GUEST_ES;
	    i <= VMX_NESTED_GUEST_GS; i++) {
		segment = &guest->segment[i];
		if (virtual8086 && segment->base !=
		    (uint64_t)segment->selector << 4)
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_BASE, failure));
		if (virtual8086 && segment->limit != 0xffff)
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_LIMIT, failure));
		if (virtual8086 && segment->access != 0xf3)
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
	}
	if (!vmx_nested_canonical_address(
	    guest->segment[VMX_NESTED_GUEST_TR].base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(
	    guest->segment[VMX_NESTED_GUEST_FS].base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(
	    guest->segment[VMX_NESTED_GUEST_GS].base,
	    capabilities->linear_address_width) ||
	    (((guest->segment[VMX_NESTED_GUEST_LDTR].access &
	    NVMX_SEG_UNUSABLE) == 0) &&
	    !vmx_nested_canonical_address(
	    guest->segment[VMX_NESTED_GUEST_LDTR].base,
	    capabilities->linear_address_width)) ||
	    (cs->base >> 32) != 0)
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_SEGMENT_BASE,
		    failure));
	for (unsigned int i = VMX_NESTED_GUEST_ES;
	    i <= VMX_NESTED_GUEST_DS; i++) {
		segment = &guest->segment[i];
		if ((segment->access & NVMX_SEG_UNUSABLE) == 0 &&
		    (segment->base >> 32) != 0)
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_BASE, failure));
	}

	if (!virtual8086) {
		if (cs_type != 9 && cs_type != 11 && cs_type != 13 &&
		    cs_type != 15 && !(unrestricted && cs_type == 3))
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
		if (!nvmx_segment_access_common(cs) ||
		    (guest_lma && (cs->access & NVMX_SEG_L) != 0 &&
		    (cs->access & NVMX_SEG_DB) != 0))
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
		if (!nvmx_segment_limit_valid(cs))
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_LIMIT, failure));
		if ((cs_type == 3 &&
		    ((cs->access & NVMX_SEG_DPL_MASK) != 0)) ||
		    ((cs_type == 9 || cs_type == 11) &&
		    ((cs->access & NVMX_SEG_DPL_MASK) >> 5) != ss_dpl) ||
		    ((cs_type == 13 || cs_type == 15) &&
		    ((cs->access & NVMX_SEG_DPL_MASK) >> 5) > ss_dpl))
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));

		for (unsigned int i = VMX_NESTED_GUEST_ES;
		    i <= VMX_NESTED_GUEST_GS; i++) {
			uint32_t type;

			if (i == VMX_NESTED_GUEST_CS)
				continue;
			segment = &guest->segment[i];
			if ((segment->access & NVMX_SEG_UNUSABLE) != 0)
				continue;
			type = segment->access & NVMX_SEG_TYPE_MASK;
			if ((i == VMX_NESTED_GUEST_SS &&
			    type != 3 && type != 7) ||
			    (i != VMX_NESTED_GUEST_SS &&
			    ((type & 1) == 0 ||
			    ((type & 8) != 0 && (type & 2) == 0))) ||
			    !nvmx_segment_access_common(segment))
				return (nvmx_guest_arch_fail(
				    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
			if (!nvmx_segment_limit_valid(segment))
				return (nvmx_guest_arch_fail(
				    VMX_NESTED_GUEST_SEGMENT_LIMIT, failure));
			if (i == VMX_NESTED_GUEST_SS) {
				if ((!unrestricted &&
				    ((segment->access & NVMX_SEG_DPL_MASK) >>
				    5) != (segment->selector & 3)) ||
				    ((cs_type == 3 ||
				    (control->cr0 & NVMX_CR0_PE) == 0) &&
				    (segment->access & NVMX_SEG_DPL_MASK) != 0))
					return (nvmx_guest_arch_fail(
					    VMX_NESTED_GUEST_SEGMENT_ACCESS,
					    failure));
			} else if (!unrestricted && type <= 11 &&
			    ((segment->access & NVMX_SEG_DPL_MASK) >> 5) <
			    (segment->selector & 3))
				return (nvmx_guest_arch_fail(
				    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
		}
	}

	segment = &guest->segment[VMX_NESTED_GUEST_TR];
	if (((guest_lma && (segment->access & NVMX_SEG_TYPE_MASK) != 11) ||
	    (!guest_lma && (segment->access & NVMX_SEG_TYPE_MASK) != 3 &&
	    (segment->access & NVMX_SEG_TYPE_MASK) != 11)) ||
	    (segment->access & (NVMX_SEG_S | NVMX_SEG_RESERVED |
	    NVMX_SEG_UNUSABLE)) != 0 ||
	    (segment->access & NVMX_SEG_PRESENT) == 0)
		return (nvmx_guest_arch_fail(
		    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
	if (!nvmx_segment_limit_valid(segment))
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_SEGMENT_LIMIT,
		    failure));
	segment = &guest->segment[VMX_NESTED_GUEST_LDTR];
	if ((segment->access & NVMX_SEG_UNUSABLE) == 0 &&
	    (((segment->access & NVMX_SEG_TYPE_MASK) != 2) ||
	    (segment->access & (NVMX_SEG_S | NVMX_SEG_RESERVED)) != 0 ||
	    (segment->access & NVMX_SEG_PRESENT) == 0))
		return (nvmx_guest_arch_fail(
		    VMX_NESTED_GUEST_SEGMENT_ACCESS, failure));
	if ((segment->access & NVMX_SEG_UNUSABLE) == 0 &&
	    !nvmx_segment_limit_valid(segment))
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_SEGMENT_LIMIT,
		    failure));

	if (!vmx_nested_canonical_address(guest->gdtr_base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(guest->idtr_base,
	    capabilities->linear_address_width) ||
	    (guest->gdtr_limit >> 16) != 0 || (guest->idtr_limit >> 16) != 0)
		return (nvmx_guest_arch_fail(
		    VMX_NESTED_GUEST_DESCRIPTOR_TABLE, failure));
	if (!guest_lma || (cs->access & NVMX_SEG_L) == 0) {
		if ((guest->rip >> 32) != 0)
			return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_RIP,
			    failure));
	} else if (!vmx_nested_high_bits_identical(guest->rip,
	    capabilities->linear_address_width))
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_RIP, failure));
	if ((guest->rflags & (~((UINT64_C(1) << 22) - 1) |
	    (UINT64_C(1) << 15) | (UINT64_C(1) << 5) |
	    (UINT64_C(1) << 3))) != 0 ||
	    (guest->rflags & (UINT64_C(1) << 1)) == 0 ||
	    ((guest_lma || (control->cr0 & NVMX_CR0_PE) == 0) &&
	    virtual8086))
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_RFLAGS,
		    failure));
	event_type = entry_intr_info & NVMX_GUEST_INTR_TYPE_MASK;
	if ((entry_intr_info & NVMX_GUEST_INTR_VALID) != 0 &&
	    event_type == NVMX_GUEST_INTR_EXTERNAL &&
	    (guest->rflags & NVMX_RFLAGS_IF) == 0)
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_RFLAGS,
		    failure));
	if ((guest->interruptibility & ~0x1fU) != 0 ||
	    (guest->interruptibility & 3) == 3 ||
	    ((guest->interruptibility & 1) != 0 &&
	    (guest->rflags & NVMX_RFLAGS_IF) == 0) ||
	    ((entry_intr_info & NVMX_GUEST_INTR_VALID) != 0 &&
	    (event_type == NVMX_GUEST_INTR_EXTERNAL || event_type == NVMX_GUEST_INTR_NMI) &&
	    (guest->interruptibility & 3) != 0) ||
	    ((guest->interruptibility & 4) != 0 && !guest->in_smm) ||
	    ((vmentry & NVMX_ENTRY_SMM) != 0 &&
	    (guest->interruptibility & 4) == 0) ||
	    ((pinbased & NVMX_PIN_VIRTUAL_NMIS) != 0 &&
	    (entry_intr_info & NVMX_GUEST_INTR_VALID) != 0 &&
	    event_type == NVMX_GUEST_INTR_NMI &&
	    (guest->interruptibility & 8) != 0) ||
	    (guest->interruptibility & 0x10) != 0)
		return (nvmx_guest_arch_fail(
		    VMX_NESTED_GUEST_INTERRUPTIBILITY, failure));
	if (guest->activity > 3 ||
	    (guest->activity == 1 && (capabilities->misc &
	    (UINT64_C(1) << 6)) == 0) ||
	    (guest->activity == 2 && (capabilities->misc &
	    (UINT64_C(1) << 7)) == 0) ||
	    (guest->activity == 3 && (capabilities->misc &
	    (UINT64_C(1) << 8)) == 0) ||
	    (guest->activity == 1 && ss_dpl != 0) ||
	    ((guest->interruptibility & 3) != 0 && guest->activity != 0) ||
	    (guest->activity == 3 && (vmentry & NVMX_ENTRY_SMM) != 0) ||
	    !nvmx_event_allowed_while_inactive(guest->activity,
	    entry_intr_info))
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_ACTIVITY,
		    failure));
	if ((guest->pending_debug & NVMX_PENDING_DEBUG_RESERVED) != 0)
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_PENDING_DEBUG,
		    failure));
	if ((guest->pending_debug & NVMX_PENDING_DEBUG_RTM) != 0 &&
	    (((capabilities->flags & VMX_NESTED_CAP_F_GUEST_RTM) == 0) ||
	    guest->pending_debug != (NVMX_PENDING_DEBUG_RTM |
	    NVMX_PENDING_DEBUG_ENABLED_BP) ||
	    (guest->interruptibility & 2) != 0))
		return (nvmx_guest_arch_fail(VMX_NESTED_GUEST_PENDING_DEBUG,
		    failure));
	if ((guest->interruptibility & 3) != 0 || guest->activity == 1) {
		bool expected_bs;

		expected_bs = (guest->rflags & NVMX_RFLAGS_TF) != 0 &&
		    (guest->debugctl & (UINT64_C(1) << 1)) == 0;
		if (((guest->pending_debug & NVMX_PENDING_DEBUG_BS) != 0) !=
		    expected_bs)
			return (nvmx_guest_arch_fail(
			    VMX_NESTED_GUEST_PENDING_DEBUG, failure));
	}
	return (0);
}
